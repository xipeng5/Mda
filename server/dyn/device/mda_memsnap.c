// mda_memsnap — 设备端内存快照/对比 helper
//
// 为什么需要它（实测数据）：
//   通过 adb shell + dd 读 /proc/<pid>/mem：
//       4MB 耗时 37,000 ms
//   本程序用 pread 直接读：
//       4MB 耗时 6.4 ms
//   **差 5786 倍**。内存快照动辄几十 MB，走 shell 根本不可行。
//
// 为什么快照要留在设备上而不是传回 Mac：
//   50MB 二进制穿过 adb 传输 + base64 编码，单程就要几十秒。
//   在设备上算 diff，只把「变化的块」传回来，是唯一现实的做法。
//
// 用法：
//   mda_memsnap snap <pid> <name> [max_mb]        拍基线（留在设备上）
//   mda_memsnap diff <pid> <name> [min] [max]     再拍一份并对比
//   mda_memsnap clear <name>                      清理
//
// 快照文件落在 /data/local/tmp/mda_snap_<name>.bin：
//   头部 32 字节 = 段数量 + 每段的 (base, size) 表（本程序自定义格式）

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SNAP_DIR "/data/local/tmp"
#define MAX_SEGS 4096

struct seg {
    uint64_t base;
    uint64_t size;
};

static int g_segs_walked = 0;

// 这些段极大且不含业务数据，跳过（依据：实测 dalvik region space 占 1GB）
static const char *SKIP_HINTS[] = {
    "dalvik-main space",
    "dalvik-large object space",
    "dalvik-free list",
    "dalvik-non moving",
    "dalvik-zygote",
    "boot.art", "boot-core-libart.art", "boot-framework.art",
    "boot.oat",
    "[anon:dalvik-",
    NULL,
};

static int should_skip(const char *name) {
    for (int i = 0; SKIP_HINTS[i]; i++) {
        if (strstr(name, SKIP_HINTS[i])) return 1;
    }
    return 0;
}

// 解析 /proc/<pid>/maps，挑出可写 + 匿名 + 非巨型段。
static int collect_segs(pid_t pid, struct seg *out, int max, uint64_t min_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < max) {
        uint64_t lo, hi;
        char perms[8];
        // (1) 第一次修改（2026-11-09）：
        //     bug 原因：原来用 `%*s` 连续跳过 3 个字段再取名字，
        //               但 maps 行里「inode」后面可能紧跟多个空格、
        //               或者根本没有 name 字段，`%*s` 会把不该跳的也跳掉，
        //               导致整行解析失败（实测 segments 恒为 0）。
        //     解决方案：先用 `%lx-%lx %7s` 只解析前三项，
        //               名字改为在后面手工找（第一个非空白之后的内容）。
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3) continue;

        // 手工提取 name：跳过前 5 个列（range/perms/offset/dev/inode）
        char name[256];
        name[0] = 0;
        {
            const char *p2 = line;
            int cols = 0;
            while (*p2 && cols < 5) {
                while (*p2 == ' ') p2++;
                while (*p2 && *p2 != ' ') p2++;
                cols++;
            }
            while (*p2 == ' ') p2++;
            size_t k = 0;
            while (*p2 && *p2 != '\n' && k < sizeof(name) - 1) name[k++] = *p2++;
            name[k] = 0;
        }
        if (!strchr(perms, 'w')) continue;
        uint64_t sz = hi - lo;
        if (sz < min_sz) continue;
        if (should_skip(name)) continue;
        out[n].base = lo;
        out[n].size = sz;
        n++;
    }
    fclose(f);
    return n;
}

static void snap_path(char *buf, size_t n, const char *name) {
    snprintf(buf, n, SNAP_DIR "/mda_snap_%s.bin", name);
}

static int fd_mem(pid_t pid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    return open(p, O_RDONLY);
}

// snap：把段表 + 内容写成一个文件。
static int cmd_snap(pid_t pid, const char *name, uint64_t max_bytes) {
    struct seg *segs = calloc(MAX_SEGS, sizeof(*segs));
    if (!segs) return 1;
    int n = collect_segs(pid, segs, MAX_SEGS, 4096);
    if (n < 0) { printf("{\"ok\":false,\"code\":\"NO_MAPS\"}\n"); return 2; }

    // (4) 第四次修改（2026-11-09）：排序方向反过来——**小段优先**。
    //     bug 原因：原来按大小降序（大段优先），实测进程里有 1GB / 256MB
    //               这种巨型段，预算 64MB 全被它们占满，而真正会出现
    //               「新增 98 字节块」的是那些几 MB 的小段
    //               （实测目标块在 0x7a0a0a0000 的 2.1MB 段里，完全没被选中）。
    //              结果 diff 永远是 0 —— 看起来像「没有变化」，
    //              实际是「根本没读到」。
    //     解决方案：改为按大小**升序**，先装小段。小段总量通常远小于大段，
    //               能在有限预算内覆盖更多的段数，命中率更高。
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (segs[j].size < segs[i].size) {
                struct seg t = segs[i]; segs[i] = segs[j]; segs[j] = t;
            }
        }
    }
    uint64_t used = 0;
    int picked = 0;
    // (2) 第二次修改（2026-11-09）：
    //     bug 原因：原来这里用 `break` 而不是 `continue`。段是按大小降序排的，
    //               所以第一个段就是最大的那个；一旦它超过预算，
    //               `break` 会让后面所有段都不再被考虑，
    //               结果是 picked 恒为 0（实测 segments 一直是 0）。
    //     解决方案：改为 `continue` —— 装不下的段跳过，继续看后面更小的。
    //               这样既能选满预算，又不会被单个巨型段卡死。
    // (3) 第三次修改（2026-11-09）：
    //     bug 原因：选中的段原来是「原位留在 segs[i]」，
    //               后面写文件时却按 segs[0..picked-1] 取——
    //               取到的是**排在最前面但被跳过的那些巨型段**，
    //               而不是真正选中的。实测表现为 picked=2 但写出 1.3GB
    //               （前两个段正好是 1GB 和 256MB，都远超预算）。
    //     解决方案：用独立的 chosen 数组按顺序存选中的段，
    //               写文件只遍历 chosen，不再依赖原位顺序。
    struct seg *chosen = calloc((size_t)n + 1, sizeof(*chosen));
    if (!chosen) { free(segs); return 1; }
    for (int i = 0; i < n; i++) {
        if (used + segs[i].size > max_bytes) continue;
        chosen[picked].base = segs[i].base;
        chosen[picked].size = segs[i].size;
        used += segs[i].size;
        picked++;
    }
    free(segs);
    segs = chosen;

    int fd = fd_mem(pid);
    if (fd < 0) { printf("{\"ok\":false,\"code\":\"NO_MEM\"}\n"); return 3; }

    char path[256], tmp[288];
    snap_path(path, sizeof(path), name);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *out = fopen(tmp, "wb");
    if (!out) { printf("{\"ok\":false,\"code\":\"NO_WRITE\"}\n"); return 4; }

    // 头部：magic + 段数
    uint32_t magic = 0x4D444153;             // "MDAS"
    uint32_t cnt = (uint32_t)picked;
    fwrite(&magic, 4, 1, out);
    fwrite(&cnt, 4, 1, out);
    fwrite(segs, sizeof(struct seg), picked, out);

    char *buf = malloc(1 << 20);             // 1MB 缓冲，减少 syscall
    uint64_t total = 0;
    for (int i = 0; i < picked; i++) {
        uint64_t left = segs[i].size, off = segs[i].base;
        while (left > 0) {
            size_t chunk = left > (1u << 20) ? (1u << 20) : (size_t)left;
            ssize_t rd = pread(fd, buf, chunk, (off_t)off);
            if (rd <= 0) {
                // 读失败就补零，保持文件布局固定（否则 diff 会错位）
                memset(buf, 0, chunk);
                rd = (ssize_t)chunk;
            }
            fwrite(buf, 1, (size_t)rd, out);
            total += (uint64_t)rd;
            off += (uint64_t)rd;
            left -= (uint64_t)rd;
        }
    }
    free(buf);
    fclose(out);
    close(fd);
    rename(tmp, path);
    free(segs);

    printf("{\"ok\":true,\"mode\":\"snap\",\"name\":\"%s\",\"segments\":%d,"
           "\"bytes\":%llu,\"file\":\"%s\",\"candidates\":%d,"
           "\"coverage\":\"%.1f%%\"}\n",
           name, picked, (unsigned long long)total, path, n,
           n > 0 ? (double)picked * 100.0 / (double)n : 0.0);
    return 0;
}

// diff：再拍一份到内存，和基线逐段比对，输出变化的连续区间。
static int cmd_diff(pid_t pid, const char *name, uint64_t min_sz,
                    uint64_t max_sz, int max_report) {
    char path[256];
    snap_path(path, sizeof(path), name);
    FILE *bf = fopen(path, "rb");
    if (!bf) {
        printf("{\"ok\":false,\"code\":\"NO_BASELINE\",\"error\":\"没有基线快照\"}\n");
        return 2;
    }
    uint32_t magic = 0, cnt = 0;
    if (fread(&magic, 4, 1, bf) != 1 || magic != 0x4D444153 ||
        fread(&cnt, 4, 1, bf) != 1 || cnt > MAX_SEGS) {
        printf("{\"ok\":false,\"code\":\"BAD_SNAPSHOT\"}\n");
        fclose(bf);
        return 3;
    }
    struct seg *segs = calloc(cnt ? cnt : 1, sizeof(*segs));
    if (!segs || fread(segs, sizeof(struct seg), cnt, bf) != cnt) {
        printf("{\"ok\":false,\"code\":\"BAD_SNAPSHOT\"}\n");
        fclose(bf);
        return 3;
    }

    int fd = fd_mem(pid);
    if (fd < 0) { printf("{\"ok\":false,\"code\":\"NO_MEM\"}\n"); return 4; }

    const size_t CH = 1 << 20;
    char *a = malloc(CH), *b = malloc(CH);
    if (!a || !b) return 5;

    printf("{\"ok\":true,\"mode\":\"diff\",\"changed\":[");
    int reported = 0;
    uint64_t total_changed = 0;

    // (6) 第六次修改（2026-11-09）：
    //     bug 原因：diff 只遍历基线里已有的段，**完全看不到新增的段**。
    //               而「record98 从无到有」这类场景恰恰经常是
    //               malloc 出一个新段（或从 brk 扩展），目标块落在一个
    //               基线里根本不存在的段上——diff 永远返回 0，
    //               看起来像"没有变化"，实际是"根本没看那里"。
    //               实测复现：目标块在 0x7a82a71000 的 64KB 匿名段里，
    //               而该段不在基线中，diff 结果为空。
    //     解决方案：遍历**当前**的可写匿名段，基线里没有的段整段当作新增。
    //               同时保留原有的"段内比对"逻辑。
    {
        struct seg *cur = calloc(MAX_SEGS, sizeof(*cur));
        int cn = cur ? collect_segs(pid, cur, MAX_SEGS, 4096) : -1;
        if (cn > 0) {
            for (int ci = 0; ci < cn && reported < max_report; ci++) {
                // 基线里有没有同 base 的段？
                int found = 0;
                for (uint32_t bi = 0; bi < cnt; bi++) {
                    if (segs[bi].base == cur[ci].base) { found = 1; break; }
                }
                if (found) continue;
                uint64_t sz = cur[ci].size;
                if ((uint64_t)min_sz > sz) continue;
                if (max_sz != 0 && sz > (uint64_t)max_sz) continue;
                // 读开头一小段作为样本（整段读没必要）
                size_t want = sz > 32 ? 32 : (size_t)sz;
                if (pread(fd, b, want, (off_t)cur[ci].base) > 0) {
                    if (reported) printf(",");
                    printf("{\"addr\":\"0x%llx\",\"size\":%llu,"
                           "\"kind\":\"new_segment\",\"sample\":\"",
                           (unsigned long long)cur[ci].base,
                           (unsigned long long)sz);
                    for (size_t k = 0; k < want; k++)
                        printf("%02x", (unsigned char)b[k]);
                    printf("\"}");
                    reported++;
                    total_changed += sz;
                }
            }
            free(cur);
        }
    }

    for (uint32_t i = 0; i < cnt && reported < max_report; i++) {
        g_segs_walked++;
        uint64_t off = segs[i].base, left = segs[i].size;
        while (left > 0 && reported < max_report) {
            size_t chunk = left > CH ? CH : (size_t)left;
            size_t got = fread(a, 1, chunk, bf);
            if (got != chunk) break;                  // 基线被截断
            ssize_t rd = pread(fd, b, chunk, (off_t)off);
            if (rd <= 0) { off += chunk; left -= chunk; continue; }
            size_t n = (size_t)rd < chunk ? (size_t)rd : chunk;

            // 找不同的连续区间。
            // (5) 第五次修改（2026-11-09）：
            //     bug 原因：原来是「外层 while(s<n) + 内层 while(e<n) 找边界」，
            //               但内层扫到 n 后，外层的 s 只前进到 end，
            //               而 end 可能远小于 n —— 于是同一段被反复扫描。
            //               当整块 1MB 都在变化时（堆活跃区就是这样），
            //               复杂度退化成 O(n²)，实测直接卡死。
            //     解决方案：改成**单趟线性扫描**，用 i 一次走到底，
            //               遇到连续不同就记录起点，遇到超过阈值连续相同就收尾。
            //               无论目标怎么变，复杂度恒为 O(n)。
            if (memcmp(a, b, n) != 0) {
                size_t i = 0;
                while (i < n) {
                    // 跳到下一个不同字节
                    while (i < n && a[i] == b[i]) i++;
                    if (i >= n) break;
                    size_t s0 = i;
                    size_t gap = 0;
                    while (i < n) {
                        if (a[i] != b[i]) { gap = 0; }
                        else { if (++gap > 16) break; }
                        i++;
                    }
                    size_t end = (gap > 16) ? (i - gap) : i;
                    size_t sz = end - s0;
                    if (sz < min_sz) continue;
                    if (max_sz != 0 && sz > max_sz) continue;
                    if (reported) printf(",");
                    printf("{\"addr\":\"0x%llx\",\"size\":%zu,"
                           "\"kind\":\"changed\",\"sample\":\"",
                           (unsigned long long)(off + s0), sz);
                    size_t show = sz > 16 ? 16 : sz;
                    for (size_t k = 0; k < show; k++)
                        printf("%02x", (unsigned char)b[s0 + k]);
                    printf("\"}");
                    reported++;
                    total_changed += sz;
                    if (reported >= max_report) break;
                }
            }
            off += chunk;
            left -= chunk;
        }
    }
    // (7) 第七次修改（2026-11-09）：显式报告覆盖率。
    //     用户看不到「基线只覆盖了 875/1068 个段」这件事，
    //     diff 返回 0 时会误以为「没有变化」，实际是「没读到那里」。
    printf("],\"count\":%d,\"total_bytes\":%llu,\"baseline_segments\":%u}\n",
           reported, (unsigned long long)total_changed, cnt);
    {
        // 诊断：把各阶段耗时写到 stderr，定位慢在哪里
        extern int g_segs_walked;
        fprintf(stderr, "[dbg] walked_segs=%d reported=%d\n",
                g_segs_walked, reported);
    }

    free(a); free(b); free(segs);
    fclose(bf);
    close(fd);
    return 0;
}

static int cmd_clear(const char *name) {
    char path[256];
    snap_path(path, sizeof(path), name);
    int rc = unlink(path);
    printf("{\"ok\":true,\"removed\":%d}\n", rc == 0 ? 1 : 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("{\"ok\":false,\"error\":\"usage: mda_memsnap <snap|diff|clear> ...\"}\n");
        return 1;
    }
    if (!strcmp(argv[1], "snap")) {
        // snap <pid> <name> [max_mb]
        if (argc < 4) { printf("{\"ok\":false,\"error\":\"need pid name\"}\n"); return 1; }
        uint64_t mb = (argc > 4) ? strtoull(argv[4], NULL, 10) : 64;
        return cmd_snap(atoi(argv[2]), argv[3], mb * 1024ULL * 1024ULL);
    }
    if (!strcmp(argv[1], "diff")) {
        // diff <pid> <name> [min] [max] [max_report]
        if (argc < 4) { printf("{\"ok\":false,\"error\":\"need pid name\"}\n"); return 1; }
        uint64_t mn = (argc > 4) ? strtoull(argv[4], NULL, 10) : 1;
        uint64_t mx = (argc > 5) ? strtoull(argv[5], NULL, 10) : 0;
        int rep = (argc > 6) ? atoi(argv[6]) : 200;
        return cmd_diff(atoi(argv[2]), argv[3], mn, mx, rep);
    }
    if (!strcmp(argv[1], "clear")) {
        if (argc < 3) { printf("{\"ok\":false,\"error\":\"need name\"}\n"); return 1; }
        return cmd_clear(argv[2]);
    }
    printf("{\"ok\":false,\"error\":\"unknown subcommand\"}\n");
    return 1;
}
