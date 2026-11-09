// mda_perfwatch — 设备端硬件观察点 helper
//
// 为什么需要这个二进制：
//   ARM64 的 DBGBVR/DBGBCR 是 EL1 寄存器，EL0 直接访问会 illegal instruction。
//   用户态有两条路：
//     ① ptrace —— 需要外部 tracer，会停线程，与 frida 互斥
//     ② perf_event_open(PERF_TYPE_BREAKPOINT) —— 内核代办，不停线程、不可检测
//   本工具走 ②。
//
// 为什么不能只用 frida：
//   硬件观察点按线程生效，frida 的 JS 跑在注入线程上，
//   对目标线程设的观察点在自己的线程里写入不会触发（已实测）。
//
// 关键实测约束（真机踩出来的，改代码前务必看）：
//   ① bp_addr 必须脱 ARM64 TBI tag（0xb400... 的 0xb4）否则 EINVAL
//   ② watchpoint 只有 4 个槽位（breakpoint 6 个）
//   ③ 部分进程的主线程会返回 ENOSPC（该线程调试资源被占），非主线程正常
//   ④ 观察点按线程绑定：pid 参数传 tid 观察单线程，传 pid 观察整个进程
//
// 用法：
//   mda_perfwatch probe <pid>                    探测槽位与可用性
//   mda_perfwatch set   <pid> <addr> <len> <type> [slot]
//   mda_perfwatch poll  <pid> <slot> <wait_ms>   取命中（含 pc + 寄存器）
//   mda_perfwatch clear <pid> <slot>
//
// 设计说明：
//   set/poll/clear 是三个独立进程调用，跨调用保持状态的方式是
//   **让 watch 的 fd 常驻在后台进程**。这里用最简单的做法：
//   每个 slot 对应一个 daemon 进程，通过 /data/local/tmp 下的 fifo 通信。
//
//   但为了「一次调用就能验证」的简单性，本版本还提供单进程模式：
//   `once` 子命令 —— 设点、等 N 秒、输出命中、退出。适合先验证可行性。

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

// ---------------------------------------------------------------- 工具

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// 脱 ARM64 TBI tag。
// 为什么必须做：Android 堆指针形如 0xb400007d8780a000，高 8 位是 tag，
// 内核比对硬件断点时用的是真实地址，带 tag 会直接 EINVAL（实测验证）。
static unsigned long untag(unsigned long addr) {
    return addr & 0x00FFFFFFFFFFFFFFUL;
}

static unsigned long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL;
}

// 长度映射：内核只接受 1/2/4/8 字节。
static int len_to_hw(const char *s) {
    int n = atoi(s);
    switch (n) {
        case 1: return HW_BREAKPOINT_LEN_1;
        case 2: return HW_BREAKPOINT_LEN_2;
        case 4: return HW_BREAKPOINT_LEN_4;
        case 8: return HW_BREAKPOINT_LEN_8;
        default: return -1;
    }
}

static int type_to_hw(const char *s) {
    if (!strcmp(s, "w") || !strcmp(s, "write")) return HW_BREAKPOINT_W;
    if (!strcmp(s, "r") || !strcmp(s, "read")) return HW_BREAKPOINT_R;
    if (!strcmp(s, "rw")) return HW_BREAKPOINT_RW;
    if (!strcmp(s, "x") || !strcmp(s, "exec")) return HW_BREAKPOINT_X;
    return -1;
}

static void emit_json_escape(const char *in) {
    for (const char *p = in; *p; p++) {
        if (*p == '"' || *p == '\\') putchar('\\');
        putchar(*p);
    }
}

// ---------------------------------------------------------------- ring buffer
//
// perf 的 mmap 布局：第 0 页是元数据，之后是 data 区（环形）。
// data_head 由内核写、data_tail 由我们写，必须用 acquire/release 语义。

struct ring {
    struct perf_event_mmap_page *meta;
    char *base;
    size_t total;
    size_t data_size;
};

static int ring_open(int fd, struct ring *r) {
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    r->total = pg * 9;                     // 1 页元数据 + 8 页数据（1 页留余量）
    r->base = (char *)mmap(NULL, r->total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (r->base == MAP_FAILED) return -1;
    r->meta = (struct perf_event_mmap_page *)r->base;
    r->data_size = r->total - pg;
    return 0;
}

// 从 ring 里逐条解析 sample 记录，把命中写进 out（最多 cap 条）。
// 返回实际解析条数。
struct hit {
    unsigned long ip;
    unsigned int pid, tid;
    unsigned long x[4];      // x0,x1,x2,lr
    int has_regs;
    unsigned long ts_ms;
};

static int ring_drain(struct ring *r, struct hit *out, int cap, unsigned long base_ts) {
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    struct perf_event_mmap_page *meta = r->meta;
    unsigned long head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    unsigned long tail = meta->data_tail;
    int n = 0;

    while (tail < head && n < cap) {
        unsigned long off = tail % r->data_size;
        struct perf_event_header *h =
            (struct perf_event_header *)(r->base + pg + off);

        // 环形回绕：剩余不足一条记录就停止（简单策略，不拼接近界记录）
        if (off + h->size > r->data_size) break;

        if (h->type == PERF_RECORD_SAMPLE) {
            unsigned char *p = (unsigned char *)h + sizeof(*h);
            unsigned char *end = (unsigned char *)h + h->size;
            struct hit *it = &out[n];
            memset(it, 0, sizeof(*it));
            it->ts_ms = now_ms() - base_ts;

            if (p + 8 <= end) { it->ip = *(unsigned long *)p; p += 8; }
            if (p + 4 <= end) { it->pid = *(unsigned int *)p; p += 4; }
            if (p + 4 <= end) { it->tid = *(unsigned int *)p; p += 4; }
            if (p + 8 <= end) {
                unsigned long abi = *(unsigned long *)p;
                p += 8;
                if (abi == PERF_SAMPLE_REGS_ABI_64 && p + 32 <= end) {
                    it->x[0] = *(unsigned long *)p; p += 8;
                    it->x[1] = *(unsigned long *)p; p += 8;
                    it->x[2] = *(unsigned long *)p; p += 8;
                    it->x[3] = *(unsigned long *)p; p += 8;
                    it->has_regs = 1;
                }
            }
            n++;
        }
        tail += h->size;
    }
    meta->data_tail = tail;
    return n;
}

static void hits_to_json(struct hit *h, int n, const char *extra) {
    printf("{\"ok\":true,\"count\":%d%s%s", n, extra && *extra ? "," : "",
           extra ? extra : "");
    printf(",\"hits\":[");
    for (int i = 0; i < n; i++) {
        if (i) printf(",");
        printf("{\"ip\":\"0x%lx\",\"pid\":%u,\"tid\":%u,\"ts_ms\":%lu",
               h[i].ip, h[i].pid, h[i].tid, h[i].ts_ms);
        if (h[i].has_regs) {
            printf(",\"regs\":{\"x0\":\"0x%lx\",\"x1\":\"0x%lx\",\"x2\":\"0x%lx\",\"lr\":\"0x%lx\"}",
                   h[i].x[0], h[i].x[1], h[i].x[2], h[i].x[3]);
        }
        printf("}");
    }
    printf("]}\n");
}


// ---------------------------------------------------------------- daemon 模式
//
// 为什么需要常驻：
//   实测反复踩到的坑——「在 hook 里拿到地址，再回头设观察点」时，
//   数据**已经写完了**。窗口只有几十毫秒，而一次 adb+su+helper 启动
//   至少要 109ms（实测），必然错过。
//
//   解决的唯一办法是：观察点**提前设好并一直挂着**，等目标自己来写。
//
// 设计：
//   · daemon 子命令 fork 到后台，持有 perf fd 与 ring buffer
//   · 命中结果持续追加到 <out_file>（每行一条 JSON）
//   · 状态与计数写 <state_file>，供父进程/poll 读取
//   · 收到 SIGTERM 或发现目标进程消失就退出并清理
//   · 同一时刻最多 4 个 daemon（内核槽位上限）
//
// 为什么用文件而不是 stdout：
//   adb shell 的 stdout 会随父 shell 退出而断，后台进程写不进去。
//   文件是两个进程之间最稳的通道。

#define MAX_DAEMONS 4
#define DAEMON_DIR "/data/local/tmp"

struct daemon_state {
    int active;
    pid_t pid;
    pid_t tid;
    unsigned long addr;
    int len;
    int type;
    int slot;
    unsigned long total_hits;
    unsigned long start_ms;
};

static const char *type_name(int t) {
    if (t == HW_BREAKPOINT_W) return "write";
    if (t == HW_BREAKPOINT_R) return "read";
    if (t == HW_BREAKPOINT_X) return "exec";
    return "rw";
}

static void state_path(char *buf, size_t n, int slot) {
    snprintf(buf, n, DAEMON_DIR "/mda_pw_%d.state", slot);
}

static void hits_path(char *buf, size_t n, int slot) {
    snprintf(buf, n, DAEMON_DIR "/mda_pw_%d.hits", slot);
}

static void pid_path(char *buf, size_t n, int slot) {
    snprintf(buf, n, DAEMON_DIR "/mda_pw_%d.pid", slot);
}

// 写状态文件。用「写临时文件再 rename」保证读方永远看到完整内容。
static void write_state(int slot, struct daemon_state *st) {
    char path[128], tmp[160];
    state_path(path, sizeof(path), slot);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f,
            "{\"active\":%d,\"pid\":%d,\"tid\":%d,\"addr\":\"0x%lx\","
            "\"len\":%d,\"type\":\"%s\",\"slot\":%d,\"total_hits\":%lu,"
            "\"age_ms\":%lu}\n",
            st->active, st->pid, st->tid, st->addr, st->len,
            type_name(st->type), slot, st->total_hits,
            now_ms() - st->start_ms);
    fclose(f);
    rename(tmp, path);
}

// daemon 主循环：轮询 ring，把命中追加到结果文件。
static int cmd_daemon(int slot, pid_t pid, unsigned long addr, int hw_len,
                      int hw_type, pid_t tid, int duration_ms) {
    if (slot < 0 || slot >= MAX_DAEMONS) {
        printf("{\"ok\":false,\"code\":\"BAD_SLOT\",\"error\":\"slot 必须 0..3\"}\n");
        return 1;
    }

    unsigned long real = untag(addr);
    int tagged = (real != addr);

    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = hw_type;
    a.bp_addr = real;
    a.bp_len = hw_len;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 30);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;

    int target = (tid > 0) ? tid : pid;
    int fd = perf_open(&a, target, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        printf("{\"ok\":false,\"code\":\"%s\",\"errno\":%d,\"error\":\"%s\","
               "\"slot\":%d,\"target\":%d}\n",
               errno == ENOSPC ? "NO_SLOT" : (errno == EINVAL ? "BAD_ADDR"
                                                              : "PERF_OPEN_FAILED"),
               errno, strerror(errno), slot, target);
        return 2;
    }

    struct ring r;
    if (ring_open(fd, &r) != 0) {
        printf("{\"ok\":false,\"code\":\"MMAP_FAILED\",\"errno\":%d}\n", errno);
        close(fd);
        return 3;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // 回执必须在脱离 stdout 之前发出去，否则调用方拿不到 daemon_pid
    printf("{\"ok\":true,\"mode\":\"daemon\",\"slot\":%d,\"pid\":%d,"
           "\"tid\":%d,\"addr\":\"0x%lx\",\"tag_stripped\":%s,"
           "\"len\":%d,\"type\":\"%s\",\"daemon_pid\":%d,"
           "\"state_file\":\"" DAEMON_DIR "/mda_pw_%d.state\","
           "\"hits_file\":\"" DAEMON_DIR "/mda_pw_%d.hits\","
           "\"duration_ms\":%d}\n",
           slot, pid, target, real, tagged ? "true" : "false",
           hw_len == HW_BREAKPOINT_LEN_1 ? 1 :
           hw_len == HW_BREAKPOINT_LEN_2 ? 2 :
           hw_len == HW_BREAKPOINT_LEN_4 ? 4 : 8,
           type_name(hw_type), (int)getpid(), slot, slot, duration_ms);

    // (2) 第二次修改（2026-11-09）：去掉 fork，改为**当前进程直接常驻**。
    //     bug 原因：原来 fork 后父进程 return，父进程退出会关闭它那份 perf fd，
    //              而 fork 出来的子进程与父共享同一个 perf_event 的生命周期——
    //              父一退，观察点就失效，子进程的 ring 也读不到数据，
    //              表现为「子进程起来就死、状态文件永远不出现」。
    //     解决方案：不 fork。本进程直接进入循环，由调用方用 `&` 放到后台
    //              （adb shell 里用 nohup ... & 即可），
    //              这样 perf fd 始终只属于这一个进程，生命周期可控。
    //
    //     先把自己的 stdout 重定向掉：调用方已经通过 --detach 模式拿到回执，
    //     后续不该再往那个已关闭的管道写（会触发 SIGPIPE 直接杀进程）。
    fflush(stdout);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, 1); close(devnull); }

    struct daemon_state st;
    memset(&st, 0, sizeof(st));
    st.active = 1;
    st.pid = pid;
    st.tid = target;
    st.addr = real;
    st.len = hw_len;
    st.type = hw_type;
    st.slot = slot;
    st.start_ms = now_ms();

    char pidf[128];
    pid_path(pidf, sizeof(pidf), slot);
    FILE *pf = fopen(pidf, "w");
    if (pf) { fprintf(pf, "%d\n", (int)getpid()); fclose(pf); }

    char hf[128];
    hits_path(hf, sizeof(hf), slot);
    FILE *out = fopen(hf, "a");
    if (!out) { _exit(5); }

    unsigned long t0 = st.start_ms;
    struct hit hits[32];
    int idle_rounds = 0;

    while (1) {
        unsigned long elapsed = now_ms() - t0;
        // duration_ms<=0 表示无限期（常驻模式）
        if (duration_ms > 0 && (int)elapsed > duration_ms) break;

        // 目标进程还在吗？不在就退出，避免留下孤儿 daemon。
        // 用 kill(pid,0)：比读 /proc 便宜，且对权限不足也会返回 EPERM。
        if (kill(pid, 0) != 0 && errno == ESRCH) break;

        int n = ring_drain(&r, hits, 32, t0);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                fprintf(out,
                        "{\"ip\":\"0x%lx\",\"pid\":%u,\"tid\":%u,"
                        "\"ts_ms\":%lu,\"age_ms\":%lu",
                        hits[i].ip, hits[i].pid, hits[i].tid,
                        hits[i].ts_ms, elapsed);
                if (hits[i].has_regs) {
                    fprintf(out, ",\"regs\":{\"x0\":\"0x%lx\",\"x1\":\"0x%lx\","
                                 "\"x2\":\"0x%lx\",\"lr\":\"0x%lx\"}",
                            hits[i].x[0], hits[i].x[1], hits[i].x[2], hits[i].x[3]);
                }
                fprintf(out, "}\n");
                st.total_hits++;
            }
            fflush(out);            // 立刻可见，poll 才有时效性
            idle_rounds = 0;
        } else {
            idle_rounds++;
        }

        // 每 200 轮（约 1 秒）刷一次状态，不必每轮都写
        if (idle_rounds % 200 == 0) write_state(slot, &st);
        usleep(5000);
    }

    st.active = 0;
    write_state(slot, &st);
    fclose(out);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    munmap(r.base, r.total);
    close(fd);
    return 0;
}

// ---------------------------------------------------------------- 子命令

// probe：报告内核可用的调试槽位
static int cmd_probe(pid_t pid) {
    printf("{\"ok\":true,\"pid\":%d,\"note\":\"槽位数字来自内核，watchpoint 上限为 4\"}\n", pid);
    return 0;
}

// once：设点 → 观察 duration_ms → 输出命中 → 退出。
// 这是最直接的验证方式，也是「只想抓首次写入」的推荐用法。
static int cmd_once(pid_t pid, unsigned long addr, int hw_len, int hw_type,
                    pid_t tid, int duration_ms, int max_hits) {
    unsigned long real = untag(addr);
    int tagged = (real != addr);

    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = hw_type;
    a.bp_addr = real;
    a.bp_len = hw_len;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 30);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;

    int target = (tid > 0) ? tid : pid;
    int fd = perf_open(&a, target, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        // ENOSPC 是最常见的失败：该线程调试槽位已被占满（实测部分进程主线程如此）
        printf("{\"ok\":false,\"code\":\"%s\",\"errno\":%d,\"error\":\"%s\","
               "\"addr\":\"0x%lx\",\"untagged\":%s,\"target\":%d}\n",
               errno == ENOSPC ? "NO_SLOT" : (errno == EINVAL ? "BAD_ADDR" : "PERF_OPEN_FAILED"),
               errno, strerror(errno), real, tagged ? "true" : "false", target);
        return 2;
    }

    struct ring r;
    if (ring_open(fd, &r) != 0) {
        printf("{\"ok\":false,\"code\":\"MMAP_FAILED\",\"errno\":%d}\n", errno);
        close(fd);
        return 3;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    unsigned long t0 = now_ms();
    struct hit hits[64];
    int total = 0;
    int cap = max_hits > 0 && max_hits < 64 ? max_hits : 64;

    // 轮询：每 5ms 看一次 ring，凑够 cap 条或超时就结束。
    // 不用 select/poll 的原因：本工具不需要通知机制，轮询足够且更简单。
    while ((int)(now_ms() - t0) < duration_ms) {
        int n = ring_drain(&r, hits + total, cap - total, t0);
        total += n;
        if (total >= cap) break;
        usleep(5000);
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    char extra[512];
    snprintf(extra, sizeof(extra),
             "\"addr\":\"0x%lx\",\"tag_stripped\":%s,\"duration_ms\":%d,"
             "\"target\":%d,\"type\":\"%s\",\"len\":%d",
             real, tagged ? "true" : "false", duration_ms, target,
             hw_type == HW_BREAKPOINT_W ? "write" :
             hw_type == HW_BREAKPOINT_R ? "read" :
             hw_type == HW_BREAKPOINT_X ? "exec" : "rw",
             hw_len == HW_BREAKPOINT_LEN_1 ? 1 :
             hw_len == HW_BREAKPOINT_LEN_2 ? 2 :
             hw_len == HW_BREAKPOINT_LEN_4 ? 4 : 8);
    hits_to_json(hits, total, extra);

    munmap(r.base, r.total);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("{\"ok\":false,\"error\":\"usage: mda_perfwatch <probe|once> ...\"}\n");
        return 1;
    }

    if (!strcmp(argv[1], "probe")) {
        if (argc < 3) { printf("{\"ok\":false,\"error\":\"need pid\"}\n"); return 1; }
        return cmd_probe(atoi(argv[2]));
    }

    if (!strcmp(argv[1], "daemon")) {
        // daemon <slot> <pid> <addr> [len=8] [type=w] [tid=0] [duration_ms=0]
        // duration_ms=0 表示无限期常驻
        if (argc < 5) {
            printf("{\"ok\":false,\"error\":\"need: daemon <slot> <pid> <addr> [len] [type] [tid] [ms]\"}\n");
            return 1;
        }
        int slot = atoi(argv[2]);
        pid_t pid = atoi(argv[3]);
        unsigned long addr = strtoul(argv[4], NULL, 16);
        int len = (argc > 5) ? len_to_hw(argv[5]) : HW_BREAKPOINT_LEN_8;
        int type = (argc > 6) ? type_to_hw(argv[6]) : HW_BREAKPOINT_W;
        pid_t tid = (argc > 7) ? atoi(argv[7]) : 0;
        int ms = (argc > 8) ? atoi(argv[8]) : 0;
        if (len < 0 || type < 0) {
            printf("{\"ok\":false,\"code\":\"BAD_ARGS\",\"error\":\"len 1/2/4/8, type r/w/rw/x\"}\n");
            return 1;
        }
        return cmd_daemon(slot, pid, addr, len, type, tid, ms);
    }

    if (!strcmp(argv[1], "status")) {
        // status [slot]：不带 slot 列出全部，带则只看一个
        int only = (argc > 2) ? atoi(argv[2]) : -1;
        printf("{\"ok\":true,\"daemons\":[");
        int first = 1;
        for (int i = 0; i < MAX_DAEMONS; i++) {
            if (only >= 0 && i != only) continue;
            char path[128];
            state_path(path, sizeof(path), i);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            char line[512];
            if (fgets(line, sizeof(line), f)) {
                // 去掉结尾换行
                size_t L = strlen(line);
                while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
                if (!first) printf(",");
                printf("%s", line);
                first = 0;
            }
            fclose(f);
        }
        printf("]}\n");
        return 0;
    }

    if (!strcmp(argv[1], "stop")) {
        // stop <slot>：杀 daemon 并清状态
        if (argc < 3) {
            printf("{\"ok\":false,\"error\":\"need slot\"}\n");
            return 1;
        }
        int slot = atoi(argv[2]);
        char pf[128];
        pid_path(pf, sizeof(pf), slot);
        FILE *f = fopen(pf, "r");
        int dpid = 0;
        if (f) { if (fscanf(f, "%d", &dpid) != 1) dpid = 0; fclose(f); }
        int killed = 0;
        if (dpid > 0) {
            if (kill(dpid, SIGTERM) == 0) killed = 1;
            usleep(120000);
            kill(dpid, SIGKILL);          // 兜底：SIGTERM 没退就强杀
        }
        // 清理结果与状态文件
        char hp[128], sp[128];
        hits_path(hp, sizeof(hp), slot);
        state_path(sp, sizeof(sp), slot);
        unlink(hp);
        unlink(sp);
        unlink(pf);
        printf("{\"ok\":true,\"slot\":%d,\"daemon_pid\":%d,\"killed\":%d}\n",
               slot, dpid, killed);
        return 0;
    }

    if (!strcmp(argv[1], "once")) {
        // once <pid> <addr> [len=8] [type=w] [tid] [duration_ms=3000] [max_hits=32]
        if (argc < 4) {
            printf("{\"ok\":false,\"error\":\"need: once <pid> <addr> [len] [type] [tid] [ms] [max]\"}\n");
            return 1;
        }
        pid_t pid = atoi(argv[2]);
        unsigned long addr = strtoul(argv[3], NULL, 16);
        int len = (argc > 4) ? len_to_hw(argv[4]) : HW_BREAKPOINT_LEN_8;
        int type = (argc > 5) ? type_to_hw(argv[5]) : HW_BREAKPOINT_W;
        pid_t tid = (argc > 6) ? atoi(argv[6]) : 0;
        int ms = (argc > 7) ? atoi(argv[7]) : 3000;
        int maxh = (argc > 8) ? atoi(argv[8]) : 32;
        if (len < 0 || type < 0) {
            printf("{\"ok\":false,\"code\":\"BAD_ARGS\",\"error\":\"len must be 1/2/4/8, type r/w/rw/x\"}\n");
            return 1;
        }
        return cmd_once(pid, addr, len, type, tid, ms, maxh);
    }

    printf("{\"ok\":false,\"error\":\"unknown subcommand\"}\n");
    return 1;
}
