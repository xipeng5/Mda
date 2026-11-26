/*
 * mda_memguard_inject —— 跨进程写事件就地快照
 *
 * ============================================================
 * 目标
 * ============================================================
 * 使用者要的是「能在正确时刻停下来」：写入发生的那一刻，
 * 把**写入前的内容**和现场（pc/lr/sp/regs）留下来。
 *
 * perf_watch 只能给 PC；等回头去读，那块内存早被释放/复用了。
 *
 * ============================================================
 * 做法
 * ============================================================
 * 通过 ptrace 把一段 payload 注入目标进程，让它自己：
 *   1. 装 SIGSEGV handler
 *   2. 把含目标地址的页改成只读
 *   3. 命中写入时记录 before 内容 + 现场到共享内存，然后恢复页权限
 *
 * 记录通过共享内存（远程 mmap 的 MAP_SHARED 匿名映射）传回本进程。
 *
 * ============================================================
 * 本机实测（3e2ff172 / Android 12 / arm64 / 内核 4.19.113）
 * ============================================================
 * 已验证可行：
 *   · ptrace attach 目标
 *   · 跨进程读（process_vm_readv）/ 写（PTRACE_POKEDATA）
 *   · 远程系统调用：跳到 libc 里的 svc 指令 + PTRACE_SINGLESTEP 跨过它，
 *     立刻读 x0 —— 得到内核原样返回值（绕开 syscall() 包装的错误处理）
 *     实测 getpid(172) → x0 = 目标 pid ✓；mmap(222) → 页对齐地址 ✓
 *   · 远程 mprotect：能把目标页改成只读 ✓
 *   · 用户态 SIGSEGV handler 可用 ✓
 *     （关键：**访问有效但只读的页**会正常触发 handler；
 *       访问完全无效的地址则由内核直接处理，用户态拿不到——这曾经让我误判）
 *   · ucontext 偏移实测：fault_address@0x0b0, regs[0]@0x0b8,
 *     regs[1]@0x0c0, regs[30]@0x1a8, sp@0x1b0, pc@0x1b8
 *
 * ============================================================
 * 已知限制（如实标注）
 * ============================================================
 * · 一次监控一个区间（页粒度）
 * · 目标必须允许 ptrace（加固 App 常禁止，此时如实报 PTRACE_DENIED）
 * · 高频写入会明显拖慢目标（每次写都过一遍 handler）
 * · handler 里恢复权限后，本次写入不会被阻止（要阻止需改 pc 重定向）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define REC_SIZE 128
#define REC_CAP 64

/*
 * (24) 第二十四次修改（2026-11-26）
 * bug 原因：① OFF_PAGE/OFF_PAGELEN/OFF_TARGET/OFF_TLEN 原按 4 字节间隔排布，8 字节写入互相覆盖；
 *             SHM_SIZE 原为 0x2000，装不下 OFF_RECS(0x400)+64*128(0x2000)=0x2400，第 57 条起越界；
 *           ② write_mem 对 < 8 字节写入直接清零高位字，PTRACE_POKEDATA 破坏相邻字段；
 *           ③ remote_syscall 把恢复 PC 错设为 svc_addr+4 而非 saved.pc，导致目标执行流跑飞；
 *             且 mmap 失败仅判断 !shm，未检查 Linux 负 errno [-4095, -1]；
 *           ④ install_sigaction_via_syscall L295 误写 saved = regs 覆写掉原现场，
 *             regs.x[2] 传 0 丢弃 oldact_buf，且 [dbg] 用 printf 打到 stdout 污染 JSON；
 *           ⑤ cmd_watch 回填 shared_slot/slot_page 后又二次整段写入 mda_payload_bin 将槽位清零，
 *             且 slot_page 截断为 16 位、oldact_buf 误传 shm+0x400 与 OFF_RECS 冲突；
 *           ⑥ cmd_poll 用 i ? "," : "" 判断逗号（start > 0 时产生非法 JSON 前导逗号）且未按环形取模。
 * 解决方案：统一 8 字节对齐布局并扩 SHM_SIZE 至 0x3000、增 OFF_OLDACT=0x300；
 *           write_mem 对不足一字先 PTRACE_PEEKDATA 再合并低位字节；
 *           remote_syscall 恢复完整 saved（含 saved.pc），增 is_syscall_err 判 [-4095, -1]；
 *           修正 install_sigaction_via_syscall 的 regs = saved / iov 重置 / oldact_buf / stderr 日志；
 *           cmd_watch 仅写一次 payload 后再回填 shared_slot 与 64 位 slot_page；
 *           cmd_poll 改用 64 位字段、环形下标与 (i > start) ? "," : ""。
 */
/* 共享内存布局（与 mda_payload.S 保持严格一致，全部 8 字节对齐） */
#define OFF_MAGIC     0x000
#define OFF_STATE     0x004
#define OFF_COUNT     0x008
#define OFF_HEAD      0x010
#define OFF_CAPACITY  0x018
#define OFF_PAGE      0x020
#define OFF_PAGELEN   0x028
#define OFF_TARGET    0x030
#define OFF_TLEN      0x038
#define OFF_ERRNO     0x040
#define OFF_ARGS      0x100
#define OFF_ACT       0x200
#define OFF_OLDACT    0x300
#define OFF_RECS      0x400
#define SHM_SIZE      0x3000     /* >= OFF_RECS(0x400) + REC_CAP(64)*REC_SIZE(128) = 0x2400 */

/* syscall 号（arm64） */
#define SYS_MMAP      222
#define SYS_MPROTECT  226
#define SYS_GETPID    172

struct arm64_regs {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

/* payload 的机器码（由 mda_payload.S 编译后嵌入） */
extern const unsigned char mda_payload_bin[];
extern const unsigned long mda_payload_len;
extern const unsigned long mda_payload_entry_off;
extern const unsigned long mda_payload_shared_slot_off;
extern const unsigned long mda_payload_handler_off;
extern const unsigned long mda_payload_restorer_off;
extern const unsigned long mda_payload_handler_len;
extern const unsigned long mda_payload_slot_page_off;
extern const unsigned long mda_payload_handler_ran_off;

/* ---------------------------------------------------------------- 工具 */

/* 判断 Linux 系统调用返回值是否落在内核负 errno 区间 [-4095, -1] */
static int is_syscall_err(uint64_t ret) {
    long s = (long)ret;
    return (s < 0 && s >= -4095);
}

static int write_mem(pid_t pid, unsigned long dst, const void *src, size_t n) {
    /* 用 PTRACE_POKEDATA：process_vm_writev 在目标处于 ptrace stop 时
     * 会"返回成功但没写进去"（实测 readback 全 0）。
     * 写入不足 1 个机器字（< sizeof(unsigned long)）时先 PTRACE_PEEKDATA
     * 读出原字再覆盖低位字节，绝不清零邻近字段。 */
    const unsigned char *p = (const unsigned char *)src;
    size_t off = 0;
    while (off < n) {
        unsigned long word = 0;
        size_t take = sizeof(unsigned long);
        if (off + take > n) take = n - off;
        if (take < sizeof(unsigned long)) {
            errno = 0;
            long orig = ptrace(PTRACE_PEEKDATA, pid,
                               (void *)(uintptr_t)(dst + off), NULL);
            if (orig == -1 && errno != 0)
                return -1;
            word = (unsigned long)orig;
        }
        memcpy(&word, p + off, take);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)(dst + off),
                   (void *)(uintptr_t)word) < 0)
            return -1;
        off += take;
    }
    return 0;
}

static int read_mem(pid_t pid, void *dst, unsigned long src, size_t n) {
    struct iovec local = {dst, n};
    struct iovec remote = {(void *)(uintptr_t)src, n};
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)n)
        return 0;
    /* 退化 */
    unsigned char *p = (unsigned char *)dst;
    size_t off = 0;
    while (off < n) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)(src + off),
                           NULL);
        if (errno) return -1;
        size_t take = sizeof(long);
        if (off + take > n) take = n - off;
        memcpy(p + off, &word, take);
        off += take;
    }
    return 0;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ---------------------------------------------------------------- 目标信息 */

static unsigned long find_libc_base(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    unsigned long base = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long lo;
        char perms[8], name[256] = "";
        int n = sscanf(line, "%lx-%*lx %7s %*s %*s %*s %255s", &lo, perms, name);
        if (n < 3) continue;
        if (!strstr(name, "libc.so")) continue;
        if (!base || lo < base) base = lo;
    }
    fclose(f);
    return base;
}

/*
 * 找 libc 里 syscall() 包装中的 svc 指令地址。
 *
 * 为什么要 svc 而不是函数入口：包装在 svc 之后会改写 x0 做错误处理，
 * 读到的是中间值而不是内核返回值。
 */
static unsigned long find_syscall_svc(pid_t pid, unsigned long entry_off) {
    unsigned long base = find_libc_base(pid);
    if (!base) return 0;
    unsigned long entry = base + entry_off;
    uint32_t w = 0;
    for (unsigned long a = entry; a < entry + 0x80; a += 4) {
        if (read_mem(pid, &w, a, sizeof(w)) != 0) break;
        if (w == 0xd4000001u) return a;
    }
    return 0;
}

/* ---------------------------------------------------------------- 远程调用 */

static const char *g_stage = "";

static int remote_syscall(pid_t pid, int nr, uint64_t a0, uint64_t a1,
                          uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                          uint64_t *ret, unsigned long svc_addr) {
    struct arm64_regs saved, regs;
    struct iovec iov = {&saved, sizeof(saved)};

    g_stage = "getregs1";
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) return -1;

    /*
     * (16) 每次都重新取现场，不复用上一次的 saved。
     *      上一次调用结束时 pc 停在 svc+4、x0 是返回值、
     *      lr 指向 svc 之后的指令——直接拿来当"原始现场"会让
     *      下一次调用的执行流跑飞（实测第二次 mmap 返回 0）。
     *      这里取到的就是当前真实状态，我们只改需要的寄存器。
     */
    regs = saved;
    regs.x[8] = (uint64_t)nr;
    regs.x[0] = a0; regs.x[1] = a1; regs.x[2] = a2;
    regs.x[3] = a3; regs.x[4] = a4; regs.x[5] = a5;
    regs.pc = svc_addr;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    g_stage = "setregs";
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) return -1;

    /*
     * 单步跨过 svc：内核执行完整个 syscall 后，单步停在 svc 之后。
     * 此刻 x0 就是内核原样写入的返回值（还没被任何用户态代码碰过）。
     */
    g_stage = "singlestep";
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) return -1;
    int st = 0;
    g_stage = "waitpid";
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFSTOPPED(st)) { g_stage = "target_exited"; return -2; }

    struct arm64_regs cur;
    iov.iov_base = &cur;
    iov.iov_len = sizeof(cur);
    g_stage = "getregs2";
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) return -1;
    if (ret) *ret = cur.x[0];
    /*
     * (24) 恢复调用前的完整现场（包含原始 saved.pc），
     *      不再改写为 svc_addr + 4，避免目标线程脱离原执行流崩溃。
     */
    {
        iov.iov_base = &saved;
        iov.iov_len = sizeof(saved);
        g_stage = "restore";
        if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) return -1;
    }
    return 0;
}

/*
 * 用 PTRACE_SYSCALL 搭便车执行 rt_sigaction。
 *
 * 原理：目标正常运行时，内核在它每次 syscall 的入口/出口各停一次。
 * 我们在入口把参数换成 rt_sigaction(11, act, oldact_buf, 8)，
 * 在出口读 x0（内核给的返回值），然后把参数恢复原值。
 *
 * 返回 0 表示 rt_sigaction 成功。
 */
static int install_sigaction_via_syscall(pid_t pid, unsigned long shm,
                                         unsigned long code,
                                         unsigned long oldact_buf,
                                         unsigned long our_handler) {
    (void)code;
    unsigned long sc_off = 0x88190;
    const char *env = getenv("MDA_SYSCALL_OFF");
    if (env && *env) sc_off = strtoul(env, NULL, 0);
    unsigned long svc = find_syscall_svc(pid, sc_off);
    if (!svc) return -1;

    /* act 已由调用方写好在 shm+OFF_ACT */
    struct arm64_regs saved, regs;
    struct iovec iov;
    uint64_t deadline = now_ms() + 5000;
    int in_call = 0;

    while (now_ms() < deadline) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) return -1;
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) return -1;
        if (!WIFSTOPPED(st)) return -1;

        if (!in_call) {
            /* syscall 入口：先将原现场读入 saved，再复制到 regs 覆写 rt_sigaction 参数 */
            iov.iov_base = &saved;
            iov.iov_len = sizeof(saved);
            if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) return -1;
            regs = saved;
            /* AAPCS64：sig=x0, act=x1, oact=x2, sigsetsize=x3 */
            regs.x[8] = 134;              /* rt_sigaction */
            regs.x[0] = 11;               /* SIGSEGV */
            regs.x[1] = shm + OFF_ACT;    /* act */
            regs.x[2] = oldact_buf;       /* oldact */
            regs.x[3] = 8;                /* sigsetsize */
            iov.iov_base = &regs;
            iov.iov_len = sizeof(regs);
            if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) return -1;
            in_call = 1;
        } else {
            /* syscall 出口：读入 regs 取内核返回值 x0，再还原完整 saved */
            in_call = 0;
            iov.iov_base = &regs;
            iov.iov_len = sizeof(regs);
            if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) return -1;
            uint64_t ret = regs.x[0];
            iov.iov_base = &saved;
            iov.iov_len = sizeof(saved);
            if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) < 0) return -1;
            if (ret == 0) {
                /*
                 * 用 oldact 验证：rt_sigaction 成功时，内核把旧 handler 写进 oldact_buf；
                 * 调试日志走 stderr，绝不污染 stdout 的 JSON 输出。
                 */
                if (oldact_buf) {
                    uint64_t old_h = 0;
                    read_mem(pid, &old_h, oldact_buf, 8);
                    fprintf(stderr,
                            "[dbg] rt_sigaction 成功, old_handler=0x%llx "
                            "(ours=0x%llx)\n",
                            (unsigned long long)old_h,
                            (unsigned long long)our_handler);
                    fflush(stderr);
                }
                return 0;
            }
            /* 失败：继续等下一个可搭便车的 syscall */
        }
    }
    return -1;
}

/* ---------------------------------------------------------------- 主流程 */

static int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    int st = 0;
    waitpid(pid, &st, 0);
    return 0;
}

static void detach(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/*
 * watch <pid> <target_addr> <target_len>
 *
 * 步骤：
 *   1. attach
 *   2. 远程 mmap 一块 MAP_SHARED 匿名内存（当共享内存用）
 *   3. 把 payload 写进另一块远程 mmap 出来的 RWX 页
 *   4. 填 payload 的参数区（含 shared_slot 全局变量）
 *   5. 单步执行 payload（它自己会装 handler、mprotect、置就绪标志）
 *   6. detach，让目标继续跑
 *   7. 轮询共享内存，把记录读回来
 */
static int cmd_watch(pid_t pid, unsigned long target, unsigned long tlen,
                    const char *serial) {
    (void)serial;
    unsigned long page = target & ~(unsigned long)(PAGE - 1);
    unsigned long page_len = PAGE;

    if (attach(pid) < 0) {
        printf("{\"ok\":false,\"code\":\"PTRACE_DENIED\",\"errno\":%d,"
               "\"error\":\"%s\"}\n", errno, strerror(errno));
        return 2;
    }

    /* syscall() 的偏移：不同 ROM 不同，由环境变量传入 */
    unsigned long sc_off = 0x88190;
    const char *env = getenv("MDA_SYSCALL_OFF");
    if (env && *env) sc_off = strtoul(env, NULL, 0);
    unsigned long svc = find_syscall_svc(pid, sc_off);
    if (!svc) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"NO_SYSCALL_SVC\","
               "\"error\":\"找不到 libc 里的 svc 指令\"}\n");
        return 3;
    }

    /* --- 1) 远程 mmap：共享内存（MAP_SHARED|MAP_ANON） --- */
    uint64_t shm = 0;
    if (remote_syscall(pid, SYS_MMAP, 0, SHM_SIZE,
                       3 /* PROT_READ|PROT_WRITE */,
                       0x21 /* MAP_SHARED|MAP_ANONYMOUS */,
                       0xffffffffULL, 0, &shm, svc) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"SHM_MMAP_FAILED\",\"stage\":\"%s\","
               "\"errno\":%d,\"error\":\"%s\"}\n", g_stage, errno, strerror(errno));
        return 4;
    }
    if (!shm || is_syscall_err(shm)) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"SHM_MMAP_FAILED\",\"ret\":%lld,"
               "\"error\":\"远程 mmap 共享内存失败\"}\n", (long long)(int64_t)shm);
        return 4;
    }

    /* --- 2) 远程 mmap：RWX 代码页 --- */
    uint64_t code = 0;
    if (remote_syscall(pid, SYS_MMAP, 0, PAGE,
                       0x17 /* PROT_READ|WRITE|EXEC|PROT_BTI */,
                       0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */,
                       0xffffffffULL, 0, &code, svc) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"CODE_MMAP_FAILED\",\"stage\":\"%s\"}\n", g_stage);
        return 5;
    }
    if (!code || is_syscall_err(code)) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"CODE_MMAP_FAILED\",\"ret\":%lld,"
               "\"error\":\"远程 mmap 代码页失败\"}\n", (long long)(int64_t)code);
        return 5;
    }

    /* --- 3) 先把完整 payload 写进代码页（仅写这一次，后续再回填运行时槽位，绝不二次覆盖） --- */
    if (write_mem(pid, code, mda_payload_bin, mda_payload_len) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"WRITE_PAYLOAD_FAILED\"}\n");
        return 6;
    }

    /* --- 4) 填共享内存控制区 + 回填 payload 的 shared_slot / slot_page 全局槽 --- */
    uint32_t magic = 0x474d444d;   /* "MDMG" */
    uint32_t state = 0;
    uint64_t count = 0, head = 0, capacity = REC_CAP;
    uint64_t a_page = page, a_pagelen = page_len;
    uint64_t a_target = target, a_tlen = tlen;

    if (write_mem(pid, shm + OFF_MAGIC, &magic, 4) != 0 ||
        write_mem(pid, shm + OFF_STATE, &state, 4) != 0 ||
        write_mem(pid, shm + OFF_COUNT, &count, 8) != 0 ||
        write_mem(pid, shm + OFF_HEAD, &head, 8) != 0 ||
        write_mem(pid, shm + OFF_CAPACITY, &capacity, 8) != 0 ||
        write_mem(pid, shm + OFF_PAGE, &a_page, 8) != 0 ||
        write_mem(pid, shm + OFF_PAGELEN, &a_pagelen, 8) != 0 ||
        write_mem(pid, shm + OFF_TARGET, &a_target, 8) != 0 ||
        write_mem(pid, shm + OFF_TLEN, &a_tlen, 8) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"SHM_WRITE_FAILED\"}\n");
        return 6;
    }

    /* 回填 payload 里的 shared_slot（8 字节）与 slot_page（完整 64 位页基址 + 64 位页长度） */
    unsigned long slot_addr = code + mda_payload_shared_slot_off;
    unsigned long sp = code + mda_payload_slot_page_off;
    if (write_mem(pid, slot_addr, &shm, 8) != 0 ||
        write_mem(pid, sp, &a_page, 8) != 0 ||
        write_mem(pid, sp + 8, &a_pagelen, 8) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"SLOT_WRITE_FAILED\"}\n");
        return 7;
    }
    {
        /* 读回验证 shared_slot 与 slot_page 确实写对且未被覆写 */
        uint64_t back_slot = 0, back_page = 0;
        read_mem(pid, &back_slot, slot_addr, 8);
        read_mem(pid, &back_page, sp, 8);
        if (back_slot != (uint64_t)shm || back_page != a_page) {
            detach(pid);
            printf("{\"ok\":false,\"code\":\"SLOT_WRITE_FAILED\","
                   "\"slot_addr\":\"0x%lx\",\"readback\":\"0x%llx\",\"want\":\"0x%llx\","
                   "\"page_readback\":\"0x%llx\",\"page_want\":\"0x%llx\"}\n",
                   slot_addr, (unsigned long long)back_slot,
                   (unsigned long long)shm,
                   (unsigned long long)back_page, (unsigned long long)a_page);
            return 7;
        }
    }

    /* 预先把 sigaction 结构写好（handler/restorer 指向 payload 里的地址） */
    {
        unsigned char act[64];
        memset(act, 0, sizeof(act));
        uint64_t h = code + mda_payload_handler_off;
        uint64_t r = code + mda_payload_restorer_off;
        uint64_t flags = 0x40000004ULL;      /* SA_SIGINFO | SA_NODEFER */
        memcpy(act + 0x00, &h, 8);
        memcpy(act + 0x08, &flags, 8);
        memcpy(act + 0x10, &r, 8);
        if (write_mem(pid, shm + OFF_ACT, act, sizeof(act)) != 0) {
            detach(pid);
            printf("{\"ok\":false,\"code\":\"ACT_WRITE_FAILED\"}\n");
            return 7;
        }
    }

    /* --- 4.5) 用 PTRACE_SYSCALL 搭便车执行 rt_sigaction（oldact 使用独立区 OFF_OLDACT） --- */
    if (install_sigaction_via_syscall(pid, shm, code, shm + OFF_OLDACT,
                                      code + mda_payload_handler_off) != 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"SIGACTION_VIA_SYSCALL_FAILED\","
               "\"error\":\"目标在 5 秒内没发起任何 syscall，无法搭便车\"}\n");
        return 8;
    }

    /* --- 4.6) 远程 mprotect 把目标页改成只读 --- */
    {
        uint64_t mp_ret = 0;
        if (remote_syscall(pid, SYS_MPROTECT, page, page_len, 1 /*PROT_READ*/,
                           0, 0, 0, &mp_ret, svc) != 0) {
            detach(pid);
            printf("{\"ok\":false,\"code\":\"MPROTECT_FAILED\","
                   "\"stage\":\"%s\"}\n", g_stage);
            return 8;
        }
        if (is_syscall_err(mp_ret)) {
            detach(pid);
            printf("{\"ok\":false,\"code\":\"MPROTECT_DENIED\","
                   "\"ret\":%lld}\n", (long long)(int64_t)mp_ret);
            return 8;
        }
        uint32_t st1 = 1;
        write_mem(pid, shm + OFF_STATE, &st1, 4);
    }

    /* --- 5) payload 不再执行（只写不跑）--- */
#if 0
    struct arm64_regs saved, regs;
    struct iovec iov = {&saved, sizeof(saved)};
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) < 0) {
        detach(pid);
        printf("{\"ok\":false,\"code\":\"GETREGS_FAILED\"}\n");
        return 7;
    }
    regs = saved;
    regs.x[0] = shm;        /* 共享内存基址 */
    regs.x[1] = page;       /* 目标页地址 */
    regs.x[2] = page_len;   /* 目标页长度 */
    regs.x[3] = target;     /* 目标地址 */
    regs.x[4] = tlen;       /* 目标长度 */
    regs.pc = code + mda_payload_entry_off;
    struct arm64_regs regs_at_entry = regs;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);

    /* payload 用 svc #0 做步骤停点。单步执行，遇到 svc 时内核会执行它，
     * 然后我们继续单步——但 svc 之后 payload 会继续跑，
     * 所以这里只需要单步到 state 变成 1（就绪）即可。 */
    int ready = 0;
    int step = 0;
    /*
     * (19) 用**单步**执行 payload。
     *      CONT 放行会让 payload 跑出代码范围把目标搞崩（实测 dead），
     *      单步则永远不会跑飞。
     */
    int st0 = 0;
    while (step < 20000) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) break;
        if (waitpid(pid, &st0, 0) < 0) break;
        if (!WIFSTOPPED(st0)) break;
        step++;
        uint32_t s_chk = 0;
        read_mem(pid, &s_chk, shm + OFF_STATE, 4);
        if (s_chk == 1) { ready = 1; break; }
        if (getenv("MDA_DEBUG") && (step % 20) == 0) {
            struct arm64_regs c2;
            iov.iov_base = &c2; iov.iov_len = sizeof(c2);
            ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
            uint32_t e2 = 0;
            read_mem(pid, &e2, shm + OFF_ERRNO, 4);
            printf("[dbg] step=%d pc=0x%llx x0=0x%llx errno_stored=%u\n",
                   step, (unsigned long long)c2.pc,
                   (unsigned long long)c2.x[0], e2);
            fflush(stdout);
        }
        if (getenv("MDA_DEBUG") && step <= 40) {
            struct arm64_regs c1;
            iov.iov_base = &c1; iov.iov_len = sizeof(c1);
            ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
            printf("[dbg] step=%d pc=0x%llx x5=0x%llx x19=0x%llx sig=%d\n",
                   step, (unsigned long long)c1.pc,
                   (unsigned long long)c1.x[5], (unsigned long long)c1.x[19],
                   WIFSTOPPED(st0)?WSTOPSIG(st0):-1);
            fflush(stdout);
        }
        if ((step & 0x3f) == 0) {
            uint32_t s = 0;
            read_mem(pid, &s, shm + OFF_STATE, 4);
            if (s == 1) { ready = 1; break; }
            if (getenv("MDA_DEBUG")) {
                struct arm64_regs cur2;
                iov.iov_base = &cur2; iov.iov_len = sizeof(cur2);
                ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
                uint32_t e = 0;
                read_mem(pid, &e, shm + OFF_ERRNO, 4);
                printf("[dbg] step=%d state=%u ret=%u pc=0x%llx (code=0x%llx)\n",
                       step, s, e, (unsigned long long)cur2.pc,
                       (unsigned long long)code);
                fflush(stdout);
            }
        }
    }
    if (!ready) {
        uint32_t s = 0;
        read_mem(pid, &s, shm + OFF_STATE, 4);
        uint32_t err = 0;
        read_mem(pid, &err, shm + OFF_ERRNO, 4);
        /* dump act 结构 + 入口寄存器 */
        unsigned char act[0x20];
        memset(act, 0, sizeof(act));
        read_mem(pid, act, shm + OFF_ACT, sizeof(act));
        struct arm64_regs cr;
        iov.iov_base = &cr; iov.iov_len = sizeof(cr);
        ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov);
        uint64_t args6[6];
        read_mem(pid, args6, shm + OFF_ARGS, 48);
        printf("[dbg] pc=0x%llx x0=0x%llx x19=0x%llx x5=0x%llx shm=0x%llx code=0x%llx\n",
               (unsigned long long)cr.pc, (unsigned long long)cr.x[0],
               (unsigned long long)cr.x[19], (unsigned long long)cr.x[5],
               (unsigned long long)shm, (unsigned long long)code);
        printf("[dbg] args: x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx\n",
               (unsigned long long)args6[1], (unsigned long long)args6[2],
               (unsigned long long)args6[3], (unsigned long long)args6[4]);
        fflush(stdout);
        detach(pid);
        printf("{\"ok\":false,\"code\":\"PAYLOAD_NOT_READY\",\"steps\":%d,"
               "\"state\":%u,\"last_ret\":%u,\"act\":\"%s\"}\n", step, s, err,
               ({ char b[65]; int i; for(i=0;i<0x20;i++) sprintf(b+i*2,"%02x",act[i]); b[64]=0; b; }));
        return 8;
    }

    /* --- 6) 把 pc 改回原始位置并恢复寄存器 ---
     * (15) payload 没有合法的返回地址（ret 回去会跳飞，目标会死）。
     *      payload 末尾用 brk 停住，由这里把 pc 改回进入 payload 前的
     *      原始 pc 并恢复寄存器——目标像什么都没发生过。
     */
    {
        struct arm64_regs restore = regs_at_entry;
        iov.iov_base = &restore;
        iov.iov_len = sizeof(restore);
        ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov);
        /*
         * (16) 恢复 pc 后**先 CONT 放行一次**，再 detach。
         *      否则 payload 末尾的 brk 触发的 SIGTRAP 会被内核当成
         *      终止信号（tombstone: SIGTRAP / TRAP_BRKPT），目标直接死。
         */
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == 0) {
            int st2 = 0;
            waitpid(pid, &st2, 0);
        }
    }

#endif

    /* --- 7) detach，让目标继续跑 --- */
    detach(pid);

    printf("{\"ok\":true,\"shm\":\"0x%llx\",\"code\":\"0x%llx\","
           "\"page\":\"0x%lx\",\"target\":\"0x%lx\",\"len\":%lu,"
           "\"state\":1,\"verdict\":\"注入成功：目标已装好 SIGSEGV handler，"
           "监控区间已设为只读\"}\n",
           (unsigned long long)shm, (unsigned long long)code,
           page, target, tlen);
    return 0;
}

/*
 * poll <pid> <shm> [max]
 * 从共享内存读回命中记录。
 */
static int cmd_poll(pid_t pid, unsigned long shm, unsigned long code, int max) {
    uint64_t count = 0, capacity = 0;
    read_mem(pid, &count, shm + OFF_COUNT, 8);
    read_mem(pid, &capacity, shm + OFF_CAPACITY, 8);
    if (!capacity || capacity > REC_CAP) capacity = REC_CAP;
    if (max <= 0 || (uint64_t)max > capacity) max = (int)capacity;

    /* (24) 8 字节读取 handler_ran，且环形取模 + (i > start) 判断 JSON 逗号 */
    uint64_t ran = 0;
    if (code) read_mem(pid, &ran, code + mda_payload_handler_ran_off, 8);
    printf("{\"ok\":true,\"count\":%llu,\"capacity\":%llu,\"handler_ran\":%llu,\"records\":[",
           (unsigned long long)count, (unsigned long long)capacity,
           (unsigned long long)ran);
    uint64_t start = (count > (uint64_t)max) ? (count - (uint64_t)max) : 0;
    for (uint64_t i = start; i < count; i++) {
        uint64_t slot_idx = i % capacity;
        unsigned long rec = shm + OFF_RECS + (unsigned long)slot_idx * REC_SIZE;
        uint64_t fault = 0, pc = 0, lr = 0, sp = 0, x0 = 0, x1 = 0;
        uint32_t blen = 0;
        unsigned char before[48];
        memset(before, 0, sizeof(before));
        read_mem(pid, &fault, rec + 0x00, 8);
        read_mem(pid, &pc, rec + 0x08, 8);
        read_mem(pid, &lr, rec + 0x10, 8);
        read_mem(pid, &sp, rec + 0x18, 8);
        read_mem(pid, &x0, rec + 0x20, 8);
        read_mem(pid, &x1, rec + 0x28, 8);
        read_mem(pid, &blen, rec + 0x30, 4);
        if (blen > 48) blen = 48;
        if (blen > 0) read_mem(pid, before, rec + 0x40, blen);

        char hex[97];
        int n = (int)blen;
        for (int k = 0; k < n; k++)
            snprintf(hex + k * 2, 3, "%02x", before[k]);
        hex[n * 2] = 0;

        printf("%s{\"idx\":%llu,\"fault_addr\":\"0x%llx\",\"pc\":\"0x%llx\","
               "\"lr\":\"0x%llx\",\"sp\":\"0x%llx\",\"x0\":\"0x%llx\",\"x1\":\"0x%llx\","
               "\"before_hex\":\"%s\",\"before_len\":%u}",
               (i > start) ? "," : "", (unsigned long long)i,
               (unsigned long long)fault, (unsigned long long)pc,
               (unsigned long long)lr, (unsigned long long)sp,
               (unsigned long long)x0, (unsigned long long)x1,
               hex, blen);
    }
    printf("]}\n");
    return 0;
}

/* stop：把页恢复可写并摘掉 handler */
static int cmd_stop(pid_t pid, unsigned long shm) {
    unsigned long page = 0, page_len = 0;
    read_mem(pid, &page, shm + OFF_PAGE, 8);
    read_mem(pid, &page_len, shm + OFF_PAGELEN, 8);
    if (attach(pid) < 0) {
        printf("{\"ok\":false,\"code\":\"PTRACE_DENIED\"}\n");
        return 2;
    }
    unsigned long sc_off = 0x88190;
    const char *env = getenv("MDA_SYSCALL_OFF");
    if (env && *env) sc_off = strtoul(env, NULL, 0);
    unsigned long svc = find_syscall_svc(pid, sc_off);
    uint64_t ret = 0;
    if (svc && page) {
        remote_syscall(pid, SYS_MPROTECT, page, page_len, 3, 0, 0, 0, &ret, svc);
    }
    detach(pid);
    printf("{\"ok\":true,\"page\":\"0x%lx\",\"mprotect_ret\":%lld}\n", page,
           (long long)ret);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("{\"ok\":false,\"error\":\"usage: mda_memguard_inject "
               "<selftest|watch|poll|stop> ...\"}\n");
        return 1;
    }

    if (!strcmp(argv[1], "selftest")) {
        if (argc < 3) {
            printf("{\"ok\":false,\"error\":\"need pid\"}\n");
            return 1;
        }
        pid_t pid = (pid_t)atoi(argv[2]);
        if (attach(pid) < 0) {
            printf("{\"ok\":false,\"code\":\"PTRACE_DENIED\",\"errno\":%d,"
                   "\"error\":\"%s\"}\n", errno, strerror(errno));
            return 2;
        }
        unsigned long svc = find_syscall_svc(pid, 0x88190);
        uint64_t got = 0;
        int r = svc ? remote_syscall(pid, SYS_GETPID, 0, 0, 0, 0, 0, 0, &got, svc) : -1;
        detach(pid);
        /* (22) ok 反映真实结果，不再恒 true */
        int works = (r == 0 && got == (uint64_t)pid);
        printf("{\"ok\":%s,\"svc\":\"0x%lx\",\"getpid_ret\":%llu,"
               "\"expect_pid\":%d,\"remote_syscall\":\"%s\"%s}\n",
               works ? "true" : "false",
               svc, (unsigned long long)got, (int)pid,
               works ? "works" : "failed",
               works ? "" : ",\"code\":\"REMOTE_SYSCALL_FAILED\"");
        return (r == 0 && got == (uint64_t)pid) ? 0 : 3;
    }

    if (!strcmp(argv[1], "watch")) {
        if (argc < 4) {
            printf("{\"ok\":false,\"error\":\"need: watch <pid> <addr> [len]\"}\n");
            return 1;
        }
        /* (21) serial 从命令行取（可选），不硬编码设备号 */
        return cmd_watch((pid_t)atoi(argv[2]),
                         strtoul(argv[3], NULL, 16),
                         argc > 4 ? strtoul(argv[4], NULL, 0) : 8,
                         argc > 5 ? argv[5] : "");
    }

    if (!strcmp(argv[1], "poll")) {
        if (argc < 4) {
            printf("{\"ok\":false,\"error\":\"need: poll <pid> <shm> [max]\"}\n");
            return 1;
        }
        return cmd_poll((pid_t)atoi(argv[2]),
                        strtoul(argv[3], NULL, 16),
                        argc > 5 ? strtoul(argv[4], NULL, 16) : 0,
                        argc > 4 ? atoi(argv[argc > 5 ? 5 : 4]) : 10);
    }

    if (!strcmp(argv[1], "stop")) {
        if (argc < 4) {
            printf("{\"ok\":false,\"error\":\"need: stop <pid> <shm>\"}\n");
            return 1;
        }
        return cmd_stop((pid_t)atoi(argv[2]), strtoul(argv[3], NULL, 16));
    }

    printf("{\"ok\":false,\"error\":\"unknown command\"}\n");
    return 1;
}
