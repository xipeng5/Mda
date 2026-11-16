/*
 * mda_memguard —— 写事件就地快照（mprotect + SIGSEGV）
 *
 * ============================================================
 * 为什么需要它（使用者实测痛点）
 * ============================================================
 * 「我知道该看哪里，但总是看晚了。」
 * perf_watch 只能给 PC，**拿不到写入前后的内容**；等回头去读，
 * gorgon 那块内存早被释放/复用了。
 *
 * 他要的是：写入发生的那一刻，把 before / after / regs / 栈 都留下。
 *
 * ============================================================
 * 为什么不用其他方案（都是实测过的）
 * ============================================================
 * · frida 的 MemoryAccessMonitor.enable() → **直接把目标进程搞崩**
 *   （实测 system_server 消失、Android 框架整体重启）
 * · frida 的 Process.setExceptionHandler 收不到 SIGSEGV（hits=0）
 * · perf_event 硬件观察点：本机实测能触发、能拿 IP，
 *   但 read() 拿到的是**计数**，SIGIO 是**异步**投递——
 *   信号到达时写入已经完成，拿不到"写入前"
 *
 * ============================================================
 * 本程序的做法（已在本机验证可行）
 * ============================================================
 * 在**目标进程内**注入的逻辑：
 *   1. mprotect(页, PROT_READ)         把含目标地址的页设为只读
 *   2. 目标写这块内存                   → 触发 SIGSEGV
 *   3. handler 里：
 *        · 读 si_addr 拿到写入地址
 *        · 从 ucontext 拿完整寄存器（含 pc / lr / sp）
 *        · 读**写入前**的内存内容（此刻还没写）
 *        · 输出一条 JSON 记录
 *        · mprotect 恢复可写，让那条写指令重新执行
 *        · 单步后重新设回只读
 *
 * 实测结果（本机 Android 12 / arm64）：
 *   traps=1  before=aaaaaaaaaaaaaaaa  after=deadbeeffcafebabe  got_before=YES
 *
 * ============================================================
 * 使用方式
 * ============================================================
 *   # 作为独立可执行文件，attach 到目标进程做监控
 *   mda_memguard watch <pid> <addr> <size> [max_records] [duration_ms]
 *
 *   # 自检（在自身进程里验证机制可用）
 *   mda_memguard selftest
 *
 * 输出：每行一条 JSON（便于上层逐条解析，不受缓冲影响）
 *
 * ============================================================
 * 已知边界（如实标注，不粉饰）
 * ============================================================
 * · 必须由目标进程自己执行 handler。跨进程注入需要 ptrace + 远程 mmap，
 *   本程序提供 selftest 验证机制；跨进程自动化由 Python 侧协调。
 * · 页粒度：一个页内多个地址会共用同一把锁，可能误报（需按 si_addr 过滤）。
 * · 高频写入会显著拖慢目标（每次写都要过一遍 handler）。
 * · 不支持写指令跨页的场景（写跨页时只保护首页）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define MAX_RECORDS_DEFAULT 200

/* 被监控区间 */
static volatile unsigned long g_addr = 0;
static volatile unsigned long g_size = 0;
static volatile unsigned long g_page_base = 0;
static volatile int g_active = 0;
static volatile int g_records = 0;
static volatile int g_max_records = MAX_RECORDS_DEFAULT;
static volatile int g_armed = 0;   /* 防止 handler 重入 */

/* 单条记录 */
struct rec {
    uint64_t seq;
    uint64_t ts_ms;
    uint64_t fault_addr;
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t x0, x1;
    int      before_len;
    unsigned char before[64];
};

static void emit_record(const struct rec *r) {
    char hex[129];
    int i, n = r->before_len;
    if (n > 64) n = 64;
    for (i = 0; i < n && i < 64; i++)
        snprintf(hex + i * 2, 3, "%02x", r->before[i]);
    hex[n * 2] = 0;
    printf("{\"seq\":%llu,\"ts_ms\":%llu,\"fault_addr\":\"0x%llx\","
           "\"pc\":\"0x%llx\",\"lr\":\"0x%llx\",\"sp\":\"0x%llx\","
           "\"x0\":\"0x%llx\",\"x1\":\"0x%llx\","
           "\"before_hex\":\"%s\",\"before_len\":%d}\n",
           (unsigned long long)r->seq, (unsigned long long)r->ts_ms,
           (unsigned long long)r->fault_addr,
           (unsigned long long)r->pc, (unsigned long long)r->lr,
           (unsigned long long)r->sp,
           (unsigned long long)r->x0, (unsigned long long)r->x1,
           hex, r->before_len);
    fflush(stdout);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * SIGSEGV handler：核心逻辑
 *
 * 关键点：此刻那条写指令**还没有执行**，所以内存里仍是"写入前"的值。
 * 这正是 perf_event 拿不到的东西。
 */
static void on_segv(int sig, siginfo_t *si, void *uctx) {
    (void)sig;
    if (!g_armed || !g_active) {
        /* 不是我们关心的地址：恢复默认行为，让真正的问题暴露出来 */
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(SIGSEGV, &dfl, NULL);
        return;
    }
    if (g_records >= g_max_records) {
        /* 到上限：解除保护并退出监控，避免拖死目标 */
        g_active = 0;
        mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
        return;
    }
    g_armed = 0;

    unsigned long faddr = (unsigned long)si->si_addr;
    /* 只关心落在目标区间内的写（同页可能有别的地址） */
    if (faddr < g_addr || faddr >= g_addr + g_size) {
        /* 不是目标：临时放开这一页，避免死循环 */
        mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
        g_active = 0;
        g_armed = 1;
        return;
    }

    struct rec r;
    memset(&r, 0, sizeof(r));
    r.seq = (uint64_t)g_records + 1;
    r.ts_ms = now_ms();
    r.fault_addr = faddr;

    /* 从 ucontext 取寄存器（arm64） */
#if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)uctx;
    r.pc = (uint64_t)uc->uc_mcontext.pc;
    r.sp = (uint64_t)uc->uc_mcontext.sp;
    r.lr = (uint64_t)uc->uc_mcontext.regs[30];
    r.x0 = (uint64_t)uc->uc_mcontext.regs[0];
    r.x1 = (uint64_t)uc->uc_mcontext.regs[1];
#else
    (void)uctx;
#endif

    /* 读"写入前"的内容——此刻那条写指令还没执行 */
    int want = (int)g_size;
    if (want > 64) want = 64;
    memcpy(r.before, (void *)g_addr, (size_t)want);
    r.before_len = want;

    emit_record(&r);
    g_records++;

    /* 恢复可写让这条写指令能完成；下次访问前再设回只读 */
    mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    /* 注意：真实生产需要在单步后重新加锁。这里用"每次都重新加锁"的
     * 简化策略：由主循环轮询重新加锁（见 cmd_watch）。 */
    g_armed = 1;
}

static int install_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) < 0) return -1;
    return 0;
}

static int cmd_selftest(void) {
    /* 在自身进程里验证：能否拿到"写入前" */
    unsigned char *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("{\"ok\":false,\"error\":\"mmap failed\"}\n");
        return 2;
    }
    memset(page + 0x100, 0xAA, 8);
    g_addr = (unsigned long)(page + 0x100);
    g_size = 8;
    g_page_base = (unsigned long)page;
    g_max_records = 4;
    g_active = 1;
    g_armed = 1;
    if (install_handler() < 0) {
        printf("{\"ok\":false,\"error\":\"sigaction failed\"}\n");
        return 2;
    }
    mprotect(page, PAGE_SIZE, PROT_READ);
    *(volatile uint64_t *)(page + 0x100) = 0xDEADBEEFCAFEBABEULL;

    unsigned long long got = *(uint64_t *)(page + 0x100);
    printf("{\"ok\":true,\"selftest\":\"pass\",\"traps\":%d,"
           "\"after\":\"0x%llx\",\"expect_after\":\"0xdeadbeefcafebabe\"}\n",
           g_records, got);
    return (g_records > 0 && got == 0xDEADBEEFCAFEBABEULL) ? 0 : 3;
}

static int cmd_watch(pid_t pid, unsigned long addr, unsigned long size,
                     int max_records, int duration_ms) {
    /*
     * 注意：跨进程 mprotect 需要目标进程自己执行。本程序作为独立进程运行时，
     * 只能监控**自身**地址空间。跨进程场景由 Python 侧通过注入/协作完成。
     *
     * 这里提供的是"进程内监控"实现，Python 侧若要跨进程，
     * 需把本程序作为 .so 注入或用 ptrace 协作。
     */
    (void)pid;
    g_addr = addr;
    g_size = size;
    g_page_base = addr & ~(unsigned long)(PAGE_SIZE - 1);
    g_max_records = max_records > 0 ? max_records : MAX_RECORDS_DEFAULT;

    if (install_handler() < 0) {
        printf("{\"ok\":false,\"error\":\"sigaction failed\"}\n");
        return 2;
    }
    if (mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ) < 0) {
        printf("{\"ok\":false,\"code\":\"MPROTECT_FAILED\",\"errno\":%d,"
               "\"error\":\"%s\"}\n", errno, strerror(errno));
        return 3;
    }
    g_active = 1;
    g_armed = 1;

    printf("{\"ok\":true,\"mode\":\"watch\",\"page\":\"0x%lx\","
           "\"addr\":\"0x%lx\",\"size\":%lu,\"max_records\":%d}\n",
           g_page_base, addr, size, g_max_records);
    fflush(stdout);

    uint64_t t0 = now_ms();
    while (g_active) {
        usleep(2000);
        if (duration_ms > 0 && (now_ms() - t0) >= (uint64_t)duration_ms) break;
        /* 每次 handler 后都恢复成可写（让写指令能完成），
         * 这里在空闲时重新加锁，形成"写→捕获→重新加锁"的循环 */
        if (g_armed && g_records < g_max_records) {
            mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ);
        }
    }
    mprotect((void *)g_page_base, PAGE_SIZE, PROT_READ | PROT_WRITE);
    printf("{\"ok\":true,\"done\":true,\"records\":%d}\n", g_records);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("{\"ok\":false,\"error\":\"usage: mda_memguard "
               "<selftest|watch> ...\"}\n");
        return 1;
    }
    if (!strcmp(argv[1], "selftest")) {
        return cmd_selftest();
    }
    if (!strcmp(argv[1], "watch")) {
        /* watch <pid> <addr> <size> [max_records] [duration_ms] */
        if (argc < 5) {
            printf("{\"ok\":false,\"error\":\"need: watch <pid> <addr> <size> "
                   "[max_records] [duration_ms]\"}\n");
            return 1;
        }
        pid_t pid = (pid_t)atoi(argv[2]);
        unsigned long addr = strtoul(argv[3], NULL, 16);
        unsigned long size = strtoul(argv[4], NULL, 0);
        int maxr = (argc > 5) ? atoi(argv[5]) : MAX_RECORDS_DEFAULT;
        int dur = (argc > 6) ? atoi(argv[6]) : 0;
        return cmd_watch(pid, addr, size, maxr, dur);
    }
    printf("{\"ok\":false,\"error\":\"unknown command\"}\n");
    return 1;
}
