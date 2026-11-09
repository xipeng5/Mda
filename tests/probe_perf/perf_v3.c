// 探针 v3：修正 perf_event_open 用法
// 关键修正：breakpoint 类型必须给 precise_ip=0，且不能设 exclude_kernel 之外的限制；
// 另外 sample_period 与 wakeup_events 的组合在某些内核要谨慎
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

static int po(struct perf_event_attr *a, pid_t p, int c, int g, unsigned long f) {
    return (int)syscall(__NR_perf_event_open, a, p, c, g, f);
}

static void attrs_init(struct perf_event_attr *a, void *addr, int len) {
    memset(a, 0, sizeof(*a));
    a->type = PERF_TYPE_BREAKPOINT;
    a->size = sizeof(*a);
    a->bp_type = HW_BREAKPOINT_W;
    a->bp_addr = (unsigned long)addr;
    a->bp_len = len;
    a->sample_period = 1;
    a->sample_type = PERF_SAMPLE_IP;
    a->disabled = 1;
    a->exclude_kernel = 1;
    a->exclude_hv = 1;
    a->wakeup_events = 1;
}

int main(void) {
    volatile char *buf = (volatile char *)malloc(4096);
    memset((void*)buf, 0, 4096);
    printf("buf=%p (16字节对齐=%d)\n", (void*)buf, ((unsigned long)buf % 16 == 0));

    struct perf_event_attr a;
    int fd;
    // 变体1：标准写法
    attrs_init(&a, (void*)buf, HW_BREAKPOINT_LEN_8);
    fd = po(&a, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    printf("  变体1 标准           -> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);

    // 变体2：去掉 exclude_hv
    attrs_init(&a, (void*)buf, HW_BREAKPOINT_LEN_8);
    a.exclude_hv = 0;
    fd = po(&a, 0, -1, -1, 0);
    printf("  变体2 无exclude_hv   -> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);

    // 变体3：不设 sample_period（只计数不用采样）
    attrs_init(&a, (void*)buf, HW_BREAKPOINT_LEN_8);
    a.sample_period = 0;
    fd = po(&a, 0, -1, -1, 0);
    printf("  变体3 无sample_period-> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);

    // 变体4：目标用 pid 而不是 0
    attrs_init(&a, (void*)buf, HW_BREAKPOINT_LEN_8);
    fd = po(&a, getpid(), -1, -1, 0);
    printf("  变体4 pid=self       -> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);

    // 变体5：cpu=0 显式
    attrs_init(&a, (void*)buf, HW_BREAKPOINT_LEN_8);
    fd = po(&a, getpid(), 0, -1, 0);
    printf("  变体5 pid+cpu0       -> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);

    // 变体6：去对齐问题 —— 用 8 字节对齐地址
    void *aligned = (void*)(((unsigned long)buf + 0x3f) & ~0x3fUL);
    attrs_init(&a, aligned, HW_BREAKPOINT_LEN_8);
    fd = po(&a, getpid(), -1, -1, 0);
    printf("  变体6 64对齐地址      -> %s errno=%d\n", fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);
    return 0;
}
