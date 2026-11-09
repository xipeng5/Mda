// 探针 v2：逐个排查 EINVAL 的原因
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

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int g, unsigned long f) {
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, g, f);
}

static int try_one(const char *label, int len, int sample_regs) {
    volatile char *buf = (volatile char *)malloc(4096);
    memset((void*)buf, 0, 4096);
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    a.bp_addr = (unsigned long)buf;
    a.bp_len  = len;
    a.sample_period = 1;
    if (sample_regs) {
        a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
    } else {
        a.sample_type = PERF_SAMPLE_IP;
    }
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;
    int fd = perf_open(&a, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    printf("  %-28s len=%d regs=%d -> %s (%d)\n", label, len, sample_regs,
           fd >= 0 ? "OK" : "FAIL", fd >= 0 ? fd : errno);
    if (fd >= 0) close(fd);
    free((void*)buf);
    return fd;
}

int main(void) {
    printf("== 排查 EINVAL ==\n");
    printf("sizeof(perf_event_attr)=%zu\n", sizeof(struct perf_event_attr));
    printf("HW_BREAKPOINT_LEN_1/2/4/8 = %d/%d/%d/%d\n",
           HW_BREAKPOINT_LEN_1, HW_BREAKPOINT_LEN_2,
           HW_BREAKPOINT_LEN_4, HW_BREAKPOINT_LEN_8);

    try_one("基础(IP only)", HW_BREAKPOINT_LEN_1, 0);
    try_one("len1", HW_BREAKPOINT_LEN_1, 0);
    try_one("len4", HW_BREAKPOINT_LEN_4, 0);
    try_one("len8", HW_BREAKPOINT_LEN_8, 0);
    try_one("len8+regs", HW_BREAKPOINT_LEN_8, 1);

    // 看看是不是 cpu=-1 + pid=0 的组合问题
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT; a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    volatile char *b = (volatile char*)malloc(256); memset((void*)b,0,256);
    a.bp_addr = (unsigned long)b; a.bp_len = HW_BREAKPOINT_LEN_4;
    a.sample_period = 1; a.disabled = 1; a.exclude_kernel = 1;
    int fd = perf_open(&a, 0, -1, -1, 0);
    printf("  不带 CLOEXEC 标志        -> %s (%d)\n", fd>=0?"OK":"FAIL", fd>=0?fd:errno);
    if (fd>=0) close(fd);
    return 0;
}
