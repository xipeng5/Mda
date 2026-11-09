// 探针 v7：区分「按线程」还是「按进程」分配槽位
// 用法: perf_thread <pid> <addr> <tid|0>
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

int main(int argc, char **argv) {
    if (argc < 3) { printf("用法: %s <pid> <addr> [tid]\n", argv[0]); return 1; }
    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);
    pid_t tid = (argc > 3) ? atoi(argv[3]) : -1;

    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    a.bp_addr = addr;
    a.bp_len = HW_BREAKPOINT_LEN_8;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;

    // pid>0 且 cpu=-1 → 观察该线程；pid>0 且 tid 给 0 → 进程级
    int fd = po(&a, tid > 0 ? tid : pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    printf("pid=%d tid=%d addr=0x%lx -> %s errno=%d (%s)\n",
           pid, tid, addr, fd>=0?"OK":"FAIL", fd>=0?0:errno,
           fd>=0?"":strerror(errno));
    if (fd >= 0) close(fd);
    return 0;
}
