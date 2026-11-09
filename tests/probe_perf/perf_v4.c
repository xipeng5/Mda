// 探针 v4：怀疑点在 bp_addr 的 ARM64 内存标记（TBI）
// Android 堆指针 0xb400... 高 8 位是 tag，硬件断点比对的是真实地址
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

static int try_addr(const char *label, unsigned long addr, int len) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    a.bp_addr = addr;
    a.bp_len = len;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP;
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;
    int fd = po(&a, 0, -1, -1, 0);
    printf("  %-30s addr=0x%016lx len=%d -> %s errno=%d\n",
           label, addr, len, fd>=0?"OK":"FAIL", fd>=0?0:errno);
    if (fd>=0) close(fd);
    return fd;
}

int main(void) {
    // 用 mmap 拿一个干净地址，避开 malloc + TBI
    void *m = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("mmap=%p\n", m);
    unsigned long raw = (unsigned long)m;
    printf("raw   =0x%016lx\n", raw);
    printf("untag =0x%016lx  (高8位清零)\n", raw & 0x00FFFFFFFFFFFFFFUL);

    try_addr("mmap 原址 len8", raw, HW_BREAKPOINT_LEN_8);
    try_addr("mmap 脱tag len8", raw & 0x00FFFFFFFFFFFFFFUL, HW_BREAKPOINT_LEN_8);
    try_addr("mmap 原址 len4", raw, HW_BREAKPOINT_LEN_4);
    try_addr("mmap 脱tag len4", raw & 0x00FFFFFFFFFFFFFFUL, HW_BREAKPOINT_LEN_4);
    try_addr("mmap 原址 len1", raw, HW_BREAKPOINT_LEN_1);
    try_addr("mmap 脱tag len1", raw & 0x00FFFFFFFFFFFFFFUL, HW_BREAKPOINT_LEN_1);

    // 用栈地址（无 tag，肯定对齐）
    int x = 0;
    try_addr("栈地址 len8", (unsigned long)&x, HW_BREAKPOINT_LEN_8);
    try_addr("栈地址 len4", (unsigned long)&x, HW_BREAKPOINT_LEN_4);

    // 用全局变量
    static int g;
    try_addr("全局变量 len4", (unsigned long)&g, HW_BREAKPOINT_LEN_4);
    return 0;
}
