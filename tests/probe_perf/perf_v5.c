// 探针 v5：完整验证 —— 设观察点 → 触发写 → 读 ring buffer → 拿 pc
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

int main(void) {
    // 用 mmap 拿无 tag 地址
    volatile unsigned long *target = (volatile unsigned long *)
        mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    *target = 0;
    printf("target=0x%016lx\n", (unsigned long)target);

    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    a.bp_addr = (unsigned long)target;
    a.bp_len = HW_BREAKPOINT_LEN_8;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL<<0)|(1ULL<<1)|(1ULL<<2)|(1ULL<<30);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;

    int fd = po(&a, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) { printf("PERF_OPEN_FAIL errno=%d\n", errno); return 2; }
    printf("PERF_OPEN_OK fd=%d\n", fd);

    size_t pg = sysconf(_SC_PAGESIZE);
    size_t msz = pg * 9;
    char *base = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { printf("MMAP_FAIL errno=%d\n", errno); return 3; }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    printf("ENABLED\n"); fflush(stdout);

    // 触发：写这块内存
    *target = 0x1122334455667788UL;
    __sync_synchronize();
    usleep(150000);

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    unsigned long head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    unsigned long tail = meta->data_tail;
    printf("HEAD=%lu TAIL=%lu\n", head, tail);

    if (head > tail) {
        size_t data_sz = msz - pg;
        unsigned long off = tail % data_sz;
        struct perf_event_header *h = (struct perf_event_header *)(base + pg + off);
        printf("HIT type=%u size=%u\n", h->type, h->size);
        if (h->type == PERF_RECORD_SAMPLE) {
            unsigned char *p = (unsigned char *)h + sizeof(*h);
            unsigned long ip = *(unsigned long*)p; p += 8;
            unsigned int pid = *(unsigned int*)p; p += 4;
            unsigned int tid = *(unsigned int*)p; p += 4;
            printf("  IP=0x%016lx pid=%u tid=%u\n", ip, pid, tid);
            // ABI
            unsigned long abi = *(unsigned long*)p; p += 8;
            printf("  regs_abi=%lu\n", abi);
            if (abi == PERF_SAMPLE_REGS_ABI_64) {
                unsigned long x0 = *(unsigned long*)p; p += 8;
                unsigned long x1 = *(unsigned long*)p; p += 8;
                unsigned long x2 = *(unsigned long*)p; p += 8;
                unsigned long lr = *(unsigned long*)p; p += 8;
                printf("  x0=0x%lx x1=0x%lx x2=0x%lx lr=0x%lx\n", x0, x1, x2, lr);
            }
        }
    } else {
        printf("HIT=0 （观察点没触发）\n");
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    return 0;
}
