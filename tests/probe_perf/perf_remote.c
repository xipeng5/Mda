// 探针 v6：跨进程 —— 观察另一个进程的地址
// 用法: perf_remote <pid> <addr_hex>
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
    if (argc < 3) { printf("用法: %s <pid> <addr>\n", argv[0]); return 1; }
    pid_t pid = atoi(argv[1]);
    unsigned long addr = strtoul(argv[2], NULL, 16);
    printf("目标 pid=%d addr=0x%lx\n", pid, addr);

    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_BREAKPOINT;
    a.size = sizeof(a);
    a.bp_type = HW_BREAKPOINT_W;
    a.bp_addr = addr;
    a.bp_len = HW_BREAKPOINT_LEN_8;
    a.sample_period = 1;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    a.sample_regs_user = (1ULL<<0)|(1ULL<<1)|(1ULL<<2)|(1ULL<<30);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.wakeup_events = 1;

    int fd = po(&a, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) { printf("PERF_OPEN_FAIL errno=%d (%s)\n", errno, strerror(errno)); return 2; }
    printf("PERF_OPEN_OK fd=%d\n", fd);

    size_t pg = sysconf(_SC_PAGESIZE), msz = pg*9;
    char *base = mmap(NULL, msz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { printf("MMAP_FAIL\n"); return 3; }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    printf("ENABLED 观察 3 秒...\n"); fflush(stdout);
    sleep(3);

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    unsigned long head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    unsigned long tail = meta->data_tail;
    printf("HEAD=%lu TAIL=%lu\n", head, tail);
    int n = 0;
    size_t data_sz = msz - pg;
    while (tail < head && n < 5) {
        unsigned long off = tail % data_sz;
        struct perf_event_header *h = (struct perf_event_header *)(base + pg + off);
        if (h->type == PERF_RECORD_SAMPLE) {
            unsigned char *p = (unsigned char*)h + sizeof(*h);
            unsigned long ip = *(unsigned long*)p; p += 8;
            unsigned int tpid = *(unsigned int*)p; p += 4;
            unsigned int tid = *(unsigned int*)p; p += 4;
            unsigned long abi = *(unsigned long*)p; p += 8;
            printf("  HIT#%d IP=0x%lx tid=%u", ++n, ip, tid);
            if (abi == PERF_SAMPLE_REGS_ABI_64) {
                unsigned long x0=*(unsigned long*)p; p+=8;
                unsigned long x1=*(unsigned long*)p; p+=8;
                unsigned long x2=*(unsigned long*)p; p+=8;
                unsigned long lr=*(unsigned long*)p; p+=8;
                printf(" x0=0x%lx x1=0x%lx x2=0x%lx lr=0x%lx", x0,x1,x2,lr);
            }
            printf("\n");
        }
        tail += h->size;
    }
    if (n == 0) printf("HIT=0\n");
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    return 0;
}
