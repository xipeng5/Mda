// perf_event 硬件观察点可行性探针
// 目的：在真机上验证 PERF_TYPE_BREAKPOINT 能否创建、能否触发、能否拿到 pc/寄存器
// 只做验证，不做正式实现
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

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    // 目标：观察本进程的一块堆内存被写
    volatile char *buf = (volatile char *)malloc(4096);
    if (!buf) { printf("malloc fail\n"); return 1; }
    memset((void *)buf, 0, 4096);
    printf("buf = %p\n", (void *)buf);

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_W;          // 写
    attr.bp_addr = (unsigned long)buf;
    attr.bp_len  = HW_BREAKPOINT_LEN_8;      // 8 字节
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    attr.sample_regs_user = (1ULL << 0) | (1ULL << 1) | (1ULL << 30); // x0,x1,lr
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.wakeup_events = 1;

    int fd = perf_open(&attr, 0 /* 当前进程 */, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        printf("PERF_OPEN_FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 2;
    }
    printf("PERF_OPEN_OK fd=%d\n", fd);

    size_t page = sysconf(_SC_PAGESIZE);
    size_t map_size = page * 9;
    char *base = (char *)mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("MMAP_FAIL errno=%d\n", errno);
        close(fd);
        return 3;
    }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    printf("ENABLED\n");
    fflush(stdout);

    // 触发写入
    buf[3] = 0x5A;

    // 给内核一点时间填充 ring buffer
    usleep(120000);

    __sync_synchronize();
    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)base;
    unsigned long head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    unsigned long tail = meta->data_tail;
    printf("DATA_HEAD=%lu TAIL=%lu\n", head, tail);
    if (head > tail) {
        printf("HIT=1\n");
        // 解析第一条记录的头
        unsigned long off = tail % (map_size - page);
        struct perf_event_header *h = (struct perf_event_header *)(base + page + off);
        printf("RECORD type=%u size=%u\n", h->type, h->size);
    } else {
        printf("HIT=0\n");
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    munmap(base, map_size);
    close(fd);
    return 0;
}
