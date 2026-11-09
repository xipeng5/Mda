// 探针：问内核「到底有几个硬件断点/观察点槽位」
// 用 PTRACE_GETREGSET(NT_ARM_HW_WATCH / NT_ARM_HW_BREAK) 读 dbg_info
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <stdint.h>
#include <linux/elf.h>
#include <asm/ptrace.h>

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403
#endif

static int probe(pid_t pid, int type, const char *name) {
    struct user_hwdebug_state st;
    memset(&st, 0, sizeof(st));
    struct iovec iov = { .iov_base = &st, .iov_len = sizeof(st) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)(long)type, &iov) == -1) {
        printf("  %-10s GETREGSET 失败 errno=%d (%s)\n", name, errno, strerror(errno));
        return -1;
    }
    printf("  %-10s dbg_info=0x%08x -> 可用槽位=%u   (iov_len=%zu)\n",
           name, st.dbg_info, st.dbg_info & 0xff, iov.iov_len);
    return (int)(st.dbg_info & 0xff);
}

int main(void) {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    printf("== 内核硬件调试槽位 ==\n");
    probe(child, NT_ARM_HW_BREAK, "BREAK");
    probe(child, NT_ARM_HW_WATCH, "WATCH");
    ptrace(PTRACE_DETACH, child, 0, 0);
    waitpid(child, &status, 0);
    return 0;
}
