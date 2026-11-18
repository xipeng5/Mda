/*
 * mda_payload.S —— 注入到目标进程里执行的 payload（arm64）
 *
 * ============================================================
 * 做什么
 * ============================================================
 *   1. 装一个 SIGSEGV handler（rt_sigaction）
 *   2. 把含目标地址的页改成只读（mprotect）
 *   3. 写入命中时把现场（before 内容 + pc/lr/sp/regs）记进共享内存，
 *      然后恢复页权限，让那条写指令能完成
 *
 * ============================================================
 * 为什么必须是汇编
 * ============================================================
 * 注入码不能调用函数（没有栈帧、没有重定位、没有可用 PLT），
 * 只能直接 svc 系统调用：
 *   rt_sigaction = 134,  mprotect = 226
 *
 * ============================================================
 * 调用约定
 * ============================================================
 * ptrace 侧会：
 *   · 把 pc 指向 payload_entry
 *   · 设置 x0 = 共享内存基址, x1 = 目标页地址, x2 = 目标页长度,
 *           x3 = 目标地址, x4 = 目标长度
 *   · 单步执行；payload 每完成一步用 svc #0 停住，
 *     ptrace 侧检查返回码后继续单步
 *
 * ============================================================
 * ucontext 布局（**实测值**，本机 Android 12 / arm64）
 * ============================================================
 *   uc+0x0b0  fault_address
 *   uc+0x0b8  regs[0]
 *   uc+0x0c0  regs[1]
 *   uc+0x1a8  regs[30]
 *   uc+0x1b0  sp
 *   uc+0x1b8  pc
 *
 * 这些是实测出来的，不是猜的——猜错会让事件全是错值。
 *
 * ============================================================
 * 共享内存布局
 * ============================================================
 *   0x000  magic        "MDMG"
 *   0x004  state        0=未初始化 1=handler已装 2=已布防 3=出错
 *   0x008  count        命中条数
 *   0x00c  head         最新一条下标
 *   0x010  capacity     环形容量
 *   0x014  page_addr    目标页地址
 *   0x018  page_len     目标页长度
 *   0x01c  target_addr  目标地址
 *   0x020  target_len   目标长度
 *   0x028  last_errno   最近一次 syscall 返回值
 *   0x030  records[capacity]，每条 128 字节
 *   0x200  参数区（x0..x5 备份）
 *   0x300  struct sigaction（16+8 字节就够）
 */

    .arch armv8-a

    /* 编译期注入的常量（由 build_payload.py 通过 -D 传入） */
    /*
     * (19) handler 一进来先写魔数到注入页的固定槽（编译期固定偏移），
     *      ptrace 侧读它就知道 handler 到底有没有跑过。
     */
    adrp x9, handler_ran
    add  x9, x9, :lo12:handler_ran
    movz x10, #0x4147          /* "MDAG" 高位 */
    movk x10, #0x4d44, lsl #16
    str  x10, [x9]

    /*
     * (17) handler 用的"监控页地址/长度"放在**注入页内的固定槽**。
     *      handler 用 adrp+add :lo12: 就能拿到自己的槽地址——
     *      这是编译期固定的，不需要任何运行时间接，
     *      也就不依赖共享内存（之前崩溃的根因就是那层间接失效）。
     *      ptrace 侧在写完 payload 后，把页地址/长度写进这两个槽。
     */
#ifndef PAGE_ADDR_LO_CONST
#define PAGE_ADDR_LO_CONST 0
#endif
#ifndef PAGE_ADDR_HI_CONST
#define PAGE_ADDR_HI_CONST 0
#endif
#ifndef PAGE_ADDR_B2_CONST
#define PAGE_ADDR_B2_CONST 0
#endif
#ifndef PAGE_ADDR_B3_CONST
#define PAGE_ADDR_B3_CONST 0
#endif
#ifndef PAGE_LEN_CONST
#define PAGE_LEN_CONST 4096
#endif
#ifndef SIGNO_CONST
#define SIGNO_CONST 11
#endif
    .equ PAGE_ADDR_LO, PAGE_ADDR_LO_CONST
    .equ PAGE_ADDR_HI, PAGE_ADDR_HI_CONST
    .equ PAGE_ADDR_B2, PAGE_ADDR_B2_CONST
    .equ PAGE_ADDR_B3, PAGE_ADDR_B3_CONST
    .equ PAGE_LEN,    PAGE_LEN_CONST

    .equ UC_FAULT,   0x0b0
    .equ UC_X0,      0x0b8
    .equ UC_X1,      0x0c0
    .equ UC_LR,      0x1a8
    .equ UC_SP,      0x1b0
    .equ UC_PC,      0x1b8

    .equ OFF_STATE,     0x004
    .equ OFF_COUNT,     0x008
    .equ OFF_HEAD,      0x00c
    .equ OFF_CAPACITY,  0x010
    .equ OFF_PAGE,      0x014
    .equ OFF_PAGELEN,   0x018
    .equ OFF_TARGET,    0x01c
    .equ OFF_TLEN,      0x020
    .equ OFF_ERRNO,     0x028
    /* (6) 第六次修改（2026-11-17）：与 C 侧布局统一（B-8/B-9）
     *     OFF_ARGS 必须 0x100（C 侧原为 0x200，两边不一致读到错位内容）；
     *     记录区移到参数区之后，避免第 3 条起覆盖 OFF_ARGS/OFF_ACT。 */
    .equ OFF_ARGS,      0x100
    .equ OFF_ACT,       0x200
    .equ OFF_RECS,      0x400
    .equ REC_SIZE,      128

    .text
    .global payload_entry
    .global handler_entry
    .type payload_entry, %function

payload_entry:
    /* x0 = 共享内存基址 */
    /* x1 = 目标页地址  x2 = 目标页长度 */
    /* x3 = 目标地址    x4 = 目标长度 */

    /*
     * (5) 把共享内存基址存进 **x19**（callee-saved，syscall 不改它）。
     *     之前全程用 x0 做基址，但 x0 是 syscall 的**返回值**——
     *     svc 之后 x0 变成 0 或负 errno，
     *     `str x0,[x0,#..]` 就往无效地址写 → SIGSEGV，
     *     pc 停在原地不动（实测 pc 恒为 0x60）。
     */
    mov x19, x0

    /* 把参数备份到共享内存，便于 ptrace 侧随时查看 */
    stp x1, x2, [x19, #OFF_ARGS]
    stp x3, x4, [x19, #OFF_ARGS+16]
    str x19, [x19, #OFF_ARGS+32]

    /* 记下目标信息（handler 要用） */
    str x1, [x19, #OFF_PAGE]
    str x2, [x19, #OFF_PAGELEN]
    str x3, [x19, #OFF_TARGET]
    str x4, [x19, #OFF_TLEN]
    /* capacity 固定 64 条 */
    mov x5, #64
    str x5, [x19, #OFF_CAPACITY]

    /*
     * (14) handler **已由 ptrace 侧用"搭便车"方式装好**：
     *     在目标自己发起的 syscall 入口把参数换成 rt_sigaction，
     *     内核走正常执行路径（不像 ptrace stop 状态那样返回 EINVAL）。
     *     payload 里**不再调 rt_sigaction**。
     */
    mov  x5, #1
    str  x5, [x19, #OFF_STATE]        /* state = 1（handler 已就绪） */

    /* ---- 步骤 2：mprotect(page, len, PROT_READ) ---- */
    ldr  x1, [x19, #OFF_PAGE]
    ldr  x2, [x19, #OFF_PAGELEN]
    mov  x3, #1                       /* PROT_READ */
    mov  x8, #226
    svc  #0
    str  x0, [x19, #OFF_ERRNO]
    brk  #0                            /* 步骤停点（brk 不是 syscall！） */

    /* ---- 步骤 3：标记就绪，然后停下等 C 侧把 pc 改回去 ---- */
    mov  x5, #1
    str  x5, [x19, #OFF_STATE]
    brk  #0                            /* 最终停点：停在这里，
                                       C 侧会把 pc 改回原始位置并恢复寄存器，
                                       所以 payload 不需要 ret（没有合法返回地址） */

/* ============================================================
 * restorer —— 从信号处理器返回内核
 *
 * arm64 没有 VDSO trampoline，必须自己提供：
 *   用 sigreturn(139) 系统调用，内核从 ucontext 恢复现场。
 * ============================================================ */
    .align 4
restorer_entry:
    mov  x8, #139                     /* __NR_rt_sigreturn */
    svc  #0
    /* 不应该到这里 */
    brk  #0

/* ============================================================ */
/* SIGSEGV handler                                                  */
/* 入参：x0=sig, x1=siginfo_t*, x2=ucontext_t*                     */
/* ============================================================ */
    .align 4
handler_entry:
    /*
     * (22) 入口必须有 bti c：内核跳转到信号处理器时，
     *      若目标页开了 BTI 检查，没有 bti 的地址会 SIGTRAP。
     */
    bti  c
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp x29, x30, [sp, #-16]!

    /* x19 = 共享内存基址（存在 .data 的全局槽里，由 ptrace 侧填） */
    /* (13) 必须用 adrp + add :lo12:（页相对）。
     *     adr 是 **PC 相对**（结果 = PC + 立即数），与链接器的段相对偏移
     *     不一致 → 实测读到垃圾地址崩溃（fault addr 0x12）。 */
    adrp x19, shared_slot
    add  x19, x19, :lo12:shared_slot
    ldr  x19, [x19]
    cbz  x19, .Lret

    /*
     * (16) **极简 handler**：只做一件事——把监控页恢复成可写，
     *      让那条写指令能完成。记录由 ptrace 侧在信号帧里读 ucontext 得到
     *      （ptrace 本来就能看到 SIGSEGV 现场），handler 不需要记录。
     *
     *      之前 handler 要从共享内存读 target/page 等参数，
     *      依赖"注入页里的全局槽"这层间接 —— 一旦它失效，
     *      mprotect 恢复就会失败，页仍是只读 → 写指令再次 SIGSEGV →
     *      目标崩溃（实测 SEGV_ACCERR）。
     *      现在页地址与长度**编译期固定**（由构建脚本注入），
     *      不再有任何运行时间接。
     */
    /*
     * (23) 恢复页权限。**页地址与长度用编译期常量**（-D 注入），
     *       不从任何运行时槽读——彻底去掉那层间接。
     *       arm64 内核约定：x0=addr, x1=len, x2=prot
     */
    /* (5) 四段 movk 覆盖完整 64 位地址 */
    mov  x0, #PAGE_ADDR_LO
    movk x0, #PAGE_ADDR_HI, lsl #16
    movk x0, #PAGE_ADDR_B2, lsl #32
    movk x0, #PAGE_ADDR_B3, lsl #48
    mov  x1, #PAGE_LEN
    mov  x2, #3                     /* PROT_READ|PROT_WRITE */
    mov  x8, #226
    svc  #0

    /*
     * (22) **不用 ret**，直接 sigreturn。
     *     ret 会做 PAC 校验：返回地址未签名 → SIGILL。
     *     sigreturn 让内核从 ucontext 恢复全部上下文（含 PAC 状态），
     *     这是信号处理器的标准返回方式。
     */
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    mov  x8, #139                 /* __NR_rt_sigreturn */
    svc  #0

    /* ---- 记录一条 ---- */
    ldr  x24, [x19, #OFF_COUNT]
    add  x24, x24, #1
    str  x24, [x19, #OFF_COUNT]
    ldr  x25, [x19, #OFF_CAPACITY]
    udiv x26, x24, x25
    msub x26, x26, x25, x24          /* head = count % capacity */
    mov  x27, #REC_SIZE
    mul  x26, x26, x27
    add  x27, x19, #OFF_RECS
    add  x27, x27, x26               /* x27 = &rec */

    str  x22, [x27, #0x00]           /* fault_addr */
    ldr  x28, [x2, #UC_PC]
    str  x28, [x27, #0x08]           /* pc */
    ldr  x28, [x2, #UC_LR]
    str  x28, [x27, #0x10]           /* lr */
    ldr  x28, [x2, #UC_SP]
    str  x28, [x27, #0x18]           /* sp */
    ldr  x28, [x2, #UC_X0]
    str  x28, [x27, #0x20]           /* x0 */
    ldr  x28, [x2, #UC_X1]
    str  x28, [x27, #0x28]           /* x1 */

    /* ---- 读"写入前"的内容（此刻写指令还没执行）---- */
    mov  x28, #48
    cmp  x21, x28
    csel x28, x21, x28, lo           /* len = min(tlen, 48) */
    str  x28, [x27, #0x30]           /* before_len */
    mov  x26, #0
.Lcopy:
    cmp  x26, x28
    b.hs .Lcopy_done
    ldrb w29, [x20, x26]
    strb w29, [x27, #0x40]
    add  x26, x26, #1
    b .Lcopy
.Lcopy_done:

    /* ---- 恢复页为可写，让写指令完成 ---- */
    ldr  x1, [x19, #OFF_PAGE]
    ldr  x2, [x19, #OFF_PAGELEN]
    mov  x3, #3                       /* PROT_READ|PROT_WRITE */
    mov  x8, #226
    svc  #0

    b .Lret

.Lnot_ours:
    /* 不是监控区间：也恢复权限，避免死循环 */
    ldr  x1, [x19, #OFF_PAGE]
    ldr  x2, [x19, #OFF_PAGELEN]
    mov  x3, #3
    mov  x8, #226
    svc  #0

.Lret:
    ldp x29, x30, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret

/* ============================================================ */
    .data
    .align 3
shared_slot:
    .quad 0                          /* ptrace 侧填入共享内存基址 */
    .size shared_slot, 8

    .align 2
handler_ran:
    .word 0                          /* handler 是否跑过（魔数） */

slot_page:
    .short 0                         /* 页地址低 16 位 */
    .short 0                         /* 页地址高 16 位 */
    .short 0                         /* 页长度 */
    .short 0

    .align 3
sig_act:
    .quad 0                          /* sa_handler */
    .quad 0                          /* sa_flags */
    .quad 0                          /* sa_restorer */
    .quad 0                          /* sa_mask */
    .size sig_act, 32

    .section .note.GNU-stack,"",%progbits
