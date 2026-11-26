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
 * 共享内存布局（与 mda_memguard_inject.c 保持严格一致，全部 8 字节对齐）
 * ============================================================
 *   0x000  magic        4B "MDMG"
 *   0x004  state        4B 0=未初始化 1=handler已装/已布防 3=出错
 *   0x008  count        8B 命中总条数
 *   0x010  head         8B 最新一条环形下标
 *   0x018  capacity     8B 环形容量（默认 64）
 *   0x020  page_addr    8B 目标页地址
 *   0x028  page_len     8B 目标页长度
 *   0x030  target_addr  8B 目标地址
 *   0x038  target_len   8B 目标长度
 *   0x040  last_errno   8B 最近一次 syscall 返回值
 *   0x100  args         参数区（x1..x4/x19 备份）
 *   0x200  act          struct sigaction（新）
 *   0x300  oldact       struct sigaction（旧）
 *   0x400  records[64]  每条 128 字节（占 0x2000，总至 0x2400，SHM_SIZE=0x3000）
 */

    .arch armv8-a

    /*
     * (24) 第二十四次修改（2026-11-26）
     * bug 原因：① 原第 66-70 行把写 handler_ran 的指令放在 .text 之前，根本不在 handler_entry 内；
     *           ② OFF_PAGE/OFF_PAGELEN/OFF_TARGET/OFF_TLEN 原按 4 字节间隔排布，64 位写互相覆盖；
     *           ③ payload_entry 的 mprotect 错用 x1/x2/x3 而非 ARM64 ABI 的 x0/x1/x2，且 str x5 覆写 OFF_STATE 会踩到 OFF_COUNT；
     *           ④ handler_entry 入口压栈 128B 而出口只弹 96B（SP 失衡致 rt_sigreturn 崩溃），
     *              且记录逻辑落在 rt_sigreturn 之后成了死代码、before 拷贝漏加索引寄存器 x9、
     *              handler_ran 只有 4 字节 .word 导致 64 位 str 越界踩坏 slot_page。
     * 解决方案：移除 .text 前游离指令，将 handler_ran 改为 8 字节 .quad 并移入 handler_entry；
     *           统一全部共享内存偏移为互不重叠的 8 字节对齐布局；修正所有 mprotect 寄存器为 x0/x1/x2；
     *           在 handler_entry 中对称压弹 128B 栈帧，在 mprotect 与 rt_sigreturn 之前完成区间校验、
     *           现场记录与逐字节 before 拷贝，最后按运行时 64 位 slot_page（回退 shared_slot/编译期常量）恢复页权限并 rt_sigreturn。
     */

    /* 编译期注入的常量（由 build_payload.py 通过 -D 传入，作为兜底） */
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
    .equ OFF_HEAD,      0x010
    .equ OFF_CAPACITY,  0x018
    .equ OFF_PAGE,      0x020
    .equ OFF_PAGELEN,   0x028
    .equ OFF_TARGET,    0x030
    .equ OFF_TLEN,      0x038
    .equ OFF_ERRNO,     0x040
    .equ OFF_ARGS,      0x100
    .equ OFF_ACT,       0x200
    .equ OFF_OLDACT,    0x300
    .equ OFF_RECS,      0x400
    .equ REC_SIZE,      128

    .text
    .global payload_entry
    .global restorer_entry
    .global handler_entry
    .type payload_entry, %function
    .type restorer_entry, %function
    .type handler_entry, %function

payload_entry:
    /* x0 = 共享内存基址 */
    /* x1 = 目标页地址  x2 = 目标页长度 */
    /* x3 = 目标地址    x4 = 目标长度 */

    /*
     * (5) 把共享内存基址存进 **x19**（callee-saved，syscall 不改它）。
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

    /* handler 由 ptrace 侧搭便车装好；此处只写 4 字节 state，不覆写 OFF_COUNT */
    mov  w5, #1
    str  w5, [x19, #OFF_STATE]

    /* ---- 步骤 2：mprotect(page, len, PROT_READ) — ARM64 ABI: x0/x1/x2 ---- */
    ldr  x0, [x19, #OFF_PAGE]
    ldr  x1, [x19, #OFF_PAGELEN]
    mov  x2, #1                       /* PROT_READ */
    mov  x8, #226
    svc  #0
    str  x0, [x19, #OFF_ERRNO]
    brk  #0                            /* 步骤停点 */

    /* ---- 步骤 3：标记就绪，然后停下等 C 侧把 pc 改回去 ---- */
    mov  w5, #1
    str  w5, [x19, #OFF_STATE]
    brk  #0

/* ============================================================
 * restorer —— 从信号处理器返回内核
 * ============================================================ */
    .align 4
restorer_entry:
    mov  x8, #139                     /* __NR_rt_sigreturn */
    svc  #0
    brk  #0

/* ============================================================ */
/* SIGSEGV handler                                              */
/* 入参：x0=sig, x1=siginfo_t*, x2=ucontext_t*                  */
/* ============================================================ */
    .align 4
handler_entry:
    /* (22) 入口必须有 bti c，避免开启 BTI 时触发 SIGTRAP/SIGILL */
    bti  c
    /* 严格压栈 128 字节（16B 对齐），与 .Lret 精确对称，确保 rt_sigreturn 时 sp 指回原 sigframe */
    sub  sp, sp, #128
    stp  x19, x20, [sp, #0]
    stp  x21, x22, [sp, #16]
    stp  x23, x24, [sp, #32]
    stp  x25, x26, [sp, #48]
    stp  x27, x28, [sp, #64]
    stp  x29, x30, [sp, #80]
    stp  x0,  x1,  [sp, #96]
    stp  x2,  x3,  [sp, #112]

    /* 保存 ucontext_t* 到 callee-saved x23 */
    mov  x23, x2

    /* 写 64 位魔数 "MDAG" 到 8 字节 handler_ran 槽，标记 handler 已执行 */
    adrp x9, handler_ran
    add  x9, x9, :lo12:handler_ran
    movz x10, #0x4147
    movk x10, #0x4d44, lsl #16
    str  x10, [x9]

    /* x19 = 共享内存基址（存在 .data 的全局槽里，由 ptrace 侧在写入 payload 之后回填） */
    adrp x19, shared_slot
    add  x19, x19, :lo12:shared_slot
    ldr  x19, [x19]
    cbz  x19, .Lrestore_page

    /* ---- 命中判断 + 在 mprotect / rt_sigreturn 之前记录写入前现场 ---- */
    cbz  x23, .Lrestore_page
    ldr  x20, [x19, #OFF_TARGET]     /* target_addr */
    ldr  x21, [x19, #OFF_TLEN]       /* target_len */
    ldr  x22, [x23, #UC_FAULT]       /* fault_address */

    /* fault_addr 必须在 [target_addr, target_addr + target_len) 内 */
    cmp  x22, x20
    b.lo .Lrestore_page
    add  x24, x20, x21
    cmp  x22, x24
    b.hs .Lrestore_page

    /* 计算环形槽位：idx = old_count % capacity */
    ldr  x25, [x19, #OFF_CAPACITY]
    cbz  x25, .Lrestore_page
    ldr  x24, [x19, #OFF_COUNT]
    udiv x26, x24, x25
    msub x26, x26, x25, x24          /* x26 = idx */
    mov  x27, #REC_SIZE
    mul  x27, x26, x27
    add  x27, x19, x27
    add  x27, x27, #OFF_RECS         /* x27 = &recs[idx] */

    str  x22, [x27, #0x00]           /* fault_addr */
    ldr  x28, [x23, #UC_PC]
    str  x28, [x27, #0x08]           /* pc */
    ldr  x28, [x23, #UC_LR]
    str  x28, [x27, #0x10]           /* lr */
    ldr  x28, [x23, #UC_SP]
    str  x28, [x27, #0x18]           /* sp */
    ldr  x28, [x23, #UC_X0]
    str  x28, [x27, #0x20]           /* x0 */
    ldr  x28, [x23, #UC_X1]
    str  x28, [x27, #0x28]           /* x1 */

    /* 读取写入前内容（此刻目标页仍为 PROT_READ 且写指令尚未提交）：len = min(tlen, 48) */
    mov  x28, #48
    cmp  x21, x28
    csel x28, x21, x28, lo
    str  x28, [x27, #0x30]           /* before_len */
    add  x29, x27, #0x40             /* x29 = &rec->before[0] */
    mov  x9, #0
.Lcopy:
    cmp  x9, x28
    b.hs .Lcopy_done
    ldrb w10, [x20, x9]
    strb w10, [x29, x9]
    add  x9, x9, #1
    b    .Lcopy
.Lcopy_done:

    /* 记录落盘后再递增 count / 更新 head */
    str  x26, [x19, #OFF_HEAD]
    add  x24, x24, #1
    str  x24, [x19, #OFF_COUNT]

.Lrestore_page:
    /* 恢复目标页为 PROT_READ|PROT_WRITE，让原写指令能继续完成。
     * 优先使用运行时 64 位 slot_page，回退到共享内存 OFF_PAGE/OFF_PAGELEN，最后回退编译期常量。 */
    adrp x9, slot_page
    add  x9, x9, :lo12:slot_page
    ldr  x0, [x9, #0]                /* 64-bit page_addr */
    ldr  x1, [x9, #8]                /* 64-bit page_len */
    cbnz x0, .Ldo_mprotect
    cbz  x19, .Luse_const_page
    ldr  x0, [x19, #OFF_PAGE]
    ldr  x1, [x19, #OFF_PAGELEN]
    cbnz x0, .Ldo_mprotect
.Luse_const_page:
    movz x0, #PAGE_ADDR_LO
    movk x0, #PAGE_ADDR_HI, lsl #16
    movk x0, #PAGE_ADDR_B2, lsl #32
    movk x0, #PAGE_ADDR_B3, lsl #48
    mov  x1, #PAGE_LEN
.Ldo_mprotect:
    cbz  x0, .Lret
    cbnz x1, .Lhas_len
    mov  x1, #4096
.Lhas_len:
    mov  x2, #3                      /* PROT_READ | PROT_WRITE */
    mov  x8, #226                    /* __NR_mprotect */
    svc  #0

.Lret:
    /* 严格恢复 128 字节栈帧后调用 rt_sigreturn（不用 ret，避免 PAC 校验失败） */
    ldp  x2,  x3,  [sp, #112]
    ldp  x0,  x1,  [sp, #96]
    ldp  x29, x30, [sp, #80]
    ldp  x27, x28, [sp, #64]
    ldp  x25, x26, [sp, #48]
    ldp  x23, x24, [sp, #32]
    ldp  x21, x22, [sp, #16]
    ldp  x19, x20, [sp, #0]
    add  sp, sp, #128
    mov  x8, #139                    /* __NR_rt_sigreturn */
    svc  #0

/* ============================================================ */
    .data
    .align 3
    .global shared_slot
shared_slot:
    .quad 0                          /* ptrace 侧填入共享内存基址 */
    .size shared_slot, 8

    .align 3
    .global handler_ran
handler_ran:
    .quad 0                          /* 8 字节魔数槽，避免 str x10 越界覆盖 slot_page */
    .size handler_ran, 8

    .align 3
    .global slot_page
slot_page:
    .quad 0                          /* 64 位目标页地址 */
    .quad 0                          /* 64 位目标页长度 */
    .size slot_page, 16

    .align 3
sig_act:
    .quad 0                          /* sa_handler */
    .quad 0                          /* sa_flags */
    .quad 0                          /* sa_restorer */
    .quad 0                          /* sa_mask */
    .size sig_act, 32

    .section .note.GNU-stack,"",%progbits
