"""VM 层断点 —— 按 (prog, idx) 停在某条 VM 指令上，读出 VM 寄存器堆与 VM 栈。

## 为什么需要它

动态加载 VM 的分析里，最关键的一步是「停在某条 VM 指令上，看当时的 VM 状态」。

传统做法是 hook 每个 opcode 的 handler，然后自己从 handler 的寄存器约定里
反算 A/B/C 字段——**每个 op 的约定都不一样**，每换一个 op 就要重新校准，
实际上不可用。

本模块换一个落点：**handler 尾部的派发段**。所有 handler 在执行完自己的
语义后，都会走同一段「保存 VM pc → 跳到下一个 handler」的代码：

    ldr  x2,  [x23, x5, lsl #3]   ; 查 handler 跳转表
    str  x21, [x27, #8]           ; 保存 VM pc
    br   x2                       ; 派发

在这一段上拦一次，就能在**每条 VM 指令执行前**拿到完整 VM 状态，
不需要理解任何单个 op 的寄存器约定。

## 真机验证的寄存器约定（2026-11-09，arm64，sgmainso 2.98MB）

    x25  → VM 寄存器堆基址，r[i] 在 [x25 + i*8]
    x21  → 当前 VM 指令指针（+0 u16 op / +2 A / +3 B / +4 C / +8 s64 imm）
    x27  → VM 上下文，[x27 + 8] = 当前 VM pc
    x23  → op → handler 的跳转表基址

    data_base = *(*(x27 + 0x240) + 0x1a0)     ← **数据区**基址，不是字节码区
    vm_idx    = (vm_pc - code_base) / 16      ← code_base 必须调用方显式给

`data_base` 的推导链（sub_170a8c，op508 host handler 调用的函数）：

    0x170a98  ldr x8, [x1, #0x240]    ; x1 = VM ctx
    0x170aa0  ldr x8, [x8, #0x1a0]    ; ← data_base
    0x170aa4  add x0, x8, x2          ; + imm = **host 变量地址**

★ 注意最后一行：加完得到的是 host 变量地址 ⇒ 这个基址指向**数据区**。
  所以它**不能**用来算 vm_idx（真机实测：算出的 idx 去查镜像是 op=4 A=28，
  不是合法指令边界）。字段原名 prog_base 具有误导性，已改为 data_base。

★ 真正的 code_base 在 ctx 里的位置**尚未确认**，因此：
  · 不传 code_base 时，vm_idx 返回 null（不伪造数字）
  · 工具会回读 vm_pc 处原始字节（vm_pc_bytes），调用方拿它比对镜像自己反推

**不能用 vm_pc 直接减模块基址**——VM 代码区是 malloc 出来的，
与 so 模块不在一处。

反汇编证据（op491 handler，文件偏移 0x76000）：

    0x76004  ldr x20, [x25, x16, lsl #3]   ; r[B]
    0x7600c  ldr x0,  [x25, x17, lsl #3]   ; r[C]
    0x76018  str x19, [x25, x1,  lsl #3]   ; r[A] = 结果
    0x76024  str x21, [x27, #8]            ; VM pc
    0x76028  br  x2

## 扫描特征（实测 805/805 = 100% 可靠）

    "str x21, [x27, #8]"  =  75 07 00 f9

**不要用 "br x2" 当特征**：实测派发寄存器完全不固定
（x7/x17/x3/x15/x6/x4/x13/x19/x20/x11 都在用），
用 br x2 只能扫到 42/805 处。

## 通用性

所有目标侧细节都是参数：

    dispatch_patterns  派发段特征字节（默认就是上面那条）
    reg_base_reg       VM 寄存器堆基址在哪个寄存器（x25）
    reg_base_offset    VM 寄存器堆相对 ctx 的偏移（0 = 不用，改看 reg_base_reg）
    ctx_reg            VM 上下文在哪个寄存器（x27）
    ip_mode / ip_reg / ip_offset  VM pc 从哪里取（ctx 解引用 / 寄存器 / 不取）
    opcode_expr        opcode 从哪里取（"sp+8" / "x8" / "ctx+0x100"）
    slot_size          每条 VM 指令多少字节（16）
    code_base          VM 代码区在进程里的基址（给了才算 idx）

换一个 VM 只改参数，不改代码。

## (4) 第四次修改（2026-11-16）：把结构假设全部参数化

    bug 原因：本模块原先隐含「寄存器堆一定在某个寄存器里、VM pc 一定在
              [ctx+8]、data_base 一定走 [ctx+0x240]+0x1a0」这三条结构假设。
              用户实测的 metasec_ml.so 完全不符合：
                  寄存器堆在 ctx + 0x6070（不是在寄存器里）
                  opcode 在 sp+8（不在结构体里）
                  派发点是 adr x22, #0x2F50D0; br x8
              于是 vm_breakpoint / vm_regs_snapshot 全部用不了，
              而这不是"偏移填错"，是**取值方式本身**不同。
    解决方案：引入「取值来源描述（spec）」这一层抽象，把「从哪取」变成参数：
                  reg      从某个寄存器直接取
                  off/ctx  相对 ctx 的偏移（可按寄存器堆/结构体字段）
                  sp       相对 native 栈指针
                  none     不取（该字段返回 null，不编造）
              四条来源覆盖了 ctx / 寄存器堆 / pc / opcode 四个关键字段，
              每个都可独立配置；旧参数（reg_base_reg / ctx_reg / ip_offset /
              reg_base_offset 默认 0）保持默认值即等于原行为，向后兼容。
"""

from __future__ import annotations

import json
import os
import re
import struct

__all__ = [
    "find_dispatch_points",
    "vm_breakpoint",
    "vm_regs_snapshot",
    "parse_value_expr",
    "VM_DEFAULT_PATTERN",
    "VM_DEFAULTS",
    "SPEC_KINDS",
]

# (4) 第四次修改（2026-11-16）：spec 支持的取值来源种类。
# 对外暴露是为了让调用方/TUI 能自解释，而不是靠读源码猜。
SPEC_KINDS = ("reg", "sp", "ctx", "regoff", "none", "bad")

# 派发段特征：str x21, [x27, #8]
# 实测 805 处全部紧跟着 br xN，是「每条 VM 指令执行完」的公共落点。
VM_DEFAULT_PATTERN = "750700f9"

# 默认寄存器约定（真机验证，见模块注释）
#
# (4) 第四次修改（2026-11-16）：新增 reg_base_offset / ip_mode / opcode_expr
#     三个参数并给**等于原行为**的默认值，保证旧调用方不传也完全一样。
VM_DEFAULTS = {
    "reg_base_reg": "x25",     # VM 寄存器堆基址
    "reg_base_offset": 0,      # 寄存器堆相对 ctx 的偏移（0 = 用 reg_base_reg）
    "ip_reg": "x21",           # VM 指令指针
    "ctx_reg": "x27",          # VM 上下文
    "ip_mode": "ctx",          # ctx=从 [ctx+ip_offset] 读；reg=直接用 ip_reg；none=不取
    "ip_offset": 8,            # [ctx + 8] = 当前 VM pc
    "opcode_expr": "",         # opcode 取值描述（"" = 不取，如 "sp+8" / "x8"）
    "slot_size": 16,           # 每条 VM 指令 16 字节
    "vm_reg_count": 32,        # VM 寄存器个数
    # data_base 的两跳解引用路径：[ctx + p1_off] → [+ p2_off] = data_base
    # （名为 prog_base_* 是历史兼容；它指向数据区，不是字节码区）
    "prog_base_p1_offset": 0x240,
    "prog_base_p2_offset": 0x1A0,
    # (4) 第四次修改（2026-11-16）：data_base 的两跳路径也可以整体关掉。
    #     bug 原因：换一个 VM 时 [ctx+0x240] 可能是任意字段，两跳解引用
    #               要么读失败、要么读出一个垃圾指针，而调用方无从判断
    #               这是"结构不同"还是"偏移填错"。
    #     解决方案：p1_offset 传负数（<0）即表示本 VM 没有这条路径，
    #               data_base 返回 null 并在返回里注明来源，不再硬读。
    "data_base_enabled": True,
}

# 派发点扫到的偏移 → 该处可用的「VM pc 寄存器」（供自动推断）
# 不写死任何 App：只表达 arm64 通用规律 —— 派发前一刻，VM pc 一定在某个
# 通用寄存器里，而那些寄存器正是 br 之前的候选。
_ARM64_GP_REGS = tuple(f"x{i}" for i in range(0, 31))


def _spec_from_args(reg: str = "", offset: int = 0, ctx_reg: str = "",
                    sp_offset: int | None = None) -> dict:
    """把「从哪取一个值」的几种写法收敛成一个 spec。

    (4) 第四次修改（2026-11-16）：新增。
        这一层存在的唯一目的：让 JS 侧**不需要知道**这个值到底来自寄存器、
        结构体偏移还是栈——它只按 spec.kind 执行对应的一条读法。
        这样换 VM 只是构造出不同的 spec，不再是「改 JS 模板」。

    优先级（同时给了多个时）：
        1) reg 非空            -> {"kind": "reg", "reg": "x20"}
        2) sp_offset 不为 None -> {"kind": "sp", "offset": 8}
        3) ctx_reg 非空且 offset>0 -> {"kind": "ctx", "ctx": "x20", "offset": 0x6070}
        4) 全空                -> {"kind": "none"}
    """
    r = str(reg or "").strip()
    if r:
        return {"kind": "reg", "reg": r}
    if sp_offset is not None:
        return {"kind": "sp", "offset": int(sp_offset)}
    c = str(ctx_reg or "").strip()
    if c and int(offset or 0) > 0:
        return {"kind": "ctx", "ctx": c, "offset": int(offset)}
    return {"kind": "none"}


def parse_value_expr(expr: str) -> dict:
    """解析「取值表达式」，把用户写的一行字符串变成 spec。

    (4) 第四次修改（2026-11-16）：新增。
        bug 原因：参数化之后，如果每个取值点都要调用方传 3~4 个参数
                  （reg / offset / ctx_reg / sp_offset），接口会变得又长
                  又容易填错，且无法表达 "sp+8" 这种最自然的写法。
        解决方案：让表达式字符串成为**第一等输入**，Python 侧统一解析：
            "x8"             -> 寄存器 x8
            "sp+8" / "sp-16" -> 栈指针加/减偏移
            "ctx+0x6070"     -> ctx 指针加偏移（ctx 默认取 ctx_reg）
            "ctx+x20+0x10"   -> 指定 ctx 所在寄存器再解引用
            "x20+0x6070"     -> 也认：寄存器 + 偏移
            "none" / ""      -> 不取
        **解析失败返回 {"kind": "bad"}**，由调用方明确报错，不静默当成 none
        （静默会让用户以为结构对了，只是没数据）。

    返回 spec：{kind, reg|offset|ctx, raw}
    """
    raw = str(expr or "").strip()
    if not raw or raw.lower() in ("none", "-", "off"):
        return {"kind": "none", "raw": raw}

    low = raw.lower().replace(" ", "")
    # sp+8 / sp-16
    m = re.fullmatch(r"sp([+-])(0x[0-9a-f]+|\d+)", low)
    if m:
        off = int(m.group(2), 16) if m.group(2).startswith("0x") else int(m.group(2))
        return {"kind": "sp", "offset": off if m.group(1) == "+" else -off,
                "raw": raw}
    # ctx+0x6070
    m = re.fullmatch(r"ctx([+-])(0x[0-9a-f]+|\d+)", low)
    if m:
        off = int(m.group(2), 16) if m.group(2).startswith("0x") else int(m.group(2))
        return {"kind": "ctx", "ctx": "", "offset": off if m.group(1) == "+" else -off,
                "raw": raw}
    # ctx+x20+0x10
    m = re.fullmatch(r"ctx\+?(x\d+)([+-])(0x[0-9a-f]+|\d+)", low)
    if m:
        off = int(m.group(3), 16) if m.group(3).startswith("0x") else int(m.group(3))
        return {"kind": "ctx", "ctx": m.group(1),
                "offset": off if m.group(2) == "+" else -off, "raw": raw}
    # x20+0x6070
    m = re.fullmatch(r"(x\d+)([+-])(0x[0-9a-f]+|\d+)", low)
    if m:
        off = int(m.group(3), 16) if m.group(3).startswith("0x") else int(m.group(3))
        return {"kind": "regoff", "reg": m.group(1),
                "offset": off if m.group(2) == "+" else -off, "raw": raw}
    # x8 / w8 / lr / sp
    m = re.fullmatch(r"(x\d+|w\d+|lr|sp|pc|fp)", low)
    if m:
        return {"kind": "reg", "reg": m.group(1), "raw": raw}
    return {"kind": "bad", "raw": raw}


def _js_spec(spec: dict) -> str:
    """把 spec 转成 JS 字面量（json 结构，键名与 JS 侧约定一致）。"""
    return json.dumps(spec if isinstance(spec, dict) else {"kind": "none"})


def _read_so_bytes(so_name: str, so=None) -> bytes:
    """取 so 的原始字节。优先用已加载的 so 对象，其次按路径读。"""
    if so is not None and getattr(so, "_raw", None):
        return so._raw
    if so is not None:
        p = getattr(so, "path", None)
        if p and os.path.isfile(p):
            with open(p, "rb") as fh:
                return fh.read()
    if os.path.isfile(so_name):
        with open(so_name, "rb") as fh:
            return fh.read()
    raise FileNotFoundError(f"读不到 so 字节：{so_name}")


def _lookup_loaded_so(so_name: str):
    """尝试从全局 Session 查找已加载的 SoFile，找不到返回 None。"""
    try:
        from server.mcp_server.tools import get_session

        ses = get_session()
        if ses is not None:
            return ses.get(so_name)
    except Exception:                                     # noqa: BLE001
        return None
    return None


def _file_off_to_vaddr(so, file_off: int) -> int | None:
    """按 SoFile._loads 将 ELF 文件偏移换算为相对模块基址的虚拟地址偏移。"""
    loads = getattr(so, "_loads", None) or []
    if not loads:
        return None
    base_va = min(va for va, _end, _off, _fl in loads)
    for va, end, f_off, _fl in loads:
        filesz = end - va
        if f_off <= file_off < f_off + filesz:
            return (va - base_va) + (file_off - f_off)
    return None


def find_dispatch_points(so_name: str, so=None,
                         pattern_hex: str = VM_DEFAULT_PATTERN,
                         limit: int = 2000) -> dict:
    """扫描 so 里所有 VM 派发段的位置。

    (8) 第八次修改（2026-11-26）
    bug 原因：① 未传 so 时仅按本地文件路径查找，传模块短名（如 libfoo.so）必报
              SO_NOT_READABLE，即便该 so 已加载在全局 Session 中；
              ② 直接把原始文件偏移当运行时虚拟偏移返回，当 PT_LOAD 的 p_vaddr 与
              p_offset 存在页对齐差值时，hook 会落到错误地址。
    解决方案：so 为 None 时优先从 get_session() 查找已加载 SoFile；
              命中文件偏移后按 so._loads 换算为虚拟地址偏移返回（同时保留 file_offset）。

    这是 `vm_breakpoint` 的前置步骤：先知道有哪几个落点，再决定挂哪个。

    返回：{count, points[], note}
    points[]: {offset, offset_hex, file_offset, file_offset_hex}
    """
    if so is None:
        so = _lookup_loaded_so(so_name)
    try:
        data = _read_so_bytes(so_name, so)
    except FileNotFoundError as exc:
        return {"ok": False, "code": "SO_NOT_READABLE", "error": str(exc)}

    try:
        pat = bytes.fromhex(str(pattern_hex).replace(" ", ""))
    except ValueError:
        return {"ok": False, "code": "BAD_PATTERN",
                "error": f"pattern_hex 不是合法十六进制：{pattern_hex}"}
    if not pat:
        return {"ok": False, "code": "BAD_PATTERN", "error": "pattern 不能为空"}

    hits: list[int] = []
    off = 0
    while len(hits) < int(limit):
        i = data.find(pat, off)
        if i < 0:
            break
        hits.append(i)
        off = i + 1

    points = []
    for h in hits:
        vaddr = _file_off_to_vaddr(so, h) if so is not None else None
        eff = vaddr if vaddr is not None else h
        points.append({
            "offset": eff,
            "offset_hex": hex(eff),
            "file_offset": h,
            "file_offset_hex": hex(h),
        })

    return {
        "ok": True,
        "so_name": so_name,
        "pattern": pat.hex(),
        "count": len(points),
        "points": points,
        "note": ("每个点都是「一条 VM 指令执行完、准备派发下一条」的位置。"
                 "挂在这些点上可以做 VM 级单步/断点。"),
    }


def vm_breakpoint(serial: str, pid: int, so_name: str, target_idx: int = -1,
                  code_base: int | str | None = None,
                  vm_pc_bytes: int = 64,
                  dispatch_offset: int | str | None = None,
                  pattern_hex: str = VM_DEFAULT_PATTERN,
                  slot_size: int = VM_DEFAULTS["slot_size"],
                  reg_base_reg: str = VM_DEFAULTS["reg_base_reg"],
                  ip_reg: str = VM_DEFAULTS["ip_reg"],
                  ctx_reg: str = VM_DEFAULTS["ctx_reg"],
                  ip_offset: int = VM_DEFAULTS["ip_offset"],
                  vm_reg_count: int = VM_DEFAULTS["vm_reg_count"],
                  prog_base_p1_offset: int = VM_DEFAULTS["prog_base_p1_offset"],
                  prog_base_p2_offset: int = VM_DEFAULTS["prog_base_p2_offset"],
                  capture_regs: int = 32,
                  stack_bytes: int = 256,
                  hold: bool = True,
                  max_hits: int = 1,
                  wait: float = 10.0,
                  reg_base_offset: int = VM_DEFAULTS["reg_base_offset"],
                  ip_mode: str = VM_DEFAULTS["ip_mode"],
                  opcode_expr: str = VM_DEFAULTS["opcode_expr"],
                  ctx_expr: str = "",
                  hold_timeout_ms: int = 2000) -> dict:
    """在 VM 的某条指令上设断点，停下时给出 VM 寄存器堆与 VM 栈。

    ## 参数

        target_idx       目标 VM 指令序号（如 11068）。**-1 = 不过滤，采所有**
                         **注意**：要按 idx 过滤，必须同时给 code_base；
                         否则无法计算 idx，本工具不会假装过滤（会返回 0 命中）
        code_base        字节码区基址（VM 指令数组起点）。**不给就不算 vm_idx**
        vm_pc_bytes      在 vm_pc 处回读多少字节原始字节码（默认 64）
        dispatch_offset  挂哪个派发点（静态偏移）。
                         不给则自动扫第一个匹配 pattern 的位置。
                         **建议给一个在频繁执行路径上的点**，否则可能长期不命中。
        pattern_hex      派发段特征字节
        slot_size        每条 VM 指令字节数
        reg_base_reg     VM 寄存器堆基址在哪个寄存器（默认 x25）
        reg_base_offset  VM 寄存器堆相对 **ctx** 的偏移（默认 0 = 不用）。
                         **非 0 时优先于 reg_base_reg**：结构体里放着寄存器堆
                         的 VM（实测 ctx+0x6070）用这个，不用找寄存器
        ctx_reg          VM 上下文在哪个寄存器（默认 x27）
        ctx_expr         ctx 指针怎么取，表达式写法（覆盖 ctx_reg）：
                         "x20" / "sp+0x10" / "x20+0x8"
        ip_mode          VM pc 怎么取：
                         "ctx"（默认）= 从 [ctx + ip_offset] 读
                         "reg"        = 直接用 ip_reg 里的值
                         "none"       = 不取（该字段返回 null）
        ip_offset        VM pc 在上下文里的偏移（默认 8）
        opcode_expr      opcode 怎么取：
                         "sp+8"（从栈）/ "x8"（寄存器）/ "ctx+0x100" / ""
                         （"" = 不取，返回 null，不编造）
        vm_reg_count     VM 寄存器个数（默认 32）
        capture_regs     捕获多少个 VM 寄存器（默认 32）
        stack_bytes      额外抓多少字节的 native 栈
        hold             命中时是否挂起（默认 True，需 resume）
        max_hits         最多命中几次后自动放行

    ## 返回

        installed        挂上了几个点
        hits[]           {index, vm_pc, data_base, vm_idx, vm_idx_source,
                          vm_pc_bytes, regs{r0..r31}, ctx, stack_hex}
        verdict

    ## 关键：data_base 与 vm_idx 不是一回事

        data_base = *(*(ctx + 0x240) + 0x1a0)     ← host 全局变量区基址
        vm_pc     = *(ctx + 8)                    ← 下一条要执行的指令地址
        vm_idx    = (vm_pc - code_base) / 16      ← **必须显式给 code_base**

    (6) 第六次修改（2026-11-09）：
        bug 原因：此前把 data_base 当成了 code_base 用来算 vm_idx
                  （字段名还叫 prog_base，更容易误解）。它的推导链末端是
                  `add x0, x8, imm`，加完得到 host 变量地址 —— 说明它指向
                  数据区。拿它减 vm_pc 算出来的「idx」只是碰巧落在某个
                  范围内，不代表指令序号：真机实测 idx=40162 去查镜像，
                  得到 op=4 A=28，不是合法指令边界。
        解决方案：① 字段改名 data_base，保留原值（它对定位 host 变量有用）；
                  ② vm_idx 只在给了 code_base 时才算，否则为 null 并标
                     vm_idx_source="unavailable"；
                  ③ 新增 vm_pc_bytes：回读 vm_pc 处原始字节，调用方拿它
                     去比对镜像，自己反推 code_base（这是目前唯一可靠的
                     定位方式，因为 code_base 在 ctx 里的位置尚未确认）。

    **不要用 vm_pc - so 模块基址**：VM 代码区是 malloc 出来的匿名内存，
    与 so 模块不在一处。

    派发点是在「当前指令执行完、下一条还没执行」的时刻被拦下的。
    所以停在这里读到的 vm_pc 是**下一条**要执行的指令。

    ## 已知边界

        · data_base 的偏移路径（+0x240 / +0x1a0）是参数，换 VM 可改
        · **不传 code_base 时 vm_idx 为 null**：这是刻意为之，
          data_base 不能算出指令序号（见上文「data_base 与 vm_idx 不是一回事」）
        · 派发点有几百个，**只挂一个**：挂在哪个点就只能看到经过那个点的指令。
          如果目标 idx 的执行路径不经过这个点，会一直不命中——
          这时换一个点（或告诉我执行路径，我帮你选）
        · 不改变目标行为，只读不写
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # (2) 第二次修改（2026-11-09）：code_base 不再是必需参数。
    #     bug 原因：原来要求调用方给 code_base，但 VM 代码区是 malloc 出来的
    #               匿名内存，和 so 模块基址不在一处，调用方根本无从得知。
    #     解决方案：改为运行时解引用 *(*(ctx + 0x240) + 0x1a0) 得到基址。
    #
    # (7) 第七次修改（2026-11-09）——上面那条方案被实测推翻：
    #     bug 原因：那个地址推导链末端是 `add host_var, base, imm`，加完是
    #               host 变量地址，说明它是**数据区**基址，不是字节码区。
    #               用它算 vm_idx 得到的数没有意义（真机实测查镜像对不上）。
    #     解决方案：该值改名 data_base 并原样返回；vm_idx 恢复为「只在调用方
    #               显式给 code_base 时才算」，同时回读 vm_pc 处原始字节，
    #               让调用方自己比对镜像反推真正的 code_base。

    if int(slot_size) not in (8, 16, 32):
        return {"ok": False, "code": "BAD_SLOT_SIZE",
                "error": f"slot_size 应为 8/16/32，收到 {slot_size}"}

    # (4) 第四次修改（2026-11-16）：把「从哪取」变成 spec，先在这里解析并校验。
    #     bug 原因：参数化后 opcode_expr / ctx_expr 是自由文本，写错时
    #               若静默退化成 none，用户会以为"结构对了只是没数据"，
    #               实际是表达式拼错——这正是最难排的一类问题。
    #     解决方案：解析失败直接返回 BAD_EXPR 并说明正确写法，
    #               不进 JS、不 attach，避免"跑一遍才发现没数据"。
    if str(ip_mode).lower() not in ("ctx", "reg", "none"):
        return {"ok": False, "code": "BAD_IP_MODE",
                "error": f"ip_mode 应为 ctx/reg/none，收到 {ip_mode!r}"}

    opcode_spec = parse_value_expr(opcode_expr)
    if opcode_spec["kind"] == "bad":
        return {"ok": False, "code": "BAD_EXPR",
                "error": (f"opcode_expr 无法解析：{opcode_expr!r}"),
                "hint": '支持写法："sp+8" / "x8" / "ctx+0x100" / ""（不取）'}
    if ctx_expr:
        ctx_spec = parse_value_expr(ctx_expr)
        if ctx_spec["kind"] == "bad":
            return {"ok": False, "code": "BAD_EXPR",
                    "error": f"ctx_expr 无法解析：{ctx_expr!r}",
                    "hint": '支持写法："x20" / "sp+0x10" / "x20+0x8"'}
    else:
        ctx_spec = {"kind": "reg", "reg": str(ctx_reg)}

    # (8) 第八次修改（2026-11-26）
    # bug 原因：dispatch_offset 为空串 "" 时 `is not None` 为真，直接进 int("", 16)
    #           报 BAD_DISPATCH_OFFSET，无法触发自动扫描；且自动扫描未传入已加载的 SoFile。
    # 解决方案：空串与 None 等价触发自动扫描；解析走 parse_addr；自动扫描先查 get_session()。
    disp = None
    if dispatch_offset is not None and str(dispatch_offset).strip() != "":
        from server.core.addr import parse_addr

        disp = parse_addr(dispatch_offset, default=None)
        if disp is None:
            return {"ok": False, "code": "BAD_DISPATCH_OFFSET",
                    "error": f"dispatch_offset 无法解析：{dispatch_offset!r}"}
    else:
        loaded_so = _lookup_loaded_so(so_name)
        scan = find_dispatch_points(so_name, so=loaded_so,
                                    pattern_hex=pattern_hex, limit=1)
        if not scan.get("ok") or not scan.get("points"):
            return {"ok": False, "code": "NO_DISPATCH_POINT",
                    "error": "没有扫到派发点；确认 so 与 pattern 是否匹配",
                    "scan": scan}
        disp = scan["points"][0]["offset"]

    user_js = _JS_VM_BREAK
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__TARGET_IDX__", str(int(target_idx))),
        ("__SLOT_SIZE__", str(int(slot_size))),
        ("__P1_OFF__", str(int(prog_base_p1_offset))),
        ("__P2_OFF__", str(int(prog_base_p2_offset))),
        ("__REG_BASE_REG__", _js_str(reg_base_reg)),
        ("__REG_BASE_OFFSET__", str(int(reg_base_offset))),
        ("__IP_REG__", _js_str(ip_reg)),
        ("__CTX_REG__", _js_str(ctx_reg)),
        ("__CTX_SPEC__", _js_spec(ctx_spec)),
        ("__IP_MODE__", _js_str(str(ip_mode).lower())),
        ("__OPCODE_SPEC__", _js_spec(opcode_spec)),
        ("__IP_OFFSET__", str(int(ip_offset))),
        ("__VM_REG_COUNT__", str(int(vm_reg_count))),
        ("__CAPTURE_REGS__", str(int(capture_regs))),
        ("__STACK_BYTES__", str(int(stack_bytes))),
        ("__HOLD__", "true" if hold else "false"),
        ("__HOLD_TIMEOUT_MS__", str(max(100, min(int(hold_timeout_ms or 2000), 30000)))),
        ("__MAX_HITS__", str(max(1, int(max_hits)))),
        # (5) 第五次修改（2026-11-09）：
        #     bug 原因：code_base 参数一直只躺在签名里，从未传给 JS
        #               （grep CODE_BASE 无结果），调用方传了也被静默忽略。
        #     解决方案：真正注入；没给就传 null，JS 侧据此不计算 vm_idx。
        ("__CODE_BASE__", _js_code_base(code_base)),
        ("__VM_PC_BYTES__", str(int(vm_pc_bytes))),
        # (4) 第四次修改（2026-11-16）：spec 取值辅助层只写一份，
        #     由三个模板共用，避免各写一套导致行为漂移。
        ("__SPEC_HELPERS__", _JS_SPEC_HELPERS),
    ):
        user_js = user_js.replace(k, v)

    return _run_vm_break(serial, int(pid), so_name, user_js,
                         hold=bool(hold), max_hits=int(max_hits),
                         wait=float(wait),
                         target_idx=int(target_idx),
                         slot_size=int(slot_size),
                         hold_timeout_ms=max(100, min(int(hold_timeout_ms or 2000), 30000)))


_JS_SPEC_HELPERS = r"""
    // ---------------- 统一取值层（spec → 值） ----------------
    //
    // (4) 第四次修改（2026-11-16）：新增。
    //     bug 原因：三个 JS 模板各自硬编码「ctx 在 x27 / VM pc 在 [ctx+8] /
    //               寄存器堆在 x25」，换一个 VM 就得改模板，改漏一处
    //               就静默读错或干脆不命中，而调用方看到的是"0 命中"。
    //     解决方案：把「从哪取」收敛成 resolveValue()，只按 spec.kind 分支。
    //               模板里从此不再出现任何具体寄存器名或结构偏移常量。
    //
    // spec 形态（由 Python 侧 parse_value_expr / _spec_from_args 产出）：
    //     {kind:'reg',    reg:'x20'}
    //     {kind:'sp',     offset:8}
    //     {kind:'ctx',    offset:0x6070}          // ctx 由调用方先解出
    //     {kind:'regoff', reg:'x20', offset:8}
    //     {kind:'none'}
    // (8) 第八次修改（2026-11-26）
    // bug 原因：① regOf 不认识 w0..w30，Frida ARM64 context 只有 x0..x30，读 wN 恒返 null；
    //           ② opcode_expr 为寄存器（kind === 'reg'）时直接对其调用 readScalar(opRes.ptr)
    //              解引用内存（把标量数值当地址读 U64），必然访问违例读不到 opcode。
    // 解决方案：① regOf 识别 /^w(\d+)$/ 并读 c['x'+idx].and(0xffffffff)；
    //           ② 新增 scalarFromReg 直接把寄存器 NativePointer/数值转为标量，绝不解引用内存。
    function regOf(c, name) {
        if (!name) { return null; }
        var n = String(name).toLowerCase();
        try {
            if (n === 'sp') { return c.sp; }
            if (n === 'pc') { return c.pc; }
            if (n === 'lr') { return c.lr; }
            if (n === 'fp') { return c.fp; }
            var wm = /^w(\d+)$/.exec(n);
            if (wm) {
                var idx = parseInt(wm[1], 10);
                if (idx >= 0 && idx <= 30) {
                    var xv = c['x' + idx];
                    if (xv === undefined || xv === null) { return null; }
                    return (typeof xv.and === 'function') ? xv.and(0xffffffff) : ptr(Number(xv) >>> 0);
                }
            }
            var v = c[n];
            return (v === undefined || v === null) ? null : v;
        } catch (e) { return null; }
    }

    // 返回 {ptr, src, err}：取不到时 ptr=null 且 err 写明原因，**不伪造地址**
    function resolveValue(c, spec, ctxp) {
        if (!spec || spec.kind === 'none') { return {ptr: null, src: 'none', err: ''}; }
        try {
            if (spec.kind === 'reg') {
                var p = regOf(c, spec.reg);
                if (p === null) { return {ptr: null, src: 'reg:' + spec.reg,
                                          err: '寄存器无值 ' + spec.reg}; }
                return {ptr: p, src: 'reg:' + spec.reg, err: ''};
            }
            if (spec.kind === 'sp') {
                return {ptr: c.sp.add(spec.offset),
                        src: 'sp' + (spec.offset >= 0 ? '+' : '') + spec.offset, err: ''};
            }
            if (spec.kind === 'ctx') {
                // (4) 第四次修改（2026-11-16）：spec 自带 ctx 寄存器名时以它为准
                //     （"ctx+x20+0x10" 这种写法），否则用调用方已解出的 ctxp。
                //     原来两种写法会得到同一个结果，等于表达式白写。
                var base = ctxp;
                if (spec.ctx) {
                    base = regOf(c, spec.ctx);
                    if (base === null) {
                        return {ptr: null, src: 'ctx:' + spec.ctx,
                                err: 'ctx 寄存器无值 ' + spec.ctx};
                    }
                }
                if (base === null || base === undefined) {
                    return {ptr: null, src: 'ctx', err: 'ctx 不可用，无法按 ctx 取偏移'};
                }
                return {ptr: base.add(spec.offset),
                        src: (spec.ctx ? spec.ctx + '+' : 'ctx+')
                             + '0x' + (spec.offset >>> 0).toString(16), err: ''};
            }
            if (spec.kind === 'regoff') {
                var rp = regOf(c, spec.reg);
                if (rp === null) { return {ptr: null, src: 'regoff',
                                           err: '寄存器无值 ' + spec.reg}; }
                return {ptr: rp.add(spec.offset),
                        src: spec.reg + '+' + spec.offset, err: ''};
            }
        } catch (e) {
            return {ptr: null, src: spec.kind, err: String(e)};
        }
        return {ptr: null, src: 'bad', err: '未知 spec.kind: ' + spec.kind};
    }

    // 读一个标量（opcode / 字段值）。返回 {n, s, err}：
    //   s 是**精确十进制字符串**（64 位不丢精度），n 只有在能安全转成
    //   JS number 时才给，否则为 null —— 不把大整数截断后当成真值。
    function readScalar(p) {
        try {
            var s = p.readU64().toString();
            var n = Number(s);
            if (!isFinite(n) || Math.abs(n) > 9007199254740991) { n = null; }
            return {n: n, s: s, err: ''};
        } catch (e) { return {n: null, s: null, err: String(e)}; }
    }

    // 寄存器标量直接转数值（绝不解引用内存），供 spec.kind === 'reg' 使用
    function scalarFromReg(p) {
        try {
            var s = BigInt(p.toString()).toString(10);
            var n = Number(s);
            if (!isFinite(n) || Math.abs(n) > 9007199254740991) { n = null; }
            return {n: n, s: s, err: ''};
        } catch (e) {
            try {
                var hs = p.toString();
                var n2 = parseInt(hs, 16);
                if (!isFinite(n2) || Math.abs(n2) > 9007199254740991) { n2 = null; }
                return {n: n2, s: hs, err: ''};
            } catch (e2) {
                return {n: null, s: null, err: String(e2)};
            }
        }
    }

    function hexOf(ptr) {
        return (ptr === null || ptr === undefined) ? null : ptr.toString();
    }
"""


_JS_VM_BREAK = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    var TARGET_IDX = __TARGET_IDX__;
    var SLOT_SIZE = __SLOT_SIZE__;
    var REG_BASE_REG = __REG_BASE_REG__;
    var REG_BASE_OFFSET = __REG_BASE_OFFSET__;
    var IP_REG = __IP_REG__;
    var CTX_REG = __CTX_REG__;
    var CTX_SPEC = __CTX_SPEC__;
    var IP_MODE = __IP_MODE__;
    var OPCODE_SPEC = __OPCODE_SPEC__;
    var IP_OFFSET = __IP_OFFSET__;
    var P1_OFF = __P1_OFF__;
    var P2_OFF = __P2_OFF__;
    var VM_REG_COUNT = __VM_REG_COUNT__;
    var CAPTURE_REGS = __CAPTURE_REGS__;
    var STACK_BYTES = __STACK_BYTES__;
    var HOLD = __HOLD__;
    var HOLD_TIMEOUT_MS = __HOLD_TIMEOUT_MS__;
    var MAX_HITS = __MAX_HITS__;
    // 显式字节码基址；null 表示调用方没给（那就不会算 vm_idx）
    var CODE_BASE = __CODE_BASE__;
    // vm_pc 处回读多少字节原始字节码（供调用方比对镜像）
    var VM_PC_BYTES = __VM_PC_BYTES__;
__SPEC_HELPERS__
    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', code: 'SO_NOT_FOUND', error: '模块未加载：' + SO_NAME});
        return;
    }

    var addr = mod.base.add(DISPATCH_OFFSET);
    var hitCount = 0;
    var ctxFail = 0;
    var ipFail = 0;
    var listener = null;

    function readVmRegs(basePtr) {
        var out = {};
        var n = Math.min(CAPTURE_REGS, VM_REG_COUNT);
        for (var i = 0; i < n; i++) {
            try { out['r' + i] = basePtr.add(i * 8).readPointer().toString(); }
            catch (e) { out['r' + i] = null; }
        }
        return out;
    }

    // data_base = *(*(ctx + P1_OFF) + P2_OFF)
    // 指向 host 全局变量区（推导链末端是 add host_var, imm），**不是**字节码区。
    // P1_OFF < 0 表示本 VM 没有这条路径 —— 直接返回 null，不硬读。
    function readDataBase(ctxp) {
        if (ctxp === null || P1_OFF < 0) { return null; }
        try {
            var p1 = ctxp.add(P1_OFF).readPointer();
            return p1.add(P2_OFF).readPointer();
        } catch (e) { return null; }
    }

    // VM pc 的取法由 IP_MODE 决定（ctx / reg / none），不再写死 [ctx+8]。
    function readVmPc(c, ctxp) {
        if (IP_MODE === 'none') { return {ptr: null, src: 'none'}; }
        if (IP_MODE === 'reg') {
            var p = regOf(c, IP_REG);
            return {ptr: p, src: p === null ? 'reg-missing' : 'reg:' + IP_REG};
        }
        if (ctxp === null) { return {ptr: null, src: 'ctx-missing'}; }
        try {
            return {ptr: ctxp.add(IP_OFFSET).readPointer(),
                    src: 'ctx+0x' + IP_OFFSET.toString(16)};
        } catch (e) { return {ptr: null, src: 'ctx-read-failed'}; }
    }

    listener = Interceptor.attach(addr, {
        onEnter: function () {
            var c = this.context;
            var ctxRes = resolveValue(c, CTX_SPEC, null);
            var ctxp = ctxRes.ptr;
            // ctx 是必须的（配置了却取不到 = 配置/结构不匹配），跳过并计数，
            // 在 stop 时如实报告，不静默当成"0 命中"。
            var ctxRequired = (CTX_SPEC.kind !== 'none') || (IP_MODE === 'ctx')
                              || (REG_BASE_OFFSET > 0)
                              || (OPCODE_SPEC.kind === 'ctx');
            if (ctxp === null && ctxRequired) { ctxFail++; return; }

            var ipRes = readVmPc(c, ctxp);
            var vmPc = ipRes.ptr;
            if (vmPc === null && IP_MODE !== 'none') {
                // ip_mode=ctx 时 vmPc 读失败 = 结构不符，跳过计数
                if (IP_MODE === 'ctx') { ipFail++; return; }
            }

            // 寄存器堆：给了 reg_base_offset(>0) 就按 ctx+offset 取（结构体内嵌），
            // 否则按 reg_base_reg 从寄存器取。两条路都不写死具体寄存器名。
            var regbase = null;
            var regBaseSrc = 'none';
            if (REG_BASE_OFFSET > 0) {
                if (ctxp !== null) {
                    regbase = ctxp.add(REG_BASE_OFFSET);
                    regBaseSrc = 'ctx+0x' + REG_BASE_OFFSET.toString(16);
                }
            } else if (REG_BASE_REG) {
                regbase = regOf(c, REG_BASE_REG);
                regBaseSrc = regbase === null ? 'reg-missing' : 'reg:' + REG_BASE_REG;
            }

            // opcode：按 OPCODE_SPEC 取（"sp+8" / "x8" / "ctx+0x100"），
            // 取不到就是 null，不编造。kind==='reg' 时寄存器装的是标量本身，绝不解引用。
            var opcodeVal = null;
            var opcodeSrc = 'none';
            if (OPCODE_SPEC.kind !== 'none') {
                var opRes = resolveValue(c, OPCODE_SPEC, ctxp);
                opcodeSrc = opRes.src;
                if (opRes.ptr !== null) {
                    var sv = (OPCODE_SPEC.kind === 'reg')
                        ? scalarFromReg(opRes.ptr) : readScalar(opRes.ptr);
                    opcodeVal = (sv.n !== null) ? sv.n : sv.s;
                }
            }

            // data_base = *(*(ctx+P1_OFF)+P2_OFF)
            //
            // (3) 第三次修改（2026-11-09）：
            //     bug 原因：这个值原名叫 prog_base，被当成「字节码区基址」用来
            //               算 vm_idx。但它的推导链末端是 `add x0, x8, imm`
            //               ——加完得到的是 host 变量地址，说明它指向**数据区**，
            //               不是字节码区。用它减 vm_pc 没有意义，算出的 idx 只是
            //               「落在某个范围里」，不代表指令序号（真机实测过
            //               idx=40162 查镜像得到 op=4 A=28，不是合法指令边界）。
            //     解决方案：改名 data_base 并原样返回（它对定位 host 变量有用）；
            //               vm_idx 只在调用方显式给 code_base 时才计算，
            //               否则返回 null 并注明 unavailable。不给假数字。
            var dataBase = readDataBase(ctxp);

            // 在 vm_pc 处读一段原始字节，供调用方自己比对镜像、反推 code_base。
            // 这是「不知道 code_base」时的唯一可靠出路：给出原料，不猜结论。
            var codeBytes = null;
            if (vmPc !== null) {
                try {
                    var nSlots = VM_PC_BYTES / SLOT_SIZE;
                    codeBytes = Array.from(new Uint8Array(vmPc.readByteArray(nSlots * SLOT_SIZE)))
                        .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                        .join('');
                } catch (e) { codeBytes = null; }
            }

            // idx 只认显式 code_base
            var idx = null;
            var idxSource = 'unavailable';
            if (CODE_BASE !== null && CODE_BASE !== 0 && CODE_BASE !== '' && vmPc !== null) {
                // (4) 第四次修改（2026-11-09）：
                //     bug 原因：原来用 vmPc.sub(base).toInt32()，toInt32 会把
                //               64 位差值截断成 32 位；当 code_base 与 vm_pc 的
                //               跨度超过 ±2GB（不同 mmap 段很常见）时会溢出成错值。
                //     解决方案：用十进制字符串转 BigInt 相减，再整除 slot_size。
                //               这样任意跨度都精确，且不依赖 frida 的 32 位转换。
                var big = null;
                try {
                    big = BigInt(vmPc.toString()) - BigInt(ptr(CODE_BASE).toString());
                } catch (e) { big = null; }
                if (big !== null) {
                    var q = big / BigInt(SLOT_SIZE);
                    var r = big % BigInt(SLOT_SIZE);
                    idx = Number(q) + Number(r) / SLOT_SIZE;
                    idxSource = 'code_base';
                }
            }

            // 给了 target_idx 但没给 code_base 时无法过滤：
            // 不假装过滤（那会静默返回 0 命中，让人以为是位置不对）
            if (TARGET_IDX >= 0) {
                if (idx === null) { return; }
                if (idx !== TARGET_IDX) { return; }
            }

            hitCount++;
            var rec = {
                kind: 'vm_hit',
                index: hitCount,
                vm_pc: hexOf(vmPc),
                ip_source: ipRes.src,
                opcode: opcodeVal,
                opcode_source: opcodeSrc,
                data_base: hexOf(dataBase),
                vm_idx: idx,
                vm_idx_source: idxSource,
                vm_pc_bytes: codeBytes,
                native_pc: c.pc.toString(),
                dispatch_addr: addr.toString(),
                ctx: hexOf(ctxp),
                ctx_source: ctxRes.src,
                reg_base: hexOf(regbase),
                reg_base_source: regBaseSrc
            };
            if (regbase !== null) { rec.regs = readVmRegs(regbase); }
            try {
                rec.stack_hex = Array.from(new Uint8Array(
                    c.sp.readByteArray(Math.min(STACK_BYTES, 1024))))
                    .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                    .join('');
            } catch (e) { rec.stack_hex = null; }

            // (8) 第八次修改（2026-11-26）：真实现 HOLD 挂起与放行协议。
            // bug 原因：原模板未声明 __HOLD__，hold=True 只是空占位符，命中后直接继续跑。
            // 解决方案：HOLD 为真时给命中记录打上 held=true 与 hold_token，发送现场后通过
            //           recv('resume', ...).wait() 真正阻塞当前目标线程，直到收到 Python 侧
            //           resume 指令或超时兜底放行，防止 ANR 死锁。
            var holdToken = HOLD ? ('vmh_' + hitCount + '_' + this.threadId) : null;
            rec.held = Boolean(HOLD);
            rec.hold_token = holdToken;
            send(rec);

            if (HOLD) {
                var released = false;
                var releaseReason = 'resumed';
                var timer = null;
                if (HOLD_TIMEOUT_MS > 0) {
                    timer = setTimeout(function () {
                        if (!released) {
                            released = true;
                            releaseReason = 'hold_timeout';
                            send({kind: 'vm_hold_timeout', token: holdToken,
                                  hold_timeout_ms: HOLD_TIMEOUT_MS});
                        }
                    }, HOLD_TIMEOUT_MS);
                }
                try {
                    var op = recv('resume', function (msg) {
                        if (!released) {
                            released = true;
                            releaseReason = (msg && msg.reason) ? String(msg.reason) : 'resumed';
                        }
                    });
                    op.wait();
                } catch (eHold) {
                    releaseReason = 'hold_error:' + String(eHold);
                }
                if (timer !== null) { try { clearTimeout(timer); } catch (eT) {} }
                send({kind: 'vm_resumed', token: holdToken, reason: releaseReason});
            }

            if (hitCount >= MAX_HITS && listener !== null) {
                listener.detach();
                listener = null;
            }
        }
    });

    send({kind: 'installed', dispatch_addr: addr.toString(),
          dispatch_offset: DISPATCH_OFFSET, target_idx: TARGET_IDX,
          module_base: mod.base.toString(), module: mod.name,
          code_base_used: CODE_BASE,
          layout: {ctx: CTX_SPEC, ip_mode: IP_MODE, ip_reg: IP_REG,
                   ip_offset: IP_OFFSET, opcode: OPCODE_SPEC,
                   reg_base_reg: REG_BASE_REG,
                   reg_base_offset: REG_BASE_OFFSET},
          data_base_path: (P1_OFF < 0) ? 'disabled'
                          : '*(*(ctx+0x' + P1_OFF.toString(16) + ')+0x'
                            + P2_OFF.toString(16) + ')'});

    recv('stop', function () {
        if (listener !== null) { try { listener.detach(); } catch (e) {} }
        send({kind: 'stopped', hits: hitCount, ctx_fail: ctxFail,
              ip_fail: ipFail});
    });
})();
"""


def _js_str(s) -> str:
    import json as _json

    return _json.dumps(str(s))


def _js_code_base(code_base) -> str:
    """把 code_base 转成 JS 字面量：没给就是 null。

    (8) 第八次修改（2026-11-26）
    bug 原因：原实现直接 return str(v)，遇到 ARM64 64 位 TBI 指针（如 0xb400007d8780a000，
              超过 JS Number 安全整数上限 2^53-1）时会被 JS 浮点舍入截断低位，
              导致 ptr(CODE_BASE) 算出的 vm_idx 错位。
    解决方案：超过 2^53-1 (0x1fffffffffffff) 的 64 位地址输出 "0x..." 字符串字面量，
              由 JS 侧 ptr("0x...") 无损解析；安全整数范围内保留十进制数字。

    支持 int 与 "0x..." / "12345" 字符串。给不出合法值一律当 null，
    宁可不算 idx，也不注入一个错的基址。
    """
    if code_base is None or code_base == "":
        return "null"
    try:
        v = int(code_base, 16) if isinstance(code_base, str) \
            and code_base.lower().startswith("0x") else int(code_base)
    except (TypeError, ValueError):
        return "null"
    if v <= 0:
        return "null"
    if v > 0x1FFFFFFFFFFFFF:
        return json.dumps(f"0x{v:x}")
    return str(v)


def _detach_async(sess, timeout: float = 2.0) -> None:
    """守护线程里 detach（本设备上同步 detach 会永久阻塞）。"""
    import threading as _th

    if sess is None:
        return

    def _w() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass

    t = _th.Thread(target=_w, name="mda-vm-detach", daemon=True)
    t.start()
    try:
        t.join(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


def _run_vm_break(serial: str, pid: int, so_name: str, user_js: str,
                  hold: bool = True, max_hits: int = 1,
                  wait: float = 10.0,
                  target_idx: int = -1,
                  slot_size: int = 16,
                  hold_timeout_ms: int = 2000) -> dict:
    """注入 VM 断点脚本并等待命中。

    (1) 第一次修改（2026-11-09）：
        bug 原因：本函数末尾的 verdict 文案里引用了 `target_idx`，但本函数
                  签名里没有这个参数（它只是 vm_breakpoint 的形参，没往下传）。
                  于是**只要一次都没命中**，走到 `elif not box["hits"]` 分支
                  就会抛 `NameError: name 'target_idx' is not defined`，
                  被外层 except 包成 VM_BREAK_FAILED。
                  表现为：target_idx 给任何值（含 -1）都报同一个 NameError。
        解决方案：把 target_idx / slot_size 显式传进来，供文案与诊断使用。

    (8) 第八次修改（2026-11-26）：配合 _JS_VM_BREAK 的 HOLD 挂起协议。
        bug 原因：原实现仅传 hold 形参但从不处理 resume，导致模板无法安全挂起。
        解决方案：收到 held=True 的命中后记录挂起令牌；单次会话收尾或超时前
                  显式 post({"type": "resume", ...}) 放行目标线程，防止 ANR 死锁，
                  并在返回值里如实报告 hold_requested / held_count / resumed_events。
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # 把 SO_NAME 换成实际模块名（脚本里用 SO_NAME 占位）
    script_src = user_js.replace("SO_NAME", _js_str(so_name))

    sess = None
    script = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(script_src)
        box: dict = {"installed": None, "hits": [], "error": None,
                     "stopped": False, "held_tokens": [], "resumed": [],
                     "hold_timeouts": []}

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["error"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "installed":
                box["installed"] = payload
            elif kind == "vm_hit":
                box["hits"].append(payload)
                if payload.get("held") and payload.get("hold_token"):
                    box["held_tokens"].append(payload["hold_token"])
            elif kind == "vm_resumed":
                box["resumed"].append(payload)
            elif kind == "vm_hold_timeout":
                box["hold_timeouts"].append(payload)
                # 超时通知到来时立即补发 resume 解除 recv().wait() 阻塞
                try:
                    script.post({"type": "resume",
                                 "token": payload.get("token"),
                                 "reason": "hold_timeout"})
                except Exception:                         # noqa: BLE001
                    pass
            elif kind == "stopped":
                box["stopped"] = True
                # (4) 第四次修改（2026-11-16）：
                #     bug 原因：命中 0 次时，原实现只能把「指令没执行 / 派发点
                #               不在路径上 / 会话失效」三种可能都列出来让用户猜。
                #               参数化之后多了一种**确定性**原因：结构配置不符
                #               （ctx 取不到、VM pc 读失败），这时本该直接说清楚。
                #     解决方案：JS 侧统计 ctx 取失败 / ip 读失败次数，
                #               在 stop 时回传；这里落进 box 供后续 verdict 判定。
                box["ctx_fail"] = int(payload.get("ctx_fail") or 0)
                box["ip_fail"] = int(payload.get("ip_fail") or 0)
            elif kind == "error":
                box["error"] = payload.get("error") or "未知错误"
                box["error_code"] = payload.get("code")

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while _time.time() - t0 < float(wait):
            if box["error"]:
                break
            if len(box["hits"]) >= max(1, max_hits):
                break
            # 多命中 hold 场景：收到前几次命中并完成采集后立即放行以等待后续命中
            if hold and len(box["held_tokens"]) > len(box["resumed"]) and max_hits > 1:
                tok = box["held_tokens"][len(box["resumed"])]
                try:
                    script.post({"type": "resume", "token": tok,
                                 "reason": "next_hit"})
                except Exception:                         # noqa: BLE001
                    pass
            _time.sleep(0.05)

        # 收尾前放行所有仍处于挂起态的线程，避免单次会话结束导致目标 ANR
        if hold and box["held_tokens"]:
            pending = max(0, len(box["held_tokens"]) - len(box["resumed"]))
            for _ in range(pending):
                try:
                    script.post({"type": "resume",
                                 "reason": "auto_release_oneshot"})
                except Exception:                         # noqa: BLE001
                    pass
            t_rel = _time.time()
            while _time.time() - t_rel < 0.5 and len(box["resumed"]) < len(box["held_tokens"]):
                _time.sleep(0.02)

        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        _time.sleep(0.2)
    except Exception as exc:                              # noqa: BLE001
        probe = None
        try:
            from server.dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception:                                 # noqa: BLE001
            probe = None
        code = "VM_BREAK_FAILED"
        msg = f"{type(exc).__name__}: {exc}"
        if probe and probe.get("alive") is False:
            code = "TARGET_DIED"
            msg += f"；进程 {pid} 已不存在"
        return {"ok": False, "code": code, "error": msg,
                "process_probe": probe}
    finally:
        _detach_async(sess)

    out: dict = {
        "ok": box["error"] is None,
        "installed": box["installed"],
        "hit_count": len(box["hits"]),
        "hits": box["hits"],
        "hold_requested": bool(hold),
        "held_count": len(box["held_tokens"]),
        "hold_timeout_ms": int(hold_timeout_ms),
    }
    if box["resumed"]:
        out["resumed_events"] = box["resumed"]
    if hold and box["hits"]:
        out["hold_note"] = (
            "命中后已通过 recv('resume').wait() 挂起目标线程并抓齐快照，"
            f"随后在单次会话结束前自动发送 resume 放行（防 ANR 超时 {int(hold_timeout_ms)}ms）；"
            "如需跨工具调用持久暂停，请使用持久会话断点 set_breakpoint(hold=True)。"
        )
    if box["error"]:
        out["code"] = box.get("error_code") or "VM_BREAK_FAILED"
        out["error"] = box["error"]
    elif not box["hits"]:
        # (2) 第二次修改（2026-11-09）：
        #     bug 原因：原提示只讲了「该指令没被执行」和「派发点不在路径上」，
        #               但真机排障时最常见的是第三种：进程还活着、frida 会话
        #               却是旧的（attach 到已失效会话后一切静默）。
        #     解决方案：把这条也写进 hint，并明确指出 target_idx 过滤只在
        #               code_base 已知时才有意义。
        ctx_fail = int(box.get("ctx_fail") or 0)
        ip_fail = int(box.get("ip_fail") or 0)
        out["ctx_fail"] = ctx_fail
        out["ip_fail"] = ip_fail
        if ctx_fail or ip_fail:
            # (4) 第四次修改（2026-11-16）：结构不符是**确定性**原因，
            #     不该和"没执行"混在一条模糊提示里。
            #     bug 原因：参数化后，ctx 取不到 / VM pc 读失败会表现为
            #               "命中 0 次"，与"VM 没跑"完全同形，用户无从区分。
            #     解决方案：JS 侧计数并在 stop 回传；这里优先判定为结构不符，
            #               直接指出该改哪个参数。
            out["verdict"] = (
                f"派发点被命中 {ctx_fail + ip_fail} 次，但每次都取不到"
                f"关键字段（ctx 失败 {ctx_fail} 次 / VM pc 失败 {ip_fail} 次）。"
                "**这是结构配置不符，不是 VM 没运行**")
            out["hint"] = (
                "按失败项改参数：① 取不到 ctx → 检查 ctx_reg / ctx_expr"
                "（用 probe_hits 的 capture_regs 看哪个寄存器像是结构体指针）；"
                "② 取不到 VM pc → 改 ip_mode=reg 并指定 ip_reg，或改 ip_offset")
            return out
        out["verdict"] = (f"{wait:.0f}s 内没有命中 idx={target_idx}。"
                          "可能原因：① 该指令在当前操作下没被执行；"
                          "② 挂的派发点不在它的执行路径上"
                          "（805 个点里只挂了 1 个）；"
                          "③ 进程虽在，但 frida 会话已失效（旧进程残留）")
        out["hint"] = ("先用 vm_regs_snapshot 确认这条链路是活的"
                       "（它能给 vm_pc 就说明会话正常）；"
                       "再挑一个在活跃路径上的派发点；"
                       "或把 target_idx 设成 -1（不过滤，采所有遇到的 idx）")
        out["target_idx_used"] = target_idx
        out["slot_size_used"] = slot_size
    else:
        h0 = box["hits"][0]
        src = h0.get("vm_idx_source") or "unknown"
        out["verdict"] = (f"命中 {len(box['hits'])} 次，"
                          f"VM pc={h0.get('vm_pc')} "
                          f"idx={h0.get('vm_idx')}（来源 {src}）")
    return out


def vm_regs_snapshot(serial: str, pid: int, so_name: str,
                     dispatch_offset: int | str | None = None,
                     pattern_hex: str = VM_DEFAULT_PATTERN,
                     capture_regs: int = 32,
                     wait: float = 3.0,
                     reg_base_reg: str = VM_DEFAULTS["reg_base_reg"],
                     reg_base_offset: int = VM_DEFAULTS["reg_base_offset"],
                     ctx_reg: str = VM_DEFAULTS["ctx_reg"],
                     ctx_expr: str = "",
                     ip_mode: str = VM_DEFAULTS["ip_mode"],
                     ip_reg: str = VM_DEFAULTS["ip_reg"],
                     ip_offset: int = VM_DEFAULTS["ip_offset"],
                     opcode_expr: str = VM_DEFAULTS["opcode_expr"],
                     vm_reg_count: int = VM_DEFAULTS["vm_reg_count"]) -> dict:
    """在派发点抓一次 VM 寄存器堆快照（不判断 idx）。

    用途：不确定 code_base 时，先用它把「当前 VM pc」打出来，
    再对照代码区基址反推。

    ## (4) 第四次修改（2026-11-16）参数化

        bug 原因：原实现把寄存器约定**写死**在函数体里（reg_base_reg/ctx_reg/
                  ip_reg/ip_offset 全取 VM_DEFAULTS，不对外开放），
                  换一个 VM 时用户即使知道结构也没法告诉工具。
                  而且它只认「寄存器堆在某个寄存器里」这一种布局，
                  结构体内嵌寄存器堆（ctx+0x6070）的 VM 完全取不到。
        解决方案：把四个取值点全部提成参数，并复用 parse_value_expr 的表达式
                  写法；未传时取 VM_DEFAULTS，**与原行为逐字节一致**。

    ## 参数

        reg_base_reg / reg_base_offset  寄存器堆来源（偏移>0 时优先按 ctx 取）
        ctx_reg / ctx_expr              ctx 来源
        ip_mode / ip_reg / ip_offset    VM pc 来源（ctx / reg / none）
        opcode_expr                     opcode 来源（"sp+8" / "x8" / "ctx+0x100"）

    返回：{ok, vm_pc, ctx, regs{r0..r31}, stack_hex, ...来源标注}
    """
    try:
        import frida                                     # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    if str(ip_mode).lower() not in ("ctx", "reg", "none"):
        return {"ok": False, "code": "BAD_IP_MODE",
                "error": f"ip_mode 应为 ctx/reg/none，收到 {ip_mode!r}"}

    opcode_spec = parse_value_expr(opcode_expr)
    if opcode_spec["kind"] == "bad":
        return {"ok": False, "code": "BAD_EXPR",
                "error": f"opcode_expr 无法解析：{opcode_expr!r}",
                "hint": '支持写法："sp+8" / "x8" / "ctx+0x100" / ""（不取）'}
    if ctx_expr:
        ctx_spec = parse_value_expr(ctx_expr)
        if ctx_spec["kind"] == "bad":
            return {"ok": False, "code": "BAD_EXPR",
                    "error": f"ctx_expr 无法解析：{ctx_expr!r}",
                    "hint": '支持写法："x20" / "sp+0x10" / "x20+0x8"'}
    else:
        ctx_spec = {"kind": "reg", "reg": str(ctx_reg)}

    # (8) 第八次修改（2026-11-26）：dispatch_offset 为 "" 时等价于 None 触发自动扫描，
    #     并从全局 Session 查找已加载 SoFile 传入 find_dispatch_points 换算虚拟地址。
    disp = None
    if dispatch_offset is not None and str(dispatch_offset).strip() != "":
        from server.core.addr import parse_addr

        disp = parse_addr(dispatch_offset, default=None)
        if disp is None:
            return {"ok": False, "code": "BAD_DISPATCH_OFFSET",
                    "error": f"无法解析：{dispatch_offset!r}"}
    else:
        loaded_so = _lookup_loaded_so(so_name)
        scan = find_dispatch_points(so_name, so=loaded_so,
                                    pattern_hex=pattern_hex, limit=1)
        if not scan.get("ok") or not scan.get("points"):
            return {"ok": False, "code": "NO_DISPATCH_POINT", "scan": scan}
        disp = scan["points"][0]["offset"]

    js = _JS_VM_SNAPSHOT
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__CAPTURE_REGS__", str(int(capture_regs))),
        # (4) 第四次修改（2026-11-16）：原来这四行取的是 VM_DEFAULTS 常量，
        #     等于参数不生效。改为取函数形参，未传时形参默认值就是
        #     VM_DEFAULTS，行为与旧版一致。
        ("__IP_OFFSET__", str(int(ip_offset))),
        ("__IP_REG__", _js_str(ip_reg)),
        ("__IP_MODE__", _js_str(str(ip_mode).lower())),
        ("__CTX_REG__", _js_str(ctx_reg)),
        ("__CTX_SPEC__", _js_spec(ctx_spec)),
        ("__OPCODE_SPEC__", _js_spec(opcode_spec)),
        ("__REG_BASE_REG__", _js_str(reg_base_reg)),
        ("__REG_BASE_OFFSET__", str(int(reg_base_offset))),
        ("__VM_REG_COUNT__", str(int(vm_reg_count))),
        ("__SPEC_HELPERS__", _JS_SPEC_HELPERS),
    ):
        js = js.replace(k, v)
    js = js.replace("SO_NAME", _js_str(so_name))

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(js)
        box: dict = {"snap": None, "error": None, "fail_count": 0, "last_err": ""}

        def _on(m, d):
            p = m.get("payload")
            if not isinstance(p, dict):
                if m.get("type") == "error":
                    box["error"] = m.get("description")
                return
            if p.get("kind") == "snapshot":
                box["snap"] = p
            elif p.get("kind") == "stopped":
                box["fail_count"] = int(p.get("fail_count") or 0)
                box["last_err"] = str(p.get("last_err") or "")
            elif p.get("kind") == "error":
                box["error"] = p.get("error")

        script.on("message", _on)
        script.load()
        import time as _time

        t0 = _time.time()
        while _time.time() - t0 < max(0.3, float(wait)):
            if box["snap"] or box["error"]:
                break
            _time.sleep(0.03)
        if not box["snap"] and not box["error"]:
            try:
                script.post({"type": "stop"})
                _time.sleep(0.1)
            except Exception:                             # noqa: BLE001
                pass
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "SNAPSHOT_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)

    if box["error"]:
        return {"ok": False, "code": "SNAPSHOT_FAILED", "error": box["error"]}
    if not box["snap"]:
        out_no: dict = {
            "ok": False, "code": "NO_SAMPLE",
            "error": "窗口内没有走到派发点（可能 VM 当前没在跑）",
            "hint": "先触发目标功能，再调用本工具",
        }
        if box.get("fail_count"):
            out_no["fail_count"] = box["fail_count"]
            out_no["last_err"] = box["last_err"]
            out_no["error"] = (
                f"派发点命中 {box['fail_count']} 次但均因 ctx 取值失败跳过"
                f"（{box['last_err']}）"
            )
            out_no["hint"] = "检查 ctx_reg / ctx_expr 配置是否与当前 VM 一致"
        return out_no
    snap = box["snap"]
    snap["ok"] = True
    snap["note"] = ("vm_pc 是「下一条要执行的 VM 指令」的 pc；"
                    "code_base 未知时可用它反推")
    return snap


_JS_VM_SNAPSHOT = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    var CAPTURE_REGS = __CAPTURE_REGS__;
    var IP_OFFSET = __IP_OFFSET__;
    var IP_REG = __IP_REG__;
    var IP_MODE = __IP_MODE__;
    var CTX_REG = __CTX_REG__;
    var CTX_SPEC = __CTX_SPEC__;
    var OPCODE_SPEC = __OPCODE_SPEC__;
    var REG_BASE_REG = __REG_BASE_REG__;
    var REG_BASE_OFFSET = __REG_BASE_OFFSET__;
    var VM_REG_COUNT = __VM_REG_COUNT__;
__SPEC_HELPERS__

    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', code: 'SO_NOT_FOUND', error: '模块未加载：' + SO_NAME});
        return;
    }
    var addr = mod.base.add(DISPATCH_OFFSET);
    // (4) 第四次修改（2026-11-16）：
    //     bug 原因：原实现一进来就把 done 置 true，于是「ctx 取不到」
    //               这种可恢复的失败会**永久关掉采样**，表现为一次都没采到
    //               就再也采不到，用户只能重启进程重试。
    //     解决方案：只在**真正 send 出一条快照**后才停；取值失败时继续等下
    //               一个派发点，并把失败原因累计进 errors 一起回报。
    var done = false;
    var failCount = 0;
    var lastErr = '';

    var listener = Interceptor.attach(addr, {
        onEnter: function () {
            if (done) { return; }
            var c = this.context;
            var rec = {kind: 'snapshot', dispatch_addr: addr.toString(),
                       native_pc: c.pc.toString()};

            var ctxRes = resolveValue(c, CTX_SPEC, null);
            var ctxp = ctxRes.ptr;
            // (8) 第八次修改（2026-11-26）
            // bug 原因：_JS_VM_SNAPSHOT 声明了 failCount/lastErr 却从未使用，
            //           ctxp === null 时仍然落空读完并置 done=true 结束采样。
            // 解决方案：当 ctx 必需且 ctxp === null 时累计 failCount/lastErr 并跳过，
            //           继续等待后续命中；opcode_expr 为寄存器时用 scalarFromReg 不解引用内存。
            var ctxRequired = (CTX_SPEC.kind !== 'none') || (IP_MODE === 'ctx')
                              || (REG_BASE_OFFSET > 0)
                              || (OPCODE_SPEC.kind === 'ctx');
            if (ctxp === null && ctxRequired) {
                failCount++;
                lastErr = ctxRes.err || 'ctx-missing';
                return;
            }
            rec.ctx = hexOf(ctxp);
            rec.ctx_source = ctxRes.src;

            // VM pc：按 IP_MODE 取，不再写死 [ctx+IP_OFFSET]
            if (IP_MODE === 'none') {
                rec.vm_pc = null;
                rec.ip_source = 'none';
            } else if (IP_MODE === 'reg') {
                var ip = regOf(c, IP_REG);
                rec.vm_pc = hexOf(ip);
                rec.ip_source = ip === null ? 'reg-missing' : 'reg:' + IP_REG;
            } else if (ctxp === null) {
                rec.vm_pc = null;
                rec.ip_source = ctxRes.err || 'ctx-missing';
            } else {
                try {
                    rec.vm_pc = ctxp.add(IP_OFFSET).readPointer().toString();
                    rec.ip_source = 'ctx+0x' + IP_OFFSET.toString(16);
                } catch (e) {
                    rec.vm_pc = null;
                    rec.ip_source = 'ctx-read-failed';
                    rec.err_ip = String(e);
                }
            }

            // 寄存器堆：ctx+offset（结构体内嵌）优先，否则按寄存器取
            var rb = null;
            if (REG_BASE_OFFSET > 0) {
                rb = (ctxp === null) ? null : ctxp.add(REG_BASE_OFFSET);
                rec.reg_base_source = 'ctx+0x' + REG_BASE_OFFSET.toString(16);
            } else if (REG_BASE_REG) {
                rb = regOf(c, REG_BASE_REG);
                rec.reg_base_source = rb === null ? 'reg-missing'
                                                  : 'reg:' + REG_BASE_REG;
            } else {
                rec.reg_base_source = 'none';
            }
            rec.reg_base = hexOf(rb);
            if (rb !== null) {
                try {
                    var regs = {};
                    var n = Math.min(CAPTURE_REGS, VM_REG_COUNT);
                    for (var i = 0; i < n; i++) {
                        regs['r' + i] = rb.add(i * 8).readPointer().toString();
                    }
                    rec.regs = regs;
                } catch (e) { rec.err_regs = String(e); }
            }

            // opcode：按 spec 取（"sp+8" / "x8" / "ctx+0x100"）；kind==='reg' 绝不解引用
            rec.opcode = null;
            rec.opcode_source = 'none';
            if (OPCODE_SPEC.kind !== 'none') {
                var opRes = resolveValue(c, OPCODE_SPEC, ctxp);
                rec.opcode_source = opRes.src;
                if (opRes.ptr !== null) {
                    var sv = (OPCODE_SPEC.kind === 'reg')
                        ? scalarFromReg(opRes.ptr) : readScalar(opRes.ptr);
                    rec.opcode = (sv.n !== null) ? sv.n : sv.s;
                    if (sv.err) { rec.err_opcode = sv.err; }
                }
            }

            try {
                rec.stack_hex = Array.from(new Uint8Array(c.sp.readByteArray(128)))
                    .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                    .join('');
            } catch (e) {}
            if (failCount > 0) {
                rec.fail_count = failCount;
                rec.last_err = lastErr;
            }
            send(rec);
            done = true;
            try { listener.detach(); } catch (e) {}
        }
    });

    recv('stop', function () {
        done = true;
        try { listener.detach(); } catch (e) {}
        send({kind: 'stopped', fail_count: failCount, last_err: lastErr});
    });
})();
"""
