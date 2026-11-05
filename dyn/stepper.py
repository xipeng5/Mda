"""单步执行的逻辑骨架：纯静态"规划"已实现，frida"执行"按要求留空。

## 为什么拆成 plan_* 与 execute_step

单步在 frida 上的常规做法是**临时断点模拟**（unidbg/frida 都这么干）：
在当前 PC 的下一条指令处 `Interceptor.attach`，放行后等命中，再摘钩。

这个做法里只有两件事：
1. **算地址** —— 下一条指令在哪、调用返回点在哪、N 条后落在哪。
   全部来自静态模型，**不需要设备**，是纯算法。
2. **下临时断点让线程真的走过去** —— 必须真机 frida。

用户明确要求「执行部分先留空、绝不造假」。故模块按此切分：
`plan_*` 返回可判定的规划结果（真数据），`execute_step` 返回
`dyn.pending.NotImplementedYet` 占位（`implemented: False`）。

## 静态可确定性的诚实边界（重要）

| 情况 | 落点能否静态确定 | 原因 |
|---|---|---|
| 普通指令 / `bl` / `blr` / 条件跳转 | ✅ 能 | 顺序执行或返回点固定 |
| `b` / `br`（尾调用） | ⚠️ 地址能算，但下一条**不会执行** | 无条件跳走 |
| `br` / `blr` 的**跳转目标** | ❌ 不能 | 目标在寄存器里 |
| 条件跳转的**实际分支** | ❌ 不能 | 取决于运行时标志位 |
| `ret` 的**返回地址** | ❌ 不能 | 来自运行时 LR |

因此同一份"单步"在不同助记符上语义不同，规划结果用
`resolvable` + `next_will_execute` 两个字段区分，不合并成一个 bool，
避免调用方把「算得出地址」误当成「这条一定会执行」。

## 复用而非重写

- 反汇编：`core.disasm.Disassembler`（已处理 capstone 解码中断、缓存）
- 读指令：`SoFile.read`（节表/PT_LOAD 双路径，dump so 也能读）
- 静态会话：`mcp_server.tools.get_session()` 单例，与 GUI/MCP 同源
  （沿用 `dyn/debugger.py::_symbolize_backtrace` 的同一做法）
- 占位结构：`dyn.pending`
"""
from __future__ import annotations

from core.disasm import Disassembler
from dyn.pending import NotImplementedYet, pending

INSN_SIZE = 4          # ARM64 指令定长
_SCAN_CHUNK = 4096     # 静态扫描分块字节数（一次读、一次解码，减少 IO）

# ---- 分支分类表（按 capstone 助记符归组，避免各处重复写 set） ----
# 无条件直接跳转：目标在指令里，但下一条指令不会执行
# 无条件直接跳转。含 b.al（always）与带指针认证的直接跳转。
_UNCOND_DIRECT = frozenset({"b", "b.al", "braa", "braaz"})
# 条件直接跳转：目标在指令里，但走哪边取决于运行时标志位
# (2) 第二次修改（2026-11-02）：补齐 b.hs / b.lo。
#     bug 原因：ARM64 的条件码 0b0010/0b0011 有**两个别名**——hs==cs、lo==cc。
#               capstone 统一按 hs/lo 输出（实测：b.cs 0x54000002 反汇编得到
#               'b.hs'，b.cc 0x54000003 得到 'b.lo'），所以表里写的 b.cs/b.cc
#               永远匹配不到任何真实指令。后果是这类条件跳转被当成普通指令
#               顺序执行，step over 落点算到"下一条"而不是跳转目标，且仍报
#               resolvable=True——落点错却不报警，属静默错误。
#     解决方案：hs/lo 与 cs/cc 同时收录。保留 cs/cc 是因为若将来换反汇编
#               后端（如 objdump 风格输出）可能用另一套别名，多收不冲突。
_COND_DIRECT = frozenset({
    "b.eq", "b.ne",
    "b.cs", "b.cc", "b.hs", "b.lo",   # cs==hs，cc==lo，两套别名都要有
    "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le",
})
# (7) 第七次修改（2026-11-05）：把 b.al / b.nv 从条件跳转里移出。
#     bug 原因：capstone 5.x 会把某些编码输出成 `b.al`（always，等价无条件跳）
#               和 `b.nv`（never，永远不跳）。原实现把两者都塞进 _COND_DIRECT，
#               于是：① b.al 被当成"走哪边看标志位"的条件跳转，
#                     而 _stops_linear_scan 又把它当无条件跳转 —— 两处自相矛盾；
#                   ② b.nv 被当成有效跳转，给出一个**永远不会执行**的落点。
#     解决方案：b.al 归入 _UNCOND_DIRECT（无条件）；b.nv 落到 seq（顺序执行，
#               因为它等价于不跳）。两者都不再算条件跳转。
# 带直接目标的比较跳转：目标同样在指令里
_COMPARE_DIRECT = frozenset({"cbz", "cbnz", "tbz", "tbnz"})
# 调用：目标在指令里，返回点固定为下一条
_DIRECT_CALL = frozenset({"bl"})
# 间接跳转：目标在寄存器里，静态不可知（AVMP 分发器 `br x16` 即此类）
# (8) 第八次修改（2026-11-05）：补齐以 PAC/异常返回结尾的间接跳转与返回族。
#     bug 原因：只认 br/blr/ret，而真实 ARM64 代码（尤其开了 BTI/PAC 的库）里
#               大量使用 braa/braaz（认证后跳转）、blraa/blraaz（认证后调用）、
#               retaa/retab（认证后返回）、eret（异常返回）。
#               漏判的后果是这些"离开当前位置"的指令被当成普通指令顺序执行，
#               step over 会给出一个根本不会执行的落点，且仍报 resolvable=True。
#     解决方案：按语义归类——
#               braa/braaz           → 间接跳转（目标在寄存器里，静态不可知）
#               blraa/blraaz         → 间接调用
#               retaa/retab/eret     → 返回（返回地址来自运行时寄存器）
_INDIRECT_JUMP = frozenset({"br", "braa", "braaz"})
_INDIRECT_CALL = frozenset({"blr", "blraa", "blraaz"})
_RET = frozenset({"ret", "retaa", "retab", "eret"})

# 这些"指令"是 Disassembler 在解码中断处的占位，不是真的机器码
_DATA_MNEMONIC = ".data"

# 规划结果里恒存在的三个键：调用方（尤其 MCP 包装层）不用判键存在
_CORE_KEYS = ("strategy", "temp_breakpoint_addr", "reason")


# ---------------- 静态模型取用（惰性、可失败、不伪造） ----------------


def _static_session():
    """取 mda 的静态会话单例；拿不到返回 None。

    惰性导入：纯静态场景下 stepper 不应在 import 期就把 mcp_server 拉起来。
    与 `dyn/debugger.py::_symbolize_backtrace` 的做法保持一致——
    整个项目只有一个静态会话，动态侧符号化、单步规划都必须看同一份数据。
    """
    try:
        from mcp_server.tools import get_session

        return get_session()
    except Exception:                                      # noqa: BLE001 - 导入/初始化异常类型不稳定
        return None


def _find_so(sess, so_name: str):
    """在静态会话里按名字找 SoFile，支持短名/全路径/被改名过的重名 so。

    与 `Rebase.find_module` 同一套匹配语义：设备侧枚举出来的模块名可能是
    全路径，而 mda 里注册的是 basename，两边必须能对上，否则「同一个 so」
    在动态侧和静态侧会各找各的。
    """
    if not so_name or sess is None:
        return None
    mods = getattr(sess, "modules", {}) or {}
    if so_name in mods:
        return mods[so_name]
    base = so_name.rsplit("/", 1)[-1]
    if base in mods:
        return mods[base]
    for key, so in mods.items():
        if key.rsplit("/", 1)[-1] == base:
            return so
        if getattr(so, "renamed_from", None) == base:
            return so
    return None


def _disassembler(sess, so_name: str, so):
    """复用会话里已建好的 Disassembler（带解码缓存），失败才新建。

    会话里的实例与 xref/伪代码等模块共用缓存，重复规划同一段代码不重复付费。
    """
    try:
        return sess.xref(so_name).disasm
    except Exception:                                      # noqa: BLE001 - 未注册/键不存在
        return Disassembler(so)


def _session_state(debugger) -> str:
    """读 debugger 的会话状态；纯本地属性，不触发任何 frida 调用。

    规划是纯静态的，状态只用于如实告知调用方「执行前还需不需要重新 attach」，
    不参与规划本身（设备断连时也应能离线算地址）。
    """
    try:
        return str(debugger.state)
    except Exception:                                      # noqa: BLE001 - 传入 None/假对象
        return ""


def _view(debugger, so_name: str):
    """统一取数入口：返回 (so, disasm, sess, err)。

    err 非空表示无法规划，调用方直接 `_fail(...)` 返回，不做猜测。
    """
    sess = _static_session()
    if sess is None:
        return None, None, None, "静态会话不可用：mcp_server 未就绪，无法读取指令"
    so = _find_so(sess, so_name)
    if so is None:
        loaded = list(getattr(sess, "modules", {}) or {})
        return None, None, sess, (
            f"{so_name} 未在 mda 中加载，无法读取指令（当前已加载：{loaded}）；"
            "先调 load_so 加载对应 so 再规划"
        )
    return so, _disassembler(sess, so_name, so), sess, ""


# ---------------- 指令读取与分类（纯静态） ----------------


def _decode_at(so, disasm, addr: int, count: int = 1) -> list:
    """从 addr 起解码 count 条指令；读不到（越界/无文件数据）返回更短的列表。

    走 `SoFile.read` + `disasm_range`：前者负责节表/PT_LOAD 双路径取字节
    （壳样本节表被抹时仍可读），后者负责 capstone 解码与缓存。
    """
    if count <= 0:
        return []
    code = so.read(addr, INSN_SIZE * count)
    usable = (len(code) // INSN_SIZE) * INSN_SIZE
    if usable < INSN_SIZE:
        return []
    return list(disasm.disasm_range(addr, usable))


def _decode_one(so, disasm, addr: int):
    """解码单条指令；不可读/不是真指令时返回 None。"""
    insns = _decode_at(so, disasm, addr, 1)
    if not insns:
        return None
    insn = insns[0]
    # .data 是解码中断处的占位，语义上等于"这里没有已知指令"
    if insn.mnemonic == _DATA_MNEMONIC:
        return None
    return insn


def _branch_target(insn) -> int | None:
    """取直接分支目标地址；取不到返回 None。

    capstone 只在第一个操作数是立即数时才会被 core.disasm 填进 call_target
    （`cbz w10, #0x65b88` 的第一个操作数是寄存器，走不到那条分支），
    故这里对比较跳转补一次 op_str 解析：目标恒为最后一个 `#0x...` 操作数。
    """
    if insn.call_target:
        return int(insn.call_target)
    op = insn.op_str or ""
    for token in reversed(op.replace(",", " ").split()):
        text = token.strip()
        if not text.startswith("#"):
            continue
        text = text[1:]
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 0)
        except ValueError:
            continue
    return None


def _classify(insn) -> tuple[str, int | None]:
    """把一条指令归入分支类别，返回 (kind, 直接目标地址)。

    kind 取值：
      seq      顺序执行（普通指令）
      call     直接调用（bl）——目标确定，返回点也确定
      jump     无条件直接跳转（b）
      cond     条件/比较跳转——目标确定，但走哪边要看运行时标志位
      indirect 间接跳转/调用（br / blr）——目标在寄存器里
      ret      函数返回——返回地址来自运行时 LR
      data     非指令（解码中断或越界）
    """
    m = insn.mnemonic
    if m == _DATA_MNEMONIC:
        return "data", None
    if m in _DIRECT_CALL:
        return "call", _branch_target(insn)
    if m in _INDIRECT_CALL:
        return "indirect", None
    if m in _UNCOND_DIRECT:
        return "jump", _branch_target(insn)
    if m in _INDIRECT_JUMP:
        return "indirect", None
    if m in _COND_DIRECT or m in _COMPARE_DIRECT:
        return "cond", _branch_target(insn)
    if m in _RET:
        # (3) 第三次修改（2026-11-02）：区分 `ret` 与 `ret xN`。
        #     bug 原因：ARM64 的 ret 可带操作数（`ret x1` 跳到 x1，而非 LR）。
        #               原实现一律返回 ("ret", None)，plan_step_out 便无条件
        #               认为"返回地址来自 LR"，对 `ret xN` 会给出错误落点，
        #               而且仍报 resolvable=True。
        #     解决方案：有操作数时标成 indirect_jump（目标在寄存器里，
        #               静态不可知）；只有裸 `ret` 才是"走 LR"。
        if (insn.op_str or "").strip():
            return "indirect", None
        return "ret", None
    return "seq", None


def _insn_snapshot(insn) -> dict:
    """指令快照：只放真实解码出来的字段，供报告/日志回显。"""
    return {
        "addr": int(insn.addr),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "text": insn.text,
        "is_call": bool(insn.is_call),
        "is_jump": bool(insn.is_jump),
        "is_ret": bool(insn.is_ret),
    }


# ---------------- 结果构造函数（保证三个核心键恒存在） ----------------


def _ok(strategy: str, temp_addr, reason: str, **extra) -> dict:
    """成功规划：strategy/temp_breakpoint_addr/reason 三键齐备。"""
    out = {
        "ok": True,
        "resolvable": bool(extra.pop("resolvable", False)),
        "strategy": strategy,
        "temp_breakpoint_addr": (int(temp_addr) if temp_addr is not None else None),
        "reason": reason,
    }
    out.update(extra)
    return out


def _fail(strategy: str, code: str, message: str, **extra) -> dict:
    """规划失败/不可确定：同样带齐三键，temp_breakpoint_addr 为 None。

    失败不返回空列表或 None——那会让上层把「不算出来」误读成「没有」，
    与 `dyn/pending.py` 的既定原则一致。
    """
    out = {
        "ok": False,
        "resolvable": False,
        "strategy": strategy,
        "temp_breakpoint_addr": None,
        "reason": message,
        "code": code,
        "error": message,
    }
    out.update(extra)
    return out


def _runtime_to_static(debugger, so_name: str, runtime_addr: int):
    """把运行时地址折算成静态地址；拿不到基址时返回 (None, 原因)。

    (4) 第四次修改（2026-11-02）：新增本函数。
        bug 原因：step_out 的静态校验直接拿运行时 lr 去比静态区间，
                  ASLR 下必然判定"离开模块"，校验形同虚设。
        解决方案：经 debugger 的 rebase（rb）取运行时模块表拿 base，
                  再 runtime - base 得到静态地址；任何一环缺失就返回 None
                  让调用方跳过校验，**绝不拿运行时地址硬比**。
    """
    rb = getattr(debugger, "rb", None)
    if rb is None:
        return None, "debugger 未暴露 rb（rebase）"
    finder = getattr(rb, "find_module", None)
    mod = None
    if callable(finder):
        try:
            mod = finder(so_name)
        except Exception:                                  # noqa: BLE001
            mod = None
    if mod is None:
        # 退化：直接在缓存模块表里按名字找
        for m in list(getattr(rb, "_modules", []) or []):
            if getattr(m, "name", "") == so_name:
                mod = m
                break
    if mod is None:
        return None, f"运行时模块表里没有 {so_name}（未 attach 或未刷新）"
    try:
        base = int(getattr(mod, "base"))
    except (TypeError, ValueError):
        return None, "模块 base 字段非法"
    if base <= 0:
        return None, "模块 base 为 0，无法区分运行时/静态地址"
    return runtime_addr - base, ""


def _session_note(debugger) -> dict:
    """把 debugger 状态附进结果，便于判断「还需不需要先 attach」。"""
    state = _session_state(debugger)
    if not state:
        return {}
    return {"session_state": state,
            "needs_attach": state in ("", "idle", "detached")}


# ---------------- 1. step over ----------------


def plan_step_over(debugger, so_name: str, static_addr: int,
                   lr: int | None = None) -> dict:
    """规划 step over：把临时断点设在哪，能让目标"跨过"当前指令。

    step over 的核心洞见：**跳过了谁**决定了断点放哪。
    - `bl`/`blr`（调用）：不进入被调函数，所以断点放**下一条指令**（返回点）。
      注意 `blr` 的目标虽是间接的，但**返回点是确定的**，故 step over 在
      `blr` 上完全可静态规划——这正是 step over 与 step into 的分水岭。
    - `b`/`br`（尾调用）：下一条指令**不会被执行**，仍按下一条下临时断点
      （用户明确要求的策略），但 `next_will_execute=False` 如实标注，
      调用方据此知道"这次单步可能永远等不到命中"。
    - `ret`：返回地址来自运行时 LR，静态不可知。调用方若已从断点上下文
      取到 LR（`hit.context["lr"]`）就传 `lr=`，否则 `resolvable=False`。
    - `b.eq`/`cbz`/`tbz` 等条件跳转：两个方向最终都会回到下一条指令，
      故断点放下一条是**正确**的（无需关心实际走了哪边）。

    参数：
        debugger    —— dyn.debugger.Debugger（只用于读会话状态，不碰设备）
        so_name     —— so 名（短名或全路径均可，与静态会话对齐）
        static_addr —— 当前指令的静态地址
        lr          —— 可选，运行时 LR 值（ret 场景需要）

    返回 dict，恒含 strategy / temp_breakpoint_addr / reason，
    另有 ok / resolvable / next_will_execute / instruction / warning 等字段。
    """
    so, disasm, _sess, err = _view(debugger, so_name)
    if err:
        return _fail("unresolvable", "SO_NOT_LOADED", err, **_session_note(debugger))

    insn = _decode_one(so, disasm, int(static_addr))
    if insn is None:
        return _fail(
            "unresolvable", "NO_INSTRUCTION",
            f"{so_name}+{int(static_addr):#x} 处读不到可解码的指令"
            "（越界、落在无文件数据的段，或该处是内联数据）",
            **_session_note(debugger),
        )

    kind, target = _classify(insn)
    snap = _insn_snapshot(insn)
    next_addr = insn.addr + insn.size          # ARM64 恒 +4，但按 size 取更稳
    base = {"instruction": snap, "next_addr": next_addr, **_session_note(debugger)}

    if kind == "ret":
        # (9) 第九次修改（2026-11-05）：`if lr:` 会把 lr=0 当成"没给"。
        #     改成显式判 None，并把非 int 的情况包成可读错误而不是 ValueError 逃逸。
        if lr is not None:
            return _ok(
                "temp_breakpoint_at_lr", int(lr),
                f"当前是 ret，返回地址取自运行时 LR（{int(lr):#x}），"
                "在 LR 处下临时断点即等价于 step out",
                resolvable=True, next_will_execute=True, **base,
            )
        return _fail(
            "unresolvable", "RET_NEEDS_LR",
            "当前是 ret，返回地址来自运行时 LR，静态不可知；"
            "请先从断点上下文取到 lr（hit.context['lr']）再传入 lr= 参数",
            **base,
        )

    if kind == "indirect":
        # br / blr：两者目标都在寄存器里，但返回点语义不同
        is_call = insn.mnemonic in _INDIRECT_CALL
        out = _ok(
            "temp_breakpoint_next", next_addr,
            (f"当前是 {insn.mnemonic}（间接{'调用' if is_call else '跳转'}），"
             f"目标寄存器内容静态不可知；step over 不进入目标，"
             f"临时断点放在下一条指令 {next_addr:#x}")
            if is_call else
            (f"当前是 {insn.mnemonic}（间接跳转/尾调用），目标静态不可知，"
             f"且下一条指令 {next_addr:#x} 实际不会执行；"
             "此处 step over 只能形式上把断点放下一条，建议改用 "
             "plan_step_until_mnemonic 或先 plan_step_into 判断去向"),
            resolvable=True, next_will_execute=is_call, **base,
        )
        if not is_call:
            out["warning"] = ("间接跳转的下一条指令不会执行：临时断点可能永不命中，"
                              "这是静态阶段就能预知的失败，不是执行出错")
            out["indirect_target_unknown"] = True
        return out

    if kind == "jump":
        out = _ok(
            "temp_breakpoint_next_tail", next_addr,
            f"当前是无条件直接跳转 b -> {target:#x}（尾调用），"
            f"下一条指令 {next_addr:#x} 不会执行；按要求仍在下一地址下临时断点，"
            "但命中可能不会发生，实际去向为 b 的目标地址",
            resolvable=True, next_will_execute=False,
            branch_target=target, **base,
        )
        out["warning"] = ("无条件跳转的下一条指令不会执行：临时断点可能永不命中；"
                          "若目的是跟到 b 的目标，应改为在 branch_target 下断点")
        return out

    if kind == "cond":
        # (10) 第十次修改（2026-11-05）：条件跳转的落点**本来就有两个**，不能只认下一条。
        #      bug 原因：原实现写"两个分支最终都回到下一条指令"，并给出
        #                next_will_execute=True —— 这在**前向条件跳转**下是错的：
        #                跳转被取走时会直接跳到 target，next_addr 根本不会执行，
        #                于是只在 next_addr 下的临时断点可能永远不命中，
        #                而调用方看到 resolvable=True 会以为万无一失。
        #     解决方案：如实标注 next_will_execute=False（未取走才执行它），
        #                把另一条可能的落点放进 alt_breakpoint_addr，
        #                并加 warning 说明"两个落点都可能，需同时下断或接受不确定"。
        out = _ok(
            "temp_breakpoint_next", next_addr,
            f"当前是条件跳转 {insn.text}：未取走则落到下一条 {next_addr:#x}"
            + (f"，取走则落到 {target:#x}" if target is not None else "，取走则目标静态不可知"),
            resolvable=True,
            next_will_execute=False,     # 只有"未取走"时它才执行
            branch_target=target,
            branch_taken_resolvable=False, **base,
        )
        out["alt_breakpoint_addr"] = target
        out["possible_targets"] = [
            {"addr": next_addr, "when": "条件不成立（未取走）"},
        ]
        if target is not None:
            out["possible_targets"].append(
                {"addr": target, "when": "条件成立（取走）"})
            out["warning"] = (
                "条件跳转有两个可能落点，静态无法确定实际走哪边；"
                f"只在 {next_addr:#x} 下断点可能永不命中。"
                "execute_step 会自动在两处都下临时断点（先命中的就是真实落点）")
        else:
            out["warning"] = (
                "条件跳转的目标静态不可解析，且取走时会离开下一条；"
                "临时断点可能永不命中")
        return out

    # seq / call：下一条指令就是正确落点
    if kind == "call":
        return _ok(
            "temp_breakpoint_next", next_addr,
            f"当前是 bl 调用（目标 {target:#x}），step over 不进入被调函数，"
            f"临时断点放在下一条指令 {next_addr:#x}（即返回点）",
            resolvable=True, next_will_execute=True, call_target=target, **base,
        )
    return _ok(
        "temp_breakpoint_next", next_addr,
        f"当前是普通指令 {insn.mnemonic}，顺序执行，"
        f"临时断点放在下一条指令 {next_addr:#x}",
        resolvable=True, next_will_execute=True, **base,
    )


# ---------------- 2. step out ----------------


def plan_step_out(debugger, lr: int,
                  so_name: str = "", static_addr: int | None = None) -> dict:
    """规划 step out：在 LR（x30）指向的返回地址处下临时断点。

    返回地址是**运行时**值，必须由调用方从断点上下文给出（如
    `hit.context["lr"]`），静态分析无法凭空算出——本函数不猜，lr 非法就明确报错。

    可选 `so_name` / `static_addr`（当前所在位置）用于**纯静态校验**：
    若 LR 落在该 so 的可执行区之外，说明这次返回会回到别的模块
    （PLT、frida trampoline、JIT 等），提前标注 `leaves_module=True`，
    免得调用方以为断点一定命中。

    参数：
        debugger    —— dyn.debugger.Debugger（只读状态，不碰设备）
        lr          —— 运行时 LR 值（整数）
        so_name     —— 可选，用于校验返回地址是否离开当前 so
        static_addr —— 可选，当前指令地址，仅用于报告回显
    """
    base = dict(_session_note(debugger))
    if static_addr is not None:
        base["from_addr"] = int(static_addr)

    try:
        ret_addr = int(lr)
    except (TypeError, ValueError):
        return _fail("temp_breakpoint_at_lr", "BAD_LR",
                     f"LR 值非法（{lr!r}），无法规划 step out", **base)
    if ret_addr <= 0:
        return _fail(
            "temp_breakpoint_at_lr", "BAD_LR",
            f"LR 值为 {ret_addr:#x}，不是有效返回地址；"
            "该帧可能是函数入口（LR 尚未被调用方写入）或 LR 已被覆盖，"
            "需从断点上下文重新取值",
            **base,
        )
    if ret_addr % INSN_SIZE:
        return _fail(
            "temp_breakpoint_at_lr", "LR_NOT_ALIGNED",
            f"LR 值 {ret_addr:#x} 未按 4 字节对齐，不可能是 ARM64 指令地址",
            **base,
        )

    # (9) 第九次修改（2026-11-05）：**先**把运行时 LR 换算成静态地址，再决定 temp_breakpoint_addr。
    #     bug 原因：原实现 `_ok("temp_breakpoint_at_lr", ret_addr, ...)` 直接拿运行时 LR
    #               当静态地址返回，而 Debugger.set_breakpoint 内部还会 rb.to_runtime()
    #               再加一次基址 → 双重加基址、断点打到野地址（实测 base=0x7a00000000、
    #               lr=0x7a00001234 时 JS 收到 0xf400001234）。
    #               同时 target_offset = ret_addr - fn.addr 混用地址空间；
    #               fn 为 None（PLT 桩/FDE 空洞）时 int(fn.addr) 直接 AttributeError。
    #     解决方案：
    #       1) 先换算 static_lr，用它作为 temp_breakpoint_addr（set_breakpoint 的正确入参）；
    #       2) 运行时值另存 runtime_lr 字段，供调用方观察；
    #       3) 换算失败（拿不到基址）时**明确失败**，绝不返回一个会让断点打空的地址；
    #       4) target_offset 用 static_lr - fn.addr；fn 判空。
    static_lr = None
    base_note = ""
    so = None
    if so_name:
        so, _disasm, _sess, err = _view(debugger, so_name)
        if err:
            return _fail(
                "temp_breakpoint_at_lr", "LR_STATIC_UNRESOLVED",
                f"无法把运行时 LR 换算成静态地址：{err}；"
                "set_breakpoint 需要静态地址，不给就不下断点",
                **base,
            )
        static_lr, base_note = _runtime_to_static(debugger, so_name, ret_addr)
    if static_lr is None:
        return _fail(
            "temp_breakpoint_at_lr", "LR_STATIC_UNRESOLVED",
            f"拿不到 {so_name} 的运行时基址（{base_note or '模块未加载'}），"
            f"无法把运行时 LR {ret_addr:#x} 换算成静态地址；"
            "先 attach 并确认该 so 已加载，或直接传 lr 的静态值",
            **base,
        )

    out = _ok(
        "temp_breakpoint_at_lr", static_lr,
        f"step out 在 LR 处下临时断点（静态 {static_lr:#x}，运行时 {ret_addr:#x}）："
        "函数返回时会落到该地址，停在这里即完成一次返回",
        resolvable=True, next_will_execute=True,
        lr=static_lr, runtime_lr=ret_addr, **base,
    )

    # 静态归属校验：static_lr 已经是静态地址，可直接查区间/函数
    if so is not None:
        regions = so.exec_regions()
        inside = any(va <= static_lr < end for va, end, _o, _f in regions)
        out["leaves_module"] = not inside
        if not inside:
            out["warning"] = (
                f"LR={ret_addr:#x}（静态 {static_lr:#x}）不在 {so.name} "
                "的可执行区内，该次返回会离开本 so"
                "（外部模块/PLT/trampoline/JIT）；临时断点仍可下"
            )
        else:
            fn = None
            try:
                fn = so.function_at(static_lr)
            except Exception:                              # noqa: BLE001 - 函数表异常不阻断规划
                fn = None
            if fn is not None:
                out["target_function"] = fn.name or f"sub_{int(fn.addr):x}"
                # 地址空间统一：静态 - 静态
                out["target_offset"] = static_lr - int(fn.addr)
            else:
                # fn 为 None 是正常情况（PLT 桩 / FDE 空洞），不能崩
                out["target_offset"] = None
                out["verify_note"] = (
                    f"静态地址 {static_lr:#x} 落在函数空洞（PLT 桩或 FDE 缺失），"
                    "无法给出所属函数与偏移")
    return out


# ---------------- 3. step into ----------------


def plan_step_into(debugger, so_name: str, static_addr: int,
                   count: int = 1) -> dict:
    """规划 step into：静态推演执行 count 条指令后的落点。

    逐条按控制流走，**只在目标真的能静态算出时才继续**：
      - 普通指令        → 下一条
      - `bl <直接目标>` → 进入被调函数（这就是 step into 与 step over 的区别）
      - `b <直接目标>`  → 跟随到目标（尾调用即跳转）
      - `br` / `blr`    → 目标在寄存器里，**停下来报不可确定**
      - 条件跳转         → 走哪边取决于运行时标志位，**报不可确定并给两候选**
      - `ret`           → 返回地址来自运行时 LR，**报不可确定**

    绝不猜：任何一步不可确定就立刻停，返回 `resolvable=False`、停下时的
    `stopped_at` 与已确定部分的 `trace`，让调用方知道"走到哪里为止是可信的"。

    参数：
        debugger    —— dyn.debugger.Debugger（只读状态，不碰设备）
        so_name     —— so 名
        static_addr —— 起始指令地址
        count       —— 要执行的指令条数（含起始这条算第 1 条）
    """
    try:
        steps = int(count)
    except (TypeError, ValueError):
        steps = 0
    if steps <= 0:
        return _fail("step_into_chain", "BAD_COUNT",
                     f"count 必须是正整数，实际为 {count!r}",
                     **_session_note(debugger))

    so, disasm, _sess, err = _view(debugger, so_name)
    if err:
        return _fail("step_into_chain", "SO_NOT_LOADED", err,
                     **_session_note(debugger))

    cur = int(static_addr)
    trace: list[dict] = []
    base = _session_note(debugger)

    for i in range(steps):
        insn = _decode_one(so, disasm, cur)
        if insn is None:
            return _fail(
                "step_into_chain", "NO_INSTRUCTION",
                f"第 {i + 1} 步在 {cur:#x} 处读不到可解码的指令"
                "（越界、数据段或解码中断），后续落点无法静态确定",
                stopped_at=cur, steps_done=i, trace=trace, **base,
            )
        kind, target = _classify(insn)
        snap = _insn_snapshot(insn)
        next_addr = insn.addr + insn.size
        trace.append({**snap, "kind": kind})

        if kind == "data":
            return _fail(
                "step_into_chain", "NOT_CODE",
                f"第 {i + 1} 步在 {cur:#x} 处不是指令（解码中断/数据），停止",
                stopped_at=cur, steps_done=i, trace=trace, **base,
            )
        if kind == "indirect":
            return _fail(
                "step_into_chain", "INDIRECT_TARGET_UNKNOWN",
                f"第 {i + 1} 步是 {insn.mnemonic} {insn.op_str}（间接"
                f"{'调用' if insn.mnemonic in _INDIRECT_CALL else '跳转'}），"
                "目标寄存器内容静态不可知——间接跳转目标无法静态确定，"
                "必须运行时读寄存器（或改用 plan_step_over，其返回点确定）",
                stopped_at=cur, steps_done=i, trace=trace,
                pending_mnemonic=insn.mnemonic, **base,
            )
        if kind == "ret":
            return _fail(
                "step_into_chain", "RET_NEEDS_LR",
                f"第 {i + 1} 步是 ret，返回地址来自运行时 LR，静态不可知；"
                "需要运行时值（hit.context['lr']）才能确定落点",
                stopped_at=cur, steps_done=i, trace=trace, **base,
            )
        if kind == "cond":
            candidates = [next_addr]
            if target is not None:
                candidates = [int(target), next_addr]
            return _fail(
                "step_into_chain", "COND_BRANCH_UNKNOWN",
                f"第 {i + 1} 步是条件跳转 {insn.text}，"
                f"实际走哪边取决于运行时标志位，静态无法确定；"
                f"两个候选落点：{[hex(a) for a in candidates]}",
                stopped_at=cur, steps_done=i, trace=trace,
                candidates=candidates, pending_mnemonic=insn.mnemonic, **base,
            )

        # 到这里落点确定：seq → 下一条；call → 进入 callee；jump → 跟到目标
        if kind == "call":
            if target is None:
                return _fail(
                    "step_into_chain", "CALL_TARGET_UNKNOWN",
                    f"第 {i + 1} 步 {insn.text} 解析不出直接调用目标",
                    stopped_at=cur, steps_done=i, trace=trace, **base,
                )
            nxt = int(target)
        elif kind == "jump":
            if target is None:
                return _fail(
                    "step_into_chain", "JUMP_TARGET_UNKNOWN",
                    f"第 {i + 1} 步 {insn.text} 解析不出直接跳转目标",
                    stopped_at=cur, steps_done=i, trace=trace, **base,
                )
            nxt = int(target)
        else:
            nxt = next_addr
        cur = nxt

    return _ok(
        "step_into_chain", cur,
        f"按静态控制流推演 {steps} 条指令，落点为 {cur:#x}"
        "（每一步的分支目标均由指令里的立即数直接算出，未做任何猜测）",
        resolvable=True, next_will_execute=True,
        target=cur, steps=steps, trace=trace, **base,
    )


# ---------------- 4. step until mnemonic ----------------


def _stops_linear_scan(mnemonic: str) -> bool:
    """该指令是否会让"下一条物理指令"不再被执行（终止线性扫描）。

    (5) 第五次修改（2026-11-02）：新增本函数。
        判断依据只看**无条件**离开当前位置的指令：
            b / b.al / br —— 无条件跳转（br 是间接的，同样离开）
            ret           —— 函数返回
        **不包含**条件跳转（b.eq 等）：条件不满足时会继续执行下一条，
        故线性扫描可以继续。也不包含 bl/blr：调用完会回到下一条。
    """
    m = (mnemonic or "").lower()
    # (8) 与 _classify 保持同一套集合，避免两处定义漂移
    return m in _UNCOND_DIRECT or m in _INDIRECT_JUMP or m in _RET


def _scan_end(so, start: int) -> tuple[int, str]:
    """静态线性扫描的上界，返回 (end, 上界来源)。

    不给上界会一路扫进数据段甚至扫穿整个 so，得到一堆假命中。

    (1) 第一次修改（自测发现）
    bug 原因：初版只用「所在函数末尾」做上界，而 libbase.so 的导出多数是
              16 字节跳转 thunk（`bti c; adrp; add; b`），block 里根本没有 bl。
              于是从 thunk 起点找 bl 必然在 4 条指令后停住返回 found=False，
              调用方只看到「没找到」，无从分辨是"整个函数真的没有"还是
              "扫描范围被函数边界截断、其实还没扫到"——这会让人误判。
    解决方案：同时给出"可执行区末尾"作为备用上界，并在结果里回显
              scan_end / scan_scope（function|exec_region）与 stopped_by
              （found|scan_end|budget），让"扫完了没有"这件事可判定。
    """
    try:
        fn = so.function_at(start)
    except Exception:                                      # noqa: BLE001 - 函数表异常不应阻断扫描
        fn = None
    if fn is not None:
        return int(fn.end), "function"
    for va, end, _off, _fl in so.exec_regions():
        if va <= start < end:
            return int(end), "exec_region"
    return 0, "none"


def plan_step_until_mnemonic(debugger, so_name: str, start_addr: int,
                             mnemonic: str, max_insns: int = 500) -> dict:
    """从 start_addr 起静态线性扫描，找到第一条指定助记符的位置。

    用途：把「跑到下一次调用/返回」表达成一次规划，避免逐条单步
    （AI 逐个 step 会又慢又吵）。典型 mnemonic：`bl`、`ret`、`br`、`b.eq`。

    实现约束（都是刻意的）：
    - **精确匹配**助记符（忽略大小写与首尾空格），不做前缀模糊匹配，
      否则 `b` 会命中 `b.eq`/`bl`/`br`，结果不可预期。
    - **只做线性扫描**，不跟随分支：跳跃会破坏"从 start_addr 起顺序执行"
      的前提，而本函数承诺的正是这个顺序语义。
    - 扫描**不越过所在函数末尾**（见 `_scan_end`）。注意这会让"从 16 字节
      thunk 起点找 bl"直接扫空——所以结果里必须带 `stopped_by`：
        found      找到目标
        scan_end   扫描上界已到，该范围内确实没有
        budget     撞到 max_insns 上限，后面还没扫
        unreadable 中途读不到字节（数据段/越界）
      调用方据此区分"确实没有"与"没扫到"，不会误判。
    - 扫满 max_insns 仍未命中属正常结果（`found=False`），不是错误。

    参数：
        debugger   —— dyn.debugger.Debugger（只读状态，不碰设备）
        so_name    —— so 名
        start_addr —— 起始扫描地址（通常为当前 PC）
        mnemonic   —— 目标助记符（如 "bl" / "ret"）
        max_insns  —— 最多扫描的指令条数，默认 500
    """
    want = (mnemonic or "").strip().lower()
    if not want:
        return _fail("scan_mnemonic", "BAD_MNEMONIC",
                     "mnemonic 不能为空，例如 'bl' / 'ret' / 'br'",
                     **_session_note(debugger))
    try:
        budget = int(max_insns)
    except (TypeError, ValueError):
        budget = 0
    if budget <= 0:
        return _fail("scan_mnemonic", "BAD_MAX_INSNS",
                     f"max_insns 必须是正整数，实际为 {max_insns!r}",
                     **_session_note(debugger))

    so, disasm, _sess, err = _view(debugger, so_name)
    if err:
        return _fail("scan_mnemonic", "SO_NOT_LOADED", err,
                     **_session_note(debugger))

    start = int(start_addr)
    end, scope = _scan_end(so, start)
    base = dict(_session_note(debugger))
    if end <= start:
        return _fail(
            "scan_mnemonic", "NOT_EXECUTABLE",
            f"{start:#x} 不在 {so.name} 的可执行区/已识别函数内，无法扫描",
            mnemonic=want, start_addr=start, **base,
        )

    cur = start
    scanned = 0
    data_hits = 0
    stopped_by = ""          # 扫描因何结束：found / scan_end / budget / unreadable
    while scanned < budget and cur < end:
        take = min(budget - scanned, max(_SCAN_CHUNK // INSN_SIZE, 1))
        limit = min(end, cur + take * INSN_SIZE)
        code = so.read(cur, limit - cur)
        usable = (len(code) // INSN_SIZE) * INSN_SIZE
        if usable < INSN_SIZE:
            stopped_by = "unreadable"
            break
        insns = disasm.disasm_range(cur, usable)
        if not insns:
            stopped_by = "unreadable"
            break
        for insn in insns:
            if scanned >= budget:
                break
            if insn.mnemonic == want:
                return _ok(
                    "temp_breakpoint_at_mnemonic", int(insn.addr),
                    f"从 {start:#x} 起线性扫描 {scanned + 1} 条指令，"
                    f"在 {int(insn.addr):#x} 找到第一条 {want}"
                    f"（{insn.text}）；在该地址下临时断点即可停在它执行前",
                    resolvable=True, next_will_execute=True,
                    found=True, addr=int(insn.addr),
                    mnemonic=want, instruction=_insn_snapshot(insn),
                    insn_count=scanned + 1, start_addr=start,
                    scan_end=end, scan_scope=scope, stopped_by="found",
                    data_skipped=data_hits, **base,
                )
            if insn.mnemonic == _DATA_MNEMONIC:
                data_hits += 1     # 解码中断处的占位，计入进度但不当成指令匹配
            scanned += 1
            # (5) 第五次修改（2026-11-02）：线性扫描遇到无条件跳转必须停止。
            #     bug 原因：扫描是按地址递增的**线性**扫描，但代码布局不等于
            #               执行顺序。遇到无条件 `b <imm>`（或 `b.al`）时，下一条
            #               物理指令根本不会被执行；继续往下扫并返回那个地址，
            #               等于给出一个**永远不会命中的断点**，调用方会误以为
            #               设置成功，实际一直等不到。
            #     解决方案：碰到无条件跳转就终止扫描，并如实说明"执行流在此
            #               离开线性区间"。跳转目标是否还有目标指令属于控制流
            #               问题，本函数不做跨块推断（那需要完整 CFG），
            #               宁可明确停下也不瞎给地址。
            if _stops_linear_scan(insn.mnemonic):
                return _fail(
                    "scan_mnemonic", "FLOW_DIVERGED",
                    f"扫描到 {int(insn.addr):#x} 是 {insn.mnemonic}"
                    f"（{insn.text}），执行流在此无条件离开线性区间，"
                    f"后续物理地址不会被执行；已扫 {scanned} 条仍未遇到 {want}。"
                    "目标可能位于跳转目标处，请改为从该跳转目标继续扫描",
                    found=False, stopped_by="flow_diverged",
                    div_insn=_insn_snapshot(insn), insn_count=scanned,
                    start_addr=start, scan_end=end, scan_scope=scope,
                    data_skipped=data_hits, **base,
                )
        last = insns[-1]
        cur = last.addr + last.size
    else:
        stopped_by = "budget" if scanned >= budget else "scan_end"

    # 未命中：如实回报「为什么停」，否则调用方无法区分
    # 「扫完整个函数确实没有」与「被函数边界/budget 截断、后面还没扫到」
    scope_text = ("到所在函数末尾" if scope == "function"
                  else "到所属可执行段末尾")
    if stopped_by == "budget":
        end_reason = f"已达 max_insns={budget} 上限，扫描未到 {end:#x} 就停了，" \
                     "后面可能还有目标；需要更大范围请调大 max_insns"
    elif stopped_by == "unreadable":
        end_reason = f"扫描在 {cur:#x} 处读不到可用字节（数据段/越界）而中止"
    else:
        end_reason = f"已{scope_text}（{end:#x}）扫完，该范围内确实没有 {want}"

    return _ok(
        "scan_mnemonic", None,
        f"从 {start:#x} 起扫了 {scanned} 条指令，未找到 {want}；{end_reason}",
        resolvable=False, found=False, addr=None, mnemonic=want,
        insn_count=scanned, start_addr=start, scan_end=end,
        scan_scope=scope, stopped_by=stopped_by or "scan_end",
        data_skipped=data_hits, budget=budget, **base,
    )


# ---------------- 5. 执行（按要求留空） ----------------


def execute_step(debugger, plan: dict, so_name: str = "",
                 timeout: float = 5.0) -> dict:
    """真正执行一次单步：在临时断点处停下，返回停下的现场。

    (6) 第六次修改（2026-11-03）：实现真执行（此前留空）。
        背景：frida-server 已对齐 17.23.3，真机链路可用，故补上。

    做法（frida 无 CPU 单步指令，只能用临时断点模拟）：
      1. 在 plan 给的 temp_breakpoint_addr 下 **hold** 断点
      2. 若当前正 paused（有线程挂起），先 resume 放行
      3. 等到新命中；校验命中的 static_addr **确实等于目标地址**
      4. 无论成功失败都摘掉临时断点（避免污染后续断点表）
      5. 停在目标处（paused），把现场交给调用方，由它决定继续还是检查

    **为什么不吞掉"没停到目标"的情况**：如果命中地址与目标不符，说明执行流
    走了别的分支（条件跳转的实际走向），这时报成功会让人以为单步到位了。
    这种情况返回 ``matched: False`` 并把实际命中地址一并给出。

    参数：
        debugger —— dyn.debugger.Debugger
        plan     —— plan_step_* 的返回值，需 resolvable=True 且有 temp_breakpoint_addr
        so_name  —— 断点所在的 so；plan 本身不记录该信息，必须显式给
        timeout  —— 等命中的秒数；超时返回 executed=False（**不算成功**）

    安全：任何异常都会尝试摘钩，不让临时断点残留。
    """
    base = {"executed": False, "implemented": True}
    if not isinstance(plan, dict):
        return {**base, "error": f"plan 不是 dict（实际 {type(plan).__name__}）",
                "code": "BAD_PLAN"}
    if not (plan.get("ok") and plan.get("resolvable")):
        return {**base,
                "error": "plan 不可执行（ok/resolvable 为假），先重新 plan_step",
                "code": "PLAN_NOT_EXECUTABLE",
                "plan_reason": str(plan.get("reason", ""))[:200]}
    addr = plan.get("temp_breakpoint_addr")
    if not isinstance(addr, int):
        return {**base, "error": "plan 没有可用的 temp_breakpoint_addr",
                "code": "NO_TARGET_ADDR"}
    if not so_name:
        return {**base,
                "error": "必须显式给 so_name：plan 只记录地址，不记录所属模块",
                "code": "NEED_SO_NAME"}

    dbg = debugger
    setter = getattr(dbg, "set_breakpoint", None)
    resume = getattr(dbg, "resume", None)
    waiter = getattr(dbg, "wait_hits", None)
    remover = getattr(dbg, "remove_breakpoint", None)
    # (7) 第七次修改（2026-11-05）：不再要求 wait_hits。
    #     bug 原因：实现已改为轮询 dbg.hits，但前置检查仍要求 wait_hits 可调用，
    #               导致"没有该方法"的实现被判成 DEBUGGER_INCOMPLETE（自相矛盾）。
    #     解决方案：只要求 set_breakpoint 与 resume 两个必备能力；hits 由调用处
    #               用 getattr 兜底读，缺失时按空列表处理。
    if not all(callable(x) for x in (setter, resume)):
        return {**base, "error": "debugger 缺少 set_breakpoint/resume",
                "code": "DEBUGGER_INCOMPLETE"}

    before_state = str(getattr(dbg, "state", ""))
    before_hits = len(getattr(dbg, "hits", []) or [])

    # (9) 第九次修改（2026-11-05）：进入前记下该地址**原本是否已有断点**。
    #     bug 原因：finally 里无条件 remove_breakpoint，而 set_breakpoint 对
    #               "同地址重复下断"只更新策略（不新建），所以如果用户在该地址
    #               本来就有断点，单步结束后会把**用户自己的断点整条删掉**。
    #     解决方案：先查断点表（_hooks 以运行时地址为键）；原本有就记下它的 policy，
    #               结束时**恢复原策略**而不是删除；原本没有才真正摘钩。
    pre_existing = None
    try:
        hooks = getattr(dbg, "_hooks", None)
        rb = getattr(dbg, "rb", None)
        if isinstance(hooks, dict) and rb is not None:
            mod = rb.find_module(so_name)
            if mod is not None:
                rt_key = rb.to_runtime(addr, mod)
                rec = hooks.get(rt_key)
                if isinstance(rec, dict):
                    pre_existing = dict(rec)
    except Exception:                                     # noqa: BLE001 - 查询失败按"没有"处理
        pre_existing = None

    ok = False
    try:
        ok = bool(setter(so_name, addr, policy="hold"))
    except Exception as exc:                              # noqa: BLE001
        return {**base, "error": f"下临时断点失败：{exc}", "code": "SET_BP_FAILED"}
    if not ok:
        return {**base, "error": f"下临时断点失败（{so_name}+{addr:#x}）",
                "code": "SET_BP_FAILED"}

    # (11) 第十一次修改（2026-11-05）：条件跳转有两个可能落点，两处都要下断点。
    #      bug 原因：plan 只给 next_addr 一个落点，而条件跳转被取走时会直接跳到
    #                target、根本不经 next_addr，于是临时断点可能永不命中，
    #                表现为"单步超时"，而真实原因是落点选错了。
    #      解决方案：plan 若给出 alt_breakpoint_addr，也在那里下 hold 断点；
    #                哪个先命中，哪个就是真实落点（matched 按实际命中地址判定）。
    alt_addr = plan.get("alt_breakpoint_addr")
    extra_set: list[int] = []
    if isinstance(alt_addr, int) and alt_addr != addr:
        try:
            if setter(so_name, alt_addr, policy="hold"):
                extra_set.append(alt_addr)
        except Exception:                                 # noqa: BLE001 - 备用落点失败不影响主流程
            pass

    result = dict(base)
    try:
        # 正 paused 时先放行，否则目标不会继续跑到临时断点
        if before_state == "paused":
            try:
                resume()
            except Exception as exc:                      # noqa: BLE001
                return {**base, "error": f"放行失败：{exc}", "code": "RESUME_FAILED"}

        # (7) 第七次修改（2026-11-05）：不再把 wait_hits 当"睡一会儿"。
        #     bug 原因：Debugger.wait_hits 的语义是"有没被它取过的命中就立即返回"
        #               （内部 `while self._version <= self._wait_cursor`）。
        #               而调用方若已经停在一个命中上再单步，`_version > _wait_cursor`
        #               恒成立 → wait_hits **立刻返回** → 取不到新增命中 →
        #               0 秒就报 STEP_TIMEOUT，还写着"timeout 秒内没有命中"（谎报时长）。
        #               全库只有这里调 wait_hits（service 走 poll_events），所以必然踩中。
        #     解决方案：不依赖 wait_hits 的游标语义，改为**自己轮询命中数变化**：
        #               进入时记下 before_hits，循环等到 len(hits) 增长或超时。
        #               等待时长用单调时钟真算，回给调用方的 waited_s 是真实秒数。
        import time as _t

        t_begin = _t.monotonic()
        deadline = t_begin + max(0.0, float(timeout or 0.0))
        fresh: list = []
        while True:
            all_hits = list(getattr(dbg, "hits", []) or [])
            fresh = all_hits[before_hits:]
            if fresh:
                break
            if _t.monotonic() >= deadline:
                break
            _t.sleep(0.02)
        waited = _t.monotonic() - t_begin
        if not fresh:
            result.update({
                "error": f"等待 {waited:.2f}s 内没有新命中：可能该路径未被执行"
                         "（例如条件跳转没走这一支、或 b 之后的下一条本就不执行）",
                "code": "STEP_TIMEOUT",
                "waited_s": round(waited, 3),
                "hits_before": before_hits,
            })
            return result

        # (8) 第八次修改（2026-11-05）：优先挑**命中目标地址**的那条。
        #     bug 原因：原来直接取 fresh[-1]，若等待期间别的断点先命中
        #               （目标进程本来就有其他断点），会把别人的命中当成"单步落点"，
        #               报 matched=False 且给出错误的现场。
        #     解决方案：先在新增命中里找 static_addr == 目标 的；找不到再退回最后一条
        #               （并明确标注这是"没停到目标"）。
        hit = None
        for cand in fresh:
            if int(getattr(cand, "static_addr", 0) or 0) == addr:
                hit = cand
                break
        if hit is None:
            hit = fresh[-1]
        got_static = int(getattr(hit, "static_addr", 0) or 0)
        matched = got_static == addr
        if not matched and got_static in extra_set:
            # 命中的是条件跳转的另一条分支：这是**合法的单步结果**，不是走错
            matched = True
            result["landed_on"] = "alt_branch"
        result.update({
            "executed": True,
            "matched": matched,
            "target_addr": hex(addr),
            "so_name": so_name,
            "hit_static_addr": hex(got_static),
            "hit_runtime_addr": hex(int(getattr(hit, "runtime_addr", 0) or 0)),
            "thread_id": int(getattr(hit, "thread_id", 0) or 0),
            "held": bool(getattr(hit, "held", False)),
            "context": getattr(hit, "context", {}) or {},
            "backtrace": getattr(hit, "backtrace", []) or [],
            "dbg_state": str(getattr(dbg, "state", "")),
            "waited_s": round(waited, 3),
            "hits_before": before_hits,
        })
        if not matched:
            result["warning"] = (
                f"命中的是 {got_static:#x} 而不是目标 {addr:#x}："
                "执行流走了别的分支，**不能当作单步到位**")
        return result
    finally:
        # 收尾：原本有用户断点 → 恢复原策略；原本没有 → 摘钩
        if pre_existing is not None:
            try:
                setter(so_name, addr,
                       policy=str(pre_existing.get("policy") or "resume"))
                result["user_bp_restored"] = True
            except Exception:                             # noqa: BLE001
                result["remove_warning"] = (
                    "该地址原本有用户断点，恢复其策略失败，策略可能被单步改成 hold")
        elif callable(remover):
            try:
                remover(so_name, addr)
            except Exception:                             # noqa: BLE001
                result["remove_warning"] = "临时断点摘钩失败，可能残留在断点表里"
        # 备用落点（条件跳转的另一条分支）无论主落点是否成功都要清理
        for a in extra_set:
            if callable(remover):
                try:
                    remover(so_name, a)
                except Exception:                         # noqa: BLE001
                    pass


__all__ = [
    "plan_step_over",
    "plan_step_out",
    "plan_step_into",
    "plan_step_until_mnemonic",
    "execute_step",
]
