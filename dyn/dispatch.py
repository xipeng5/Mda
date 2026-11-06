"""全库扫描 switch 跳转表（ARM64 分发表自动发现）。

为什么需要它（与 resolve_br / read_jump_table 的分工）：
    read_jump_table  读**一张**已知地址的表
    resolve_br       解**一条** br 的目标（给定地址）
    本模块           不给定任何地址，**遍历整个 so 的所有函数**，
                     自动找出所有 switch 分发表并一次性汇总

也就是说：前两者是"我知道某处有分发，帮我看看"，
本模块是"我不知道哪里有分发，帮我把它们都找出来"。
这才是分析加固样本（VM 解释器）时真正省事的入口——实测 sg_real.so 里
光前 500 个函数就有 874 条 br，人工逐个问是不可能的。

复用而非重写：
    · 反汇编一律走 core.disasm.Disassembler（带区间缓存，且能跨数据块继续）
    · A 模式（adr + ldrsw + add + br）直接调 bridge._ti_analyse
    · 读表一律调 bridge.read_jump_table
    · 取址回溯一律调 bridge._ti_trace_table_base

(1) 第一次修改（2026-11-06）：新增本模块。
    bug 原因：resolve_br 只能对**给定地址**逐条解，而加固样本的 br 动辄上千条，
              调用方（MCP 工具/AI）得先猜地址才能问，等于没法用；
              更根本的是"这个样本里到底有哪些 switch 表"这个问题
              当时没有任何接口能回答。
    解决方案：新增全库扫描器，一次遍历所有函数、匹配三种 ARM64 常见
              分发表形态，输出统一的表清单，并给每张表打 confidence。
"""
from __future__ import annotations

from core.disasm import Disassembler

# 每种模式最多列多少个目标（返回体要能被 MCP 传，不能兆级）
_MAX_LISTED_TARGETS = 32

# br 指令前最多看多少条指令找取表指令（分发表的取址链通常很短）
_BR_WINDOW = 8

# 单条 br 解不出来时的兜底说明
_NOTE_NO_TABLE = (
    "confidence=low 或 targets 为空表示该处静态不可知（表在运行时才填充/解密，"
    "或取址链跨了寄存器传递），这类需要动态断点配合，本模块不会编造目标"
)


def _ti_import():
    """惰性拿 bridge 的内部工具（避免模块级循环导入，也便于单测打桩）。

    dyn/bridge.py 已实现好取址回溯、内存访问器与关系统一；本模块刻意
    **不复制**这些逻辑，直接借用，保证两处的判定口径永远一致。
    """
    from dyn import bridge as B

    return B


class _FastRangeHook:
    """扫描期间把 bridge._ti_disasm_range 换成"走共享 Disassembler"的版本。

    (4) 第四次修改（2026-11-06）
        bug 原因：仅把实例挂到 so 上还不够——bridge._ti_disasm_range 根本不看
                  这个属性，它内部写死了 `Disassembler(so).disasm_range(...)`，
                  每次仍新建实例，区间缓存依旧不命中（profile 复测仍 60s+）。
        解决方案：扫描期间**临时替换** bridge 模块里的 _ti_disasm_range，
                  让它优先复用本模块的共享实例；扫描结束（含异常）必定还原。
                  这是本模块对其它模块的唯一侵入点，且只在 with 块内生效，
                  对 bridge 的其它调用方零影响。

        替换后的行为与原来等价：仍然返回 Instruction 列表、仍然能跨数据块。
        唯一区别是复用实例，于是相同的 (addr,size) 命中区间缓存。
    """

    def __init__(self, B, so, disasm: Disassembler):
        self.B = B
        self.so = so
        self.disasm = disasm
        self._orig = None

    def __enter__(self):
        self._orig = getattr(self.B, "_ti_disasm_range", None)

        def _patched(so, start: int, size: int):
            # 只对本模块正在扫的 so 走快路径；别的 so 保持原行为
            if so is self.so:
                try:
                    return list(self.disasm.disasm_range(int(start), int(size)))
                except Exception:                         # noqa: BLE001
                    pass
            if callable(self._orig):
                return self._orig(so, start, size)
            return []

        try:
            self.B._ti_disasm_range = _patched
        except Exception:                                 # noqa: BLE001
            pass
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if callable(self._orig):
                self.B._ti_disasm_range = self._orig
        except Exception:                                 # noqa: BLE001
            pass
        return False


# ---------------- 可执行段判定 ----------------


def _exec_ranges(so) -> list[tuple[int, int]]:
    """可执行段区间列表 [(start, end)]。

    取 PT_LOAD 且 flags 含 X（fl & 1）。这是"这个地址是不是代码"的
    唯一可靠判据——用 so.in_load 会把 .data/.rodata 也算进来，
    而分发表的目标必然是代码。
    """
    out = []
    try:
        for va, end, _off, fl in so.exec_regions():
            if fl & 1:
                out.append((int(va), int(end)))
    except Exception:                                     # noqa: BLE001
        pass
    return out


def _in_exec(ranges: list[tuple[int, int]], addr: int) -> bool:
    """地址是否落在任一可执行段内。"""
    for lo, hi in ranges:
        if lo <= addr < hi:
            return True
    return False


# ---------------- 模式匹配 ----------------


def _index_reg(mem_op: str) -> str:
    """取 `[x23, x16, lsl #3]` 里的索引寄存器；纯立即数偏移返回空串。

    (2) 第二次修改（2026-11-06）
        bug 原因：第一版直接取逗号分隔的第 2 项，遇到 `[x21, #8]`
                  这种"基址+立即数"的写法会把 "#8" 当成寄存器名，
                  进而去回溯一个叫 "#8" 的寄存器，永远失败且掩盖真实形态。
        解决方案：第二项必须以 # 开头就视为无索引寄存器（返回空串），
                  由调用方判为"不是索引表"。
    """
    B = _ti_import()
    op = mem_op or ""
    if "[" not in op or "]" not in op:
        return ""
    inner = op[op.index("[") + 1: op.index("]")]
    parts = [p.strip() for p in inner.split(",")]
    if len(parts) < 2:
        return ""
    cand = parts[1]
    if not cand or cand.startswith("#"):
        return ""
    return B._ti_norm(cand)


def _mem_shift(mem_op: str) -> int:
    """取 `[xN, xI, lsl #3]` 的移位量；没有 lsl 返回 0。"""
    op = (mem_op or "").lower()
    if "lsl" not in op:
        return 0
    tail = op.rsplit("lsl", 1)[1]
    if "#" not in tail:
        return 0
    try:
        return int(tail.split("#", 1)[1].strip().split()[0], 0)
    except (ValueError, IndexError):
        return 0


def _find_br(insns):
    """遍历函数内所有 br/braa 指令的下标。"""
    for i, ins in enumerate(insns):
        if ins.mnemonic in ("br", "braa", "braaz"):
            yield i, ins


# ---------------- 三种模式各自的解析 ----------------


# 表基址回溯的记忆化缓存：key=(id(insns), 表寄存器, 该寄存器在该序列里的位置)。
# 同一函数内几十条 br 常常引用同一个表基址寄存器，逐条回溯会重复解码同一段
# 代码（实测最狠的函数里有 50 次）。缓存在**单次扫描内**有效，扫描结束即丢弃。
_TRACE_MEMO: dict[tuple, tuple] = {}


def _trace_table_base_memo(B, insns, before_idx: int, reg: str, so):
    """bridge._ti_trace_table_base 的记忆化包装（签名与返回值完全一致）。

    (6) 第六次修改（2026-11-06）
        bug 原因：全库扫描 19s 里，跨函数回溯要解码 16KB 代码（单次约 36ms），
                  而同一函数内的多条 br 常共用同一个表基址寄存器——
                  实测 173 个函数重复回溯，最多的一个函数回溯了 50 次，
                  等于把同一段 16KB 重复解码 50 遍。
        解决方案：按 (本函数指令序列, 表寄存器, 回溯起点) 记忆化。
                  指令序列用 id() 做主键（同一次扫描内同一个函数对象复用同一
                  list，id 稳定）；缓存会在下次扫描开始时清空（见主入口）。
                  返回结构不变，调用方无感知。
    """
    key = (id(insns), reg, int(before_idx))
    hit = _TRACE_MEMO.get(key)
    if hit is not None:
        return hit
    res = B._ti_trace_table_base(insns, before_idx, reg, so)
    _TRACE_MEMO[key] = res
    return res


def _match_signed_offset_4(insns, idx: int, so):
    """模式 A：adr/adrp 基址 + ldrsw 取 4 字节有符号偏移 + add + br。

    直接复用 bridge._ti_analyse（它已经把"跨基本块回溯表基址""用 cmp 上界
    定表长""adrp 不猜"这些坑都蹚过了），本模块只做结果格式转换。

    返回 dict 或 None（None = 形态不成立，交给下一种模式）。
    """
    B = _ti_import()
    ti = B._ti_analyse(insns, idx, so)
    if ti is None:
        return None
    return {
        "mode": "signed_offset_4",
        "table_addr": int(ti["table_addr"]),
        "code_base": int(ti["base_addr"]),
        "entry_size": int(ti["entry_size"]),
        "count": int(ti.get("count") or 16),
        "signed": True,
        "detail": ti.get("detail") or "",
        "certain": bool(ti.get("certain", True)),
    }


def _match_pointer_table(insns, idx: int, so):
    """模式 B / C 合体：`ldr xM, [xN, xIdx, lsl #k]` + `br xM` 的指针表。

    (5) 第五次修改（2026-11-06）
        bug 原因：第一版把 B（绝对指针表）与 C（byte 索引二级表）拆成两个
                  matcher 依次尝试，结果是**同一条 br 会做两次表基址回溯**。
                  profile 实测 1002 次回溯里大半是这种重复——两个 matcher 的
                  真正差别只是"窗口里有没有 ldrb/ldrh"，回溯逻辑完全一样。
        解决方案：合并成一个 matcher，回溯**只做一次**；靠窗口里是否出现
                  字节读来区分 signed/byte 两种子形态，各自标注 mode。

    两种子形态的共同本质：
        表地址都由 ``ldr 的基址寄存器``给出（不是 br 寄存器），所以都要
        往前回溯该寄存器的 adrp/adr 来历 —— 这正是 B/C 与 A 的分水岭。

    子形态判定：
        · 窗口里有 ldrb/ldrh/ldrsb/ldrsh  → mode = "byte_indexed"
          （索引来自字节读，典型是二级表/opcode 派发）
        · 否则                            → mode = "absolute_ptr_8"
          （纯指针表，索引直接来自寄存器）

    entry_size 一律跟随 ldr 的目标寄存器宽度：ldr x → 8，ldr w → 4。
    """
    B = _ti_import()
    br = insns[idx]
    br_reg = B._ti_norm(B._ti_reg_name(br.op_str))
    if not br_reg:
        return None

    lo = max(0, idx - _BR_WINDOW)
    window = insns[lo:idx]
    has_byte_load = any(
        ins.mnemonic in ("ldrb", "ldrh", "ldrsb", "ldrsh") for ins in window)

    for j in range(idx - 1, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic not in ("ldr", "ldrsw", "ldrsh"):
            continue
        dst = B._ti_norm(B._ti_reg_name(ins.op_str))
        if dst != br_reg:
            continue
        # ldrsw 是"读 4 字节有符号值"，属偏移表（模式 A），不在这里解
        if ins.mnemonic != "ldr":
            return None
        idx_reg = _index_reg(ins.op_str)
        if not idx_reg:
            return None                     # 无索引寄存器 → 不是索引表
        shift = _mem_shift(ins.op_str)
        entry_size = 8 if dst.startswith("x") else 4
        # 表项宽度必须与索引移位自洽：移位 0 或与 entry_size 匹配才算索引表
        if shift not in (0, 3 if entry_size == 8 else 2):
            return None
        table_reg = B._ti_mem_base(ins.op_str)[0]
        if not table_reg:
            return None
        # ← 回溯只在这里做一次
        table_addr, detail, certain = _trace_table_base_memo(B, insns, j, table_reg, so)
        if table_addr is None or table_addr <= 0:
            return None
        count, bound_detail = B._ti_table_count(insns, j, idx_reg)
        mode = "byte_indexed" if has_byte_load else "absolute_ptr_8"
        extra = ""
        if has_byte_load:
            bi = next(i2 for i2 in window
                      if i2.mnemonic in ("ldrb", "ldrh", "ldrsb", "ldrsh"))
            extra = f" ; byte 索引 {bi.mnemonic} {bi.op_str}"
        return {
            "mode": mode,
            "table_addr": int(table_addr),
            "code_base": 0,                 # 指针表存绝对地址，无基址偏移
            "entry_size": entry_size,
            "count": int(count),
            "signed": False,
            "detail": (f"{ins.mnemonic} {ins.op_str}{extra} ; {detail}"
                       + (f" ; {bound_detail}" if bound_detail else "")),
            "certain": bool(certain),
        }
    return None


def _match_byte_offset_table(insns, idx: int, so):
    """模式 D：**两级字节表**（adr 目标基址 + ldrb 字节索引 + add lsl #2 + br）。

    实测形态（samples/liblog.so 的 br@0x593c）：
        0x5920: adrp x4, #0x2000
        0x5928: add  x4, x4, #0xcd0      ; x4 = 0x2cd0  ← **字节表地址**
        0x5930: adr  x5, #0x58a8         ; x5 = 目标基址
        0x5934: ldrb w6, [x4, x15]       ; 从字节表取一个 u8 索引
        0x5938: add  x5, x5, x6, lsl #2  ; 目标 = 0x58a8 + byte*4
        0x593c: br   x5

    为什么单独成一种形态（不能归到 A/B/C）：
        · 不是 A：A 的索引直接乘 entry_size 从**同一张表**里读 4/8 字节有符号偏移，
          而这里读的是 **1 字节**，且偏移要再左移 2 才是字节偏移量。
        · 不是 B/C：B/C 的 br 寄存器来自 ``ldr`` 的**目标**，这里来自 ``adr`` +
          一次字节查表后的算术，br 寄存器由 adr 给基址。
        · 表地址取的是 **ldrb 的基址寄存器**（x4=0x2cd0），不是 adr 那个（x5）。

    判定条件（全部满足才认，任一不满足返回 None，绝不猜）：
        1. add 形如 `add Xb, Xb, Xi, lsl #2`，Xb 就是 br 的寄存器
        2. Xb 由窗口内的 adr/adrp 给出基址（这就是目标基址）
        3. Xi 由窗口内的 `ldrb/ldrh` 从某基址取来，该基址寄存器要能回溯出地址
           （回溯复用 bridge._ti_trace_table_base，与其它模式同一套口径）
        4. 读出的字节表项按 `base + byte * 4` 换算后**至少有一项落在可执行段**
           ——否则说明这不是分发表，宁可放弃

    返回的 code_base 是 adr 的基址（目标 = code_base + entry*4），
    table_addr 是字节表地址，entry_size 固定 1（字节表项宽度）。
    A 类 offset 表项的语义在 read_jump_table 里不支持"字节*4"，所以本模式的
    targets 由 _read_byte_table_targets 自己算（仍复用 read_jump_table 拿原始项）。
    """
    B = _ti_import()
    br = insns[idx]
    br_reg = B._ti_norm(B._ti_reg_name(br.op_str))
    if not br_reg:
        return None

    lo = max(0, idx - _BR_WINDOW)
    window = insns[lo:idx]

    # ---- ① add Xb, Xb, Xi, lsl #2（Xb == br 寄存器）----
    add_ins = add_pos = None
    for j in range(idx - 1, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic != "add":
            continue
        low = (ins.op_str or "").lower()
        if "lsl #2" not in low:
            continue
        ops = [p.strip() for p in (ins.op_str or "").split(",")]
        if len(ops) != 4:
            continue
        if B._ti_norm(ops[0]) != br_reg or B._ti_norm(ops[1]) != br_reg:
            continue
        add_ins, add_pos = ins, j
        index_reg = B._ti_norm(ops[2])
        break
    if add_ins is None:
        return None

    # ---- ② index 寄存器由 ldrb/ldrh 从某基址取来 ----
    byte_ins = None
    for j in range(add_pos - 1, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic not in ("ldrb", "ldrh", "ldrsb", "ldrsh"):
            continue
        if B._ti_norm(B._ti_reg_name(ins.op_str)) != index_reg:
            continue
        byte_ins = ins
        break
    if byte_ins is None:
        return None
    table_reg = B._ti_mem_base(byte_ins.op_str)[0]
    if not table_reg:
        return None
    table_addr, tdetail, tcertain = _trace_table_base_memo(
        B, insns, insns.index(byte_ins), table_reg, so)
    if not table_addr or table_addr <= 0:
        return None

    # ---- ③ adr/adrp 给出目标基址（br 寄存器的来历）----
    base_addr = None
    base_ins = None
    for j in range(add_pos - 1, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic in ("adr", "adrp") and B._ti_writes(ins, br_reg):
            base_addr = B._ti_imm(ins)
            base_ins = ins
            # adrp 只给页基址，还需后续 add 补偏移；这里要求紧接着有 add
            if ins.mnemonic == "adrp":
                for k in range(j + 1, add_pos):
                    ins2 = insns[k]
                    if ins2.mnemonic == "add" and B._ti_writes(ins2, br_reg):
                        imm2 = B._ti_imm(ins2)
                        if imm2 is not None:
                            base_addr = (base_addr or 0) + imm2
                            base_ins = ins2
                        break
            break
    if not base_addr or base_addr <= 0:
        return None

    # ---- ④ 校验：字节表项换算后至少一项落在可执行段 ----
    ranges = _exec_ranges(so)
    if not ranges:
        return None
    raw = _read_bytes(so, int(table_addr), 64)
    if not raw:
        return None
    hit = 0
    for b in raw[:32]:
        if _in_exec(ranges, int(base_addr) + b * 4):
            hit += 1
    if hit == 0:
        return None                     # 全都不指向代码 → 不是分发表

    count, bound_detail = B._ti_table_count(insns, add_pos, index_reg)
    return {
        "mode": "byte_offset_table",
        "table_addr": int(table_addr),
        "code_base": int(base_addr),
        "entry_size": 1,                # 字节表项就是 1 字节
        "count": max(1, min(int(count), 256)),
        "signed": False,
        "byte_index": True,             # 告诉读表函数"目标 = base + byte*4"
        "detail": (f"{base_ins.mnemonic} {base_ins.op_str} ; "
                   f"{byte_ins.mnemonic} {byte_ins.op_str} ; "
                   f"add {add_ins.op_str} ; 字节表 {table_addr:#x}（{tdetail}）"
                   + (f" ; {bound_detail}" if bound_detail else "")),
        "certain": bool(tcertain),
    }


def _read_bytes(so, addr: int, size: int) -> bytes:
    """读 so 静态文件的原始字节（复用 bridge 的段表换算，避免 VA≠文件偏移）。"""
    B = _ti_import()
    try:
        return B._read_so_bytes(so, int(addr), int(size))
    except Exception:                                     # noqa: BLE001
        return b""


# 匹配顺序很重要：A 的判据最强（adr+ldrsw+add 三段俱全），先认；
# B 认指针表；C 只在"窗口里有字节读"时才进来兜底。
_MATCHERS = (
    _match_signed_offset_4,
    _match_pointer_table,
    _match_byte_offset_table,
)


def _read_table_targets(B, so_name: str, so, parsed: dict) -> list[int]:
    """按模式语义读出这张表的全部目标（复用 read_jump_table 读原始项）。

    (7) 第七次修改（2026-11-06）
        bug 原因：read_jump_table 的语义是 `target = code_base + entry`
                  （entry 为 4/8 字节有符号/无符号值）。而新模式
                  byte_offset_table 的表项是 **1 字节**、且目标 = base + byte*4，
                  直接把 entry_size=1 丢给它，会按 4 字节解包并漏掉 *4，
                  算出来的目标全是错的（比不给结果更糟）。
        解决方案：本函数做模式分流——
                  · byte_offset_table：自己按 1 字节读、按 *4 换算（表项语义特殊，
                    无法用 read_jump_table 的通用公式表达）
                  · 其它模式：原样交给 read_jump_table，不做二次计算
                  两条路径都只返回"读出来的值"，可执行段过滤统一放在上层做。
    """
    mode = parsed.get("mode")
    if mode == "byte_offset_table":
        count = max(1, min(int(parsed.get("count") or 16), 256))
        raw = _read_bytes(so, int(parsed["table_addr"]), count)
        if not raw:
            return []
        base = int(parsed["code_base"])
        return [base + int(b) * 4 for b in raw]

    raw = B.read_jump_table(
        so_name,
        int(parsed["table_addr"]),
        entry_size=int(parsed["entry_size"]),
        count=max(1, min(int(parsed["count"] or 16), 4096)),
        code_base=int(parsed["code_base"]),
        signed=bool(parsed["signed"]),
        so=so,
    )
    if not raw.get("ok"):
        return []
    return [int(t, 16) if isinstance(t, str) else int(t)
            for t in (raw.get("targets") or [])]


# ---------------- 置信度 ----------------


def _confidence(targets: list[int], ranges: list[tuple[int, int]],
                min_entries: int, certain: bool = True) -> str:
    """按"目标是否落在可执行段"给置信度。

    high   全部落在可执行段且数量 >= min_entries
    medium 多数（>=50%）落在可执行段，或全部可执行但数量偏少
    low    解出目标但多数不可执行（很可能是误报，如实标注）
    """
    if not targets:
        return "low"
    ok = sum(1 for t in targets if _in_exec(ranges, t))
    ratio = ok / len(targets)
    if ratio == 1.0 and ok >= min_entries:
        return "high"
    if ratio >= 0.5:
        return "medium"
    return "low"


# ---------------- 主入口 ----------------


def find_dispatch_tables(so_name: str, so=None, session=None,
                         max_tables: int = 200,
                         min_entries: int = 3) -> dict:
    """全库扫描：找出 so 里**所有** switch 跳转表。

    参数：
        so_name      要扫描的 so 名（mda 会话里的键）
        so           直接给 SoFile 可绕过会话查找（离线单测用）
        session      core.session.Session；so 为 None 时用它找 so
        max_tables   最多返回多少张表（防止加固样本刷出上万个）
        min_entries  少于这么多目标就不算一张可信的 switch 表

    返回：
        {ok, implemented, so_name, tables[], table_count,
         scanned_functions, scanned_instructions, elapsed_ms, mode_counts{}, note}

        tables 每项：
            table_addr / found_at_br / enclosing_function / mode / entry_size /
            code_base / resolved_entries / targets[<=32] / targets_in_executable /
            confidence / detail

        mode ∈ signed_offset_4（A）/ absolute_ptr_8（B）/ byte_indexed（C）

    绝不算假：形态不成立就跳过；表读不出有效项就不进结果（或在 note 里说明）。
    """
    import time

    B = _ti_import()

    t0 = time.time()

    # ---- 取 so ----
    if so is None:
        try:
            use_session = session
            if use_session is None:
                from mcp_server.tools import get_session

                use_session = get_session()
            so = B._find_so(use_session, so_name)
        except Exception:                                 # noqa: BLE001
            so = None
    if so is None:
        return {"ok": False, "code": "SO_NOT_LOADED",
                "error": f"{so_name} 未加载到 mda；先调 load_so"}

    ranges = _exec_ranges(so)
    if not ranges:
        return {"ok": False, "code": "NO_EXEC_SEGMENT",
                "error": f"{so_name} 没有可执行段，无法判断表项是否指向代码"}

    # ---- 反汇编器只建一次（复用区间缓存，绝不在循环里 new）----
    disasm = None
    try:
        disasm = Disassembler(so)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "DISASM_INIT_FAILED",
                "error": f"Disassembler 初始化失败：{exc}"}

    fns = []
    try:
        fns = list(so.function_list)
    except Exception:                                     # noqa: BLE001
        try:
            fns = sorted(so.functions.values(),
                         key=lambda f: int(getattr(f, "addr", 0) or 0))
        except Exception:                                 # noqa: BLE001
            fns = []

    _TRACE_MEMO.clear()   # 每次扫描独立，避免上一轮的行号/id 复用残留

    # 扫描期间让 bridge 的跨函数回溯复用同一个 Disassembler（区间缓存生效，
    # 这是把全库扫描从 38.5s 压到秒级的关键，见 _FastRangeHook 的说明）
    with _FastRangeHook(B, so, disasm):
        (tables, _seen, scanned_insns,
         truncated, mode_counts) = _scan_functions(
            B, so, disasm, fns, ranges, so_name,
            int(max_tables), int(min_entries), [], set(), {})

    # 置信度高、目标多的排前面——调用方通常只关心最像 switch 的几张
    order = {"high": 0, "medium": 1, "low": 2}
    tables.sort(key=lambda t: (order.get(t["confidence"], 9),
                               -int(t["resolved_entries"]),
                               int(t["table_addr"], 16)))

    elapsed = (time.time() - t0) * 1000.0
    notes = [_NOTE_NO_TABLE]
    if truncated:
        notes.append(f"已达 max_tables={int(max_tables)} 上限，扫描提前停止，结果不完整")
    if not tables:
        notes.append("没有找到满足条件的跳转表（可能是样本里确实没有 switch，"
                     "或分发表在运行时才构造）")
    low = sum(1 for t in tables if t["confidence"] == "low")
    if low:
        notes.append(f"其中 {low} 张为 low（多数目标不在可执行段，可能是误报，请人工确认）")

    return {
        "ok": True,
        "implemented": True,
        "so_name": so_name,
        "tables": tables,
        "table_count": len(tables),
        "scanned_functions": len(fns),
        "scanned_instructions": scanned_insns,
        "mode_counts": mode_counts,
        "elapsed_ms": round(elapsed, 1),
        "note": "；".join(notes),
    }


def _scan_functions(B, so, disasm, fns, ranges, so_name,
                    max_tables: int, min_entries: int,
                    tables: list, seen_table: set, mode_counts: dict):
    """逐函数扫描主体（从 find_dispatch_tables 抽出来，便于套共享反汇编器）。

    返回 (tables, seen_table, scanned_insns, truncated, mode_counts)。
    """
    scanned_insns = 0
    truncated = False

    for fn in fns:
        if len(tables) >= max_tables:
            truncated = True
            break
        fn_addr = int(getattr(fn, "addr", 0) or 0)
        try:
            insns = disasm.disasm_function(fn_addr)
        except Exception:                                 # noqa: BLE001
            continue
        if not insns:
            continue
        scanned_insns += len(insns)

        for idx, _br in _find_br(insns):
            if len(tables) >= int(max_tables):
                truncated = True
                break
            parsed = None
            for matcher in _MATCHERS:
                try:
                    parsed = matcher(insns, idx, so)
                except Exception:                         # noqa: BLE001
                    parsed = None
                if parsed is not None:
                    break
            if parsed is None:
                continue

            key = (int(parsed["table_addr"]), parsed["mode"])
            if key in seen_table:
                continue                      # 同一张表被多处 br 引用：只记一次
            seen_table.add(key)

            # ---- 读表（复用 read_jump_table，绝不自造表数据）----
            all_targets = _read_table_targets(B, so_name, so, parsed)
            if not all_targets:
                continue                      # 读不出就不进结果，不编造
            if not all_targets:
                continue

            in_exec = [t for t in all_targets if _in_exec(ranges, t)]
            # 目标一个都不在可执行段 → 表地址算错了，宁可丢掉也不报假表
            if not in_exec:
                continue

            conf = _confidence(in_exec, ranges, min_entries, parsed["certain"])
            entry = {
                "table_addr": hex(int(parsed["table_addr"])),
                "found_at_br": hex(int(_br.addr)),
                "enclosing_function": (getattr(fn, "name", "") or f"sub_{fn_addr:x}"),
                "enclosing_function_addr": hex(fn_addr),
                "mode": parsed["mode"],
                "entry_size": int(parsed["entry_size"]),
                "code_base": hex(int(parsed["code_base"])) if parsed["code_base"] else None,
                "resolved_entries": len(in_exec),
                "targets": [hex(t) for t in in_exec[:_MAX_LISTED_TARGETS]],
                "targets_in_executable": True,
                "confidence": conf,
                "detail": parsed["detail"],
            }
            if len(in_exec) > _MAX_LISTED_TARGETS:
                entry["targets_truncated"] = True
                entry["targets_total"] = len(in_exec)
            tables.append(entry)
            mode_counts[parsed["mode"]] = mode_counts.get(parsed["mode"], 0) + 1

    return tables, seen_table, scanned_insns, truncated, mode_counts
