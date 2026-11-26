"""DEX 字节码反汇编：指令格式表 + 上下文相关的 payload 处理。

—— 坑 3：变长指令的 code unit 数 ——

DEX 指令长度不写在指令里，全靠格式（instruction-formats）决定。**每一处
unit 数写错，后面整条指令流都会错位**，而且错位后仍然能解出「看起来正常」
的指令，是最难发现的一类 bug。两个最容易记错的点：

    · move-wide/16 (0x06) 是 **32x = 3 units**，不是 2 units。
      2 units 的是 22x 族：move/from16 (0x02)、move-wide/from16 (0x05)、
      move-object/from16 (0x08) —— 它们后面只跟 1 个 unit 的寄存器号。
      32x 族（move/16 0x03、move-wide/16 0x06、move-object/16 0x09）
      后面跟 2 个 unit（vAAAA、vBBBB 各 16 bit）。
    · 51l（const-wide，0x18）是 5 units，45cc/4rcc 是 4 units。
      这两族很少出现，但一旦出现同样的错位。

本模块的 unit 数来自 FORMAT_UNITS 表，逐格式对齐官方 instruction-formats；
tests/test_dex.py 里对 4 个 dex（含 038 的新格式）做了逐指令交叉验证。

—— 坑 4：payload ident 是上下文相关的 ——

0x0100 / 0x0200 / 0x0300 这几个 16-bit 值**本身不是指令**，它们是
packed-switch-payload / sparse-switch-payload / fill-array-data-payload 的
ident。只有在下面这种关系里它们才是 payload：

    0x2b packed-switch vAA, +BBBBBBBB      -> 目标 = 本指令偏移 + 偏移
    0x2c sparse-switch vAA, +BBBBBBBB      -> 同上
    0x26 fill-array-data vAA, +BBBBBBBB    -> 同上

也就是说，payload 的地址**由前面那条 switch/fill 指令给出**，解码到那里时
必须按 payload 结构解析并按其长度跳过；而顺序解码时如果仅仅遇到 0x0100 而
没有这样的上下文，它只是「一条 nop（opcode=0x00）加一个参数字节」，必须按
nop 处理并留下标记（本模块用 note 标记，见 Insn.note）。

不区分上下文、见到 0x0100 就当 payload 解析的写法，会把普通的 nop 序列
误当 payload，进而按「size」跳过任意长的字节 —— 静默产出垃圾。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# ---------- 格式 -> code unit 数 ----------

# 官方 instruction-formats。key 是格式名，value 是占用的 16-bit code unit 数。
FORMAT_UNITS: dict[str, int] = {
    "10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1,
    "20t": 2, "22x": 2, "21t": 2, "21s": 2, "21h": 2, "21c": 2,
    "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2,
    "32x": 3, "30t": 3, "31t": 3, "31i": 3, "31c": 3, "35c": 3, "3rc": 3,
    "45cc": 4, "4rcc": 4,
    "51l": 5,
}

# 引用种类：决定操作数里要解析哪张表
REF_NONE = ""
REF_STRING = "string"
REF_TYPE = "type"
REF_FIELD = "field"
REF_METHOD = "method"
REF_PROTO = "proto"
REF_CALL_SITE = "call_site"
REF_METHOD_HANDLE = "method_handle"

# ---------- opcode 表：0x00..0xff 顺序排列 ----------
# 每项 (助记符, 格式, 引用种类)。
# 0xfa..0xff 是 DEX 038 起才引入的指令；DEX 035 里这些字节非法，
# 但格式表按 038 的布局解（与 dexdump 一致，dexdump 也只用一张表）。
OPCODES: list[tuple[str, str, str]] = [
    # 0x00
    ("nop", "10x", REF_NONE),
    ("move", "12x", REF_NONE),
    ("move/from16", "22x", REF_NONE),
    ("move/16", "32x", REF_NONE),
    ("move-wide", "12x", REF_NONE),
    ("move-wide/from16", "22x", REF_NONE),
    ("move-wide/16", "32x", REF_NONE),
    ("move-object", "12x", REF_NONE),
    ("move-object/from16", "22x", REF_NONE),
    ("move-object/16", "32x", REF_NONE),
    ("move-result", "11x", REF_NONE),
    ("move-result-wide", "11x", REF_NONE),
    ("move-result-object", "11x", REF_NONE),
    ("move-exception", "11x", REF_NONE),
    ("return-void", "10x", REF_NONE),
    ("return", "11x", REF_NONE),
    # 0x10
    ("return-wide", "11x", REF_NONE),
    ("return-object", "11x", REF_NONE),
    ("const/4", "11n", REF_NONE),
    ("const/16", "21s", REF_NONE),
    ("const", "31i", REF_NONE),
    ("const/high16", "21h", REF_NONE),
    ("const-wide/16", "21s", REF_NONE),
    ("const-wide/32", "31i", REF_NONE),
    ("const-wide", "51l", REF_NONE),
    ("const-wide/high16", "21h", REF_NONE),
    ("const-string", "21c", REF_STRING),
    ("const-string/jumbo", "31c", REF_STRING),
    ("const-class", "21c", REF_TYPE),
    ("monitor-enter", "11x", REF_NONE),
    ("monitor-exit", "11x", REF_NONE),
    ("check-cast", "21c", REF_TYPE),
    # 0x20
    ("instance-of", "22c", REF_TYPE),
    ("array-length", "12x", REF_NONE),
    ("new-instance", "21c", REF_TYPE),
    ("new-array", "22c", REF_TYPE),
    ("filled-new-array", "35c", REF_TYPE),
    ("filled-new-array/range", "3rc", REF_TYPE),
    ("fill-array-data", "31t", REF_NONE),
    ("throw", "11x", REF_NONE),
    ("goto", "10t", REF_NONE),
    ("goto/16", "20t", REF_NONE),
    ("goto/32", "30t", REF_NONE),
    ("packed-switch", "31t", REF_NONE),
    ("sparse-switch", "31t", REF_NONE),
    ("cmpl-float", "23x", REF_NONE),
    ("cmpg-float", "23x", REF_NONE),
    ("cmpl-double", "23x", REF_NONE),
    # 0x30
    ("cmpg-double", "23x", REF_NONE),
    ("cmp-long", "23x", REF_NONE),
    ("if-eq", "22t", REF_NONE),
    ("if-ne", "22t", REF_NONE),
    ("if-lt", "22t", REF_NONE),
    ("if-ge", "22t", REF_NONE),
    ("if-gt", "22t", REF_NONE),
    ("if-le", "22t", REF_NONE),
    ("if-eqz", "21t", REF_NONE),
    ("if-nez", "21t", REF_NONE),
    ("if-ltz", "21t", REF_NONE),
    ("if-gez", "21t", REF_NONE),
    ("if-gtz", "21t", REF_NONE),
    ("if-lez", "21t", REF_NONE),
    ("unused-3e", "10x", REF_NONE),
    ("unused-3f", "10x", REF_NONE),
    # 0x40
    ("unused-40", "10x", REF_NONE),
    ("unused-41", "10x", REF_NONE),
    ("unused-42", "10x", REF_NONE),
    ("unused-43", "10x", REF_NONE),
    ("aget", "23x", REF_NONE),
    ("aget-wide", "23x", REF_NONE),
    ("aget-object", "23x", REF_NONE),
    ("aget-boolean", "23x", REF_NONE),
    ("aget-byte", "23x", REF_NONE),
    ("aget-char", "23x", REF_NONE),
    ("aget-short", "23x", REF_NONE),
    ("aput", "23x", REF_NONE),
    ("aput-wide", "23x", REF_NONE),
    ("aput-object", "23x", REF_NONE),
    ("aput-boolean", "23x", REF_NONE),
    # 0x50
    ("aput-byte", "23x", REF_NONE),
    ("aput-char", "23x", REF_NONE),
    ("aput-short", "23x", REF_NONE),
    ("iget", "22c", REF_FIELD),
    ("iget-wide", "22c", REF_FIELD),
    ("iget-object", "22c", REF_FIELD),
    ("iget-boolean", "22c", REF_FIELD),
    ("iget-byte", "22c", REF_FIELD),
    ("iget-char", "22c", REF_FIELD),
    ("iget-short", "22c", REF_FIELD),
    ("iput", "22c", REF_FIELD),
    ("iput-wide", "22c", REF_FIELD),
    ("iput-object", "22c", REF_FIELD),
    ("iput-boolean", "22c", REF_FIELD),
    ("iput-byte", "22c", REF_FIELD),
    # 0x60
    ("iput-char", "22c", REF_FIELD),
    ("iput-short", "22c", REF_FIELD),
    ("sget", "21c", REF_FIELD),
    ("sget-wide", "21c", REF_FIELD),
    ("sget-object", "21c", REF_FIELD),
    ("sget-boolean", "21c", REF_FIELD),
    ("sget-byte", "21c", REF_FIELD),
    ("sget-char", "21c", REF_FIELD),
    ("sget-short", "21c", REF_FIELD),
    ("sput", "21c", REF_FIELD),
    ("sput-wide", "21c", REF_FIELD),
    ("sput-object", "21c", REF_FIELD),
    ("sput-boolean", "21c", REF_FIELD),
    ("sput-byte", "21c", REF_FIELD),
    ("sput-char", "21c", REF_FIELD),
    ("sput-short", "21c", REF_FIELD),
    # 0x70
    ("invoke-virtual", "35c", REF_METHOD),
    ("invoke-super", "35c", REF_METHOD),
    ("invoke-direct", "35c", REF_METHOD),
    ("invoke-static", "35c", REF_METHOD),
    ("invoke-interface", "35c", REF_METHOD),
    ("unused-73", "10x", REF_NONE),
    ("invoke-virtual/range", "3rc", REF_METHOD),
    ("invoke-super/range", "3rc", REF_METHOD),
    ("invoke-direct/range", "3rc", REF_METHOD),
    ("invoke-static/range", "3rc", REF_METHOD),
    ("invoke-interface/range", "3rc", REF_METHOD),
    ("unused-79", "10x", REF_NONE),
    ("unused-7a", "10x", REF_NONE),
    ("neg-int", "12x", REF_NONE),
    ("not-int", "12x", REF_NONE),
    ("neg-long", "12x", REF_NONE),
    # 0x80
    ("not-long", "12x", REF_NONE),
    ("neg-float", "12x", REF_NONE),
    ("neg-double", "12x", REF_NONE),
    ("int-to-long", "12x", REF_NONE),
    ("int-to-float", "12x", REF_NONE),
    ("int-to-double", "12x", REF_NONE),
    ("long-to-int", "12x", REF_NONE),
    ("long-to-float", "12x", REF_NONE),
    ("long-to-double", "12x", REF_NONE),
    ("float-to-int", "12x", REF_NONE),
    ("float-to-long", "12x", REF_NONE),
    ("float-to-double", "12x", REF_NONE),
    ("double-to-int", "12x", REF_NONE),
    ("double-to-long", "12x", REF_NONE),
    ("double-to-float", "12x", REF_NONE),
    ("int-to-byte", "12x", REF_NONE),
    # 0x90
    ("int-to-char", "12x", REF_NONE),
    ("int-to-short", "12x", REF_NONE),
    ("add-int", "23x", REF_NONE),
    ("sub-int", "23x", REF_NONE),
    ("mul-int", "23x", REF_NONE),
    ("div-int", "23x", REF_NONE),
    ("rem-int", "23x", REF_NONE),
    ("and-int", "23x", REF_NONE),
    ("or-int", "23x", REF_NONE),
    ("xor-int", "23x", REF_NONE),
    ("shl-int", "23x", REF_NONE),
    ("shr-int", "23x", REF_NONE),
    ("ushr-int", "23x", REF_NONE),
    ("add-long", "23x", REF_NONE),
    ("sub-long", "23x", REF_NONE),
    ("mul-long", "23x", REF_NONE),
    # 0xa0
    ("div-long", "23x", REF_NONE),
    ("rem-long", "23x", REF_NONE),
    ("and-long", "23x", REF_NONE),
    ("or-long", "23x", REF_NONE),
    ("xor-long", "23x", REF_NONE),
    ("shl-long", "23x", REF_NONE),
    ("shr-long", "23x", REF_NONE),
    ("ushr-long", "23x", REF_NONE),
    ("add-float", "23x", REF_NONE),
    ("sub-float", "23x", REF_NONE),
    ("mul-float", "23x", REF_NONE),
    ("div-float", "23x", REF_NONE),
    ("rem-float", "23x", REF_NONE),
    ("add-double", "23x", REF_NONE),
    ("sub-double", "23x", REF_NONE),
    ("mul-double", "23x", REF_NONE),
    # 0xb0
    ("div-double", "23x", REF_NONE),
    ("rem-double", "23x", REF_NONE),
    ("add-int/2addr", "12x", REF_NONE),
    ("sub-int/2addr", "12x", REF_NONE),
    ("mul-int/2addr", "12x", REF_NONE),
    ("div-int/2addr", "12x", REF_NONE),
    ("rem-int/2addr", "12x", REF_NONE),
    ("and-int/2addr", "12x", REF_NONE),
    ("or-int/2addr", "12x", REF_NONE),
    ("xor-int/2addr", "12x", REF_NONE),
    ("shl-int/2addr", "12x", REF_NONE),
    ("shr-int/2addr", "12x", REF_NONE),
    ("ushr-int/2addr", "12x", REF_NONE),
    ("add-long/2addr", "12x", REF_NONE),
    ("sub-long/2addr", "12x", REF_NONE),
    ("mul-long/2addr", "12x", REF_NONE),
    ("div-long/2addr", "12x", REF_NONE),
    # 0xc0
    ("rem-long/2addr", "12x", REF_NONE),
    ("and-long/2addr", "12x", REF_NONE),
    ("or-long/2addr", "12x", REF_NONE),
    ("xor-long/2addr", "12x", REF_NONE),
    ("shl-long/2addr", "12x", REF_NONE),
    ("shr-long/2addr", "12x", REF_NONE),
    ("ushr-long/2addr", "12x", REF_NONE),
    ("add-float/2addr", "12x", REF_NONE),
    ("sub-float/2addr", "12x", REF_NONE),
    ("mul-float/2addr", "12x", REF_NONE),
    ("div-float/2addr", "12x", REF_NONE),
    ("rem-float/2addr", "12x", REF_NONE),
    ("add-double/2addr", "12x", REF_NONE),
    ("sub-double/2addr", "12x", REF_NONE),
    ("mul-double/2addr", "12x", REF_NONE),
    ("div-double/2addr", "12x", REF_NONE),
    # 0xd0
    ("rem-double/2addr", "12x", REF_NONE),
    ("add-int/lit16", "22s", REF_NONE),
    ("rsub-int", "22s", REF_NONE),
    ("mul-int/lit16", "22s", REF_NONE),
    ("div-int/lit16", "22s", REF_NONE),
    ("rem-int/lit16", "22s", REF_NONE),
    ("and-int/lit16", "22s", REF_NONE),
    ("or-int/lit16", "22s", REF_NONE),
    ("xor-int/lit16", "22s", REF_NONE),
    ("add-int/lit8", "22b", REF_NONE),
    ("rsub-int/lit8", "22b", REF_NONE),
    ("mul-int/lit8", "22b", REF_NONE),
    ("div-int/lit8", "22b", REF_NONE),
    ("rem-int/lit8", "22b", REF_NONE),
    ("and-int/lit8", "22b", REF_NONE),
    ("or-int/lit8", "22b", REF_NONE),
    # 0xe0
    ("xor-int/lit8", "22b", REF_NONE),
    ("shl-int/lit8", "22b", REF_NONE),
    ("shr-int/lit8", "22b", REF_NONE),
    ("ushr-int/lit8", "22b", REF_NONE),
    ("unused-e3", "10x", REF_NONE),
    ("unused-e4", "10x", REF_NONE),
    ("unused-e5", "10x", REF_NONE),
    ("unused-e6", "10x", REF_NONE),
    ("unused-e7", "10x", REF_NONE),
    ("unused-e8", "10x", REF_NONE),
    ("unused-e9", "10x", REF_NONE),
    ("unused-ea", "10x", REF_NONE),
    ("unused-eb", "10x", REF_NONE),
    ("unused-ec", "10x", REF_NONE),
    ("unused-ed", "10x", REF_NONE),
    ("unused-ee", "10x", REF_NONE),
    # 0xf0
    ("unused-ef", "10x", REF_NONE),
    ("unused-f0", "10x", REF_NONE),
    ("unused-f1", "10x", REF_NONE),
    ("unused-f2", "10x", REF_NONE),
    ("unused-f3", "10x", REF_NONE),
    ("unused-f4", "10x", REF_NONE),
    ("unused-f5", "10x", REF_NONE),
    ("unused-f6", "10x", REF_NONE),
    ("unused-f7", "10x", REF_NONE),
    ("unused-f8", "10x", REF_NONE),
    ("unused-f9", "10x", REF_NONE),
    ("invoke-polymorphic", "45cc", REF_METHOD),
    ("invoke-polymorphic/range", "4rcc", REF_METHOD),
    ("invoke-custom", "35c", REF_CALL_SITE),
    ("invoke-custom/range", "3rc", REF_CALL_SITE),
    ("const-method-handle", "21c", REF_METHOD_HANDLE),
    ("const-method-type", "21c", REF_PROTO),
]

if len(OPCODES) != 256:  # 表少一项就整体错位，这里直接拒绝加载
    raise AssertionError(f"opcode 表必须是 256 项，实际 {len(OPCODES)}")

MNEMONIC = [o[0] for o in OPCODES]
FORMAT = [o[1] for o in OPCODES]
REF = [o[2] for o in OPCODES]
WIDTH = [FORMAT_UNITS[o[1]] for o in OPCODES]

# 会把控制流引向 payload 的三条指令 -> 对应 payload 的 ident
PAYLOAD_OP = {0x2b: 0x0100, 0x2c: 0x0200, 0x26: 0x0300}
PAYLOAD_IDENT_NAME = {0x0100: "packed-switch-data", 0x0200: "sparse-switch-data",
                      0x0300: "array-data"}

# (1) 第一次修改（2026-11-26）
# bug 原因：0xfc/0xfd（invoke-custom / invoke-custom/range）的操作数索引是 call_site_idx
#           而非 method_idx，混入 INVOKE_OPS 会导致 dex_callers 把 call_site_idx 误当 method_idx 误报调用者。
# 解决方案：从 INVOKE_OPS 中移除 0xfc/0xfd，仅保留引用 method_ids 的 invoke-* 指令。
# invoke-* 家族（仅引用 method_ids 的指令；不含 invoke-custom），dex_callers 只扫这些
INVOKE_OPS = frozenset({0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78,
                        0xfa, 0xfb})


# ---------- 位段取值的工具 ----------

def _s4(v: int) -> int:
    """4 位有符号整数符号扩展（-8..7），专供 11n（const/4）格式。"""
    v &= 0xF
    return v - 0x10 if v >= 8 else v


def _s8(v: int) -> int:
    return v - 0x100 if v & 0x80 else v


def _s16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def _s32(v: int) -> int:
    return v - 0x100000000 if v & 0x80000000 else v


def _s64(v: int) -> int:
    return v - 0x10000000000000000 if v & 0x8000000000000000 else v


def _bytes_at(tables, unit_off: int, n: int) -> bytes:
    """按 code unit 偏移取原始字节（method 内的数据区，如 array payload 内容）。"""
    data = tables.data
    off = tables.insns_base + unit_off * 2
    return data[off:off + n]


def _escape(raw: str) -> str:
    """字符串转义：控制字符/引号/反斜杠写成 \\xNN 或 \\uNNNN（与 dexdump 同风格）。"""
    out = []
    for ch in raw:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o == 0x0A:
            out.append("\\n")
        elif o == 0x0D:
            out.append("\\r")
        elif o == 0x09:
            out.append("\\t")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o < 0x100:
            out.append(f"\\x{o:02x}")
        elif o < 0x10000:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out)


# ---------- 数据结构 ----------

@dataclass
class Payload:
    """一个 switch / fill-array-data 的 payload。"""

    unit_off: int
    ident: int
    units: int
    # 引用这个 payload 的 switch 指令偏移。payload 里的 target 是**相对该指令**
    # 的偏移（官方 instruction-formats: "relative to the switch instruction"），
    # 不是相对 payload 起点 —— 拿 payload 起点当基址算出来的目标会落在 payload 内部。
    ref_off: int = -1
    first_key: int = 0
    keys: tuple[int, ...] = ()
    targets: tuple[int, ...] = ()
    element_width: int = 0
    size: int = 0
    data_unit_off: int = 0

    @property
    def label(self) -> str:
        return PAYLOAD_IDENT_NAME.get(self.ident, "payload")


@dataclass
class Insn:
    """一条反汇编结果（payload 也是一个 Insn，is_payload=True）。"""

    unit_off: int
    byte_off: int
    units: int
    mnemonic: str
    operands: str = ""
    raw_hex: str = ""
    ref_kind: str = REF_NONE
    ref_idx: int = -1
    ref_text: str = ""
    is_payload: bool = False
    payload: Payload | None = None
    note: str = ""
    detail: list[str] = field(default_factory=list)


# ---------- payload 解析 ----------

def payload_units(units, insns_size: int, off: int) -> int:
    """算 payload 占多少 code unit（不解析内容，供调用者快速跳过）。

    公式（官方 instruction-formats / dexdump 实测一致）：
        packed-switch-payload : 4 + size*2   （ident,size,first_key 各 1 unit，
                                              targets 每条 2 units）
        sparse-switch-payload : 2 + size*4   （keys 与 targets 各 size*2 units）
        fill-array-data-payload: 4 + ceil(size*element_width/2)
    算不出来时返回 1（安全停一步，避免越界跳飞）。
    """
    try:
        ident = units[off]
        if ident == 0x0100:
            return 4 + units[off + 1] * 2
        if ident == 0x0200:
            return 2 + units[off + 1] * 4
        if ident == 0x0300:
            width = units[off + 1]
            size = units[off + 2] | (units[off + 3] << 16)
            return 4 + (size * width + 1) // 2
    except IndexError:
        return 1
    return 1


def _parse_payload(tables, units, insns_size: int, off: int, expect_ident: int,
                   switch_off: int = -1) -> tuple[Payload | None, str]:
    """按 offset 解析 payload；返回 (Payload, 错误说明)。"""
    if off < 0 or off >= insns_size:
        return None, f"payload 偏移 u0x{off:x} 超出 insns 范围（共 {insns_size} units）"
    if off + 2 > insns_size:
        return None, f"payload 头部越界（u0x{off:x}）"
    ident = units[off]
    if ident != expect_ident:
        return None, (
            f"payload ident 不匹配：此处是 0x{ident:04x}，期望 0x{expect_ident:04x}"
            "（说明这条指令的偏移算错了，或该位置根本不是 payload）"
        )
    total = payload_units(units, insns_size, off)
    if off + total > insns_size:
        return None, f"payload 声明 {total} units，实际剩余只有 {insns_size - off} units"
    if off % 2:
        return None, f"payload 起点 u0x{off:x} 不是偶地址（DEX 要求 payload 偶数对齐）"

    if ident == 0x0100:
        size = units[off + 1]
        first_key = _s32(units[off + 2] | (units[off + 3] << 16))
        targets = tuple(
            _s32(units[off + 4 + i * 2] | (units[off + 5 + i * 2] << 16))
            for i in range(size)
        )
        return Payload(unit_off=off, ident=ident, units=total, ref_off=switch_off,
                       first_key=first_key, targets=targets, size=size), ""
    if ident == 0x0200:
        size = units[off + 1]
        keys = tuple(
            _s32(units[off + 2 + i * 2] | (units[off + 3 + i * 2] << 16))
            for i in range(size)
        )
        base = 2 + size * 2
        targets = tuple(
            _s32(units[off + base + i * 2] | (units[off + base + i * 2 + 1] << 16))
            for i in range(size)
        )
        return Payload(unit_off=off, ident=ident, units=total, ref_off=switch_off,
                       keys=keys, targets=targets, size=size), ""
    # 0x0300 fill-array-data
    width = units[off + 1]
    size = units[off + 2] | (units[off + 3] << 16)
    return Payload(unit_off=off, ident=ident, units=total, ref_off=switch_off,
                   element_width=width, size=size, data_unit_off=off + 4), ""


# ---------- 操作数渲染 ----------

def _ref_text(tables, kind: str, idx: int) -> tuple[str, str]:
    """解析引用，返回 (可读文本, 注释文本)。解析不到时给出索引本身，不编造。"""
    if kind == REF_STRING:
        try:
            return '"' + _escape(tables.string(idx)) + '"', f"string@{idx:04x}"
        except Exception:
            return f"string@{idx:04x}", f"string@{idx:04x}"
    if kind == REF_TYPE:
        try:
            return tables.type_desc(idx), f"type@{idx:04x}"
        except Exception:
            return f"type@{idx:04x}", f"type@{idx:04x}"
    if kind == REF_FIELD:
        try:
            return str(tables.field(idx)), f"field@{idx:04x}"
        except Exception:
            return f"field@{idx:04x}", f"field@{idx:04x}"
    if kind == REF_METHOD:
        try:
            m = tables.method(idx)
            return f"{m.class_desc}.{m.name}{m.proto.descriptor}", f"method@{idx:04x}"
        except Exception:
            return f"method@{idx:04x}", f"method@{idx:04x}"
    if kind == REF_PROTO:
        try:
            return tables.proto(idx).descriptor, f"proto@{idx:04x}"
        except Exception:
            return f"proto@{idx:04x}", f"proto@{idx:04x}"
    if kind == REF_CALL_SITE:
        # call_site_id 在 map_list 的 TYPE_CALL_SITE_ID_ITEM 段里，
        # 本实现未解析该段（DEX 035 之前不存在），只给索引不编造内容。
        return f"call_site@{idx:04x}", ""
    if kind == REF_METHOD_HANDLE:
        return f"method_handle@{idx:04x}", ""
    return "", ""


# (1) 第一次修改（2026-11-26）
# bug 原因：此前 _reglist 对任意 >=3 个寄存器都折叠成 `{v首 .. v尾}`，而 35c/45cc 的寄存器
#           列表可以是非连续、任意顺序的（如 v0, v5, v2），折叠后会丢失中间寄存器并误导为连续区间。
# 解决方案：默认逐个列出全部寄存器；仅当 is_range=True（3rc/4rcc 连续区间格式）且 >=2 个时才折叠。
def _reglist(regs: list[int], is_range: bool = False) -> str:
    """寄存器列表格式化：35c/45cc 逐个列出，3rc/4rcc 连续区间可用 {vN .. vM}。"""
    if not regs:
        return "{}"
    if is_range and len(regs) >= 2:
        return f"{{v{regs[0]} .. v{regs[-1]}}}"
    return "{" + ", ".join(f"v{r}" for r in regs) + "}"


def _branch_text(target: int, rel: int) -> str:
    """分支目标：绝对 code unit 偏移 + 相对偏移，两者都给（对数偏移最有用）。"""
    return f"u0x{target:04x} // {rel:+#x}"


def render(tables, op: int, units, i: int, base_insns: int) -> Insn:
    """渲染一条指令（不含 payload 指令；payload 走 render_payload）。"""
    fmt = FORMAT[op]
    width = WIDTH[op]
    u0 = units[i]
    u1 = units[i + 1] if width > 1 else 0
    u2 = units[i + 2] if width > 2 else 0
    u3 = units[i + 3] if width > 3 else 0
    u4 = units[i + 4] if width > 4 else 0

    vAA = (u0 >> 8) & 0xFF
    vA = (u0 >> 8) & 0xF
    vB = (u0 >> 12) & 0xF
    ref_kind = REF[op]
    ref_idx = -1
    ref_txt = ""
    ref_note = ""
    operands = ""
    note = ""

    if fmt == "10x":
        operands = ""
    elif fmt == "12x":
        operands = f"v{vA}, v{vB}"
    elif fmt == "11n":
        # (1) 第一次修改（2026-11-26）
        # bug 原因：此前对 4 位有符号立即数调用 _s8((u0 >> 12) & 0xF)，位 7 恒为 0，
        #           导致 -1 (0xF) 被错解为 15、-8 (0x8) 错解为 8。
        # 解决方案：改用 _s4 做 4-bit 符号扩展。
        lit = _s4((u0 >> 12) & 0xF)  # 4 bit 有符号（-8..7）
        operands = f"v{vA}, #int {lit} // #{lit & 0xF:x}"
    elif fmt == "11x":
        operands = f"v{vAA}"
    elif fmt == "10t":
        rel = _s8(vAA)
        operands = _branch_text(i + rel, rel)
    elif fmt == "20t":
        rel = _s16(u1)
        operands = _branch_text(i + rel, rel)
    elif fmt == "30t":
        rel = _s32(u1 | (u2 << 16))
        operands = _branch_text(i + rel, rel)
    elif fmt == "22x":
        operands = f"v{vAA}, v{u1}"
    elif fmt == "21t":
        rel = _s16(u1)
        operands = f"v{vAA}, {_branch_text(i + rel, rel)}"
    elif fmt == "21s":
        lit = _s16(u1)
        operands = f"v{vAA}, #int {lit} // #{lit & 0xFFFF:x}"
    elif fmt == "21h":
        if op == 0x19:  # const-wide/high16：高 16 位 -> 64 bit 带符号
            val = _s64(u1 << 48)
            operands = f"v{vAA}, #long {val} // #{u1:04x}"
        else:           # const/high16：高 16 位 -> 32 bit 带符号
            val = _s32(u1 << 16)
            operands = f"v{vAA}, #int {val} // #{u1:04x}"
    elif fmt == "21c":
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        operands = f"v{vAA}, {ref_txt}"
    elif fmt == "23x":
        operands = f"v{vAA}, v{u1 & 0xFF}, v{(u1 >> 8) & 0xFF}"
    elif fmt == "22b":
        operands = f"v{vAA}, v{u1 & 0xFF}, #int {_s8((u1 >> 8) & 0xFF)} // #{_s8((u1 >> 8) & 0xFF) & 0xFF:x}"
    elif fmt == "22t":
        rel = _s16(u1)
        operands = f"v{vA}, v{vB}, {_branch_text(i + rel, rel)}"
    elif fmt == "22s":
        lit = _s16(u1)
        operands = f"v{vA}, v{vB}, #int {lit} // #{lit & 0xFFFF:x}"
    elif fmt == "22c":
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        operands = f"v{vA}, v{vB}, {ref_txt}"
    elif fmt == "32x":
        operands = f"v{u1}, v{u2}"
    elif fmt == "31i":
        lit = _s32(u1 | (u2 << 16))
        operands = f"v{vAA}, #int {lit} // #{lit & 0xFFFFFFFF:x}"
    elif fmt == "31c":
        ref_idx = u1 | (u2 << 16)
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        operands = f"v{vAA}, {ref_txt}"
    elif fmt == "31t":
        rel = _s32(u1 | (u2 << 16))
        target = i + rel
        operands = f"v{vAA}, {_branch_text(target, rel)}"
    elif fmt == "35c":
        count = (u0 >> 12) & 0xF
        g = (u0 >> 8) & 0xF
        c = u2 & 0xF
        d = (u2 >> 4) & 0xF
        e = (u2 >> 8) & 0xF
        f = (u2 >> 12) & 0xF
        regs = [c, d, e, f, g][:count]
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        operands = f"{_reglist(regs)}, {ref_txt}"
    elif fmt == "3rc":
        count = (u0 >> 8) & 0xFF
        first = u2
        regs = list(range(first, first + count))
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        operands = f"{_reglist(regs, is_range=True)}, {ref_txt}"
    elif fmt == "45cc":
        # 4 units: A|G|op, meth@BBBB, F|E|D|C, proto@HHHH
        count = (u0 >> 12) & 0xF
        g = (u0 >> 8) & 0xF
        c = u2 & 0xF
        d = (u2 >> 4) & 0xF
        e = (u2 >> 8) & 0xF
        f = (u2 >> 12) & 0xF
        regs = [c, d, e, f, g][:count]
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        proto_txt, _pn = _ref_text(tables, REF_PROTO, u3)
        operands = f"{_reglist(regs)}, {ref_txt}, {proto_txt}"
        ref_note = f"{ref_note}, proto@{u3:04x}"
    elif fmt == "4rcc":
        # 4 units: AA|op, meth@BBBB, vCCCC, proto@HHHH
        count = (u0 >> 8) & 0xFF
        regs = list(range(u2, u2 + count))
        ref_idx = u1
        ref_txt, ref_note = _ref_text(tables, ref_kind, ref_idx)
        proto_txt, _pn = _ref_text(tables, REF_PROTO, u3)
        operands = f"{_reglist(regs, is_range=True)}, {ref_txt}, {proto_txt}"
        ref_note = f"{ref_note}, proto@{u3:04x}"
    elif fmt == "51l":
        lit = _s64(u1 | (u2 << 16) | (u3 << 32) | (u4 << 48))
        operands = f"v{vAA}, #long {lit} // #{lit & 0xFFFFFFFFFFFFFFFF:016x}"
    else:  # 理论上不可达（FORMAT_UNITS 与上面分支一一对应）
        note = f"未知格式 {fmt}，按 {width} units 跳过"

    raw = _raw_hex(tables, i, width)
    insn = Insn(
        unit_off=i, byte_off=i * 2, units=width, mnemonic=MNEMONIC[op],
        operands=operands, raw_hex=raw, ref_kind=ref_kind, ref_idx=ref_idx,
        ref_text=ref_note, note=note,
    )
    return insn


def _raw_hex(tables, i: int, width: int) -> str:
    """原始 code unit 的十六进制（内存序，每 unit 4 个 hex 字符，空格分组）。"""
    data = tables.data
    off = tables.insns_base + i * 2
    raw = data[off:off + width * 2]
    if len(raw) < width * 2:
        raw = raw + b"\x00" * (width * 2 - len(raw))
    return " ".join(raw[j * 2:j * 2 + 2].hex() for j in range(width))


def render_payload(tables, p: Payload) -> Insn:
    """渲染 payload 块，并把每一条 case / 数据摘要放进 detail。"""
    detail: list[str] = []
    # target 相对 switch 指令，不相对 payload（见 Payload.ref_off 注释）
    base = p.ref_off if p.ref_off >= 0 else p.unit_off
    if p.ident == 0x0100:
        text = f"({p.units} units, first_key={p.first_key}, {p.size} cases)"
        for idx, rel in enumerate(p.targets):
            key = p.first_key + idx
            detail.append(f"case key={key} (0x{key & 0xFFFFFFFF:x}) -> u0x{base + rel:04x}")
    elif p.ident == 0x0200:
        text = f"({p.units} units, {p.size} cases)"
        for key, rel in zip(p.keys, p.targets):
            detail.append(f"case key={key} -> u0x{base + rel:04x}")
    else:
        text = f"({p.units} units, element_width={p.element_width}, size={p.size})"
        nbytes = p.size * p.element_width
        take = min(nbytes, 64)
        try:
            raw = _bytes_at(tables, p.data_unit_off, take)
            detail.append(f"data[0:{take}] = {raw.hex()}" + (" ..." if take < nbytes else ""))
        except Exception as exc:  # 取不到就说取不到
            detail.append(f"data 读取失败：{exc}")
    return Insn(
        unit_off=p.unit_off, byte_off=p.unit_off * 2, units=p.units,
        mnemonic=p.label, operands=text,
        raw_hex=_raw_hex(tables, p.unit_off, min(p.units, 4)),
        is_payload=True, payload=p, detail=detail,
    )


# ---------- 主解码循环 ----------

def iter_invokes(units, insns_size: int):
    """只扫 invoke-*，产出 (unit_off, opcode, ref_idx)。

    专供 dex_callers 用：不建 Insn、不渲染文本、不解析符号，只走指令长度表。
    调用者扫描要遍历几十万条指令，这个循环是热路径，任何多余开销都会被放大。
    payload 区同样要跳过，否则 switch 后面的数据会被当成指令、进而全线错位。
    """
    i = 0
    skips: dict[int, int] = {}
    while i < insns_size:
        n = skips.get(i)
        if n:
            i += n
            continue
        op = units[i] & 0xFF
        width = WIDTH[op]
        if op in INVOKE_OPS:
            # 35c / 3rc / 45cc / 4rcc 的引用索引都在第 2 个 unit
            if i + 2 <= insns_size:
                yield i, op, units[i + 1]
        elif op in PAYLOAD_OP:
            # 坑 4：只有 switch/fill 指令指向的地址才是 payload
            if i + 3 <= insns_size:
                rel = _s32(units[i + 1] | (units[i + 2] << 16))
                target = i + rel
                if 0 <= target < insns_size and units[target] == PAYLOAD_OP[op]:
                    skips[target] = payload_units(units, insns_size, target)
        i += width


def disassemble(tables, units, insns_size: int) -> list[Insn]:
    """顺序解码整个 code_item，返回指令列表（payload 已按上下文正确跳过）。

    tables 需提供：data（dex 字节）、insns_base（本方法 insns 的文件偏移）、
    string/type_desc/field/method/proto 五个解析方法。
    """
    out: list[Insn] = []
    payloads: dict[int, Payload] = {}
    i = 0
    while i < insns_size:
        ready = payloads.get(i)
        if ready is not None:
            out.append(render_payload(tables, ready))
            i += ready.units
            continue

        op = units[i] & 0xFF
        width = WIDTH[op]

        # 坑 4：顺序撞上 payload ident 却没有上下文 —— 按 nop 处理并标记
        if op == 0x00 and units[i] in (0x0100, 0x0200, 0x0300):
            insn = Insn(
                unit_off=i, byte_off=i * 2, units=1, mnemonic="nop",
                operands="", raw_hex=_raw_hex(tables, i, 1),
                note=(f"疑似 payload ident 0x{units[i]:04x}，但没有任何 switch/fill "
                      "指令指向这里，按 nop 处理（后续解码可能错位）"),
            )
            out.append(insn)
            i += 1
            continue

        if i + width > insns_size:
            out.append(Insn(
                unit_off=i, byte_off=i * 2, units=insns_size - i, mnemonic="<truncated>",
                raw_hex=_raw_hex(tables, i, insns_size - i),
                note=f"指令需要 {width} units，但只剩 {insns_size - i} units",
            ))
            break

        insn = render(tables, op, units, i, insns_size)

        # 坑 4 的另一半：switch/fill 指令在这里把 payload 注册进 payloads，
        # 等到顺序推进到那个偏移时再按 payload 解析并整块跳过
        if op in PAYLOAD_OP:
            rel = _s32(units[i + 1] | (units[i + 2] << 16))
            target = i + rel
            p, err = _parse_payload(tables, units, insns_size, target, PAYLOAD_OP[op],
                                    switch_off=i)
            if p is None:
                insn.note = err
            else:
                payloads[target] = p
        out.append(insn)
        i += width
    return out
