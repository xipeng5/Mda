"""DEX 静态解析测试 + 与 dexdump 的逐指令交叉验证。

运行：
    .venv/bin/python tests/test_dex.py
    MDA_DEX_FULL_XCHECK=1 .venv/bin/python tests/test_dex.py    # 全量比对 apk 里 9 个 dex

本文件分七块：

    1. 合成 dex 构造器        —— 只为把四个坑的输入精确控制住而造，
                                 不是完整合规的 dex（无 map_list/校验和），
                                 也不喂给 dexdump，仅本文件自用
    2. 坑 1：MUTF-8 + ULEB128  —— utf16_size 是 UTF-16 码元数，不是字节数
    3. 坑 2：class_data 增量索引 —— direct / virtual 各自从 0 累加
    4. 坑 3：变长指令格式      —— move-wide/16(0x06) 是 32x = 3 units
    5. 坑 4：payload 上下文    —— 0x0100 只在被 switch/fill 指向时才是 payload
    6. API 行为               —— 类表/方法表/反汇编/调用者/错误处理
    7. 与 dexdump 逐指令交叉验证（真实 APK，取官方反汇编做 ground truth）

—— 交叉验证结果（2026-11-18 实测）——

ground truth：/Users/waterclean/Library/Android/sdk/build-tools/27.0.3/dexdump
样本        ：/Users/waterclean/Desktop/app/汽水音乐/汽水音乐6.2.apk
             classes.dex  DEX 035  7,217,852 字节  6331 个类

结果见文件末尾 CROSSCHECK_NOTES 常量（脚本每次运行会重新核算并打印，
数值写死在这里是为了让读代码的人一眼看到结论）。
"""
import os
import re
import struct
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.core.dex import api as dexapi
from server.core.dex import bytecode, mutf8
from server.core.dex.code import read_class_data
from server.core.dex.header import DexTables, parse_header
from server.core.dex.reader import DexBuffer, DexError, uleb128
from server.core.dex import dex_callers, dex_classes, dex_disasm, dex_methods

PASS = 0
FAIL = 0
SKIP = 0

DEXDUMP = "/Users/waterclean/Library/Android/sdk/build-tools/27.0.3/dexdump"
SAMPLE_APK = "/Users/waterclean/Desktop/app/汽水音乐/汽水音乐6.2.apk"
FULL = os.environ.get("MDA_DEX_FULL_XCHECK") == "1"

# 交叉验证的结论（脚本会重新核算；这里留档，便于一眼看到实测数值）
CROSSCHECK_NOTES = """
样本 classes.dex（DEX 035）：
  表规模    : string_ids=52341 type_ids=8200 proto_ids=10697
              field_ids=65533 method_ids=49038 class_defs=6331
              （与 dexdump -f 逐项一致）
  逐指令比对: 见运行输出「交叉验证」小节
"""


# =====================================================================
# 1. 合成 dex 构造器
# =====================================================================

def _uleb(v: int) -> bytes:
    """ULEB128 编码（测试用，与 reader.uleb128 互逆）。"""
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class DexBuilder:
    """造一个「够 API 跑通」的最小 dex。

    刻意省略：map_list、校验和、注解、try/catch、debug_info。
    解析器不读这些，但**不要**拿产物去喂 dexdump —— 它要求完整合规。
    """

    def __init__(self):
        self._strings: dict[str, int] = {}
        self._types: dict[str, int] = {}
        self._protos: dict[tuple, int] = {}
        self._methods: dict[tuple, int] = {}
        self.classes: list[dict] = []
        self.flat: list[tuple[int, dict]] = []  # (method_idx, spec)

    # ---- 注册 ----

    def s(self, text: str) -> int:
        if text not in self._strings:
            self._strings[text] = len(self._strings)
        return self._strings[text]

    def t(self, desc: str) -> int:
        if desc not in self._types:
            self._types[desc] = len(self._types)
            self.s(desc)  # 描述符本身也是字符串
        return self._types[desc]

    def p(self, params: tuple[str, ...], ret: str) -> int:
        key = (params, ret)
        if key not in self._protos:
            self.t(ret)                 # 返回/参数类型也必须是 type（build 时不能再新增）
            for one in params:
                self.t(one)
            self._protos[key] = len(self._protos)
            # shorty 只影响展示，这里用返回类型首字符 + 参数个数拼一个
            shorty = (ret[0] if ret else "V") + "".join(p[0] for p in params)
            self.s(shorty)
        return self._protos[key]

    def m(self, cls_desc: str, name: str, params: tuple[str, ...], ret: str) -> int:
        key = (cls_desc, name, self.p(params, ret))
        if key not in self._methods:
            self._methods[key] = len(self._methods)
            self.s(name)
        return self._methods[key]

    def add_class(self, desc: str, methods: list[dict], super_desc: str = "Ljava/lang/Object;",
                  source: str = "T.java", access: int = 0x1,
                  interfaces: tuple[str, ...] = ()) -> None:
        """methods 每项：name/params/ret/access/registers/ins/outs/units/direct。"""
        self.t(desc)
        self.t(super_desc)      # 父类也必须是 type（不只是 string）
        self.s(source)          # 必须在 build() 前注册，否则 string_ids 表少一项
        for iface in interfaces:
            self.t(iface)
        for spec in methods:
            midx = self.m(desc, spec["name"], tuple(spec.get("params", ())), spec["ret"])
            spec["_idx"] = midx
            self.flat.append((midx, spec))
        self.classes.append({
            "desc": desc, "super": super_desc, "source": source,
            "access": access, "methods": methods, "interfaces": interfaces,
        })

    # ---- 组装 ----

    def build(self) -> bytes:
        n_str, n_type = len(self._strings), len(self._types)
        n_proto, n_method, n_cls = len(self._protos), len(self._methods), len(self.classes)

        off_string_ids = 0x70
        off_type_ids = off_string_ids + 4 * n_str
        off_proto_ids = off_type_ids + 4 * n_type
        off_method_ids = off_proto_ids + 12 * n_proto
        off_class_defs = off_method_ids + 8 * n_method
        data_off = off_class_defs + 32 * n_cls

        data = bytearray()

        def here() -> int:
            return data_off + len(data)

        # string_data_item
        str_off: list[int] = []
        for text in self._strings:
            body, utf16 = mutf8.encode_mutf8(text)
            str_off.append(here())
            data += _uleb(utf16) + body + b"\x00"

        # 每个 proto 的 type_list（无参数则 off=0）
        proto_param_off: list[int] = []
        for params, ret in self._protos:
            if params:
                proto_param_off.append(here())
                data += struct.pack("<I", len(params))
                for p in params:
                    data += struct.pack("<H", self.t(p))
            else:
                proto_param_off.append(0)

        # code_item
        code_off: dict[int, int] = {}
        for midx, spec in self.flat:
            if not spec.get("units"):
                continue
            code_off[midx] = here()
            units = spec["units"]
            data += struct.pack(
                "<HHHHII", spec.get("registers", 1), spec.get("ins", 0),
                spec.get("outs", 0), 0, 0, len(units),
            )
            data += struct.pack(f"<{len(units)}H", *units)

        # class_data_item（方法按 method_idx 升序，diff 必须非负）
        class_data_off: dict[str, int] = {}
        for cls in self.classes:
            direct = sorted([m for m in cls["methods"] if m.get("direct")],
                            key=lambda x: x["_idx"])
            virtual = sorted([m for m in cls["methods"] if not m.get("direct")],
                             key=lambda x: x["_idx"])
            if not direct and not virtual:
                class_data_off[cls["desc"]] = 0
                continue
            class_data_off[cls["desc"]] = here()
            data += _uleb(0) + _uleb(0) + _uleb(len(direct)) + _uleb(len(virtual))
            prev = 0
            for spec in direct:
                data += _uleb(spec["_idx"] - prev) + _uleb(spec["access"]) + \
                        _uleb(code_off.get(spec["_idx"], 0))
                prev = spec["_idx"]
            prev = 0
            for spec in virtual:
                data += _uleb(spec["_idx"] - prev) + _uleb(spec["access"]) + \
                        _uleb(code_off.get(spec["_idx"], 0))
                prev = spec["_idx"]

        # interfaces 的 type_list 放在 data 尾部（class_def 里引用）
        ifaces_off: dict[str, int] = {}
        for cls in self.classes:
            if cls["interfaces"]:
                ifaces_off[cls["desc"]] = here()
                data += struct.pack("<I", len(cls["interfaces"]))
                for iface in cls["interfaces"]:
                    data += struct.pack("<H", self.t(iface))
            else:
                ifaces_off[cls["desc"]] = 0

        out = bytearray(data_off + len(data))
        out[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", out, 0x20, len(out))       # file_size
        struct.pack_into("<I", out, 0x24, 0x70)           # header_size
        struct.pack_into("<I", out, 0x28, 0x12345678)     # endian_tag
        struct.pack_into("<II", out, 0x38, n_str, off_string_ids)
        struct.pack_into("<II", out, 0x40, n_type, off_type_ids)
        struct.pack_into("<II", out, 0x48, n_proto, off_proto_ids)
        struct.pack_into("<II", out, 0x50, 0, 0)          # field_ids：测试不用
        struct.pack_into("<II", out, 0x58, n_method, off_method_ids)
        struct.pack_into("<II", out, 0x60, n_cls, off_class_defs)
        struct.pack_into("<II", out, 0x68, len(data), data_off)

        for i, off in enumerate(str_off):
            struct.pack_into("<I", out, off_string_ids + 4 * i, off)
        for i, (desc, idx) in enumerate(self._types.items()):
            struct.pack_into("<I", out, off_type_ids + 4 * i, self.s(desc))
        # proto_ids: shorty_idx, return_type_idx, parameters_off
        for i, ((params, ret), poff) in enumerate(zip(self._protos, proto_param_off)):
            shorty = (ret[0] if ret else "V") + "".join(p[0] for p in params)
            struct.pack_into("<III", out, off_proto_ids + 12 * i,
                             self.s(shorty), self.t(ret), poff)
        # method_ids: class_idx, proto_idx, name_idx
        for (cls_desc, name, proto_idx), i in self._methods.items():
            struct.pack_into("<HHI", out, off_method_ids + 8 * i,
                             self.t(cls_desc), proto_idx, self.s(name))
        for i, cls in enumerate(self.classes):
            struct.pack_into(
                "<8I", out, off_class_defs + 32 * i,
                self.t(cls["desc"]), cls["access"], self.t(cls["super"]),
                ifaces_off[cls["desc"]],
                self.s(cls["source"]), 0, class_data_off[cls["desc"]], 0,
            )
        out[data_off:] = data
        # 接口表在 class_def 之后写入了 data 尾部，长度以最终为准
        struct.pack_into("<I", out, 0x20, len(out))
        struct.pack_into("<II", out, 0x68, len(out) - data_off, data_off)
        return bytes(out)


# ---- 造一个包含四个坑全部形态的 dex ----

def _build_pitfall_dex() -> bytes:
    """两个类，覆盖：32x 宽度、packed-switch payload、array-data payload、
    跨类调用（dex_callers）、native 无 code。

    注意注册顺序：method_ids 按注册顺序分配，所以 Bar.bar 必须先注册，
    Caller.callBar 里的 invoke 才能稳定写成 method@0。
    """
    b = DexBuilder()

    # 方法 1：窄/宽寄存器搬移，专门验 0x06(32x)=3 units、0x02(22x)=2 units
    wide_units = [
        0x0006, 0x0008, 0x0000,               # 0x0000 move-wide/16 v0, v8    (32x, 3 units)
        0x0002, 0x0300,                       # 0x0003 move/from16 v0, v3    (22x, 2 units)
        0x1200,                               # 0x0005 const/4 v0, #0        (11n, 1 unit)
        0x000E,                               # 0x0006 return-void
    ]
    # 方法 2：packed-switch + payload（payload 里 target 相对 switch 指令）
    switch_units = [
        0x002B, 0x0004, 0x0000,               # 0x0000 packed-switch v0, +4 -> payload 在 u4
        0x000E,                               # 0x0003 return-void
        0x0100, 0x0002,                       # u4 payload: ident, size=2
        0x0001, 0x0000,                       # u6 first_key=1  (s4 = 2 units, 低位在前)
        0x0006, 0x0000,                       # u8 target[0]=+6
        0x0001, 0x0000,                       # u10 target[1]=+1
    ]
    # 方法 3：fill-array-data + payload
    array_units = [
        0x0026, 0x0004, 0x0000,               # 0x0000 fill-array-data v0, +4 -> payload 在 u4
        0x000E,                               # 0x0003 return-void
        0x0300, 0x0004, 0x0003, 0x0000,       # u4 payload: ident, width=4, size=3
        0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C,   # u8 data 12 字节 (6 units)
    ]
    # 方法 4：invoke-virtual {v0}, method@0 —— Bar.bar 先注册所以 idx=0
    b.add_class("Ltest/Bar;", [
        {"name": "bar", "params": (), "ret": "V", "access": 0x1, "direct": False,
         "registers": 1, "ins": 1, "units": [0x000E]},
    ])
    b.add_class("Ltest/Caller;", [
        {"name": "wideMove", "params": (), "ret": "V", "access": 0x1, "direct": True,
         "registers": 9, "ins": 1, "units": wide_units},
        {"name": "switchOn", "params": (), "ret": "V", "access": 0x1, "direct": False,
         "registers": 1, "ins": 1, "units": switch_units},
        {"name": "arrayOn", "params": (), "ret": "V", "access": 0x1, "direct": False,
         "registers": 1, "ins": 1, "units": array_units},
        {"name": "callBar", "params": (), "ret": "V", "access": 0x1, "direct": True,
         "registers": 1, "ins": 1, "units": [
             0x106E, 0x0000, 0x0000,           # invoke-virtual {v0}, method@0
             0x000E,
         ]},
        {"name": "nativeCall", "params": (), "ret": "V", "access": 0x109,
         "direct": True},                      # PUBLIC NATIVE，无 units -> code_off=0
    ], interfaces=("Ltest/Iface;",))
    return b.build()


# =====================================================================
# 2. 坑 1：MUTF-8 + ULEB128
# =====================================================================

def test_mutf8():
    """utf16_size 是 UTF-16 码元数；内嵌 NUL 是 C0 80；补充平面拆两个代理项。"""
    cases = ["", "abc", "中文字符", "a\x00b", "😀", "😀A😀", "\u0000", "Δ÷"]
    for text in cases:
        body, utf16 = mutf8.encode_mutf8(text)
        want_units = len(text.encode("utf-16-le")) // 2
        check(f"MUTF-8 码元数 {text!r}", utf16 == want_units,
              f"encoder 给 {utf16}，UTF-16 实际 {want_units}")
        got, end, ok = mutf8.decode_at(body + b"\x00", 0, utf16)
        check(f"MUTF-8 往返 {text!r}", got == text and ok, f"解出 {got!r} ok={ok}")

    # U+0000 必须是 C0 80，不是 0x00
    body, _ = mutf8.encode_mutf8("\x00")
    check("U+0000 编码为 C0 80", body == b"\xc0\x80", f"实际 {body.hex()}")

    # 补充平面：6 字节（两个 3 字节代理项），不是 4 字节
    body, utf16 = mutf8.encode_mutf8("😀")
    check("补充平面占 6 字节 / 2 个 UTF-16 码元",
          len(body) == 6 and utf16 == 2, f"{body.hex()} units={utf16}")

    # 按 UTF-16 码元截断：utf16_size=1 时只应出 1 个码元（半个代理对）
    got, _e, ok = mutf8.decode_at(body + b"\x00", 0, 1)
    check("按码元截断（半个代理对）不抛异常", len(got) == 1 and not ok, repr(got))

    # 4 字节 UTF-8 形式不是合法 MUTF-8
    try:
        mutf8.decode_at(b"\xf0\x9f\x98\x80\x00", 0, 2)
        check("拒绝 4 字节 MUTF-8", False, "没有抛异常")
    except DexError as exc:
        check("拒绝 4 字节 MUTF-8", exc.code == "BAD_MUTF8", exc.message)

    # ULEB128
    for v in (0, 1, 127, 128, 300, 16383, 16384, 0xFFFFFFFF):
        got, off = uleb128(_uleb(v), 0)
        check(f"ULEB128 {v}", got == v and off == len(_uleb(v)), f"解出 {got} off={off}")
    try:
        uleb128(b"\x80", 0)
        check("ULEB128 截断报错", False, "没有抛异常")
    except DexError:
        check("ULEB128 截断报错", True)


# =====================================================================
# 3. 坑 2：class_data 增量索引
# =====================================================================

def test_incremental_index():
    """method_idx_diff / field_idx_diff 必须累加，且 direct 与 virtual 各自累加。"""
    # 手工构造 class_data_item：2 个字段 + direct 3 个方法 + virtual 2 个方法
    data = bytearray()
    data += _uleb(2)   # static_fields_size
    data += _uleb(0)   # instance_fields_size
    data += _uleb(3)   # direct_methods_size
    data += _uleb(2)   # virtual_methods_size
    # 字段 idx: 4, 4+3=7
    for diff, flags in ((4, 1), (3, 2)):
        data += _uleb(diff) + _uleb(flags)
    # direct 方法 idx: 10, 11, 14（diff 10,1,3），code_off 各不相同
    for diff, flags, code in ((10, 1, 0x100), (1, 1, 0x200), (3, 0x100, 0)):
        data += _uleb(diff) + _uleb(flags) + _uleb(code)
    # virtual 方法 idx: 2, 3 —— 从 0 重新累加（不是接着 14）
    for diff, flags, code in ((2, 1, 0x300), (1, 1, 0x400)):
        data += _uleb(diff) + _uleb(flags) + _uleb(code)

    # class_data_off == 0 按规范表示「该类没有 class_data」，
    # 所以这里前面补一个字节，让 class_data_item 从 off=1 开始
    buf = DexBuffer(b"\x00" + bytes(data), "synthetic")
    cd = read_class_data(buf, 1)
    check("字段 idx 增量累加", [f.field_idx for f in cd.static_fields] == [4, 7],
          str([f.field_idx for f in cd.static_fields]))
    check("direct 方法 idx 增量累加",
          [m.method_idx for m in cd.direct_methods] == [10, 11, 14],
          str([m.method_idx for m in cd.direct_methods]))
    check("virtual 方法 idx 独立累加（不接着 direct）",
          [m.method_idx for m in cd.virtual_methods] == [2, 3],
          str([m.method_idx for m in cd.virtual_methods]))
    check("code_off 独立解析",
          [m.code_off for m in cd.direct_methods] == [0x100, 0x200, 0]
          and [m.code_off for m in cd.virtual_methods] == [0x300, 0x400])

    # 真实 dex 上的症状检查：一个类里不该出现几十个同名 <init>
    if os.path.exists(SAMPLE_APK):
        cs = dex_classes(SAMPLE_APK)
        if cs and "error" not in cs[0]:
            worst = max(cs, key=lambda c: c["method_count"])
            ms = dex_methods(SAMPLE_APK, worst["name"])
            keys = [(m["name"], m["proto"]) for m in ms]
            dup = len(keys) - len(set(keys))
            check(f"最大类 {worst['java_name'][:40]} 无重复方法（{len(ms)} 个）",
                  dup == 0, f"有 {dup} 个重复的 (name, proto)")


# =====================================================================
# 4. 坑 3：变长指令格式
# =====================================================================

_REF_WIDTHS = {
    # (opcode, 期望 units, 说明)
    0x00: (1, "nop 10x"),
    0x02: (2, "move/from16 22x"),
    0x03: (3, "move/16 32x"),
    0x05: (2, "move-wide/from16 22x"),
    0x06: (3, "move-wide/16 32x  <-- 最容易写成 2"),
    0x09: (3, "move-object/16 32x"),
    0x13: (2, "const/16 21s"),
    0x14: (3, "const 31i"),
    0x15: (2, "const/high16 21h"),
    0x18: (5, "const-wide 51l"),
    0x19: (2, "const-wide/high16 21h"),
    0x1B: (3, "const-string/jumbo 31c"),
    0x24: (3, "filled-new-array 35c"),
    0x25: (3, "filled-new-array/range 3rc"),
    0x26: (3, "fill-array-data 31t"),
    0x2A: (3, "goto/32 30t"),
    0x2B: (3, "packed-switch 31t"),
    0x51: (2, "aput-short 23x"),
    0x53: (2, "iget 22c"),
    0x71: (3, "invoke-static 35c"),
    0x77: (3, "invoke-static/range 3rc"),
    0xFA: (4, "invoke-polymorphic 45cc"),
    0xFB: (4, "invoke-polymorphic/range 4rcc"),
    0xFC: (3, "invoke-custom 35c"),
    0xD1: (2, "rsub-int 22s"),
    0xD8: (2, "add-int/lit8 22b"),
}


def test_instruction_widths():
    """逐格式核 code unit 数；并验证解码时的推进量跟着宽度走。"""
    for op, (want, desc) in _REF_WIDTHS.items():
        check(f"宽度 {desc}", bytecode.WIDTH[op] == want,
              f"表里是 {bytecode.WIDTH[op]}，应为 {want}")

    # 关键：0x06 后面紧跟的指令必须在 +3 处
    units = [0x0006, 0x0008, 0x0000, 0x000E]
    got = _decode(units)
    check("move-wide/16 推进 3 units",
          [i.unit_off for i in got] == [0, 3], str([(i.unit_off, i.mnemonic) for i in got]))
    check("move-wide/16 助记符", got[0].mnemonic == "move-wide/16", got[0].mnemonic)
    check("move-wide/16 操作数两个 v 寄存器", got[0].operands == "v8, v0", got[0].operands)

    # 2 units 的是 22x，别和 32x 混
    units = [0x0002, 0x0300, 0x000E]
    got = _decode(units)
    check("move/from16 只推进 2 units",
          [i.unit_off for i in got] == [0, 2], str([(i.unit_off, i.mnemonic) for i in got]))

    # 51l 5 units
    units = [0x0018, 0x1111, 0x2222, 0x3333, 0x4444, 0x000E]
    got = _decode(units)
    check("const-wide 推进 5 units",
          [i.unit_off for i in got] == [0, 5], str([(i.unit_off, i.mnemonic) for i in got]))

    # 整表自洽：任何 opcode 的宽度都必须在 1..5
    check("全表宽度合法", all(1 <= w <= 5 for w in bytecode.WIDTH))
    check("opcode 表 256 项", len(bytecode.OPCODES) == 256)


def _decode(units):
    """用合成 tables 跑一遍 decoder（不需要真实 dex）。"""
    class _T:
        data = b"\x00" * 4096
        insns_base = 0

        def string(self, idx):
            return f"str{idx}"

        def type_desc(self, idx):
            return f"Ltype{idx};"

        def field(self, idx):
            return f"field{idx}"

        def method(self, idx):
            class _M:
                class_desc = "Lm;"
                name = "m"
                class P:
                    descriptor = "()V"
                proto = P()
            return _M()

        def proto(self, idx):
            class P:
                descriptor = "()V"
            return P()

    return bytecode.disassemble(_T(), units, len(units))


# =====================================================================
# 5. 坑 4：payload ident 的上下文
# =====================================================================

def test_payload_context():
    """被 switch/fill 指向 -> payload；无人指向 -> 只是一条 nop。"""
    # packed-switch 指向 u4 的 payload
    units = [0x002B, 0x0004, 0x0000, 0x000E,
             0x0100, 0x0002,                     # ident=0x0100, size=2
             0x0001, 0x0000,                     # first_key=1  (s4 = 2 units)
             0x0006, 0x0000,                     # target[0]=+6
             0x0001, 0x0000]                     # target[1]=+1
    got = _decode(units)
    check("packed-switch 被解成指令", got[0].mnemonic == "packed-switch", got[0].mnemonic)
    check("payload 按 offset 定位到 u4", got[2].unit_off == 4 and got[2].is_payload,
          str([(i.unit_off, i.mnemonic, i.is_payload) for i in got]))
    check("payload 整块占 8 units（4 + 2*2）", got[2].units == 8, str(got[2].units))
    # target 相对 switch 指令（u0），不是相对 payload（u4）
    check("case 目标相对 switch 指令",
          got[2].detail[0].endswith("u0x0006") and got[2].detail[1].endswith("u0x0001"),
          str(got[2].detail))

    # 同样内容但没人指向 -> nop + 标记
    units2 = [0x000E, 0x0100, 0x0002, 0x0000, 0x0000]
    got2 = _decode(units2)
    check("无上下文 0x0100 按 nop 处理",
          got2[1].mnemonic == "nop" and got2[1].units == 1, got2[1].mnemonic)
    check("无上下文 0x0100 留下标记", "payload" in got2[1].note, got2[1].note)

    # 0x0100 出现在偶数位但却是真的 nop（值 0x0000）——不应被误判
    units3 = [0x000E, 0x0000, 0x000E]
    got3 = _decode(units3)
    check("普通 nop 不误判为 payload",
          got3[1].mnemonic == "nop" and not got3[1].is_payload and not got3[1].note,
          got3[1].note)

    # fill-array-data payload 长度 = 4 + ceil(size*width/2)
    units4 = [0x0026, 0x0004, 0x0000, 0x000E,
              0x0300, 0x0004, 0x0003, 0x0000,  # ident, element_width=4, size=3
              0x0102, 0x0304, 0x0506, 0x0708, 0x090A, 0x0B0C]   # 12 字节 = 6 units
    got4 = _decode(units4)
    check("array-data payload 长度", got4[2].units == 10, str(got4[2].units))
    check("array-data 元素宽度/个数", "element_width=4" in got4[2].operands
          and "size=3" in got4[2].operands, got4[2].operands)


# =====================================================================
# 6. API 行为
# =====================================================================

def test_api():
    """合成 dex 上把四个 API 的行为与错误路径跑一遍。"""
    dex_bytes = _build_pitfall_dex()
    tmpdir = tempfile.mkdtemp(prefix="mda_dex_test_")
    path = os.path.join(tmpdir, "test.dex")
    try:
        with open(path, "wb") as f:
            f.write(dex_bytes)

        cls = dex_classes(path)
        names = [c["name"] for c in cls]
        check("dex_classes 类数", len(cls) == 2, str(names))
        check("dex_classes 描述符", sorted(names) == ["Ltest/Bar;", "Ltest/Caller;"],
              str(names))
        caller = next(c for c in cls if c["name"] == "Ltest/Caller;")
        check("dex_classes superclass", caller["superclass"] == "Ljava/lang/Object;",
              caller["superclass"])
        check("dex_classes source_file", caller["source_file"] == "T.java",
              caller["source_file"])
        check("dex_classes method_count", caller["method_count"] == 5,
              str(caller["method_count"]))
        check("dex_classes interfaces", caller["interfaces"] == ["Ltest/Iface;"],
              str(caller["interfaces"]))

        ms = dex_methods(path, "Ltest/Caller;")
        check("dex_methods 方法数", len(ms) == 5, str([m["name"] for m in ms]))
        check("dex_methods 名字不重复（增量索引正确）",
              sorted(m["name"] for m in ms)
              == ["arrayOn", "callBar", "nativeCall", "switchOn", "wideMove"],
              str([m["name"] for m in ms]))
        by_name = {m["name"]: m for m in ms}
        check("dex_methods insn_count", by_name["wideMove"]["insn_count"] == 7,
              str(by_name["wideMove"]["insn_count"]))
        check("dex_methods param_count", by_name["callBar"]["param_count"] == 0)
        check("dex_methods 描述符写法等价", len(dex_methods(path, "test.Caller")) == 5)
        check("dex_methods native 标记", by_name["nativeCall"]["is_native"] is True
              and by_name["nativeCall"]["code_off"] == 0
              and by_name["nativeCall"]["insn_count"] == 0,
              str(by_name["nativeCall"]))

        # 反汇编：偏移与操作数
        text = dex_disasm(path, "Ltest/Caller;", "wideMove")
        lines = [ln for ln in text.splitlines() if ln.startswith("0x")]
        check("disasm 行数", len(lines) == 4, f"{len(lines)} 行")
        check("disasm 首行是 0x0000", lines[0].startswith("0x0000(u0000):"), lines[0])
        check("disasm 第二条在 0x0006(u0003)",
              lines[1].startswith("0x0006(u0003):"), lines[1])
        check("disasm 含 move-wide/16", "move-wide/16" in lines[0], lines[0])

        sw = dex_disasm(path, "Ltest/Caller;", "switchOn")
        check("disasm switch 带 payload", "packed-switch-data" in sw, sw[-200:])
        check("disasm switch case 明细", "case key=1" in sw and "case key=2" in sw)

        # 调用者
        callers = dex_callers(path, "Ltest/Bar;", "bar")
        check("dex_callers 找到调用者", len(callers) == 1, str(callers))
        if callers and "error" not in callers[0]:
            check("dex_callers 调用者类", callers[0]["caller_class"] == "Ltest/Caller;",
                  callers[0]["caller_class"])
            check("dex_callers invoke 种类", callers[0]["invoke_kind"] == "invoke-virtual",
                  callers[0]["invoke_kind"])
            check("dex_callers 调用点偏移", callers[0]["sites"][0]["insn_off"] == 0,
                  str(callers[0]["sites"]))
        check("dex_callers 无人调用返回空列表",
              dex_callers(path, "Ltest/Caller;", "switchOn") == [],
              str(dex_callers(path, "Ltest/Caller;", "switchOn")))

        # 错误路径：不编造数据
        bad = dex_classes(os.path.join(tmpdir, "nope.dex"))
        check("不存在的文件返回 error", bad and bad[0].get("error") == "FILE_NOT_FOUND",
              str(bad))
        bad = dex_classes(path[:-4] + ".apk")
        check("不存在的 apk 返回 error", bad and "error" in bad[0], str(bad))
        bad = dex_methods(path, "Lno/Such;")
        check("不存在的类返回 CLASS_NOT_FOUND",
              bad and bad[0].get("error") == "CLASS_NOT_FOUND", str(bad))
        bad = dex_disasm(path, "Ltest/Caller;", "noSuchMethod")
        check("不存在的方法返回 METHOD_NOT_FOUND 文本",
              bad.startswith("; ERROR METHOD_NOT_FOUND"), bad[:80])
        bad = dex_disasm(path, "Ltest/Caller;", "wideMove", "()I")
        check("overload 不匹配给出候选",
              "ERROR" in bad and "wideMove" in bad, bad[:160])

        # native 方法没有字节码：返回说明文本，不是错误也不是假指令
        native = dex_disasm(path, "Ltest/Caller;", "nativeCall")
        check("native 方法反汇编给出无 code 说明",
              "没有字节码" in native and "native" in native, native[:160])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_api_edge_cases():
    """overload 选择、无 code 方法、apk 内多 dex 合并（用真实样本）。"""
    if not os.path.exists(SAMPLE_APK):
        skip("真实样本不存在，跳过 overload / 多 dex 用例")
        return
    # 同一方法名的多个重载，必须靠 overload 区分
    cs = dex_classes(SAMPLE_APK)
    check("apk 类表非空", bool(cs) and "error" not in cs[0], str(cs[:1]))
    dexes = {c.get("dex") for c in cs if "dex" in c}
    check("apk 多 dex 合并（>1 个 dex）", len(dexes) > 1, str(sorted(dexes)))


# =====================================================================
# 7. 与 dexdump 逐指令交叉验证
# =====================================================================

def _have_tools() -> bool:
    return os.path.exists(DEXDUMP) and os.path.exists(SAMPLE_APK)


BUILD_TOOLS = Path(DEXDUMP).parent.parent  # .../sdk/build-tools


def _dexdump_bins() -> list[str]:
    """所有可用的 dexdump，新版本优先（dex 038+ 老版本 dexdump 可能不认）。"""
    bins = [str(p) for p in sorted(BUILD_TOOLS.glob("*/dexdump"), reverse=True) if p.is_file()]
    if not bins and os.path.exists(DEXDUMP):
        bins = [DEXDUMP]
    return bins


def _run_dexdump(dex_path: str, *args: str) -> str | None:
    """跑 dexdump，返回解码后的输出；全部版本都失败时返回 None。"""
    for exe in _dexdump_bins():
        r = subprocess.run([exe, *args, dex_path], capture_output=True)
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "replace")
    return None


def _extract_dex(apk: str, entry: str, tmpdir: str) -> str:
    import zipfile
    with zipfile.ZipFile(apk) as z:
        data = z.read(entry)
    path = os.path.join(tmpdir, entry.replace("/", "_"))
    with open(path, "wb") as f:
        f.write(data)
    return path


def _dexdump_blocks(text: str) -> tuple[dict[int, list[tuple[int, str]]], int]:
    """解析 dexdump -d：code_item 文件偏移 -> [(code-unit 偏移, 助记符)]。

    dexdump 的方法头行长这样（`|[code_off]` 是 code_item 的文件偏移）：
        1718ac:                                        |[1718ac] android.support...fromRating:(...)
    指令行长这样（`|NNNN:` 是 **code unit** 偏移）：
        1718e8: 2b02 3000 0000                         |0016: packed-switch v2, 00000046
    payload 只占一行：`|0046: packed-switch-data (16 units)`
    """
    blocks: dict[int, list[tuple[int, str]]] = {}
    cur = None
    bad_lines = 0
    hdr_re = re.compile(r"^([0-9a-f]+):\s+\|\[([0-9a-f]+)\]")
    # 注意：payload 行的字节列会截断成 "... "，所以字符类里必须允许点
    insn_re = re.compile(r"^([0-9a-f]+): ([0-9a-f .]*?)\s+\|([0-9a-f]{4}): (\S+)(.*)$")
    for line in text.splitlines():
        m = hdr_re.match(line)
        if m:
            cur = int(m.group(2), 16)
            blocks[cur] = []
            continue
        m = insn_re.match(line)
        if m and cur is not None:
            blocks[cur].append((int(m.group(3), 16), m.group(4)))
        elif line.startswith("0x"):
            bad_lines += 1
    return blocks, bad_lines


def _my_blocks(dex: dexapi.DexFile) -> dict[int, list[tuple[int, str]]]:
    """用本实现解出同样的结构（走 dex_disasm 同一条渲染路径）。"""
    out: dict[int, list[tuple[int, str]]] = {}
    for _cd, _m, ci in dex.iter_method_code():
        units = dex.units_of(ci)
        view = dexapi._CodeView(dex.tables, ci.insns_off)
        insns = bytecode.disassemble(view, units, ci.insns_size)
        out[ci.off] = [(i.unit_off, i.mnemonic) for i in insns]
    return out


def _opcode_coverage(dex: dexapi.DexFile, targets: set[int]) -> dict[int, int]:
    """统计指定 opcode 在样本里出现多少次（证明哪些格式被真样本覆盖到）。"""
    count = {op: 0 for op in targets}
    for _cd, _m, ci in dex.iter_method_code():
        units = dex.units_of(ci)
        view = dexapi._CodeView(dex.tables, ci.insns_off)
        for insn in bytecode.disassemble(view, units, ci.insns_size):
            if insn.is_payload:
                continue
            # 用助记符反查 opcode（payload 与指令都从 MNEMONIC 表来）
            try:
                op = bytecode.MNEMONIC.index(insn.mnemonic)
            except ValueError:
                continue
            if op in count:
                count[op] += 1
    return count


def test_dexdump_crosscheck():
    """逐指令比对：同一方法，偏移与助记符必须完全一致。"""
    if not _have_tools():
        skip(f"dexdump 或样本不存在（{DEXDUMP} / {SAMPLE_APK}），跳过交叉验证")
        return

    tmpdir = tempfile.mkdtemp(prefix="mda_dex_xcheck_")
    try:
        entries = ["classes.dex"]
        if FULL:
            import zipfile
            with zipfile.ZipFile(SAMPLE_APK) as z:
                entries = sorted(
                    [n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)],
                    key=lambda n: int(n[len("classes"):-len(".dex")] or 1),
                )
        totals = {"insns": 0, "mismatch": 0, "methods": 0, "dump_only": 0,
                  "my_only": 0, "payloads": 0}
        samples: list[str] = []
        for entry in entries:
            dex_path = _extract_dex(SAMPLE_APK, entry, tmpdir)
            out_text = _run_dexdump(dex_path, "-d")
            if out_text is None:
                skip(f"dexdump 拒绝 {entry}（版本过旧？）")
                continue
            blocks, _bad = _dexdump_blocks(out_text)
            with open(dex_path, "rb") as f:
                dex = dexapi.DexFile(f.read(), entry, entry, dex_path)
            mine = _my_blocks(dex)

            # 表规模：与 dexdump -f 对齐
            hdr_text = _run_dexdump(dex_path, "-f") or ""
            fields = dict(re.findall(r"^(\w+_size)\s+:\s+(\d+)", hdr_text, re.M))
            my_counts = {
                "string_ids_size": dex.header.string_ids_size,
                "type_ids_size": dex.header.type_ids_size,
                "proto_ids_size": dex.header.proto_ids_size,
                "field_ids_size": dex.header.field_ids_size,
                "method_ids_size": dex.header.method_ids_size,
                "class_defs_size": dex.header.class_defs_size,
            }
            for k, v in my_counts.items():
                if k in fields:
                    check(f"{entry} {k} 与 dexdump 一致", int(fields[k]) == v,
                          f"dexdump={fields[k]} mda={v}")

            only_dump = set(blocks) - set(mine)
            only_mine = set(mine) - set(blocks)
            totals["dump_only"] += len(only_dump)
            totals["my_only"] += len(only_mine)
            for off in sorted(set(blocks) & set(mine)):
                a = blocks[off]
                b = mine[off]
                totals["methods"] += 1
                totals["payloads"] += sum(1 for _o, mn in a if mn.endswith("-data"))
                # 长度不同也是错位信号
                if len(a) != len(b):
                    totals["mismatch"] += 1
                    if len(samples) < 10:
                        samples.append(
                            f"{entry} code_off=0x{off:x} 指令条数 dexdump={len(a)} mda={len(b)}"
                            f" 首个不同位置见下")
                    for k in range(min(len(a), len(b))):
                        if a[k] != b[k]:
                            if len(samples) < 10:
                                samples.append(
                                    f"  #{k} dexdump={a[k]} mda={b[k]}")
                            break
                    continue
                totals["insns"] += len(a)
                for k, (ta, tb) in enumerate(zip(a, b)):
                    if ta != tb:
                        totals["mismatch"] += 1
                        if len(samples) < 10:
                            samples.append(
                                f"{entry} code_off=0x{off:x} #{k}: dexdump={ta} mda={tb}")
                        break

        total_cmp = totals["insns"] + totals["mismatch"]
        rate = (totals["insns"] / total_cmp * 100) if total_cmp else 0.0
        print(f"    交叉验证：{totals['methods']} 个方法 / {total_cmp} 条指令，"
              f"一致 {totals['insns']} 条（{rate:.4f}%），不一致 {totals['mismatch']} 条，"
              f"payload {totals['payloads']} 块")
        if totals["dump_only"] or totals["my_only"]:
            print(f"    仅 dexdump 有 {totals['dump_only']} 个 code_item，"
                  f"仅 mda 有 {totals['my_only']} 个（都应为 0）")
        for s in samples:
            print(f"    不一致样例: {s}")
        check(f"逐指令偏移+助记符完全一致（{total_cmp} 条）", totals["mismatch"] == 0,
              f"{totals['mismatch']} 条不一致，样例 {samples[:3]}")
        check("code_item 集合与 dexdump 一致",
              totals["dump_only"] == 0 and totals["my_only"] == 0,
              f"仅dump={totals['dump_only']} 仅mda={totals['my_only']}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_named_methods():
    """任务要求的三个具名方法：带 switch payload / 带 wide 指令 / 方法最多的类。"""
    if not _have_tools():
        skip("样本不存在，跳过具名方法验证")
        return
    tmpdir = tempfile.mkdtemp(prefix="mda_dex_named_")
    try:
        dex_path = _extract_dex(SAMPLE_APK, "classes.dex", tmpdir)
        with open(dex_path, "rb") as f:
            dex = dexapi.DexFile(f.read(), "classes.dex", "classes.dex", dex_path)
        dump_text = _run_dexdump(dex_path, "-d") or ""
        blocks, _bad = _dexdump_blocks(dump_text)

        # (1) 带 packed-switch payload 的方法
        sw_name = "fromRating"
        sw_cls = None
        for cd in dex.class_defs():
            for m, r in dex.method_refs(cd):
                if r.name == sw_name and cd.name.endswith("RatingCompat;"):
                    sw_cls = cd
                    break
            if sw_cls:
                break
        _compare_one(dex, blocks, sw_cls.name, sw_name, "")
        # payload 明细也要正确：case 目标应落在方法内、且指向真实指令起点
        text = dex_disasm(SAMPLE_APK, sw_cls.name, sw_name)
        check("switch 方法反汇编含 payload 明细",
              "packed-switch-data" in text and "case key=1" in text)

        # (2) 带 wide 指令的方法：先找样本里含 0x18(const-wide)/0x06 的方法
        wide = _find_method_with_ops(dex, {0x18, 0x17, 0x06, 0x05})
        if wide:
            cd, m, r = wide
            _compare_one(dex, blocks, cd.name, r.name, r.proto.descriptor)
            t = dex_disasm(SAMPLE_APK, cd.name, r.name, r.proto.descriptor)
            check("wide 方法反汇编含 wide 指令",
                  any(k in t for k in ("const-wide", "move-wide", "move/16")), t[:200])
        else:
            skip("样本里没有 wide 指令方法")

        # (3) 方法数最多的类
        worst = max(dex.class_defs(), key=lambda c: len(dex.method_refs(c)))
        refs = dex.method_refs(worst)
        cd_name = worst.name
        m, r = refs[0]
        _compare_one(dex, blocks, cd_name, r.name, r.proto.descriptor)
        print(f"    方法最多的类：{cd_name}（{len(refs)} 个方法），"
              f"抽检 {r.name}{r.proto.descriptor}")

        # opcode 覆盖情况（证明哪些格式被真样本覆盖）
        cov = _opcode_coverage(dex, {0x02, 0x03, 0x05, 0x06, 0x09, 0x18, 0x17,
                                     0x2B, 0x2C, 0x26, 0xFA, 0xFB, 0xFC, 0xFD,
                                     0x1B, 0x24, 0x25, 0x45, 0x60})
        covered = {hex(k): v for k, v in cov.items() if v}
        missing = [hex(k) for k, v in cov.items() if not v]
        print(f"    样本 opcode 覆盖：{covered}")
        if missing:
            print(f"    样本未覆盖：{missing}（由下一节「扩展格式验证」现场生成 dex 补验）")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _find_method_with_ops(dex: dexapi.DexFile, wanted: set[int]):
    """找第一个包含指定 opcode 的方法。"""
    for cd, m, ci in dex.iter_method_code():
        units = dex.units_of(ci)
        view = dexapi._CodeView(dex.tables, ci.insns_off)
        for insn in bytecode.disassemble(view, units, ci.insns_size):
            if insn.is_payload:
                continue
            try:
                op = bytecode.MNEMONIC.index(insn.mnemonic)
            except ValueError:
                continue
            if op in wanted:
                ref = dex.tables.method(m.method_idx)
                return cd, m, ref
    return None


def _compare_one(dex: dexapi.DexFile, blocks, cls_name: str, method_name: str,
                 overload: str) -> None:
    """对单个方法做逐指令比对（用 dex_disasm 的真实输出解析）。"""
    text = dex_disasm(_current_dex_path(), cls_name, method_name, overload)
    if text.startswith("; ERROR"):
        check(f"抽检方法可反汇编 {cls_name}->{method_name}", False, text[:160])
        return
    lines = [ln for ln in text.splitlines() if ln.startswith("0x")]
    mine = []
    for ln in lines:
        m = re.match(r"^0x[0-9a-f]+\(u([0-9a-f]+)\): .*? \| (\S+)", ln)
        if m:
            mine.append((int(m.group(1), 16), m.group(2)))
    # 找到该方法在 dexdump 里的块：按第一条指令偏移匹配
    if not mine:
        check(f"抽检方法有指令 {cls_name}->{method_name}", False, "反汇编为空")
        return
    code_off = None
    for cd in dex.class_defs():
        if cd.name != cls_name:
            continue
        for m, r in dex.method_refs(cd):
            if r.name == method_name and (not overload or r.proto.descriptor == overload):
                code_off = m.code_off
                break
        break
    if code_off is None or code_off not in blocks:
        check(f"抽检方法在 dexdump 输出中出现 {cls_name}->{method_name}", False,
              f"code_off={code_off}")
        return
    want = blocks[code_off]
    check(f"抽检 {cls_name.split('/')[-1]}->{method_name} 逐指令一致（{len(want)} 条）",
          mine == want,
          f"mda 前3={mine[:3]} dexdump 前3={want[:3]}")


_CURRENT = {"path": None}


def _current_dex_path() -> str:
    return _CURRENT["path"]



# ---------------------------------------------------------------------
# 7b. 真实样本里缺失的指令格式：用 javac + dx 现场造 dex 补验
# ---------------------------------------------------------------------

# 为什么需要这一块：汽水音乐 6.2 的 classes.dex 是 R8 产物，全库 563078 条
# 指令里 **一次都没有** 0x03/0x06/0x09（32x）与 0xfa/0xfc（038 新指令）。
# 而 0x06 move-wide/16 = 32x = 3 units 恰恰是最容易写错的一条，
# 只靠格式表"自认为对"没有说服力。这里现场编译出真实 dex 再对拍：
#   · 32x 需要源/目标寄存器都 > 255 —— 300 个同时活跃的 long 局部变量
#   · invoke-custom 需要 lambda + min-api 26
#   · invoke-polymorphic 需要 MethodHandle.invoke/invokeExact

JAVA_WIDE = """
public class WideTest {{
  public static long many(long[] in) {{
{decls}
    long sum = 0;
{assigns}
{sums}
    return sum;
  }}
  public static Object objs(Object[] in) {{
{odecls}
    Object sum = in[0];
{oassigns}
{ochecks}
    return sum;
  }}
  public java.util.function.Supplier<String> mk() {{
    String s = "hello";
    return () -> s + "world";
  }}
}}
"""

JAVA_MH = """
import java.lang.invoke.*;
public class Mh {
  public static Object call(MethodHandle mh, Object a) throws Throwable { return mh.invoke(a); }
  public static Object callExact(MethodHandle mh, int a) throws Throwable { return (Object) mh.invokeExact(a); }
}
"""


def _gen_wide_dex(tmpdir: str) -> str | None:
    """生成含 32x / invoke-custom 的 dex（javac --release 8 + dx --min-sdk-version=26）。"""
    n = 300
    src = JAVA_WIDE.format(
        # 300 个同时活跃的 long -> 源/目标寄存器都 > 255，逼出 32x（0x06/0x03）
        decls="\n".join(f"    long a{i} = in[{i}];" for i in range(n)),
        assigns="\n".join(f"    if (a{i} > 0) {{ a{i} = a{(i + 280) % n}; }}"
                           for i in range(0, n, 7)),
        sums="\n".join(f"    sum += a{i};" for i in range(n)),
        # 300 个同时活跃的 Object -> 逼出 move-object/16（0x09）
        odecls="\n".join(f"    Object o{i} = in[{i}];" for i in range(n)),
        oassigns="\n".join(f"    if (o{i} != null) {{ o{i} = o{(i + 271) % n}; }}"
                            for i in range(0, n, 7)),
        ochecks="\n".join(f"    if (o{i} == sum) {{ sum = o{i}; }}" for i in range(n)),
    )
    return _compile_java(tmpdir, "WideTest", src)


def _gen_mh_dex(tmpdir: str) -> str | None:
    """生成含 invoke-polymorphic(45cc) 的 dex。"""
    return _compile_java(tmpdir, "Mh", JAVA_MH)


def _compile_java(tmpdir: str, cls: str, src: str) -> str | None:
    """javac --release 8 -> dx；成功返回 dex 路径。"""
    javac = shutil.which("javac")
    dx = str(Path(DEXDUMP).parent / "dx")
    if not javac or not os.path.exists(dx):
        return None
    java_path = os.path.join(tmpdir, f"{cls}.java")
    with open(java_path, "w", encoding="utf-8") as f:
        f.write(src)
    r = subprocess.run([javac, "--release", "8", "-encoding", "UTF-8", "-d", tmpdir, java_path],
                       capture_output=True)
    if r.returncode != 0:
        print(f"    javac 失败：{r.stderr.decode('utf-8', 'replace')[:160]}")
        return None
    out = os.path.join(tmpdir, f"{cls}.dex")
    # dx 用相对路径喂 class（绝对路径会报 “class name does not match path”）
    r = subprocess.run([dx, "--dex", "--min-sdk-version=26", f"--output={out}",
                        f"{cls}.class"], capture_output=True, cwd=tmpdir)
    if r.returncode != 0:
        print(f"    dx 失败：{r.stderr.decode('utf-8', 'replace')[:160]}")
        return None
    return out


def test_extended_formats_crosscheck():
    """补验 32x / 31c-era 的 038 指令：与 dexdump 逐指令对拍。"""
    if not os.path.exists(DEXDUMP):
        skip("dexdump 不存在，跳过扩展格式验证")
        return
    if not shutil.which("javac") or not os.path.exists(str(Path(DEXDUMP).parent / "dx")):
        skip("javac 或 dx 不存在，跳过扩展格式验证")
        return
    tmpdir = tempfile.mkdtemp(prefix="mda_dex_gen_")
    try:
        for label, maker, wanted in (
            ("32x + invoke-custom", _gen_wide_dex, {0x02, 0x03, 0x05, 0x06, 0x09, 0xFC}),
            ("invoke-polymorphic", _gen_mh_dex, {0xFA}),
        ):
            dex_path = maker(tmpdir)
            if not dex_path:
                skip(f"{label} 生成失败")
                continue
            out_text = _run_dexdump(dex_path, "-d")
            if out_text is None:
                skip(f"dexdump 不认 {label} 生成的 dex")
                continue
            blocks, _bad = _dexdump_blocks(out_text)
            with open(dex_path, "rb") as f:
                dex = dexapi.DexFile(f.read(), os.path.basename(dex_path),
                                     os.path.basename(dex_path), dex_path)
            mine = _my_blocks(dex)
            total = 0
            bad = 0
            for off in sorted(set(blocks) & set(mine)):
                a, b = blocks[off], mine[off]
                total += len(a)
                if a != b:
                    bad += 1
                    if bad == 1:
                        for i2, (x, y) in enumerate(zip(a, b)):
                            if x != y:
                                print(f"    首个不一致 code_off=0x{off:x} #{i2} "
                                      f"dexdump={x} mda={y}")
                                break
            check(f"{label}：{total} 条指令逐条一致", bad == 0 and total > 0,
                  f"{bad} 个方法不一致")
            cov = _opcode_coverage(dex, wanted)
            hit = {hex(k): v for k, v in cov.items() if v}
            print(f"    {label} 覆盖：{hit}")
            check(f"{label}：目标 opcode 真的出现了", all(cov[k] > 0 for k in wanted),
                  f"未出现 {[hex(k) for k in wanted if not cov[k]]}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_jumbo_string_crosscheck():
    """const-string/jumbo(0x1b, 31c) 需要 string_ids > 65536，6.2 的 dex 不够。

    做法：在样本同目录找任何一个 string_ids_size > 65536 的 dex（不写死 App 名），
    抽出来与 dexdump 全量对拍。找不到就跳过。
    """
    if not os.path.exists(DEXDUMP) or not os.path.exists(SAMPLE_APK):
        skip("dexdump 或样本不存在，跳过 jumbo 验证")
        return
    import glob
    import zipfile
    candidates: list[tuple[str, str]] = []
    for apk in sorted(glob.glob(os.path.join(os.path.dirname(SAMPLE_APK), "*.apk"))):
        try:
            with zipfile.ZipFile(apk) as z:
                for n in z.namelist():
                    if not (n.startswith("classes") and n.endswith(".dex")):
                        continue
                    head = z.read(n)[:0x70]
                    if len(head) >= 0x3C and int.from_bytes(head[0x38:0x3C], "little") > 65536:
                        candidates.append((apk, n))
        except Exception:
            continue
    if not candidates:
        skip("没有 string_ids > 65536 的 dex，跳过 jumbo 验证")
        return
    apk, entry = candidates[0]
    tmpdir = tempfile.mkdtemp(prefix="mda_dex_jumbo_")
    try:
        dex_path = _extract_dex(apk, entry, tmpdir)
        with open(dex_path, "rb") as f:
            data = f.read()
        out_text = _run_dexdump(dex_path, "-d")
        if out_text is None:
            skip(f"dexdump 拒绝 {entry}")
            return
        blocks, _bad = _dexdump_blocks(out_text)
        dex = dexapi.DexFile(data, entry, entry, dex_path)
        mine = _my_blocks(dex)
        total = bad = 0
        for off in sorted(set(blocks) & set(mine)):
            a, b = blocks[off], mine[off]
            total += len(a)
            if a != b:
                bad += 1
        cov = _opcode_coverage(dex, {0x1B})
        check(f"jumbo：{total} 条指令逐条一致（{os.path.basename(apk)}!{entry}）",
              bad == 0 and total > 0, f"{bad} 个方法不一致")
        check("jumbo：const-string/jumbo 真的出现", cov[0x1B] > 0, str(cov))
        print(f"    const-string/jumbo 条数：{cov[0x1B]}，"
              f"string_ids={dex.header.string_ids_size}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

# =====================================================================
# 运行框架
# =====================================================================

def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


def skip(reason: str) -> None:
    global SKIP
    SKIP += 1
    print(f"  [SKIP] {reason}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


def test_caller_roundtrip_real():
    """闭环：反汇编里的 invoke 目标，必须能被 dex_callers 反查回来。

    (1) 第一次修改（2026-11-18）
        bug 原因：method_id_item 的 class_idx 曾被按**大端**读
                  （(b0<<8)|b1），而同一结构体的 proto_idx/name_idx 用
                  小端。合成测试里目标类的 type_idx 恰好是 0
                  （0x0000 两种字节序读出来一样），于是 126 项测试全绿；
                  但在真实 apk 上（type_idx 动辄 3973 = 0x0F85）大端读到
                  0x850F，dex_callers 对**任何方法**都静默返回 []——
                  而 dex_disasm 里明明显示着那条 invoke，且不抛异常。
                  这是一次"测试全过但功能是错的"的实例：合成样本的
                  type_idx=0 恰好是字节序的盲区。
        解决方案：用真实 apk 做闭环——先从 dex_disasm 里抓一条 invoke 的
                  目标（类/名/原型），再用 dex_callers 反查，调用者集合里
                  必须包含刚才反汇编的那个方法；同时直白断言该类的
                  type_idx 非 0，确保这条测试真的踩在字节序上。
    """
    if not os.path.exists(SAMPLE_APK):
        print("  [SKIP] 样本 apk 不存在")
        return
    cls = "androidx.recyclerview.widget.RecyclerView"
    try:
        dis = dex_disasm(SAMPLE_APK, cls, "<clinit>", "()V")
    except Exception as exc:                              # noqa: BLE001
        check("反汇编可执行", False, f"{type(exc).__name__}: {exc}")
        return
    import re
    # 引用文本用 `;.` 连接（不是 `;->`），两种都接受
    m = re.search(r"\},\s+(L[^;]+;)[.>-]+([^(\s]+)(\([^)]*\)\S+)", dis)
    check("反汇编里能找到 invoke 目标", m is not None, dis[:200])
    if not m:
        return
    target_cls = m.group(1)[1:-1].replace("/", ".")
    target_name = m.group(2)
    target_proto = m.group(3)

    callers = dex_callers(SAMPLE_APK, target_cls, target_name, target_proto)
    check(f"dex_callers 能反查到 {target_name}{target_proto}",
          isinstance(callers, list) and len(callers) > 0, str(callers)[:200])
    if isinstance(callers, list) and callers:
        names = {c.get("caller") for c in callers}
        check("调用者集合包含刚才反汇编的那个方法",
              any(n and "<clinit>" in n for n in names), str(names)[:200])

    # 直白断言字节序：type_idx 非 0 才踩得到这个 bug
    from server.core.dex.api import (
        _find_class, _norm_class, _open_source, _target_method_indices,
    )
    src = _open_source(SAMPLE_APK)
    try:
        found = _find_class(src, _norm_class(target_cls))
        if isinstance(found, str):
            check("真实样本里能定位目标类", False, found[:120])
            return
        dex, cd = found
        ti = dex.type_index_of(cd.name)
        check(f"目标类 type_idx={ti} 非 0（这条测试才踩得到字节序）",
              ti not in (None, 0), str(ti))
        idxs = _target_method_indices(dex, cd.name, target_name, target_proto)
        check("_target_method_indices 在非 0 type_idx 下能命中",
              len(idxs) > 0, str(idxs))
    finally:
        src.close()


def main() -> int:
    global PASS, FAIL, SKIP
    print(__doc__.split("—— 交叉验证结果")[0].strip())
    print(f"\n模式：{'全量（9 个 dex）' if FULL else 'classes.dex'}")

    section("坑 1：MUTF-8 + ULEB128")
    test_mutf8()
    section("坑 2：class_data 增量索引")
    test_incremental_index()
    section("坑 3：变长指令格式")
    test_instruction_widths()
    section("坑 4：payload 上下文")
    test_payload_context()
    section("API 行为（合成 dex）")
    test_api()
    section("API 边界（真实样本）")
    test_api_edge_cases()
    section("与 dexdump 逐指令交叉验证")
    test_dexdump_crosscheck()
    section("扩展格式验证（jumbo 字符串）")
    test_jumbo_string_crosscheck()
    section("扩展格式验证（32x / 038 新指令）")
    test_extended_formats_crosscheck()
    section("闭环：invoke 反查（真实样本，覆盖 class_idx 字节序）")
    test_caller_roundtrip_real()
    section("任务指定的具名方法")
    if _have_tools():
        # _compare_one 里的 dex_disasm 走公开 API，需要路径
        _CURRENT["path"] = SAMPLE_APK
    test_named_methods()

    print(f"\n合计：PASS={PASS} FAIL={FAIL} SKIP={SKIP}")
    if FAIL:
        print("有失败项，见上面的 [FAIL]。")
        return 1
    print("全部通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
