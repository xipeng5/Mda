"""class_data_item 与 code_item 解析。

—— 坑 2（本模块存在的理由）——

class_data_item 里，字段与方法的索引是 **增量（diff）**编码的：

    class_data_item:
        uleb128 static_fields_size
        uleb128 instance_fields_size
        uleb128 direct_methods_size
        uleb128 virtual_methods_size
        encoded_field  static_fields[static_fields_size]
        encoded_field  instance_fields[instance_fields_size]
        encoded_method direct_methods[direct_methods_size]
        encoded_method virtual_methods[virtual_methods_size]

    encoded_field : uleb128 field_idx_diff, uleb128 access_flags
    encoded_method: uleb128 method_idx_diff, uleb128 access_flags, uleb128 code_off

field_idx_diff / method_idx_diff 是**相对上一条**的增量，必须累加：
当前 idx = 上一条 idx + diff，且**两个列表各自独立累加**
（direct 与 virtual 的累加起点都是 0，不是接着对方的末值）。

不累加的典型症状：整类所有方法解成同一个 idx。落在方法表上就是「一个类里
出现几十个同名 <init>」——这正是本模块开头把这一点写死的原因。
code_off 也是相对 data 段起点的偏移（绝对文件偏移），不是 diff。

code_item:
    u2 registers_size, u2 ins_size, u2 outs_size, u2 tries_size,
    u4 debug_info_off, u4 insns_size, u2 insns[insns_size], 对齐填充,
    try_item[tries_size], encoded_catch_handler_list
本模块只切出 insns 的位置（反汇编不需要 try/catch 结构，见 docs 里的遗留问题）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .reader import DexBuffer, uleb128

# code_item 头部固定 16 字节，之后才是 insns
CODE_ITEM_HEADER = 16


@dataclass
class EncodedField:
    """一条 encoded_field（idx 已累加完毕）。"""

    field_idx: int
    access_flags: int
    is_static: bool


@dataclass
class EncodedMethod:
    """一条 encoded_method（idx 已累加完毕）。"""

    method_idx: int
    access_flags: int
    code_off: int
    is_direct: bool

    @property
    def has_code(self) -> bool:
        """native / abstract 方法 code_off 为 0。"""
        return self.code_off != 0


@dataclass
class ClassData:
    """class_data_item 解析结果（四个列表保持文件里的原始顺序）。"""

    static_fields: list[EncodedField] = field(default_factory=list)
    instance_fields: list[EncodedField] = field(default_factory=list)
    direct_methods: list[EncodedMethod] = field(default_factory=list)
    virtual_methods: list[EncodedMethod] = field(default_factory=list)

    @property
    def methods(self) -> list[EncodedMethod]:
        """direct 在前、virtual 在后 —— 与 dexdump 的输出顺序一致。"""
        return self.direct_methods + self.virtual_methods

    @property
    def fields(self) -> list[EncodedField]:
        return self.static_fields + self.instance_fields


@dataclass
class CodeItem:
    """code_item 的位置与尺寸信息（insns 未展开）。"""

    off: int
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int
    insns_off: int

    @property
    def byte_size(self) -> int:
        """字节码区字节数（insns_size 的单位是 16-bit code unit）。"""
        return self.insns_size * 2


def _read_encoded_fields(buf: DexBuffer, off: int, count: int, is_static: bool,
                         out: list[EncodedField]) -> int:
    """读 count 条 encoded_field，增量累加 field_idx。返回新偏移。"""
    data = buf.data
    idx = 0
    for _ in range(count):
        diff, off = uleb128(data, off)
        flags, off = uleb128(data, off)
        # 坑 2：增量累加。少了这一行，整类字段会是同一个 idx
        idx += diff
        out.append(EncodedField(field_idx=idx, access_flags=flags, is_static=is_static))
    return off


def _read_encoded_methods(buf: DexBuffer, off: int, count: int, is_direct: bool,
                          out: list[EncodedMethod]) -> int:
    """读 count 条 encoded_method，增量累加 method_idx。返回新偏移。"""
    data = buf.data
    idx = 0
    for _ in range(count):
        diff, off = uleb128(data, off)
        flags, off = uleb128(data, off)
        code_off, off = uleb128(data, off)
        # 坑 2：增量累加。少了这一行，一个类里会出现几十个同名 <init>
        idx += diff
        out.append(
            EncodedMethod(
                method_idx=idx, access_flags=flags, code_off=code_off, is_direct=is_direct
            )
        )
    return off


def read_class_data(buf: DexBuffer, off: int) -> ClassData:
    """解析 class_data_item。off=0 表示该类没有数据（只有接口/注解）。"""
    cd = ClassData()
    if off == 0:
        return cd
    buf.need(off, 4, "class_data_item 头部")
    data = buf.data
    static_size, p = uleb128(data, off)
    instance_size, p = uleb128(data, p)
    direct_size, p = uleb128(data, p)
    virtual_size, p = uleb128(data, p)

    p = _read_encoded_fields(buf, p, static_size, True, cd.static_fields)
    p = _read_encoded_fields(buf, p, instance_size, False, cd.instance_fields)
    # direct 与 virtual 各自从 0 开始累加
    p = _read_encoded_methods(buf, p, direct_size, True, cd.direct_methods)
    p = _read_encoded_methods(buf, p, virtual_size, False, cd.virtual_methods)
    return cd


def read_code_item(buf: DexBuffer, off: int) -> CodeItem:
    """解析 code_item 头部并定位 insns。"""
    if off == 0:
        raise ValueError("code_off=0：该方法没有字节码")
    buf.need(off, CODE_ITEM_HEADER, "code_item 头部")
    data = buf.data
    (registers_size, ins_size, outs_size, tries_size,
     debug_info_off, insns_size) = (
        int.from_bytes(data[off:off + 2], "little"),
        int.from_bytes(data[off + 2:off + 4], "little"),
        int.from_bytes(data[off + 4:off + 6], "little"),
        int.from_bytes(data[off + 6:off + 8], "little"),
        int.from_bytes(data[off + 8:off + 12], "little"),
        int.from_bytes(data[off + 12:off + 16], "little"),
    )
    insns_off = off + CODE_ITEM_HEADER
    buf.need(insns_off, insns_size * 2, "code_item insns")
    return CodeItem(
        off=off,
        registers_size=registers_size,
        ins_size=ins_size,
        outs_size=outs_size,
        tries_size=tries_size,
        debug_info_off=debug_info_off,
        insns_size=insns_size,
        insns_off=insns_off,
    )
