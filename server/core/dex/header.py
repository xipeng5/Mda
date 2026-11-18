"""DEX 头部与各 id 表。

职责：解析 header_item（0x70 字节）与 6 张 id 表 / 1 张类定义表，并提供
「按索引取字符串 / 类型描述符 / 原型 / 字段引用 / 方法引用」的统一入口。

    string_ids  -> string_data_item（MUTF-8，见 mutf8.py）
    type_ids    -> 指向 string_ids 的描述符
    proto_ids   -> shorty + 返回类型 + 参数类型列表(type_list)
    field_ids   -> class_idx + type_idx + name_idx
    method_ids  -> class_idx + proto_idx + name_idx
    class_defs  -> class_def_item（32 字节）

索引解析全部带缓存：一张 dex 的 string 可能被几十万次引用，重复解 MUTF-8 会让
类表/方法表解析慢一个数量级。

错误处理：任何一个 offset 字段越界都抛 DexError（上层转成 error 字段），
**不做「跳过坏条目继续」的假兜底**——坏 dex 静默跳过只会产出残缺的表。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .mutf8 import read_string_data
from .reader import DexBuffer, DexError

# header_item 固定 0x70 字节
HEADER_SIZE = 0x70
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412

# 支持的 dex 版本（035 = Android 5，037/038 = 7/8，039 = 9，040 = 14）
KNOWN_VERSIONS = {"035", "037", "038", "039", "040"}


@dataclass
class DexHeader:
    """header_item 的原样字段（不做语义解释）。"""

    version: str
    checksum: int
    signature: str          # hex 串，仅展示
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int
    notes: list[str] = field(default_factory=list)


def parse_header(buf: DexBuffer) -> DexHeader:
    """解析并校验 header_item。"""
    b = buf
    b.need(0, HEADER_SIZE, "header_item")
    magic = bytes(b.data[:8])
    if magic[:4] != b"dex\n" or magic[7:8] != b"\x00":
        raise DexError("NOT_A_DEX", f"magic 非法：{magic.hex()}")
    version = magic[4:7].decode("ascii", "replace")

    checksum = b.u4(0x08)
    signature = bytes(b.data[0x0C:0x0C + 20]).hex()
    file_size = b.u4(0x20)
    header_size = b.u4(0x24)
    endian_tag = b.u4(0x28)

    if header_size != HEADER_SIZE:
        raise DexError(
            "BAD_HEADER",
            f"header_size 应为 0x{HEADER_SIZE:x}，实际 0x{header_size:x}",
        )
    if endian_tag == REVERSE_ENDIAN_CONSTANT:
        raise DexError("BAD_ENDIAN", "big-endian dex：DEX 规范不允许，工具不支持")
    if endian_tag != ENDIAN_CONSTANT:
        raise DexError(
            "BAD_ENDIAN", f"endian_tag 非法：0x{endian_tag:08x}（应为 0x{ENDIAN_CONSTANT:08x}）"
        )

    notes: list[str] = []
    if file_size != len(b.data):
        # 不致命：dex 被嵌在别的容器里、或被截断/追加都见过。记下来但不猜。
        notes.append(f"header.file_size={file_size} 与实际长度 {len(b.data)} 不一致")
    if version not in KNOWN_VERSIONS:
        notes.append(f"dex 版本 {version} 不在已知集合 {sorted(KNOWN_VERSIONS)} 内，按最新布局解析")

    h = DexHeader(
        version=version,
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        link_size=b.u4(0x2C),
        link_off=b.u4(0x30),
        map_off=b.u4(0x34),
        string_ids_size=b.u4(0x38),
        string_ids_off=b.u4(0x3C),
        type_ids_size=b.u4(0x40),
        type_ids_off=b.u4(0x44),
        proto_ids_size=b.u4(0x48),
        proto_ids_off=b.u4(0x4C),
        field_ids_size=b.u4(0x50),
        field_ids_off=b.u4(0x54),
        method_ids_size=b.u4(0x58),
        method_ids_off=b.u4(0x5C),
        class_defs_size=b.u4(0x60),
        class_defs_off=b.u4(0x64),
        data_size=b.u4(0x68),
        data_off=b.u4(0x6C),
        notes=notes,
    )
    _check_table(b, "string_ids", h.string_ids_off, h.string_ids_size, 4)
    _check_table(b, "type_ids", h.type_ids_off, h.type_ids_size, 4)
    _check_table(b, "proto_ids", h.proto_ids_off, h.proto_ids_size, 12)
    _check_table(b, "field_ids", h.field_ids_off, h.field_ids_size, 8)
    _check_table(b, "method_ids", h.method_ids_off, h.method_ids_size, 8)
    _check_table(b, "class_defs", h.class_defs_off, h.class_defs_size, 32)
    return h


def _check_table(b: DexBuffer, name: str, off: int, size: int, entry: int) -> None:
    """校验一张 id 表落在文件内。size=0 时 off 允许为 0。"""
    if size == 0:
        return
    if off == 0:
        raise DexError("BAD_TABLE", f"{name} 声明 {size} 项但偏移为 0")
    b.need(off, size * entry, name)


@dataclass(frozen=True)
class ProtoRef:
    """method prototype：shorty（返回+参数的短描述）+ 返回类型 + 参数类型。"""

    shorty: str
    return_type: str
    params: tuple[str, ...]

    @property
    def descriptor(self) -> str:
        """(参数类型...)返回类型 —— 与 Java 方法描述符一致，也是 overload 参数。"""
        return f"({''.join(self.params)}){self.return_type}"


@dataclass(frozen=True)
class FieldRef:
    class_desc: str
    type_desc: str
    name: str

    def __str__(self) -> str:
        # 与 dexdump 一致：Lcom/x/Y;.name:Type;
        return f"{self.class_desc}.{self.name}:{self.type_desc}"


@dataclass(frozen=True)
class MethodRef:
    class_desc: str
    name: str
    proto: ProtoRef

    def __str__(self) -> str:
        # 与 dexdump 一致：Lcom/x/Y;.name:(I)V
        return f"{self.class_desc}.{self.name}{self.proto.descriptor}"


@dataclass
class ClassDef:
    """class_def_item（32 字节）解析结果。"""

    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    source_file_idx: int
    annotations_off: int
    class_data_off: int
    static_values_off: int
    # 解析后的名字（parse_class_defs 填充）
    name: str = ""
    superclass: str = ""
    interfaces: tuple[str, ...] = ()
    source_file: str = ""

    @property
    def java_name(self) -> str:
        """Lcom/x/Y; -> com.x.Y（给人看的形态；描述符仍以 name 为准）。"""
        n = self.name
        if len(n) >= 2 and n[0] == "L" and n[-1] == ";":
            return n[1:-1].replace("/", ".")
        return n


class DexTables:
    """id 表访问层。所有索引解析都在这里，带缓存。"""

    def __init__(self, buf: DexBuffer, header: DexHeader):
        self.buf = buf
        self.header = header
        self.data = buf.data
        self._strings: dict[int, str] = {}
        self._types: dict[int, str] = {}
        self._protos: dict[int, ProtoRef] = {}
        self._fields: dict[int, FieldRef] = {}
        self._methods: dict[int, MethodRef] = {}

    # ---------- string / type ----------

    def string(self, idx: int) -> str:
        """string_ids[idx] -> 字符串（MUTF-8 解码）。"""
        hit = self._strings.get(idx)
        if hit is not None:
            return hit
        if not 0 <= idx < self.header.string_ids_size:
            raise DexError(
                "BAD_STRING_IDX",
                f"string_idx={idx} 超出范围（共 {self.header.string_ids_size} 项）",
            )
        data_off = struct.unpack_from("<I", self.data, self.header.string_ids_off + idx * 4)[0]
        if data_off == 0:
            raise DexError("BAD_STRING", f"string_ids[{idx}] 的偏移为 0")
        text, _end, _ok = read_string_data(self.data, data_off)
        self._strings[idx] = text
        return text

    def type_desc(self, idx: int) -> str:
        """type_ids[idx] -> 类型描述符，如 Ljava/lang/String; / I / [B。"""
        hit = self._types.get(idx)
        if hit is not None:
            return hit
        if not 0 <= idx < self.header.type_ids_size:
            raise DexError(
                "BAD_TYPE_IDX", f"type_idx={idx} 超出范围（共 {self.header.type_ids_size} 项）"
            )
        str_idx = struct.unpack_from("<I", self.data, self.header.type_ids_off + idx * 4)[0]
        desc = self.string(str_idx)
        self._types[idx] = desc
        return desc

    # ---------- proto / field / method ----------

    def proto(self, idx: int) -> ProtoRef:
        """proto_ids[idx] -> ProtoRef（参数类型列表在 type_list 里）。"""
        hit = self._protos.get(idx)
        if hit is not None:
            return hit
        if not 0 <= idx < self.header.proto_ids_size:
            raise DexError(
                "BAD_PROTO_IDX", f"proto_idx={idx} 超出范围（共 {self.header.proto_ids_size} 项）"
            )
        off = self.header.proto_ids_off + idx * 12
        shorty_idx, return_type_idx, params_off = struct.unpack_from("<III", self.data, off)
        params = tuple(self.type_desc(t) for t in self.type_list(params_off))
        proto = ProtoRef(
            shorty=self.string(shorty_idx),
            return_type=self.type_desc(return_type_idx),
            params=params,
        )
        self._protos[idx] = proto
        return proto

    def type_list(self, off: int) -> list[int]:
        """type_list：u4 size + u2 items[size]。off=0 表示空表。"""
        if off == 0:
            return []
        self.buf.need(off, 4, "type_list")
        size = struct.unpack_from("<I", self.data, off)[0]
        if size == 0:
            return []
        self.buf.need(off + 4, size * 2, "type_list items")
        return list(struct.unpack_from(f"<{size}H", self.data, off + 4))

    def field(self, idx: int) -> FieldRef:
        """field_ids[idx] -> FieldRef。"""
        hit = self._fields.get(idx)
        if hit is not None:
            return hit
        if not 0 <= idx < self.header.field_ids_size:
            raise DexError(
                "BAD_FIELD_IDX", f"field_idx={idx} 超出范围（共 {self.header.field_ids_size} 项）"
            )
        off = self.header.field_ids_off + idx * 8
        class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.data, off)
        ref = FieldRef(self.type_desc(class_idx), self.type_desc(type_idx), self.string(name_idx))
        self._fields[idx] = ref
        return ref

    def method(self, idx: int) -> MethodRef:
        """method_ids[idx] -> MethodRef。"""
        hit = self._methods.get(idx)
        if hit is not None:
            return hit
        if not 0 <= idx < self.header.method_ids_size:
            raise DexError(
                "BAD_METHOD_IDX", f"method_idx={idx} 超出范围（共 {self.header.method_ids_size} 项）"
            )
        off = self.header.method_ids_off + idx * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, off)
        ref = MethodRef(self.type_desc(class_idx), self.string(name_idx), self.proto(proto_idx))
        self._methods[idx] = ref
        return ref

    # ---------- class_def ----------

    def class_defs(self) -> list[ClassDef]:
        """解析全部 class_def_item（含名字/父类/接口/源文件）。"""
        out: list[ClassDef] = []
        base = self.header.class_defs_off
        for i in range(self.header.class_defs_size):
            off = base + i * 32
            (class_idx, access_flags, superclass_idx, interfaces_off,
             source_file_idx, annotations_off, class_data_off, static_values_off,
             ) = struct.unpack_from("<8I", self.data, off)
            cd = ClassDef(
                class_idx=class_idx,
                access_flags=access_flags,
                superclass_idx=superclass_idx,
                interfaces_off=interfaces_off,
                source_file_idx=source_file_idx,
                annotations_off=annotations_off,
                class_data_off=class_data_off,
                static_values_off=static_values_off,
            )
            cd.name = self.type_desc(class_idx)
            # NO_INDEX = 0xFFFFFFFF 表示「无」
            cd.superclass = "" if superclass_idx == 0xFFFFFFFF else self.type_desc(superclass_idx)
            cd.interfaces = tuple(self.type_desc(t) for t in self.type_list(interfaces_off))
            cd.source_file = "" if source_file_idx == 0xFFFFFFFF else self.string(source_file_idx)
            out.append(cd)
        return out


# ---------- access_flags ----------

# 0x20 在类上叫 SUPER、在方法上叫 SYNCHRONIZED；0x40 在字段上是 VOLATILE、
# 在方法上是 BRIDGE —— 同一个位不同实体含义不同，所以按实体分三张表。
_ACC_CLASS = (
    (0x1, "PUBLIC"), (0x2, "PRIVATE"), (0x4, "PROTECTED"), (0x8, "STATIC"),
    (0x10, "FINAL"), (0x20, "SUPER"), (0x200, "INTERFACE"), (0x400, "ABSTRACT"),
    (0x1000, "SYNTHETIC"), (0x2000, "ANNOTATION"), (0x4000, "ENUM"),
)
_ACC_FIELD = (
    (0x1, "PUBLIC"), (0x2, "PRIVATE"), (0x4, "PROTECTED"), (0x8, "STATIC"),
    (0x10, "FINAL"), (0x40, "VOLATILE"), (0x80, "TRANSIENT"),
    (0x1000, "SYNTHETIC"), (0x4000, "ENUM"),
)
_ACC_METHOD = (
    (0x1, "PUBLIC"), (0x2, "PRIVATE"), (0x4, "PROTECTED"), (0x8, "STATIC"),
    (0x10, "FINAL"), (0x20, "SYNCHRONIZED"), (0x40, "BRIDGE"), (0x80, "VARARGS"),
    (0x100, "NATIVE"), (0x400, "ABSTRACT"), (0x800, "STRICT"),
    (0x1000, "SYNTHETIC"), (0x10000, "CONSTRUCTOR"), (0x20000, "DECLARED_SYNCHRONIZED"),
)
ACC_TABLES = {"class": _ACC_CLASS, "field": _ACC_FIELD, "method": _ACC_METHOD}

ACC_PUBLIC = 0x1
ACC_STATIC = 0x8
ACC_NATIVE = 0x100
ACC_INTERFACE = 0x200
ACC_ABSTRACT = 0x400


def acc_names(flags: int, kind: str = "method") -> list[str]:
    """把 access_flags 拆成名字列表；未知位保留为 0xXX，不丢信息。"""
    table = ACC_TABLES.get(kind, _ACC_METHOD)
    known = 0
    out: list[str] = []
    for bit, name in table:
        if flags & bit:
            out.append(name)
            known |= bit
    rest = flags & ~known
    if rest:
        out.append(f"0x{rest:x}")
    return out


def acc_text(flags: int, kind: str = "method") -> str:
    """形如 "PUBLIC STATIC" 的文本（与 dexdump 的括号内内容一致）。"""
    return " ".join(acc_names(flags, kind))
