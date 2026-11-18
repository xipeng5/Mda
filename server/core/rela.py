"""ELF 重定位表解析（节表 / PT_DYNAMIC 双路径）。

## 为什么需要它（用户实测反馈）

分析加固 so 时，函数经常通过 **vtable / GOT 间接调用**，没有 `bl` 指向它：

```
ldr x8, [x0, #8]      ; 取 vtable[1]
blr x8                ; 间接调用——引用图里没有任何 bl 边
```

这种函数会被函数发现漏掉，`function_at` 还会把多个逻辑函数粘成一个。
用户手写 Python 读 `.rela.dyn` 才找到 `vtable[4] = 0x196424`，
而 mda 没有对外接口。本模块补上这块。

## 两条解析路径（同一套遍历逻辑，避免两份实现漂移）

1. **节表可用**：`.rela.dyn` / `.rela.plt` / `.rel.dyn` / `.rel.plt`
2. **节表被抹的 dump so**：`PT_DYNAMIC` 的 `DT_RELA/DT_RELASZ/DT_RELAENT`、
   `DT_REL/DT_RELSZ`、`DT_JMPREL/DT_PLTRELSZ/DT_PLTREL`
   —— 加固样本只靠这条路径。

两条路径的差异只在「表在文件里的偏移怎么来」和「符号名从哪取」，
逐条解码由同一个 `_walk()` 完成。

## addend 语义（必须分清，否则会把数据地址当函数地址）

| rtype | 名字 | addend 是什么 |
|---|---|---|
| 1027 | R_AARCH64_RELATIVE | **就是目标虚拟地址**（vtable 项的真实值） |
| 1032 | R_AARCH64_IRELATIVE | IFUNC resolver 地址（也是可执行目标） |
| 257  | R_AARCH64_ABS64 | 附加到 **符号值** 上的偏移，不是最终地址 |
| 1025 | R_AARCH64_GLOB_DAT | 同上 |
| 1026 | R_AARCH64_JUMP_SLOT | 通常 0，真值在符号里（导入） |

只有 RELATIVE / IRELATIVE 的 addend 可以直接当"目标地址"用，
条目上用 `addend_is_target` 如实标出，不靠调用方记表。

## 不解析的编码（如实报告，绝不硬猜）

* Android 压缩重定位 `APS2`（`SHT_ANDROID_RELA` / `DT_ANDROID_RELA`）：
  只压缩了 r_info 的流式格式，本模块不硬解——按定长遍历会把压缩流
  当结构体读，产出成批假条目（这是同项目 dyn/jni.py 踩过的坑）。
* `RELR`（`DT_RELR` / `DT_ANDROID_RELR`）：只编码写入地址、不含 addend。

两者都记在 `RelocTable.packed` / `.relr` 与 `warnings` 里，
调用方可以据此解释"为什么 RELATIVE 条目是 0"。
"""
from __future__ import annotations

import struct
from bisect import bisect_right
from dataclasses import dataclass, field

__all__ = [
    "RelocEntry",
    "RelocTable",
    "parse",
    "rela_dump",
    "vtable_at",
    "code_targets",
    "rela_summary",
]

# ---------------------------------------------------------------- ELF 常量
# 只列本模块用得到的；不做 ELF 头全量建模（建模在 elf_model）
PT_LOAD = 1
PT_DYNAMIC = 2
SHT_RELA = 4
SHT_REL = 9
SHT_RELR = 19
SHT_ANDROID_REL = 0x60000001
SHT_ANDROID_RELA = 0x60000002
SHT_ANDROID_RELR = 0x6FFFFF00

DT_NULL = 0
DT_PLTRELSZ = 2
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23
DT_RELRSZ = 35
DT_RELR = 36
DT_RELRENT = 37
DT_ANDROID_REL = 0x6000000F
DT_ANDROID_RELSZ = 0x60000010
DT_ANDROID_RELA = 0x60000011
DT_ANDROID_RELASZ = 0x60000012
DT_ANDROID_RELR = 0x6FFFE000
DT_ANDROID_RELRSZ = 0x6FFFE001
DT_ANDROID_RELRENT = 0x6FFFE003

_APS2_MAGIC = b"APS2"
# 防越界保护：DT_*SZ 被抹成垃圾值时，不能让 range() 跑上千万次
_MAX_ENTRIES = 2_000_000

# models.Section.sec_type 声明为 int，但 elf_model 里直接透传 pyelftools 的
# sh_type ——**已知类型会被 pyelftools 转成字符串**（'SHT_RELA'），未知类型才是
# int（Android 压缩重定位 0x60000002 就是 int）。两边都要认，否则判类型时崩。
_SHT_NAME_TO_INT = {
    "SHT_RELA": SHT_RELA,
    "SHT_REL": SHT_REL,
    "SHT_RELR": SHT_RELR,
    "SHT_ANDROID_REL": SHT_ANDROID_REL,
    "SHT_ANDROID_RELA": SHT_ANDROID_RELA,
    "SHT_ANDROID_RELR": SHT_ANDROID_RELR,
}


def _sht_int(sec_type) -> int:
    """section 类型统一成整数；不认识的字符串返回 -1。"""
    if isinstance(sec_type, int):
        return sec_type
    return _SHT_NAME_TO_INT.get(str(sec_type), -1)

# ---------------------------------------------------------------- 架构相关表
# 架构键 = e_machine（与 models.Arch 的取值一致）
_EM_ARM = 40
_EM_AARCH64 = 183
_EM_X86 = 3
_EM_X86_64 = 62

_PTR_SIZE = {_EM_AARCH64: 8, _EM_X86_64: 8, _EM_ARM: 4, _EM_X86: 4}
_RELATIVE_TYPE = {_EM_AARCH64: 1027, _EM_ARM: 23, _EM_X86_64: 8, _EM_X86: 8}
_IRELATIVE_TYPE = {_EM_AARCH64: 1032, _EM_ARM: 160, _EM_X86_64: 37, _EM_X86: 37}

# 只收录逆向时真会遇到的类型；未收录的按空名处理，不编造 "R_XXX_<数字>"。
_RTYPE_NAMES: dict[int, dict[int, str]] = {
    _EM_AARCH64: {
        0: "R_AARCH64_NONE",
        257: "R_AARCH64_ABS64",
        258: "R_AARCH64_ABS32",
        259: "R_AARCH64_ABS16",
        260: "R_AARCH64_PREL64",
        261: "R_AARCH64_PREL32",
        262: "R_AARCH64_PREL16",
        274: "R_AARCH64_ADR_PREL_LO21",
        275: "R_AARCH64_ADR_PREL_PG_HI21",
        277: "R_AARCH64_ADD_ABS_LO12_NC",
        278: "R_AARCH64_LDST8_ABS_LO12_NC",
        282: "R_AARCH64_JUMP26",
        283: "R_AARCH64_CALL26",
        1025: "R_AARCH64_GLOB_DAT",
        1026: "R_AARCH64_JUMP_SLOT",
        1027: "R_AARCH64_RELATIVE",
        1028: "R_AARCH64_TLS_DTPMOD64",
        1029: "R_AARCH64_TLS_DTPREL64",
        1030: "R_AARCH64_TLS_TPREL64",
        1031: "R_AARCH64_TLSDESC",
        1032: "R_AARCH64_IRELATIVE",
    },
    _EM_ARM: {
        0: "R_ARM_NONE",
        2: "R_ARM_ABS32",
        3: "R_ARM_REL32",
        21: "R_ARM_GLOB_DAT",
        22: "R_ARM_JUMP_SLOT",
        23: "R_ARM_RELATIVE",
        24: "R_ARM_GOTOFF32",
        25: "R_ARM_BASE_PREL",
        26: "R_ARM_GOT_BREL",
        17: "R_ARM_TLS_DTPMOD32",
        18: "R_ARM_TLS_DTPOFF32",
        19: "R_ARM_TLS_TPOFF32",
        160: "R_ARM_IRELATIVE",
    },
    _EM_X86_64: {
        0: "R_X86_64_NONE",
        1: "R_X86_64_64",
        2: "R_X86_64_PC32",
        6: "R_X86_64_GLOB_DAT",
        7: "R_X86_64_JUMP_SLOT",
        8: "R_X86_64_RELATIVE",
        37: "R_X86_64_IRELATIVE",
    },
    _EM_X86: {
        0: "R_386_NONE",
        1: "R_386_32",
        2: "R_386_PC32",
        6: "R_386_GLOB_DAT",
        7: "R_386_JMP_SLOT",
        8: "R_386_RELATIVE",
        37: "R_386_IRELATIVE",
    },
}

# 节表路径的遍历顺序：与 elf_model 历史实现保持一致（先 .plt 后 .dyn），
# 这样 SoFile.relocations 的条目顺序不会因为重构而改变。
_SECTION_ORDER = (".rela.plt", ".rela.dyn", ".rel.plt", ".rel.dyn")


def arch_of(so) -> int:
    """取 so 的 e_machine 整数值（SoFile.arch 是 Arch 枚举，int() 即可）。"""
    try:
        return int(getattr(so, "arch"))
    except Exception:                                     # noqa: BLE001
        return 0


def _ptr_size(arch: int) -> int:
    return _PTR_SIZE.get(arch, 8)


def _rtype_name(arch: int, rtype: int) -> str:
    """rtype → 名字；未收录返回空串（不编造名字）。"""
    return _RTYPE_NAMES.get(arch, {}).get(rtype, "")


# ---------------------------------------------------------------- 数据结构


@dataclass
class RelocEntry:
    """一条重定位。

    offset        r_offset：要写入的位置（GOT 槽 / vtable 槽 / 数据槽）
    rtype         r_info 低位的类型号
    sym_idx       r_info 高位的符号索引（无符号时 0）
    sym_name      符号名；符号表不可用或索引 0 时为空
    addend        见模块头表格；addend_is_target 为真时它才是目标地址
    source        rela.dyn / rela.plt / rel.dyn / rel.plt / dynamic
    sym_resolved  符号表是否可用且索引有效（**不是**"名字非空"）
    addend_implicit  REL（无显式 addend）时 addend 从目标位置读出
    """

    offset: int
    rtype: int
    sym_idx: int = 0
    sym_name: str = ""
    addend: int = 0
    source: str = "dynamic"
    rtype_name: str = ""
    sym_resolved: bool = False
    addend_implicit: bool = False
    addend_is_target: bool = False

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "offset_hex": hex(self.offset),
            "rtype": self.rtype,
            "rtype_name": self.rtype_name,
            "sym_idx": self.sym_idx,
            "sym_name": self.sym_name,
            "sym_resolved": self.sym_resolved,
            "addend": self.addend,
            "addend_hex": hex(self.addend),
            # addend 是否为"可直接使用的目标地址"：只有 RELATIVE/IRELATIVE 是
            "addend_is_target": self.addend_is_target,
            "addend_implicit": self.addend_implicit,
            "source": self.source,
        }


@dataclass
class RelocTable:
    """一张 so 的重定位表（含解析元信息与能力边界）。"""

    entries: list[RelocEntry] = field(default_factory=list)
    path: str = ""                      # sections | dynamic | ""
    error: str = ""                     # 明确失败原因（空串=正常）
    warnings: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)  # source -> 条数
    symtab: str = ""                    # 符号名来源：.dynsym / PT_DYNAMIC / ""
    packed: bool = False                # 存在未解析的 Android APS2 压缩重定位
    relr: bool = False                  # 存在未解析的 RELR
    packed_where: list[str] = field(default_factory=list)  # 压缩表出现在哪
    arch: int = 0
    ptr_size: int = 8
    # 派生的块索引（惰性构建，不参与比较/打印）
    _relative: list[RelocEntry] | None = field(default=None, repr=False, compare=False)
    _blocks: list[list[RelocEntry]] | None = field(default=None, repr=False, compare=False)
    _block_starts: list[int] | None = field(default=None, repr=False, compare=False)

    # ---- 派生视图 ----

    def relative_entries(self) -> list[RelocEntry]:
        """RELATIVE 条目，按 r_offset 升序（vtable 块由它拼出）。

        未知架构（e_machine 不在 ARM/AArch64/x86 内）按 AArch64 的 1027 处理，
        与 SoFile._detect_arch 只认这几种架构的口径一致。
        """
        if self._relative is None:
            rel_type = _RELATIVE_TYPE.get(self.arch, 1027)
            self._relative = sorted(
                (e for e in self.entries if e.rtype == rel_type),
                key=lambda e: e.offset,
            )
        return self._relative

    def blocks(self) -> list[list[RelocEntry]]:
        """把 RELATIVE 条目切成「指针步长连续的块」。

        vtable 在重定位表里的唯一特征就是**连续 8 字节一项**：
        第 i 项 r_offset = 块首 + i*8。中间断一格就是另一块。
        """
        if self._blocks is None:
            step = self.ptr_size or 8
            blocks: list[list[RelocEntry]] = []
            cur: list[RelocEntry] = []
            for e in self.relative_entries():
                if cur and e.offset - cur[-1].offset != step:
                    blocks.append(cur)
                    cur = []
                cur.append(e)
            if cur:
                blocks.append(cur)
            self._blocks = blocks
            self._block_starts = [b[0].offset for b in blocks]
        return self._blocks

    def block_of(self, addr: int) -> tuple[int, int] | None:
        """addr 落在哪个块的第几项。返回 (块下标, 项下标)；不在返回 None。

        只认**块内项地址**（步长对齐的 r_offset），不做区间包含判断——
        vtable 的槽就是重定位的 offset，偏移 4 字节的地址不是任何槽。
        """
        blocks = self.blocks()
        if not blocks:
            return None
        starts = self._block_starts or []
        i = bisect_right(starts, addr) - 1
        if i < 0:
            return None
        block = blocks[i]
        step = self.ptr_size or 8
        delta = addr - block[0].offset
        if delta < 0 or delta % step:
            return None
        idx = delta // step
        if idx >= len(block):
            return None
        return i, idx

    def block_covering(self, addr: int) -> int | None:
        """addr 是否**落在某个块的地址区间内**（不管是否对齐到槽）。

        与 block_of 的分工：block_of 只认槽地址（vtable 项本身），
        本方法回答"这个地址在块的范围里但不在槽上"——例如 vtable 中间
        偏 4 字节的地址，用来给出精确的 not_a_slot 理由。
        """
        blocks = self.blocks()
        if not blocks:
            return None
        starts = self._block_starts or []
        i = bisect_right(starts, addr) - 1
        if i < 0:
            return None
        block = blocks[i]
        step = self.ptr_size or 8
        if block[0].offset <= addr < block[-1].offset + step:
            return i
        return None


# ---------------------------------------------------------------- 底层读取


def _phdrs(raw: bytes) -> list[dict]:
    """按 ELF 头手工读 Program Header（不碰 pyelftools/section API）。

    节表损坏的样本连 pyelftools 的 segment 迭代都可能抛异常，
    所以这里直接读原始字节——这是 PT_DYNAMIC 路径的地基。
    """
    if len(raw) < 0x40 or raw[:4] != b"\x7fELF":
        return []
    is64 = raw[4] == 2
    try:
        if is64:
            e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x36)
        else:
            e_phoff = struct.unpack_from("<I", raw, 0x1C)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x2A)
    except struct.error:
        return []
    size = 56 if is64 else 32
    if e_phentsize < size:
        return []
    out: list[dict] = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + size > len(raw):
            break
        if is64:
            p_type, p_flags = struct.unpack_from("<II", raw, o)
            p_off, p_va, _pa, p_fsz, p_msz, _al = struct.unpack_from("<QQQQQQ", raw, o + 8)
        else:
            p_type, p_off, p_va, _pa, p_fsz, p_msz, p_flags, _al = struct.unpack_from(
                "<IIIIIIII", raw, o)
        out.append({
            "type": p_type, "flags": p_flags, "off": p_off,
            "va": p_va, "filesz": p_fsz, "memsz": p_msz,
        })
    return out


def _loads_of(so, raw: bytes) -> list[tuple[int, int, int, int]]:
    """取 PT_LOAD 列表 [(vaddr, end, file_off, flags)]。

    优先用 SoFile 已解析好的 `_loads`（它已被现有 2200+ 用例验证过）；
    没有时按原始字节自建，保证本模块可独立工作。
    """
    loads = getattr(so, "_loads", None)
    if loads:
        return list(loads)
    out = [
        (p["va"], p["va"] + p["filesz"], p["off"], p["flags"])
        for p in _phdrs(raw) if p["type"] == PT_LOAD and p["filesz"] > 0
    ]
    return sorted(out)


def _v2o(loads, vaddr: int) -> int | None:
    """虚拟地址 → 文件偏移。返回 None 表示不在任何可映射段内。"""
    for va, end, off, _fl in loads:
        if va <= vaddr < end:
            return off + (vaddr - va)
    return None


def _cstr(raw: bytes, off: int, max_len: int) -> str:
    """读一个以 NUL 结尾的字符串；越界返回空串。"""
    if off < 0 or off >= len(raw):
        return ""
    limit = min(len(raw), off + max(0, max_len))
    end = raw.find(b"\0", off, limit)
    if end < 0:
        end = limit
    return raw[off:end].decode("utf-8", "replace")


def _read_symtab(raw: bytes, sym_off: int, count: int, str_off: int,
                 strsz: int, ptr: int) -> list[str]:
    """按索引读符号表的名字，返回与索引对齐的列表。

    索引对齐是关键：调用方用 r_info 高位的 sym_idx 直接下标取名字，
    所以**不能**跳过空名/未定义符号（那会让名字整体错位）。
    """
    out: list[str] = []
    ent = 24 if ptr == 8 else 16
    if sym_off < 0 or count <= 0:
        return out
    for i in range(count):
        o = sym_off + i * ent
        if o + ent > len(raw):
            break
        # Elf32_Sym 与 Elf64_Sym 的 st_name 都在结构体首 4 字节
        st_name = struct.unpack_from("<I", raw, o)[0]
        if st_name == 0 or st_name >= max(1, strsz):
            out.append("")
            continue
        out.append(_cstr(raw, str_off + st_name, strsz - st_name))
    return out


def _dynamic_tags(raw: bytes) -> tuple[dict[int, int], str]:
    """读 PT_DYNAMIC 的 tag→value。返回 (tags, error)。

    32/64 位都要认：Elf64_Dyn 是 16 字节（tag/value 各 8），
    Elf32_Dyn 是 8 字节（各 4）。DT_REL 是 32 位才有的表，
    若这里只按 16 字节读，ARM32 样本的动态段会被整体读错。
    """
    phs = _phdrs(raw)
    if not phs:
        return {}, "不是合法 ELF 或 Program Header 不可读"
    dyn = next((p for p in phs if p["type"] == PT_DYNAMIC), None)
    if dyn is None:
        return {}, "没有 PT_DYNAMIC 段（该 so 不是动态链接产物）"
    dyn_off = dyn["off"]
    dyn_sz = dyn["filesz"]
    is64 = raw[4] == 2
    ent = 16 if is64 else 8
    if dyn_off <= 0 or dyn_sz < ent:
        return {}, "PT_DYNAMIC 段为空（动态段被抹/加密）"
    tags: dict[int, int] = {}
    for i in range(dyn_sz // ent):
        o = dyn_off + i * ent
        if o + ent > len(raw):
            break
        if is64:
            tag, val = struct.unpack_from("<QQ", raw, o)
        else:
            tag, val = struct.unpack_from("<II", raw, o)
        if tag == DT_NULL:
            break
        tags.setdefault(tag, val)
    if not tags:
        return {}, "PT_DYNAMIC 首个标签就是 DT_NULL（动态段被抹/加密）"
    return tags, ""


# ---------------------------------------------------------------- 逐条解码


def _walk(raw: bytes, file_off: int, size: int, ent: int, is_rela: bool,
          ptr: int, source: str, names: list[str] | None, table: RelocTable,
          loads=None) -> None:
    """把一张重定位表逐条解成 RelocEntry（节表 / PT_DYNAMIC 共用）。

    两条路径唯一的差异是入参怎么算出来的，解码只有这一份实现。
    """
    if ent <= 0 or size <= 0:
        return
    n = size // ent
    if n > _MAX_ENTRIES:
        table.error = (
            f"{source} 条目数异常（{n} > {_MAX_ENTRIES}）："
            f"表头 size={size:#x} ent={ent} 不可信，拒绝解析"
        )
        return
    if file_off < 0 or file_off >= len(raw):
        table.error = f"{source} 的文件偏移越界（{file_off:#x}，文件 {len(raw)} 字节）"
        return
    arch = table.arch
    rel_type = _RELATIVE_TYPE.get(arch, 1027)
    irel_type = _IRELATIVE_TYPE.get(arch, 1032)
    added = 0
    for i in range(n):
        o = file_off + i * ent
        if o + ent > len(raw):
            table.warnings.append(
                f"{source} 被文件尾截断：声明 {n} 条，实际只读到 {i} 条"
            )
            break
        if is_rela and ptr == 8:
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", raw, o)
        elif is_rela:
            r_offset, r_info, r_addend = struct.unpack_from("<IIi", raw, o)
        elif ptr == 8:
            r_offset, r_info = struct.unpack_from("<QQ", raw, o)
            r_addend = None
        else:
            r_offset, r_info = struct.unpack_from("<II", raw, o)
            r_addend = None

        if ptr == 8:
            rtype = r_info & 0xFFFFFFFF
            sym_idx = r_info >> 32
        else:
            rtype = r_info & 0xFF
            sym_idx = r_info >> 8

        addend = int(r_addend) if r_addend is not None else 0
        addend_implicit = False
        # REL（无显式 addend）：只有 RELATIVE 的 addend 语义唯一（目标地址），
        # 从目标位置读回来才有意义；其他类型保持 0，不做猜测。
        if r_addend is None and rtype == rel_type and loads:
            fo = _v2o(loads, r_offset)
            # 读不到就保持 addend=0 且 **不**标 implicit——
            # 标了却给 0，调用方会以为"目标地址就是 0"
            if fo is not None and fo + ptr <= len(raw):
                addend = int.from_bytes(raw[fo:fo + ptr], "little", signed=True)
                addend_implicit = True

        sym_name = ""
        sym_resolved = False
        if names is not None and 0 <= sym_idx < len(names):
            sym_name = names[sym_idx]
            sym_resolved = True

        table.entries.append(RelocEntry(
            offset=r_offset,
            rtype=rtype,
            sym_idx=sym_idx,
            sym_name=sym_name,
            addend=addend,
            source=source,
            rtype_name=_rtype_name(arch, rtype),
            sym_resolved=sym_resolved,
            addend_implicit=addend_implicit,
            addend_is_target=rtype in (rel_type, irel_type),
        ))
        added += 1
    if added:
        table.counts[source] = table.counts.get(source, 0) + added


def _walk_vaddr(raw: bytes, loads, vaddr: int, size: int, ent: int,
                is_rela: bool, ptr: int, source: str, names: list[str] | None,
                table: RelocTable, label: str) -> None:
    """PT_DYNAMIC 路径：vaddr+size → 文件偏移后交给 _walk。"""
    if not vaddr or not size:
        return
    fo = _v2o(loads, vaddr)
    if fo is None:
        table.warnings.append(
            f"{label} 地址 {vaddr:#x} 不在任何 PT_LOAD 内，无法换算文件偏移"
        )
        return
    if fo + size > len(raw):
        table.warnings.append(
            f"{label} 声明 {size:#x} 字节但越过文件尾（{fo + size:#x} > {len(raw):#x}），"
            "按可用部分解析"
        )
    _walk(raw, fo, size, ent, is_rela, ptr, source, names, table, loads)


# ---------------------------------------------------------------- 符号名


def _names_from_sections(so, raw: bytes, table: RelocTable) -> list[str] | None:
    """节表路径取符号名：.dynsym + .dynstr。不可用返回 None。"""
    secs = {s.name: s for s in (getattr(so, "sections", None) or [])}
    dynsym = secs.get(".dynsym")
    dynstr = secs.get(".dynstr")
    if dynsym is None or dynstr is None:
        table.warnings.append("无 .dynsym/.dynstr 节：符号名无法恢复（sym_name 留空）")
        return None
    ptr = table.ptr_size
    ent = 24 if ptr == 8 else 16
    count = dynsym.size // ent
    names = _read_symtab(raw, dynsym.offset, count, dynstr.offset, dynstr.size, ptr)
    if names:
        table.symtab = ".dynsym"
    return names


def _names_from_dynamic(raw: bytes, loads, tags: dict[int, int],
                        table: RelocTable, max_sym: int) -> list[str] | None:
    """PT_DYNAMIC 路径取符号名：DT_SYMTAB + DT_STRTAB。

    符号总数优先用 DT_HASH.nchain（精确）；没有 hash 时只解析
    「重定位真实引用到的最大索引」——不猜整张表有多大。
    """
    symtab = tags.get(DT_SYMTAB, 0)
    strtab = tags.get(DT_STRTAB, 0)
    strsz = tags.get(DT_STRSZ, 0)
    if not symtab or not strtab or not strsz:
        table.warnings.append(
            "PT_DYNAMIC 缺 DT_SYMTAB/DT_STRTAB/DT_STRSZ："
            "符号名无法恢复（sym_name 留空，sym_resolved=False）"
        )
        return None
    sym_off = _v2o(loads, symtab)
    str_off = _v2o(loads, strtab)
    if sym_off is None or str_off is None:
        table.warnings.append("DT_SYMTAB/DT_STRTAB 地址不在 PT_LOAD 内：符号名无法恢复")
        return None
    count = 0
    hash_v = tags.get(DT_HASH)
    if hash_v:
        ho = _v2o(loads, hash_v)
        if ho is not None and ho + 8 <= len(raw):
            count = struct.unpack_from("<II", raw, ho)[1]   # nbucket, nchain
    if not count:
        # 无 hash：至少覆盖重定位引用到的索引
        count = max_sym + 1
    count = min(count, _MAX_ENTRIES)
    names = _read_symtab(raw, sym_off, count, str_off, strsz, table.ptr_size)
    if names:
        table.symtab = "PT_DYNAMIC"
    return names


# ---------------------------------------------------------------- 两条路径


def _parse_from_sections(so, raw: bytes, table: RelocTable) -> None:
    """节表路径：按 .rela.plt/.rela.dyn/.rel.plt/.rel.dyn 逐张解。"""
    secs = {s.name: s for s in (getattr(so, "sections", None) or [])}
    if not secs:
        return
    names = _names_from_sections(so, raw, table)
    ptr = table.ptr_size
    # RELR（相对重定位压缩表）：只编码写入地址、不含 addend，本模块不解析。
    # 标记出来才能解释"为什么这个 so 的 RELATIVE 条目明显偏少"。
    for sname, sec in secs.items():
        if _sht_int(sec.sec_type) in (SHT_RELR, SHT_ANDROID_RELR) or "relr" in sname.lower():
            table.relr = True
            table.warnings.append(
                f"{sname} 是 RELR 相对重定位（只编码地址、不含 addend），本工具不解析"
            )
            break
    for name in _SECTION_ORDER:
        sec = secs.get(name)
        if sec is None:
            continue
        sec_type = _sht_int(sec.sec_type)
        # 类型校验：节名对但类型不对（壳样本常见全 NULL / 全 0x75）不可解析
        if sec_type in (SHT_ANDROID_RELA, SHT_ANDROID_REL):
            table.packed = True
            kind = "RELA" if sec_type == SHT_ANDROID_RELA else "REL"
            table.packed_where.append(f"{name}(SHT_ANDROID_{kind})")
            table.warnings.append(
                f"{name} 是 Android APS2 压缩重定位（节类型 {sec_type:#x}），"
                "本工具不解析——该表内的 RELATIVE 条目（vtable 关键）暂不可见"
            )
            continue
        is_rela = sec_type == SHT_RELA
        is_rel = sec_type == SHT_REL
        if not (is_rela or is_rel):
            table.warnings.append(
                f"{name} 节类型 {sec.sec_type!r} 不是 RELA({SHT_RELA})/REL({SHT_REL})，已跳过"
            )
            continue
        # 有些链接器把压缩表标成 PROGBITS/其它类型，靠魔数兜一层
        if raw[sec.offset:sec.offset + 4] == _APS2_MAGIC:
            table.packed = True
            table.packed_where.append(f"{name}(APS2)")
            table.warnings.append(
                f"{name} 内容为 APS2 压缩流（魔数命中），本工具不解析"
            )
            continue
        ent = ptr * (3 if is_rela else 2)
        # source 统一成不带前导点的表名（rela.dyn/rela.plt/rel.dyn/rel.plt），
        # 与 PT_DYNAMIC 路径同名，两条路径的条目才能逐项直接比对
        _walk(raw, sec.offset, sec.size, ent, is_rela, ptr, name.lstrip("."),
              names, table)


def _parse_from_dynamic(raw: bytes, loads, table: RelocTable) -> None:
    """PT_DYNAMIC 路径：节表被抹的 dump so 靠这条。

    先按「没有符号名」解表，再按真实引用到的最大 sym_idx 决定符号表
    读多少条，最后回填名字。这样不必在解码前为了数符号表把整张表
    再解一遍（那是同一段解码逻辑的第二份实现，容易漂移）。
    """
    tags, err = _dynamic_tags(raw)
    if err:
        table.error = f"PT_DYNAMIC 解析失败：{err}"
        return
    ptr = table.ptr_size
    rela_v, rela_sz = tags.get(DT_RELA, 0), tags.get(DT_RELASZ, 0)
    rel_v, rel_sz = tags.get(DT_REL, 0), tags.get(DT_RELSZ, 0)
    jmp_v, jmp_sz = tags.get(DT_JMPREL, 0), tags.get(DT_PLTRELSZ, 0)
    plt_is_rela = tags.get(DT_PLTREL, DT_RELA) != DT_REL
    ent_rela = tags.get(DT_RELAENT, 0) or ptr * 3
    ent_rel = tags.get(DT_RELENT, 0) or ptr * 2

    # 顺序与节表路径一致：先 .plt 后 .dyn
    if jmp_v and jmp_sz:
        if plt_is_rela:
            _walk_vaddr(raw, loads, jmp_v, jmp_sz, ent_rela, True, ptr,
                        "rela.plt", None, table, "DT_JMPREL")
        else:
            _walk_vaddr(raw, loads, jmp_v, jmp_sz, ent_rel, False, ptr,
                        "rel.plt", None, table, "DT_JMPREL")
    elif jmp_v and not jmp_sz:
        table.warnings.append("DT_JMPREL 存在但 DT_PLTRELSZ 为 0：PLT 重定位不可解析")

    if rela_v and rela_sz:
        _walk_vaddr(raw, loads, rela_v, rela_sz, ent_rela, True, ptr,
                    "rela.dyn", None, table, "DT_RELA")
    if rel_v and rel_sz:
        _walk_vaddr(raw, loads, rel_v, rel_sz, ent_rel, False, ptr,
                    "rel.dyn", None, table, "DT_REL")

    # 名字回填：符号表要读多少条由「真实引用到的最大索引」决定
    max_sym = max((e.sym_idx for e in table.entries), default=0)
    names = _names_from_dynamic(raw, loads, tags, table, max_sym)
    if names is not None:
        for e in table.entries:
            if 0 <= e.sym_idx < len(names):
                e.sym_name = names[e.sym_idx]
                e.sym_resolved = True

    # 能力边界如实记录
    if tags.get(DT_ANDROID_RELA) or tags.get(DT_ANDROID_RELASZ):
        table.packed = True
        table.packed_where.append("DT_ANDROID_RELA")
        table.warnings.append(
            "该 so 用 Android 压缩重定位 DT_ANDROID_RELA(APS2)，本工具不解析；"
            "其中的 RELATIVE 条目（vtable 关键）暂不可见"
        )
    if tags.get(DT_ANDROID_REL) or tags.get(DT_ANDROID_RELSZ):
        table.packed = True
        table.packed_where.append("DT_ANDROID_REL")
        table.warnings.append("该 so 用 Android 压缩重定位 DT_ANDROID_REL(APS2)，本工具不解析")
    if any(tags.get(t) for t in (DT_RELR, DT_RELRSZ, DT_ANDROID_RELR, DT_ANDROID_RELRSZ)):
        table.relr = True
        table.warnings.append(
            "该 so 带 RELR 相对重定位（DT_RELR/DT_ANDROID_RELR），"
            "本工具不解析：RELR 只编码写入地址，不含 addend"
        )

    if not table.entries and not table.error:
        table.error = (
            "没有可解析的标准重定位表：DT_RELA/DT_REL/DT_JMPREL 均为空"
            + ("（该 so 用的是 APS2 压缩格式，见 warnings）" if table.packed else "")
        )


def parse(so, path: str = "auto") -> RelocTable:
    """解析一个 so 的重定位表。

    path  "auto"（默认，优先节表）/ "sections" / "dynamic"
          测试与诊断需要强制某条路径时显式指定，便于比对两条路径的一致性。
    """
    if path not in ("auto", "sections", "dynamic"):
        raise ValueError(f"未知 path={path!r}，支持 auto/sections/dynamic")
    arch = arch_of(so)
    table = RelocTable(arch=arch, ptr_size=_ptr_size(arch))
    raw = getattr(so, "_raw", None) or b""
    if not raw:
        table.error = "没有原始字节（so._raw 为空）：无法解析重定位"
        return table
    loads = _loads_of(so, raw)

    sections_usable = bool(getattr(so, "_sections_usable", False))
    if path == "sections" and not sections_usable:
        table.path = "sections"
        table.error = "节表不可用，无法走节表路径"
        return table

    if path in ("auto", "sections") and sections_usable:
        _parse_from_sections(so, raw, table)
        table.path = "sections"
        if table.entries or path == "sections":
            return table
        table.warnings.append("节表路径没找到任何重定位节，改走 PT_DYNAMIC")
        # 节表路径的失败原因（若有）对动态路径的结果不再成立，
        # 降级为 warning 保留现场，但 error 必须清空——
        # 否则"解析成功且有 235 条"的表却对外报 error
        if table.error:
            table.warnings.append(table.error)
            table.error = ""

    if path == "sections":
        table.path = "sections"
        if not table.error:
            table.error = "节表中没有 .rela.dyn/.rela.plt/.rel.dyn/.rel.plt"
        return table

    _parse_from_dynamic(raw, loads, table)
    table.path = "dynamic"
    return table


def _table_of(so) -> RelocTable:
    """取（并复用）so 的重定位表：有 rela_table 属性就是缓存版。"""
    t = getattr(so, "rela_table", None)
    if isinstance(t, RelocTable):
        return t
    return parse(so)


# ---------------------------------------------------------------- 可执行段判定


def _in_regions(regions, addr: int) -> bool:
    return any(va <= addr < end for va, end, *_ in regions)


def _exec_regions(so):
    """可执行段 [(vaddr, end, off, flags)]；SoFile 无该方法时按 PT_LOAD 兜底。"""
    fn = getattr(so, "exec_regions", None)
    if callable(fn):
        return fn()
    raw = getattr(so, "_raw", None) or b""
    return [(va, end, off, fl) for va, end, off, fl in _loads_of(so, raw) if fl & 1]


def _in_image(so, addr: int) -> bool:
    raw = getattr(so, "_raw", None) or b""
    return _in_regions(_loads_of(so, raw), addr)


# ---------------------------------------------------------------- 对外查询


def _entry_dict(e: RelocEntry, execs, loads) -> dict:
    d = e.to_dict()
    # 这三个字段回答"这个 addend 到底是不是代码地址"，
    # 非 RELATIVE 类型（GLOB_DAT/ABS64/JUMP_SLOT）一律 False，避免误喂函数发现
    d["addend_exec"] = bool(e.addend_is_target and _in_regions(execs, e.addend))
    d["addend_in_image"] = bool(e.addend_is_target and _in_regions(loads, e.addend))
    return d


def rela_dump(so, addr_from: int = 0, addr_to: int = 0,
              kind: str = "all", limit: int = 500) -> list[dict]:
    """按 r_offset 范围与类别导出重定位条目。

    addr_from/addr_to  r_offset 区间，左闭右开；两者为 0 表示不限
    kind               all            全部
                       code_target    只要 addend 落在**可执行段**的项
                                      （反喂函数发现的关键入口）
                       relative       只要 RELATIVE / IRELATIVE
                       plt            只要 PLT 表里的项（rela.plt / rel.plt）
    limit              <=0 表示不限制；达到上限即为截断

    解析失败时返回空列表——失败原因从 rela_summary() 取，
    **不返回编造的占位条目**。
    """
    if kind not in ("all", "code_target", "relative", "plt"):
        raise ValueError(
            f"未知 kind={kind!r}，支持 all/code_target/relative/plt"
        )
    table = _table_of(so)
    execs = _exec_regions(so)
    raw = getattr(so, "_raw", None) or b""
    loads = _loads_of(so, raw)
    out: list[dict] = []
    for e in table.entries:
        if addr_from and e.offset < addr_from:
            continue
        if addr_to and e.offset >= addr_to:
            continue
        row = _entry_dict(e, execs, loads)
        # 判据只认 row 里的字段，不在这里另写一份——否则和 _entry_dict 会漂移
        if kind == "code_target" and not row["addend_exec"]:
            continue
        if kind == "relative" and not row["addend_is_target"]:
            continue
        if kind == "plt" and row["source"] not in ("rela.plt", "rel.plt"):
            continue
        out.append(row)
        if limit and limit > 0 and len(out) >= limit:
            break
    return out


# vtable 判定阈值：判据只此一处，vtable_at 与 rela_summary 共用，
# 否则"查询说它是 vtable、汇总说不算"这种自相矛盾迟早出现
_VTABLE_MIN_SLOTS = 2          # 少于两项与孤立指针无法区分
_VTABLE_MIN_EXEC_RATIO = 0.5   # vtable 项是函数指针；数据指针块会被挡掉


def _block_view(so, table: RelocTable, block: list[RelocEntry]) -> dict:
    """一个连续 RELATIVE 块的统计（vtable 判定用）。"""
    execs = _exec_regions(so)
    step = table.ptr_size or 8
    exec_n = sum(1 for e in block if _in_regions(execs, e.addend))
    return {
        "start": block[0].offset,
        "end": block[-1].offset + step,
        "slots": len(block),
        "exec_targets": exec_n,
        "exec_ratio": round(exec_n / len(block), 3),
    }


def _block_verdict(view: dict) -> str:
    """连续 RELATIVE 块 → 判定码：ok / single_slot / no_code_target / mostly_data。"""
    if view["slots"] < _VTABLE_MIN_SLOTS:
        return "single_slot"
    if view["exec_targets"] == 0:
        return "no_code_target"
    if view["exec_ratio"] < _VTABLE_MIN_EXEC_RATIO:
        return "mostly_data"
    return "ok"


def vtable_at(so, addr: int) -> dict:
    """判断 addr 是否落在某个「连续 RELATIVE 重定位块」（vtable）内。

    判定分三层，任一层不过都明确给出理由（reason + detail），不猜：
      1. addr 必须是某条 RELATIVE 的 r_offset（槽地址，按指针宽度对齐）
      2. 该槽所在的连续块至少 2 项（单槽无法与孤立指针区分）
      3. 块内 addend 落在可执行段的比例 >= 0.5（vtable 项是函数指针；
         字符串表/typeinfo 表这类数据指针块会被判为非 vtable）

    返回字段见下方 return；不是 vtable 时同样返回块信息（若已覆盖），
    方便人工判断"是数据块还是我的判据太严"。
    """
    table = _table_of(so)
    execs = _exec_regions(so)
    out: dict = {
        "is_vtable": False,
        "addr": addr,
        "addr_hex": hex(addr),
        "reason": "",
        "detail": "",
        "block_start": 0,
        "block_end": 0,
        "block_slots": 0,
        "index": -1,
        "slot_addr": 0,
        "target": 0,
        "target_hex": "",
        "target_exec": False,
        "target_in_image": False,
        # 命中块后才有意义；先给空值保证返回 schema 稳定（调用方不必判 key）
        "source": "",
        "rtype_name": "",
        "block_exec_targets": 0,
        "block_exec_ratio": 0.0,
        "function": "",
        "function_addr": 0,
        "at_function_entry": False,
        "function_offset": 0,
    }

    if not table.entries:
        out["reason"] = "no_relocations"
        out["detail"] = (
            table.error or "该 so 没有任何可解析的重定位"
        ) + (f"；能力边界：{'；'.join(table.warnings)}" if table.warnings else "")
        return out

    hit = table.block_of(addr)
    if hit is None:
        # 三种"没命中"要分开说，否则调用方无法判断是该改判据还是换地址：
        #   ① 该地址是别的重定位的写入位置（GOT/PLT）→ not_relative
        #   ② 地址落在 vtable 块区间内但不在槽上（步长不对）→ not_a_slot
        #   ③ 完全没有任何 RELATIVE 覆盖 → no_relocation
        non_rel = next((e for e in table.entries if e.offset == addr), None)
        ci = table.block_covering(addr)
        if non_rel is not None:
            out["reason"] = "not_relative"
            out["detail"] = (
                f"该地址是 {non_rel.rtype_name or non_rel.rtype} 重定位的写入位置"
                f"（source={non_rel.source}），不是 RELATIVE 槽，"
                "属于 GOT/PLT 或绝对地址项，不是 vtable 项"
            )
        elif ci is not None:
            block = table.blocks()[ci]
            step = table.ptr_size or 8
            out.update({
                "reason": "not_a_slot",
                "block_start": block[0].offset,
                "block_end": block[-1].offset + step,
                "block_slots": len(block),
                "detail": (
                    f"该地址落在连续块 [{block[0].offset:#x}, "
                    f"{block[-1].offset + step:#x}) 内，但不是 {step} 字节对齐的槽地址"
                    "——vtable 项必须正好是某条重定位的 r_offset"
                ),
            })
        else:
            out["reason"] = "no_relocation"
            out["detail"] = (
                "该地址没有任何 RELATIVE 重定位覆盖：既不是槽地址，也不在连续块内"
            )
            if table.packed:
                out["detail"] += (
                    f"；注意该 so 使用 Android APS2 压缩重定位（{','.join(table.packed_where)}），"
                    "RELATIVE 条目未解析，vtable 可能因此不可见"
                )
            elif table.relative_entries():
                out["detail"] += (
                    f"；该 so 共 {len(table.relative_entries())} 条 RELATIVE，"
                    "但这一地址不落在任何块上（可能是未参与重定位的普通数据）"
                )
        return out

    bi, idx = hit
    block = table.blocks()[bi]
    view = _block_view(so, table, block)
    entry = block[idx]
    out.update({
        "block_start": view["start"],
        "block_end": view["end"],
        "block_slots": view["slots"],
        "index": idx,
        "slot_addr": entry.offset,
        "target": entry.addend,
        "target_hex": hex(entry.addend),
        "target_exec": _in_regions(execs, entry.addend),
        "target_in_image": _in_image(so, entry.addend),
        "source": entry.source,
        "rtype_name": entry.rtype_name,
        "block_exec_targets": view["exec_targets"],
        "block_exec_ratio": view["exec_ratio"],
    })

    # 目标函数名（函数表可能没有这个名字：未命名函数给 sub_ 形式，与
    # SoFile.symbol_name 的约定一致）
    fn = None
    function_at = getattr(so, "function_at", None)
    if callable(function_at) and entry.addend:
        fn = function_at(entry.addend)
    if fn is not None:
        out["function"] = fn.name or f"sub_{fn.addr:x}"
        out["function_addr"] = fn.addr
        out["at_function_entry"] = (fn.addr == entry.addend)
        out["function_offset"] = entry.addend - fn.addr

    verdict = _block_verdict(view)
    if verdict != "ok":
        out["reason"] = verdict
        if verdict == "single_slot":
            out["detail"] = "该地址是孤立的单条 RELATIVE（前后无连续指针槽），无法判定为 vtable"
        elif verdict == "no_code_target":
            out["detail"] = (
                f"连续块 [{view['start']:#x}, {view['end']:#x}) 共 {view['slots']} 项，"
                "但 addend 无一落在可执行段——更像是数据指针数组（字符串表/typeinfo/GOT）"
            )
        else:
            out["detail"] = (
                f"连续块共 {view['slots']} 项，仅 {view['exec_targets']} 项指向可执行段"
                f"（{view['exec_ratio']:.0%} < {_VTABLE_MIN_EXEC_RATIO:.0%}），"
                "不足以判定为 vtable"
            )
        return out

    out["is_vtable"] = True
    out["reason"] = "ok"
    out["detail"] = (
        f"vtable 块 [{view['start']:#x}, {view['end']:#x}) 共 {view['slots']} 项，"
        f"{view['exec_targets']} 项指向可执行段；本项 index={idx} "
        f"-> {entry.addend:#x}"
    )
    return out


def code_targets(so) -> list[int]:
    """所有 addend 落在可执行段的去重地址（供函数发现反喂）。

    只取 addend 语义为"目标地址"的类型（RELATIVE / IRELATIVE）——
    把 ABS64/GLOB_DAT 的 addend 当代码地址会把数据段喂进函数发现。
    """
    table = _table_of(so)
    execs = _exec_regions(so)
    out = {
        e.addend for e in table.entries
        if e.addend_is_target and e.addend and _in_regions(execs, e.addend)
    }
    return sorted(out)


def rela_summary(so) -> dict:
    """重定位解析概况与能力边界（解析失败时这里给原因，不是空列表）。"""
    table = _table_of(so)
    execs = _exec_regions(so)
    rel = table.relative_entries()
    targets = code_targets(so)
    vtables = sum(
        1 for b in table.blocks()
        if _block_verdict(_block_view(so, table, b)) == "ok"
    )
    return {
        "path": table.path,
        "arch": table.arch,
        "ptr_size": table.ptr_size,
        "total": len(table.entries),
        "counts": dict(table.counts),
        "symtab": table.symtab,
        "error": table.error,
        "warnings": list(table.warnings),
        "packed_android": table.packed,
        "packed_where": list(table.packed_where),
        "relr": table.relr,
        "relative": len(rel),
        "relative_exec": sum(1 for e in rel if _in_regions(execs, e.addend)),
        "vtable_blocks": vtables,
        "code_targets": len(targets),
    }
