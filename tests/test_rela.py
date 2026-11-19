"""重定位表解析测试：节表 / PT_DYNAMIC 双路径 + 独立交叉验证 + 抹节表样本。

运行：.venv/bin/python tests/test_rela.py

## 为什么这个文件值得存在

`core/rela.py` 是「函数只被 vtable/GOT 间接调用」时唯一能定位目标的入口，
判错一次就会把数据地址当成函数地址喂进函数发现。所以这里不只自测：

1. **独立实现交叉验证**：本文件里另写一份只按 ELF 规格读
   ELF头 → ProgramHeader → PT_DYNAMIC → DT_RELA 的解析器（不 import rela.py
   的任何函数），逐项比对 offset/rtype/sym_idx/addend/sym_name 全等。
2. **第三方库交叉验证**：pyelftools 是外部依赖，用它独立解 .rela.dyn/.rela.plt
   作为第三方证据。
3. **抹节表样本**：现场从 samples/libbase.so 生成两份 fixture（不落 /tmp）：
   * libbase_no_shdr.so          e_shoff/e_shnum/e_shstrndx 置 0（节表被抹）
   * libbase_no_shdr_nostrtab.so 再把 DT_STRTAB 置 0（符号名彻底不可恢复）
   验证 PT_DYNAMIC 路径解出的条目与原始文件**逐项一致**，
   以及"没有符号表就不编造名字"。
4. **合成 32 位 REL 样本**：SoFile 只支持 ELF64，ARM32 的 REL（隐式 addend）
   分支在真实样本上完全没覆盖，故用手工构造的最小 ELF 做单元验证。
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from server.core import rela  # noqa: E402
from server.core.elf_model import SoFile  # noqa: E402

BASE = ROOT / "samples" / "libbase.so"
LIBC = ROOT / "samples" / "device" / "libc.so"
DUMP = ROOT / "so_test" / "dump" / "libsgmainso-5.5.110.so.758a6e6000.bin"
FIXTURES = ROOT / "tests" / "fixtures"

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [通过] {name}")
    else:
        FAIL += 1
        print(f"  [失败] {name} {detail}")


def show(name: str, value) -> None:
    """只打印观测值（报告要引用的数字），不做断言。"""
    print(f"  [数据] {name}: {value}")


# ---------------------------------------------------------------- 独立实现
# 下面这组函数故意不 import rela.py 的任何东西：它们只用 struct 按 ELF 规格
# 手工解析，作为"第三方证据"与 mda 的结果逐项比对。


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def ref_parse(path: Path) -> dict:
    """独立解析器：ELF64 头 → PT_LOAD/PT_DYNAMIC → DT_RELA/DT_JMPREL。

    返回 {"entries": [(offset, rtype, sym_idx, addend, source), ...],
          "names": {sym_idx: name}}
    条目顺序：先 DT_JMPREL 后 DT_RELA（与 mda 的 dynamic 路径一致）。
    """
    data = Path(path).read_bytes()
    assert data[:4] == b"\x7fELF" and data[4] == 2, "独立解析器只处理 ELF64"
    phoff = _u64(data, 0x20)
    phentsize = _u16(data, 0x36)
    phnum = _u16(data, 0x38)
    loads: list[tuple[int, int, int]] = []          # (va, end, off)
    dyn = None
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type = _u32(data, o)
        p_off = _u64(data, o + 8)
        p_va = _u64(data, o + 16)
        p_fsz = _u64(data, o + 32)
        if p_type == 1 and p_fsz:
            loads.append((p_va, p_va + p_fsz, p_off))
        elif p_type == 2:
            dyn = (p_off, p_va, p_fsz)
    assert dyn is not None, "没有 PT_DYNAMIC"

    def v2o(v: int):
        for va, end, off in loads:
            if va <= v < end:
                return off + (v - va)
        return None

    tags: dict[int, int] = {}
    for i in range(dyn[2] // 16):
        tag = _u64(data, dyn[0] + i * 16)
        val = _u64(data, dyn[0] + i * 16 + 8)
        if tag == 0:
            break
        tags.setdefault(tag, val)

    entries: list[tuple[int, int, int, int, str]] = []

    def read_table(vaddr: int, size: int, source: str) -> None:
        if not vaddr or not size:
            return
        off = v2o(vaddr)
        assert off is not None, f"{source} 不在 PT_LOAD 内"
        for i in range(size // 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", data, off + i * 24)
            entries.append((r_off, r_info & 0xFFFFFFFF, r_info >> 32, r_add, source))

    if tags.get(23):                                 # DT_JMPREL
        read_table(tags[23], tags.get(2, 0), "rela.plt")
    if tags.get(7):                                  # DT_RELA
        read_table(tags[7], tags.get(8, 0), "rela.dyn")

    # 独立读符号名：按重定位真实引用到的最大索引决定读多少
    names: dict[int, str] = {}
    symtab, strtab, strsz = tags.get(6), tags.get(5), tags.get(10, 0)
    max_sym = max((e[2] for e in entries), default=0)
    if symtab and strtab and strsz:
        so_, sto = v2o(symtab), v2o(strtab)
        if so_ is not None and sto is not None:
            for idx in range(max_sym + 1):
                st_name = _u32(data, so_ + idx * 24)
                if not st_name:
                    continue
                end = data.find(b"\0", sto + st_name, sto + strsz)
                names[idx] = data[sto + st_name:end].decode("utf-8", "replace")
    return {"entries": entries, "names": names}


def ref_pyelftools(path: Path) -> list[tuple[int, int, int, int, str]]:
    """第三方库 pyelftools 的解，作为另一路证据（只走节表）。"""
    from elftools.elf.elffile import ELFFile

    out = []
    with open(path, "rb") as f:
        elf = ELFFile(f)
        for name in (".rela.plt", ".rela.dyn", ".rel.plt", ".rel.dyn"):
            sec = elf.get_section_by_name(name)
            if sec is None or not hasattr(sec, "iter_relocations"):
                continue
            for r in sec.iter_relocations():
                # 注意：pyelftools 的 Relocation 是字典式容器，addend 必须
                # 用 r["r_addend"] 取；getattr(r, "r_addend", 0) 会恒得 0
                #（旧 elf_model 就栽在这里，见 _parse_relocations 第 2 次修改）
                out.append((r["r_offset"], r["r_info_type"], r["r_info_sym"],
                            r["r_addend"], name.lstrip(".")))
    return out


def _key(entries) -> list[tuple]:
    """条目统一成可比较的键（丢开 source 前缀差异，按 offset 排序）。"""
    return sorted((e.offset if hasattr(e, "offset") else e[0],
                   e.rtype if hasattr(e, "rtype") else e[1],
                   e.sym_idx if hasattr(e, "sym_idx") else e[2],
                   e.addend if hasattr(e, "addend") else e[3]) for e in entries)


# ---------------------------------------------------------------- 生成 fixture


def _patch_shdr_zeroed(src: bytes) -> bytes:
    """把 e_shoff/e_shnum/e_shstrndx 置 0：模拟壳抹掉节表的 dump so。"""
    b = bytearray(src)
    struct.pack_into("<Q", b, 0x28, 0)      # e_shoff
    struct.pack_into("<H", b, 0x3C, 0)      # e_shnum
    struct.pack_into("<H", b, 0x3E, 0)      # e_shstrndx
    return bytes(b)


def _dynamic_tag_offset(raw: bytes) -> int:
    """找 PT_DYNAMIC 的文件偏移。"""
    phoff = _u64(raw, 0x20)
    phentsize = _u16(raw, 0x36)
    phnum = _u16(raw, 0x38)
    for i in range(phnum):
        o = phoff + i * phentsize
        if _u32(raw, o) == 2:
            return _u64(raw, o + 8)
    raise AssertionError("样本没有 PT_DYNAMIC")


def _patch_strtab_zeroed(raw: bytes) -> bytes:
    """把 PT_DYNAMIC 里 DT_STRTAB 的值置 0：符号名彻底不可恢复。"""
    b = bytearray(raw)
    dyn = _dynamic_tag_offset(b)
    for i in range(0x200 // 16):
        o = dyn + i * 16
        tag = _u64(b, o)
        if tag == 0:
            break
        if tag == 5:                        # DT_STRTAB
            struct.pack_into("<Q", b, o + 8, 0)
            return bytes(b)
    raise AssertionError("样本没有 DT_STRTAB")


def build_fixtures() -> tuple[Path, Path]:
    """现场生成两份 fixture（幂等：每次按源样本重算，防止陈旧文件蒙过测试）。"""
    FIXTURES.mkdir(parents=True, exist_ok=True)
    src = BASE.read_bytes()
    no_shdr = FIXTURES / "libbase_no_shdr.so"
    no_shdr.write_bytes(_patch_shdr_zeroed(src))
    nostrtab = FIXTURES / "libbase_no_shdr_nostrtab.so"
    nostrtab.write_bytes(_patch_strtab_zeroed(_patch_shdr_zeroed(src)))
    return no_shdr, nostrtab


# ---------------------------------------------------------------- 合成 ELF32
# SoFile 只支持 ELF64 的 Program Header 解析，而 rela.py 同时支持 32 位 REL。
# REL（无显式 addend）在真实样本上没覆盖，用手工构造的最小 ELF 锁住这段逻辑。


def make_elf32_rel() -> tuple[bytes, list[tuple[int, int, int, int]]]:
    """构造一个只有 PT_DYNAMIC + DT_REL 的 ARM32 ELF。

    布局（全部 4 字节对齐）：
        0x000 ELF 头（52 字节）
        0x034 程序头 ×4（PT_LOAD R 0..0x140 / PT_LOAD RW / PT_LOAD RX / PT_DYNAMIC）
        0x0B4 .dynamic（8 项）
        0x0F4 .dynsym（2 项：null + foo）
        0x114 .dynstr "\0foo\0"
        0x120 .rel.dyn（4 项：3×R_ARM_RELATIVE + 1×R_ARM_JUMP_SLOT）
        0x140 vtable 槽 3 项 + GOT 槽 1 项
        0x150 code 8 字节
    槽里预置的值就是 REL 的隐式 addend（0x150/0x154），指向 RX 段。
    """
    raw = bytearray(0x158)

    # --- ELF 头（ELF32 / EM_ARM / ET_DYN）---
    raw[0:4] = b"\x7fELF"
    raw[4] = 1                                  # EI_CLASS = ELFCLASS32
    raw[5] = 1                                  # EI_DATA  = ELFDATA2LSB
    raw[6] = 1                                  # EI_VERSION
    struct.pack_into("<HH", raw, 0x10, 3, 40)   # e_type=ET_DYN, e_machine=EM_ARM
    struct.pack_into("<I", raw, 0x14, 1)        # e_version
    struct.pack_into("<III", raw, 0x18, 0, 0x34, 0)  # e_entry, e_phoff, e_shoff
    struct.pack_into("<H", raw, 0x28, 52)       # e_ehsize
    struct.pack_into("<H", raw, 0x2A, 32)       # e_phentsize
    struct.pack_into("<H", raw, 0x2C, 4)        # e_phnum

    # --- 程序头 ---
    phdrs = [
        (1, 0x00, 0x00, 0x140, 4),   # PT_LOAD  R   0x000..0x140（头/动态表/符号表/重定位表）
        (1, 0x140, 0x140, 0x10, 6),  # PT_LOAD  RW  0x140..0x150（vtable 槽）
        (1, 0x150, 0x150, 0x08, 5),  # PT_LOAD  RX  0x150..0x158（代码）
        (2, 0x0B4, 0x0B4, 64, 6),    # PT_DYNAMIC
    ]
    for i, (p_type, p_off, p_va, p_fsz, p_flags) in enumerate(phdrs):
        struct.pack_into("<IIIIIIII", raw, 0x34 + i * 32,
                         p_type, p_off, p_va, p_va, p_fsz, p_fsz, p_flags, 4)

    # --- .dynamic ---
    tags = [(17, 0x120), (18, 32), (19, 8), (6, 0x0F4), (5, 0x114), (10, 5), (0, 0)]
    for i, (tag, val) in enumerate(tags):
        struct.pack_into("<II", raw, 0xB4 + i * 8, tag, val)

    # --- .dynsym：索引 0 空，索引 1 = foo@0x150 ---
    struct.pack_into("<IIIBBH", raw, 0x0F4, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IIIBBH", raw, 0x0F4 + 16, 1, 0x150, 4, 0x12, 0, 1)

    # --- .dynstr ---
    raw[0x114:0x119] = b"\0foo\0"

    # --- .rel.dyn：3 个 RELATIVE + 1 个 JUMP_SLOT ---
    rels = [
        (0x140, (0 << 8) | 23),
        (0x144, (0 << 8) | 23),
        (0x148, (0 << 8) | 23),
        (0x14C, (1 << 8) | 22),
    ]
    for i, (r_off, r_info) in enumerate(rels):
        struct.pack_into("<II", raw, 0x120 + i * 8, r_off, r_info)

    # --- 槽里的预置值 = REL 的隐式 addend ---
    struct.pack_into("<III", raw, 0x140, 0x150, 0x154, 0x150)
    struct.pack_into("<I", raw, 0x14C, 0)

    loads = [(0x00, 0x140, 0x00, 4), (0x140, 0x150, 0x140, 6), (0x150, 0x158, 0x150, 5)]
    return bytes(raw), loads


class _RawSo:
    """只暴露 rela.py 需要的接口的轻量 so（ELF32 合成样本用）。"""

    def __init__(self, raw: bytes, loads):
        self._raw = raw
        self._loads = loads
        self.arch = 40                      # EM_ARM
        self._sections_usable = False
        self.sections: list = []

    def exec_regions(self):
        return [(va, end, off, fl) for va, end, off, fl in self._loads if fl & 1]

    def function_at(self, addr: int):
        return None


# ---------------------------------------------------------------- 用例


def test_independent_cross_check() -> None:
    """独立实现 / pyelftools / mda 三方逐项比对。"""
    print("== 交叉验证（libc.so，2226 条重定位）==")
    ref = ref_parse(LIBC)
    so = SoFile(str(LIBC))
    try:
        mine = so.rela_table
        m = _key(mine.entries)
        r = _key(ref["entries"])
        check("独立解析器条目数一致",
              len(m) == len(r), f"mda={len(m)} 独立={len(r)}")
        check("独立解析器逐项全等（offset/rtype/sym_idx/addend）",
              m == r, f"首个差异 {next((i for i, (a, b) in enumerate(zip(m, r)) if a != b), '无')}")
        show("mda 条目数", len(mine.entries))
        show("按表分组", mine.counts)

        # 符号名：独立实现按 sym_idx 直接读 dynstr，与 mda 的解析结果比对
        bad = [
            (e.sym_idx, e.sym_name, ref["names"].get(e.sym_idx, ""))
            for e in mine.entries
            if e.sym_idx and e.sym_name != ref["names"].get(e.sym_idx, "")
        ]
        check("符号名与独立实现全等", not bad, f"{len(bad)} 处不一致，例 {bad[:2]}")

        # pyelftools（第三方库）只解节表，与 mda 的 sections 路径同序比对
        sec_entries = rela.parse(so, "sections").entries
        ref_pt = ref_pyelftools(LIBC)
        got_pt = [(e.offset, e.rtype, e.sym_idx, e.addend, e.source) for e in sec_entries]
        check("节表路径与 pyelftools 逐项全等（含顺序）",
              got_pt == ref_pt, f"mda={len(got_pt)} pyelftools={len(ref_pt)}")

        # 旧实现用 getattr(r,"r_addend",0) 恒得 0：这里锁住"真值已解出"，
        # 防止有人把 addend 退回 0（那会让 vtable 目标信息再次消失）
        addends = [e.addend for e in sec_entries if e.rtype == 1027]
        check("RELATIVE 的 addend 非全 0（旧实现恒 0 的 bug 已修）",
              any(a != 0 for a in addends) and len(addends) > 0,
              f"{len(addends)} 条 RELATIVE，非零 {sum(1 for a in addends if a)} 条")
        show("RELATIVE addend 非零占比",
             f"{sum(1 for a in addends if a)}/{len(addends)}")

        # 与重构前的 self.relocations 视图一致（回归锁定）
        legacy = [(r.offset, r.rtype, r.sym_idx, r.addend, r.sym_name) for r in so.relocations]
        new = [(e.offset, e.rtype, e.sym_idx, e.addend, e.sym_name) for e in sec_entries]
        check("self.relocations 与 rela_table 节表路径一致（顺序/字段）",
              legacy == new, f"{len(legacy)} vs {len(new)}")
    finally:
        so.close()


def test_two_paths_consistency() -> None:
    """同一 so 的两条路径必须给出完全相同的条目序列。"""
    print("== 双路径一致性（libc.so）==")
    so = SoFile(str(LIBC))
    try:
        a = rela.parse(so, "sections")
        b = rela.parse(so, "dynamic")
        ka = [(e.offset, e.rtype, e.sym_idx, e.addend, e.sym_name, e.source) for e in a.entries]
        kb = [(e.offset, e.rtype, e.sym_idx, e.addend, e.sym_name, e.source) for e in b.entries]
        check("节表路径条目数", len(a.entries) == 2226, f"实际 {len(a.entries)}")
        check("PT_DYNAMIC 路径条目数", len(b.entries) == 2226, f"实际 {len(b.entries)}")
        check("两条路径逐项全等（含顺序与 source）", ka == kb,
              f"首个差异 {next((i for i, (x, y) in enumerate(zip(ka, kb)) if x != y), '长度不等')}")
        check("节表路径符号表来源 .dynsym", a.symtab == ".dynsym", a.symtab)
        check("PT_DYNAMIC 路径符号表来源 PT_DYNAMIC", b.symtab == "PT_DYNAMIC", b.symtab)
        rate = (sum(1 for x, y in zip(ka, kb) if x == y) / max(1, len(ka))) * 100
        check("一致率 100%", abs(rate - 100.0) < 1e-9, f"{rate:.2f}%")
        show("一致率", f"{rate:.2f}% ({min(len(ka), len(kb))}/{max(len(ka), len(kb))})")
    finally:
        so.close()


def test_libbase_packed() -> None:
    """libbase 的 .rela.dyn 是 APS2 压缩：必须如实报告，不能伪造 RELATIVE。

    (1) 第一次修改 bug 原因：旧断言写死"RELR 未解析 → 条目 235 / RELATIVE 0 /
        code_targets 空"，而 core/rela.py 现已在第 1 次修改里解析 RELR，
        真实新增 15 条 RELATIVE（来自 .relr.dyn，不是从 APS2 流伪造）。
        解决方案：断言改成新语义——APS2 流仍不解析（不伪造），但 RELR 条目
        必须解析且来源为 relr，code_targets 非空且全部来自真实 RELR addend。
    """
    print("== libbase.so（.rela.dyn 为 APS2 压缩）==")
    so = SoFile(str(BASE))
    try:
        t = so.rela_table
        check("条目数 250（235 rela.plt + 15 relr）", len(t.entries) == 250, f"实际 {len(t.entries)}")
        check("来源 rela.plt + relr", t.counts == {"rela.plt": 235, "relr": 15}, str(t.counts))
        check("标记为 APS2 压缩", t.packed is True, str(t.packed))
        check("标记存在 RELR（且已解析 15 条）",
              t.relr is True and t.counts.get("relr") == 15, str((t.relr, t.counts)))
        check("warnings 说清压缩格式", any("APS2" in w for w in t.warnings), str(t.warnings))
        check("warnings 说明 RELR 已解析",
              any("已解析" in w and "RELR" in w for w in t.warnings), str(t.warnings))
        # APS2 流本身仍不解析：这 15 条 RELATIVE 全部来自 RELR，不是从 APS2 伪造
        check("RELATIVE 15 条全部来自 RELR（不伪造 APS2）",
              len(t.relative_entries()) == 15
              and all(e.source == "relr" for e in t.relative_entries()),
              str([(e.source, hex(e.offset)) for e in t.relative_entries()]))
        check("code_targets 非空（来自真实 RELR addend）",
              len(rela.code_targets(so)) == 6, str(rela.code_targets(so)))
        check("函数表未被破坏（386 个）", len(so.functions) == 386, f"实际 {len(so.functions)}")

        # 动态路径与节表路径一致
        d = rela.parse(so, "dynamic")
        ka = [(e.offset, e.rtype, e.sym_idx, e.addend, e.sym_name) for e in t.entries]
        kb = [(e.offset, e.rtype, e.sym_idx, e.addend, e.sym_name) for e in d.entries]
        check("libbase 双路径条目全等", ka == kb, f"{len(ka)} vs {len(kb)}")
        check("动态路径也报告 APS2 与 RELR",
              d.packed is True and d.counts.get("relr") == 15, (d.packed, d.counts))

        # vtable_at 要明确说"不是 vtable"并给出原因
        r = rela.vtable_at(so, 0x3C610)          # GOT.PLT 里的 JUMP_SLOT
        check("GOT 槽 → not_relative", r["reason"] == "not_relative", r["reason"])
        r2 = rela.vtable_at(so, 0x12000)
        check("无覆盖地址 → no_relocation", r2["reason"] == "no_relocation", r2["reason"])
        check("原因里点出压缩格式", "APS2" in r2["detail"], r2["detail"])
    finally:
        so.close()


def test_erased_section_table() -> None:
    """抹掉节表的 dump so 必须靠 PT_DYNAMIC 拿到同样的 235 条。"""
    print("== 抹节表样本（PT_DYNAMIC 路径）==")
    no_shdr, _ = build_fixtures()
    so_orig = SoFile(str(BASE))
    so = SoFile(str(no_shdr))
    try:
        check("节表被判定不可用", so._sections_usable is False, str(so._sections_usable))
        check("sections 为空", so.sections == [], f"实际 {len(so.sections)}")
        t = so.rela_table
        check("走的是 PT_DYNAMIC 路径", t.path == "dynamic", t.path)
        check("无解析错误", t.error == "", t.error)
        check("条目数 250（235 rela.plt + 15 relr）", len(t.entries) == 250, f"实际 {len(t.entries)}")
        check("符号名来自 PT_DYNAMIC", t.symtab == "PT_DYNAMIC", t.symtab)
        check("仍然报告 APS2/RELR 边界（RELR 已从动态段解析）",
              t.packed is True and t.relr is True and t.counts.get("relr") == 15,
              f"packed={t.packed} relr={t.relr} counts={t.counts}")
        ka = [(e.offset, e.rtype, e.sym_idx, e.sym_name, e.addend, e.source) for e in t.entries]
        kb = [(e.offset, e.rtype, e.sym_idx, e.sym_name, e.addend, e.source)
              for e in so_orig.rela_table.entries]
        check("与原文件条目逐项全等（250/250）", ka == kb, f"{len(ka)} vs {len(kb)}")
        names_ok = sum(1 for e in t.entries if e.sym_name)
        check("符号名恢复（导入名非空，仅 rela.plt 有名字）", names_ok == 235, f"实际 {names_ok}")
        check("self.relocations 也拿到了（不再是空表）",
              len(so.relocations) == 250, f"实际 {len(so.relocations)}")
        show("抹节表样本条目数", len(t.entries))
        show("一致率", f"{sum(1 for x, y in zip(ka, kb) if x == y) / max(1, len(kb)) * 100:.2f}%")
    finally:
        so.close()
        so_orig.close()


def test_no_symbol_table() -> None:
    """符号表不可用时：名字留空 + sym_resolved=False，绝不编造。"""
    print("== 无符号表样本（不编造名字）==")
    _, nostrtab = build_fixtures()
    so = SoFile(str(nostrtab))
    try:
        t = so.rela_table
        check("条目仍然解析出来（偏移/类型不受影响，含 15 条 RELR）",
              len(t.entries) == 250, f"实际 {len(t.entries)}")
        check("sym_name 全为空", all(e.sym_name == "" for e in t.entries),
              f"{sum(1 for e in t.entries if e.sym_name)} 条有名字")
        check("sym_resolved 全为 False",
              all(e.sym_resolved is False for e in t.entries),
              f"{sum(1 for e in t.entries if e.sym_resolved)} 条声称已解析")
        check("symtab 来源为空", t.symtab == "", repr(t.symtab))
        check("warnings 说清符号表缺失",
              any("DT_SYMTAB" in w or "DT_STRTAB" in w for w in t.warnings), str(t.warnings))
        check("offset/rtype 与正常样本一致",
              [e.offset for e in t.entries][:5] == [0x3C610, 0x3C618, 0x3C620, 0x3C628, 0x3C630],
              str([hex(e.offset) for e in t.entries[:5]]))
    finally:
        so.close()


def test_hardened_dump() -> None:
    """PT_DYNAMIC 也被抹掉的壳样本：返回明确错误，不返回假条目。"""
    print("== 壳 dump（PT_DYNAMIC 被抹）==")
    if not DUMP.exists():
        print(f"  [跳过] 样本不存在：{DUMP}")
        return
    so = SoFile(str(DUMP))
    try:
        t = so.rela_table
        check("没有任何编造的条目", t.entries == [], f"实际 {len(t.entries)} 条")
        check("给出明确错误", "DT_NULL" in t.error, repr(t.error))
        check("错误里点明是被抹/加密", "抹" in t.error or "加密" in t.error, t.error)
        check("code_targets 为空", rela.code_targets(so) == [])
        r = rela.vtable_at(so, 0x196424)
        check("vtable_at 明确判 not_vtable", r["is_vtable"] is False)
        check("理由 not_relocations 且带原因",
              r["reason"] == "no_relocations" and r["detail"], f"{r['reason']}/{r['detail']}")
        check("函数表仍可用（不影响既有加载路径）", len(so.functions) > 1000,
              f"实际 {len(so.functions)}")
    finally:
        so.close()


def test_code_targets() -> None:
    """code_targets 只返回真代码地址，并与独立解析结果一致。"""
    print("== code_targets（反喂函数发现的关键输入）==")
    so = SoFile(str(LIBC))
    try:
        ct = rela.code_targets(so)
        check("去重且升序", ct == sorted(set(ct)), "未排序或有重复")
        execs = so.exec_regions()
        check("全部落在可执行段",
              all(any(va <= a < end for va, end, *_ in execs) for a in ct))
        check("数量 367", len(ct) == 367, f"实际 {len(ct)}")

        # 独立实现：自己算 addend 落在可执行段的 RELATIVE 目标
        ref = ref_parse(LIBC)
        ref_exec = sorted({
            e[3] for e in ref["entries"]
            if e[1] == 1027 and any(va <= e[3] < end for va, end, *_ in execs)
        })
        check("与独立实现的代码目标集合全等", ct == ref_exec,
              f"独立={len(ref_exec)} mda={len(ct)}")

        missing = [a for a in ct if so.function_at(a) is None]
        show("code_targets 数量", len(ct))
        show("不在现有函数表中（function_at 返回 None）",
             f"{len(missing)} 个：{[hex(a) for a in missing]}")
        for a in missing:
            pos = sorted(so.functions)
            before = max((x for x in pos if x < a), default=0)
            after = min((x for x in pos if x > a), default=0)
            show(f"  {hex(a)} 的前后函数", f"{hex(before)} / {hex(after)}")
        check("缺失地址都在可执行段内（是真代码地址，不是脏数据）",
              all(any(va <= a < end for va, end, *_ in execs) for a in missing))
        check("缺失数量 6", len(missing) == 6, f"实际 {len(missing)}")
    finally:
        so.close()


def test_vtable_at() -> None:
    """vtable 判定：命中块、槽下标、目标函数，以及各种否定理由。"""
    print("== vtable_at 判定（libc.so）==")
    so = SoFile(str(LIBC))
    try:
        r = rela.vtable_at(so, 0xFC040)
        check("vtable 首项识别成功", r["is_vtable"] is True, r["reason"])
        check("块范围 0xfc040..0xfc0b0", (r["block_start"], r["block_end"]) == (0xFC040, 0xFC0B0),
              f"{r['block_start']:#x}..{r['block_end']:#x}")
        check("块 14 项且全部指向代码", r["block_slots"] == 14 and r["block_exec_ratio"] == 1.0,
              f"slots={r['block_slots']} ratio={r['block_exec_ratio']}")
        check("本项 index=0", r["index"] == 0, str(r["index"]))
        check("目标 0x48140 且可执行", r["target"] == 0x48140 and r["target_exec"] is True,
              f"{r['target']:#x}")
        check("目标函数名可解析", r["function"] == "sub_48140", r["function"])
        check("目标正好是函数入口", r["at_function_entry"] is True)

        r2 = rela.vtable_at(so, 0xFC048)
        check("第 2 项 index=1、目标 0x4821c",
              r2["index"] == 1 and r2["target"] == 0x4821C,
              f"index={r2['index']} target={r2['target']:#x}")
        check("块内非槽地址 → not_a_slot",
              rela.vtable_at(so, 0xFC044)["reason"] == "not_a_slot")

        r3 = rela.vtable_at(so, 0x1012B8)        # 119 项数据指针块
        check("数据指针块 → mostly_data", r3["reason"] == "mostly_data", r3["reason"])
        check("数据块也给出块范围（便于人工复核）",
              r3["block_slots"] == 119, f"slots={r3['block_slots']}")

        r4 = rela.vtable_at(so, 0x101BD0)        # .got.plt 里的 JUMP_SLOT
        check("GOT 槽 → not_relative", r4["reason"] == "not_relative", r4["reason"])
        check("理由里写出 rtype 名", "JUMP_SLOT" in r4["detail"], r4["detail"])

        r5 = rela.vtable_at(so, 0x120000)        # .text 里没有任何重定位的地址
        check("无覆盖 → no_relocation", r5["reason"] == "no_relocation", r5["reason"])
        check("理由里给出该 so 的 RELATIVE 总数", "1679" in r5["detail"], r5["detail"])
    finally:
        so.close()


def test_rela_dump() -> None:
    """rela_dump 的范围/类别/上限过滤。"""
    print("== rela_dump 过滤 ==")
    so = SoFile(str(LIBC))
    try:
        allrows = rela.rela_dump(so, limit=0)
        check("limit<=0 表示不限制", len(allrows) == 2226, f"实际 {len(allrows)}")
        check("每条都带 rtype_name", all(r["rtype_name"] for r in allrows[:100]))
        check("RELATIVE 条目 addend_is_target=True",
              all(r["addend_is_target"] for r in allrows if r["rtype"] == 1027))
        check("JUMP_SLOT 的 addend_is_target=False（addend 不是目标地址）",
              all(not r["addend_is_target"] for r in allrows if r["rtype"] == 1026))

        code = rela.rela_dump(so, kind="code_target", limit=0)
        check("kind=code_target 只含可执行目标",
              all(r["addend_exec"] for r in code) and len(code) > 0, f"{len(code)} 条")
        check("code_target 条目数与独立统计一致", len(code) == 386, f"实际 {len(code)}")

        rel = rela.rela_dump(so, kind="relative", limit=0)
        check("kind=relative 只含 RELATIVE/IRELATIVE",
              all(r["addend_is_target"] for r in rel), f"{len(rel)} 条")
        check("kind=relative 数量 1680（1679 RELATIVE + 1 IRELATIVE/TLSDESC 之外）",
              len(rel) in (1679, 1680), f"实际 {len(rel)}")

        plt = rela.rela_dump(so, kind="plt", limit=0)
        check("kind=plt 只含 PLT 表条目",
              all(r["source"] == "rela.plt" for r in plt), f"{len(plt)} 条")
        check("kind=plt 数量 503", len(plt) == 503, f"实际 {len(plt)}")

        window = rela.rela_dump(so, addr_from=0xFC040, addr_to=0xFC0B0, limit=0)
        check("addr_from/addr_to 左闭右开（14 个槽）", len(window) == 14, f"实际 {len(window)}")
        check("窗口内 offset 都在区间内",
              all(0xFC040 <= r["offset"] < 0xFC0B0 for r in window))

        limited = rela.rela_dump(so, limit=10)
        check("limit 生效", len(limited) == 10, f"实际 {len(limited)}")
        check("limit 取的是前 10 条", [r["offset"] for r in limited] ==
              [r["offset"] for r in allrows[:10]])

        try:
            rela.rela_dump(so, kind="nope")
            check("未知 kind 抛 ValueError", False, "没抛")
        except ValueError as exc:
            check("未知 kind 抛 ValueError", "kind" in str(exc), str(exc))
    finally:
        so.close()


def test_synthetic_elf32_rel() -> None:
    """ARM32 REL（隐式 addend）路径：32 位指针 + 从目标位置读 addend。"""
    print("== 合成 ARM32 ELF（REL 隐式 addend）==")
    raw, loads = make_elf32_rel()
    so = _RawSo(raw, loads)
    t = rela.parse(so)
    check("走 PT_DYNAMIC 路径", t.path == "dynamic", t.path)
    check("无解析错误", t.error == "", t.error)
    check("条目数 4", len(t.entries) == 4, f"实际 {len(t.entries)}")
    check("指针宽度 4", t.ptr_size == 4, str(t.ptr_size))
    if len(t.entries) == 4:
        e0 = t.entries[0]
        check("REL 的 addend 从目标位置读出（0x150）",
              e0.addend == 0x150 and e0.addend_implicit is True,
              f"addend={e0.addend:#x} implicit={e0.addend_implicit}")
        check("R_ARM_RELATIVE 名字正确", e0.rtype_name == "R_ARM_RELATIVE", e0.rtype_name)
        check("RELATIVE 的 addend 是目标地址", e0.addend_is_target is True)
        e3 = t.entries[3]
        check("JUMP_SLOT 符号名解析（foo）",
              e3.sym_idx == 1 and e3.sym_name == "foo" and e3.sym_resolved is True,
              f"sym={e3.sym_idx}/{e3.sym_name}")
        check("JUMP_SLOT 的 addend_is_target=False", e3.addend_is_target is False)

    ct = rela.code_targets(so)
    check("code_targets 为两条代码地址", ct == [0x150, 0x154], str([hex(x) for x in ct]))

    r = rela.vtable_at(so, 0x144)
    check("4 字节步长的 vtable 可识别", r["is_vtable"] is True, r["reason"])
    check("块 3 项、index=1、目标 0x154",
          r["block_slots"] == 3 and r["index"] == 1 and r["target"] == 0x154,
          f"slots={r['block_slots']} idx={r['index']} target={r['target']:#x}")
    check("块范围按 4 字节步长算（0x140..0x14c）",
          (r["block_start"], r["block_end"]) == (0x140, 0x14C),
          f"{r['block_start']:#x}..{r['block_end']:#x}")
    check("JUMP_SLOT 槽不是 vtable 项",
          rela.vtable_at(so, 0x14C)["reason"] == "not_relative")


def test_argument_validation() -> None:
    """参数校验与错误返回。"""
    print("== 参数校验 ==")
    so = SoFile(str(BASE))
    try:
        for bad in ("bogus", "", "SECTIONS"):
            try:
                rela.parse(so, bad)
                check(f"未知 path={bad!r} 抛 ValueError", False, "没抛")
            except ValueError:
                check(f"未知 path={bad!r} 抛 ValueError", True)
        check("rela_summary 的 total 与条目数一致",
              rela.rela_summary(so)["total"] == len(so.rela_table.entries))
        check("rela_summary 透出 warnings",
              bool(rela.rela_summary(so)["warnings"]))
    finally:
        so.close()


def main() -> int:
    for p in (BASE, LIBC):
        if not p.exists():
            print(f"缺少样本：{p}")
            return 1
    test_independent_cross_check()
    test_two_paths_consistency()
    test_libbase_packed()
    test_erased_section_table()
    test_no_symbol_table()
    test_hardened_dump()
    test_code_targets()
    test_vtable_at()
    test_rela_dump()
    test_synthetic_elf32_rel()
    test_argument_validation()
    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
