"""ELF 文件封装。

职责：把 ELF 结构（section / symbol / relocation / FDE）解析成 models.py 的数据类型，
并提供 vma -> 字节 的统一读取接口。

不依赖 capstone，可独立测试。
"""
from __future__ import annotations

import bisect

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.callframe import CallFrameInfo
from elftools.dwarf.structs import DWARFStructs

from server.core import rela as rela_parser
from server.models import Arch, Function, Relocation, Section, Symbol, SymbolKind

import io
import struct


def is_arm64_plt_stub(insns) -> bool:
    """ARM64 标准 PLT 桩判定：adrp x16 / ldr x17 / add x16 / br x17。

    (2) 第二次修改
    bug 原因：该 4 条指令模板此前在 core/discover.py:is_plt_stub() 与
    core/elf_model.py:_scan_plt_stubs_by_segment() 各写一份，两处判据一旦
    漂移就会出现"发现阶段排除、扫描阶段漏判"的隐性不一致。
    解决方案：抽成唯一实现，两处共用（判据只有一处可改）。
    """
    if len(insns) != 4:
        return False
    a, b, c, d = insns
    return (
        a.mnemonic == "adrp" and a.op_str.startswith("x16")
        and b.mnemonic == "ldr" and b.op_str.startswith("x17")
        and c.mnemonic == "add" and c.op_str.startswith("x16")
        and d.mnemonic == "br" and d.op_str.strip() == "x17"
    )


class SoFile:
    """单个 .so 文件的封装。一个实例对应一个已加载的 so。"""

    def __init__(self, path: str):
        self.path = path
        # 短名用于展示，如 "liblog.so"
        self.name = path.rsplit("/", 1)[-1]
        self._stream = open(path, "rb")
        self._elf = ELFFile(self._stream)
        self._cache: dict[int, bytes] = {}
        self._sections: list[Section] = []
        self._func_ranges: list[tuple[int, int]] = []  # 供地址反查，需排序
        self._starts: list[int] = []  # 函数起点升序（function_at 二分查找用）
        # 段表兜底：PT_LOAD 列表 [(vaddr, end, file_off, flags)]，
        # 节表损坏的 dump so 靠它完成 vma↔文件换算与代码发现
        self._loads: list[tuple[int, int, int, int]] = []
        self._raw: bytes | None = None
        self._is64: bool = True
        self._sections_usable = False  # 节表损坏时 False，全部 get_section_by_name 短路
        self.section_warning: str = ""  # 节表无效时的诊断信息（GUI/日志展示）
        # (1) 第一次修改：段表模式扫描到的 PLT 桩地址集合（不伪造符号名）
        self.plt_stubs: set[int] = set()
        # (2) 第二次修改：桩地址排序缓存，供 in_plt_stub 二分查找
        self._stub_sorted: list[int] = []
        # 重定位表惰性缓存（core/rela.py 的解析结果，含 PT_DYNAMIC 路径）
        self._rela_table: rela_parser.RelocTable | None = None
        self._parse()

    # ---------- 解析 ----------

    def _parse(self) -> None:
        e = self._elf
        self.arch = self._detect_arch()
        self.is_pie = e["e_type"] == "ET_DYN"
        self.entry = e["e_entry"]

        # 第一步：先取 PT_LOAD（永远可信）。节表若坏，这是唯一的事实来源。
        self._parse_loads()

        # 第二步：尝试按节表解析。壳处理的 so 常把 e_shoff 抹成非法值，
        # pyelftools 迭代 section 时会抛 ELFParseError —— 捕获后走纯段表模式。
        sections_ok = self._parse_sections()
        if not sections_ok:
            # 节表不可用：从 PT_DYNAMIC 手工解析 dynsym/dynstr（符号与导入的事实来源）
            self._parse_dynamic_fallback()

        self._parse_symbols()
        self._parse_relocations()
        self._parse_plt()
        self._scan_plt_stubs_by_segment()
        self._parse_functions()

    def _iter_phdrs(self) -> list[tuple[int, int, int, int, int, int]]:
        """按 EI_CLASS 手工解析 Program Header，返回 [(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)]。"""
        raw = self._raw
        if raw is None:
            self._stream.seek(0)
            raw = self._stream.read()
            self._raw = raw
        if len(raw) < 0x34 or raw[:4] != b"\x7fELF":
            raise ValueError("非 ELF 文件")
        ei_class = raw[4]
        if ei_class == 2:
            if len(raw) < 0x40:
                raise ValueError("非 ELF 文件")
            self._is64 = True
            e_phoff, = struct.unpack_from("<Q", raw, 0x20)
            e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x36)
            min_ent = 56
        elif ei_class == 1:
            self._is64 = False
            e_phoff, = struct.unpack_from("<I", raw, 0x1C)
            e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x2A)
            min_ent = 32
        else:
            raise ValueError(f"不支持的 ELF 类别: EI_CLASS={ei_class}")
        if e_phentsize < min_ent:
            return []
        out: list[tuple[int, int, int, int, int, int]] = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + min_ent > len(raw):
                break
            if self._is64:
                p_type, p_flags = struct.unpack_from("<II", raw, off)
                p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", raw, off + 8)
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags = struct.unpack_from(
                    "<IIIIIII", raw, off
                )
            out.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        return out

    def _v2o(self, v: int) -> int | None:
        """根据 PT_LOAD 将虚拟地址换算为文件偏移，不在段内返回 None。"""
        for va, end, off, _fl in self._loads:
            if va <= v < end:
                return off + (v - va)
        return None

    # (2) 第二次修改（2026-11-26）
    # bug 原因：此前固定按 ELF64 偏移与 56 字节 Program Header 解包，加载 ELF32（如 ARM32）
    #           时会把程序头读错，导致 _loads 错乱或截断。
    # 解决方案：抽取 _iter_phdrs() 根据 EI_CLASS（1=ELF32, 2=ELF64）正确解包程序头。
    def _parse_loads(self) -> None:
        """手工解析 Program Header 取 PT_LOAD。

        bug 原因（第 1 次修复）：依赖 pyelftools 的 iter_segments() 时，
        PT_DYNAMIC 的构造函数内部会再次迭代 section 触发同一 ELFParseError，
        导致坏节表文件连段表都拿不到。
        解决：直接按 e_phoff/e_phentsize 读原始字节，完全不碰 section API。
        """
        PT_LOAD = 1
        self._loads = []
        for p_type, p_flags, p_offset, p_vaddr, p_filesz, _memsz in self._iter_phdrs():
            if p_type == PT_LOAD and p_filesz > 0:
                self._loads.append((p_vaddr, p_vaddr + p_filesz, p_offset, p_flags))
        self._loads.sort()

    def _parse_sections(self) -> bool:
        """按节表解析。成功返回 True；节表损坏/内容非法返回 False。

        BUG-4/10 修复：除捕获 ELFParseError 外，增加节表有效性校验——
        全部节 sh_type 为 SHT_NULL(0)、名字是 ELF 魔数、或 sh_addr/sh_offset
        指向文件外，都视为"节表无效"，走段表兜底而非降级输出垃圾。
        """
        import struct as _s

        try:
            sections: list[Section] = []
            bad_names = 0
            total = 0
            file_len = len(self._raw or b"")
            for s in self._elf.iter_sections():
                total += 1
                if s["sh_size"] == 0:
                    continue
                # BUG-1 修复：不再因 sh_addr == 0 丢弃节。
                # 根因：PIE/共享库的首个 PT_LOAD 常规布局就是 vaddr=0
                #（4.2MB 的 .text 全在此），旧逻辑 `if sh_addr == 0: continue`
                # 把整段代码丢掉，导致 read() 全空、反汇编无米下锅。
                # 真正需要排除的是「无虚拟地址语义」的节（.shstrtab 等
                # 不参与映射的 SHT_STRTAB/SHT_SYMTAB 且 addr==0），
                # 用 sh_flags 的 SHF_ALLOC 位判定：未分配内存的节才跳过。
                sh_flags_raw = s["sh_flags"]
                is_alloc = bool(sh_flags_raw & 0x2)  # SHF_ALLOC
                is_nobits = s["sh_type"] == "SHT_NOBITS"
                if s["sh_addr"] == 0 and not is_alloc and not is_nobits:
                    continue
                # 名称合法性校验：坏 shstrtab 会让 sh_name 指向 ELF 头，
                # 读出的"名字"是 \x7fELF 魔数——识别并丢弃假名。
                name = s.name
                if name.startswith("\x7fELF") or any(ord(c) < 32 for c in name):
                    bad_names += 1
                    name = f"(bad_name@{s['sh_offset']:#x})"
                # 地址合法性：sh_offset 超出文件大小的节不可信
                if s["sh_type"] != "SHT_NOBITS" and s["sh_offset"] > file_len:
                    bad_names += 1
                    continue
                data = b"" if is_nobits else s.data()
                flags = sh_flags_raw
                sec = Section(
                    name=name,
                    addr=s["sh_addr"],
                    size=s["sh_size"],
                    offset=s["sh_offset"],
                    sec_type=s["sh_type"],
                    is_exec=bool(flags & 0x4),
                    is_write=bool(flags & 0x1),
                )
                sections.append(sec)
                # 缓存以 addr 为键：vaddr=0 的合法节（PIE 首段）与
                # 被跳过的非分配节不会争抢；同址时保留数据量更大者
                # （防止零长/占位节覆盖真实代码段）
                prev = self._cache.get(sec.addr)
                if prev is None or len(data) > len(prev):
                    self._cache[sec.addr] = data
            # 有效性判定：全 NULL 型（用户 dump 实测 24 项全 SHT_NULL）、
            # 或过半节名非法 → 节表视为无效
            all_null = total > 0 and all(
                self._elf.get_section(i)["sh_type"] == "SHT_NULL"
                for i in range(total)
            )
            if not sections or all_null or (total and bad_names > total // 2):
                self._sections = []
                self._cache.clear()
                self._sections_usable = False
                self.section_warning = (
                    f"节表无效（{total} 项, {bad_names} 个假名, all_null={all_null}）"
                    "——已切换 PT_LOAD 段表兜底模式"
                )
                return False
            self._sections = sections
            self._sections_usable = True
            return True
        except Exception:
            # 节表损坏（e_shoff 被壳抹掉是常见手法）：走段表兜底
            self._sections = []
            self._cache.clear()
            self._sections_usable = False
            return False

    # (1) 第一次修改（2026-11-26）
    # bug 原因：① 旧代码把 `st_value == 0` 的条目一律跳过，导致所有合法导入符号（st_shndx == 0
    #           且 st_value == 0）全部丢失；② 无 DT_HASH 时盲目用 `strsz // 4` 估算符号数，
    #           现代 Android so 多用 DT_GNU_HASH，导致越界把紧随其后的 .gnu.version/.dynstr
    #           字节解析成上百个假导出符号；③ 硬编码 ELF64 结构，不支持 ELF32。
    # 解决方案：① 兼容 ELF32/ELF64 动态段与符号表结构；② 符号总数优先取 DT_HASH.nchain，
    #           其次解析 DT_GNU_HASH（最大 bucket 沿 chain 走到 bit0==1），再兜底用 symtab 到
    #           紧邻更高虚拟地址动态表或所在 PT_LOAD 末尾的最小正差值除以 sym_ent；
    #           ③ 跳过索引 0（STN_UNDEF）和 st_name==0，仅过滤非未定义且 st_value==0 的条目。
    def _parse_dynamic_fallback(self) -> None:
        """从 PT_DYNAMIC 手工提取 dynsym/dynstr（节表不可用时的符号来源）。"""
        PT_DYNAMIC = 2
        DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_STRSZ = 3, 4, 5, 6, 7, 10
        DT_GNU_HASH = 0x6FFFFEF5
        dyn_v = dyn_sz = 0
        for p_type, _fl, _off, p_vaddr, p_filesz, _mem in self._iter_phdrs():
            if p_type == PT_DYNAMIC:
                dyn_v, dyn_sz = p_vaddr, p_filesz
                break
        if not dyn_v:
            return

        raw = self._raw or b""
        do = self._v2o(dyn_v)
        if do is None:
            return
        is64 = self._is64
        dyn_ent = 16 if is64 else 8
        dyn_fmt = "<QQ" if is64 else "<II"
        tags: dict[int, int] = {}
        for i in range(dyn_sz // dyn_ent):
            pos = do + i * dyn_ent
            if pos + dyn_ent > len(raw):
                break
            tag, val = struct.unpack_from(dyn_fmt, raw, pos)
            if tag == 0:
                break
            tags.setdefault(tag, val)

        symtab = tags.get(DT_SYMTAB, 0)
        strtab = tags.get(DT_STRTAB, 0)
        strsz = tags.get(DT_STRSZ, 0)
        if not (symtab and strtab and strsz):
            return
        so_, sto = self._v2o(symtab), self._v2o(strtab)
        if so_ is None or sto is None:
            return

        sym_ent = 24 if is64 else 16
        # 确定符号表真实上界：DT_HASH -> DT_GNU_HASH -> 相邻更高表偏移
        nchain = 0
        hash_v = tags.get(DT_HASH, 0)
        if hash_v:
            ho = self._v2o(hash_v)
            if ho is not None and ho + 8 <= len(raw):
                nchain = struct.unpack_from("<II", raw, ho)[1]

        if not nchain:
            gnu_hash_v = tags.get(DT_GNU_HASH, 0)
            if gnu_hash_v:
                gho = self._v2o(gnu_hash_v)
                if gho is not None and gho + 16 <= len(raw):
                    nbuckets, symoffset, bloom_size, _bloom_shift = struct.unpack_from("<IIII", raw, gho)
                    bloom_word = 8 if is64 else 4
                    boff = gho + 16 + bloom_size * bloom_word
                    coff = boff + nbuckets * 4
                    if nbuckets <= 1_000_000 and bloom_size <= 1_000_000 and coff <= len(raw):
                        max_sym = 0
                        for k in range(nbuckets):
                            b = struct.unpack_from("<I", raw, boff + k * 4)[0]
                            if b > max_sym:
                                max_sym = b
                        if max_sym == 0:
                            nchain = symoffset
                        elif max_sym >= symoffset:
                            idx = max_sym
                            limit = symoffset + 1_000_000
                            while idx < limit:
                                c_off = coff + (idx - symoffset) * 4
                                if c_off + 4 > len(raw):
                                    break
                                c_val = struct.unpack_from("<I", raw, c_off)[0]
                                idx += 1
                                if c_val & 1:
                                    break
                            nchain = idx

        # 计算基于地址布局的安全字节上界（既是无 hash 时的兜底，也能防止损坏 hash 越界）
        addr_tags = (
            DT_PLTGOT, DT_HASH, DT_STRTAB, DT_RELA, 12, 13, 17, 23, 25, 26, 36,
            0x6000000F, 0x60000011, 0x6FFFE000, DT_GNU_HASH,
            0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE,
        )
        upper_bytes = [tags[t] - symtab for t in addr_tags if tags.get(t, 0) > symtab]
        for va, end, _off, _fl in self._loads:
            if va <= symtab < end:
                upper_bytes.append(end - symtab)
                break
        max_by_layout = (min(upper_bytes) // sym_ent) if upper_bytes else 0
        if not nchain:
            nchain = min(max_by_layout, 200_000)
        elif max_by_layout > 0:
            nchain = min(nchain, max_by_layout, 200_000)

        # 字典在 _parse_symbols 初始化，而本方法在其之前运行（节表坏时）
        # —— 必须自行初始化，否则 AttributeError
        self.symbols: list[Symbol] = []
        self.imports: dict[str, Symbol] = {}
        self.exports: dict[str, Symbol] = {}
        str_limit = min(len(raw), sto + strsz)
        # 索引 0 为 STN_UNDEF，固定跳过
        for idx in range(1, nchain):
            base = so_ + idx * sym_ent
            if base + sym_ent > len(raw):
                break
            if is64:
                st_name, st_info, _o, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", raw, base)
            else:
                st_name, st_value, st_size, st_info, _o, st_shndx = struct.unpack_from("<IIIBBH", raw, base)
            undef = st_shndx == 0
            if st_name == 0 or st_name >= strsz:
                continue
            if not undef and st_value == 0:
                continue
            end = raw.find(b"\0", sto + st_name, str_limit)
            if end < 0:
                continue
            name = raw[sto + st_name : end].decode("utf-8", "replace")
            if not name:
                continue
            is_func = (st_info & 0xF) == 2  # STT_FUNC
            sym = Symbol(
                name=name, addr=st_value, size=st_size,
                kind=(SymbolKind.IMPORT if undef else SymbolKind.EXPORT),
                is_func=is_func, source="PT_DYNAMIC",
            )
            self.symbols.append(sym)
            if undef:
                self.imports[name] = sym
            else:
                self.exports[name] = sym


    def _sec_by_name(self, name: str):
        """get_section_by_name 的安全包装。

        bug 原因（第 2 次修复）：坏节表下 get_section_by_name 内部构建
        节名映射同样抛 ELFParseError，_parse_sections 捕获了但后续
        _parse_symbols/_parse_relocations/_parse_plt/_parse_functions
        里的直接调用没防护，导致 load_so 整体失败。
        解决：统一走本方法；_sections_usable=False 时直接返回 None。
        """
        if not self._sections_usable:
            return None
        try:
            return self._elf.get_section_by_name(name)
        except Exception:
            self._sections_usable = False
            return None

    def _detect_arch(self) -> Arch:
        m = self._elf["e_machine"]
        return {
            "EM_ARM": Arch.ARM32,
            "EM_AARCH64": Arch.ARM64,
            "EM_386": Arch.X86,
            "EM_X86_64": Arch.X86_64,
        }.get(m, Arch.UNKNOWN)

    def _parse_symbols(self) -> None:
        """按节表解析符号。

        (1) 第一次修改（2026-11-06）：
            bug 原因：本方法开头**无条件**把 symbols/imports/exports 重置成空，
                      然后才检查 .dynsym 节是否存在。而壳样本的节表被抹掉，
                      `_sec_by_name` 返回 None 就直接 return——把
                      `_parse_dynamic_fallback()` **刚刚从 PT_DYNAMIC 解出来的
                      符号全部抹掉**了。
                      实测：sg_real.so 的 fallback 正确解出 7 个符号
                      （含 JNI_OnLoad@0x5b4d8），但随后被本方法清零，
                      最终 symbols=0、exports=0，表现为"这个 so 没有导出任何符号"，
                      进而导致 JNI 注册表分析、导出函数画像全部失效。
            解决方案：先探测 .dynsym 节是否存在；**不存在就直接返回，
                      保留 fallback 的成果**；存在才重置并重新解析。
        """
        # 确保三个容器一定存在——即便走的是"保留 fallback 结果"的分支。
        # 否则调用方访问 so.exports 会 AttributeError。
        if not hasattr(self, "symbols"):
            self.symbols = []
        if not hasattr(self, "imports"):
            self.imports = {}
        if not hasattr(self, "exports"):
            self.exports = {}

        dynsym = self._sec_by_name(".dynsym")
        if dynsym is None:
            # 节表不可用：保留 _parse_dynamic_fallback 已解析的结果，不清空
            return
        self.symbols: list[Symbol] = []
        self.imports: dict[str, Symbol] = {}
        self.exports: dict[str, Symbol] = {}
        for sym in dynsym.iter_symbols():
            name = sym.name
            if not name:
                continue
            info = sym["st_info"]
            is_func = info["type"] == "STT_FUNC"
            undef = sym["st_shndx"] == "SHN_UNDEF"
            if undef:
                kind = SymbolKind.IMPORT
            else:
                kind = SymbolKind.EXPORT
            s = Symbol(
                name=name,
                addr=sym["st_value"],
                size=sym["st_size"],
                kind=kind,
                is_func=is_func,
                source=".dynsym",
            )
            self.symbols.append(s)
            if undef:
                self.imports[name] = s
            else:
                self.exports[name] = s

    def _parse_relocations(self) -> None:
        """解析重定位表 → self.relocations（models.Relocation）。

        (1) 第一次修改（2026-11-18）
            bug 原因：本方法只走节表（`_sec_by_name(".rela.dyn")` 等），
                      而壳处理的 dump so 节表被抹，`so.relocations` 恒为空。
                      于是「函数只被 vtable/GOT 间接调用」时，mda 既没有
                      bl 边也没有重定位可查——用户只能自己写 Python 读
                      .rela.dyn 才找到 vtable[4] = 0x196424。
                      另外解码逻辑与 dyn/jni.py 各有一份，容易漂移。
            解决方案：委托 `core/rela.py` 的 parse()（节表不可用时自动走
                      PT_DYNAMIC）。本方法只做 RelocEntry → Relocation 的
                      字段适配，条目顺序沿用「.rela.plt 先、.rela.dyn 后」，
                      因此既有样本上的 offset/rtype/sym_name 逐项不变
                      （libbase 235 条、libc 2226 条，见 tests/test_rela.py）。

        (2) 第二次修改（2026-11-18）
            bug 原因：旧实现读 addend 用的是 `getattr(r, "r_addend", 0)`，
                      而 pyelftools 的 Relocation 是**字典式**容器（字段走
                      `r["r_addend"]`），属性访问一律 miss → 静默退回 0。
                      实测 libc.so 的 `.rela.dyn` 首项真实 addend=0xfc020
                      被读成 0：所有 RELATIVE 条目的 addend 全变 0，
                      「vtable 槽指向哪个函数」这一核心信息在 so.relocations
                      里根本没存在过。这种"取不到就当 0"的兜底不会报错，
                      只会让人以为样本里没有 addend。
            解决方案：addend 由 core/rela.py 直接按 ELF 结构体字节解
                      （`<QQq`），拿到真值。行为变化仅此一项：addend 从
                      恒 0 变为真值，属修复而非回退（无调用方依赖 0）。
        """
        table = self.rela_table
        self.relocations: list[Relocation] = [
            Relocation(
                offset=e.offset,
                rtype=e.rtype,
                sym_idx=e.sym_idx,
                sym_name=e.sym_name,
                addend=e.addend,
            )
            for e in table.entries
        ]

    # (1) 第一次修改（2026-11-26）
    # bug 原因：① `if mem.base == reg and mem.disp:` 把页对齐（mem.disp == 0）的 GOT 槽过滤掉了
    #           （实测 libc.so 漏掉 fchmodat）；② 未校验架构，非 ARM64 样本误用 ARM64 反汇编。
    # 解决方案：开头校验 self.arch == Arch.ARM64，并将条件放宽为 `if mem.base == reg:`。
    def _parse_plt(self) -> None:
        """建立 PLT stub 地址 -> 导入符号名 的映射。

        原理：.rela.plt 给出 GOT 槽地址 -> 符号名；PLT stub 内部
        adrp xN,page ; ldr xM,[xN,#off] 恰好解出该 GOT 槽地址。

        实现说明：必须用 capstone 解码而非手写位运算。ADRP 的立即数
        编码为 immhi(19) + immlo(2) 拼成 21 位后再 <<12 并做 PC 相对
        寻址与 33 位符号扩展，手写极易算错（曾因此得到 plt_map=0）。
        capstone 的 operands[1].imm 已直接给出页基址。
        """
        self.plt_map: dict[int, str] = {}
        if self.arch != Arch.ARM64:
            return
        got2name = {r.offset: r.sym_name for r in self.relocations if r.sym_name}
        plt = self._sec_by_name(".plt")
        if plt is None or not got2name:
            return

        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        # 不设 detail=True 时访问 operands 会抛 CS_ERR_DETAIL
        md.detail = True
        base = plt["sh_addr"]
        # PLT0 头部的 adrp/ldr 不属于任何符号，靠「能否解出已知 GOT 槽」自然过滤
        pending: tuple[int, int, int] | None = None  # (page, stub_addr, reg_id)
        for insn in md.disasm(plt.data(), base):
            if insn.mnemonic == "adrp" and len(insn.operands) == 2:
                pending = (insn.operands[1].imm, insn.address, insn.operands[0].reg)
            elif insn.mnemonic == "ldr" and pending is not None and len(insn.operands) == 2:
                page, stub_addr, reg = pending
                mem = insn.operands[1].mem
                if mem.base == reg:
                    name = got2name.get(page + mem.disp)
                    if name:
                        self.plt_map[stub_addr] = name
                pending = None

    def _parse_functions(self) -> None:
        """函数发现：优先 .eh_frame FDE，其次 .eh_frame_hdr（段表模式），
        再次 dynsym 导出。"""
        self.functions: dict[int, Function] = {}
        fde_ranges: list[tuple[int, int]] = []

        eh = self._sec_by_name(".eh_frame")
        if eh is not None:
            try:
                # 参数顺序易错：DWARFStructs(little_endian, dwarf_format, address_size)
                structs = DWARFStructs(True, 32, 8 if self._is64 else 4)
                cfi = CallFrameInfo(
                    io.BytesIO(eh.data()), len(eh.data()), eh["sh_addr"], structs, for_eh_frame=True
                )
                for entry in cfi.get_entries():
                    if entry.__class__.__name__ != "FDE":
                        continue
                    pc = entry.header["initial_location"]
                    size = entry.header["address_range"]
                    if size <= 0:
                        continue
                    fde_ranges.append((pc, size))
            except Exception:
                # FDE 解析失败时退化为其他方案，不阻塞加载
                pass

        # 段表兜底：无节表时从 .eh_frame_hdr 的 binary search table 恢复函数边界。
        # dump so 的 PT_GNU_EH_FRAME（p_type=0x6474e550）在 RX 段内完好，
        # 其表项 (sdata4 pcrel) 直接给出每个函数起点。
        if not fde_ranges:
            fde_ranges = self._functions_from_eh_frame_hdr()

        for pc, size in fde_ranges:
            self.functions[pc] = Function(
                addr=pc, size=size, discovered_by="fde", so_name=self.name
            )

        # dynsym 导出函数补充（FDE 未覆盖的）
        for name, sym in self.exports.items():
            if sym.is_func and sym.addr > 0 and sym.addr not in self.functions:
                size = sym.size or self._guess_size(sym.addr)
                self.functions[sym.addr] = Function(
                    addr=sym.addr,
                    size=size,
                    name=name,
                    discovered_by="dynsym",
                    is_export=True,
                    so_name=self.name,
                )
        for addr, fn in self.functions.items():
            if not fn.name:
                sym = self.exports.get(addr)
                if sym is None:
                    # 按地址反查导出符号
                    for name, s in self.exports.items():
                        if s.addr == addr:
                            sym = s
                            break
                if sym is not None:
                    fn.name = sym.name
                    fn.is_export = True

        # (1) 第一次修改
        # bug 原因：无节表样本里 FDE 会把 PLT 桩当成普通函数登记，
        # 实测 0x1a4140 被调用 1436 次霸占扇入榜首，污染枢纽分析；
        # 且 FDE 边界不准时还会在桩内部登记假入口（如 0x1a4124）。
        # 解决方案：剔除落在任一桩 16 字节区间内的所有函数入口。
        if self.plt_stubs:
            for addr in [a for a in self.functions if self.in_plt_stub(a)]:
                self.functions.pop(addr, None)

        self._refresh_functions()

    # ---------- 函数表维护（IDC / 递归发现 / FDE 共用） ----------

    def _refresh_functions(self) -> None:
        """重建函数区间索引，并保证区间**互不重叠**。

        不重叠是 function_at 能用二分的前提，也是 P1 类缺陷的修法：
        FDE 边界可能粗到覆盖多个逻辑函数（如一条 FDE 罩住
        0x29b2d0..0x29c830），若不按后出现的入口切开，反查永远返回
        外层大函数（BUG-17 与用户发现的 P1 是同一根因）。
        """
        starts = sorted(self.functions)
        for i, addr in enumerate(starts):
            fn = self.functions[addr]
            gap = (starts[i + 1] - addr) if i + 1 < len(starts) else 0x10000
            # 注意不要给 size 设 0x10 下限：跳转表里存在相距仅 4 字节的
            # 紧邻入口，抬到 0x10 会让区间互相重叠（实测 93 处重叠），
            # 而重叠会让 function_at 的二分退化并返回错函数。
            if fn.size <= 0 or fn.size > gap:
                fn.size = min(gap, 0x10000)
        self._starts = starts                      # 起点升序（function_at 二分用）
        self._func_ranges = [(a, self.functions[a].end) for a in starts]

    def in_load(self, addr: int) -> bool:
        """地址是否落在任一 PT_LOAD 段内（过滤数据块误识别产生的野目标）。"""
        return any(va <= addr < end for va, end, _off, _fl in self._loads)

    # (1) 第一次修改（2026-11-26）
    # bug 原因：新建函数分支固定写死 size=0，忽略调用方显式传入的非 0 size 参数；
    #           修改已有函数 size 时未清空 instructions 缓存。
    # 解决方案：新建分支尊重正整数 size 参数（未传或 0 时仍留 0 交由 _refresh_functions 计算）；
    #           更新已有函数 size 时顺带清空其指令缓存。
    def add_function(
        self, addr: int, size: int | None = None,
        discovered_by: str = "manual", name: str = "",
    ) -> Function:
        """新增函数入口；若落在已有函数内部，把宿主从该入口处切开。

        供 IDC MakeFunction/MakeName 与递归函数发现共用（避免两处
        各写一份切分逻辑）。切开后区间保持不重叠，function_at 退化为二分。
        """
        host = self.function_at(addr)
        if host is not None and host.addr < addr:
            host.size = addr - host.addr       # 宿主上界截断到新入口
            host.instructions = []             # 边界变化 → 解码缓存失效
        fn = self.functions.get(addr)
        if fn is None:
            # size 未传或为 0 时留 0，让 _refresh_functions 用「到下一个起点的距离」填满；
            # 调用方显式指定正 size 时直接尊重该大小。
            init_size = int(size) if size and size > 0 else 0
            fn = Function(addr=addr, size=init_size, name=name,
                          discovered_by=discovered_by, so_name=self.name)
            self.functions[addr] = fn
        else:
            if name:
                fn.name = name
            if size and size > 0:
                fn.size = int(size)
                fn.instructions = []
        self._refresh_functions()
        return fn

    # (1) 第一次修改（2026-11-26）
    # bug 原因：旧实现无视 .eh_frame_hdr 4 字节编码头，固定假设表项从 ho+12 开始且按
    #           `entry + loc_off`（把文件偏移 entry 当基址）计算函数起点；而实际常见编码
    #           table_enc=0x3b 为 DW_EH_PE_datarel(0x30)|sdata4(0x0b)，基址应为 .eh_frame_hdr
    #           的虚拟地址 hdr_v！导致无节表样本全部函数起点错位（每条递增偏差 12+8*i）。
    # 解决方案：按 LSB 规范完整解析头部 4 字节（version/eh_frame_ptr_enc/fde_count_enc/
    #           table_enc）及对应 DW_EH_PE 编码，依据 table_enc 高位（0x30=datarel 基址 hdr_v，
    #           0x10=pcrel 基址条目 VA hdr_v+(pos-ho)，0x00=绝对地址）准确还原函数起点。
    def _functions_from_eh_frame_hdr(self) -> list[tuple[int, int]]:
        """从 PT_GNU_EH_FRAME 的 binary search table 恢复函数起点表。

        dump so 节表被抹后，.eh_frame 节头不可用，但 PT_GNU_EH_FRAME
        段在 PT_LOAD 内完好。按头部 4 字节声明的 DW_EH_PE 编码依次读取
        eh_frame_ptr、fde_count 与查找表项。
        """
        PT_GNU_EH_FRAME = 0x6474E550
        hdr_v = hdr_sz = 0
        for p_type, _fl, _off, p_vaddr, p_filesz, _mem in self._iter_phdrs():
            if p_type == PT_GNU_EH_FRAME:
                hdr_v, hdr_sz = p_vaddr, p_filesz
                break
        if not hdr_v:
            return []

        raw = self._raw or b""
        ho = self._v2o(hdr_v)
        if ho is None or ho + 4 > len(raw):
            return []
        version, ptr_enc, count_enc, table_enc = raw[ho], raw[ho + 1], raw[ho + 2], raw[ho + 3]
        if version != 1 or count_enc == 0xFF or table_enc == 0xFF:
            return []

        mask = 0xFFFFFFFFFFFFFFFF if self._is64 else 0xFFFFFFFF
        ptr_sz = 8 if self._is64 else 4

        def _read_pe(pos: int, enc: int) -> tuple[int | None, int]:
            """按 DW_EH_PE 编码从 raw[pos] 读一个值，返回 (解析后的值, 新偏移)。"""
            if enc == 0xFF:
                return None, pos
            fmt = enc & 0x0F
            app = enc & 0x70
            field_va = hdr_v + (pos - ho)
            n = len(raw)
            if fmt == 0x00:
                if pos + ptr_sz > n:
                    return None, pos
                val = struct.unpack_from("<Q" if self._is64 else "<I", raw, pos)[0]
                pos += ptr_sz
            elif fmt == 0x01:
                val, shift = 0, 0
                while pos < n:
                    b = raw[pos]
                    pos += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80):
                        break
            elif fmt == 0x02:
                if pos + 2 > n:
                    return None, pos
                val = struct.unpack_from("<H", raw, pos)[0]
                pos += 2
            elif fmt == 0x03:
                if pos + 4 > n:
                    return None, pos
                val = struct.unpack_from("<I", raw, pos)[0]
                pos += 4
            elif fmt == 0x04:
                if pos + 8 > n:
                    return None, pos
                val = struct.unpack_from("<Q", raw, pos)[0]
                pos += 8
            elif fmt == 0x09:
                val, shift = 0, 0
                while pos < n:
                    b = raw[pos]
                    pos += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80):
                        if b & 0x40:
                            val |= -(1 << shift)
                        break
            elif fmt == 0x0A:
                if pos + 2 > n:
                    return None, pos
                val = struct.unpack_from("<h", raw, pos)[0]
                pos += 2
            elif fmt == 0x0B:
                if pos + 4 > n:
                    return None, pos
                val = struct.unpack_from("<i", raw, pos)[0]
                pos += 4
            elif fmt == 0x0C:
                if pos + 8 > n:
                    return None, pos
                val = struct.unpack_from("<q", raw, pos)[0]
                pos += 8
            else:
                return None, pos

            if app == 0x00:
                return val & mask, pos
            if app == 0x10:  # DW_EH_PE_pcrel：基址是当前条目虚拟地址
                return (field_va + val) & mask, pos
            if app == 0x30:  # DW_EH_PE_datarel：基址是 .eh_frame_hdr 虚拟地址
                return (hdr_v + val) & mask, pos
            return None, pos

        pos = ho + 4
        _eh_ptr, pos = _read_pe(pos, ptr_enc)
        count, pos = _read_pe(pos, count_enc)
        if not count or count < 0 or count > 2_000_000:
            return []

        starts: list[int] = []
        for _ in range(count):
            start, next_pos = _read_pe(pos, table_enc)
            if start is None or next_pos == pos:
                break
            _fde_ptr, next_pos2 = _read_pe(next_pos, table_enc)
            if next_pos2 == next_pos:
                break
            pos = next_pos2
            if self.in_load(start):
                starts.append(start)

        starts = sorted(set(starts))
        out: list[tuple[int, int]] = []
        for i, pc in enumerate(starts):
            sz = (starts[i + 1] - pc) if i + 1 < len(starts) else 0x200
            if sz > 0:
                out.append((pc, sz))
        return out

    # (1) 第一次修改（2026-11-26）
    # bug 原因：调用方在把 addr 放进 self.functions 之前就调用 _guess_size(addr)，
    #           旧实现只在 `start == addr` 时计算间距，导致查不到自身而恒返回 16 字节。
    # 解决方案：用 bisect_right 直接找大于 addr 的下一个已排序函数起点算大小并设上限 0x4000。
    def _guess_size(self, addr: int) -> int:
        """按已排序函数起点猜测未标注大小函数的体积。"""
        starts = sorted(self.functions)
        i = bisect.bisect_right(starts, addr)
        if i < len(starts):
            return min(starts[i] - addr, 0x4000)
        return 16

    # ---------- 查询 ----------

    @property
    def sections(self) -> list[Section]:
        return self._sections

    @property
    def rela_table(self) -> rela_parser.RelocTable:
        """重定位表（惰性解析，节表不可用时自动走 PT_DYNAMIC）。

        与 `self.relocations` 的关系：后者是 models.Relocation 的**兼容视图**
        （只有 offset/rtype/sym_idx/sym_name/addend 五个字段），条目数、
        顺序、符号名与改动前逐项一致；唯一变化是 addend 由恒 0 修正为真值
        （见 _parse_relocations 第 2 次修改）。本属性给出 core/rela.py 的
        完整条目（含 rtype_name、sym_resolved、addend 语义标记、来源表名），
        并带解析元信息（error/warnings/packed/relr），供
        vtable_at / code_targets / rela_dump 使用。

        惰性是必要的：一条重定位都不查的调用方（只取符号表、只搜字节）
        不该为解析付钱；libc.so 有 2226 条，首次解析约 10ms。
        """
        if self._rela_table is None:
            self._rela_table = rela_parser.parse(self)
        return self._rela_table

    def read(self, addr: int, size: int) -> bytes:
        """按虚拟地址读取字节。

        三级读取：
        1. section 缓存（节表模式）——索引用「section 内偏移」addr - sh_addr，
           不是文件偏移 sh_offset（二者在 sh_addr != sh_offset 时不同）
        2. PT_LOAD 段表（兜底模式）——vaddr → file offset 换算后读原始字节
        3. 都 miss 时返回空（.bss 等无文件数据的地址这是正确行为）

        BUG-5 部分修复：非法入参（负地址/负长度）抛 ValueError；
        地址完全不在任何已注册区域时记录 _read_miss 并返回空——
        与"无数据"的区分靠 _read_miss + maps() 诊断接口。
        """
        if addr < 0 or size < 0:
            raise ValueError(f"非法参数: addr={addr:#x} size={size}")
        if size == 0:
            return b""
        for sec in self._sections:
            if sec.contains(addr):
                data = self._cache.get(sec.addr, b"")
                start = addr - sec.addr
                # (5) 第五次修改（2026-11-02）：节内读取也要卡住节边界。
                #     bug 原因：data[start:start+size] 越过节末尾时 Python 切片
                #               不会报错，只是变短——看似"安全"，但上层若按
                #               size 解析（如 read_typed 取 uint32）就会把不足
                #               长度的数据当成完整值，或与后续字节拼成错值。
                #               实测 0x227796 请求 4 字节只返回 2 字节，
                #               read_typed 仍报 ok:true。
                #     解决方案：截断到节边界返回，由上层按 len() 判断完整性。
                avail = max(0, sec.size - start)
                return data[start : start + min(size, avail)]
        # 段表兜底：dump so 的唯一读取路径
        for va, end, off, _fl in self._loads:
            if va <= addr < end:
                raw = self._raw or b""
                fo = off + (addr - va)
                # (5) 第五次修改（2026-11-02）：段表读取必须卡住段尾，不能续读。
                #     bug 原因：旧实现在 fo+size 超出文件时直接 raw[fo:]（截断），
                #               但「段尾」和「文件尾」是两回事——当请求跨越段末尾，
                #               而文件在该偏移之后仍有其他段的数据时，
                #               raw[fo:fo+size] 会**越过段边界继续读文件**，
                #               把不属于该地址的字节当成该地址的内存返回。
                #               实测：dump 样本 0x227796 请求 4 字节，返回
                #               0000bf15，其中后 2 字节已越过段尾 0x227798，
                #               是文件中紧随其后的别段内容——这是凭空造数据。
                #     解决方案：先按段尾算可用长度，取 min(size, 段内剩余)，
                #               再与文件长度取 min，绝不跨段续读。
                seg_avail = end - addr
                take = min(size, seg_avail)
                if fo + take > len(raw):
                    take = max(0, len(raw) - fo)
                return raw[fo : fo + take]
        self._read_miss = addr  # 诊断标记：最近一次完全 miss 的地址
        return b""

    def exec_regions(self) -> list[tuple[int, int, int, int]]:
        """可执行区域列表 [(vaddr, end, file_off, flags)]。

        (4) 第四次修改（2026-10-30）：新增公开访问器。
        bug 原因：search_bytes 等上层功能只遍历 so.sections，而壳处理过的
                  dump so 节表被抹（_sections=[]），导致「按字节搜索」在
                  最需要它的样本上恒返回 0（实测搜单字节 d2 也为 0，
                  而同一模式按 PT_LOAD 扫可命中 110 处 br x16）。
        解决方案：暴露 PT_LOAD 中的可执行段，供上层在无节表时兜底扫描。
        """
        return [(va, end, off, fl) for va, end, off, fl in self._loads if fl & 1]

    def maps(self) -> list[dict]:
        """已注册的虚拟地址区域（sections + PT_LOAD），诊断 read miss 用。"""
        out = [
            {"kind": "section", "name": s.name, "addr": s.addr, "end": s.end,
             "exec": s.is_exec, "write": s.is_write}
            for s in self._sections
        ]
        out += [
            {"kind": "PT_LOAD", "name": "", "addr": va, "end": end,
             "exec": bool(fl & 1), "write": bool(fl & 2)}
            for va, end, _o, fl in self._loads
        ]
        return sorted(out, key=lambda m: m["addr"])

    def section_at(self, addr: int) -> Section | None:
        for sec in self._sections:
            if sec.contains(addr):
                return sec
        return None

    @property
    def function_list(self) -> list:
        """函数对象列表（按地址升序）。

        (1) 第一次修改（2026-11-06）：
            bug 原因：`so.functions` 是 dict[int, Function]，`len()` 返回个数
                      看起来很自然，但 `for f in so.functions` 拿到的是**整数键**，
                      再访问 `f.addr` 就抛 AttributeError: 'int' object has no
                      attribute 'addr'——使用方被这个隐式约定绊住。
            解决方案：新增 `function_list` 属性，明确返回**函数对象列表**；
                      保留 `functions` 字典不动（大量内部代码按地址查它），
                      但把"要遍历请用 function_list"写进两者的文档。
        """
        fns = getattr(self, "functions", None) or {}
        if isinstance(fns, dict):
            return sorted(fns.values(), key=lambda f: int(getattr(f, "addr", 0) or 0))
        return sorted(list(fns), key=lambda f: int(getattr(f, "addr", 0) or 0))

    def function_at(self, addr: int) -> Function | None:
        """反查地址所属函数（二分，O(log N)）。

        (1) BUG-17 修复：区间曾**重叠**（FDE 粗边界罩住内部子函数），
            旧实现取首个命中 → 返回外层大函数，UI 打开错函数、显示旧名。
        (2) 现由 _refresh_functions() 保证区间互不重叠且起点升序，
            因此「最后一个 start <= addr」若不包含 addr，即落在空洞，
            无需再往前找——反查从 O(N) 降为 O(log N)。
        (3) 第二次修改 bug 原因：桩已从函数表剔除，但 _refresh_functions
            按间隙把前一函数的 size 拉长，把桩字节圈进了函数体（实测
            桩 0x1a4104 落在 0x1a4084 的区间 [0x1a4084,0x1a4124) 里），
            导致 function_at(桩) 返回真函数——错误的归属。
            解决方案：落在 PLT 桩区间内的地址一律返回 None。
        """
        if not self._starts:
            return None
        if self.in_plt_stub(addr):
            return None
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0:
            return None
        fn = self.functions.get(self._starts[i])
        return fn if fn is not None and addr < fn.end else None

    def plt_name(self, addr: int) -> str | None:
        return self.plt_map.get(addr)

    def in_plt_stub(self, addr: int) -> bool:
        """addr 是否落在任一 PLT 桩的 16 字节指令区间内。

        (1) 第一次修改
        bug 原因：FDE 边界不准时会在桩**内部**登记假函数入口，
        实测 0x1a4124 是桩 0x1a4120 的第 2 条指令却被登记成函数，
        只按桩起点精确匹配（addr in plt_stubs）会漏掉这类假入口。
        解决方案：按 [stub, stub+16) 区间判定，起点与内部一网打尽。

        (2) 第二次修改
        bug 原因：初版对 plt_stubs 做线性扫描，而本函数在引用图构建时
        每条 call 指令都要问一次（实测 15814 个调用点 × 165 个桩），
        把引用图构建拖慢约 9%（6.5s → 7.1s）。
        解决方案：改用排好序的 _stub_sorted + bisect，O(log n)。
        """
        if not self.plt_stubs:
            return False
        # 防御：外部若直接改动 plt_stubs，排序缓存可能过期，按长度重建
        if len(self._stub_sorted) != len(self.plt_stubs):
            self._stub_sorted = sorted(self.plt_stubs)
        i = bisect.bisect_right(self._stub_sorted, addr) - 1
        if i < 0:
            return False
        return self._stub_sorted[i] <= addr < self._stub_sorted[i] + 16

    def _scan_plt_stubs_by_segment(self) -> None:
        """段表模式下扫描 PLT 桩（无 .plt/.rela.plt 节表时）。

        (1) 第一次修改
        bug 原因：加固样本把节表与 PT_DYNAMIC 一起抹掉后，_parse_plt()
        取不到 .plt 节直接 return，plt_map 保持为空；而 FDE 会把 PLT 桩
        当成普通函数登记。实测 libsgmainso-6.7.260202.so：164 个标准桩
        （adrp x16/ldr x17/add x16/br x17）全部进了函数表，其中
        0x1a4140 被调用 1436 次，直接霸占扇入排行，污染枢纽排序。
        解决方案：按 ARM64 标准桩模板扫可执行 PT_LOAD，命中地址记入
        plt_stubs；符号名无法恢复（dynsym/rela 均已抹除），**plt_map
        保持为空**，只记录地址，不伪造符号名。

        (2) 第二次修改
        bug 原因：初版对每个 4 字节偏移都解 16 字节交给 capstone，
        实测 libsgmainso-6.7 构造耗时 4.79s（其中扫描 3.44s，
        可执行段 1.7MB → 43 万次解码），样本越大越慢。
        解决方案：先用 ADRP 位模式预筛（`(w & 0x9F000000) == 0x90000000`
        且 `Rd == 16`），只对候选偏移做 capstone 校验。
        实测 3.44s → 0.065s（53 倍），命中结果完全一致（差异 0）。
        附带收益：预筛天然只落在合法指令编码上，减少非指令边界误判。
        """
        # (3) 第三次修改（2026-11-26）
        # bug 原因：① 未校验架构，非 ARM64 样本误按 ARM64 指令扫描 PLT 桩；
        #           ② 截断的 dump 文件里 `off + i * 4 + 4` 可能越过 `len(raw)` 触发 struct.error。
        # 解决方案：开头校验 self.arch == Arch.ARM64，并在解包前检查 `pos + 4 <= len(raw)`。
        # 无节表时才需要；有节表走 _parse_plt 已有通路
        if self._sections_usable or self.arch != Arch.ARM64:
            return
        raw = self._raw
        if not raw:
            return
        exec_loads = [(va, end, off) for va, end, off, fl in self._loads if fl & 1]
        if not exec_loads:
            return
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        for va, end, off in exec_loads:
            for i in range((end - va) // 4):
                pos = off + i * 4
                if pos + 4 > len(raw):
                    break
                # 预筛：ADRP（op=1）且 Rd == x16，才值得做 4 条指令校验
                w = struct.unpack_from("<I", raw, pos)[0]
                if (w & 0x9F000000) != 0x90000000 or (w & 0x1F) != 16:
                    continue
                code = raw[pos: pos + 16]
                if len(code) < 16:
                    continue
                if is_arm64_plt_stub(list(md.disasm(code, va + i * 4))):
                    self.plt_stubs.add(va + i * 4)
        # 排序缓存：in_plt_stub 是热路径（每条 call 指令都会问一次），
        # 线性扫描 165~308 个桩会把引用图构建拖慢约 9%
        self._stub_sorted = sorted(self.plt_stubs)

    def symbol_name(self, addr: int) -> str | None:
        """把地址解析为最合适的名字：函数名 > PLT 符号 > 空。"""
        fn = self.function_at(addr)
        if fn is not None:
            return fn.name or f"sub_{addr:x}"
        name = self.plt_map.get(addr)
        if name:
            return name
        return None

    def close(self) -> None:
        self._stream.close()

# ---------------------------------------------------------------- C++ 符号还原
# 为什么需要：Android 的 so 里 206/386 个函数名是 mangled 形式
# （_ZN7android4base24SendFileDescriptorVectorEiPKvm...），
# 人只会按 "SendFileDescriptorVector" 去找，按原样字符串根本搜不到。
# 系统里不一定有 c++filt（实测本机没有），所以用标准库自己实现。

_ITANIUM_PRIMITIVES = {
    "v": "void", "b": "bool", "c": "char", "a": "signed char",
    "h": "unsigned char", "s": "short", "t": "unsigned short",
    "i": "int", "j": "unsigned int", "l": "long", "m": "unsigned long",
    "x": "long long", "y": "unsigned long long",
    "f": "float", "d": "double", "e": "long double",
    "w": "wchar_t", "z": "...",
}


def demangle(name: str) -> str:
    """把 Itanium C++ ABI 的 mangled 名还原成可读形式。

    (1) 第一次修改（2026-11-13）：
        背景：加固 so 的函数名基本都是 mangled（_Z 开头），
              而 function_by_name 只做原样子串匹配 —— 人按 "SendFileDescriptor"
              永远搜不到 _ZN7android4base24SendFileDescriptorVectorEiPKvm。
              实测 libbase.so：207 个有名字的函数里 206 个是 mangled。
        做法：实现 Itanium ABI 的**常见子集**（嵌套名 + 基础类型 + 指针/引用）。
              解析不出来的原样返回，不编造。
    """
    if not name or not name.startswith("_Z"):
        return name
    try:
        return _demangle_itanium(name[2:]) or name
    except Exception:                                     # noqa: BLE001
        return name


def _read_number(s: str, i: int) -> tuple[int, int]:
    """读一串数字，返回 (数值, 新下标)。读不到数字返回 (0, i)。"""
    j = i
    while j < len(s) and s[j].isdigit():
        j += 1
    if j == i:
        return 0, i
    return int(s[i:j]), j


def _parse_name(s: str, i: int) -> tuple[list[str], int]:
    """解析 <嵌套名>，返回 (部分列表, 新下标)。"""
    parts: list[str] = []
    while i < len(s):
        ch = s[i]
        if ch == "N":                       # 嵌套名 N ... E
            i += 1
            while i < len(s) and s[i] != "E":
                sub, i = _parse_single(s, i)
                if not sub:
                    break
                parts.extend(sub)
            if i < len(s) and s[i] == "E":
                i += 1
            return parts, i
        sub, i = _parse_single(s, i)
        if not sub:
            break
        parts.extend(sub)
        return parts, i
    return parts, i


def _parse_single(s: str, i: int) -> tuple[list[str], int]:
    """解析一个 <源名>：<长度><标识符>，或 St 之类的特殊前缀。"""
    if i >= len(s):
        return [], i
    # St = std::
    if s.startswith("St", i):
        return ["std"], i + 2
    n, j = _read_number(s, i)
    if n <= 0:
        return [], i
    ident = s[j:j + n]
    return [ident], j + n


def _parse_type(s: str, i: int) -> tuple[str, int]:
    """解析一个类型，返回 (可读类型, 新下标)。"""
    if i >= len(s):
        return "", i
    ch = s[i]
    if ch in _ITANIUM_PRIMITIVES:
        return _ITANIUM_PRIMITIVES[ch], i + 1
    if ch == "P":
        inner, j = _parse_type(s, i + 1)
        return f"{inner}*", j
    if ch == "R":
        inner, j = _parse_type(s, i + 1)
        return f"{inner}&", j
    if ch == "K":
        inner, j = _parse_type(s, i + 1)
        return f"{inner} const", j
    if ch == "N":                       # 嵌套类型（如 NSt3__16vectorI...E）
        parts, j = _parse_name(s, i)
        base = "::".join(parts)
        if j < len(s) and s[j] == "I":
            depth, k = 0, j
            while k < len(s):
                if s[k] == "I":
                    depth += 1
                elif s[k] == "E":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            return base, k
        return base, j
    # 普通类型名
    parts, j = _parse_single(s, i)
    return "::".join(parts) if parts else "", j


def _demangle_itanium(s: str) -> str:
    """_Z 之后的正文 → 可读形式。失败返回空串。"""
    parts, i = _parse_name(s, 0)
    if not parts:
        return ""
    scope = "::".join(parts)
    # 没有参数表（数据符号）就到名字为止
    if i >= len(s):
        return scope
    args: list[str] = []
    while i < len(s) and s[i] != "E":
        t, i = _parse_type(s, i)
        if not t:
            break
        args.append(t)
    if not args:
        return scope
    return f"{scope}({', '.join(args)})"
