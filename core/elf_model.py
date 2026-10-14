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

from models import Arch, Function, Relocation, Section, Symbol, SymbolKind

import io


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
        self._sections_usable = False  # 节表损坏时 False，全部 get_section_by_name 短路
        self.section_warning: str = ""  # 节表无效时的诊断信息（GUI/日志展示）
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
        self._parse_functions()

    def _parse_loads(self) -> None:
        """手工解析 Program Header 取 PT_LOAD。

        bug 原因（第 1 次修复）：依赖 pyelftools 的 iter_segments() 时，
        PT_DYNAMIC 的构造函数内部会再次迭代 section 触发同一 ELFParseError，
        导致坏节表文件连段表都拿不到。
        解决：直接按 e_phoff/e_phentsize 读原始字节，完全不碰 section API。
        """
        import struct

        self._stream.seek(0)
        head = self._stream.read(64)
        if len(head) < 0x40 or head[:4] != b"\x7fELF":
            raise ValueError("非 ELF 文件")
        e_phoff, = struct.unpack_from("<Q", head, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", head, 0x36)
        PT_LOAD = 1
        self._loads = []
        for i in range(e_phnum):
            self._stream.seek(e_phoff + i * e_phentsize)
            ph = self._stream.read(e_phentsize)
            if len(ph) < 56:
                break
            p_type, p_flags = struct.unpack_from("<II", ph, 0)
            p_offset, p_vaddr, _pa, p_filesz, _memsz = struct.unpack_from("<QQQQQ", ph, 8)
            if p_type == PT_LOAD and p_filesz > 0:
                self._loads.append((p_vaddr, p_vaddr + p_filesz, p_offset, p_flags))
        self._loads.sort()
        # 缓存全文件字节：段表模式下 read() 走这里
        self._stream.seek(0)
        self._raw = self._stream.read()

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

    def _parse_dynamic_fallback(self) -> None:
        """从 PT_DYNAMIC 手工提取 dynsym/dynstr（节表不可用时的符号来源）。"""
        import struct as _s

        # 找 PT_DYNAMIC 的 vaddr 与大小
        self._stream.seek(0)
        head = self._stream.read(64)
        e_phoff, = _s.unpack_from("<Q", head, 0x20)
        e_phentsize, e_phnum = _s.unpack_from("<HH", head, 0x36)
        PT_DYNAMIC, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ = 2, 4, 5, 6, 10
        dyn_v = dyn_sz = 0
        for i in range(e_phnum):
            self._stream.seek(e_phoff + i * e_phentsize)
            ph = self._stream.read(e_phentsize)
            if len(ph) < 56:
                break
            p_type, _fl = _s.unpack_from("<II", ph, 0)
            if p_type == PT_DYNAMIC:
                _off, p_vaddr, _pa, p_filesz, _mem = _s.unpack_from("<QQQQQ", ph, 8)
                dyn_v, dyn_sz = p_vaddr, p_filesz
                break
        if not dyn_v:
            return

        def v2o(v: int) -> int | None:
            for va, end, off, _fl in self._loads:
                if va <= v < end:
                    return off + (v - va)
            return None

        raw = self._raw or b""
        do = v2o(dyn_v)
        if do is None:
            return
        tags: dict[int, int] = {}
        for i in range(dyn_sz // 16):
            if do + i * 16 + 16 > len(raw):
                break
            tag, val = _s.unpack_from("<QQ", raw, do + i * 16)
            if tag == 0:
                break
            tags[tag] = val
        symtab, strtab, strsz = tags.get(DT_SYMTAB), tags.get(DT_STRTAB), tags.get(DT_STRSZ, 0)
        hash_v = tags.get(DT_HASH)
        if not (symtab and strtab):
            return
        so_, sto = v2o(symtab), v2o(strtab)
        if so_ is None or sto is None:
            return
        # 符号数：DT_HASH 的 nchain；无 hash 则按 strtab 间距估算
        nchain = 0
        if hash_v:
            ho = v2o(hash_v)
            if ho is not None and ho + 8 <= len(raw):
                nchain = _s.unpack_from("<II", raw, ho)[1]
        if not nchain:
            nchain = min(strsz // 4, 65536) if strsz else 0

        # 字典在 _parse_symbols 初始化，而本方法在其之前运行（节表坏时）
        # —— 必须自行初始化，否则 AttributeError
        self.symbols: list[Symbol] = []
        self.imports: dict[str, Symbol] = {}
        self.exports: dict[str, Symbol] = {}
        for idx in range(nchain):
            base = so_ + idx * 24
            if base + 24 > len(raw):
                break
            st_name, st_info, _o, st_shndx, st_value, st_size = _s.unpack_from("<IBBHQQ", raw, base)
            if st_name >= strsz or st_value == 0:
                continue
            end = raw.find(b"\0", sto + st_name, sto + strsz)
            if end < 0:
                continue
            name = raw[sto + st_name : end].decode("utf-8", "replace")
            if not name:
                continue
            is_func = (st_info & 0xF) == 2  # STT_FUNC
            undef = st_shndx == 0
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
        self.symbols: list[Symbol] = []
        self.imports: dict[str, Symbol] = {}
        self.exports: dict[str, Symbol] = {}
        dynsym = self._sec_by_name(".dynsym")
        if dynsym is None:
            return
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
        self.relocations: list[Relocation] = []
        dynsym = self._sec_by_name(".dynsym")
        for sec_name in (".rela.plt", ".rela.dyn", ".rel.plt", ".rel.dyn"):
            sec = self._sec_by_name(sec_name)
            if sec is None:
                continue
            # 只有 RelocationSection 才有 iter_relocations；
            # .rela.dyn 若被标记为其他类型需跳过，避免 AttributeError
            if not hasattr(sec, "iter_relocations"):
                continue
            for r in sec.iter_relocations():
                sym_name = ""
                if dynsym is not None:
                    sym = dynsym.get_symbol(r["r_info_sym"])
                    sym_name = sym.name
                self.relocations.append(
                    Relocation(
                        offset=r["r_offset"],
                        rtype=r["r_info_type"],
                        sym_idx=r["r_info_sym"],
                        sym_name=sym_name,
                        # pyelftools 的 Relocation 是属性容器，非 dict；
                        # .rel（32 位）节无 addend 字段，用 getattr 兜底
                        addend=getattr(r, "r_addend", 0),
                    )
                )

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
                pending = (insn.operands[1].imm, insn.address & ~0xF, insn.operands[0].reg)
            elif insn.mnemonic == "ldr" and pending is not None and len(insn.operands) == 2:
                page, stub_addr, reg = pending
                mem = insn.operands[1].mem
                if mem.base == reg and mem.disp:
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
                structs = DWARFStructs(True, 32, 8)
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
            # size 传 0 让 _refresh_functions 用「到下一个起点的距离」填满。
            # （若直接给 0x10，新发现函数只会反汇编 4 条指令——实测踩过）
            fn = Function(addr=addr, size=0, name=name,
                          discovered_by=discovered_by, so_name=self.name)
            self.functions[addr] = fn
        else:
            if name:
                fn.name = name
            if size:
                fn.size = size
        self._refresh_functions()
        return fn

    def _functions_from_eh_frame_hdr(self) -> list[tuple[int, int]]:
        """从 PT_GNU_EH_FRAME 的 binary search table 恢复函数起点表。

        dump so 节表被抹后，.eh_frame 节头不可用，但 PT_GNU_EH_FRAME
        段在 PT_LOAD 内完好。表项编码 sdata4 pcrel（0x3b），值为
        相对条目自身地址的有符号偏移。函数大小未知时用下一函数起点
        或默认 0x200 兜底（后续 bl 目标反推可补充）。
        """
        import struct as _s

        PT_GNU_EH_FRAME = 0x6474E550
        self._stream.seek(0)
        head = self._stream.read(64)
        e_phoff, = _s.unpack_from("<Q", head, 0x20)
        e_phentsize, e_phnum = _s.unpack_from("<HH", head, 0x36)
        hdr_v = hdr_sz = 0
        for i in range(e_phnum):
            self._stream.seek(e_phoff + i * e_phentsize)
            ph = self._stream.read(e_phentsize)
            if len(ph) < 56:
                break
            p_type, _fl = _s.unpack_from("<II", ph, 0)
            if p_type == PT_GNU_EH_FRAME:
                _off, p_vaddr, _pa, p_filesz, _mem = _s.unpack_from("<QQQQQ", ph, 8)
                hdr_v, hdr_sz = p_vaddr, p_filesz
                break
        if not hdr_v:
            return []

        def v2o(v: int) -> int | None:
            for va, end, off, _fl in self._loads:
                if va <= v < end:
                    return off + (v - va)
            return None

        raw = self._raw or b""
        ho = v2o(hdr_v)
        if ho is None or ho + 12 > len(raw):
            return []
        # table_enc 低 nibble 0xb = sdata4 pcrel；高 nibble 3 = 有 4 字节计数头
        count = _s.unpack_from("<I", raw, ho + 8)[0]
        table = ho + 12
        out: list[tuple[int, int]] = []
        prev_start = 0
        for i in range(count):
            entry = table + i * 8
            if entry + 8 > len(raw):
                break
            loc_off, _fde = _s.unpack_from("<ii", raw, entry)
            start = (entry + loc_off) & 0xFFFFFFFFFFFFFFFF
            if prev_start:
                # 上一函数大小 = 本函数起点 - 上一函数起点
                out.append((prev_start, start - prev_start))
            prev_start = start
        if prev_start:
            out.append((prev_start, 0x200))
        # 过滤：起点必须落在 PT_LOAD 内
        return [
            (pc, sz) for pc, sz in out
            if any(va <= pc < end for va, end, _o, _fl in self._loads)
        ]

    def _guess_size(self, addr: int) -> int:
        """按已排序函数区间猜测未标注大小函数的体积。"""
        ranges = sorted((a, f.end) for a, f in self.functions.items())
        for i, (start, end) in enumerate(ranges):
            if start == addr:
                if i + 1 < len(ranges):
                    return max(16, ranges[i + 1][0] - addr)
                return 16
        return 16

    # ---------- 查询 ----------

    @property
    def sections(self) -> list[Section]:
        return self._sections

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
                return data[start : start + size]
        # 段表兜底：dump so 的唯一读取路径
        for va, end, off, _fl in self._loads:
            if va <= addr < end:
                raw = self._raw or b""
                fo = off + (addr - va)
                if fo + size <= len(raw):
                    return raw[fo : fo + size]
                return raw[fo:]
        self._read_miss = addr  # 诊断标记：最近一次完全 miss 的地址
        return b""

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

    def function_at(self, addr: int) -> Function | None:
        """反查地址所属函数（二分，O(log N)）。

        (1) BUG-17 修复：区间曾**重叠**（FDE 粗边界罩住内部子函数），
            旧实现取首个命中 → 返回外层大函数，UI 打开错函数、显示旧名。
        (2) 现由 _refresh_functions() 保证区间互不重叠且起点升序，
            因此「最后一个 start <= addr」若不包含 addr，即落在空洞，
            无需再往前找——反查从 O(N) 降为 O(log N)。
        """
        if not self._starts:
            return None
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0:
            return None
        fn = self.functions.get(self._starts[i])
        return fn if fn is not None and addr < fn.end else None

    def plt_name(self, addr: int) -> str | None:
        return self.plt_map.get(addr)

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
