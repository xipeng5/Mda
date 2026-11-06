"""JNI 动态注册表（JNINativeMethod 数组）的静态定位。

## 解决什么问题

Java 调 so 里的 native 方法有两条路：
  A. **静态注册**：符号名按 ``Java_包名_类名_方法名`` 约定导出，工具能直接看导出表。
  B. **动态注册**：so 在 ``JNI_OnLoad`` 里调 ``RegisterNatives(env, clazz, methods, n)``，
     真正的函数名/签名/地址只存在于一个 ``JNINativeMethod`` 数组里，导出表里什么都没有。

对加固样本，导出表往往是 0，**B 是唯一入口**。本模块就是去文件里把那张表挖出来。

``JNINativeMethod``（arm64/64 位，24 字节）：
    +0x00  const char* name        -> "doCommandNative"
    +0x08  const char* signature   -> "(I[BI[B)Ljava/lang/String;"
    +0x10  void*       fnPtr       -> 函数地址

## 两条独立的取材路径（本模块的核心设计）

### 路径一：明文表扫描（pattern scan）
在 .data / .rodata / .data.rel.ro / .bss 里按 24 字节步长滑窗，
要求连续 >=3 组满足「name 指向合法 Java 标识符」「signature 指向合法 JNI 描述符」。
这是最可靠的判据——签名串的形状几乎不可能被巧合命中。

### 路径二：重定位反推（rela based）
``fnPtr`` 在文件里通常是 0，真值在 RELA 的 ``r_addend`` 里。
加固样本往往把整个表加密/抽走，但**重定位是加载器要用的，不能被加密**，
所以「一段连续的 RELATIVE 重定位，addend 全部落在可执行段」这个形态，
是"这里曾经有一张函数指针数组"的强证据。

两条路径各自独立产出，再按「表基址+条目数」归并：路径二能补路径一拿不到的
``fn_static_addr``；路径一能补路径二拿不到的 ``name/signature``。
**任一路径单独命中都如实返回，不假装另一路也成功**。

## 为什么不能直接用 SoFile.relocations

``core/elf_model.py`` 的 ``_parse_relocations`` 依赖 section 表（``_sec_by_name(".rela.dyn")``）。
壳处理过的样本节表被抹（``_sections == []``），此时 ``so.relocations`` 是**空列表**——
不是"没有重定位"，而是"没解析到"。本模块因此自带 PT_DYNAMIC 解析：
DT_RELA / DT_RELASZ / DT_RELAENT / DT_JMPREL / DT_PLTRELSZ，完全不碰节表。

(1) 第1次修改（2026-11-06）：
bug 原因：直接读 ``so.relocations`` 时，对 /tmp/sg_real.so（2.8MB 加固样本）
         返回 0 条，而该文件实际有 5265 条 RELA。若据此判断"没有重定位"，
         路径二会全程失效，且会给出错误的结论。
解决方案：自己解析 PT_DYNAMIC。实测该样本得到 RELA=0x2228 / RELASZ=0x1ed98 /
         JMPREL=0x20fc0，共 5218 条 RELATIVE + 43 条 ABS64 + 4 条 GLOB_DAT = 5265，
         与 DT_RELACOUNT(5218) 声明一致，说明解析口径正确。
"""
from __future__ import annotations

import re
import struct

from core.elf_model import SoFile

__all__ = [
    "JniError",
    "find_jni_registrations",
    "parse_relocations",
    "scan_tables_by_pattern",
    "scan_tables_by_relocations",
]

# JNINativeMethod 在 64 位下固定 24 字节（3 个指针）
_ENTRY_SIZE = 24
# 判定为"一张表"所需的最小连续条目数
_MIN_ENTRIES = 3
# 字符串读取上限（任务要求 512）
_MAX_STR = 512
# 表之间的最小间隔：同一张表里条目步长是 24，这里退一个量级避免把一张表拆成多张
_TABLE_GAP = _ENTRY_SIZE * 2

# 合法 Java 方法名：标识符，允许 $（内部类）与 _ 开头
_RE_JAVA_NAME = re.compile(rb"[A-Za-z_$][A-Za-z0-9_$]*\Z")
# 合法 JNI 类型描述符：以 ( 开头，含 ), 后面是返回类型描述符
_RE_JNI_SIG = re.compile(rb"\([^)\x00]{0,250}\)(\[*(?:[VZBSCIJFD]|L[A-Za-z0-9_$/.\-]+;))+\Z")

# AArch64 重定位类型（本项目样本全 arm64）
_R_AARCH64_RELATIVE = 1027
_R_AARCH64_ABS64 = 257
_R_AARCH64_GLOB_DAT = 1025
_R_AARCH64_JUMP_SLOT = 1026

# PT_DYNAMIC 里的 tag（标准值 + Android 私有值）
_DT_NULL = 0
_DT_PLTRELSZ = 2
_DT_RELA = 7
_DT_RELASZ = 8
_DT_RELAENT = 9
_DT_JMPREL = 23
# Android 私有扩展（bionic 的 android_dynamic_tags.h）：
#   0x60000011 DT_ANDROID_RELA      / 0x60000012 DT_ANDROID_RELASZ
#   0x6000000f DT_ANDROID_REL       / 0x60000010 DT_ANDROID_RELSZ
# 注意：DT_ANDROID_RELA 的内容是**压缩的 APS2 格式**，不是普通 RELA 数组；
# 本项目只在"标准 DT_RELA 缺失"时用它做存在性提示，不硬解压缩格式（见 parse_relocations）。
_DT_ANDROID_RELA = 0x60000011
_DT_ANDROID_RELASZ = 0x60000012
# DT_RELR（相对重定位压缩表）：0x24 DT_RELR / 0x25 DT_RELRSZ / 0x23 DT_RELRENT
_DT_RELR = 0x24
_DT_RELRSZ = 0x25

# 扫描候选节名（明文表可能落在哪）
_SCAN_SECTIONS = (".data", ".rodata", ".data.rel.ro", ".bss", ".got", ".init_array")


class JniError(RuntimeError):
    """JNI 分析的可预期失败：带机器可读 code（与 memread.MemReadError 同形）。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------- ELF 底层：地址换算与 RELA 解析 ----------


def _loads(so: SoFile) -> list[tuple[int, int, int, int]]:
    """取 PT_LOAD 段表 [(vaddr, end, file_off, flags)]。

    用私有的 ``_loads`` 而不只是公开 ``maps()``：``maps()`` 把 section 和
    PT_LOAD 混在一起、且不含 flags 的完整信息，而本模块需要「文件偏移」与
    「是否可执行」两样，PT_LOAD 才是唯一权威来源（节表被抹时更是如此）。
    只读不写，风险可控。
    """
    return list(getattr(so, "_loads", []) or [])


def _v2o(so: SoFile, vaddr: int) -> int | None:
    """虚拟地址 -> 文件偏移；不在任何 PT_LOAD 内返回 None。"""
    for va, end, off, _fl in _loads(so):
        if va <= vaddr < end:
            return off + (vaddr - va)
    return None


def _o2v(so: SoFile, file_off: int) -> int | None:
    """文件偏移 -> 虚拟地址；不属于任何 PT_LOAD 返回 None。"""
    for va, end, off, _fl in _loads(so):
        if off <= file_off < off + (end - va):
            return va + (file_off - off)
    return None


def _in_exec(so: SoFile, vaddr: int) -> bool:
    """地址是否落在可执行段（flags 的 PF_X 位）。"""
    for va, end, _off, fl in _loads(so):
        if va <= vaddr < end:
            return bool(fl & 1)
    return False


def _read_cstr(so: SoFile, vaddr: int, limit: int = _MAX_STR) -> bytes | None:
    """按虚拟地址读一个 C 字符串（遇 \\0 停）。

    三种"读不到"统一返回 None，让调用方用同一个判断：
      - 地址不在任何段内
      - 起始字节就是 \\0（空串，不是有效名字/签名）
      - limit 内没有 \\0（截断的，不可信）
    """
    if vaddr <= 0:
        return None
    off = _v2o(so, vaddr)
    if off is None:
        return None
    raw = getattr(so, "_raw", None) or b""
    if off >= len(raw):
        return None
    end = raw.find(b"\x00", off, off + limit)
    if end < 0 or end == off:
        return None
    return raw[off:end]


def _dynamic_tags(so: SoFile) -> dict[int, int]:
    """解析 PT_DYNAMIC，返回 {tag: value}（只保留首个出现的值）。

    不碰节表（壳样本节表被抹也能用），这是本模块拿 RELA 的唯一可靠入口。
    """
    raw = getattr(so, "_raw", None) or b""
    if len(raw) < 0x40:
        return {}
    import struct as _s

    try:
        e_phoff, = _s.unpack_from("<Q", raw, 0x20)
        e_phentsize, e_phnum = _s.unpack_from("<HH", raw, 0x36)
    except _s.error:
        return {}
    PT_DYNAMIC = 2
    dyn_off = dyn_sz = 0
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + 56 > len(raw):
            break
        p_type, _fl = _s.unpack_from("<II", raw, o)
        if p_type == PT_DYNAMIC:
            p_offset, _va, _pa, p_filesz, _ms = _s.unpack_from("<QQQQQ", raw, o + 8)
            dyn_off, dyn_sz = p_offset, p_filesz
            break
    if not dyn_off or not dyn_sz:
        return {}
    tags: dict[int, int] = {}
    for i in range(dyn_sz // 16):
        o = dyn_off + i * 16
        if o + 16 > len(raw):
            break
        tag, val = _s.unpack_from("<QQ", raw, o)
        if tag == _DT_NULL:
            break
        tags.setdefault(tag, val)
    return tags


def parse_relocations(so: SoFile) -> list[dict]:
    """解析 ELF 的重定位表（RELA + JMPREL），返回统一结构的列表。

    为什么不用 ``so.relocations``：它依赖节表，壳样本上恒为空（见模块头注释）。

    返回每项：{offset, rtype, sym_idx, addend, table}
      table 标明来自 "rela"（DT_RELA）还是 "jmprel"（DT_JMPREL），便于溯源。
    (7) 第7次修改（2026-11-06）：
    bug 原因：liblog.so（AOSP 正常库）实测 **DT_RELA = 0**，它用的是
             0x60000011 DT_ANDROID_RELA + 0x60000012 DT_ANDROID_RELASZ。
             只认标准 DT_RELA 时，这类 so 的重定位会全部解析为 0 条，
             路径二直接失效，而调用方看不出区别（都表现为"没有表"）。
    解决方案：解析结果里如实记录每个 tag 的来源与实际能力。
             标准 RELA / JMPREL 照旧逐条解；DT_ANDROID_RELA 是 **AP S2 压缩格式**
             （只压缩了 r_info，需按 SLEB128 流解），本模块**不硬解**——
             与其给出一个可能错的地址，不如如实报告"该 so 用的是 Android 压缩格式，
             本工具未解析"，让结论的边界清晰。DT_RELR 同理只报告不解析。

    (8) 第8次修改（2026-11-06）：
    bug 原因：上一版把 DT_ANDROID_RELA 当普通 RELA 数组直接按 24 字节遍历，
             会把压缩流当结构体读，产出成批垃圾重定位（可能数万条假记录），
             是典型的"看起来有数据、其实是错的"。
    解决方案：绝不对压缩格式做未经验证的定长遍历。改为写入 ``unparsed_indices``，
             由上层在 note 里如实说明。
    """
    raw = getattr(so, "_raw", None) or b""
    tags = _dynamic_tags(so)
    out: list[dict] = []

    def _walk(vaddr: int, size: int, ent: int, table: str) -> None:
        if not vaddr or not size or ent < 8:
            return
        off = _v2o(so, vaddr)
        if off is None:
            return
        for i in range(size // ent):
            o = off + i * ent
            if o + ent > len(raw):
                break
            try:
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", raw, o)
            except struct.error:
                break
            out.append({
                "offset": r_offset,
                "rtype": r_info & 0xFFFFFFFF,
                "sym_idx": r_info >> 32,
                "addend": r_addend,
                "table": table,
            })

    ent = tags.get(_DT_RELAENT, 24)
    _walk(tags.get(_DT_RELA, 0), tags.get(_DT_RELASZ, 0), ent, "rela")
    # JMPREL 的条目尺寸与 RELA 相同（arm64 上都是 24）
    _walk(tags.get(_DT_JMPREL, 0), tags.get(_DT_PLTRELSZ, 0), ent, "jmprel")
    return out


def relocation_capabilities(so: SoFile) -> dict:
    """报告该 so 用了哪种重定位编码，以及本工具能解析哪些。

    单独抽出来是为了让"找不到"有可核查的原因（而不是一句"没找到"）：
      parsed_standard  标准 DT_RELA / DT_JMPREL 是否解析到条目
      android_compressed DT_ANDROID_RELA/REL 存在（压缩格式，本工具不解析）
      relr              DT_RELR 存在（压缩相对重定位，本工具不解析）
    """
    tags = _dynamic_tags(so)
    return {
        "dt_rela": tags.get(_DT_RELA, 0),
        "dt_relasz": tags.get(_DT_RELASZ, 0),
        "dt_jmprel": tags.get(_DT_JMPREL, 0),
        "dt_pltrelsz": tags.get(_DT_PLTRELSZ, 0),
        "android_compressed": bool(tags.get(_DT_ANDROID_RELA) or tags.get(_DT_ANDROID_RELASZ)),
        "android_rela": tags.get(_DT_ANDROID_RELA, 0),
        "android_relasz": tags.get(_DT_ANDROID_RELASZ, 0),
        "relr": bool(tags.get(_DT_RELR) or tags.get(_DT_RELRSZ)),
        "relr_addr": tags.get(_DT_RELR, 0),
        "relr_size": tags.get(_DT_RELRSZ, 0),
    }


def _rela_map(rels: list[dict]) -> dict[int, dict]:
    """r_offset -> 重定位记录（同址取首个）。"""
    out: dict[int, dict] = {}
    for r in rels:
        out.setdefault(r["offset"], r)
    return out


# ---------- 路径一：明文表 pattern scan ----------


def _valid_name(so: SoFile, vaddr: int) -> str | None:
    """vaddr 指向的字符串是否是合法 Java 方法名。"""
    b = _read_cstr(so, vaddr)
    if b is None or not _RE_JAVA_NAME.match(b):
        return None
    return b.decode("utf-8", "replace")


def _valid_signature(so: SoFile, vaddr: int) -> str | None:
    """vaddr 指向的字符串是否是合法 JNI 方法签名。"""
    b = _read_cstr(so, vaddr)
    if b is None or not _RE_JNI_SIG.match(b):
        return None
    return b.decode("utf-8", "replace")


def _entry_at(so: SoFile, addr: int, rela: dict[int, dict]) -> dict | None:
    """把 addr 处的 24 字节解释成一个 JNINativeMethod 条目；不像就返回 None。

    判据（两条硬性的 + 一条记录性的）：
      1. qword0 指向合法 Java 标识符  —— 硬性
      2. qword1 指向合法 JNI 描述符    —— 硬性
      3. qword2 是函数地址；文件里可能是 0，真值去 RELA 的 addend 取 —— 记录性
    两条硬性判据同时成立的概率极低，不设宽松阈值。
    """
    off = _v2o(so, addr)
    raw = getattr(so, "_raw", None) or b""
    if off is None or off + _ENTRY_SIZE > len(raw):
        return None
    name_p, sig_p, fn_p = struct.unpack_from("<QQQ", raw, off)

    name = _valid_name(so, name_p)
    if name is None:
        return None
    sig = _valid_signature(so, sig_p)
    if sig is None:
        return None

    fn_addr = fn_p
    fn_source = "file"
    if fn_p == 0:
        # fnPtr 在文件里是 0：真值在加载器要用的重定位里
        rl = rela.get(addr + 0x10)
        if rl is not None and rl["rtype"] in (
            _R_AARCH64_RELATIVE, _R_AARCH64_ABS64, _R_AARCH64_GLOB_DAT,
        ):
            fn_addr = rl["addend"]
            fn_source = "rela"
        else:
            # 既没值也没重定位：如实标注，不编造地址
            fn_source = "none"

    return {
        "name": name,
        "signature": sig,
        "fn_static_addr": fn_addr,
        "fn_source": fn_source,
        "fn_name": "",
    }


def scan_tables_by_pattern(so: SoFile, rela: dict[int, dict],
                           max_tables: int = 50) -> list[dict]:
    """路径一：在候选节里滑窗找连续的 JNINativeMethod 条目。

    只在**非可执行**的已注册区域内扫（.data/.rodata/.data.rel.ro/.bss 等）：
    表是数据，扫代码段既慢又必然误报。

    返回的每张表字段：{table_static_addr, count, entries, detected_by}
    """
    raw = getattr(so, "_raw", None) or b""

    # 候选区域：优先按节名；节表被抹时退化为「所有非可执行 PT_LOAD」
    regions: list[tuple[int, int]] = []
    sections = getattr(so, "sections", []) or []
    if sections:
        for sec in sections:
            if sec.name in _SCAN_SECTIONS and not sec.is_exec and sec.size >= _ENTRY_SIZE * _MIN_ENTRIES:
                regions.append((sec.addr, sec.addr + sec.size))
    if not regions:
        for va, end, _off, fl in _loads(so):
            if not (fl & 1) and end - va >= _ENTRY_SIZE * _MIN_ENTRIES:
                regions.append((va, end))

    tables: list[dict] = []
    covered_until = -1  # 防止一张表被重复切分：已经成表区间的尾部不再重新起表

    for start, end in sorted(regions):
        # (9) 第9次修改（2026-11-06）：
        # bug 原因：上一版用「区域起点向上取整到 24」定扫描起点，
        #          隐含假设"区域起点本身 24 对齐"。真实 so 里 PT_LOAD 起点不一定
        #          是 24 的倍数（例如 0x1af400 是，但别的样本可能是 0x1af410），
        #          此时从该起点按 +24 步进访问的地址全部 ≡ 起点 (mod 24)，
        #          **永远扫不到真正 24 对齐的表**，表现为"表明明在文件里却找不到"。
        # 解决方案：按**绝对地址**对齐（往上找到第一个 addr % 24 == 0 的位置），
        #          与区域起点无关。这样任何 24 对齐的表都必被访问到。
        addr = -(-start // _ENTRY_SIZE) * _ENTRY_SIZE
        while addr + _ENTRY_SIZE * _MIN_ENTRIES <= end:
            if addr < covered_until:
                addr = -(-covered_until // _ENTRY_SIZE) * _ENTRY_SIZE
                continue
            entries: list[dict] = []
            cur = addr
            while cur + _ENTRY_SIZE <= end:
                e = _entry_at(so, cur, rela)
                if e is None:
                    break
                entries.append(e)
                cur += _ENTRY_SIZE
            if len(entries) >= _MIN_ENTRIES:
                tables.append({
                    "table_static_addr": addr,
                    "count": len(entries),
                    "entries": entries,
                    "detected_by": "pattern",
                })
                covered_until = cur
                addr = cur
                if len(tables) >= max_tables:
                    return tables
            else:
                addr += _ENTRY_SIZE
    return tables


# ---------- 路径二：重定位反推 ----------


def _is_func_prologue(so: SoFile, vaddr: int) -> bool:
    """vaddr 处的指令是否像 AArch64 函数序言。

    为什么要这一步（第2次修改的直接动因）：
    只要求「addend 落在可执行段」太松——实测 sg_real.so 里 0x22d8e / 0x231f1 /
    0x234ee 三个 addend 落在可执行段，但它们指向的是字符串数据（字节
    0x736473 = "sds"），不是代码。若不过滤，会把数据表误报成函数指针表。

    判据取 AArch64 最常见的四种首指令（宁严不松，漏掉的真表由路径一兜底）：
      stp x29,x30,[sp,#-N]!  0xA98xxxxx   —— 绝大多数 clang 函数的第一条
      sub sp, sp, #N         0xD10xxxxx
      stp <reg>,[sp,#imm]    0xA90xxxxx
      str <reg>,[sp,#-N]!    0xF80xxxxx
    """
    o = _v2o(so, vaddr)
    raw = getattr(so, "_raw", None) or b""
    if o is None or o + 4 > len(raw):
        return False
    w = struct.unpack_from("<I", raw, o)[0]
    return bool(
        (w & 0xFFC00000) == 0xA9800000
        or (w & 0xFFC00000) == 0xD1000000
        or (w & 0xFFC00000) == 0xA9000000
        or (w & 0xFFC00000) == 0xF8000000
    )


def _slot_is_plausible(so: SoFile, entry_addr: int, off: int,
                       rels_by_off: dict[int, dict]) -> bool:
    """64 位下一个 JNINativeMethod 的 name/sig 槽是否"像个指针槽"。

    合法形态只有两种：
      a) 值为 0（文件里待重定位填、或该字段本次不用）
      b) 值指向**可读数据段**内的地址，且读得出一个不以 \\0 开头的字符串
    若该槽有重定位，则以 addend 为准做同样的校验。

    (3) 第3次修改（2026-11-06）：
    bug 原因：加「24 等差 + 函数序言」两条判据后仍报出 14 张表，但复审发现
             name/sig 槽里是 0x33 / 0x7 / 0x15180 这类**小整数**，
             甚至 0xb87582df8c89d673 这种乱码串。真正的 JNINativeMethod 里
             这两个字段必然是指针或 0，不可能存小整数——说明这些是普通的
             函数指针数组（vtbl / dispatch table），不是 JNI 表。
    解决方案：逐个校验 name/sig 槽。任一条目不合格即整张表作废——
             宁可少报（漏掉真表由路径一兜底），也不能把假表当 JNI 表交出去。

    (5) 第5次修改（2026-11-06）：
    bug 原因：上一条只判「是否落在映像内」，但本样本第一个 PT_LOAD 的 vaddr
             就是 0x0，于是 0x33 / 0x7 / 0x15180 / 0x2710 这些小整数
             **全部"落在映像内"**，判据形同失效，仍报 10 张假表。
             这是 PIE 共享库 vaddr 从 0 起的通病，光看范围不够。
    解决方案：改成"必须真能读出一个非空 C 字符串"——
             名字/签名是字符串指针，这是它最本质的属性，也绕不开。
             小整数 0x33 处读到的不是可打印串，自然被拒。

    (6) 第6次修改（2026-11-06）：
    bug 原因：第 5 次改后仍剩 3 张假表。根因是 `_read_cstr` 只要求"有 \\0 且非空"，
             而 0x33 处读到的是 ELF 头 \\x7fELF —— 字节非空、有 \\0 之后就返回了，
             于是被判"是字符串"。sig 槽 0x5 / 0x28 / 0x15180 同理。
    解决方案：\u5b57\u7b26\u4e32\u5224\u5b9a\u5fc5\u987b\u8981\u6c42**\u5168\u662f\u53ef\u6253\u5370 ASCII**（0x20..0x7E）。
             \u65b9\u6cd5\u540d/\u7b7e\u540d\u672c\u6765\u5c31\u53ea\u80fd\u662f\u53ef\u6253\u5370 ASCII\uff0c
             \u8fd9\u6761\u7ea6\u675f\u6ca1\u6709\u4efb\u4f55\u8bef\u6740\u98ce\u9669\u3002
    """
    raw = getattr(so, "_raw", None) or b""
    o = _v2o(so, entry_addr)
    if o is None or o + _ENTRY_SIZE > len(raw):
        return False
    value = struct.unpack_from("<Q", raw, o + off)[0]
    rl = rels_by_off.get(entry_addr + off)
    if rl is not None:
        value = rl["addend"]
    if value == 0:
        return True
    s = _read_cstr(so, value)
    if s is None:
        return False
    # 方法名/签名只能是可打印 ASCII；含控制字节或高位字节的一律不算字符串
    return all(0x20 <= c < 0x7F for c in s)


def scan_tables_by_relocations(so: SoFile, rels: list[dict],
                               max_tables: int = 50) -> list[dict]:
    """路径二：从「24 字节等差 + addend 指向函数序言 + 另两槽像指针」重定位反推函数指针数组。

    形态依据：一张 JNINativeMethod 表的 fnPtr 槽地址是 24 字节等差的
    （name/sig/fn 三个指针一组），每个槽一条 RELATIVE 重定位，addend 是该
    函数的静态地址。四条判据同时成立：
      1. 槽地址严格 24 字节等差  —— 步长是 8 还是 24，直接决定它是不是 JNI 表
      2. addend 落在可执行段
      3. addend 处是函数序言      —— 排除"指向字符串数据"的假阳性
      4. 同一条目的 name/sig 槽是 0 或有效指针 —— 排除普通函数指针数组

    (2) 第2次修改（2026-11-06）：
    bug 原因：只用判据 1+2 时，sg_real.so 上报出 13 张表共 51 条，但复审发现
             其中 3 条的 addend 指向字符串（"sds"/"umfacadevalu"/"uvm_sw2"），
             不是函数。且不加判据 3 无法区分「8 字节步长的普通指针数组」。
    解决方案：加判据 3（函数序言），并在候选阶段就过滤掉非序言的目标；
              一条不合格就断开成两组，绝不把不合格的混进表里。

    (4) 第4次修改（2026-11-06）：
    bug 原因：判据 1+2+3 之后仍剩 14 张"表"，但逐条查 name/sig 槽发现是
             0x33/0x7/0x15180 这类小整数甚至是乱码，显然不是指针。
             这些是普通函数指针数组（vtbl/dispatch table），不是 JNINativeMethod。
             若原样返回，等于把 14 张假表当结论交出去。
    解决方案：加判据 4。**结果：sg_real.so 从 14 张降到 0 张**——
             与该文件"全文件不存在任何明文 JNI 签名串"的独立证据一致。
             这个"归零"是正确结论，不是功能失效。

    局限（必须如实说明）：即使命中，从这里也**拿不到 name/signature**，
    因为加固样本常把它们加密或运行时才生成。此时条目 name/signature 为空串，
    ``has_strings`` 为 False，由调用方决定怎么呈现——**绝不编造方法名**。
    """
    rels_by_off = _rela_map(rels)

    # 四条判据的候选：RELATIVE + 可执行段 + 函数序言
    candidates: list[tuple[int, int]] = []  # (slot_addr, addend)
    seen: set[int] = set()
    for r in rels:
        if r["rtype"] != _R_AARCH64_RELATIVE:
            continue
        slot = r["offset"]
        if slot in seen:
            continue
        addend = r["addend"]
        if not _in_exec(so, addend):
            continue
        if not _is_func_prologue(so, addend):
            continue
        candidates.append((slot, addend))
        seen.add(slot)
    candidates.sort()

    tables: list[dict] = []
    if not candidates:
        return tables

    def _flush(run: list[tuple[int, int]]) -> bool:
        """把一组折成表；返回 True 表示已达 max_tables。

        落表前执行判据 4：整组内每个条目的 name/sig 槽都必须是 0 或有效指针。
        """
        if len(run) < _MIN_ENTRIES:
            return False
        base = run[0][0] - 0x10  # fnPtr 槽相对结构起点偏移 0x10
        for (slot, _addend) in run:
            entry = slot - 0x10
            if not _slot_is_plausible(so, entry, 0, rels_by_off):
                return False
            if not _slot_is_plausible(so, entry, 8, rels_by_off):
                return False
        tables.append(_run_to_table(run, so))
        return len(tables) >= max_tables

    cur_run: list[tuple[int, int]] = [candidates[0]]
    for slot, addend in candidates[1:]:
        if slot - cur_run[-1][0] == _ENTRY_SIZE:
            cur_run.append((slot, addend))
        else:
            if _flush(cur_run):
                return tables
            cur_run = [(slot, addend)]
    _flush(cur_run)
    return tables


def _run_to_table(run: list[tuple[int, int]], so: SoFile) -> dict:
    """把一串 (slot, addend) 折成表结构。

    fnPtr 槽相对结构起点偏移 0x10，所以表基址 = 首个槽地址 - 0x10。
    """
    base = run[0][0] - 0x10
    entries = []
    for idx, (slot, addend) in enumerate(run):
        entries.append({
            "name": "",
            "signature": "",
            "fn_static_addr": addend,
            "fn_source": "rela",
            "fn_name": "",
            # addend 不落在可执行段时上层已被过滤，这里恒 True；保留字段便于调试
            "fn_in_exec": _in_exec(so, addend),
            "_slot": slot,
            "_level": idx,
        })
    return {
        "table_static_addr": base,
        "count": len(entries),
        "entries": entries,
        "detected_by": "rela",
        "has_strings": False,
    }


# ---------- 归并与对外接口 ----------


def _merge_tables(pattern_tables: list[dict], rela_tables: list[dict]) -> list[dict]:
    """把两条路径的结果按「表基址重叠」归并。

    归并规则：
      - 两条路径报同一张表（基址落在对方区间内） -> 合并成一张，
        detected_by 记为 "pattern+rela"，fn_static_addr 以 pattern 的为准
        （pattern 走的是精确的 r_offset+0x10 查表，比路径二按等差推出的更确定）
      - 只有一方命中 -> 原样保留，detected_by 标明来源
    合并后按表基址排序，输出前统一补 fn_name。
    """
    merged: list[dict] = []

    def _overlaps(a_base: int, a_cnt: int, b_base: int, b_cnt: int) -> bool:
        a_end = a_base + a_cnt * _ENTRY_SIZE
        b_end = b_base + b_cnt * _ENTRY_SIZE
        return a_base < b_end and b_base < a_end

    used_rela: set[int] = set()
    for pt in pattern_tables:
        entries = [dict(e) for e in pt["entries"]]
        detected = "pattern"
        for i, rt in enumerate(rela_tables):
            if i in used_rela:
                continue
            if _overlaps(pt["table_static_addr"], pt["count"],
                         rt["table_static_addr"], rt["count"]):
                used_rela.add(i)
                detected = "pattern+rela"
                # 用 rela 的地址补齐 pattern 里 fn_source == "none" 的条目
                by_slot = {e.get("_slot"): e for e in rt["entries"]}
                for idx, e in enumerate(entries):
                    if e["fn_source"] == "none":
                        slot = pt["table_static_addr"] + idx * _ENTRY_SIZE + 0x10
                        hit = by_slot.get(slot)
                        if hit is not None:
                            e["fn_static_addr"] = hit["fn_static_addr"]
                            e["fn_source"] = "rela"
                break
        merged.append({
            "table_static_addr": pt["table_static_addr"],
            "count": pt["count"],
            "entries": entries,
            "detected_by": detected,
        })
    for i, rt in enumerate(rela_tables):
        if i in used_rela:
            continue
        merged.append({
            "table_static_addr": rt["table_static_addr"],
            "count": rt["count"],
            "entries": [dict(e) for e in rt["entries"]],
            "detected_by": "rela",
        })
    merged.sort(key=lambda t: t["table_static_addr"])
    return merged


def _annotate_functions(so: SoFile, tables: list[dict]) -> None:
    """给每个条目补 fn_name（命中已知函数就给名字，否则 sub_<addr>）。

    就地修改，不返回新表。地址不在可执行段时 fn_name 留空并标注——
    这种情况说明 addend 不是代码指针，是重要线索，不能静默当函数处理。
    """
    funcs = getattr(so, "functions", {}) or {}
    for t in tables:
        for e in t["entries"]:
            addr = e.get("fn_static_addr") or 0
            if not addr:
                e["fn_name"] = ""
                continue
            fn = funcs.get(addr)
            if fn is None and hasattr(so, "function_at"):
                fn = so.function_at(addr)
            name = getattr(fn, "name", "") if fn is not None else ""
            if not name:
                name = f"sub_{addr:x}"
            e["fn_name"] = name


def _clean_entries(tables: list[dict]) -> None:
    """去掉内部调试字段（下划线前缀），保证输出结构干净。"""
    for t in tables:
        for e in t["entries"]:
            for k in [k for k in e if k.startswith("_")]:
                e.pop(k, None)


def find_jni_registrations(so_name: str, so: SoFile | None = None,
                           session=None, max_tables: int = 50) -> dict:
    """静态定位 so 里的 JNI 动态注册表。

    参数：
      so_name    —— so 的名字（用于返回与日志；so/session 都没给时按名字找）
      so         —— 直接传 SoFile 实例（推荐，MCP 层用 session.get(so_name) 取）
      session    —— core.session.Session；给了就用 session.get(so_name) 取 so
      max_tables —— 最多返回多少张表（防异常样本把结果撑爆）

    返回：
      {
        "ok": True, "implemented": True,
        "so_name": "...", "tables": [...],
        "table_count": N, "entry_total": M,
        "relocations": {...}, "searched": {...}, "note": "..."
      }

    找不到时 tables 为空、并给出 searched 说明搜了哪里 —— **绝不编造**。
    """
    # 取 so：so > session > 报错（不按名字瞎猜文件路径，避免读错文件）
    if so is None and session is not None:
        try:
            so = session.get(so_name)
        except Exception as exc:                      # noqa: BLE001 - 会话取不到就报清楚
            raise JniError("SO_NOT_LOADED",
                           f"会话里没有 {so_name!r}：{exc}（先加载该 so）") from exc
    if so is None:
        raise JniError("BAD_SO",
                       "必须提供 so（SoFile 实例）或 session；"
                       "本函数不按名字猜测文件路径，避免读错文件")
    if not isinstance(so, SoFile):
        raise JniError("BAD_SO", f"so 参数应为 SoFile，实际 {type(so).__name__}")
    if not isinstance(max_tables, int) or max_tables < 1:
        raise JniError("BAD_REQUEST", f"max_tables 必须为正整数，实际 {max_tables!r}")

    raw = getattr(so, "_raw", None) or b""
    rels = parse_relocations(so)
    rela = _rela_map(rels)

    pattern_tables = scan_tables_by_pattern(so, rela, max_tables=max_tables)
    rela_tables = scan_tables_by_relocations(so, rels, max_tables=max_tables)
    tables = _merge_tables(pattern_tables, rela_tables)

    _annotate_functions(so, tables)
    _clean_entries(tables)

    searched = {
        "sections": [s.name for s in (getattr(so, "sections", []) or [])
                     if s.name in _SCAN_SECTIONS],
        "section_table_available": bool(getattr(so, "sections", [])),
        "relocation_total": len(rels),
        "rela_relative": sum(1 for r in rels if r["rtype"] == _R_AARCH64_RELATIVE),
        "rela_in_exec": sum(1 for r in rels
                            if r["rtype"] == _R_AARCH64_RELATIVE and _in_exec(so, r["addend"])),
        "entry_size": _ENTRY_SIZE,
        "min_entries": _MIN_ENTRIES,
        "pattern_candidates": len(pattern_tables),
        "rela_candidates": len(rela_tables),
    }
    cap = relocation_capabilities(so)
    reloc_info = {
        "total": len(rels),
        "by_table": {
            "rela": sum(1 for r in rels if r["table"] == "rela"),
            "jmprel": sum(1 for r in rels if r["table"] == "jmprel"),
        },
        "parse_source": "PT_DYNAMIC" if rels else "none",
        # 该 so 用了哪些重定位编码；android_compressed / relr 为 True 时，
        # 本工具**无法**从中取 fnPtr 真值（压缩格式未解析），这是结论的边界
        "capabilities": cap,
        "unparsed": [],
        "note_shadowed_api": (
            "core 的 so.relocations 依赖节表；本函数改用 PT_DYNAMIC 解析，"
            "因此壳样本（节表被抹）也能拿到重定位" if not getattr(so, "relocations", None)
            else ""
        ),
    }
    if cap["android_compressed"]:
        reloc_info["unparsed"].append(
            "DT_ANDROID_RELA/REL（Android 压缩重定位，PSA APS2 格式）：本工具未解析，"
            "该文件里的 .rela.dyn 内容不可按定长数组读取"
        )
    if cap["relr"]:
        reloc_info["unparsed"].append(
            "DT_RELR（压缩相对重定位位图）：本工具未解析"
        )

    entry_total = sum(t["count"] for t in tables)
    result = {
        "ok": True,
        "implemented": True,
        "so_name": getattr(so, "name", so_name),
        "tables": tables,
        "table_count": len(tables),
        "entry_total": entry_total,
        "relocations": reloc_info,
        "searched": searched,
        "note": "",
    }

    if not tables:
        parts = [
            "未找到符合 JNINativeMethod 特征的数组："
            f"已扫描 {len(searched['sections']) or len(_loads(so))} 个区域、"
            f"{len(rels)} 条重定位，没有连续 {_MIN_ENTRIES} 组同时满足"
            "「name 是合法 Java 标识符」+「signature 是合法 JNI 描述符」。",
            "可能原因：表被加密或运行时才构造 / 方法名与签名不是明文常量 / "
            "该 so 走静态注册而非 RegisterNatives。",
        ]
        if cap["android_compressed"] or cap["relr"]:
            # 这是结论的边界：重定位没解析全，路径二本就不完整
            parts.append(
                "注意：该 so 使用 Android 压缩重定位"
                f"（ANDROID_RELA={cap['android_compressed']}, RELR={cap['relr']}），"
                "本工具未解析这些编码，因此**仅凭重定位反推的方式在此文件上不完整**；"
                "此处的『未找到』只代表明文表扫描也没命中。"
            )
        result["note"] = "".join(parts)
    else:
        no_str = [t for t in tables if not any(e.get("name") for e in t["entries"])]
        if no_str:
            result["note"] = (
                f"找到 {len(tables)} 张表、{entry_total} 个条目；其中 "
                f"{len(no_str)} 张只有重定位证据、拿不到 name/signature"
                "（这些表的字符串字段被加密或运行时生成，条目里从未编造方法名）。"
            )
        else:
            result["note"] = (
                f"找到 {len(tables)} 张明文表、{entry_total} 个条目，"
                "name/signature 均来自文件内真实字符串。"
            )
    return result
