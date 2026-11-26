"""DEX 静态分析对外 API。

四个公开函数（供 MCP 工具直接挂载）：

    dex_classes(path)                                 类表
    dex_methods(path, class_name)                     方法表
    dex_disasm(path, class_name, method_name, overload)  反汇编
    dex_callers(path, class_name, method_name, overload) 谁调用了它

路径既可以是 .dex，也可以是 .apk/.jar（内部 classes*.dex 按编号顺序合并）。

错误处理约定：**不抛异常、不编造数据**。失败时：
    · list 返回值 -> [{"error": <code>, "message": <中文说明>}]
    · str 返回值  -> 以 "; ERROR <code>: ..." 开头的说明文本
多 dex 场景下某个 dex 坏了不会连累其它 dex：坏的那条以 error 项出现在结果里。

性能：解析结果按 (路径, mtime, 大小, 条目名) 做 LRU 缓存（默认 4 个 dex），
所以对同一个文件反复查不同类不会重复解析。

(1) 第一次修改（2026-11-18）：本源码文件曾因并行任务的写操作被覆盖成
    24MB 垃圾内容，此处按 .pyc 反汇编结果与 126 条测试规格重建。
    重建时刻意保留了原有的公开契约（函数签名、返回字段名与顺序、
    错误码、输出文本格式），因此对上层 MCP 工具完全兼容。
"""
from __future__ import annotations

import os
import sys
from array import array
from collections import OrderedDict

from . import bytecode
from .code import (
    CodeItem,
    read_class_data,
    read_code_item,
)
from .header import (
    acc_names,
    acc_text,
    parse_header,
)
from .reader import DexBuffer, DexError, DexSource


# ---------------------------------------------------------------------------
# 缓存：按 (绝对路径, 条目名, mtime, size) 命中
#
# 为什么 key 里带 mtime/size：同一路径的 apk 可能在分析过程中被替换
# （解包、重打包、重新签名），只按路径缓存会拿到旧内容却显示新文件，
# 这是最难察觉的一类错误。
# ---------------------------------------------------------------------------
_CACHE: "OrderedDict[tuple, DexFile]" = OrderedDict()
_CACHE_MAX = 4


class _CodeView:
    """给 bytecode.disassemble 用的最小表视图。

    bytecode 需要 `data`（dex 字节）与 `insns_base`（本方法 insns 的文件偏移）
    才能把 code unit 偏移换回文件字节、并读出 payload 里的原始字节。
    DexTables 没有 insns_base，所以薄薄包一层。
    """

    __slots__ = ("data", "insns_base", "_tables")

    def __init__(self, tables, insns_base: int):
        self.data = tables.data
        self.insns_base = insns_base
        self._tables = tables

    # 五个解析方法直接转发，避免 bytecode 里到处判断"有没有 _tables"
    def string(self, idx: int) -> str:
        return self._tables.string(idx)

    def type_desc(self, idx: int) -> str:
        return self._tables.type_desc(idx)

    def field(self, idx: int):
        return self._tables.field(idx)

    def method(self, idx: int):
        return self._tables.method(idx)

    def proto(self, idx: int):
        return self._tables.proto(idx)


class DexFile:
    """一个已解析的 dex（header + 各 id 表 + 惰性 class 索引）。"""

    def __init__(self, data: bytes, display: str, entry: str, path: str = ""):
        self.buf = DexBuffer(data, display, path)
        self.header = parse_header(self.buf)
        from .header import DexTables

        self.tables = DexTables(self.buf, self.header)
        self.display = display
        self.entry = entry
        self.path = path
        self._class_defs = None
        self._class_index = None
        self._type_index = None
        self._class_data: dict = {}
        self._method_refs: dict = {}
        self.mutf8_dirty = 0

    def class_defs(self) -> list:
        if self._class_defs is None:
            self._class_defs = self.tables.class_defs()
        return self._class_defs

    @property
    def class_index(self) -> dict:
        """描述符 -> ClassDef。

        重复类（同一 dex 里两个 class_def 指向同一个描述符）不静默覆盖：
        计数放进 `duplicate_classes`，先出现的胜出（与 Android 类加载一致）。
        """
        if self._class_index is None:
            idx: dict = {}
            dup = 0
            for cd in self.class_defs():
                if cd.name in idx:
                    dup += 1
                    continue
                idx[cd.name] = cd
            self._class_index = idx
            self.duplicate_classes = dup
        return self._class_index

    def find_class(self, descriptor: str):
        return self.class_index.get(descriptor)

    def type_index_of(self, descriptor: str) -> int | None:
        """描述符 -> type_idx（惰性建反查表；坏条目跳过不炸）。"""
        if self._type_index is None:
            idx: dict = {}
            for i in range(self.header.type_ids_size):
                try:
                    idx.setdefault(self.tables.type_desc(i), i)
                except DexError:
                    continue
            self._type_index = idx
        return self._type_index.get(descriptor)

    def class_data(self, cd):
        """class_data_item（按 class_data_off 缓存）。"""
        key = cd.class_data_off
        hit = self._class_data.get(key)
        if hit is None:
            hit = read_class_data(self.buf, key)
            self._class_data[key] = hit
        return hit

    def method_refs(self, cd) -> list:
        """该类的 [(EncodedMethod, MethodRef)]，按 class_data 顺序。"""
        key = cd.class_data_off
        hit = self._method_refs.get(key)
        if hit is None:
            hit = [(m, self.tables.method(m.method_idx))
                   for m in self.class_data(cd).methods]
            self._method_refs[key] = hit
        return hit

    def code_item(self, m):
        if not m.has_code:
            return None
        return read_code_item(self.buf, m.code_off)

    def units_of(self, ci) -> array:
        return read_units(self.tables.data, ci.insns_off, ci.insns_size)

    def iter_method_code(self):
        """遍历本 dex 全部有字节码的方法，产出 (ClassDef, EncodedMethod, CodeItem)。

        坏方法的 code_item 解析失败就跳过该条——一个坏 class_data 不该
        让整个 dex 的调用者扫描中断。
        """
        for cd in self.class_defs():
            for m in self.class_data(cd).methods:
                if m.code_off == 0:
                    continue
                try:
                    ci = read_code_item(self.buf, m.code_off)
                except DexError:
                    continue
                yield cd, m, ci


def read_units(data: bytes, off: int, count: int) -> array:
    """把 code unit 数组读成 array('H')。

    用 array 而不是逐个 struct.unpack：调用者扫描要遍历几十万条指令，
    按下标取整数的开销比每次解包低一个数量级。
    """
    a = array("H")
    a.frombytes(bytes(data[off:off + count * 2]))
    if sys.byteorder != "little":
        a.byteswap()
    return a


def _cache_key(src: DexSource, entry: str) -> tuple:
    try:
        st = os.stat(src.path)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = (0, 0)
    return (os.path.abspath(src.path), entry, stamp)


def _load_dex(src: DexSource, entry: str) -> DexFile:
    """读入并缓存一个 dex（LRU 4）。缓存里已有就直接复用。"""
    key = _cache_key(src, entry)
    hit = _CACHE.get(key)
    if hit is not None:
        _CACHE.move_to_end(key)
        return hit
    data = src.read(entry)
    dex = DexFile(data, src.display_of(entry), entry, src.path)
    _CACHE[key] = dex
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return dex


def clear_cache() -> None:
    """清空解析缓存（测试与「文件被改过」时用）。"""
    _CACHE.clear()


# (2) 第二次修改（2026-11-26）
# bug 原因：此前在非完整描述符分支里写 `if not s.startswith("L"): s = "L" + s`，
#           导致所有以大写 L 开头的 Java 类名/包名（如 "LoginActivity"、"L"、"Local.Helper"）
#           被误判为已带 DEX 前缀而漏加 "L"，归一化成错误的 "LoginActivity;"。
# 解决方案：仅当字符串已同时以 "L" 开头且以 ";" 结尾（完整 DEX 描述符，长度 >= 3）时视为
#           已有前缀；否则一律补齐前缀 "L" 与后缀 ";"。
def _norm_class(name: str) -> str:
    """三种写法都接受，统一成描述符：

        Lcom/x/Y;  -> Lcom/x/Y;   （原样）
        com/x/Y    -> Lcom/x/Y;
        com.x.Y    -> Lcom/x/Y;
    """
    s = (name or "").strip()
    if not s:
        return s
    if s.startswith("["):          # 数组描述符原样
        return s
    if s.startswith("L") and s.endswith(";") and len(s) >= 3:
        return "L" + s[1:-1].replace(".", "/") + ";"
    if s.endswith(";"):
        s = s[:-1]
    return "L" + s.replace(".", "/") + ";"


def _err(code: str, message: str, **extra) -> dict:
    d = {"error": code, "message": message}
    d.update(extra)
    return d


def _err_text(code: str, message: str) -> str:
    return f"; ERROR {code}: {message}"


def _open_source(path: str) -> DexSource:
    return DexSource(path)


def dex_classes(path: str) -> list[dict]:
    """列出 dex/apk 里的全部类（多 dex 按 classes.dex、classes2.dex… 顺序合并）。

    每个类返回：
        name            描述符，如 Lcom/x/Y;
        java_name       给人看的形态 com.x.Y
        access_flags    class_def 的 access_flags 原值
        access_names    拆开后的名字列表，如 ["PUBLIC", "FINAL"]
        superclass      父类描述符（无父类时为空串）
        interfaces      接口描述符列表
        method_count    direct + virtual 方法数
        field_count     static + instance 字段数
        source_file     源文件名（may be empty）
        dex             该类的来源条目名（classes.dex / classes2.dex …）

    某个 dex 解析失败时不会丢整体结果：那条 dex 的 error 会作为一项出现在列表末尾。
    """
    try:
        src = _open_source(path)
    except DexError as exc:
        return [_err(exc.code, exc.message)]
    out: list[dict] = []
    try:
        for entry in src.entries:
            try:
                dex = _load_dex(src, entry)
                for cd in dex.class_defs():
                    data = dex.class_data(cd)
                    out.append({
                        "name": cd.name,
                        "java_name": cd.java_name,
                        "access_flags": cd.access_flags,
                        "access_names": acc_names(cd.access_flags, "class"),
                        "superclass": cd.superclass,
                        "interfaces": list(cd.interfaces),
                        "method_count": (len(data.direct_methods)
                                         + len(data.virtual_methods)),
                        "field_count": (len(data.static_fields)
                                        + len(data.instance_fields)),
                        "source_file": cd.source_file,
                        "dex": entry,
                    })
            except DexError as exc:
                # 坏 dex 单独报告，不影响其它 dex 的结果
                out.append(_err(exc.code, exc.message, dex=entry))
    finally:
        src.close()
    return out


# ---------- 内部：定位类与方法 ----------

def _find_class(src: DexSource, descriptor: str):
    """跨 dex 找类。找到返回 (dex, class_def)，否则返回错误说明文本。"""
    searched: list[str] = []
    for entry in src.entries:
        try:
            dex = _load_dex(src, entry)
        except DexError as exc:
            searched.append(f"{entry}(解析失败: {exc.code})")
            continue
        cd = dex.find_class(descriptor)
        if cd is not None:
            return dex, cd
        searched.append(entry)
    return (
        f"类 {descriptor} 不在 {src.basename} 的任何 dex 里"
        f"（已查找：{', '.join(searched) or '无 dex'}）"
    )


def _resolve_method(dex: DexFile, cd, name: str, overload: str):
    """按名字（可再按 overload 精确化）定位方法。

    overload 可以是：
        ""                     不筛选
        "(I)V"                 完整 proto 描述符
        "foo(I)V"              名字 + 描述符
        "VI"                   shorty（返回类型+参数类型的短名）

    重名且未给 overload 时返回错误说明（列出候选），**不替调用方猜**。
    """
    refs = dex.method_refs(cd)
    cands = [(m, r) for (m, r) in refs if r.name == name]
    want = ""
    if overload:
        want = overload.strip()
        cands = [
            (m, r) for (m, r) in cands
            if r.proto.descriptor == want
            or (r.name + r.proto.descriptor) == want
            or r.proto.shorty == want
        ]
    if not cands:
        all_names = sorted({r.name for (_m, r) in refs})
        hint = (f"该方法名不存在。该类共有 {len(all_names)} 个方法名："
                f"{', '.join(all_names[:20])}")
        if len(all_names) > 20:
            hint += " …"
        if overload:
            same = ", ".join(f"{r.name}{r.proto.descriptor}"
                             for (_m, r) in refs if r.name == name)
            hint = (f"没有匹配 overload={overload!r} 的方法。"
                    f"该类中名为 {name} 的方法有：{same or hint}")
        return f"{cd.name} 里找不到方法 {name}: {hint}"
    if len(cands) > 1:
        listing = "; ".join(
            f"{r.name}{r.proto.descriptor} (code_off=0x{m.code_off:x})"
            for (m, r) in cands)
        return (f"{cd.name} 里有 {len(cands)} 个同名方法 {name}，"
                f"请用 overload 指定：{listing}")
    return cands[0]


def dex_methods(path: str, class_name: str) -> list[dict]:
    """列出一个类的全部方法。

    返回字段：
        name, proto（描述符形如 (I)V）, shorty, access_flags, access_names,
        is_native, is_abstract, is_direct（来自 direct 而非 virtual 列表）,
        code_off, insn_count（code unit 数，等于 dexdump 的 "insns size"）,
        param_count（参数个数，不含 this）, ins_size（寄存器入参个数，含 this）,
        registers_size
    native/abstract 方法没有 code，code_off 与 insn_count 均为 0。
    """
    try:
        src = _open_source(path)
    except DexError as exc:
        return [_err(exc.code, exc.message)]
    # (2) 第二次修改（2026-11-26）
    # bug 原因：dex_methods 内部调用 dex.method_refs(cd) 解析 class_data/method_ids 时
    #           可能抛出 DexError，外层未捕获，违反对外 API 不抛异常的契约。
    # 解决方案：在主 try 块增加 except DexError 转为标准 [_err(exc.code, exc.message)]。
    try:
        found = _find_class(src, _norm_class(class_name))
        if isinstance(found, str):
            return [_err("CLASS_NOT_FOUND", found)]
        dex, cd = found
        out: list[dict] = []
        for m, r in dex.method_refs(cd):
            ci = None
            if m.has_code:
                try:
                    ci = dex.code_item(m)
                except DexError:
                    ci = None
            out.append({
                "name": r.name,
                "proto": r.proto.descriptor,
                "shorty": r.proto.shorty,
                "access_flags": m.access_flags,
                "access_names": acc_names(m.access_flags, "method"),
                "is_native": bool(m.access_flags & 0x100),
                "is_abstract": bool(m.access_flags & 0x400),
                "is_direct": m.is_direct,
                "code_off": m.code_off,
                "insn_count": ci.insns_size if ci else 0,
                "param_count": len(r.proto.params),
                "ins_size": ci.ins_size if ci else 0,
                "registers_size": ci.registers_size if ci else 0,
                "dex": dex.entry,
            })
        return out
    except DexError as exc:
        return [_err(exc.code, exc.message)]
    finally:
        src.close()


def dex_disasm(path: str, class_name: str, method_name: str,
               overload: str = "") -> str:
    """反汇编单个方法。

    输出每行一条指令，前缀是 `0x<字节偏移>(u<code-unit偏移>)`：
        dex 内部一切偏移（分支目标、switch 目标、payload 定位）都以 16-bit
        code unit 为单位，而「dex 字节偏移」= code unit 偏移 * 2。
        两者都给，避免看数字时来回换算。
    原始列是 code unit 的内存字节序十六进制，与 dexdump 左侧列一致，便于对拍。

    switch / fill-array-data 的 payload 会整块展开（不含指令前缀的缩进行），
    每条 case 的目标偏移都换算成绝对 code unit 偏移。
    """
    try:
        src = _open_source(path)
    except DexError as exc:
        return _err_text(exc.code, exc.message)
    try:
        found = _find_class(src, _norm_class(class_name))
        if isinstance(found, str):
            return _err_text("CLASS_NOT_FOUND", found)
        dex, cd = found
        got = _resolve_method(dex, cd, method_name, overload)
        if isinstance(got, str):
            return _err_text("METHOD_NOT_FOUND", got)
        m, r = got

        head = [
            f"; 文件: {dex.display} (DEX {dex.header.version})",
            f"; 类:   {cd.name}   [{acc_text(cd.access_flags, 'class')}]",
            f"; 方法: {r.name}{r.proto.descriptor}   "
            f"[{acc_text(m.access_flags, 'method')}]",
        ]
        if not m.has_code:
            if m.access_flags & 0x100:
                kind = "native"
            elif m.access_flags & 0x400:
                kind = "abstract"
            else:
                kind = "无 code"
            head.append(
                f"; 该方法没有字节码（{kind}，code_off=0），无可反汇编内容")
            return "\n".join(head)

        ci = dex.code_item(m)
        head.append(
            f"; 代码: code_off=0x{ci.off:x} insns_off=0x{ci.insns_off:x}"
            f" registers={ci.registers_size} ins={ci.ins_size}"
            f" outs={ci.outs_size} tries={ci.tries_size}")
        head.append(
            f"; 规模: {ci.insns_size} code units / {ci.byte_size} 字节")
        head.append(
            "; 列: 0x<方法内字节偏移>(u<code-unit偏移>): "
            "<原始 code unit> | <指令>")

        units = dex.units_of(ci)
        view = _CodeView(dex.tables, ci.insns_off)
        body = [_render_insn(i)
                for i in bytecode.disassemble(view, units, ci.insns_size)]
        return "\n".join(head + body)
    except DexError as exc:
        return _err_text(exc.code, exc.message)
    finally:
        src.close()


def _render_insn(insn) -> str:
    """把一条 Insn 渲染成一行文本；payload 明细作为后续缩进行。"""
    label = f"0x{insn.byte_off:04x}(u{insn.unit_off:04x}):"
    text = insn.mnemonic
    if insn.operands:
        text += " " + insn.operands
    # 只有"引用类"指令才把符号名作为注释追上去（否则每条常量指令都多一坨）
    if insn.ref_text and insn.ref_idx >= 0 and insn.ref_kind != "":
        text += f" // {insn.ref_text}"
    if insn.note:
        text += f"   ; NOTE: {insn.note}"
    line = f"{label} {insn.raw_hex:<24} | {text}"
    if insn.detail:
        line += "\n" + "\n".join(f"            {d}" for d in insn.detail)
    return line


def dex_callers(path: str, class_name: str, method_name: str,
                overload: str = "") -> list[dict]:
    """静态扫描「谁调用了这个方法」。

    做法：把每个 dex 的所有方法体按指令格式走一遍，凡 invoke-virtual/super/
    direct/static/interface（含 /range 与 038 的 invoke-polymorphic/custom）
    指向目标 method_idx 的，就算一个调用点。

    返回按调用次数降序的列表，每项：
        caller           Lcom/x/Y;->foo(I)V（便于直接阅读）
        caller_class / caller_method / caller_proto
        invoke_kind      invoke-virtual 等
        call_count       该调用者里命中多少次
        sites            [{insn_off, insn_byte_off}] 每个调用点的偏移
        dex              调用者所在的 dex 条目

    注意：
      · 这是**静态**扫描，反射/动态代理/JNI 回调都扫不到（会把这一点写在文档里）。
      · 会扫描 apk 里的全部 dex（跨 dex 调用很常见），因此大 apk 会慢一些。
      · 没有任何调用者时返回 []，不是错误。
    """
    try:
        src = _open_source(path)
    except DexError as exc:
        return [_err(exc.code, exc.message)]
    # (2) 第二次修改（2026-11-26）
    # bug 原因：① 多 dex 场景下若某个 dex 损坏，out 里会追加不含 call_count 的错误字典，
    #           末尾 `out.sort(key=lambda x: -x["call_count"])` 会直接抛 KeyError 崩溃；
    #           ② 外层 _resolve_method 以及内层 _target_method_indices / iter_method_code
    #           抛出的 DexError 未被捕获，违反不抛异常契约。
    # 解决方案：① 排序键改为 `(1 if "error" in x else 0, -x.get("call_count", 0))`，
    #           错误条目排在末尾且绝不 KeyError；② 内外层完整捕获 DexError 转 _err(...)。
    try:
        found = _find_class(src, _norm_class(class_name))
        if isinstance(found, str):
            return [_err("CLASS_NOT_FOUND", found)]
        dex0, cd = found
        got = _resolve_method(dex0, cd, method_name, overload)
        if isinstance(got, str):
            return [_err("METHOD_NOT_FOUND", got)]
        _target_m, target_r = got
        target_cls = cd.name
        target_name = target_r.name
        target_proto = target_r.proto.descriptor

        out: list[dict] = []
        for entry in src.entries:
            try:
                dex = _load_dex(src, entry)
                idxs = set(_target_method_indices(dex, target_cls, target_name,
                                                  target_proto))
                if not idxs:
                    continue
                for cdd, mm, ci in dex.iter_method_code():
                    try:
                        units = dex.units_of(ci)
                    except DexError:
                        continue
                    hits: dict[int, dict] = {}
                    for unit_off, op, ref_idx in bytecode.iter_invokes(
                            units, ci.insns_size):
                        if ref_idx not in idxs:
                            continue
                        kind = bytecode.OPCODES[op][0]
                        h = hits.get(ref_idx)
                        if h is None:
                            h = hits[ref_idx] = {"kind": kind, "sites": []}
                        h["sites"].append({
                            "insn_off": unit_off,
                            "insn_byte_off": unit_off * 2,
                            "invoke_kind": kind,
                        })
                    if not hits:
                        continue
                    try:
                        caller_ref = dex.tables.method(mm.method_idx)
                    except DexError:
                        continue
                    sites = [s for h in hits.values() for s in h["sites"]]
                    out.append({
                        "caller": f"{cdd.name}->{caller_ref.name}"
                                  f"{caller_ref.proto.descriptor}",
                        "caller_class": cdd.name,
                        "caller_method": caller_ref.name,
                        "caller_proto": caller_ref.proto.descriptor,
                        "invoke_kind": next(iter(hits.values()))["kind"],
                        "call_count": len(sites),
                        "sites": sites,
                        "dex": entry,
                    })
            except DexError as exc:
                out.append(_err(exc.code, exc.message, dex=entry))
                continue
        out.sort(key=lambda x: (1 if "error" in x else 0, -x.get("call_count", 0)))
        return out
    except DexError as exc:
        return [_err(exc.code, exc.message)]
    finally:
        src.close()


def _target_method_indices(dex: DexFile, class_desc: str, name: str,
                           proto_desc: str) -> list[int]:
    """在该 dex 的 method_ids 里找出 (类, 名, 原型) 全部匹配的索引。

    只用一次 method_ids 线性扫描 + 便宜的 class_idx 比较，不做全表符号解析
    （一张 method_ids 可能有十几万条，逐条解析三张表会慢一个数量级）。

    读法注意：method_id_item 是 8 字节 —— u2 class_idx / u2 proto_idx /
    u4 name_idx，**三个字段全部小端**。

    (1) 第一次修改（2026-11-18）
        bug 原因：class_idx 曾按大端解（(b0<<8)|b1），而 proto_idx/name_idx
                  用 int.from_bytes('little')。同一结构体里两种字节序混用，
                  结果 class_idx 几乎永远对不上：
                  实测 RecyclerView$3 的 <init>()V，小端匹配 2 条、
                  大端匹配 **0 条**，于是 dex_callers 静默返回 []——
                  而反汇编里明明显示有这条 invoke。
                  更隐蔽的是：没有任何异常，只是"查不到调用者"。
        解决方案：class_idx 也按小端读（b0 | b1<<8）。
    """
    type_idx = dex.type_index_of(class_desc)
    if type_idx is None:
        return []
    h = dex.header
    if h.method_ids_size == 0:
        return []
    out: list[int] = []
    data = dex.tables.data
    base = h.method_ids_off
    for i in range(h.method_ids_size):
        off = base + i * 8
        class_idx = data[off] | (data[off + 1] << 8)      # 小端
        if class_idx != type_idx:
            continue
        name_idx = int.from_bytes(data[off + 4:off + 8], "little")
        try:
            if dex.tables.string(name_idx) != name:
                continue
            proto_idx = int.from_bytes(data[off + 2:off + 4], "little")
            if dex.tables.proto(proto_idx).descriptor != proto_desc:
                continue
        except DexError:
            continue
        out.append(i)
    return out
