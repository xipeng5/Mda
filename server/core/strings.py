"""字符串提取与引用还原。

职责：从只读数据节提取可打印字符串，并反向定位哪些函数引用了它。
这是逆向定位业务逻辑最常用的入口（如 URL、密钥、错误信息）。

依赖 core.elf_model / models。
"""
from __future__ import annotations

import bisect
import re

from server.core.elf_model import SoFile
from server.models import StringRef

# (1) 第一次修改（2026-11-13）：ASCII 可打印 -> 可打印 UTF-8，最小长度 4 -> 2。
# bug 原因（两个缺陷叠在一起，属于同一处扫描逻辑）：
#   ① 旧实现逐字节判 `0x20 <= c < 0x7F` 且 `_MIN_LEN = 4`，非 ASCII 字节一律当
#      终止符、≤3 字符的整类丢弃。实测 libbase.so 237 个数据引用目标里 128 个
#      查不到字符串：其中 32 个是 ≤3 字符的真实常量（"ms"、"]"、", "、"."），
#      50 个含非 ASCII 字节。而 Android 应用里本地化文案、欧洲重音域名带
#      UTF-8 是常态。
#   ② 因为查不到 StringRef，这些引用永远归不到引用者身上——string_refs、
#      伪代码、界面"这个函数引用了哪些字符串"全都漏，且**静默**（只是空列表）。
# 解决方案：
#   · 字符集 = ASCII 可打印 ∪ 合法 UTF-8 多字节序列。按 Unicode 规则排除
#     overlong / 代理项 / 超 U+10FFFF 的编码，并排除 C1 控制符 U+0080..U+009F。
#     规则只依赖 UTF-8 编码本身是否合法，**不针对任何样本做特征判断**，故通用。
#   · 长度：≥2 字符一律收（"ms"、"]"、"== " 都是真实常量）；**单字符只在紧跟
#     NUL 时收**——单字符在二进制里绝大多数是偶然字节，但 `'h'\0 'm'\0 's'\0`
#     这类单位表是真实字符串表，用 NUL 结尾这个客观依据区分，不猜内容。
#   · 全空白（空格 / NBSP / 全角空格）是对齐填充，不算字符串。
# 性能：旧实现是 Python 逐字节循环，新实现用字节级正则走 C 层，一次 finditer
#   同时完成"切段 + 合法性判定"。实测扫描 .rodata：
#     libc.so    2367 条 / 6.2ms  ->  4165 条 / 8.6ms
#     libbase.so  145 条 / 0.5ms  ->   421 条 / 0.8ms
#   增量来自"多提取出 78% 的字符串"这件事本身的逐条解码开销，扫描本身没有
#   数量级变化；反过来在大 .rodata（MB 级）上，原来的逐字节 Python 循环会
#   比正则慢一个数量级（2MB 合成数据实测 141ms vs 8ms/等效按段）。
_MIN_LEN = 2
# 提取的节白名单：只读数据 + 数据，避免扫 .text 产生误报
_STRING_SECTIONS = (".rodata", ".data.rel.ro", ".data")

_ASCII_RANGE = rb"\x20-\x7e"
_UTF8_SEQ = (
    rb"\xc2[\xa0-\xbf]"                  # U+00A0..U+00BF（排除 C1 控制符）
    rb"|[\xc3-\xdf][\x80-\xbf]"          # U+00C0..U+07FF
    rb"|\xe0[\xa0-\xbf][\x80-\xbf]"      # U+0800..U+0FFF（排除 overlong）
    rb"|[\xe1-\xec\xee-\xef][\x80-\xbf]{2}"   # U+1000..U+CFFF / U+E000..U+FFFF
    rb"|\xed[\x80-\x9f][\x80-\xbf]"      # 排除代理项 U+D800..U+DFFF
    rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}"   # U+10000..U+3FFFF
    rb"|[\xf1-\xf3][\x80-\xbf]{3}"       # 其余补充平面
    rb"|\xf4[\x80-\x8f][\x80-\xbf]{2}"   # 上限 U+10FFFF
)
_CHAR = rb"(?:[%s]|%s)" % (_ASCII_RANGE, _UTF8_SEQ)
# 主分支：{_MIN_LEN,} 个字符的连续段；备用分支：单字符且后面紧跟 NUL
_RUN_RE = re.compile(rb"%s{%d,}|%s(?=\x00)"
                     % (_CHAR, _MIN_LEN, _CHAR))


def _extract_printable(data: bytes, base: int) -> list[StringRef]:
    """扫连续可打印字符（ASCII + 合法 UTF-8），遇 NUL/不可打印字节即断开。"""
    out: list[StringRef] = []
    for m in _RUN_RE.finditer(data):
        try:
            text = m.group().decode("utf-8")
        except UnicodeDecodeError:        # 正则已保证合法，兜底不抛
            continue
        # 全空白（空格 / NBSP / 全角空格…）是对齐填充，不是字符串
        if not text.strip():
            continue
        out.append(StringRef(addr=base + m.start(), value=text, section=""))
    return out


class StringAnalyzer:
    """单个 so 的字符串分析器。"""

    def __init__(self, so: SoFile):
        self.so = so
        self._strings: list[StringRef] = []
        self._by_addr: dict[int, StringRef] = {}
        # 地址索引（供二分查找，与 _strings 同步按 addr 升序）
        self._addr_index: list[int] | None = None
        # 每条字符串的字节上界（UTF-8 下与字符数不同，见 build() 里的说明）
        self._end_index: list[int] = []
        self._built = False
        # 引用归并与字符串提取是两个独立步骤，需分开标记。
        # 若复用 _built 会导致「先 build 后 annotate」的调用被跳过归并。
        self._annotated = False

    def build(self) -> None:
        if self._built:
            return
        secs = list(self.so.sections)
        if not secs and getattr(self.so, "_loads", None):
            # 节表损坏的 dump so：无 section，从 PT_LOAD 兜底。
            # 挑非可写段（只读数据大概率在此）；RX 段也含常量故一并扫。
            class _FallbackSec:
                def __init__(self, addr: int, size: int, name: str):
                    self.addr, self.size, self.name = addr, size, name

            for va, end, _off, fl in self.so._loads:
                if not (fl & 0x2):  # 非 W
                    secs.append(_FallbackSec(va, end - va, ""))
        for sec in secs:
            if sec.name and sec.name not in _STRING_SECTIONS:
                continue
            if not sec.name and sec.size > 8 * 1024 * 1024:
                continue  # 兜底段超大（>8MB）跳过，防误扫巨型区间
            data = self.so.read(sec.addr, sec.size)
            if not data:
                continue
            for ref in _extract_printable(data, sec.addr):
                ref.section = sec.name or "(segment)"
                self._strings.append(ref)
        self._by_addr = {s.addr: s for s in self._strings}
        # 按地址排序，UI 展示需要
        self._strings.sort(key=lambda s: s.addr)
        self._addr_index = [s.addr for s in self._strings]
        # (1) 第一次修改（2026-11-13）：同时记下每条字符串的**字节**上界。
        # bug 原因：string_starting_at_or_before 用 `len(s.value)` 当字节长度做
        #           区间包含判断，而 len() 数的是**字符**。支持 UTF-8 之后两者
        #           不再相等（一个汉字 3 字节、1 字符），落在字符串尾部的数据
        #           引用会被判成"不在这个字符串里"，等于又把刚修好的东西漏掉。
        # 解决方案：build 时一次性算好 addr + utf8 字节长度，查询时直接用，
        #           不在热路径上反复 encode。
        self._end_index = [s.addr + len(s.value.encode("utf-8"))
                           for s in self._strings]
        self._built = True

    def all_strings(self) -> list[StringRef]:
        self.build()
        return self._strings

    def string_at(self, addr: int) -> StringRef | None:
        """精确地址查字符串。"""
        self.build()
        return self._by_addr.get(addr)

    def string_starting_at_or_before(self, addr: int) -> StringRef | None:
        """引用可能指向字符串中间（编译器优化），向前最近的一个即起点。

        性能修复：原实现每次线性扫描全部字符串（O(N)）。而
        annotate_refs 会对**每个**数据引用调用一次——libAPSE 级样本
        15756 个引用 × 约 3 万条字符串 = 4.7 亿次迭代，占全量构建
        58 秒的大部分。改为按地址二分（O(log N)）。
        _strings 在 build() 里已按 addr 排序，可用 bisect 直接定位。
        """
        self.build()
        if not self._strings:
            return None
        if self._addr_index is None:
            self._addr_index = [s.addr for s in self._strings]
        if len(self._end_index) != len(self._strings):
            # 兜底：索引与字符串表不同步（例如外部改过 _strings）时就地重建
            self._end_index = [s.addr + len(s.value.encode("utf-8"))
                               for s in self._strings]
        # 找最后一个 addr <= 目标的字符串
        i = bisect.bisect_right(self._addr_index, addr) - 1
        while i >= 0:
            s = self._strings[i]
            # (1) 第一次修改（2026-11-13）：区间上界改成**字节**长度，
            #     与 _end_index 一致；+1 覆盖结尾的 NUL。
            if s.addr <= addr < self._end_index[i] + 1:
                return s
            # 字符串互不重叠且有序：更早的若已结束于 addr 之前，无需再查
            if i == 0 or self._end_index[i - 1] + 1 <= addr:
                break
            i -= 1
        return None

    def search(self, keyword: str, limit: int = 100) -> list[StringRef]:
        """子串搜索，大小写不敏感。

        BUG-9 修复：limit<=0 视为"不限制"会与 0 语义矛盾且易产生
        意外全量输出——统一约定：limit<=0 返回空列表，调用方显式
        传大数表示不限制。
        """
        self.build()
        if limit <= 0:
            return []
        kw = keyword.lower()
        return [s for s in self._strings if kw in s.value.lower()][:limit]

    def annotate_refs(self, data_refs: dict[int, list[int]]) -> None:
        """把 xref 的 data_refs 归并到字符串的 referenced_by。

        引用可能指向字符串中间，先归一到字符串起点。
        已归并过时直接返回（幂等），避免重复追加。
        """
        if self._annotated:
            return
        self.build()
        for addr, sites in data_refs.items():
            s = self.string_starting_at_or_before(addr)
            if s is not None:
                s.referenced_by.extend(sites)
        for s in self._strings:
            s.referenced_by = sorted(set(s.referenced_by))
        self._annotated = True
