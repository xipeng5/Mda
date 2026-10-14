"""字符串提取与引用还原。

职责：从只读数据节提取可打印字符串，并反向定位哪些函数引用了它。
这是逆向定位业务逻辑最常用的入口（如 URL、密钥、错误信息）。

依赖 core.elf_model / models。
"""
from __future__ import annotations

import bisect

from core.elf_model import SoFile
from models import StringRef

# 最小字符串长度，短于该值多为对齐填充或单字符常量
_MIN_LEN = 4
# 提取的节白名单：只读数据 + 数据，避免扫 .text 产生误报
_STRING_SECTIONS = (".rodata", ".data.rel.ro", ".data")


def _extract_printable(data: bytes, base: int) -> list[StringRef]:
    """扫连续可打印 ASCII，遇 NUL 结尾。"""
    out: list[StringRef] = []
    start = 0
    n = len(data)
    for i in range(n):
        c = data[i]
        is_print = 0x20 <= c < 0x7F
        if is_print:
            continue
        # 遇到结束符，结算这一段
        length = i - start
        if length >= _MIN_LEN and data[start - 1 if start else 0] if False else length >= _MIN_LEN:
            raw = data[start:i]
            try:
                text = raw.decode("ascii")
            except UnicodeDecodeError:
                start = i + 1
                continue
            out.append(StringRef(addr=base + start, value=text, section=""))
        start = i + 1
    return out


class StringAnalyzer:
    """单个 so 的字符串分析器。"""

    def __init__(self, so: SoFile):
        self.so = so
        self._strings: list[StringRef] = []
        self._by_addr: dict[int, StringRef] = {}
        # 地址索引（供二分查找，与 _strings 同步按 addr 升序）
        self._addr_index: list[int] | None = None
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
        # 找最后一个 addr <= 目标的字符串
        i = bisect.bisect_right(self._addr_index, addr) - 1
        while i >= 0:
            s = self._strings[i]
            if s.addr <= addr < s.addr + len(s.value) + 1:
                return s
            # 字符串互不重叠且有序：更早的若已结束于 addr 之前，无需再查
            if i == 0 or self._strings[i - 1].addr + len(self._strings[i - 1].value) + 1 <= addr:
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
