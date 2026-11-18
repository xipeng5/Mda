"""DEX 纯静态解析（只用标准库，不依赖第三方）。

模块划分：
    reader.py    字节读取 / ULEB128·SLEB128 / 路径 -> 多个 dex 字节块（.dex 与 .apk）
    mutf8.py     MUTF-8 解码（坑 1：utf16_size 是 UTF-16 码元数，不是字节数）
    header.py    header_item 与 6 张 id 表 / class_def / access_flags
    code.py      class_data_item（坑 2：idx 是增量）/ code_item
    bytecode.py  指令格式表（坑 3：变长 code unit 数）+ 反汇编（坑 4：payload 上下文）
    api.py       对外四个 API + 多 dex 合并 + LRU 缓存

对外用法：
    from server.core.dex import dex_classes, dex_methods, dex_disasm, dex_callers
"""
from __future__ import annotations

from .api import (
    _CACHE,
    DexFile,
    clear_cache,
    dex_callers,
    dex_classes,
    dex_disasm,
    dex_methods,
)
from .reader import DexError

__all__ = [
    "DexError",
    "DexFile",
    "clear_cache",
    "dex_classes",
    "dex_methods",
    "dex_disasm",
    "dex_callers",
]
