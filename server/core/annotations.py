"""注释/重命名持久化（通用能力）。

## 解决什么问题

`set_comment` / `rename_function` 只改内存里的 Session，
mda 重启后全部丢失。Ghidra 存到项目、IDA 存到 idb——
mda 缺这个能力。

本模块把它们持久化到工作区的 `.dsh/mda_annotations/<so名>.json`，
下次 load_so 时自动恢复。

## 为什么是通用能力

纯存储层，不含任何具体 so 特征。按 so 的文件名（去路径）分文件，
不依赖样本内容。

## 用法

    annotation_store.save(so_name, addr, comment=..., rename=...)
    annotation_store.load(so_name) → {addr: {...}}
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_STORE_DIR = Path(".dsh/mda_annotations")


class AnnotationStore:
    """so 注释/重命名的持久化存储。"""

    def __init__(self, root: str | None = None):
        self.root = Path(root) if root else Path.cwd()
        self.dir = self.root / _STORE_DIR

    def _path(self, so_name: str) -> Path:
        # 只取 basename，避免路径里的 / 变成子目录
        safe = os.path.basename(str(so_name)).replace("..", "_")
        return self.dir / (safe + ".json")

    def load(self, so_name: str) -> dict:
        p = self._path(so_name)
        if not p.exists():
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:                                 # noqa: BLE001
            return {}

    def save(self, so_name: str, addr: int, *, comment: str | None = None,
             rename: str | None = None) -> dict:
        data = self.load(so_name)
        key = hex(int(addr))
        item = data.get(key, {})
        if comment is not None:
            item["comment"] = comment
        if rename is not None:
            item["rename"] = rename
        item["updated"] = True
        data[key] = item
        p = self._path(so_name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return data

    def apply(self, so, so_name: str) -> int:
        """把持久化的注释/重命名应用到刚加载的 so。返回应用条数。"""
        data = self.load(so_name)
        n = 0
        for key, item in data.items():
            try:
                addr = int(key, 16)
            except (ValueError, TypeError):
                continue
            fn = so.function_at(addr)
            if fn is None:
                continue
            rename = item.get("rename")
            if rename:
                fn.name = rename
                n += 1
        return n


store = AnnotationStore()
