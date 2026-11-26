"""本地 so 指纹库（用户自建的样本经验库，不含任何内置特征）。

## 重要声明

这是**用户自己积累的分析结果数据库**。库初始为空，不含任何内置特征数据。
禁止把任何具体 App / so / 样本的特征、地址、常量、偏移写进本文件或默认数据。
所有指纹全靠调用方通过 save 动作逐条积累。

## 解决什么问题

同类 so 的分析经验（算法函数地址、签名头、vtable、反 hook 手段等）如果每次都从零开始，
会重复几十轮试错。把用户确认过的分析结果按 so 指纹（size + sha256）存起来，
下次遇到同类 so 先 match 命中历史经验，可把试错轮数从几百轮压缩到几十轮。

## 持久化

JSON 文件：~/.mda/fingerprints.json，第一次使用时自动创建目录。

## 动作

    save   保存指纹（同名需 force:true 才覆盖，否则返回 would_overwrite:true）
    list   列出所有指纹摘要
    query  按 name 取完整指纹
    match  按 path / module_size / sha256 找最匹配的指纹，给 high/medium/low 置信度

## 用法

plugin_run(name="so_fingerprint", args={"action": "list"})
plugin_run(name="so_fingerprint", args={"action": "save", "name": "libfoo-1.2",
    "path": "/abs/path/libfoo.so", "features": {"algo_addrs": {...}, "sig_headers": [...]}})
plugin_run(name="so_fingerprint", args={"action": "match", "path": "/abs/path/libfoo.so"})
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from server.core.plugins import PluginBase

# 指纹库路径：用户主目录下，只在用到时创建
_DB_PATH = Path.home() / ".mda" / "fingerprints.json"


def _load_db():
    """用途：读取指纹库 JSON；文件不存在或结构异常时返回空库。"""
    if not _DB_PATH.exists():
        return {"fingerprints": {}}
    try:
        data = json.loads(_DB_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), dict):
            return {"fingerprints": {}}
        return data
    except Exception:                                        # noqa: BLE001
        return {"fingerprints": {}}


def _save_db(data):
    """用途：把指纹库写回 JSON，自动创建 ~/.mda 目录。"""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DB_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _sha256_of(path):
    """用途：计算文件 SHA-256；路径无效或读失败返回 None。"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:                                        # noqa: BLE001
        return None


def _size_of(path):
    """用途：取文件大小（字节）；路径无效返回 None。"""
    try:
        return os.path.getsize(path)
    except Exception:                                        # noqa: BLE001
        return None


class Plugin(PluginBase):
    name = "so_fingerprint"
    description = "本地 so 指纹库（用户自建样本经验库，无内置特征）"
    usage = ("args: {action:'save'|'list'|'query'|'match', name:str, path:str|None=None, "
             "module_size:int|None=None, features:dict|None=None, limit:int=20, "
             "sha256:str|None=None, force:bool=False}")

    def run(self, session, args):
        """用途：插件入口——按 action 分派到 save / list / query / match。"""
        action = str(args.get("action") or "list").lower()
        if action == "save":
            return self._save(args)
        if action == "list":
            return self._list(args)
        if action == "query":
            return self._query(args)
        if action == "match":
            return self._match(args)
        return {"ok": False, "error": "未知 action: %s" % action,
                "code": "BAD_ACTION"}

    def _save(self, args):
        """用途：保存一条指纹；同名未 force 时先返回 would_overwrite:true 要求调用方确认。

        (1) 第一次修改（2026-11-18）：覆盖时继承旧定位信息。
            bug 原因：force 覆盖若只传 features 不传 path/module_size，会把已有的
                     sha256/module_size 清成 None，导致之后 match 从 high/medium
                     退化成 low——用户只想更新分析结果，却丢了样本定位信息。
            解决方案：新记录缺省字段从同名旧指纹继承，只有显式传入或给了 path 才覆盖。
        """
        name = args.get("name")
        if not name:
            return {"ok": False, "error": "save 需要 name", "code": "BAD_ARGS"}
        features = args.get("features")
        if not isinstance(features, dict):
            return {"ok": False, "error": "save 需要 features（任意 JSON 对象）",
                    "code": "BAD_ARGS"}
        # (2) 第二次修改（2026-11-26）
        # bug 原因：1) save 传入不存在的 path 时未校验路径有效性，静默保存了 sha256/size 为 None 的空指纹；
        #           2) match/save 未对 sha256 做小写归一，传入大写 SHA256 时匹配失败。
        # 解决方案：save 传入 path 时先校验文件存在，不存在返 NO_FILE；save 与 match 均将 sha256 归一为小写。
        path = args.get("path")
        if path:
            if not os.path.isfile(path):
                return {"ok": False, "error": f"找不到文件：{path}", "code": "NO_FILE"}
            sha = _sha256_of(path)
        else:
            raw_sha = args.get("sha256")
            sha = str(raw_sha).strip().lower() if raw_sha is not None and str(raw_sha).strip() else None
        size = args.get("module_size")
        if size is None and path:
            size = _size_of(path)

        db = _load_db()
        old = db["fingerprints"].get(name) or {}
        if name in db["fingerprints"] and not args.get("force"):
            return {
                "ok": True, "action": "save", "would_overwrite": True,
                "name": name,
                "existing": self._summary(name, db["fingerprints"][name]),
                "note": "同名指纹已存在；确认覆盖请加 force:true",
            }
        rec = {
            "name": name,
            "module_size": size if size is not None else old.get("module_size"),
            "sha256": sha if sha is not None else old.get("sha256"),
            "features": features,
        }
        db["fingerprints"][name] = rec
        _save_db(db)
        return {
            "ok": True, "action": "save",
            "saved": self._summary(name, rec),
            "note": "已保存；库初始为空，全部由用户积累，无内置特征",
        }

    def _list(self, args):
        """用途：列出所有指纹摘要（name/module_size/sha256前16/features 的 key 列表）。"""
        db = _load_db()
        limit = int(args.get("limit", 20))
        items = [self._summary(n, r) for n, r in db["fingerprints"].items()]
        return {"ok": True, "action": "list", "count": len(items),
                "total": len(items), "items": items[:limit]}

    def _query(self, args):
        """用途：按 name 取回完整指纹（含全部 features）。"""
        name = args.get("name")
        db = _load_db()
        rec = db["fingerprints"].get(name)
        if rec is None:
            return {"ok": True, "action": "query", "found": False, "name": name,
                    "note": "未找到；可用 list 查看现有指纹"}
        return {"ok": True, "action": "query", "found": True, "fingerprint": rec}

    def _match(self, args):
        """用途：按 path/module_size/sha256 找最匹配指纹，size+sha 全同=high，仅一项同=medium，都不同给最近的=low。"""
        path = args.get("path")
        if path:
            if not os.path.isfile(path):
                return {"ok": False, "error": f"找不到文件：{path}", "code": "NO_FILE"}
            sha = _sha256_of(path)
        else:
            raw_sha = args.get("sha256")
            sha = str(raw_sha).strip().lower() if raw_sha is not None and str(raw_sha).strip() else None
        if sha is not None:
            sha = sha.strip().lower()
        size = args.get("module_size")
        if size is None and path:
            size = _size_of(path)
        if sha is None and size is None:
            return {"ok": False, "error": "match 需要 path 或 sha256 或 module_size",
                    "code": "BAD_ARGS"}

        db = _load_db()
        limit = int(args.get("limit", 20))
        rank = {"high": 0, "medium": 1, "low": 2}
        cands = []
        for n, r in db["fingerprints"].items():
            size_same = size is not None and r.get("module_size") == size
            rec_sha = (str(r.get("sha256")).strip().lower()
                       if r.get("sha256") is not None else None)
            sha_same = sha is not None and rec_sha == sha
            if size_same and sha_same:
                conf = "high"
            elif size_same or sha_same:
                conf = "medium"
            else:
                conf = "low"
            rsize = r.get("module_size")
            try:
                diff = abs(int(size) - int(rsize)) if (size is not None and rsize is not None) else -1
            except (TypeError, ValueError):
                diff = -1
            cands.append({
                "name": n,
                "confidence": conf,
                "size_match": size_same,
                "sha256_match": sha_same,
                "size_diff": diff,
                "fingerprint": self._summary(n, r),
            })
        cands.sort(key=lambda c: (rank[c["confidence"]],
                                  c["size_diff"] if c["size_diff"] >= 0 else 1 << 62))
        top = cands[:limit] if cands else []
        return {
            "ok": True, "action": "match",
            "query": {"path": path, "module_size": size, "sha256": sha},
            "count": len(top), "candidates": top,
            "note": "库初始为空，全部由用户 save 积累；无内置特征。"
                    "high=size 与 sha256 全同，medium=仅一项同，low=都不匹配但按 size 距离给最近候选。",
        }

    @staticmethod
    def _summary(name, rec):
        """用途：生成指纹摘要（name/module_size/sha256 前 16 位/features 的 key 列表）。"""
        sha = rec.get("sha256") or ""
        feats = rec.get("features") or {}
        return {
            "name": name,
            "module_size": rec.get("module_size"),
            "sha256_16": sha[:16],
            "feature_keys": list(feats.keys()) if isinstance(feats, dict) else [],
        }
