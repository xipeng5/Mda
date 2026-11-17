"""版本 Diff 插件（通用能力）。

## 解决什么问题

同一 so 的不同版本间，签名核心代码一定变（对抗分析），无关代码基本不变。
对比两个版本能直接缩小"哪个函数是核心"的范围。
用户手上没有两个版本时也能用本工具对比任意两个 so。

## 做法

    - 对两个 so 建"函数指纹"：入口相对偏移 + 指令序列规范化哈希
      （把 bl 目标/adrp 目标归一化，避免基址变化造成误判）
    - 按名字 + 指纹匹配
    - 输出：新增 / 删除 / 修改的函数，以及修改函数内的常量差异

## 为什么是通用能力

纯结构化对比，不含任何具体 so / 版本 / 函数特征。
两个 so 都是调用方传入的。
"""
from __future__ import annotations

import hashlib
import re
import struct

from server.core.plugins import PluginBase


def _norm_insn(text: str) -> str:
    """归一化指令文本：去掉立即数里的具体地址（保留操作码与结构）。"""
    text = re.sub(r"#0x[0-9a-f]{4,}", "#IMM", text)
    text = re.sub(r"\b0x[0-9a-f]{6,}\b", "ADDR", text)
    return re.sub(r"\s+", " ", text).strip()


class Plugin(PluginBase):
    name = "diff_so"
    description = "两个 so 的函数级 diff：新增/删除/修改 + 常量差异"
    usage = "args: {so_a: str, so_b: str, min_size: int=16, limit: int=100}"

    def run(self, session, args: dict):
        a_name, b_name = args.get("so_a"), args.get("so_b")
        if not a_name or not b_name:
            return {"error": "需要 so_a 与 so_b", "code": "BAD_ARGS"}
        try:
            sa, sb = session.get(a_name), session.get(b_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        from server.core.disasm import Disassembler

        min_size = int(args.get("min_size", 16))
        limit = int(args.get("limit", 100))

        fa = self._fingerprints(sa, Disassembler, min_size)
        fb = self._fingerprints(sb, Disassembler, min_size)

        # 按函数入口相对偏移匹配（更稳），名字作辅助
        by_off_a = {v["offset"]: v for v in fa}
        by_off_b = {v["offset"]: v for v in fb}
        added = [v for o, v in by_off_b.items() if o not in by_off_a]
        removed = [v for o, v in by_off_a.items() if o not in by_off_b]
        modified = []
        for off, va in by_off_a.items():
            vb = by_off_b.get(off)
            if not vb:
                continue
            if va["hash"] != vb["hash"] or va["size"] != vb["size"]:
                const_a = set(va["consts"])
                const_b = set(vb["consts"])
                modified.append({
                    "offset": hex(off),
                    "name_a": va["name"], "name_b": vb["name"],
                    "size_a": va["size"], "size_b": vb["size"],
                    "consts_added": [hex(x) for x in sorted(const_b - const_a)][:10],
                    "consts_removed": [hex(x) for x in sorted(const_a - const_b)][:10],
                })

        added.sort(key=lambda x: x["offset"])
        removed.sort(key=lambda x: x["offset"])
        modified.sort(key=lambda x: x["offset"])
        return {
            "ok": True,
            "so_a": sa.name, "so_b": sb.name,
            "stats": {"a": len(fa), "b": len(fb),
                      "added": len(added), "removed": len(removed),
                      "modified": len(modified)},
            "added": added[:limit],
            "removed": removed[:limit],
            "modified": modified[:limit],
            "note": ("按函数入口相对偏移匹配（不受 ASLR 影响），"
                     "指令序列归一化后算哈希；常量差异另行列出。"),
        }

    def _fingerprints(self, so, Disassembler, min_size):
        base = min([s.addr for s in getattr(so, "sections", [])] or [0])
        dis = Disassembler(so)
        out = []
        for fn in so.functions.values():
            if not fn.size or fn.size < min_size:
                continue
            insns = dis.disasm_range(fn.addr, fn.size)
            if not insns:
                continue
            norm = "\n".join(_norm_insn(i.text) for i in insns)
            h = hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:16]
            # 收集代码里的 4 字节常量（mov 立即数等）
            consts = []
            for i in insns:
                m = re.search(r"#(0x[0-9a-f]{4,8})", i.text or "")
                if m:
                    try:
                        v = int(m.group(1), 16)
                        if v not in consts:
                            consts.append(v)
                    except ValueError:
                        pass
            out.append({
                "offset": fn.addr - base,
                "addr": fn.addr,
                "name": fn.name or f"sub_{fn.addr:x}",
                "size": fn.size,
                "hash": h,
                "consts": consts,
            })
        return out
