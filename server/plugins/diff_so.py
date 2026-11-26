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

        # (1) 第一次修改（2026-11-26）
        # bug 原因：1) base 只看 sections，无节表样本计算错误；
        #           2) 只按相对偏移匹配，跨版本函数位移时把同一具名函数误报为删除+新增；
        #           3) added/removed 的 offset 为 int、modified 为 hex 串，且按字符串字典序排序；
        #           4) 未捕获非 ARM64 架构下 Disassembler 抛出的 ValueError。
        # 解决方案：base 增加 so._loads 兜底；优先按唯一非匿名函数名匹配，匿名再按偏移匹配；
        #           统一格式化 offset/addr 为 hex 字符串并按数值排序；捕获 ValueError 返 UNSUPPORTED_ARCH。
        try:
            fa = self._fingerprints(sa, Disassembler, min_size)
            fb = self._fingerprints(sb, Disassembler, min_size)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}

        # 1) 优先按唯一非匿名函数名匹配
        name_cnt_a: dict[str, int] = {}
        name_cnt_b: dict[str, int] = {}
        for v in fa:
            if v["is_named"]:
                name_cnt_a[v["name"]] = name_cnt_a.get(v["name"], 0) + 1
        for v in fb:
            if v["is_named"]:
                name_cnt_b[v["name"]] = name_cnt_b.get(v["name"], 0) + 1

        named_a = {v["name"]: v for v in fa if v["is_named"] and name_cnt_a[v["name"]] == 1}
        named_b = {v["name"]: v for v in fb if v["is_named"] and name_cnt_b[v["name"]] == 1}
        matched_a_ids: set[int] = set()
        matched_b_ids: set[int] = set()
        pairs: list[tuple[dict, dict]] = []

        for nm, va in named_a.items():
            vb = named_b.get(nm)
            if vb is not None:
                pairs.append((va, vb))
                matched_a_ids.add(id(va))
                matched_b_ids.add(id(vb))

        # 2) 未按名配对的函数再按相对偏移匹配
        rem_a = {v["offset"]: v for v in fa if id(v) not in matched_a_ids}
        rem_b = {v["offset"]: v for v in fb if id(v) not in matched_b_ids}
        for off, va in rem_a.items():
            vb = rem_b.get(off)
            if vb is not None:
                pairs.append((va, vb))
                matched_a_ids.add(id(va))
                matched_b_ids.add(id(vb))

        def _fmt_entry(v: dict) -> dict:
            """将函数指纹条目格式化为统一 hex 字符串输出。"""
            return {
                "offset": hex(v["offset"]),
                "addr": hex(v["addr"]),
                "name": v["name"],
                "size": v["size"],
                "hash": v["hash"],
            }

        added = [_fmt_entry(v) for v in fb if id(v) not in matched_b_ids]
        removed = [_fmt_entry(v) for v in fa if id(v) not in matched_a_ids]
        modified = []
        for va, vb in pairs:
            if va["hash"] != vb["hash"] or va["size"] != vb["size"]:
                const_a = set(va["consts"])
                const_b = set(vb["consts"])
                item = {
                    "offset": hex(va["offset"]),
                    "name_a": va["name"], "name_b": vb["name"],
                    "size_a": va["size"], "size_b": vb["size"],
                    "consts_added": [hex(x) for x in sorted(const_b - const_a)][:10],
                    "consts_removed": [hex(x) for x in sorted(const_a - const_b)][:10],
                }
                if va["offset"] != vb["offset"]:
                    item["offset_b"] = hex(vb["offset"])
                modified.append(item)

        added.sort(key=lambda x: int(x["offset"], 16))
        removed.sort(key=lambda x: int(x["offset"], 16))
        modified.sort(key=lambda x: int(x["offset"], 16))
        return {
            "ok": True,
            "so_a": sa.name, "so_b": sb.name,
            "stats": {"a": len(fa), "b": len(fb),
                      "added": len(added), "removed": len(removed),
                      "modified": len(modified)},
            "added": added[:limit],
            "removed": removed[:limit],
            "modified": modified[:limit],
            "note": ("优先按非匿名函数名匹配，匿名函数按相对偏移匹配，"
                     "指令序列归一化后算哈希；常量差异另行列出。"),
        }

    def _fingerprints(self, so, Disassembler, min_size):
        loads = getattr(so, "_loads", []) or []
        secs = [s for s in getattr(so, "sections", []) if getattr(s, "size", 0)]
        if loads:
            base = min(a for a, _b, _o, _f in loads)
        elif secs:
            base = min(s.addr for s in secs)
        else:
            base = 0
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
            raw_name = getattr(fn, "name", "") or ""
            is_named = bool(raw_name and not raw_name.startswith("sub_"))
            out.append({
                "offset": fn.addr - base,
                "addr": fn.addr,
                "name": raw_name or f"sub_{fn.addr:x}",
                "is_named": is_named,
                "size": fn.size,
                "hash": h,
                "consts": consts,
            })
        return out
