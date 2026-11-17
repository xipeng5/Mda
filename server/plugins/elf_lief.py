"""基于 LIEF 的 ELF 增强解析插件（通用能力）。

## 为什么用 LIEF

mda 自己的 elf_model 是手写的，加固样本（无节表/损坏节表）上信息不全。
[LIEF](https://github.com/lief-project/LIEF)（Apache-2.0，`pip install lief`）
提供更完整的 ELF 解析：符号、动态符号、重定位、段、动态表。

本插件是**可选增强**——LIEF 没装时给明确提示，不影响 mda 其他功能。

## 提供什么

    - symbols     动态符号表（名字 + 值 + 类型）
    - relocations 重定位表（含 addend）—— 用户找格式串引用需要这个
    - sections/segment 信息
    - 按地址解析：某个地址属于哪个段/符号

## 通用性

纯 ELF 标准解析，不含任何具体 so 特征。
"""
from __future__ import annotations

from pathlib import Path

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "elf_lief"
    description = "基于 LIEF 的 ELF 增强解析：符号/重定位/段（可选依赖）"
    usage = ("args: {so: str, mode: 'symbols'|'relocations'|'segments'|'info'|'resolve', "
             "addr: int|None=None, keyword: str='', limit: int=100}")

    def run(self, session, args: dict):
        try:
            import lief
        except ImportError:
            return {"error": "LIEF 未安装。pip install lief（Apache-2.0，有 wheel）",
                    "code": "LIEF_NOT_INSTALLED"}

        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        path = getattr(so, "path", None)
        if not path or not Path(path).exists():
            return {"error": f"找不到 so 文件：{path}", "code": "NO_FILE"}

        try:
            binary = lief.parse(path)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"LIEF 解析失败：{exc}", "code": "PARSE_FAILED"}

        mode = args.get("mode", "info")
        limit = int(args.get("limit", 100))
        kw = str(args.get("keyword", "")).lower()

        if mode == "info":
            return {"ok": True, "so": so.name,
                    "arch": str(binary.header.machine_type),
                    "is_pie": binary.is_pie,
                    "symbols": len(binary.symbols),
                    "dynamic_symbols": len(binary.dynamic_symbols),
                    "relocations": len(binary.relocations),
                    "segments": len(binary.segments),
                    "sections": len(binary.sections)}

        if mode == "symbols":
            out = []
            for s in list(binary.dynamic_symbols) + list(binary.symbols):
                nm = getattr(s, "name", "") or ""
                if kw and kw not in nm.lower():
                    continue
                out.append({"name": nm, "value": hex(int(s.value)),
                            "size": int(getattr(s, "size", 0) or 0),
                            "type": str(getattr(s, "type", ""))})
                if len(out) >= limit:
                    break
            return {"ok": True, "so": so.name, "mode": mode,
                    "count": len(out), "symbols": out}

        if mode == "relocations":
            addr = args.get("addr")
            target = int(addr) if addr is not None else None
            out = []
            for r in binary.relocations:
                addend = int(getattr(r, "addend", 0) or 0)
                if target is not None and addend != target:
                    continue
                out.append({"address": hex(int(r.address)),
                            "addend": hex(addend),
                            "type": str(getattr(r, "type", "")),
                            "symbol": getattr(r, "symbol", ""),
                            "has_symbol": r.has_symbol if hasattr(r, "has_symbol") else None})
                if len(out) >= limit:
                    break
            return {"ok": True, "so": so.name, "mode": mode,
                    "filter_addend": hex(target) if target is not None else None,
                    "count": len(out), "relocations": out}

        if mode == "segments":
            out = []
            for s in binary.segments:
                out.append({"type": str(s.type), "vaddr": hex(int(s.virtual_address)),
                            "size": int(s.physical_size),
                            "flags": str(getattr(s, "flags", ""))})
            return {"ok": True, "so": so.name, "mode": mode,
                    "count": len(out), "segments": out[:limit]}

        if mode == "resolve":
            addr = args.get("addr")
            if addr is None:
                return {"error": "mode=resolve 需要 addr", "code": "BAD_ARGS"}
            a = int(addr, 16) if isinstance(addr, str) and \
                str(addr).lower().startswith("0x") else int(addr)
            seg = None
            for s in binary.segments:
                lo = int(s.virtual_address)
                if lo <= a < lo + int(s.physical_size):
                    seg = {"type": str(s.type), "vaddr": hex(lo),
                           "size": int(s.physical_size)}
                    break
            sym = None
            best = None
            for s in list(binary.dynamic_symbols) + list(binary.symbols):
                v = int(s.value)
                if v and v <= a and (best is None or v > best):
                    best = v
                    sym = {"name": s.name, "value": hex(v)}
            return {"ok": True, "so": so.name, "addr": hex(a),
                    "segment": seg, "symbol": sym,
                    "note": "symbol 取地址之前最近的符号（可能是上一个函数）"}

        return {"error": f"未知 mode={mode}", "code": "BAD_MODE"}
