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

from server.core.addr import parse_addr
from server.core.plugins import PluginBase


def _is_load_segment(seg) -> bool:
    """判断 LIEF 段是否为 PT_LOAD 段。"""
    return str(getattr(seg, "type", "")).endswith("LOAD")


def _unique_symbols(binary) -> list:
    """合并 dynamic_symbols 与 symbols 并去重，避免重复输出同一符号。"""
    seen: set[tuple[str, int, int]] = set()
    result = []
    for sym in list(binary.dynamic_symbols) + list(binary.symbols):
        nm = getattr(sym, "name", "") or ""
        val = int(getattr(sym, "value", 0) or 0)
        sz = int(getattr(sym, "size", 0) or 0)
        key = (nm, val, sz)
        if key in seen:
            continue
        seen.add(key)
        result.append(sym)
    return result


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

        # (3) 第三次修改（2026-11-26）
        # bug 原因：lief.parse(path) 遇到无效/非 ELF 文件时返回 None 而非抛异常，
        #           后续访问 binary.header 等属性直接触发 AttributeError。
        # 解决方案：显式校验 binary is None，返回明确的 ELF_PARSE_FAILED 错误。
        try:
            binary = lief.parse(path)
        except Exception as exc:                          # noqa: BLE001
            return {"ok": False, "error": f"LIEF 解析失败：{exc}",
                    "code": "ELF_PARSE_FAILED"}
        if binary is None:
            return {"ok": False, "error": f"LIEF 无法解析 ELF 文件：{path}",
                    "code": "ELF_PARSE_FAILED"}

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
            # (4) 第四次修改（2026-11-26）
            # bug 原因：直接拼接 dynamic_symbols 与 symbols 会把同一符号重复输出两遍。
            # 解决方案：通过 _unique_symbols 按 (name, value, size) 去重后再过滤截断。
            out = []
            for s in _unique_symbols(binary):
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
            # (5) 第五次修改（2026-11-26）
            # bug 原因：1) addr 直接 int(addr) 不支持 "0x..." 字符串且非法值抛异常；
            #           2) symbol 字段直接放 LIEF C++ Symbol 对象导致 JSON 序列化崩溃。
            # 解决方案：addr 改用 parse_addr 并校验合法性；symbol 仅取字符串名。
            addr = args.get("addr")
            target = None
            if addr is not None:
                target = parse_addr(addr)
                if target is None:
                    return {"ok": False, "code": "BAD_ADDR",
                            "error": f"非法地址参数 addr={addr!r}"}
            out = []
            for r in binary.relocations:
                addend = int(getattr(r, "addend", 0) or 0)
                if target is not None and addend != target:
                    continue
                has_sym = bool(getattr(r, "has_symbol", False))
                sym_name = (r.symbol.name if has_sym and getattr(r, "symbol", None)
                            else "")
                out.append({"address": hex(int(r.address)),
                            "addend": hex(addend),
                            "type": str(getattr(r, "type", "")),
                            "symbol": sym_name,
                            "has_symbol": has_sym if hasattr(r, "has_symbol") else None})
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

        if mode == "patch":
            # (1) 静态 patch：按 vaddr 改文件内容，另存新文件。
            #     与运行时 patch（patch_memory 插件）互补：
            #     本项改磁盘文件、持久；那项改内存、重启即恢复。
            # (6) 第六次修改（2026-11-26）
            # bug 原因：1) 遍历全部 segments 未过滤 PT_LOAD，可能错误命中 PT_PHDR/PT_GNU_RELRO；
            #           2) 未校验写入长度是否超出段尾 lo + fsize，可能跨段写坏后续数据；
            #           3) addr 未使用 parse_addr，非法值直接抛异常。
            # 解决方案：仅匹配 PT_LOAD 段、校验 va + len(pdata) <= lo + fsize，并统一用 parse_addr。
            paddr = args.get("addr")
            phex = str(args.get("hex") or "").strip().replace(" ", "")
            out_path = args.get("out") or (str(path) + ".patched")
            if paddr is None or not phex:
                return {"ok": False, "error": "mode=patch 需要 addr 与 hex",
                        "code": "BAD_ARGS"}
            va = parse_addr(paddr)
            if va is None:
                return {"ok": False, "code": "BAD_ADDR",
                        "error": f"非法地址参数 addr={paddr!r}"}
            try:
                pdata = bytes.fromhex(phex)
            except ValueError:
                return {"ok": False, "error": f"hex 不是合法十六进制：{phex[:40]}",
                        "code": "BAD_HEX"}

            # 找虚拟地址落在哪个 PT_LOAD 段，换算文件偏移
            target_seg = None
            file_off = None
            seg_end = None
            for seg in binary.segments:
                if not _is_load_segment(seg):
                    continue
                lo = int(seg.virtual_address)
                # (2) 用 physical_size：vsize 含 .bss（文件里无内容），
                #     用它定界会算到段外去写坏别的段
                fsize = int(seg.physical_size or 0)
                if fsize <= 0:
                    continue
                if lo <= va < lo + fsize:
                    target_seg = seg
                    seg_end = lo + fsize
                    file_off = int(seg.file_offset) + (va - lo)
                    break
            if target_seg is None:
                return {"ok": False, "error": f"0x{va:x} 不在任何 PT_LOAD 段内",
                        "code": "ADDR_NOT_MAPPED"}
            if va + len(pdata) > seg_end:
                return {"ok": False,
                        "error": f"写入超出当前 PT_LOAD 段尾（0x{va + len(pdata):x} > 0x{seg_end:x}）",
                        "code": "OUT_OF_RANGE"}

            blob = bytearray(Path(path).read_bytes())
            if file_off + len(pdata) > len(blob):
                return {"ok": False, "error": "写入越界（超出文件大小）",
                        "code": "OUT_OF_RANGE"}
            old = bytes(blob[file_off:file_off + len(pdata)])
            blob[file_off:file_off + len(pdata)] = pdata
            Path(out_path).write_bytes(bytes(blob))
            return {"ok": True, "so": so.name, "mode": "patch",
                    "vaddr": hex(va), "file_offset": hex(file_off),
                    "old_hex": old.hex(), "new_hex": pdata.hex(),
                    "out_path": out_path,
                    "note": ("改的是**磁盘文件**的副本（持久）。"
                             "运行时 patch 请用 patch_memory 插件。")}

        if mode == "dump":
            # (1) 把某个段按文件布局导出（配合 dumpso 做「磁盘 vs 内存」对比）
            # (7) 第七次修改（2026-11-26）
            # bug 原因：未限制只匹配 PT_LOAD 段，且 addr 未用 parse_addr。
            # 解决方案：只匹配 PT_LOAD 段，并统一用 parse_addr 解析 addr。
            daddr = args.get("addr")
            if daddr is None:
                return {"ok": False, "error": "mode=dump 需要 addr", "code": "BAD_ARGS"}
            dva = parse_addr(daddr)
            if dva is None:
                return {"ok": False, "code": "BAD_ADDR",
                        "error": f"非法地址参数 addr={daddr!r}"}
            for seg in binary.segments:
                if not _is_load_segment(seg):
                    continue
                lo = int(seg.virtual_address)
                if lo <= dva < lo + int(seg.virtual_size or seg.physical_size):
                    content = bytes(seg.content)
                    out_path = args.get("out") or (str(path) + f".seg_{lo:x}.bin")
                    Path(out_path).write_bytes(content)
                    return {"ok": True, "so": so.name, "mode": "dump",
                            "vaddr": hex(lo), "size": len(content),
                            "out_path": out_path}
            return {"ok": False, "error": f"0x{dva:x} 不在任何 PT_LOAD 段内",
                    "code": "ADDR_NOT_MAPPED"}

        if mode == "resolve":
            # (8) 第八次修改（2026-11-26）
            # bug 原因：1) resolve 未限定 PT_LOAD 段；2) 未去重 symbols；3) addr 未用 parse_addr。
            # 解决方案：仅匹配 PT_LOAD 段、复用 _unique_symbols、统一使用 parse_addr。
            addr = args.get("addr")
            if addr is None:
                return {"ok": False, "error": "mode=resolve 需要 addr", "code": "BAD_ARGS"}
            a = parse_addr(addr)
            if a is None:
                return {"ok": False, "code": "BAD_ADDR",
                        "error": f"非法地址参数 addr={addr!r}"}
            seg = None
            for s in binary.segments:
                if not _is_load_segment(s):
                    continue
                lo = int(s.virtual_address)
                seg_sz = int(s.virtual_size or s.physical_size)
                if lo <= a < lo + seg_sz:
                    seg = {"type": str(s.type), "vaddr": hex(lo),
                           "size": int(s.physical_size)}
                    break
            sym = None
            best = None
            for s in _unique_symbols(binary):
                v = int(s.value)
                if v and v <= a and (best is None or v > best):
                    best = v
                    sym = {"name": s.name, "value": hex(v)}
            return {"ok": True, "so": so.name, "addr": hex(a),
                    "segment": seg, "symbol": sym,
                    "note": "symbol 取地址之前最近的符号（可能是上一个函数）"}

        return {"error": f"未知 mode={mode}", "code": "BAD_MODE"}
