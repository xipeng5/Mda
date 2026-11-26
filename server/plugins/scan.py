"""批量指令扫描插件（通用能力）。

## 解决什么问题

使用者反复自己写 capstone 脚本循环扫 so（BL 调用点、adrp+add、常量）。
本插件把这些常见扫描做成统一工具：

    - bl_call   扫所有 bl 指令，给出目标
    - adrp_add  扫所有 adrp+add 组合，给出计算出的地址
    - const     扫所有含指定常量的指令
    - string_ref 扫所有引用某地址的指令（adrp+add/ldr）

## 为什么是通用能力

四种扫描都是标准指令模式，目标常量/地址由调用方传入，
不含任何具体样本特征。
"""
from __future__ import annotations

import re

from server.core.addr import parse_addr
from server.core.plugins import PluginBase


def _parse_target(raw):
    """解析目标地址/常量（兼容正负十六进制与十进制），非法返回 None。"""
    val = parse_addr(raw)
    if val is not None:
        return val
    if isinstance(raw, str):
        s = raw.strip()
        if s.lower().startswith("-0x"):
            try:
                return int(s, 16)
            except ValueError:
                return None
    return None


class Plugin(PluginBase):
    name = "scan"
    description = "批量指令扫描：bl_call/adrp_add/const/string_ref"
    usage = ("args: {so: str, kind: 'bl_call|adrp_add|const|string_ref', "
             "target: str|int|None=None, limit: int=200}")


    def _exec_ranges(self, so):
        """(1) 可执行区域：优先 exec_regions()（PT_LOAD 兜底），
        无节表/节表被抹的加固样本也能扫到。见 elf_model.exec_regions 的注释。

        bug 原因：四个插件只遍历 so.sections，而加固样本的节表常被抹
                  （is_exec 全 False），导致恒返回 0 且**无任何警告**。
                  实测 libDexHelper_patched_full.so：5 个节全不可执行，
                  但 exec_regions() 有 0x4ca0 字节可执行代码，
                  四个插件全部 count=0/ok=true —— 最该分析的样本上静默失效。
        解决方案：改用 exec_regions() 兜底。
        """
        out = []
        for s in getattr(so, "sections", []):
            if getattr(s, "is_exec", False) and getattr(s, "size", 0):
                out.append((s.addr, s.size))
        if not out:
            for va, end, _off, _fl in getattr(so, "exec_regions", lambda: [])():
                if end > va:
                    out.append((va, end - va))
        return out

    def run(self, session, args: dict):
        so_name = args.get("so")
        kind = args.get("kind", "bl_call")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        from server.core.disasm import Disassembler

        # (3) 第三次修改（2026-11-26）
        # bug 原因：1) adrp_add 未过滤 is_call/is_jump，导致把 bl/b 也混进结果；
        #           2) const 正则不支持负十六进制且仅用 re.search 只查首个立即数；
        #           3) string_ref 缺 target 时未返回 BAD_ARGS；
        #           4) target 解析未用 parse_addr，且未捕获非 ARM64 的 ValueError。
        # 解决方案：提前校验 kind/target（使用 _parse_target），捕获非 ARM64 返 UNSUPPORTED_ARCH；
        #           adrp_add 排除 is_call/is_jump；const 用 findall 匹配正负十六进制/十进制立即数。
        if kind not in ("bl_call", "adrp_add", "const", "string_ref"):
            return {"ok": False, "error": f"未知 kind={kind}", "code": "BAD_KIND"}

        raw_target = args.get("target")
        target = None
        if raw_target is not None:
            target = _parse_target(raw_target)
            if target is None:
                return {"ok": False, "code": "BAD_ADDR",
                        "error": f"非法 target 参数：{raw_target!r}"}
        if kind in ("const", "string_ref") and target is None:
            return {"ok": False, "error": f"kind={kind} 需要 target", "code": "BAD_ARGS"}

        limit = int(args.get("limit", 200))
        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}

        results = []
        scanned = 0
        ranges = self._exec_ranges(so)
        if not ranges:
            return {"ok": False, "code": "NOTHING_SCANNED",
                    "error": "该 so 没有可执行区域（节表与 PT_LOAD 都为空）"}
        for _rva, _rsz in ranges:
            insns = dis.disasm_range(_rva, _rsz)
            scanned += len(insns)
            for i in insns:
                text = i.text or ""
                if kind == "bl_call":
                    # (2) 用 is_call 而非 call_target：后者对 b/cbz 等
                    #     跳转也填值，实测放大 2.41 倍（1381 vs 573）
                    # (4) 第四次修改（2026-11-26）
                    #     bug 原因：disasm 将间接调用 blr 正确归为 is_call=True（call_target=None）后，
                    #               这里 if t is not None 把 blr 过滤掉，导致 bl_call 总数少于 is_call 数。
                    #     解决方案：保留间接调用条目（target=None, indirect=True），使 scan 与 is_call 口径完全一致。
                    if not getattr(i, "is_call", False):
                        continue
                    t = getattr(i, "call_target", None)
                    if t is not None:
                        results.append({"addr": hex(i.addr), "target": hex(int(t)),
                                        "insn": text})
                    else:
                        results.append({"addr": hex(i.addr), "target": None,
                                        "indirect": True, "insn": text})
                elif kind == "adrp_add":
                    if getattr(i, "is_call", False) or getattr(i, "is_jump", False):
                        continue
                    r = getattr(i, "ref_addr", None)
                    if r is not None:
                        results.append({"addr": hex(i.addr),
                                        "computed": hex(int(r)), "insn": text})
                elif kind == "const":
                    for raw_imm in re.findall(r"#(-?0x[0-9a-fA-F]+|-?\d+)", text):
                        if int(raw_imm, 0) == target:
                            results.append({"addr": hex(i.addr), "insn": text})
                            break
                elif kind == "string_ref":
                    if getattr(i, "is_call", False) or getattr(i, "is_jump", False):
                        continue
                    r = getattr(i, "ref_addr", None)
                    if r is not None and int(r) == target:
                        results.append({"addr": hex(i.addr), "insn": text})

        return {
            "ok": True, "so": so.name, "kind": kind,
            "scanned_insns": scanned,
            "count": len(results),
            "results": results[:limit],
            "truncated": len(results) > limit,
            "note": "复用 mda 的 Disassembler 语义识别（ref_addr/call_target）",
        }
