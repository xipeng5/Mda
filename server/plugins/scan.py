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

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "scan"
    description = "批量指令扫描：bl_call/adrp_add/const/string_ref"
    usage = ("args: {so: str, kind: 'bl_call|adrp_add|const|string_ref', "
             "target: str|int|None=None, limit: int=200}")

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

        target = args.get("target")
        if target is not None:
            target = int(str(target), 16) if isinstance(target, str) and \
                     str(target).lower().startswith("0x") else int(target)
        limit = int(args.get("limit", 200))
        dis = Disassembler(so)

        results = []
        scanned = 0
        for sec in getattr(so, "sections", []):
            if not getattr(sec, "is_exec", False) or not sec.size:
                continue
            insns = dis.disasm_range(sec.addr, sec.size)
            scanned += len(insns)
            for i in insns:
                text = i.text or ""
                if kind == "bl_call":
                    t = getattr(i, "call_target", None)
                    if t is not None:
                        results.append({"addr": hex(i.addr), "target": hex(int(t)),
                                        "insn": text})
                elif kind == "adrp_add":
                    r = getattr(i, "ref_addr", None)
                    if r is not None:
                        results.append({"addr": hex(i.addr),
                                        "computed": hex(int(r)), "insn": text})
                elif kind == "const":
                    if target is None:
                        return {"error": "kind=const 需要 target", "code": "BAD_ARGS"}
                    m = re.search(r"#(0x[0-9a-f]+|-?\d+)", text)
                    if m:
                        v = int(m.group(1), 16) if m.group(1).startswith("0x") \
                            else int(m.group(1))
                        if v == target:
                            results.append({"addr": hex(i.addr), "insn": text})
                elif kind == "string_ref":
                    r = getattr(i, "ref_addr", None)
                    if target is not None and r is not None and int(r) == target:
                        results.append({"addr": hex(i.addr), "insn": text})
                else:
                    return {"error": f"未知 kind={kind}", "code": "BAD_KIND"}

        return {
            "ok": True, "so": so.name, "kind": kind,
            "scanned_insns": scanned,
            "count": len(results),
            "results": results[:limit],
            "truncated": len(results) > limit,
            "note": "复用 mda 的 Disassembler 语义识别（ref_addr/call_target）",
        }
