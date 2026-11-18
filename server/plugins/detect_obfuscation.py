"""OLLVM 混淆手法识别插件（通用能力）。

## 解决什么问题

使用者在一个加固 so 里人工识别了 6 种混淆手法，每种都有客观的指令特征。
本插件把这些特征做成**参数化检测器**——不硬编码具体地址/寄存器/常量，
只识别结构模式：

  1. retaddr_hijack   bl get_pc; add xN,x0,#imm; br xN  → 实为 b
  2. binary_dispatch   多个 cmp + b.ge/b.hs 顺序比较     → switch 分派
  3. opaque_predicate  lsl+sub 构造恒等表达式后 cmp      → 恒真/假
  4. jump_thunk        mov wN,wzr; br xM                 → 尾调用桩
  5. identity_wrapper  mov wN,wzr; b target              → 恒等包装
  6. base_reloc        adrp+add 落点超模块 + 后续寄存器补偿

## 为什么是通用能力

每条规则都是**结构化指令模式**（助记符序列 + 操作数关系），
不含任何具体 App 的偏移/寄存器/常量。返回位置 + 手法 + 置信度，
由调用方决定是否采信。
"""
from __future__ import annotations

import re

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "detect_obfuscation"
    description = "识别 6 种常见 OLLVM/ARM64 混淆手法（结构模式，非样本特征）"
    usage = ("args: {so: str, addr: str|int|None=None, methods: list[str]|None=None, "
             "limit: int=100}")

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        from server.core.disasm import Disassembler

        addr = args.get("addr")
        methods = set(args.get("methods") or [
            "retaddr_hijack", "binary_dispatch", "opaque_predicate",
            "jump_thunk", "identity_wrapper", "base_reloc",
        ])
        limit = int(args.get("limit", 100))

        dis = Disassembler(so)
        ranges = self._ranges(so, addr)
        loads = getattr(so, "_loads", []) or []
        if loads:
            mod_lo = min(a for a, _b, _o, _f in loads)
            mod_hi = max(b for _a, b, _o, _f in loads)
        else:
            mod_lo, mod_hi = 0, 1 << 63
        found = []
        for base, size in ranges:
            insns = dis.disasm_range(base, size)
            texts = [(i.addr, i.text or "") for i in insns]
            for idx, (ia, text) in enumerate(texts):
                window = texts[idx:idx + 6]
                for method in methods:
                    hit = self._match(method, window, idx, texts, insns,
                                      (mod_lo, mod_hi))
                    if hit:
                        found.append({"addr": hex(ia), "method": method, **hit})

        found.sort(key=lambda r: r["addr"])
        return {
            "ok": True, "so": so.name,
            "scanned_ranges": len(ranges),
            "count": len(found),
            "findings": found[:limit],
            "note": ("按结构模式识别，不含样本特征。"
                     "命中≠确认——高置信度也需要人工复核控制流。"),
        }

    def _ranges(self, so, addr):
        if addr is not None:
            a = int(str(addr), 16) if isinstance(addr, str) and \
                str(addr).lower().startswith("0x") else int(addr)
            fn = so.function_at(a)
            if fn:
                return [(fn.addr, max(fn.size, 4))]
            return [(a, 4096)]
        # (1) 节表被抹时用 exec_regions() 兜底（加固样本主战场）
        out = [(s.addr, s.size) for s in getattr(so, "sections", [])
               if getattr(s, "is_exec", False) and s.size]
        if not out:
            for va, end, _off, _fl in getattr(so, "exec_regions", lambda: [])():
                if end > va:
                    out.append((va, end - va))
        return out

    def _match(self, method, w, idx, texts, insns, mod_range):
        """返回命中详情或 None。w 是从当前指令开始的窗口。"""
        t = [x[1] for x in w]
        if len(t) < 2:
            return None

        if method == "retaddr_hijack":
            # bl → (mov xN,x0)? → add xN,x0,#imm → br xN
            if not t[0].startswith("bl "):
                return None
            for j in range(1, min(len(t), 4)):
                m = re.match(r"add\s+(x\d+),\s*\w+,\s*#(0x[0-9a-f]+|\d+)", t[j])
                if m and any(x.startswith("br " + m.group(1)) for x in t[j + 1:]):
                    return {"confidence": "high",
                            "pattern": t[:j + 2],
                            "note": "bl 后取返回地址加偏移再 br，等价于直接跳转"}

        elif method == "binary_dispatch":
            # 连续多个 cmp + 条件跳转（>=3 组）
            pairs = 0
            for j in range(0, len(w) - 1):
                if t[j].startswith("cmp ") and re.match(r"b\.(ge|hs|hi|gt)", t[j + 1]):
                    pairs += 1
            if pairs >= 2 and idx + 8 <= len(texts):
                # 看更大窗口里是否 >=3 组
                big = [x[1] for x in texts[idx:idx + 24]]
                total = sum(1 for j in range(len(big) - 1)
                            if big[j].startswith("cmp ") and
                            re.match(r"b\.(ge|hs|hi|gt)", big[j + 1]))
                if total >= 3:
                    return {"confidence": "high", "cmp_branch_pairs": total,
                            "note": "多个有序 cmp+条件跳转，疑似 switch 分派器"}

        elif method == "opaque_predicate":
            # lsl wA,wB,#N ; sub wC,wA,wB ; cmp ...  (wC = wB*(2^N-1))
            if len(t) >= 3:
                m1 = re.match(r"lsl\s+(w\d+),\s*(w\d+),\s*#(\d+)", t[0])
                m2 = re.match(r"sub\s+(w\d+),\s*(w\d+),\s*(w\d+)", t[1])
                if m1 and m2 and m1.group(2) == m2.group(2) and \
                        m1.group(1) == m2.group(1) and t[2].startswith("cmp "):
                    return {"confidence": "high",
                            "pattern": t[:3],
                            "note": "lsl/sub 构造 wB*(2^N-1) 后比较，疑似恒等谓词"}

        elif method == "jump_thunk":
            if re.match(r"mov\s+w\d+,\s*wzr", t[0]) and t[1].startswith("br "):
                return {"confidence": "medium", "pattern": t[:2],
                        "note": "清零参数寄存器后间接跳转，疑似尾调用桩"}

        elif method == "identity_wrapper":
            if re.match(r"mov\s+w\d+,\s*wzr", t[0]) and t[1].startswith("b "):
                return {"confidence": "low", "pattern": t[:2],
                        "note": "清零后无条件跳转，可能是恒等包装"}

        elif method == "base_reloc":
            # adrp+add 目标超出模块范围（由 run() 传入上下文）
            insn = insns[idx]
            t_addr = getattr(insn, "ref_addr", None)
            if t_addr is None:
                return None
            lo, hi = mod_range
            val = int(t_addr)
            over = (val - hi) if val >= hi else (lo - val if val < lo else 0)
            if over > 0x10000:
                return {"confidence": "high", "computed": hex(val),
                        "out_of_range_by": hex(over),
                        "note": "adrp+add 目标超出模块范围，疑似基址重定位混淆"}
        return None
        return None
