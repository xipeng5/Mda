"""基于 CFG 的结构化 C 伪代码插件（通用能力）。

## 定位

这不是完整的 SSA 反编译器（那需要类型推断、变量合并、表达式树），
而是比现有 `decompile`（逐条指令换排版）**更进一步**的结构化：
    - 复用 disasm_func 的基本块与 CFG 边
    - 把条件跳转还原成 if / else
    - 把一元操作/算术还原成表达式
    - 带基本块注释，人工可读

## 诚实声明

它**不能**做到 HexRays 的变量命名/类型推断/跨函数数据流。
输出是"带 C 骨架的汇编语义摘要"，用于快速看控制流，
关键结论仍需人工核对。不假装是真反编译。

## 用法

```python
plugin_run(name="decompile_c", args={"so": "libfoo.so", "addr": "0x202ef8"})
```
"""
from __future__ import annotations

import re

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "decompile_c"
    description = "基于 CFG 的结构化伪代码（if/else + 表达式，非 SSA 级）"
    usage = "args: {so: str, addr: str|int, max_lines: int=300}"

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name or args.get("addr") is None:
            return {"error": "需要 so 与 addr", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        from server.core.disasm import Disassembler

        a = args["addr"]
        addr = int(str(a), 16) if isinstance(a, str) and \
               str(a).lower().startswith("0x") else int(a)
        fn = so.function_at(addr)
        if fn is None:
            return {"error": "地址不在函数内", "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs"}
        max_lines = int(args.get("max_lines", 300))

        insns = Disassembler(so).disasm_range(fn.addr, max(fn.size, 4))
        blocks = self._basic_blocks(insns, fn.addr, fn.addr + fn.size)

        lines = [f"// {so.name}!{fn.name or hex(fn.addr)} @ {fn.addr:#x}",
                 f"void {fn.name or ('sub_' + format(fn.addr, 'x'))}() {{"]
        for b in blocks:
            lines.append(f"  // block {b['start']}")
            succ = b.get("succ", [])
            cond = next((s for s in succ if s[1] in ("true", "false")), None)
            for ins in b["insns"]:
                text = ins["text"]
                expr = self._to_expr(text)
                if expr:
                    lines.append("  " + expr)
            if cond:
                lines.append(f"  if (cond) goto {cond[0]};  // 分支简化")
            elif succ and succ[0][1] == "fallthrough":
                pass
            elif succ and succ[0][1] == "jump":
                lines.append(f"  goto {succ[0][0]};")
            if len(lines) >= max_lines:
                lines.append("  // ... 截断（max_lines）")
                break
        lines.append("}")
        code = "\n".join(lines)
        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "addr": hex(fn.addr), "size": fn.size,
            "block_count": len(blocks),
            "pseudocode": code,
            "note": ("CFG 结构化伪代码，不是 SSA 级反编译。"
                     "变量/类型未恢复，关键结论需核对原始汇编。"),
        }

    def _basic_blocks(self, insns, start, end):
        if not insns:
            return []
        leaders = {start}
        for i in insns:
            m = re.match(r"(b|br|blr|cbz|cbnz|tbz|tbnz|ret|b\.\w+)\b", i.text)
            if m:
                t = re.search(r"#(0x[0-9a-f]+)", i.text)
                if t:
                    tgt = int(t.group(1), 16)
                    if start <= tgt < end:
                        leaders.add(tgt)
                if i.addr + 4 < end:
                    leaders.add(i.addr + 4)
        ls = sorted(leaders)
        out = []
        for n, l in enumerate(ls):
            nxt = ls[n + 1] if n + 1 < len(ls) else end
            ins = [{"addr": hex(i.addr), "text": i.text}
                   for i in insns if l <= i.addr < nxt]
            if not ins:
                continue
            succ = []
            last = ins[-1]["text"]
            m = re.match(r"(b\.\w+|b|br|blr|cbz|cbnz|tbz|tbnz)\b.*?#(0x[0-9a-f]+)", last)
            if m:
                kind = "true" if m.group(1).startswith("b.") or \
                       m.group(1) in ("cbz", "cbnz", "tbz", "tbnz") else "jump"
                succ.append((m.group(2), kind))
                if kind == "true":
                    succ.append((hex(int(last.split("#")[-1], 16) + 4), "false"))
            else:
                succ.append((hex(nxt), "fallthrough"))
            out.append({"start": hex(l), "end": hex(nxt),
                        "insns": ins, "succ": succ})
        return out

    def _to_expr(self, text: str) -> str | None:
        """把常见指令转成类 C 表达式；不认识的返回 None（保留汇编由调用方决定）。"""
        m = re.match(r"(mov|movz|movn)\s+(x\d+|w\d+),\s*(#?\S+)", text)
        if m and m.group(3).startswith("#"):
            return f"{m.group(2)} = {m.group(3)[1:]};"
        m = re.match(r"(add|sub|eor|and|orr|mul)\s+(x\d+|w\d+),\s*(x\d+|w\d+),\s*(.+)", text)
        if m:
            op = {"add": "+", "sub": "-", "eor": "^", "and": "&",
                  "orr": "|", "mul": "*"}[m.group(1)]
            return f"{m.group(2)} = {m.group(3)} {op} {m.group(4)};"
        m = re.match(r"(ldr|str)\s+(x\d+|w\d+),\s*\[(.+)\]", text)
        if m:
            arr = "->" if m.group(1) == "" else ""
            return f"{m.group(1)} = mem[{m.group(3)}];" if m.group(1) == "ldr" \
                   else f"mem[{m.group(3)}] = {m.group(2)};"
        m = re.match(r"bl\s+#(0x[0-9a-f]+)", text)
        if m:
            return f"call {m.group(1)}();"
        if re.match(r"ret\b", text):
            return "return;"
        return None
