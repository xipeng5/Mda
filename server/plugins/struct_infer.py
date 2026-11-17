"""结构体字段推断插件（通用能力）。

## 解决什么问题

用户靠人工看 `str x8,[x0]` / `stp w8,w0,[x19,#8]` 推断 C++ string 结构和
z_stream 结构，花了 2 轮。本插件把"访问模式 → 字段布局"自动化：
    - 扫所有 [base_reg + offset] 访问
    - 按 offset 分组
    - 根据访问宽度（strb/strh/str/ldr/ldp）推断字段宽度
    - 输出候选 struct 定义

## 为什么是通用能力

pure 模式匹配，不硬编码任何具体结构（string/z_stream 只是用户案例）。
调用方传基址寄存器名，插件回答"这个指针被当什么结构用"。

## 用法

```python
plugin_run(name="struct_infer", args={
    "so": "libfoo.so", "addr": "0x1eb684",  # 函数范围
    "reg": "x0", "size": 0x100,
})
```
"""
from __future__ import annotations

import re
from collections import defaultdict

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "struct_infer"
    description = "从 [reg+offset] 访问模式推断结构体字段布局"
    usage = ("args: {so: str, addr: str|int, reg: str='x0', "
             "max_fields: int=64}")

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

        reg = self._norm(str(args.get("reg", "x0")).lower())
        a = args["addr"]
        a = int(str(a), 16) if isinstance(a, str) and \
            str(a).lower().startswith("0x") else int(a)
        fn = so.function_at(a)
        if fn is None:
            return {"error": "地址不在已知函数内", "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs"}
        insns = Disassembler(so).disasm_range(fn.addr, max(fn.size, 4))

        # offset → {widths, accesses}
        fields = defaultdict(lambda: {"widths": [], "accesses": []})
        pat = re.compile(r"\b(ldr|str|ldrb|strb|ldrh|strh|ldrsw|ldp|stp|ldrsw)\b")
        for insn in insns:
            text = insn.text or ""
            if not pat.search(text):
                continue
            m = re.search(r"\b(ldr|str|ldrb|strb|ldrh|strh|ldrsw|ldp|stp)\b.*?"
                          r"\[(" + re.escape(reg) + r"|\w+)"
                          r"(?:,\s*#(0x[0-9a-f]+|-?\d+))?\]", text)
            if not m:
                continue
            mn = m.group(1)
            base = self._norm(m.group(2))
            if base != reg:
                continue
            off = m.group(3)
            off = int(off, 16) if isinstance(off, str) and off.startswith("0x") \
                  else (int(off) if off else 0)
            # 宽度：先看 mnemonic 后缀，再看寄存器宽度（w=4, x=8）
            operands_text = text.split("[", 1)[0]
            reg_width = 4 if re.search(r"\bw\d+\b", operands_text) else 8
            if mn.endswith("b"):
                w = 1
            elif mn.endswith("h"):
                w = 2
            elif mn == "ldrsw":
                w = 4
            elif mn in ("ldp", "stp"):
                w = reg_width
            else:
                w = reg_width
            f = fields[off]
            if w not in f["widths"]:
                f["widths"].append(w)
            if len(f["accesses"]) < 3:
                f["accesses"].append({"addr": hex(insn.addr), "insn": text})

        out = []
        for off in sorted(fields)[:int(args.get("max_fields", 64))]:
            f = fields[off]
            # 取出现过的最大宽度作为推断宽度（或最常见）
            width = max(f["widths"])
            ctype = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t",
                     8: "void*"}.get(width, f"byte[{width}]")
            out.append({"offset": hex(off), "offset_dec": off,
                        "width": width, "ctype": ctype,
                        "accesses": f["accesses"]})

        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "base_reg": reg,
            "field_count": len(out),
            "fields": out,
            "note": ("基于访问模式的推断，不是类型证明。"
                     "void* 只是宽度 8 的占位，实际可能是 uint64_t/double。"),
        }

    @staticmethod
    def _norm(r: str) -> str:
        m = re.match(r"w(\d+)$", r)
        return "x" + m.group(1) if m else r
