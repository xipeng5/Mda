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

from server.core.addr import parse_addr
from server.core.plugins import PluginBase

# 访存助记符集合（含非缩放/带符号扩展变体）
_MEM_OPS = (
    r"ldr|str|ldrb|strb|ldrh|strh|ldrsw|ldrsh|ldrsb|"
    r"ldur|stur|ldurb|sturb|ldurh|sturh|ldursw|ldursh|ldursb|"
    r"ldp|stp"
)


def _reg_width(operands_text: str) -> int:
    """根据访存指令首个目标/源寄存器名推断字段字节宽度。"""
    m = re.search(r"\b(wzr|xzr|[bhsdqwx]\d+)\b", operands_text.lower())
    if not m:
        return 8
    tok = m.group(1)
    if tok.startswith("b"):
        return 1
    if tok.startswith("h"):
        return 2
    if tok == "wzr" or tok.startswith(("w", "s")):
        return 4
    if tok.startswith("q"):
        return 16
    return 8


def _record_field(fields, off: int, width: int, insn_addr: int, text: str) -> None:
    """向偏移表登记一条字段访问宽度与示例指令。"""
    f = fields[off]
    if width not in f["widths"]:
        f["widths"].append(width)
    if len(f["accesses"]) < 3:
        f["accesses"].append({"addr": hex(insn_addr), "insn": text})


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

        # (1) 第一次修改（2026-11-26）
        # bug 原因：1) addr 未使用 parse_addr 且未捕获非 ARM64 的 Disassembler ValueError；
        #           2) ldp/stp 仅登记首偏移，遗漏第二个寄存器对应字段；
        #           3) 偏移正则不支持负十六进制，且指令表缺少 ldur/stur/ldurb/sturb/ldurh/sturh/ldursw/ldrsh/ldrsb；
        #           4) reg_width 只认 w\d+，把 wzr/s*/b*/h* 全部误判为 8 字节。
        # 解决方案：统一 parse_addr 并捕获非 ARM64；扩充指令表与负十六进制偏移正则；
        #           按寄存器前缀精准推断宽度，并为 ldp/stp 同步登记第二个偏移字段。
        reg = self._norm(str(args.get("reg", "x0")).lower())
        a = parse_addr(args["addr"])
        if a is None:
            return {"ok": False, "code": "BAD_ADDR",
                    "error": f"非法地址参数 addr={args['addr']!r}"}
        fn = so.function_at(a)
        if fn is None:
            return {"error": "地址不在已知函数内", "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs"}
        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}
        insns = dis.disasm_range(fn.addr, max(fn.size, 4))

        # offset → {widths, accesses}
        fields = defaultdict(lambda: {"widths": [], "accesses": []})
        pat = re.compile(rf"\b({_MEM_OPS})\b")
        mem_pat = re.compile(
            rf"\b({_MEM_OPS})\b.*?\[({re.escape(reg)}|\w+)"
            r"(?:,\s*#(-?0x[0-9a-fA-F]+|-?\d+))?\]"
        )
        for insn in insns:
            text = insn.text or ""
            if not pat.search(text):
                continue
            m = mem_pat.search(text)
            if not m:
                continue
            mn = m.group(1)
            base = self._norm(m.group(2))
            if base != reg:
                continue
            off_raw = m.group(3)
            off = int(off_raw, 0) if off_raw else 0
            operands_text = text.split("[", 1)[0]
            # 去掉助记符本身再判断操作数寄存器宽度
            ops_no_mn = operands_text[operands_text.find(mn) + len(mn):]
            reg_width = _reg_width(ops_no_mn)
            if mn.endswith("b"):
                w = 1
            elif mn.endswith("h"):
                w = 2
            elif mn in ("ldrsw", "ldursw"):
                w = 4
            else:
                w = reg_width
            _record_field(fields, off, w, insn.addr, text)
            if mn in ("ldp", "stp"):
                _record_field(fields, off + w, w, insn.addr, text)

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
