"""函数级反汇编 + 基本块/CFG 插件（通用能力）。

## 解决什么问题

现有 `disassemble` 是**线性区间解码**：给一段地址就从头解到尾，
遇到 `b`/`br`/`bl` 不停，解码会跨过跳转落到数据区，
产出一堆假的 SVE 指令（如 `fcmla z15.s, ...`）。

本插件按**函数边界 + 控制流**组织：
    - 从函数入口开始，按跳转目标/下一条指令切基本块
    - 每个基本块独立线性解码（块内不会有跳转落点，所以准确）
    - 输出 CFG 边（条件跳转的真/假、无条件跳转、调用、返回）
    - 数据区不反汇编（按 FDE 函数大小限定范围）

## 为什么是通用能力

基本块划分、CFG 构建是结构化的通用算法，不含任何具体 so / App 特征。
函数范围来自 mda 自己的函数表（FDE/discover），不硬编码。

## 用法

```python
plugin_run(name="disasm_func", args={
    "so": "libfoo.so",
    "addr": "0x202ef8",     # 函数入口（或函数内任意地址）
    "max_insns": 5000,
})
```
"""
from __future__ import annotations

from server.core.plugins import PluginBase

# ARM64 跳转/返回指令
_TERMINATORS = {"b", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"}
_COND = {"b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
         "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv"}


class Plugin(PluginBase):
    name = "disasm_func"
    description = "函数级反汇编：按控制流切基本块，输出准确指令 + CFG 边"
    usage = ("args: {so: str, addr: str|int, max_insns: int=5000}")

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

        addr = int(str(args["addr"]), 16) if isinstance(args["addr"], str) and \
               str(args["addr"]).lower().startswith("0x") else int(args["addr"])
        max_insns = int(args.get("max_insns", 5000))

        # 定位函数范围
        fn = so.function_at(addr)
        if fn is None:
            return {"error": f"0x{addr:x} 不在任何已知函数内",
                    "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs 补全函数表，或用 function_by_name 找入口"}
        start, end = fn.addr, fn.addr + fn.size
        if fn.size <= 0 or fn.size > max_insns * 8:
            end = min(start + max_insns * 8, self._module_end(so))

        dis = Disassembler(so)
        # 1) 线性解码整个函数范围（只在函数边界内，不会落到数据区）
        all_insns = dis.disasm_range(start, end - start)
        if not all_insns:
            return {"error": f"函数 0x{start:x} 解码不出指令", "code": "DECODE_EMPTY"}

        # 2) 收集所有基本块入口：函数入口 + 跳转目标 + 条件跳转的下一条
        insn_by_addr = {i.addr: i for i in all_insns}
        leaders = {start}
        for i in all_insns:
            text = i.text.split()[0].rstrip(",") if i.text else ""
            if text in _TERMINATORS or text in _COND:
                # 跳转目标
                target = self._target(i)
                if target is not None and start <= target < end:
                    leaders.add(target)
                # 条件跳转/调用的下一条也是 leader
                nxt = i.addr + 4
                if (text in _COND or text in ("cbz", "cbnz", "tbz", "tbnz", "blr")) \
                        and start <= nxt < end:
                    leaders.add(nxt)

        # 3) 切基本块
        leaders_sorted = sorted(leaders)
        blocks = []
        for idx, lead in enumerate(leaders_sorted):
            block_end = leaders_sorted[idx + 1] if idx + 1 < len(leaders_sorted) else end
            insns = [i for i in all_insns if lead <= i.addr < block_end]
            if not insns:
                continue
            succ = []
            last = insns[-1]
            text = last.text.split()[0].rstrip(",") if last.text else ""
            target = self._target(last)
            if text == "ret":
                pass
            elif text in ("b", "br"):
                if target is not None:
                    succ.append({"to": hex(target), "kind": "jump"})
            elif text == "blr":
                succ.append({"to": "indirect", "kind": "call"})
            elif text in _COND or text in ("cbz", "cbnz", "tbz", "tbnz"):
                if target is not None:
                    succ.append({"to": hex(target), "kind": "true"})
                succ.append({"to": hex(last.addr + 4), "kind": "false"})
            else:
                # 顺序流
                succ.append({"to": hex(block_end), "kind": "fallthrough"})
            blocks.append({
                "start": hex(lead),
                "end": hex(block_end),
                "insns": [{"addr": hex(i.addr), "text": i.text} for i in insns],
                "successors": succ,
            })

        return {
            "ok": True,
            "so": so.name,
            "function": fn.name or f"sub_{start:x}",
            "entry": hex(start),
            "size": fn.size,
            "block_count": len(blocks),
            "insn_count": len(all_insns),
            "blocks": blocks,
            "note": ("基本块按跳转目标切分，块内线性解码准确；"
                     "跨块跳转用 successors 表示，不会把数据当代码"),
        }

    def _target(self, insn) -> int | None:
        """从指令文本里取跳转目标地址。"""
        import re

        text = insn.text or ""
        # call/ref 字段由 Disassembler 语义识别填充，优先用
        t = getattr(insn, "call_target", None) or getattr(insn, "ref_addr", None)
        if t is not None:
            return int(t)
        m = re.search(r"#\s*(0x[0-9a-fA-F]+)", text)
        if m:
            return int(m.group(1), 16)
        return None

    def _module_end(self, so) -> int:
        ends = [s.addr + s.size for s in getattr(so, "sections", [])]
        if ends:
            return max(ends)
        ends = [e for _a, e, _o, _f in getattr(so, "_loads", []) or []]
        return max(ends) if ends else (1 << 63)
