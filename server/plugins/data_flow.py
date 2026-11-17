"""寄存器数据流后向切片插件（通用能力）。

## 解决什么问题

追"x20 从哪来"只能人工翻汇编（用户翻了 4 处）。
本插件在**函数范围内**做轻量的后向数据流：
    - 从目标指令的寄存器出发
    - 往前找最后一次写入该寄存器的指令
    - 递归展开它的源寄存器（树形）
    - 跨基本块也追（在函数范围内线性往前）

## 与符号执行的区别

这不是符号执行——不做约束求解，不试图"反解 x24"。
它只回答"这个寄存器在此处的值，可能来自哪些指令"，
是**人工阅读汇编的加速器**。

## 为什么是通用能力

纯指令语义模式（目的寄存器 = 源寄存器 的写关系），
不硬编码任何具体寄存器号或地址。调用方传 reg 参数决定追谁。

## 用法

```python
plugin_run(name="data_flow", args={
    "so": "libfoo.so", "addr": "0x20318c", "reg": "x20",
    "max_depth": 4, "max_nodes": 100,
})
```
"""
from __future__ import annotations

import re

from server.core.plugins import PluginBase

# 写目的寄存器的模式：str 是"目的"，其余是自己解析
WRITE_PATTERNS = [
    re.compile(r"^\s*(mov|movz|movk|movn|add|sub|adr|adrp|ldr|ldur|ldp|eor|and|orr|lsl|lsr|mul|madd|csel|cbz|cbnz)\s+"),
]


class Plugin(PluginBase):
    name = "data_flow"
    description = "寄存器后向数据流切片：追踪某个寄存器的所有来源"
    usage = ("args: {so: str, addr: str|int, reg: str='x20', "
             "max_depth: int=4, max_nodes: int=100}")

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

        reg = self._norm(str(args.get("reg", "x20")).lower())
        max_depth = int(args.get("max_depth", 4))
        max_nodes = int(args.get("max_nodes", 100))
        addr = args.get("addr")
        a = int(str(addr), 16) if isinstance(addr, str) and \
            str(addr).lower().startswith("0x") else int(addr)

        fn = so.function_at(a)
        if fn is None:
            return {"error": f"0x{a:x} 不在任何已知函数内", "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs 补全函数表"}
        dis = Disassembler(so)
        insns = dis.disasm_range(fn.addr, max(fn.size, 4))
        if not insns:
            return {"error": "函数解码为空", "code": "DECODE_EMPTY"}

        # 建 addr → index
        idx_of = {i.addr: n for n, i in enumerate(insns)}
        target_idx = idx_of.get(a)
        if target_idx is None:
            # 找最近的
            nearest = [i for i in insns if i.addr <= a]
            if not nearest:
                return {"error": "地址不在函数指令范围内", "code": "BAD_ADDR"}
            target_idx = idx_of[nearest[-1].addr]

        visited = set()
        nodes = []

        def walk(idx: int, cur_reg: str, depth: int, path: list):
            if depth > max_depth or len(nodes) >= max_nodes:
                return
            key = (idx, cur_reg)
            if key in visited:
                return
            visited.add(key)
            for j in range(idx, -1, -1):
                insn = insns[j]
                text = insn.text or ""
                dst, srcs = self._parse(text)
                if dst != cur_reg:
                    continue
                node = {
                    "addr": hex(insn.addr),
                    "insn": text,
                    "reg": cur_reg,
                    "depth": depth,
                    "sources": srcs,
                    "path": [hex(x) for x in path],
                }
                nodes.append(node)
                for s in srcs:
                    walk(j - 1, s, depth + 1, path + [insn.addr])
                return              # 找到最后一次写入就停

        walk(target_idx, reg, 0, [])
        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "entry": hex(fn.addr),
            "query": {"addr": hex(a), "reg": reg},
            "node_count": len(nodes),
            "nodes": nodes,
            "note": ("函数范围内后向切片，找每个寄存器的最后一次写入。"
                     "跨函数参数传递需人工跟进 call_chain；"
                     "这不是符号执行，不反解运行时值。"),
        }

    @staticmethod
    def _norm(r: str) -> str:
        """wN 与 xN 是同一物理寄存器，统一成 xN。"""
        m = re.match(r"w(\d+)$", r)
        return "x" + m.group(1) if m else r

    # 这些指令读第一个操作数，不写它
    _READ_FIRST = {"cbz", "cbnz", "tbz", "tbnz", "str", "strb", "strh",
                   "stp", "cmp", "cmn", "tst", "stur", "sturb", "sturh"}

    def _parse(self, text: str):
        """返回 (目的寄存器, 源寄存器列表)。"""
        m = re.match(r"\s*(\w+)\s+([\w\[\]\s,#\-:]+)", text)
        if not m:
            return None, []
        mnemonic = m.group(1)
        if mnemonic in self._READ_FIRST:
            # 整条指令的所有寄存器都是"源"，没有目的
            srcs = []
            for r in re.findall(r"\b(x\d+|w\d+|sp)\b", m.group(2)):
                r = self._norm(r)
                if r not in srcs:
                    srcs.append(r)
            return None, srcs
        ops = [o.strip() for o in m.group(2).split(",")]
        if not ops:
            return None, []
        dst = ops[0]
        # 取第一个 token：x0 / w0 / [x0, #8] 里的 x0
        dm = re.match(r"(\[)?(x\d+|w\d+|sp|xzr|wzr)", dst)
        d = self._norm(dm.group(2)) if dm else self._norm(dst)
        srcs = []
        for op in ops[1:]:
            for r in re.findall(r"\b(x\d+|w\d+|sp)\b", op):
                r = self._norm(r)
                if r not in srcs:
                    srcs.append(r)
        return d, srcs
