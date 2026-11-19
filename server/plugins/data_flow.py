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
    # 跨函数模式（新增）：沿 call_chain 往上传，看寄存器最终来自哪个调用点
    "interproc": True, "up_depth": 3,
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
             "max_depth: int=4, max_nodes: int=100, "
             "interproc: bool=false, up_depth: int=3}")

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

        # (1) 第一次修改（2026-11-18）
        #     bug 原因：原实现只做函数内切片，追到"寄存器来自函数参数"就没了，
        #               用户要跨函数看它最终来自哪个调用点，必须人工跟进 call_chain。
        #     解决方案：新增 interproc 模式，复用函数内切片做单层，再沿调用者往上传播；
        #               原函数内行为完全不变（interproc 默认 false）。
        interproc = bool(args.get("interproc", False))
        up_depth = int(args.get("up_depth", 3))
        if interproc:
            return self._run_interproc(session, so, fn, a, reg, max_depth, max_nodes,
                                       up_depth)

        dis = Disassembler(so)
        insns = dis.disasm_range(fn.addr, max(fn.size, 4))
        if not insns:
            return {"error": "函数解码为空", "code": "DECODE_EMPTY"}

        nodes = self._slice_in_function(insns, a, reg, max_depth, max_nodes)
        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "entry": hex(fn.addr),
            "query": {"addr": hex(a), "reg": reg},
            "node_count": len(nodes),
            "nodes": nodes,
            "cross_function": False,
            "note": ("函数范围内后向切片，找每个寄存器的最后一次写入。"
                     "跨函数参数传递需人工跟进 call_chain（可设 interproc=True）；"
                     "这不是符号执行，不反解运行时值。"),
        }

    def _slice_in_function(self, insns: list, a: int, reg: str,
                           max_depth: int, max_nodes: int) -> list:
        """函数内后向切片：返回节点列表。复用给普通模式与跨函数模式的每一层。"""
        idx_of = {i.addr: n for n, i in enumerate(insns)}
        target_idx = idx_of.get(a)
        if target_idx is None:
            nearest = [i for i in insns if i.addr <= a]
            if not nearest:
                return []
            target_idx = idx_of[nearest[-1].addr]

        visited: set = set()
        nodes: list = []

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
        return nodes

    def _run_interproc(self, session, so, fn, a: int, reg: str,
                       max_depth: int, max_nodes: int, up_depth: int) -> dict:
        """跨函数模式：函数内切片追到参数 → 沿调用者往上传播（轻量静态近似）。

        (1) 第一次修改（2026-11-18）
            bug 原因：原 data_flow 只在函数内切片，跨函数参数传递要人工跟进 call_chain。
            解决方案：从 (addr,reg) 出发，每层做函数内切片；若切片追到函数参数
            （x0-x7 / 入口无写入），就用 xrefs_to(fn.addr) 找调用点，在调用者里
            看 bl 前最后一次写入对应参数寄存器，递归 up_depth 层。
            不建模栈/堆/别名，"bl 前最后写入"是启发式，note 中如实说明。
        """
        from server.core.disasm import Disassembler

        dis = Disassembler(so)
        chain: list = []
        scanned_functions = 0
        scanned_insns = 0
        cross_function = False

        # 当前正在分析的 (函数, 地址, 寄存器)
        cur_fn = fn
        cur_addr = a
        cur_reg = reg

        for level in range(up_depth + 1):
            fn_insns = dis.disasm_range(cur_fn.addr, max(cur_fn.size, 4))
            scanned_functions += 1
            scanned_insns += len(fn_insns)
            if not fn_insns:
                break

            nodes = self._slice_in_function(fn_insns, cur_addr, cur_reg,
                                            max_depth, max_nodes)
            # 来源：切片里最深层节点的源寄存器；没有节点则视为"入口即参数"
            sources: list = []
            if nodes:
                sources = nodes[-1].get("sources", [])
            # nodes 里 addr 是 hex 字符串，转回 int 供写入查找
            last_addr = int(nodes[-1]["addr"], 16) if nodes else cur_addr
            is_param = (not nodes) or any(
                self._is_param(s) and not self._has_writer_before(
                    fn_insns, last_addr, s)
                for s in sources
            )
            # 追到的参数寄存器：优先取 sources 里的参数寄存器，否则用当前 reg
            param_regs = [s for s in sources if self._is_param(s)]
            if not param_regs and (not nodes):
                param_regs = [cur_reg]

            chain.append({
                "level": level,
                "function": cur_fn.name or f"sub_{cur_fn.addr:x}",
                "entry": hex(cur_fn.addr),
                "site": hex(cur_addr) if level else hex(a),
                "reg": cur_reg,
                "sources": sources,
                "param_regs": param_regs,
                "is_param": bool(is_param),
                "nodes": nodes,
            })

            if not is_param or level == up_depth:
                break

            # 沿调用者往上传：找调用 cur_fn 的位置
            callers = session.xref(so.name).xrefs_to(cur_fn.addr)
            caller_sites = []
            for site in callers:
                cf = so.function_at(site)
                if cf is not None:
                    caller_sites.append((cf, site))
            if not caller_sites:
                break
            cross_function = True

            # 对每个调用者，看 bl 前最后一次写入对应参数寄存器
            next_fn, next_site, next_reg = None, 0, None
            for cf, site in caller_sites:
                cf_insns = dis.disasm_range(cf.addr, max(cf.size, 4))
                for p in param_regs:
                    # 简单映射：被调用者用 xN → 调用者调用前 xN 的最后写入
                    w = self._last_write_before(cf_insns, site, p)
                    if w is not None:
                        next_fn, next_site, next_reg = cf, site, p
                        break
                if next_fn is not None:
                    break
            if next_fn is None:
                # 调用者里没找到显式写入：保守地用第一个参数寄存器继续
                cf, site = caller_sites[0]
                next_fn, next_site, next_reg = cf, site, (param_regs or ["x0"])[0]

            cur_fn, cur_addr, cur_reg = next_fn, next_site, next_reg

        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "entry": hex(fn.addr),
            "query": {"addr": hex(a), "reg": reg},
            "cross_function": cross_function,
            "scanned_functions": scanned_functions,
            "scanned_insns": scanned_insns,
            "interproc_chain": chain,
            "node_count": sum(len(c["nodes"]) for c in chain),
            "note": ("轻量跨函数静态传播：函数内后向切片追到参数后，沿调用者往上传，"
                     "看参数寄存器来自哪个调用点。不建模栈/堆/别名；"
                     "'bl 前最后写入'只是启发式（可能跨基本块、可能被后续指令覆盖）。"
                     "这不是符号执行，不反解运行时值。"),
        }

    @staticmethod
    def _is_param(r: str) -> bool:
        """x0-x7 视为函数参数寄存器（AArch64 ATPCS）。"""
        m = re.match(r"x([0-7])$", r)
        return m is not None

    def _last_write_before(self, insns: list, addr: int, reg: str):
        """在 addr 之前找 reg 的最后一次写入，返回指令地址；没有返回 None。"""
        for ins in reversed(insns):
            if ins.addr >= addr:
                continue
            dst, _ = self._parse(ins.text or "")
            if dst == reg:
                return ins.addr
        return None

    def _has_writer_before(self, insns: list, addr, reg: str) -> bool:
        return self._last_write_before(insns, addr, reg) is not None

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
