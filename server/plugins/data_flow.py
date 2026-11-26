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

from server.core.addr import parse_addr
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

        # (2) 第二次修改（2026-11-26）
        # bug 原因：addr 未使用 parse_addr 且未捕获非 ARM64 架构 Disassembler 的 ValueError。
        # 解决方案：统一通过 parse_addr 解析 addr（非法返 BAD_ADDR），捕获非 ARM64 返 UNSUPPORTED_ARCH。
        reg = self._norm(str(args.get("reg", "x20")).lower())
        max_depth = int(args.get("max_depth", 4))
        max_nodes = int(args.get("max_nodes", 100))
        a = parse_addr(args.get("addr"))
        if a is None:
            return {"ok": False, "code": "BAD_ADDR",
                    "error": f"非法地址参数 addr={args.get('addr')!r}"}

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
        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}
        if interproc:
            return self._run_interproc(session, so, dis, fn, a, reg, max_depth, max_nodes,
                                       up_depth)

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
                dsts, srcs = self._parse_rw(text)
                if cur_reg not in dsts:
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

    def _run_interproc(self, session, so, dis, fn, a: int, reg: str,
                       max_depth: int, max_nodes: int, up_depth: int) -> dict:
        """跨函数模式：函数内切片追到参数 → 沿调用者往上传播（轻量静态近似）。

        (1) 第一次修改（2026-11-18）
            bug 原因：原 data_flow 只在函数内切片，跨函数参数传递要人工跟进 call_chain。
            解决方案：从 (addr,reg) 出发，每层做函数内切片；若切片追到函数参数
            （x0-x7 / 入口无写入），就用 xrefs_to(fn.addr) 找调用点，在调用者里
            看 bl 前最后一次写入对应参数寄存器，递归 up_depth 层。
            不建模栈/堆/别名，"bl 前最后写入"是启发式，note 中如实说明。

        (3) 第三次修改（2026-11-26）
            bug 原因：interproc=True 直接调用 xref.xrefs_to(cur_fn.addr)，未先构建 xref
                      索引导致常返空列表，且 xrefs_to 混入了非调用的数据引用点。
            解决方案：先调用 session.ensure_xrefs(so.name) / xr.build() 确保索引就绪，
                      再优先通过 callers_of_fn 只取调用点。
        """
        chain: list = []
        scanned_functions = 0
        scanned_insns = 0
        cross_function = False

        # 确保跨函数调用索引已构建
        if hasattr(session, "ensure_xrefs"):
            session.ensure_xrefs(so.name)
        xr = session.xref(so.name)
        if hasattr(xr, "build"):
            xr.build()

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

            # 沿调用者往上传：优先只取调用点（callers_of_fn）
            if hasattr(xr, "callers_of_fn"):
                callers = xr.callers_of_fn(cur_fn.addr)
            else:
                callers = [
                    site for site in xr.xrefs_to(cur_fn.addr)
                    if any(i.is_call for i in dis.disasm_range(site, 4))
                ]
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
            dsts, _ = self._parse_rw(ins.text or "")
            if reg in dsts:
                return ins.addr
        return None

    def _has_writer_before(self, insns: list, addr, reg: str) -> bool:
        return self._last_write_before(insns, addr, reg) is not None

    @staticmethod
    def _norm(r: str) -> str:
        """wN 与 xN 是同一物理寄存器，统一成 xN。"""
        m = re.match(r"w(\d+)$", r)
        return "x" + m.group(1) if m else r

    # (4) 第四次修改（2026-11-26）
    # bug 原因：1) ldp 把第二个目的寄存器 rd2 误当成源寄存器；
    #           2) blr/br/ret/stlr* 未在 _READ_FIRST 中，会把 blr x8 的 x8 误判为写入；
    #           3) movk 只覆写 16 位却丢弃原目的寄存器依赖，切断了前序 movz；
    #           4) bl 未截断返回值寄存器 x0，导致后向切片越过调用连到旧值。
    # 解决方案：扩充 _READ_FIRST；新增 _parse_rw 支持多目的寄存器（ldp/ldnp/ldxp/ldaxp），
    #           movk 将目的寄存器加入源列表，bl 截断 x0；保留 _parse 兼容外部调用。
    _READ_FIRST = {
        "cbz", "cbnz", "tbz", "tbnz", "str", "strb", "strh", "stp", "stnp",
        "cmp", "cmn", "tst", "stur", "sturb", "sturh",
        "stlr", "stlrb", "stlrh", "blr", "br", "ret",
    }
    _PAIR_LOADS = {"ldp", "ldnp", "ldxp", "ldaxp", "ldpsw"}

    def _parse_rw(self, text: str) -> tuple[list[str], list[str]]:
        """解析指令的读写寄存器，返回 (目的寄存器列表, 源寄存器列表)。"""
        m = re.match(r"\s*(\w+)(?:\s+([\w\[\]\s,#\-:!]+))?", text)
        if not m:
            return [], []
        mnemonic = m.group(1).lower()
        rest = (m.group(2) or "").strip()

        if mnemonic == "bl":
            # 函数调用会覆写返回值寄存器 x0，截断防止越过调用连到旧值
            return ["x0"], []

        if mnemonic in self._READ_FIRST:
            srcs = []
            for r in re.findall(r"\b(x\d+|w\d+|sp)\b", rest):
                r = self._norm(r)
                if r not in srcs:
                    srcs.append(r)
            return [], srcs

        if not rest:
            return [], []

        ops = [o.strip() for o in rest.split(",")]
        if mnemonic in self._PAIR_LOADS and len(ops) >= 3:
            dsts = []
            for op in ops[:2]:
                dm = re.match(r"(x\d+|w\d+|sp|xzr|wzr)\b", op)
                if dm:
                    rn = self._norm(dm.group(1))
                    if rn not in ("xzr", "wzr") and rn not in dsts:
                        dsts.append(rn)
            srcs = []
            for op in ops[2:]:
                for r in re.findall(r"\b(x\d+|w\d+|sp)\b", op):
                    r = self._norm(r)
                    if r not in srcs:
                        srcs.append(r)
            return dsts, srcs

        dst = ops[0]
        dm = re.match(r"(\[)?(x\d+|w\d+|sp|xzr|wzr)", dst)
        d = self._norm(dm.group(2)) if dm else self._norm(dst)
        dsts = [] if d in ("xzr", "wzr") else [d]
        srcs = []
        if mnemonic == "movk" and dsts:
            srcs.append(dsts[0])
        for op in ops[1:]:
            for r in re.findall(r"\b(x\d+|w\d+|sp)\b", op):
                r = self._norm(r)
                if r not in srcs:
                    srcs.append(r)
        return dsts, srcs

    def _parse(self, text: str):
        """返回 (首目的寄存器, 源寄存器列表)（兼容旧接口）。"""
        dsts, srcs = self._parse_rw(text)
        return (dsts[0] if dsts else None), srcs
