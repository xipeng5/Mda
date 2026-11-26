"""vtable 遍历插件（通用能力）。

## 解决什么问题

现有 call_graph._vtable_edges / xref_enhanced._vtable_refs 只给
「槽 → 目标」的重定位表反查，不给「哪条 adrp+add 加载了这张表」。
实测某加固 so 里 0xd1890 处 `add x10, x10, #0xcd0 -> 0x117cd0`
这类 adrp+add 数据引用确实存在（全 so 线性扫 28 万条指令找到 29 条
落到该 vtable 页），但 `xrefs_to(0x117cd0) = 0` —— xref 索引没收录
这个方向（按函数收集 + .text 线性扫描只补了部分 adrp+add）。

本插件提供的是**另一条独立证据通道**：给定表地址，线性扫全 so 的
可执行段，列出所有「计算出的地址落在该表范围内」的指令，并尝试
识别它后面是否跟着 `ldr xN,[xM,#imm]; blr xN` 的虚调用模式。

## 为什么是通用能力

adrp+add / adr 是 ARM64 标准寻址；「目标落在给定地址附近」用调用方
传入的 vtable_addr + radius 判定，不硬编码任何样本地址、寄存器号或
so 名字。虚调用识别只按寄存器数据流（含 mov 传递）做启发式匹配，
不对任何具体 App 特调。

## 诚实边界（写进返回的 note）

「计算出该地址」≠「运行时一定读它」：分支可能不走，地址可能被存到
别处再由别的寄存器解引用。虚调用匹配是启发式，未命中不代表没有虚调用。
"""
from __future__ import annotations

import re

from server.core.addr import parse_addr
from server.core.plugins import PluginBase

# 用途：从反汇编文本里抽取寄存器与寻址模式，用于虚调用启发式匹配。
# 只匹配 64 位 x 寄存器：vtable 里存的是函数指针（8 字节）。
_RE_LDR = re.compile(r"^ldr\s+(x\d+),\s*\[(x\d+)(?:,.*)?\]$")
_RE_BLR = re.compile(r"^blr\s+(x\d+)$")
_RE_MOV = re.compile(r"^mov\s+(x\d+),\s*(x\d+)$")
_RE_ADR = re.compile(r"^adr\s+x\d+,\s*#(0x[0-9a-fA-F]+|\d+)$")
_RE_DST = re.compile(r"^\w+\s+(x\d+),")


class Plugin(PluginBase):
    name = "vtable_traversal"
    description = "给定 vtable 地址，扫全 so 找计算该地址的 adrp+add/adr 指令及疑似虚调用"
    usage = "args: {so: str, vtable_addr: str|int, radius: int=0x1000, limit: int=50}"

    def _parse_int(self, value):
        """用途：把调用方给的地址/半径统一转成 int，兼容 '0x117cd0' 与十进制。

        不猜格式：字符串带 0x 按 16 进制，其余按 10 进制；失败抛 ValueError
        由 run 捕获成 BAD_ARGS，不静默当 0 处理（0 会让半径语义反转）。
        """
        if isinstance(value, int):
            return value
        s = str(value).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)

    def _exec_ranges(self, so):
        """用途：返回全部可执行段 [(va, size), ...]，供线性反汇编遍历。

        优先 exec_regions()：它来自 PT_LOAD 且按 PF_X 过滤，返回的是
        **4 元素** (va, end, off, flags)，不是 (va, size) —— 这里取 end-va。
        节表模式作为兜底：某些 so 的节表被抹时 exec_regions 仍可用，
        反过来没有 PT_LOAD 信息的内存 dump 才靠 is_exec 的节。
        """
        out = []
        for va, end, _off, _fl in getattr(so, "exec_regions", lambda: [])():
            if end > va:
                out.append((va, end - va))
        if not out:
            for s in getattr(so, "sections", []):
                if getattr(s, "is_exec", False) and getattr(s, "size", 0):
                    out.append((s.addr, s.size))
        return out

    def _dest_reg(self, insn):
        """用途：取一条指令的目的寄存器（add 的 xd / ldr 的 xt / adr 的 xd）。

        虚调用模式要以「算出表地址的寄存器」为根去跟后面的 ldr 基址，
        目的寄存器就是根。解析不出来返回 None（不编造寄存器号）。
        """
        m = _RE_DST.match(insn.text or "")
        return m.group(1) if m else None

    def _virtual_call(self, insns, idx):
        """用途：从命中指令往后 8 条内找 `ldr xN,[xM,#imm]` + `blr xN` 的虚调用模式。

        判据（启发式，非数据流证明）：
          1. ldr 的基址 xM 与命中指令的目的寄存器一致，或由 `mov xM, xDest` 传递而来;
          2. 该 ldr 加载的 xN 随后被 blr 调用（同一 8 条窗口内）。
        命中返回 {addr, insn, load_addr, load_insn, base_reg, call_reg}；
        未命中返回 None。窗口外的调用一律不看，避免把无关 blr 算成证据。
        """
        root = self._dest_reg(insns[idx])
        if root is None:
            return None
        equiv = {root}  # 与表地址寄存器等价的寄存器集合（含 mov 传递）
        last = min(idx + 9, len(insns))  # 命中之后最多看 8 条
        for j in range(idx + 1, last):
            text = insns[j].text or ""
            m = _RE_MOV.match(text)
            if m and m.group(2) in equiv:
                equiv.add(m.group(1))
                continue
            m = _RE_LDR.match(text)
            if m is None or m.group(2) not in equiv:
                continue
            loaded = m.group(1)
            for k in range(j + 1, last):
                b = _RE_BLR.match(insns[k].text or "")
                if b and b.group(1) == loaded:
                    return {
                        "addr": hex(insns[k].addr),
                        "insn": insns[k].text,
                        "load_addr": hex(insns[j].addr),
                        "load_insn": insns[j].text,
                        "base_reg": m.group(2),
                        "call_reg": loaded,
                    }
        return None

    def run(self, session, args: dict):
        # 用途：插件入口——线性扫全 so 可执行段，列出所有指向 vtable 范围的静态引用。
        so_name = args.get("so")
        if not so_name or args.get("vtable_addr") is None:
            return {"error": "需要 so 与 vtable_addr 参数", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        # (1) 第一次修改（2026-11-26）
        # bug 原因：1) vtable_addr 未统一使用 parse_addr 且非法输入未返回 BAD_ADDR；
        #           2) 未捕获非 ARM64 架构下 Disassembler(so) 抛出的 ValueError。
        # 解决方案：使用 parse_addr 解析 vtable_addr（非法返 BAD_ADDR），捕获 ValueError 返 UNSUPPORTED_ARCH。
        vtable_addr = parse_addr(args["vtable_addr"])
        if vtable_addr is None:
            return {"ok": False, "error": f"非法地址参数 vtable_addr={args['vtable_addr']!r}",
                    "code": "BAD_ADDR"}
        try:
            radius = parse_addr(args.get("radius", 0x1000))
            if radius is None:
                raise ValueError(f"非法 radius={args.get('radius')!r}")
            limit = int(args.get("limit", 50))
        except (ValueError, TypeError) as exc:
            return {"error": f"参数解析失败：{exc}", "code": "BAD_ARGS"}
        if radius < 0 or limit < 0:
            return {"error": "radius 与 limit 不能为负", "code": "BAD_ARGS"}

        from server.core.disasm import Disassembler

        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}
        ranges = self._exec_ranges(so)
        if not ranges:
            return {"ok": True, "so": so.name, "vtable_addr": hex(vtable_addr),
                    "radius": hex(radius), "scanned_insns": 0, "hits": [],
                    "note": "该 so 没有可执行区域，0 命中是『没扫到任何指令』而非『没有引用』。"}

        scanned = 0
        hits = []
        for va, size in ranges:
            insns = dis.disasm_range(va, size)
            for idx, insn in enumerate(insns):
                scanned += 1
                # disasm 对 b/bl 也填 ref_addr；调用/跳转不是「加载表地址」，
                # 混进来会把误报当证据（与 xref_enhanced 同一过滤口径）。
                if getattr(insn, "is_call", False) or getattr(insn, "is_jump", False):
                    continue
                target = getattr(insn, "ref_addr", None)
                # adr 的立即数在 capstone 里已经是 PC+偏移 的绝对地址；
                # disasm.py 只给 adrp+add/adrp+ldr 填 ref_addr，裸 adr 在此补齐。
                if target is None and insn.mnemonic == "adr":
                    m = _RE_ADR.match(insn.text or "")
                    if m:
                        target = int(m.group(1), 0)
                if target is None:
                    continue
                target = int(target)
                in_range = (target == vtable_addr) if radius == 0 else \
                           (vtable_addr <= target < vtable_addr + radius)
                if not in_range:
                    continue
                if len(hits) >= limit:
                    break
                hits.append({
                    "site": hex(insn.addr),
                    "insn": insn.text,
                    "target": hex(target),
                    "virtual_call": self._virtual_call(insns, idx),
                })
            if len(hits) >= limit:
                break

        return {
            "ok": True,
            "so": so.name,
            "vtable_addr": hex(vtable_addr),
            "radius": hex(radius),
            "region_count": len(ranges),
            "scanned_insns": scanned,
            "hits": hits,
            "note": (
                "这是**静态**引用：某条 adrp+add / adr 计算出该表范围内的地址，"
                "只证明代码里存在指向这段范围的寻址，**不代表运行时一定读它**"
                "（分支可能不走、地址可能写进别的对象再由别的寄存器解引用）。"
                "radius>0 是范围匹配，不是精确等于表头；radius=0 才是精确匹配。"
                "virtual_call 的 `ldr xN,[xM,#imm]; blr xN` 是**启发式**模式匹配"
                "（只按寄存器名与命中后 8 条窗口，含 mov 传递，不做数据流证明）；"
                "未匹配到不代表没有虚调用。scanned_insns 是实际解码的指令条数，"
                "用来区分『扫描为空』与『确实没有引用』。"
            ),
        }
