"""增强交叉引用 + 基址重定位混淆检测（通用能力）。

## 解决什么问题

现有 `xrefs_to` 只覆盖 `bl` 调用和部分 adrp+add 数据引用。
使用者追格式串 `{"x0":"{0}",...}` 的引用者时，4 种方法（adrp+add /
.data.rel.ro / RELA / adrp 到该页）全部返回 0 处——
因为那个 so 用了**基址重定位混淆**：所有目标地址都是
`真地址 + 大偏移`，静态算出来超出模块范围。

本插件做两件事：
  1. find_refs：全库扫 adrp+add / adrp+ldr，输出所有数据引用（不只 bl）
  2. check_base_reloc：找出目标超出模块范围的组合，标记为 SUSPICIOUS，
     并尝试发现后续的抵消运算（add/eor/sub 里补偿的寄存器）

## 为什么是通用能力

adrp+add 是 ARM64 标准寻址模式，超范围判定用模块自身边界（客观事实），
不硬编码任何具体偏移（如 0xa62000）或寄存器（如 x23/x24）。
补偿寄存器的发现是数据流模式识别，不是针对某个 App 的特征。
"""
from __future__ import annotations

import re

from server.core.addr import parse_addr
from server.core.plugins import PluginBase

# 允许的 mode 及其归一化映射（兼容 docstring 中的别名）
_MODE_ALIAS = {
    "all": "all",
    "refs": "refs",
    "find_refs": "refs",
    "check_reloc": "check_reloc",
    "check_base_reloc": "check_reloc",
    "indirect": "indirect",
    "vtable": "indirect",
}


def _reg_norm(reg: str) -> str:
    """将 ARM64 的 xN/wN 寄存器归一为同号标识，便于追踪 32/64 位别名。"""
    r = reg.lower()
    if len(r) >= 2 and r[0] in ("x", "w") and r[1:].isdigit():
        return "r" + r[1:]
    return r


class Plugin(PluginBase):
    name = "xref_enhanced"
    description = "增强引用扫描 + 基址重定位混淆检测（超范围 adrp+add）"
    usage = ("args: {so: str, mode: 'refs'|'check_reloc'|'all'='all', "
             "addr: int|None=None, limit: int=100}")


    def _exec_ranges(self, so):
        """(1) 可执行区域：优先节表，无则用 exec_regions()（PT_LOAD）兜底。

        bug 原因：只遍历 so.sections，加固样本节表被抹（is_exec 全 False）时
                  恒返回 0 且无警告。实测 libDexHelper 有 0x4ca0 可执行字节
                  却扫出 0 条。
        解决方案：exec_regions() 兜底。
        """
        out = []
        for s in getattr(so, "sections", []):
            if getattr(s, "is_exec", False) and getattr(s, "size", 0):
                out.append((s.addr, s.size))
        if not out:
            for va, end, _off, _fl in getattr(so, "exec_regions", lambda: [])():
                if end > va:
                    out.append((va, end - va))
        return out

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so 参数", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        # (5) 第五次修改（2026-11-26）
        # bug 原因：1) addr_filter 在循环内才做 int(addr_filter)，不支持 "0x..." 字符串且非法值抛异常；
        #           2) mode 未做白名单校验，未知 mode 静默返回不完整结构，且与 docstring 别名不兼容；
        #           3) 未捕获非 ARM64 架构下 Disassembler 抛出的 ValueError。
        # 解决方案：循环外提前通过 parse_addr 解析 addr_filter，非法返 BAD_ADDR；
        #           校验并归一化 mode（兼容 find_refs/check_base_reloc/indirect/vtable），未知返 BAD_MODE；
        #           捕获非 ARM64 异常返 UNSUPPORTED_ARCH。
        raw_mode = args.get("mode", "all")
        mode = _MODE_ALIAS.get(str(raw_mode))
        if mode is None:
            return {"ok": False, "code": "BAD_MODE",
                    "error": f"未知 mode={raw_mode!r}，可选：all/refs/check_reloc/indirect/vtable"}

        raw_addr = args.get("addr")
        addr_filter = None
        if raw_addr is not None:
            addr_filter = parse_addr(raw_addr)
            if addr_filter is None:
                return {"ok": False, "code": "BAD_ADDR",
                        "error": f"非法地址参数 addr={raw_addr!r}"}

        limit = int(args.get("limit", 100))
        mod_lo, mod_hi = self._module_range(so)

        if mode == "indirect":
            return {
                "ok": True, "so": so.name,
                "module_range": [hex(mod_lo), hex(mod_hi)],
                "scanned_insns": 0, "scanned_ranges": 0,
                "indirect": self._vtable_refs(so, addr_filter, limit),
            }

        from server.core.disasm import Disassembler

        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}

        # 全库线性扫（可执行段）
        refs = []
        suspicious = []
        ranges = self._exec_ranges(so)
        if not ranges:
            return {"ok": False, "code": "NOTHING_SCANNED",
                    "error": "该 so 没有可执行区域"}
        # (4) 第四次修改（2026-11-18）：记录扫描规模，让 0 结果能区分原因。
        #     bug 原因：使用者反馈「xref_enhanced 返回 0 时不知道是函数里确实
        #               没有引用，还是根本没扫到」。旧实现只有 refs.count=0，
        #               既不说扫了多少指令，也不说覆盖了几个可执行段。
        #     解决方案：累计 scanned_insns / scanned_ranges，放进返回结构。
        scanned_insns = 0
        for _rva, _rsz in ranges:
            insns = dis.disasm_range(_rva, _rsz)
            scanned_insns += len(insns)
            for idx, insn in enumerate(insns):
                t = getattr(insn, "ref_addr", None)
                if t is None:
                    continue
                # (2) 排除调用/跳转：disasm 对 b/bl 也填 ref_addr，
                #     不过滤会让 suspicious 里 49/50 是普通 bl（实测）
                if getattr(insn, "is_call", False) or getattr(insn, "is_jump", False):
                    continue
                t = int(t)
                in_range = mod_lo <= t < mod_hi
                # 目标过滤
                if addr_filter is not None and addr_filter != t:
                    continue
                refs.append({
                    "from": hex(insn.addr),
                    "to": hex(t),
                    "in_range": in_range,
                    "insn": insn.text,
                })
                if not in_range and mode in ("check_reloc", "all"):
                    over = (t - mod_hi) if t >= mod_hi else (mod_lo - t)
                    # (2) 只标记"大偏移"（>64KB）——正常 GOT/PLT 外部引用
                    #     通常就在模块范围附近，不会偏离这么远。
                    if over > 0x10000:
                        comp = self._find_compensation(insns, idx)
                        suspicious.append({
                            "from": hex(insn.addr),
                            "computed": hex(t),
                            "out_of_range_by": hex(over),
                            "insn": insn.text,
                            "compensation": comp,
                            "confidence": "high" if comp else "medium",
                            "note": ("目标超出模块 [0x%x,0x%x) 达 %s，"
                                     "疑似基址重定位混淆（大偏移+运行时补偿）"
                                     % (mod_lo, mod_hi, hex(over))),
                        })

        out = {"ok": True, "so": so.name,
               "module_range": [hex(mod_lo), hex(mod_hi)],
               # (4) 扫描规模：0 结果时据此判断"确实没有"还是"没扫到"
               "scanned_insns": scanned_insns,
               "scanned_ranges": len(ranges)}
        if mode in ("refs", "all"):
            out["refs"] = {"count": len(refs), "items": refs[:limit]}
        if mode in ("check_reloc", "all"):
            out["suspicious"] = {"count": len(suspicious),
                                 "items": suspicious[:limit]}
        # (3) 第三次修改（2026-11-18）：补 vtable / 函数指针表引用。
        #     bug 原因：使用者反馈「xref_enhanced 找不到虚调用者」。核实成立：
        #               本插件只扫 adrp+add / adrp+ldr 的数据引用，且主动
        #               排除 is_call/is_jump。而虚调用的目标在
        #               `ldr x8,[x0,#8]; blr x8` 的**寄存器**里，静态无操作数
        #               可查——实测对 vtable 目标地址查 refs 得 0。
        #     解决方案：重定位表里 addend 落在可执行段的条目，就是
        #               「函数指针表项」，它的 r_offset 才是**证据位置**。
        #               单列 indirect 一节，明确说明这是"函数指针表引用"，
        #               而不是"代码里 adrp 到它"。
        if mode in ("refs", "all", "check_reloc"):
            out["indirect"] = self._vtable_refs(so, addr_filter, limit)
        return out

    def _vtable_refs(self, so, addr_filter, limit):
        """vtable / 函数指针表引用（证据来自重定位表，不是代码扫描）。

        返回 {count, items, note}。items 每项：
            slot            函数指针表的槽地址（r_offset）
            target          槽里指向的函数地址
            target_function 该地址所在函数名
            rtype           重定位类型
            block           [起, 止) 该槽所在的连续指针块（vtable 范围）
        """
        # (6) 第六次修改（2026-11-26）
        # bug 原因：1) _vtable_refs 未校验 is_vtable 与 block_end > block_start，
        #              对 IRELATIVE 等条目会输出假块 ["0x0", "0x0"]；
        #           2) _find_compensation 未检查补偿指令是否引用了当前 adrp/add 的目的寄存器，产生无关误报。
        # 解决方案：仅当 blk.get("is_vtable") 且 block_end > block_start 时输出 block；
        #           _find_compensation 提取当前指令目的寄存器，仅保留真正引用它的补偿指令。
        try:
            from server.core import rela as _rela

            parsed_filter = parse_addr(addr_filter) if addr_filter is not None else None
            items = []
            for it in _rela.rela_dump(so, 0, 0, "code_target", 0):
                tgt = int(it["addend_hex"], 16)
                if parsed_filter is not None and parsed_filter != tgt:
                    continue
                slot = int(it["offset_hex"], 16)
                blk = _rela.vtable_at(so, slot)
                fn = so.function_at(tgt)
                b_start = blk.get("block_start")
                b_end = blk.get("block_end")
                has_block = (bool(blk.get("is_vtable"))
                             and b_start is not None
                             and b_end is not None
                             and b_end > b_start)
                items.append({
                    "slot": hex(slot),
                    "target": hex(tgt),
                    "target_function": ((fn.name if fn and fn.name
                                         else f"sub_{tgt:x}") if fn else None),
                    "at_function_entry": bool(fn and fn.addr == tgt),
                    "rtype": it.get("rtype_name", ""),
                    "block": [hex(b_start), hex(b_end)] if has_block else None,
                    "at_function_entry_slot": blk.get("index") if has_block else None,
                })
            return {
                "count": len(items),
                "items": items[:limit],
                "note": ("这些是**函数指针表引用**（证据=重定位表里的槽），"
                         "不是代码里 adrp 到该地址。虚调用 "
                         "`ldr x8,[x0,#n]; blr x8` 的目标在寄存器里，静态"
                         "无法从指令操作数得到——只有表里那条记录能证明"
                         "「这个函数被放在某张表里」。"),
            }
        except Exception as exc:                          # noqa: BLE001
            return {"count": 0, "items": [],
                    "error": f"重定位解析失败：{type(exc).__name__}: {exc}"}


    def _find_compensation(self, insns, idx):
        """在后继指令里找引用了当前 adrp/add 目的寄存器的补偿运算（add/eor/sub）。"""
        cur_text = insns[idx].text or ""
        m0 = re.match(r"\w+\s+(x\d+|w\d+)\b", cur_text)
        tracked = {_reg_norm(m0.group(1))} if m0 else set()
        found = []
        for insn in insns[idx + 1: idx + 9]:
            text = insn.text or ""
            m = re.match(r"(add|eor|sub)\s+(\w+),\s*(\w+),\s*(\w+)", text)
            if m:
                dst_n = _reg_norm(m.group(2))
                s1_n = _reg_norm(m.group(3))
                s2_n = _reg_norm(m.group(4))
                if not tracked or s1_n in tracked or s2_n in tracked:
                    found.append({"addr": hex(insn.addr),
                                  "op": m.group(1),
                                  "dst": m.group(2),
                                  "src1": m.group(3),
                                  "src2": m.group(4),
                                  "insn": text})
                    if tracked:
                        tracked.add(dst_n)
                elif dst_n in tracked:
                    tracked.discard(dst_n)
        return found

    def _module_range(self, so):
        # (1) 优先 PT_LOAD：那是真实映射范围，不会被 .note 这类小节干扰
        loads = getattr(so, "_loads", []) or []
        if loads:
            return (min(a for a, _b, _o, _f in loads),
                    max(b for _a, b, _o, _f in loads))
        # 兜底：只用可执行+数据节，排除 notes 之类
        lows, highs = [], []
        for s in getattr(so, "sections", []):
            if getattr(s, "size", 0) and getattr(s, "addr", 0):
                lows.append(s.addr); highs.append(s.addr + s.size)
        if not lows:
            return (0, 1 << 63)
        return (min(lows), max(highs))
