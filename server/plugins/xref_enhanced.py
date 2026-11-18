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

from server.core.plugins import PluginBase


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

        from server.core.disasm import Disassembler

        mode = args.get("mode", "all")
        addr_filter = args.get("addr")
        limit = int(args.get("limit", 100))
        mod_lo, mod_hi = self._module_range(so)
        dis = Disassembler(so)

        # 全库线性扫（可执行段）
        refs = []
        suspicious = []
        ranges = self._exec_ranges(so)
        if not ranges:
            return {"ok": False, "code": "NOTHING_SCANNED",
                    "error": "该 so 没有可执行区域"}
        for _rva, _rsz in ranges:
            insns = dis.disasm_range(_rva, _rsz)
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
                if addr_filter is not None and int(addr_filter) != t:
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
               "module_range": [hex(mod_lo), hex(mod_hi)]}
        if mode in ("refs", "all"):
            out["refs"] = {"count": len(refs), "items": refs[:limit]}
        if mode in ("check_reloc", "all"):
            out["suspicious"] = {"count": len(suspicious),
                                 "items": suspicious[:limit]}
        return out

    def _find_compensation(self, insns, idx):
        """在后继指令里找可能的补偿运算（add/eor/sub 带寄存器）。"""
        found = []
        for insn in insns[idx + 1: idx + 9]:
            m = re.match(r"(add|eor|sub)\s+(\w+),\s*(\w+),\s*(\w+)", insn.text or "")
            if m:
                found.append({"addr": hex(insn.addr),
                              "op": m.group(1),
                              "dst": m.group(2),
                              "src1": m.group(3),
                              "src2": m.group(4),
                              "insn": insn.text})
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
