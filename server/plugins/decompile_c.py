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

from server.core.addr import parse_addr
from server.core.plugins import PluginBase


def _extract_last_hex_imm(text: str) -> str | None:
    """从跳转指令文本提取最后一个 #(0x...) 目标地址，避免误取 tbz/tbnz 的位号。"""
    hits = re.findall(r"#(0x[0-9a-fA-F]+)", text)
    return hits[-1] if hits else None


def _pair_step(reg: str) -> int:
    """根据 ARM64 寄存器前缀返回 ldp/stp 第二个槽位的字节步长。"""
    low = reg.lower()
    if low.startswith(("w", "s")):
        return 4
    if low.startswith("q"):
        return 16
    return 8


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

        addr = parse_addr(args["addr"])
        if addr is None:
            return {"ok": False, "code": "BAD_ADDR",
                    "error": f"非法地址参数 addr={args['addr']!r}"}
        fn = so.function_at(addr)
        if fn is None:
            return {"error": "地址不在函数内", "code": "NO_FUNCTION",
                    "hint": "先 build_xrefs"}
        max_lines = int(args.get("max_lines", 300))

        try:
            dis = Disassembler(so)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}
        insns = dis.disasm_range(fn.addr, max(fn.size, 4))
        blocks = self._basic_blocks(insns, fn.addr, fn.addr + fn.size)

        # (1) 第一次修改 bug 原因：块末 if 行是写死的 "cond"，且条件跳转指令在块内
        #     由 _to_expr 输出后又在块末重复输出；未识别指令被静默丢弃。
        #     解决方案：条件跳转不在块内输出，块末统一输出"源指令 @地址: 真实条件"，
        #     未知指令保留原始文本，记录每条 if 行地址与未恢复条件数。
        lines = [f"// {so.name}!{fn.name or hex(fn.addr)} @ {fn.addr:#x}",
                 f"void {fn.name or ('sub_' + format(fn.addr, 'x'))}() {{"]
        if_lines = []                   # 每条 if 行对应的源指令地址
        condition_not_recovered = 0     # 无法识别条件的条件跳转数量
        truncated = False

        def emit(line: str):
            """追加一行；达到 max_lines 时截断并置位，供外层提前 break。"""
            nonlocal truncated
            if truncated:
                return
            lines.append(line)
            if len(lines) >= max_lines:
                lines.append("  // ... 截断（max_lines）")
                truncated = True

        for b in blocks:
            if truncated:
                break
            lines.append(f"  // block {b['start']}")
            succ = b.get("succ", [])
            block_insns = b["insns"]
            for idx, ins in enumerate(block_insns):
                if truncated:
                    break
                text = ins["text"]
                # 块末的条件跳转留到块末统一输出，避免与真实条件重复
                if idx == len(block_insns) - 1 and self._is_cond_branch(text):
                    continue
                expr = self._to_expr(text)
                if expr:
                    emit("  " + expr)
                elif self._is_control_flow(text):
                    # 无条件跳转/返回由块末统一处理，不在块内产生注释
                    continue
                else:
                    # 未识别指令不再静默丢弃，保留原始文本供对回汇编
                    emit(f"  // {ins['addr']}  {text}")

            tail = block_insns[-1]["text"]
            tail_addr = block_insns[-1]["addr"]
            info = self._cond_branch_info(tail)
            if info:
                cond_line = (f"  if ({info['raw']} @{tail_addr}: "
                             f"{info['cond']}) goto {info['target']};")
                emit(cond_line)
                if_lines.append({"addr": tail_addr, "line": cond_line.strip()})
                false_target = next((s[0] for s in succ if s[1] == "false"), None)
                if false_target:
                    emit(f"  else goto {false_target};")
            elif self._is_cond_branch(tail):
                # 识别为条件跳转但解析不出条件：计数并降级，不假装已恢复
                condition_not_recovered += 1
                target = next((s[0] for s in succ if s[1] == "true"), hex(fn.addr))
                emit(f"  if (cond) goto {target};  // 条件未识别 @{tail_addr}")
            else:
                m = re.match(r"(b|br|blr)\b.*?#(0x[0-9a-f]+)", tail)
                if m:
                    emit(f"  goto {m.group(2)};")
                elif re.match(r"(br|blr)\b", tail):
                    # 间接跳转目标无法静态确定，如实说明而不是丢弃
                    emit(f"  // {tail_addr}  {tail}  (间接跳转，目标未恢复)")
                # ret 由 _to_expr 输出 return;；fallthrough 无需额外输出

        lines.append("}")
        code = "\n".join(lines)
        return {
            "ok": True, "so": so.name,
            "function": fn.name or f"sub_{fn.addr:x}",
            "addr": hex(fn.addr), "size": fn.size,
            "block_count": len(blocks),
            "pseudocode": code,
            "if_lines": if_lines,
            "condition_not_recovered": condition_not_recovered,
            "note": ("CFG 结构化伪代码，不是 SSA 级反编译。"
                     "变量/类型未恢复，关键结论需核对原始汇编。"),
        }

    # (5) 第五次修改（2026-11-26）
    # bug 原因：tbz/tbnz 位号 >= 10（如 tbz w0, #0xf, #0x1030）时，re.search/惰性正则
    #           误将第一个 #0xf 当成跳转目标而非最后一个 #0x1030。
    # 解决方案：统一通过 _extract_last_hex_imm 提取最后一个 #(0x...) 作为跳转目标。
    def _basic_blocks(self, insns, start, end):
        if not insns:
            return []
        leaders = {start}
        for i in insns:
            m = re.match(r"(b|br|blr|cbz|cbnz|tbz|tbnz|ret|b\.\w+)\b", i.text)
            if m:
                t_hex = _extract_last_hex_imm(i.text)
                if t_hex:
                    tgt = int(t_hex, 16)
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
            m_op = re.match(r"(b\.\w+|b|br|blr|cbz|cbnz|tbz|tbnz)\b", last)
            t_hex = _extract_last_hex_imm(last) if m_op else None
            if m_op and t_hex:
                op = m_op.group(1)
                kind = "true" if op.startswith("b.") or \
                       op in ("cbz", "cbnz", "tbz", "tbnz") else "jump"
                succ.append((t_hex, kind))
                if kind == "true":
                    # (4) 第四次修改 bug 原因：假分支原用"跳转目标+4"计算，
                    #     tbz/cbz 的真目标是别处，+4 得到的不是 fallthrough 地址。
                    #     解决方案：假分支 = 块末条件指令地址 + 4（即下一条顺序指令）。
                    fall = int(ins[-1]["addr"], 16) + 4
                    succ.append((hex(fall), "false"))
            else:
                succ.append((hex(nxt), "fallthrough"))
            out.append({"start": hex(l), "end": hex(nxt),
                        "insns": ins, "succ": succ})
        return out

    # ---- 条件与比较指令的通用识别（无样本/地址/so 特调）----

    # (2) 第二次修改 bug 原因：_to_expr 不识别 cmp/cmn/tst，比较指令被丢弃，
    #     输出丢失"比较产生了什么标志"。解决方案：转成 flags = <表达式>;。
    _FLAG_OPS = {
        "cmp": "-", "cmn": "+",  # cmn 是操作数取负的减法，语义近似，注明即可
        "tst": "&",
    }

    _CONDS = {
        "eq": "ZF", "ne": "ZF == 0", "cs": "CF", "cc": "CF == 0",
        "mi": "NF", "pl": "NF == 0", "vs": "VF", "vc": "VF == 0",
        "hi": "CF == 1 && ZF == 0", "ls": "CF == 0 || ZF == 1",
        "ge": "NF == VF", "lt": "NF != VF",
        "gt": "ZF == 0 && NF == VF", "le": "ZF == 1 || NF != VF",
        "al": "true", "nv": "false",
    }

    def _is_cond_branch(self, text: str) -> bool:
        """判断是否是条件跳转（含 b.<cond> / cbz / cbnz / tbz / tbnz）。"""
        return bool(re.match(
            r"(b\.[a-z]+|cbz|cbnz|tbz|tbnz)\b", text, re.IGNORECASE))

    def _is_control_flow(self, text: str) -> bool:
        """无条件跳转 / 返回：由块末统一处理，块内不再输出重复注释。"""
        return bool(re.match(r"(b|br|blr|ret)\b", text))

    @staticmethod
    def _imm(v: str) -> str:
        """去掉立即数的 '#' 前缀，保留原始 0x 字面量。"""
        return v[1:] if v.startswith("#") else v

    @classmethod
    def _cond_branch_info(cls, text: str) -> dict | None:
        """解析条件跳转，返回 {raw, cond, target}；解析不出来返回 None。"""
        # b.<cond> <target>
        m = re.match(r"b\.([a-z]+)\s+(#?0x[0-9a-f]+)", text, re.IGNORECASE)
        if m:
            suffix = m.group(1).lower()
            return {"raw": text,
                    "cond": cls._CONDS.get(suffix, f"cond.{suffix}"),
                    "target": m.group(2).lstrip("#")}
        # cbz / cbnz <reg>, <target>
        m = re.match(r"(cbz|cbnz)\s+(x\d+|w\d+),\s*(#?0x[0-9a-f]+)",
                     text, re.IGNORECASE)
        if m:
            op = "==" if m.group(1).lower() == "cbz" else "!="
            return {"raw": text,
                    "cond": f"{m.group(2)} {op} 0",
                    "target": m.group(3).lstrip("#")}
        # tbz / tbnz <reg>, #bit, <target>
        # bit 可能是十进制(#0/#2)或十六进制(#0x2)，target 同理，统一用 _IMM 模式
        imm = r"#?(?:0x[0-9a-f]+|\d+)"
        m = re.match(rf"(tbz|tbnz)\s+(x\d+|w\d+),\s*({imm}),\s*({imm})",
                     text, re.IGNORECASE)
        if m:
            op = "==" if m.group(1).lower() == "tbz" else "!="
            bit = cls._imm(m.group(3))
            return {"raw": text,
                    "cond": f"({m.group(2)} & (1<<{bit})) {op} 0",
                    "target": m.group(4).lstrip("#")}
        return None

    # (6) 第六次修改（2026-11-26）
    # bug 原因：1) movn 直接输出原立即数而非按位取反值；
    #           2) movz 带 lsl #shift 时输出多余逗号且丢弃移位量；
    #           3) 不支持寄存器到寄存器的 mov rd, rm；
    #           4) ldp/stp 不处理负偏移、零偏移和 32 位寄存器（w*/s* 步长应为 +4 而非写死 +8）。
    # 解决方案：完整解析 mov/movz/movn（含 lsl 与位取反）和 mov rd, rm；
    #           ldp/stp 区分寄存器宽度步长并正确计算正/负/零偏移。
    def _to_expr(self, text: str) -> str | None:
        """把常见指令转成类 C 表达式；不认识的返回 None（保留汇编由调用方决定）。"""
        m = re.match(
            r"(mov|movz|movn)\s+(x\d+|w\d+|sp),\s*#(-?0x[0-9a-fA-F]+|-?\d+)"
            r"(?:,\s*lsl\s*#(0x[0-9a-fA-F]+|\d+))?",
            text,
        )
        if m:
            op, rd = m.group(1), m.group(2)
            imm = int(m.group(3), 0)
            shift = int(m.group(4), 0) if m.group(4) else 0
            val = imm << shift
            if op == "movn":
                mask = 0xFFFFFFFF if rd.startswith("w") else 0xFFFFFFFFFFFFFFFF
                val = (~val) & mask
            return f"{rd} = {val:#x};"
        m = re.match(r"mov\s+(x\d+|w\d+|sp),\s*(x\d+|w\d+|sp|xzr|wzr)\b", text)
        if m:
            return f"{m.group(1)} = {m.group(2)};"
        m = re.match(r"(add|sub|eor|and|orr|mul)\s+(x\d+|w\d+),\s*(x\d+|w\d+),\s*(.+)", text)
        if m:
            op = {"add": "+", "sub": "-", "eor": "^", "and": "&",
                  "orr": "|", "mul": "*"}[m.group(1)]
            return f"{m.group(2)} = {m.group(3)} {op} {m.group(4)};"
        # (3) 第三次修改 bug 原因：ldr/str 正则把助记符(m.group(1))当目的寄存器，
        #     "ldr x8, [x0]" 被输出成 "ldr = mem[x0]"，目的寄存器丢失。
        #     解决方案：正确取 m.group(2) 为目的寄存器；并补 ldp/stp 双寄存器访存。
        m = re.match(r"(ldr|str)\s+(x\d+|w\d+|s\d+|d\d+|q\d+|xzr|wzr),\s*\[([^\]]+)\]", text)
        if m:
            mem = m.group(3)
            return (f"{m.group(2)} = mem[{mem}];" if m.group(1) == "ldr"
                    else f"mem[{mem}] = {m.group(2)};")
        m = re.match(
            r"(ldp|stp)\s+([xwsdq]\d+|xzr|wzr),\s*([xwsdq]\d+|xzr|wzr),\s*\[([^\]]+)\]",
            text,
        )
        if m:
            regs, mem = (m.group(2), m.group(3)), m.group(4).strip()
            step = _pair_step(regs[0])
            mo = re.match(r"(.+?),\s*#(-?0x[0-9a-fA-F]+|-?\d+)$", mem)
            if mo:
                base, off = mo.group(1).strip(), mo.group(2)
                val2 = int(off, 0) + step
                off2 = f"-0x{-val2:x}" if val2 < 0 else f"0x{val2:x}"
                mem2 = f"{base}, #{off2}"
            else:
                mem2 = f"{mem}, #{step:#x}"
            if m.group(1) == "ldp":
                return f"{regs[0]} = mem[{mem}]; {regs[1]} = mem[{mem2}];"
            return f"mem[{mem}] = {regs[0]}; mem[{mem2}] = {regs[1]};"
        # 比较/测试指令：产出标志，供后续 b.<cond> 使用
        m = re.match(r"(cmp|cmn|tst)\s+(x\d+|w\d+),\s*(\S+)", text)
        if m:
            op = self._FLAG_OPS[m.group(1)]
            rhs = self._imm(m.group(3))
            note = "  // cmn 为加取负的近似" if m.group(1) == "cmn" else ""
            return f"flags = {m.group(2)} {op} {rhs};{note}"
        m = re.match(r"bl\s+#(0x[0-9a-f]+)", text)
        if m:
            return f"call {m.group(1)}();"
        if re.match(r"ret\b", text):
            return "return;"
        return None
