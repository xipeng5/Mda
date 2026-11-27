"""ARM64 结构化伪 C 代码生成器（解耦模块，面向 F5 并排对照视图）。

职责：把 ARM64 反汇编指令提升为可读的 C 风格伪代码，同时为每一行保留精确源指令地址，
支持与左侧反汇编双向联动高亮。

核心变换（全部基于确定性指令语义，绝不凭空编造逻辑）：
  1. 自动折叠栈帧保存/恢复与 PAC/Stack-Canary 噪声指令
  2. 推断函数入参（a1..a8）与局部变量名（v8..v28 / var_XX）
  3. 折叠 adrp + add/ldr 为真实字符串字面量或全局符号地址
  4. 折叠 cmp/cmn/tst 到后续 b.<cond>/csel/csinc/cset 真实 C 条件表达式
  5. 折叠 bl 前的参数赋值（x0..x3）为标准 C 函数调用 `func(arg1, arg2)`
  6. 识别常见 ARM64 算术/位运算/类型扩展/定宽指针解引用（*(uint8_t *) 等）
  7. 识别简单 `if (cond) { ... }` 与 `if (cond) return ...;` 结构，仅对实际被跳目标生成标签
"""
from __future__ import annotations

import re
from typing import Any

from server.core.disasm import Disassembler
from server.core.elf_model import SoFile
from server.models import Instruction

# 纯噪声帧/安全指令
_SKIP_MNEMS = frozenset({"paciasp", "autiasp", "pacibsp", "autibsp", "bti", "nop", "hint"})

# ARM64 条件后缀 -> C 比较运算符（用于配对 cmp a, b）
_CMP_OPS = {
    "eq": "==", "ne": "!=",
    "lt": "<",  "le": "<=", "gt": ">",  "ge": ">=",
    "lo": "<",  "cc": "<",  "ls": "<=", "hi": ">", "hs": ">=", "cs": ">=",
    "mi": "<",  "pl": ">=",
}
_CMP_INVERT = {
    "eq": "ne", "ne": "eq",
    "lt": "ge", "ge": "lt", "le": "gt", "gt": "le",
    "lo": "hs", "hs": "lo", "cc": "cs", "cs": "cc",
    "ls": "hi", "hi": "ls", "mi": "pl", "pl": "mi",
}
_UNSIGNED_CONDS = frozenset({"lo", "cc", "ls", "hi", "hs", "cs"})

# 内存读写指令对应的 C 指针类型
_LOAD_TYPES = {
    "ldr":   ("uint64_t", "uint32_t"),
    "ldur":  ("uint64_t", "uint32_t"),
    "ldar":  ("uint64_t", "uint32_t"),
    "ldxr":  ("uint64_t", "uint32_t"),
    "ldaxr": ("uint64_t", "uint32_t"),
    "ldrb":  ("uint8_t",  "uint8_t"),
    "ldurb": ("uint8_t",  "uint8_t"),
    "ldarb": ("uint8_t",  "uint8_t"),
    "ldrh":  ("uint16_t", "uint16_t"),
    "ldurh": ("uint16_t", "uint16_t"),
    "ldarh": ("uint16_t", "uint16_t"),
    "ldrsb": ("int8_t",   "int8_t"),
    "ldrsh": ("int16_t",  "int16_t"),
    "ldrsw": ("int32_t",  "int32_t"),
    "ldursw": ("int32_t", "int32_t"),
}
_STORE_TYPES = {
    "str":   ("uint64_t", "uint32_t"),
    "stur":  ("uint64_t", "uint32_t"),
    "stlr":  ("uint64_t", "uint32_t"),
    "strb":  ("uint8_t",  "uint8_t"),
    "sturb": ("uint8_t",  "uint8_t"),
    "stlrb": ("uint8_t",  "uint8_t"),
    "strh":  ("uint16_t", "uint16_t"),
    "sturh": ("uint16_t", "uint16_t"),
    "stlrh": ("uint16_t", "uint16_t"),
}

# 常见标准库/Android 函数参数个数提示（用于折叠 bl 前的 x0..x3 参数）
_KNOWN_ARITY: dict[str, int] = {
    "strlen": 1, "free": 1, "close": 1, "atoi": 1, "atol": 1, "strdup": 1, "malloc": 1,
    "strcmp": 2, "strcasecmp": 2, "strchr": 2, "strrchr": 2, "strstr": 2,
    "strcpy": 2, "strcat": 2, "calloc": 2, "realloc": 2, "fopen": 2,
    "strncmp": 3, "strncasecmp": 3, "strncpy": 3, "memcpy": 3, "memmove": 3,
    "memset": 3, "memcmp": 3, "read": 3, "write": 3, "open": 3,
    "snprintf": 4, "vsnprintf": 4, "__android_log_print": 4, "__android_log_write": 3,
    "__system_property_get": 2, "property_get": 3,
    "pthread_mutex_lock": 1, "pthread_mutex_unlock": 1, "pthread_mutex_trylock": 1,
}

_REG_RE = re.compile(r"^(x|w|q|d|s)(\d+)$")


def _reg_num(reg: str) -> int | None:
    """提取通用寄存器编号（x0/w0 -> 0），非 x/w 寄存器返回 None。"""
    r = reg.strip().lower()
    if r in ("xzr", "wzr"):
        return -1
    m = re.match(r"^[xw](\d+)$", r)
    return int(m.group(1)) if m else None


def _is_32(reg: str) -> bool:
    return reg.strip().lower().startswith("w")


def _fmt_imm(tok: str) -> str:
    """格式化 ARM64 立即数为易读 C 常量（去掉 #，小正数用十进制，大数用十六进制）。"""
    s = tok.strip()
    if s.startswith("#"):
        s = s[1:]
    try:
        v = int(s, 0)
    except ValueError:
        return s
    if -16 <= v <= 16:
        return str(v)
    if v < 0:
        return f"-0x{-v:x}"
    return f"0x{v:x}"


def _parse_int(tok: str) -> int | None:
    s = tok.strip().lstrip("#")
    try:
        return int(s, 0)
    except ValueError:
        return None


def _split_ops(op_str: str) -> list[str]:
    """按顶层逗号拆分操作数（保留方括号 [x0, #8] 内部逗号）。"""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in op_str:
        if ch == "[":
            depth += 1
            cur.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return [x for x in out if x]


def _c_str_escape(s: str) -> str:
    """把真实字符串转义成合法 C 字面量（截断过长文本）。"""
    raw = s[:72]
    esc = (
        raw.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{esc}"'


class PseudoCGenerator:
    """ARM64 → 伪 C 代码生成器（每行附带精确源指令地址）。"""

    def __init__(self, so: SoFile, disasm: Disassembler, resolve=None):
        self.so = so
        self.disasm = disasm
        self.resolve = resolve

    def generate(self, fn_addr: int) -> dict[str, Any]:
        """生成结构化伪 C 代码与逐行源地址映射。"""
        fn = self.so.function_at(fn_addr)
        if fn is None:
            return {
                "ok": False,
                "error": f"地址 {fn_addr:#x} 不在任何已知函数内",
                "code": f"// 地址 {fn_addr:#x} 不在任何已知函数内",
                "lines": [],
            }
        insns = fn.instructions or self.disasm.disasm_function(fn_addr)
        if not insns:
            return {
                "ok": True,
                "code": f"// 函数 {fn.name or hex(fn.addr)} 无指令",
                "lines": [{"addr": fn.addr, "text": f"// 函数 {fn.name or hex(fn.addr)} 无指令"}],
            }

        fn_name = fn.name or f"sub_{fn.addr:x}"
        fn_start = fn.addr
        fn_end = fn.addr + max(fn.size, 4)

        # 1) 推断函数使用到的入参（x0..x7 中先读后写的寄存器）
        param_count = self._infer_param_count(insns)
        arg_names = {i: f"a{i + 1}" for i in range(param_count)}

        # 2) 收集所有函数内部跳转目标，仅对真实跳转目标生成 label_xxxx:
        internal_targets: set[int] = set()
        for ins in insns:
            tgt = self._branch_target(ins)
            if tgt is not None and fn_start <= tgt < fn_end:
                internal_targets.add(tgt)

        # 3) 识别极短尾块（仅 1 条给 x0/w0 赋值 + b/ret），便于把 `if (c) goto L` 折叠为 `if (c) return K;`
        short_ret_blocks = self._detect_short_return_blocks(insns, fn_start, fn_end)

        # 4) 识别栈帧保存/恢复与 stack-canary 模板地址集合
        frame_skip = self._detect_frame_and_canary(insns)

        # 5) 逐指令提升为中间语句列表：[(addr, kind, text, extra)]
        #    kind: "label" | "stmt" | "if_goto" | "if_ret" | "goto" | "ret"
        stmts = self._lift_statements(
            insns, arg_names, internal_targets, short_ret_blocks, frame_skip, fn_start, fn_end
        )

        # 6) 轻量级结构化：折叠单块 `if (!cond) { ... }` 并裁剪未被引用的标签
        structured = self._structure_blocks(stmts)

        # 7) 组装最终 C 函数文本 + 行级源地址数组
        ret_type = self._infer_return_type(insns)
        sig_params = ", ".join(f"int64_t a{i + 1}" for i in range(param_count))
        out_lines: list[dict[str, Any]] = [
            {"addr": None, "text": f"// {self.so.name}!{fn_name} @ {fn.addr:#x} ({len(insns)} insns, {fn.size} B)"},
            {"addr": fn.addr, "text": f"{ret_type} {fn_name}({sig_params}) {{"},
        ]
        out_lines.extend(structured)
        out_lines.append({"addr": None, "text": "}"})

        code_text = "\n".join(x["text"] for x in out_lines)
        return {
            "ok": True,
            "so": self.so.name,
            "addr": hex(fn.addr),
            "style": "c",
            "code": code_text,
            "lines": out_lines,
        }

    # ---------------------------------------------------------------- 静态辅助分析

    def _var(self, reg: str, arg_names: dict[int, str], written: set[int]) -> str:
        """寄存器转可读 C 变量名（未覆写的入参用 a1..a8，其余用 v0..v28 / sp）。"""
        r = reg.strip().lower()
        if r in ("xzr", "wzr"):
            return "0"
        if r == "sp":
            return "sp"
        if r == "x29" or r == "fp":
            return "fp"
        if r == "x30" or r == "lr":
            return "lr"
        n = _reg_num(r)
        if n is None:
            return r
        if n in arg_names and n not in written:
            return arg_names[n]
        return f"v{n}"

    def _lhs_var(self, reg: str) -> str:
        r = reg.strip().lower()
        if r in ("xzr", "wzr"):
            return "_discard"
        if r == "sp":
            return "sp"
        n = _reg_num(r)
        return f"v{n}" if n is not None else r

    def _branch_target(self, ins: Instruction) -> int | None:
        m = ins.mnemonic.lower()
        if not (m == "b" or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz")):
            return None
        if ins.call_target is not None:
            return ins.call_target
        hits = re.findall(r"#(0x[0-9a-fA-F]+)", ins.op_str)
        return int(hits[-1], 16) if hits else None

    def _infer_param_count(self, insns: list[Instruction]) -> int:
        """扫描开头基本块，判断 x0..x7 中哪些在首次写之前被读取。"""
        written: set[int] = set()
        read_before_write: set[int] = set()
        for ins in insns[:48]:
            m = ins.mnemonic.lower()
            if m in _SKIP_MNEMS:
                continue
            ops = _split_ops(ins.op_str)
            # bl 会读取前几个参数并覆写 x0
            if m in ("bl", "blr"):
                if 0 not in written:
                    read_before_write.add(0)
                written.add(0)
                break
            dst_idx = self._written_reg_indices(m, ops)
            src_idx = self._read_reg_indices(m, ops)
            for r in src_idx:
                if 0 <= r <= 7 and r not in written:
                    read_before_write.add(r)
            for r in dst_idx:
                if 0 <= r <= 7:
                    written.add(r)
            if m == "ret":
                break
        if not read_before_write:
            return 0
        return min(8, max(read_before_write) + 1)

    def _infer_return_type(self, insns: list[Instruction]) -> str:
        """判断函数是否向 x0/w0 写过返回值。"""
        for ins in insns:
            m = ins.mnemonic.lower()
            if m in ("bl", "blr"):
                return "int64_t"
            ops = _split_ops(ins.op_str)
            if 0 in self._written_reg_indices(m, ops):
                return "int64_t"
        return "void"

    def _written_reg_indices(self, m: str, ops: list[str]) -> list[int]:
        if not ops:
            return []
        if m.startswith("st") or m in ("cmp", "cmn", "tst", "b", "br", "cbz", "cbnz", "tbz", "tbnz", "ret") or m.startswith("b."):
            return []
        if m in ("ldp", "ldxp", "ldnp") and len(ops) >= 2:
            out = []
            for r in (ops[0], ops[1]):
                n = _reg_num(r)
                if n is not None and n >= 0:
                    out.append(n)
            return out
        n = _reg_num(ops[0])
        return [n] if (n is not None and n >= 0) else []

    def _read_reg_indices(self, m: str, ops: list[str]) -> list[int]:
        if not ops:
            return []
        # 访存/比较/跳转类所有操作数里的寄存器都算读
        if m.startswith("st") or m in ("cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz", "br", "blr"):
            target_ops = ops
        elif m in ("ldp", "ldxp", "ldnp"):
            target_ops = ops[2:]
        else:
            target_ops = ops[1:]
        out: list[int] = []
        for op in target_ops:
            for tok in re.findall(r"\b[xw]\d+\b", op.lower()):
                n = _reg_num(tok)
                if n is not None and n >= 0:
                    out.append(n)
        return out

    def _detect_frame_and_canary(self, insns: list[Instruction]) -> set[int]:
        """标记纯栈帧保存/恢复（x19..x30 压栈出栈、sp 调整）及 stack canary 样板指令。"""
        skip: set[int] = set()
        n = len(insns)
        for idx, ins in enumerate(insns):
            m = ins.mnemonic.lower()
            ops = _split_ops(ins.op_str)
            if m in _SKIP_MNEMS:
                skip.add(ins.addr)
                continue
            # mov x29, sp
            if m == "mov" and len(ops) == 2 and ops[0].lower() == "x29" and ops[1].lower() == "sp":
                skip.add(ins.addr)
                continue
            # stp/ldp 保存/恢复 callee-saved (x19..x30) 到 [sp, ...]
            if m in ("stp", "ldp") and len(ops) >= 3 and "sp" in ops[2].lower():
                r1, r2 = _reg_num(ops[0]), _reg_num(ops[1])
                if r1 is not None and r2 is not None and r1 >= 19 and r2 >= 19:
                    skip.add(ins.addr)
                    continue
            # 单寄存器 str/ldr 保存/恢复 x19..x30 到 [sp, ...]（只在函数首尾 12 条内判定为帧保存）
            if m in ("str", "ldr") and len(ops) == 2 and "sp" in ops[1].lower() and (idx < 10 or idx >= n - 10):
                r1 = _reg_num(ops[0])
                if r1 is not None and r1 >= 19:
                    skip.add(ins.addr)
                    continue
            # 开头/结尾纯栈帧增减 sub sp, sp, #imm / add sp, sp, #imm
            if m in ("sub", "add") and len(ops) == 3 and ops[0].lower() == "sp" and ops[1].lower() == "sp" and ops[2].startswith("#"):
                if idx < 10 or idx >= n - 8:
                    skip.add(ins.addr)
                    continue
            # Stack canary 读取模板：mrs xN, tpidr_el0 ; ldr xM, [xN, #0x28] ; stur/str xM, [x29/sp, ...]
            if m == "mrs" and "tpidr_el0" in ins.op_str.lower() and idx + 2 < n:
                i1, i2 = insns[idx + 1], insns[idx + 2]
                if i1.mnemonic.lower() == "ldr" and "#0x28" in i1.op_str.lower() and i2.mnemonic.lower() in ("str", "stur"):
                    skip.update((ins.addr, i1.addr, i2.addr))
                    continue
        return skip

    def _detect_short_return_blocks(
        self, insns: list[Instruction], fn_start: int, fn_end: int
    ) -> dict[int, str]:
        """识别形如 `mov w0, #K; b epilogue` 或 `mov w0, #K; ret` 的短返回块，映射 addr -> 返回值表达式。"""
        by_addr = {ins.addr: idx for idx, ins in enumerate(insns)}
        epilogue_addrs: set[int] = set()
        # 找出所有直接通往 ret 的纯 epilogue 起点
        for idx, ins in enumerate(insns):
            if ins.mnemonic.lower() == "ret":
                epilogue_addrs.add(ins.addr)
                k = idx - 1
                while k >= 0:
                    pm = insns[k].mnemonic.lower()
                    op_low = insns[k].op_str.lower()
                    if pm in _SKIP_MNEMS or (
                        pm in ("ldp", "ldr") and "sp" in op_low
                    ) or (
                        pm == "add" and op_low.startswith("sp, sp,")
                    ):
                        epilogue_addrs.add(insns[k].addr)
                        k -= 1
                    else:
                        break

        ret_map: dict[int, str] = {}
        for idx, ins in enumerate(insns):
            if ins.addr in epilogue_addrs:
                ret_map[ins.addr] = "v0"
                continue
            m = ins.mnemonic.lower()
            ops = _split_ops(ins.op_str)
            val_expr: str | None = None
            if m in ("mov", "movz", "movn") and len(ops) == 2 and _reg_num(ops[0]) == 0:
                if ops[1].startswith("#"):
                    v = _parse_int(ops[1])
                    if v is not None:
                        if m == "movn":
                            v = ~v
                        val_expr = str(v) if -16 <= v <= 16 else (f"-0x{-v:x}" if v < 0 else f"0x{v:x}")
                elif ops[1].lower() in ("wzr", "xzr"):
                    val_expr = "0"
            if val_expr is not None and idx + 1 < len(insns):
                nxt = insns[idx + 1]
                nm = nxt.mnemonic.lower()
                if nm == "ret" or nxt.addr in epilogue_addrs:
                    ret_map[ins.addr] = val_expr
                elif nm == "b":
                    bt = self._branch_target(nxt)
                    if bt in epilogue_addrs:
                        ret_map[ins.addr] = val_expr
        return ret_map

    def _name_of(self, addr: int) -> str:
        if self.resolve is not None:
            r = self.resolve(self.so.name, addr)
            if r:
                return f"{r[0]}!{r[1]}" if r[0] else r[1]
        fn = self.so.function_at(addr)
        if fn and fn.name:
            return fn.name
        plt = self.so.plt_name(addr)
        if plt:
            return plt
        return f"sub_{addr:x}"

    def _string_at(self, addr: int) -> str | None:
        data = self.so.read(addr, 80)
        if not data:
            return None
        end = data.find(b"\0")
        raw = data[: end if end > 0 else len(data)]
        if len(raw) >= 2 and all(0x20 <= c < 0x7F for c in raw):
            return raw.decode("ascii")
        return None

    # ---------------------------------------------------------------- 指令提升主循环

    def _lift_statements(
        self,
        insns: list[Instruction],
        arg_names: dict[int, str],
        internal_targets: set[int],
        short_ret_blocks: dict[int, str],
        frame_skip: set[int],
        fn_start: int,
        fn_end: int,
    ) -> list[dict[str, Any]]:
        """把指令流提升为结构化中间语句（支持 adrp+add 折叠、cmp 折叠、bl 参数折叠）。"""
        out: list[dict[str, Any]] = []
        written: set[int] = set()
        # 最近一次 cmp/cmn/tst 产生的条件上下文：(kind, lhs_expr, rhs_expr, addr)
        last_cmp: tuple[str, str, str, int] | None = None
        # 追踪刚给 x0..x3 赋值的临时表达式，用于 bl 调用参数折叠：reg_num -> (expr, stmt_index)
        pending_args: dict[int, tuple[str, int]] = {}
        # 追踪 adrp 写入的页基址，折叠后续 add/ldr 消除裸 adrp：reg_num -> (page_addr, stmt_index)
        pending_adrp: dict[int, tuple[int, int]] = {}

        def _invalidate_arg(rnum: int) -> None:
            pending_args.pop(rnum, None)
            pending_adrp.pop(rnum, None)

        def _record_stmt(addr: int, kind: str, text: str, **extra: Any) -> int:
            idx = len(out)
            out.append({"addr": addr, "kind": kind, "text": text, **extra})
            return idx

        def _render_mem_expr(mem_op: str) -> str:
            """把 `[x0, #0x10]` / `[x0]` 转成 C 地址表达式。"""
            inner = mem_op.strip()
            if inner.startswith("["):
                inner = inner[1:]
            if inner.endswith("]!"):
                inner = inner[:-2]
            elif inner.endswith("]"):
                inner = inner[:-1]
            parts = [p.strip() for p in inner.split(",")]
            base = self._var(parts[0], arg_names, written)
            if len(parts) == 1:
                return base
            off_raw = parts[1]
            if off_raw.startswith("#"):
                v = _parse_int(off_raw)
                if v == 0:
                    return base
                if v is not None and v < 0:
                    return f"{base} - 0x{-v:x}"
                return f"{base} + {_fmt_imm(off_raw)}"
            idx_var = self._var(off_raw, arg_names, written)
            return f"{base} + {idx_var}"

        for i_idx, ins in enumerate(insns):
            if ins.addr in internal_targets:
                _record_stmt(ins.addr, "label", f"L_{ins.addr:x}:", target=ins.addr)
                last_cmp = None
                pending_args.clear()
                pending_adrp.clear()

            if ins.addr in frame_skip:
                continue

            m = ins.mnemonic.lower()
            ops = _split_ops(ins.op_str)

            # 1) adrp rd, #page —— 先暂存，若后续紧跟 add/ldr 同一寄存器则合并折叠
            if m == "adrp" and len(ops) == 2:
                rd = _reg_num(ops[0])
                pg = _parse_int(ops[1])
                if rd is not None and rd >= 0 and pg is not None:
                    s_idx = _record_stmt(ins.addr, "stmt", f"{self._lhs_var(ops[0])} = (void *){pg:#x};")
                    pending_adrp[rd] = (pg, s_idx)
                    written.add(rd)
                    continue

            # 2) cmp / cmn / tst —— 仅记录比较上下文供下一条分支或 csel 使用
            if m in ("cmp", "cmn", "tst") and len(ops) >= 2:
                lhs = self._var(ops[0], arg_names, written)
                rhs = _fmt_imm(ops[1]) if ops[1].startswith("#") else self._var(ops[1], arg_names, written)
                last_cmp = (m, lhs, rhs, ins.addr)
                continue

            # 3) 条件跳转 b.<cond> / cbz / cbnz / tbz / tbnz
            if m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
                tgt = self._branch_target(ins)
                cond_expr = self._build_cond(m, ops, last_cmp, arg_names, written)
                last_cmp = None
                pending_args.clear()
                if tgt is not None and tgt in short_ret_blocks and tgt not in (ins.addr + 4,):
                    # 若目标是极短返回块，直接内联成 if (cond) return K;
                    ret_val = short_ret_blocks[tgt]
                    _record_stmt(ins.addr, "if_ret", f"if ({cond_expr}) return {ret_val};",
                                 cond=cond_expr, ret_val=ret_val)
                elif tgt is not None:
                    _record_stmt(ins.addr, "if_goto", f"if ({cond_expr}) goto L_{tgt:x};",
                                 cond=cond_expr, target=tgt)
                else:
                    _record_stmt(ins.addr, "stmt", f"// {ins.text}")
                continue

            # 4) 无条件跳转 b
            if m == "b":
                tgt = self._branch_target(ins)
                pending_args.clear()
                last_cmp = None
                if tgt is not None and not (fn_start <= tgt < fn_end):
                    # 尾调用（tail call）
                    cname = self._name_of(tgt)
                    _record_stmt(ins.addr, "ret", f"return {cname}();")
                elif tgt is not None and tgt in short_ret_blocks and tgt != ins.addr:
                    _record_stmt(ins.addr, "ret", f"return {short_ret_blocks[tgt]};")
                elif tgt is not None:
                    _record_stmt(ins.addr, "goto", f"goto L_{tgt:x};", target=tgt)
                continue

            # 5) 函数调用 bl / blr —— 折叠最近准备好的 x0..x3 参数
            if m in ("bl", "blr"):
                cname = self._name_of(ins.call_target) if (m == "bl" and ins.call_target is not None) else f"(*{self._var(ops[0], arg_names, written)})"
                base_name = cname.split("!")[-1].split("@")[0]
                arity = _KNOWN_ARITY.get(base_name)
                if arity is None:
                    # 按实际在调用前赋值的连续参数寄存器数量推断（最多 4 个）
                    arity = 0
                    for k in range(4):
                        if k in pending_args:
                            arity = k + 1
                call_args: list[str] = []
                consumed_indices: set[int] = set()
                for k in range(arity):
                    if k in pending_args:
                        expr, s_idx = pending_args[k]
                        call_args.append(expr)
                        consumed_indices.add(s_idx)
                    else:
                        call_args.append(self._var(f"x{k}", arg_names, written))
                # 仅隐藏纯参数准备语句（不删除外部可见的副作用）
                for c_idx in consumed_indices:
                    if 0 <= c_idx < len(out):
                        out[c_idx]["hidden"] = True
                pending_args.clear()
                pending_adrp.clear()
                last_cmp = None
                written.add(0)
                # 判断返回值 v0 是否在接下来被消费
                uses_ret = self._next_uses_x0(insns, i_idx)
                call_str = f"{cname}({', '.join(call_args)})"
                if uses_ret:
                    _record_stmt(ins.addr, "stmt", f"v0 = {call_str};")
                else:
                    _record_stmt(ins.addr, "stmt", f"{call_str};")
                continue

            # 6) ret
            if m == "ret":
                ret_expr = "v0"
                if 0 in pending_args:
                    expr, s_idx = pending_args[0]
                    ret_expr = expr
                    if 0 <= s_idx < len(out):
                        out[s_idx]["hidden"] = True
                pending_args.clear()
                _record_stmt(ins.addr, "ret", f"return {ret_expr};" if 0 in written else "return;")
                continue

            # 7) 普通指令转 C 表达式
            c_stmt, dst_reg, rhs_expr, adrp_folded_idx = self._lift_single(
                ins, m, ops, arg_names, written, last_cmp, pending_adrp
            )
            if adrp_folded_idx is not None and 0 <= adrp_folded_idx < len(out):
                out[adrp_folded_idx]["hidden"] = True
            if c_stmt:
                s_idx = _record_stmt(ins.addr, "stmt", c_stmt)
                if dst_reg is not None and dst_reg >= 0:
                    written.add(dst_reg)
                    _invalidate_arg(dst_reg)
                    if dst_reg <= 3 and rhs_expr is not None:
                        pending_args[dst_reg] = (rhs_expr, s_idx)
                elif m.startswith("st"):
                    # 内存写不清空参数准备，但刷新寄存器依赖
                    pass
                else:
                    pending_args.clear()
            else:
                _record_stmt(ins.addr, "stmt", f"/* {ins.text} */")
                pending_args.clear()

            # 除了 csel/csinc/cset 之外，写指令若改了比较寄存器则清空 last_cmp
            if m not in ("csel", "csinc", "csinv", "csneg", "cset", "csetm"):
                if m.endswith("s") and m not in ("mrs", "ubfms", "sbfms"):
                    last_cmp = None

        return [s for s in out if not s.get("hidden")]

    def _next_uses_x0(self, insns: list[Instruction], call_idx: int) -> bool:
        """前瞻后续几条指令是否读取了 x0/w0（决定是否渲染 `v0 = func(...)`）。"""
        for ins in insns[call_idx + 1: call_idx + 8]:
            m = ins.mnemonic.lower()
            ops = _split_ops(ins.op_str)
            if 0 in self._read_reg_indices(m, ops):
                return True
            if m in ("ret",):
                return True
            if 0 in self._written_reg_indices(m, ops) or m in ("bl", "blr"):
                return False
        return False

    def _build_cond(
        self,
        m: str,
        ops: list[str],
        last_cmp: tuple[str, str, str, int] | None,
        arg_names: dict[int, str],
        written: set[int],
    ) -> str:
        if m == "cbz" and ops:
            return f"{self._var(ops[0], arg_names, written)} == 0"
        if m == "cbnz" and ops:
            return f"{self._var(ops[0], arg_names, written)} != 0"
        if m in ("tbz", "tbnz") and len(ops) >= 2:
            reg = self._var(ops[0], arg_names, written)
            bit = _parse_int(ops[1])
            mask = f"(1 << {bit})" if (bit is not None and bit > 0) else "1"
            op = "==" if m == "tbz" else "!="
            return f"({reg} & {mask}) {op} 0"
        if m.startswith("b."):
            cc = m[2:].lower()
            if last_cmp is not None:
                ckind, lhs, rhs, _ = last_cmp
                if ckind == "tst":
                    op = "==" if cc == "eq" else "!="
                    return f"({lhs} & {rhs}) {op} 0"
                cmp_op = _CMP_OPS.get(cc)
                if cmp_op:
                    if ckind == "cmn":
                        return f"({lhs} + {rhs}) {cmp_op} 0"
                    if cc in _UNSIGNED_CONDS:
                        return f"(uint64_t){lhs} {cmp_op} {rhs}"
                    return f"{lhs} {cmp_op} {rhs}"
            return f"cond_{cc}"
        return "cond"

    def _invert_cond(self, cond: str) -> str:
        """取反简单 C 条件，用于 `if (!cond) { ... }` 结构化缩进。"""
        for a, b in ((" == ", " != "), (" != ", " == "), (" <= ", " > "), (" >= ", " < "), (" < ", " >= "), (" > ", " <= ")):
            if a in cond and "&&" not in cond and "||" not in cond:
                return cond.replace(a, b, 1)
        return f"!({cond})"

    def _lift_single(
        self,
        ins: Instruction,
        m: str,
        ops: list[str],
        arg_names: dict[int, str],
        written: set[int],
        last_cmp: tuple[str, str, str, int] | None,
        pending_adrp: dict[int, tuple[int, int]],
    ) -> tuple[str | None, int | None, str | None, int | None]:
        """把单条非分支指令转成 `(C 语句, 目的寄存器号, 右值表达式, 可隐藏的 adrp 语句下标)`。"""
        # 优先检查 adrp+add 数据/字符串引用折叠
        if m == "add" and len(ops) == 3 and ins.ref_addr is not None:
            rd = _reg_num(ops[0])
            rn = _reg_num(ops[1])
            adrp_info = pending_adrp.get(rn) if rn is not None else None
            folded_idx = adrp_info[1] if (adrp_info and rd == rn) else None
            s = self._string_at(ins.ref_addr)
            if s:
                rhs = _c_str_escape(s)
            else:
                sym = self._name_of(ins.ref_addr)
                rhs = f"&{sym}" if not sym.startswith("sub_") else f"(void *){ins.ref_addr:#x}"
            lhs = self._lhs_var(ops[0])
            return f"{lhs} = {rhs};", rd, rhs, folded_idx

        # mov / movz / movn / mvn / neg
        if m in ("mov", "movz", "movn", "mvn", "neg") and len(ops) >= 2:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            if ops[1].startswith("#"):
                v = _parse_int(ops[1])
                if v is not None:
                    shift = 0
                    if len(ops) >= 3 and "lsl" in ops[2].lower():
                        sh = _parse_int(ops[2].split()[-1])
                        shift = sh or 0
                    val = v << shift
                    if m == "movn":
                        val = ~val
                    elif m == "neg":
                        val = -val
                    rhs = str(val) if -16 <= val <= 16 else (f"-0x{-val:x}" if val < 0 else f"0x{val:x}")
                    return f"{lhs} = {rhs};", rd, rhs, None
            src = self._var(ops[1], arg_names, written)
            if m == "mvn":
                rhs = f"~{src}"
            elif m == "neg":
                rhs = f"-{src}"
            else:
                rhs = src
            return f"{lhs} = {rhs};", rd, rhs, None

        if m == "movk" and len(ops) >= 2:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            imm = _fmt_imm(ops[1])
            sh = ops[2] if len(ops) >= 3 else ""
            rhs = f"({lhs} | ({imm} << {_fmt_imm(sh.split()[-1])}))" if "lsl" in sh.lower() else f"({lhs} | {imm})"
            return f"{lhs} = {rhs};", rd, rhs, None

        # 二元算术 / 位运算
        bin_ops = {
            "add": "+", "adds": "+", "sub": "-", "subs": "-",
            "mul": "*", "udiv": "/", "sdiv": "/",
            "and": "&", "ands": "&", "orr": "|", "eor": "^",
            "lsl": "<<", "lsr": ">>", "asr": ">>",
        }
        if m in bin_ops and len(ops) >= 3:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            a = self._var(ops[1], arg_names, written)
            b = _fmt_imm(ops[2]) if ops[2].startswith("#") else self._var(ops[2], arg_names, written)
            if len(ops) >= 4 and "lsl" in ops[3].lower():
                sh = _fmt_imm(ops[3].split()[-1])
                b = f"({b} << {sh})"
            if m == "orr" and a == "0":
                rhs = b
            else:
                rhs = f"{a} {bin_ops[m]} {b}"
            return f"{lhs} = {rhs};", rd, rhs, None

        if m in ("bic", "bics") and len(ops) >= 3:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            a = self._var(ops[1], arg_names, written)
            b = _fmt_imm(ops[2]) if ops[2].startswith("#") else self._var(ops[2], arg_names, written)
            rhs = f"{a} & ~{b}"
            return f"{lhs} = {rhs};", rd, rhs, None

        # 位域与符号/零扩展
        if m in ("uxtb", "uxth", "sxtb", "sxth", "sxtw") and len(ops) == 2:
            cast = {"uxtb": "uint8_t", "uxth": "uint16_t", "sxtb": "int8_t", "sxth": "int16_t", "sxtw": "int32_t"}[m]
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            rhs = f"({cast}){self._var(ops[1], arg_names, written)}"
            return f"{lhs} = {rhs};", rd, rhs, None

        if m in ("ubfx", "sbfx") and len(ops) == 4:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            src = self._var(ops[1], arg_names, written)
            lsb = _parse_int(ops[2]) or 0
            width = _parse_int(ops[3]) or 1
            mask = (1 << width) - 1
            shifted = f"({src} >> {lsb})" if lsb else src
            rhs = f"{shifted} & {mask:#x}"
            return f"{lhs} = {rhs};", rd, rhs, None

        # 条件选择 csel / csinc / csinv / csneg / cset
        if m in ("csel", "csinc", "csinv", "csneg") and len(ops) == 4:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            t_val = self._var(ops[1], arg_names, written)
            f_base = self._var(ops[2], arg_names, written)
            f_val = {"csel": f_base, "csinc": f"({f_base} + 1)", "csinv": f"(~{f_base})", "csneg": f"(-{f_base})"}[m]
            cond = self._build_cond(f"b.{ops[3].lower()}", [], last_cmp, arg_names, written)
            rhs = f"({cond}) ? {t_val} : {f_val}"
            return f"{lhs} = {rhs};", rd, rhs, None

        if m in ("cset", "csetm") and len(ops) == 2:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            cond = self._build_cond(f"b.{ops[1].lower()}", [], last_cmp, arg_names, written)
            rhs = f"({cond}) ? -1 : 0" if m == "csetm" else f"({cond})"
            return f"{lhs} = {rhs};", rd, rhs, None

        if m in ("cinc", "cinv", "cneg") and len(ops) == 3:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            src = self._var(ops[1], arg_names, written)
            cond = self._build_cond(f"b.{ops[2].lower()}", [], last_cmp, arg_names, written)
            true_expr = {"cinc": f"({src} + 1)", "cinv": f"(~{src})", "cneg": f"(-{src})"}[m]
            rhs = f"({cond}) ? {true_expr} : {src}"
            return f"{lhs} = {rhs};", rd, rhs, None

        # 内存读取 ldr*
        if m in _LOAD_TYPES and len(ops) >= 2:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            t64, t32 = _LOAD_TYPES[m]
            ctype = "uint128_t" if ops[0].strip().lower().startswith("q") else (t32 if _is_32(ops[0]) else t64)
            mem_expr = self._mem_addr(ops[1], arg_names, written)
            rhs = f"*({ctype} *)({mem_expr})" if ("+" in mem_expr or "-" in mem_expr) else f"*({ctype} *){mem_expr}"
            return f"{lhs} = {rhs};", rd, rhs, None

        # 内存写入 str*
        if m in _STORE_TYPES and len(ops) >= 2:
            t64, t32 = _STORE_TYPES[m]
            ctype = "uint128_t" if ops[0].strip().lower().startswith("q") else (t32 if _is_32(ops[0]) else t64)
            val = self._var(ops[0], arg_names, written)
            mem_expr = self._mem_addr(ops[1], arg_names, written)
            ptr = f"*({ctype} *)({mem_expr})" if ("+" in mem_expr or "-" in mem_expr) else f"*({ctype} *){mem_expr}"
            return f"{ptr} = {val};", None, None, None

        # 双寄存器读写 ldp / stp
        if m in ("ldp", "stp") and len(ops) >= 3:
            step = 4 if _is_32(ops[0]) else 8
            ctype = "uint32_t" if step == 4 else "uint64_t"
            m1 = self._mem_addr(ops[2], arg_names, written)
            m2 = self._mem_addr(ops[2], arg_names, written, extra_off=step)
            p1 = f"*({ctype} *)({m1})" if ("+" in m1 or "-" in m1) else f"*({ctype} *){m1}"
            p2 = f"*({ctype} *)({m2})" if ("+" in m2 or "-" in m2) else f"*({ctype} *){m2}"
            if m == "ldp":
                r1, r2 = self._lhs_var(ops[0]), self._lhs_var(ops[1])
                n1, n2 = _reg_num(ops[0]), _reg_num(ops[1])
                if n1 is not None and n1 >= 0:
                    written.add(n1)
                if n2 is not None and n2 >= 0:
                    written.add(n2)
                return f"{r1} = {p1}; {r2} = {p2};", None, None, None
            v1, v2 = self._var(ops[0], arg_names, written), self._var(ops[1], arg_names, written)
            return f"{p1} = {v1}; {p2} = {v2};", None, None, None

        # madd / msub
        if m in ("madd", "msub") and len(ops) == 4:
            rd = _reg_num(ops[0])
            lhs = self._lhs_var(ops[0])
            a, b, c = (self._var(ops[k], arg_names, written) for k in (1, 2, 3))
            rhs = f"{c} + {a} * {b}" if m == "madd" else f"{c} - {a} * {b}"
            return f"{lhs} = {rhs};", rd, rhs, None

        return None, None, None, None

    def _mem_addr(
        self, mem_op: str, arg_names: dict[int, str], written: set[int], extra_off: int = 0
    ) -> str:
        inner = mem_op.strip()
        if inner.startswith("["):
            inner = inner[1:]
        if inner.endswith("]!"):
            inner = inner[:-2]
        elif inner.endswith("]"):
            inner = inner[:-1]
        parts = [p.strip() for p in inner.split(",")]
        base = self._var(parts[0], arg_names, written)
        off_int: int | None = 0
        off_expr = ""
        if len(parts) >= 2:
            if parts[1].startswith("#"):
                off_int = _parse_int(parts[1]) or 0
            else:
                off_int = None
                off_expr = self._var(parts[1], arg_names, written)
                if len(parts) >= 3 and "lsl" in parts[2].lower():
                    sh = _fmt_imm(parts[2].split()[-1])
                    off_expr = f"({off_expr} << {sh})"
        if off_int is not None:
            total = off_int + extra_off
            if total == 0:
                return base
            if total < 0:
                return f"{base} - 0x{-total:x}"
            return f"{base} + {total if total <= 16 else hex(total)}"
        if extra_off:
            return f"{base} + {off_expr} + {extra_off}"
        return f"{base} + {off_expr}"

    # ---------------------------------------------------------------- 轻量级控制流结构化

    def _structure_blocks(self, stmts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """将向前跳过短直线的 `if (c) goto L_end; ... L_end:` 折叠成 `if (!c) { ... }` 并裁剪无用标签。"""
        label_pos: dict[int, int] = {}
        for i, s in enumerate(stmts):
            if s["kind"] == "label":
                label_pos[s["target"]] = i

        # 统计每个标签被多少处 goto/if_goto 引用
        ref_cnt: dict[int, int] = {}
        for s in stmts:
            t = s.get("target")
            if s["kind"] in ("if_goto", "goto") and t is not None:
                ref_cnt[t] = ref_cnt.get(t, 0) + 1

        # 识别可折叠的向前短 if-then 块（1~14 条语句，内部不含向该块内外部乱跳），并裁剪已被内联的不可达尾块
        structured_lines: list[dict[str, Any]] = []
        dead = False
        i = 0
        n = len(stmts)
        while i < n:
            s = stmts[i]
            if s["kind"] == "label":
                if ref_cnt.get(s["target"], 0) > 0:
                    dead = False
                    structured_lines.append({"addr": s["addr"], "text": f"  {s['text']}"})
                i += 1
                continue
            if dead:
                i += 1
                continue
            if s["kind"] == "if_goto":
                tgt = s["target"]
                pos = label_pos.get(tgt)
                if pos is not None and i + 1 < pos <= i + 15:
                    inner = stmts[i + 1: pos]
                    # 块内无标签则可安全折叠成 `if (!cond) { ... }`
                    if all(x["kind"] != "label" for x in inner):
                        inv = self._invert_cond(s["cond"])
                        structured_lines.append({"addr": s["addr"], "text": f"    if ({inv}) {{"})
                        for x in inner:
                            structured_lines.append({"addr": x["addr"], "text": f"        {x['text']}"})
                        structured_lines.append({"addr": None, "text": "    }"})
                        ref_cnt[tgt] = max(0, ref_cnt.get(tgt, 1) - 1)
                        i = pos
                        continue
            structured_lines.append({"addr": s["addr"], "text": f"    {s['text']}"})
            if s["kind"] in ("ret", "goto"):
                dead = True
            i += 1

        return structured_lines
