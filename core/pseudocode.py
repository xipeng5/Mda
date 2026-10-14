"""结构化伪代码生成。

第一阶段不做真反编译（需要数据流分析+SSA，工作量巨大），
而是把 ARM64 指令按控制流归类成带缩进的类 C 文本：
- 调用替换为符号名（跨 so 解析）
- adrp+add 数据引用替换为字符串字面量或 &symbol
- 分支生成 if/goto 框架

这是性价比最高的"类 IDA F5"近似。
"""
from __future__ import annotations

from core.disasm import Disassembler
from core.elf_model import SoFile
from models import Instruction


class PseudocodeGenerator:
    """单个 so 的伪代码生成器。"""

    def __init__(self, so: SoFile, disasm: Disassembler):
        self.so = so
        self.disasm = disasm

    def generate(self, fn_addr: int, resolve=None) -> str:
        """生成函数伪代码。resolve 可选，签名 (so_name, target)->(so,name,addr)。"""
        fn = self.so.function_at(fn_addr)
        if fn is None:
            # BUG-13 修复：未建函数返回结构化错误标记（首行 _MDA_ERROR_），
            # 与空字符串/正常输出可区分，MCP/GUI 可识别
            return f"_MDA_ERROR_\nno_function\n{fn_addr:#x}"
        insns = fn.instructions or self.disasm.disasm_function(fn_addr)
        if not insns:
            return f"// 函数 {fn.name or hex(fn_addr)} 无指令（可能位于数据节）"

        name = fn.name or f"sub_{fn.addr:x}"
        lines = [f"// {self.so.name}!{name} @ {fn.addr:#x} (size {fn.size:#x})"]
        lines.append(f"void {name}() {{")

        for ins in insns:
            line = self._render(ins, resolve)
            if line is None:  # 框架性指令（如栈保护）跳过
                continue
            lines.append(f"    {line}")

        lines.append("}")
        return "\n".join(lines)

    def _render(self, ins: Instruction, resolve) -> str | None:
        m = ins.mnemonic
        # 栈保护与 PAC 框架指令，不影响语义理解
        if m in ("paciasp", "autiasp", "bti", "bti c", "nop"):
            return None
        if m in ("stp",) and "x29" in ins.op_str and "x30" in ins.op_str:
            return None
        if m in ("ldp",) and "x29" in ins.op_str and "x30" in ins.op_str:
            return None
        if m == "mov" and ins.op_str in ("x29, sp",):
            return None

        # 调用：解析为符号名
        if ins.is_call and ins.call_target is not None:
            target_name = self._name_of(ins.call_target, resolve)
            return f"{target_name}(...);  // {ins.text}"

        # 数据引用：字符串优先
        if ins.ref_addr is not None:
            s = self._string_at(ins.ref_addr)
            if s:
                return f'/* "{s[:40]}" */ {ins.text}'
            name = self._name_of(ins.ref_addr, resolve)
            return f"{ins.text}  // -> {name}"

        # 返回
        if m == "ret":
            return "return;"

        return ins.text

    def _name_of(self, addr: int, resolve) -> str:
        """地址 -> 符号名。

        bug 原因：resolve 回调返回的 CallLink 里 callee_so 可能为空串
        （导入符号无对应已加载 so），拼 "so!name" 会输出 "!name"。
        解决：空 so 名时只返回符号名本身。
        """
        if resolve is not None:
            r = resolve(self.so.name, addr)
            if r:
                return f"{r[0]}!{r[1]}" if r[0] else r[1]
        fn = self.so.function_at(addr)
        if fn and fn.name:
            return fn.name
        plt = self.so.plt_name(addr)
        if plt:
            return plt
        return hex(addr)

    def _string_at(self, addr: int) -> str | None:
        data = self.so.read(addr, 64)
        if not data:
            return None
        end = data.find(b"\0")
        raw = data[: end if end > 0 else len(data)]
        if len(raw) >= 3 and all(0x20 <= c < 0x7F for c in raw):
            return raw.decode("ascii")
        return None
