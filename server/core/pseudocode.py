"""结构化伪代码生成。

第一阶段不做真反编译（需要数据流分析+SSA，工作量巨大），
而是把 ARM64 指令按控制流归类成带缩进的类 C 文本：
- 调用替换为符号名（跨 so 解析）
- adrp+add 数据引用替换为字符串字面量或 &symbol
- 分支生成 if/goto 框架

这是性价比最高的"类 IDA F5"近似。
"""
from __future__ import annotations

from server.core.disasm import Disassembler
from server.core.elf_model import SoFile
from server.models import Instruction


# 函数正常收尾的最后一条指令（与 discover._TERMINATORS 同口径）
_TERMINATORS = {"ret", "b", "br", "brk"}

# 已知「不返回」的函数名（bionic / libc++ / Fortify）。
# 末条指令是 bl 到这些函数，是**合法的函数收尾**，不是 size 被截断。
# 为什么必须区分：实测 libbase 269 个、liblog 48 个、libcutils 93 个函数
# 的末条就是 `bl __stack_chk_fail` / `bl abort` / `bl __throw_*`，
# 不加这个白名单，WARNING 的假警报率是 43%~70%——一旦成为噪音，
# 真正被截断的那一次谁也看不到了。
_NORETURN_EXACT = frozenset({
    "abort", "exit", "_exit", "_Exit", "quick_exit",
    "__stack_chk_fail", "__stack_chk_fail_local",
    "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid",
    "__cxa_call_unexpected", "__cxa_pure_virtual", "__cxa_deleted_virtual",
    "longjmp", "siglongjmp", "pthread_exit", "_longjmp",
    "__assert", "__assert2", "android_set_abort_message",
    "__android_log_assert", "__fortify_fail", "__fortify_fail_abort",
    "terminate", "std::terminate", "__terminate",
})
# mangled 名（libc++ 的 std::__1::__throw_*）靠子串兜住
_NORETURN_SUBSTR = ("__throw_", "9__throw_", "stack_chk_fail", "9terminate")


class PseudocodeGenerator:
    """单个 so 的伪代码生成器。"""

    def __init__(self, so: SoFile, disasm: Disassembler):
        self.so = so
        self.disasm = disasm

    def generate(self, fn_addr: int, resolve=None, with_addr: bool = True) -> str:
        """生成函数伪代码。

        resolve 可选，签名 (so_name, target)->(so,name,addr)。
        with_addr=True 时每行前缀源地址注释 `// 0x1234`。

        (1) 第一次修改（2026-11-18）：加源地址注释 + 覆盖统计 + 截断告警。
            bug 原因：扁平化状态机里 26 个分支全部 `b.ne` 回同一个分发器，
                      伪代码里 26 行文本**完全一致**，无法对回源指令，
                      使用者被迫回字节码一条条数——实测卡住整条分析线。
                      更糟的是「伪代码少了一个 bl」时无任何提示，而真实
                      原因往往是 fn.size 被截断（disasm_function 只解码
                      size 字节），不是渲染层丢的，两者无法区分。
            解决方案：
              ① 每行前缀 `// {addr}`，让每一行都可直接回到字节码；
              ② 头部输出 `N insns, M bl, K shown, S skipped` 覆盖统计，
                 把"框架指令被省略"与"代码没解到"分成两个数；
              ③ 末条不是 ret/b/br/brk 时输出 WARNING 行，指出 size 可能
                 被截断、并给出继续反汇编的确切地址。
            with_addr=False 可退回旧格式（输出体积敏感时用）。
        """
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

        # 统计分两路：bl 总数来自真解析到目标的 call；skipped 只统计被
        # _render 判为框架指令而省略的条数——两者都不等于"漏掉的代码"。
        bl_total = sum(1 for i in insns if i.is_call and i.call_target is not None)
        body: list[str] = []
        skipped = 0
        for ins in insns:
            line = self._render(ins, resolve)
            if line is None:  # 框架性指令（stack guard / pac / fp 帧）跳过
                skipped += 1
                continue
            body.append(f"    // {ins.addr:#x}  {line}" if with_addr
                        else f"    {line}")

        lines.append(
            f"// {len(insns)} insns, {bl_total} bl, {len(body)} shown, "
            f"{skipped} skipped (frame only: paciasp/bti/nop/stp|ldp fp,lr/mov x29,sp)"
        )

        tail = insns[-1]
        if not self._is_legal_tail(tail):
            lines.append(
                f"// WARNING 末条指令 {tail.addr:#x} 是 `{tail.text}`，不是函数收尾"
                f"（应为 {'/'.join(sorted(_TERMINATORS))} 或 noreturn 调用）"
                f"⇒ fn.size 可能被截断，其后的代码本轮**未解码**。"
                f"用 disassemble(so, {tail.addr:#x}, N) 或 "
                f"export_disasm 扩大范围确认结尾。"
            )

        lines.append(f"void {name}() {{")
        lines.extend(body)
        lines.append("}")
        return "\n".join(lines)

    def _is_legal_tail(self, ins: Instruction) -> bool:
        """末条指令是否是**合法的函数收尾**（不是 size 被截断）。

        (1) 第一次修改（2026-11-18）：新增。
            bug 原因：初版判据只看 `末条 mnemonic 属于 ret/b/br/brk`，
                      而实测大量函数末条就是 `bl __stack_chk_fail` /
                      `bl abort` / `bl std::__1::__throw_length_error`——
                      被调者不返回，函数到此结束，属**完全正常**。
                      假警报率：libbase 269/386 (69.7%)、liblog 48/111
                      (43.2%)、libcutils 93/168 (55.4%)。WARNING 一变成
                      每三个函数响两次的噪音，真截断那次就没人看了。

        (2) 第二次修改（2026-11-18）：补两条判据。
            bug 原因：libcutils 0xe57c 仍误报——它的末条是 `bl 0xee48`，
                      而 0xee48 是无名 PLT 桩（符号在样本里已丢），
                      靠名字名单永远判不出来；同时 `0xee48` 之后的
                      `0xe65c` 恰好是**下一个函数的入口**，这本身就是
                      「边界精确、没有截断」的硬证据。
            解决方案：按证据强度依次判定——
                      ① 末条是 ret/b/br/brk            → 合法
                      ② 末条是 bl 且目标在 noreturn 名单 → 合法
                      ③ 末条是 bl 且 tail.addr+4 正好是下一个函数入口
                         （或落在某个函数起点上）      → 合法（边界精确）
                      ④ 其余                           → 视为可疑，交
                         generate() 输出 WARNING
        """
        if ins.mnemonic in _TERMINATORS:
            return True
        if not (ins.is_call and ins.call_target is not None):
            return False

        # 判据③：本条指令之后就是下一个函数入口 ⇒ 当前函数到此为止，
        # 这条 bl 是不返回调用（否则后续必然还有 ret，FDE 不会这么切）。
        if self.so.functions.get(ins.addr + ins.size) is not None:
            return True

        # 判据②：靠符号名判断 noreturn
        name = self.so.plt_name(ins.call_target) or ""
        if not name:
            fn = self.so.function_at(ins.call_target)
            name = fn.name if fn is not None else ""
        if not name:
            # 无名目标（典型是无符号的 PLT 桩）：无法证伪，
            # 宁可漏报也不制造噪音——否则无符号 dump so 上全是假警报。
            return self.so.in_plt_stub(ins.call_target)
        base = name.split("@")[0].strip()
        if base in _NORETURN_EXACT:
            return True
        return any(sub in base for sub in _NORETURN_SUBSTR)

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
