"""反汇编封装与 ARM64 指令语义识别。

职责：把原始字节变成 models.Instruction，并识别出
调用 / 返回 / 跳转 / 数据引用（adrp+add, adrp+ldr）四类语义。

依赖 core.elf_model.SoFile 与 models。
"""
from __future__ import annotations

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone import arm64_const as _arm64_c
from capstone.arm64_const import ARM64_INS_BL, ARM64_INS_B, ARM64_INS_RET

from server.core.elf_model import SoFile
from server.models import Instruction

# (1) 第一次修改（2026-11-26）
# bug 原因：① _COND_JUMPS 遗漏了 ARM64 条件分支别名 b.hs/b.lo；② blr 被错放进
#           _UNCOND_JUMPS 标成了 is_jump 而非 is_call；③ 缺少 caller-saved 寄存器表，
#           无法在 bl/blr 后清除被破坏的 adrp 页基址。
# 解决方案：补全 b.hs/b.lo，将 blr 移出 _UNCOND_JUMPS 并在解码中标为 is_call，
#           预构建 x0..x18 及 wN->xN 映射表用于失效 reg_page。
# ARM64 跳转族，用于控制流分析
_COND_JUMPS = {
    "b.eq", "b.ne", "b.cs", "b.cc", "b.hs", "b.lo", "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
}
_UNCOND_JUMPS = {"b", "br", "cbz", "cbnz", "tbz", "tbnz"}
# AAPCS64 caller-saved 寄存器 x0..x18（调用返回后页基址不再可信）
_CALLER_SAVED_REGS = frozenset(
    getattr(_arm64_c, f"ARM64_REG_X{i}") for i in range(19)
    if hasattr(_arm64_c, f"ARM64_REG_X{i}")
)
# 32 位寄存器写入会零扩展覆写对应的 64 位寄存器
_W_TO_X = {
    getattr(_arm64_c, f"ARM64_REG_W{i}"): getattr(_arm64_c, f"ARM64_REG_X{i}")
    for i in range(31)
    if hasattr(_arm64_c, f"ARM64_REG_W{i}") and hasattr(_arm64_c, f"ARM64_REG_X{i}")
}


class Disassembler:
    """针对单个 SoFile 的反汇编器。一个实例绑定一个 so。"""

    def __init__(self, so: SoFile):
        self.so = so
        if so.arch != 183:  # EM_AARCH64
            raise ValueError(f"暂仅支持 ARM64，实际 arch={so.arch}")
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        # 不设 detail 会拿不到 operands，访问时抛 CS_ERR_DETAIL
        self.md.detail = True
        # 区间解码缓存：key=(addr,size)。用户按固定分块反复扫描同一段
        # （全库扫 adrp 之类）时命中，避免重复付全量解码。
        self._range_cache: dict[tuple[int, int], list[Instruction]] = {}
        self._range_cache_cap = 64  # 上限，防内存无限增长

    def disasm_range(self, addr: int, size: int) -> list[Instruction]:
        """反汇编指定虚拟地址范围。相同 (addr,size) 命中缓存。"""
        key = (addr, size)
        hit = self._range_cache.get(key)
        if hit is not None:
            return hit
        code = self.so.read(addr, size)
        if not code:
            return []
        insns = list(self._decode(code, addr))
        if len(self._range_cache) >= self._range_cache_cap:
            self._range_cache.pop(next(iter(self._range_cache)))  # FIFO 淘汰最旧
        self._range_cache[key] = insns
        return insns

    def disasm_function(self, addr: int) -> list[Instruction]:
        """反汇编单个函数，函数边界来自 FDE。

        性能修复：结果写入 fn.instructions 且后续直接复用。
        此前每次调用都完整重解码——用户 BFS 遍历几百个函数时
        每个节点都付一次全量解码，O(N×指令数) 直接把 MCP 打超时。
        （Xref._insn_cache 只在 build 路径有缓存，脚本直调
        disasm_function 不经过它，所以必须在这里兜底。）
        失效时机：MakeFunction/MakeName 改边界后由 idc 层清缓存。
        """
        fn = self.so.function_at(addr)
        if fn is None:
            return []
        if fn.instructions:
            return fn.instructions          # 已解码，直接复用
        code = self.so.read(fn.addr, fn.size)
        if not code:
            return []
        insns = list(self._decode(code, fn.addr))
        fn.instructions = insns
        return insns

    def invalidate_cache(self, addr: int | None = None) -> None:
        """使解码缓存失效（函数边界/名字被 IDC 修改后调用）。

        addr=None 清全部；否则清该地址所在函数的缓存。
        """
        if addr is None:
            for f in self.so.functions.values():
                f.instructions = []
            self._range_cache.clear()
            return
        fn = self.so.function_at(addr)
        if fn is not None:
            fn.instructions = []

    def _decode(self, code: bytes, addr: int) -> list[Instruction]:
        """解码一段字节为指令序列。

        兼顾两件事（两者曾经互相打架）：
        - BUG-4 的正确性：capstone 的 disasm() 遇到无法解码的字节会终止迭代。
          加固样本内联跳转表会导致后续代码全丢（实测 2380 字节函数只出 71 条）。
        - 性能：不能对每条指令都调一次 disasm(count=1)（跨语言调用，
          profile 显示 20 万次调用占大半耗时，建索引 32s）。
        解法（混合式）：**批量迭代**解出连续可解码段；一旦中断，
        按 ARM64 定长跳 4 字节记为 .data，然后从新位置**重新批量迭代**。
        既保留跨数据块能力，又让正常段走 C 层批量循环（实测 7.9× 加速）。
        """
        out: list[Instruction] = []
        pos = 0
        total = len(code)
        reg_page: dict[int, int] = {}
        # 一次性视图，避免每条指令切片复制
        view = memoryview(code)

        def make_item(insn) -> Instruction:
            return Instruction(
                addr=insn.address,
                size=insn.size,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=insn.bytes,
            )

        while pos < total:
            decoded = 0
            # 批量迭代：从 pos 起连续解码
            for insn in self.md.disasm(code[pos:], addr + pos):
                item = make_item(insn)
                ops = insn.operands
                m = insn.mnemonic
                out.append(item)
                decoded += insn.size
                pos += insn.size
                # (1) 第一次修改（2026-11-26）
                # bug 原因：① blr 未标为 is_call；② cbz/cbnz/tbz/tbnz 目标立即数不在 ops[0]
                #           导致 call_target 恒为 None；③ adrp+ldr 过滤了 mem.disp == 0 丢失页对齐引用；
                #           ④ add/ldr*/ldp 覆写目的寄存器后未清除 reg_page，且 bl/blr 未清除
                #           caller-saved 寄存器 x0..x18，导致后续结构体成员访问产生大量假 xref。
                # 解决方案：① bl/blr 均标 is_call 并清空 x0..x18 的 reg_page；② 分支目标从 ops
                #           逆序取最后一个立即数操作数，统一覆盖 b/b.*/cbz/cbnz/tbz/tbnz；
                #           ③ ldr*/ldp 允许 disp==0（仅排除带索引寄存器寻址），计算完 ref_addr 后
                #           清除被覆写的目的寄存器（含 ldp 的 ops[0]/ops[1] 与 wN->xN）。
                if m == "bl":
                    item.is_call = True
                    if ops and ops[0].type == 2:  # CS_OP_IMM
                        item.call_target = ops[0].imm
                        item.ref_addr = ops[0].imm
                    for r in _CALLER_SAVED_REGS:
                        reg_page.pop(r, None)
                elif m == "blr":
                    item.is_call = True
                    for r in _CALLER_SAVED_REGS:
                        reg_page.pop(r, None)
                elif m in _UNCOND_JUMPS or m in _COND_JUMPS:
                    item.is_jump = True
                    for op in reversed(ops):
                        if op.type == 2:  # CS_OP_IMM（覆盖 b/b.*/cbz/cbnz/tbz/tbnz）
                            item.call_target = op.imm
                            break
                elif m == "ret":
                    item.is_ret = True
                elif m == "adrp" and len(ops) == 2 and ops[0].type == 1 and ops[1].type == 2:
                    reg_page[ops[0].reg] = ops[1].imm
                elif m == "add" and len(ops) == 3 and ops[1].type == 1 and ops[2].type == 2:
                    base = reg_page.get(ops[1].reg)
                    if base is not None:
                        imm = ops[2].imm
                        if getattr(ops[2], "shift", None) and ops[2].shift.type == _arm64_c.ARM64_SFT_LSL:
                            imm <<= ops[2].shift.value
                        item.ref_addr = (base + imm) & 0xFFFFFFFFFFFFFFFF
                    if ops[0].type == 1:
                        reg_page.pop(_W_TO_X.get(ops[0].reg, ops[0].reg), None)
                elif m.startswith("ldr") and len(ops) >= 2 and ops[1].type == 3:
                    base = reg_page.get(ops[1].mem.base)
                    if base is not None and not ops[1].mem.index:
                        item.ref_addr = (base + ops[1].mem.disp) & 0xFFFFFFFFFFFFFFFF
                    if ops[0].type == 1:
                        reg_page.pop(_W_TO_X.get(ops[0].reg, ops[0].reg), None)
                elif m == "ldp" and len(ops) >= 3:
                    if ops[2].type == 3:
                        base = reg_page.get(ops[2].mem.base)
                        if base is not None and not ops[2].mem.index:
                            item.ref_addr = (base + ops[2].mem.disp) & 0xFFFFFFFFFFFFFFFF
                    if ops[0].type == 1:
                        reg_page.pop(_W_TO_X.get(ops[0].reg, ops[0].reg), None)
                    if ops[1].type == 1:
                        reg_page.pop(_W_TO_X.get(ops[1].reg, ops[1].reg), None)
                elif len(ops) > 0 and ops[0].type == 1:
                    if not m.startswith(("str", "stp", "stur", "stlr", "cmp", "cmn", "tst")):
                        reg_page.pop(_W_TO_X.get(ops[0].reg, ops[0].reg), None)
            if decoded:
                continue  # 这一段解完了，继续（可能还有剩余尾部）
            # 一个字节都没解出 → 数据块：跳一个指令宽度
            skip = min(4, total - pos)
            chunk = bytes(view[pos:pos + skip])
            out.append(Instruction(
                addr=addr + pos,
                size=skip,
                mnemonic=".data",
                op_str=chunk.hex(" "),
                bytes=chunk,
            ))
            reg_page.clear()  # 数据边界后寄存器追踪失效
            pos += skip
        return out
