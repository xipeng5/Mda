"""递归函数发现：补全 FDE（.eh_frame）漏掉的函数入口。

缺陷原因（用户实测 + 本地复现，libAPSE_loadable.so）：
  PT_GNU_EH_FRAME 的 binary search table 只登记"有展开信息"的函数，
  加壳样本里大量函数没有 FDE：
  - P0：表内仅 6047 条，而 bl 目标中带标准序言、却不在表内的入口有 1207 个
  - P1：FDE 边界过粗，一条 FDE 覆盖多个逻辑函数。实测 0x29BD54
        （序言 sub sp,sp,#0x80; stp x28,x29）被 sub_29B2D0
        （0x29b2d0..0x29c830）整体吞掉
  - P2：build_xrefs 在构建前不补函数，导致 called_by 看着 100% 覆盖，
        实际边是缺的

解决方案（迭代到不动点）：
  1. 收集所有已知函数的 bl 目标
  2. 目标是「落在 PT_LOAD 内 + 4 字节对齐 + 不在函数表 + 首指令为标准序言」
  3. 建为函数；SoFile.add_function 会把宿主从该入口切开（修 P1）
  4. 重复，因为新函数的 bl 目标可能带出更多入口
"""
from __future__ import annotations

import struct

# 标准序言首指令（精确匹配）
_PROLOGUE_EXACT = {
    0xD503233F,  # paciasp
    0xD503245F,  # bti c
    0xD50324DF,  # bti j
    0xD503249F,  # bti jc
}
# stp x29, x30, [sp, #-N]!（经典 fp/lr 帧）
_STP_FP_LR = 0xA9807BFD
_MASK_STP_FP_LR = 0xFFC07FFF
# sub sp, sp, #N（sh=0）
_SUB_SP = 0xD10003FF
_MASK_SUB_SP = 0xFFC003FF
# stp <x19..x30>, <x19..x30>, [sp, #-N]!（无 fp 的叶子函数）
_MASK_STP_PRE = 0xFFC00000
_STP_PRE = 0xA9800000
# 终止指令：其后紧跟序言即可判定为新函数入口（IDA 的同类启发式）
_TERMINATORS = {"ret", "b", "br", "brk"}


class FunctionDiscoverer:
    """用 bl 目标 + 序言特征递归补全函数表。"""

    def __init__(self, so, disasm):
        self.so = so
        self.disasm = disasm

    # ---------- 序言判定 ----------

    @staticmethod
    def is_prologue(word: int, next_word: int = 0) -> bool:
        """首指令（必要时结合第二条）是否构成标准函数序言。"""
        if word in _PROLOGUE_EXACT:
            return True
        if (word & _MASK_STP_FP_LR) == _STP_FP_LR:
            return True
        if (word & _MASK_SUB_SP) == _SUB_SP:
            return True
        # stp 族：pre-index 且基址是 SP，两个寄存器都在 x19..x30
        if (word & _MASK_STP_PRE) == _STP_PRE:
            rn = (word >> 5) & 0x1F
            rt, rt2 = word & 0x1F, (word >> 10) & 0x1F
            if rn == 31 and all(19 <= r <= 30 for r in (rt, rt2)):
                return True
        return False

    def _entry_ok(self, addr: int) -> bool:
        """目标是否像真实函数入口（可加载 + 对齐 + 序言）。"""
        if addr in self.so.functions:
            return False
        if not self.so.in_load(addr) or addr % 4:
            return False
        data = self.so.read(addr, 8)
        if len(data) < 4:
            return False
        word, = struct.unpack_from("<I", data, 0)
        nxt = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
        return self.is_prologue(word, nxt)

    def _md(self):
        return self.disasm.md

    def is_plt_stub(self, addr: int) -> bool:
        """PLT 桩识别（ARM64 标准 4 条桩指令）。

        缺陷原因：加固样本的 .dynsym/.rela.plt 被剥，plt_map 为空，
        但 PLT 桩仍留在代码里，会被当成普通 bl 目标。实测形态为
        `adrp x16,pg; ldr x17,[x16,#imm]; add x16,x16,#imm; br x17`
        （我最初按 3 条判定而全部漏掉，因为中间还有一条 add）。
        """
        ins = list(self._md().disasm(self.so.read(addr, 16), addr))[:4]
        if len(ins) != 4:
            return False
        return (
            ins[0].mnemonic == "adrp" and ins[0].op_str.startswith("x16")
            and ins[1].mnemonic == "ldr" and ins[1].op_str.startswith("x17")
            and ins[2].mnemonic == "add" and ins[2].op_str.startswith("x16")
            and ins[3].mnemonic == "br" and ins[3].op_str.strip() == "x17"
        )

    def _bl_entry_ok(self, addr: int) -> bool:
        """bl 目标能否建为函数（**不要求标准序言**）。

        缺陷原因：旧判据沿用 _entry_ok（要求标准序言），而叶子函数没有
        栈帧也就没有序言——实测 0x3495F4 首指令 `ldrb w8,[x0]`（随后
        tbnz/ret），被 486 处调用、来自 100 个不同函数，却被判为"不合格"，
        导致 FDE 之外的 979 个 bl 目标（其中 976 个是真入口）全被忽略。
        排除项：PLT 桩（导入跳板，不算本 so 函数）、未定义指令（数据误识别）。
        """
        if addr in self.so.functions:
            return False
        if not self.so.in_load(addr) or addr % 4:
            return False
        first = next(self._md().disasm(self.so.read(addr, 4), addr), None)
        if first is None or first.mnemonic in ("udf", ".byte"):
            return False
        return not self.is_plt_stub(addr)

    # ---------- 迭代发现 ----------

    def discover(self, max_rounds: int = 6, aggressive: bool = False) -> dict:
        """迭代发现直到不动点。

        aggressive=False（默认，安全）：只认 bl 目标。
            bl 是「被直接调用」的硬证据，实测误报率 0。
        aggressive=True（激进）：额外认「终止指令后紧跟序言」的入口。
            能捞到跳转表分发的 handler（如 SIGN handler 0xB9DA4），
            但**会把 switch 的 case 块也切成函数**——实测 libbase 的
            386 个函数被切成 557 个，171 个新增全部不是 bl 目标，
            而是同一个 switch 的连续 case 块（每块 bti jc; mov w0,#imm）。
            需要这种细粒度时显式开启，并自行甄别。
        """
        added = 0
        rounds = 0
        by_reason: dict[str, int] = {}
        for rounds in range(1, max_rounds + 1):
            found = self._scan_round(aggressive=aggressive)
            if not found:
                break
            for addr, reason in sorted(found.items()):
                self.so.add_function(addr, discovered_by=reason)
                by_reason[reason] = by_reason.get(reason, 0) + 1
            added += len(found)
        return {"added": added, "rounds": rounds,
                "total": len(self.so.functions), "by_reason": by_reason}

    def _scan_round(self, aggressive: bool = False) -> dict[int, str]:
        """一轮扫描：返回 {新入口地址: 发现依据}。

        依据两类，便于事后审计误报率：
          bl_target —— 有 bl 直接调用它（硬证据，默认启用）
          prologue  —— 上一条是终止指令且本条是序言（仅 aggressive 开启）
        """
        found: dict[int, str] = {}
        for addr in list(self.so.functions):
            insns = self.disasm.disasm_function(addr)
            for i, ins in enumerate(insns):
                # 类型 1：bl 目标带序言（函数被调用但 FDE 未登记）
                if ins.is_call and ins.call_target and self._bl_entry_ok(ins.call_target):
                    found[ins.call_target] = "bl_target"
                if not aggressive:
                    continue
                # 类型 2（激进）：上一条是终止指令，本条是序言。可捕获
                # 跳转表分发的 handler，但 switch 的 case 块同形——见 discover()
                if i > 0 and ins.mnemonic != ".data":
                    prev = insns[i - 1]
                    if prev.mnemonic in _TERMINATORS and self._entry_ok(ins.addr):
                        found.setdefault(ins.addr, "prologue")
        return found
