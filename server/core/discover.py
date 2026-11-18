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

from server.core.elf_model import is_arm64_plt_stub

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
        # 重定位 code target 的惰性缓存（一次解析，多轮复用）
        self._rela_cache: list[int] | None = None

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

    @staticmethod
    def is_frame_prologue(word: int) -> bool:
        """该指令是否**建立栈帧**（严格模式唯一认可的序言证据）。

        (1) 第一次修改（2026-11-18）：新增。
            bug 原因：`is_prologue` 把裸 `bti c` / `paciasp` 也算序言，
                      而它们只是**分支保护标记**，不是函数边界证据。
                      实测 libbase.so 用 aggressive=True 时新增的 171 个入口
                      **100% 是裸 bti**，后接 `mov w0,#imm`——同一个 switch
                      的连续 case 块（每个 case 前都有 bti jc）。
                      反过来统计首指令分布：
                        paciasp | sub  | stp   152 处  ← 真函数
                        paciasp | stp  | str    76 处  ← 真函数
                        paciasp | stp  | stp    69 处  ← 真函数
                        bti     | bfi  | mov    21 处  ← case 块
                        bti     | mov  | mov    17 处  ← case 块
                        bti     | adrp | adrp   11 处  ← case 块
                      即「bti/paciasp 后面跟不跟栈帧」才是分水岭。
            解决方案：只认三条真正的栈帧建立指令，裸 bti/paciasp 一律不算。
        """
        if (word & _MASK_STP_FP_LR) == _STP_FP_LR:      # stp x29,x30,[sp,#-N]!
            return True
        if (word & _MASK_SUB_SP) == _SUB_SP:            # sub sp, sp, #N
            return True
        if (word & _MASK_STP_PRE) == _STP_PRE:          # stp <callee>,<callee>,[sp,#-N]!
            rn = (word >> 5) & 0x1F
            rt, rt2 = word & 0x1F, (word >> 10) & 0x1F
            return rn == 31 and all(19 <= r <= 30 for r in (rt, rt2))
        return False

    def is_prologue_strict(self, addr: int, window: int = 3) -> bool:
        """严格序言判定：入口后 `window` 条内必须出现**栈帧建立**。

        允许入口处有 1~2 条 bti/paciasp（编译器在 `-mbranch-protection`
        下给每个函数入口都加），但**不把它们本身当证据**——必须随后
        真的建了栈帧，否则就是 switch case 块 / 其他代码块。

        实测对照（libbase.so）：
          - aggressive=True 旧行为：+171，全是裸 bti 的 case 块 → 误报
          - 本判据：接受 `sub sp,sp,#N` / `stp x29,x30,[sp,#-N]!` 开头的
            真函数，拒绝 case 块；代价是没有栈帧的叶子函数漏掉（它们若
            被 bl 调用，走 bl_target 那条路径照样能收到）。
        """
        data = self.so.read(addr, window * 4)
        if len(data) < 4:
            return False
        for off in range(0, len(data) - 3, 4):
            word, = struct.unpack_from("<I", data, off)
            if word in _PROLOGUE_EXACT:
                continue            # bti / paciasp：跳过，继续往下看栈帧
            return self.is_frame_prologue(word)
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

        (2) 第二次修改：判据改由 elf_model.is_arm64_plt_stub() 统一提供，
        避免与段表扫描各写一份导致判据漂移。
        """
        ins = list(self._md().disasm(self.so.read(addr, 16), addr))[:4]
        return is_arm64_plt_stub(ins)

    def rela_targets(self) -> list[int]:
        """重定位表里 addend 落在**可执行段**的去重地址（间接调用目标）。

        (1) 第一次修改（2026-11-18）：新增。
            bug 原因：vtable / 函数指针表里的函数**没有任何 bl 指向**，
                      默认档永远发现不了它们，它们又被外层粗 FDE 区间罩住，
                      于是 function_at 返回错函数、伪代码里出现"凭空多出的
                      一半逻辑"。这是第 33 轮反馈里最误导人的一条，
                      而它和"没有 RELA 解析"是同一个根因。
            解决方案：把重定位表的 code target 作为**第三类入口证据**
                      （与「被 bl 调用」同级）。判定见 _code_entry_ok。

        解析失败（无节表且无 PT_DYNAMIC、不支持的压缩编码）时返回空列表，
        并在 rela_summary 里能查到原因——不静默、也不编造目标。
        """
        if self._rela_cache is None:
            try:
                from server.core import rela as _rela
                self._rela_cache = _rela.code_targets(self.so)
            except Exception:                             # noqa: BLE001
                # 解析不了就当没有这条证据来源，绝不影响 bl/序言两条主路径
                self._rela_cache = []
        return self._rela_cache

    def _code_entry_ok(self, addr: int) -> bool:
        """地址能否作为代码入口（bl 目标与 rela target 共用同一套判据）。

        与 `_bl_entry_ok` 判据完全一致：可加载 + 对齐 + 不在函数表 +
        不在 PLT 桩 + 首指令可解码。共用是为了避免两条证据路径漂移
        （曾经因为两处各写一份判据，导致同一地址在一条路径能建函数、
        在另一条不能）。
        """
        return self._bl_entry_ok(addr)

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
        # (1) 第一次修改：段表模式已扫出的 PLT 桩直接排除，
        # 按 16 字节区间判定（桩内部地址同样要排除），
        # 省下对每个 bl 目标重复解码 4 条指令模板的开销
        if self.so.in_plt_stub(addr):
            return False
        first = next(self._md().disasm(self.so.read(addr, 4), addr), None)
        if first is None or first.mnemonic in ("udf", ".byte"):
            return False
        return not self.is_plt_stub(addr)

    # ---------- 迭代发现 ----------

    def discover(self, max_rounds: int = 6, aggressive: bool = False,
                 strict_prologue: bool = True, use_rela: bool = True,
                 use_prologue: bool | None = None) -> dict:
        """迭代发现直到不动点。

        ## 三个开关名（`use_prologue` 是 `aggressive` 的语义化别名）

        历史参数 `aggressive` 名字起得不好：它同时表示"要不要用序言检测"，
        但真正决定松紧的是 `strict_prologue`。所以补一个直白别名：

        | 档位 | 等价调用 |
        |---|---|
        | **bl_only** | `discover()` 或 `use_prologue=False` |
        | **strict**（推荐） | `use_prologue=True`（默认 `strict_prologue=True`） |
        | **loose** | `use_prologue=True, strict_prologue=False` |

        `use_prologue=None`（默认）时沿用 `aggressive` 的取值，因此
        `discover(aggressive=True)` 的老写法行为不变（且默认落到 strict 档）。
        

        ## 三档（第 33 轮反馈的直接产物）

        旧版只有两档，中间是空的：默认太保守（只认 bl，实测某个 so 只补出
        21 个，远不够），激进太脏（裸 bti 当序言，libbase +171 全是 switch
        case 块）。使用者要的是「既不漏、又不过切」，所以补出中间档：

        | aggressive | strict_prologue | 行为 |
        |---|---|---|
        | False | —（无效） | 只认 bl 目标。bl 是「被直接调用」的硬证据，误报率 0 |
        | True | **True（默认）** | bl + 「终止指令后紧跟**完整栈帧**」。推荐档 |
        | True | False | bl + 「终止指令后紧跟任何序言（含裸 bti/paciasp）」。旧行为，会切碎 switch |

        为什么 strict 的判据是「栈帧」而不是「序言」：
        实测 libbase 首指令分布说明裸 bti 与真函数无关（见
        `is_frame_prologue` 的统计），而 switch 的每个 case 块都以 bti jc
        开头，用旧判据必然把它们切出来。

        ## 返回值新增字段

        - `prologue_mode`：`off` / `strict` / `loose`，让调用方能判断结果口径
        - `skipped_loose_prologue`：strict 模式下**因只有裸 bti 而被跳过**的
          候选数。这不是错误，而是「本档刻意不收」的量——需要时用
          strict_prologue=False 重跑（注意会引入 case 块）。
        - `reached_max_rounds`：是否跑满 max_rounds 仍未到不动点。
          跑满说明函数表可能还没补完，需要加大轮次而不是认为已收敛。

        (1) 第一次修改（2026-11-18）：新增 strict_prologue 与上面三个返回字段。
            bug 原因：旧版只有 aggressive 二元开关，使用者实测某个 so
                      默认档只补出 21 个、激进档把 case 块切碎，
                      中间没有可用档；且 max_rounds 跑满与真的收敛
                      在返回里长得一样，无法判断函数表补完没有。
            解决方案：见上表与字段说明。
        """
        # use_prologue 是 aggressive 的语义化别名（见 docstring 的三档表）。
        # 显式给 use_prologue 时以它为准；否则沿用 aggressive，保证老调用不变。
        if use_prologue is not None:
            aggressive = bool(use_prologue)
        added = 0
        rounds = 0
        by_reason: dict[str, int] = {}
        skipped_loose = 0
        for rounds in range(1, max_rounds + 1):
            found, skipped = self._scan_round(aggressive=aggressive,
                                              strict_prologue=strict_prologue,
                                              use_rela=use_rela)
            skipped_loose += skipped
            if not found:
                break
            for addr, reason in sorted(found.items()):
                self.so.add_function(addr, discovered_by=reason)
                by_reason[reason] = by_reason.get(reason, 0) + 1
            added += len(found)
        if not aggressive:
            mode = "off"
        elif strict_prologue:
            mode = "strict"
        else:
            mode = "loose"
        return {"added": added, "rounds": rounds,
                "total": len(self.so.functions), "by_reason": by_reason,
                "prologue_mode": mode,
                "use_rela": bool(use_rela),
                "rela_targets": len(self.rela_targets()) if use_rela else 0,
                "skipped_loose_prologue": skipped_loose,
                # 跑满轮次说明没到不动点（最后一轮仍有新增）
                "reached_max_rounds": rounds >= max_rounds,
                "max_rounds": max_rounds}

    def _scan_round(self, aggressive: bool = False,
                    strict_prologue: bool = True,
                    use_rela: bool = True) -> tuple[dict[int, str], int]:
        """一轮扫描：返回 ({新入口地址: 发现依据}, 被 strict 跳过的候选数)。

        依据三类，便于事后审计误报率：
          bl_target    —— 有 bl 直接调用它（硬证据，默认启用）
          rela_target  —— 被重定位表当成代码指针（vtable/函数指针表项，
                          硬证据，默认启用；间接调用的唯一静态来源）
          prologue     —— 上一条是终止指令且本条是序言（仅 aggressive 开启）
        """
        found: dict[int, str] = {}
        skipped = 0

        # 类型 3 先跑：先建这些入口，后续两轮就能解到它们发出的 bl，
        # 从而带出更多被调函数（顺序反过来会多花一轮）。
        if use_rela:
            for addr in self.rela_targets():
                if self._code_entry_ok(addr):
                    found.setdefault(addr, "rela_target")

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
                        # (1) 第一次修改（2026-11-18）：strict 档要求**完整栈帧**。
                        #     bug 原因：裸 bti 被当序言，把 switch 的 case 块
                        #              全切成函数（libbase +171 全是误报）。
                        #     解决方案：strict 时要求 3 条内出现栈帧建立指令；
                        #              只有裸 bti 的候选计入 skipped，不建函数。
                        if strict_prologue and not self.is_prologue_strict(ins.addr):
                            skipped += 1
                            continue
                        found.setdefault(ins.addr, "prologue")
        return found, skipped
