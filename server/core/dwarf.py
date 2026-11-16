"""DWARF CFI 栈回溯：用 .eh_frame 的展开规则逐帧还原调用栈。

## 为什么需要它

frida 的 `Thread.backtrace(ACCURATE)` 依赖**帧指针链**或它自己的 DWARF 展开。
加固 so 普遍开 PAC（指针认证）且省略帧指针，实测只能拿到 2 帧且是同一地址重复。
`.eh_frame` 是编译器生成的**权威**展开信息，比扫栈猜候选帧可靠得多——
libunwind / libgcc 走的就是同一条路。

## 必须说清的前提（不粉饰）

**不是所有 so 都有可用的 `.eh_frame`。** 实测 sscronet.so：

    .eh_frame      392 字节   （正常 4.9MB 的 so 应有几百 KB）
    .eh_frame_hdr  116 字节
    FDE 覆盖 .text 比例  0.04%

这明显被刻意剥离。这种样本上本模块**救不了**——所以它算三个判据
（字节数 < 1KB / FDE < 10 / 覆盖率 < 5%），任一命中就把 `cfi_coverage.enough`
置 False 并给 warning，让调用方知道"别信这个结果"，绝不给假成功。

## 实现范围（实测数据见 docs/dwarf-cfi.md）

支持（这些覆盖了全部 4 个真样本里出现的指令）：
    DW_CFA_advance_loc / _loc1 / _loc2 / _loc4 / set_loc
    DW_CFA_def_cfa / _def_cfa_register / _def_cfa_offset
    DW_CFA_def_cfa_sf / _def_cfa_offset_sf
    DW_CFA_offset / _offset_extended / _offset_extended_sf
    DW_CFA_val_offset / _val_offset_sf
    DW_CFA_register / _same_value / _undefined
    DW_CFA_restore / _restore_extended
    DW_CFA_remember_state / _restore_state
    DW_CFA_AARCH64_negate_ra_state（PAC 标志，只记录不改 CFA）
    DW_CFA_nop / GNU_args_size（无副作用）

不支持且**会如实上报**（`unsupported_ops`）：
    DW_CFA_def_cfa_expression   → CFA 变成表达式，本模块算不出，该 FDE 直接放弃
    DW_CFA_expression / _val_expression → 对应寄存器值未知（RA 未知则放弃该帧）
    未知 opcode                 → 编码长度不可知，安全做法是放弃该 FDE，不猜
"""
from __future__ import annotations

import struct

__all__ = [
    "CfiUnavailable",
    "CfiUnwinder",
    "parse_eh_frame",
    "unwind_frames",
]

# ---------------------------------------------------------------- CFI 常量

# primary opcode：高 2 位决定类别，低 6 位是参数
_PRIMARY_ADVANCE_LOC = 0x40
_PRIMARY_OFFSET = 0x80
_PRIMARY_RESTORE = 0xC0

# extended opcode（高 2 位为 0，整字节即操作码）
_E_SET_LOC = 0x01
_E_ADVANCE_LOC1 = 0x02
_E_ADVANCE_LOC2 = 0x03
_E_ADVANCE_LOC4 = 0x04
_E_OFFSET_EXTENDED = 0x05
_E_RESTORE_EXTENDED = 0x06
_E_UNDEFINED = 0x07
_E_SAME_VALUE = 0x08
_E_REGISTER = 0x09
_E_REMEMBER_STATE = 0x0A
_E_RESTORE_STATE = 0x0B
_E_DEF_CFA = 0x0C
_E_DEF_CFA_REGISTER = 0x0D
_E_DEF_CFA_OFFSET = 0x0E
_E_DEF_CFA_EXPRESSION = 0x0F
_E_EXPRESSION = 0x10
_E_OFFSET_EXTENDED_SF = 0x11
_E_DEF_CFA_SF = 0x12
_E_DEF_CFA_OFFSET_SF = 0x13
_E_VAL_OFFSET = 0x14
_E_VAL_OFFSET_SF = 0x15
_E_VAL_EXPRESSION = 0x16
_E_AARCH64_NEGATE_RA_STATE = 0x2D   # 与 SPARC 的 GNU_window_save 同值
_E_GNU_ARGS_SIZE = 0x2E
_E_NOP = 0x00

# ARM64 DWARF 寄存器编号：0..30 = x0..x30，31 = sp
_REG_SP = 31
_REG_LR = 30          # 默认 return_address_register

# 覆盖充足的判据（任务要求 + 覆盖率这一条更强的信号）
_MIN_EH_FRAME_BYTES = 1024
_MIN_FDES = 10
_MIN_COVERAGE_RATIO = 0.05

# 栈窗口预取：CFA 附近的保存寄存器几乎都落在负偏移侧（实测最大 -0x100 内）
_PREFETCH_BELOW = 0x200
_PREFETCH_ABOVE = 0x40


class CfiUnavailable(RuntimeError):
    """这个 so 没有可用 CFI，或起点无法展开。

    code 供调用方做程序化判断；coverage 一并带出，便于上层把
    "为什么不行"完整交代给使用者（而不是只给一句 error）。
    """

    def __init__(self, code: str, message: str, coverage: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.coverage = coverage or {}


# ---------------------------------------------------------------- LEB128


def _uleb(data: bytes, i: int) -> tuple[int, int]:
    """读 ULEB128；读到末尾就停（不抛异常，由调用方按需判断）。"""
    val = 0
    shift = 0
    n = len(data)
    while i < n:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return val, i


def _sleb(data: bytes, i: int) -> tuple[int, int]:
    """读 SLEB128（data_alignment_factor 是负数，必须按有符号读）。"""
    val = 0
    shift = 0
    n = len(data)
    while i < n:
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                val |= -(1 << shift)
            break
    return val, i


def _cstr(data: bytes, i: int) -> tuple[str, int]:
    """读 NUL 结尾的 augmentation 字符串。"""
    j = data.find(b"\x00", i)
    if j < 0:
        return "", len(data)
    return data[i:j].decode("ascii", "replace"), j + 1


# ---------------------------------------------------------------- CIE / FDE


class _Cie:
    """一条 Common Information Entry。"""

    __slots__ = ("code_align", "data_align", "ra_reg", "fde_enc", "has_z",
                 "insns", "initial_regs", "initial_cfa")

    def __init__(self) -> None:
        self.code_align = 1
        self.data_align = 1
        self.ra_reg = _REG_LR
        self.fde_enc = 0x00       # 无 'R' 时的默认（absptr）
        self.has_z = False
        self.insns = b""
        # CIE 初始指令执行完后的规则，作为 FDE 里 DW_CFA_restore 的复原基准
        self.initial_regs: dict[int, tuple] = {}
        self.initial_cfa: tuple | None = None


class _Fde:
    """一条 Frame Description Entry。"""

    __slots__ = ("pc_begin", "pc_end", "insns", "cie")

    def __init__(self, pc_begin: int, pc_end: int, insns: bytes, cie: _Cie):
        self.pc_begin = pc_begin
        self.pc_end = pc_end
        self.insns = insns
        self.cie = cie


def _read_encoded(data: bytes, i: int, enc: int, field_va: int) -> tuple[int | None, int]:
    """读一个 DW_EH_PE 编码的值，返回 (value, new_i)。

    支持 absptr / uleb / udata2/4/8 / sleb / sdata2/4/8，应用位支持
    pcrel（+字段自身地址）与 datarel。不支持的编码返回 (None, i)。
    """
    if enc == 0xFF:                       # DW_EH_PE_omit
        return None, i
    fmt = enc & 0x0F
    app = enc & 0x70
    n = len(data)

    def _need(k: int) -> bool:
        return i + k <= n

    if fmt == 0x00:                        # absptr（按地址宽度取，elf64 → 8）
        if not _need(8):
            return None, i
        val = struct.unpack_from("<Q", data, i)[0]
        i += 8
    elif fmt == 0x01:                      # uleb128
        val, i = _uleb(data, i)
    elif fmt == 0x02:                      # udata2
        if not _need(2):
            return None, i
        val = struct.unpack_from("<H", data, i)[0]
        i += 2
    elif fmt == 0x03:                      # udata4
        if not _need(4):
            return None, i
        val = struct.unpack_from("<I", data, i)[0]
        i += 4
    elif fmt == 0x04:                      # udata8
        if not _need(8):
            return None, i
        val = struct.unpack_from("<Q", data, i)[0]
        i += 8
    elif fmt == 0x09:                      # sleb128
        val, i = _sleb(data, i)
    elif fmt == 0x0A:                      # sdata2
        if not _need(2):
            return None, i
        val = struct.unpack_from("<h", data, i)[0]
        i += 2
    elif fmt == 0x0B:                      # sdata4
        if not _need(4):
            return None, i
        val = struct.unpack_from("<i", data, i)[0]
        i += 4
    elif fmt == 0x0C:                      # sdata8
        if not _need(8):
            return None, i
        val = struct.unpack_from("<q", data, i)[0]
        i += 8
    else:
        return None, i

    if app == 0x10:                        # pcrel：相对该字段自身地址
        val += field_va
    elif app == 0x50:                      # datarel：本实现无 datarel 基址，如实放弃
        return None, i
    return val, i


def _skip_encoded(data: bytes, i: int, enc: int, field_va: int) -> int:
    """跳过（不解析）一个 DW_EH_PE 值——用于跳过 personality 指针等。"""
    _, i = _read_encoded(data, i, enc, field_va)
    return i


def _parse_cie(body: bytes, unsupported: set) -> _Cie | None:
    """解析 CIE 正文（已去掉 length 与 CIE_id）。

    字段顺序严格按 DWARF 规范，v4 多两个字节：
        version
        augmentation string (NUL 结尾)
        [v>=4] address_size (1) + segment_selector_size (1)
        code_alignment_factor  (ULEB)
        data_alignment_factor  (SLEB)
        return_address_register (v1: 1 字节；v3+: ULEB)
        ['z' 开头时] augmentation_length (ULEB) + augmentation data
        initial instructions
    """
    if len(body) < 4:
        return None
    cie = _Cie()
    ver = body[0]
    p = 1
    aug, p = _cstr(body, p)

    if ver >= 4:
        # v4/v5：先 address_size / segment_selector_size，跳过
        p += 2
    # code_alignment_factor：规范里恒为 ULEB（v1 也是）
    cie.code_align, p = _uleb(body, p)
    # data_alignment_factor：**恒为 SLEB**，且通常是 -4（ARM64）
    cie.data_align, p = _sleb(body, p)
    if ver == 1:
        if p >= len(body):
            return None
        cie.ra_reg = body[p]
        p += 1
    else:
        cie.ra_reg, p = _uleb(body, p)
    if not cie.code_align:
        cie.code_align = 1
    if not cie.data_align:
        cie.data_align = 1

    if aug.startswith("z"):
        cie.has_z = True
        aug_len, p = _uleb(body, p)
        aug_data = body[p:p + aug_len]
        p += aug_len
        _parse_augmentation(cie, aug[1:], aug_data, unsupported)

    cie.insns = body[p:]
    return cie


def _parse_augmentation(cie: _Cie, chars: str, data: bytes,
                        unsupported: set) -> None:
    """解析 augmentation data，取出 'R'（FDE 指针编码）。

    需要完整跳过的有 'L'（LSDA 编码，1 字节）与 'P'（personality，
    编码字节 + 一个按该编码编码的值）。跳错会让后续 insns 起点错位，
    这条 FDE 就整条废掉——所以宁可标 unsupported 也不瞎猜。
    """
    q = 0
    for ch in chars:
        if ch == "R":
            if q < len(data):
                cie.fde_enc = data[q]
                q += 1
        elif ch == "L":
            q += 1
        elif ch == "P":
            if q >= len(data):
                break
            enc = data[q]
            q += 1
            q = _skip_encoded(data, q, enc, 0)
        elif ch == "S":
            pass                            # 信号帧，无载荷
        elif ch in ("B", "G"):
            pass                            # 极罕见，无载荷假设不可靠
            unsupported.add(ord(ch))
        else:
            unsupported.add(ord("?") if not ch.isprintable() else ord(ch))
            break


def _parse_fde(body: bytes, cie: _Cie, rec_va: int,
               unsupported: set) -> _Fde | None:
    """解析 FDE 正文（已去掉 length 与 cie_pointer）。

    body 起点 = 紧接 cie_pointer 之后，即 initial_location 字段所在处。
    """
    enc = cie.fde_enc
    # initial_location 的 pcrel 基址 = 该字段自身的地址
    pc_begin, p = _read_encoded(body, 0, enc, rec_va)
    if pc_begin is None:
        unsupported.add(0xFF01)             # 编码不支持
        return None
    # address_range 只用格式位，**不带**应用位（规范：applied only to location）
    pc_range, p = _read_encoded(body, p, enc & 0x0F, rec_va + p)
    if pc_range is None:
        unsupported.add(0xFF01)
        return None
    insns = body[p:]
    if cie.has_z:
        # FDE 的 augmentation data：长度前缀 + 内容（通常是 LSDA 指针），整体跳过
        aug_len, q = _uleb(insns, 0)
        insns = insns[q + aug_len:]
    if pc_range <= 0:
        return None
    return _Fde(pc_begin, pc_begin + pc_range, insns, cie)


# ---------------------------------------------------------------- 规则状态机

# 寄存器规则用元组表示，避免建一堆小对象：
#   ("offset", n)      值在 [CFA + n]
#   ("val_offset", n)  值就是 CFA + n（不是解引用）
#   ("register", r)    值在寄存器 r 里
#   ("same",)          值没变（沿用上一帧）
#   ("undefined",)     值不可得
#   ("expr", bytes)    DWARF 表达式，本实现不解 → 视为值未知


class _State:
    """CFI 规则的累积状态：CFA 规则 + 各寄存器保存规则。"""

    __slots__ = ("loc", "cfa_reg", "cfa_off", "cfa_known", "regs", "ra_signed")

    def __init__(self, loc: int) -> None:
        self.loc = loc
        self.cfa_reg: int | None = None
        self.cfa_off = 0
        self.cfa_known = False
        self.regs: dict[int, tuple] = {}
        self.ra_signed = False

    def clone(self) -> "_State":
        s = _State(self.loc)
        s.cfa_reg = self.cfa_reg
        s.cfa_off = self.cfa_off
        s.cfa_known = self.cfa_known
        s.regs = dict(self.regs)       # 浅拷贝：规则元组不可变，值拷贝足够
        s.ra_signed = self.ra_signed
        return s


def _block(data: bytes, i: int) -> tuple[bytes, int]:
    """读一个 DWARF block（ULEB 长度 + 内容）。"""
    n, i = _uleb(data, i)
    return data[i:i + n], i + n


_STOP = 1        # 目标 PC 已命中，停止执行
_ABORT = 2       # 该 FDE 无法可靠展开（指令编码不可知 / CFA 变表达式）


def _run_stream(st: _State, data: bytes, cie: _Cie, initial: dict[int, tuple],
                target_pc: int, unsupported: set) -> int:
    """执行一段 CFI 指令流，把规则累积进 st。

    返回 _STOP（已到达 target_pc 对应的行）/ _ABORT（放弃该 FDE）/ 0（走完）。

    (1) 第一次修改（2026-11-16）
    bug 原因：初版实现把 DW_CFA_AARCH64_negate_ra_state（0x2d）当成"未知
              opcode"直接 break 掉整个指令流。而 0x2d 是 **PAC 编译的必出指令**，
              在 prologue 里紧跟在 advance_loc 之后、def_cfa 之前。
              于是 def_cfa / offset 这些真正的规则一条都没执行到。
              实测 libbase 的 0x12094：objdump 真值是 CFA=reg29+32、
              reg30=[CFA-24]，而初版返回 ('sp', 0, None)——**看起来是个合法
              的 CFA 规则**，调用方完全看不出它其实是错的。
    解决方案：显式识别 0x2d 并只切换 ra_signed 标志（PAC 只影响签名，
              不改变 CFA 基址与返回地址位置）；把"未知 opcode"单独留在
              最后的 else 分支，因为它的**编码长度不可知**，无法安全跳过。
    """
    i = 0
    n = len(data)
    stack: list[_State] = []

    while i < n:
        op = data[i]
        i += 1
        primary = op & 0xC0
        arg = op & 0x3F

        # ---- primary opcode ----
        if primary == _PRIMARY_ADVANCE_LOC:
            new_loc = st.loc + arg * cie.code_align
            if new_loc > target_pc:
                return _STOP
            st.loc = new_loc
            continue
        if primary == _PRIMARY_OFFSET:
            off, i = _uleb(data, i)
            st.regs[arg] = ("offset", off * cie.data_align)
            continue
        if primary == _PRIMARY_RESTORE:
            if arg in initial:
                st.regs[arg] = initial[arg]
            else:
                st.regs.pop(arg, None)
            continue

        # ---- extended opcode ----
        if op == _E_NOP:
            continue

        if op == _E_SET_LOC:
            if i + 8 > n:
                return _ABORT
            st.loc = struct.unpack_from("<Q", data, i)[0]
            i += 8
            if st.loc > target_pc:
                return _STOP
            continue

        if op in (_E_ADVANCE_LOC1, _E_ADVANCE_LOC2, _E_ADVANCE_LOC4):
            size = {_E_ADVANCE_LOC1: 1, _E_ADVANCE_LOC2: 2, _E_ADVANCE_LOC4: 4}[op]
            if i + size > n:
                return _ABORT
            delta = int.from_bytes(data[i:i + size], "little")
            i += size
            new_loc = st.loc + delta * cie.code_align
            if new_loc > target_pc:
                return _STOP
            st.loc = new_loc
            continue

        if op == _E_DEF_CFA:
            reg, i = _uleb(data, i)
            off, i = _uleb(data, i)
            st.cfa_reg = reg
            st.cfa_off = off
            st.cfa_known = True
            continue

        if op == _E_DEF_CFA_SF:
            reg, i = _uleb(data, i)
            off, i = _sleb(data, i)
            st.cfa_reg = reg
            st.cfa_off = off * cie.data_align
            st.cfa_known = True
            continue

        if op == _E_DEF_CFA_REGISTER:
            reg, i = _uleb(data, i)
            st.cfa_reg = reg
            st.cfa_known = st.cfa_known or True
            continue

        if op == _E_DEF_CFA_OFFSET:
            off, i = _uleb(data, i)
            st.cfa_off = off
            continue

        if op == _E_DEF_CFA_OFFSET_SF:
            off, i = _sleb(data, i)
            st.cfa_off = off * cie.data_align
            continue

        if op == _E_DEF_CFA_EXPRESSION:
            # CFA 变成 DWARF 表达式：本模块不解表达式，如实放弃整条 FDE
            _, i = _block(data, i)
            unsupported.add(_E_DEF_CFA_EXPRESSION)
            return _ABORT

        if op in (_E_OFFSET_EXTENDED, _E_VAL_OFFSET):
            reg, i = _uleb(data, i)
            off, i = _uleb(data, i)
            kind = "offset" if op == _E_OFFSET_EXTENDED else "val_offset"
            st.regs[reg] = (kind, off * cie.data_align)
            continue

        if op in (_E_OFFSET_EXTENDED_SF, _E_VAL_OFFSET_SF):
            reg, i = _uleb(data, i)
            off, i = _sleb(data, i)
            kind = "offset" if op == _E_OFFSET_EXTENDED_SF else "val_offset"
            st.regs[reg] = (kind, off * cie.data_align)
            continue

        if op == _E_REGISTER:
            reg, i = _uleb(data, i)
            reg2, i = _uleb(data, i)
            st.regs[reg] = ("register", reg2)
            continue

        if op == _E_SAME_VALUE:
            reg, i = _uleb(data, i)
            st.regs[reg] = ("same",)
            continue

        if op == _E_UNDEFINED:
            reg, i = _uleb(data, i)
            st.regs[reg] = ("undefined",)
            continue

        if op == _E_RESTORE_EXTENDED:
            reg, i = _uleb(data, i)
            if reg in initial:
                st.regs[reg] = initial[reg]
            else:
                st.regs.pop(reg, None)
            continue

        if op in (_E_EXPRESSION, _E_VAL_EXPRESSION):
            reg, i = _uleb(data, i)
            _, i = _block(data, i)
            st.regs[reg] = ("expr", b"")
            unsupported.add(op)
            continue

        if op == _E_REMEMBER_STATE:
            stack.append(st.clone())
            continue

        if op == _E_RESTORE_STATE:
            if stack:
                saved = stack.pop()
                saved.loc = st.loc        # 位置不随状态回滚
                st = _copy_into(st, saved)
            continue

        if op == _E_AARCH64_NEGATE_RA_STATE:
            # PAC：标记"返回地址已签名"。只影响签名认证，不改变 CFA/RA 位置。
            # 真机展开时无法做认证，故读出的 RA 需要剥掉签名位（见 _strip_pac）。
            st.ra_signed = not st.ra_signed
            continue

        if op == _E_GNU_ARGS_SIZE:
            _, i = _uleb(data, i)
            continue

        # 未知 opcode：**编码长度不可知，无法安全跳过**。
        # 继续往下读必然错位并解出垃圾规则——这正是"给假结果"的来源，必须放弃。
        unsupported.add(op)
        return _ABORT

    return 0


def _copy_into(dst: _State, src: _State) -> _State:
    """把 src 的规则搬进 dst（restore_state 用，保持对象引用不变）。"""
    dst.cfa_reg = src.cfa_reg
    dst.cfa_off = src.cfa_off
    dst.cfa_known = src.cfa_known
    dst.regs = src.regs
    dst.ra_signed = src.ra_signed
    return dst


def _rules_at(fde: _Fde, pc: int, unsupported: set) -> _State | None:
    """算出 pc 处的完整规则状态；无法可靠算出返回 None。

    执行顺序是 CIE 初始指令 → FDE 指令（CIE 的规则是 FDE 的基线）。
    """
    cie = fde.cie
    st = _State(fde.pc_begin)
    rc = _run_stream(st, cie.insns, cie, {}, pc, unsupported)
    if rc == _ABORT:
        return None
    if rc == _STOP:                     # target_pc 落在 CIE 指令覆盖范围（罕见）
        return st
    # CIE 执行完的规则即 FDE 里 restore 的复原基准。
    # (2) 第二次修改（2026-11-16）
    #     bug 原因：初版把 `initial = st.regs`（**同一个 dict**）当复原基准。
    #               而 FDE 指令流是原地修改 st.regs 的，于是 DW_CFA_restore
    #               会从"已经被改过的字典"里取值——恢复出来的是错误规则，
    #               而不是 CIE 的初始值。这种错不会报异常，只会让某几个
    #               寄存器悄悄变成错的值。
    #     解决方案：先 dict(...) 拷贝一份作为 initial，之后再继续执行。
    initial = dict(st.regs)
    cie.initial_regs = dict(st.regs)
    cie.initial_cfa = (st.cfa_reg, st.cfa_off)

    rc = _run_stream(st, fde.insns, cie, initial, pc, unsupported)
    if rc == _ABORT:
        return None
    return st


def _cfa_at(fde: dict, pc: int, unsupported: set) -> tuple | None:
    """兼容接口：返回 (cfa_reg_name, cfa_offset, ra_rule_desc)。

    真正的实现是 `_rules_at`；本函数保留旧签名供测试与外部调用方使用。
    fde 参数接受 `parse_eh_frame` 产出的 dict，也接受内部 _Fde 对象。
    """
    internal = _as_internal_fde(fde)
    if internal is None:
        return None
    st = _rules_at(internal, pc, unsupported)
    if st is None or not st.cfa_known or st.cfa_reg is None:
        return None
    ra = st.regs.get(internal.cie.ra_reg)
    return (_reg_name(st.cfa_reg), st.cfa_off, _rule_desc(ra, internal.cie))


def _rule_desc(rule: tuple | None, cie: _Cie) -> str | None:
    """把寄存器规则压成可读描述，如 "CFA-24" / "reg x29"。"""
    if rule is None:
        return None
    kind = rule[0]
    if kind == "offset":
        return f"CFA{rule[1]:+d}"
    if kind == "val_offset":
        return f"CFA{rule[1]:+d} (value)"
    if kind == "register":
        return f"reg {_reg_name(rule[1])}"
    if kind == "same":
        return "same value"
    if kind == "undefined":
        return "undefined"
    if kind == "expr":
        return "expression (unsupported)"
    return None


def _as_internal_fde(fde) -> _Fde | None:
    """parse_eh_frame 的 dict 与内部 _Fde 互相兼容。"""
    if isinstance(fde, _Fde):
        return fde
    if isinstance(fde, dict):
        cie = fde.get("_cie_obj")
        if cie is not None:
            return _Fde(fde["pc_begin"], fde["pc_end"], fde["insns"], cie)
    return None


def _reg_name(num: int) -> str:
    """DWARF 寄存器号 → mda 上下文里的名字（ARM64 约定）。"""
    if num == _REG_SP:
        return "sp"
    if 0 <= num <= 30:
        return f"x{num}"
    return f"dwarf_reg_{num}"


# ---------------------------------------------------------------- .eh_frame 定位


def _pt_gnu_eh_frame(so) -> tuple[int, int]:
    """从原始程序头取 PT_GNU_EH_FRAME 的 (vaddr, filesz)。

    不走 pyelftools 的 iter_segments()：节表被抹的 dump so 上它会抛
    ELFParseError，而这恰恰是最需要兜底的场合（与 elf_model 同一套做法）。
    """
    try:
        so._stream.seek(0)                              # noqa: SLF001 - 复用同一文件流
        head = so._stream.read(64)                      # noqa: SLF001
        if len(head) < 0x40 or head[:4] != b"\x7fELF":
            return 0, 0
        e_phoff, = struct.unpack_from("<Q", head, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", head, 0x36)
        for k in range(e_phnum):
            so._stream.seek(e_phoff + k * e_phentsize)  # noqa: SLF001
            ph = so._stream.read(e_phentsize)           # noqa: SLF001
            if len(ph) < 56:
                break
            p_type, = struct.unpack_from("<I", ph, 0)
            if p_type == 0x6474E550:                    # PT_GNU_EH_FRAME
                _off, p_vaddr, _pa, p_filesz, _memsz = struct.unpack_from(
                    "<QQQQQ", ph, 8)
                return p_vaddr, p_filesz
    except Exception:                                   # noqa: BLE001
        pass
    return 0, 0


def _decode_eh_frame_hdr(so) -> dict:
    """解析 .eh_frame_hdr：拿到 .eh_frame 的地址与 FDE 计数。

    头格式：version(1) eh_frame_ptr_enc(1) fde_count_enc(1) table_enc(1)
            然后 eh_frame_ptr、fde_count，再往后是二分查找表。
    这个头在无节表样本里是**唯一**能找到 .eh_frame 的入口。
    """
    out: dict = {"found": False}
    sec = None
    for s in getattr(so, "sections", None) or []:
        if s.name == ".eh_frame_hdr":
            sec = s
            break
    if sec is not None:
        addr, size = sec.addr, sec.size
    else:
        addr, size = _pt_gnu_eh_frame(so)
    if not addr or not size:
        return out

    data = so.read(addr, min(int(size), 4096))
    if len(data) < 4:
        return out
    version = data[0]
    ptr_enc, count_enc, table_enc = data[1], data[2], data[3]
    p = 4
    frame_ptr, p = _read_encoded(data, p, ptr_enc, addr + p)
    count, p = _read_encoded(data, p, count_enc, addr + p)
    out.update({
        "found": True,
        "version": version,
        "eh_frame_addr": frame_ptr,
        "fde_count": count,
        "table_encoding": table_enc,
        "hdr_bytes": int(size),
    })
    return out


def _find_eh_frame(so) -> tuple[int, int]:
    """定位 .eh_frame 的 (vaddr, size)。

    优先用节表；节表被抹时用 .eh_frame_hdr 的 eh_frame_ptr。
    后者的长度未知，用"读到终止记录 / 读不到"来定上界。
    """
    for s in getattr(so, "sections", None) or []:
        if s.name == ".eh_frame":
            if s.size:
                return s.addr, s.size
            return 0, 0

    hdr = _decode_eh_frame_hdr(so)
    start = hdr.get("eh_frame_addr") or 0
    if not start:
        return 0, 0
    # 长度未知：按块往后读，直到 EOF 或读到 0 长度终止记录。
    # 上界 16MB 只是防御（.eh_frame 不会真有这么大）。
    total = 0
    while total < (16 << 20):
        chunk = so.read(start + total, 64 << 10)
        if not chunk:
            break
        total += len(chunk)
        if len(chunk) < (64 << 10):
            break
    return start, total


# ---------------------------------------------------------------- 公开解析接口


def parse_eh_frame(so) -> dict:
    """解析 so 的 .eh_frame，返回 {cies, fdes, coverage, unsupported, hdr}。

    fdes 每条是 dict：{pc_begin, pc_end, insns, _cie_obj, code_align,
                       data_align, ra_reg}
    同时给出 cfi_coverage —— 调用方必须读它，不能只看 fdes 非空。
    """
    cached = getattr(so, "_dwarf_cfi_cache", None)
    if cached is not None:
        return cached

    eh_addr, eh_size = _find_eh_frame(so)
    if not eh_addr or not eh_size:
        raise CfiUnavailable(
            "NO_EH_FRAME",
            "这个 so 没有 .eh_frame（或已被剥离），无法做 DWARF CFI 回溯。"
            "可改用 get_callstack(method='scan') 的启发式扫描",
            {"eh_frame_bytes": 0, "total_fdes": 0, "enough": False,
             "covered_pc": False,
             "warning": ".eh_frame 不存在或长度为 0"})

    data = so.read(eh_addr, eh_size)
    if not data:
        raise CfiUnavailable("EH_FRAME_UNREADABLE",
                             f".eh_frame（{eh_addr:#x}，{eh_size} 字节）读不出来",
                             {"eh_frame_bytes": eh_size, "total_fdes": 0,
                              "enough": False, "covered_pc": False})

    cies: dict[int, _Cie] = {}
    fdes: list[_Fde] = []
    unsupported: set[int] = set()

    i = 0
    n = len(data)
    while i + 4 <= n:
        rec_start = i
        length, = struct.unpack_from("<I", data, i)
        j = i + 4
        if length == 0:
            break                                   # 终止记录
        if length == 0xFFFFFFFF:                    # 64 位长度（Android so 极少）
            if j + 8 > n:
                break
            length, = struct.unpack_from("<Q", data, j)
            j += 8
        rec_end = j + length
        if rec_end > n or length < 4:
            break                                   # 截断：停在这里，不猜
        cie_id, = struct.unpack_from("<I", data, j)
        body = data[j + 4:rec_end]

        if cie_id == 0:
            cie = _parse_cie(body, unsupported)
            if cie is not None:
                cies[rec_start] = cie
        else:
            # .eh_frame 里 cie_pointer 是**反向位移**，相对本记录的
            # cie_pointer 字段起点：cie_off = rec_start + 4 - cie_id
            cie_off = rec_start + 4 - cie_id
            cie = cies.get(cie_off)
            if cie is not None:
                # initial_location 字段的 VA = 记录起点 + 8（length + cie_ptr 之后）
                fde = _parse_fde(body, cie, eh_addr + rec_start + 8, unsupported)
                if fde is not None:
                    fdes.append(fde)
        i = rec_end

    hdr = _decode_eh_frame_hdr(so)
    coverage = _build_coverage(so, eh_size, cies, fdes, hdr)

    out = {
        "cies": cies,
        "fdes": [_fde_dict(f) for f in fdes],
        "coverage": coverage,
        "unsupported": sorted(x for x in unsupported if x < 0x100),
        "hdr": hdr,
    }
    try:
        so._dwarf_cfi_cache = out                     # noqa: SLF001 - 解析结果缓存
    except Exception:                                 # noqa: BLE001
        pass
    return out


def _fde_dict(f: _Fde) -> dict:
    """对外暴露的 FDE 形态（保留 _cie_obj 给内部用，避免二次解析）。"""
    cie = f.cie
    return {
        "pc_begin": f.pc_begin,
        "pc_end": f.pc_end,
        "insns": f.insns,
        "code_align": cie.code_align,
        "data_align": cie.data_align,
        "ra_reg": cie.ra_reg,
        "_cie_obj": cie,
    }


def _build_coverage(so, eh_size: int, cies: dict, fdes: list[_Fde],
                    hdr: dict) -> dict:
    """算 CFI 覆盖度，并给出「够不够用」的判断与理由。

    三条判据（任一不满足就判不足）：
        ① .eh_frame 字节数 >= 1KB
        ② FDE 条数 >= 10
        ③ FDE 覆盖的代码字节 / 可执行段字节 >= 5%
    第 ③ 条是最强的信号：被剥离的样本往往 FDE 条数还凑合（十几个），
    但只覆盖 .text 的千分之几——只看条数会误判成"够用"。

    (3) 第三次修改（2026-11-16）
    bug 原因：初版只有 `len(fdes) >= 10` 这一条判据，于是 sscronet.so
              （.eh_frame 仅 392 字节、13 条 FDE、覆盖 0.04%）被判成
              enough=True **且完全没有 warning**。这正好是本任务明令禁止的
              "假装成功"——调用方会拿着一条只有 1 帧的栈当完整调用栈用。
    解决方案：加"字节数"与"覆盖率"两条判据，任一不过就 enough=False，
              并生成可解释的 warning（把具体数字写进去，便于判断是不是被剥离）。
    """
    covered = sum(max(0, f.pc_end - f.pc_begin) for f in fdes)
    code_bytes = 0
    try:
        for s in getattr(so, "sections", None) or []:
            if s.is_exec and s.name not in (".plt",):
                code_bytes += s.size
        if not code_bytes:
            code_bytes = sum(b - a for a, b, _o, fl in so.exec_regions())
    except Exception:                                 # noqa: BLE001
        code_bytes = 0
    ratio = (covered / code_bytes) if code_bytes else 0.0

    reasons: list[str] = []
    if eh_size < _MIN_EH_FRAME_BYTES:
        reasons.append(f".eh_frame 仅 {eh_size} 字节（< {_MIN_EH_FRAME_BYTES}）")
    if len(fdes) < _MIN_FDES:
        reasons.append(f"只有 {len(fdes)} 条 FDE（< {_MIN_FDES}）")
    if ratio < _MIN_COVERAGE_RATIO:
        reasons.append(f"FDE 只覆盖可执行段的 {ratio * 100:.2f}%"
                       f"（< {_MIN_COVERAGE_RATIO * 100:.0f}%）")

    enough = not reasons
    cov = {
        "eh_frame_bytes": int(eh_size),
        "total_fdes": len(fdes),
        "fdes": len(fdes),                 # 兼容既有断言用名
        "cies": len(cies),
        "text_bytes": int(code_bytes),
        "covered_bytes": int(covered),
        "coverage_ratio": round(ratio, 6),
        "enough": enough,
        "covered_pc": False,               # 由 unwind 阶段填
    }
    if hdr.get("found"):
        cov["eh_frame_hdr"] = {
            "bytes": hdr.get("hdr_bytes"),
            "fde_count": hdr.get("fde_count"),
        }
        # hdr 的二分表条数应当与解析出的 FDE 数一致；差太多说明解析漏了
        want = hdr.get("fde_count")
        if isinstance(want, int) and want > 0 and abs(want - len(fdes)) > 1:
            cov["fde_count_mismatch"] = (
                f".eh_frame_hdr 声明 {want} 条 FDE，实际解析出 {len(fdes)} 条")
    if not enough:
        cov["warning"] = (
            "CFI 信息不足，回溯结果**不可信**：" + "；".join(reasons) +
            "。这个 so 的 .eh_frame 很可能被剥离/裁剪过。"
            "建议改用 get_callstack(method='scan')（启发式扫栈）"
            "或 method='accurate'（frida），并注意它们同样可能不完整。")
    return cov


# ---------------------------------------------------------------- 栈内存读取


class _StackReader:
    """按 CFA 附近窗口批量取栈内存，带页级缓存。

    为什么要缓存：一次展开每帧只应付出**一次** RPC。保存寄存器集中在
    [CFA-0x200, CFA+0x40)，预取这一窗就能服务该帧所有 offset 规则。
    """

    def __init__(self, read_mem=None, page: int = 0x400) -> None:
        self._read_mem = read_mem
        self._page = page
        self._cache: dict[int, bytes] = {}
        self.calls = 0

    @property
    def available(self) -> bool:
        return callable(self._read_mem)

    def prefetch(self, cfa: int) -> None:
        """预取 CFA 附近的栈窗口（失败忽略，后续单点读会如实失败）。"""
        if not self.available:
            return
        lo = (cfa - _PREFETCH_BELOW) & ~0xF
        hi = cfa + _PREFETCH_ABOVE
        page = self._page
        start = lo & ~(page - 1)
        while start < hi:
            self._fetch_page(start)
            start += page

    def _fetch_page(self, base: int) -> bytes:
        if base in self._cache:
            return self._cache[base]
        data = b""
        if self.available:
            try:
                self.calls += 1
                data = self._read_mem(base, self._page) or b""
            except Exception:                          # noqa: BLE001
                data = b""
        self._cache[base] = data
        return data

    def read(self, addr: int, size: int = 8) -> bytes:
        """读 size 字节；任一页缺失就返回空（调用方据此判定不可得）。"""
        if not self.available:
            return b""
        if size <= 0:
            return b""
        if addr <= 0:
            return b""
        out = bytearray()
        cur = addr
        remain = size
        while remain > 0:
            page = cur & ~(self._page - 1)
            in_page = cur - page
            chunk = self._fetch_page(page)
            if len(chunk) <= in_page:
                return b""
            take = min(self._page - in_page, remain)
            out.extend(chunk[in_page:in_page + take])
            cur += take
            remain -= take
            if len(chunk) < self._page and in_page + take > len(chunk):
                break
        return bytes(out)

    def read_ptr(self, addr: int) -> int | None:
        raw = self.read(addr, 8)
        if len(raw) != 8:
            return None
        return int.from_bytes(raw, "little")


# ---------------------------------------------------------------- 展开


def _strip_pac(addr: int) -> int:
    """剥掉 ARM64 PAC 签名位（顶层比特），取真实地址。

    PAC 把签名放在 VA 最高位之上：48 位 VA 时签名占 bit63..48。
    判断方式（通用，不含任何样本特征）：若高位非零，而低 48 位看起来
    像个正常用户空间地址，就采用低 48 位。
    """
    if addr >> 48 == 0:
        return addr
    low = addr & ((1 << 48) - 1)
    return low if low > 0x1000 else addr


class CfiUnwinder:
    """跨模块的 CFI 展开器。

    用法：
        w = CfiUnwinder(read_mem=fn)
        w.add_module(base=0x7a00000000, size=..., so=so_file, name="libx.so")
        out = w.unwind(pc=..., regs={"sp": ..., "x0": ...}, limit=64)
    """

    def __init__(self, read_mem=None) -> None:
        self._modules: list[dict] = []      # [{base, size, so, name, index}]
        self._reader = _StackReader(read_mem)
        self._unsupported: set[int] = set()
        self._first_cov: dict | None = None

    def add_module(self, base: int, size: int, so=None, name: str = "") -> None:
        """登记一个模块。so 为 None 表示"知道范围但没加载静态文件"。"""
        if not base or not size:
            return
        self._modules.append({"base": int(base), "size": int(size),
                              "so": so, "name": name or getattr(so, "name", "")})
        self._modules.sort(key=lambda m: m["base"])

    def _module_for(self, addr: int) -> dict | None:
        for m in self._modules:
            if m["base"] <= addr < m["base"] + m["size"]:
                return m
        return None

    def _fde_for(self, module: dict, static_pc: int):
        """在该模块的 FDE 表里找覆盖 static_pc 的那条（二分）。"""
        so = module.get("so")
        if so is None:
            return None
        table = module.get("_table")
        if table is None:
            try:
                parsed = parse_eh_frame(so)
            except CfiUnavailable:
                module["_table"] = ([], [])
                return None
            arr = sorted(parsed["fdes"], key=lambda f: f["pc_begin"])
            table = (arr, [f["pc_begin"] for f in arr])
            module["_table"] = table
            module["_coverage"] = parsed["coverage"]
            if self._first_cov is None:
                self._first_cov = parsed["coverage"]
        arr, begins = table
        if not arr:
            return None
        lo, hi, best = 0, len(begins) - 1, -1
        while lo <= hi:
            mid = (lo + hi) // 2
            if begins[mid] <= static_pc:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if best < 0:
            return None
        f = arr[best]
        return f if f["pc_begin"] <= static_pc < f["pc_end"] else None

    def unwind(self, pc: int, regs: dict, limit: int = 64) -> dict:
        """从 (pc, regs) 逐帧展开。

        regs 支持两种键名：x0..x30 / sp / pc（mda 上下文原样），以及
        fp / lr 别名。缺少 sp 会直接报错——那是硬性前提，不能猜。
        """
        limit = max(1, min(int(limit), 512))
        cur = _normalize_regs(regs)
        if cur.get("sp") is None:
            raise CfiUnavailable(
                "NO_SP",
                "DWARF 展开需要 sp，但断点现场的 context 里没有 sp。"
                "确认目标是 arm64 且断点确实命中过。",
                self._first_cov or {})

        frames: list[dict] = []
        first_cov: dict | None = None
        start_pc = int(pc)
        covered_start = False
        seen: set[int] = set()
        stop_reason = ""

        cur_pc = start_pc
        for depth in range(limit):
            if cur_pc in seen:
                stop_reason = f"检测到循环：PC {cur_pc:#x} 已出现过，停止"
                break
            seen.add(cur_pc)

            mod = self._module_for(cur_pc)
            if mod is None:
                frames.append({
                    "depth": depth,
                    "pc": cur_pc,
                    "note": "该 PC 不在任何已登记模块范围内，无法继续展开",
                })
                if depth == 0:
                    stop_reason = "起点 PC 不在已登记模块范围内"
                break

            # 第 2 帧起 PC 是"返回地址"，指向调用指令的下一条。
            # 查 FDE 必须回到调用指令本身所在地址（ARM64 指令 4 字节）。
            lookup_pc = cur_pc if depth == 0 else _ret_addr_to_call(cur_pc)
            static_pc = lookup_pc - mod["base"]
            fde = self._fde_for(mod, static_pc)
            if fde is None:
                frames.append({
                    "depth": depth,
                    "pc": cur_pc,
                    "so": mod["name"],
                    "note": (f"PC {lookup_pc:#x}（静态 {static_pc:#x}）"
                             "不在任何 FDE 覆盖范围内，无法继续展开"),
                })
                if depth == 0:
                    stop_reason = "起点 PC 没有对应的 FDE（CFI 未覆盖该函数）"
                else:
                    stop_reason = ("上一帧的返回地址没有 FDE 覆盖，"
                                   "说明调用链进入了无 CFI 的代码")
                break
            if depth == 0:
                covered_start = True
                first_cov = mod.get("_coverage")

            internal = _as_internal_fde(fde)
            rules = _rules_at(internal, lookup_pc - mod["base"], self._unsupported)
            if rules is None or not rules.cfa_known or rules.cfa_reg is None:
                frames.append({
                    "depth": depth,
                    "pc": cur_pc,
                    "so": mod["name"],
                    "static_addr": static_pc,
                    "note": "该处 CFA 规则算不出来（含不支持的 CFI 指令），停止",
                })
                stop_reason = "CFA 规则不可用"
                break

            cfa_reg_name = _reg_name(rules.cfa_reg)
            cfa_base = cur.get(cfa_reg_name)
            if cfa_base is None:
                frames.append({
                    "depth": depth,
                    "pc": cur_pc,
                    "so": mod["name"],
                    "static_addr": static_pc,
                    "cfa_rule": f"{cfa_reg_name}{rules.cfa_off:+d}",
                    "note": f"CFA 依赖 {cfa_reg_name}，但该寄存器值未知，停止",
                })
                stop_reason = f"CFA 依赖的寄存器 {cfa_reg_name} 值未知"
                break

            cfa = int(cfa_base) + int(rules.cfa_off)
            frame = {
                "depth": depth,
                "pc": cur_pc,
                "so": mod["name"],
                "static_addr": static_pc,
                "cfa": cfa,
                "cfa_rule": f"{cfa_reg_name}{rules.cfa_off:+d}",
                "lookup_pc": lookup_pc,
            }
            if rules.ra_signed:
                frame["ra_signed"] = True

            # ---- 取返回地址 ----
            ra_rule = rules.regs.get(internal.cie.ra_reg)
            next_pc, ra_note = _resolve_return_pc(
                ra_rule, cfa, cur, internal.cie.ra_reg, self._reader, rules)
            frame["ra_rule"] = _rule_desc(ra_rule, internal.cie)
            if next_pc is None:
                frame["note"] = ra_note or "返回地址不可得，停止"
                frames.append(frame)
                stop_reason = ra_note or "返回地址不可得"
                break
            frames.append(frame)
            if next_pc == 0:
                stop_reason = "返回地址为 0（调用栈顶）"
                break

            # ---- 恢复寄存器，为下一帧准备 ----
            new_regs = dict(cur)
            new_regs["sp"] = cfa
            self._reader.prefetch(cfa)
            for regnum, rule in rules.regs.items():
                name = _reg_name(regnum)
                kind = rule[0]
                if kind == "offset":
                    val = self._reader.read_ptr(cfa + rule[1])
                    if val is None:
                        continue          # 读不到就保留旧值，下一帧会如实失败
                    new_regs[name] = _strip_pac(val) if regnum == internal.cie.ra_reg else val
                elif kind == "val_offset":
                    new_regs[name] = cfa + rule[1]
                elif kind == "register":
                    src = cur.get(_reg_name(rule[1]))
                    if src is not None:
                        new_regs[name] = src
            # RA 规则也可能来自 "register"（罕见：LR 未入栈）
            new_regs["pc"] = next_pc
            cur = new_regs
            cur_pc = next_pc
        else:
            stop_reason = f"达到帧数上限 {limit}（可能有更多帧）"

        cov = dict(first_cov or self._first_cov or {})
        if not cov:
            cov = {"total_fdes": 0, "enough": False, "covered_pc": covered_start,
                   "warning": "没有任何模块的 .eh_frame 可用"}
        cov["covered_pc"] = covered_start
        for f in frames:
            if f.get("so") and not f.get("in_gap"):
                f["in_gap"] = False
        covered_frames = sum(1 for f in frames if "cfa" in f)
        return {
            "method": "dwarf",
            "frame_count": len(frames),
            "frames": frames,
            "cfi_coverage": cov,
            "unsupported_ops": [f"0x{x:02x}" for x in sorted(self._unsupported)],
            "mem_reads": self._reader.calls,
            "decisive_frames": covered_frames,
            "stop_reason": stop_reason or "正常结束（返回地址为 0 或栈顶）",
        }


def _ret_addr_to_call(ra: int) -> int:
    """把返回地址折回"调用指令"的地址，用于查 FDE。

    返回地址指向调用指令的下一条；若它正好落在下一个函数的起始处，
    直接用它会查到错误的 FDE。回退 4 字节（ARM64 定长指令）即可落回
    真正含调用点的函数内。
    """
    return ra - 4 if ra > 4 else ra


def _normalize_regs(regs: dict) -> dict:
    """把上下文寄存器字典规整成 {x0..x30, sp, pc}。

    只保留能转成 int 的值；"0x..." 字符串与 int 都接受。
    缺 fp/lr 与 x29/x30 互为别名（与 dyn/debugger 的约定一致）。
    """
    out: dict[str, int] = {}
    if not isinstance(regs, dict):
        return out
    for key, val in regs.items():
        name = str(key).lower()
        iv = _to_int(val)
        if iv is None:
            continue
        out[name] = iv
    for short, long in (("fp", "x29"), ("lr", "x30")):
        if short in out and long not in out:
            out[long] = out[short]
        elif long in out and short not in out:
            out[short] = out[long]
    return out


def _to_int(val) -> int | None:
    """寄存器值 → int；转不了返回 None（不伪造 0）。"""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    text = str(val).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _resolve_return_pc(rule: tuple | None, cfa: int, regs: dict, ra_reg: int,
                       reader: _StackReader, rules: _State) -> tuple[int | None, str]:
    """按规则求返回地址，同时给出「为什么拿不到」的中文理由。"""
    if rule is None:
        # 没有规则 = 该寄存器未保存，按"值未变"处理（DWARF 默认语义）
        val = regs.get(_reg_name(ra_reg))
        if val is None:
            return None, f"返回地址寄存器 {_reg_name(ra_reg)} 既无规则也无已知值"
        return _strip_pac(int(val)), ""

    kind = rule[0]
    if kind == "offset":
        addr = cfa + rule[1]
        if not reader.available:
            return None, (
                f"返回地址在 [CFA{rule[1]:+d}]={addr:#x}，但本次没有可用的"
                "内存读取器（未能附加目标进程），无法读出")
        val = reader.read_ptr(addr)
        if val is None:
            return None, (f"返回地址应在 {addr:#x}（CFA{rule[1]:+d}），"
                          "但该栈地址读不到（栈页不可读或已越过栈顶）")
        return _strip_pac(val), ""

    if kind == "val_offset":
        return _strip_pac(cfa + rule[1]), ""
    if kind == "register":
        src = regs.get(_reg_name(rule[1]))
        if src is None:
            return None, f"返回地址在寄存器 {_reg_name(rule[1])}，但该值未知"
        return _strip_pac(int(src)), ""
    if kind == "same":
        val = regs.get(_reg_name(ra_reg))
        if val is None:
            return None, "返回地址规则为 same-value，但寄存器值未知"
        return _strip_pac(int(val)), ""
    if kind == "undefined":
        return None, "返回地址被标记为 undefined（该帧不含可回溯的返回地址）"
    if kind == "expr":
        return None, "返回地址由 DWARF 表达式计算（本模块不支持表达式）"
    return None, f"无法解释的返回地址规则：{kind}"


def unwind_frames(so, pc: int, regs: dict, limit: int = 32,
                  read_mem=None, base: int = 0, module_size: int = 0) -> dict:
    """单 so 便捷入口（向后兼容）。

    read_mem(addr, size) -> bytes 是读取**目标进程活内存**的回调；
    不给就只能展开第 0 帧，并在 stop_reason 里说清原因——不伪造后续帧。
    """
    w = CfiUnwinder(read_mem=read_mem)
    size = int(module_size or 0)
    if not size:
        # 范围取可执行+数据的最大上界；只用于"这个地址属于哪个 so"的判断
        try:
            size = max((b for _a, b, _o, _f in so._loads), default=0)  # noqa: SLF001
        except Exception:                                            # noqa: BLE001
            size = 0
    if not size:
        size = 1 << 32
    w.add_module(base=int(base), size=int(size), so=so,
                 name=getattr(so, "name", ""))
    return w.unwind(int(pc), regs, limit=int(limit))
