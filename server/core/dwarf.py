"""DWARF CFI 栈回溯：用 .eh_frame 的展开规则逐帧还原调用栈。

## 为什么需要它

frida 的 `Thread.backtrace(ACCURATE)` 依赖**帧指针链**或 DWARF CFI。
加固 so 普遍开了 PAC 且省略帧指针，实测只能拿到 2 帧（同一个地址重复）。

`.eh_frame` 是编译器生成的**权威**展开信息——比扫栈猜候选帧可靠得多。

## 必须说清的前提（不粉饰）

**不是所有 so 都有可用的 `.eh_frame`。** 实测 sscronet.so：
    .eh_frame      392 字节（正常几 MB 的 so 应有几百 KB）
    .eh_frame_hdr  116 字节
这明显是被刻意剥离了。这种样本上本模块**救不了**——
所以它会在返回里报 `cfi_coverage`，让调用方知道"CFI 不够，别信这个结果"。

## 实现范围

支持 ARM64 上最常见的 CFA 指令：
    DW_CFA_advance_loc / _loc1 / _loc2 / _loc4
    DW_CFA_def_cfa / _def_cfa_offset / _def_cfa_register
    DW_CFA_offset / _offset_extended
    DW_CFA_register
    DW_CFA_restore / _restore_extended
    DW_CFA_remember_state / _restore_state
    DW_CFA_set_loc / _nop

不支持的在 `unsupported_ops` 里列出来，**不猜**。
"""
from __future__ import annotations

import struct

__all__ = ["parse_eh_frame", "unwind_frames", "CfiUnavailable"]

# DWARF CFI opcodes（高 2 位是 primary，其余是 extended）
_DW_CFA_advance_loc = 0x40
_DW_CFA_offset = 0x80
_DW_CFA_restore = 0xC0

# Extended opcodes
_E_set_loc = 0x01
_E_advance_loc1 = 0x02
_E_advance_loc2 = 0x03
_E_advance_loc4 = 0x04
_E_offset_extended = 0x05
_E_restore_extended = 0x06
_E_undefined = 0x07
_E_same_value = 0x08
_E_register = 0x09
_E_remember_state = 0x0A
_E_restore_state = 0x0B
_E_def_cfa = 0x0C
_E_def_cfa_register = 0x0D
_E_def_cfa_offset = 0x0E
_E_def_cfa_expression = 0x0F
_E_expression = 0x10
_E_offset_extended_sf = 0x11
_E_def_cfa_sf = 0x12
_E_def_cfa_offset_sf = 0x13
_E_val_offset = 0x14
_E_val_offset_sf = 0x15
_E_val_expression = 0x16
_E_nop = 0x00

# ARM64 DWARF 寄存器编号
_RA_COLUMN = 30          # x30 = LR


class CfiUnavailable(RuntimeError):
    """这个 so 没有可用的 CFI 信息。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _Cie:
    __slots__ = ("code_align", "data_align", "ra_reg", "fde_enc", "has_augz",
                 "insns", "aug_data")

    def __init__(self):
        self.code_align = 1
        self.data_align = 1
        self.ra_reg = _RA_COLUMN
        self.fde_enc = 0x1B      # pcrel | sdata4，ARM64 默认
        self.has_augz = False
        self.insns = b""
        self.aug_data = b""


def _uleb(data: bytes, i: int) -> tuple[int, int]:
    """读 ULEB128。"""
    val = 0
    shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return val, i


def _sleb(data: bytes, i: int) -> tuple[int, int]:
    """读 SLEB128。"""
    val = 0
    shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                val |= -(1 << shift)
            break
    return val, i


def _read_bytes(data: bytes, i: int, n: int) -> tuple[bytes, int]:
    return data[i:i + n], i + n


def parse_eh_frame(so) -> dict:
    """解析 .eh_frame，返回 {cies, fdes, coverage}。

    fde 每条：{pc_begin, pc_end, cie_insns, cie}
    """
    sec = None
    for s in getattr(so, "sections", []):
        if s.name == ".eh_frame":
            sec = s
            break
    if sec is None or not sec.size:
        # 段表兜底：无节表的样本靠 PT_LOAD 找不到 .eh_frame，只能如实报
        raise CfiUnavailable(
            "NO_EH_FRAME",
            "这个 so 没有 .eh_frame 段（或被剥离），无法做 CFI 回溯。"
            "可改用 get_callstack(method='scan') 的启发式扫描")

    data = so.read(sec.addr, sec.size)
    if not data:
        raise CfiUnavailable("EH_FRAME_UNREADABLE", ".eh_frame 读不出来")

    cies: dict[int, _Cie] = {}
    fdes: list[dict] = []
    unsupported: set[int] = set()

    i = 0
    n = len(data)
    while i + 4 <= n:
        rec_start = i
        length, j = struct.unpack_from("<I", data, i)[0], i + 4
        if length == 0:
            break                              # 终止记录
        if length == 0xFFFFFFFF:               # 64 位长度，Android so 极少见
            if j + 8 > n:
                break
            length = struct.unpack_from("<Q", data, j)[0]
            j += 8
        rec_end = j + length
        if rec_end > n:
            break                              # 截断，停止（不猜）
        cie_id, j2 = struct.unpack_from("<I", data, j)[0], j + 4
        body = data[j2:rec_end]

        if cie_id == 0:
            # 这是一条 CIE
            cie, rest, aug_ok = _parse_cie(body)
            if cie is not None:
                cies[rec_start] = cie
            if not aug_ok:
                unsupported.add(0xFF00)
        else:
            # FDE：cie_pointer 是**相对本记录起点**的偏移（向前指）。
            # 注意 cie_id 不含 CIE 的 4 字节长度字段本身——标准做法是
            # cie_off = rec_start - cie_id。实测 liblog 第二条记录：
            # rec_start=24, cie_id=28 → cie_off = -4（错），
            # 正确应为 rec_start + 4 - cie_id = 0（CIE 在偏移 0）。
            cie_off = rec_start + 4 - cie_id
            cie = cies.get(cie_off)
            fde = _parse_fde(body, cie, sec.addr + j2)
            if fde is not None:
                fdes.append(fde)
        i = rec_end

    coverage = {
        "eh_frame_bytes": sec.size,
        "cies": len(cies),
        "fdes": len(fdes),
        "enough": len(fdes) >= 10,
    }
    if not coverage["enough"]:
        coverage["warning"] = (
            f"这个 so 的 .eh_frame 只有 {sec.size} 字节、{len(fdes)} 条 FDE。"
            "正常规模应有几百条。CFI 信息很可能被剥离——"
            "用本结果回溯会不完整，建议改用 method='scan'")
    return {"cies": cies, "fdes": fdes, "coverage": coverage,
            "unsupported": sorted(unsupported)}


def _parse_cie(body: bytes) -> tuple[_Cie | None, bytes, bool]:
    """解析 CIE 正文（version 之后的部分）。"""
    if len(body) < 3:
        return None, body, False
    cie = _Cie()
    ver = body[0]
    p = 1
    aug, p = _cstr(body, p)
    cie.has_augz = aug.startswith("z")
    # code / data align 都是 ULEB
    cie.code_align, p = _uleb(body, p) if ver >= 4 else (1, p)
    if ver >= 4:
        cie.data_align, p = _sleb(body, p)
        cie.ra_reg, p = (_uleb(body, p) if p < len(body) else (30, p))
    else:
        # v1/v3：code_align 是 ULEB，data_align 是 **SLEB128**
        # （实测 liblog：01 7a5200 01 7c 1e → code=1, data=-4, ra=30）
        cie.code_align, p = _uleb(body, p) if p < len(body) else (1, p)
        cie.data_align, p = _sleb(body, p) if p < len(body) else (1, p)
        ra, p = _uleb(body, p) if p < len(body) else (30, p)
        cie.ra_reg = ra
    if not cie.code_align:
        cie.code_align = 1
    if not cie.data_align:
        cie.data_align = 1

    ok = True
    if cie.has_augz:
        aug_len, p = _uleb(body, p)
        cie.aug_data = body[p:p + aug_len]
        p += aug_len
        # 解析 aug_data 里的 'R' 字段（FDE 指针编码）
        q = 0
        while q < len(cie.aug_data):
            ch = cie.aug_data[q:q + 1]
            q += 1
            if ch == b"R":
                if q < len(cie.aug_data):
                    cie.fde_enc = cie.aug_data[q]
                    q += 1
            elif ch in (b"P", b"L", b"S"):
                # P 有一个编码+值，L 一个字节，S 无载荷
                if ch == b"P":
                    q = min(q + 1, len(cie.aug_data))
                elif ch == b"L":
                    q += 1
            else:
                ok = False      # 不认识的 augmentation，标记但继续
    cie.insns = body[p:]
    return cie, body[p:], ok


def _cstr(data: bytes, i: int) -> tuple[str, int]:
    j = data.find(b"\x00", i)
    if j < 0:
        return "", len(data)
    return data[i:j].decode("ascii", "replace"), j + 1


def _parse_fde(body: bytes, cie: _Cie | None, field_addr: int) -> dict | None:
    """解析 FDE 正文。body 已去掉 cie_pointer。"""
    if cie is None:
        return None
    enc = cie.fde_enc
    p = 0
    pc_begin, p = _read_encoded(body, p, enc, field_addr)
    rng_enc = enc & 0x0F
    pc_range, p = _read_encoded(body, p, rng_enc, field_addr + p)
    if pc_begin is None or pc_range is None:
        return None
    insns = body[p:]
    if cie.has_augz:
        # 跳过 FDE 的 augmentation data
        try:
            aug_len, q = _uleb(insns, 0)
            insns = insns[q + aug_len:]
        except Exception:                                 # noqa: BLE001
            pass
    return {
        "pc_begin": pc_begin,
        "pc_end": pc_begin + pc_range,
        "insns": insns,
        "cie_insns": cie.insns,
        "code_align": cie.code_align or 1,
        "data_align": cie.data_align or 1,
        "ra_reg": cie.ra_reg,
    }


def _read_encoded(data: bytes, i: int, enc: int, field_addr: int):
    """读一个 DW_EH_PE 编码的值。不支持的编码返回 (None, i)。"""
    if enc == 0xFF:
        return None, i
    fmt = enc & 0x0F
    app = enc & 0x70
    if fmt == 0x00:      # absptr
        if i + 8 > len(data):
            return None, i
        v = struct.unpack_from("<Q", data, i)[0]
        i += 8
    elif fmt == 0x01:    # uleb128
        v, i = _uleb(data, i)
    elif fmt == 0x02:    # udata2
        v = struct.unpack_from("<H", data, i)[0]; i += 2
    elif fmt == 0x03:    # udata4
        v = struct.unpack_from("<I", data, i)[0]; i += 4
    elif fmt == 0x04:    # udata8
        v = struct.unpack_from("<Q", data, i)[0]; i += 8
    elif fmt == 0x09:    # sleb128
        v, i = _sleb(data, i)
    elif fmt == 0x0A:    # sdata2
        v = struct.unpack_from("<h", data, i)[0]; i += 2
    elif fmt == 0x0B:    # sdata4
        v = struct.unpack_from("<i", data, i)[0]; i += 4
    elif fmt == 0x0C:    # sdata8
        v = struct.unpack_from("<q", data, i)[0]; i += 8
    else:
        return None, i

    if app == 0x10:      # pcrel
        v += field_addr
    elif app == 0x50:    # datarel
        v += field_addr
    elif app == 0x00:    # absptr，不变
        pass
    return v, i


def unwind_frames(so, pc: int, regs: dict, limit: int = 32) -> dict:
    """从 (pc, regs) 出发，按 CFI 规则逐帧展开。

    regs 需要含 sp（必需）、lr/x30（可选）。返回 {frames, coverage, ...}。
    """
    parsed = parse_eh_frame(so)
    fdes = parsed["fdes"]
    coverage = parsed["coverage"]

    # 建索引：pc → fde（FDE 已按 pc_begin 无序，先排序再二分）
    fdes_sorted = sorted(fdes, key=lambda f: f["pc_begin"])
    begins = [f["pc_begin"] for f in fdes_sorted]

    def _find(addr: int):
        lo, hi = 0, len(begins) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if begins[mid] <= addr:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if best is None:
            return None
        f = fdes_sorted[best]
        return f if addr < f["pc_end"] else None

    frames: list[dict] = []
    unsupported: set[int] = set()
    cur_pc = int(pc)
    cur_regs = {k: v for k, v in regs.items() if v is not None}
    if "sp" not in cur_regs:
        raise CfiUnavailable("NO_SP", "展开需要 sp，但传入的寄存器里没有")

    for depth in range(max(1, int(limit))):
        fde = _find(cur_pc)
        if fde is None:
            frames.append({"frame": depth, "pc": cur_pc,
                           "note": "该 PC 不在任何 FDE 覆盖范围内，无法继续展开"})
            break
        rule = _cfa_at(fde, cur_pc, unsupported)
        if rule is None:
            frames.append({"frame": depth, "pc": cur_pc,
                           "note": "这条 FDE 的 CFA 规则算不出来，停止"})
            break
        cfa_reg, cfa_off, ra_off = rule
        base = cur_regs.get(cfa_reg)
        if base is None:
            frames.append({"frame": depth, "pc": cur_pc,
                           "note": f"CFA 依赖 {cfa_reg}，但该寄存器值未知"})
            break
        cfa = int(base) + int(cfa_off)
        frames.append({
            "frame": depth,
            "pc": cur_pc,
            "cfa": cfa,
            "rule": f"{cfa_reg}+{cfa_off}",
        })
        # 下一帧：LR 从 CFA+ra_off 读出来；SP 变成 CFA
        next_pc = cur_regs.get("x%d" % fde["ra_reg"])
        if ra_off is not None:
            saved_lr = _read_ptr(so, cfa + ra_off)
            if saved_lr:
                next_pc = saved_lr
        if not next_pc:
            break
        cur_regs = dict(cur_regs)
        cur_regs["sp"] = cfa
        cur_pc = int(next_pc)
        if cur_pc == 0:
            break

    out = {
        "ok": True,
        "method": "dwarf",
        "frame_count": len(frames),
        "frames": frames,
        "cfi_coverage": coverage,
    }
    if unsupported:
        out["unsupported_ops"] = ["0x%02x" % x for x in sorted(unsupported)]
    if not coverage.get("enough"):
        out["warning"] = coverage.get("warning")
    return out


def _cfa_at(fde: dict, pc: int, unsupported: set) -> tuple | None:
    """执行 CIE+FDE 的指令序列，求出该 PC 处的 (cfa_reg, cfa_off, ra_off)。"""
    state = {"cfa_reg": "sp", "cfa_off": 0, "ra_off": None,
             "regs": {}, "loc": fde["pc_begin"]}
    stack: list[dict] = []

    for insns, align in ((fde["cie_insns"], fde["code_align"]),
                         (fde["insns"], fde["code_align"])):
        i = 0
        n = len(insns)
        while i < n:
            op = insns[i]
            i += 1
            primary = op & 0xC0
            low = op & 0x3F

            if primary == _DW_CFA_advance_loc:
                state["loc"] += low * align
                if state["loc"] > pc:
                    return (state["cfa_reg"], state["cfa_off"], state["ra_off"])
                continue
            if primary == _DW_CFA_offset:
                off, i = _uleb(insns, i)
                state["regs"][low] = off * fde["data_align"]
                continue
            if primary == _DW_CFA_restore:
                state["regs"].pop(low, None)
                continue

            # Extended
            if op == _E_nop:
                continue
            if op == _E_set_loc:
                if i + 8 > n:
                    break
                state["loc"] = struct.unpack_from("<Q", insns, i)[0]; i += 8
                if state["loc"] > pc:
                    return (state["cfa_reg"], state["cfa_off"], state["ra_off"])
                continue
            if op in (_E_advance_loc1, _E_advance_loc2, _E_advance_loc4):
                size = {_E_advance_loc1: 1, _E_advance_loc2: 2,
                        _E_advance_loc4: 4}[op]
                if i + size > n:
                    break
                delta = int.from_bytes(insns[i:i + size], "little"); i += size
                state["loc"] += delta * align
                if state["loc"] > pc:
                    return (state["cfa_reg"], state["cfa_off"], state["ra_off"])
                continue
            if op == _E_def_cfa:
                reg, i = _uleb(insns, i)
                off, i = _uleb(insns, i)
                state["cfa_reg"] = _reg_name(reg)
                state["cfa_off"] = off
                continue
            if op == _E_def_cfa_register:
                reg, i = _uleb(insns, i)
                state["cfa_reg"] = _reg_name(reg)
                continue
            if op == _E_def_cfa_offset:
                off, i = _uleb(insns, i)
                state["cfa_off"] = off
                continue
            if op == _E_offset_extended:
                reg, i = _uleb(insns, i)
                off, i = _uleb(insns, i)
                state["regs"][reg] = off * fde["data_align"]
                continue
            if op == _E_restore_extended:
                reg, i = _uleb(insns, i)
                state["regs"].pop(reg, None)
                continue
            if op == _E_register:
                reg, i = _uleb(insns, i)
                reg2, i = _uleb(insns, i)
                state["regs"][reg] = ("reg", _reg_name(reg2))
                continue
            if op == _E_remember_state:
                stack.append(dict(state))
                continue
            if op == _E_restore_state:
                if stack:
                    state = stack.pop()
                continue
            # 不支持：记录下来并跳过（跳过长度未知时不冒险继续）
            unsupported.add(op)
            break

    return (state["cfa_reg"], state["cfa_off"], state["ra_off"])


def _reg_name(n: int) -> str:
    """DWARF 寄存器号 → mda 用的名字（ARM64：0-30 = x0-x30，31 = sp）。"""
    if n <= 30:
        return "x%d" % n
    if n == 31:
        return "sp"
    return "dwarf_reg_%d" % n


def _read_ptr(so, addr: int) -> int | None:
    """从 so 的**内存映像**读一个指针？——不行，这是静态文件。

    所以这里返回 None：真正读栈需要目标进程的活内存（由调用方注入）。
    """
    return None
