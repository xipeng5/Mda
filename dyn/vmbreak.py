"""VM 层断点 —— 按 (prog, idx) 停在某条 VM 指令上，读出 VM 寄存器堆与 VM 栈。

## 为什么需要它

动态加载 VM 的分析里，最关键的一步是「停在某条 VM 指令上，看当时的 VM 状态」。

传统做法是 hook 每个 opcode 的 handler，然后自己从 handler 的寄存器约定里
反算 A/B/C 字段——**每个 op 的约定都不一样**，每换一个 op 就要重新校准，
实际上不可用。

本模块换一个落点：**handler 尾部的派发段**。所有 handler 在执行完自己的
语义后，都会走同一段「保存 VM pc → 跳到下一个 handler」的代码：

    ldr  x2,  [x23, x5, lsl #3]   ; 查 handler 跳转表
    str  x21, [x27, #8]           ; 保存 VM pc
    br   x2                       ; 派发

在这一段上拦一次，就能在**每条 VM 指令执行前**拿到完整 VM 状态，
不需要理解任何单个 op 的寄存器约定。

## 真机验证的寄存器约定（2026-11-09，arm64，sgmainso 2.98MB）

    x25  → VM 寄存器堆基址，r[i] 在 [x25 + i*8]
    x21  → 当前 VM 指令指针（+0 u16 op / +2 A / +3 B / +4 C / +8 s64 imm）
    x27  → VM 上下文，[x27 + 8] = 当前 VM pc
    x23  → op → handler 的跳转表基址

    prog_base = *(*(x27 + 0x240) + 0x1a0)     ← 用来把 vm_pc 换算成 idx
    idx       = (vm_pc - prog_base) / 16

`prog_base` 的推导链（sub_170a8c，op508 host handler 调用的函数）：

    0x170a98  ldr x8, [x1, #0x240]    ; x1 = VM ctx
    0x170aa0  ldr x8, [x8, #0x1a0]    ; ← prog_base
    0x170aa4  add x0, x8, x2          ; + imm = host 变量地址

实测（真机，2026-11-09）：prog_base 只有 12~13 个不同值，
与 prog 数量吻合；用它算出的 idx 100% 落在合法范围内。
**不能用 vm_pc 直接减模块基址**——VM 代码区是 malloc 出来的，
与 so 模块不在一处。

反汇编证据（op491 handler，文件偏移 0x76000）：

    0x76004  ldr x20, [x25, x16, lsl #3]   ; r[B]
    0x7600c  ldr x0,  [x25, x17, lsl #3]   ; r[C]
    0x76018  str x19, [x25, x1,  lsl #3]   ; r[A] = 结果
    0x76024  str x21, [x27, #8]            ; VM pc
    0x76028  br  x2

## 扫描特征（实测 805/805 = 100% 可靠）

    "str x21, [x27, #8]"  =  75 07 00 f9

**不要用 "br x2" 当特征**：实测派发寄存器完全不固定
（x7/x17/x3/x15/x6/x4/x13/x19/x20/x11 都在用），
用 br x2 只能扫到 42/805 处。

## 通用性

所有目标侧细节都是参数：

    dispatch_patterns  派发段特征字节（默认就是上面那条）
    reg_base_offset    VM 寄存器堆在哪个参数寄存器（x25）
    ctx_offset         VM 上下文在哪个参数寄存器（x27）
    ip_offset          VM pc 在上下文里的偏移（+8）
    slot_size          每条 VM 指令多少字节（16）
    code_base          VM 代码区在进程里的基址

换一个 VM 只改参数，不改代码。
"""

from __future__ import annotations

import json
import os
import re
import struct

__all__ = [
    "find_dispatch_points",
    "vm_breakpoint",
    "vm_regs_snapshot",
    "VM_DEFAULT_PATTERN",
]

# 派发段特征：str x21, [x27, #8]
# 实测 805 处全部紧跟着 br xN，是「每条 VM 指令执行完」的公共落点。
VM_DEFAULT_PATTERN = "750700f9"

# 默认寄存器约定（真机验证，见模块注释）
VM_DEFAULTS = {
    "reg_base_reg": "x25",     # VM 寄存器堆基址
    "ip_reg": "x21",           # VM 指令指针
    "ctx_reg": "x27",          # VM 上下文
    "ip_offset": 8,            # [ctx + 8] = 当前 VM pc
    "slot_size": 16,           # 每条 VM 指令 16 字节
    "vm_reg_count": 32,        # VM 寄存器个数
    # prog_base 的两跳解引用路径：[ctx + p1_off] → [+ p2_off] = prog_base
    "prog_base_p1_offset": 0x240,
    "prog_base_p2_offset": 0x1A0,
}


def _read_so_bytes(so_name: str, so=None) -> bytes:
    """取 so 的原始字节。优先用已加载的 so 对象，其次按路径读。"""
    if so is not None and getattr(so, "_raw", None):
        return so._raw
    if so is not None:
        p = getattr(so, "path", None)
        if p and os.path.isfile(p):
            with open(p, "rb") as fh:
                return fh.read()
    if os.path.isfile(so_name):
        with open(so_name, "rb") as fh:
            return fh.read()
    raise FileNotFoundError(f"读不到 so 字节：{so_name}")


def find_dispatch_points(so_name: str, so=None,
                         pattern_hex: str = VM_DEFAULT_PATTERN,
                         limit: int = 2000) -> dict:
    """扫描 so 里所有 VM 派发段的位置。

    这是 `vm_breakpoint` 的前置步骤：先知道有哪几个落点，再决定挂哪个。

    返回：{count, points[], note}
    points[]: {offset, offset_hex}
    """
    try:
        data = _read_so_bytes(so_name, so)
    except FileNotFoundError as exc:
        return {"ok": False, "code": "SO_NOT_READABLE", "error": str(exc)}

    try:
        pat = bytes.fromhex(str(pattern_hex).replace(" ", ""))
    except ValueError:
        return {"ok": False, "code": "BAD_PATTERN",
                "error": f"pattern_hex 不是合法十六进制：{pattern_hex}"}
    if not pat:
        return {"ok": False, "code": "BAD_PATTERN", "error": "pattern 不能为空"}

    hits: list[int] = []
    off = 0
    while len(hits) < int(limit):
        i = data.find(pat, off)
        if i < 0:
            break
        hits.append(i)
        off = i + 1

    return {
        "ok": True,
        "so_name": so_name,
        "pattern": pat.hex(),
        "count": len(hits),
        "points": [{"offset": h, "offset_hex": hex(h)} for h in hits],
        "note": ("每个点都是「一条 VM 指令执行完、准备派发下一条」的位置。"
                 "挂在这些点上可以做 VM 级单步/断点。"),
    }


def vm_breakpoint(serial: str, pid: int, so_name: str, target_idx: int = -1,
                  code_base: int | str | None = None,
                  dispatch_offset: int | str | None = None,
                  pattern_hex: str = VM_DEFAULT_PATTERN,
                  slot_size: int = VM_DEFAULTS["slot_size"],
                  reg_base_reg: str = VM_DEFAULTS["reg_base_reg"],
                  ip_reg: str = VM_DEFAULTS["ip_reg"],
                  ctx_reg: str = VM_DEFAULTS["ctx_reg"],
                  ip_offset: int = VM_DEFAULTS["ip_offset"],
                  vm_reg_count: int = VM_DEFAULTS["vm_reg_count"],
                  prog_base_p1_offset: int = VM_DEFAULTS["prog_base_p1_offset"],
                  prog_base_p2_offset: int = VM_DEFAULTS["prog_base_p2_offset"],
                  capture_regs: int = 32,
                  stack_bytes: int = 256,
                  hold: bool = True,
                  max_hits: int = 1,
                  wait: float = 10.0) -> dict:
    """在 VM 的某条指令上设断点，停下时给出 VM 寄存器堆与 VM 栈。

    ## 参数

        target_idx       目标 VM 指令序号（如 11068）。**-1 = 不过滤，采所有**
        dispatch_offset  挂哪个派发点（静态偏移）。
                         不给则自动扫第一个匹配 pattern 的位置。
                         **建议给一个在频繁执行路径上的点**，否则可能长期不命中。
        pattern_hex      派发段特征字节
        slot_size        每条 VM 指令字节数
        reg_base_reg     VM 寄存器堆基址在哪个寄存器（默认 x25）
        ip_reg           VM 指令指针在哪个寄存器（默认 x21）
        ctx_reg          VM 上下文在哪个寄存器（默认 x27）
        ip_offset        VM pc 在上下文里的偏移（默认 8）
        vm_reg_count     VM 寄存器个数（默认 32）
        capture_regs     捕获多少个 VM 寄存器（默认 32）
        stack_bytes      额外抓多少字节的 native 栈
        hold             命中时是否挂起（默认 True，需 resume）
        max_hits         最多命中几次后自动放行

    ## 返回

        installed        挂上了几个点
        hits[]           {index, vm_pc, vm_idx, regs{r0..r31}, ctx, stack_hex}
        verdict

    ## 关键：idx 是怎么算出来的

        prog_base = *(*(ctx + 0x240) + 0x1a0)     ← 运行时解引用，不用调用方提供
        vm_pc     = *(ctx + 8)
        idx       = (vm_pc - prog_base) / 16

    **不要用 vm_pc - 模块基址**：VM 代码区是 malloc 出来的匿名内存，
    与 so 模块不在一处。实测该公式算出的 idx 100% 合法。

    派发点是在「当前指令执行完、下一条还没执行」的时刻被拦下的。
    所以停在这里读到的 vm_pc 是**下一条**要执行的指令。
    要停在第 target_idx 条「执行之前」，判断条件就是 vm_idx == target_idx。

    ## 已知边界

        · prog_base 的偏移路径（+0x240 / +0x1a0）是参数，换 VM 可改
        · 派发点有几百个，**只挂一个**：挂在哪个点就只能看到经过那个点的指令。
          如果目标 idx 的执行路径不经过这个点，会一直不命中——
          这时换一个点（或告诉我执行路径，我帮你选）
        · 不改变目标行为，只读不写
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # (2) 第二次修改（2026-11-09）：code_base 不再是必需参数。
    #     bug 原因：原来要求调用方给 code_base，但 VM 代码区是 malloc 出来的
    #               匿名内存，和 so 模块基址不在一处，调用方根本无从得知。
    #     解决方案：prog_base 改为运行时从 VM 上下文解引用得到：
    #               prog_base = *(*(ctx + 0x240) + 0x1a0)
    #               调用方不再需要提供任何基址。

    if int(slot_size) not in (8, 16, 32):
        return {"ok": False, "code": "BAD_SLOT_SIZE",
                "error": f"slot_size 应为 8/16/32，收到 {slot_size}"}

    # 决定挂哪个派发点
    disp = None
    if dispatch_offset is not None:
        try:
            disp = int(dispatch_offset, 16) if isinstance(dispatch_offset, str) \
                else int(dispatch_offset)
        except (TypeError, ValueError):
            return {"ok": False, "code": "BAD_DISPATCH_OFFSET",
                    "error": f"dispatch_offset 无法解析：{dispatch_offset!r}"}
    else:
        scan = find_dispatch_points(so_name, pattern_hex=pattern_hex, limit=1)
        if not scan.get("ok") or not scan.get("points"):
            return {"ok": False, "code": "NO_DISPATCH_POINT",
                    "error": "没有扫到派发点；确认 so 与 pattern 是否匹配",
                    "scan": scan}
        disp = scan["points"][0]["offset"]

    user_js = _JS_VM_BREAK
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__TARGET_IDX__", str(int(target_idx))),
        ("__SLOT_SIZE__", str(int(slot_size))),
        ("__P1_OFF__", str(int(prog_base_p1_offset))),
        ("__P2_OFF__", str(int(prog_base_p2_offset))),
        ("__REG_BASE_REG__", _js_str(reg_base_reg)),
        ("__IP_REG__", _js_str(ip_reg)),
        ("__CTX_REG__", _js_str(ctx_reg)),
        ("__IP_OFFSET__", str(int(ip_offset))),
        ("__VM_REG_COUNT__", str(int(vm_reg_count))),
        ("__CAPTURE_REGS__", str(int(capture_regs))),
        ("__STACK_BYTES__", str(int(stack_bytes))),
        ("__HOLD__", "true" if hold else "false"),
        ("__MAX_HITS__", str(max(1, int(max_hits)))),
    ):
        user_js = user_js.replace(k, v)

    return _run_vm_break(serial, int(pid), so_name, user_js,
                         hold=bool(hold), max_hits=int(max_hits),
                         wait=float(wait))


_JS_VM_BREAK = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    var TARGET_IDX = __TARGET_IDX__;
    var SLOT_SIZE = __SLOT_SIZE__;
    var REG_BASE_REG = __REG_BASE_REG__;
    var IP_REG = __IP_REG__;
    var CTX_REG = __CTX_REG__;
    var IP_OFFSET = __IP_OFFSET__;
    var P1_OFF = __P1_OFF__;
    var P2_OFF = __P2_OFF__;
    var VM_REG_COUNT = __VM_REG_COUNT__;
    var CAPTURE_REGS = __CAPTURE_REGS__;
    var STACK_BYTES = __STACK_BYTES__;
    var MAX_HITS = __MAX_HITS__;

    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', code: 'SO_NOT_FOUND', error: '模块未加载：' + SO_NAME});
        return;
    }

    var addr = mod.base.add(DISPATCH_OFFSET);
    var hitCount = 0;
    var listener = null;

    function readVmRegs(basePtr) {
        var out = {};
        var n = Math.min(CAPTURE_REGS, VM_REG_COUNT);
        for (var i = 0; i < n; i++) {
            try { out['r' + i] = basePtr.add(i * 8).readPointer().toString(); }
            catch (e) { out['r' + i] = null; }
        }
        return out;
    }

    function ctxReg(ctx, name) {
        try { var v = ctx[name]; return v === undefined ? null : v; }
        catch (e) { return null; }
    }

    // prog_base = *(*(ctx + P1_OFF) + P2_OFF)
    // 这是把 vm_pc 换算成 idx 的关键：VM 代码区是 malloc 出来的，
    // 与 so 模块基址不在一处，**不能**用 pc - 模块基址。
    function readProgBase(ctxp) {
        try {
            var p1 = ctxp.add(P1_OFF).readPointer();
            return p1.add(P2_OFF).readPointer();
        } catch (e) { return null; }
    }

    listener = Interceptor.attach(addr, {
        onEnter: function () {
            var c = this.context;
            var ctxp = ctxReg(c, CTX_REG);
            var regbase = ctxReg(c, REG_BASE_REG);
            if (ctxp === null) { return; }

            var vmPc;
            try { vmPc = ctxp.add(IP_OFFSET).readPointer(); }
            catch (e) { return; }

            var progBase = readProgBase(ctxp);
            if (progBase === null) { return; }

            // 用有符号差再除，避免 vm_pc 小于 prog_base 时被当成巨大正数
            var delta = vmPc.sub(progBase).toInt32();
            var idx = delta / SLOT_SIZE;

            if (TARGET_IDX >= 0 && idx !== TARGET_IDX) { return; }

            hitCount++;
            var rec = {
                kind: 'vm_hit',
                index: hitCount,
                vm_pc: vmPc.toString(),
                prog_base: progBase.toString(),
                vm_idx: idx,
                native_pc: c.pc.toString(),
                dispatch_addr: addr.toString(),
                ctx: ctxp.toString(),
                reg_base: regbase === null ? null : regbase.toString()
            };
            if (regbase !== null) { rec.regs = readVmRegs(regbase); }
            try {
                rec.stack_hex = Array.from(new Uint8Array(
                    c.sp.readByteArray(Math.min(STACK_BYTES, 1024))))
                    .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                    .join('');
            } catch (e) { rec.stack_hex = null; }

            send(rec);

            if (hitCount >= MAX_HITS && listener !== null) {
                listener.detach();
                listener = null;
            }
        }
    });

    send({kind: 'installed', dispatch_addr: addr.toString(),
          dispatch_offset: DISPATCH_OFFSET, target_idx: TARGET_IDX,
          module_base: mod.base.toString(), module: mod.name,
          prog_base_path: '*(*(ctx+0x' + P1_OFF.toString(16) + ')+0x'
                          + P2_OFF.toString(16) + ')'});

    recv('stop', function () {
        if (listener !== null) { try { listener.detach(); } catch (e) {} }
        send({kind: 'stopped', hits: hitCount});
    });
})();
"""


def _js_str(s) -> str:
    import json as _json

    return _json.dumps(str(s))


def _detach_async(sess, timeout: float = 2.0) -> None:
    """守护线程里 detach（本设备上同步 detach 会永久阻塞）。"""
    import threading as _th

    if sess is None:
        return

    def _w() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass

    t = _th.Thread(target=_w, name="mda-vm-detach", daemon=True)
    t.start()
    try:
        t.join(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


def _run_vm_break(serial: str, pid: int, so_name: str, user_js: str,
                  hold: bool = True, max_hits: int = 1,
                  wait: float = 10.0) -> dict:
    """注入 VM 断点脚本并等待命中。"""
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # 把 SO_NAME 换成实际模块名（脚本里用 SO_NAME 占位）
    script_src = user_js.replace("SO_NAME", _js_str(so_name))

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(script_src)
        box: dict = {"installed": None, "hits": [], "error": None,
                     "stopped": False}

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["error"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "installed":
                box["installed"] = payload
            elif kind == "vm_hit":
                box["hits"].append(payload)
            elif kind == "stopped":
                box["stopped"] = True
            elif kind == "error":
                box["error"] = payload.get("error") or "未知错误"
                box["error_code"] = payload.get("code")

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while _time.time() - t0 < float(wait):
            if box["error"]:
                break
            if len(box["hits"]) >= max(1, max_hits):
                break
            _time.sleep(0.05)
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        _time.sleep(0.2)
    except Exception as exc:                              # noqa: BLE001
        probe = None
        try:
            from dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception:                                 # noqa: BLE001
            probe = None
        code = "VM_BREAK_FAILED"
        msg = f"{type(exc).__name__}: {exc}"
        if probe and probe.get("alive") is False:
            code = "TARGET_DIED"
            msg += f"；进程 {pid} 已不存在"
        return {"ok": False, "code": code, "error": msg,
                "process_probe": probe}
    finally:
        _detach_async(sess)

    out: dict = {
        "ok": box["error"] is None,
        "installed": box["installed"],
        "hit_count": len(box["hits"]),
        "hits": box["hits"],
    }
    if box["error"]:
        out["code"] = box.get("error_code") or "VM_BREAK_FAILED"
        out["error"] = box["error"]
    elif not box["hits"]:
        out["verdict"] = (f"{wait:.0f}s 内没有命中 idx={target_idx}。"
                          "可能原因：① 该指令在当前操作下没被执行；"
                          "② 挂的派发点不在它的执行路径上"
                          "（805 个点里只挂了 1 个）")
        out["hint"] = ("先用 vm_regs_snapshot 看当前 VM 在跑哪些 idx，"
                       "再挑一个在活跃路径上的派发点；"
                       "或把 target_idx 设成 -1（不过滤，采所有遇到的 idx）")
    else:
        h0 = box["hits"][0]
        out["verdict"] = (f"命中 {len(box['hits'])} 次，"
                          f"VM pc={h0.get('vm_pc')} idx={h0.get('vm_idx')}")
    return out


def vm_regs_snapshot(serial: str, pid: int, so_name: str,
                     dispatch_offset: int | str | None = None,
                     pattern_hex: str = VM_DEFAULT_PATTERN,
                     capture_regs: int = 32,
                     wait: float = 3.0) -> dict:
    """在派发点抓一次 VM 寄存器堆快照（不判断 idx）。

    用途：不确定 code_base 时，先用它把「当前 VM pc」打出来，
    再对照代码区基址反推。

    返回：{ok, vm_pc, ctx, regs{r0..r31}, stack_hex}
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    disp = None
    if dispatch_offset is not None:
        try:
            disp = int(dispatch_offset, 16) if isinstance(dispatch_offset, str) \
                else int(dispatch_offset)
        except (TypeError, ValueError):
            return {"ok": False, "code": "BAD_DISPATCH_OFFSET",
                    "error": f"无法解析：{dispatch_offset!r}"}
    else:
        scan = find_dispatch_points(so_name, pattern_hex=pattern_hex, limit=1)
        if not scan.get("ok") or not scan.get("points"):
            return {"ok": False, "code": "NO_DISPATCH_POINT", "scan": scan}
        disp = scan["points"][0]["offset"]

    js = _JS_VM_SNAPSHOT
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__CAPTURE_REGS__", str(int(capture_regs))),
        ("__IP_OFFSET__", str(VM_DEFAULTS["ip_offset"])),
        ("__IP_REG__", _js_str(VM_DEFAULTS["ip_reg"])),
        ("__CTX_REG__", _js_str(VM_DEFAULTS["ctx_reg"])),
        ("__REG_BASE_REG__", _js_str(VM_DEFAULTS["reg_base_reg"])),
        ("__VM_REG_COUNT__", str(VM_DEFAULTS["vm_reg_count"])),
    ):
        js = js.replace(k, v)
    js = js.replace("SO_NAME", _js_str(so_name))

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(js)
        box: dict = {"snap": None, "error": None}

        def _on(m, d):
            p = m.get("payload")
            if not isinstance(p, dict):
                if m.get("type") == "error":
                    box["error"] = m.get("description")
                return
            if p.get("kind") == "snapshot":
                box["snap"] = p
            elif p.get("kind") == "error":
                box["error"] = p.get("error")

        script.on("message", _on)
        script.load()
        import time as _time

        t0 = _time.time()
        while _time.time() - t0 < max(0.3, float(wait)):
            if box["snap"] or box["error"]:
                break
            _time.sleep(0.03)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "SNAPSHOT_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)

    if box["error"]:
        return {"ok": False, "code": "SNAPSHOT_FAILED", "error": box["error"]}
    if not box["snap"]:
        return {"ok": False, "code": "NO_SAMPLE",
                "error": "窗口内没有走到派发点（可能 VM 当前没在跑）",
                "hint": "先触发目标功能，再调用本工具"}
    snap = box["snap"]
    snap["ok"] = True
    snap["note"] = ("vm_pc 是「下一条要执行的 VM 指令」的 pc；"
                    "code_base 未知时可用它反推")
    return snap


_JS_VM_SNAPSHOT = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    var CAPTURE_REGS = __CAPTURE_REGS__;
    var IP_OFFSET = __IP_OFFSET__;
    var IP_REG = __IP_REG__;
    var CTX_REG = __CTX_REG__;
    var REG_BASE_REG = __REG_BASE_REG__;
    var VM_REG_COUNT = __VM_REG_COUNT__;

    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', error: '模块未加载：' + SO_NAME});
        return;
    }
    var addr = mod.base.add(DISPATCH_OFFSET);
    var done = false;

    var listener = Interceptor.attach(addr, {
        onEnter: function () {
            if (done) { return; }
            done = true;
            var c = this.context;
            var rec = {kind: 'snapshot', dispatch_addr: addr.toString(),
                       native_pc: c.pc.toString()};
            try {
                var ctxp = c[CTX_REG];
                rec.ctx = ctxp === null ? null : ctxp.toString();
                rec.vm_pc = ctxp.add(IP_OFFSET).readPointer().toString();
            } catch (e) { rec.err_ctx = String(e); }
            try {
                var rb = c[REG_BASE_REG];
                rec.reg_base = rb === null ? null : rb.toString();
                var regs = {};
                var n = Math.min(CAPTURE_REGS, VM_REG_COUNT);
                for (var i = 0; i < n; i++) {
                    regs['r' + i] = rb.add(i * 8).readPointer().toString();
                }
                rec.regs = regs;
            } catch (e) { rec.err_regs = String(e); }
            try {
                rec.stack_hex = Array.from(new Uint8Array(c.sp.readByteArray(128)))
                    .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                    .join('');
            } catch (e) {}
            send(rec);
            try { listener.detach(); } catch (e) {}
        }
    });
})();
"""
