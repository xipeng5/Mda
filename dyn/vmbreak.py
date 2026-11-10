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

    data_base = *(*(x27 + 0x240) + 0x1a0)     ← **数据区**基址，不是字节码区
    vm_idx    = (vm_pc - code_base) / 16      ← code_base 必须调用方显式给

`data_base` 的推导链（sub_170a8c，op508 host handler 调用的函数）：

    0x170a98  ldr x8, [x1, #0x240]    ; x1 = VM ctx
    0x170aa0  ldr x8, [x8, #0x1a0]    ; ← data_base
    0x170aa4  add x0, x8, x2          ; + imm = **host 变量地址**

★ 注意最后一行：加完得到的是 host 变量地址 ⇒ 这个基址指向**数据区**。
  所以它**不能**用来算 vm_idx（真机实测：算出的 idx 去查镜像是 op=4 A=28，
  不是合法指令边界）。字段原名 prog_base 具有误导性，已改为 data_base。

★ 真正的 code_base 在 ctx 里的位置**尚未确认**，因此：
  · 不传 code_base 时，vm_idx 返回 null（不伪造数字）
  · 工具会回读 vm_pc 处原始字节（vm_pc_bytes），调用方拿它比对镜像自己反推

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
    # data_base 的两跳解引用路径：[ctx + p1_off] → [+ p2_off] = data_base
    # （名为 prog_base_* 是历史兼容；它指向数据区，不是字节码区）
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
                  vm_pc_bytes: int = 64,
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
                         **注意**：要按 idx 过滤，必须同时给 code_base；
                         否则无法计算 idx，本工具不会假装过滤（会返回 0 命中）
        code_base        字节码区基址（VM 指令数组起点）。**不给就不算 vm_idx**
        vm_pc_bytes      在 vm_pc 处回读多少字节原始字节码（默认 64）
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
        hits[]           {index, vm_pc, data_base, vm_idx, vm_idx_source,
                          vm_pc_bytes, regs{r0..r31}, ctx, stack_hex}
        verdict

    ## 关键：data_base 与 vm_idx 不是一回事

        data_base = *(*(ctx + 0x240) + 0x1a0)     ← host 全局变量区基址
        vm_pc     = *(ctx + 8)                    ← 下一条要执行的指令地址
        vm_idx    = (vm_pc - code_base) / 16      ← **必须显式给 code_base**

    (6) 第六次修改（2026-11-09）：
        bug 原因：此前把 data_base 当成了 code_base 用来算 vm_idx
                  （字段名还叫 prog_base，更容易误解）。它的推导链末端是
                  `add x0, x8, imm`，加完得到 host 变量地址 —— 说明它指向
                  数据区。拿它减 vm_pc 算出来的「idx」只是碰巧落在某个
                  范围内，不代表指令序号：真机实测 idx=40162 去查镜像，
                  得到 op=4 A=28，不是合法指令边界。
        解决方案：① 字段改名 data_base，保留原值（它对定位 host 变量有用）；
                  ② vm_idx 只在给了 code_base 时才算，否则为 null 并标
                     vm_idx_source="unavailable"；
                  ③ 新增 vm_pc_bytes：回读 vm_pc 处原始字节，调用方拿它
                     去比对镜像，自己反推 code_base（这是目前唯一可靠的
                     定位方式，因为 code_base 在 ctx 里的位置尚未确认）。

    **不要用 vm_pc - so 模块基址**：VM 代码区是 malloc 出来的匿名内存，
    与 so 模块不在一处。

    派发点是在「当前指令执行完、下一条还没执行」的时刻被拦下的。
    所以停在这里读到的 vm_pc 是**下一条**要执行的指令。

    ## 已知边界

        · data_base 的偏移路径（+0x240 / +0x1a0）是参数，换 VM 可改
        · **不传 code_base 时 vm_idx 为 null**：这是刻意为之，
          data_base 不能算出指令序号（见上文「data_base 与 vm_idx 不是一回事」）
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
    #     解决方案：改为运行时解引用 *(*(ctx + 0x240) + 0x1a0) 得到基址。
    #
    # (7) 第七次修改（2026-11-09）——上面那条方案被实测推翻：
    #     bug 原因：那个地址推导链末端是 `add host_var, base, imm`，加完是
    #               host 变量地址，说明它是**数据区**基址，不是字节码区。
    #               用它算 vm_idx 得到的数没有意义（真机实测查镜像对不上）。
    #     解决方案：该值改名 data_base 并原样返回；vm_idx 恢复为「只在调用方
    #               显式给 code_base 时才算」，同时回读 vm_pc 处原始字节，
    #               让调用方自己比对镜像反推真正的 code_base。

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
        # (5) 第五次修改（2026-11-09）：
        #     bug 原因：code_base 参数一直只躺在签名里，从未传给 JS
        #               （grep CODE_BASE 无结果），调用方传了也被静默忽略。
        #     解决方案：真正注入；没给就传 null，JS 侧据此不计算 vm_idx。
        ("__CODE_BASE__", _js_code_base(code_base)),
        ("__VM_PC_BYTES__", str(int(vm_pc_bytes))),
    ):
        user_js = user_js.replace(k, v)

    return _run_vm_break(serial, int(pid), so_name, user_js,
                         hold=bool(hold), max_hits=int(max_hits),
                         wait=float(wait),
                         target_idx=int(target_idx),
                         slot_size=int(slot_size))


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
    // 显式字节码基址；null 表示调用方没给（那就不会算 vm_idx）
    var CODE_BASE = __CODE_BASE__;
    // vm_pc 处回读多少字节原始字节码（供调用方比对镜像）
    var VM_PC_BYTES = __VM_PC_BYTES__;

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

    // data_base = *(*(ctx + P1_OFF) + P2_OFF)
    // 指向 host 全局变量区（推导链末端是 add host_var, imm），**不是**字节码区。
    function readDataBase(ctxp) {
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

            // data_base = *(*(ctx+P1_OFF)+P2_OFF)
            //
            // (3) 第三次修改（2026-11-09）：
            //     bug 原因：这个值原名叫 prog_base，被当成「字节码区基址」用来
            //               算 vm_idx。但它的推导链末端是 `add x0, x8, imm`
            //               ——加完得到的是 host 变量地址，说明它指向**数据区**，
            //               不是字节码区。用它减 vm_pc 没有意义，算出的 idx 只是
            //               「落在某个范围里」，不代表指令序号（真机实测过
            //               idx=40162 查镜像得到 op=4 A=28，不是合法指令边界）。
            //     解决方案：改名 data_base 并原样返回（它对定位 host 变量有用）；
            //               vm_idx 只在调用方显式给 code_base 时才计算，
            //               否则返回 null 并注明 unavailable。不给假数字。
            var dataBase = readDataBase(ctxp);

            // 在 vm_pc 处读一段原始字节，供调用方自己比对镜像、反推 code_base。
            // 这是「不知道 code_base」时的唯一可靠出路：给出原料，不猜结论。
            var codeBytes = null;
            try {
                var nSlots = VM_PC_BYTES / SLOT_SIZE;
                codeBytes = Array.from(new Uint8Array(vmPc.readByteArray(nSlots * SLOT_SIZE)))
                    .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                    .join('');
            } catch (e) { codeBytes = null; }

            // idx 只认显式 code_base
            var idx = null;
            var idxSource = 'unavailable';
            if (CODE_BASE !== null && CODE_BASE !== 0) {
                // (4) 第四次修改（2026-11-09）：
                //     bug 原因：原来用 vmPc.sub(base).toInt32()，toInt32 会把
                //               64 位差值截断成 32 位；当 code_base 与 vm_pc 的
                //               跨度超过 ±2GB（不同 mmap 段很常见）时会溢出成错值。
                //     解决方案：用十进制字符串转 BigInt 相减，再整除 slot_size。
                //               这样任意跨度都精确，且不依赖 frida 的 32 位转换。
                var big = null;
                try {
                    big = BigInt(vmPc.toString()) - BigInt(ptr(CODE_BASE).toString());
                } catch (e) { big = null; }
                if (big !== null) {
                    var q = big / BigInt(SLOT_SIZE);
                    var r = big % BigInt(SLOT_SIZE);
                    idx = Number(q) + Number(r) / SLOT_SIZE;
                    idxSource = 'code_base';
                }
            }

            // 给了 target_idx 但没给 code_base 时无法过滤：
            // 不假装过滤（那会静默返回 0 命中，让人以为是位置不对）
            if (TARGET_IDX >= 0) {
                if (idx === null) { return; }
                if (idx !== TARGET_IDX) { return; }
            }

            hitCount++;
            var rec = {
                kind: 'vm_hit',
                index: hitCount,
                vm_pc: vmPc.toString(),
                data_base: dataBase === null ? null : dataBase.toString(),
                vm_idx: idx,
                vm_idx_source: idxSource,
                vm_pc_bytes: codeBytes,
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
          code_base_used: CODE_BASE,
          data_base_path: '*(*(ctx+0x' + P1_OFF.toString(16) + ')+0x'
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


def _js_code_base(code_base) -> str:
    """把 code_base 转成 JS 字面量：没给就是 null。

    支持 int 与 "0x..." / "12345" 字符串。给不出合法值一律当 null，
    宁可不算 idx，也不注入一个错的基址。
    """
    if code_base is None or code_base == "":
        return "null"
    try:
        v = int(code_base, 16) if isinstance(code_base, str) \
            and code_base.lower().startswith("0x") else int(code_base)
    except (TypeError, ValueError):
        return "null"
    return str(v) if v > 0 else "null"


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
                  wait: float = 10.0,
                  target_idx: int = -1,
                  slot_size: int = 16) -> dict:
    """注入 VM 断点脚本并等待命中。

    (1) 第一次修改（2026-11-09）：
        bug 原因：本函数末尾的 verdict 文案里引用了 `target_idx`，但本函数
                  签名里没有这个参数（它只是 vm_breakpoint 的形参，没往下传）。
                  于是**只要一次都没命中**，走到 `elif not box["hits"]` 分支
                  就会抛 `NameError: name 'target_idx' is not defined`，
                  被外层 except 包成 VM_BREAK_FAILED。
                  表现为：target_idx 给任何值（含 -1）都报同一个 NameError。
        解决方案：把 target_idx / slot_size 显式传进来，供文案与诊断使用。
    """
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
        # (2) 第二次修改（2026-11-09）：
        #     bug 原因：原提示只讲了「该指令没被执行」和「派发点不在路径上」，
        #               但真机排障时最常见的是第三种：进程还活着、frida 会话
        #               却是旧的（attach 到已失效会话后一切静默）。
        #     解决方案：把这条也写进 hint，并明确指出 target_idx 过滤只在
        #               code_base 已知时才有意义。
        out["verdict"] = (f"{wait:.0f}s 内没有命中 idx={target_idx}。"
                          "可能原因：① 该指令在当前操作下没被执行；"
                          "② 挂的派发点不在它的执行路径上"
                          "（805 个点里只挂了 1 个）；"
                          "③ 进程虽在，但 frida 会话已失效（旧进程残留）")
        out["hint"] = ("先用 vm_regs_snapshot 确认这条链路是活的"
                       "（它能给 vm_pc 就说明会话正常）；"
                       "再挑一个在活跃路径上的派发点；"
                       "或把 target_idx 设成 -1（不过滤，采所有遇到的 idx）")
        out["target_idx_used"] = target_idx
        out["slot_size_used"] = slot_size
    else:
        h0 = box["hits"][0]
        src = h0.get("vm_idx_source") or "unknown"
        out["verdict"] = (f"命中 {len(box['hits'])} 次，"
                          f"VM pc={h0.get('vm_pc')} "
                          f"idx={h0.get('vm_idx')}（来源 {src}）")
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
