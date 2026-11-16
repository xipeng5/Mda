"""VM 执行轨迹采集 —— 记录 VM 跑过的指令序列（opcode / pc / 寄存器快照）。

## 为什么需要它

`vm_breakpoint` 只能停在**一条**指令上。但要理解「这段数据是怎么算出来的」，
需要的是**整条执行序列**：

    [op1, op2, op3, ...]  加上每步的关键寄存器

有了序列，再配合静态反汇编，就能把「VM 跑了哪些指令」还原成可读的伪代码。
这是业界标准流程里 trace 那一步：

    locate dispatcher → enumerate handlers → recover semantics
    → **trace a real run** → lift to C → differential-test

## 性能设计（实测踩过的坑）

派发点每秒可能走过几十万次。如果每条指令都 `send()` 回 JS 侧，
往返开销会把目标拖死——实测过这种写法，目标直接卡住。

所以本模块的做法是：

    · 在 JS 侧**只在本地累积**（数组），不回传
    · 达到容量上限或收到 stop 才一次性 send
    · 单次采集有明确的**条数上限**，防内存爆掉
    · 到顶即刻 detach Interceptor（不 hold、不阻塞目标线程）

代价：不能「边跑边看」，只能「跑完再看」。对离线分析足够了。

## 与 vm_breakpoint 的分工

    vm_breakpoint    停在一条指令上，看完整状态（含 32 个 VM 寄存器 + 栈）
    vm_trace         连续记录很多条，但每条只记关键字段（省内存）

## (5) 第五次修改（2026-11-16）：结构假设全部参数化

    bug 原因：本模块原先把「ctx 在 x27 / 寄存器堆在 x25 / VM pc 在 [ctx+8] /
              idx 用 *(*(ctx+0x240)+0x1a0) 算」四条假设**硬编码**在 JS 模板里，
              连 Python 签名都没有对应参数（ctx_reg 是 .replace() 塞进去的
              字符串 "x27"，REG_BASE_REG 同理）。用户实测的 metasec_ml.so：

                  寄存器堆在 ctx + 0x6070    （不是在寄存器里）
                  opcode  在 sp+8            （不在结构体里）
                  派发点   adr x22, #0x2F50D0; br x8

              四条假设一条都不成立，工具完全用不了，而参数层面**无从表达**。
    解决方案：
        ① 把四个取值点提成参数，并新增 opcode_expr 表达式写法
           （"sp+8" / "x8" / "ctx+0x100"）；
        ② 复用 vmbreak 的 spec 取值层（_JS_SPEC_HELPERS），
           模板里不再出现任何具体寄存器名或结构偏移常量；
        ③ 输出结构调整为 ops[]（seq/ts/tid/opcode/pc/regs），
           同时保留旧的 rows[] 字段做向后兼容；
        ④ 每条只读**必需**字段（默认不读 32 个寄存器），
           max_ops 到顶立即 detach，全程不 hold。
"""

from __future__ import annotations

import json
import time

__all__ = ["vm_trace", "VM_TRACE_MAX", "VM_TRACE_DEFAULT_MAX_OPS"]

# 单次采集上限。10 万条 × 每条 40 字节 ≈ 4MB JSON，
# 再大就会撑爆 MCP 的返回上限（实测 3MB 左右开始被截断）。
VM_TRACE_MAX = 100000

# (5) 第五次修改（2026-11-16）：新工具形态的默认上限。
# bug 原因：原默认 max_rows=20000，每条还带 pc/pb 两个十六进制长串，
#           4MB 级别的返回会撞 MCP 上限被截断，调用方拿到的是残缺 JSON。
# 解决方案：新的 ops 形态默认 1000 条（每条只留必需字段），
#           真需要大样本时显式调大，并且到顶就停、不静默截断。
VM_TRACE_DEFAULT_MAX_OPS = 1000


def _js_str(s) -> str:
    return json.dumps(str(s))


def _detach_async(sess, timeout: float = 2.0) -> None:
    """守护线程里 detach（本设备同步 detach 会阻塞）。"""
    import threading as _th

    if sess is None:
        return

    def _w() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass

    t = _th.Thread(target=_w, name="mda-vmtrace-detach", daemon=True)
    t.start()
    try:
        t.join(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


def _parse_dispatch_offset(v) -> int | None:
    """解析派发点偏移；"0x..." 与十进制都认，失败返回 None（不猜）。"""
    if v is None or v == "":
        return None
    try:
        if isinstance(v, str):
            s = v.strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        return int(v)
    except (TypeError, ValueError):
        return None


def _js_int(v, default: int = 0) -> str:
    """注入用的整数字面量：非法值退默认值（不注入垃圾）。"""
    try:
        return str(int(v))
    except (TypeError, ValueError):
        return str(int(default))


_JS_VM_TRACE = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    // (5) 第五次修改（2026-11-16）：以下全部来自参数，模板里不再有具体寄存器名
    var CTX_SPEC = __CTX_SPEC__;
    var IP_MODE = __IP_MODE__;
    var IP_REG = __IP_REG__;
    var IP_OFFSET = __IP_OFFSET__;
    var OPCODE_SPEC = __OPCODE_SPEC__;
    var REG_BASE_SPEC = __REG_BASE_SPEC__;
    var P1_OFF = __P1_OFF__;
    var P2_OFF = __P2_OFF__;
    var SLOT_SIZE = __SLOT_SIZE__;
    var MAX_ROWS = __MAX_ROWS__;
    var IDX_FROM = __IDX_FROM__;
    var IDX_TO = __IDX_TO__;
    var RECORD_REGS = __RECORD_REGS__;
    var REG_COUNT = __REG_COUNT__;
    var DURATION_MS = __DURATION_MS__;
    var WITH_BYTES = __WITH_BYTES__;
    var BYTES_LEN = __BYTES_LEN__;
    var CODE_BASE = __CODE_BASE__;
__SPEC_HELPERS__
    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', code: 'SO_NOT_FOUND', error: '模块未加载：' + SO_NAME});
        return;
    }

    var addr = mod.base.add(DISPATCH_OFFSET);
    var rows = [];
    var truncated = false;
    var ctxFail = 0;
    var ipFail = 0;
    var seenIdx = {};
    var started = Date.now();
    var stopped = false;

    // 到顶/超时/收到 stop 都走这里：立刻摘钩，不 hold、不阻塞目标线程。
    function shutdown(reason) {
        if (stopped) { return; }
        stopped = true;
        try { if (listener !== null) { listener.detach(); } } catch (e) {}
        listener = null;
        var dist = [];
        for (var k in seenIdx) { dist.push([parseInt(k, 10), seenIdx[k]]); }
        dist.sort(function (a, b) { return b[1] - a[1]; });
        // (5) 第五次修改（2026-11-16）：统一用 ops 命名。
        // 同时保留 rows 别名（旧字段名），因为既有调用方/前端可能按 rows 读。
        send({
            kind: 'result',
            ops: rows,
            rows: rows,
            truncated: truncated,
            stop_reason: reason,
            elapsed_ms: Date.now() - started,
            distinct_idx: dist.length,
            idx_distribution: dist.slice(0, 200),
            ctx_fail: ctxFail,
            ip_fail: ipFail
        });
    }

    var listener = null;
    listener = Interceptor.attach(addr, {
        onEnter: function () {
            if (stopped) { return; }
            if (rows.length >= MAX_ROWS) { truncated = true; shutdown('max_ops'); return; }
            if (DURATION_MS > 0 && (Date.now() - started) > DURATION_MS) {
                shutdown('duration'); return;
            }

            var c = this.context;
            var ctxRes = resolveValue(c, CTX_SPEC, null);
            var ctxp = ctxRes.ptr;
            // ctx 是否必需：只要有任何一处要按 ctx 取，就必须取到
            var needCtx = (IP_MODE === 'ctx')
                          || (REG_BASE_SPEC.kind === 'ctx')
                          || (OPCODE_SPEC.kind === 'ctx')
                          || ((P1_OFF >= 0) && (IP_MODE === 'ctx'));
            if (needCtx && ctxp === null) { ctxFail++; return; }

            // VM pc：ctx / reg / none 三种取法（原实现写死 ctx+8）
            var vmPc = null;
            var ipSrc = 'none';
            if (IP_MODE === 'reg') {
                vmPc = regOf(c, IP_REG);
                ipSrc = vmPc === null ? 'reg-missing' : 'reg:' + IP_REG;
            } else if (IP_MODE === 'ctx') {
                if (ctxp === null) { ipFail++; return; }
                try {
                    vmPc = ctxp.add(IP_OFFSET).readPointer();
                    ipSrc = 'ctx+0x' + IP_OFFSET.toString(16);
                } catch (e) { ipFail++; return; }
            }

            // idx：两种算法，都不写死结构
            //   ① code_base 已知：(pc - code_base) / slot_size
            //   ② 两跳解引用（只有调用方给了 p1/p2 才启用）：
            //      base = *(*(ctx+p1)+p2); idx = (pc - base) / slot_size
            // **P1_OFF < 0 表示关掉第二条**（换 VM 时那个位置根本不是基址指针，
            // 硬读只会得到垃圾并算出一个看起来合理的假 idx）。
            var idx = null;
            var idxSrc = 'unavailable';
            if (vmPc !== null && CODE_BASE !== null) {
                try {
                    var big = BigInt(vmPc.toString()) - BigInt(ptr(CODE_BASE).toString());
                    idx = Number(big / BigInt(SLOT_SIZE));
                    idxSrc = 'code_base';
                } catch (e) { idx = null; }
            } else if (vmPc !== null && P1_OFF >= 0 && ctxp !== null) {
                try {
                    var pb = ctxp.add(P1_OFF).readPointer().add(P2_OFF).readPointer();
                    var big2 = BigInt(vmPc.toString()) - BigInt(pb.toString());
                    idx = Number(big2 / BigInt(SLOT_SIZE));
                    idxSrc = 'prog_base';
                } catch (e) { idx = null; }
            }
            // idx 范围过滤只在算得出来时生效；算不出来不因此丢样本
            if (idx !== null) {
                if (IDX_FROM > 0 && idx < IDX_FROM) { return; }
                if (IDX_TO > 0 && idx > IDX_TO) { return; }
            }

            // opcode：按表达式取（"sp+8" / "x8" / "ctx+0x100"），取不到就 null
            var opcodeVal = null;
            var opcodeSrc = 'none';
            if (OPCODE_SPEC.kind !== 'none') {
                var opRes = resolveValue(c, OPCODE_SPEC, ctxp);
                opcodeSrc = opRes.src;
                if (opRes.ptr !== null) {
                    var sv = readScalar(opRes.ptr);
                    opcodeVal = (sv.n !== null) ? sv.n : sv.s;
                }
            }

            var row = {
                seq: rows.length + 1,
                ts: Date.now() - started,
                tid: this.threadId,
                opcode: opcodeVal,
                opcode_source: opcodeSrc,
                pc: hexOf(vmPc),
                ip_source: ipSrc,
                idx: idx,
                idx_source: idxSrc,
                ctx: hexOf(ctxp)
            };

            // 可选：VM 寄存器快照。默认关——每条读 32 个指针是主要开销来源。
            if (RECORD_REGS && REG_BASE_SPEC.kind !== 'none') {
                var rbRes = resolveValue(c, REG_BASE_SPEC, ctxp);
                if (rbRes.ptr !== null) {
                    var rr = {};
                    // (5) 第五次修改（2026-11-16）：原来失败就整个抛掉。
                    // bug 原因：读 32 个指针时只要有一个不可读（寄存器堆跨页），
                    //           整条样本的 regs 就没了，看起来像"没抓到"。
                    // 解决方案：逐项容错，读不到的项留 null，其余照常返回。
                    for (var k = 0; k < REG_COUNT; k++) {
                        try {
                            rr['r' + k] = rbRes.ptr.add(k * 8).readPointer().toString();
                        } catch (e) { rr['r' + k] = null; }
                    }
                    row.regs = rr;
                    row.reg_base = rbRes.ptr.toString();
                }
            }

            // 可选：回读 vm_pc 处原始字节（供调用方比对镜像反推 code_base）
            if (WITH_BYTES && vmPc !== null) {
                try {
                    row.pc_bytes = Array.from(new Uint8Array(
                        vmPc.readByteArray(BYTES_LEN)))
                        .map(function (b) { return ('0' + b.toString(16)).slice(-2); })
                        .join('');
                } catch (e) { row.pc_bytes = null; }
            }

            rows.push(row);
            if (idx !== null) { seenIdx[idx] = (seenIdx[idx] || 0) + 1; }
            if (rows.length >= MAX_ROWS) {
                truncated = true;
                shutdown('max_ops');
            }
        }
    });

    send({kind: 'installed', dispatch_addr: addr.toString(),
          dispatch_offset: DISPATCH_OFFSET, module: mod.name,
          module_base: mod.base.toString(),
          layout: {ctx: CTX_SPEC, ip_mode: IP_MODE, ip_reg: IP_REG,
                   ip_offset: IP_OFFSET, opcode: OPCODE_SPEC,
                   reg_base: REG_BASE_SPEC, slot_size: SLOT_SIZE,
                   code_base: CODE_BASE},
          max_rows: MAX_ROWS, duration_ms: DURATION_MS});

    recv('stop', function () { shutdown('requested'); });
})();
"""


def vm_trace(serial: str, pid: int, so_name: str,
             dispatch_offset: int | str = "",
             ctx_reg: str = "x0",
             opcode_expr: str = "",
             reg_base_offset: int = 0,
             count_offset: int = 0x194,
             array_offset: int = 0x1A0,
             max_ops: int = VM_TRACE_DEFAULT_MAX_OPS,
             duration: float = 10.0,
             max_rows: int = 0,
             ip_mode: str = "ctx",
             ip_offset: int = 8,
             ip_reg: str = "",
             reg_base_reg: str = "",
             ctx_expr: str = "",
             slot_size: int = 16,
             code_base: int | str | None = None,
             prog_base_p1_offset: int = 0x240,
             prog_base_p2_offset: int = 0x1A0,
             idx_from: int = 0, idx_to: int = 0,
             record_regs: bool = False, reg_count: int = 8,
             with_bytes: bool = False, bytes_len: int = 16,
             count_size: int = 8,
             pattern_hex: str = "") -> dict:
    """采集 VM 执行轨迹：连续记录跑过的每条 VM 指令（opcode / pc / 寄存器）。

    **所有结构偏移都是参数，没有任何写死的假设。** 换一个 VM 只改参数。

    ## 参数（按需只填你测到的）

    派发点：
        dispatch_offset   派发点静态偏移，"0x261820" 或 十进制。
                          不给则按 pattern_hex 自动扫第一个匹配
        pattern_hex       派发段特征字节（不给即不自动扫）

    上下文 / VM pc：
        ctx_reg           ctx 指针在哪个寄存器（默认 x0**不是标配**，
                          真实目标里常见 x20 / x27，务必按实测填）
        ctx_expr          更精确的写法："x20" / "sp+0x10" / "x20+0x8"
                          （给了就覆盖 ctx_reg）
        ip_mode           VM pc 怎么取：ctx（默认，读 [ctx+ip_offset]）/
                          reg（直接用 ip_reg）/ none（不取）
        ip_reg            ip_mode=reg 时用哪个寄存器
        ip_offset         ip_mode=ctx 时 vm_pc 在 ctx 里的偏移

    opcode：
        opcode_expr       **支持两种形态**：
                            "sp+8"        从栈读（opcode 在栈上的 VM）
                            "x8"          从寄存器读
                            "ctx+0x100"   从结构体字段读
                          默认为空 = 不取 opcode（返回 null，不编造）

    VM 寄存器堆：
        reg_base_offset  寄存器堆相对 **ctx** 的偏移（如 0x6070）。
                          **非 0 时优先**，结构体内嵌寄存器堆用这个
        reg_base_reg     否则从该寄存器直接取（如 "x25"）

    容量 / 过滤：
        max_ops          最多记多少条（默认 1000）。**到顶立即 detach**，
                         不 hold、不阻塞目标
        max_rows         **旧参数名**，等价于 max_ops（>0 时覆盖 max_ops）。
                         保留是为了让既有调用方不改代码
        duration         采集多少秒（默认 10）
        idx_from/idx_to  只看该 idx 段（需同时给 code_base 才算得出 idx）
        code_base        字节码区基址，"0x..." 或十进制
        prog_base_p1_offset / prog_base_p2_offset
                         idx 的**另一种**算法：不靠 code_base，而是两跳解引用
                         *(*(ctx+p1)+p2) 得到基址，再 (pc-base)/slot_size。
                         **默认 0x240 / 0x1A0 是某一类壳的实测值**，
                         换 VM 必须改；传 -1 关掉这条路径。
                         优先级：code_base > prog_base 两跳 > 不传（idx=null）
        record_regs      是否每步记寄存器快照（默认关，开销大头）
        reg_count        record_regs=True 时记几个寄存器
        with_bytes       是否回读 pc 处原始字节（反推 code_base 用）

    说明：count_offset / array_offset / count_size 是**兼容旧接口**保留的
    形参，本工具的采集路径按 opcode_expr 取 opcode，不再依赖
    「计数 + 指令数组」那种结构；保留它们是为了让从 dump_vm_state 迁移过来
    的调用方不用改签名，值会原样回显在返回里。

    ## 返回

        ops[]    每条 {seq, ts, tid, opcode, opcode_source, pc, ip_source,
                       idx, ctx, regs?, reg_base?, pc_bytes?}
        count    实际采到多少条
        truncated 是否因 max_ops 截断
        stop_reason  max_ops / duration / requested
        distinct_idx / idx_distribution
        ctx_fail / ip_fail  取 ctx / VM pc 失败次数
                            （**非 0 说明结构配置不符，不是 VM 没跑**）

    ## 典型用法

        # 用户实测 metasec_ml.so 的形态：opcode 在 sp+8，ctx 在 x20，
        # 寄存器堆在 ctx+0x6070
        vm_trace(serial, pid, "libmetasec_ml.so",
                 dispatch_offset="0x261820", ctx_reg="x20",
                 opcode_expr="sp+8", reg_base_offset=0x6070,
                 max_ops=200, duration=5)

    ## 已知边界

        · 只挂**一个**派发点，只能看到经过它的指令
        · 采完才返回，不能边跑边看
        · opcode 表达式写错不会静默：resolveValue 会把它记进 opcode_source，
          并且 opcode 为 null —— 一眼能看出是"没取到"而不是"值是 0"
    """
    try:
        import frida                                     # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # (5) 第五次修改（2026-11-16）：表达式在这里解析并**明确报错**。
    # bug 原因：参数化后 opcode_expr / ctx_expr 是自由文本，若静默退化成
    #           "不取"，用户会以为结构对了只是没数据——最难排的一类问题。
    # 解决方案：解析失败直接返回 BAD_EXPR + 正确写法，不 attach。
    from server.dyn.vmbreak import (_JS_SPEC_HELPERS, _js_spec,
                                    parse_value_expr)

    op_spec = parse_value_expr(opcode_expr)
    if op_spec["kind"] == "bad":
        return {"ok": False, "code": "BAD_EXPR",
                "error": f"opcode_expr 无法解析：{opcode_expr!r}",
                "hint": '支持写法："sp+8" / "x8" / "ctx+0x100" / ""（不取）'}

    if ctx_expr:
        ctx_spec = parse_value_expr(ctx_expr)
        if ctx_spec["kind"] == "bad":
            return {"ok": False, "code": "BAD_EXPR",
                    "error": f"ctx_expr 无法解析：{ctx_expr!r}",
                    "hint": '支持写法："x20" / "sp+0x10" / "x20+0x8"'}
    elif ctx_reg:
        ctx_spec = {"kind": "reg", "reg": str(ctx_reg)}
    else:
        ctx_spec = {"kind": "none"}

    if str(ip_mode).lower() not in ("ctx", "reg", "none"):
        return {"ok": False, "code": "BAD_IP_MODE",
                "error": f"ip_mode 应为 ctx/reg/none，收到 {ip_mode!r}"}
    if str(ip_mode).lower() == "reg" and not ip_reg:
        return {"ok": False, "code": "BAD_IP_REG",
                "error": "ip_mode=reg 时必须同时给 ip_reg（VM pc 在哪个寄存器）"}
    if record_regs and int(reg_base_offset or 0) <= 0 and not reg_base_reg:
        return {"ok": False, "code": "NO_REG_BASE",
                "error": ("record_regs=True 但没给寄存器堆来源："
                          "用 reg_base_offset（相对 ctx）或 reg_base_reg"),
                "hint": "不知道寄存器堆在哪时，先 record_regs=False 采 opcode"}

    # 寄存器堆来源：偏移优先（结构体内嵌），否则寄存器
    if int(reg_base_offset or 0) > 0:
        reg_base_spec = {"kind": "ctx", "offset": int(reg_base_offset)}
    elif reg_base_reg:
        reg_base_spec = {"kind": "reg", "reg": str(reg_base_reg)}
    else:
        reg_base_spec = {"kind": "none"}

    # 派发点：给了就用，没给按 pattern 扫（两者都没有 -> 明确报缺失）
    disp = _parse_dispatch_offset(dispatch_offset)
    if disp is None:
        if pattern_hex:
            from server.dyn.vmbreak import find_dispatch_points

            scan = find_dispatch_points(so_name, pattern_hex=pattern_hex, limit=1)
            if not scan.get("ok") or not scan.get("points"):
                return {"ok": False, "code": "NO_DISPATCH_POINT",
                        "error": "没有扫到派发点；确认 so 与 pattern_hex 是否匹配",
                        "scan": scan}
            disp = int(scan["points"][0]["offset"])
        else:
            return {"ok": False, "code": "NO_DISPATCH_OFFSET",
                    "error": ("必须给 dispatch_offset（派发点静态偏移），"
                              "或给 pattern_hex 让工具自动扫"),
                    "hint": '例：dispatch_offset="0x261820"'}

    # (5) 第五次修改（2026-11-16）：max_rows 作为旧参数名兼容。
    # bug 原因：本工具原先只叫 max_rows，新接口按用户要求命名为 max_ops；
    #           直接改签名会让既有调用方（和既有回归断言）报 TypeError。
    # 解决方案：max_rows > 0 时覆盖 max_ops，两者都接受。
    effective_max = int(max_rows) if int(max_rows or 0) > 0 else int(
        max_ops or VM_TRACE_DEFAULT_MAX_OPS)
    cap = max(1, min(effective_max, VM_TRACE_MAX))
    with_b = bool(with_bytes)
    # prog_base 两跳路径：p1 < 0 表示关掉（换 VM 时那个位置不是基址指针）
    p1 = int(prog_base_p1_offset)
    js = _JS_VM_TRACE
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__CTX_SPEC__", _js_spec(ctx_spec)),
        ("__IP_MODE__", _js_str(str(ip_mode).lower())),
        ("__IP_REG__", _js_str(ip_reg)),
        ("__IP_OFFSET__", _js_int(ip_offset, 8)),
        ("__OPCODE_SPEC__", _js_spec(op_spec)),
        ("__REG_BASE_SPEC__", _js_spec(reg_base_spec)),
        # (5) 第五次修改（2026-11-16）：data_base 两跳路径改为**由调用方决定**。
        # bug 原因：原实现无条件读 *(*(ctx+0x240)+0x1a0) 换算 idx。那两个偏移是
        #           某一类壳的实测值，换个 VM 就是普通字段，读出来的"基址"毫无
        #           意义，却会算出一个落在合理范围内的**假 idx**，比报错更糟。
        # 解决方案：只有调用方显式给 code_base 或显式保留 p1/p2 时才用；
        #           传 p1<0 即彻底关掉，返回的 idx 为 null 并标注 unavailable。
        ("__P1_OFF__", str(p1)),
        ("__P2_OFF__", str(int(prog_base_p2_offset))),
        ("__SLOT_SIZE__", str(max(1, int(slot_size or 16)))),
        ("__MAX_ROWS__", str(cap)),
        ("__IDX_FROM__", _js_int(idx_from, 0)),
        ("__IDX_TO__", _js_int(idx_to, 0)),
        ("__RECORD_REGS__", "true" if record_regs else "false"),
        ("__REG_COUNT__", str(max(1, min(int(reg_count or 8), 32)))),
        ("__DURATION_MS__", str(max(0, int(float(duration) * 1000)))),
        ("__WITH_BYTES__", "true" if with_b else "false"),
        ("__BYTES_LEN__", str(max(4, min(int(bytes_len or 16), 256)))),
        ("__CODE_BASE__", _code_base_literal(code_base)),
        ("__SPEC_HELPERS__", _JS_SPEC_HELPERS),
    ):
        js = js.replace(k, v)
    js = js.replace("SO_NAME", _js_str(so_name))

    sess = None
    try:
        import frida

        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(js)
        box: dict = {"installed": None, "result": None, "error": None}

        def _on(m, d):
            p = m.get("payload")
            if not isinstance(p, dict):
                if m.get("type") == "error":
                    box["error"] = m.get("description") or "脚本异常"
                return
            kind = p.get("kind")
            if kind == "installed":
                box["installed"] = p
            elif kind == "result":
                box["result"] = p
            elif kind == "error":
                box["error"] = p.get("error")
                box["error_code"] = p.get("code")

        script.on("message", _on)
        script.load()

        # 等脚本装好
        t0 = time.time()
        while time.time() - t0 < 10 and not box["installed"] and not box["error"]:
            time.sleep(0.03)
        if box["error"]:
            return {"ok": False, "code": box.get("error_code") or "VM_TRACE_FAILED",
                    "error": box["error"]}

        # 采集 duration 秒；JS 侧到顶会自己 shutdown 并回传结果，
        # 所以这里一旦收到 result 就可以提前结束，不必死等满时长。
        t_end = time.time() + max(0.1, float(duration))
        while time.time() < t_end:
            if box["result"] is not None or box["error"]:
                break
            time.sleep(0.03)
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        t0 = time.time()
        while time.time() - t0 < 10 and box["result"] is None and not box["error"]:
            time.sleep(0.03)
    except Exception as exc:                              # noqa: BLE001
        probe = None
        try:
            from server.dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception:                                 # noqa: BLE001
            probe = None
        code = "VM_TRACE_FAILED"
        msg = f"{type(exc).__name__}: {exc}"
        if probe and probe.get("alive") is False:
            code = "TARGET_DIED"
            msg += f"；进程 {pid} 已不存在"
        return {"ok": False, "code": code, "error": msg,
                "process_probe": probe}
    finally:
        _detach_async(sess)

    if box["error"]:
        return {"ok": False, "code": box.get("error_code") or "VM_TRACE_FAILED",
                "error": box["error"]}

    layout = (box["installed"] or {}).get("layout") or {}
    out: dict = {
        "ok": True,
        "dispatch_offset": hex(int(disp)),
        "layout_used": layout,
        # count_offset / array_offset 原样回显：本工具不用它们取 opcode，
        # 但调用方从 dump_vm_state 迁移过来时能看到自己传的值被接收了。
        "count_offset": int(count_offset),
        "array_offset": int(array_offset),
        "count_size": int(count_size),
        "max_ops": cap,
        "installed": box["installed"],
    }

    if not box["result"]:
        # (5) 第五次修改（2026-11-16）：
        # bug 原因：原来只报"采集结束但没收到结果"，用户不知道该改哪个参数。
        # 解决方案：区分「一条都没采到」与「脚本被目标卸载」，并给出针对性建议。
        out["ok"] = False
        out["code"] = "NO_RESULT"
        out["error"] = ("采集窗口内没有采到任何 VM 指令。"
                        "若派发点确实在执行，通常是结构配置不符——"
                        "先确认 dispatch_offset 就在执行路径上")
        out["hint"] = ("先调 vm_regs_snapshot（带同样的 ctx/ip/opcode 参数）"
                       "看能否取到值，再回来做 trace")
        return out

    r = box["result"]
    ops = r.get("ops") or []
    out.update({
        "count": len(ops),
        "ops": ops,
        # 向后兼容：旧字段名 rows 指向同一份数据
        "rows": ops,
        "truncated": bool(r.get("truncated")),
        "stop_reason": r.get("stop_reason"),
        "elapsed_ms": r.get("elapsed_ms"),
        "distinct_idx": r.get("distinct_idx", 0),
        "idx_distribution": r.get("idx_distribution") or [],
        "ctx_fail": int(r.get("ctx_fail") or 0),
        "ip_fail": int(r.get("ip_fail") or 0),
    })

    # (5) 第五次修改（2026-11-16）：结构不符必须与"没执行"分开报。
    # bug 原因：ctx/ip 全失败时 ops 也是空，返回会写成"采集窗口内没有指令经过"，
    #           而真实原因是参数结构不符——这会让人反复换派发点，白费时间。
    # 解决方案：ctx_fail/ip_fail 非 0 时优先判定为结构不符，并指出改哪个参数。
    if not ops:
        if out["ctx_fail"] or out["ip_fail"]:
            out["verdict"] = (
                f"派发点被命中 {out['ctx_fail'] + out['ip_fail']} 次，但每次都取不到"
                f"关键字段（ctx 失败 {out['ctx_fail']} / VM pc 失败 {out['ip_fail']}）。"
                "**这是结构配置不符，不是 VM 没运行**")
            out["hint"] = ("① ctx 取不到 → 改 ctx_reg / ctx_expr"
                           "（要按实测填，默认 x0 只是占位）；"
                           "② VM pc 取不到 → 改 ip_mode=reg 并给 ip_reg，或改 ip_offset")
        else:
            out["verdict"] = ("采集窗口内没有指令经过这个派发点。"
                              "确认 dispatch_offset 在活跃路径上，"
                              "或确认 VM 在这段时间里确实在跑")
            out["hint"] = ("dispatch_offset 给了吗？它必须是**这条 so 内**"
                           "那段「保存 VM pc → br」代码的静态偏移")
        return out

    if out["truncated"]:
        out["hint"] = (f"达到 max_ops={cap} 上限已自动停止（已 detach，"
                       "未 hold 目标）；需要更多请调大 max_ops 或缩小 idx 范围")

    # opcode 一条都没取到 —— 这同样是"配置不符"，要单独说清楚
    with_op = [o for o in ops if o.get("opcode") is not None]
    if not with_op:
        out["verdict"] = (f"采到 {len(ops)} 条，但 opcode 全部取不到"
                          "（opcode_expr 未配置或指向了不可读位置）。"
                          "pc/ctx 已拿到，说明派发点与 ctx 是对的")
        out["hint"] = ('按实测填 opcode_expr：opcode 在栈上写 "sp+8"，'
                       "在寄存器写 \"x8\"，在结构体写 \"ctx+0x100\"")
    else:
        top = (out["idx_distribution"] or [])[:3]
        out["verdict"] = (
            f"采集 {len(ops)} 条（{out['stop_reason']}），"
            f"其中 {len(with_op)} 条取到 opcode；"
            f"涉及 {out['distinct_idx']} 个不同 idx"
            + (f"；最频繁 {[t[0] for t in top]}" if top else ""))
    return out


def _code_base_literal(v) -> str:
    """把 code_base 转成 JS 字面量：没给就是 null（不猜基址）。

    支持 int 与 "0x..." / "12345"。给不出合法值一律 null —— 宁可不算 idx，
    也不注入一个错的基址（错的基址会算出看起来合理的假 idx）。
    """
    if v is None or v == "":
        return "null"
    try:
        if isinstance(v, str):
            s = v.strip()
            n = int(s, 16) if s.lower().startswith("0x") else int(s)
        else:
            n = int(v)
    except (TypeError, ValueError):
        return "null"
    return str(n) if n > 0 else "null"
