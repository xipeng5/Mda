"""VM 执行轨迹采集 —— 记录 VM 跑过的指令序列（idx + 寄存器快照）。

## 为什么需要它

`vm_breakpoint` 只能停在**一条**指令上。但要理解「这段数据是怎么算出来的」，
需要的是**整条执行序列**：

    [idx1, idx2, idx3, ...]  加上每步的关键寄存器

有了序列，再配合静态反汇编（vm_disasm 一类），就能把「VM 跑了哪些指令」
还原成可读的伪代码。这是业界标准流程里 trace 那一步：

    locate dispatcher → enumerate handlers → recover semantics
    → **trace a real run** → lift to C → differential-test

## 性能设计（实测踩过的坑）

派发点每秒可能走过几十万次。如果每条指令都 `send()` 回 JS 侧，
往返开销会把目标拖死——实测过这种写法，目标直接卡住。

所以本模块的做法是：

    · 在 JS 侧**只在本地累积**（数组），不回传
    · 达到容量上限或收到 stop 才一次性 send
    · 单次采集有明确的**条数上限**，防内存爆掉

代价：不能「边跑边看」，只能「跑完再看」。对离线分析足够了。

## 与 vm_breakpoint 的分工

    vm_breakpoint    停在一条指令上，看完整状态（含 32 个 VM 寄存器 + 栈）
    vm_trace         连续记录很多条，但每条只记关键字段（省内存）
"""

from __future__ import annotations

import json
import time

__all__ = ["vm_trace", "VM_TRACE_MAX"]

# 单次采集上限。10 万条 × 每条 40 字节 ≈ 4MB JSON，
# 再大就会撑爆 MCP 的返回上限（实测 3MB 左右开始被截断）。
VM_TRACE_MAX = 100000


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


_JS_VM_TRACE = r"""
(function () {
    var DISPATCH_OFFSET = __DISPATCH_OFFSET__;
    var CTX_REG = __CTX_REG__;
    var IP_OFFSET = __IP_OFFSET__;
    var P1_OFF = __P1_OFF__;
    var P2_OFF = __P2_OFF__;
    var SLOT_SIZE = __SLOT_SIZE__;
    var MAX_ROWS = __MAX_ROWS__;
    var IDX_FROM = __IDX_FROM__;
    var IDX_TO = __IDX_TO__;
    var RECORD_REGS = __RECORD_REGS__;
    var REG_COUNT = __REG_COUNT__;
    var DURATION_MS = __DURATION_MS__;

    var mod = Process.findModuleByName(SO_NAME);
    if (mod === null) {
        send({kind: 'error', code: 'SO_NOT_FOUND', error: '模块未加载：' + SO_NAME});
        return;
    }

    var addr = mod.base.add(DISPATCH_OFFSET);
    var rows = [];
    var truncated = false;
    var idxSeen = {};
    var started = Date.now();

    var listener = Interceptor.attach(addr, {
        onEnter: function () {
            if (rows.length >= MAX_ROWS) { truncated = true; return; }
            if (DURATION_MS > 0 && (Date.now() - started) > DURATION_MS) { return; }

            var c = this.context;
            var ctxp;
            try { ctxp = c[CTX_REG]; } catch (e) { return; }
            if (ctxp === null) { return; }

            var vmPc, progBase;
            try { vmPc = ctxp.add(IP_OFFSET).readPointer(); } catch (e) { return; }
            try {
                progBase = ctxp.add(P1_OFF).readPointer().add(P2_OFF).readPointer();
            } catch (e) { return; }

            var idx = vmPc.sub(progBase).toInt32() / SLOT_SIZE;

            // 范围过滤：只在 [IDX_FROM, IDX_TO] 内记（<=0 表示不限）
            if (IDX_FROM > 0 && idx < IDX_FROM) { return; }
            if (IDX_TO > 0 && idx > IDX_TO) { return; }

            var row = {i: idx, pc: vmPc.toString(), pb: progBase.toString()};

            // 可选：记录 VM 寄存器快照。全记会显著增大体积，
            // 默认只记 r0-r7（多数运算用不到高位）。
            if (RECORD_REGS) {
                try {
                    var rb = c[REG_BASE_REG];
                    var rr = [];
                    for (var k = 0; k < REG_COUNT; k++) {
                        rr.push(rb.add(k * 8).readPointer().toString());
                    }
                    row.r = rr;
                } catch (e) {}
            }
            rows.push(row);
            idxSeen[idx] = (idxSeen[idx] || 0) + 1;
        }
    });

    send({kind: 'installed', dispatch_addr: addr.toString(),
          max_rows: MAX_ROWS, duration_ms: DURATION_MS});

    recv('stop', function () {
        try { listener.detach(); } catch (e) {}
        // 汇总：不同 idx 的分布（按出现次数降序）
        var dist = [];
        for (var k in idxSeen) { dist.push([parseInt(k, 10), idxSeen[k]]); }
        dist.sort(function (a, b) { return b[1] - a[1]; });
        send({
            kind: 'result',
            rows: rows,
            truncated: truncated,
            elapsed_ms: Date.now() - started,
            distinct_idx: dist.length,
            idx_distribution: dist.slice(0, 200)
        });
    });
})();
"""


def vm_trace(serial: str, pid: int, so_name: str,
             dispatch_offset: int | str = "0x76024",
             duration: float = 3.0, max_rows: int = 20000,
             idx_from: int = 0, idx_to: int = 0,
             record_regs: bool = False, reg_count: int = 8,
             slot_size: int = 16,
             prog_base_p1_offset: int = 0x240,
             prog_base_p2_offset: int = 0x1A0) -> dict:
    """采集 VM 执行轨迹：连续记录跑过的每条 VM 指令的 idx。

    ## 参数

        dispatch_offset  挂哪个派发点
        duration         采集多少秒
        max_rows         最多记多少条（默认 2 万，上限 10 万）
        idx_from/idx_to  只看这个范围的 idx（0 = 不限）——
                         **强烈建议用**，能把无关指令滤掉，容量留给目标区间
        record_regs      是否同时记 VM 寄存器快照（体积会大很多，默认否）
        reg_count        record_regs=True 时记几个寄存器（默认 8）

    ## 返回

        rows[]              [{i: idx, pc, pb}]（record_regs 时多一个 r[]）
        distinct_idx        出现了多少种不同的 idx
        idx_distribution[]  [[idx, 次数], ...] 按次数降序，最多 200 项
        truncated           是否因 max_rows 截断
        elapsed_ms          实际采集时长

    ## 典型用法：找出 record98 生成前后跑了哪些 idx

        vm_trace(pid=..., duration=2, idx_from=13000, idx_to=14000, max_rows=5000)
        → idx_distribution 直接告诉你这段区间里哪些指令在跑、
          哪条跑得最多

    ## 已知边界

        · 只挂**一个**派发点，只能看到经过它的指令（805 个点里选一个）
        · 采完才返回，不能边跑边看
        · record_regs 打开后体积可能撑爆返回上限，建议配 idx 范围过滤
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    try:
        disp = int(dispatch_offset, 16) if isinstance(dispatch_offset, str) \
            else int(dispatch_offset)
    except (TypeError, ValueError):
        return {"ok": False, "code": "BAD_DISPATCH_OFFSET",
                "error": f"无法解析：{dispatch_offset!r}"}

    cap = max(1, min(int(max_rows), VM_TRACE_MAX))
    js = _JS_VM_TRACE
    for k, v in (
        ("__DISPATCH_OFFSET__", str(int(disp))),
        ("__CTX_REG__", _js_str("x27")),
        ("__IP_OFFSET__", "8"),
        ("__P1_OFF__", str(int(prog_base_p1_offset))),
        ("__P2_OFF__", str(int(prog_base_p2_offset))),
        ("__SLOT_SIZE__", str(int(slot_size))),
        ("__MAX_ROWS__", str(cap)),
        ("__IDX_FROM__", str(int(idx_from))),
        ("__IDX_TO__", str(int(idx_to))),
        ("__RECORD_REGS__", "true" if record_regs else "false"),
        ("__REG_COUNT__", str(max(1, min(int(reg_count), 32)))),
        ("__DURATION_MS__", str(max(0, int(float(duration) * 1000)))),
    ):
        js = js.replace(k, v)
    js = js.replace("REG_BASE_REG", _js_str("x25"))
    js = js.replace("SO_NAME", _js_str(so_name))

    sess = None
    try:
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

        # 采集 duration 秒
        time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        t0 = time.time()
        while time.time() - t0 < 10 and box["result"] is None:
            time.sleep(0.03)
    except Exception as exc:                              # noqa: BLE001
        probe = None
        try:
            from dyn.adb import Adb

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
    if not box["result"]:
        return {"ok": False, "code": "NO_RESULT",
                "error": "采集结束但没收到结果（脚本可能被目标卸载）"}
    r = box["result"]
    rows = r.get("rows") or []
    out = {
        "ok": True,
        "count": len(rows),
        "rows": rows,
        "distinct_idx": r.get("distinct_idx", 0),
        "idx_distribution": r.get("idx_distribution") or [],
        "truncated": bool(r.get("truncated")),
        "elapsed_ms": r.get("elapsed_ms"),
        "installed": box["installed"],
    }
    if not rows:
        out["verdict"] = ("采集窗口内没有指令经过这个派发点。"
                          "换个 dispatch_offset（805 个点可选），"
                          "或确认 VM 在这段时间里确实在跑")
    else:
        top = (out["idx_distribution"] or [])[:3]
        out["verdict"] = (f"采集 {len(rows)} 条，涉及 {out['distinct_idx']} 个不同 idx；"
                          f"最频繁的是 {[t[0] for t in top]}")
    if out["truncated"]:
        out["hint"] = (f"达到 max_rows={cap} 上限被截断；"
                       "建议用 idx_from/idx_to 缩小范围，或分多次采")
    return out
