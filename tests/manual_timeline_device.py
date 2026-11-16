"""真机验证：timeline 的时间戳精度 + auto_resume 的真实放行 + 时间线去重。

为什么要有这个脚本（而不是只靠单元测试）：
    R102 用假 debugger 锁住了**行为契约**，但三个关键数只有真机能给：

      ① timeline 里相邻命中的 t_rel_ms 到底有多可信（IPC 抖动实测值）；
      ② auto_resume 到期是否**真的**让被 hold 的线程继续跑（假 debugger
         只能说"resume 被调用了"，说不出线程有没有被唤醒）；
      ③ 真实路径下命中会不会在时间线里重复出现（单元测试里我人工构造了
         breakpoint_hit 事件，真实路径是 _sync_hits 造出来的，得验一次）。

跑法：
    .venv/bin/python tests/manual_timeline_device.py [serial] [seconds]

安全边界：
    · 只对**自己 attach** 的目标下断点，结束后 detach 并撤掉断点；
    · 不碰任何 App 的业务函数——断点下在 libc 的 usleep/gettimeofday 这类
      高频只读符号上，命中即证明链路通，不影响业务逻辑；
    · 风控：只用 Interceptor（本机既有机制），不额外引入 uprobe/perf。
"""
import json
import sys
import time

sys.path.insert(0, ".")

SERIAL = sys.argv[1] if len(sys.argv) > 1 else "3e2ff172"
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0


def pick_pid() -> int:
    import subprocess

    r = subprocess.run(["adb", "-s", SERIAL, "shell", "ps -A -o PID,NAME"],
                       capture_output=True, text=True)
    cands = {}
    for line in (r.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            cands[parts[1]] = int(parts[0])
    for name in ("com.android.systemui", "com.android.settings", "mediaserver"):
        if name in cands:
            return cands[name]
    raise SystemExit("没找到可注入的进程")


def main() -> int:
    from server.dyn.rebase import Rebase
    from server.dyn.service import STATE_PAUSED, get_dyn

    pid = pick_pid()
    print(f"serial={SERIAL} pid={pid}", flush=True)

    svc = get_dyn()
    tgt = svc.attach(SERIAL, pid)
    print("attached", flush=True)

    # 挑一个高频、只读、必然被调用的导入符号作为观测点。
    # **不依赖任何 App 特征**：libc 的 gettimeofday/usleep 在任何进程里都常见；
    # 找不到就如实说，不假装验过。
    mod = None
    for cand in ("libc.so", "libc_apex.so"):
        mod = tgt.rb.find_module(cand)
        if mod is not None:
            break
    if mod is None:
        print("FAIL: 目标进程里找不到 libc，无法验证")
        return 1
    local = None
    for path in ("samples/device/libc.so",):
        try:
            from server.core.session import Session

            ses = Session()
            so = ses.add(path)
            if so.name:
                local = so
                break
        except Exception as exc:                          # noqa: BLE001
            print("本地 libc 加载失败:", exc)
    if local is None:
        print("FAIL: 本地没有 samples/device/libc.so")
        return 1

    # 选 usleep：每个进程基本都会调到，且它是叶子调用（不影响业务返回值）
    target_sym = None
    for name, sym in local.exports.items():
        if name in ("usleep", "gettimeofday", "nanosleep", "clock_gettime"):
            target_sym = sym
            break
    if target_sym is None:
        print("FAIL: 本地 libc 里没有可用符号")
        return 1
    addr = int(sym_addr := target_sym.addr)
    print(f"观测点 = {local.exports and [n for n, s in local.exports.items() if s.addr == addr][:1]}"
          f" @ {addr:#x}", flush=True)

    results: dict = {}

    # ---- 实验 1：hold + auto_resume，验证**真的**自动放行 ----
    # 用 300ms：够短以便一个窗口里多次命中，又够长以便观察到 armed 状态
    bp = svc.set_breakpoint(SERIAL, pid, mod.name, addr, hold=True,
                            auto_resume_after_ms=300)
    print("set_breakpoint ->", json.dumps(
        {k: bp.get(k) for k in ("id", "hold", "auto_resume_ms", "existing")},
        ensure_ascii=False), flush=True)

    t0 = time.time()
    paused_seen = 0
    while time.time() - t0 < SECONDS:
        st = svc.state()
        for t in st.get("targets") or []:
            if t.get("key") == f"{SERIAL}:{pid}" and t.get("state") == STATE_PAUSED:
                paused_seen += 1
        time.sleep(0.05)

    hits = svc.hits(SERIAL, pid)
    events = svc.poll_events(SERIAL, pid, timeout=0, limit=1000)
    types = [e.get("type") for e in events]
    results["hit_count"] = len(hits)
    results["paused_observations"] = paused_seen
    results["event_types"] = sorted(set(types))
    results["auto_resumed_count"] = types.count("auto_resumed")
    results["auto_armed_count"] = types.count("auto_resume_armed")
    results["final_state"] = svc.state()["targets"][0].get("state") \
        if svc.state().get("targets") else None

    # ---- 实验 2：timeline 并检查**不重复** + 精度 ----
    tl = svc.timeline(SERIAL, pid, duration=0)
    evs = tl.get("events") or []
    results["timeline_count"] = tl.get("count")
    results["timeline_samples"] = evs[:6]
    # 去重验证：同一 (kind, addr, tid, ts) 不应出现两次
    seen = set()
    dup = 0
    for e in evs:
        key = (e.get("kind"), e.get("addr"), e.get("tid"), round(e.get("ts") or 0, 6))
        if key in seen:
            dup += 1
        seen.add(key)
    results["duplicate_rows"] = dup
    results["precision"] = tl.get("precision")

    # 真实相邻命中的间隔分布（IPC 抖动的直接体现）
    bp_events = [e for e in evs if e.get("kind") == "bp"]
    deltas = []
    for a, b in zip(bp_events, bp_events[1:]):
        deltas.append(round(float(b["t_rel_ms"]) - float(a["t_rel_ms"]), 3))
    results["bp_delta_ms_sample"] = deltas[:12]

    # ---- 清理 ----
    try:
        svc.resume(SERIAL, pid)
    except Exception:                                     # noqa: BLE001
        pass
    try:
        svc.remove_breakpoint(bp["id"])
    except Exception:                                     # noqa: BLE001
        pass
    svc.detach(SERIAL, pid)

    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
