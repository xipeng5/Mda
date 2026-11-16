"""探测 2：timeline 各数据源的时间戳精度上限（真机实测）。

要回答三个数（报告里必须给真值，不能猜）：

  ① **断点命中（bp）时间戳的误差**：
     现在的 hits[].ts 是 **Python 侧收到 frida 消息那一刻** 的墙钟，
     真实命中时刻在设备侧。两者之差 = 设备→主机单向 IPC 延迟。
     单向没法直接量（两个时钟域），用 **往返 RTT/2** 作为上界估计：
     Python 发 ping → JS 立刻回 → Python 收到，全程都在 Python 的
     monotonic 域里，不需要跨域换算。

  ② **mem_write（perfwatch）对齐误差**：
     helper 的 ts_ms 是相对 daemon 启动的设备单调时钟；要落到墙钟轴
     必须知道 daemon 启动的墙钟时刻，而它是用 "读状态文件的墙钟 - age_ms"
     反推的。误差 = adb 读文件延迟 + 状态文件刷新周期（helper 每约 1s 写一次）。

  ③ 设备单调时钟的分辨率（manual_timeline_clock 已测：约 6µs）。

跑法：.venv/bin/python tests/manual_timeline_precision.py [serial]
"""
import json
import statistics
import subprocess
import sys
import time

sys.path.insert(0, ".")

import frida  # noqa: E402

SERIAL = sys.argv[1] if len(sys.argv) > 1 else "3e2ff172"

# JS：收到 ping 立刻回 pong，并顺带回一个"断点命中同款大小"的载荷，
# 用来量"大载荷"与"小载荷"的往返差异（命中消息带 36 寄存器 + 栈快照）。
JS = r"""
var clock_gettime = Module.findGlobalExportByName("clock_gettime");
var tsp = Memory.alloc(16);
var fn = (clock_gettime === null) ? null
    : new NativeFunction(clock_gettime, 'int', ['int', 'pointer']);
function monoNs() {
    if (fn === null) { return 0; }
    fn(1, tsp);
    return tsp.readS64() * 1000000000 + tsp.add(8).readS64();
}

function bigPayload() {
    // 模拟一次断点命中的载荷规模：36 个寄存器 + 24 帧 + 512 字节栈
    var ctx = {};
    for (var i = 0; i <= 30; i++) { ctx['x' + i] = '0x7f' + ('0'.repeat(10)) + i; }
    ctx.sp = '0x7ffd00001000'; ctx.pc = '0x7a0005201c';
    ctx.lr = '0x7a00052040'; ctx.fp = '0x7ffd00001100'; ctx.nzcv = '0x0';
    var bt = [];
    for (var j = 0; j < 24; j++) { bt.push('0x7a00' + ('0'.repeat(8)) + j); }
    var stack = ('ab'.repeat(256));
    return {ctx: ctx, bt: bt, stack: stack};
}

recv('ping', function (m) {
    var kind = m.payload.kind;
    var t = monoNs();
    if (kind === 'big') {
        var p = bigPayload();
        p.kind = 'pong'; p.seq = m.payload.seq; p.mono_ns = t;
        send(p);
    } else {
        send({kind: 'pong', seq: m.payload.seq, mono_ns: t});
    }
});
send({kind: 'ready', mono_ns: monoNs()});
"""


def pick_pid() -> int:
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


def rtt_probe(script, box, kind: str, rounds: int = 120) -> dict:
    """Python monotonic 域内量往返：发 ping → 等 pong → 记录差值。"""
    samples = []
    for i in range(rounds):
        got = {"hit": None}

        def on_msg(msg, data, _got=got):
            p = msg.get("payload") or {}
            if p.get("kind") == "pong":
                _got["hit"] = p

        script.on("message", on_msg)
        t0 = time.monotonic()
        script.post({"type": "ping", "kind": kind, "seq": i})
        deadline = time.monotonic() + 2.0
        while got["hit"] is None and time.monotonic() < deadline:
            time.sleep(0.0002)
        t1 = time.monotonic()
        if got["hit"] is None:
            continue
        samples.append((t1 - t0) * 1000.0)
        time.sleep(0.01)
    if not samples:
        return {"ok": False, "rounds": 0}
    return {
        "ok": True, "kind": kind, "rounds": len(samples),
        "rtt_min_ms": round(min(samples), 3),
        "rtt_median_ms": round(statistics.median(samples), 3),
        "rtt_p90_ms": round(sorted(samples)[int(len(samples) * 0.9)], 3),
        "rtt_max_ms": round(max(samples), 3),
        "one_way_est_median_ms": round(statistics.median(samples) / 2.0, 3),
    }


def adb_latency(rounds: int = 8) -> dict:
    """adb shell cat 的往返延迟（mem_write 对齐误差的一部分）。"""
    samples = []
    for _ in range(rounds):
        t0 = time.monotonic()
        subprocess.run(["adb", "-s", SERIAL, "shell", "true"],
                       capture_output=True, text=True)
        samples.append((time.monotonic() - t0) * 1000.0)
    return {"rounds": len(samples),
            "min_ms": round(min(samples), 1),
            "median_ms": round(statistics.median(samples), 1),
            "max_ms": round(max(samples), 1)}


def state_cadence() -> dict:
    """perfwatch 状态文件的刷新间隔（helper 每约 1s 写一次）。

    不用起观察点也能量：读两次 /proc/uptime 无关；这里直接看设备端
    /data/local/tmp/mda_pw_*.state 是否存在并观察 age_ms 的步进。
    没有 daemon 时如实返回 skipped。
    """
    r = subprocess.run(["adb", "-s", SERIAL, "shell",
                        "su -c 'ls /data/local/tmp/mda_pw_*.state 2>/dev/null'"],
                       capture_output=True, text=True)
    files = [x for x in (r.stdout or "").split() if x.endswith(".state")]
    if not files:
        return {"ok": False, "reason": "当前没有 perfwatch daemon 在跑，跳过"}
    path = files[0]
    ages = []
    for _ in range(6):
        rr = subprocess.run(["adb", "-s", SERIAL, "shell", f"su -c 'cat {path}'"],
                            capture_output=True, text=True)
        line = (rr.stdout or "").strip().splitlines()[-1] if rr.stdout else ""
        try:
            ages.append((time.monotonic(),
                         json.loads(line).get("age_ms")))
        except Exception:                                 # noqa: BLE001
            pass
        time.sleep(0.35)
    deltas = []
    for (t_a, age_a), (t_b, age_b) in zip(ages, ages[1:]):
        if age_a is None or age_b is None:
            continue
        deltas.append({"host_dt_ms": round((t_b - t_a) * 1000, 1),
                       "age_delta_ms": age_b - age_a})
    return {"ok": True, "file": path, "samples": deltas}


def main() -> int:
    pid = pick_pid()
    print(f"serial={SERIAL} pid={pid}")
    dev = frida.get_device(SERIAL, timeout=10)
    sess = dev.attach(pid)
    ready: dict = {}
    script = sess.create_script(JS)

    def on_ready(msg, data):
        p = msg.get("payload") or {}
        if p.get("kind") == "ready":
            ready["mono_ns"] = p.get("mono_ns")

    script.on("message", on_ready)
    script.load()
    t0 = time.time()
    while "mono_ns" not in ready and time.time() - t0 < 10:
        time.sleep(0.02)
    print("device mono_ns at script load =", ready.get("mono_ns"))

    out = {"pid": pid}
    out["rtt_small"] = rtt_probe(script, out, "small")
    out["rtt_big"] = rtt_probe(script, out, "big")
    print(json.dumps(out, indent=2, ensure_ascii=False))

    print("adb latency:", json.dumps(adb_latency(), ensure_ascii=False))
    print("state cadence:", json.dumps(state_cadence(), ensure_ascii=False))
    try:
        script.unload()
    except Exception:                                     # noqa: BLE001
        pass
    sess.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
