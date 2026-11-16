"""探测：mda 时间线可用的时钟精度上限（真机实测）。

为什么需要这个探测：
    任务要求"用设备侧单调时钟对齐，不用 Python 的 Date.now()"，
    并且"如果拿不到高精度时钟，如实说明精度上限"。
    所以必须先量出三件事，才能决定 timeline 用哪个时钟源：

      ① frida JS 里 Date.now() 的实际分辨率（墙钟，ms 级？）
      ② frida JS 能否调 clock_gettime(CLOCK_MONOTONIC)（纳秒单调）
      ③ ② 与设备侧 helper（mda_perfwatch，也用 CLOCK_MONOTONIC）
         是否同一个时钟域——决定断点命中与内存写入能否直接对齐

跑法：
    .venv/bin/python tests/manual_timeline_clock.py [serial] [pid]

不传 pid 就自动挑一个非 mda 自身的小进程。只读，不注入目标业务代码。
"""
import json
import sys
import time

sys.path.insert(0, ".")

import frida  # noqa: E402

SERIAL = sys.argv[1] if len(sys.argv) > 1 else "3e2ff172"

JS = r"""
var out = {};

// ① Date.now() 的分辨率：连续取值，看最小非零步进
try {
    var minStep = null;
    var prev = Date.now();
    for (var i = 0; i < 200000; i++) {
        var now = Date.now();
        if (now > prev) {
            var d = now - prev;
            if (minStep === null || d < minStep) { minStep = d; }
            prev = now;
        }
    }
    out.date_now_min_step_ms = minStep;
} catch (e) {
    out.date_now_min_step_ms = "ERR:" + e;
}

// ② clock_gettime 取址：CLOCK_MONOTONIC(1) / CLOCK_MONOTONIC_RAW(4)
function resolveSym(name) {
    try { return Module.findGlobalExportByName(name); } catch (e) { return null; }
}

var cgt = resolveSym("clock_gettime");
out.clock_gettime_found = (cgt !== null);
if (cgt !== null) {
    // struct timespec { long tv_sec; long tv_nsec; } —— 16 字节足够
    var tsp = Memory.alloc(16);
    var f = new NativeFunction(cgt, 'int', ['int', 'pointer']);

    function readNs(clockid) {
        var rc = f(clockid, tsp);
        if (rc !== 0) { return null; }
        var sec = tsp.readS64();
        var nsec = tsp.add(8).readS64();
        return sec * 1000000000 + nsec;
    }
    out.monotonic_readable = (readNs(1) !== null);

    // 单调性 + 两次读取之间的最小步进（反映时钟真实粒度）
    var prev = readNs(1);
    var minStep = null;
    var steps = 0;
    for (var i = 0; i < 200000; i++) {
        var now = readNs(1);
        if (now > prev) {
            var d = now - prev;
            if (minStep === null || d < minStep) { minStep = d; }
            prev = now;
            steps++;
            if (steps > 300) { break; }
        }
    }
    out.monotonic_min_step_ns = minStep;
    // 采样三个值，供 Python 侧与 adb 侧 /proc/uptime 对照时钟域
    out.monotonic_samples_ns = [readNs(1), readNs(1), readNs(1)];
    // 同时给墙钟，供换算
    out.wall_clock_ns = readNs(0);   // CLOCK_REALTIME
}

// ③ 线程 id 与 tid 级时间：确认能拿到当前线程
try { out.tid = Process.getCurrentThreadId(); } catch (e) { out.tid = null; }

send(out);
"""


def pick_pid() -> int:
    """挑一个稳定的小进程：优先 system_server 之外的自带进程。"""
    import subprocess

    r = subprocess.run(["adb", "-s", SERIAL, "shell",
                        "ps -A -o PID,NAME"], capture_output=True, text=True)
    cands = {}
    for line in (r.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        cands[parts[1]] = int(parts[0])
    for name in ("com.android.systemui", "com.android.settings", "mediaserver",
                 "surfaceflinger"):
        if name in cands:
            return cands[name]
    raise SystemExit("没找到可注入的进程")


def uptime_ms() -> float:
    """adb 侧 /proc/uptime（同一 CLOCK_BOOTTIME 近亲，用于域对照）。"""
    import subprocess

    r = subprocess.run(["adb", "-s", SERIAL, "shell", "cat /proc/uptime"],
                       capture_output=True, text=True)
    try:
        return float((r.stdout or "").split()[0]) * 1000.0
    except Exception:                                     # noqa: BLE001
        return -1.0


def main() -> int:
    pid = pick_pid()
    print(f"serial={SERIAL} pid={pid}")
    dev = frida.get_device(SERIAL, timeout=10)
    sess = dev.attach(pid)
    got: list = []
    script = sess.create_script(JS)
    script.on("message", lambda m, d: got.append(m.get("payload")))
    script.load()
    t0 = time.time()
    while not got and time.time() - t0 < 20.0:
        time.sleep(0.05)
    print("payload =", json.dumps(got[0] if got else None, indent=2, ensure_ascii=False))

    # 用 adb 侧 uptime 做一次粗对照：monotonic 与 uptime 应同源（差 < 1s）
    ms = got[0].get("monotonic_samples_ns") if got else None
    if ms:
        mono_s = ms[-1] / 1e9
        up_s = uptime_ms() / 1000.0
        print(f"monotonic={mono_s:.3f}s  /proc/uptime={up_s:.3f}s  "
              f"diff={mono_s - up_s:+.3f}s")
    sess.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
