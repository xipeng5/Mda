"""硬件观察点（perf_event）—— 不依赖 frida 的另一条路。

## 为什么要有这个模块

frida 的 `trace_write` 用的是 Interceptor hook 常用 libc 内存函数
（memcpy/memset/strcpy…）。它的覆盖率有个硬上限：

- **编译器内联的 `str` / `stp` 抓不到**（现代编译器大量内联短拷贝）
- 目标必须真的走到那些函数才会产生事件

而「谁写了这块内存」在很多场景下是唯一能回答「这块数据怎么来的」的手段。
本模块换一条路：**perf_event 硬件观察点**。

## 为什么不用 frida 的 setHardwareWatchpoint

实测（frida 17.23.3）：
- API 在**线程对象**上（`thread.setHardwareWatchpoint`），不在 `Thread` 全局对象上
- 它**按线程生效**，而 frida 的 JS 跑在自己的注入线程里
- `Process.enumerateThreads()` **看不到 JS 自己的线程**
  → 于是对目标线程设的观察点，JS 里的写操作不会触发；对 JS 线程设又找不到对象

结论：frida 这条路在「观察目标线程自己的写」这个场景下不可用。

## perf_event 这条路的实测结论

真机验证（Android 12 / arm64 / 内核 4.19）：

    内核配置：CONFIG_PERF_EVENTS=y / CONFIG_HW_PERF_EVENTS=y
              CONFIG_HAVE_HW_BREAKPOINT=y / perf_event_paranoid=-1
    槽位：breakpoint 6 个，watchpoint 4 个（内核 dbg_info 直接给出）

抓到真实写入（32 字节缓冲，每 100ms 写一次）：

    {"ip":"0x79afd58de0","tid":14286,"ts_ms":73,
     "regs":{"x0":"0x0","x1":"0x1cc94f...","x2":"0x0","lr":"0x79afd58c78"}}

优势（相对 frida hook）：
- **不停线程**：硬件触发 + 异步采样，目标无感知
- **不可检测**：不像 frida 有明显注入特征
- **覆盖全部指令**：CPU 层面，含内联 str/stp
- **开销极低**：无插桩

## 三条必须知道的实测约束

① **地址必须脱 ARM64 TBI tag**
   Android 堆指针形如 `0xb400007d8780a000`，高 8 位是 tag。
   带 tag 传给 `bp_addr` 直接 `EINVAL`。本模块自动脱。

② **观察点是「按线程」绑定的**
   不指定 tid 时观察整个进程，但**实际触发只在该线程上**才有效。
   想抓某段代码的写，得给**真正执行写的那个线程**的 tid。
   这是本模块最容易踩的坑，工具会在 0 命中时提示。

③ **watchpoint 只有 4 个槽位**
   要观察第 5 个地址得先清掉一个。本模块按 slot 管理。

④ **部分进程的主线程返回 ENOSPC**
   实测某 App 主线程的调试资源被占（与 frida 无关，进程刚启动也如此），
   换非主线程正常。工具会把 ENOSPC 明确报告为 `NO_SLOT`。

## 设备端依赖

需要推送一个交叉编译的 ARM64 helper（`dyn/device/mda_perfwatch`）。
设备上没有 python，也没有编译器，所以必须走这一步。

编译：`./dyn/device/build.sh`（自动探测 NDK）
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time

__all__ = [
    "perf_watch",
    "perf_watch_probe",
    "perf_watch_daemon",
    "perf_watch_poll",
    "perf_watch_stop",
    "perf_watch_list",
    "ensure_helper",
    "PERF_WATCH_MAX_SLOTS",
    "PERF_WATCH_MAX_LEN",
]

# 内核硬件观察点上限（实测 dbg_info=0x804 → 4）
PERF_WATCH_MAX_SLOTS = 4
# 内核只接受这三种长度
PERF_WATCH_MAX_LEN = 8

_DEVICE_PATH = "/data/local/tmp/mda_perfwatch"
_HELPER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device")
_LOCAL_HELPER = os.path.join(_HELPER_DIR, "mda_perfwatch")


def _adb(serial: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """跑一条 adb 命令。统一在这里处理路径与超时。"""
    from dyn.adb import resolve_adb

    exe = resolve_adb()
    cmd = [exe, "-s", serial] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _shell_root(serial: str, command: str, timeout: int = 90) -> subprocess.CompletedProcess:
    """以 root 身份在设备上执行命令。

    (1) 第一次修改（2026-11-09）：perf_event 需要 CAP_PERFMON，
        普通 shell 身份会被拒，必须 su。
    """
    return _adb(serial, "shell", f"su -c '{command}'", timeout=timeout)


def _helper_built() -> bool:
    return os.path.isfile(_LOCAL_HELPER)


def ensure_helper(serial: str, force_push: bool = False) -> dict:
    """确保设备上有可用的 helper 二进制，返回状态。

    本地没有编译产物时给明确指引，而不是让上层拿到一个看不懂的失败。
    """
    out: dict = {"ok": False, "device_path": _DEVICE_PATH, "pushed": False}

    if not _helper_built():
        out["error"] = ("本地没有编译产物：dyn/device/mda_perfwatch 不存在；"
                        "先运行 ./dyn/device/build.sh（需要 Android NDK）")
        out["code"] = "HELPER_NOT_BUILT"
        return out

    local_size = os.path.getsize(_LOCAL_HELPER)
    out["local_size"] = local_size

    if not force_push:
        # 设备上已有且大小一致就跳过推送
        try:
            r = _adb(serial, "shell", f"ls -l {_DEVICE_PATH} 2>/dev/null")
            m = re.search(r"\s(\d+)\s", r.stdout or "")
            if m and int(m.group(1)) == local_size:
                out["ok"] = True
                out["note"] = "设备上已有同版本 helper，跳过推送"
                return out
        except Exception:                                 # noqa: BLE001
            pass

    try:
        r = _adb(serial, "push", _LOCAL_HELPER, _DEVICE_PATH, timeout=120)
        if r.returncode != 0:
            out["error"] = f"推送失败：{(r.stderr or r.stdout or '').strip()[:200]}"
            out["code"] = "PUSH_FAILED"
            return out
        _adb(serial, "shell", f"chmod 755 {_DEVICE_PATH}")
        out["ok"] = True
        out["pushed"] = True
    except Exception as exc:                              # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["code"] = "PUSH_FAILED"
    return out


def perf_watch_probe(serial: str) -> dict:
    """检查这条路径在当前设备是否可用（不设观察点，只验证 helper 能跑）。"""
    h = ensure_helper(serial)
    if not h.get("ok"):
        return {"ok": False, "code": h.get("code"), "error": h.get("error"),
                "helper": h}
    try:
        r = _shell_root(serial, f"{_DEVICE_PATH} probe 0")
        payload = _parse_json(r.stdout)
        return {"ok": True, "helper": h, "device": payload,
                "max_slots": PERF_WATCH_MAX_SLOTS,
                "max_len": PERF_WATCH_MAX_LEN,
                "note": ("硬件观察点最多 4 个槽位；"
                         "地址会自动脱 ARM64 tag；"
                         "观察点按线程生效，0 命中时先确认 tid")}
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "PROBE_FAILED",
                "error": f"{type(exc).__name__}: {exc}", "helper": h}


def _list_tids(serial: str, pid: int, limit: int = 12) -> list[int]:
    """列出目标进程的线程 id（排除主线程）。

    (2) 第二次修改（2026-11-09）：新增。
        为什么要排除主线程：实测主线程设观察点会 NO_SLOT，
        换非主线程即可，自动重试时没必要再撞一次。
    """
    try:
        r = _shell_root(serial, f"ls /proc/{int(pid)}/task")
        tids = sorted(int(x) for x in (r.stdout or "").split() if x.isdigit())
        return [t for t in tids if t != int(pid)][:max(1, int(limit))]
    except Exception:                                     # noqa: BLE001
        return []


def _retry_other_threads(serial: str, pid: int, addr: int, size: int,
                         wt: str, ms: int, cap: int) -> dict:
    """NO_SLOT 时换几个非主线程重试，返回第一个成功的。

    不无限试：最多 6 个线程、每个观察窗口缩到 1/3，
    避免主线程被占时这里卡太久。
    """
    tried: list[int] = []
    for tid in _list_tids(serial, pid, limit=6):
        tried.append(tid)
        short = max(150, ms // 3)
        cmd = (f"{_DEVICE_PATH} once {int(pid)} 0x{int(addr):x} {int(size)} "
               f"{wt} {int(tid)} {short} {int(cap)}")
        try:
            r = _shell_root(serial, cmd, timeout=max(20, short // 1000 + 20))
            p = _parse_json(r.stdout)
        except Exception:                                 # noqa: BLE001
            continue
        if p.get("ok"):
            return {"ok": True, "payload": p, "tried": tried, "used_tid": tid}
    return {"ok": False, "tried": tried}


def _parse_json(text: str) -> dict:
    """从 helper 的 stdout 里取第一行 JSON。

    helper 可能因 su 混入额外输出，所以只认第一个 `{` 开头的完整行。
    """
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"ok": False, "code": "BAD_HELPER_OUTPUT",
            "error": (text or "").strip()[:300] or "helper 没有输出"}




# ---------------------------------------------------------------- 常驻 daemon
#
# 为什么需要常驻：
#   实测踩到的核心痛点——「在 hook 里拿到地址，再回头设观察点」时，
#   数据**已经写完了**。一次 adb+su+helper 启动至少 109ms（实测），
#   而写操作发生在几十毫秒内，必然错过。
#
#   唯一的解法是：观察点**提前设好并一直挂着**，等目标自己来写。
#
# 设计：
#   · daemon 是设备端常驻进程，持有 perf fd，把命中追加到文件
#   · 最多 4 个（内核槽位上限），按 slot 管理
#   · 目标进程消失后 daemon 自己退出，不留孤儿

_DAEMON_DIR = "/data/local/tmp"
_MAX_SLOTS = PERF_WATCH_MAX_SLOTS


def _slot_state(serial: str, slot: int) -> dict:
    """读一个 slot 的状态文件（daemon 写的）。

    (4) 第四次修改（2026-11-09）：文件不存在时必须返回**空字典**。
        bug 原因：原来直接 `return _parse_json(...)`，而 `_parse_json` 在
                  无输出时会返回 {"ok": False, "code": "BAD_HELPER_OUTPUT"}——
                  这是个**非空字典**。于是调用方 `if not st and not hits:`
                  判断失效，把「slot 不存在」误报成
                  「daemon 已退出（可能目标进程结束）」，
                  调用方永远看不到 NO_SUCH_SLOT，会以为观察点曾经存在过。
        解决方案：解析结果里只要没有真正的状态字段（pid/addr/slot），
                  就当作不存在，返回空字典。
    """
    try:
        r = _shell_root(serial, f"cat {_DAEMON_DIR}/mda_pw_{int(slot)}.state 2>/dev/null")
        st = _parse_json(r.stdout)
        # 只有含真实状态字段才算「这个 slot 有 daemon」
        if not isinstance(st, dict) or "pid" not in st or "slot" not in st:
            return {}
        return st
    except Exception:                                     # noqa: BLE001
        return {}


def _slot_hits(serial: str, slot: int, limit: int = 200) -> list:
    """读一个 slot 已采集到的命中（每行一条 JSON）。"""
    try:
        r = _shell_root(serial, f"cat {_DAEMON_DIR}/mda_pw_{int(slot)}.hits 2>/dev/null | tail -n {int(limit)}")
        out = []
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
    except Exception:                                     # noqa: BLE001
        return []


def perf_watch_daemon(serial: str, pid: int, addr: int | str, slot: int = 0,
                      size: int = 8, watch_type: str = "w", tid: int = 0,
                      duration: float = 0) -> dict:
    """起一个**常驻**观察点：提前设好，等目标自己来写。

    与 `perf_watch` 的区别：

        perf_watch         设点 → 等 N 秒 → 返回（窗口固定，错过了就没了）
        perf_watch_daemon  设点 → 一直盯着 → 随时用 poll 取（不丢事件）

    **这是抓 record98 这类「拿不到时机」场景的正确用法**：
    在 buffer 刚分配、还是空的时候就设好，然后不管多久之后被写都能抓到。

    ## 参数

        slot        0..3，硬件只有 4 个槽位
        addr/size/watch_type/tid  同 perf_watch
        duration    0 = 无限期常驻；>0 表示这么多秒后自动退出

    ## 返回

        ok / slot / daemon_pid / addr / tid / state_file / hits_file

    ## 用法

        perf_watch_daemon(serial, pid, addr, slot=0, tid=<写线程>)
        # ... 让目标跑，随便多久 ...
        perf_watch_poll(serial, slot=0)      # 取命中
        perf_watch_stop(serial, slot=0)      # 停掉
    """
    try:
        raw = int(addr, 16) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"ok": False, "code": "BAD_ADDR", "error": f"addr 无法解析：{addr!r}"}
    if int(size) not in (1, 2, 4, 8):
        return {"ok": False, "code": "BAD_SIZE",
                "error": f"size 只能是 1/2/4/8，收到 {size}"}
    if not (0 <= int(slot) < _MAX_SLOTS):
        return {"ok": False, "code": "BAD_SLOT",
                "error": f"slot 必须 0..{_MAX_SLOTS - 1}",
                "hint": "硬件只有 4 个观察点槽位"}

    h = ensure_helper(serial)
    if not h.get("ok"):
        return {"ok": False, "code": h.get("code"), "error": h.get("error")}

    # 先清掉同名 slot，避免叠加
    _shell_root(serial, f"{_DEVICE_PATH} stop {int(slot)}")

    ms = max(0, int(float(duration) * 1000)) if duration else 0
    picked_tid = int(tid or 0)
    if picked_tid == 0:
        cands = _list_tids(serial, int(pid), limit=1)
        if cands:
            picked_tid = cands[0]
    inner = (f"{_DEVICE_PATH} daemon {int(slot)} {int(pid)} 0x{raw:x} "
             f"{int(size)} {watch_type} {picked_tid} {ms}")
    # 用 nohup + & 让它在 adb shell 退出后继续活着。
    # 实测不加 nohup 时进程会被 sd 一并回收。
    cmd = f"nohup {inner} >/dev/null 2>&1 &"
    try:
        _shell_root(serial, cmd, timeout=30)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "START_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    # 等状态文件出现（最多 3 秒），确认 daemon 真的起来了
    t0 = time.time()
    st: dict = {}
    while time.time() - t0 < 3.0:
        st = _slot_state(serial, int(slot))
        if st:
            break
        time.sleep(0.12)

    if not st:
        return {"ok": False, "code": "DAEMON_NOT_STARTED",
                "error": "daemon 起来了但没写出状态文件",
                "hint": ("可能该线程没有可用槽位（主线程常见），"
                         "换一个 tid 再试")}

    out = {"ok": True, "slot": int(slot), "addr": st.get("addr"),
           "tid": st.get("tid"), "size": int(size), "type": watch_type,
           "state": st,
           "state_file": f"{_DAEMON_DIR}/mda_pw_{int(slot)}.state",
           "hits_file": f"{_DAEMON_DIR}/mda_pw_{int(slot)}.hits",
           "note": ("观察点已常驻，目标任何时候写入都会被记录；"
                    "用 perf_watch_poll 取结果")}
    if not int(tid or 0):
        out["hint"] = ("没指定 tid，观察的是整个进程。"
                       "若 poll 一直为 0，先确认写入发生在哪个线程——"
                       "硬件观察点按线程生效")
    return out


def perf_watch_poll(serial: str, slot: int = 0, limit: int = 200) -> dict:
    """取一个常驻观察点的当前结果（可反复调用，增量看新增）。"""
    if not (0 <= int(slot) < _MAX_SLOTS):
        return {"ok": False, "code": "BAD_SLOT",
                "error": f"slot 必须 0..{_MAX_SLOTS - 1}"}
    st = _slot_state(serial, int(slot))
    hits = _slot_hits(serial, int(slot), limit=limit)
    if not st and not hits:
        return {"ok": False, "code": "NO_SUCH_SLOT",
                "error": f"slot {slot} 没有 daemon 在跑",
                "hint": "先用 perf_watch_daemon 起一个"}

    out = {
        "ok": True,
        "slot": int(slot),
        "active": bool(st.get("active")),
        "addr": st.get("addr"),
        "tid": st.get("tid"),
        "total_hits": int(st.get("total_hits") or 0),
        "age_ms": st.get("age_ms"),
        "count": len(hits),
        "hits": hits,
    }
    if hits:
        pcs = sorted({h.get("ip") for h in hits if h.get("ip")})
        out["distinct_pcs"] = pcs
        out["verdict"] = f"已捕获 {out['total_hits']} 次访问，来自 {len(pcs)} 个 pc"
    elif out["active"]:
        out["verdict"] = "daemon 在跑，但还没捕获到访问"
        out["hint"] = ("① 确认 tid 是真正执行写的那个线程；"
                       "② 确认地址在进程可写映射内；"
                       "③ 目标可能还没执行到那段代码")
    else:
        out["verdict"] = "daemon 已退出（可能目标进程结束或达到 duration）"
    return out


def perf_watch_stop(serial: str, slot: int = 0) -> dict:
    """停掉一个常驻观察点并清理文件。"""
    try:
        r = _shell_root(serial, f"{_DEVICE_PATH} stop {int(slot)}")
        return _parse_json(r.stdout)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "STOP_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}


def perf_watch_list(serial: str) -> dict:
    """列出所有常驻观察点及其状态。"""
    try:
        r = _shell_root(serial, f"{_DEVICE_PATH} status")
        payload = _parse_json(r.stdout)
        for d in payload.get("daemons") or []:
            sl = d.get("slot")
            d["hits_count"] = len(_slot_hits(serial, int(sl), limit=500)) if sl is not None else 0
        return payload
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "LIST_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}


def perf_watch(
    serial: str,
    pid: int,
    addr: int | str,
    size: int = 8,
    watch_type: str = "w",
    tid: int = 0,
    duration: float = 3.0,
    max_hits: int = 32,
) -> dict:
    """在指定地址上设硬件观察点，采集一段时间内的命中。

    ## 参数

        addr        运行时绝对地址。带 ARM64 tag（0xb4...）也行，内部会脱
        size        观察字节数，只能 1/2/4/8（内核限制）
        watch_type  "w" 写 / "r" 读 / "rw" 读写 / "x" 执行
        tid         观察哪个线程。**0 = 整个进程**。
                    但注意：实际触发只发生在该线程上，
                    抓不到时先换写操作真正所在的 tid
        duration    采集秒数
        max_hits    最多返回多少条

    ## 返回

        ok / count / hits[] / addr / tag_stripped / target / type / len
        hits[]: {ip, pid, tid, ts_ms, regs:{x0,x1,x2,lr}}

    ## 0 命中时的排查顺序

        ① tid 对不对（最常见）——写入几乎总在某个特定线程
        ② 地址对不对（用 mem_read 确认那里真的在变）
        ③ 该线程是否有可用槽位（NO_SLOT）
        ④ 写入是否发生在观察窗口内

    ## 已知边界

        · 只有 4 个槽位，同时观察 4 个以上地址需要排队
        · 部分进程主线程返回 NO_SLOT（调试资源被占），换非主线程
        · 记录的是**写指令的 pc**，不是调用栈；
          要调用栈请用返回的 ip 去 frida 侧下断点补
    """
    # 地址归一化：允许 "0x..." 字符串、十进制、带 tag
    try:
        raw = int(addr, 16) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"ok": False, "code": "BAD_ADDR",
                "error": f"addr 无法解析：{addr!r}"}

    if int(size) not in (1, 2, 4, 8):
        return {"ok": False, "code": "BAD_SIZE",
                "error": f"size 只能是 1/2/4/8（内核限制），收到 {size}",
                "hint": "要观察更大范围请设多个观察点覆盖"}

    wt = str(watch_type or "w").strip().lower()
    if wt not in ("w", "r", "rw", "x", "write", "read", "exec"):
        return {"ok": False, "code": "BAD_TYPE",
                "error": f"watch_type 只能是 w/r/rw/x，收到 {watch_type!r}"}

    h = ensure_helper(serial)
    if not h.get("ok"):
        return {"ok": False, "code": h.get("code"), "error": h.get("error"),
                "helper": h}

    # (3) 第三次修改（2026-11-09）：tid=0 时**主动避开主线程**。
    #     bug 原因：tid=0 会让 helper 观察整个进程，实际落到主线程上，
    #              而主线程的 debug 寄存器常被 frida 的 Interceptor 占着，
    #              必然 NO_SLOT。用户看到的就是「工具坏了」。
    #     解决方案：tid=0 时先自动挑一个非主线程；挑不到再退回 0。
    #              全程记录 picked_tid，不隐瞒。
    picked_tid = int(tid or 0)
    auto_pick = False
    if picked_tid == 0:
        cands = _list_tids(serial, int(pid), limit=1)
        if cands:
            picked_tid = cands[0]
            auto_pick = True

    ms = max(100, int(float(duration) * 1000))
    cap = max(1, min(int(max_hits), 64))
    cmd = (f"{_DEVICE_PATH} once {int(pid)} 0x{raw:x} {int(size)} {wt} "
           f"{picked_tid} {ms} {cap}")
    try:
        r = _shell_root(serial, cmd, timeout=max(30, ms // 1000 + 30))
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": "TIMEOUT",
                "error": f"{ms}ms 观察窗口 + 启动开销超过等待上限"}
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "RUN_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    payload = _parse_json(r.stdout)
    payload["helper_pushed"] = h.get("pushed", False)
    if auto_pick:
        payload["picked_tid"] = picked_tid
        payload["picked_tid_reason"] = ("未指定 tid，已自动避开主线程"
                                        "（frida 常占用主线程的 debug 寄存器）")

    # (2) 第二次修改（2026-11-09）：NO_SLOT 时自动换线程重试。
    #     bug 原因：实测同一地址、同一长度，指定**主线程**会返回
    #               NO_SLOT(errno=28)，而指定任意非主线程都能成功。
    #               根因是该进程主线程的调试资源被占（与 frida 无关，
    #               进程刚启动、TracerPid=0 时同样如此）。
    #               用户拿到 NO_SLOT 完全不知道下一步该干什么——
    #               而答案很简单：换个线程。
    #     解决方案：NO_SLOT 且没指定 tid（或指定的是主线程）时，
    #               自动枚举几个非主线程重试；成功则沿用该 tid 继续采集。
    #               全程如实记录 tried_tids，不隐瞒换过线程。
    if (not payload.get("ok")) and payload.get("code") == "NO_SLOT":
        auto = _retry_other_threads(serial, int(pid), raw, int(size), wt,
                                    ms, cap)
        if auto.get("ok"):
            payload = auto["payload"]
            payload["auto_thread_retry"] = True
            payload["tried_tids"] = auto["tried"]
            payload["note"] = ("指定的线程没有可用硬件槽位，"
                               f"已自动改用 tid={auto.get('used_tid')}")

    # 0 命中时补排查提示——这是最有用的部分，不要只回个 0
    if payload.get("ok") and int(payload.get("count") or 0) == 0:
        target = payload.get("target")
        hints = []
        if not tid:
            hints.append("你观察的是整个进程（tid=0）。观察点按线程生效，"
                         "写入往往只发生在某个特定线程——"
                         "用 list_threads 找到写线程的 tid 再试")
        hints.append("确认这个地址在观察窗口内真的被写过（用它前后各读一次比对）")
        hints.append("部分进程主线程会 NO_SLOT，可换非主线程")
        payload["hint"] = "；".join(hints)
        payload["verdict"] = (f"{ms}ms 内没有捕获到对该地址的"
                              f"{'写' if wt in ('w','write') else '访问'}")
    elif payload.get("ok"):
        hits = payload.get("hits") or []
        pcs = sorted({h0.get("ip") for h0 in hits if h0.get("ip")})
        payload["verdict"] = (f"捕获 {payload.get('count')} 次访问，"
                              f"来自 {len(pcs)} 个不同 pc")
        payload["distinct_pcs"] = pcs
    else:
        # 失败时补可操作建议
        code = payload.get("code")
        if code == "NO_SLOT":
            # (3) 第三次修改（2026-11-09）：修正 NO_SLOT 的归因。
            #     bug 原因：我原以为「主线程槽位被占是进程固有特性」，
            #              但用户做了 force-stop 对照实验证明：
            #                frida 已附着  → 主线程 NO_SLOT
            #                force-stop 后 → 主线程 ok
            #              → 真因是 **frida 的 Interceptor 占用了主线程的 debug 寄存器**，
            #                不是进程本身的问题。
            #              这个归因很关键：它决定了下一步该怎么做
            #              （换线程 vs 先 detach frida），结论完全不同。
            #     解决方案：提示里说明真因，并给出两条可操作路线。
            payload["hint"] = (
                "该线程的硬件观察点槽位被占（内核只有 4 个）。"
                "**实测真因：frida 的 Interceptor 占用了主线程的 debug 寄存器**"
                "（对照实验：frida 附着时主线程 NO_SLOT，"
                "force-stop 后不附着则正常）。"
                "两条路：① 换一个非主线程的 tid（已自动尝试）；"
                "② 先 detach_target 断开 frida 再设观察点")
        elif code == "BAD_ADDR":
            payload["hint"] = ("内核拒绝这个地址。已自动脱 ARM64 tag，"
                               "若仍失败请确认地址落在可写映射内")
    return payload
