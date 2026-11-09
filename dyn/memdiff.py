"""内存快照 diff —— 两次快照之间「多了什么」。

## 用途

「某个东西从无到有」这类问题，正向追很难（不知道起点），
但两次快照一 diff，新增的块就直接浮出来了。

典型场景：
    快照 t1 → 触发目标功能 → 快照 t2 → diff → 新增的内存块

拿到地址后可以接 `perf_watch_daemon` 观察「谁写了它」。

## 为什么必须用设备端 helper（实测数据）

    通过 adb shell + dd 读 /proc/<pid>/mem：4MB 耗时 37,000 ms
    设备端 native pread 直接读：            4MB 耗时 6.4 ms
    **差 5786 倍**

快照动辄几十 MB，走 shell 完全不可行。而且快照留在设备上、
在设备上算 diff，只把「变化的块」传回来——这比传 50MB 回 Mac 快几个数量级。

## 实测性能（systemui，870 段 / 16MB）

    snap : 0.3 秒
    diff : 0.04 秒

## 段选择策略（踩过的坑）

**小段优先**。原来按大段优先，结果 1GB 的 dalvik region space 一次就吃光
64MB 预算，而真正会出现「新增 98 字节块」的是那些几 MB 的小段，
导致 diff 永远返回 0——看起来像「没有变化」，实际是「根本没读到」。

改为小段优先后，同样预算能覆盖 3000+ 段而不是 2 段。

## 通用性

段筛选规则、大小区间、预算全是参数，不绑定任何具体 App。
"""

from __future__ import annotations

import json
import os
import subprocess

__all__ = ["mem_snapshot", "mem_diff", "mem_snapshot_clear",
           "ensure_memsnap_helper", "SNAPSHOT_DEFAULT_MAX_MB"]

SNAPSHOT_DEFAULT_MAX_MB = 64

_HELPER_DEVICE = "/data/local/tmp/mda_memsnap"
_HELPER_LOCAL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "device", "mda_memsnap")


def ensure_memsnap_helper(serial: str) -> dict:
    """确保设备上有 memsnap helper（本地没有就先编译提示）。"""
    out: dict = {"ok": False, "device_path": _HELPER_DEVICE, "pushed": False}
    if not os.path.isfile(_HELPER_LOCAL):
        out["error"] = ("本地没有编译产物：dyn/device/mda_memsnap 不存在；"
                        "先运行 ./dyn/device/build.sh（需要 Android NDK）")
        out["code"] = "HELPER_NOT_BUILT"
        return out
    try:
        from dyn.adb import resolve_adb

        exe = resolve_adb()
        size = os.path.getsize(_HELPER_LOCAL)
        r = subprocess.run([exe, "-s", serial, "shell",
                            f"ls -l {_HELPER_DEVICE} 2>/dev/null"],
                           capture_output=True, text=True, timeout=20)
        import re

        m = re.search(r"\s(\d+)\s", r.stdout or "")
        if m and int(m.group(1)) == size:
            out["ok"] = True
            out["note"] = "设备上已有同版本 helper，跳过推送"
            return out
        subprocess.run([exe, "-s", serial, "push", _HELPER_LOCAL,
                        _HELPER_DEVICE], capture_output=True, timeout=120)
        subprocess.run([exe, "-s", serial, "shell",
                        f"chmod 755 {_HELPER_DEVICE}"], capture_output=True)
        out["ok"] = True
        out["pushed"] = True
    except Exception as exc:                              # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["code"] = "PUSH_FAILED"
    return out


def _run(serial: str, args: str, timeout: int = 120) -> dict:
    """以 root 执行 helper 并解析 JSON。"""
    from dyn.perfwatch import _parse_json, _shell_root

    try:
        r = _shell_root(serial, f"{_HELPER_DEVICE} {args}", timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": "TIMEOUT",
                "error": f"helper 超过 {timeout}s 未返回（目标内存变化过于激烈？）"}
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "RUN_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    return _parse_json(r.stdout)


def mem_snapshot(serial: str, pid: int,
                 max_mb: int = SNAPSHOT_DEFAULT_MAX_MB,
                 key: str = "default") -> dict:
    """在设备上拍一份内存快照（只取可写匿名段，小段优先）。

    ## 参数

        max_mb  最多读多少 MB
        key     快照名，diff 时用同一个 key

    ## 返回

        segments / bytes / file

    ## 注意

    快照**留在设备上**（/data/local/tmp/mda_snap_<key>.bin），
    不传回 Mac。diff 也在设备上算，只返回变化的块。
    """
    h = ensure_memsnap_helper(serial)
    if not h.get("ok"):
        return {"ok": False, "code": h.get("code"), "error": h.get("error")}

    safe = "".join(c for c in str(key) if c.isalnum() or c in "_-")[:32] or "default"
    r = _run(serial, f"snap {int(pid)} {safe} {int(max_mb)}", timeout=180)
    r["key"] = safe
    r["helper_pushed"] = h.get("pushed", False)
    if r.get("ok"):
        r["note"] = ("快照留在设备上。触发目标功能后调 mem_diff 对比，"
                     "只返回变化的块。")
        # (3) 第三次修改（2026-11-09）：把覆盖率显式回给调用方。
        #     实测 16MB 预算只能覆盖 87.6% 的段（840/959）。
        #     用户看不到这件事时，diff 返回 0 会误以为「没有变化」，
        #     实际是「那个段根本没被读到」——这是最误导人的失败模式。
        cov = r.get("coverage")
        if cov:
            try:
                pct = float(str(cov).rstrip("%"))
            except ValueError:
                pct = None
            if pct is not None and pct < 99.0:
                r["coverage_warning"] = (
                    f"本次只覆盖了 {cov} 的段"
                    f"（{r.get('segments')}/{r.get('candidates')}）。"
                    "**没被覆盖的段里发生的变化，diff 看不到。**"
                    "要提高覆盖率：加大 max_mb，或先用 maps 缩小关注范围。")
    return r


def mem_diff(serial: str, pid: int, key: str = "default",
             min_size: int = 1, max_size: int = 0,
             max_report: int = 100) -> dict:
    """再拍一份并对比，找出**新增/变化的块**。

    ## 参数

        min_size   只看至少这么大的块
        max_size   只看至多这么大的（0 = 不限）——
                   **找「新的 98 字节块」时设 90~110 最有效**
        max_report 最多报多少块

    ## 返回

        changed[]  {addr, size, sample}
        count / total_bytes

    ## 用法

        mem_snapshot(pid=..., key="r98")      # t1
        # ... 触发 record98 生成 ...
        mem_diff(pid=..., key="r98", min_size=90, max_size=110)
        → 直接列出新增的 90~110 字节块
    """
    safe = "".join(c for c in str(key) if c.isalnum() or c in "_-")[:32] or "default"
    r = _run(serial, f"diff {int(pid)} {safe} {int(min_size)} "
                     f"{int(max_size)} {int(max_report)}", timeout=180)
    if r.get("ok"):
        cnt = int(r.get("count") or 0)
        if cnt == 0:
            r["verdict"] = ("没找到符合大小区间的变化。"
                            "可能目标功能还没执行，或大小区间设得太窄")
            r["hint"] = ("**注意**：快照只覆盖一部分段（见 mem_snapshot 返回的 "
                         "coverage）。如果目标块不在被覆盖的段里，这里永远返回 0。"
                         "先加大 max_mb 重拍基线再试。")
        else:
            r["verdict"] = (f"找到 {cnt} 处变化，"
                            f"共 {r.get('total_bytes')} 字节")
            r["hint"] = "对关心的地址用 perf_watch_daemon 观察谁写了它"
    return r


def mem_snapshot_clear(serial: str, key: str = "default") -> dict:
    """删掉设备上的快照文件。"""
    safe = "".join(c for c in str(key) if c.isalnum() or c in "_-")[:32] or "default"
    return _run(serial, f"clear {safe}", timeout=30)
