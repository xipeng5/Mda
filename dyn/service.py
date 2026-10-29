"""动态分析会话注册表（DynSession）。

为什么需要它：
    frida 的 session/script 是有生命周期的进程内对象。原实现每个 MCP 工具都
    `Rebase.attach()` 再 detach，函数一返回断点就随脚本回收，导致"下断点→再查"
    永远查不到，且每次调用都重新 attach（抖动、重复 hook）。

职责边界：
    - 只持有状态：谁 attach 了、有哪些断点、命中了什么。
    - 不碰静态分析（core/），不做传输（server/），不做展示（web/）。
    - MCP 与 HTTP 共用这一个单例，所以"AI 下的断点"和"界面上看到的断点"是同一批。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from dyn.adb import DynError


@dataclass
class Target:
    """一个已附加的目标进程。"""

    serial: str
    pid: int
    rb: object
    dbg: object
    breakpoints: dict[str, dict] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.serial}:{self.pid}"


class DynamicService:
    """进程内单例：断点与命中状态的唯一持有者。"""

    def __init__(self) -> None:
        self._targets: dict[str, Target] = {}
        self._lock = threading.RLock()

    # ---------- 生命周期 ----------

    def attach(self, serial: str, pid: int) -> Target:
        """附加到进程；同一 (serial,pid) 重复调用返回同一个会话（幂等）。"""
        key = f"{serial}:{pid}"
        with self._lock:
            if key in self._targets:
                return self._targets[key]
            from dyn.debugger import Debugger
            from dyn.rebase import Rebase

            try:
                rb = Rebase.attach(serial, pid)
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                raise DynError("ATTACH_FAILED", _explain(exc)) from exc
            tgt = Target(serial=serial, pid=pid, rb=rb, dbg=Debugger(rb))
            self._targets[key] = tgt
            return tgt

    def detach(self, serial: str, pid: int) -> bool:
        with self._lock:
            tgt = self._targets.pop(f"{serial}:{pid}", None)
        if tgt is None:
            return False
        try:
            tgt.dbg.close()
        except Exception:                                  # noqa: BLE001
            pass
        try:
            tgt.rb.detach()
        except Exception:                                  # noqa: BLE001
            pass
        return True

    def close_all(self) -> None:
        """退出时清理，避免留下 hook 或占用设备。"""
        for key in list(self._targets):
            serial, _, pid = key.partition(":")
            self.detach(serial, int(pid))

    # ---------- 查询 ----------

    def state(self) -> dict:
        with self._lock:
            targets = []
            for tgt in self._targets.values():
                targets.append({
                    "key": tgt.key,
                    "serial": tgt.serial,
                    "pid": tgt.pid,
                    "breakpoints": list(tgt.breakpoints.values()),
                    "hits": len(getattr(tgt.dbg, "hits", [])),
                })
        return {"targets": targets}

    def list_breakpoints(self) -> list[dict]:
        with self._lock:
            return [bp for tgt in self._targets.values() for bp in tgt.breakpoints.values()]

    def modules(self, serial: str, pid: int, keyword: str = "") -> list[dict]:
        tgt = self.attach(serial, pid)
        mods = tgt.rb.refresh_modules()
        kw = keyword.lower()
        return [
            {"name": m.name, "base": hex(m.base), "size": hex(m.size), "path": m.path}
            for m in mods
            if not kw or kw in m.name.lower()
        ][:200]

    # ---------- 断点 ----------

    def set_breakpoint(self, serial: str, pid: int, so_name: str,
                       static_addr: int, hold: bool = False) -> dict:
        """下断点并持有它的脚本，返回断点 id（同一地址重复下返回既有 id）。"""
        bp_id = f"{serial}:{pid}:{so_name}:{static_addr:x}"   # 不含 '#'，可直接进 URL
        tgt = self.attach(serial, pid)
        with self._lock:
            if bp_id in tgt.breakpoints:
                return {**tgt.breakpoints[bp_id], "existing": True}
        mod = tgt.rb.find_module(so_name)
        if mod is None:
            raise DynError("MODULE_NOT_LOADED", f"{so_name} 未加载到进程 {pid}")
        runtime_addr = tgt.rb.to_runtime(static_addr, mod)
        ok = tgt.dbg.set_breakpoint(so_name, static_addr,
                                    policy="hold" if hold else "resume")
        if not ok:
            raise DynError("BREAKPOINT_FAILED", f"{so_name}+{static_addr:#x} 下断点失败")
        bp = {
            "id": bp_id,
            "serial": serial,
            "pid": pid,
            "so_name": so_name,
            "static_addr": static_addr,
            "runtime_addr": runtime_addr,
            "hold": bool(hold),
        }
        with self._lock:
            tgt.breakpoints[bp_id] = bp
        return {**bp, "existing": False}

    def remove_breakpoint(self, bp_id: str) -> bool:
        with self._lock:
            for tgt in self._targets.values():
                if bp_id in tgt.breakpoints:
                    # frida 侧无法单点撤销 Interceptor，最稳妥是整会话重建；
                    # 这里先移除记录并提示"脚本仍在"，等需要时再做得更细。
                    tgt.breakpoints.pop(bp_id, None)
                    return True
        return False

    # ---------- 命中 ----------

    def wait_hits(self, serial: str, pid: int, timeout: float = 10.0) -> list[dict]:
        tgt = self._target(serial, pid)
        hits = tgt.dbg.wait_hits(timeout=timeout)
        return [_hit_dict(h) for h in hits]

    def hits(self, serial: str, pid: int) -> list[dict]:
        tgt = self._target(serial, pid)
        return [_hit_dict(h) for h in list(getattr(tgt.dbg, "hits", []))]

    def resume(self, serial: str, pid: int) -> bool:
        tgt = self._target(serial, pid)
        tgt.dbg.resume()
        return True

    # ---------- 内存 ----------

    def read_memory(self, serial: str, pid: int, so_name: str,
                    static_addr: int, size: int = 32) -> dict:
        if not (1 <= size <= 4096):
            raise DynError("BAD_REQUEST", "size 必须在 1..4096")
        tgt = self.attach(serial, pid)
        mod = tgt.rb.find_module(so_name)
        if mod is None:
            raise DynError("MODULE_NOT_LOADED", f"{so_name} 未加载到进程 {pid}")
        runtime = tgt.rb.to_runtime(static_addr, mod)
        data = tgt.rb.read_memory(runtime, size)
        if not data:
            raise DynError("READ_FAILED", f"地址 {runtime:#x} 不可读或超时")
        return {"static_addr": static_addr, "runtime_addr": runtime,
                "hex": data.hex(), "size": len(data)}

    # ---------- 内部 ----------

    def _target(self, serial: str, pid: int) -> Target:
        tgt = self._targets.get(f"{serial}:{pid}")
        if tgt is None:
            raise DynError("NOT_ATTACHED", f"尚未附加到 {serial}:{pid}")
        return tgt


def _hit_dict(hit) -> dict:
    return {
        "so_name": hit.so_name,
        "static_addr": hit.static_addr,
        "runtime_addr": hit.runtime_addr,
        "thread_id": hit.thread_id,
        "context": hit.context,
        "backtrace": hit.backtrace,
        "ts": hit.ts,
    }


def _explain(exc: Exception) -> str:
    """把 frida 的英文异常翻译成下一步该干什么。"""
    text = str(exc)
    if "unable to communicate with remote frida-server" in text:
        return ("连不上设备端 frida-server：请确认 frida-server 已启动，"
                "且与本机 frida 客户端大版本一致（dyn/adb.py 的 FRIDA_SERVER_VERSION）")
    if "Failed to spawn" in text or "permission" in text.lower():
        return f"附加被拒绝（可能未 root 或目标有反调试）：{text}"
    return text


# 模块级单例：MCP 与 HTTP 都从这里取，保证"AI 下的断点 = 界面看到的断点"
_service: DynamicService | None = None
_service_lock = threading.Lock()


def get_dyn() -> DynamicService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = DynamicService()
    return _service
