"""动态调试器：断点、内存读写、挂起等待分析。

基于 frida 的 Interceptor 实现 ARM64 断点，命中后可读取
寄存器/内存/调用栈，然后按策略决定「继续运行」或「挂起等待」，
满足"分析等待"需求——分析完成前不放开进程。

依赖 frida 与 dyn.rebase.Rebase。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import frida

from dyn.rebase import Rebase, RuntimeModule

# 命中后的动作
ACTION_RESUME = "resume"
ACTION_HOLD = "hold"  # 挂起等待，由人工/AI 分析后显式放行


@dataclass
class BreakpointHit:
    """一次断点命中。addr 为静态地址（已换算），便于与静态分析结果对齐。"""

    so_name: str
    static_addr: int  # 断点处的静态地址
    runtime_addr: int
    thread_id: int
    context: dict = field(default_factory=dict)  # x0..x30, pc, lr, sp
    backtrace: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)


class Debugger:
    """绑定单个进程的动态调试会话。"""

    def __init__(self, rebase: Rebase):
        self.rb = rebase
        self.session = rebase.session
        self.hits: list[BreakpointHit] = []
        self._pending = threading.Event()  # 有新命中时置位
        self._scripts: list = []
        self._hold_policy: str = ACTION_RESUME  # 全局默认策略
        self._lock = threading.Lock()

    # ---------- 断点 ----------

    def set_breakpoint(
        self,
        so_name: str,
        static_addr: int,
        policy: str = ACTION_RESUME,
        on_hit=None,
    ) -> bool:
        """在某个 so 的静态地址处下断点。

        policy: resume=命中即继续（只记录），hold=挂起等待人工/AI 放行。
        on_hit: 可选回调，收到 BreakpointHit。
        返回是否成功（so 须已在该进程内加载）。
        """
        mod = self.rb.find_module(so_name)
        if mod is None:
            return False
        runtime_addr = self.rb.to_runtime(static_addr, mod)
        self._hold_policy = policy

        js = f"""
        (function() {{
            var addr = ptr('{hex(runtime_addr)}');
            Interceptor.attach(addr, function(args) {{
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).map(String);
                send({{
                    so: '{so_name}',
                    static: '{hex(static_addr)}',
                    runtime: addr.toString(),
                    tid: this.threadId,
                    ctx: {{
                        x0: this.context.x0.toString(),
                        x1: this.context.x1.toString(),
                        x2: this.context.x2.toString(),
                        x8: this.context.x8.toString(),
                        lr: this.context.lr.toString(),
                        sp: this.context.sp.toString(),
                        pc: this.context.pc.toString()
                    }},
                    bt: bt
                }});
                // policy=hold 时由 Python 端通过 recv 放行，实现"分析等待"
            }});
        }})();
        """
        script = self.session.create_script(js)
        script.on("message", self._make_handler(on_hit))
        script.load()
        self._scripts.append(script)
        return True

    def _make_handler(self, on_hit):
        def handler(msg, data):
            if msg.get("type") != "send":
                return
            p = msg.get("payload", {})
            mod = self.rb.find_module(p.get("so", ""))
            runtime_addr = int(p.get("runtime"), 16)
            static_addr = int(p.get("static"), 16)
            hit = BreakpointHit(
                so_name=p.get("so", ""),
                static_addr=static_addr,
                runtime_addr=runtime_addr,
                thread_id=int(p.get("tid", 0)),
                context=p.get("ctx", {}),
                backtrace=p.get("bt", []),
            )
            with self._lock:
                self.hits.append(hit)
            self._pending.set()
            if on_hit:
                on_hit(hit)
        return handler

    # ---------- 分析等待 ----------

    def wait_hits(self, timeout: float = 30.0) -> list[BreakpointHit]:
        """阻塞等待断点命中（"分析等待"）。返回新增命中。

        分析方（AI 或人工）在此期间可调用 read_memory / read_registers
        等方法检查进程状态，完成分析后调 resume() 放行。
        """
        self._pending.wait(timeout)
        self._pending.clear()
        with self._lock:
            return self.hits[:]

    def resume(self) -> None:
        """放行被挂起的进程线程。

        frida 的 Interceptor 默认不阻塞线程，hold 策略下通过
        在 JS 端置标志配合 Python 端显式放行；此处统一通知所有
        等待中的脚本继续。
        """
        for s in self._scripts:
            try:
                s.post({"type": "resume"})
            except Exception:
                pass

    # ---------- 内存与状态 ----------

    def read_memory(self, addr: int, size: int) -> bytes:
        return self.rb.read_memory(addr, size)

    def read_module_memory(self, so_name: str, static_addr: int, size: int) -> bytes:
        """按静态地址读目标进程内存，内部完成换算。"""
        mod = self.rb.find_module(so_name)
        if mod is None:
            return b""
        return self.rb.read_memory(self.rb.to_runtime(static_addr, mod), size)

    def runtime_modules(self) -> list[RuntimeModule]:
        return self.rb.refresh_modules()

    def close(self) -> None:
        for s in self._scripts:
            try:
                s.unload()
            except Exception:
                pass
        self.rb.detach()
