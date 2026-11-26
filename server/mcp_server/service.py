"""GUI 内置 MCP 服务器管理。

设计原则：**UI 是主，服务是仆**。
  - GUI 启动 → 服务自动启动（默认行为）
  - GUI 关闭 → 服务优雅停止、端口立即释放，不留孤儿后台
  - AI 客户端（stdio 代理）检测到 GUI 消失后自动退出，不悬挂

实现要点：
  1. 用 uvicorn.Server 对象持有实例，通过 should_exit 触发优雅停机
     （此前用 server.run() 无法停机，只能靠进程退出兜底）
  2. 启动前探测端口：若被占用，明确报错而非静默失败
"""
from __future__ import annotations

import socket
import threading


class McpService:
    """在后台线程跑 MCP HTTP 服务（供 AI 客户端连接）。"""

    # (1) 第一次修改（2026-11-26）
    # bug 原因：① start_http() 仅拉起线程就立刻返回 True，不等 uvicorn 实际绑定端口就绪，
    #             若绑定失败/启动抛 SystemExit 调用方会拿到假成功；
    #          ② start_http() 与 stop() 存在竞态窗口：若在后台线程创建 _server 之前调用
    #             stop()，stop() 看到 _server 为 None 无法下发 should_exit，随后后台线程
    #             仍继续启动 uvicorn，失控占住 8765 端口。
    # 解决方案：引入 threading.Lock 保护生命周期状态与 _stop_requested 标志，并用
    #          threading.Event 等待 uvicorn 实际 startup 就绪或失败退出；若在创建 _server
    #          前后检测到 _stop_requested，后台线程直接退出不监听端口。
    def __init__(self, log=None):
        self.log = log or (lambda t: None)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._server = None  # uvicorn.Server 实例，用于优雅停机
        self._running = False
        self._stop_requested = False
        self.port = 8765

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    # ---------- 端口 ----------

    def port_in_use(self) -> bool:
        """检测端口是否已被占用（可能是上次异常退出的残留实例）。"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", self.port))
                return False
            except OSError:
                return True

    # ---------- 生命周期 ----------

    def start_http(self, timeout: float = 5.0) -> bool:
        """以 streamable-http 启动（后台线程），等待 uvicorn 实际就绪或失败。"""
        with self._lock:
            if self._running:
                return True
            if self.port_in_use():
                self.log(f"[MCP] 端口 {self.port} 被占用——可能有另一个 MDA 实例在运行，"
                         f"服务未启动")
                return False
            self._running = True
            self._stop_requested = False

        ready = threading.Event()
        start_state: dict = {"started": False, "error": None}

        def run():
            try:
                import uvicorn

                from server.mcp_server.tools import server as mcp_server

                with self._lock:
                    if self._stop_requested:
                        return

                class _ReadyServer(uvicorn.Server):
                    """启动监听成功后通知 ready 事件的 uvicorn.Server 子类。"""

                    async def startup(self, sockets=None) -> None:
                        await super().startup(sockets=sockets)
                        if self.started:
                            start_state["started"] = True
                            ready.set()

                app = mcp_server.streamable_http_app()
                config = uvicorn.Config(
                    app, host="127.0.0.1", port=self.port, log_level="warning"
                )
                srv = _ReadyServer(config)
                with self._lock:
                    if self._stop_requested:
                        srv.should_exit = True
                        return
                    self._server = srv
                srv.run()
            except BaseException as e:                    # noqa: BLE001 - uvicorn 绑定失败抛 SystemExit
                start_state["error"] = e
                self.log(f"[MCP] 服务异常退出: {e}")
            finally:
                with self._lock:
                    self._running = False
                    self._server = None
                ready.set()

        t = threading.Thread(target=run, daemon=True, name="mda-mcp")
        with self._lock:
            if self._stop_requested:
                self._running = False
                return False
            self._thread = t
        t.start()

        ready.wait(timeout=max(0.1, float(timeout)))
        with self._lock:
            if self._stop_requested:
                return False
            ok = bool(start_state["started"]) and start_state["error"] is None and self._running
        if ok:
            self.log(f"[MCP] 已启动: http://127.0.0.1:{self.port}/mcp  (AI 客户端接入点)")
            return True
        if start_state["error"] is None and not start_state["started"]:
            self.log(f"[MCP] 服务启动超时（>{timeout}s），端口 {self.port} 未就绪")
            self.stop(wait=0.5)
        return False

    def stop(self, wait: float = 0.0) -> None:
        """优雅停机：通知 uvicorn 退出。

        参数 wait 控制是否阻塞等待线程收敛：
          - GUI 的 closeEvent 用 wait=0（默认）：只发停止信号，不阻塞
            主线程（uvicorn 的 shutdown 可能耗时数百毫秒，同步 join 会
            冻结窗口关闭动画甚至死锁在 Qt 事件循环里）
          - 需要确认端口已释放时（测试/退出前）传 wait=3.0
        """
        with self._lock:
            if not self._running and self._server is None and self._thread is None:
                return
            self._stop_requested = True
            self._running = False
            srv = self._server
            th = self._thread
            if srv is not None:
                srv.should_exit = True  # uvicorn 的优雅停机开关
        # 守护线程会随进程退出自动结束；不需要时不做 join
        if wait <= 0:
            return
        if th is not None and th.is_alive():
            th.join(timeout=wait)
        with self._lock:
            if self._thread is th and (th is None or not th.is_alive()):
                self._thread = None
                self._server = None
        self.log("[MCP] 已停止，端口已释放")

    def wait_stopped(self, timeout: float = 3.0) -> bool:
        """等待服务线程真正退出。返回是否已停止（供退出前确认端口释放）。"""
        with self._lock:
            th = self._thread
        if th is None:
            return True
        th.join(timeout=timeout)
        stopped = not th.is_alive()
        if stopped:
            with self._lock:
                if self._thread is th:
                    self._thread = None
                    self._server = None
        return stopped

    def status(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp" if self.running else "未启动"
