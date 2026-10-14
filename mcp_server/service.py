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

    def __init__(self, log=None):
        self.log = log or (lambda t: None)
        self._thread: threading.Thread | None = None
        self._server = None  # uvicorn.Server 实例，用于优雅停机
        self._running = False
        self.port = 8765

    @property
    def running(self) -> bool:
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

    def start_http(self) -> bool:
        """以 streamable-http 启动（后台线程）。"""
        if self._running:
            return True
        if self.port_in_use():
            self.log(f"[MCP] 端口 {self.port} 被占用——可能有另一个 MDA 实例在运行，"
                     f"服务未启动")
            return False
        self._running = True

        def run():
            try:
                import uvicorn

                from mcp_server.tools import server as mcp_server

                app = mcp_server.streamable_http_app()
                config = uvicorn.Config(
                    app, host="127.0.0.1", port=self.port, log_level="warning"
                )
                self._server = uvicorn.Server(config)
                self._server.run()
            except Exception as e:
                self.log(f"[MCP] 服务异常退出: {e}")
            finally:
                self._running = False
                self._server = None

        self._thread = threading.Thread(target=run, daemon=True, name="mda-mcp")
        self._thread.start()
        self.log(f"[MCP] 已启动: http://127.0.0.1:{self.port}/mcp  (AI 客户端接入点)")
        return True

    def stop(self, wait: float = 0.0) -> None:
        """优雅停机：通知 uvicorn 退出。

        参数 wait 控制是否阻塞等待线程收敛：
          - GUI 的 closeEvent 用 wait=0（默认）：只发停止信号，不阻塞
            主线程（uvicorn 的 shutdown 可能耗时数百毫秒，同步 join 会
            冻结窗口关闭动画甚至死锁在 Qt 事件循环里）
          - 需要确认端口已释放时（测试/退出前）传 wait=3.0
        """
        if not self._running and self._server is None:
            return
        self._running = False
        if self._server is not None:
            self._server.should_exit = True  # uvicorn 的优雅停机开关
        # 守护线程会随进程退出自动结束；不需要时不做 join
        if wait <= 0:
            return
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=wait)
        self._thread = None
        self._server = None
        self.log("[MCP] 已停止，端口已释放")

    def wait_stopped(self, timeout: float = 3.0) -> bool:
        """等待服务线程真正退出。返回是否已停止（供退出前确认端口释放）。"""
        if self._thread is None:
            return True
        self._thread.join(timeout=timeout)
        stopped = not self._thread.is_alive()
        if stopped:
            self._thread = None
            self._server = None
        return stopped

    def status(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp" if self._running else "未启动"
