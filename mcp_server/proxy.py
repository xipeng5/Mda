"""stdio → HTTP 代理：让 AI 客户端与 GUI 共用同一个分析会话。

问题背景（根因）：
  DeepSeek/Claude 等客户端用 stdio 启动 `mda.py mcp`，那是一个**独立进程**，
  有自己的 Session 内存。而人工看的 GUI（app.py）是另一个进程。
  两者内存隔离 → AI 的所有操作（加载 so、反汇编、改名）GUI 完全看不到。

方案：
  stdio 进程不再自己跑分析，而是把每条 JSON-RPC 原样转发给
  GUI 进程内嵌的 HTTP MCP 端点（默认 http://127.0.0.1:8765/mcp）。
  这样 AI 的所有调用都在 GUI 进程内执行，天然共享同一 Session：
  AI 加载的 so 立即出现在模块树、AI 跳转的地址立即定位、AI 的改名立即生效。

降级：
  GUI 未启动（HTTP 不可达）时，回退为本进程内置分析（离线可用），
  并在 stderr 提示"GUI 未运行，操作不会同步到界面"。
"""
from __future__ import annotations

import json
import os
import sys

GUI_MCP_URL = os.environ.get("MDA_GUI_MCP", "http://127.0.0.1:8765/mcp")
# 探测超时：GUI 没起时要快速失败并降级，不能让 AI 客户端卡住
PROBE_TIMEOUT = 2.0
# 工具调用可能很慢（大 so 构建引用图），转发超时给足
CALL_TIMEOUT = float(os.environ.get("MDA_PROXY_TIMEOUT", "600"))


def gui_available() -> bool:
    """探测 GUI 的 HTTP MCP 端点是否可用（且是本项目实例）。"""
    import httpx2 as httpx

    try:
        r = httpx.get(GUI_MCP_URL, timeout=PROBE_TIMEOUT)
        # Streamable HTTP 端点 GET 通常返回 405/406（要求 POST），
        # 只要 TCP 通了并拿到任何 HTTP 响应就说明服务在
        return r.status_code < 500
    except Exception:
        return False


class StaleSession(RuntimeError):
    """GUI 重启导致的会话失效（需重新 initialize）。"""


class HttpProxy:
    """把 stdio 上的 JSON-RPC 请求转发到 GUI 的 HTTP MCP 端点。

    MCP Streamable HTTP 要求：
      - POST 消息，Accept: application/json, text/event-stream
      - 首次 initialize 响应带 mcp-session-id 头，后续请求须回传
    """

    def __init__(self, url: str = GUI_MCP_URL):
        import httpx2 as httpx

        self.url = url
        self.session_id: str | None = None
        self.client = httpx.Client(timeout=CALL_TIMEOUT)

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            h["mcp-session-id"] = self.session_id
        return h

    def post(self, message: dict) -> dict | None:
        """转发一条 JSON-RPC；会话失效时自动重新握手并重试一次。

        缺陷原因：MCP 的 streamable HTTP 会话（mcp-session-id）保存在
        GUI 进程内存里，GUI 一重启旧 id 就作废。而 DeepSeek 拉起的
        stdio 代理是**长驻进程**，此前遇到 4xx 直接抛错且从不清理
        session_id，于是「重启 GUI 后代理永久报错」，AI 侧的表现就是
        工具列表失效、进而凭记忆瞎编工具名。
        解决：识别会话失效 → 清空 id → 重新 initialize → 重试一次。
        """
        try:
            return self._post_once(message)
        except StaleSession:
            self.session_id = None
            self._initialize()
            return self._post_once(message)

    def _post_once(self, message: dict) -> dict | None:
        r = self.client.post(self.url, json=message, headers=self._headers())
        if "mcp-session-id" in r.headers:
            self.session_id = r.headers["mcp-session-id"]
        if r.status_code >= 400:
            # 404/400 且带过会话 id → 该会话已随 GUI 重启消失
            if self.session_id and r.status_code in (400, 404):
                raise StaleSession(r.text[:120])
            raise RuntimeError(f"GUI MCP 返回 {r.status_code}: {r.text[:200]}")
        text = r.text.strip()
        if not text:
            return None  # 通知消息无响应体
        # SSE 格式：多行 "event: message" / "data: {...}"
        if text.startswith("event:") or "\ndata:" in text or text.startswith("data:"):
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload:
                        return json.loads(payload)
            return None
        return json.loads(text)

    def _initialize(self) -> None:
        """重新与 GUI 握手（会话失效后的恢复路径）。"""
        self._post_once({
            "jsonrpc": "2.0", "id": "proxy-reinit", "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "mda-proxy", "version": "1"}},
        })
        self._post_once({"jsonrpc": "2.0", "method": "notifications/initialized"})


def run_proxy() -> int:
    """stdio 主循环：逐行读 JSON-RPC，转发给 GUI，把响应写回 stdout。

    生命周期：GUI 是主，代理是仆。GUI 消失（连接失败）时代理立即退出，
    避免留下悬挂进程让 AI 客户端误以为服务还活着。
    """
    proxy = HttpProxy()
    print(f"[mda-proxy] 已连接 GUI 会话: {GUI_MCP_URL}", file=sys.stderr, flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = proxy.post(msg)
        except Exception as e:
            # GUI 已退出：不再重试，直接结束代理（stdin 关闭后客户端会感知）
            if not gui_available():
                print(
                    f"[mda-proxy] GUI 已关闭，代理退出：{e}",
                    file=sys.stderr, flush=True,
                )
                return 0
            # GUI 仍在但本次调用失败：回错误给请求方
            if "id" in msg:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32603, "message": f"GUI 代理失败: {e}"},
                }
            else:
                continue
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def run() -> int:
    """入口：GUI 可用则代理，否则降级为内置分析并提示。"""
    if gui_available():
        return run_proxy()
    print(
        "[mda-proxy] 未检测到运行中的 MDA GUI（http://127.0.0.1:8765）。\n"
        "            AI 操作将在本进程内独立执行，界面不会同步。\n"
        "            若要可视化 AI 操作，请先启动: .venv/bin/python app.py",
        file=sys.stderr,
        flush=True,
    )
    from mcp_server.tools import start_stdio

    start_stdio()
    return 0
