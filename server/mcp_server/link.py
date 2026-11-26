"""会话链路：让 stdio 进程在 GUI 可用时把工具调用转发过去。

问题背景（根因，2026-10-30 实测）：
    MCP 客户端用 stdio 拉起 MDA 时，若那一刻 GUI 尚未启动，旧实现
    （proxy.run 的一次性探测）会让该进程永久降级为「内置独立分析」。
    此后 GUI 虽然起来了，两边仍是两个进程各持一份 Session 单例：
      - MCP 侧 list_modules 返回 2 个 so
      - GUI 的 /api/modules 返回 []
      - lsof 也证实 GUI 进程从未打开过那两个 so 文件
    表现就是「AI 明明在分析，界面一动不动」，且 AI 侧毫无察觉。

本模块的职责（比 proxy 更低一层）：
    proxy 在「传输层」做转发（整条 JSON-RPC 原样转给 GUI）；
    本模块在「工具调用层」做转发——即使当前进程是降级模式，
    只要 GUI 变得可用，**每次工具调用前**都会重新判断并转发到 GUI。
    这样降级不再是永久的，GUI 一启动，下一条调用就自动回到同一会话。

防递归：
    GUI 进程自己也会注册这些工具。它必须不转发（否则自己调自己无限循环），
    由 MDA_IS_GUI=1 标记区分，见 server/api.py 的 lifespan。

保密约定：
    只有「工具调用」走这里；initialize / tools/list 等握手仍由各自进程处理，
    因为两边工具表一致，转发它们没有收益。
"""
from __future__ import annotations

import json
import os
import threading

# GUI 的 Streamable HTTP MCP 端点
GUI_MCP_URL = os.environ.get("MDA_GUI_MCP", "http://127.0.0.1:8765/mcp")
# 单次探测超时（GUI 没起时要快速失败，不能让工具调用卡住）
PROBE_TIMEOUT = 1.0
# 工具调用转发超时：大 so 构建引用图可能很慢
CALL_TIMEOUT = float(os.environ.get("MDA_PROXY_TIMEOUT", "600"))


# (3) 第三次修改（2026-11-26）
# bug 原因：① _GuiLink 多线程并发调用工具时共享 _client / session_id 无锁保护，
#             存在重握手竞争与状态串写；
#          ② _parse 解析 SSE 遇到首条 data: 即返回，易被前序通知事件截胡；
#          ③ call() 收到 GUI 返回的 JSON-RPC error 时因无 result 字段返回 None，
#             触发调用方回退本地执行，分裂出双会话；
#          ④ forward() 把成功空文本 ""（bool("") 为 False）误判为 None，同样触发本地重跑。
# 解决方案：① 给 _GuiLink 加 threading.RLock() 串行化共享状态访问；
#          ② _parse 遍历全部 data: 行，优先取带 id 的响应，否则取末条有效 JSON；
#          ③ call() 把 JSON-RPC error 转成 isError=True 的结果字典，交由 forward() 包装为
#             CallToolResult(is_error=True) 上抛；
#          ④ forward() 明确区分成功空文本 "" 与转发失败 None（含 content 且非 isError 返回 ""）。
class _GuiLink:
    """持有与 GUI 的 MCP 会话（session id 会随 GUI 重启失效，需自动重握）。"""

    def __init__(self) -> None:
        self.session_id: str | None = None
        self._client = None
        self._lock = threading.RLock()

    # ---------- 底层 ----------

    def _http(self):
        with self._lock:
            if self._client is None:
                import httpx2 as httpx

                self._client = httpx.Client(timeout=CALL_TIMEOUT)
            return self._client

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            h["mcp-session-id"] = self.session_id
        return h

    @staticmethod
    def _parse(text: str) -> dict | None:
        """解析响应体：既支持纯 JSON，也支持 SSE（event:/data: 多行）。"""
        text = (text or "").strip()
        if not text:
            return None
        if text.startswith("event:") or text.startswith("data:") or "\ndata:" in text:
            id_msg = None
            last_msg = None
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if not payload:
                        continue
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    last_msg = parsed
                    if isinstance(parsed, dict) and "id" in parsed:
                        id_msg = parsed
            return id_msg if id_msg is not None else last_msg
        return json.loads(text)

    def _post(self, message: dict) -> dict | None:
        with self._lock:
            r = self._http().post(GUI_MCP_URL, json=message, headers=self._headers())
            if "mcp-session-id" in r.headers:
                self.session_id = r.headers["mcp-session-id"]
            if r.status_code >= 400:
                # 4xx 且带着旧 session id → GUI 重启过，id 已作废
                if self.session_id and r.status_code in (400, 404):
                    self.session_id = None
                    raise _Stale()
                raise RuntimeError(f"GUI MCP 返回 {r.status_code}: {r.text[:160]}")
            return self._parse(r.text)

    def _handshake(self) -> None:
        """与 GUI 建立一次 MCP 会话（initialize + initialized）。"""
        with self._lock:
            self.session_id = None
            self._post({
                "jsonrpc": "2.0",
                "id": "mda-link-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mda-link", "version": "1"},
                },
            })
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # ---------- 对外 ----------

    def alive(self) -> bool:
        """GUI 是否在线（本进程不是 GUI 才有意义）。"""
        if os.environ.get("MDA_IS_GUI") == "1":
            return False
        import httpx2 as httpx

        try:
            r = httpx.get(GUI_MCP_URL, timeout=PROBE_TIMEOUT)
            return r.status_code < 500
        except Exception:
            return False

    def call(self, tool: str, arguments: dict) -> dict | None:
        """把一次工具调用转发给 GUI 执行，返回 MCP 的 result 字典。

        失败返回 None，由调用方回退到本地执行（GUI 挂了也不能让 AI 断手）。
        注意：result 里可能带 isError=True（GUI 侧工具自身报错或 JSON-RPC error），
        调用方需据此判定，不能一律当成功，也不能误当离线回退本地执行。
        """
        msg = {
            "jsonrpc": "2.0",
            "id": "mda-link-call",
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}},
        }
        with self._lock:
            try:
                if self.session_id is None:
                    self._handshake()
                resp = self._post(msg)
            except _Stale:
                # 会话失效：重握手后重试一次
                try:
                    self._handshake()
                    resp = self._post(msg)
                except Exception:
                    return None
            except Exception:
                return None
        if not isinstance(resp, dict):
            return None
        # JSON-RPC error 表示 GUI 已收到并拒绝/报错，不能返回 None 触发本地重跑分裂会话
        if "error" in resp and resp["error"] is not None:
            err = resp["error"]
            if isinstance(err, dict):
                code = err.get("code")
                detail = err.get("message") or json.dumps(err, ensure_ascii=False)
                text = f"GUI MCP 错误 (code={code}): {detail}" if code is not None else f"GUI MCP 错误: {detail}"
            else:
                text = f"GUI MCP 错误: {err}"
            return {"content": [{"type": "text", "text": text}], "isError": True}
        result = resp.get("result")
        return result if isinstance(result, dict) else None


class _Stale(RuntimeError):
    """GUI 重启导致的会话失效。"""


_link = _GuiLink()


def should_forward() -> bool:
    """本进程是否应当把工具调用转发出去。

    与 gui_online() 的区别：
      - gui_online() 回答「结果是否与 GUI 同会话」（GUI 进程自己也返回 True）
      - should_forward() 回答「要不要转发」——GUI 进程自己**绝不能**转发，
        否则自己调自己形成自环（由 MDA_IS_GUI=1 标记区分）。
    """
    if os.environ.get("MDA_IS_GUI") == "1":
        return False
    return _link.alive()


def forward(tool: str, arguments: dict):
    """尝试把工具调用转发给 GUI。

    返回值三种：
      - str：GUI 成功执行，返回其文本结果
      - CallToolResult(is_error=True)：GUI 侧工具自身报错，**必须保留错误标记**
      - None：没转发（本进程就是 GUI，或 GUI 不可达/失败），调用方走本地执行

    (1) 第一次修改（2026-10-30）：
        bug 原因：旧实现里「是否降级」在进程启动时一次性决定，GUI 后启动
                 或重启后仍永久停留在独立会话，AI 操作与界面彻底脱节。
        解决方案：改为每次调用前判断，GUI 可用即转发，降级状态可自愈。
    (2) 第二次修改（2026-10-30）：
        bug 原因：初版把 GUI 返回的 content 文本一律当成功字符串返回，
                 丢掉了 isError 标记。GUI 侧工具报错时，AI 会收到一个
                 "内容像报错但状态是成功" 的结果，无法据此自纠。
        解决方案：检测 result["isError"]，为真时构造 is_error=True 的
                 CallToolResult 原样上抛，保持错误语义不丢失。
    (3) 第三次修改（2026-11-26）：
        bug 原因：GUI 成功返回空文本 "" 时，旧写法 `return text if text else None`
                 把合法空字符串返回成了 None，调用方误以为转发失败又在本地重跑。
        解决方案：只要结果含 content 列表且非 isError，即使文本为空也返回 "" 而非 None。
    """
    if not should_forward():
        return None
    result = _link.call(tool, arguments)
    if result is None:
        return None

    content = result.get("content")
    text = ""
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text", "")
                break

    if result.get("isError"):
        from mcp.types import CallToolResult, TextContent

        return CallToolResult(
            content=[TextContent(text=text or "GUI 侧工具执行失败（无错误详情）")],
            is_error=True,  # mcp 2.x 字段名（isError 是 1.x 的）
        )
    if isinstance(content, list):
        return text
    return text if text else None


def gui_online() -> bool:
    """供工具返回元信息使用：当前结果是否来自 GUI 同一会话。"""
    if os.environ.get("MDA_IS_GUI") == "1":
        return True
    return _link.alive()
