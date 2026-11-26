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

(1) 第一次修改（2026-10-30）：
    bug 原因：降级是**永久**的。旧实现只在进程启动时探测一次
             `gui_available()`，若那一刻 GUI 恰好没起（或端口未就绪），
             此后哪怕 GUI 起来了，该 stdio 进程也永远留在独立会话里，
             AI 的分析操作在界面上完全不可见（实测：MCP 侧已加载 2 个
             so，GUI 的 /api/modules 与 lsof 均显示 0 个，两进程各持
             一份 Session）。
    解决方案：把"是否降级"从**启动时一次性决定**改为**每次调用前判定**。
             探测结果带短 TTL 缓存（避免每条 JSON-RPC 都发 HTTP 请求），
             一旦 GUI 可用即自动切回转发，不需要重启 AI 客户端。
"""
from __future__ import annotations

import json
import os
import sys
import time

GUI_MCP_URL = os.environ.get("MDA_GUI_MCP", "http://127.0.0.1:8765/mcp")
# 探测超时：GUI 没起时要快速失败并降级，不能让 AI 客户端卡住
PROBE_TIMEOUT = 2.0
# 工具调用可能很慢（大 so 构建引用图），转发超时给足
CALL_TIMEOUT = float(os.environ.get("MDA_PROXY_TIMEOUT", "600"))
# (1) 探测结果缓存秒数：GUI 可能后启动，需要周期性重新判定。
#     取 3 秒——足够快地在 GUI 起来后切回，又不会让每条 JSON-RPC 都付一次 HTTP。
PROBE_TTL = float(os.environ.get("MDA_PROBE_TTL", "3"))

# (1) 缓存：(判定结果, 判定时刻)。gui_available() 读它，超 TTL 才真探测。
_probe_cache: dict = {"ok": False, "at": 0.0}


# ---------------------------------------------------------------- 单例守护
# 为什么要这层：AI 客户端每次重连都会拉起一个 --mcp-stdio 进程，
# 而 GUI 重启后旧代理并不会立刻死（它的 stdin 还开着）。
# 实测出现过同时 3 个 MDA 进程（1 主 + 2 stdio），其中老的那个连的是
# 已经不存在的会话，表现为"MCP 连上了但 AI 的操作界面看不见"。
#
# 做法：用文件锁保证同一时刻只有一个 stdio 代理在服务。
#   · 拿到锁 → 正常服务
#   · 拿不到 → 说明已有代理在跑，**直接退出**（客户端会复用那条连接）
# 锁文件放在用户级临时目录，跟随 PID，进程死锁自动释放（flock 语义）。

_LOCK_PATH = os.path.join(
    os.environ.get("TMPDIR", "/tmp"), "mda-mcp-stdio.lock"
)


def _acquire_singleton():
    """尝试独占 stdio 代理身份；成功返回文件对象（需持有到进程退出）。"""
    try:
        import fcntl
    except ImportError:                       # 非 POSIX，直接放行
        return True
    try:
        fh = open(_LOCK_PATH, "a+")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        return fh
    except (BlockingIOError, OSError):
        return None


def _holder_pid() -> str:
    """读锁文件里记录的占用者 PID（仅用于提示，不可靠也不算错）。"""
    try:
        with open(_LOCK_PATH) as f:
            return f.read().strip()
    except Exception:                                     # noqa: BLE001
        return "?"


def gui_available(force: bool = False) -> bool:
    """探测 GUI 的 HTTP MCP 端点是否可用（且是本项目实例）。

    (1) 增加 force 与 TTL 缓存：force=True 跳过缓存强制探测（降级路径与
        出错恢复时用）；默认读 3 秒内的缓存结果，避免高频 HTTP。
    """
    now = time.time()
    if not force and (now - _probe_cache["at"]) < PROBE_TTL:
        return bool(_probe_cache["ok"])

    import httpx2 as httpx

    ok = False
    try:
        r = httpx.get(GUI_MCP_URL, timeout=PROBE_TIMEOUT)
        # Streamable HTTP 端点 GET 通常返回 405/406（要求 POST），
        # 只要 TCP 通了并拿到任何 HTTP 响应就说明服务在
        ok = r.status_code < 500
    except Exception:
        ok = False
    _probe_cache["ok"] = ok
    _probe_cache["at"] = now
    return ok


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

    # (2) 第二次修改（2026-11-26）
    # bug 原因：① 当客户端发送的 message 本身就是 initialize 且触发 StaleSession 时，
    #             旧实现先调 _initialize() 再重发 message，导致二次初始化冲突；
    #          ② _post_once 解析 SSE 遇到第一条 data: 就立即 return，若流里先推送了
    #             无 id 的通知事件，真正的 JSON-RPC 响应会被截胡丢弃；
    #          ③ gui_available() 中残留未使用的 session_epoch 死代码；
    #          ④ run_proxy 异常分支调 gui_available() 未传 force=True，3 秒缓存内会
    #             误判已退出的 GUI 仍在线。
    # 解决方案：① initialize 触发 StaleSession 时清空 session_id 后直接重发原消息；
    #          ② SSE 遍历全部 data: 行，优先返回含 "id" 的 JSON-RPC 响应，否则取末条；
    #          ③ 删除无效 session_epoch 死代码；④ 异常探测改用 gui_available(force=True)。
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
            # 当前消息本身就是 initialize 时直接重发，不再先 _initialize() 造成二次初始化
            if isinstance(message, dict) and message.get("method") == "initialize":
                return self._post_once(message)
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
        # 遍历全部 data: 行，优先取带 id 的 JSON-RPC 响应，避免被前序通知截胡
        if text.startswith("event:") or "\ndata:" in text or text.startswith("data:"):
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
            # (2) 第二次修改（2026-11-26）：强制实时探测，避免命中 3 秒旧缓存误判 GUI 仍在
            # GUI 已退出：不再重试，直接结束代理（stdin 关闭后客户端会感知）
            if not gui_available(force=True):
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
    """入口：GUI 可用则代理，否则降级为内置分析并提示。

    (1) 未检测到 GUI 时不再「永久降级」。降级只是**当次**的选择：
        走本地 stdio 服务，而具体的工具调用每次执行前都会经
        mcp_server.link 重新判定 GUI 是否上线，一旦上线即自动转发。
        所以即使这里是降级分支，GUI 后启动也能自愈，无需重启 AI 客户端。
    """
    # ── A：stdio 单例守护 ──
    # 已有代理在服务时直接退出，避免多个 stdio 并存。
    # 客户端如果拿不到响应，会自行重连到 GUI 的 HTTP 端点或重新拉起本进程。
    lock = _acquire_singleton()
    if lock is None:
        print(
            f"[mda-proxy] 已有 stdio 代理在运行（pid {_holder_pid()}），本进程退出。\n"
            "            多个代理并存会导致「连上了但界面不同步」，这里主动让位。",
            file=sys.stderr, flush=True,
        )
        return 0

    if gui_available(force=True):
        return run_proxy()
    print(
        "[mda-proxy] 未检测到运行中的 MDA GUI（http://127.0.0.1:8765）。\n"
        "            AI 操作将在本进程内独立执行；GUI 一旦启动会自动切回同步，\n"
        "            无需重启客户端。若要立即可视化，请先启动: .venv/bin/python app.py",
        file=sys.stderr,
        flush=True,
    )
    from server.mcp_server.tools import start_stdio

    start_stdio()
    return 0
