"""MDA Web API：把 core.Session 暴露成 REST + WebSocket，供 TS 前端使用。

设计约定：
- 只做传输层，不含任何分析逻辑；分析全部走 core.Session（与 Qt 版、MCP 版同一套内核）。
- 端口固定 8766（避开 MCP 的 8765），需要改端口用环境变量 MDA_API_PORT。
- 不接收命令行参数（项目规范：Python 禁止命令行传参）。
- 单进程单会话：一个 API 进程对应一个 Session，前端与 AI 看到的是同一份数据。

启动：
    .venv/bin/python -m server.api
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

from mcp_server.tools import get_session, on_activity, on_ui_sync

API_HOST = os.environ.get("MDA_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("MDA_API_PORT", "8766"))
# 开发期前端跑在 5173；打包后前端由本服务托管，同样走这个端口
DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

# (1) 第一次修改：与 MCP 共用同一个 Session
#     bug 原因：这里原本自己 new 了一个 Session，导致 AI 通过 MCP 看到的会话
#               和界面看到的是两份数据（互相看不见对方加载的 so）。
#     解决方案：统一取 mcp_server.tools 的单例 Session，UI 与 AI 同会话。
_session = get_session()
_loaded_paths: dict[str, str] = {}      # 绝对路径 -> 已加载的 so 名（防重复加载同名文件）
_clients: set = set()
_mcp_port = 8765            # lifespan 里按实际启动端口更新，供配置接口返回
_loop: asyncio.AbstractEventLoop | None = None


# ---------------------------------------------------------------- 事件推送

def _broadcast_sync(event: dict[str, Any]) -> None:
    """从同步代码（线程）里推送事件：转交给事件循环，不能直接 await。"""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_broadcast(event), _loop)


async def _broadcast(event: dict[str, Any]) -> None:
    dead = []
    payload = json.dumps(event, ensure_ascii=False)
    for ws in list(_clients):
        try:
            await ws.send_text(payload)
        except Exception:                      # noqa: BLE001 - 客户端断开就丢弃
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


def _activity(tool: str, summary: str) -> None:
    _broadcast_sync({"type": "activity", "tool": tool, "summary": summary,
                     "ts": time.strftime("%H:%M:%S")})


# ---------------------------------------------------------------- 工具函数

def _mod_brief(so) -> dict[str, Any]:
    return {
        "so": so.name,
        "path": str(getattr(so, "path", "")),
        "functions": len(so.functions),
        "exports": sum(1 for f in so.functions.values() if f.is_export),
        "sections": len(so.sections),
    }


def _fn_row(fn) -> dict[str, Any]:
    return {
        "name": fn.name or f"sub_{fn.addr:x}",
        "addr": fn.addr,
        "size": fn.size,
        "is_export": bool(fn.is_export),
        "discovered_by": getattr(fn, "discovered_by", ""),
    }


def _err(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=code)


# ---------------------------------------------------------------- 路由

async def health(request):
    return JSONResponse({"ok": True, "modules": list(_session.modules)})


async def modules(request):
    return JSONResponse({"modules": [_mod_brief(m) for m in _session.modules.values()]})


async def load(request):
    body = await request.json()
    path = str(body.get("path", "")).strip()
    if not path:
        return _err("缺少 path")
    if not os.path.isfile(path):
        return _err(f"文件不存在：{path}", 404)

    def work():
        real = os.path.abspath(path)
        # 幂等：同一个文件重复 POST 不重复加载（否则会生成 libbase_2/_3 这样的副本）
        if real in _loaded_paths:
            name = _loaded_paths[real]
            if name in _session.modules:
                return _mod_brief(_session.modules[name])
        so = _session.add(path)
        _loaded_paths[real] = so.name
        return _mod_brief(so)

    info = await run_in_threadpool(work)
    _activity("load_so", f"{info['so']}:{info['functions']}")
    return JSONResponse({"module": info})


async def load_upload(request):
    """接收前端拖入的文件：落盘到 .cache/uploads/ 后再走正常加载流程。

    为什么要落盘：分析内核按路径读 ELF，浏览器拖入拿到的是字节内容，
    先在本地存一份（不参与打包、不提交）是最小改动。
    """
    name = os.path.basename(request.query_params.get("name", "") or "uploaded.so")
    body = await request.body()
    if not body:
        return _err("空文件")
    if len(body) > 512 * 1024 * 1024:
        return _err("文件超过 512MB", 413)
    cache = os.path.join(_cache_root(), "uploads")
    os.makedirs(cache, exist_ok=True)
    path = os.path.join(cache, name)

    def work():
        with open(path, "wb") as fh:
            fh.write(body)
        so = _session.add(path)
        _loaded_paths[os.path.abspath(path)] = so.name
        return _mod_brief(so)

    try:
        info = await run_in_threadpool(work)
    except Exception as exc:                       # noqa: BLE001 - 坏 ELF 等
        return _err(f"解析失败：{exc}", 422)
    _activity("load_so", f"{info['so']}:{info['functions']}")
    return JSONResponse({"module": info, "path": path})


async def functions(request):
    name = request.query_params.get("so", "")
    kw = request.query_params.get("kw", "").strip().lower()
    try:
        limit = int(request.query_params.get("limit", "500"))
        offset = int(request.query_params.get("offset", "0"))
    except ValueError:
        return _err("limit/offset 必须是整数")
    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}，当前有 {list(_session.modules)}", 404)

    def work():
        # (1) 第一次修改：函数表补上"被引用次数"，供球体分级着色/列表排序。
        #     未构建引用图时一律 0，构建后才有真实值（不估算、不猜）。
        x = _session.xref(name)
        built = x.progress().get("built", False)
        rows = []
        for fn in so.functions.values():
            row = _fn_row(fn)
            row["refs"] = len(x.called_by.get(fn.addr, [])) if built else 0
            if kw and kw not in row["name"].lower() and kw not in hex(row["addr"]):
                continue
            rows.append(row)
        rows.sort(key=lambda r: r["addr"])
        total = len(rows)
        return {"total": total, "items": rows[offset: offset + limit]}

    return JSONResponse(await run_in_threadpool(work))


async def disasm(request):
    name = request.query_params.get("so", "")
    addr_text = request.query_params.get("addr", "0")
    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(addr_text, 0)
    except ValueError:
        return _err("addr 非法")

    def work():
        x = _session.xref(name)
        x.ensure_function(addr)
        insns = x.disasm.disasm_function(addr)
        return {
            "addr": addr,
            "items": [
                {
                    "addr": ins.addr,
                    "bytes": bytes(ins.bytes).hex(),
                    "text": (ins.mnemonic + (" " + ins.op_str if ins.op_str else "")).strip(),
                    "is_call": bool(ins.is_call),
                    "is_ret": bool(ins.is_ret),
                    "call_target": ins.call_target,
                }
                for ins in insns
            ],
        }

    return JSONResponse(await run_in_threadpool(work))


async def xrefs(request):
    name = request.query_params.get("so", "")
    addr_text = request.query_params.get("addr", "0")
    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(addr_text, 0)
    except ValueError:
        return _err("addr 非法")

    def work():
        x = _session.xref(name)
        x.ensure_function(addr)
        fn = so.function_at(addr)
        base = fn.addr if fn else addr
        return {
            "addr": base,
            "callers": [hex(a) for a in (x.callers_of_fn(base) or [])],
            "callees": [hex(a) for a in (x.callees_of_fn(base) or [])],
        }

    return JSONResponse(await run_in_threadpool(work))


async def strings(request):
    name = request.query_params.get("so", "")
    kw = request.query_params.get("kw", "").strip()
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        st = _session.strings(name)
        rows = []
        for s in st.all_strings():
            if kw and kw not in s.value:
                continue
            rows.append({"addr": s.addr, "value": s.value[:200], "refs": len(s.referenced_by)})
            if len(rows) >= 500:
                break
        return {"items": rows}

    return JSONResponse(await run_in_threadpool(work))


async def build_xrefs(request):
    """全量引用图构建：大样本 20-30 秒，进度通过 WebSocket 推进前端。"""
    body = await request.json()
    name = str(body.get("so", ""))
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        x = _session.xref(name)
        for pct in (10, 30, 50, 70, 90):
            _broadcast_sync({"type": "xref_progress", "so": name, "percent": pct})
            # 真实进度由 x.progress() 提供，这里只做阶段播报，不编造百分比来源
        _session.ensure_xrefs(name)
        _broadcast_sync({"type": "xref_progress", "so": name, "percent": 100})
        return {"so": name, "ok": True, "progress": x.progress()}

    return JSONResponse(await run_in_threadpool(work))


async def mcp_config(request):
    """给 AI 用的 MCP 配置：路径按当前运行形态算，不让用户手写绝对路径。"""
    import sys

    return JSONResponse({
        "mcp_port": _mcp_port,
        "http_url": f"http://127.0.0.1:{_mcp_port}/mcp",
        "stdio": {"command": sys.executable,
                  "args": [os.path.join(_ROOT, "app.py"), "--mcp-stdio"]},
    })


async def events(ws):
    await ws.accept()
    _clients.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "hello", "modules": list(_session.modules)},
                                      ensure_ascii=False))
        while True:
            # 前端不需要发消息；recv 只为感知断开
            await ws.receive_text()
    except Exception:                          # noqa: BLE001 - 正常断开
        pass
    finally:
        _clients.discard(ws)


@asynccontextmanager
async def lifespan(_app):
    """启动内置 MCP（AI 接入点）+ 把 AI 活动翻译成前端事件。"""
    global _loop
    _loop = asyncio.get_running_loop()

    # AI 每调用一次工具 → 推给前端：日志、观察列表、球体脉冲
    def _on_ai(entry: dict) -> None:
        _broadcast_sync({
            "type": "ai",
            "tool": entry.get("tool", ""),
            "summary": entry.get("summary", ""),
            "args": entry.get("args", {}),
            "ts": entry.get("ts", ""),
            "ms": entry.get("ms", 0),
        })

    # AI 的工具调用翻译成的"等价界面操作"（goto / filter_funcs / show_xrefs …）
    def _on_ui(ev: dict) -> None:
        _broadcast_sync({"type": "ui", "event": ev})

    on_activity(_on_ai)
    on_ui_sync(_on_ui)

    # 内置 MCP：AI 客户端连 127.0.0.1:8765，与界面共享同一会话
    from mcp_server.service import McpService

    # (2) 第二次修改：MCP 端口可用环境变量覆盖
    #     原因：用户已安装的 MDA.app 常驻占用 8765，开发实例起不来，无法验证联动。
    #     方案：默认仍是 8765；设 MDA_MCP_PORT 可换端口（仅开发验证用）。
    mcp = McpService(log=lambda t: print(t, flush=True))
    global _mcp_port
    mcp.port = int(os.environ.get("MDA_MCP_PORT", "8765"))
    _mcp_port = mcp.port
    mcp.start_http()
    yield
    mcp.stop(wait=1.0)


routes = [
    Route("/api/health", health),
    Route("/api/mcp-config", mcp_config),
    Route("/api/modules", modules),
    Route("/api/load", load, methods=["POST"]),
    Route("/api/load_upload", load_upload, methods=["POST"]),
    Route("/api/functions", functions),
    Route("/api/disasm", disasm),
    Route("/api/xrefs", xrefs),
    Route("/api/strings", strings),
    Route("/api/xrefs/build", build_xrefs, methods=["POST"]),
    WebSocketRoute("/api/events", events),
]

# 前端构建产物（web/dist）存在时，用同一个端口托管；开发期仍可用 vite 的 5173 热更新
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 打包后代码在 sys._MEIPASS 里，前端构建产物也随包放在同一层
_BASE = getattr(sys, "_MEIPASS", _ROOT)
_DIST = os.path.join(_BASE, "web", "dist")


def _cache_root() -> str:
    """可写目录：包内是只读的，冻结后改用用户目录（拖入文件要落盘）。"""
    env = os.environ.get("MDA_CACHE_DIR", "").strip()
    if env:
        return env
    if getattr(sys, "frozen", False):
        return os.path.expanduser("~/Library/Application Support/MDA")
    return os.path.join(_ROOT, ".cache")
if os.path.isdir(_DIST):
    routes.append(Mount("/", app=StaticFiles(directory=_DIST, html=True), name="web"))

app = Starlette(routes=routes, lifespan=lifespan)
app = CORSMiddleware(app, allow_origins=DEV_ORIGINS, allow_methods=["*"], allow_headers=["*"])


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")


if __name__ == "__main__":
    main()
