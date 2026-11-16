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
import re
import sys
import time
import threading
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

from server.mcp_server.tools import get_session, on_activity, on_ui_sync

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

def _broadcast_sync_json(payload: str) -> None:
    """广播一条已经序列化好的 JSON（用于大快照，避免二次 dump）。"""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_broadcast_raw(payload), _loop)


def _broadcast_sync(event: dict[str, Any]) -> None:
    """从同步代码（线程）里推送事件：转交给事件循环，不能直接 await。"""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_broadcast(event), _loop)


async def _broadcast_raw(payload: str) -> None:
    """把已序列化好的 JSON 发给所有客户端（大快照用，省一次 dump）。"""
    dead = []
    for ws in list(_clients):
        try:
            await ws.send_text(payload)
        except Exception:                      # noqa: BLE001
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


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


# ---------------------------------------------------------------- 会话事实
# 左栏要显示「派发点 805 / 命中 48 / 轨迹 199」这类数字。它们不是常量，
# 而是 **AI 最近一次相关工具调用的结果**。
#
# 通用做法（不针对具体工具写解析分支）：
#   任何工具调用都记下 (调用次数, 最近一次 summary)，取数字时用
#   「summary 里的第一个整数」。哪个工具供给哪个导航条目，由前端映射，
#   加新工具只改那一处映射。
_tool_facts: dict[str, dict[str, Any]] = {}
_facts_lock = threading.Lock()
_FIRST_INT = re.compile(r"\d+")

# behavior_monitor 的参数 → 它实际挂哪些 hook。
# 这是**参数表**不是演示数据：工具的 crypto/file/activity/assets/shell
# 就是它支持的五个开关，每个开关对应哪几个 hook 是工具本身的定义。
_HOOK_GROUPS: dict[str, tuple[str, ...]] = {
    "crypto": ("MessageDigest", "Cipher", "Mac"),
    "file": ("FileIn", "FileOut"),
    "activity": ("Activity",),
    "assets": ("Assets",),
    "shell": ("exec",),
}


def _record_fact(tool: str, summary: str) -> None:
    """记一次工具调用的事实（调用次数 + 最近 summary + 其中第一个整数）。"""
    if not tool:
        return
    m = _FIRST_INT.search(summary or "")
    num = int(m.group(0)) if m else None
    with _facts_lock:
        cur = _tool_facts.get(tool) or {"calls": 0, "num": None, "summary": ""}
        _tool_facts[tool] = {
            "calls": cur["calls"] + 1,
            # 没解析到数字时保留上一次的，避免一次无关调用把数字清成 0
            "num": num if num is not None else cur.get("num"),
            "summary": summary or "",
            "ts": time.strftime("%H:%M:%S"),
        }


def _facts_snapshot() -> dict[str, dict[str, Any]]:
    with _facts_lock:
        return {k: dict(v) for k, v in _tool_facts.items()}


def _hooks_state() -> dict[str, Any]:
    """当前有没有行为监控挂着；挂了的话哪些 hook 是开的。

    数据来源是待命表里 behavior_monitor_start 那条记录的**真实参数**，
    没挂过就返回 armed=False（界面显示未挂，不编造）。
    """
    with _armed_lock:
        arm = next((v for v in _armed.values()
                    if v.get("tool") == "behavior_monitor_start"), None)
    if not arm:
        return {"armed": False, "on": [], "off": [n for g in _HOOK_GROUPS.values() for n in g]}
    args = arm.get("args") or {}
    on: list[str] = []
    off: list[str] = []
    for flag, names in _HOOK_GROUPS.items():
        # 参数缺省与工具默认值一致：只有 shell 默认关
        default = flag != "shell"
        enabled = bool(args.get(flag, default))
        (on if enabled else off).extend(names)
    return {"armed": True, "pid": args.get("pid"), "on": on, "off": off}




# ---------------------------------------------------------------- 待命状态
# AI 装上某种监控后，目标会一直带着这个状态，直到对应工具把它撤掉。
# 这是**持久状态**，和事件流（一次性）不是一回事——所以要单独维护一张表。
#
# 怎么判定：不针对具体工具写死 if/else，而是一张声明式规则表：
#   装上类 → 把参数拼成标签，记一条
#   清理类 → 按映射删掉对应的装上项
# 新增工具只需要在表里加一行。

_ARM_SPECS: dict[str, tuple[str, tuple[str, ...]]] = {
    # tool: (标签模板, 目标必需参数)
    "set_breakpoint":         ("断点 {so_name}@{static_addr}", ("so_name", "static_addr")),
    "behavior_monitor_start": ("行为监控 pid={pid}",            ("pid",)),
    "perf_watch":             ("观察点 pid={pid}@{addr}",       ("pid", "addr")),
    "perf_watch_daemon":      ("观察点 pid={pid}@{addr}",       ("pid", "addr")),
    "java_hook":              ("Java hook {pattern}",           ("pattern",)),
    "vm_breakpoint":          ("VM 断点 {so_name}",             ("so_name",)),
    "freeze_process":         ("冻结 pid={pid}",                ("pid",)),
    "trace_code":             ("代码追踪 pid={pid}",             ("pid",)),
}

# 清理类工具 → 它撤掉哪些装上项
_CLEAR_MAP: dict[str, tuple[str, ...]] = {
    "remove_breakpoint":     ("set_breakpoint",),
    "behavior_monitor_stop": ("behavior_monitor_start",),
    "perf_watch_stop":       ("perf_watch", "perf_watch_daemon"),
    "unfreeze_process":      ("freeze_process",),
    "detach_target":         ("set_breakpoint", "java_hook", "vm_breakpoint", "trace_code"),
    "unload_so":             ("set_breakpoint", "vm_breakpoint"),
    "clear_modules":         ("set_breakpoint", "vm_breakpoint"),
}

_armed: dict[str, dict[str, Any]] = {}
_armed_lock = threading.Lock()


def _arm_label(tool: str, args: dict[str, Any]) -> tuple[str, str, str] | None:
    """一次工具调用是否产生待命状态；有则返回 (key, label, target)。

    target 是「这个东西装在谁身上」，用于界面上归组。
    """
    spec = _ARM_SPECS.get(tool)
    if not spec:
        return None
    tpl, needed = spec
    if not all(args.get(k) not in (None, "") for k in needed):
        return None          # 参数不全（例如失败了）就不记
    label = tpl
    for k in needed:
        v = args.get(k)
        # 地址类参数统一按 0x 显示，和反汇编/引用页的写法保持一致
        if "addr" in k:
            try:
                v = hex(int(v, 0) if isinstance(v, str) else int(v))
            except (TypeError, ValueError):
                pass
        label = label.replace("{" + k + "}", str(v))
    key = tool + "|" + "|".join(f"{k}={args.get(k)}" for k in needed)
    target = str(args.get(needed[0]))
    return key, label, target


def _track_armed(tool: str, args: dict[str, Any], summary: str = "") -> bool:
    """维护待命表；状态有变化返回 True（调用方据此决定要不要广播）。

    summary 以 "✗" 开头表示这次调用失败了——失败不能记成待命，
    否则界面会显示一个根本不存在的断点。
    """
    ok = not summary.startswith("✗")
    changed = False
    with _armed_lock:
        for t in _CLEAR_MAP.get(tool, ()):
            for k in [k for k in _armed if k.startswith(t + "|")]:
                _armed.pop(k, None)
                changed = True
        got = _arm_label(tool, args) if ok else None
        if got:
            key, label, target = got
            if key not in _armed:
                changed = True
            _armed[key] = {
                "key": key,
                "tool": tool,
                "label": label,
                "target": target,
                "ts": time.strftime("%H:%M:%S"),
                # 保留原始参数：界面上要据此还原「这个监控开了哪些开关」
                # （例如 behavior_monitor 的 crypto/file/activity/assets）
                "args": dict(args or {}),
            }
    return changed


def _armed_list() -> list[dict[str, Any]]:
    with _armed_lock:
        return sorted(_armed.values(), key=lambda x: x["ts"], reverse=True)


async def armed(request):
    """当前有哪些目标上装着监控（AI 正在盯着什么）。"""
    items = _armed_list()
    return JSONResponse({"count": len(items), "items": items})


async def armed_clear(request):
    """手动清空待命表。

    注意：这**只是清界面显示**，不会真的撤掉设备上的断点/监控。
    真要撤，得让 AI 调对应的 stop/remove 工具。界面不越权做这件事。
    """
    with _armed_lock:
        n = len(_armed)
        _armed.clear()
    _broadcast_sync({"type": "armed_changed", "count": 0})
    return JSONResponse({"cleared": n})


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
    # 版本号唯一来源是 version.py；这里透出去，前端不再硬编码
    try:
        from server.version import __version__ as _ver
    except Exception:                                     # noqa: BLE001
        _ver = ""
    return JSONResponse({"ok": True, "version": _ver,
                         "modules": list(_session.modules)})


async def modules(request):
    return JSONResponse({"modules": [_mod_brief(m) for m in _session.modules.values()]})


async def unload(request):
    """卸载一个模块（释放 mda 内的静态分析结果，不影响设备进程）。

    (1) 第一次修改（2026-11-11）：
        bug 原因：① 直接在事件循环里调 _session.unload()，而它内部的
                     gc.collect() 在大堆时会卡住整个事件循环（WebSocket/HTTP 全停）；
                  ② 用**输入名**清理 _loaded_paths，但 unload 内部可能把名字
                     解析成别名/改名后的键，导致旧映射残留——同一文件再加载
                     会被"幂等"逻辑误拦；
                  ③ request.json() 没兜底，坏 JSON 直接 500。
        解决方案：① 放到线程池执行；
                  ② 用返回里的真实键 res["so"] 清理；
                  ③ JSON 解析加 try。
    """
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    name = str(body.get("so", "")).strip()
    if not name:
        return _err("缺少 so")

    # ① 线程池：gc.collect 会阻塞事件循环
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, _session.unload, name)
    if not res.get("ok"):
        return _err(res.get("error") or "卸载失败", 404)

    # ② 用真实键清理，而不是输入名
    real_key = res.get("so") or name
    for real, so_name in list(_loaded_paths.items()):
        if so_name in (name, real_key):
            _loaded_paths.pop(real, None)
    _broadcast_sync({"type": "modules_changed", "action": "unload",
                     "so": real_key, "modules": list(_session.modules)})
    return JSONResponse(res)


async def clear_modules(request):
    """批量卸载，body 可带 {"keep": ["xxx.so"]}。"""
    body = {}
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        body = {}
    keep = body.get("keep")
    # keep 的类型校验在 Session.clear 里做（传 str 视为单个模块名，
    # 传其它类型直接报 BAD_KEEP），这里只负责透传
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, _session.clear, keep)
    for real, so_name in list(_loaded_paths.items()):
        if so_name not in _session.modules:
            _loaded_paths.pop(real, None)
    _broadcast_sync({"type": "modules_changed", "action": "clear",
                     "modules": list(_session.modules)})
    return JSONResponse(res)


async def module_memory(request):
    """各模块内存占用估算。"""
    return JSONResponse(_session.memory_usage())


async def nav_stats(request):
    """左栏导航需要的全部真实计数。

    为什么一次返回：左栏有 20 多个条目，一条一个请求会打 20 多个往返，
    而且它们要同时刷新（任何一个变了都应该一起变）。
    """
    name = request.query_params.get("so", "")
    so = _session.modules.get(name)

    def work():
        # 这两块与「当前 so」无关，任何一次 nav_stats 都带上：
        #   facts —— 本次会话 AI 干过什么（左栏动态/VM/行为组的数字）
        #   hooks —— 行为监控开了哪些 hook（实时页左栏的 Hook 墙）
        common = {"facts": _facts_snapshot(), "hooks": _hooks_state()}

        # 不带 so 时：只报服务端有哪些模块（供前端启动时决定加载谁）
        if so is None:
            return {
                **common,
                "loaded": False,
                "serverModules": [
                    {"so": m.name, "path": getattr(m, "path", ""),
                     "functions": len(getattr(m, "functions", {}) or {})}
                    for m in _session.modules.values()
                ],
            }

        funcs = so.functions() if callable(getattr(so, "functions", None)) else so.functions
        if isinstance(funcs, dict):
            funcs = list(funcs.values())
        sections = getattr(so, "sections", []) or []
        strings = []
        try:
            strs = _session.strings(name)
            strings = strs.all_strings() if strs else []
        except Exception:                                 # noqa: BLE001
            strings = []
        try:
            x = _session.xref(name)
            prog = x.progress() or {}
        except Exception:                                 # noqa: BLE001
            prog = {}

        # 顺带把服务端全部模块报回去：前端不再依赖 /api/modules
        # （那条路径在 WKWebView 里会被缓存成旧空数组，实测排了很久）
        all_mods = [
            {"so": m.name, "path": getattr(m, "path", ""),
             "functions": len(getattr(m, "functions", {}) or {})}
            for m in _session.modules.values()
        ]
        return {
            **common,
            "loaded": True,
            "so": so.name,
            "serverModules": all_mods,
            "functions": len(funcs),
            "exports": sum(1 for f in funcs if getattr(f, "is_export", False)),
            "strings": len(strings),
            "sections": len(sections),
            # 引用数 = 全部函数的真实出边累加
            # 未建图时 calls 为空，此时给 None（前端显示「建图」而不是 0，
            # 0 会被误读成"这个模块没有引用"）
            "refs": (sum(len(getattr(f, "calls", []) or []) for f in funcs)
                     if prog.get("built") else None),
            "xref_built": bool(prog.get("built")),
        }

    return JSONResponse(await run_in_threadpool(work))


async def heatmap(request):
    """代码页顶部的热力条：每个函数一格，位置=真实地址，颜色=真实引用数。

    为什么后端做：行数据需要按地址排序并给出跨度，前端拿到的 funcs 是
    按发现顺序；而且大模块（131K 函数）在浏览器里逐格建 DOM 会卡死，
    所以这里直接压成定长桶（默认 220 桶）。
    """
    name = request.query_params.get("so", "")
    try:
        buckets = max(40, min(600, int(request.query_params.get("buckets", "220"))))
    except ValueError:
        buckets = 220

    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        # calls 只在引用图建好后才有值；先确保建好，否则整条热力条全灰
        try:
            _session.ensure_xrefs(name)
        except Exception:                                  # noqa: BLE001
            pass

        funcs = so.functions() if callable(getattr(so, "functions", None)) else so.functions
        if isinstance(funcs, dict):
            funcs = list(funcs.values())
        funcs = sorted(funcs, key=lambda f: f.addr)
        if not funcs:
            return {"so": so.name, "lo": "0x0", "hi": "0x0",
                    "functions": 0, "max_refs": 0, "buckets": []}

        lo = funcs[0].addr
        hi = max(f.end if getattr(f, "end", 0) else f.addr + max(4, f.size or 4) for f in funcs)
        span = max(1, hi - lo)

        # 每桶累计引用数：位置是地址，颜色是密度，这是测量不是装饰
        acc = [0] * buckets
        for f in funcs:
            idx = min(buckets - 1, int((f.addr - lo) / span * buckets))
            acc[idx] += len(getattr(f, "calls", []) or [])

        return {
            "so": so.name,
            "lo": hex(lo), "hi": hex(hi),
            "functions": len(funcs),
            "max_refs": max(acc) if acc else 0,
            "buckets": acc,
        }

    return JSONResponse(await run_in_threadpool(work))



async def foreground(request):
    """当前前台 App 的包名（左栏目标栏用来决定展示谁）。

    为什么要这个端点：界面不该写死某个包名——"在看的 App"就是用户
    此刻在前台的那个。设备没连或读不到就如实返回错误，不猜。
    """
    serial = (request.query_params.get("serial") or "").strip()
    try:
        from server.mcp_server.tools import preflight

        if not serial:
            pf = json.loads(preflight())
            devs = pf.get("devices") or []
            if not devs:
                return JSONResponse({"ok": False, "error": "没有可用的 adb 设备"})
            first = devs[0]
            serial = first.get("serial") if isinstance(first, dict) else str(first)

        from server.dyn.adb import Adb

        adb = Adb(serial)
        pkg = adb.foreground_package() if hasattr(adb, "foreground_package") else ""
        if not pkg:
            # 退一步：直接问 dumpsys
            out = adb._cmd("shell", "dumpsys", "activity", "activities") or ""
            import re as _re

            m = _re.search(r"mResumedActivity.*?u0 ([\w.]+)/", out)
            pkg = m.group(1) if m else ""
        return JSONResponse({"ok": bool(pkg), "package": pkg, "serial": serial})
    except Exception as exc:                              # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


async def dyn_state(request):
    """动态侧的全部真实状态，供左栏各入口使用。

    为什么合并成一个接口：左栏有断点 / 命中 / 内存 / 派发点 / 行为监控
    等多个入口，各自开一个端点会让前端在一次渲染里发 5+ 个请求
    （实测 WKWebView 下这种并发最容易互相拖慢）。一次取全更稳。

    拿不到的部分给空数组 + error，**不编造**。
    """
    out: dict[str, Any] = {
        "ok": True,
        "targets": [],
        "breakpoints": [],
        "hits": [],
        "memory": [],
        "vm": {"dispatch": [], "regs": [], "trace": []},
        "behavior": {"armed": False, "categories": [], "events": []},
        "errors": [],
    }

    # 1) 已附加的目标 + 断点
    try:
        from server.dyn.service import get_dyn

        dyn = get_dyn()
        for key, tgt in list(getattr(dyn, "_targets", {}).items()):
            bps = list((getattr(tgt, "breakpoints", {}) or {}).values())
            out["targets"].append({
                "key": key,
                "serial": getattr(tgt, "serial", ""),
                "pid": getattr(tgt, "pid", None),
                "state": getattr(tgt, "state", ""),
                "breakpoints": len(bps),
            })
            for bp in bps:
                out["breakpoints"].append({
                    "id": bp.get("id", ""),
                    "so": bp.get("so_name", ""),
                    "addr": bp.get("static_addr"),
                    "addr_hex": hex(int(bp.get("static_addr") or 0)),
                    "runtime": bp.get("runtime_addr"),
                    "hold": bool(bp.get("hold")),
                    "armed": bool(bp.get("armed")),
                    "serial": bp.get("serial", ""),
                    "pid": bp.get("pid"),
                })
            # 2) 命中记录。debugger._hits 是有界 deque，直接读最近 100 条。
            dbg = getattr(tgt, "dbg", None)
            raw_hits = list(getattr(dbg, "_hits", []) or [])
            for h in raw_hits[-100:]:
                if isinstance(h, dict):
                    out["hits"].append(h)
                else:
                    # BreakpointHit dataclass：只取界面需要的几项
                    out["hits"].append({
                        "so": getattr(h, "so_name", ""),
                        "static": getattr(h, "static_addr", None),
                        "static_hex": hex(int(getattr(h, "static_addr", 0) or 0)),
                        "runtime": getattr(h, "runtime_addr", None),
                        "tid": getattr(h, "thread_id", None),
                        "seq": getattr(h, "seq", None),
                        "held": bool(getattr(h, "held", False)),
                    })
    except Exception as exc:                              # noqa: BLE001
        out["errors"].append(f"动态会话: {type(exc).__name__}: {exc}")

    # 3) 内存快照（mem_snapshot 留下的）
    try:
        import glob as _glob
        import os as _os

        import tempfile as _tf

        td = _tf.gettempdir()
        for p2 in sorted(_glob.glob(_os.path.join(td, "mda_snap_*.bin"))):
            st = _os.stat(p2)
            out["memory"].append({
                "name": _os.path.basename(p2).replace("mda_snap_", "")
                          .replace(".bin", ""),
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })
    except Exception:                                     # noqa: BLE001
        pass

    # 4) 行为监控（复用已有的 hooks 状态，不重复探测）
    try:
        hk = _hooks_state()
        out["behavior"] = {
            "armed": bool(hk.get("armed")),
            "categories": list(hk.get("on") or []),
            "off": list(hk.get("off") or []),
        }
    except Exception:                                     # noqa: BLE001
        pass

    # 5) 待命表里能反映的 VM / 派发点痕迹
    try:
        facts = _facts_snapshot()
        for tool, nm in (("find_dispatch_tables", "dispatch"),
                         ("vm_regs_snapshot", "regs"),
                         ("trace_code", "trace")):
            f = facts.get(tool)
            if f:
                out["vm"][nm] = [{
                    "calls": f.get("calls"),
                    "num": f.get("num"),
                    "ts": f.get("ts"),
                    "summary": f.get("summary", ""),
                }]
    except Exception:                                     # noqa: BLE001
        pass

    return JSONResponse(out)


async def tools_catalog(request):
    """列出全部 MCP 工具的真实元数据（名/描述/参数）。

    为什么直接读注册表：这是唯一可信来源。前端另存一份清单必然过期——
    我们这一轮就加了 5 个工具，任何手写副本都会立刻不同步。
    """
    from server.mcp_server.tools import server

    ts = await server.list_tools()
    out = []
    for t in ts:
        sch = getattr(t, "input_schema", None) or {}
        out.append({
            "name": t.name,
            "desc": (t.description or "").strip().split("\n")[0][:120],
            "params": list((sch.get("properties") or {}).keys()),
            "required": list(sch.get("required") or []),
        })
    return JSONResponse({"count": len(out), "tools": out})


async def app_processes(request):
    """列出一个包名下的全部进程（真实网络活动）。

    入参：?package=com.xxx 或 ?pid=1234
    pid 时先从 /proc/<pid>/cmdline 反推包名。

    这是纯 /proc 只读，不注入、不 attach，目标完全无感知。
    """
    pkg = (request.query_params.get("package") or "").strip()
    pid_raw = (request.query_params.get("pid") or "").strip()
    serial = (request.query_params.get("serial") or "").strip()

    try:
        from server.mcp_server.tools import preflight

        # 没给 serial 就用第一个在线设备
        if not serial:
            pf = json.loads(preflight())
            devs = pf.get("devices") or []
            if not devs:
                return _err("没有可用的 adb 设备", 404)
            first = devs[0]
            serial = first.get("serial") if isinstance(first, dict) else str(first)

        if not pkg and pid_raw.isdigit():
            from server.dyn.appproc import package_of_pid

            pkg = package_of_pid(serial, int(pid_raw))
        if not pkg:
            return _err("需要 package 或 pid")

        from server.dyn.appproc import list_app_processes

        res = list_app_processes(serial, pkg)
        return JSONResponse(res)
    except Exception as exc:                              # noqa: BLE001
        return _err(f"{type(exc).__name__}: {exc}", 500)


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
    # 通知前端：模块列表变了。前端收到就重建模块（和 unload/clear 同一个协议），
    # 否则用 REST 加载后界面一直显示"未加载"，必须手动刷新。
    # 先推模块名（让前端知道有变化），再推完整快照（含函数表）。
    # 前端在 WKWebView 里拉不动 HTTP，只能靠推。
    _broadcast_sync({
        "type": "modules_changed",
        "modules": list(_session.modules.keys()),
    })
    _broadcast_sync_json(_snapshot_payload())
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


async def sections(request):
    """段/节表（含地址范围与权限）。

    原型左栏有「段 / 节」入口，点进去看的就是这张表——
    它是判断一个 so 是否被加固（缺节表、权限异常）的第一手依据。
    """
    name = request.query_params.get("so", "")
    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        rows = []
        for sec in getattr(so, "sections", []) or []:
            rows.append({
                "name": sec.name,
                "addr": hex(sec.addr),
                "offset": hex(getattr(sec, "offset", 0)),
                "size": int(getattr(sec, "size", 0)),
                "flags": (
                    ("r" if True else "")
                    + ("w" if getattr(sec, "is_write", False) else "-")
                    + ("x" if getattr(sec, "is_exec", False) else "-")
                ),
                "type": str(getattr(sec, "sec_type", "") or ""),
            })
        rows.sort(key=lambda r: int(r["addr"], 16))
        return {"so": so.name, "count": len(rows), "items": rows}

    return JSONResponse(await run_in_threadpool(work))


async def fn_detail(request):
    """函数检视器：一个函数的全部已知事实（右侧那块面板的数据源）。

    返回「概况 + 调用者 + 被调用 + 引用字符串 + 动态状态」。
    为什么后端拼：调用者/被调用要做地址→名字映射，字符串要读回原文，
    这些在前端做都要么卡（131K 函数）要么读不到（字符串在 so 里）。
    """
    name = request.query_params.get("so", "")
    so = _session.modules.get(name)
    if so is None:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(request.query_params.get("addr", "0"), 0)
    except ValueError:
        return _err("addr 非法")

    def work():
        x = _session.xref(name)
        try:
            x.ensure_function(addr)
        except Exception:                                 # noqa: BLE001
            pass
        fn = so.function_at(addr)
        base = fn.addr if fn else addr

        def named(a: int) -> dict:
            f = so.function_at(a)
            return {
                "addr": hex(a),
                # 未命名函数的 name 可能是空串，必须兜底，否则界面上一行只有地址
                "name": (f.name or f"sub_{a:x}") if f else f"sub_{a:x}",
                "is_export": bool(f.is_export) if f else False,
            }

        # 调用者 / 被调用：地址 → 名字
        callers = [named(a) for a in x.callers_of_fn(base)]
        callees: list[dict] = []
        plt_addrs = set(getattr(x, "plt_calls", {}) or {})
        for a in x.callees_of_fn(base):
            item = named(a)
            # 落在 PLT 的是外部导入（calloc / __errno 这类），标出来
            item["plt"] = a in plt_addrs
            callees.append(item)

        # 这个函数引用了哪些字符串（xref 已有反向索引，这里取正向）
        strings: list[dict] = []
        try:
            st = _session.strings(name)
            for sa in x.string_refs_of(base) or []:
                ref = st.string_at(sa) or st.string_starting_at_or_before(sa)
                if ref is not None and ref.value:
                    strings.append({"addr": hex(ref.addr), "value": ref.value[:160]})
        except Exception:                                 # noqa: BLE001
            strings = []

        # 所在段：地址落进哪个 section
        section = ""
        for sec in getattr(so, "sections", []) or []:
            try:
                if int(sec.addr) <= base < int(sec.addr) + int(sec.size):
                    section = sec.name
                    break
            except Exception:                             # noqa: BLE001
                continue

        # 动态：这个地址上有没有断点、命中过几次
        bp = any(v.get("tool") in ("set_breakpoint", "vm_breakpoint")
                 and str((v.get("args") or {}).get("static_addr", "")).lower()
                 in (hex(base), str(base), hex(base).replace("0x", ""))
                 for v in _armed_list())

        return {
            "ok": True,
            "so": so.name,
            "addr": hex(base),
            "name": (fn.name or f"sub_{base:x}") if fn else f"sub_{base:x}",
            "is_export": bool(fn.is_export) if fn else False,
            "size": int(fn.size) if fn else 0,
            "refs_in": len(callers),
            "refs_out": len(callees),
            "section": section,
            "attached": False,          # mda 的分析会话本身不 attach 进程
            "callers": callers,
            "callees": callees,
            "strings": strings,
            "breakpoint": bp,
            "hits": 0,
        }

    return JSONResponse(await run_in_threadpool(work))


async def xref_tree(request):
    """当前函数的调用关系（带函数名），供引用页与图谱共用。

    入参：?so=liblog.so&addr=0x5020&depth=2

    为什么后端做名字映射：前端只认地址的话，界面上就只能显示 0x5248，
    人看不懂。而拉全部函数再在浏览器里做映射，131K 函数的模块会卡死。
    """
    name = request.query_params.get("so", "")
    addr_text = request.query_params.get("addr", "0")
    try:
        depth = max(1, min(3, int(request.query_params.get("depth", "1"))))
    except ValueError:
        depth = 1

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

        def _as_int(v) -> int:
            """引用可能以 int / "0x..." / "123" 三种形态出现，统一成 int。"""
            if isinstance(v, int):
                return v
            return int(str(v), 0)

        def named(a: int) -> dict:
            f = so.function_at(a)
            return {
                "addr": hex(a),
                "name": f.name if f else f"sub_{a:x}",
                "is_export": bool(f.is_export) if f else False,
                "size": int(f.size) if f else 0,
            }

        def layer(a: int, level: int) -> dict:
            node = named(a)
            if level <= 1:
                return node
            node["callers_tree"] = [
                layer(_as_int(c), level - 1)
                for c in (x.callers_of_fn(a) or [])[:5]
            ]
            node["callees_tree"] = [
                layer(_as_int(c), level - 1)
                for c in (x.callees_of_fn(a) or [])[:5]
            ]
            return node

        return {
            "root": layer(base, depth),
            "callers": [named(_as_int(c)) for c in (x.callers_of_fn(base) or [])],
            "callees": [named(_as_int(c)) for c in (x.callees_of_fn(base) or [])],
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


def _snapshot_payload() -> str:
    """当前模块 + 每个模块的函数表，序列化成 WS 消息。

    为什么带函数表：前端建模块需要它，而那条 HTTP GET（/api/functions）
    在 WKWebView 里会被复用成旧/空响应（实测）。一次推全，前端直接用。
    """
    details = []
    for m in _session.modules.values():
        fns = getattr(m, "functions", None)
        if callable(fns):
            fns = fns()
        elif isinstance(fns, dict):
            fns = list(fns.values())
        details.append({
            "so": m.name,
            "path": getattr(m, "path", ""),
            "functions": [
                {
                    "name": f.name,
                    "addr": f.addr,
                    "size": int(getattr(f, "size", 0) or 0),
                    "is_export": bool(getattr(f, "is_export", False)),
                    "refs": len(getattr(f, "calls", []) or []),
                }
                for f in (fns or [])
            ],
        })
    return json.dumps({"type": "modules_snapshot", "details": details},
                      ensure_ascii=False)


async def events(ws):
    await ws.accept()
    _clients.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "hello", "modules": list(_session.modules)},
                                      ensure_ascii=False))
        # 连上就先推一份完整快照：前端定时器在 WKWebView 里不可靠（实测不触发），
        # 所以数据必须由后端主动送到。
        await ws.send_text(_snapshot_payload())
        while True:
            raw = await ws.receive_text()
            # 前端可以主动要一次模块列表：WebSocket 不走 HTTP 缓存，
            # 这是在 WKWebView 里唯一可靠的数据通道（实测 /api GET 会被复用旧响应）
            try:
                msg = json.loads(raw)
            except Exception:                             # noqa: BLE001
                continue
            if isinstance(msg, dict) and msg.get("type") == "sync":
                await ws.send_text(json.dumps({
                    "type": "modules_snapshot",
                    "modules": list(_session.modules),
                    "details": [
                        {
                            "so": m.name,
                            "path": getattr(m, "path", ""),
                            # 函数表一起推：前端 appendModule 需要它，
                            # 走 HTTP 会被 WKWebView 复用旧响应（实测）
                            "functions": [
                                {
                                    "name": f.name,
                                    "addr": f.addr,
                                    "size": int(getattr(f, "size", 0) or 0),
                                    "is_export": bool(getattr(f, "is_export", False)),
                                    "refs": len(getattr(f, "calls", []) or []),
                                }
                                for f in (
                                    m.functions() if callable(getattr(m, "functions", None))
                                    else (m.functions.values() if isinstance(getattr(m, "functions", None), dict)
                                          else m.functions)
                                )
                            ],
                        }
                        for m in _session.modules.values()
                    ],
                }, ensure_ascii=False))
    except Exception:                          # noqa: BLE001 - 正常断开
        pass
    finally:
        _clients.discard(ws)


# ---------------------------------------------------------------- 孤儿代理清理
# 为什么需要：AI 客户端每次重连都会拉起一个 `MDA --mcp-stdio`。
# GUI 重启后，旧代理的 stdin 仍开着，它不会自己发现目标换了，于是堆积。
# 实测出现过 1 主 + 2 转发，其中老的连的是已消失的会话——
# 表现就是"MCP 连上了，但 AI 的操作界面看不见"。
#
# 做法：GUI 启动时把所有 `--mcp-stdio` 进程收掉，只留自己。
#   · 只杀"命令里带 --mcp-stdio"的，绝不误伤主进程
#   · 杀完客户端会在下一次连接时重新拉起一个（那时会通过单例锁让位/接管）
#   · 失败不影响启动（清理是尽力而为，不能因为权限问题挡住主流程）


def _reap_orphan_stdio() -> int:
    """杀掉所有孤儿 stdio 代理进程，返回清理个数。"""
    killed = 0
    try:
        import subprocess

        # pgrep -f 用完整命令行匹配，比 ps 解析更稳
        out = subprocess.run(
            ["pgrep", "-f", "MDA --mcp-stdio"],
            capture_output=True, text=True, timeout=5,
        )
        pids = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
        me = os.getpid()
        for pid in pids:
            if pid == me:
                continue
            try:
                os.kill(pid, 9)
                killed += 1
            except OSError:
                pass
    except Exception:                                     # noqa: BLE001
        pass
    return killed


@asynccontextmanager
async def lifespan(_app):
    """启动内置 MCP（AI 接入点）+ 把 AI 活动翻译成前端事件。"""
    global _loop
    _loop = asyncio.get_running_loop()

    # C：收掉孤儿 stdio 代理，避免多个转发进程并存（见上方注释）
    _reaped = _reap_orphan_stdio()
    if _reaped:
        print(f"[MCP] 已清理 {_reaped} 个孤儿 stdio 代理", flush=True)

    # 定时把所有模块快照推给连着的客户端（2 秒一次）。
    # 前端定时器在 WKWebView 里不可靠，数据必须由后端主动送。
    async def _push_loop():
        while True:
            await asyncio.sleep(2.0)
            if not _clients:
                continue
            try:
                await _broadcast_raw(_snapshot_payload())
            except Exception:                             # noqa: BLE001
                pass

    asyncio.create_task(_push_loop())

    # (3) 第三次修改（2026-10-30）：标记本进程是 GUI。
    #     bug 原因：新增「工具调用转发到 GUI」机制后（mcp_server/link.py），
    #               GUI 进程自己也注册了同一批工具；若它不声明身份，
    #               link.gui_online() 会判定「GUI 在线」并转发给自己 → 自环。
    #     解决方案：GUI 进程在启动内置 MCP 前显式置 MDA_IS_GUI=1，
    #               mcp_server.link 据此拒绝转发。
    #     时机：必须在 mcp.start_http() 之前设置，避免启动瞬间就被转发命中。
    os.environ["MDA_IS_GUI"] = "1"

    # AI 每调用一次工具 → 推给前端：日志、观察列表、球体脉冲
    def _on_ai(entry: dict) -> None:
        # 先维护待命表：装上/撤掉都要让界面知道，否则「AI 在盯着什么」会失真
        tool = entry.get("tool", "")
        args = entry.get("args", {}) or {}
        # 记一次会话事实：左栏那些「派发点/命中/轨迹」的数字来自这里
        try:
            _record_fact(tool, entry.get("summary", ""))
        except Exception:                                 # noqa: BLE001
            pass
        try:
            if _track_armed(tool, args, entry.get("summary", "")):
                items = _armed_list()
                _broadcast_sync({"type": "armed_changed",
                                 "count": len(items), "items": items})
        except Exception:                                 # noqa: BLE001
            pass          # 待命表是辅助信息，不能因为它挂掉完整的事件流
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
    from server.mcp_server.service import McpService

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
    Route("/api/unload", unload, methods=["POST"]),
    Route("/api/clear_modules", clear_modules, methods=["POST"]),
    Route("/api/module_memory", module_memory),
    Route("/api/tools", tools_catalog),
    Route("/api/nav_stats", nav_stats),
    Route("/api/foreground", foreground),
    Route("/api/heatmap", heatmap),
    Route("/api/xref_tree", xref_tree),
    Route("/api/fn_detail", fn_detail),
    Route("/api/sections", sections),
    Route("/api/armed", armed),
    Route("/api/dyn_state", dyn_state),
    Route("/api/armed/clear", armed_clear),
    Route("/api/app_processes", app_processes),
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

async def index_html(request):
    """返回 index.html，并把服务端当前模块**内联**进去。

    (47) 第四十七次修改（2026-11-11）：
    bug 原因：WKWebView 里 /api/modules 的响应恒为空（带唯一时间戳、
              curl 同 URL 正常、XHR 也无效），前端拿不到模块列表，
              界面永远显示"未加载"。排了很多轮没找到 WebKit 层面的原因。
    解决方案：改成"页面加载时就把模块列表写进 HTML"——不再依赖那次请求。
              这是最可靠的：静态 HTML 由服务端按当前状态生成，WKWebView
              无论如何都拿不到旧值。后续变化仍走 WebSocket 推送。
    """
    import os as _os

    path = _os.path.join(_DIST, "index.html")
    try:
        with open(path, encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return _err("前端未构建（web/dist 不存在）", 404)

    mods = [
        {"so": m.name, "path": getattr(m, "path", "")}
        for m in _session.modules.values()
    ]
    # 注入到 window.__MDA_BOOT__，前端启动时优先用它
    boot = (
        '<script>window.__MDA_BOOT__=' +
        json.dumps({"modules": mods}, ensure_ascii=False) +
        ';</script>'
    )
    html = html.replace("</head>", boot + "</head>", 1)
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


if os.path.isdir(_DIST):
    # 首页用动态生成（内联模块列表），其余静态文件照常
    routes.append(Route("/", index_html))
    routes.append(Mount("/", app=StaticFiles(directory=_DIST, html=True), name="web"))

# (38) 第三十八次修改（2026-11-11）：
#      bug 原因：WKWebView 缓存了 GET /api/modules 的空响应。前端加
#                cache:"no-store" 也没用——它在**网络层**复用旧响应。
#                实测前端拿到的原始文本就是 {"modules":[]}，而后端明明有模块；
#                Chrome 不会这样，所以浏览器一直正常、窗口一直空，极难定位。
#      解决方案：服务端对 /api/ 全部响应下发禁缓存头。这是唯一能压住
#                WKWebView 的层面（客户端参数它不完全遵守）。



class _NoCacheAPI:
    """纯 ASGI 中间件：给 /api/ 响应加禁缓存头。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return


        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = [
                    (k, v) for k, v in message.get("headers", [])
                    if k.lower() not in (b"cache-control", b"pragma", b"expires")
                ]
                headers += [
                    (b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0"),
                    (b"pragma", b"no-cache"),
                    (b"expires", b"0"),
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


app = Starlette(routes=routes, lifespan=lifespan)
app = CORSMiddleware(app, allow_origins=DEV_ORIGINS, allow_methods=["*"], allow_headers=["*"])
app = _NoCacheAPI(app)



def main() -> None:
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")


if __name__ == "__main__":
    main()
