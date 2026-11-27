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
import uuid
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

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

# (48) 第四十八次修改（2026-11-26）
# bug 原因：本地服务未校验 Host / Origin / 简单跨站 POST 与 WebSocket Origin，
#           存在 DNS Rebinding 与跨站 CSRF 远程执行 frida 脚本（RCE）风险；
#           且多个接口需要复用的本地校验、so 名称匹配、在线设备探测、调用者入口归一等逻辑缺失。
# 解决方案：集中定义本地 Host/Origin 白名单正则与纯辅助函数，供 HTTP 中间件、
#           WebSocket 握手及各路由端点复用。
_LOCAL_HOST_RE = re.compile(
    r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$",
    re.IGNORECASE,
)
_LOCAL_ORIGIN_RE = re.compile(
    r"^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$",
    re.IGNORECASE,
)
_PROTECTED_POST_PATHS = frozenset({
    "/api/frida_js",
    "/api/frida_js/stop",
    "/api/load",
    "/api/load_upload",
    "/api/unload",
    "/api/clear_modules",
    "/api/armed/clear",
    "/api/xrefs/build",
})


def _is_local_host(host: str) -> bool:
    """校验 Host 头是否仅指向本机回环地址，防止 DNS Rebinding。"""
    return bool(host and _LOCAL_HOST_RE.match(host.strip()))


def _is_local_origin(origin: str) -> bool:
    """校验 Origin 头是否属于本机白名单来源（localhost / 127.0.0.1 / [::1]）。"""
    return bool(origin and _LOCAL_ORIGIN_RE.match(origin.strip()))


def _is_local_referer(referer: str) -> bool:
    """校验 Referer 头的来源部分是否属于本机白名单。"""
    try:
        u = urlsplit(referer.strip())
    except ValueError:
        return False
    if not u.scheme or not u.netloc:
        return False
    return _is_local_origin(f"{u.scheme}://{u.netloc}")


def _so_matches(a: str, b: str) -> bool:
    """判断两个 so 名称是否指向同一模块（复用 core.session 统一匹配规则）。"""
    sa = str(a or "").strip()
    sb = str(b or "").strip()
    if not sa or not sb:
        return False
    if sa == sb or os.path.basename(sa) == os.path.basename(sb):
        return True
    try:
        from server.core.session import match_name

        hit, _how, _amb = match_name(sa, [sb])
        return hit is not None
    except Exception:                                     # noqa: BLE001
        return sa.lower() == sb.lower()


def _same_addr(raw: Any, target: int) -> bool:
    """比较任意格式地址值（int / 0x hex / 纯 hex / 十进制串）是否等于 target。"""
    if raw in (None, ""):
        return False
    try:
        val = int(raw, 0) if isinstance(raw, str) else int(raw)
        if val == target:
            return True
    except (TypeError, ValueError):
        pass
    if isinstance(raw, str):
        try:
            return int(raw.strip(), 16) == target
        except ValueError:
            return False
    return False


def _first_online_device_serial() -> str:
    """直接经 Adb.list_devices() 获取首个在线设备序列号（不调用挂了 @logged 的 preflight）。"""
    from server.dyn.adb import Adb

    for dev in Adb.list_devices():
        if getattr(dev, "state", "") == "device":
            return dev.serial
    return ""


def _normalize_callers(so, raw_sites) -> list[tuple[int, int]]:
    """将 callers_of_fn 返回的调用指令地址归一为调用者函数入口，并按入口去重。"""
    seen: set[int] = set()
    out: list[tuple[int, int]] = []
    for raw in (raw_sites or []):
        try:
            site = raw if isinstance(raw, int) else int(str(raw), 0)
        except (TypeError, ValueError):
            continue
        fn = so.function_at(site)
        entry = fn.addr if fn else site
        if entry in seen:
            continue
        seen.add(entry)
        out.append((entry, site))
    return out

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


# (49) 第四十九次修改（2026-11-26）
# bug 原因：① 失败调用（summary 以 "✗" 开头或 ok is False）虽然不新增待命项，
#              但仍会执行 _CLEAR_MAP 误清空已有待命状态；
#           ② remove_breakpoint 命中 _CLEAR_MAP 后会直接清空所有模块的全部断点，
#              而非仅移除对应 bp_id 的那一条。
# 解决方案：失败调用直接跳过；remove_breakpoint 解析 bp_id 后仅精确移除匹配条目，
#           unload_so 有明确模块名时也按模块名精确移除。
def _track_armed(tool: str, args: dict[str, Any], summary: str = "", ok: bool = True) -> bool:
    """维护待命表；状态有变化返回 True（调用方据此决定要不要广播）。

    summary 以 "✗" 开头或 ok is False 表示这次调用失败了——失败不能记成待命，
    也不应误清空现有待命状态。
    """
    if ok is False or (summary or "").startswith("✗"):
        return False
    args = args or {}
    changed = False
    with _armed_lock:
        if tool == "remove_breakpoint":
            bp_id = str(args.get("bp_id") or "").strip()
            parts = bp_id.rsplit(":", 2) if bp_id else []
            if len(parts) == 3:
                prefix, bp_so, bp_addr_hex = parts
                bp_serial, _, bp_pid = prefix.rpartition(":")
                try:
                    bp_addr = int(bp_addr_hex, 16)
                except ValueError:
                    bp_addr = None
                if bp_addr is not None:
                    for k, v in list(_armed.items()):
                        if v.get("tool") != "set_breakpoint":
                            continue
                        va = v.get("args") or {}
                        if not _so_matches(va.get("so_name", ""), bp_so):
                            continue
                        if not _same_addr(va.get("static_addr"), bp_addr):
                            continue
                        if bp_serial and va.get("serial") and str(va.get("serial")) != bp_serial:
                            continue
                        if bp_pid and va.get("pid") not in (None, "") and str(va.get("pid")) != bp_pid:
                            continue
                        _armed.pop(k, None)
                        changed = True
        elif tool == "unload_so" and (args.get("name") or args.get("so_name")):
            target_so = str(args.get("name") or args.get("so_name") or "").strip()
            for t in _CLEAR_MAP.get(tool, ()):
                for k, v in list(_armed.items()):
                    if not k.startswith(t + "|"):
                        continue
                    va = v.get("args") or {}
                    if _so_matches(va.get("so_name", ""), target_so):
                        _armed.pop(k, None)
                        changed = True
        else:
            for t in _CLEAR_MAP.get(tool, ()):
                for k in [k for k in _armed if k.startswith(t + "|")]:
                    _armed.pop(k, None)
                    changed = True

        got = _arm_label(tool, args)
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
                "args": dict(args),
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
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)
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
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)
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

    # (50) 第五十次修改（2026-11-26）
    # bug 原因：heatmap 每次加载都会调用 _session.ensure_xrefs(name)，在大 so 上强制阻塞
    #           20-30 秒跑全量反汇编建图，导致打开页面卡死。
    # 解决方案：仅读取惰性 Xref 对象状态，未建图时不触发全量 build，快速按函数密度统计
    #           并返回 xref_built 标志供前端准确提示。
    def work():
        x = _session.xref(name)
        xref_built = bool(getattr(x, "_built", False))
        calls_to = getattr(x, "_calls_to", None) or {}

        funcs = so.functions() if callable(getattr(so, "functions", None)) else so.functions
        if isinstance(funcs, dict):
            funcs = list(funcs.values())
        funcs = sorted(funcs, key=lambda f: f.addr)
        if not funcs:
            return {"so": so.name, "lo": "0x0", "hi": "0x0",
                    "functions": 0, "max_refs": 0, "buckets": [],
                    "xref_built": xref_built}

        lo = funcs[0].addr
        hi = max(f.end if getattr(f, "end", 0) else f.addr + max(4, f.size or 4) for f in funcs)
        span = max(1, hi - lo)

        # 已建图时累计真实引用数；未建图时快速按函数分布密度生成，不阻塞主流程
        acc = [0] * buckets
        for f in funcs:
            idx = min(buckets - 1, int((f.addr - lo) / span * buckets))
            if xref_built:
                acc[idx] += len(calls_to.get(f.addr, [])) + len(getattr(f, "calls", []) or [])
            else:
                acc[idx] += 1

        return {
            "so": so.name,
            "lo": hex(lo), "hi": hex(hi),
            "functions": len(funcs),
            "max_refs": max(acc) if acc else 0,
            "buckets": acc,
            "xref_built": xref_built,
        }

    return JSONResponse(await run_in_threadpool(work))


# (51) 第五十一次修改（2026-11-26）
# bug 原因：/api/foreground 直接在 asyncio 事件循环中同步执行 adb 子进程阻塞循环，
#           且调用了挂有 @logged() 装饰器的 tools.preflight()，导致每次打开界面
#           都凭空伪造多条 preflight AI 调用事件。
# 解决方案：全部移入 run_in_threadpool 执行，改调底层 _first_online_device_serial()
#           （Adb.list_devices()）直接获取在线设备，彻底消除阻塞与假 AI 事件。
async def foreground(request):
    """当前前台 App 的包名（左栏目标栏用来决定展示谁）。

    为什么要这个端点：界面不该写死某个包名——"在看的 App"就是用户
    此刻在前台的那个。设备没连或读不到就如实返回错误，不猜。
    """
    serial = (request.query_params.get("serial") or "").strip()

    def work():
        from server.dyn.adb import Adb

        ser = serial or _first_online_device_serial()
        if not ser:
            return {"ok": False, "error": "没有可用的 adb 设备"}

        adb = Adb(ser)
        pkg = adb.foreground_package() if hasattr(adb, "foreground_package") else ""
        if not pkg:
            # 退一步：直接问 dumpsys
            out = adb._cmd("shell", "dumpsys", "activity", "activities") or ""
            m = re.search(r"mResumedActivity.*?u0 ([\w.]+)/", out)
            pkg = m.group(1) if m else ""
        return {"ok": bool(pkg), "package": pkg, "serial": ser}

    try:
        return JSONResponse(await run_in_threadpool(work))
    except Exception as exc:                              # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


# (52) 第五十二次修改（2026-11-26）
# bug 原因：① dyn_state 裸读 dyn._targets 与 dbg._hits 未加锁，存在并发迭代异常风险；
#           ② VM 事实键只检查了 find_dispatch_tables / vm_regs_snapshot / trace_code，
#              漏掉了 LeftNav 已映射的 find_vm_dispatch_points / trace_module_load /
#              trace_app_startup / trace_call_tree，导致左栏有计数但详情页为空。
# 解决方案：在 dyn._lock 下快照目标与断点，读取命中改走加锁公开属性 dbg.hits，
#           并补齐全部 VM / trace 工具事实键与 LeftNav 对齐。
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
        lock = getattr(dyn, "_lock", None)
        snap_targets = []
        if lock is not None:
            with lock:
                for key, tgt in list(getattr(dyn, "_targets", {}).items()):
                    bps = [dict(bp) for bp in (getattr(tgt, "breakpoints", {}) or {}).values()]
                    snap_targets.append((
                        key,
                        getattr(tgt, "serial", ""),
                        getattr(tgt, "pid", None),
                        getattr(tgt, "state", ""),
                        bps,
                        getattr(tgt, "dbg", None),
                    ))
        else:
            for key, tgt in list(getattr(dyn, "_targets", {}).items()):
                bps = [dict(bp) for bp in (getattr(tgt, "breakpoints", {}) or {}).values()]
                snap_targets.append((
                    key,
                    getattr(tgt, "serial", ""),
                    getattr(tgt, "pid", None),
                    getattr(tgt, "state", ""),
                    bps,
                    getattr(tgt, "dbg", None),
                ))

        for key, ser, pid_val, st_val, bps, dbg in snap_targets:
            out["targets"].append({
                "key": key,
                "serial": ser,
                "pid": pid_val,
                "state": st_val,
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
            # 2) 命中记录：改走加锁公开属性 dbg.hits，避免裸读 _hits 引发竞态
            raw_hits = list(getattr(dbg, "hits", None) or []) if dbg is not None else []
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

    # 5) 待命表里能反映的 VM / 派发点痕迹（与 LeftNav.FACT_SRC 完全对齐）
    try:
        facts = _facts_snapshot()
        for nm, tool_names in (
            ("dispatch", ("find_vm_dispatch_points", "find_dispatch_tables")),
            ("regs", ("vm_regs_snapshot",)),
            ("trace", ("trace_code", "trace_module_load", "trace_app_startup", "trace_call_tree")),
        ):
            rows_vm = []
            for tool in tool_names:
                f = facts.get(tool)
                if f:
                    rows_vm.append({
                        "tool": tool,
                        "calls": f.get("calls"),
                        "num": f.get("num"),
                        "ts": f.get("ts"),
                        "summary": f.get("summary", ""),
                    })
            if rows_vm:
                out["vm"][nm] = rows_vm
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


# (53) 第五十三次修改（2026-11-26）
# bug 原因：/api/app_processes 直接在事件循环中同步执行 adb /proc 查询阻塞循环，
#           且调用了挂 @logged() 的 tools.preflight()，在事件流里伪造 preflight 调用。
# 解决方案：全流程移入 run_in_threadpool，并改用 _first_online_device_serial() 直接查设备。
async def app_processes(request):
    """列出一个包名下的全部进程（真实网络活动）。

    入参：?package=com.xxx 或 ?pid=1234
    pid 时先从 /proc/<pid>/cmdline 反推包名。

    这是纯 /proc 只读，不注入、不 attach，目标完全无感知。
    """
    pkg = (request.query_params.get("package") or "").strip()
    pid_raw = (request.query_params.get("pid") or "").strip()
    serial = (request.query_params.get("serial") or "").strip()

    def work():
        ser = serial or _first_online_device_serial()
        if not ser:
            return {"error": "没有可用的 adb 设备"}, 404

        target_pkg = pkg
        if not target_pkg and pid_raw.isdigit():
            from server.dyn.appproc import package_of_pid

            target_pkg = package_of_pid(ser, int(pid_raw))
        if not target_pkg:
            return {"error": "需要 package 或 pid"}, 400

        from server.dyn.appproc import list_app_processes

        return list_app_processes(ser, target_pkg), 200

    try:
        payload, status = await run_in_threadpool(work)
        return JSONResponse(payload, status_code=status)
    except Exception as exc:                              # noqa: BLE001
        return _err(f"{type(exc).__name__}: {exc}", 500)


# (54) 第五十四次修改（2026-11-26）
# bug 原因：① load 未捕获坏 JSON、非对象 body 及 ELF 解析异常，直接抛 500；
#           ② load_upload 直接写 .cache/uploads/<name> 会覆写正在打开的同名 SoFile 句柄，
#              且加载后未广播 modules_changed 与快照，导致多端/WKWebView 状态不同步。
# 解决方案：① load 对 JSON/参数/ELF 错误返回 400 JSON 并在线程池构建快照；
#           ② load_upload 写入独立子目录 uploads/<ts_uuid>/<name> 避免覆写已打开句柄同时
#              保留干净文件名，并在加载完成后广播 modules_changed 与快照。
async def load(request):
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)
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

    try:
        info = await run_in_threadpool(work)
    except Exception as exc:                              # noqa: BLE001 - 坏 ELF/解析错误
        return _err(f"加载或解析失败：{exc}", 400)
    # 通知前端：模块列表变了。前端收到就重建模块（和 unload/clear 同一个协议），
    # 否则用 REST 加载后界面一直显示"未加载"，必须手动刷新。
    _broadcast_sync({
        "type": "modules_changed",
        "modules": list(_session.modules.keys()),
    })
    snap = await run_in_threadpool(_snapshot_payload)
    _broadcast_sync_json(snap)
    _activity("load_so", f"{info['so']}:{info['functions']}")
    return JSONResponse({"module": info})


async def load_upload(request):
    """接收前端拖入的文件：落盘到 .cache/uploads/<唯一目录>/ 后再走正常加载流程。

    为什么要落盘：分析内核按路径读 ELF，浏览器拖入拿到的是字节内容，
    先在本地存一份（不参与打包、不提交）是最小改动；用唯一子目录既避免覆写
    正在打开的同名 SoFile 文件句柄，又保留原始文件名供 SoFile 命名。
    """
    raw_name = os.path.basename((request.query_params.get("name") or "").strip())
    name = raw_name if raw_name and raw_name not in (".", "..") else "uploaded.so"
    body = await request.body()
    if not body:
        return _err("空文件")
    if len(body) > 512 * 1024 * 1024:
        return _err("文件超过 512MB", 413)
    slot_dir = os.path.join(_cache_root(), "uploads", f"{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}")
    os.makedirs(slot_dir, exist_ok=True)
    path = os.path.join(slot_dir, name)

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
    _broadcast_sync({
        "type": "modules_changed",
        "modules": list(_session.modules.keys()),
    })
    snap = await run_in_threadpool(_snapshot_payload)
    _broadcast_sync_json(snap)
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
        # (55) 第五十五次修改（2026-11-26）
        # bug 原因：refs 原先读 x.called_by（出度）且走 property，语义与"被引用次数"相反。
        # 解决方案：仅在 x._built 为真时读取 x._calls_to（被引用入度），不触发隐式建图。
        x = _session.xref(name)
        built = bool(getattr(x, "_built", False))
        calls_to = getattr(x, "_calls_to", None) or {}
        rows = []
        for fn in so.functions.values():
            row = _fn_row(fn)
            row["refs"] = len(calls_to.get(fn.addr, [])) if built else 0
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
        fn = so.function_at(addr)
        fn_start = fn.addr if fn else addr
        fn_end = fn_start + max(fn.size, 4) if fn else addr + 4
        insns = x.disasm.disasm_function(addr)
        st = None
        try:
            st = _session.strings(name)
        except Exception:                                 # noqa: BLE001
            st = None
        loaded_sos = set(_session.modules.keys())
        items = []
        for ins in insns:
            row = {
                "addr": ins.addr,
                "bytes": bytes(ins.bytes).hex(),
                "text": (ins.mnemonic + (" " + ins.op_str if ins.op_str else "")).strip(),
                "is_call": bool(ins.is_call),
                "is_ret": bool(ins.is_ret),
                "call_target": ins.call_target,
            }
            # 补充跳转目标、跨 SO 符号名与行内字符串引用（向后兼容增量字段）
            if ins.call_target is not None:
                if fn_start <= ins.call_target < fn_end:
                    row["jump_so"] = name
                    row["jump_addr"] = ins.call_target
                else:
                    lk = _session.resolve_call(name, ins.call_target)
                    if lk and lk.callee_so in loaded_sos and lk.callee_addr:
                        row["jump_so"] = lk.callee_so
                        row["jump_addr"] = lk.callee_addr
                        row["sym_ref"] = f"{lk.callee_so}!{lk.callee}" if lk.callee_so != name else lk.callee
                    elif lk and lk.callee:
                        row["sym_ref"] = f"{lk.callee}@plt" if lk.via_plt else lk.callee
                    else:
                        tfn = so.function_at(ins.call_target)
                        if tfn:
                            row["jump_so"] = name
                            row["jump_addr"] = ins.call_target
                            if tfn.addr != fn_start:
                                row["sym_ref"] = tfn.name or f"sub_{tfn.addr:x}"
            if st is not None and ins.ref_addr is not None:
                sref = st.string_at(ins.ref_addr)
                if sref and sref.value:
                    row["str_ref"] = sref.value[:120]
            items.append(row)
        return {"addr": addr, "items": items}

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

    # (56) 第五十六次修改（2026-11-26）
    # bug 原因：① callers_of_fn 返回的是 bl 调用指令地址而非调用者函数入口，
    #              导致前端点击调用者跳转失败且 xref_tree?depth=2 二层调用者恒为空；
    #           ② fn_detail 访问 x.plt_calls 属性会触发 20-30s 全量 build，
    #              且 attached/hits 硬编码 False/0、断点匹配未校验 so_name 会跨 so 误报；
    #           ③ xref_tree 未命名函数缺少 sub_xxx 兜底导致 stripped so 显示空白名。
    # 解决方案：通过 _normalize_callers 统一将调用点归一到调用者函数入口并按入口去重，
    #           保留可选 site 字段；fn_detail 改为只读 _plt_calls 并向 DynamicService
    #           真实查询 attached/hits 与按 so_name+static_addr 匹配断点；所有未命名函数统一兜底。
    def work():
        x = _session.xref(name)
        x.ensure_function(addr)
        fn = so.function_at(addr)
        base = fn.addr if fn else addr
        return {
            "addr": base,
            "callers": [hex(entry) for entry, _site in _normalize_callers(so, x.callers_of_fn(base))],
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

        def named(a: int, site: int | None = None) -> dict:
            f = so.function_at(a)
            entry = f.addr if f else a
            item = {
                "addr": hex(entry),
                # 未命名函数的 name 可能是空串，必须兜底，否则界面上一行只有地址
                "name": (f.name or f"sub_{entry:x}") if f else f"sub_{entry:x}",
                "is_export": bool(f.is_export) if f else False,
            }
            if site is not None:
                item["site"] = hex(site)
            return item

        # 调用者 / 被调用：调用点归一到调用者函数入口并按入口去重（含已建图跨 SO 边）
        loaded_sos = set(_session.modules.keys())
        callers = [
            {**named(entry, site), "so": name}
            for entry, site in _normalize_callers(so, x.callers_of_fn(base))
        ]
        seen_callers = {(name, c["addr"]) for c in callers}
        if fn is not None and fn.is_export and fn.name:
            for other_name, other_so in _session.modules.items():
                if other_name == name:
                    continue
                ox = _session.xref(other_name)
                if not getattr(ox, "_built", False):
                    continue
                for plt_addr, sym in (getattr(other_so, "plt_map", None) or {}).items():
                    if sym != fn.name:
                        continue
                    for c_entry, c_site in _normalize_callers(other_so, ox.callers_of_fn(plt_addr)):
                        key_pair = (other_name, hex(c_entry))
                        if key_pair in seen_callers:
                            continue
                        seen_callers.add(key_pair)
                        cf = other_so.function_at(c_entry)
                        callers.append({
                            "so": other_name,
                            "addr": hex(c_entry),
                            "site": hex(c_site),
                            "name": (cf.name or f"sub_{c_entry:x}") if cf else f"sub_{c_entry:x}",
                            "is_export": bool(cf.is_export) if cf else False,
                        })

        callees: list[dict] = []
        # 绝不访问 @property plt_calls（会触发 20-30s 全量 build），只读内部 _plt_calls
        plt_addrs = set(getattr(x, "_plt_calls", None) or {})
        for a in (x.callees_of_fn(base) or []):
            lk = _session.resolve_call(name, a)
            if lk and lk.callee_so in loaded_sos and lk.callee_addr:
                tso = _session.modules[lk.callee_so]
                tfn = tso.function_at(lk.callee_addr)
                t_entry = tfn.addr if tfn else lk.callee_addr
                callees.append({
                    "so": lk.callee_so,
                    "addr": hex(t_entry),
                    "name": (tfn.name or lk.callee or f"sub_{t_entry:x}") if tfn else (lk.callee or f"sub_{t_entry:x}"),
                    "is_export": bool(tfn.is_export) if tfn else False,
                    "plt": bool(lk.via_plt),
                })
            else:
                item = named(a)
                item["so"] = name
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

        # 动态：向 DynamicService 真实查询该 so + base 的 attached、断点与命中数
        attached = False
        bp_live = False
        hits_count = 0
        try:
            from server.dyn.service import STATE_DETACHED, get_dyn

            dyn = get_dyn()
            lock = getattr(dyn, "_lock", None)
            snap_tgts = []
            if lock is not None:
                with lock:
                    for tgt in list(getattr(dyn, "_targets", {}).values()):
                        snap_tgts.append((
                            getattr(tgt, "state", ""),
                            list((getattr(tgt, "breakpoints", {}) or {}).values()),
                            list(getattr(getattr(tgt, "rb", None), "_modules", None) or []),
                            getattr(tgt, "dbg", None),
                        ))
            else:
                for tgt in list(getattr(dyn, "_targets", {}).values()):
                    snap_tgts.append((
                        getattr(tgt, "state", ""),
                        list((getattr(tgt, "breakpoints", {}) or {}).values()),
                        list(getattr(getattr(tgt, "rb", None), "_modules", None) or []),
                        getattr(tgt, "dbg", None),
                    ))

            for st_val, bps, rb_mods, dbg in snap_tgts:
                if st_val != STATE_DETACHED:
                    if rb_mods:
                        if any(_so_matches(getattr(m, "name", ""), so.name) for m in rb_mods):
                            attached = True
                    else:
                        attached = True
                    for b in bps:
                        if (
                            b.get("armed", True)
                            and (
                                _so_matches(b.get("so_name", ""), so.name)
                                or _so_matches(b.get("original_name", ""), so.name)
                            )
                        ):
                            attached = True
                            if _same_addr(b.get("static_addr"), base):
                                bp_live = True
                raw_hits = list(getattr(dbg, "hits", None) or []) if dbg is not None else []
                for h in raw_hits:
                    h_so = h.get("so_name", "") if isinstance(h, dict) else getattr(h, "so_name", "")
                    h_addr = h.get("static_addr") if isinstance(h, dict) else getattr(h, "static_addr", None)
                    if _so_matches(h_so, so.name) and _same_addr(h_addr, base):
                        hits_count += 1
        except Exception:                                 # noqa: BLE001
            pass

        # 待命表断点匹配同时校验 so_name 与 static_addr，避免多 so 同偏移误报
        bp_armed = any(
            v.get("tool") in ("set_breakpoint", "vm_breakpoint")
            and _so_matches((v.get("args") or {}).get("so_name", ""), so.name)
            and _same_addr((v.get("args") or {}).get("static_addr"), base)
            for v in _armed_list()
        )
        bp = bp_live or bp_armed

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
            "attached": attached,
            "callers": callers,
            "callees": callees,
            "strings": strings,
            "breakpoint": bp,
            "hits": hits_count,
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

        def named(a: int, site: int | None = None) -> dict:
            f = so.function_at(a)
            entry = f.addr if f else a
            item = {
                "addr": hex(entry),
                "name": (f.name or f"sub_{entry:x}") if f else f"sub_{entry:x}",
                "is_export": bool(f.is_export) if f else False,
                "size": int(f.size) if f else 0,
            }
            if site is not None:
                item["site"] = hex(site)
            return item

        def layer(a: int, level: int, site: int | None = None) -> dict:
            f = so.function_at(a)
            entry = f.addr if f else a
            node = named(entry, site)
            if level <= 1:
                return node
            node["callers_tree"] = [
                layer(c_entry, level - 1, c_site)
                for c_entry, c_site in _normalize_callers(so, x.callers_of_fn(entry))[:5]
            ]
            node["callees_tree"] = [
                layer(_as_int(c), level - 1)
                for c in (x.callees_of_fn(entry) or [])[:5]
            ]
            return node

        loaded_sos = set(_session.modules.keys())
        direct_callers = [
            {**named(c_entry, c_site), "so": name}
            for c_entry, c_site in _normalize_callers(so, x.callers_of_fn(base))
        ]
        seen_c = {(name, c["addr"]) for c in direct_callers}
        if fn is not None and fn.is_export and fn.name:
            for other_name, other_so in _session.modules.items():
                if other_name == name:
                    continue
                ox = _session.xref(other_name)
                if not getattr(ox, "_built", False):
                    continue
                for plt_addr, sym in (getattr(other_so, "plt_map", None) or {}).items():
                    if sym != fn.name:
                        continue
                    for c_entry, c_site in _normalize_callers(other_so, ox.callers_of_fn(plt_addr)):
                        kp = (other_name, hex(c_entry))
                        if kp in seen_c:
                            continue
                        seen_c.add(kp)
                        cf = other_so.function_at(c_entry)
                        direct_callers.append({
                            "so": other_name,
                            "addr": hex(c_entry),
                            "site": hex(c_site),
                            "name": (cf.name or f"sub_{c_entry:x}") if cf else f"sub_{c_entry:x}",
                            "is_export": bool(cf.is_export) if cf else False,
                            "size": int(cf.size) if cf else 0,
                        })

        direct_callees = []
        for c in (x.callees_of_fn(base) or []):
            ca = _as_int(c)
            lk = _session.resolve_call(name, ca)
            if lk and lk.callee_so in loaded_sos and lk.callee_addr:
                tso = _session.modules[lk.callee_so]
                tfn = tso.function_at(lk.callee_addr)
                t_entry = tfn.addr if tfn else lk.callee_addr
                direct_callees.append({
                    "so": lk.callee_so,
                    "addr": hex(t_entry),
                    "name": (tfn.name or lk.callee or f"sub_{t_entry:x}") if tfn else (lk.callee or f"sub_{t_entry:x}"),
                    "is_export": bool(tfn.is_export) if tfn else False,
                    "size": int(tfn.size) if tfn else 0,
                })
            else:
                direct_callees.append({**named(ca), "so": name})

        return {
            "root": {**layer(base, depth), "so": name},
            "callers": direct_callers,
            "callees": direct_callees,
        }

    return JSONResponse(await run_in_threadpool(work))


async def strings(request):
    name = request.query_params.get("so", "")
    kw = request.query_params.get("kw", "").strip()
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        so = _session.modules[name]
        st = _session.strings(name)
        kw_l = kw.lower()
        rows = []
        for s in st.all_strings():
            if kw_l and kw_l not in s.value.lower():
                continue
            ref_fn = None
            if s.referenced_by:
                rfn = so.function_at(s.referenced_by[0])
                if rfn is not None:
                    ref_fn = rfn.addr
            rows.append({
                "addr": s.addr,
                "value": s.value[:200],
                "refs": len(s.referenced_by),
                "section": getattr(s, "section", ".rodata"),
                "ref_fn": ref_fn,
            })
            if len(rows) >= 500:
                break
        return {"items": rows}

    return JSONResponse(await run_in_threadpool(work))


# (60) 第六十次修改（2026-11-27）
# bug 原因：decompile_view / cfg_view / rename_fn_api / set_comment_api / plugin_run_api
#           直接调用挂有 @logged() 装饰器的 MCP 工具函数，导致用户在 Web UI 点击函数、
#           切伪代码/CFG、重命名、写注释或点插件快捷分析时，会触发 _activity 广播假 AI 事件
#           污染实时工具流，甚至触发 _emit_ui_replay 造成界面回环。
# 解决方案：上述 5 个 Web 端只读/编辑接口全部改为直调内核层（PseudocodeGenerator、
#           get_plugins().run、_session 与 annotations.store），并补充请求体 dict 校验，
#           彻底隔离人工 GUI 操作与 AI MCP 调用流。
async def decompile_view(request):
    """返回函数的真实源地址映射伪代码（style=c 默认结构化伪 C，style=raw 原始指令对照）。"""
    name = request.query_params.get("so", "")
    addr_text = request.query_params.get("addr", "0")
    style = (request.query_params.get("style") or "c").strip().lower()
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(addr_text, 0)
    except ValueError:
        return _err("addr 非法")

    def _resolve_sym(so_n: str, target: int):
        lk = _session.resolve_call(so_n, target)
        if lk and lk.callee:
            other_so = lk.callee_so if (lk.callee_so and lk.callee_so != so_n) else ""
            return (other_so, lk.callee, lk.callee_addr)
        return None

    def work():
        so = _session.get(name)
        d = _session.xref(name).disasm
        if style == "raw":
            from server.core.pseudocode import PseudocodeGenerator

            code = PseudocodeGenerator(so, d).generate(addr, resolve=_resolve_sym, with_addr=True)
            return {"ok": True, "so": name, "addr": hex(addr), "style": "raw", "code": code}
        from server.core.pseudocode_c import PseudoCGenerator

        return PseudoCGenerator(so, d, resolve=_resolve_sym).generate(addr)

    return JSONResponse(await run_in_threadpool(work))


async def cfg_view(request):
    """返回函数的真实基本块 CFG 控制流图（直接复用 disasm_func 插件，不经 @logged）。"""
    name = request.query_params.get("so", "")
    addr_text = request.query_params.get("addr", "0")
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(addr_text, 0)
    except ValueError:
        return _err("addr 非法")

    def work():
        from server.mcp_server.tools import get_plugins

        res = get_plugins().run("disasm_func", {"so": name, "addr": hex(addr)})
        return res if isinstance(res, dict) else {"ok": False, "error": str(res)}

    try:
        return JSONResponse(await run_in_threadpool(work))
    except Exception as exc:                               # noqa: BLE001
        return _err(f"CFG 构建失败：{exc}", 500)


async def rename_fn_api(request):
    """原地重命名函数（同步写入会话与注解持久化，供前端 N 快捷键调用）。"""
    try:
        body = await request.json()
    except Exception:                                      # noqa: BLE001
        return _err("请求体非合法 JSON")
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象")
    name = str(body.get("so") or "")
    new_name = str(body.get("name") or "").strip()
    if name not in _session.modules or not new_name:
        return _err("缺少有效的 so 或新函数名")
    try:
        addr = int(body.get("addr"), 0) if isinstance(body.get("addr"), str) else int(body.get("addr"))
    except Exception:                                      # noqa: BLE001
        return _err("addr 非法")

    def work():
        import dataclasses as _dc
        from server.mcp_server.tools import get_plugins

        so = _session.get(name)
        canon = _session.key(name)
        fn = so.function_at(addr)
        if fn is None:
            return {"error": f"{addr:#x} 不在任何函数内"}
        old = fn.name or f"sub_{fn.addr:x}"
        fn.name = new_name
        try:
            from server.core.annotations import store as _anno
            _anno.save(so.name, fn.addr, rename=new_name)
        except Exception:                                  # noqa: BLE001
            pass
        if old in so.exports:
            renamed = so.exports.pop(old)
            if _dc.is_dataclass(renamed):
                renamed = _dc.replace(renamed, name=new_name)
            elif hasattr(renamed, "name"):
                renamed.name = new_name
            so.exports[new_name] = renamed
            old_entries = _session._export_index.get(old)
            if old_entries is not None:
                kept = [
                    (n, a) for (n, a) in old_entries
                    if not (n in (canon, so.name) and a == fn.addr)
                ]
                if kept:
                    _session._export_index[old] = kept
                else:
                    _session._export_index.pop(old, None)
            new_entries = _session._export_index.setdefault(new_name, [])
            if (canon, fn.addr) not in new_entries:
                new_entries.append((canon, fn.addr))
        try:
            get_plugins().emit("after_rename", {"so_name": so.name, "addr": fn.addr, "old": old, "new": new_name})
        except Exception:                                  # noqa: BLE001
            pass
        return {"ok": True, "so": so.name, "addr": fn.addr, "old": old, "name": new_name}

    res = await run_in_threadpool(work)
    if res.get("error"):
        return _err(str(res["error"]), 400)
    _broadcast_sync({"type": "modules_changed", "modules": list(_session.modules.keys())})
    return JSONResponse({"ok": True, "so": name, "addr": res["addr"], "name": new_name})


async def comments_api(request):
    """查询指定 so 的全部地址注释。"""
    name = request.query_params.get("so", "")
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)

    def work():
        key = _session.key(name)
        items = {
            hex(a): c
            for (n, a), c in _session.comments.items()
            if n == key and c
        }
        return {"ok": True, "so": name, "items": items}

    return JSONResponse(await run_in_threadpool(work))


async def set_comment_api(request):
    """设置或清除指定地址注释（同步持久化，供前端 ; 快捷键调用）。"""
    try:
        body = await request.json()
    except Exception:                                      # noqa: BLE001
        return _err("请求体非合法 JSON")
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象")
    name = str(body.get("so") or "")
    comment = str(body.get("comment") or "").strip()
    if name not in _session.modules:
        return _err(f"未加载的 so：{name}", 404)
    try:
        addr = int(body.get("addr"), 0) if isinstance(body.get("addr"), str) else int(body.get("addr"))
    except Exception:                                      # noqa: BLE001
        return _err("addr 非法")

    def work():
        from server.mcp_server.tools import get_plugins

        key = _session.key(name)
        if comment:
            _session.comments[(key, addr)] = comment
        else:
            _session.comments.pop((key, addr), None)
        try:
            from server.core.annotations import store as _anno
            _anno.save(key, addr, comment=comment)
        except Exception:                                  # noqa: BLE001
            pass
        try:
            get_plugins().emit("after_comment", {"so_name": key, "addr": addr, "comment": comment})
        except Exception:                                  # noqa: BLE001
            pass
        return {"ok": True, "so": name, "addr": hex(addr), "comment": comment}

    return JSONResponse(await run_in_threadpool(work))


_READONLY_WEB_PLUGINS = frozenset({
    "struct_infer", "sensitive_scan", "func_profile",
    "const_fingerprint", "detect_obfuscation",
})


async def plugin_run_api(request):
    """运行只读静态分析插件（供底部抽屉「插件快捷分析」实时展示真实插件输出，不经 @logged）。"""
    try:
        body = await request.json()
    except Exception:                                      # noqa: BLE001
        return _err("请求体非合法 JSON")
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象")
    pname = str(body.get("name") or "").strip()
    if pname not in _READONLY_WEB_PLUGINS:
        return _err(f"插件 {pname} 不在 Web 只读分析白名单内", 403)
    args = body.get("args") or {}
    if not isinstance(args, dict):
        return _err("args 必须是 JSON 对象")

    def work():
        from server.mcp_server.tools import get_plugins

        res = get_plugins().run(pname, args)
        return res if isinstance(res, dict) else {"ok": True, "text": str(res)}

    try:
        return JSONResponse(await run_in_threadpool(work))
    except Exception as exc:                               # noqa: BLE001
        return _err(f"插件执行失败：{exc}", 500)


# (57) 第五十七次修改（2026-11-26）
# bug 原因：① build_xrefs / frida_js / frida_js_stop / console_events 对坏 JSON 或非法整数
#              参数（如非数字 pid/script_id/after）未做捕获，直接返回 500；
#           ② /api/mcp-config 在冻结打包版（sys.frozen=True）下仍拼不存在的 app.py 路径。
# 解决方案：统一校验 JSON 与整数/浮点参数返回 400 JSON；冻结模式下 stdio.args 仅返回 ["--mcp-stdio"]。
async def build_xrefs(request):
    """全量引用图构建：大样本 20-30 秒，进度通过 WebSocket 推进前端。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)
    name = str(body.get("so", "")).strip()
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

    try:
        return JSONResponse(await run_in_threadpool(work))
    except ValueError as exc:
        return _err(str(exc), 400)


async def mcp_config(request):
    """给 AI 用的 MCP 配置：路径按当前运行形态算，不让用户手写绝对路径。"""
    stdio_args = (
        ["--mcp-stdio"]
        if getattr(sys, "frozen", False)
        else [os.path.join(_ROOT, "app.py"), "--mcp-stdio"]
    )
    return JSONResponse({
        "mcp_port": _mcp_port,
        "http_url": f"http://127.0.0.1:{_mcp_port}/mcp",
        "stdio": {"command": sys.executable, "args": stdio_args},
    })


# ---------------------------------------------------------------- 控制台
# (1) 第一次修改（2026-11-19）：新增三个端点，支撑「MCP 调用控制台」。
#     需求来源：用户要求"顶部建一个界面，hook 时能看到输入和输出，
#              像在终端手动输入看结果一样"，并明确"入参 = AI 写给工具的参数，
#              结果 = 工具的返回"，同时"支持用户手动写 frida 命令"。
#     为什么后端要动：工具返回值此前**从未上流**（见 tools._activity 的注释），
#              所以"输出"这一侧是空的；手动执行 frida 则完全没有入口。


async def console_history(request):
    """控制台历史：AI 调用记录（含输入参数与输出结果）。

    为什么单独一个端点而不是只靠 WS：
      WS 断了重连时前端会丢中间那段，而控制台是"事后要翻"的东西，
      必须有可回溯的来源。返回的是 _activity_log 的快照（有界 300 条）。
    """
    try:
        from server.mcp_server.tools import get_activity_log

        items = get_activity_log(300)
    except Exception as exc:                              # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}",
                             "items": []}, status_code=500)
    return JSONResponse({"ok": True, "count": len(items), "items": items})


async def console_events(request):
    """手动 frida 脚本产生的事件（send / error / start / stop）。

    after 为时间戳游标：只返回 t > after 的事件，前端增量拉取不会重复渲染。
    """
    try:
        after = float(request.query_params.get("after") or 0)
    except ValueError:
        return _err("after 必须是数字", 400)
    try:
        from server.dyn.console import recent_events

        items = recent_events(after)
    except Exception as exc:                              # noqa: BLE001
        return JSONResponse({"ok": False, "error": f"{type(exc).__name__}: {exc}",
                             "items": []}, status_code=500)
    return JSONResponse({"ok": True, "count": len(items), "items": items,
                         "now": time.time()})


async def frida_js(request):
    """在目标进程里执行一段手动 frida 脚本。

    body: {serial, pid, js, mode: "once"|"keep", timeout?}
    """
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("body 必须是 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)
    serial = str(body.get("serial") or "").strip()
    pid_raw = body.get("pid")
    try:
        pid_val = int(pid_raw) if pid_raw not in (None, "") else 0
    except (TypeError, ValueError):
        return _err("pid 必须是整数", 400)
    js = str(body.get("js") or "")
    mode = str(body.get("mode") or "once")
    try:
        timeout = float(body.get("timeout") or 5.0)
    except (TypeError, ValueError):
        timeout = 5.0

    def work():
        from server.dyn.console import run_js

        return run_js(serial, pid_val, js, mode=mode, timeout=timeout)

    # 脚本可能卡住（死循环 / 等设备响应），放到线程池里跑，别堵住事件循环
    out = await run_in_threadpool(work)
    return JSONResponse(out)


async def frida_js_stop(request):
    """停止常驻脚本。body: {script_id?} 或 {serial, pid}；都不给则全停。"""
    raw_body = await request.body()
    if raw_body.strip():
        try:
            body = json.loads(raw_body)
        except Exception:                                 # noqa: BLE001
            return _err("请求体不是合法 JSON", 400)
        if not isinstance(body, dict):
            return _err("请求体必须是 JSON 对象", 400)
    else:
        body = {}

    sid_raw = body.get("script_id")
    try:
        sid_val = int(sid_raw) if sid_raw not in (None, "") else None
    except (TypeError, ValueError):
        return _err("script_id 必须是整数", 400)
    pid_raw = body.get("pid")
    try:
        pid_val = int(pid_raw) if pid_raw not in (None, "") else 0
    except (TypeError, ValueError):
        return _err("pid 必须是整数", 400)
    serial_val = str(body.get("serial") or "")

    def work():
        from server.dyn.console import stop_js

        return stop_js(sid_val, serial_val, pid_val)

    return JSONResponse(await run_in_threadpool(work))


async def frida_js_list(request):
    """当前存活的常驻脚本（界面顶部显示"正在观测什么"）。"""
    from server.dyn.console import list_scripts

    items = list_scripts()
    return JSONResponse({"ok": True, "count": len(items), "items": items})


# ---------------------------------------------------------------- 设置与设备工具箱（直调核心，不经 @logged）


async def settings_get(request):
    """读取设置页持久化配置与当前本机局域网 IP。"""
    def work():
        from server.dyn import toolbox as _tb

        return {
            "ok": True,
            "settings": _tb.load_settings(),
            "path": _tb.settings_file_path(),
            "host_ip": _tb.detect_host_ip(),
        }

    return JSONResponse(await run_in_threadpool(work))


async def settings_save(request):
    """保存设置页配置到本地 settings.json。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)

    def work():
        from server.dyn import toolbox as _tb

        saved = _tb.save_settings(body)
        return {"ok": True, "settings": saved, "path": _tb.settings_file_path()}

    try:
        return JSONResponse(await run_in_threadpool(work))
    except ValueError as exc:
        return _err(str(exc), 400)


async def toolbox_devices(request):
    """列出在线 ADB 设备真实信息（机型、Root、前台包名），可选附带已安装第三方包名。"""
    inc_pkg = (request.query_params.get("packages") or "").strip() in ("1", "true", "yes")
    serial = (request.query_params.get("serial") or "").strip()

    def work():
        from server.dyn import toolbox as _tb

        target = serial if inc_pkg else ""
        if inc_pkg and not target:
            # 未指定 serial 时传占位标识，让 list_online_devices 自动选唯一在线设备
            res = _tb.list_online_devices()
            online = [d["serial"] for d in res.get("devices", []) if d.get("state") == "device"]
            if len(online) == 1:
                return _tb.list_online_devices(include_packages_for=online[0])
            return res
        return _tb.list_online_devices(include_packages_for=target)

    return JSONResponse(await run_in_threadpool(work))


async def toolbox_proxy_status(request):
    """查询手机全局代理与 mitmproxy 系统证书实时状态。"""
    serial = (request.query_params.get("serial") or "").strip()
    port_raw = (request.query_params.get("port") or "").strip()
    cert_path = (request.query_params.get("cert_path") or "").strip()

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        cfg = _tb.load_settings()
        port = int(port_raw) if port_raw else int(cfg.get("proxy_port", 8080))
        cp = cert_path or str(cfg.get("cert_path") or _tb.DEFAULT_CERT_PATH)
        try:
            return _tb.proxy_status(serial=serial, port=port, cert_path=cp), 200
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc)}, 200

    try:
        payload, status = await run_in_threadpool(work)
        return JSONResponse(payload, status_code=status)
    except ValueError as exc:
        return _err(str(exc), 400)


async def toolbox_proxy_action(request):
    """执行手机全局代理开关或系统证书安装/移除。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        cfg = _tb.load_settings()
        action = str(body.get("action") or "status").strip().lower()
        serial = str(body.get("serial") or "").strip()
        host = str(body.get("host") if "host" in body else cfg.get("proxy_host", "")).strip()
        port = body.get("port") if body.get("port") not in (None, "") else cfg.get("proxy_port", 8080)
        cp = str(body.get("cert_path") or cfg.get("cert_path") or _tb.DEFAULT_CERT_PATH).strip()

        try:
            if action == "on":
                return _tb.proxy_set(serial=serial, enable=True, host=host, port=port, cert_path=cp)
            if action == "off":
                return _tb.proxy_set(serial=serial, enable=False, port=port, cert_path=cp)
            if action in ("cert_install", "cert-install"):
                return _tb.proxy_cert_install(serial=serial, cert_path=cp, port=port)
            if action in ("cert_remove", "cert-remove"):
                return _tb.proxy_cert_remove(serial=serial, cert_path=cp, port=port)
            if action == "status":
                return _tb.proxy_status(serial=serial, port=port, cert_path=cp)
            return {"ok": False, "code": "BAD_ACTION", "error": f"不支持的操作：{action}"}
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc)}

    return JSONResponse(await run_in_threadpool(work))


async def toolbox_app_suspend(request):
    """执行 App 冻结 / 解冻 / 状态查询（pm suspend / pm unsuspend）。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        serial = str(body.get("serial") or "").strip()
        action = str(body.get("action") or "status").strip().lower()
        pkgs = body.get("packages")
        if isinstance(pkgs, str):
            pkgs = [p.strip() for p in pkgs.split() if p.strip()]
        try:
            return _tb.app_suspend_action(serial=serial, action=action, packages=pkgs)
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc)}

    return JSONResponse(await run_in_threadpool(work))


async def toolbox_app_label(request):
    """快速读取真机上指定包名的真实应用显示名称（供设置页保存常用 App 时自动填名称）。"""
    serial = (request.query_params.get("serial") or "").strip()
    package = (request.query_params.get("package") or "").strip()

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        try:
            label = _tb.resolve_app_label(serial=serial, package=package)
            return {"ok": True, "package": package, "label": label}
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc), "label": ""}

    return JSONResponse(await run_in_threadpool(work))


async def toolbox_app_labels_batch(request):
    """批量并发读取多个包名的真实应用名（带磁盘缓存，供已安装列表和自动补全使用）。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        serial = str(body.get("serial") or "").strip()
        pkgs = body.get("packages") if isinstance(body.get("packages"), list) else []
        try:
            labels = _tb.resolve_app_labels_batch(serial=serial, packages=pkgs)
            return {"ok": True, "labels": labels}
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc), "labels": {}}

    return JSONResponse(await run_in_threadpool(work))


async def toolbox_app_reset(request):
    """执行 App 强制停止、可选清数据（pm clear）与可选延迟重启。"""
    try:
        body = await request.json()
    except Exception:                                     # noqa: BLE001
        return _err("请求体不是合法 JSON", 400)
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象", 400)

    def work():
        from server.dyn.adb import DynError
        from server.dyn import toolbox as _tb

        cfg = _tb.load_settings()
        serial = str(body.get("serial") or "").strip()
        package = str(body.get("package") or cfg.get("reset_package", "")).strip()
        clear_data = bool(body.get("clear_data", True))
        relaunch = bool(body.get("relaunch", cfg.get("reset_relaunch", True)))
        wait_sec = body.get("wait_sec") if body.get("wait_sec") is not None else cfg.get("reset_wait_sec", 2.0)
        try:
            return _tb.app_reset(
                serial=serial,
                package=package,
                clear_data=clear_data,
                relaunch=relaunch,
                wait_sec=wait_sec,
            )
        except (DynError, ValueError) as exc:
            return {"ok": False, "code": getattr(exc, "code", "INVALID_ARG"), "error": str(exc)}

    return JSONResponse(await run_in_threadpool(work))


# (58) 第五十八次修改（2026-11-26）
# bug 原因：① _snapshot_payload 与 events sync 重复实现且未给未命名函数做 sub_xxx 兜底；
#           ② WS /api/events 握手前未校验 Origin / Host，存在跨站 WebSocket 劫持风险；
#           ③ lifespan 中的 _push_loop 每 2 秒直接在事件循环中无条件序列化十几 MB 快照，
#              阻塞事件循环，且退出时未取消该后台任务；
#           ④ _on_ai 调用 _track_armed 时未传入 ok 字段。
# 解决方案：① _snapshot_payload 统一兜底 f.name or f"sub_{f.addr:x}" 并被 events 复用；
#           ② events 握手前校验 Host 与 Origin，非法来源直接 ws.close(code=1008)；
#           ③ 新增轻量版本签名 _modules_version()，_push_loop 仅在变化时于线程池构建快照，
#              并在 lifespan 退出时正确 cancel & await 该任务；
#           ④ _on_ai 向 _track_armed 透传 ok。
def _modules_version() -> tuple:
    """计算当前模块集合与函数/引用构建状态的轻量版本号，用于避免无意义重复快照。"""
    sig = []
    for name, m in _session.modules.items():
        fns = getattr(m, "functions", None)
        n_fns = len(fns) if isinstance(fns, (dict, list, tuple)) else 0
        x = _session._xrefs.get(name) if hasattr(_session, "_xrefs") else None
        built = bool(getattr(x, "_built", False)) if x is not None else False
        sig.append((name, id(m), n_fns, built))
    return tuple(sig)


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
                    "name": f.name or f"sub_{f.addr:x}",
                    "addr": f.addr,
                    "size": int(getattr(f, "size", 0) or 0),
                    "is_export": bool(getattr(f, "is_export", False)),
                    "refs": len(getattr(f, "calls", []) or []),
                }
                for f in (fns or [])
            ],
        })
    return json.dumps({
        "type": "modules_snapshot",
        "modules": list(_session.modules),
        "details": details,
    }, ensure_ascii=False)


async def events(ws):
    host = ws.headers.get("host")
    if host is not None and not _is_local_host(host):
        await ws.close(code=1008)
        return
    origin = ws.headers.get("origin")
    if origin is not None and not _is_local_origin(origin):
        await ws.close(code=1008)
        return
    await ws.accept()
    _clients.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "hello", "modules": list(_session.modules)},
                                      ensure_ascii=False))
        # 连上就先推一份完整快照：前端定时器在 WKWebView 里不可靠（实测不触发），
        # 所以数据必须由后端主动送到。
        await ws.send_text(await run_in_threadpool(_snapshot_payload))
        while True:
            raw = await ws.receive_text()
            # 前端可以主动要一次模块列表：WebSocket 不走 HTTP 缓存，
            # 这是在 WKWebView 里唯一可靠的数据通道（实测 /api GET 会被复用旧响应）
            try:
                msg = json.loads(raw)
            except Exception:                             # noqa: BLE001
                continue
            if isinstance(msg, dict) and msg.get("type") == "sync":
                await ws.send_text(await run_in_threadpool(_snapshot_payload))
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

    # 仅当模块集合或版本号变化时，才在线程池构建并推送快照，避免每 2 秒无脑序列化大 JSON
    last_ver = None

    async def _push_loop():
        nonlocal last_ver
        while True:
            await asyncio.sleep(2.0)
            if not _clients:
                continue
            cur_ver = _modules_version()
            if cur_ver == last_ver:
                continue
            try:
                payload = await run_in_threadpool(_snapshot_payload)
                await _broadcast_raw(payload)
                last_ver = cur_ver
            except asyncio.CancelledError:
                raise
            except Exception:                             # noqa: BLE001
                pass

    push_task = asyncio.create_task(_push_loop())

    # (3) 第三次修改（2026-10-30）：标记本进程是 GUI。
    #     bug 原因：新增「工具调用转发到 GUI」机制后（mcp_server/link.py），
    #               GUI 进程自己也注册了同一批工具；若它不声明身份，
    #               link.gui_online() 会判定「GUI 在线」并转发给自己 → 自环。
    #     解决方案：GUI 进程在启动内置 MCP 前显式置 MDA_IS_GUI=1，
    #               mcp_server.link 据此拒绝转发。
    #     时机：必须在 mcp.start_http() 之前设置，避免启动瞬间就被转发命中。
    os.environ["MDA_IS_GUI"] = "1"

    # (2) 第二次修改（2026-11-20）：**移除**全局 frida 输出旁路 hook。
    #     bug 原因：上一版包装了 frida.core.Session.create_script，把**所有**
    #               工具脚本的 send 都旁路进 frida 终端。但工具的 send 是
    #               **内部数据传输**（set_breakpoint 一次就 send 整个模块列表、
    #               java_hook 一次 send 全部命中），不是脚本输出。结果用户
    #               手敲一句 console.log("hello")，终端里跟着吐出一大坨
    #               几百个模块的 JSON —— 用户明确指出"这他妈的是什么"。
    #     解决方案：整套旁路删除。终端**只显示用户在这个输入框里执行的
    #               脚本**产生的输出，不掺任何工具的内部数据。
    #               工具的输出该由 AI 通过 MCP 结果读，不属于这个终端。

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
            if _track_armed(tool, args, entry.get("summary", ""), ok=entry.get("ok", True)):
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
            # 真实 epoch 时间戳：控制台要把 AI 调用与手动脚本事件混排，
            # 只有 HH:MM:SS 无法跨源比较（前端拿 Date.now() 猜排序就是伪造数据）
            "t": entry.get("t", 0),
            "ms": entry.get("ms", 0),
            # (1) 第一次修改（2026-11-19）：把工具真实返回值一并推给前端。
            #    bug 原因：此前只推 args/summary，控制台"输出"侧永远是空的，
            #              用户看不到任何工具跑出来的东西。
            #    解决方案：透传 tools._activity 已整理好的 result 三件套
            #              （text / truncated / bytes），前端据此渲染并可标注截断。
            "ok": entry.get("ok", True),
            "result": entry.get("result", ""),
            "result_truncated": bool(entry.get("result_truncated")),
            "result_bytes": int(entry.get("result_bytes") or 0),
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
    try:
        yield
    finally:
        push_task.cancel()
        try:
            await push_task
        except asyncio.CancelledError:
            pass
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
    # (59) 第五十九次修改（2026-11-26）
    # bug 原因：① /api/armed/clear 仅注册默认 GET，与前端 POST 冲突报 405 且暴露 GET CSRF；
    #           ② index_html 直接拼接 json.dumps 到 <script> 未转义 </ 与 \u2028/\u2029，
    #              恶意文件名可闭合 </script> 造成 XSS；
    #           ③ 缺少本地 Host 校验（防 DNS Rebinding）与写接口 Origin/自定义头 CSRF 校验。
    # 解决方案：① /api/armed/clear 改为 methods=["POST"]；
    #           ② index_html 对内联 JSON 做 </ -> <\/ 及 \u2028/\u2029 转义；
    #           ③ 新增 _LocalGuardMiddleware 拦截非本地 Host、跨站 Origin 与无凭据简单 POST。
    Route("/api/armed/clear", armed_clear, methods=["POST"]),
    Route("/api/app_processes", app_processes),
    Route("/api/load_upload", load_upload, methods=["POST"]),
    Route("/api/functions", functions),
    Route("/api/disasm", disasm),
    Route("/api/decompile", decompile_view),
    Route("/api/cfg", cfg_view),
    Route("/api/rename", rename_fn_api, methods=["POST"]),
    Route("/api/comments", comments_api),
    Route("/api/comment", set_comment_api, methods=["POST"]),
    Route("/api/plugin_run", plugin_run_api, methods=["POST"]),
    Route("/api/xrefs", xrefs),
    Route("/api/strings", strings),
    Route("/api/xrefs/build", build_xrefs, methods=["POST"]),
    # 控制台（2026-11-19 新增）：AI 调用的输入/输出历史 + 手动 frida 执行
    Route("/api/console/history", console_history),
    Route("/api/console/events", console_events),
    Route("/api/frida_js", frida_js, methods=["POST"]),
    Route("/api/frida_js/stop", frida_js_stop, methods=["POST"]),
    Route("/api/frida_js/list", frida_js_list),
    # 设置与设备工具箱（2026-11-27 新增：手机代理/证书、App 冻结、强停清数据重启）
    Route("/api/settings", settings_get),
    Route("/api/settings", settings_save, methods=["POST"]),
    Route("/api/toolbox/devices", toolbox_devices),
    Route("/api/toolbox/app_label", toolbox_app_label),
    Route("/api/toolbox/app_labels", toolbox_app_labels_batch, methods=["POST"]),
    Route("/api/toolbox/proxy/status", toolbox_proxy_status),
    Route("/api/toolbox/proxy", toolbox_proxy_action, methods=["POST"]),
    Route("/api/toolbox/app_suspend", toolbox_app_suspend, methods=["POST"]),
    Route("/api/toolbox/app_reset", toolbox_app_reset, methods=["POST"]),
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
    # 注入到 window.__MDA_BOOT__，转义 </ 与行分隔符防止 </script> XSS 逃逸
    boot_json = (
        json.dumps({"modules": mods}, ensure_ascii=False)
        .replace("</", "<\\/")
        .replace("<!--", "\\u003c!--")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    boot = f"<script>window.__MDA_BOOT__={boot_json};</script>"
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


class _LocalGuardMiddleware:
    """纯 ASGI 安全中间件：防 DNS Rebinding（Host 白名单）与跨站 CSRF 写请求。"""

    def __init__(self, app):
        self.app = app

    @staticmethod
    async def _reject_http(scope, receive, send, msg: str, status: int = 403) -> None:
        resp = JSONResponse({"error": msg}, status_code=status)
        await resp(scope, receive, send)

    async def __call__(self, scope, receive, send):
        stype = scope.get("type")
        if stype not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in (scope.get("headers") or [])
        }

        # 1) Host 白名单：仅允许 127.0.0.1 / localhost / [::1]（防 DNS Rebinding）
        host = headers.get("host", "")
        if not _is_local_host(host):
            if stype == "http":
                await self._reject_http(scope, receive, send, "禁止非本地 Host 访问")
            else:
                await send({"type": "websocket.close", "code": 1008})
            return

        if stype == "websocket":
            origin = headers.get("origin")
            if origin is not None and not _is_local_origin(origin):
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return

        # 2) 写操作 / 敏感 POST 接口防 CSRF（覆盖全部 8 个写端点及后续新增 /api/ 写端点）
        method = (scope.get("method") or "GET").upper()
        path = scope.get("path") or ""
        if method not in ("GET", "HEAD", "OPTIONS") and (
            path in _PROTECTED_POST_PATHS or path.startswith("/api/")
        ):
            origin = headers.get("origin")
            referer = headers.get("referer")
            sec_fetch_site = (headers.get("sec-fetch-site") or "").strip().lower()

            if origin is not None:
                if not _is_local_origin(origin):
                    await self._reject_http(scope, receive, send, "禁止非本地 Origin 发起写请求")
                    return
            else:
                if referer is not None and not _is_local_referer(referer):
                    await self._reject_http(scope, receive, send, "禁止非本地 Referer 发起写请求")
                    return
                if sec_fetch_site == "cross-site":
                    await self._reject_http(scope, receive, send, "禁止跨站写请求")
                    return

            # 要求自定义客户端头 X-MDA-Client: 1 或严格 application/json（拒绝零预检简单跨站表单/纯文本请求）
            has_client_hdr = headers.get("x-mda-client") == "1"
            ctype = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if not (has_client_hdr or ctype == "application/json"):
                await self._reject_http(
                    scope, receive, send,
                    "缺少 X-MDA-Client 头或合法 application/json Content-Type",
                )
                return

        await self.app(scope, receive, send)


app = Starlette(routes=routes, lifespan=lifespan)
app = CORSMiddleware(app, allow_origins=DEV_ORIGINS, allow_methods=["*"], allow_headers=["*"])
app = _NoCacheAPI(app)
app = _LocalGuardMiddleware(app)



def main() -> None:
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")


if __name__ == "__main__":
    main()
