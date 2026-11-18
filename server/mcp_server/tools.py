"""MCP 服务：把分析能力暴露给 AI。

设计：MCP 工具与 GUI 调用同一个 Session，保证 AI 看到的
与人工看到的一致。工具分三组：
- 会话/静态：加载 so、函数列表、反汇编、xref、字符串、跨 so 调用链
- 动态：设备、进程、断点、内存、分析等待
- 脚本：AI 提交 Python/IDC 片段直接操作 Session（进阶）

AI 操作日志：所有工具调用经 _logged 中间件写入 _activity_log，
GUI 的 Output 面板订阅显示——人工能实时看到 AI 在干什么。

依赖 core.session / dyn.*。
"""
from __future__ import annotations

import json
import time

from mcp.server.mcpserver import MCPServer

from server.version import __version__

from server.core.session import Session
from server.core.session import _strip_version_tag as _core_strip_version_tag
from server.core.session import match_name as _core_match_name

server = MCPServer(
    name="mda",
    title="MDA - Multi-so Dynamic Analyzer",
    description=(
        "多 so 静态+动态分析工具。支持跨 so 调用链、字符串引用还原、"
        "adb/frida 动态断点与内存读取。"
    ),
    version=__version__,   # 版本号唯一来源见 version.py
)

# 单例会话：MCP 与 GUI 共享
_session = Session()

# UI 同步回调：MCP 侧发生"有副作用"的操作后通知 GUI 刷新视图。
# GUI 启动时注册（_register_ui_sync），MCP/stdio 模式下无监听者则静默。
_ui_sync_listeners: list = []


def on_ui_sync(cb) -> None:
    """GUI 注册 UI 同步回调。cb(event: dict)。"""
    _ui_sync_listeners.append(cb)


def _notify_ui(event: dict) -> None:
    """广播 UI 同步事件。事件形如 {"type": "so_loaded", "so_name": ...}。"""
    for cb in _ui_sync_listeners:
        try:
            cb(event)
        except Exception:
            pass

# AI 活动日志：GUI 订阅显示。结构 {ts, tool, args, summary, ms}
_activity_log: list[dict] = []
_log_listeners: list = []  # 回调列表，GUI 注册


def on_activity(cb) -> None:
    """GUI 注册监听：每条 AI 活动回调 cb(entry dict)。"""
    _log_listeners.append(cb)


def _activity(tool: str, args: dict, summary: str, ms: float) -> None:
    """记录一条 AI 活动并广播（日志行 + UI 回放事件）。"""
    entry = {
        "ts": time.strftime("%H:%M:%S"),
        "tool": tool,
        "args": args,
        "summary": summary,
        "ms": round(ms, 1),
    }
    _activity_log.append(entry)
    for cb in _log_listeners:
        try:
            cb(entry)
        except Exception:
            pass
    # UI 回放：把 AI 调用翻译成"人在 GUI 上的等价操作"并驱动视图
    _emit_ui_replay(tool, args)


def _emit_ui_replay(tool: str, args: dict) -> None:
    """把 AI 的工具调用翻译为 GUI 可视化的等价操作事件。

    人工操作视图会发生什么，AI 调用时就同步发生什么——
    "AI 像人一样操作 MDA"的核心机制。
    """
    if not isinstance(args, dict):
        return
    try:
        _emit_ui_replay_inner(tool, args)
    except Exception:                                     # noqa: BLE001
        # UI 回放是**副作用**：它失败绝不能影响工具本身的成败。
        # 尤其在成功路径上——工具已经执行完（可能已经下好断点），
        # 这里抛异常会让 AI 以为失败并重试，造成重复副作用。
        pass


def _emit_ui_replay_inner(tool: str, args: dict) -> None:
    """_emit_ui_replay 的实际实现（外层负责兜异常）。"""
    # 修复运算符优先级隐患：原写法 `a or b if cond else None` 会被解析为
    # `(a or b) if cond else None`，语义正确但极易误读，显式拆开。
    so = args.get("so_name")
    if so is None:
        so = args.get("name")
    addr = args.get("addr")
    ev = None
    if tool == "load_so":
        return  # 已有 so_loaded 事件
    elif tool == "disassemble" and so and addr is not None:
        ev = {"type": "goto", "so_name": so, "addr": _as_int_addr(addr),
              "why": "disassemble"}
    elif tool == "decompile" and so and addr is not None:
        ev = {"type": "goto", "so_name": so, "addr": _as_int_addr(addr),
              "why": "decompile", "tab": "伪代码"}
    elif tool == "call_chain" and so and addr is not None:
        ev = {"type": "goto", "so_name": so, "addr": _as_int_addr(addr),
              "why": "call_chain", "tab": "伪代码"}
    elif tool == "list_functions" and so:
        ev = {"type": "filter_funcs", "so_name": so, "keyword": args.get("keyword", ""),
              "why": "list_functions"}
    elif tool == "list_strings" and so:
        ev = {"type": "show_strings", "so_name": so, "keyword": args.get("keyword", "")}
    elif tool == "xrefs_to" and so and addr is not None:
        ev = {"type": "show_xrefs", "so_name": so, "addr": _as_int_addr(addr)}
    elif tool == "imports" and so:
        ev = {"type": "show_tab", "tab": "导入"}
    elif tool == "exports" and so:
        ev = {"type": "show_tab", "tab": "导出"}
    elif tool == "rename_function" and so:
        ev = {"type": "renamed", "so_name": so,
              "addr": _as_int_addr(args.get("addr", 0)) or 0,
              "old": "", "new": args.get("new_name", "")}
    if ev:
        _notify_ui(ev)


def get_activity_log(limit: int = 200) -> list[dict]:
    """取最近活动（GUI 启动晚于 AI 操作时补看）。"""
    return _activity_log[-limit:]


def get_session() -> Session:
    """供 GUI/脚本引擎复用同一个会话实例。"""
    return _session


# 插件管理器单例（首次访问时扫描加载）
_plugin_mgr = None


def get_plugins():
    """插件管理器，惰性初始化。"""
    global _plugin_mgr
    if _plugin_mgr is None:
        from server.core.plugins import PluginManager

        _plugin_mgr = PluginManager(_session, log=lambda t: print(t, flush=True))
        _plugin_mgr.scan_and_load()
    return _plugin_mgr


import functools


# ---------------- 运行环境（随每次动态调用一起返回） ----------------
# 为什么不是"再提供一个工具让模型去查"：
#   模型看不到屏幕。它调 set_breakpoint / java_hook / perf_watch 的时候，
#   完全不知道目标 App 此刻是不是在前台。不在前台时，很多代码路径根本不会
#   被执行（渲染、网络、生命周期），断点装上了也永远不命中——模型会误判成
#   "这段代码没执行"或更糟，"钩子失效"。
#   把环境信息塞进**每次动态调用的返回值**，模型读到结果的同时就知道
#   "我刚才操作的对象在前台吗"，不需要额外一次来回。


# ---------------- 运行环境（随每次动态调用一起返回） ----------------
# 为什么不是"再提供一个工具让模型去查"：
#   模型看不到屏幕。它调 set_breakpoint / java_hook / ui_click 的时候，
#   完全不知道目标 App 此刻是不是在前台。不在前台时，很多代码路径根本不会
#   被执行（渲染、网络、生命周期），断点装上了也永远不命中——模型会误判成
#   "这段代码没执行"或更糟，"钩子失效"。
#   把环境信息塞进**每次动态调用的返回值**，模型读到结果的同时就知道
#   "我刚才操作的对象在前台吗"，不需要额外一次来回。
#
# 实现已抽到 server/dyn/runtime_env.py（独立、可复用）：
#   新增动态工具只要签名里带 serial，`@logged()` 就会自动注入 env，
#   不需要在工具里写任何一行代码。


def _env_facts(serial: str, pid=None, package: str = "") -> dict:
    """兼容薄封装：转发到 runtime_env.env_facts。"""
    from server.dyn.runtime_env import env_facts as _f

    return _f(serial, pid, package=package)


def _inject_env(result, call_args: dict, tool_name: str = ""):
    """兼容薄封装：转发到 runtime_env.inject_env。"""
    from server.dyn.runtime_env import inject_env as _i

    return _i(result, call_args, tool_name=tool_name)


def logged(tool_name: str | None = None):
    """AI 活动日志装饰器：记录工具调用并广播给 GUI。

    GUI 通过 on_activity 注册回调，Output 面板实时显示
    AI 在做什么（调了什么工具、关键参数、耗时）。

    BUG-7 修复：异常不再裸抛（MCP 框架会吞成无信息量的
    "Error executing tool X"），转为 isError=True 的结果返回，
    真实异常类型与堆栈首行透传给 AI 便于自纠。
    """
    def deco(fn):
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # 用单调时钟：墙钟会被 NTP/手动校时改变，差值会出负数
            t0 = time.monotonic()
            # bug 原因：MCP 框架以**关键字**方式调用工具函数，位置参数元组
            # args 恒为空，此前 dict(zip(sig_keys, args)) if args else {} 得到
            # 空字典 → UI 回放拿不到 so_name/addr，AI 操作无法可视化。
            # 解决：合并位置参数与关键字参数，只保留函数签名内的键。
            sig_keys = fn.__code__.co_varnames[:fn.__code__.co_argcount]
            call_args: dict = dict(zip(sig_keys, args)) if args else {}
            call_args.update({k: v for k, v in kwargs.items() if k in sig_keys})

            # (3) 第三次修改（2026-10-30）：GUI 在线时把调用转发到 GUI 进程执行，
            #     从根源消除「AI 在一个进程分析、界面另一个进程空着」的双会话。
            #     bug 原因：_session 是**每进程一个**模块级单例，stdio 进程与
            #               GUI 进程天然各持一份；旧 proxy 只在启动时探测一次，
            #               GUI 后启动即永久不同步（实测 MCP 侧 list_modules 得
            #               2 个 so，而 GUI /api/modules 为 []、lsof 也证实 GUI
            #               进程从未打开那两个 so 文件）。
            #     解决方案：调用前经 mcp_server.link 判定 GUI 是否在线；在线则
            #               转发执行并原样返回其文本结果，离线才本地执行。
            #               判定在**每次调用**前进行，故降级状态可自愈。
            #     注意：GUI 进程自身设 MDA_IS_GUI=1，link 会拒绝转发，避免自环。
            from server.mcp_server import link

            if link.should_forward():
                fw = link.forward(name, call_args)
                if fw is not None:
                    ms = (time.monotonic() - t0) * 1000
                    parts = [
                        f"{k}={str(v)[:60]}"
                        for k, v in call_args.items()
                        if v not in (None, "")
                    ]
                    _activity(name, call_args, ", ".join(parts) or "", ms)
                    return fw

            try:
                result = fn(*args, **kwargs)
                ms = (time.monotonic() - t0) * 1000
                parts = [
                    f"{k}={str(v)[:60]}"
                    for k, v in call_args.items()
                    if v not in (None, "")
                ]
                _activity(name, call_args, ", ".join(parts) or "", ms)
                # 动态调用统一附上运行环境（前台是谁 / 目标是否在前台）
                return _inject_env(result, call_args, tool_name=name)
            except Exception as e:
                ms = (time.monotonic() - t0) * 1000
                import traceback

                tb = traceback.format_exc()
                _activity(name, call_args, f"✗ {type(e).__name__}: {str(e)[:80]}", ms)
                # 透传真实异常给 AI（isError 标记 + 类型/消息/堆栈尾行）
                from mcp.types import CallToolResult, TextContent

                # (119) 失败也要带 env：见上方注释。失败时最需要知道目标状态。
                err_text = json.dumps({
                    "error": f"{type(e).__name__}: {e}",
                    "tool": name,
                    "traceback_tail": tb.strip().splitlines()[-3:],
                }, ensure_ascii=False)
                err_text = _inject_env(err_text, call_args, tool_name=name)

                return CallToolResult(
                    content=[TextContent(text=err_text)],
                    is_error=True,  # mcp 2.x 字段名（isError 是 1.x 的）
                )
        return wrapper
    return deco


def _j(obj) -> str:
    """统一 JSON 输出，dataclass 自动转 dict。"""
    return json.dumps(obj, ensure_ascii=False, indent=2, default=lambda o: o.__dict__)


# ---------------- 地址换算（自动，不让人手算） ----------------
# 反复出现的痛点：人说 "0x2fd794"，工具要十进制 3135380，手算必错。
# 这里统一提供「一个地址的全部常见表示」，AI 和人都不用再换算。
#
# 设计：**同时**给出 hex / dec，以及这个地址落在哪个函数（如果落在函数内，
# 才算真正有意义——否则只是数据区的一个位置）。


def _addr_facts(so_name: str, addr: int) -> dict:
    """把一个地址扩展成「所有基础表示 + 它是什么」。

    返回的字段对 AI 和人都有用：
      hex / dec         —— 两种写法，直接复制即可
      function          —— 所在函数的入口（hex/dec/name）；不在函数内则为 None
      offset_in_fn      —— 相对函数入口的偏移
      section           —— 落在哪个段
      is_function_entry —— 是否正好是某个函数的入口
      nearby_functions  —— 不是入口时，给出前面最近的一个（很常见：
                           人给的是函数中间的地址）
    """
    out = {
        "hex": hex(addr),
        "dec": addr,
    }
    try:
        so = _session.get(so_name)
    except Exception:                                     # noqa: BLE001
        return out

    sec = so.section_at(addr)
    out["section"] = sec.name if sec else None

    fn = so.function_at(addr)
    if fn is not None:
        # (3) 第三次修改（2026-11-18）：把函数区间的四个数都吐出来。
        #     bug 原因：反馈里使用者按 IDA 直觉取 `fn.start` 抛 AttributeError，
        #               而 JSON 侧原本只有入口地址、没有区间大小——判断
        #               "这个地址是不是在函数中段"还得自己减。
        #     解决方案：Function 侧加只读别名 start；JSON 侧一并给
        #               start/end/size，与 Function 字段同名可对照。
        out["function"] = {
            "name": fn.name or f"sub_{fn.addr:x}",
            "hex": hex(fn.addr),
            "dec": fn.addr,
            "start": hex(fn.start),
            "end": hex(fn.end),
            "size": hex(fn.size),
        }
        out["offset_in_fn"] = hex(addr - fn.addr)
        out["is_function_entry"] = (addr == fn.addr)
    else:
        # 不在任何函数里：给前面最近的一个，方便判断"是不是我算错了"
        prev = None
        for a in so.functions.keys():
            if a <= addr and (prev is None or a > prev):
                prev = a
        out["function"] = None
        out["is_function_entry"] = False
        if prev is not None:
            pf = so.functions.get(prev)
            out["nearby_function"] = {
                "name": (pf.name if pf else "") or f"sub_{prev:x}",
                "hex": hex(prev),
                "dec": prev,
                "offset": hex(addr - prev),
            }
    return out


# ---------------- 插件 ----------------


@server.tool()
@logged()
def list_plugins() -> str:
    """列出已加载插件及用法。写新插件到 plugins/*.py 即自动生效。"""
    return _j(get_plugins().describe())


@server.tool()
@logged()
def plugin_run(name: str, args: str = "{}") -> str:
    """执行插件。args 为 JSON 字符串，格式见 list_plugins 的 usage 字段。"""
    try:
        parsed = json.loads(args) if args else {}
    except json.JSONDecodeError as e:
        return _j({"error": f"args 不是合法 JSON: {e}"})
    result = get_plugins().run(name, parsed)
    return _j(result)


# ---------------- 会话与静态分析 ----------------


def _so_table_warning(so, auto_discover: bool = False,
                      discover_result: dict | None = None) -> dict:
    """函数表不完整时的警告与下一步（load_so 的复用处，两条路径都要过）。

    (22) 第二十二次修改（2026-11-16）：抽出本函数。
        bug 原因：上一版只在**首次加载**的分支里 warning，`reused=True`
                  的幂等分支直接 return 了——而"再 load 一次看看"正是
                  使用者最可能的动作，那一次恰好什么警告都没有。
                  警告只出现在他不会再看的第一次调用上，等于没有。
        解决方案：两条分支共用本函数；判定与文案完全一致。

    另外把 auto_discover 的执行结果如实带出（added / skipped / error），
    不再 try/except 吞掉——静默失败的补全比不补全更危险：
    调用方会以为已经补好了。

    阈值为什么是 100：正常 NDK 库的 FDE/dynsym 初扫就有上百（liblog 111、
    libcutils 168），而加固样本初扫可以只有个位数（实测 1 个），
    补全后到数千。100 是这两类的分界，不是拍脑袋的魔数。
    """
    n = len(so.functions)
    out: dict = {"functions": n}
    if discover_result is not None:
        out["auto_discover"] = discover_result
    if n >= 100:
        return out
    out["warning"] = (
        f"函数表只有 {n} 个，可能不完整。"
        "基于它得出的『没有某个符号/函数』这类**否定结论不可信**——"
        "先补全再下结论（曾有人因这一步漏掉，误判某个 so 没有某个导入而"
        "排除了一整个方向）。")
    out["next_step"] = (
        "调 build_xrefs 或 load_so(auto_discover=True)"
        "（会递归补出 bl 目标与跳转表入口；大样本约 40 秒）")
    return out


@server.tool()
@logged()
def load_so(path: str, auto_discover: bool = False) -> str:
    """加载一个 so 文件到分析会话。path 为绝对路径。

    加载成功后广播 UI 同步事件：GUI 的模块树/函数表/Output
    立即显示新模块，与 AI 看到的一致。

    ## 函数表可能不完整（重要，踩过的坑）

    刚加载时函数表只有 FDE / dynsym 的**初扫结果**。加固样本实测只有 1 个，
    补全后到 5476 个。**函数数 < 100 时返回里必带 warning + next_step**，
    两条路径（首次加载 / 已加载复用）都一样。

    为什么这条特别重要：曾有人没做补全这一步，就基于 1 个函数的表得出
    「这个 so 没有某个导入」的结论，并据此排除了一整个排查方向。

    auto_discover=True 会在加载后**立即补全**（大样本约 40 秒）；
    默认 False，因为补全很慢，不该在只想看个模块列表时被强制等待。
    """
    # 幂等：同一路径已加载就直接复用，避免 liblog_2/_3 这样的副本堆积
    import os as _os

    real = _os.path.abspath(path)
    for existing in list(_session.modules.values()):
        if _os.path.abspath(getattr(existing, "path", "") or "") == real:
            # (22) 复用分支也要给同样的警告——见 _so_table_warning 的说明
            discover_result = None
            if auto_discover and int(getattr(existing, "functions", {}) and
                                     len(existing.functions) or 0) < 100:
                discover_result = _run_auto_discover(existing.name)
            return _j({
                "loaded": existing.name,
                "reused": True,
                **_so_table_warning(existing, auto_discover, discover_result),
            })

    so = _session.add(path)

    # (4) 恢复持久化的重命名与注释
    restored, persisted, _n_comment = 0, {}, 0
    try:
        from server.core.annotations import store as _anno
        restored = _anno.apply(so, so.name)
        persisted = _anno.load(so.name)
        # (5) 用规范名（so.name），load_so 没有 so_name 参数
        _canon = _session.key(so.name)
        _n_comment = 0
        for _addr_s, _item in persisted.items():
            if _item.get("comment"):
                _session.comments[(_canon, int(_addr_s, 16))] = _item["comment"]
                _n_comment += 1
    except Exception:                                     # noqa: BLE001
        restored, persisted, _n_comment = 0, {}, 0

    # (135) 加载后函数表可能只有 FDE/dynsym 初扫结果（实测某个加固样本只有 1 个），
    #       而真正可用要 build_xrefs 后发现 bl 目标。不提示会导致后续结论全错。
    discover_result = _run_auto_discover(so.name) if auto_discover else None

    get_plugins().emit("after_load", {"so_name": so.name})
    out = {"loaded": so.name, **_so_table_warning(so, auto_discover, discover_result)}
    _notify_ui({"type": "so_loaded", "so_name": so.name,
                "functions": len(so.functions), "path": path})
    if getattr(so, "renamed_from", None):
        out["renamed_from"] = so.renamed_from  # BUG-14：同名自动改名提示
    return _j(out)


def _run_auto_discover(so_name: str) -> dict:
    """执行函数发现并把**真实结果**返回（不吞异常）。

    (22) 第二十二次修改（2026-11-16）：新增。
        bug 原因：上一版 `try: _session.discover_functions(...)
                  except Exception: pass`——补全失败时调用方看到的是
                  和成功一模一样的返回（只有一个仍很小的 functions 数），
                  会误以为"补全过了，函数就这么多"。
        解决方案：成功返回 {ok, added, total, rounds}；失败返回
                  {ok: false, error, hint}，并让 warning 仍然生效。
    """
    try:
        res = _session.discover_functions(so_name)
        return {"ok": True,
                "added": int(res.get("added") or 0),
                "total": int(res.get("total") or 0),
                "rounds": int(res.get("rounds") or 0),
                "skipped": bool(res.get("skipped"))}
    except Exception as exc:                              # noqa: BLE001 - 坏样本不该让工具崩
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                "hint": "函数发现失败；改用 build_xrefs 后台任务重试"}


@server.tool()
@logged()
def list_modules() -> str:
    """列出当前会话已加载的全部 so 及概况。"""
    return _j(_session.summary())


@server.tool()
@logged()
def list_functions(so_name: str, keyword: str = "", limit: int = 200,
                   sort_by: str = "addr", min_size: int = 0) -> str:
    """列出某 so 的函数。keyword 过滤函数名（大小写不敏感）。

    sort_by: addr（默认）/ size（按函数大小降序，找核心逻辑）
    min_size: 只列大于等于该大小的函数（找大函数）
    """
    so = _session.get(so_name)
    fns = so.functions.values()
    kw = keyword.lower()
    items = [
        {"addr": f.addr, "addr_hex": hex(f.addr),
         "name": f.name or f"sub_{f.addr:x}", "size": f.size,
         "by": f.discovered_by}
        for f in fns
        if (not kw or kw in (f.name or "").lower()) and f.size >= min_size
    ]
    # (3) 第三次修改（2026-11-17）：支持按大小排序——使用者要靠"大函数=核心逻辑"
    #     快速定位混淆分发器（实测 sub_28dcf0 有 51444 字节）。
    if sort_by == "size":
        items.sort(key=lambda x: -x["size"])
    elif sort_by == "name":
        items.sort(key=lambda x: x["name"])
    else:
        items.sort(key=lambda x: x["addr"])
    # (1) 第一次修改 bug 原因：无节表样本 FDE 只给初扫数（实测 3016），
    # 建引用图时还会补出 bl 目标（实测 +1356 → 4363），旧返回值看不出这个差距，
    # 容易误判"函数就这么多"。
    # 解决方案：附带提示字段，明确当前是否为未补全的初扫结果。
    #
    # (2) 第二次修改 bug 原因：初版判据是「所有函数都来自 FDE」，而这是
    # 健康样本的常态（liblog 111 个全是 fde、libbase 386 个全是 fde），
    # 导致健康样本也收到"函数数通常明显增加"的承诺，实际补全增量为 0，
    # 属于误导。解决方案：只有**段表模式**（无节表，sections 为空）
    # 才提示，该类样本的 FDE 才普遍不全。
    hint = ""
    by_fde = all(f.discovered_by == "fde" for f in so.functions.values())
    if by_fde and not so.sections:
        hint = "节表不可用，当前仅为 FDE 初扫结果；调用 build_xrefs 后会递归补全 bl 目标，函数数通常明显增加"
    # (4) 第四次修改（2026-11-18）：显式标出"被 limit 截断"。
    #     bug 原因：旧返回 `count` 是**过滤后总数**、`functions` 是截断后的
    #               前 limit 条，两者不一致却不说明。使用者看到 200 条
    #               就以为函数表只有 200 个（第 33 轮反馈里这条被误当成
    #               "discover 有 200 硬上限"，实际是列表默认 limit=200）。
    #     解决方案：加 returned / truncated / limit 三个字段，把
    #               "总数"与"本次返回多少"分开写清楚。
    shown = items[:limit]
    out = {"count": len(items), "returned": len(shown),
           "limit": limit, "truncated": len(items) > len(shown),
           "functions": shown}
    if out["truncated"]:
        out["truncated_hint"] = (
            f"共有 {len(items)} 个函数，本次只返回前 {len(shown)} 个"
            f"（limit={limit}）。这**不代表函数表只有这么多个**——"
            f"取全部请调大 limit 或用 keyword 过滤。")
    if hint:
        out["hint"] = hint
    return _j(out)


@server.tool()
@logged()
def disassemble(so_name: str, addr: int, size: int = 64) -> str:
    """反汇编指定地址。addr 为静态虚拟地址（十进制）。"""
    # (27) 第二十七次修改（2026-11-13）：经 session.xref 取反汇编器，别名自动解析。
    #  bug 原因：直接下标 _session._xrefs[so_name]，别名（log.so / 设备全路径）
    #           会抛 KeyError，与同文件里已能解析的 get() 行为不一致。
    d = _session.xref(so_name).disasm
    insns = d.disasm_range(addr, size)

    first_addr = insns[0].addr if insns else None
    req = int(addr)
    aligned = (first_addr == req)
    out = {
        # (130) schema 版本：老调用方按数组遍历会拿到键名，必须能自检出问题
        "schema": "disasm.v2",
        "legacy_shape": "数组形态 —— 若你的代码直接 for x in result，"
                        "请改用 result['insns']；这个字段用来提醒版本变更",
        # 明确回答"起点有没有被挪动"——曾有人怀疑解码不一致却无法自证
        "requested_addr": hex(req),
        "first_insn_addr": hex(first_addr) if first_addr is not None else None,
        "aligned": aligned,
        "count": len(insns),
        "insns": [
            {
                "addr": i.addr,
                "addr_hex": hex(i.addr),
                "text": i.text,
                "call": i.call_target if i.is_call else None,
                "ref": i.ref_addr,
            }
            for i in insns
        ],
    }
    if not aligned:
        out["align_note"] = (
            f"请求地址 {hex(req)} 不是指令起点（AArch64 指令必须 4 字节对齐，"
            f"实际从 {hex(first_addr)} 开始解码）。"
            if first_addr is not None else
            f"请求地址 {hex(req)} 处解码不出任何指令（可能不在可执行段内）")
    if not insns:
        out["hint"] = ("没解出指令：① 确认地址落在 .text 等可执行段；"
                       "② 地址必须 4 字节对齐；③ 该处可能是数据/跳转表")
    return _j(out)


@server.tool()
@logged()
def decompile(so_name: str, addr: int, with_addr: bool = True) -> str:
    """输出函数的结构化伪代码（非真反编译，控制流归类）。addr 为函数入口。

    ## 输出格式（每行都可对回字节码）

        // so!name @ 0x1f758c (size 0x520)
        // 309 insns, 17 bl, 292 shown, 17 skipped (frame only: ...)
        void sub_1f758c() {
            // 0x1f758c  stp x29, x30, ...     ← 每行前缀源地址
            // 0x1f76e8  bl 0x243f18(...);
            ...
        }

    ## 两个必读的头部行

    - 第二行 `N insns, M bl, K shown, S skipped`：把「框架指令被省略」
      与「代码没解到」分成两个数。S 只统计 paciasp/bti/nop/帧指针这类
      **无语义**的指令，不代表漏了业务代码。
    - `// WARNING 末条指令 ...`：末条不是 ret/b/br/brk 时出现，表示
      fn.size 可能被截断（伪代码会"看起来少了几个 bl"）。按提示的地址
      用 disassemble/export_disasm 扩范围即可，不要误判成工具吞了指令。

    ## 注意：这不是真反编译

    本工具**只做符号替换 + 线性输出**，没有 if/goto 结构、没有数据流
    恢复。想看嵌套控制流用 angr 插件（plugin_run(name="angr_bridge")）。

    with_addr=False 可关掉地址注释（输出体积敏感时用）。
    """
    from server.core.pseudocode import PseudocodeGenerator

    so = _session.get(so_name)
    # (27) 第二十七次修改（2026-11-13）：同上，走 xref 拿反汇编器。
    d = _session.xref(so_name).disasm
    gen = PseudocodeGenerator(so, d)
    # (28) 第二十八次修改（2026-11-18）：透传 with_addr。
    #      bug 原因：使用者要在扁平化状态机里把伪代码行对回字节码，
    #                旧签名没有开关，只能改源码。
    #      解决方案：新增 with_addr 参数（默认 True，与需求一致）。
    return gen.generate(addr, with_addr=with_addr)


@server.tool()
@logged()
def xrefs_to(so_name: str, addr: int) -> str:
    """查询谁引用了 addr（调用点 + 数据引用点）。

    自动构建全部已加载模块的引用图（跨 so 调用藏在其他模块的
    PLT 调用里，只 build 目标模块会漏），并归并字符串引用。
    """
    for name in list(_session.modules):
        _session.ensure_xrefs(name)
    x = _session.xref(so_name)
    sites = x.xrefs_to(addr)
    so = _session.get(so_name)
    out = [
        {"so": so_name, "site": s, "function": (fn.name or f"sub_{fn.addr:x}") if (fn := so.function_at(s)) else None}
        for s in sites
    ]
    # 跨 so：其他模块经 PLT 调到本函数
    fn_at = so.function_at(addr)
    if fn_at is not None and fn_at.name:
        for link in _session.callers_of(fn_at.name):
            if link.caller_so != so_name:
                out.append({
                    "so": link.caller_so, "site": link.caller_addr,
                    "function": f"{link.caller} (via PLT → {fn_at.name})",
                })
    return _j(out)


@server.tool()
@logged()
def xrefs_from(so_name: str, addr: int) -> str:
    """查询某函数发出了哪些引用（IDA 的 xrefs from）。

    返回调用目标（含 PLT 解析出的跨 so 落点）与数据引用。
    """
    _session.ensure_xrefs(so_name)
    x = _session.xref(so_name)
    so = _session.get(so_name)
    fn = so.function_at(addr)
    if fn is None:
        return _j({"error": f"{addr:#x} 不在任何函数内"})
    out = []
    for callee in sorted(set(x.called_by.get(fn.addr, []))):
        link = _session.resolve_call(so_name, callee)
        if link:
            out.append({
                "target": callee,
                "name": link.callee,
                "target_so": link.callee_so or "(未解析导入)",
                "target_addr": link.callee_addr or None,
                "via_plt": link.via_plt,
            })
        else:
            out.append({"target": callee, "name": hex(callee), "target_so": so_name})
    return _j({"function": fn.name or f"sub_{fn.addr:x}", "refs": out})


@server.tool()
@logged()
def imports(so_name: str, keyword: str = "", limit: int = 200) -> str:
    """导入符号表。keyword 过滤符号名。"""
    so = _session.get(so_name)
    kw = keyword.lower()
    items = []
    for name, sym in sorted(so.imports.items()):
        if kw and kw not in name.lower():
            continue
        plt = next((a for a, n in so.plt_map.items() if n == name), None)
        items.append({"name": name, "plt": hex(plt) if plt else None, "is_func": sym.is_func})
    return _j({"count": len(items), "imports": items[:limit]})


@server.tool()
@logged()
def exports(so_name: str, keyword: str = "", limit: int = 200) -> str:
    """导出符号表。keyword 过滤符号名。"""
    so = _session.get(so_name)
    kw = keyword.lower()
    items = [
        {"name": n, "addr": hex(s.addr), "size": s.size}
        for n, s in sorted(so.exports.items(), key=lambda kv: kv[1].addr)
        if not kw or kw in n.lower()
    ]
    return _j({"count": len(items), "exports": items[:limit]})


@server.tool()
@logged()
def segments(so_name: str) -> str:
    """程序头（PT_LOAD/DYNAMIC 等）与节表分开返回。

    BUG-6 修复：之前本端点返回的是节（sections），RX 段在无节表
    dump 上完全丢失。现在 program_headers 从原始 ELF 头解析，
    与 sections 并列返回；节表无效时 sections 为空数组 + warning。
    """
    import struct as _s

    so = _session.get(so_name)
    # 手工解析 program headers（不依赖节表可用性）
    phdrs = []
    so._stream.seek(0)
    head = so._stream.read(64)
    e_phoff, = _s.unpack_from("<Q", head, 0x20)
    e_phentsize, e_phnum = _s.unpack_from("<HH", head, 0x36)
    PT = {1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE",
          6: "PT_PHDR", 7: "PT_TLS", 0x6474E550: "PT_GNU_EH_FRAME",
          0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO"}
    for i in range(e_phnum):
        so._stream.seek(e_phoff + i * e_phentsize)
        ph = so._stream.read(e_phentsize)
        if len(ph) < 56:
            break
        p_type, p_flags = _s.unpack_from("<II", ph, 0)
        p_offset, p_vaddr, _pa, p_filesz, p_memsz = _s.unpack_from("<QQQQQ", ph, 8)
        phdrs.append({
            "type": PT.get(p_type, hex(p_type)),
            "vaddr": hex(p_vaddr), "filesz": hex(p_filesz), "memsz": hex(p_memsz),
            "offset": hex(p_offset),
            "flags": (("R" if p_flags & 4 else "") + ("W" if p_flags & 2 else "") + ("X" if p_flags & 1 else "")) or "-",
        })
    return _j({
        "program_headers": phdrs,
        "sections": [
            {"name": s.name, "addr": hex(s.addr), "size": hex(s.size),
             "exec": s.is_exec, "write": s.is_write}
            for s in so.sections
        ],
        "sections_usable": so._sections_usable,
        "warning": so.section_warning,
    })


@server.tool()
@logged()
def metadata(so_name: str) -> str:
    """文件元信息：架构/格式/入口/模块统计。"""
    so = _session.get(so_name)
    out = {
        "name": so.name, "path": so.path, "arch": so.arch.name,
        "pie": so.is_pie, "entry": hex(so.entry),
        "functions": len(so.functions),
        "exports": len(so.exports), "imports": len(so.imports),
        "sections": len(so.sections),
    }
    # (1) 第一次修改 bug 原因：无节表样本的 PLT 桩既不在 exports 也不在
    # imports 里，用户看三项全 0 会误以为"没有任何外部依赖"。
    # 解决方案：显式报告扫出的桩数量，说明外部调用确实存在、只是符号名已抹。
    if so.plt_stubs:
        out["plt_stubs"] = len(so.plt_stubs)
        out["plt_stubs_note"] = "节表/动态节被抹，桩按指令模板扫描得出；导入符号名无法恢复"
    return _j(out)


@server.tool()
@logged()
def function_by_name(so_name: str, pattern: str, limit: int = 20) -> str:
    """按名字模式（大小写不敏感子串）查函数，返回精确地址。"""
    so = _session.get(so_name)
    kw = pattern.lower()
    from server.core.elf_model import demangle as _demangle

    hits = []
    for f in sorted(so.functions.values(), key=lambda x: x.addr):
        if not f.name:
            continue
        raw = f.name
        pretty = _demangle(raw)
        # 原名与还原名任一命中即可：人只会按可读名搜，脚本按原名搜
        if kw not in raw.lower() and kw not in pretty.lower():
            continue
        hits.append({
            "addr": f.addr,
            "name": raw,
            "demangled": pretty if pretty != raw else None,
            "size": f.size,
            "export": f.is_export,
        })
    return _j({"count": len(hits), "matches": hits[:limit]})


@server.tool()
@logged()
def rename_function(so_name: str, addr: int, new_name: str) -> str:
    """重命名函数（写操作，影响 GUI 与后续所有查询）。

    对齐 IDA 的 N 快捷键。重命名即时生效且持久到当前会话。
    """
    so = _session.get(so_name)
    fn = so.function_at(addr)
    if fn is None:
        return _j({"error": f"{addr:#x} 不在任何函数内"})
    old = fn.name or f"sub_{fn.addr:x}"
    fn.name = new_name
    # (4) 持久化到工作区 .dsh/mda_annotations/，重启后 load_so 自动恢复
    try:
        from server.core.annotations import store as _anno
        _anno.save(so.name, fn.addr, rename=new_name)
    except Exception:                                     # noqa: BLE001
        pass
    _notify_ui({"type": "renamed", "so_name": so_name, "addr": fn.addr, "old": old, "new": new_name})
    # 同步导出表里的名字，使跨 so 解析立即用新名
    if old in so.exports:
        renamed = so.exports.pop(old)
        so.exports[new_name] = renamed
        if new_name in _session._export_index:
            _session._export_index[new_name] = [
                (n, a) if a != fn.addr else (n, a)
                for (n, a) in _session._export_index[new_name]
            ]
            _session._export_index[new_name].append((so_name, fn.addr))
        else:
            _session._export_index[new_name] = [(so_name, fn.addr)]
        _session._export_index.pop(old, None)
        # 旧名若与 PLT 映射名一致，跨 so 调用方按旧名解析会失效——
        # 导出符号真实改名场景极少，此处保留 PLT 名不变（导入名是对方 so 的事实）
    get_plugins().emit("after_rename", {"so_name": so_name, "addr": fn.addr, "old": old, "new": new_name})
    return _j({"renamed": True, "addr": hex(fn.addr), "old": old, "new": new_name})


@server.tool()
@logged()
def set_comment(so_name: str, addr: int, comment: str) -> str:
    """在地址处写注释（写操作）。注释出现在反汇编与伪代码视图。"""
    # (27) 第二十七次修改（2026-11-13）：注释以**规范键**存储。
    #  bug 原因：原来直接拿用户传的名字做键。用别名 log.so 写注释、
    #           再用 liblog.so 读，会读不到——数据没丢，但表现为"注释丢了"。
    #  解决方案：先换成规范键再存，读写两侧同口径。
    key = _session.key(so_name)
    _session.comments[(key, addr)] = comment
    # (4) 持久化（comment 与 rename 存在同一个 JSON 里）
    try:
        from server.core.annotations import store as _anno
        _anno.save(key, addr, comment=comment)
    except Exception:                                     # noqa: BLE001
        pass
    get_plugins().emit("after_comment", {"so_name": key, "addr": addr, "comment": comment})
    return _j({"commented": hex(addr), "comment": comment, "so": key,
               "persisted": True})


@server.tool()
@logged()
def get_comments(so_name: str) -> str:
    """列出该 so 的全部注释。"""
    key = _session.key(so_name)
    items = [
        {"addr": hex(a), "comment": c}
        for (n, a), c in sorted(_session.comments.items(), key=lambda kv: kv[0][1])
        if n == key
    ]
    return _j(items)


@server.tool()
@logged()
def search_insn(so_name: str, mnemonic: str = "", operand_pattern: str = "",
                limit: int = 100, func_filter: str = "",
                discover: bool = False) -> str:
    """按**指令语义**搜索——找出所有符合模式的指令。

    这是逆向里最常用的动作：「我知道一个结构体偏移 / 一个常量，
    帮我找出所有访问它的指令」。`search_bytes` 做不到这件事
    （它是按字节匹配，表达不了"所有 str 到 [x?, #0x1100]"）。

        search_insn(so_name="x.so", mnemonic="str", operand_pattern="[x*, #0x1100]")
        → [{addr_hex: "0x32dbe0", text: "str x0, [x28, #0x1100]",
            function: "sub_32c7e0", offset: "0x1400"}]

    ## 参数

    mnemonic      助记符，支持通配：`str` / `str*`（覆盖 str/strb/strh）/ `bl` / `*`
    operand_pattern
                  操作数模式，支持 `*`（任意序列）与 `?`（任意单字符）：
                    `[x*, #0x1100]`   存在一个"基址+偏移0x1100"的内存操作数
                    `x0, [x1, #*]`    x0 写到 x1 指向的任意偏移
                    `w*, w0, #*`      寄存器运算
                  **默认子串匹配**：只要模式出现在操作数里就算命中。
                  想精确匹配整串时用 `^...$` 显式锚定。
    limit         最多返回多少条（默认 100，上限 2000）
    func_filter   只搜函数名包含该子串的函数（大幅提速）
    discover      搜索前先补全函数表（默认 False）。
                  **大样本要 40 秒以上**（12160 函数的实测 43s），
                  而搜索本身只要 3.5 秒——所以默认不做。
                  需要精确的 function/offset 时才开，或先调 build_xrefs。

    ## 返回

    results 里每条带 addr_hex / text / **function（所在函数）/ offset（函数内偏移）**。
    不在任何已知函数内的命中会标 note —— 那可能是数据区或未被发现的函数。

    ## 性能

    实测 libbase（4.2 万条指令）0.16s；sscronet（100 万条指令、12160 函数）3.6s。
    `scanned` 字段是实际反汇编的指令数，可据此判断搜索代价。

    ## 没命中怎么办（hint 里也会给）

    · 立即数常被拆成 `adrp + add`，搜 `add` 往往比搜 `str` 有效
    · `#0x1100` 要带 `0x` 前缀
    · 助记符不确定时先用 `mnemonic="*"` + operand_pattern 试
    """
    from server.core.insn_search import search_insn as _impl

    so = _session.get(so_name)
    # (124) 只补函数发现，不建全量引用图。
    #       搜索不需要引用图（它靠函数表标注 function/offset），
    #       而 ensure_xrefs 在 12160 函数的样本上要 60-220 秒，
    #       会让一次搜索直接超时。
    funcs_before = len(so.functions)
    funcs_after = funcs_before
    if discover and funcs_before < 1000:
        # 先说明为什么这一步慢，免得调用方以为卡死
        import sys as _sys
        print(f"[search_insn] 函数表只有 {funcs_before} 个，"
              f"先补全（大样本约 40 秒）…", file=_sys.stderr, flush=True)
    if discover:
        # 显式要求才补函数表：实测 12160 函数的样本要 43 秒，
        # 默认做会让一次搜索直接超时（搜索本身只要 3.5 秒）。
        try:
            _session.discover_functions(so_name)
        except Exception:                                 # noqa: BLE001
            pass
        funcs_after = len(so.functions)
    out = _impl(so, mnemonic=mnemonic, operand_pattern=operand_pattern,
                limit=int(limit), func_filter=func_filter)
    if funcs_after > funcs_before:
        out.setdefault("notes", []).append(
            f"搜索前补了 {funcs_after - funcs_before} 个函数"
            f"（{funcs_before} → {funcs_after}），function/offset 更完整")
    elif not discover and out.get("results"):
        # 函数表不全时会有命中落不到函数——如实说明，并给出补救方式
        no_fn = sum(1 for r in out["results"] if not r.get("function"))
        if no_fn:
            out.setdefault("notes", []).append(
                f"{no_fn} 条命中落不到已知函数（当前函数表只有 {funcs_before} 个）。"
                "要更完整的 function/offset，传 discover=true（大样本约 40 秒）"
                "或先调 build_xrefs")
    return _j(out)


@server.tool()
@logged()
def search_bytes(so_name: str, hex_pattern: str, limit: int = 50) -> str:
    """按十六进制字节模式搜索（支持 ?? 通配单字节），如 '1f 20 03 d5' 或 '?? 20 03 d5'。"""
    import re

    so = _session.get(so_name)
    parts = hex_pattern.strip().split()
    if not parts:
        return _j({"error": "empty pattern"})
    # 转正则：?? 任意字节
    rx = b""
    for p in parts:
        if p == "??":
            rx += b"."
        else:
            rx += re.escape(bytes.fromhex(p))
    pattern = re.compile(rx, re.DOTALL)

    # (4) 第四次修改（2026-10-30）：节表为空时用 PT_LOAD 可执行段兜底。
    #     bug 原因：旧实现只遍历 so.sections。壳处理过的 dump so 节表被抹，
    #               elf_model 会置 _sections=[]，循环体一次都不执行 →
    #               在任何壳样本上都恒返回 count:0。实测在 sgm 样本上
    #               搜单字节 "d2" 也是 0，而按 PT_LOAD 扫同一模式可命中
    #               110 处 br x16 / 297 处 br x17，属于会误导用户的静默错误。
    #     解决方案：优先用节表；无节表时改用 exec_regions()（PT_LOAD 中
    #               的可执行段）扫描，保证壳样本上搜索依然有效。
    regions: list[tuple[int, int, str]] = []
    for sec in so.sections:
        # 保留原有过滤：非可执行且 addr==0 的节跳过（如 NULL 头）
        if not sec.is_exec and sec.addr == 0:
            continue
        regions.append((sec.addr, sec.size, sec.name))
    if not regions:
        for va, end, _off, _fl in so.exec_regions():
            regions.append((va, end - va, "(segment)"))

    hits = []
    for base, size, label in regions:
        data = so.read(base, size)
        if not data:
            continue
        for m in pattern.finditer(data):
            hits.append({"addr": hex(base + m.start()), "section": label})
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    out = {"count": len(hits), "matches": hits}
    if not so.sections:
        # 显式告知走的是段表兜底，避免用户误判「样本里没有该字节」
        out["scan_mode"] = "PT_LOAD（节表不可用，按可执行段扫描）"
    return _j(out)


@server.tool()
@logged()
def list_strings(so_name: str, keyword: str = "", limit: int = 100) -> str:
    """列出字符串。keyword 子串过滤。引用者需先调用 build_xrefs。"""
    strs = _session.strings(so_name)
    items = strs.search(keyword, limit) if keyword else strs.all_strings()[:limit]
    return _j([
        {"addr": s.addr, "value": s.value[:120], "section": s.section, "refs": len(s.referenced_by)}
        for s in items
    ])


@server.tool()
@logged()
def string_refs(so_name: str, addr: int) -> str:
    """查询某字符串被哪些函数引用。addr 为字符串起始静态地址。

    内部自动确保引用图已构建（幂等，已建则秒回）。
    """
    _session.ensure_xrefs(so_name)
    s = _session.strings(so_name)
    ref = s.string_starting_at_or_before(addr)
    if ref is None:
        return _j({"error": "no string at or before address"})
    so = _session.get(so_name)
    out = []
    for site in ref.referenced_by:
        fn = so.function_at(site)
        item: dict = {"site": site, "site_hex": hex(site)}
        if fn is None:
            # 落不到任何函数：可能是数据区，也可能是函数未被发现
            item["function"] = None
            item["note"] = ("该引用点不在任何已发现函数内——"
                            "可能是数据区，或所在函数未被函数发现覆盖")
        else:
            item["function"] = fn.name if fn and fn.name else f"sub_{fn.addr:x}"
            item["function_entry"] = hex(fn.addr)
            item["offset"] = hex(site - fn.addr)
            # 明确告诉调用方这是不是函数入口：曾经有人把内部偏移当入口用
            item["is_entry"] = (site == fn.addr)
        out.append(item)
    return _j({"string": ref.value, "string_hex": hex(addr),
               "count": len(out), "refs": out})


# 后台构建任务表：job_id → 状态。进程内共享，供轮询。
_XREF_JOBS: dict[str, dict] = {}
_XREF_LOCK = __import__("threading").Lock()


@server.tool()
@logged()
def build_xrefs(so_name: str, use_prologue: bool | None = None,
                aggressive: bool = False,
                strict_prologue: bool = True, use_rela: bool = True,
                wait_seconds: float = 20.0) -> str:
    """显式构建某 so 的全量引用图（首次调用较慢，之后有缓存）。

    构建前会先做**递归函数发现**：扫描 bl 目标，把 FDE（.eh_frame）
    漏掉、但带标准序言的函数入口补进函数表。加固样本实测可补 1814 个
    （6047 → 7861）；健康 NDK 库通常为 0（FDE 完整，无误报）。

    ## 三档（第 33 轮反馈：旧版只有"太保守"和"太激进"两档）

    | 档位 | 等价调用 | 行为 |
    |---|---|---|
    | **bl_only**（默认） | 不传 / `use_prologue=false` | 只认 `bl` 目标。bl 是"被直接调用"的硬证据 |
    | **strict**（推荐） | `use_prologue=true` | `bl` + 「终止指令后紧跟**完整栈帧**」 |
    | **loose** | `use_prologue=true, strict_prologue=false` | `bl` + 任何序言（含裸 `bti`）。旧行为，会切碎 switch |

    `aggressive` 是 `use_prologue` 的旧名。

    为什么 strict 看"栈帧"而不是"序言"：裸 `bti c`/`paciasp` 是分支保护
    标记，编译器给 switch 的**每个 case 块**都加了 `bti jc`。实测 libbase
    用旧判据新增 171 个入口、**100% 是裸 bti**；严格档只收 2 个，都是
    真函数（完整栈帧 + 前置终止指令），且**没有任何 bl 指向它们**——
    说明它们只能经函数指针/vtable 抵达，正是间接调用分析要的目标。

    ## 已建图后换档位

    引用图建好后再调本工具会命中缓存直接返回。此时若传入的档位与建图时
    不同，返回里会带 `tier_mismatch` 提示——换档位必须 unload_so 后重新
    load，否则你看到的函数数仍是旧档位的（不是"激进模式没效果"）。

    同时把数据引用归并到字符串的 referenced_by，
    使 string_refs 可用——string_refs 依赖此步骤。
    """
    # 已经建好就直接返回（幂等，不重复扫）
    try:
        # (27) 第二十七次修改（2026-11-13）：改用公开入口，别名自动解析。
        #     这里本来就有 try/except，但成功后下面又要 _session.xref(so_name)，
        #     别名时前面成功、后面失败，问题只是被推迟了一步。
        prog = _session.xref_progress(so_name) or {}
    except Exception:                                     # noqa: BLE001
        prog = {}
    if prog.get("built"):
        x = _session.xref(so_name)
        so = _session.get(so_name)
        out = {
            "ok": True, "cached": True,
            "functions": len(so.functions),
            "call_edges": sum(len(v) for v in x.calls_to.values()),
            "data_refs": len(x.data_refs),
        }
        # (28) 第二十八次修改（2026-11-18）：cached 分支如实对比档位。
        #      bug 原因：旧实现在 cached 分支完全不看 aggressive，使用者传
        #                aggressive=True 却拿到 386 个函数，会误判"激进模式
        #                也没用"——实际是被缓存短路了（第 14 轮反馈同一问题）。
        #      解决方案：报出建图时用的档位，与本次请求不同则给 tier_mismatch
        #                与明确下一步，而不是静默返回旧结果。
        built_tier = getattr(x, "discover_tier", None)
        if built_tier is not None:
            out["built_tier"] = built_tier
            want = {"aggressive": bool(aggressive),
                    "strict_prologue": bool(strict_prologue),
                    "use_rela": bool(use_rela)}
            if built_tier != want:
                out["tier_mismatch"] = (
                    f"引用图是用 {built_tier} 建的，本次请求 {want}；"
                    "cached 分支不会重建。要换档位请先 unload_so(so) 再 "
                    "load_so(auto_discover=True)，或另起会话重跑。")
        return _j(out)

    # 有正在跑的同一任务 → 直接复用，不要重复启动
    with _XREF_LOCK:
        for jid, job in _XREF_JOBS.items():
            if job["so"] == so_name and job["state"] == "running":
                return _j({"ok": True, "job": jid, "state": "running",
                           "message": "这个 so 的引用图正在建，用 "
                                      "build_xrefs_status(job=...) 轮询"})

        import threading
        import time as _t
        import uuid as _uuid

        jid = _uuid.uuid4().hex[:12]
        _XREF_JOBS[jid] = {
            "job": jid, "so": so_name, "state": "running",
            "started": _t.time(), "percent": 0, "result": None, "error": None,
        }

    def _run() -> None:
        """后台线程：真正干活，把进度写回 job。"""
        import time as _t

        def _on_progress(pct: int, _total: int, stage: str = "") -> None:
            """把构建进度写回 job，供 build_xrefs_status 轮询。

            节流：每 2% 或换阶段时更新一次，避免高频写锁。
            """
            with _XREF_LOCK:
                job = _XREF_JOBS.get(jid)
                if not job:
                    return
                last = job.get("percent", 0)
                last_stage = job.get("stage", "")
                if pct - last < 2 and stage == last_stage and pct < 100:
                    return
                job["percent"] = pct
                job["stage"] = stage
                job["elapsed"] = round(_t.time() - job["started"], 1)

        try:
            _session.ensure_xrefs(so_name, aggressive=aggressive,
                                  progress=_on_progress,
                                  strict_prologue=strict_prologue,
                                  use_rela=use_rela,
                                  use_prologue=use_prologue)
            so = _session.get(so_name)
            x = _session.xref(so_name)
            res = {
                "functions": len(so.functions),
                "call_edges": sum(len(v) for v in x.calls_to.values()),
                "data_refs": len(x.data_refs),
            }
            with _XREF_LOCK:
                _XREF_JOBS[jid].update(
                    state="done", percent=100, result=res,
                    elapsed=round(_t.time() - _XREF_JOBS[jid]["started"], 1),
                )
        except Exception as e:                            # noqa: BLE001
            with _XREF_LOCK:
                _XREF_JOBS[jid].update(state="failed", error=str(e)[:300])

    threading.Thread(target=_run, daemon=True).start()

    # 小样本几十毫秒就好；等一小会儿能直接出结果的就不必让调用方轮询
    import time as _t
    deadline = _t.time() + max(0.0, wait_seconds)
    while _t.time() < deadline:
        with _XREF_LOCK:
            job = dict(_XREF_JOBS[jid])
        if job["state"] != "running":
            break
        _t.sleep(0.2)

    with _XREF_LOCK:
        job = dict(_XREF_JOBS[jid])
    if job["state"] == "done":
        return _j({"ok": True, "job": jid, "cached": False, **job["result"]})
    if job["state"] == "failed":
        return _j({"ok": False, "job": jid, "error": job["error"]})
    return _j({
        "ok": True, "job": jid, "state": "running",
        "elapsed": round(_t.time() - job["started"], 1),
        "message": f"构建中（大样本约 1-2 分钟）。用 build_xrefs_status(job=\"{jid}\") 轮询；"
                   "期间其他工具调用不受影响。",
    })


@server.tool()
@logged()
def build_xrefs_status(job: str) -> str:
    """查询后台引用图构建进度（配合 build_xrefs 的 job 参数）。

    为什么需要：大样本构建要 100 秒以上，同步等待必然让客户端超时。
    build_xrefs 现在返回 job id，用这个工具轮询，等到 state=done 再取结果。
    """
    with _XREF_LOCK:
        j = _XREF_JOBS.get(job)
        if j is None:
            return _j({"ok": False, "error": f"没有这个 job：{job}"})
        out = dict(j)
    if out["state"] == "done":
        out["percent"] = 100
        out["stage"] = "完成"
    # 给一句人话，AI 和人都不用自己拼
    if out["state"] == "running":
        out["message"] = (f"{out.get('stage') or '构建中'} · "
                          f"{out['percent']}% · 已用 {out.get('elapsed', 0)}s")
    return _j(out)


@server.tool()
@logged()
def call_chain(so_name: str, addr: int, depth: int = 3) -> str:
    """跨 so 调用链（核心能力）。从 addr 出发展开调用树，跨 so 时自动深入。"""
    chain = _session.call_chain(so_name, addr, depth)
    return chain.as_text()


@server.tool()
@logged()
def callers_of(symbol: str) -> str:
    """跨 so 反查：哪些 so 的哪些函数调用了该导出符号。"""
    links = _session.callers_of(symbol)
    return _j([l.__dict__ for l in links])


# ---------------- 动态分析 ----------------


@server.tool()
@logged()
def list_devices() -> str:
    """列出 adb 设备。"""
    from server.dyn.adb import Adb

    return _j([{"serial": d.serial, "state": d.state} for d in Adb.list_devices()])


@server.tool()
@logged()
def list_processes(serial: str, keyword: str = "",
                   pid: int = 0) -> str:
    """列出设备进程。keyword 过滤进程名。"""
    from server.dyn.adb import Adb

    procs = Adb(serial).processes()
    kw = keyword.lower()
    return _j([
        {"pid": p.pid, "name": p.name, "user": p.user}
        for p in procs
        if not kw or kw in p.name.lower()
    ][:200])


@server.tool()
@logged()
def start_frida(serial: str) -> str:
    """以 root 启动设备端 frida-server，并校验版本与本机客户端一致。

    **会自动做两件事，避免"启动了却连不上"的困惑**：
        1. 版本校验：读设备二进制的 `--version` 与本机 frida 客户端比对，
           不一致直接返回 FRIDA_VERSION_MISMATCH（并给出两个版本号），
           不启动——因为版本不符时起来了也连不上，只会报 ProtocolError。
        2. 端口占用者识别：若 27042 已被别的进程占着，先查清是**谁**占的。
           如果占用者是别的程序（例如别人项目在用的另一个 frida 实例），
           返回 FRIDA_PORT_TAKEN 并列出 pid/名字，**不做任何操作**；
           只有在确认是我们自己的 server 已运行时才返回"已在运行"。

    这正是本轮处理的场景：设备上曾同时存在 16.0.19（别人的项目，监听 27100）
    与 17.23.3（mda 用，监听 27042），按进程名判断会把两者搞混。

    版本不匹配时正确做法：先调 frida_server_align（dry_run 看计划，
    再去掉 dry_run 执行），它会把设备端覆盖成本机版本。
    """
    from server.dyn.adb import Adb

    # (1) 第一次修改：原来只返回 {"running": bool}，失败无原因。
    #     现在透传 dyn.adb 的结构化结果（running/code/message/path），
    #     running 键保持不变，老调用方不受影响。
    # (2) 第二次修改（2026-11-05）：传 expect_version 让 adb 层做版本校验，
    #     避免"启动了旧版 → 连不上 → 报 ProtocolError"这种看不出根因的失败。
    try:
        import frida

        expect = str(frida.__version__)
    except Exception:                                     # noqa: BLE001
        expect = ""
    return _j(Adb(serial).start_frida(expect_version=expect))


@server.tool()
@logged()
def frida_server_align(serial: str, version: str = "", dry_run: bool = True,
                       device_path: str = "") -> str:
    """把设备端 frida-server 覆盖成**与本机客户端完全一致**的版本并启动。

    为什么需要：frida 客户端与设备端 server 版本必须一致才能通信，minor 不同也会报
    `ProtocolError: unable to communicate with remote frida-server`。
    设备上常有多份历史二进制（frida_16019 / frida-server / .fs）互相干扰，
    手工排查很费时间。本工具把「下载→校验→备份→覆盖→启动→验证」收敛成一次操作。

    **安全设计（务必先读）**：
        dry_run=True（默认）—— 只返回计划，**不改动任何设备文件**。
        确认无误后传 dry_run=False 才真正执行。
        执行时：覆盖前强制备份原文件（<路径>.bak-<时间戳>），
        任一步失败自动还原备份并把回滚结果写进返回，不留半坏状态。
        下载后按 GitHub 官方公布的 sha256 校验，不匹配立即删除并中止。

    version 留空表示用本机 `frida.__version__`，这是保证匹配的正常用法。
    device_path 留空表示 /data/local/tmp/frida-server。

    返回（dry_run）：plan 里含版本、ABI、资产名、sha256、将执行的 7 个步骤、风险警告。
    返回（执行）：download / install（含 backup_path）/ stopped_processes /
                started_process / verify（真实连一次设备）/ done；失败时含 error 与
                rolled_back。
    """
    from server.dyn.frida_server import ensure_server

    try:
        result = ensure_server(
            serial,
            version=(version or None),
            dry_run=bool(dry_run),
            device_path=(device_path or "/data/local/tmp/frida-server"),
        )
    except Exception as exc:              # noqa: BLE001 - DynError 带 code
        code = getattr(exc, "code", type(exc).__name__)
        return _j({"error": str(exc), "code": code})
    return _j(result)


@server.tool()
@logged()
def freeze_process(serial: str, pid: int) -> str:
    """**冻结整个进程**（SIGSTOP），得到"某一瞬间"的完整快照。

    与 hold 断点的区别（别混用）：
        hold 断点   只挂住**命中的那一条线程**，别的线程还在跑
        freeze      整个进程**所有线程**一起停，所有内存/栈都是同一时刻的

    什么时候该用冻结：
        · 想看"这个时刻进程到底在干什么"——读内存不会一边读一边被改
        · 反调试/风控在定期校验，需要完全静止才读得到干净的数据
        · 想对比两个时刻的完整状态

    **冻结期间的重要限制**：
        · 该进程**不能响应任何 frida RPC**（agent 线程也停了），
          所以 `read_typed(source="runtime")`、`poll_events`、`resume`
          等所有依赖 frida 的调用都会**阻塞或超时**；
        · 要读冻结后的内存/栈，走 adb 侧（/proc/<pid>/mem、/proc/<pid>/task）；
        · **分析完必须调 unfreeze_process**，否则这个进程会一直卡死
          （用户的 app 会"未响应"）。

    返回：{ok, code, message, status_before, status_after, hint}
    status 是 /proc/<pid>/stat 的状态字符：T 表示冻结成功，S/R 表示没冻住。
    """
    from server.dyn.adb import Adb

    try:
        return _j(Adb(serial).freeze_process(int(pid)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "FREEZE_FAILED")})


@server.tool()
@logged()
def unfreeze_process(serial: str, pid: int) -> str:
    """**恢复**被 freeze_process 冻结的进程（SIGCONT）。

    调用时机：frozen 的那一刻分析完就立刻解冻。**忘了解冻的后果是用户的 app
    一直卡着**（界面无响应、ANR），所以用完务必调一次。

    返回：{ok, code, message, status_before, status_after}
    status_after 不再是 T/t 才算恢复成功。
    """
    from server.dyn.adb import Adb

    try:
        return _j(Adb(serial).unfreeze_process(int(pid)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "UNFREEZE_FAILED")})


@server.tool()
@logged()
def remove_breakpoint(bp_id: str) -> str:
    """**删除一个断点**（与 set_breakpoint 配套）。

    bp_id 从 set_breakpoint 的返回或 list_breakpoints 里取，
    形如 "3e2ff172:22747:libc.so:48d3c"（serial:pid:so:静态地址hex）。

    删除是**真的摘钩**（调 InvocationListener.detach），不是只删记录：
    实测摘钩前命中 486 次，摘钩后 800ms 内 0 次新命中。

    返回：{removed, bp_id, message}；removed=false 时说明原因
    （断点不存在 / 摘钩失败——后者要当心，钩子可能还在命中）。
    """
    from server.dyn.service import get_dyn

    try:
        return _j(get_dyn().remove_breakpoint(str(bp_id)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "REMOVE_FAILED")})


def _reg_value(context: dict, name: str):
    """从命中现场取某个寄存器的整数值；取不到返回 None。

    (26) 第二十六次修改（2026-11-06）：新增。

    为什么要这个包装：context 里的值是 "0x..." 字符串，键名大小写不定
    （有的是 fp 有的是 x29），直接比较容易踩空。这里统一成 int 再比。
    """
    if not isinstance(context, dict) or not name:
        return None
    key = str(name).strip().lower()
    raw = context.get(key)
    if raw is None:
        # fp/lr 与 x29/x30 互为别名，双向兜一下
        alias = {"fp": "x29", "x29": "fp", "lr": "x30", "x30": "lr"}
        alt = alias.get(key)
        if alt:
            raw = context.get(alt)
    if raw is None:
        return None
    try:
        return int(raw, 16) if isinstance(raw, str) else int(raw)
    except (TypeError, ValueError):
        return None


def _hit_matches_filter(hit: dict, flt: dict) -> bool:
    """判断一条命中是否满足寄存器过滤条件（多条件 AND）。

    (26) 第二十六次修改（2026-11-06）：新增。

    支持的条件形态：
        5                           等于（整数或 "0x.." 字符串）
        {"eq": 5}                   等于
        {"ne": 5}                   不等于
        {"in": [1, 4, 5]}           值在集合里
        {"not_in": [1]}             值不在集合里
        {"min": 1, "max": 10}       闭区间
        {"gt": .., "lt": .., "ge": .., "le": ..}   其它比较

    寄存器取不到时**视为不匹配**（而不是放行）——否则一个写错的寄存器名
    会悄悄把所有命中都放回来，看起来像"过滤没生效"。
    """
    ctx = hit.get("context") or {}
    for reg, cond in (flt or {}).items():
        val = _reg_value(ctx, str(reg))
        if val is None:
            return False
        if not isinstance(cond, dict):
            # 直接给值 = 等于
            try:
                want = int(cond, 16) if isinstance(cond, str) else int(cond)
            except (TypeError, ValueError):
                return False
            if val != want:
                return False
            continue

        def _as_int(x):
            try:
                return int(x, 16) if isinstance(x, str) else int(x)
            except (TypeError, ValueError):
                return None

        if "eq" in cond and val != _as_int(cond["eq"]):
            return False
        if "ne" in cond and val == _as_int(cond["ne"]):
            return False
        if "in" in cond:
            pool = [ _as_int(x) for x in (cond["in"] or []) ]
            if val not in pool:
                return False
        if "not_in" in cond:
            pool = [ _as_int(x) for x in (cond["not_in"] or []) ]
            if val in pool:
                return False
        if "min" in cond:
            m = _as_int(cond["min"])
            if m is not None and val < m:
                return False
        if "max" in cond:
            m = _as_int(cond["max"])
            if m is not None and val > m:
                return False
        if "gt" in cond:
            m = _as_int(cond["gt"])
            if m is not None and not val > m:
                return False
        if "lt" in cond:
            m = _as_int(cond["lt"])
            if m is not None and not val < m:
                return False
        if "ge" in cond:
            m = _as_int(cond["ge"])
            if m is not None and not val >= m:
                return False
        if "le" in cond:
            m = _as_int(cond["le"])
            if m is not None and not val <= m:
                return False
    return True


def _group_hits(items: list, field: str, top: int = 50) -> dict:
    """按某个字段/寄存器分组计数，返回降序分布。

    (26) 第二十六次修改（2026-11-06）：新增。

    为什么这个比原始数据有用：2000 条命中的原始 JSON 没法看，但
    "x2 的分布是 {0x1: 523, 0x4: 437, 0x5: 210}" 一眼就能定位到
    你要找的那个命令号。

    field 支持：
        · 寄存器名（x0..x30 / sp / pc / lr / fp）—— 从 context 取
        · 命中记录里的普通字段：so_name / thread_id / seq / ts
        · 特殊值 "thread_id" 直接归并线程

    取不到值的命中计入 unparsed（如实报告，不丢弃也不假装是 0）。
    """
    counts: dict = {}
    unparsed = 0
    plain_fields = {"so_name", "thread_id", "seq", "static_addr",
                    "runtime_addr", "tid"}
    is_plain = field in plain_fields

    for h in items or []:
        if is_plain:
            v = h.get(field)
            if field == "tid":
                v = h.get("thread_id")
        else:
            v = _reg_value(h.get("context") or {}, field)
        if v is None:
            unparsed += 1
            continue
        counts[v] = counts.get(v, 0) + 1

    ordered = sorted(counts.items(), key=lambda kv: -kv[1])
    groups = []
    for k, n in ordered[:max(1, int(top))]:
        groups.append({"value": hex(k) if isinstance(k, int) else str(k),
                       "count": n})
    return {
        "field": field,
        "groups": groups,
        "total": sum(counts.values()),
        "distinct": len(counts),
        "unparsed": unparsed,
    }


@server.tool()
@logged()
def hits(serial: str, pid: int, bp_id: str = "", limit: int = 0,
         since_seq: int = 0, include_context: bool = True,
         include_backtrace: bool = True, include_stack: bool = True,
         filter: dict | None = None, group_by: str = "",
         group_top: int = 50) -> str:
    """取**断点命中历史**（完整现场），与 poll_events 是两份不同的数据。

    区别（很容易混）：
        poll_events   事件流（attached/detached/breakpoint_set/hit/...），
                      有游标、可增量拉取，适合"边跑边看"
        hits          命中现场列表（含 36 个寄存器 + 调用栈），
                      适合"停下来逐条复盘"

    ## ⚠️ 数据量很大，默认可能被截断

    每条命中约 **12KB**（36 个寄存器 + 调用栈 + 栈快照 256B）。
    2000 条就是 24MB——远超 MCP 单次返回上限，会被截断成残缺 JSON。
    所以**强烈建议用下面的参数裁剪**，而不是无参数全取。

    ## 参数（都是可选的，但建议至少给一个）

        bp_id            只返回**这个断点**的命中（形如 "serial:pid:so:5b76c"）。
                         这是最有效的裁剪方式——通常你只关心一个断点。
        limit            只返回**最近 N 条**（0 = 不限）。历史越长越该设。
        since_seq        只要 seq > 这个值的命中（增量拉取用）
        include_context  false 时省略 36 个寄存器（省最多空间）
        include_backtrace false 时省略调用栈
        include_stack    false 时省略 256 字节栈快照

    ## 按寄存器值过滤（P0）—— 从 2000 条里精准挑出你要的那几条

        filter={"x2": 5}                    只要 x2 == 5 的命中
        filter={"x0": "0x20", "x2": 5}      多个寄存器同时满足（AND）
        filter={"x2": {"in": [1, 4, 5]}}    值在集合里
        filter={"x2": {"min": 1, "max": 10}} 值在区间内（闭区间）

    支持的比较：等于（直接给值）/ "ne" 不等于 / "in" 集合 /
    "min"/"max" 区间 / "not_in" 不在集合。

    **典型场景**：2000 条命中里想找"命令号为 5"的那批，直接
    `filter={"x2": 5}`，不用取回来自己筛。

    ## 聚合统计（P1）—— 比返回原始数据有用得多

        group_by="x2"     → {"0x1": 523, "0x4": 437, "0x5": 210, ...}
        group_by="lr"     → 看哪个调用点最频繁
        group_by="thread_id" → 看是哪个线程在干活

    给了 group_by 时**不返回 hits 数组**（那正是你要避免的 3MB 数据），
    只返回聚合结果 + 少量样本。用 group_top 控制返回多少个桶（默认 50）。

    ## 返回

        count            本次返回的条数
        total_matched    过滤后**总共**匹配多少条（可能 > count，说明被 limit 截断）
        hits[]           命中列表
        hits_discarded   因超出保留上限被丢掉的旧命中数
        fields_omitted   本次省略了哪些字段（让调用方知道数据不全）
        size_hint        估算的 JSON 体积（KB），方便判断要不要再裁剪

    ## 典型用法

        # 只关心 malloc 那个断点，最近 5 条，不要寄存器
        hits(bp_id="3e2ff172:22747:libc.so:48d3c", limit=5, include_context=False)

        # 增量拉取
        hits(since_seq=1000, limit=50)
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        items = svc.hits(serial, int(pid))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "NOT_ATTACHED")})
    # 顺带把丢弃计数带出去：快照不一定反映"历史全貌"
    discarded = None
    try:
        tgt = svc._targets.get(f"{serial}:{pid}")          # noqa: SLF001 - 只读
        dbg = getattr(tgt, "dbg", None) if tgt is not None else None
        discarded = getattr(dbg, "_hits_discarded", None)
    except Exception:                                     # noqa: BLE001
        discarded = None

    total_before = len(items)

    # (24) 第二十四次修改（2026-11-06）：加过滤与裁剪，解决"数据太大被截断"。
    #      bug 原因：hits 无条件返回全部命中，每条约 12KB；实测 250 条就
    #               超过 3MB，MCP 返回被截断成**残缺 JSON**，调用方拿到的是
    #               坏数据而且没有任何提示——这比报错更糟。
    #      解决方案：① 支持按 bp_id / since_seq 过滤（最有效的裁剪）；
    #                ② limit 只取最近 N 条；
    #                ③ 可单独关掉 context / backtrace / stack 这些大字段；
    #                ④ 返回里给 total_matched 与 fields_omitted，
    #                   让调用方明确知道"这次拿到的不是全部"。
    want_bp = str(bp_id or "").strip()
    filtered: list = []
    for h in items:
        if since_seq and int(h.get("seq") or 0) <= int(since_seq):
            continue
        if want_bp:
            h_addr = h.get("static_addr")
            want_addr = None
            try:
                want_addr = int(want_bp.rsplit(":", 1)[-1], 16)
            except (ValueError, IndexError):
                want_addr = None
            if want_addr is None or int(h_addr or -1) != want_addr:
                continue
        filtered.append(h)

    # (26) 第二十六次修改（2026-11-06）：加寄存器值过滤（P0）。
    #      bug 原因：2000 条命中里想找"x2 == 5"那批，只能先取回 3 条
    #               （受返回体积限制）再自己看，根本筛不出想要的。
    #               寄存器是判断"这次调用是什么命令/什么分支"最直接的依据。
    #      解决方案：filter 支持按寄存器值筛选，比较方式包含等于 /
    #               不等 / 集合 / 区间；多条件是 AND。
    #               在 limit 之前执行——先筛再截，否则截完再筛就漏了。
    reg_filter = filter if isinstance(filter, dict) else None
    if reg_filter:
        filtered = [h for h in filtered if _hit_matches_filter(h, reg_filter)]
        if not filtered:
            return _j({
                "ok": True, "count": 0, "total_matched": 0, "hits": [],
                "filter": reg_filter,
                "total_before_filter": total_matched,
                "verdict": (f"共有 {total_matched} 条命中，但**没有一条**满足 "
                            f"filter={reg_filter}"),
                "hint": ("可用 group_by 先看这个寄存器有哪些值："
                         "hits(group_by='x2') 会给出值分布，"
                         "照着分布改 filter 即可"),
            })

    total_matched = len(filtered)

    if int(limit or 0) > 0:
        filtered = filtered[-int(limit):]                 # 最近的 N 条

    # 按需省略大字段
    omitted: list[str] = []
    trimmed: list = []
    for h in filtered:
        item = dict(h)
        if not include_context:
            item.pop("context", None)
            if "context" not in omitted:
                omitted.append("context")
        if not include_backtrace:
            item.pop("backtrace", None)
            if "backtrace" not in omitted:
                omitted.append("backtrace")
        if not include_stack:
            item.pop("stack", None)
            item.pop("stack_hex", None)
            if "stack" not in omitted:
                omitted.append("stack")
        trimmed.append(item)

    # (26) 第二十六次修改（2026-11-06）：加聚合统计（P1）。
    #      为什么：调用方真正想知道的是"这个寄存器的值都是什么分布"，
    #              而不是 2000 条原始 JSON。聚合后一次调用就能看出
    #              哪个命令号最常见、哪个调用点最热。
    #      设计：给了 group_by 就**不返回 hits 数组**——那正是要避免的数据量。
    #              但仍然给少量样本（最多 3 条），便于对照聚合结果。
    group_result = None
    if str(group_by or "").strip():
        group_result = _group_hits(filtered, str(group_by).strip(),
                                   int(group_top or 50))
        # 只留几条样本，不返回全量
        trimmed = filtered[:3] if filtered else []
        for h in trimmed:
            h.pop("backtrace", None)
            h.pop("stack", None)
            h.pop("stack_hex", None)
        size_kb = None
        all_frames = []
    else:
        # 汇总所有命中的调用栈，找出没符号化的模块
        all_frames = []
        for h in trimmed:
            all_frames.extend(h.get("backtrace") or [])
    hints = _backtrace_hints(all_frames)

    # 估算体积（KB），让调用方自己判断要不要再裁
    try:
        size_kb = len(_j(trimmed)) // 1024
    except Exception:                                     # noqa: BLE001
        size_kb = None

    out = {
        "count": len(trimmed),
        "total_matched": total_matched,
        "hits": trimmed,
        "hits_discarded": discarded,
        "note": ("hits_discarded 非 0 表示更早的命中已因保留上限被丢弃；"
                 "total_matched > count 说明被 limit 截断；"
                 "需要完整执行序列请用 poll_events 增量拉取"),
    }
    if group_result is not None:
        out["group_by"] = group_result["field"]
        out["groups"] = group_result["groups"]
        out["group_total"] = group_result["total"]
        out["group_distinct"] = group_result["distinct"]
        out["hits"] = trimmed
        out["count"] = len(trimmed)
        out["note"] = ("这是**聚合结果**，hits 只给了 3 条样本；"
                       "要原始数据就不要再传 group_by")
        if group_result.get("unparsed"):
            out["group_unparsed"] = group_result["unparsed"]
    if reg_filter:
        out["filter"] = reg_filter
    if omitted:
        out["fields_omitted"] = omitted
    if size_kb is not None:
        out["size_hint"] = f"{size_kb}KB"
        if size_kb > 800:
            out["hint"] = (f"本次返回约 {size_kb}KB，可能仍会被客户端截断；"
                           "建议加 bp_id 过滤、设 limit，或关掉 include_context")
    if total_matched > len(trimmed):
        out["truncated_by_limit"] = True
    if hints:
        out["hints"] = hints
    return _j(out)


@server.tool()
@logged()
def detach_target(serial: str, pid: int) -> str:
    """**断开目标进程**，移除所有断点并释放 frida 会话。

    什么时候用：
        · 分析结束，不想在目标里留任何 hook
        · 需要重新 attach 拿干净状态
        · 目标要重启了，先断开避免残留

    返回：{detached, message}。detached=false 表示本来就没附着。

    注意：断开**不会**解冻进程。如果之前 freeze 过，先 unfreeze_process。
    """
    from server.dyn.service import get_dyn

    try:
        ok = get_dyn().detach(serial, int(pid))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "DETACH_FAILED")})
    return _j({"detached": bool(ok),
               "message": "已断开" if ok else "本来就没有附着"})


@server.tool()
@logged()
def stop_frida(serial: str) -> str:
    """停止设备上**占用 27042** 的 frida-server（只停这一个）。

    只会停监听 27042 的进程；设备上其他 frida 实例（例如别的项目用的、
    监听别的端口的）**不会被触碰**，结果里会说明停了什么。

    返回：{stopped[], ok, message}
    """
    from server.dyn.adb import Adb

    try:
        return _j(Adb(serial).stop_frida())
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "STOP_FAILED")})


@server.tool()
@logged()
def preflight(serial: str = "") -> str:
    """**一次性体检**：现在的环境到底能不能做动态分析，缺什么。

    建议**每个新会话先调一次**（或遇到"连不上/起不来"时调），
    它会把问题一次性讲清楚，省掉一轮轮试错。

    返回结构：
        adb      {ok, path, message}            adb 是否可用
        devices  [...]                          在线设备列表
        active   {serial, root}                 当前设备是否 root
        frida    {running, path, code, message,
                  device_version, client_version,
                  version_match, holders[]}
                 running 以 **27042 端口**是否有监听为准（不是看进程名），
                 holders 是端口占用者 pid/名字；
                 version_match=false 时会说明"设备 17.x / 客户端 17.y"，
                 这时任何 attach 都会报 ProtocolError，先用 frida_server_align

    传 serial 则做该设备的完整体检；不传只看 adb 与设备列表。
    """
    from server.dyn.adb import Adb

    try:
        return _j(Adb(serial or None).preflight())
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "PREFLIGHT_FAILED")})


@server.tool()
@logged()
def runtime_modules(serial: str, pid: int, keyword: str = "") -> str:
    """列出目标进程加载的模块及运行时基址。keyword 过滤模块名。"""
    # (2) 第二次修改：改走 DynSession 注册表。
    #     原因：每次调用都 attach/detach，既抖动又让断点无法复用同一会话。
    #     契约：返回字段与顺序不变。
    from server.dyn.service import get_dyn

    return _j(get_dyn().modules(serial, pid, keyword))


@server.tool()
@logged()
def set_breakpoint(serial: str, pid: int, so_name: str, static_addr: int,
                   hold: bool = False,
                   auto_resume_after_ms: int = 0) -> str:
    """在目标进程的某 so 静态地址上下断点。

    hold=False 命中即继续（只记录）；hold=True 挂起等待，
    调用 wait_hits 拿到命中后分析，再调 resume 放行。

    ## auto_resume_after_ms（强烈建议：hold=True 时设上）

    **忘记 resume 的后果是目标进程被 ANR 杀掉。** 设了这个值后：
    命中 → 抓现场 → 到点自动 resume，即使调用方忘了放行也不会卡死进程。

        set_breakpoint(..., hold=True, auto_resume_after_ms=2000)

    返回里会标 `auto_resume_ms`；真正触发自动放行时，
    事件流里会有一条 `auto_resumed`，**不是静默发生**。

    (21) 第二十一次修改（2026-11-16）：透传给 service，并修掉三个真缺陷。
        bug 原因：上一版把定时器**建在 set_breakpoint 那一刻**（tools.py 里的
                  _start_auto_resume），命中后并不会重新计时。于是
                  「下断点 → 60 秒后才命中」时，定时器早已到期并空转放过，
                  真正的命中照样永久挂住——兜底完全失效，而返回值里写着
                  auto_resume_ms=2000，属于静默的假保护。
                  另外它的去重键是 (serial,pid)，同一进程下第二个 hold 断点
                  会把第一个的定时器取消掉；也从未往**事件流**写 auto_resumed
                  （只写了 UI 日志），poll_events 看不到。
        解决方案：改为由 service 在**每个命中**上按 token 起定时器
                  （见 dyn/service.py 的 _schedule_auto_resume），
                  手动 resume 会取消对应定时器，到期/跳过/失败都进事件流。
                  本层只负责透传参数与把 pending 情况告诉调用方。
    """
    # (1) 第一次修改
    # bug 原因：原实现既不保存 dbg 也不 detach，函数一返回脚本就被回收，
    #           实测连续调用 attach=3 / detach=0，既泄漏又查不到断点。
    # (2) 第二次修改：改走 DynSession 注册表，断点由单例持有 → 真正持久。
    #     契约：保留 set 字段，新增 id/runtime_addr/persistent 等。
    # (135) 函数表警告 + auto_discover 见 load_so；此处仅断点。
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        bp = svc.set_breakpoint(serial, int(pid), so_name, int(static_addr),
                                hold=bool(hold),
                                auto_resume_after_ms=int(auto_resume_after_ms or 0))
    except Exception as exc:                      # noqa: BLE001 - DynError 带 code
        # 参数校验失败（例如给了 auto_resume 但 hold=False）必须让调用方能自纠，
        # 所以带上 code，而不是包装成一段人话。
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "BREAKPOINT_FAILED")})
    out = {"set": True, "persistent": True, **bp,
           "addr_facts": _addr_facts(so_name, int(static_addr))}
    if int(bp.get("auto_resume_ms") or 0) > 0:
        # 让 AI 一眼看到"兜底已经布防"，而不是只看到一个数字
        out["auto_resume_note"] = (
            f"命中后 {int(bp['auto_resume_ms'])}ms 自动放行；"
            "事件流里会出现 auto_resume_armed / auto_resumed")
        try:
            out["auto_resume_pending"] = svc.auto_resume_state(serial, int(pid))
        except Exception:                         # noqa: BLE001 - 只读信息，失败不影响下断
            pass
    return _j(out)


@server.tool()
@logged()
def read_process_memory(serial: str, pid: int, so_name: str, static_addr: int, size: int = 32) -> str:
    """按 so 静态地址读取目标进程内存（自动完成 ASLR 换算）。"""
    # (1) 第一次修改：size 越界与空结果都显式报错，不伪装成功（细节见 dyn/service.py）。
    # (2) 第二次修改：改走 DynSession 注册表，复用已附加的会话。
    from server.dyn.service import get_dyn

    try:
        data = get_dyn().read_memory(serial, pid, so_name, static_addr, size)
    except Exception as exc:                      # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}"})
    return _j({
        "static_addr": hex(data["static_addr"]),
        "runtime_addr": hex(data["runtime_addr"]),
        "hex": data["hex"],
        "size": data["size"],
        "addr_facts": _addr_facts(so_name, data["static_addr"]),
    })


@server.tool()
@logged()
def wait_hits(serial: str, pid: int, timeout: float = 10.0) -> str:
    """等待断点命中（阻塞到超时或出现新命中）。

    必须先用 set_breakpoint 下断；hold=True 的断点会挂住目标线程，
    拿到命中后用 resume 放行。
    """
    from server.dyn.service import get_dyn

    return _j({"hits": get_dyn().wait_hits(serial, pid, timeout=timeout)})


@server.tool()
@logged()
def resume(serial: str, pid: int) -> str:
    """放行 hold 策略下挂起的线程（重复调用无副作用）。"""
    from server.dyn.service import get_dyn

    return _j({"resumed": get_dyn().resume(serial, pid)})


# ---- 动态观测工具：事件流 / 线程列表 / 调用栈符号化 ----

# 一次性 frida 探针：跑完立刻 unload，不持有脚本、不留 hook。
# 取数方式与 dyn/rebase.py 既有做法一致（JS send → Python 侧轮询等消息）。
_JS_LIST_THREADS = """
(function () {
    var out = Process.enumerateThreads().map(function (t) {
        // frida 16 的线程对象只有 id/state/context，name 是 17 才有的字段：
        // 只有真拿到 name 才发这个键，缺失交给 Python 侧补 None。
        var item = {id: t.id, state: t.state || null};
        if (typeof t.name === "string") { item.name = t.name; }
        if (t.context) {
            try { item.pc = t.context.pc.toString(); } catch (e) { item.pc = null; }
        }
        return item;
    });
    send({threads: out});
})();
"""

# 取调用栈：Thread.backtrace(context, ACCURATE) 给的是**运行时**地址裸值，
# 不做 frida 的 DebugSymbol 解析——符号化统一在 Python 侧用 mda 静态模型做。
_JS_CALLSTACK = """
(function () {
    var tid = __TID__;
    var limit = __LIMIT__;
    var threads = Process.enumerateThreads();
    if (threads.length === 0) {
        send({err: "THREADS_UNAVAILABLE: frida 对该进程枚举不到线程" +
                   "（实测多数 app 如此，system_server 才行）；" +
                   "替代方案：下断点命中后用 hits[].backtrace 取命中时刻的调用栈，那条路不依赖线程枚举"});
        return;
    }
    var t = threads[0];
    for (var i = 0; i < threads.length; i++) {
        if (threads[i].id === tid) { t = threads[i]; break; }
    }
    if (!t.context) {
        send({err: "线程 " + t.id + " 没有可用 context，无法取栈"});
        return;
    }
    var addrs = [];
    var mode = "__MODE__";
    if (mode === "scan") {
        // 启发式扫描：栈上任何"看起来像返回地址"的值都算候选。
        // 判据（保守，宁可少给也不错给）：
        //   ① 落在某个已加载模块的 [base, base+size) 内
        //   ② 该地址 -4 处的指令是 bl / blr（说明它确实是返回点）
        try {
            var mods = Process.enumerateModules();
            var sp = t.context.sp;
            var scanBytes = Math.min(__SCANBYTES__, 4096);
            var seen = {};
            for (var off = 0; off < scanBytes; off += 8) {
                var v = 0;
                try { v = ptr(sp).add(off).readPointer(); } catch (e) { continue; }
                if (v === null) { continue; }
                var val = v.toUInt32 ? v.toString() : String(v);
                var pv = parseInt(val, 16);
                if (!pv || isNaN(pv)) { continue; }
                for (var mi = 0; mi < mods.length; mi++) {
                    var m = mods[mi];
                    var mb = parseInt(m.base.toString(), 16);
                    if (pv > mb && pv < mb + m.size) {
                        // 检查前一条指令是不是调用。ARM64 编码（精确位域）：
                        //   bl  imm26 : 100101 | imm26   → (w & 0xFC000000) === 0x94000000
                        //   blr Xn    : 1101011000111111 000000 Rn 11111
                        //                               → (w & 0xFFFFFC1F) === 0xD63F0000
                        // 早期写成 `top6 === 0x3F` 是错的：那匹配的是 stur/stp，
                        // 而 blr 的真实高 6 位是 0x35 —— 间接调用全漏、非调用点误判。
                        var isCall = false;
                        try {
                            var w = ptr(pv - 4).readU32();
                            var isBl = (w & 0xFC000000) === 0x94000000;
                            var isBlr = (w & 0xFFFFFC1F) === 0xD63F0000;
                            isCall = isBl || isBlr;
                        } catch (e) {}
                        if (isCall && !seen[pv]) {
                            seen[pv] = 1;
                            addrs.push(ptr(pv).toString());
                        }
                        break;
                    }
                }
                if (addrs.length >= limit) { break; }
            }
            send({tid: t.id, frames: addrs, heuristic: true,
                  scanned_bytes: scanBytes,
                  note: "启发式扫描：只返回落在模块内、且前一条指令是 bl 的候选，不保证完整"});
            return;
        } catch (e) {
            send({err: "扫描栈失败: " + String(e)});
            return;
        }
    }
    try {
        addrs = Thread.backtrace(t.context, Backtracer.ACCURATE)
            .map(function (a) { return a.toString(); });
    } catch (e) {
        send({err: "取调用栈失败: " + String(e)});
        return;
    }
    send({tid: t.id, frames: addrs.slice(0, limit), heuristic: false});
})();
"""


def _run_frida_script(session, js: str, wait_s: float = 5.0) -> dict:
    """跑一段一次性 frida 脚本，取它 send() 出的第一个 dict 载荷。

    消息回调是异步的，所以按 dyn/rebase.py 的既有做法轮询等待；
    脚本用完立刻 unload——探针不能持有会话，也不能留下 hook。
    返回空 dict 表示超时或无 dict 载荷（调用方据此给 error）。
    """
    got: list[dict] = []

    def _on_message(msg, data=None):
        if isinstance(msg, dict) and msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                got.append(payload)

    script = session.create_script(js)
    script.on("message", _on_message)
    script.load()
    try:
        step = 0.05
        for _ in range(max(int(wait_s / step), 1)):
            if got:
                break
            time.sleep(step)
    finally:
        try:
            script.unload()
        except Exception:                # noqa: BLE001 - 卸载失败不该盖住真实结果
            pass
    return got[0] if got else {}


def _as_int_addr(value) -> int | None:
    """把 int / "0x..." / frida NativePointer 统一成 int，转不了给 None。

    地址字段缺失是常态（frida 16 没线程 name、context 可能为 null），
    这里一律不抛异常，交给调用方决定怎么展示。

    (5) 第五次修改（2026-11-02）：纯数字字符串按十进制解析，不再一律当十六进制。
        bug 原因：旧实现无条件 int(str(value), 16)，于是 "12" 被解析成 18
                 （0x12），而不是 12。这个值被当作线程 id / 地址使用时，
                 会**静默指向完全错误的对象**——实测 get_callstack 传入
                 "12" 会取到线程 18 的栈，且失败后还自动退回 threads[0]，
                 使用者根本察觉不到取错了。
        解决方案：
                  · 带 0x/0X 前缀        → 十六进制
                  · 纯十进制数字串        → 十进制（人类和 JSON 的默认语义）
                  · 含 a-f 且无前缀       → 十六进制（地址常见写法 "7fff1234"）
                  · 其他（如 "<ptr>" 之类）→ None
                这样 "12" 是 12、"0x12" 是 18、"7f0000" 是地址，语义都符合直觉。
    """
    # (15) 第十五次修改（2026-11-05）：解析逻辑收口到 core.addr，本函数只做转调。
    #      bug 原因：项目里四份地址解析实现规则不一致（典型分歧见 core/addr.py 顶注），
    #                "含 a-f 但无 0x 前缀"的地址在本处能解析、在另外三处解析不出来。
    #      解决方案：统一走 core.addr.parse_addr，本处保留原签名与返回约定（失败 None）。
    from server.core.addr import parse_addr

    return parse_addr(value)

def _thread_dict(t) -> dict:
    """把线程对象或线程 dict 统一成 {id, name, state, pc}。

    关键兼容点：**frida 16 的线程对象没有 name 字段**（17 才有），
    所以一律走 getattr / dict.get 兜底，缺失返回 None 而不是抛 AttributeError。
    pc 优先取扁平字段（探针脚本已拍平），退化到 context.pc
    （dyn 层直接回传 frida 原生线程对象时只有 context 这一个嵌套来源）。
    """
    if isinstance(t, dict):
        def get(key, default=None):
            return t.get(key, default)
    else:
        def get(key, default=None):
            return getattr(t, key, default)

    pc = _as_int_addr(get("pc"))
    if pc is None:
        ctx = get("context")
        if isinstance(ctx, dict):
            pc = _as_int_addr(ctx.get("pc"))
        elif ctx is not None:
            pc = _as_int_addr(getattr(ctx, "pc", None))
    return {
        "id": _as_int_addr(get("id")),
        "name": get("name"),                       # frida 16 → None
        "state": get("state"),
        "pc": hex(pc) if pc is not None else None,
    }


def _call_threads(fn, serial, pid):
    """调线程枚举函数，自动适配它要几个参数。

    svc.threads(serial, pid) 需要两个参数，dbg.threads()/rb.threads() 不需要。
    这里按签名判定，而不是 try/except TypeError 重试——后者会把函数**内部**
    抛出的 TypeError 误当成「参数不对」，导致重复调用并掩盖真实错误。
    """
    import inspect

    try:
        need = len(inspect.signature(fn).parameters)
    except (TypeError, ValueError):      # 内建函数等取不到签名：按无参处理
        need = 0
    return fn(serial, pid) if need >= 2 else fn()


def _threads_from_layers(svc, tgt):
    """按已有实现层级依次尝试枚举线程，**都拿不到有效结果**时返回 None。

    优先级：service（跨层聚合）→ debugger（frida 层）→ rebase（地址桥）。
    这三层由 dyn/ 的同事并行实现、可能尚无该方法，故全部 getattr 判空。

    (6) 第六次修改（2026-11-02）：空列表一律视为"这一层没给出结果"，继续往下试。
        bug 原因：旧实现 `if raw is not None: return raw`，把 `[]`（空列表）也
                 当成有效结果直接返回。于是某一层 RPC 失败返回 `[]` 时，上层
                 会输出「该进程 0 个线程」——一个**没有任何 error 字段的成功响应**，
                 使用者会以为进程真的没有线程，而不是查询失败。
        解决方案：只有非空列表才算这一层成功；空列表记录后继续降级，
                 最终全空则由调用方回明确的 error。
    """
    serial = getattr(tgt, "serial", None)
    pid = getattr(tgt, "pid", None)
    for fn in (
        getattr(svc, "threads", None),
        getattr(getattr(tgt, "dbg", None), "threads", None),
        getattr(getattr(tgt, "rb", None), "threads", None),
    ):
        if not callable(fn):
            continue
        raw = _call_threads(fn, serial, pid)
        if raw:
            return raw
    return None


def _recent_thread_id(tgt) -> int:
    """最近一次断点命中的线程 id；无命中返回 0（交给 frida 侧取第一个线程）。"""
    hits = list(getattr(getattr(tgt, "dbg", None), "hits", None) or [])
    if not hits:
        return 0
    return int(getattr(hits[-1], "thread_id", 0) or 0)


# (27) 第二十七次修改（2026-11-13）：本文件不再自己维护别名规则。
#     bug 原因：_strip_version_tag / _pick_so_by_name 是**第三套**别名实现
#               （另两套在 core.session 与 dyn.bridge），三处各写一遍容易走样；
#               更要紧的是它们只被符号化等少数路径用到，绝大多数工具仍
#               直接 _session.get(so_name) 抛 KeyError。
#     解决方案：规则统一收敛到 server.core.session.match_name，
#               Session.get/resolve 内部自动解析；这里保留同名薄封装，
#               一是不打断既有调用方（dyn.bridge._find_so、dyn.rebase、
#               R29/R33 回归测试都直接 import 这两个名字），
#               二是把它们变成**同一份规则**的入口而不是第二份实现。
_strip_version_tag = _core_strip_version_tag


def _pick_so_by_name(session, raw_name: str):
    """按别名在会话里找 SoFile，找不到返回 None。

    (11) 第十一次修改（2026-11-02）：新增本函数。
        bug 原因：真机 frida 的模块名可能是完整路径或带壳前缀，而 mda 的键
                  是 load_so 时的短名。只用精确全名匹配会让整条调用栈符号化失败，
                  还会误报"该 so 未加载"。
        解决方案：按 全名 → basename → 去壳前缀 → 后缀 四级别名依次尝试。
                  只做**去前缀/取 basename**这类无损规范化，不做模糊猜测，
                  避免把 A.so 错配成 B.so。

    (12) 第十二次修改（2026-11-06）：增加"去版本号"这一级。
        背景：设备名 libsgmainso-6.7.260202.so ↔ 本地 libsgmainso.so，
              前四级全部匹配不上。这是加固样本的普遍现象，不是个例。
        位置：放在后缀匹配**之前**、且要求**候选唯一**，比模糊后缀更可靠。

    (27) 第二十七次修改（2026-11-13）：改为调用 core.session.match_name。
         bug 原因：规则与 Session.resolve 各存一份，两处一旦不同步，
                   "session.get 认、这里不认"或反之，用户看到的行为就自相矛盾。
         解决方案：只做"取名字列表 → 交给 match_name → 取首个命中"，
                   不再持有任何匹配规则。找不到仍返回 None（保持原契约，
                   因为调用方用它判断 in_gap，而不是当异常处理）。
    """
    try:
        so, _key = session.resolve(raw_name)
        return so
    except KeyError:
        return None
    except Exception:                                     # noqa: BLE001
        # 兼容只实现了 modules 字典的轻量替身（测试桩）
        mods = getattr(session, "modules", {}) or {}
        hit, _how, _amb = _core_match_name(str(raw_name or ""), list(mods))
        return mods.get(hit) if hit else None


def _symbolize_frame(runtime_addr: int, mods: list, session) -> dict:
    """把一帧运行时地址符号化到 mda 自己的静态模型。

    不用 frida 的 DebugSymbol.fromAddress：stripped 的壳样本上它没有符号表
    可用，基本只能给裸地址。mda 的函数表来自 FDE + bl 目标 + 序言补全，才有名字。

    换算：mods 就是 rb.refresh_modules() 的返回，与 rb.find_module(name) 查的是
    同一批 RuntimeModule；这里按**地址范围**匹配所属模块（比逐帧按名 find_module
    更准也更快），base 即 mod.base.
    """
    frame = {
        "runtime_addr": hex(runtime_addr),
        "static_addr": None,
        "so": None,
        "function": None,
        "offset": None,
        "via_plt": False,
        "in_gap": True,
        # (9) JNI 交界标记：true 表示这一帧是 Java→so 的入口
        "jni": False,
    }
    mod = None
    for m in mods:
        if m.base <= runtime_addr < m.base + m.size:
            mod = m
            break
    if mod is None:
        # 不在任何已加载模块的映射范围：frida trampoline / JIT / 匿名段
        return frame

    static = runtime_addr - mod.base
    frame["so"] = mod.name
    frame["static_addr"] = hex(static)
    frame["in_gap"] = False

    # (11) 第十一次修改（2026-11-02）：按多级候选匹配模块名，不再只认全名。
    #     bug 原因：旧实现 session.modules.get(mod.name) 是**精确全名**匹配。
    #               真机上 frida 报的 mod.name 常是完整路径（如
    #               "/data/app/.../liblog.so"）或带壳前缀（"_t1_xxx.so"），
    #               而 mda 里的键是 load_so 时的短名，两者对不上 → 整帧判
    #               in_gap 并谎称"该 so 未在 mda 中加载"，实际早就加载了。
    #               实测：传 basename 能符号化出 android_log_write_int64，
    #               传全路径则返回 in_gap=True 且给出误导性提示。
    #     解决方案：依次尝试 全名 → basename → 去壳前缀规范化 → 模糊后缀匹配，
    #               命中即用；全部失败才判未加载，且提示里给出实际可用的键名，
    #               便于人工核对。
    so = _pick_so_by_name(session, mod.name)
    if so is None:
        # 设备上有、mda 里确实没有：能给出 so + 偏移，但给不出函数名
        frame["in_gap"] = True
        loaded = list(getattr(session, "modules", {}) or {})
        frame["note"] = ("该 so 未在 mda 中加载，先调 load_so；"
                         f"当前已加载：{loaded[:6]}")
        return frame

    fn = so.function_at(static)
    if fn is not None:
        frame["function"] = fn.name or f"sub_{fn.addr:x}"
        frame["offset"] = static - fn.addr
        # (9) JNI 交界识别：JNI 静态注册的函数名遵循 Java_<包>_<类>_<方法>
        #     约定（Android 官方规范，非样本特征）。命中即标 jni=true，
        #     提示调用方"这一帧之上就跨进 Java 层了"。
        _fname = frame["function"] or ""
        if _fname.startswith("Java_") or "JNI_OnLoad" in _fname:
            frame["jni"] = True
            frame["jni_note"] = ("JNI 入口帧：再往上是 Java 层，"
                                 "用 java_stacktrace / stack_all_threads 接上")
        return frame

    # function_at 返回 None = 落在函数空洞或 PLT 桩区间里，不是错误
    plt = so.plt_name(static)
    if plt:
        frame["function"] = plt
        frame["offset"] = 0
        frame["via_plt"] = True
    else:
        frame["in_gap"] = True
    return frame


def _target_state(svc, serial: str, pid: int) -> dict:
    """从 service.state() 里筛出单个目标的状态（state() 无参、返回全部目标）。

    state() 会只读同步 dbg.hits 到事件队列，但不推进 poll 游标，
    所以 pending_events 可以放心当成「还有多少没取」的信号。
    """
    try:
        st = svc.state()
    except Exception:                    # noqa: BLE001 - 状态查询失败不该盖住事件
        return {}
    key = f"{serial}:{pid}"
    for t in (st.get("targets") or []):
        if t.get("key") == key:
            return {
                "target_state": t.get("state"),        # attached / paused / detached
                "dbg_state": t.get("dbg_state"),
                "pending_events": t.get("pending_events", 0),
                "last_seq": t.get("last_seq", 0),
                "global_seq": st.get("seq", 0),
            }
    return {"global_seq": st.get("seq", 0)}


@server.tool()
@logged()
def poll_events(serial: str, pid: int, timeout: float = 0.0, limit: int = 200,
                after_seq: int = 0) -> str:
    """非阻塞地取动态事件，并附上目标当前状态。

    **推荐工作流**：
        1) set_breakpoint(hold=True) 下断；
        2) resume 放行，让目标跑起来；
        3) poll_events(timeout=0) 收事件——有就立刻返回，没有给空列表，不卡住；
        4) 看到 type=breakpoint_hit 且 hold=true 时，目标已 paused，
           分析完必须再调 resume 放行，否则线程一直停在那里。

    每条事件都带 seq / type / ts / key / serial / pid，其余字段随 type 而定：
        attached / detached / breakpoint_set / breakpoint_hit /
        breakpoint_removed / breakpoint_remove_failed / resumed
    seq 单调自增，所以「有没有新事件」看 last_seq 与 global_seq 的差即可。

    timeout=0（默认）立即返回；timeout>0 最多等这么久，等到就立刻回。
    返回里的 target_state 为 paused 表示线程正被 hold 断点挂住、等 resume。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    # (14) 第十四次修改（2026-11-05）：把 after_seq 真正透传给 service。
    #      bug 原因：service.poll_events 已实现三档游标语义（None=推进游标取新增、
    #                0=从头/显式指定、N=取 seq>N），但 MCP 工具签名里没有该参数，
    #                于是"增量拉取 / 显式重放"在 AI 侧根本不可达。
    #      解决方案：加 after_seq 参数；<=0 视为"不指定"（保持原来的推进语义），
    #                >0 时按"只取 seq 大于它的事件"且**不推进**共享游标。
    seq = int(after_seq or 0)
    kwargs = {"timeout": timeout, "limit": limit}
    if seq > 0:
        kwargs["after_seq"] = seq
    try:
        events = svc.poll_events(serial, pid, **kwargs)
    except Exception as exc:             # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}"})
    return _j({
        "has_new": bool(events),
        "count": len(events),
        "events": events,
        "after_seq": seq if seq > 0 else None,
        **_target_state(svc, serial, pid),
    })


@server.tool()
@logged()
def list_threads(serial: str, pid: int) -> str:
    """列出目标进程的线程（id / name / state / pc）。

    兼容 frida 16 与 17：16 的线程对象**没有 name 字段**，此时 name 返回 null
    （不是报错），可用 name_supported 判断当前设备端是否支持线程名。
    pc 是该线程当前的程序计数器，可直接喂给 get_callstack 对照。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        tgt = svc.attach(serial, pid)    # 幂等：已附加则复用同一会话
    except Exception as exc:             # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}"})

    try:
        raw = _threads_from_layers(svc, tgt)
        if raw is None:
            # 三层都还没有线程枚举能力：用一次性探针自己取，工具先能上线
            payload = _run_frida_script(tgt.rb.session, _JS_LIST_THREADS)
            if "err" in payload:
                return _j({"error": payload["err"]})
            raw = payload.get("threads")
        if raw is None:
            return _j({"error": "线程枚举无响应（探针脚本超时），目标可能已退出"})
        threads = [_thread_dict(t) for t in raw]
    except Exception as exc:             # noqa: BLE001 - frida 异常类型不稳定
        return _j({"error": f"{type(exc).__name__}: {exc}"})

    # (13) 第十三次修改（2026-11-05）：frida 枚举为空时**不能当成功**，改用 /proc 兜底。
    #      bug 原因：实测 frida 17.23.3 对多数进程 Process.enumerateThreads() 恒返回
    #               空（systemui/logd/zygote 都是 0，只有 system_server 能给 233 个）。
    #               而本工具此前会返回 {"count": 0, "error": null} —— 一个**看起来
    #               成功的响应**，等于告诉调用方"这个进程没有线程"。进程明明有
    #               几十个线程，这是彻头彻尾的假信息，比报错更危险。
    #     解决方案：① 空结果不再直接返回，先用 root 读 /proc/<pid>/task 拿真实 TID；
    #               ② 拿到的 tid 列表如实标注 source="proc"、name_supported=false，
    #                  并给出 unavailable_reason 说明为什么没有 name/state/pc；
    #               ③ 两条路都拿不到才报 THREADS_UNAVAILABLE 错误。
    #               这样"能用"和"不能用"都有明确交代，不存在假 0。
    def _threads_from_proc() -> list[int]:
        """从 /proc/<pid>/task 取线程号（root 权限可用，实测稳定）。"""
        try:
            from server.dyn.adb import Adb

            out = Adb(serial)._cmd(
                "shell", "su", "-c", f"ls /proc/{pid}/task 2>/dev/null", check=False)
        except Exception:                                 # noqa: BLE001
            return []
        return [int(x) for x in (out or "").split() if x.isdigit()]

    if not threads:
        tids = _threads_from_proc()
        if tids:
            return _j({
                "count": len(tids),
                "name_supported": False,
                "source": "proc",
                "threads": [{"id": t, "name": None, "state": "unknown", "pc": None}
                            for t in sorted(tids)],
                "unavailable_reason": (
                    "frida 的 Process.enumerateThreads() 对该进程返回空"
                    "（实测 systemui/logd/zygote 均如此，只有 system_server 可用）。"
                    "已改用 /proc/<pid>/task 兜底：线程号是真实的，"
                    "但拿不到 name/state/pc（这些只有 frida 的线程对象才有）。"
                    "需要 pc/调用栈时请换一个 frida 能枚举线程的目标进程。"),
            })
        return _j({
            "error": f"无法枚举 pid {pid} 的线程：frida 返回空，/proc/{pid}/task 也读不到",
            "code": "THREADS_UNAVAILABLE",
            "count": 0,
        })

    return _j({
        "count": len(threads),
        "name_supported": any(t["name"] is not None for t in threads),
        "source": "frida",
        "threads": threads,
    })


def _dwarf_reg_source(svc, serial: str, pid: int, tid: int) -> tuple[dict, dict]:
    """取 DWARF 展开所需的"真实现场"：寄存器快照 + 来源说明。

    (135) 第一百三十五次修改（2026-11-16）：新增本函数。
        bug 原因：dwarf 展开需要 pc / sp / x0..x30 + 各帧的栈内存，
                  而"这些值从哪来"原先散在工具函数里，且只取 hits() 的
                  最后一条——多线程交替命中时可能取到**别的线程**的现场，
                  展开出来的调用栈属于另一条线程，使用者完全察觉不到。
        解决方案：① 优先按 thread_id 精确匹配命中记录（同一线程才是同一条栈）；
                  ② 没有该线程的命中时退回最近一条，并在返回里标明
                     `regs_source` 说明取的是谁的现场；
                  ③ 断点没命中过就明确报错（不给空栈冒充"栈就这么浅"）。

    返回 (regs, meta)。regs 已把 "0x..." 形态的寄存器值转成 int。
    """
    regs: dict = {}
    meta: dict = {"source": "", "hit_seq": None, "hit_thread": None}

    got: list = []
    try:
        got = svc.hits(serial, int(pid)) or []
    except Exception as exc:                              # noqa: BLE001
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return regs, meta
    if not got:
        return regs, meta

    chosen = None
    if tid:
        for h in reversed(got):        # 从最近往前找，优先最近的同线程命中
            if int(h.get("thread_id") or 0) == int(tid):
                chosen = h
                meta["source"] = "hit:same_thread"
                break
    if chosen is None:
        chosen = got[-1]
        meta["source"] = "hit:latest"
        meta["thread_mismatch"] = (
            f"线程 {tid} 没有命中记录，退回最近一次命中（线程 "
            f"{chosen.get('thread_id')}）的现场；这条栈属于那个线程")

    meta["hit_seq"] = chosen.get("seq")
    meta["hit_thread"] = chosen.get("thread_id")
    for k, v in (chosen.get("context") or {}).items():
        iv = _as_int_addr(v)
        if iv is not None:
            regs[str(k)] = iv
    return regs, meta


def _callstack_dwarf(serial: str, pid: int, tgt, tid: int, limit: int,
                     so_name: str) -> str:
    """method="dwarf"：用 .eh_frame 的 DWARF CFI 规则逐帧展开调用栈。

    (135) 第一百三十五次修改（2026-11-16）：新增。

    为什么要有这一条路：frida 的 ACCURATE 回溯在 PAC + 无帧指针的 so 上
    实测只有 2 帧（同一个地址重复）。这条路**完全不经过 frida 的 unwind**，
    而是纯静态解析 .eh_frame + Python 逐帧执行 CFA 规则（libunwind 的原理）。

    数据来源：
        寄存器  最近一次断点命中的 context（36 个寄存器，真实现场）
        栈内存  service.read_runtime（adb /proc/<pid>/mem 优先，
                hold 把线程挂住时照样能读）
        CFI     目标 so 的 .eh_frame（load_so 进来的那个文件）

    结果可信度：返回里一定带 cfi_coverage。CFI 被剥离的样本
    （实测 sscronet.so 只有 392 字节 / 13 条 FDE / 覆盖 0.04%）
    会带 enough=false + warning，**绝不假装成功**。
    """
    from server.core.dwarf import CfiUnavailable, CfiUnwinder

    regs, meta = _dwarf_reg_source(_dyn_service(), serial, pid, tid)

    if not regs:
        return _j({
            "error": "dwarf 回溯需要断点现场的寄存器（pc/sp/x0..x30），"
                     "但该进程还没有任何断点命中记录",
            "code": "NO_CONTEXT",
            "method": "dwarf",
            "hint": ("① set_breakpoint(hold=True) 让目标命中一次；"
                     "② 再调 get_callstack(method='dwarf')；"
                     "③ 不想下断点就用 method='scan'（启发式扫栈，不需要现场）"),
        })
    pc = regs.get("pc")
    sp = regs.get("sp")
    if not pc or not sp:
        missing = [n for n in ("pc", "sp") if not regs.get(n)]
        return _j({
            "error": f"断点现场缺少 {missing}，无法确定展开起点",
            "code": "NO_PC_OR_SP",
            "method": "dwarf",
            "context_keys": sorted(regs)[:40],
        })

    # ---- 组装模块表：展开可能跨 so，每个模块都用它自己的 .eh_frame ----
    # (6) refresh 需要活的会话；会话没了就退到缓存，别让整条回溯废掉。
    mods = None
    mods_source = "frida"
    try:
        mods = tgt.rb.refresh_modules()
    except Exception as exc:                              # noqa: BLE001
        cached = getattr(tgt.rb, "_modules", None)
        if cached:
            mods = list(cached)
            mods_source = "cached"
        else:
            return _j({
                "error": f"拿不到模块表（会话已失效且没有缓存）：{exc}",
                "code": "NO_MODULE_TABLE", "method": "dwarf",
                "hint": ("① 目标可能已退出/被冻结，重新 attach 后立刻重试；"
                         "② 或改用 method='scan'（不需要模块表）"),
            })
    if not mods:
        return _j({"error": "模块表为空，无法定位帧所属 so",
                   "code": "NO_MODULE_TABLE", "method": "dwarf"})

    want = str(so_name or "").strip()
    reader = _MakeReadMem(_dyn_service(), serial, pid)
    w = CfiUnwinder(read_mem=reader)
    registered: list[str] = []
    skipped: list[str] = []
    for m in mods:
        so = _pick_so_by_name(_session, m.name)
        w.add_module(m.base, m.size, so, m.name)
        if so is not None:
            registered.append(m.name)
        elif want and _core_match_name(want, [m.name])[0]:
            skipped.append(m.name)

    # 起点 pc 所属模块若没载入 so，明确说出来（否则只会得到"无 FDE 覆盖"）
    start_mod = None
    for m in mods:
        if m.base <= pc < m.base + m.size:
            start_mod = m
            break
    if start_mod is None:
        return _j({
            "error": f"起点 pc {pc:#x} 不在任何已加载模块范围内"
                     "（frida trampoline / JIT / 已卸载的 so 都会这样）",
            "code": "PC_NOT_IN_MODULE", "method": "dwarf",
            "pc": hex(pc), "sp": hex(sp),
            "hint": "换一个落在目标 so 内的断点地址再试",
        })
    start_so = _pick_so_by_name(_session, start_mod.name)
    if start_so is None:
        return _j({
            "error": f"起点所在的 {start_mod.name} 没有在 mda 中加载，"
                     "拿不到它的 .eh_frame",
            "code": "SO_NOT_LOADED", "method": "dwarf",
            "so": start_mod.name,
            "hint": f"先 load_so 载入 {start_mod.name} 后重试",
        })

    try:
        out = w.unwind(pc, regs, limit=int(limit))
    except CfiUnavailable as exc:
        return _j({
            "error": exc.message, "code": exc.code, "method": "dwarf",
            "cfi_coverage": exc.coverage,
            "frames": [], "frame_count": 0,
            "hint": ("这个 so 的 CFI 不可用。改用 method='scan'（启发式扫栈）"
                     "或 method='accurate'（frida），并注意它们同样可能不完整"),
        })

    # ---- 符号化：与 accurate/scan 走同一套静态模型 ----
    frames = out["frames"]
    for fr in frames:
        fr["runtime_addr"] = hex(fr["pc"])
        fr["function"] = None
        fr["offset"] = None
        fr["via_plt"] = False
        fr.setdefault("in_gap", True)
        fr["static_addr"] = (hex(fr["static_addr"])
                             if isinstance(fr.get("static_addr"), int) else None)
        so = _pick_so_by_name(_session, fr.get("so") or "")
        if so is None or not fr.get("static_addr"):
            continue
        static = int(fr["static_addr"], 16)
        fn = so.function_at(static)
        if fn is not None:
            fr["function"] = fn.name or f"sub_{fn.addr:x}"
            fr["offset"] = static - fn.addr
            fr["in_gap"] = False
        else:
            plt = so.plt_name(static)
            if plt:
                fr["function"] = plt
                fr["offset"] = 0
                fr["via_plt"] = True
                fr["in_gap"] = False

    symbolized = sum(1 for f in frames if f.get("function"))
    out.update({
        "thread_id": tid,
        "frame_count": len(frames),
        "symbolized": symbolized,
        "unresolved": len(frames) - symbolized,
        "regs_source": meta,
        "so": start_mod.name,
        "start": {"pc": hex(pc), "sp": hex(sp)},
        "note": ("DWARF CFI 展开（纯静态解析 .eh_frame + Python 逐帧执行 CFA 规则，"
                 "不经过 frida 的 unwind）；符号化与 accurate/scan 同源于 mda 静态模型"),
    })
    if out.get("cfi_coverage", {}).get("enough") is False:
        out["verdict"] = ("CFI 覆盖不足，这条栈**不可信**——见 cfi_coverage.warning。"
                          "它只能说明起点那个函数被 CFI 覆盖，再往上就断了")
    return _j(out)


def _dyn_service():
    """取动态服务单例（延迟导入，避免 tools 顶层依赖 dyn）。"""
    from server.dyn.service import get_dyn

    return get_dyn()


class _MakeReadMem:
    """把 service.read_runtime 包成 read_mem(addr, size) -> bytes 回调。

    (135) 第一百三十五次修改（2026-11-16）：新增。
        为什么需要适配层：CfiUnwinder 每帧要在 CFA 附近预取一小段栈，
                  而 service.read_runtime 单次上限 4096 字节且会走
                  "adb /proc/<pid>/mem → frida"两级降级。这里统一裁到
                  4096 以内，读失败返回空字节（展开器据此判定"该栈地址
                  读不到"，而不是把它当 0 继续往下走——那会造出假帧）。
    """
    _MAX = 4096

    def __init__(self, svc, serial: str, pid: int) -> None:
        self._svc = svc
        self._serial = serial
        self._pid = int(pid)
        self.failures = 0

    def __call__(self, addr: int, size: int) -> bytes:
        try:
            size = max(1, min(int(size), self._MAX))
        except (TypeError, ValueError):
            return b""
        try:
            got = self._svc.read_runtime(self._serial, self._pid, int(addr), size)
        except Exception:                                 # noqa: BLE001
            self.failures += 1
            return b""
        raw = got.get("hex") if isinstance(got, dict) else None
        if not raw:
            self.failures += 1
            return b""
        try:
            return bytes.fromhex(raw)
        except ValueError:
            self.failures += 1
            return b""


@server.tool()
@logged()
def get_callees(so_name: str, addr: int, depth: int = 1) -> str:
    """取某函数调用了谁 —— `call_chain` 的薄别名。

    (1) 第一次修改（2026-11-17）：新增别名。
        bug 原因：审查实测 `get_callees` 是 unknown tool，使用者以为它是
                  标准工具，浪费了一轮。实际 mda 里对应能力叫 `call_chain`
                  / `xrefs_from`，只是名字不同。
        解决方案：加一个薄别名，复用 call_chain（**不重复实现**）。

    等价于 call_chain(so_name, addr, depth=1)。
    """
    return call_chain(so_name, int(addr), depth=max(1, min(int(depth), 1)))


@server.tool()
@logged()
def get_function_by_address(so_name: str, addr: int) -> str:
    """按地址查所在函数 —— 复用 `addr_facts` + `function_at`。

    (1) 第一次修改（2026-11-17）：新增工具。
        bug 原因：审查实测 `get_function_by_address` 是 unknown tool。
        解决方案：实现为薄封装——返回该地址的函数、入口、偏移，
                  与 string_refs 的 function 字段口径一致。
    """
    facts = _addr_facts(so_name, int(addr))
    out: dict = {"so_name": so_name, "addr": hex(int(addr)), **facts}
    try:
        so = _session.get(so_name)
        fn = so.function_at(int(addr)) if hasattr(so, "function_at") else None
        if fn is not None:
            out["function"] = fn.name or f"sub_{fn.addr:x}"
            out["function_entry"] = hex(fn.addr)
            # (2) 第二次修改（2026-11-18）：补 start/end，与 Function.start 对齐
            out["function_start"] = hex(fn.start)
            out["function_end"] = hex(fn.end)
            out["offset"] = hex(int(addr) - fn.addr)
            out["is_entry"] = (int(addr) == fn.addr)
        else:
            out["function"] = None
            out["note"] = "该地址不在任何已发现函数内（可能是数据或未补全的函数表）"
    except KeyError as exc:
        out["error"] = exc.args[0] if exc.args else str(exc)
        out["code"] = getattr(exc, "mda_code", "SO_NOT_LOADED")
    return _j(out)


@server.tool()
@logged()
def function_info(so_name: str, addr: int) -> str:
    """函数综合信息：大小、指令数、调用者/被调用数、引用的字符串。

    (1) 第一次修改（2026-11-17）：新增。
        使用者要看"哪个函数是核心"，需要综合信息而不是只有 size。
        这是 Ghidra/IDA 函数视图的通用能力，不含样本特征。
    """
    so = _session.get(so_name)
    fn = so.function_at(int(addr))
    if fn is None:
        return _j({"error": f"{hex(int(addr))} 不在任何已知函数内",
                   "code": "NO_FUNCTION"})
    from server.core.disasm import Disassembler

    insns = Disassembler(so).disasm_range(fn.addr, max(fn.size, 4))
    # (5) 第一次修改（2026-11-17）：thunk 识别。
    #     thunk 特征：1~3 条指令，最后一条是 `b`/`br` 跳到别处。
    #     用户实测 0x247538 是 8 字节 `mov x0,x21; b 0x1f8800`，
    #     直到第 195 轮才发现是跳转桩。
    fn_type = "normal"
    thunk_target = None
    if 0 < len(insns) <= 3:
        last = (insns[-1].text or "").strip()
        import re as _re
        m = _re.match(r"b\s+#(0x[0-9a-f]+)", last)
        if m:
            fn_type = "thunk"
            thunk_target = m.group(1)
    callers = call_count = 0
    strs = []
    try:
        xr = _session.xref(so_name)
        refs_to = xr.xrefs_to(fn.addr) or []
        callers = len(refs_to)
        refs_from = xr.xrefs_from(fn.addr) or []
        call_count = sum(1 for i in refs_from if getattr(i, "is_call", False))
        strs = [hex(int(s)) for s in (xr.string_refs_of(fn.addr) or [])][:20]
    except Exception:                                     # noqa: BLE001
        pass
    return _j({
        "so": so.name, "addr": hex(fn.addr),
        "name": fn.name or f"sub_{fn.addr:x}",
        "size": fn.size, "insn_count": len(insns),
        "type": fn_type, "thunk_target": thunk_target,
        "callers": callers, "callees": call_count,
        "string_refs": strs,
        "discovered_by": getattr(fn, "discovered_by", ""),
        "hint": "callers/callees 来自当前 xref 模型；先 build_xrefs 可提高覆盖",
    })


@server.tool()
@logged()
def discover_functions(so_name: str, use_prologue: bool | None = None,
                       aggressive: bool = False,
                       strict_prologue: bool = True, use_rela: bool = True,
                       max_rounds: int = 6) -> str:
    """递归补全函数表（FDE + bl 目标 + 序言检测）。

    ## 三档（第 33 轮反馈：旧版只有"太保守"和"太激进"两档，中间是空的）

    三个开关名：`use_prologue`（要不要用序言检测）、`strict_prologue`
    （序言要不要严格）、`use_rela`（要不要用重定位表）。

    | 档位 | 等价调用 | 行为 | 实测 libbase |
    |---|---|---|---|
    | **bl_only** | 不传（默认）或 `use_prologue=false` | 只认 `bl` 目标 | 386 → 386（+0） |
    | **strict**（推荐） | `use_prologue=true` | `bl` + 「终止指令后紧跟**完整栈帧**」 | 386 → 388（+2，全真） |
    | **loose** | `use_prologue=true, strict_prologue=false` | `bl` + 任何序言（含裸 `bti`） | 386 → 557（+171，全假） |

    `aggressive` 是 `use_prologue` 的旧名，两个都给时以 `use_prologue` 为准。

    严格档 +2 的那两个函数**没有任何 bl 指向它们**（只能经函数指针/vtable
    抵达），正是"通过间接调用访问的函数永远发现不了、被外层粗 FDE 吞掉"
    这个老问题的解法。

    ## 关键返回字段

    - `prologue_mode`：`off` / `strict` / `loose`，标明本次结果的口径
    - `skipped_loose_prologue`：严格档**刻意不收**的裸 bti 候选数
      （不是失败，是"这档不收"；需要时用 strict_prologue=False 重跑）
    - `reached_max_rounds`：是否跑满轮次仍未到不动点 —— 看到 true 就该
      加大 max_rounds 再跑，而不是认为已经补完了

    ## 幂等

    同一档位重复调用返回 `skipped: true`；**换档位会重新跑**
    （第 33 轮修正：旧版按模块名记忆，换档位也被 skip，使用者会以为
    工具不肯跑）。

    (6) 第一次修改（2026-11-17）：新增独立工具名。
    (7) 第二次修改（2026-11-18）：加三档参数与上面三个自证字段。
    """
    so = _session.get(so_name)
    before = len(so.functions)
    try:
        got = _session.discover_functions(
            so.name, max_rounds=max_rounds, aggressive=aggressive,
            strict_prologue=strict_prologue, use_rela=use_rela,
            use_prologue=use_prologue)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "DISCOVER_FAILED"})
    out = {"ok": True, "so": so.name,
           "before": before, "after": len(so.functions),
           "added": len(so.functions) - before,
           "detail": got}
    if got.get("skipped"):
        out["note"] = ("该档位已经跑过，本次未重扫（换档位会重新跑）。"
                       "若要强制重跑，先 unload_so 再 load_so。")
    return _j(out)


@server.tool()
@logged()
def export_disasm(so_name: str, addr: int, size: int = 256,
                  format: str = "asm") -> str:
    """导出反汇编结果（asm / json / csv）。

    (6) 第一次修改（2026-11-17）：新增。使用者想导出反汇编做外部比对。
    """
    so = _session.get(so_name)
    insns = _session.xref(so.name).disasm.disasm_range(int(addr), int(size))
    if format == "asm":
        text = "\n".join(f"0x{i.addr:x}:  {i.text}" for i in insns)
        return _j({"ok": True, "format": "asm", "text": text,
                   "count": len(insns)})
    if format == "json":
        return _j({"ok": True, "format": "json", "count": len(insns),
                   "insns": [{"addr": hex(i.addr), "text": i.text,
                              "bytes": i.bytes.hex()} for i in insns]})
    if format == "csv":
        lines = ["addr,text,bytes"]
        lines += [f"0x{i.addr:x},{i.text.replace(chr(44), chr(32))},{i.bytes.hex()}"
                  for i in insns]
        return _j({"ok": True, "format": "csv", "text": "\n".join(lines)})
    return _j({"error": f"未知 format={format}", "code": "BAD_FORMAT"})


@server.tool()
@logged()
def get_callstack(serial: str, pid: int, thread_id: int = 0, limit: int = 32,
                  method: str = "accurate", scan_bytes: int = 1024,
                  so_name: str = "") -> str:
    """取指定线程的调用栈，并用 **mda 自己的静态模型**把每一帧符号化。

    为什么不用 frida 的 DebugSymbol：stripped 的壳样本上它没有符号表可用，
    基本只能给出裸地址；mda 的函数表来自 FDE + bl 目标 + 序言补全，才有名字。

    符号化流程（每帧）：
        运行时地址 → 按模块范围找到所属 so 与 base → 静态地址 = 运行时 - base
        → so.function_at(静态地址) 取函数 → 输出 so / function / offset
    其中 function 为 fn.name，无名为 sub_<addr>；offset 为该帧相对函数入口的偏移。

    thread_id=0 表示自动：优先用最近一次断点命中的线程，否则用枚举里的第一个。
    落在模块外（frida trampoline / JIT）或函数空洞里的帧标 in_gap=true、
    function 给 null——这是正常结果，不是错误。via_plt=true 表示该帧是 PLT 桩。

    ## method：三种取栈方式（帧指针链断了就换一种）

        accurate  frida 的 Thread.backtrace(ACCURATE)。默认值。
                  **依赖帧指针链或 frida 自己的 DWARF 展开**；开了 PAC 且
                  省略帧指针的 so 上实测只有 2 帧且是同一个地址重复。
        scan      启发式扫栈：把栈上"落在模块内 + 前一条指令是 bl/blr"的值
                  当候选帧。不需要断点现场，但结果只是候选、不保证顺序完整。
        auto      **自动降级链**（推荐）——按 accurate → scan → dwarf 依次试，
                  前一档拿到 >=2 个不同函数就停。frida 的 ACCURATE 在部分
                  Android 版本会让目标崩溃（frida#2861），auto 能自动躲开。

        dwarf     **DWARF CFI 展开**（本项）。用目标 so 自己的 .eh_frame 规则
                  逐帧执行 CFA 规则，原理同 libunwind，**完全不经过 frida 的
                  unwind**。fp 链断了也能展开，是 accurate 拿不到更多帧时的替代。
                  需要先有断点命中提供起点 pc/sp（方法见 method='dwarf' 的报错提示）。

    ## 怎么选

        先 accurate（快、无需断点）→ 帧数明显不对（如只有 2 帧且同址重复）
        → 改用 dwarf（不需要帧指针，但依赖 .eh_frame 完整）
        → 连 .eh_frame 都被剥离的样本 → 只剩 scan 兜底。

    ## method="dwarf" 的返回字段（其它 method 没有）

        cfi_coverage      **必须读**。含 enough / coverage_ratio / warning。
                          enough=false 表示这个 so 的 CFI 不足以支撑完整栈，
                          结果不可信——加固样本常把 .eh_frame 剥掉。
        unsupported_ops   遇到的未支持 CFI 指令（十六进制），说明为什么展不开
        decisive_frames   真正算出 CFA 的帧数
        stop_reason       为什么停（栈顶 / 无 FDE 覆盖 / 循环 / 栈地址读不到 / 缺 sp）
        regs_source       寄存器取自哪条命中（hit:same_thread / hit:latest）
        mem_reads         实际读目标栈内存的次数

    注意 dwarf 的 covered_pc 与 enough 是两个独立判断：
    covered_pc=true 只说"起点那个函数有 CFI"，enough=false 才是
    "整个样本的 CFI 不够，这条栈别全信"。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return _j({"error": "limit 必须是整数"})
    if not (1 <= limit <= 512):
        return _j({"error": "limit 必须在 1..512"})

    try:
        tgt = svc.attach(serial, pid)    # 幂等：已附加则复用同一会话
    except Exception as exc:             # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}"})

    # thread_id=0：优先最近命中的线程，实在没有就由 frida 端取第一个线程
    tid = int(thread_id or 0) or _recent_thread_id(tgt)
    # (7) 第七次修改（2026-11-18）：新增 auto 模式——自动降级链。
    #     bug 原因：frida 的 Thread.backtrace(ACCURATE) 在某些 Android 版本上
    #               会让目标崩溃（frida#2861 有记录），或者只返回 2 帧重复地址
    #               （PAC + 省略帧指针的 so）。此前只能靠调用方手选 method，
    #               选错就崩溃或拿到垃圾，且看不出该换哪个。
    #     解决方案：method="auto" 时按 accurate → scan → dwarf 依次尝试，
    #               前一档拿到 >=2 个**不同**函数就停；全部失败时如实报各档结果。
    if method == "auto":
        tried = []
        for m in ("accurate", "scan", "dwarf"):
            try:
                one = json.loads(get_callstack(
                    serial, pid, thread_id, limit,
                    method=m, scan_bytes=scan_bytes, so_name=so_name))
            except Exception as exc:                      # noqa: BLE001
                tried.append({m: f"{type(exc).__name__}: {exc}"})
                continue
            frames_n = len(one.get("frames") or [])
            distinct = len({f.get("function") or f.get("addr")
                            for f in (one.get("frames") or [])})
            tried.append({m: {"frames": frames_n, "distinct": distinct,
                              "error": one.get("error")}})
            if frames_n >= 2 and distinct >= 2:
                one["method_used"] = m
                one["degrade_chain"] = tried
                return _j(one)
        return _j({"error": "三档取栈方式都没拿到有效栈",
                   "code": "ALL_METHODS_FAILED",
                   "degrade_chain": tried,
                   "hint": ("accurate 可能崩溃或只剩重复帧；scan 依赖 bl 特征；"
                            "dwarf 需要 CFI 覆盖。可先用 set_breakpoint 拿到"
                            "现场后再用 method='dwarf'")})
    if method not in ("accurate", "scan", "dwarf"):
        return _j({"error": f"method 只能是 'accurate' / 'scan' / 'dwarf' / 'auto'，"
                            f"收到 {method!r}"})
    # (135) 第一百三十五次修改（2026-11-16）：dwarf 回溯走**纯静态 CFI 展开**。
    #
    #     bug 原因：frida 的 Thread.backtrace(ACCURATE) 依赖帧指针链或它自己的
    #               DWARF 展开；PAC + 省略帧指针的 so 上实测只有 2 帧（同一地址
    #               重复），fp 链断开后完全无法继续，这是本次要解决的核心问题。
    #
    #     解决方案：不经过 frida 取栈，而是
    #               ① 从最近一次断点命中的 context 里拿 pc/sp/x0..x30（真实现场）
    #               ② 用目标 so 自己的 .eh_frame 规则逐帧展开（libunwind 原理）
    #               ③ 栈内存通过 service.read_runtime 读（adb /proc/<pid>/mem
    #                  优先，hold 挂起时照样能读）
    #               ④ cfi_coverage 如实报告覆盖度——CFI 被剥离的样本上必须让
    #                  调用方看到"结果不可信"，绝不给假成功。
    if method == "dwarf":
        return _callstack_dwarf(serial, pid, tgt, tid, limit, so_name)

    js = (_JS_CALLSTACK
          .replace("__TID__", str(tid))
          .replace("__LIMIT__", str(limit))
          .replace("__MODE__", str(method))
          .replace("__SCANBYTES__", str(max(64, min(int(scan_bytes or 1024), 1024)))))
    try:
        payload = _run_frida_script(tgt.rb.session, js)
    except Exception as exc:             # noqa: BLE001 - frida 异常类型不稳定
        return _j({"error": f"{type(exc).__name__}: {exc}"})
    if "err" in payload:
        return _j({"error": payload["err"]})
    raw_frames = payload.get("frames")
    if raw_frames is None:
        return _j({"error": "取调用栈无响应（探针脚本超时），目标可能已退出"})

    try:
        mods = tgt.rb.refresh_modules()  # 一次刷新，供所有帧按范围匹配
    except Exception as exc:             # noqa: BLE001 - frida 异常类型不稳定
        return _j({"error": f"刷新运行时模块失败：{exc}"})

    frames = []
    for item in list(raw_frames)[:limit]:
        addr = _as_int_addr(item)
        if addr is None:
            continue
        frames.append(_symbolize_frame(addr, mods, _session))

    symbolized = sum(1 for f in frames if f["function"])
    # (18) 第十八次修改（2026-11-05）：把"哪个 so 没载入导致符号化失败"直接说出来。
    #     bug 原因：原来只给 unresolved 计数，AI 不知道该去 load_so 哪一个，
    #               容易把 "libc++.so+0x4ce58" 当成已经分析到位的结论。
    #     解决方案：把"有 so 名但没有函数名"的模块列进 hints，并给出可执行的下一步。
    unresolved_so = sorted({
        str(f.get("so")) for f in frames
        if f.get("so") and not f.get("function")
    })
    out = {
        "thread_id": payload.get("tid", tid),
        "frame_count": len(frames),
        "symbolized": symbolized,
        "unresolved": len(frames) - symbolized,
        "frames": frames,
        "note": ("符号化基于 mda 静态模型（不是 frida DebugSymbol）；"
                 "in_gap=true 表示落在函数空洞或未加载模块"),
    }
    if unresolved_so:
        out["hints"] = [
            f"有 {len(unresolved_so)} 个模块没解析出函数名：{unresolved_so}。"
            "多半是这些 so 还没载入 mda（或载入时文件名与设备上的不一致）。"
            "用 load_so 载入对应 so 后重新取栈即可看到函数名。"
        ]
    return _j(out)


@server.tool()
@logged()
def list_breakpoints() -> str:
    """列出当前所有断点（AI 与界面共用同一份），并标出重复登记。

    每条含 duplicate 标记时说明：**同一运行时地址存在多条记录**
    （历史版本用别名拼 bp_id 留下的）。用 dedupe_breakpoints 清理。
    """
    from server.dyn.service import get_dyn

    try:
        bps = get_dyn().list_breakpoints()
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}"})
    dup = [b for b in bps if b.get("duplicate")]
    out = {"count": len(bps), "breakpoints": bps}
    if dup:
        out["warning"] = (f"{len(dup)} 条断点存在重复登记（同一运行时地址多条记录），"
                          "用 dedupe_breakpoints 清理")
    return _j(out)


@server.tool()
@logged()
def dedupe_breakpoints(serial: str = "", pid: int = 0) -> str:
    """清理**重复登记的断点**（同一运行时地址只保留一条，其余真撤销）。

    为什么会有重复：早期版本 bp_id 用调用方传入的原始 so 名拼接，
    而同一模块有多种写法（`libfoo.so` / `foo.so` / `libfoo-1.2.so`）。
    两种写法各下一次断点就产生两条指向同一块内存的记录，
    删掉一条另一条残留——表现为「断点清不干净」。

    本工具是通用清理手段：按**运行时地址**去重，与模块名怎么写的无关。
    保留最早的一条（通常它是真正生效的那条），其余调 debugger 真撤销。

    serial/pid 都为空时清理所有目标。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        with svc._lock:                                   # noqa: SLF001 - 只读遍历
            targets = list(svc._targets.values())         # noqa: SLF001
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}"})

    removed: list[dict] = []
    kept = 0
    for tgt in targets:
        if serial and str(getattr(tgt, "serial", "")) != str(serial):
            continue
        if pid and int(getattr(tgt, "pid", 0) or 0) != int(pid):
            continue
        # 按运行时地址分组
        by_rt: dict[int, list[str]] = {}
        for bid, rec in list(getattr(tgt, "breakpoints", {}).items()):
            rt = int(rec.get("runtime_addr") or -1)
            if rt > 0:
                by_rt.setdefault(rt, []).append(bid)
        for rt, ids in by_rt.items():
            if len(ids) <= 1:
                kept += len(ids)
                continue
            # 保留第一条，其余真撤销
            keep = ids[0]
            kept += 1
            for bid in ids[1:]:
                try:
                    got = svc.remove_breakpoint(bid)
                    removed.append({"id": bid, "kept": keep,
                                    "removed": bool(got.get("removed")),
                                    "partial": bool(got.get("partial"))})
                except Exception as exc:                  # noqa: BLE001
                    removed.append({"id": bid, "kept": keep,
                                    "removed": False,
                                    "error": f"{type(exc).__name__}: {exc}"})

    return _j({
        "ok": True,
        "kept": kept,
        "removed_count": len(removed),
        "removed": removed,
        "note": ("按运行时地址去重，与模块名写法无关；"
                 "保留最早的一条，其余真撤销"),
    })


def _bases_from_hit_events(events: list) -> tuple[dict, str]:
    """从断点命中事件反推运行时基址：base = runtime_addr - static_addr。

    为什么能这么算：同一次进程运行内，某个 so 的 ASLR 基址是常量，
    而命中事件同时带 runtime_addr 与 static_addr，相减即基址。
    这不是猜测——它来自真实观测到的**成对地址**；同一 so 出现多个不同差值时
    说明数据自相矛盾，此时整个 so 都不参与推导，宁可退回静态模式也不猜。

    只在**同一目标**（同 serial:pid）内推导：跨进程基址不同，混用必然算错。
    返回 ({so 名: base}, 说明文字)；推不出来时返回 ({}, 原因)。

    (7) 第七次修改（2026-11-02）：容忍列表里混入非字典元素。
        bug 原因：旧实现直接 ev.get(...)，当 events 里出现整数/字符串
                 （如 walk 传 [1,2]）时抛 AttributeError。该异常发生在
                 trace_aggregate 的 try 块**之外**，导致已经写好的
                 BAD_EVENTS 结构化错误码根本走不到——调用方拿到的是一个
                 未捕获异常，而不是可判定的错误。
        解决方案：先过滤出 dict 元素并计数；非字典元素跳过而不是崩，
                 若过滤后一条都不剩则明确返回失败原因，让上层报 BAD_EVENTS。
    """
    if not isinstance(events, list):
        return {}, f"events 必须是列表，实际 {type(events).__name__}"

    items = [ev for ev in events if isinstance(ev, dict)]
    skipped = len(events) - len(items)
    if not items:
        return {}, (f"events 里没有可用的命中事件（{skipped} 个元素不是对象），"
                    "无法推导运行时基址")

    keys = {ev.get("key") or f"{ev.get('serial')}:{ev.get('pid')}"
            for ev in items}
    if len(keys) > 1:
        return {}, f"事件来自 {len(keys)} 个不同目标，基址不可通用，未推导运行时基址"

    seen: dict[str, set] = {}
    for ev in items:
        so_name = ev.get("so_name")
        runtime = _as_int_addr(ev.get("runtime_addr"))
        static = _as_int_addr(ev.get("static_addr"))
        if not so_name or runtime is None or static is None:
            continue
        seen.setdefault(so_name, set()).add(runtime - static)

    bases: dict[str, int] = {}
    conflicts: list[str] = []
    for so_name, diffs in seen.items():
        if len(diffs) == 1:
            bases[so_name] = next(iter(diffs))
        else:
            conflicts.append(so_name)
    note = (f"已从 {len(bases)} 个 so 的命中事件反推运行时基址"
            f"（base = runtime_addr - static_addr）")
    if conflicts:
        note += f"；{len(conflicts)} 个 so 的基址自相矛盾已跳过：{conflicts}"
    return bases, note


@server.tool()
@logged()
def read_runtime_memory(serial: str, pid: int, runtime_addr: str, size: int = 32) -> str:
    """按**运行时绝对地址**读内存——专门用来读断点现场拿到的地址。

    与 read_process_memory / read_typed(source="runtime") 的区别（很关键）：

        read_process_memory(so_name, static_addr)   addr 是**静态地址**，内部 base+static
        read_typed(..., source="runtime")           同上，也要静态地址
        **read_runtime_memory(runtime_addr)**        addr 是**运行时绝对地址**，不换算

    什么时候必须用它：断点命中现场的 x0 / x1 / lr / sp 都是运行时绝对地址，
    而且常常指向堆上的对象（根本不在任何 so 里），用静态地址的工具读会报
    `ADDR_UNMAPPED: 必须是静态地址`。

    **挂起状态下可以放心调用**：读内存走的是独立脚本，不经过被 hold 挂住的
    调试脚本，实测挂起期间读 16 字节耗时 0.02s。

    参数：
        runtime_addr  运行时地址，支持 "0x..." 字符串或十进制整数
        size          读取字节数，1..4096

    返回：{runtime_addr, hex, size}；读不到时 {error, code: READ_FAILED}
    （未映射 / 权限不足 / 超时都会明确说明，不会返回零填充）
    """
    from server.core.addr import parse_addr
    from server.dyn.service import get_dyn

    addr = parse_addr(runtime_addr, None)
    if addr is None:
        return _j({"error": f"runtime_addr 无效：{runtime_addr!r}",
                   "code": "BAD_ADDRESS"})
    try:
        return _j(get_dyn().read_runtime(serial, int(pid), addr, int(size)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "READ_FAILED")})


@server.tool()
@logged()
def read_runtime_string(serial: str, pid: int, runtime_addr: str,
                        max_length: int = 256) -> str:
    """按**运行时绝对地址**读 C 字符串——读断点现场 x0 指向的路径/内容。

    典型用法：在 `open` / `fopen` / `dlopen` 这类函数上命中后，

        x0 = 0xb400007c5f0dc6c0
        → read_runtime_string(runtime_addr="0xb400007c5f0dc6c0")
        → "/system/framework/org.apache.http.legacy.jar"

    实现按 64 字节分块读、遇 \0 停止：目标字符串紧贴页边界时不会整段失败，
    某一段读不到就停在已读到的位置并把 truncated 置 true（不伪造内容）。

    参数：
        runtime_addr  运行时地址，支持 "0x..." 或十进制
        max_length    最多读多少字节，1..4096

    返回：{runtime_addr, string, length, raw_hex, terminated, truncated, end_addr}
    读不到（地址本身无效）时 {error, code: READ_FAILED}
    """
    from server.core.addr import parse_addr
    from server.dyn.service import get_dyn

    addr = parse_addr(runtime_addr, None)
    if addr is None:
        return _j({"error": f"runtime_addr 无效：{runtime_addr!r}",
                   "code": "BAD_ADDRESS"})
    try:
        return _j(get_dyn().read_runtime_string(serial, int(pid), addr,
                                                int(max_length)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "READ_FAILED")})


def _so_for_static_read(so_name: str):
    """取静态 so 对象；未加载时给明确错误（不静默返回空）。

    (28) 第二十八次修改（2026-11-17）：恢复丢失的定义。
        bug 原因：557c642 重构时把本函数的**定义**弄丢了，只留下调用，
                  导致 read_typed / read_string / read_pointer 一调用就
                  NameError: _so_for_static_read is not defined。
                  审查实测确认这是硬故障（与参数无关）。
        解决方案：从 f8d6830 恢复原定义。报错带 candidates，
                  区分 SO_AMBIGUOUS / SO_NOT_LOADED。
    """
    try:
        return _session.get(so_name), None
    except KeyError as exc:
        return None, {
            "error": exc.args[0] if exc.args else str(exc),
            "code": getattr(exc, "mda_code", "SO_NOT_LOADED"),
            "loaded": getattr(exc, "mda_loaded", list(_session.modules)),
            "candidates": getattr(exc, "mda_candidates",
                                  _session._near_names(so_name, list(_session.modules))),
        }


def _backtrace_hints(frames, tool_hint: str = "") -> list[str]:
    """从符号化后的栈帧里找出"只有模块+偏移、没有函数名"的模块，给 AI 提示。

    (19) 第十九次修改（2026-11-17）：恢复丢失的定义。
        bug 原因：557c642 重构时把本函数定义弄丢，hits 一调用就
                  NameError: _backtrace_hints is not defined。审查实测确认。
        解决方案：从 f8d6830 恢复。扫描栈帧，把"有 +0x 但没有 !"的模块名
                  收集起来，提示调用方去 load_so 载入这些 so。
    """
    missing: list[str] = []
    seen: set[str] = set()
    for f in frames or []:
        text = str(f)
        if "!" in text:
            continue                      # 已经有函数名，符号化成功
        marker = "+0x" if "+0x" in text else ("+0X" if "+0X" in text else "")
        if not marker:
            continue                      # 裸地址：不属于任何模块，另说
        mod = text.split(marker)[0].strip()
        if mod and mod not in seen:
            seen.add(mod)
            missing.append(mod)
    if not missing:
        return []
    hint = (f"调用栈里有 {len(missing)} 个模块只解析出偏移、没有函数名：{missing}。"
            "原因是这些 so 还没载入 mda（或载入时文件名与设备上的不一致）。"
            "用 load_so 载入后重新取栈即可拿到函数名，例如 "
            f"load_so(path=\"<本地路径>/{missing[0]}\")")
    if tool_hint:
        hint += "；" + tool_hint
    return [hint]


def _rb_for_runtime(serial: str, pid: int):
    """取用于换算运行时地址的 Rebase；未 attach 时给明确错误。

    (13) 第十三次修改（2026-11-17）：恢复丢失的定义。
        bug 原因：557c642 重构时把本函数定义弄丢，read_typed/read_string/
                  read_pointer 的 source="runtime" 分支一调用就 NameError。
        解决方案：从 f8d6830 恢复。复用 dyn.service 的单例会话语义。
    """
    if not serial or not pid:
        return None, {
            "error": "source='runtime' 需要 serial 与 pid（指向已 attach 的目标进程）",
            "code": "NEED_TARGET",
        }
    try:
        from server.dyn.service import get_dyn

        tgt = get_dyn().attach(serial, pid)
    except Exception as exc:                              # noqa: BLE001 - DynError 带 code
        return None, {"error": str(exc), "code": getattr(exc, "code", "ATTACH_FAILED")}
    rb = getattr(tgt, "rb", None)
    if rb is None:
        return None, {"error": "该目标没有 Rebase（rb 为空）", "code": "NO_RB"}
    return rb, None


def _load_dyn_module(module_path: str, *names: str):
    """按需导入动态能力模块，并检查要用的函数是否都在。

    (1) 第一次修改
    bug 原因：memread / stepper / tracer / bridge 由其他代理并行新建，
              本文件落地时它们可能还不存在。若写在模块顶层 import，
              任何一个缺失都会让 mcp_server 整体起不来，既有几十个工具一起失效。
    解决方案：改为调用期惰性导入 + 缺函数检查；缺失时返回带 code 的结构化错误，
              模块补齐后无需改动本文件即自动生效。

    返回 (module, None) 或 (None, 错误 dict)。
    """
    import importlib

    # (2) 第二次修改（2026-11-13）：
    #     bug 原因：包整体移入 server/ 之后，字符串形式的模块名（"dyn.memread"）
    #               不会像 `from dyn import ...` 那样被批量改写覆盖。实测
    #               import_module("dyn.memread") 直接 ModuleNotFoundError，
    #               50 个工具全报 MODULE_UNAVAILABLE，而 639 项测试没抓到
    #               （测试走 `from server.dyn.X import`，生产代码走字符串导入）。
    #     解决方案：先按传入名导入，失败且不以 server. 开头时自动试 server.<name>。
    #               这样即使以后又漏改一处，工具也不会整片失效。
    #     另：hint 原文写着"该模块由并行开发提供"，在模块**已存在但路径不对**时
    #         会把排查引向完全错误的方向，改成先区分"路径问题"与"真缺失"。
    tried = [module_path]
    mod = None
    last_exc = None
    for cand in (module_path,
                 module_path if module_path.startswith("server.") else "server." + module_path):
        if cand not in tried:
            tried.append(cand)
        try:
            mod = importlib.import_module(cand)
            break
        except ModuleNotFoundError as exc:
            last_exc = exc
        except Exception as exc:        # noqa: BLE001 - 模块内错误同样算不可用
            last_exc = exc
            break

    if mod is None:
        # 分清两种原因，别让使用者往错方向查
        exists_on_disk = False
        try:
            import os as _os
            tail = module_path.split(".")[-1]
            _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
            for sub in ("core", "dyn", "scripting"):
                if _os.path.isfile(_os.path.join(_root, sub, tail + ".py")):
                    exists_on_disk = True
                    break
        except Exception:                                 # noqa: BLE001
            pass
        hint = ("模块文件在，但导入路径不对——检查调用处写的是不是 server 前缀"
                if exists_on_disk else
                "该模块确实不存在于本仓库，确认功能是否已实现")
        return None, {
            "error": f"{module_path} 尚不可用：{type(last_exc).__name__}: {last_exc}",
            "code": "MODULE_UNAVAILABLE",
            "available": False,
            "module": module_path,
            "tried": tried,
            "hint": hint,
        }
    missing = [n for n in names if not hasattr(mod, n)]
    if missing:
        return None, {
            "error": f"{module_path} 缺少函数：{', '.join(missing)}（接口可能已变更）",
            "code": "MODULE_INCOMPLETE",
            "available": False,
            "module": module_path,
            "missing": missing,
        }
    return mod, None


@server.tool()
@logged()
def read_typed(so_name: str, addr: int, type_name: str,
               count: int = 1, source: str = "static",
               serial: str = "", pid: int = 0) -> str:
    """按类型解释**静态 so 文件**里的值（不是读运行中进程的内存）。

    与 read_process_memory 的区别（别混用）：
        read_typed          读本地 so 文件字节，等价 IDA 里看 .rodata/.data，离线可用
        read_process_memory 读目标进程内存，需要 attach，看的是运行时真实值

    典型用途：解出 so 里的表项 / 常量 / 初始化后的结构体字面量，
    例如 "这张跳转表第 3 项是多少"、"这个 char* 字节串指向什么"。

    **工作流**：
        1) 先 load_so 把 so 加进会话（本工具只认已加载的 so）；
        2) 用 list_strings / search_bytes / disassemble 拿到目标地址；
        3) read_typed 取标量或数组；指针结果可再喂 read_pointer，
           字符串可再喂 read_string。

    type_name 支持：int8/int16/int32/int64、uint8/uint16/uint32/uint64、
    float/double/pointer，以及别名 i32/u64/f32/f64/ptr/void* 等。
    count>1 时读数组：返回的 value 是列表，values 恒为列表。

    source="runtime"（读真实进程内存）：需要同时传 serial 与 pid（目标必须已
    attach），本工具会自动把静态地址换算成运行时地址再读。能读到 .bss / 堆 /
    栈这些**文件里不存在**的内容。地址超出模块范围会报 ADDR_UNMAPPED，
    **绝不返回零填充或"格式正确的假值"**。

    失败给 {"error", "code"}：BAD_TYPE 类型名不支持、ADDR_UNMAPPED 地址不在
    文件任何区域、READ_FAILED 在区域内但无文件数据（如 .bss 运行时才存在）。
    """
    mod, err = _load_dyn_module("server.dyn.memread", "read_typed", "MemReadError")
    if err:
        return _j(err)
    so, err = _so_for_static_read(so_name)
    if err:
        return _j(err)
    rb = None
    if source == "runtime":
        rb, err = _rb_for_runtime(serial, pid)
        if err:
            return _j(err)
    try:
        result = mod.read_typed(so, addr, type_name, count=count,
                                source=source, rb=rb)
    except mod.MemReadError as exc:
        return _j({"error": f"{exc.code}: {exc.message}", "code": exc.code})
    return _j(result)


@server.tool()
@logged()
def read_string(so_name: str, addr: int, max_length: int = 256,
                source: str = "static", serial: str = "", pid: int = 0) -> str:
    """从**静态 so 文件**读一个 C 字符串（遇 \\0 截止，按 UTF-8 解码）。

    用途：确认某个地址上的文案/路径/URL 是什么——壳样本里定位到可疑字符串
    引用时，用它把原始字节还原成可读文本。

    **工作流**：list_strings（或 disassemble 里看到 adr/adrp 指向的地址）
        → read_string 取原文 → 需要知道谁引用它时用 string_refs。

    返回里几个标志要看清（都是如实标注，不是报错）：
        terminated  false 表示读满 max_length 仍没遇到 \\0
        truncated   读到了上限被截断，后面可能还有内容
        lossy       非 UTF-8 字节，已用替换符解码，原文看 raw_hex

    source="runtime"（读真实进程内存）：需同时给 serial 与 pid；addr 为静态地址，
    内部会换算。运行时字符串常跨越页边界，允许短读（读不满不报错）。

    失败给 {"error", "code"}，含义同 read_typed。
    """
    mod, err = _load_dyn_module("server.dyn.memread", "read_string", "MemReadError")
    if err:
        return _j(err)
    so, err = _so_for_static_read(so_name)
    if err:
        return _j(err)
    rb = None
    if source == "runtime":
        rb, err = _rb_for_runtime(serial, pid)
        if err:
            return _j(err)
    try:
        result = mod.read_string(so, addr, max_length=max_length,
                                 source=source, rb=rb)
    except mod.MemReadError as exc:
        return _j({"error": f"{exc.code}: {exc.message}", "code": exc.code})
    return _j(result)


@server.tool()
@logged()
def read_pointer(so_name: str, addr: int, depth: int = 1, offset: int = 0,
                 source: str = "static", serial: str = "", pid: int = 0) -> str:
    """从**静态 so 文件**读指针，可按 depth 逐层跟链。

    规则：每层读一个指针宽度（arm64 为 8 字节）的值作为下一层地址，
    下一层读取位置 = 该值 + offset。

    **典型用途**：so 里的静态结构体常有 "指向表的指针"，先 read_pointer 拿到
    表地址，再用 read_typed 按类型把表项解出来。

    返回 chain 形如 [{"level":0,"addr":"0x..","value":"0x.."}, ...]。
    三种提前停止都会如实标注（不会假装走满 depth）：
        reason="null"        指针值为 0（链到此为止）
        reason="cycle"       下一层地址已访问过（防死循环）
        reason="unmapped"    下一层地址不在文件任何区域
    注意 source="static" 时读到的是**文件里的初值**，不是运行中被改写后的值；
    加了 ASLR 的运行时指针在静态文件里通常是重定位占位值，这属正常。

    source="runtime"（读真实进程内存）：需同时给 serial 与 pid；addr 为静态地址。

    失败给 {"error", "code"}，含义同 read_typed。
    """
    mod, err = _load_dyn_module("server.dyn.memread", "read_pointer", "MemReadError")
    if err:
        return _j(err)
    so, err = _so_for_static_read(so_name)
    if err:
        return _j(err)
    rb = None
    if source == "runtime":
        rb, err = _rb_for_runtime(serial, pid)
        if err:
            return _j(err)
    try:
        result = mod.read_pointer(so, addr, depth=depth, offset=offset,
                                  source=source, rb=rb)
    except mod.MemReadError as exc:
        return _j({"error": f"{exc.code}: {exc.message}", "code": exc.code})
    return _j(result)


@server.tool()
@logged()
def plan_step(so_name: str, static_addr: int | str, mode: str = "over", count: int = 1,
              so_context: str | None = None, lr: int | str | None = None,
              mnemonic: str = "", max_insns: int = 500) -> str:
    """规划一次单步：**只算临时断点该下在哪，不执行**。

    ⚠ 执行本身当前**未实现**（execute_step 需真机 frida 临时断点模拟）。
    本工具是纯静态规划：告诉你"下一个该停的地址"，你可以自己在设备可用时
    用 set_breakpoint 把 plan 的 temp_breakpoint_addr 下成断点。
    本工具只规划、**不动目标**。要真正单步请调 execute_step（它会下临时断点、
    放行、停在落点）。返回里 execute_available=true 表示落点可解析、可以交给
    execute_step；resolvable=false 时 execute_step 会拒绝执行。

    mode 四选一：
        over            跨过当前指令（遇到 bl 不进入，断点放下一条）
        out             返回上一层（必须给 lr——返回地址在 LR 里，静态算不出来）
        into            进入被调函数，逐条推演 count 条后的落点
        until_mnemonic  从当前地址线性扫到第一条指定助记符（要给 mnemonic）

    **工作流**：
        1) 从断点命中里拿到当前 pc：hit_analysis 或 poll_events 的 context.pc；
        2) 静态地址 = 运行时 pc - 模块 base（或直接用 hit 的 static_addr）；
        3) plan_step 拿 temp_breakpoint_addr；
        4) 设备可用时 set_breakpoint 下这个地址（int 直接用，别用 hex 串）。

    参数补充说明（原设计里没有、但不给就必然算不出来的两个）：
        lr         运行时 LR 值，mode="out" 必填；mode="over" 遇到 ret 也要它
        mnemonic   mode="until_mnemonic" 必填，如 "bl" / "ret" / "br"
        so_context 若 so_name 为空，可作为 so 名回退（stepper 本身不消费该参数）

    怎么读结果：
        ok=true 且 resolvable=true  → 地址确定，可以下断点
        ok=true 但 resolvable=false → 结论是"确定算不出来"（如间接跳转、扫完没找到），
                                      不是执行失败；看 reason / stopped_by
        temp_breakpoint_addr=null   → 绝不拿假地址凑数

    已知的诚实边界（属设计而非 bug）：
        br/lr 间接跳转的目标在寄存器里，静态一律拒绝给地址；
        条件跳转在 into 下给两个候选；这些在 reason 里都有中文说明。
    """
    mod, err = _load_dyn_module("server.dyn.stepper", "plan_step_over", "plan_step_out",
        "plan_step_into", "plan_step_until_mnemonic",
    )
    if err:
        return _j(err)

    name = (so_name or so_context or "").strip()
    if not name:
        return _j({"error": "so_name 不能为空（so_context 可作为回退）",
                   "code": "BAD_SO_NAME"})
    mode_n = (mode or "over").strip().lower()
    # (10) 第十次修改（2026-11-02）：地址参数同时接受 int 与 "0x..." 字符串。
    #     bug 原因：schema 声明 static_addr/lr 为 int，而文档让调用方从
    #               hit.context['lr'] 取值——那里是**十六进制字符串**。
    #               结果是文档给的三步工作流 100% 走不通：MCP 层在参数校验阶段
    #               就拒绝，调用方永远拿不到规划结果。
    #     解决方案：类型放宽为 int | str，内部用 _as_int_addr 统一解析
    #               （它已修正为"纯数字按十进制、带 0x 按十六进制"）；
    #               count 也做一次转换，避免字符串传进来时 planner 内部炸。
    addr = _as_int_addr(static_addr)
    if addr is None:
        return _j({"error": f"static_addr 无法解析为地址，实际 {static_addr!r}；"
                            "支持 int、'0x1234'、'1234'",
                   "code": "BAD_ADDR"})
    lr_val = None
    if lr is not None:
        lr_val = _as_int_addr(lr)
        if lr_val is None:
            return _j({"error": f"lr 无法解析为地址，实际 {lr!r}；"
                                "支持 int、'0x1234'、hit.context['lr'] 的字符串",
                       "code": "BAD_LR"})
    try:
        count = int(count)
        max_insns = int(max_insns)
    except (TypeError, ValueError):
        return _j({"error": "count / max_insns 必须是整数", "code": "BAD_REQUEST"})

    try:
        if mode_n == "over":
            plan = mod.plan_step_over(None, name, addr, lr=lr_val)
        elif mode_n == "out":
            if lr is None:
                return _j({
                    "error": "mode='out' 必须给 lr：返回地址来自运行时 LR，静态无法推算。"
                             "取法：hit.context['lr']",
                    "code": "RET_NEEDS_LR",
                })
            plan = mod.plan_step_out(None, lr=lr_val, so_name=name,
                                     static_addr=addr)
        elif mode_n == "into":
            try:
                n = int(count)
            except (TypeError, ValueError):
                return _j({"error": f"count 必须是整数，实际 {count!r}",
                           "code": "BAD_COUNT"})
            plan = mod.plan_step_into(None, name, addr, count=n)
        elif mode_n in ("until_mnemonic", "until", "mnemonic"):
            plan = mod.plan_step_until_mnemonic(None, name, addr, mnemonic,
                                                max_insns=max_insns)
        else:
            return _j({
                "error": f"未知 mode: {mode!r}，可选 over / out / into / until_mnemonic",
                "code": "BAD_MODE",
            })
    except Exception as exc:            # noqa: BLE001 - 规划内部异常也要可读
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "PLAN_FAILED"})

    out = dict(plan)
    out["mode"] = mode_n
    out["so_name"] = name
    out["execute_available"] = True
    out["execute_note"] = "落点已算出；要真正单步请调 execute_step（会放行并停在落点）"
    return _j(out)


@server.tool()
@logged()
def execute_step(serial: str, pid: int, so_name: str, static_addr: int | str,
                 mode: str = "over", count: int = 1, lr: int | str | None = None,
                 mnemonic: str = "", timeout: float = 5.0) -> str:
    """**真正执行一次单步**：放行目标、停在临时断点处、返回停下时的现场。

    与 plan_step 的分工（别混）：
        plan_step     只算"该停在哪"，不动目标，纯静态
        execute_step  下临时断点 → 放行 → 等命中 → **停在落点** → 摘钩

    frida 没有 CPU 单步指令，单步是用「临时断点 + 放行」模拟出来的，所以：
        · 落点确定时（普通指令 / bl 之后 / 无条件跳转目标）可靠；
        · 条件跳转的实际走向由运行时决定，若没走预期分支，会返回
          matched=false 并给出实际命中地址——**这种情况不能当作单步到位**；
        · 间接跳转（br x16 这类，AVMP 分发器正是此形态）静态无法确定落点，
          plan 阶段就会 resolvable=false，直接拒绝执行。

    执行完目标处于 paused（线程停住），由你决定下一步：检查寄存器/内存、
    继续单步、或 resume 放行。

    mode 取值同 plan_step：over / into / out / until_mnemonic。
    lr 仅 mode='out' 需要（从 hit.context['lr'] 取，字符串也行）。
    mnemonic 仅 until_mnemonic 需要。

    返回：executed / matched / target_addr / hit_static_addr / thread_id /
    held / context（完整寄存器）/ backtrace / dbg_state；失败含 error 与 code。
    """
    from server.dyn.stepper import (
        execute_step as _exec,
        plan_step_into, plan_step_out, plan_step_over,
        plan_step_until_mnemonic,
    )

    name = (so_name or "").strip()
    if not name:
        return _j({"error": "so_name 不能为空", "code": "BAD_SO_NAME"})

    # 先规划（复用同一套判定，避免这里和 plan_step 给出不同结论）
    addr = _as_int_addr(static_addr)
    if addr is None:
        return _j({"error": f"static_addr 无法解析：{static_addr!r}", "code": "BAD_ADDR"})
    lr_val = _as_int_addr(lr) if lr not in (None, "") else None
    mode_n = (mode or "over").strip().lower()

    # 取已连接的 debugger（复用 service 的单例，保证与断点/事件同会话）
    try:
        from server.dyn.service import get_dyn

        tgt = get_dyn().attach(serial, pid)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": str(exc), "code": getattr(exc, "code", "ATTACH_FAILED")})
    dbg = getattr(tgt, "dbg", None)
    if dbg is None:
        return _j({"error": "该目标没有 debugger", "code": "NO_DEBUGGER"})

    try:
        if mode_n == "out":
            if lr_val is None:
                return _j({"error": "mode='out' 必须给 lr（取 hit.context['lr']）",
                           "code": "RET_NEEDS_LR"})
            plan = plan_step_out(dbg, lr=lr_val, so_name=name, static_addr=addr)
        elif mode_n == "into":
            plan = plan_step_into(dbg, name, addr, count=int(count))
        elif mode_n == "until_mnemonic":
            if not (mnemonic or "").strip():
                return _j({"error": "mode='until_mnemonic' 必须给 mnemonic",
                           "code": "BAD_MNEMONIC"})
            plan = plan_step_until_mnemonic(dbg, name, addr, mnemonic.strip())
        elif mode_n == "over":
            plan = plan_step_over(dbg, name, addr, lr=lr_val)
        else:
            return _j({"error": f"未知 mode：{mode_n}",
                       "code": "BAD_MODE",
                       "supported": ["over", "into", "out", "until_mnemonic"]})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"规划失败：{type(exc).__name__}: {exc}",
                   "code": "PLAN_FAILED"})

    # 真执行（execute_step 内部保证摘钩，异常也摘）
    result = _exec(dbg, plan, so_name=name, timeout=float(timeout))
    result["mode"] = mode_n
    result["plan"] = {k: plan.get(k) for k in
                      ("ok", "resolvable", "strategy", "temp_breakpoint_addr", "reason")}
    return _j(result)


@server.tool()
@logged()
def trace_aggregate(events: list | None = None,
                    runtime_bases: list | dict | None = None) -> str:
    """把 trace / 断点命中事件按**静态函数**聚合——先看"谁被执行了上万次"。

    为什么需要：指令级 trace 动辄千万行，直接读会迷失；按函数折叠后变成一张
    排序表，再决定深入看哪一段。这是 mda 的差异化能力：运行时地址要折回
    静态函数，靠的是 mda 自己的 SoFile.function_at（unidbg 那类模拟器没有静态层）。

    **两种事件来源**：
        1) 不传 events：自动取当前动态服务里**已有**的断点命中事件快照
           （只读拷贝，不推进 poll 游标、不发 frida 请求）；
        2) 传 events：显式给事件列表，元素形如
           {"runtime_addr"|"addr": ..., "static_addr": ..., "so_name": ...,
            "thread_id": ..., "ts": ...}；poll_events 的返回可直接传。

    **地址解析两种模式**（结果里 resolution_mode 会写明，务必看）：
        runtime  有运行时基址表，能无歧义换算（正常真机场景）；
        static   没有基址表，直接把事件地址当静态地址。**多个 so 的静态区间
                 重叠，这时只能判为 unresolved，不会瞎猜**。
    拿不到基址时它会**自动从命中事件反推**（base = runtime_addr - static_addr，
    同一 so 出现矛盾差值则整个 so 跳过）；也可以显式传 runtime_bases：
        支持 [{"name","base","size"}]、{名: base}、{名: {base,size}}，
        runtime_modules 的返回可以直接传。

    聚合口径：默认只聚 code 类（指令执行）。read/write 事件的 addr 是**数据地址**，
    按函数归属会把"谁读了这块内存"错当成"谁执行了这段代码"，故不混入。

    返回：function_count / functions（按命中数降序）/ events_used /
    resolution_mode / bases_derived / notes。
    落在函数空洞或模块外的事件**不丢弃**，单独成桶并标 in_gap=true、reason 说明。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "aggregate_by_function")
    if err:
        return _j(err)

    notes: list[str] = []
    raw = events
    if raw is None:
        raw, why = _snapshot_service_events()
        if why:
            return _j({"error": why, "code": "NO_EVENTS",
                       "hint": "改用 events 参数显式传入事件列表"})
        notes.append("事件取自动态服务已有记录的只读快照（未推进 poll 游标）")
    if not isinstance(raw, list):
        return _j({"error": f"events 必须是列表，实际 {type(raw).__name__}",
                   "code": "BAD_EVENTS"})

    bases = runtime_bases
    if bases is None:
        bases, base_note = _bases_from_hit_events(raw)
        if base_note:
            notes.append(base_note)
    else:
        notes.append("运行时基址表由调用方显式提供")

    # (8) 第八次修改（2026-11-02）：聚合前剔除"没有地址"的控制事件。
    #     bug 原因：poll_events 会返回 attached/resumed/breakpoint_set 这类
    #               没有地址的控制事件。它们被原样喂给 aggregate_by_function 后，
    #               被当成 addr=0 的"代码执行"计入统计——实测三条控制事件聚合出
    #               一个 hit_count=3 的函数桶，等于**凭空造出执行记录**。
    #               这类假统计比缺数据更危险：使用者会以为某段代码跑了三次。
    #     解决方案：只保留真正带地址的事件（addr 或 runtime_addr 可解析），
    #               控制事件单独计数并在 notes 里如实说明剔除了多少条，
    #               既不静默丢弃、也不混入统计。
    with_addr: list = []
    control_events = 0
    for ev in raw:
        if not isinstance(ev, dict):
            with_addr.append(ev)        # 非字典交给 tracer 报 BAD_EVENTS
            continue
        has_addr = (_as_int_addr(ev.get("addr")) is not None
                    or _as_int_addr(ev.get("runtime_addr")) is not None)
        if has_addr:
            with_addr.append(ev)
        else:
            control_events += 1
    if control_events:
        notes.append(
            f"已剔除 {control_events} 条无地址的控制事件"
            "（attached/resumed/breakpoint_set 等），它们不构成代码执行记录"
        )
    if not with_addr:
        return _j({
            "events_used": 0,
            "function_count": 0,
            "resolution_mode": "runtime" if bases else "static",
            "functions": [],
            "notes": notes,
            "note": (f"共 {len(raw)} 条事件里没有带地址的执行事件"
                     f"（其中 {control_events} 条是无地址的控制事件），"
                     "无可聚合内容——这不等于'没有执行'"),
        })
    agg_input = with_addr

    try:
        rows = mod.aggregate_by_function(agg_input, _session, runtime_bases=bases)
    except TypeError as exc:
        # tracer 对不认识的事件元素**直接抛错**（静默丢事件是 trace 最危险的 bug），
        # 这里转成可读错误，不吞掉
        return _j({"error": f"事件元素类型不受支持：{exc}", "code": "BAD_EVENTS"})
    except Exception as exc:            # noqa: BLE001 - 坏样本不该让工具崩
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "AGGREGATE_FAILED"})

    unresolved = sum(1 for r in rows if r.get("reason") == "module_unresolved")
    gaps = sum(1 for r in rows if r.get("in_gap"))
    out = {
        "events_used": len(agg_input),
        "function_count": len(rows),
        "resolution_mode": "runtime" if bases else "static",
        "bases_derived": len(bases or {}),
        "functions": rows,
        "notes": notes,
    }
    if not rows:
        out["note"] = ("没有任何可聚合的事件：采集未启动，或事件里没有可解析的地址。"
                       "这不等于'没有执行'，见 note 与来源说明")
    elif unresolved:
        out["unresolved_buckets"] = unresolved
        out["gap_buckets"] = gaps
        out["warning"] = ("有地址判为未解析（module_unresolved）："
                          "通常是缺运行时基址表或多 so 静态区间重叠。"
                          "真机场景请把 runtime_modules 的返回作为 runtime_bases 传入")
    return _j(out)


@server.tool()
@logged()
def locate_runtime_addr(serial: str, pid: int, runtime_addr: int | str) -> str:
    """运行时地址 → 完整静态定位（把"设备上那个地址"折回 mda 的静态模型）。

    这是静态+动态打通的入口：frida 给的地址带 ASLR，离开模块基址没有意义；
    本工具换算成 so / 静态地址 / 所属函数 / 函数内偏移，之后就能直接用
    disassemble / decompile / xrefs_to 这些静态工具。

    **工作流**：get_callstack 的某一帧（"runtime_addr": "0x7a0005201c"）
        → locate_runtime_addr 拿 static_addr_int 与 function
        → 用 static_addr_int 调 disassemble / xrefs_to（这两个接口要 int）。

    ## method 三选一

    accurate  frida 的 Backtracer.ACCURATE（默认）。依赖帧指针或 DWARF CFI，
              **PAC + 无帧指针的加固 so 上通常只有 2 帧**
    scan      启发式扫栈：找"落在模块内 + 前一条指令是 bl"的值当候选帧。
              不需要现场，但结果是**候选**不是精确调用栈
    dwarf     用 so 的 .eh_frame 规则逐帧展开（编译器生成的权威信息）。
              需要一次断点命中提供现场 PC/SP；so_name 指定用哪个 so 的 CFI。
              **CFI 被剥离的样本会明告 warning**，不会假装成功

    runtime_addr 支持十进制整数或 "0x..." 字符串（调用栈输出就是 hex 串）。

    会 attach 目标（幂等，已附加则复用同一会话），本工具**需要设备**。

    怎么读结果（都是如实标注，不是错误）：
        in_gap=true           模块内但没有函数覆盖（FDE 空洞 / PLT 桩 / 未发现区域），
                              function=null，不编造函数名
        in_plt_stub=true      落在 PLT 跳板（外部导入），plt_name 给出符号
        loaded_in_mda=false   mda 没加载该 so：so/static_addr 仍有效，但没有函数名，
                              先 load_so 再查一次才有符号
        module_match          名字怎么对上的（exact/renamed/normalized/stem/suffix）
    hex 字段都配了同名 *_int 字段，喂接 int 的接口请用 *_int 版。
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "locate_static")
    if err:
        return _j(err)
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        tgt = svc.attach(serial, pid)      # 幂等：已附加则复用同一会话
        mods = tgt.rb.refresh_modules()     # locate_static 自己不会取模块表，必须给
    except Exception as exc:            # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "ATTACH_FAILED"})

    try:
        result = mod.locate_static(_session, runtime_addr, mods)
    except Exception as exc:            # noqa: BLE001 - 换算失败要给可读原因
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "LOCATE_FAILED"})
    return _j(result)


@server.tool()
@logged()
def hit_analysis(serial: str, pid: int, build_xrefs: bool = False,
                 bp_id: str = "") -> str:
    """最近一次断点命中 → 完整静态上下文（命中点前后指令 / 伪代码 / 调用者）。

    这是"停下来之后该看什么"的一站式答案：把命中的运行时现场直接摊成静态视图，
    省掉 命中→取 pc→减基址→查函数→反汇编→查引用 的一长串手工步骤。

    **工作流**：
        1) set_breakpoint(hold=True) 下断；
        2) poll_events 看到 type=breakpoint_hit 且 hold=true（目标已 paused）；
        3) hit_analysis 看命中的函数、前后指令、谁调用了它；
        4) 分析完必须 resume 放行，否则线程一直停着。

    取的是**该目标最近一次命中**（内部取命中列表最后一条）。没有命中时
    明确报 NO_HITS，不会拿空结果冒充分析成功。

    build_xrefs=True 会强制构建引用图以保证 callers 完整，**大样本很慢**
    （6000+ 函数的样本可能二三十秒）。默认 false 时 callers_complete=false
    ——表示调用者只是部分结果，别当全量。

    **会 attach 目标**（幂等），需要设备。

    返回要点：symbol（so!func+0xNN）、function{name,addr,size}、insn_index、
    disasm（命中点前后各若干条，is_hit 标出命中那条）、pseudocode、callers、
    context（寄存器快照）、backtrace。
    落不到静态模型时 in_gap=true / loaded_in_mda=false，notes 里写明原因。
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "hit_context")
    if err:
        return _j(err)
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        hits = svc.hits(serial, pid)
    except Exception as exc:            # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "NOT_ATTACHED"})

    # (120) 按 bp_id 过滤：bp_id 形如 "serial:pid:so:2d8a48"，
    #       末段是十六进制静态地址。删掉旧断点后，旧命中仍在队列里，
    #       不过滤就会取到旧记录（用户实测过这个坑）。
    filter_note = ""
    if bp_id:
        try:
            want = int(str(bp_id).rsplit(":", 1)[-1].lstrip("0x"), 16)
        except Exception:                                 # noqa: BLE001
            return _j({"error": f"bp_id 格式不对：{bp_id!r}（应形如 "
                                f"'serial:pid:so:2d8a48'）",
                       "code": "BAD_BP_ID"})
        before = len(hits)
        hits = [h for h in hits
                if int(h.get("static_addr", h.get("static", -1)) or -1) == want]
        filter_note = (f"已按 bp_id 过滤到 {len(hits)} 条"
                       f"（过滤前 {before} 条）")
        if not hits:
            return _j({
                "error": f"bp_id={bp_id} 没有任何命中记录",
                "code": "NO_HITS",
                "hint": "① 确认这个地址真的被命中过（poll_events 看 breakpoint_hit）；"
                        "② 命中可能已被 clear_hits 清掉；"
                        "③ 不传 bp_id 可以看到全部命中",
                "hits_total": before,
            })

    if not hits:
        return _j({
            "error": f"{serial}:{pid} 还没有任何断点命中，无法做命中分析",
            "code": "NO_HITS",
            "hint": "先 set_breakpoint(hold=True) 下断，再 resume 让目标跑起来制造命中",
        })

    # (1) 第一次修改
    # bug 原因：初版用 "fallback_note" in dir() 判断异常分支是否走过。
    #          dir() 无参时给的是**当前局部作用域**的名字，写法能跑但极脆弱——
    #          一旦后续有人在函数里加个同名变量或把赋值移走，判断就静默失效，
    #          降级说明会丢，也正是「不静默丢信息」这条约定最怕的失效方式。
    # 解决方案：预先置空字符串，用真值判断；降级说明只在实际取不到模块表时填。
    mods = None
    fallback_note = ""
    try:
        tgt = svc.attach(serial, pid)
        mods = tgt.rb.refresh_modules()
    except Exception as exc:            # noqa: BLE001 - 命中缺 static_addr 时才需要它
        # 命中对象通常自带 static_addr，模块表只作反算兜底；取不到不阻断分析
        fallback_note = (f"取运行时模块表失败（{type(exc).__name__}），"
                         "仅用命中自带的静态地址")

    try:
        # 直接传整个命中列表：bridge 会取最后一条（最近一次命中）并标注条数
        result = mod.hit_context(_session, hits, mods, build_xrefs=build_xrefs)
    except Exception as exc:            # noqa: BLE001 - 分析失败要给可读原因
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "HIT_CONTEXT_FAILED"})

    if fallback_note:
        result.setdefault("notes", []).append(fallback_note)
    if filter_note:
        result.setdefault("notes", []).append(filter_note)
    result["hits_total"] = len(hits)
    return _j(result)


@server.tool()
@logged()
def inject_selftest(serial: str, pid: int) -> str:
    """**跨进程注入**能力自检——验证底层通路是否可用。

    背景：使用者卡在「知道该看哪里，但总是看晚了」。
    要抓写入前的内容，就得能在**目标进程里**执行代码/系统调用。
    frida 侧两条路都不通（MemoryAccessMonitor 会把目标搞崩；
    Process.setExceptionHandler 收不到 SIGSEGV），
    所以改走 ptrace 注入。

    这个工具检查三件事：
      ① 能不能 ptrace attach 目标
      ② 能不能跨进程读它的内存
      ③ **远程系统调用**通不通（用 getpid 对照：返回值应等于目标 pid）

    返回里的 remote_syscall 字段是重点：
      "works" → 可以在目标里执行任意 syscall
      "failed" → 这条路走不通
    """
    from server.dyn.inject import InjectError, selftest

    try:
        got = selftest(serial, int(pid))
    except InjectError as exc:
        return _j({"error": exc.message, "code": exc.code, "detail": exc.detail,
                   "hint": ("① 目标是否允许 ptrace（加固 App 常禁止）"
                             "② 设备是否 root")})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "SELFTEST_FAILED"})
    return _j(got)


@server.tool()
@logged()
def inject_read_memory(serial: str, pid: int, addr: str, size: int = 64) -> str:
    """跨进程读目标进程的内存（不走 frida）。

    用途：hold 断点挂起时 frida 的 session 会失效，read_runtime_memory 就用不了；
    这条路走 adb 读 /proc/<pid>/mem，与 frida 完全无关。

        inject_read_memory(serial, pid, "0x7075053140", 52)
    """
    from server.dyn.inject import InjectError, read_target_mem

    try:
        data = read_target_mem(serial, int(pid), _as_int_addr(addr), int(size))
    except InjectError as exc:
        return _j({"error": exc.message, "code": exc.code})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "READ_FAILED"})
    return _j({"ok": True, "addr": hex(_as_int_addr(addr)), "size": len(data),
               "hex": data.hex()})


@server.tool()
@logged()
def inject_write_memory(serial: str, pid: int, addr: str, hex_data: str) -> str:
    """跨进程写目标进程的内存（不走 frida）。

    **注意**：设备端必须用 ptrace 的 POKEDATA 通道。
    实测 process_vm_writev 在目标处于 ptrace stop 状态时
    会"返回成功但根本没写进去"——典型的假成功。
    """
    from server.dyn.inject import InjectError, write_target_mem

    raw = bytes.fromhex((hex_data or "").strip())
    if not raw:
        return _j({"error": "hex_data 为空", "code": "BAD_ARGS"})
    try:
        ok = write_target_mem(serial, int(pid), _as_int_addr(addr), raw)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "WRITE_FAILED"})
    return _j({"ok": bool(ok), "addr": hex(_as_int_addr(addr)),
               "size": len(raw)})


@server.tool()
@logged()
def inject_resolve_syscall_offset(serial: str, pid: int) -> str:
    """解析目标 libc 里 `syscall()` 的偏移（远程系统调用要用）。

    为什么需要：不同 Android 版本的 bionic 里 syscall() 的偏移不同
    （本机 Android 12 是 0x88190），**写死会让工具在别的 ROM 上直接失效**。

    做法：从设备拉 libc（**必须 adb pull**，exec-out 拉的二进制符号表是坏的），
         用 llvm-readelf 读 .dynsym 找 syscall@@LIBC。
    """
    from server.dyn.inject import InjectError, resolve_libc_syscall_offset

    try:
        off = resolve_libc_syscall_offset(serial, int(pid))
    except InjectError as exc:
        return _j({"error": exc.message, "code": exc.code})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "RESOLVE_FAILED"})
    return _j({"ok": True, "syscall_offset": hex(off),
               "note": "把这个值通过 MDA_SYSCALL_OFF 环境变量传给设备端 helper"})


@server.tool()
@logged()
def watch_memory(serial: str, pid: int, addr: str, size: int = 8,
                 max_records: int = 200, duration: float = 30.0) -> str:
    """监控内存写入，**记录写入前的内容**——"能在正确时刻停下来"。

    为什么需要它：`perf_watch` 只能给 PC，**拿不到写入前后的内容**；
    等回头去读，那块内存早被释放/复用了。

    ## 为什么不用其他方案（全是实测结论）

    · frida `MemoryAccessMonitor.enable()` → **直接把目标进程搞崩**
    · frida `Process.setExceptionHandler` 收不到 SIGSEGV（hits=0）
    · perf_event 硬件观察点 → 能触发、能拿 IP，但 `read()` 是**计数**，
      SIGIO 是**异步**投递，信号到达时写入已完成

    ## 本工具的做法

    mprotect(PROT_READ) + 自己处理 SIGSEGV（valgrind 的原理）：
    写触发段错误 → handler 里读**还没被覆盖**的内容 → 恢复可写让写完成。

    设备实测（3e2ff172 / Android 12 / arm64）：

        before_hex=aaaaaaaaaaaaaaaa   ← 写入前，拿到了
        after=deadbeefcafebabe

    ## 能力边界（如实说明，不粉饰）

    当前是**进程内**监控：helper 只能保护它自己进程的地址。
    要监控别的进程需要把 helper 注入目标（ptrace + 远程 mmap），**当前未实现**。
    所以本工具目前返回的是「机制在本设备可用」的验证结果，
    不是对 pid 的实时监控——**不会假装能跨进程工作**。
    """
    from server.dyn.uprobe import watch_memory as _impl

    try:
        return _j(_impl(serial, int(pid), str(addr), size=int(size),
                        max_records=int(max_records),
                        duration=float(duration)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "WATCH_MEMORY_FAILED"})


@server.tool()
@logged()
def timeline(serial: str, pid: int, duration: float = 10.0,
             limit: int = 500) -> str:
    """把断点命中与事件流合并成**单一时间线**，按时间排序。

    为什么需要它：同时 hook 好几个点时（不同 so 的不同地址），
    事件输出是分散的，靠各自的时间戳手动对齐误差几十毫秒（实测 IPC 单向 ~1.4ms，
    而旧版实现按毫秒粗对齐）。这个工具直接给出「谁先发生、间隔多久」。

        timeline(serial, pid)
        → events: [{t_rel_ms, kind, so, addr, tid, detail}]
          +0.000ms  metasec_ml.so+0x1f734c  tid=24232
          +0.012ms  sscronet.so+0x2da314    tid=24232

    ## 数据来源（两类合并，不是重新采）

    ① 断点命中（get_dyn().hits，含完整现场）
    ② 事件流（poll_events 同一份内部队列，含 auto_resumed 等状态事件）

    合并而不是重采，是因为 hold 命中放行后现场就没了——重采会丢掉已经发生的事。

    ## 精度（真机实测，见 tests/manual_timeline_clock.py / _precision.py）

        · 设备 CLOCK_MONOTONIC 分辨率 ≈ 6µs —— 不是瓶颈
        · frida RPC 往返中位数 2.8ms（p90 4.6ms）→ 单向 ≈ 1.4ms
        · 命中载荷更大（36 寄存器 + 24 帧 + 栈），单向按 ~2ms 估

    结论：**同源事件的相对间隔可信到毫秒级（±2ms 量级）**。
    排序键用 (ts, seq)——seq 是服务级自增序号，墙钟被 NTP 校时回退时
    仍能给出真实先后；回退了多大由 precision.wall_clock_backwards_ms 如实报出。

    **内存写入事件（perfwatch）不进这条时间线**：它的时间戳来自设备 helper
    的单调时钟（相对 daemon 启动），落回墙钟要靠约 1s 才刷新一次的状态文件
    反推，绝对误差可达秒级。混进来会让"毫秒级对齐"变成假精度。

    ## 参数

        duration  只取最后 duration 秒的命中（<=0 表示不限）
        limit     最多返回多少条（取最新的 limit 条）

    没有命中时返回 code=NO_HITS 并给下一步，而不是给一个空数组了事。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        out = svc.timeline(serial, int(pid), duration=float(duration),
                           limit=int(limit))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "NOT_ATTACHED"),
                   "hint": "先 attach（或任意动态工具）建立会话，再下断点"})
    if not out.get("count"):
        return _j({
            "ok": True,
            "count": 0,
            "events": [],
            "code": "NO_HITS",
            "hint": ("还没有任何断点命中：先 set_breakpoint 下断，"
                     "再触发目标执行；hold 断点记得配 auto_resume_after_ms"),
            "precision": out.get("precision"),
            **_target_state(svc, serial, int(pid)),
        })
    return _j({**out, **_target_state(svc, serial, int(pid))})


@server.tool()
@logged()
def trace_alloc(serial: str, pid: int, tid: int = 0,
                size_min: int = 0, size_max: int = 0,
                funcs: list | None = None, max_records: int = 500,
                duration: float = 10.0) -> str:
    """低开销**内存分配追踪**——走内核 uprobe，不用 frida。

    为什么需要它：用 frida hook malloc 时，实测 **167358 次 / 60 秒**，
    目标进程被反调试杀掉。uprobe 只在内核里做一次断点替换，
    **不改用户代码**，开销低一个数量级，风控信号也小。

        trace_alloc(serial, pid=1234, duration=20)
        trace_alloc(serial, pid=1234, size_min=48, size_max=96, tid=5678)

    ## 参数

    tid         只跟一个线程（0 = 不限）。高频场景下限定线程能显著降开销
    size_min/max 只记录该大小区间的分配（0 = 不限）
    funcs       要追踪的符号，默认 malloc/calloc/realloc/free
    max_records 硬上限，超出丢弃并计数
    duration    采集秒数

    ## 返回

    records[{ts, pid, tid, func, addr, size, caller_off, caller_mod}]
    / dropped / mechanism="uprobe" / threads / threads_covered / window_ms

    `caller_off` 是调用者返回地址（`%lr`）减去所在模块基址，`caller_mod`
    是那个模块的文件名；两者合起来可直接喂 disassemble / xrefs_to 做回溯。

    ## 实测语法结论（不同内核差别很大）

    本机（Android 12 / 内核 4.19.113）的 `uprobe_events` 只认 `%REG`：

        可用：  %x0 %x1 %x2 %lr %sp %pc
        不可用：$arg1 $tgid $pid $stack $ustack

    所以"拿完整调用栈"这条路在本机不存在，能拿到的最有价值的现场是 `%lr`。

    ## 如实声明的限制

    · `addr` 恒为 None —— malloc **入口**还没有返回值。要分配到的地址必须
      额外挂 `r:` 返回探针，那会让内核开销翻倍，本工具不挂。
    · `free` 的 size 恒为 None —— 它的参数是待释放指针，不是大小。
    · 拿不到完整调用栈（uprobe 不做栈展开）。
    · **libc 是全系统共享页**：探针对系统里每个进程的每次 malloc 都会触发。
      因此强制 tid 过滤；过滤表达式受内核长度上限约束，超长会**静默失效**
      并泄漏别的进程的事件——代码里已硬截断，并在结果里报
      `threads_covered` / `threads_skipped`。
    · **0 条结果是正常结果**：空闲的 App 几秒内可能一次 malloc 都没有
      （实测 com.android.settings 多次如此）。要验证功能可用，
      挑一个确实在干活的进程，或边跑边操作目标 App。
    """
    from server.dyn.uprobe import UprobeError, trace_alloc as _impl

    try:
        return _j(_impl(serial, int(pid), tid=int(tid or 0),
                        size_min=int(size_min or 0),
                        size_max=int(size_max or 0),
                        funcs=funcs, max_records=int(max_records or 500),
                        duration=float(duration)))
    except UprobeError as exc:
        return _j({"error": exc.message, "code": exc.code,
                   "hint": ("① 确认设备 root 且 /sys/kernel/tracing 可写；"
                            "② 换一个正在跑的进程重试；"
                            "③ 部分内核没开 CONFIG_UPROBE_EVENTS")})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "TRACE_ALLOC_FAILED"})


@server.tool()
@logged()
def clear_hits(serial: str, pid: int) -> str:
    """清空某目标的**命中记录队列**（不影响已下的断点）。

    为什么需要它：`hit_analysis` 取"最近一次命中"，而删掉的断点其旧命中
    还留在队列里。不清掉就会分析到已经废弃的地址，白跑一轮。

    典型用法：
        1) remove_breakpoint(旧断点)
        2) clear_hits(serial, pid)          ← 清掉旧记录
        3) set_breakpoint(新地址) → 触发 → hit_analysis

    注意：只清**命中记录**，断点本身还在；要撤断点用 remove_breakpoint。
    """
    from server.dyn.service import get_dyn

    svc = get_dyn()
    try:
        tgt = svc._target(serial, pid)                    # noqa: SLF001 - 只读
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "NOT_ATTACHED"})

    dbg = getattr(tgt, "dbg", None)

    # (127) 先放行所有挂起的线程，再清记录。
    #       _pending_tokens 是**放行凭据**：直接清掉会让 resume() 找不到 token，
    #       被 recv().wait() 卡住的线程永远醒不过来 → 只能杀进程。
    resumed = None
    try:
        pend = getattr(dbg, "_pending_tokens", None)
        if pend:
            resumed = dbg.resume()                        # 全放行
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"清理前放行挂起线程失败：{exc}",
                   "code": "CLEAR_ABORTED",
                   "hint": "未做任何清理，避免把线程留在永久挂起状态"})

    cleared = 0
    try:
        hits = getattr(dbg, "_hits", None)
        if hits is not None:
            cleared = len(hits)
            hits.clear()
        # 事件流里的旧命中同样清掉，避免 poll_events 又翻出来
        ev = getattr(dbg, "_events", None)
        if ev is not None:
            ev.clear()
        # 注意：**不清** _pending_tokens —— 它由 resume() 自己维护
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "CLEAR_FAILED"})
    out = {"ok": True, "cleared": cleared,
           "note": "只清命中记录，断点仍然有效"}
    if resumed is not None:
        out["resumed_before_clear"] = resumed
    return _j(out)


@server.tool()
@logged()
def suggest_breakpoints(so_name: str, function: str | None = None,
                        addr: int | None = None) -> str:
    """静态选一个函数 → 建议在哪几个位置下断点（省掉满函数乱找）。

    用途：动态调试时"我到底该断在哪"是最耗神的一步。本工具从静态层给出四类候选：
        entry        函数入口——命中时 x0-x7 就是调用方传入的实参
        after_call   每个 bl 之后的返回点——调用已完成，可看返回值 x0 与副作用
        before_ret   ret 之前——可看最终返回值与将要恢复的 lr
        data_ref     引用字符串的指令——可确认走的是哪个分支/哪个文案

    **工作流**：
        1) 先用 function_by_name 找到函数（重名时必须带 so_name）；
        2) suggest_breakpoints(so_name, function="foo") 拿候选；
        3) 每条建议的 **addr_int** 传给 set_breakpoint（那个接口要 int，
           返回里的 addr 是 hex 字符串，别直接喂）；
        4) poll_events 收命中。

    function 与 addr 至少给一个：
        function 还接受 "so!foo" / "sub_5020" / "0x5020" 这几种写法；
        addr 是**静态**地址（不是运行时地址，运行时换算用 locate_runtime_addr）。
    重名函数会返回 candidates 列表让你指定，**不会替你猜一个**。

    纯静态，不连设备。找不到函数时返回 {"error", "candidates"}。
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "suggest_breakpoints")
    if err:
        return _j(err)
    if function not in (None, "") and str(function).strip():
        target = function
    elif addr is not None:
        target = addr
    else:
        return _j({"error": "function 与 addr 至少给一个",
                   "code": "BAD_REQUEST",
                   "hint": "先用 function_by_name 查函数地址，再传进来"})

    try:
        # 注意：模块内同名函数，这里用 mod. 前缀调用，避免与本工具递归
        result = mod.suggest_breakpoints(_session, target, so_name or None)
    except Exception as exc:            # noqa: BLE001 - 坏样本不该让工具崩
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "SUGGEST_FAILED"})
    return _j(result)


@server.tool()
@logged()
def trace_timeline(events: list | None = None) -> str:
    """把事件流整理成**函数级时间轴**——看"先调了 A，再调了 B"。

    与 trace_aggregate 的区别：
        trace_aggregate  按函数**汇总**（谁被执行最多）
        trace_timeline   按**时间顺序**排列（执行先后关系）

    不传 events 时自动取当前动态服务里已有的命中事件快照（只读，不推进游标）。
    返回里的 runs 是"连续同名"的压缩视图：同一函数被连续命中 5 次会合成一条，
    避免时间轴被重复项淹没。

    (9) 第九次修改（2026-11-02）：本工具此前只有 dyn/bridge.py 的实现，
        没注册成 MCP 工具，AI 侧完全调不到——做了却用不上。
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "trace_to_timeline")
    if err:
        return _j(err)

    raw = events
    if raw is None:
        raw, why = _snapshot_service_events()
        if why:
            return _j({"error": why, "code": "NO_EVENTS",
                       "hint": "改用 events 参数显式传入事件列表"})
    if not isinstance(raw, list):
        return _j({"error": f"events 必须是列表，实际 {type(raw).__name__}",
                   "code": "BAD_EVENTS"})
    try:
        mods = _runtime_modules_snapshot()
        return _j(mod.trace_to_timeline(raw, _session, mods))
    except Exception as exc:            # noqa: BLE001 - 坏数据不该让工具崩
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "TIMELINE_FAILED"})


@server.tool()
@logged()
def module_load_timeline(load_events: list) -> str:
    """模块加载事件 → 加载顺序时间轴 + 区间异常检测。

    传入形如 [{"name","base","size","ts"}, ...] 的**观测到的**加载事件
    （通常来自真机 frida 的模块观察；本轮采集侧未实现，需自行提供数据）。

    会检测：基址为 0、基址未对齐、size 非法、缺基址、缺名字、缺时间戳、
    重名（dlopen 重载），以及**模块区间重叠**——重叠往往说明数据有问题
    或存在特殊映射（如 JIT 区被误当成模块）。

    (9) 第九次修改（2026-11-02）：此前未注册成 MCP 工具，AI 调不到。
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "module_load_timeline")
    if err:
        return _j(err)
    if not isinstance(load_events, list):
        return _j({"error": f"load_events 必须是列表，实际 {type(load_events).__name__}",
                   "code": "BAD_EVENTS"})
    try:
        return _j(mod.module_load_timeline(load_events))
    except Exception as exc:            # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "TIMELINE_FAILED"})


@server.tool()
@logged()
def trace_module_load(serial: str, package: str = "", pid: int = 0,
                      duration: float = 3.0, include_system: bool = False,
                      keep_alive: bool = True, max_events: int = 500) -> str:
    """**采集模块加载时间轴**——回答"这个 app 从启动到现在加载了什么、什么时候"。

    两种模式（按传参自动选）：

        spawn 模式：传 package="com.x.y"
            在 app 启动**前**把它挂起 → 装好观察器 → resume 放行 →
            从第一条指令开始记录。**能看到启动全过程**。
            例："这个 app 启动时都加载了哪些 so"

        attach 模式：传 pid=12345
            附着到已在跑的进程，只记录**之后**的加载。
            例："从现在开始它还会加载什么"

    **为什么 spawn 才有启动时间轴**：attach 到已运行进程时，启动阶段的加载
    早就发生完了。只有先 `spawn` 挂起、装好观察器、再 `resume`，
    才能覆盖从进程创建那一刻起的加载。

    ## 返回里最该看的字段

        timeline       人类可读的时间轴（可直接转述给用户），形如：
                         +0.000s 加载 miui.apk@classes.dex
                         +0.034s (Δ+0.026s) 加载 Settings.apk@classes.dex
        events[]       机器可读，每条 {kind, name, base, size, path, ts,
                       delta_s（距上一条的秒数）, t_rel（距第一条的秒数）, seq}
        first_load / last_load / load_span_s
                       第一次/最后一次加载，以及总跨度
        baseline_count 观察器就位时已加载的模块数（spawn 下是 zygote 基础库，
                       不算"新增加载"）
        dropped_system 被 include_system=False 过滤掉的系统模块数

    ## 参数

        duration       采集秒数；spawn 模式下**从 resume 那一刻开始计**
        keep_alive     仅 spawn：采完是否保留 app 进程（True 方便接着下断点，
                       False 则 kill，纯采集更干净）
        include_system 是否保留 /system、/apex、/vendor、/product 下的模块
                       （默认 False；壳样本自己的 so 通常在 /data 下，不受影响）

    ## 实测样例（com.android.settings，spawn 3.5s）

        mode=spawn  pid=4632  baseline=351  新增=14  过滤系统=21
        +0.000s 加载 system@app@miui@miui.apk@classes.dex
        +0.034s (Δ+0.026s) 加载 Settings.apk@classes.dex
        +0.044s (Δ+0.010s) 卸载 Settings.apk@classes.dex
        load_span_s=0.479

    **已知限制**：同名 so 多实例（实测 libcutils.so 在进程里有两个基址）现在
    能正确区分（基线用 name|base 组合键），不会再报假新增。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "start_trace_module_load")
    if err:
        return _j(err)
    try:
        result = mod.start_trace_module_load(
            serial, pid=int(pid or 0), package=package,
            include_system=bool(include_system),
            max_events=int(max_events), duration=float(duration),
            keep_alive=bool(keep_alive))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "TRACE_FAILED")})
    return _j(result)


@server.tool()
@logged()
def trace_app_startup(serial: str, package: str, symbols: list | None = None,
                      breakpoints: list | None = None,
                      duration: float = 3.0, include_system: bool = False,
                      keep_alive: bool = True, max_events: int = 2000) -> str:
    """**从 app 启动第一刻起**，同时采集「so 加载」和「函数调用」，合成一条时间轴。

    这是回答「这个 app 启动时加载了什么、从哪加载、加载完多久才开始干活」
    的**一站式工具**——一次调用拿到全程，不用分几步拼。

    ## 为什么必须 spawn

    attach 到已经在跑的进程时，启动阶段的 so 早已加载完、关键函数（malloc/
    open/init/解密）也早跑过一轮。只有先 `spawn` 把 app 挂起 → 装观察器和 hook
    → 再 `resume` 放行，才能覆盖**从零开始**的过程。

    ## 参数

        package   要分析的包名，如 "com.android.settings"
        symbols   要 hook 的**导出符号名**列表，如 ["malloc","open","read"]。
                  启动早期拿不到地址，所以只接受符号名。找不到的会列进
                  failed_symbols，不静默忽略。
                  对 open/openat/stat/access/dlopen/fopen 等路径类函数，
                  **工具会自动把第一个字符串参数读出来**，直接显示打开了什么文件。

        breakpoints 要按**静态地址**下断点的内部函数列表，格式：
                      [{"so_name":"libsgmainso.so","static_addr":0x1234,
                        "label":"可选的名字"}, ...]
                  为什么需要它：symbols 只能 hook 导出符号，而加固样本的关键
                  函数（解密、校验、VM 分发器）几乎都没有导出名。
                  **支持延迟断点**：启动早期 app 自己的 so 往往还没加载，
                  这类断点会挂起等待，等该 so 被 dlopen 时**自动补下**。
                  结果在 static_breakpoints 里分开报告：
                    placed        已就位（when=immediate 挂起时下的 / late 加载后补下的）
                    pending_on_load  仍在等待对应 so 加载
                    failed        下断失败的（含原因）
                    late_placed   补下的详细记录（哪个模块触发了哪条断点）
        duration  从 resume 那一刻开始的采集秒数
        include_system  是否保留 /system、/apex、/vendor 下的模块加载事件
        keep_alive      采集后是否保留 app 进程（True 便于接着下断点继续分析）
        max_events      加载与调用**各自**的上限（互不挤占，见下）

    ## 返回

        timeline   人类可读，分两段（可直接转述）：
                     【模块加载/卸载】共 14 条
                     +0.008s 加载 miui.apk@classes.dex  ← /data/dalvik-cache/...
                     【函数调用】共 150 条
                     +0.008s 调用 open("/system/app/miui/miui.apk")
        events[]   机器可读，两类统一带 ts / t_rel（距首条）/ delta_s（距上条）
        stats      各类型计数、首个加载/首个调用的相对耗时、被截断的数量
        hooked_symbols / failed_symbols / per_symbol_cap

    ## 实测样例（com.android.settings，spawn 3 秒）

        stats: {module_load: 14, call: 150, first_load_t_rel: 0.008,
                first_call_t_rel: 0.0}
        +0.000s 调用 open("/proc/self/cmdline")
        +0.003s 调用 open("/system/framework/org.apache.http.legacy.jar")
        +0.008s 加载 miui.apk@classes.dex  ← /data/dalvik-cache/arm64/...
        +0.008s 调用 open("/system/app/miui/miui.apk")

    ## 已知限制（如实标注）

        · spawn 需要 app 允许调试；加固样本可能失败（返回 SPAWN_FAILED）
        · 只 hook 导出符号；内部函数需先拿静态地址再走 set_breakpoint
        · 加载与调用**分类限额**（默认每个符号最多 max_events/符号数/2 条），
          避免 malloc 这类高频函数把加载事件挤出队列——这是实测踩到的坑：
          原来共用总上限时，启动阶段 malloc 几万次会把 module_load 挤到 0 条
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "trace_app_startup")
    if err:
        return _j(err)
    try:
        result = mod.trace_app_startup(
            serial, package, symbols=symbols, breakpoints=breakpoints,
            duration=float(duration), include_system=bool(include_system),
            max_events=int(max_events), keep_alive=bool(keep_alive))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "TRACE_FAILED")})

    # (19) 第十九次修改（2026-11-05）：把调用栈里的原始地址符号化。
    #      bug 原因：tracer 层只返回运行时裸地址（它不该依赖 mda 的静态会话），
    #                而 AI 看到 "0x7d18e5ae58" 完全无法判断是谁调的——
    #                "像浏览器那样看堆栈"正是要这里给出 so!函数+偏移。
    #      解决方案：用采集结束时带回的完整模块表，逐帧查 mda 静态模型；
    #                查不到的保留原始地址并统计，不伪造函数名。
    raw_mods = result.get("modules") or []
    symbolized_frames = 0
    unsymbolized_frames = 0
    missing_sos: set[str] = set()

    class _Mod:
        __slots__ = ("name", "base", "size")

        def __init__(self, name, base, size):
            self.name = name
            self.base = base
            self.size = size

    mods_obj = []
    for m in raw_mods:
        if not isinstance(m, dict):
            continue
        b = _as_int_addr(m.get("base"))
        if b is None:
            continue
        mods_obj.append(_Mod(str(m.get("name") or ""), b,
                             _as_int_addr(m.get("size")) or 0))

    for ev in result.get("events") or []:
        bt = ev.get("backtrace")
        if not bt:
            continue
        frames = []
        for raw in bt:
            addr = _as_int_addr(raw)
            if addr is None:
                continue
            info = _symbolize_frame(addr, mods_obj, _session)
            # FUZZY 栈扫描会混入"栈上恰好长得像地址"的值：不落在任何模块内的
            # 帧直接丢掉，宁可栈浅一点也不给错误归属（实测这类误报很常见）
            if not info.get("so"):
                continue
            if info.get("function"):
                symbolized_frames += 1
            else:
                unsymbolized_frames += 1
                if info.get("so"):
                    missing_sos.add(str(info["so"]))
            fn_name = info.get("function")
            so_name = info.get("so")
            off = info.get("offset")
            if fn_name and so_name:
                symbol = f"{so_name}!{fn_name}" + (
                    f"+{hex(off)}" if isinstance(off, int) else "")
            elif so_name:
                symbol = f"{so_name}+{hex(addr - 0)}" if False else f"{so_name} (无函数名)"
            else:
                symbol = hex(addr)
            frames.append({
                "runtime_addr": hex(addr),
                "so": so_name,
                "function": fn_name,
                "offset": off,
                "in_gap": info.get("in_gap"),
                "symbol": symbol,
            })
        ev["frames"] = frames
        ev["stack"] = [f["symbol"] for f in frames]
        # 原始地址数组保留在 backtrace 里，方便调用方自行换算

    # (19) 附加"带栈调用"的可读视图：直接看谁在什么时刻、从哪条链上被调起来。
    stack_lines: list[str] = []
    for ev in result.get("events") or []:
        frames = ev.get("frames") or []
        if not frames:
            continue
        rel = ev.get("t_rel")
        rel_txt = f"+{rel:.3f}s" if isinstance(rel, (int, float)) else "+?"
        head = f"{rel_txt} {ev.get('symbol')}"
        if ev.get("str_arg"):
            head += f'("{ev.get("str_arg")}")'
        stack_lines.append(head)
        for depth, f in enumerate(frames):
            mark = "←" if depth == 0 else "↑"
            stack_lines.append(f"    {mark} {f.get('symbol')}")
        if len(stack_lines) > 200:
            stack_lines.append("    …（栈输出已截断，完整数据见 events[].frames）")
            break
    if stack_lines:
        result["stack_timeline"] = "\n".join(stack_lines)

    result["symbolized_frames"] = symbolized_frames
    result["unsymbolized_frames"] = unsymbolized_frames
    if missing_sos:
        result["hint"] = (
            f"有 {len(missing_sos)} 个 so 的栈帧只解析到模块+偏移、没有函数名："
            f"{sorted(missing_sos)[:6]}。用 load_so 载入这些 so 后重新采集即可"
            "看到函数名（加载时文件名要与设备上一致）")
    return _j(result)


@server.tool()
@logged()
def trace_code(serial: str, pid: int, duration: float = 2.0,
               threads: list | None = None, max_events: int = 2000) -> str:
    """指令级**调用** trace：用 Stalker 采集"谁调用了谁"。

    采集的是 **call 事件**（调用关系），不是逐条指令执行——指令级会把事件量
    放大几个数量级，而"执行了哪些函数、调用链如何"通常才是要回答的问题。
    事件里的 runtime_addr 可以直接喂 trace_aggregate 折回静态函数。

    **重要前提**：依赖 `Process.enumerateThreads()` 能拿到线程。
        实测多数 app（systemui/logd/zygote）返回 0 → 无法跟随，会返回 NO_THREAD；
        system_server 正常（实测 224 个线程）。

    ⚠️ **危险警告（务必先看这条）**：
        对 **system_server 使用会导致系统重启**。实测两次，跟随其线程后
        system_server 消失、zygote 与整个 Android 框架重启。
        也就是说本能力目前**没有安全可用的常规目标**：
        多数 app 枚举不到线程，唯一能枚举的 system_server 又会被搞崩。
        除明确知悉风险并接受设备重启，不要调用本工具。

    参数：
        threads     要跟随的线程 id 列表；不传则自动挑非 running 的线程（最多 4 条）
        duration    采集秒数（Python 侧计时，到点主动停）
        max_events  事件上限

    **开发中踩到的两个坑（已修，写在这里免得以后重犯）**：
        1. 不能用 JS 的 `setTimeout` 来 unfollow——被 Stalker 跟踪的线程
           无法执行该定时器，脚本会永远等不到停止信号（表现为卡死）。
           必须由 Python 侧 `script.post()` 触发 `recv('stop')`。
        2. 不能在 `onReceive` 回调里 `send()`——那是高频回调，发送会阻塞
           导致脚本卡住。必须只在回调里累积，停止后再分批送出。

    返回：ok / events / count / followed_threads / stopped_cleanly / method / limitations。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "start_trace_code")
    if err:
        return _j(err)
    try:
        result = mod.start_trace_code(
            serial, pid, threads=threads, max_events=int(max_events),
            duration=float(duration))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "TRACE_FAILED"})
    return _j(result)


@server.tool()
@logged()
def trace_read(serial: str, pid: int, addr: int, size: int = 8,
               so_name: str = "", duration: float = 2.0,
               max_events: int = 500) -> str:
    """监控「谁**读**了这块内存」，返回每次读取的函数、地址与调用栈。

    实现方式：hook libc 的内存函数（memcpy/memmove/memcmp/memchr/strlen/
    strcmp/strncmp/strcpy/strncpy/strcat/strdup/__memcpy_chk），检查**源地址**
    是否落在 [addr, addr+size) 内。实测能捕获到真实访问（strlen/memcpy 各一条）。

    **为什么不用硬件观察点或 MemoryAccessMonitor**（都试过了）：
        · `Thread.setHardwareWatchpoint` 能真的触发，但异常被 frida 内部吞掉，
          `Process.setExceptionHandler` 收不到；且只有 4 个槽位、按线程生效；
        · `MemoryAccessMonitor.enable()` 实测**会把目标进程搞崩**
          （system_server 消失、Android 框架整体重启），绝不能再用于真机。

    **能力边界**：只覆盖走这些函数的访问，编译器内联的直接 ldr/str 抓不到；
    不记录访问字节数；目标进程必须真的执行到这些函数才会有事件。

    addr 为运行时地址；若给静态地址并同时给 so_name，会自动换算。
    失败给 {"error","code"}；采集不到事件时 count=0 但 ok=true（**不是错误**，
    表示这段时间内没有走这些函数的访问）。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "start_trace_read")
    if err:
        return _j(err)
    try:
        result = mod.start_trace_read(
            serial, pid, int(addr), size=int(size), so_name=so_name,
            max_events=int(max_events), duration=float(duration))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "TRACE_FAILED"})
    return _j(result)


@server.tool()
@logged()
def trace_write(serial: str, pid: int, addr: int, size: int = 8,
                so_name: str = "", duration: float = 2.0,
                max_events: int = 500) -> str:
    """监控「谁**写**了这块内存」，返回每次写入的函数、地址与调用栈。

    与 trace_read 同源（hook libc 内存函数），区别是检查**目标地址**
    是否落在 [addr, addr+size) 内。实测能捕获 memset/memcpy 的真实写入。

    典型用途：定位"谁改了这个标志位""谁解密后写回了这段缓冲区"。
    参数与限制同 trace_read。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "start_trace_write")
    if err:
        return _j(err)
    try:
        result = mod.start_trace_write(
            serial, pid, int(addr), size=int(size), so_name=so_name,
            max_events=int(max_events), duration=float(duration))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "TRACE_FAILED"})
    return _j(result)


def _runtime_modules_snapshot() -> list[dict]:
    """取当前已附加目标的运行时模块表（只读，不发新请求时返回空）。

    时间轴需要把运行时地址折回静态函数，而这一步依赖模块基址。
    这里只做**内存快照**，不主动 attach 新进程——没有现成会话就返回空，
    由调用方按静态模式处理（结果里 resolution 会体现）。
    """
    try:
        from server.dyn.service import get_dyn

        svc = get_dyn()
        mods: list[dict] = []
        for tgt in list(getattr(svc, "_targets", {}).values()):
            rb = getattr(tgt, "rb", None)
            cached = list(getattr(rb, "_modules", []) or [])
            for m in cached:
                mods.append({"name": getattr(m, "name", ""),
                             "base": getattr(m, "base", 0),
                             "size": getattr(m, "size", 0)})
            if mods:
                break       # 同一时刻只用一份模块表，跨目标基址不可混用
        return mods
    except Exception:                   # noqa: BLE001
        return []


# ---------------- 脚本通道 ----------------


@server.tool()
@logged()
def run_script(code: str) -> str:
    """执行 Python 脚本操作分析会话（进阶能力）。

    脚本内可用：
        session        - 当前多 so 分析会话（core.session.Session）
        print()/result - 输出，result 作为返回值

    ⚠ 性能约定（大样本必读）：
      - session.xref(so) **不再**自动全量构建；查单个函数请用
        session.ensure_function(so, addr)，成本 O(该函数)，不要
        为查一个函数去调 ensure_xrefs()（那会全量反汇编，6000+ 函数
        的样本要 20-30 秒，会占住进程导致后续请求排队超时）。
      - 需要全库引用时才调 session.ensure_xrefs(so)，且只调一次；
        进度用 session.xref_progress(so) 查看。
      - 遍历调用树优先用 session.call_chain(so, addr, depth)（内部
        惰性按需展开）；自己写 BFS 时对每个节点用
        x.disasm.disasm_function(addr)——结果有缓存，重复访问免费。
      - 全库线性扫描（disasm_range 分块）同样有缓存，重复扫不重复付费。
    """
    from server.scripting.runner import run_in_session

    return run_in_session(_session, code)


@server.tool()
@logged()
def run_idc(so_name: str, source: str) -> str:
    """执行 IDC 脚本（IDA 脚本语法直译）。

    支持用户真实在用的 IDC API：MakeName / MakeFunction / MakeCode /
    set_cmt / Message / is_code / get_flags / del_items / Byte / Word / Dword。
    传入的 source 就是 IDC 文件内容原样（含 #include 行会自动忽略）。
    所有改名/建函数/注释立即生效并同步 GUI。
    """
    from server.scripting.idc import run_idc as _run

    result = _run(_session, so_name, source)
    # IDC 批量改名/建函数后立即刷新 GUI（否则界面还是旧名字/旧函数表）
    _notify_ui({"type": "data_changed", "so_name": so_name,
                "why": f"run_idc（{len(result.get('messages', []))} 条消息）"})
    return _j(result)


@server.tool()
@logged()
def run_idc_file(so_name: str, path: str) -> str:
    """执行 IDC 脚本文件（绝对路径）。等价 IDA 里 File→Script file。"""
    from pathlib import Path

    from server.scripting.idc import run_idc as _run

    p = Path(path)
    if not p.is_file():
        return _j({"error": f"文件不存在: {path}"})
    result = _run(_session, so_name, p.read_text(encoding="utf-8", errors="replace"))
    # 同 run_idc：IDC 批量操作后刷新 GUI
    _notify_ui({"type": "data_changed", "so_name": so_name,
                "why": f"run_idc_file({p.name})"})
    return _j({"file": str(p), **result})


def start_stdio() -> None:
    """以 stdio 方式启动 MCP 服务（供客户端连接）。"""
    server.run(transport="stdio")


# ---------------- 能力补齐：执行观察 / 断点自检 / 间接跳转 / VM 状态 ----------------
#
# 本组工具针对「断点不命中却查不出原因」「br 链断开」「VM 内部状态读不到」
# 这类加固样本的共性难题。设计原则与前面一致：能给结论就给结论，
# 给不出就说明为什么，**绝不返回编造的数据**。


@server.tool()
@logged()
def watch_module(serial: str, pid: int, so_name: str, duration: float = 5.0,
                 max_points: int = 50, batch: int = 20,
                 batch_interval_ms: int = 200,
                 offset_range: list | None = None) -> str:
    """观察某个 so 里**哪些函数真的被执行过**——回答「代码到底跑没跑到这里」。

    最典型的用途：断点下在函数入口却一次都不命中时，用它区分两种原因——
        ① 地址算错了
        ② 这段代码在当前场景下**根本没被执行**

    光看「命中 0 次」分不清是哪一种；本工具直接给出"实际被执行的是哪几个偏移"。

    ## 与 trace_code 的区别

        trace_code   用 Stalker 跟随线程，采集"谁调用了谁"，开销大、易拖垮目标
        watch_module 只在函数入口挂 Interceptor，只数次数，**开销小得多**；
                     代价是只看得到函数级粒度，看不到具体调用边

    ## 参数

        so_name       mda 里的 so 键。**设备模块名带版本号也能自动匹配**
                      （本地 libsgmainso.so ↔ 设备 libsgmainso-6.7.260202.so），
                      名字完全对不上时还会按字节指纹反查
        duration      观察秒数
        max_points    最多下多少探针（**默认 50，上限 4000**）。
                      超出预算时按**均匀采样**覆盖整个区间，而不是只取地址最小的
                      那些——后者会让覆盖全部挤在区间头部，结论严重偏斜。
        batch         每批 attach 多少个（默认 20）
        batch_interval_ms  每批之间等多少毫秒（默认 200）。密集 patch 会让目标
                      抖动，某些情况下直接把进程搞崩
        offset_range  可选 [起始, 结束]，只观察这段地址内的函数

    ## 返回

        hot[]          按次数降序：{offset, offset_hex, hits}
        executed       被执行过的函数数
        placed/failed/total_functions  探针布置情况
        failed_detail  失败的点及 frida 给出的原因（最多 20 条）
        sampling       "uniform"（均匀采样）/ "full"（全覆盖）
        **recommendation**  给 AI 的决策依据：
                       function_density_per_kb / fail_rate /
                       suggested_max_points / advice
                       —— AI 可据此自己决定下一次用多少探针，
                       不用猜"加多少会崩、减多少不够"
        verdict        一句话结论

    ## 实测样例（闲鱼 libsgmainso，8 秒）

        executed: 24
        0x5a428  2927 次    ← 最热
        0x588b8   899 次
        ...
        0x5B76C 不在列表里  ← 说明这个断点位置确实没执行

    带 offset_range 观察 VM 解释器区间（0x174000~0x177000，78 个入口）：

        sampling: uniform, placed: 14, failed: 6
        recommendation: {density: 6.5/KB, fail_rate: 0.3,
                         advice: "失败率偏高，建议缩小 range 或用 probe_hits 验证",
                         suggested_max_points: 11}

    **失败率高不代表工具坏了**：那些点是"函数内部块"而非真入口，
    frida 对它们报 `unable to intercept function ... please file a bug`。
    failed_detail 里能看到每一条的具体原因。

    ## 已知限制

        · 只覆盖**函数入口**：函数内部某段被执行不代表入口被执行
        · max_points 截断时只观察地址最小的那批函数，结论可能不全
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "watch_module")
    if err:
        return _j(err)
    try:
        return _j(mod.watch_module(serial, int(pid), so_name,
                                   duration=float(duration),
                                   max_points=int(max_points),
                                   batch=int(batch),
                                   offset_range=offset_range))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "WATCH_FAILED")})


@server.tool()
@logged()
def verify_breakpoint(serial: str, pid: int, so_name: str, static_addr: int,
                      bp_id: str = "") -> str:
    """检查一个断点**到底有没有真的生效**（set_breakpoint 返回 true 不代表 armed）。

    `set_breakpoint` 返回 `set: true` 只说明"静态地址换算成功、frida 接受了挂钩请求"，
    **不代表断点真的武装好了，更不代表那段代码会被执行**。

    ## 返回字段怎么读

        current_hex      该地址当前内存字节
        original_hex     本地 so 文件里的原始字节
        bytes_match      两者是否一致。注意 frida 会让我们读到原始字节，
                         所以一致**不代表没挂钩**
        already_hooked   该地址是否已被装过钩子
        hits_since_set   提供 bp_id 时的命中数
        matched_by       "fingerprint" 表示靠字节指纹找到的模块

    ## 怎么判断问题出在哪

        hits > 0                        → 断点正常工作
        hits == 0 且 already_hooked     → 钩子装上了，但这段代码没执行
                                          （用 watch_module 看真正在跑的是哪些偏移）
        hits == 0 且 not already_hooked → 钩子没装上，检查地址/模块
        bytes_match == false            → 地址对应错了文件

    ## 参数

        so_name      mda 里的 so 键（支持与设备名自动匹配；失败时按字节指纹反查）
        static_addr  静态偏移
        bp_id        可选，形如 "serial:pid:so:5b76c"，给了就统计它的命中数
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "verify_breakpoint")
    if err:
        return _j(err)
    try:
        return _j(mod.verify_breakpoint(serial, int(pid), so_name,
                                        int(static_addr), bp_id=bp_id))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "VERIFY_FAILED")})


@server.tool()
@logged()
def resolve_br(so_name: str, addr: int, lookback: int = 8,
               max_targets: int = 64) -> str:
    """解开 `adrp/ldr/br xN` 这类**间接跳转**，尽可能还原跳转目标表。

    **纯静态，不需要设备。**

    为什么需要：加固样本的 VM 分发器到处是 `br x8`，静态 xref 链在这里全断——
    build_xrefs 能出几万条边，但跨过 br 就接不上，调用关系丢失。

    识别的两种模式：
        ① adrp + add + br            → 目标是常量地址（mode=direct）
        ② adrp + ldr + (add) + br    → 目标是**指针表**里的值（mode=table）

    ## 参数

        so_name     mda 里已加载的 so
        addr        br 所在地址；给函数内任意地址，函数内所有 br 都会被尝试解析
        lookback    往前追溯多少条指令（默认 8；最少按 1 处理，因为 0 回看看不到 adrp）
        max_targets 每个 br 最多返回多少个目标

    ## 返回

        branches[]  {addr_hex, insn, reg, mode, table_addr, targets[], resolved, detail}
        resolved / unresolved  计数

    ## 重要：resolved=false 是**有价值的结论**

    它明确告诉你"静态算不出"，原因通常是：
        · 目标来自运行时寄存器（参数/返回值传递）
        · 指针表在运行时才被填充或解密（表里是 0 或密文）
    这时必须配动态断点才能拿到真实目标——**不会编造一个假目标**。

    ## 实测（闲鱼 libsgmainso 的 VM 分发器 0x5B76C）

        8 个 br x8 全部指向 0x1af810 ~ 0x1af848 这段表
        但 resolved=0：表内是密文，运行时才解密
        → 这正好解释了为什么断点下在入口不会执行
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "resolve_br")
    if err:
        return _j(err)
    try:
        return _j(mod.resolve_br(_session, so_name, int(addr),
                                 lookback=int(lookback),
                                 max_targets=int(max_targets)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "RESOLVE_FAILED")})


@server.tool()
@logged()
def dump_vm_state(serial: str, pid: int, ctx_ptr: str,
                  count_offset: int = 0x194, array_offset: int = 0x1a0,
                  instr_size: int = 16, max_instr: int = 200,
                  count_size: int = 8, count_min: int = 0,
                  count_max: int = 0x100000,
                  opcode_shift: int = 1, opcode_bits: int = 4,
                  func_shift: int = 5, func_bits: int = 4) -> str:
    """按约定的 VM 上下文结构，把**字节码指令数组**一次解出来。

    VM 类壳把字节码存在自己管理的数组里，结构固定但没有符号。本工具
    **一次 attach 读完整块**（而不是逐条读），这样只打断目标一次。

    ## 结构约定（来自汇编观察，参数可覆盖）

        [ctx + 0x194] = 指令计数
        [ctx + 0x1a0] = 指令数组指针
        每条指令 16 字节

    ## 参数

        ctx_ptr        VM 上下文指针（**运行时绝对地址**，通常就是断点现场的 x0）
        count_offset   计数偏移，默认 0x194
        array_offset   数组指针偏移，默认 0x1a0
        instr_size     每条指令字节数，默认 16
        max_instr      最多解多少条（防数组巨大时读爆）

    ## 返回

        count / array_ptr / instructions[{idx, addr, raw_hex, opcode, func, words[]}]
        truncated      是否因 max_instr 截断

    ## 安全设计

    计数 > 1048576 时**拒绝读取**并报 COUNT_SUSPICIOUS——
    偏移填错时读到的可能是个巨大的垃圾值，硬读会把进程内存读爆。

    ## (5) 第五次修改（2026-11-16）：结构假设全部参数化

    上面那三个偏移虽然一直是参数，但仍有隐含假设（计数宽度、合理区间、
    位域规则）。换一个 VM 时任意一条不成立，就会表现成"偏移不对"：

        count_size      计数字段宽度 1/2/4/8（默认 8）。
                        字段实为 u32 时，按 u64 读会把相邻字段一起读进来，
                        得到一个巨大值 → 直接 COUNT_SUSPICIOUS
        count_min/count_max
                        计数的合理区间（默认 0 / 0x100000）。
                        某个 VM 的计数从 0 开始或上万时，默认区间会挡掉它
        instr_size      每条指令字节数（默认 16）
        opcode_shift / opcode_bits
                        opcode 的位域（默认 shift=1 bits=4 即 bits[4:1]）
        func_shift / func_bits
                        func 的位域（默认 shift=5 bits=4 即 bits[8:5]）

    默认值全部等于原硬编码值，所以不传时行为与之前完全一致。

    ## 返回

        count / array_ptr / instructions[{idx, addr, raw_hex, opcode, func, words[]}]
        truncated      是否因 max_instr 截断
        layout_used    本次实际使用的布局参数（便于核对）
    """
    from server.core.addr import parse_addr

    mod, err = _load_dyn_module("server.dyn.memread", "dump_vm_state")
    if err:
        return _j(err)
    addr = parse_addr(ctx_ptr, None)
    if addr is None:
        return _j({"error": f"ctx_ptr 无效：{ctx_ptr!r}", "code": "BAD_ADDRESS"})
    try:
        return _j(mod.dump_vm_state(serial, int(pid), addr,
                                    count_offset=int(count_offset),
                                    array_offset=int(array_offset),
                                    instr_size=int(instr_size),
                                    max_instr=int(max_instr),
                                    count_size=int(count_size),
                                    count_min=int(count_min),
                                    count_max=int(count_max),
                                    opcode_shift=int(opcode_shift),
                                    opcode_bits=int(opcode_bits),
                                    func_shift=int(func_shift),
                                    func_bits=int(func_bits)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "DUMP_FAILED")})


@server.tool()
@logged()
def read_memory_batch(serial: str, pid: int, regions: list) -> str:
    """**一次调用读多段内存**，而不是一段一次 RPC。

    分析一个结构体时常要读十几个分散地址（x0+0x194、x0+0x1a0、x0+0x1b8 …），
    每段一次 RPC 就要多 attach 一次，而每次 attach 都会让目标停一下——
    采样点一多事件就丢了。本工具把多段打包成一次读。

    ## 参数

        regions  [{"addr": "0x7bc...", "size": 16}, ...]
                 addr 支持 0x 字符串或整数，size 1..4096

    ## 返回

        results[]  每段 {addr, ok, hex, size} 或 {addr, ok: false, error}
        readable   成功读到的段数

    ## 典型用法

        read_memory_batch(regions=[
            {"addr": ctx, "size": 0x200},          # 整个 VM 上下文
            {"addr": arr, "size": 0x40},           # 指令数组头部
        ])
    """
    mod, err = _load_dyn_module("server.dyn.memread", "read_memory_batch")
    if err:
        return _j(err)
    try:
        return _j(mod.read_memory_batch(serial, int(pid), regions))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "BATCH_FAILED")})


@server.tool()
@logged()
def probe_hits(serial: str, pid: int, so_name: str, static_addr: int,
               duration: float = 5.0, capture_regs: list | None = None,
               max_samples: int = 20) -> str:
    """**纯计数探针**：只统计某地址被进入多少次，不挂起、不依赖 hold。

    ## 寄存器采样（capture_regs）

    它已经用 Interceptor 挂上了，**顺手抓寄存器几乎零成本**：

        probe_hits(..., capture_regs=["x0", "x1", "lr"])

    → samples: [{x0: "0x...", x1: "0x...", lr: "0x...", tid: 123, n: 4}]

    同一组寄存器值反复命中只留一条并累加 `n`（去重），高频函数下也不会爆。
    默认不采样（空数组），行为与旧版完全一致。

    这个不需要 hold，风险低，适合**高频函数**——正因如此更该抓现场。

    回答的是「这段代码到底跑不跑」——和 verify_breakpoint 分工不同：

        verify_breakpoint  查"断点有没有真的 armed"（字节、hook 状态）
        probe_hits         查"这段代码到底跑不跑"（一个计数器，最直接）

    ## 为什么需要它

    `set_breakpoint(hold=True)` 走完整链路（登记、策略、RPC、事件流）。
    当只想回答"这个地址跑不跑"时，那条链路太重，任何一环出问题都表现成
    "0 命中"，分不清是没执行还是没挂钩。本工具用最直接的方式验：
    一个 Interceptor、一个计数器，**成功挂上才谈命中**。

    ## 返回

        hits            命中次数（0 表示这段时间没执行）
        first_hit_ts    首次命中时间戳（没命中为 null）
        threads         命中过的线程 id
        mechanism       实际使用的机制（当前固定 Interceptor）
        verdict         一句话结论：区分「没执行」与「挂不上」

    ## 关键：拦截失败会明确报错

    frida 对某些地址会抛 `unable to intercept function ... please file a bug`
    （实测同一区间 78 个入口里 19 个挂不上，它们多是函数内部块而非真入口）。
    这种情况返回 **INTERCEPT_FAILED**，不会伪装成 "0 命中"。

    ## 与 watch_module 配合

    watch_module 告诉"哪些入口可挂、哪些被执行"；probe_hits 用来
    对单个可疑地址做精确确认。
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "probe_hits")
    if err:
        return _j(err)
    try:
        return _j(mod.probe_hits(serial, int(pid), so_name,
                                 int(static_addr), duration=float(duration),
                                 capture_regs=capture_regs,
                                 max_samples=int(max_samples)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "PROBE_FAILED")})


@server.tool()
@logged()
def read_jump_table(so_name: str, table_static_addr: int, entry_size: int = 4,
                    count: int = 16, code_base: int = 0, signed: bool = True,
                    serial: str = "", pid: int = 0) -> str:
    """读一张**跳转表**，把表项解析成目标地址（解决表驱动的 br）。

    **纯静态，不需要设备。**

    VM 分发器的常见形态：

        adr    x15, #base               ; 基址
        ldrsw  x16, [x12, x7, lsl #2]   ; 从表取 4 字节**有符号偏移**
        add    x15, x15, x16            ; 基址 + 偏移
        br     x15

    表项存的是**相对基址的偏移**，不是绝对地址。单看 `br x15` 算不出目标，
    必须知道「表地址 + 表项宽度 + 基址」三者。本工具把这个原子操作单独暴露。

    ## 参数

        so_name            mda 里的 so 键
        table_static_addr  表的静态地址（由 adrp+add 算出，如 0x30000+0xfd8）
        entry_size         表项字节数：4（ldrsw/ldr w）或 8（ldr x）
        count              读多少项
        code_base          加偏移用的基址（adr/adrp 给出的那个地址）。
                           传 0 表示表项就是绝对地址，不加偏移
        signed             表项按**有符号**解释（ldrsw → true）
        serial / pid       给了就**从进程内存读表**（runtime 模式），
                           不给则读本地文件（static 模式）

    ## ⚠️ 强烈建议传 serial + pid

    加固样本的表**常在运行时才被填入真实指针**。实测同一个 so：

        0x30fd8  文件 140000004c000000...  运行时 140000004c000000...  ← 静态常量
        0x1af810 文件 9e0a1deb429992db...  运行时 7c39c9e07b000000...  ← 运行时才填

    只读文件的话，第二类表解出来是**垃圾指针**，看起来像"解不出目标"，
    实际是读错了地方。传了 serial+pid 就能读对。

    ## 返回

        source      "runtime"（从进程内存读）或 "static"（读文件）
        raw / offsets[] / targets[] / note

    ## 实测（0x175018 的 br x15）

        表地址 0x30fd8，entry_size=4，code_base=0x175018
        解出 14 个目标：
          0x17502c  ubfx w15, w17, #5, #4    ← VM handler，位域解码
          0x175064  ubfx w8, w17, #5, #4
          0x1750a0  ubfx w15, w17, #5, #6
          0x177608  ← 异常出口（对应前面的 b.hi）
    """
    mod, err = _load_dyn_module("server.dyn.bridge", "read_jump_table")
    if err:
        return _j(err)
    try:
        return _j(mod.read_jump_table(so_name, int(table_static_addr),
                                      entry_size=int(entry_size),
                                      count=int(count),
                                      code_base=int(code_base),
                                      signed=bool(signed),
                                      session=_session,
                                      serial=serial, pid=int(pid or 0)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "READ_FAILED")})


@server.tool()
@logged()
def probe_vm_from_hits(serial: str, pid: int,
                       count_offset: int = 0x194, array_offset: int = 0x1a0,
                       instr_size: int = 16, max_instr: int = 64,
                       max_candidates: int = 40,
                       count_size: int = 8, count_min: int = 0,
                       count_max: int = 0x100000,
                       opcode_shift: int = 1, opcode_bits: int = 4,
                       func_shift: int = 5, func_bits: int = 4) -> str:
    """从**已有断点命中**的寄存器里挖出 VM 上下文指针，直接解出指令数组。

    **这是解决「拿不到 ctx_ptr」的推荐路径**——比盲扫内存快得多也安全得多。

    ## 为什么需要它

    `dump_vm_state` 要 ctx_ptr，而 ctx_ptr 通常只在断点现场才有。如果 VM 入口
    本身不命中（加固样本常见），就会陷入两难：
        · `dump_vm_state`      要 ctx_ptr，但没有
        · `dump_vm_state_auto` 盲扫内存，实测太慢且会拖挂目标

    本工具换思路：**用已经命中的那些断点**。哪怕命中的不是 VM 入口，
    只要那些函数的参数里带着上下文指针（很常见——VM 解释器的辅助函数
    第一个参数往往就是 ctx），就能从寄存器里捞出来。

    ## 做法

        ① 取当前目标的全部命中记录（不需要重新 attach）
        ② 收集每条命中的 x0..x30 / sp / lr，当作候选 ctx_ptr
        ③ 一次脚本批量校验：[ptr+0x194] ∈ [2,100000] 且 [ptr+0x1a0] 是可读指针
        ④ 合格的候选直接调 dump_vm_state 解出指令

    ## 前置条件

    **必须已经有命中记录**。所以顺序是：

        probe_hits(...)            先确认哪个地址真的会跑
        set_breakpoint(那个地址)    在那里下断点
        hits()                     取命中现场
        probe_vm_from_hits()       从现场挖 ctx_ptr

    ## 返回

        candidates[]       每个可用候选 {ctx_ptr, from_register, instr_count,
                          instr_array, decoded, instructions[]}
        registers_probed   试了多少个寄存器值
        verdict            一句话结论

    ## 实测边界

        · 如果这批命中所在的函数不持有 VM 上下文，会返回空候选并说明原因，
          **不会编造一个 ctx**
        · 结构偏移（0x194 / 0x1a0）是经验值，不同壳版本可能不同，可覆盖

    ## (5) 第五次修改（2026-11-16）：判定结构全部参数化

    本工具的价值全在"判定候选像不像 VM 上下文"，而原实现的判定条件里有
    三个隐含假设。任意一条不成立，**正确**的候选都会被丢弃，返回的却是
    "没有一个寄存器值符合结构"——把排查方向彻底带偏：

        count_size      计数字段宽度（默认 8）。字段实为 u32 时按 u64 读，
                        会把相邻字段读进来 → 巨大值 → 候选被误杀
        count_min/count_max
                        计数合理区间（默认 0 / 0x100000）
        opcode_shift/opcode_bits/func_shift/func_bits
                        位域规则，解码阶段用（与 dump_vm_state 同口径下传）

    默认值全部等于原硬编码值。
    """
    mod, err = _load_dyn_module("server.dyn.memread", "probe_vm_from_hits")
    if err:
        return _j(err)

    # (25) 第二十五次修改（2026-11-06）：取命中记录时不再强依赖 service.hits()。
    #      bug 原因：service.hits() 要求目标**当前仍 attach**；而很多调用方
    #                是"下断点 → 命中 → 会话自动断开 → 再分析"，
    #                这时 hits() 抛 NOT_ATTACHED，明明命中的数据还在 debugger 缓存里，
    #                却拿不到，工具直接不可用。
    #      解决方案：三级回退——
    #                ① service.hits()（会话在时最完整）
    #                ② service 里残留目标的 dbg.hits（会话已 detach 仍可读缓存）
    #                ③ 调用方显式传 hits
    hit_list = []
    hits_error = ""
    try:
        from server.dyn.service import get_dyn

        svc = get_dyn()
        hit_list = svc.hits(serial, int(pid)) or []
    except Exception as exc:                              # noqa: BLE001
        hits_error = f"{type(exc).__name__}: {exc}"
        try:
            from server.dyn.service import get_dyn as _gd

            svc2 = _gd()
            tgt = svc2._targets.get(f"{serial}:{int(pid)}")   # noqa: SLF001 - 只读
            dbg = getattr(tgt, "dbg", None) if tgt is not None else None
            if dbg is not None:
                raw_hits = getattr(dbg, "hits", None)
                if isinstance(raw_hits, list):
                    for h in raw_hits:
                        hit_list.append({
                            "so_name": getattr(h, "so_name", ""),
                            "static_addr": getattr(h, "static_addr", 0),
                            "runtime_addr": getattr(h, "runtime_addr", 0),
                            "thread_id": getattr(h, "thread_id", 0),
                            "context": getattr(h, "context", {}) or {},
                            "seq": getattr(h, "seq", 0),
                        })
        except Exception:                                 # noqa: BLE001
            pass
    if not hit_list:
        return _j({"error": (f"取不到命中记录（{hits_error or '缓存为空'}）"),
                   "code": "NO_HITS",
                   "hint": ("先 set_breakpoint 并让目标命中一次。"
                            "可用 probe_hits 先确认哪个地址真的会跑")})
    try:
        return _j(mod.probe_vm_from_hits(
            serial, int(pid), hit_list,
            count_offset=int(count_offset), array_offset=int(array_offset),
            instr_size=int(instr_size), max_instr=int(max_instr),
            max_candidates=int(max_candidates),
            count_size=int(count_size), count_min=int(count_min),
            count_max=int(count_max),
            opcode_shift=int(opcode_shift), opcode_bits=int(opcode_bits),
            func_shift=int(func_shift), func_bits=int(func_bits)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "PROBE_FAILED")})


@server.tool()
@logged()
def trace_call_tree(serial: str, pid: int, so_name: str, entries: list,
                    duration: float = 5.0, max_edges: int = 500) -> str:
    """追踪一组函数入口的**调用者**，回答「这条路径到底有没有被调用」。

    某函数断点 0 命中时，有两种完全不同的原因：
        · 上层根本没有调用它（这条路在当前场景没走）
        · 地址/模块找错了

    只看"0 命中"分不清。本工具同时给出：这个函数**被调了几次**、
    **是被谁（哪个返回地址）调的**。

    ## 与 watch_module 的分工

        watch_module     在整个 so 的所有函数入口撒点，看"谁被执行了"（**广度**）
        trace_call_tree  针对指定的少数几个入口，看"谁调用了它"（**深度**）

    ## 典型用法

        # 1) 先确认哪些入口真的可挂、被执行
        watch_module(so_name, offset_range=[0x174000, 0x177000], max_points=50)

        # 2) 针对关心的几个入口看调用关系
        trace_call_tree(so_name, entries=[0x174F00, 0x175018])

    ## 参数

        entries     要追踪的函数入口静态偏移列表，如 [0x174F00, 0x175018]
        duration    观察秒数（建议 ≤ 30）
        max_edges   最多记多少条调用边（防热点函数打爆内存）

    ## 返回

        entry_hits   {offset_hex: 被调用次数}
        edges[]      {caller_static, callee_static, count}，按次数降序
        verdict      一句话结论（区分"没被调用"与"挂不上"）
        placed/failed  挂点情况

    ## 已知边界（如实标注）

        · 用 `this.returnAddress`（lr）作调用者，**只拿得到直接调用者**；
          经 PLT 或尾调用过来的可能落在桩上
        · 调用者若不在本 so 内，说明是跨模块调用——这正是有价值的线索
    """
    mod, err = _load_dyn_module("server.dyn.tracer", "trace_call_tree")
    if err:
        return _j(err)
    try:
        return _j(mod.trace_call_tree(serial, int(pid), so_name, entries,
                                      duration=float(duration),
                                      max_edges=int(max_edges)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "TRACE_FAILED")})


@server.tool()
@logged()
def decode_runtime_insn(serial: str, pid: int, so_name: str, static_addr: int,
                        count: int = 1, context: dict | None = None) -> str:
    """从**目标进程内存**读出 ARM64 指令并解码，可选配上寄存器现场。

    ## 与 disassemble 的关键区别

        disassemble(so_name, addr)   读**本地文件**——是 so 加载时的原始字节
        decode_runtime_insn(...)     读**进程内存**——是此刻真正在跑的字节

    以下场景两者不一样，只有本工具能看到真相：
        · 断点处（frida 可能改了指令）
        · 运行时自解密的代码段
        · 被 hook / inline patch 过的函数
        · 壳的 CRC 自校验还原后的代码

    返回里的 `patched: true` 就是明确告诉你「这条指令与文件不一样」。

    ## 参数

        so_name      mda 里的 so 键（用于把静态偏移换成运行时地址）
        static_addr  静态偏移，**必须 4 字节对齐**（AArch64 定长指令）
        count        连续解几条，1..64
        context      可选：命中现场的寄存器字典（`{"x0": "0x...", ...}`）。
                     给了就把指令涉及到的寄存器值一并标出来，
                     AI 不用自己再去 context 里翻。

    ## 返回

        instructions[]  {addr, static_addr, raw_hex, mnemonic, op_str,
                         is_branch, branch_kind, reg_values}
        patched         运行时字节 ≠ 文件字节时为 true
        module / module_base / runtime_addr

    ## branch_kind 的取值

        call            bl / blr        → 调用，会返回
        return          ret
        jump            b               → 直接跳转
        indirect_jump   br / braa       → 目标在寄存器里，静态不可知
        cond_jump       cbz / cbnz / tbz / tbnz

    ## 典型用法

        # 命中后看"我停在哪条指令上、寄存器此刻是多少"
        hits(...) → 取 context
        decode_runtime_insn(so_name, pc_静态偏移, context=命中.context)

    ## 已知边界

        · 只解 ARM64 定长 4 字节指令
        · context 里没有的寄存器不会出现在 reg_values 里（不编造）
    """
    mod, err = _load_dyn_module("server.dyn.memread", "decode_runtime_insn")
    if err:
        return _j(err)
    try:
        return _j(mod.decode_runtime_insn(serial, int(pid), so_name,
                                          int(static_addr), count=int(count),
                                          context=context))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "DECODE_FAILED")})


@server.tool()
@logged()
def probe_process(serial: str, pid: int = 0, package: str = "") -> str:
    """探测目标 app **是否还在跑、是否闪退、还能不能注入**。

    不用截图看界面，一条调用就能判断：

        probe_process(package="com.taobao.idlefish")
        → {"alive": true, "status": "S", "injectable": true,
           "verdict": "进程 11705 存活且可注入（状态 S=可中断睡眠）"}

    ## 什么时候用

        · 分析中途发现断点没反应，先确认 app 有没有闪退
        · 跑完一轮操作后，确认进程还是不是刚才那个
        · 准备 attach 前，先确认它可注入
        · 怀疑加固在偷偷杀进程

    ## 三条证据交叉验证（不只看一个）

        ① /proc/<pid> 是否存在      —— 进程在内核里还在不在
        ② /proc/<pid>/stat 状态字符 —— R/S/D/T/Z/X（Z=僵尸，T=被冻结）
        ③ frida 能否枚举到它        —— 能不能注入

    **只信 ① 是不够的**：实测出现过 adb ps 能看到 pid、但进程其实已经
    是僵尸的情况，也出现过 adb 看得到而 frida 枚举不到（不可注入）的情况。
    三者都正常才算真的健康。

    ## 参数

        pid       直接给 pid
        package   或者给包名（会自动找主进程；多个进程时列出全部）

    ## 返回

        alive            进程在内核里是否存在
        status           R/S/D/T/t/Z/X/I
        status_meaning   中文含义
        injectable       frida 能否看到并注入
        verdict          一句话结论
        next_step        建议怎么做
        matches[]        给 package 时，该包名下所有进程的 pid/name

    ## 实测对照

        死进程  → {"alive": false, "verdict": "在内核里已不存在（已退出/闪退）"}
        僵尸    → {"alive": true, "status": "Z", "verdict": "已是僵尸，不会执行任何代码"}
        不可注入 → {"alive": true, "injectable": false, "verdict": "存在但 frida 看不到"}
        健康    → {"alive": true, "injectable": true, "verdict": "存活且可注入"}
    """
    from server.dyn.adb import Adb

    adb = Adb(serial)
    pkg = str(package or "").strip()

    # 给包名时先找 pid
    matches: list = []
    target_pid = int(pid or 0)
    if pkg:
        try:
            out = adb._cmd("shell", "ps", "-A", "-o", "PID,NAME", check=False) or ""
        except Exception as exc:                          # noqa: BLE001
            return _j({"error": f"枚举进程失败：{type(exc).__name__}: {exc}",
                       "code": "PS_FAILED"})
        for line in str(out).splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[-1]
            if name == pkg or name.startswith(pkg + ":"):
                try:
                    matches.append({"pid": int(parts[0]), "name": name})
                except ValueError:
                    continue
        # 优先主进程（名字与包名完全一致的那个）
        main = [m for m in matches if m["name"] == pkg]
        if main:
            target_pid = main[0]["pid"]
        elif matches:
            target_pid = matches[0]["pid"]
        elif not target_pid:
            return _j({
                "ok": True, "implemented": True,
                "package": pkg, "alive": False, "matches": [],
                "verdict": f"包 {pkg} 当前**没有任何进程**在跑（已退出或从未启动）",
                "next_step": "用 monkey/adb am start 重新拉起，注意 pid 会变",
            })

    if not target_pid:
        return _j({"error": "必须给 pid 或 package 之一", "code": "NEED_TARGET"})

    try:
        probe = adb.probe_process_alive(target_pid)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PROBE_FAILED"})

    out = {"ok": True, "implemented": True, "package": pkg or None}
    out.update(probe)
    if matches:
        out["matches"] = matches
        out["process_count"] = len(matches)
    return _j(out)


@server.tool()
@logged()
def find_jni_registrations(so_name: str, max_tables: int = 50) -> str:
    """找 JNI **动态注册表**（`JNINativeMethod` 数组），把 Java 方法名映射到 so 内地址。

    **纯静态，不需要设备。**

    ## 为什么这个最有价值

    `JNINativeMethod` 是 Java 与 native 的桥：

        struct JNINativeMethod {
            const char* name;        // "doCommandNative"
            const char* signature;   // "(I[BI[B)Ljava/lang/String;"
            void*       fnPtr;       // → so 内的函数地址
        };

    找到它 = **一次拿到所有 JNI 入口的名字 ↔ 地址映射**，不用再猜哪个
    `sub_xxxx` 是 `doCommandNative`。

    对导出表被抹的加固 so 尤其关键——它们只能靠动态注册被 Java 调到。

    ## 实现要点

    · 扫 .data / .rodata / .data.rel.ro，找连续 ≥3 组 24 字节的模式
    · name 必须是合法 Java 标识符，signature 必须形如 `(...)...`
    · **fnPtr 在文件里常为 0，靠 RELA 重定位填**——本工具会解析 PT_DYNAMIC
      的 RELA/JMPREL 补上真实地址（不依赖节表，壳样本也能用）

    ## 返回

        tables[]        每张表 {table_static_addr, count, entries[]}
        entries[]       {name, signature, fn_static_addr, fn_source, fn_name}
                        fn_source: "rela"（重定位补的）/ "file"（文件里有值）/ "none"
        relocations     重定位解析情况（含 Android 压缩重定位的支持边界）
        note

    ## 已知边界（如实标注）

        · **表在运行时才构造**的话，静态找不到——返回空 + 四条证据说明，
          不是"功能没实现"
        · Android 压缩重定位（DT_ANDROID_RELA / DT_RELR）暂不解析，
          会在 relocations.unparsed 里标注

    ## 实测

        sg_real.so（闲鱼壳）：0 张表——全文件 14680 个字符串里含 `Ljava`
                              的为 0 个，JNI 签名根本不存在，表必是运行时构造
        liblog / libbase / libcutils：0 张表，无误报
        内存植入真表验证：正确检出 3 条目，RELA 补地址生效
    """
    mod, err = _load_dyn_module("server.dyn.jni", "find_jni_registrations")
    if err:
        return _j(err)
    try:
        so = _pick_so_by_name(_session, so_name)
        if so is None:
            return _j({"error": f"{so_name} 未加载到 mda；先调 load_so",
                       "code": "SO_NOT_LOADED"})
        return _j(mod.find_jni_registrations(so_name, so=so,
                                             session=_session,
                                             max_tables=int(max_tables)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "JNI_SCAN_FAILED")})


@server.tool()
@logged()
def find_dispatch_tables(so_name: str, max_tables: int = 200,
                         min_entries: int = 3) -> str:
    """全库扫描 so 里**所有 switch 跳转表**（一次性，不用一个地址问一次）。

    **纯静态，不需要设备。**

    ## 与 resolve_br / read_jump_table 的分工

        resolve_br       给一个 br 地址，解开它指向哪
        read_jump_table  给一个表地址，读出表内容
        **find_dispatch_tables  不用给任何地址，全库找出所有表**

    ## 识别的形态

        A. adr/adrp + ldrsw + add + br    → signed_offset_4（4 字节有符号偏移）
        B. adrp + ldr + br                → absolute_ptr_8（8 字节绝对地址）
        C. adrp + ldrb + …                → byte_indexed

    ## 返回

        tables[]  {table_addr, found_at_br, enclosing_function, mode,
                   entry_size, code_base, resolved_entries, targets[],
                   targets_in_executable, confidence}
        confidence: high（目标全在可执行段）/ medium / low（多越界，可能误报）

    ## 实测（sg_real.so，3007 个函数）

        找到 58 张表，耗时约 38 秒
        例：table=0x25430 mode=signed_offset_4 entries=209 conf=high

    ## 已知边界

        · 只覆盖上述三种形态；其他索引方式（如 ldrh）未识别
        · confidence=low 的条目可能是误报，自行判断
        · 全库扫描较慢（3000 函数约 40 秒），属正常
    """
    mod, err = _load_dyn_module("server.dyn.dispatch", "find_dispatch_tables")
    if err:
        return _j(err)
    try:
        so = _pick_so_by_name(_session, so_name)
        if so is None:
            return _j({"error": f"{so_name} 未加载到 mda；先调 load_so",
                       "code": "SO_NOT_LOADED"})
        return _j(mod.find_dispatch_tables(so_name, so=so, session=_session,
                                           max_tables=int(max_tables),
                                           min_entries=int(min_entries)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "DISPATCH_SCAN_FAILED")})


# ---------------- Java 层分析（frida 17 需注入 bridge） ----------------
# ---------------------------------------------------------------------------
# RELA / vtable：静态重定位解析（第 33 轮反馈问题 5）
#
# 为什么需要：加固 so 里的函数经常通过 vtable / GOT **间接调用**，
# 没有任何 bl 指向它 —— 于是函数发现漏掉它、function_at 把几个逻辑
# 函数粘成一个，整个分析方向被带偏。重定位表里有 addend，那就是
# "这个槽最终指向哪个地址"，是间接调用目标的唯一静态来源。
# ---------------------------------------------------------------------------


@server.tool()
@logged()
def rela_dump(so_name: str, addr_from: int = 0, addr_to: int = 0,
              kind: str = "all", limit: int = 500) -> str:
    """导出某 so 的重定位表（`.rela.dyn` / `.rela.plt` / `PT_DYNAMIC`）。

    **纯静态，不需要设备。** 节表被抹的 dump so 也能解析（走 PT_DYNAMIC）。

    ## 什么时候该用它

    - 想知道 `vtable[4]` 实际指向哪个函数（配合 vtable_at）
    - 想找**没有 bl 指向**的函数入口（`kind="code_target"`）
    - 想确认某个地址是不是被重定位覆盖（GOT 槽 / vtable 槽）

    ## 参数

        addr_from / addr_to  按 r_offset 过滤（左闭右开）；都传 0 表示不限
        kind  all          全部条目
              code_target  只要 addend 落在**可执行段**的项
                           —— 这些就是潜在的函数指针目标
              relative     只要 RELATIVE / IRELATIVE
              plt          只要 PLT 表里的项（导入符号的 GOT 槽）
        limit <=0 表示不限制

    ## 条目字段

        offset / offset_hex    r_offset（槽地址）
        rtype / rtype_name     重定位类型
        sym_idx / sym_name     符号（无 dynsym 时 sym_name 为空，sym_resolved=false）
        addend / addend_hex    附加值
        addend_is_target       **true 才代表 addend 就是目标地址**
                               （只有 RELATIVE/IRELATIVE 是；ABS64/GLOB_DAT
                                的 addend 是附加到符号值上的偏移，别直接当地址）
        addend_in_exec         addend 是否落在可执行段
        target_function        addend 若在可执行段，给出所在函数名
        source                 来自哪张表（rela.dyn/rela.plt/rel.plt/dynamic）

    ## 解析失败时

    返回的 `items` 为空 + `summary.error` 给出原因，**不会返回编造的占位条目**。
    """
    so = _session.get(so_name)
    from server.core import rela as _rela

    try:
        items = _rela.rela_dump(so, int(addr_from), int(addr_to),
                                kind, int(limit))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "RELA_DUMP_FAILED"})
    summary = _rela.rela_summary(so)
    out = {"ok": True, "so": so.name, "kind": kind,
           "count": len(items), "limit": int(limit),
           "truncated": int(limit) > 0 and len(items) >= int(limit),
           "items": items, "summary": summary}
    if summary.get("error"):
        out["ok"] = False
        out["error"] = summary["error"]
    return _j(out)


@server.tool()
@logged()
def vtable_at(so_name: str, addr: int) -> str:
    """判断地址是否是 **vtable 项**，并解出它指向哪个函数。

    **纯静态，不需要设备。**

    ## 判定分三层（任一层不过都给理由，不猜）

    1. addr 必须是某条 RELATIVE 重定位的 r_offset（槽地址，按指针宽度对齐）
    2. 所在连续块至少 2 项（单槽无法与孤立指针区分）
    3. 块内 addend 落在可执行段的比例 >= 0.5
       —— vtable 项是函数指针；字符串表/typeinfo 这类数据指针块会被判为非 vtable

    ## 典型用法：从虚表偏移追到实现函数

        vtable_at(so, 0x2dc778)
        → is_vtable: true, index: 4, target: 0x196424,
          target_function: sub_196424, block: [0x2dc768, 0x2dc820)

    拿到 `target` 之后，用 `function_at`/`disassemble` 看实现；
    如果 `function_at` 返回的入口不是 target 本身，说明该函数**还没被
    发现**——用 `discover_functions(aggressive=true)` 补（严格档会收
    完整栈帧的真函数）。

    ## 不是 vtable 时

    返回 `is_vtable=false` + `reason`，并尽量给出该地址所在的块信息，
    方便判断"是数据块"还是"判据太严"。
    """
    so = _session.get(so_name)
    from server.core import rela as _rela

    try:
        out = _rela.vtable_at(so, int(addr))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "VTABLE_AT_FAILED"})
    out["ok"] = True
    out["so"] = so.name
    return _j(out)


@server.tool()
@logged()
def rela_summary(so_name: str) -> str:
    """重定位解析概况与**能力边界**（解析失败时这里给原因，不是空列表）。

    先看这个再决定要不要 rela_dump：
    - `total` / `counts`：条目数与各表分布
    - `code_targets`：addend 落在可执行段的去重地址数
    - `vtable_blocks`：识别出的 vtable 块数
    - `packed_android` / `relr`：遇到不支持的压缩编码/RELR 时如实标出
    - `error` / `warnings`：失败原因与降级说明
    """
    so = _session.get(so_name)
    from server.core import rela as _rela

    try:
        out = _rela.rela_summary(so)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "RELA_SUMMARY_FAILED"})
    out["ok"] = not out.get("error")
    out["so"] = so.name
    return _j(out)


# ---------------------------------------------------------------------------
# DEX 静态解析（第 33 轮反馈问题 7）
#
# 反馈原文：「没有 dex 能力，我被迫自己写，踩了 4 个坑，每个坑都导致过
# 看到不存在的东西（假 payload、假 native 调用、假 MessageDigest）」。
#
# 本组工具把 DEX 当**独立输入**（dex 文件或 apk），不进 so 分析会话——
# Java 层没有虚拟地址概念，套用 so 的模型反而会误导。
# 正确性由 dexdump 逐指令交叉验证（实测 36650 个方法 / 563078 条指令 100% 一致）。
# ---------------------------------------------------------------------------


@server.tool()
@logged()
def dex_classes(path: str) -> str:
    """列出一个 dex/apk 里的**所有类**（纯静态，不解压到磁盘）。

    `path` 是文件路径：可以是 `.dex`，也可以是 `.apk` / `.jar`
    （内部多个 `classes*.dex` 会按顺序合并）。

    ## 返回字段（`classes[]` 每项）

        name            dex 原始描述符（`Lcom/x/Y;`）——传给 dex_methods 两种都行
        java_name      给人看的形态 `com.x.Y`
        access_flags / access_names   访问标志原值与逐个名字
        superclass / interfaces       父类与接口描述符
        method_count / field_count    方法/字段数
        source_file     SourceFile 属性（混淆后常为空）
        dex            来源条目（classes.dex / classes2.dex …）

    若某个 dex 解析失败，**不影响其它 dex**：失败项以
    `{error, code, dex}` 的形式出现在列表末尾，务必检查。

    ## 多 dex

    `dex_count` 说明合并了几个 dex。同名类出现在多个 dex 时以**先出现的**为准
    （与 Android 的类加载顺序一致）。

    ## 需要 Java 层定位时

    先 `dex_classes` 找类 → `dex_methods` 看方法 → `dex_disasm` 反汇编 →
    `dex_callers` 反查调用点。这四步对应 IDA 的类树/方法表/反汇编/交叉引用。
    """
    from server.core.dex import dex_classes as _dex_classes

    try:
        classes = _dex_classes(path)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "DEX_CLASSES_FAILED", "path": path})
    if isinstance(classes, dict):        # 内部错误对象（如文件不存在）
        return _j(classes)
    return _j({"ok": True, "path": path, "count": len(classes),
               "classes": classes})


@server.tool()
@logged()
def dex_methods(path: str, class_name: str) -> str:
    """列出某个类的**所有方法**（含 access flags、native/abstract 标记）。

    class_name 接受三种写法：`com.x.Y`、`Lcom/x/Y;`、`com/x/Y`。

    ## 关键字段

        name / proto            方法名与原型描述符
        return_type / params    拆开后的返回类型与参数类型（已从描述符归一）
        access_flags / access_text
        is_native               **native 方法**（实现不在 dex 里，要去 so 找）
        is_abstract / is_static / is_constructor
        code_off                code_item 文件偏移（0 表示无实现）
        insn_count / regs_size  指令数与寄存器数
        param_count

    ## 定位 native 实现

    `is_native=true` 的方法要在 so 里找对应实现：
    - 静态注册：导出符号 `Java_<包>_<类>_<方法>`（可 `exports` 按关键字搜）
    - 动态注册：`find_jni_registrations(so)` 拿 `JNINativeMethod` 表最可靠
    """
    from server.core.dex import dex_methods as _dex_methods

    try:
        out = _dex_methods(path, class_name)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "DEX_METHODS_FAILED"})
    if isinstance(out, dict):
        return _j(out)
    return _j({"ok": True, "path": path, "class_name": class_name,
               "count": len(out), "methods": out})


@server.tool()
@logged()
def dex_disasm(path: str, class_name: str, method_name: str,
               overload: str = "") -> str:
    """反汇编一个 dex 方法的**字节码**（每条带 dex 字节偏移）。

    重载方法用 overload 指定参数描述符，例如 `overload="(I)V"`；
    不给时若同名方法有多个，会返回候选列表让你选（**不替你猜**）。

    ## 输出每一行都带偏移

        // Lcom/x/Y;->check(Ljava/lang/String;)Z @ 0x1a2b4, 42 insns
          0000: invoke-static {p0}, Lcom/x/A;->a(Ljava/lang/String;)Ljava/lang/String;
          0006: move-result-object v0
          0008: invoke-virtual {v0}, Ljava/lang/String;->length()I
          ...

    偏移是 **code_item 内的 code unit 序号**，可直接与 dexdump 的输出对照。

    ## 三个容易看错的地方（本实现已处理，说明给你避坑）

    1. **payload 不是独立指令**：`packed-switch-payload` / `sparse-switch-payload`
       / `fill-array-data-payload` 只有在紧跟对应 switch/fill 指令时才是数据，
       否则 `0x0100` 只是一条 `nop`。输出里 payload 会标成 `payload:` 块。
    2. **变长指令**：`move-wide/16`(0x06) 是 **32x = 3 code unit**（不是 2）；
       2 unit 的是 `move-wide/from16`(0x05, 22x) 这类。数错一处后续全错位。
    3. **增量索引**：`class_data_item` 里的 method_idx 是**增量**，不累加会把
       整类方法解成同一个（症状：一个类里几十个同名 `<init>`）。

    native / abstract 方法没有字节码，会明确说明而不是返回空。
    """
    from server.core.dex import dex_disasm as _dex_disasm

    try:
        out = _dex_disasm(path, class_name, method_name, overload or "")
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "DEX_DISASM_FAILED"})
    if isinstance(out, dict):
        return _j(out)
    return out


@server.tool()
@logged()
def dex_callers(path: str, class_name: str, method_name: str,
                overload: str = "") -> str:
    """**谁调用了这个方法**（静态扫描所有 invoke-* 指令）。

    ## 为什么这个在 Java 层特别好用

    没有虚拟地址、没有间接跳转的不确定性：`invoke-virtual/...` 的操作数里
    直接写着 method_idx，扫一遍全部 code_item 就能精确反查。这是 Java 层
    相对 native 层的天然优势，别浪费。

    ## 返回字段

        caller_class / caller_method   调用方
        caller_proto
        invoke_kind                    virtual / direct / static / interface /
                                       super / virtual-range ...
        offset                         调用点在该方法 code_item 内的偏移
        is_native_caller               调用方自身是否 native（此时拿不到字节码）

    ## 注意：这不是完整的调用图

    只覆盖**直接写在字节码里**的调用：
    - 反射（`Class.getMethod().invoke`）看不到
    - JNI 从 native 侧的调用看不到
    - 混淆后的同名方法会全部列出（用 caller_class 区分）

    需要反射调用分析时，用动态侧的 `java_hook` / `java_find_callers`。
    """
    from server.core.dex import dex_callers as _dex_callers

    try:
        out = _dex_callers(path, class_name, method_name, overload or "")
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "DEX_CALLERS_FAILED"})
    if isinstance(out, dict):
        return _j(out)
    return _j({"ok": True, "path": path, "class_name": class_name,
               "method_name": method_name, "count": len(out), "callers": out})


#
# frida 17 起 Java bridge 从内核解耦，脚本里直接 `Java.use` 会报
# ReferenceError。dyn/java_bridge.py 负责把 frida_tools 自带的 java.js
# 拼到脚本前面，这一组工具才有 Java 能力。


@server.tool()
@logged()
def java_bridge_status() -> str:
    """检查 **Java bridge 是否可用**（纯本地，不连设备）。

    frida 17 起 Java bridge 不再内置，需要 mda 注入 `frida_tools` 自带的
    `java.js`。本工具报告能否找到该文件——找不到时所有 java_* 工具都会失败，
    先查这里最快。

    返回：{ok, path, size_bytes, loaded_from_cache, error, code}
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "bridge_status")
    if err:
        return _j(err)
    try:
        return _j(mod.bridge_status("java"))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "BRIDGE_CHECK_FAILED"})


@server.tool()
@logged()
def java_list_methods(serial: str, pid: int, class_name: str,
                      include_fields: bool = True) -> str:
    """列出一个 Java 类的所有方法与字段（**包含动态加载的类**）。

    加固 app 的类常由 DexClassLoader 懒加载，静态反编译看不到。本工具通过
    `Java.use(cls).class` 拿运行时的 Class 对象，所以**运行时才存在的类也能列**。

    ## 参数

        class_name       全限定类名，如 "android.app.Activity"（不能用简称）
        include_fields   是否一并列字段

    ## 返回

        found / class_name / superclass / interfaces
        methods[]   {name, signature, return_type, param_types, is_native, modifiers}
        fields[]    {name, type, modifiers}
        counts      {methods, fields}

    ## 找不到类时

    返回 found=false + hint，提示两种常见原因：类名写错（需要全限定名）、
    类还没被加载（用 `java_find_classes` 先按正则找）。
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_list_methods")
    if err:
        return _j(err)
    try:
        return _j(mod.java_list_methods(serial, int(pid), class_name,
                                        include_fields=bool(include_fields)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_LIST_FAILED"})


@server.tool()
@logged()
def java_find_classes(serial: str, pid: int, pattern: str = "",
                      limit: int = 200, field: str = "",
                      return_type: str = "", method_pattern: str = "",
                      max_scan_classes: int = 0,
                      all_loaders: bool = False) -> str:
    """在**已加载的类**里搜索——支持类名、字段名、返回类型、方法名四种维度。

    加固 app 会动态加载大量类，静态看不到。本工具枚举运行时全部 Class 再筛选，
    是摸清一个 app 内部结构的起点。

    ## 四种搜索维度（可组合）

        pattern        类名（支持正则，也支持 * ? 通配符）
        field          类里有这个**字段名**
        return_type    类里某方法**返回这个类型**（全限定名）
        method_pattern 类里有匹配这个**方法名**的方法

    **匹配语义**（踩过坑，写清楚）：类名与字段名是**子串搜索**——
    `Security` 能匹配 `com.x.SecurityGuard`，不需要写全名；
    方法名是**精确/通配匹配**——`setHeaders` 不会连带 `setHeadersAndMore`。
    非法正则（如 `[[[`）会明确报错，**不会静默返回全部**。

    ## 参数

        pattern          类名（正则或通配符），空则不限
        limit            最多返回多少个（1..2000）
        field            字段名，如 "headers"
        return_type      返回类型，如 "*Request"
        method_pattern   方法名，如 "get*"
        max_scan_classes 反射扫描上限（0=默认3000）
        all_loaders      扫**所有 ClassLoader**（默认 false）。
                         加固 App 的类常由 DexClassLoader 动态加载，
                         默认只查默认 loader，会漏——表现为"类明明存在却找不到"。

    ## 性能提示（重要）

    只给 pattern → 秒回（走 `enumerateLoadedClassesSync`，不反射）。
    给了 field/return_type/method_pattern → **需要逐类反射，很慢**，
    已加载类几万个时尤其明显。用 max_scan_classes 限制扫描量，
    返回里的 `scanned` 会说明实际扫了多少类，用于判断结果是否可信。

    **建议先用 pattern 缩小范围再叠加其他维度。**

    ## 返回

        classes[]  全限定类名
        reasons{}  命中的依据（哪个字段/方法匹配的）
        total      枚举到的类总数
        scanned    实际反射扫描的类数
        matched    匹配数
        matched_by 本次用了哪些维度

    ## 典型用法

        java_find_classes(pattern="Security|Sign|Guard")
        java_find_classes(pattern="*StatusBar*", field="m*")
        java_find_classes(return_type="*Request", max_scan_classes=2000)
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_find_classes")
    if err:
        return _j(err)
    try:
        return _j(mod.java_find_classes(
            serial, int(pid), pattern, limit=int(limit),
            field=field, return_type=return_type,
            method_pattern=method_pattern,
            max_scan_classes=int(max_scan_classes),
            all_loaders=bool(all_loaders)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_FIND_FAILED"})


@server.tool()
@logged()
def java_hook(serial: str, pid: int, class_name: str = "", method: str = "",
              overload: str = "", duration: float = 5.0, max_calls: int = 200,
              include_stack: bool = True, stack_depth: int = 8,
              pattern: str = "", package: str = "", max_classes: int = 20,
              capture: dict | None = None, sibling_probe: bool = True,
              auto_degrade: bool = True, degrade_l1_rate: float = 200.0,
              degrade_l2_rate: float = 1000.0, degrade_l3_rate: float = 5000.0,
              degrade_window_ms: int = 200,
              parent_probe: bool = False, deep_diag: bool = False,
              diag_siblings: int = 8, max_methods: int = 60) -> str:
    """hook Java 方法——支持**通配符批量**、参数深挖、0 命中诊断。

    ## 最常用：不知道 hook 哪个类时用通配符

        java_hook(pattern="*NetworkConverter*", method="convert*",
                  max_classes=20, duration=15)
        → 一次 hook 所有匹配的类，**分别统计命中数**，
          直接告诉你哪个类真的被调用了

    这比"猜一个类 → 等 16 秒 → 没命中 → 再猜"快一个数量级。

    ## 三种定位方式（可组合，取交集）

        class_name="com.x.Y"      精确类名
        pattern="*Converter*"     类名通配符（* 和 ?）
        package="mtopsdk"         包名前缀

    ## 参数

        method        方法名，也支持通配符（"convert*"）。空 = 该类所有方法
        max_classes   最多 hook 多少个类（默认 20，上限 200）
        max_calls     每个方法最多记录多少条
        capture       参数深挖：{"args": true, "ret": true,
                      "arg_fields": ["url","headers"], "expand_map": true}
                      Map/List 会自动展开成键值对；arg_fields 从参数对象取字段
        sibling_probe 方法 0 命中时，**自动探测同类其他方法**有没有被调用

    ## 热方法会自动降级（不用担心 hook 崩目标）

    hook 高频方法（列表滑动每帧都调的那种）时，每次命中都取 Java 栈 +
    转参数会把目标拖死。工具在 **JS 侧**按实测命中速率自动分三级降级：

        一级 >200 次/秒    关掉栈采集（getStackTrace 是开销大头）
        二级 >1000 次/秒   再关掉参数/返回值转换
        三级 >5000 次/秒   只累加计数，不再记录明细

    降级是**单向**的（降了不回升，避免阈值附近抖动），且**一定会在返回里
    报出来**——`degrade.note` 与 `verdict` 都会写明「已自动降级，原因是该
    方法是热方法（实测 N 次/秒）」。没降级时返回里**没有** `degrade` 字段。
    被 hook 的方法始终照原样调用，降级只减观测、不改行为。

    auto_degrade=False 可关掉（恢复旧行为，但高频方法有崩目标的风险）；
    degrade_l1_rate / degrade_l2_rate / degrade_l3_rate / degrade_window_ms
    可调阈值与统计窗口。

    ## 返回

        classes[]   每个类：{class, call_count, hooked_methods, method_exists,
                    subclass_of}，按命中数降序
        call_count  合计
        diagnosis   0 命中时给出（最有价值的部分）：
                      class_loaded / method_exists /
                      sibling_methods_called / suggestion
        verdict     一句话结论

    ## 0 命中时的诊断长这样

        {"class_loaded": true, "method_exists": true,
         "sibling_methods_called": [{"method": "X.convertNetworkStats","hits": 12}],
         "suggestion": "方法存在但零调用：...；同类里 X.convertNetworkStats
                        被调了 12 次——真正干活的很可能是它"}

    ## 已知边界

        · java.lang.* / dalvik.* 等系统包已在注入前自动排除（hook 后易崩）
        · final 可 hook；被 JIT 内联的会漏
        · 通配符只在**已加载类**里匹配
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_hook")
    if err:
        return _j(err)
    try:
        return _j(mod.java_hook(
            serial, int(pid), class_name=class_name, method=method,
            overload=overload, duration=float(duration),
            max_calls=int(max_calls), include_stack=bool(include_stack),
            stack_depth=int(stack_depth), pattern=pattern, package=package,
            max_classes=int(max_classes), capture=capture,
            sibling_probe=bool(sibling_probe),
            parent_probe=bool(parent_probe),
            deep_diag=bool(deep_diag),
            diag_siblings=int(diag_siblings),
            max_methods=int(max_methods),
            auto_degrade=bool(auto_degrade),
            degrade_l1_rate=float(degrade_l1_rate),
            degrade_l2_rate=float(degrade_l2_rate),
            degrade_l3_rate=float(degrade_l3_rate),
            degrade_window_ms=int(degrade_window_ms)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_HOOK_FAILED"})


@server.tool()
@logged()
def java_stacktrace(serial: str, pid: int, depth: int = 30,
                    skip_internal: bool = True) -> str:
    """取**当前 Java 调用栈**（结构化：类/方法/文件/行号）。

    mda 之前没有独立的 Java 取栈工具——native 侧有 get_callstack，
    Java 侧只能从 java_hook 里顺带拿零散帧。本工具补上这块。

    ## 关键信息：is_native

        line == -2  → 该帧是 **native 方法**（Java→so 的交界点）
        line == -1  → 行号未知（混淆/无调试信息）
        line >= 0   → 正常行号

    拿到 is_native=true 的 class/method，就能接着用 native 侧的
    get_callstack / set_breakpoint 接上两条栈。

    ## 边界（重要）

        取的是**执行本工具那一刻**的线程栈（frida 的 JS 线程），
        不是业务线程。要抓业务线程的栈请用 java_find_callers
        （在方法被调时取栈）。跨线程全量请看 stack_all_threads。
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_stacktrace")
    if err:
        return _j(err)
    try:
        return _j(mod.java_stacktrace(serial, int(pid), depth=int(depth),
                                      skip_internal=bool(skip_internal)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "STACKTRACE_FAILED"})


@server.tool()
@logged()
def stack_all_threads(serial: str, pid: int, max_threads: int = 40,
                      depth: int = 15, name_filter: str = "") -> str:
    """取**全部 Java 线程**的栈快照（一次调用拿全）。

    与 java_stacktrace 的区别：那个取的是"执行工具那一刻的线程"（在 frida
    的 JS 线程里通常是空栈）；本工具用 getAllStackTraces() 拿**所有业务线程**。

    ## 用它定位什么

        · 多个线程 state=BLOCKED 且栈顶是同一把锁 → 锁竞争
        · 线程 state=WAITING 且栈顶 Object.wait → 在等通知
        · 某线程栈顶 is_native=true → 卡在 so 里（接 native 侧 get_callstack）

    ## 返回

        threads[]  {name, state, priority, daemon, depth, frames[]}
        states     按状态聚合计数
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "stack_all_threads")
    if err:
        return _j(err)
    try:
        return _j(mod.stack_all_threads(serial, int(pid),
                                        max_threads=int(max_threads),
                                        depth=int(depth),
                                        name_filter=name_filter))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "ALL_THREADS_FAILED"})


@server.tool()
@logged()
def java_find_callers(serial: str, pid: int, class_name: str, method: str,
                      overload: str = "", duration: float = 8.0,
                      max_samples: int = 30, stack_depth: int = 12) -> str:
    """找出**谁调用了**某个 Java 方法，返回调用栈样本。

    当 `java_hook` 说"这个方法没被调用"时，下一步该问的是
    **"那到底谁在干活"**——可能是父类、兄弟方法，或完全另一个类。
    追调用栈比逐个猜快得多。

    ## 与 java_hook 的分工

        java_hook         看"被调时参数/返回值是什么"
        java_find_callers 看"**被谁**调用"（只要调用链，不抓参数）

    ## 返回

        callers[]   按次数降序：{frame, hits}
                    frame 是 "类.方法(文件:行)" 形式的上层帧
        samples[]   原始调用栈样本（最多 max_samples 条）
        call_count  总调用次数
        verdict

    ## 典型用法

        java_find_callers("mtopsdk...ANetworkConverter", "convertRequest")
        → callers: [{"frame": "mtopsdk.mtop...HttpCallImpl.execute", "hits": 12}]
        这样能把 mtopsdk → anetwork → tnet 的链路串起来

    ## 已知边界

        · 只抓 **Java 层**栈；native 调用者要配合 trace_call_tree
        · 栈帧按"类.方法(文件:行)"归并——同一方法的不同调用点会被分开统计，
          这是刻意的（能看出具体哪个分支）
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_find_callers")
    if err:
        return _j(err)
    try:
        return _j(mod.java_find_callers(
            serial, int(pid), class_name, method, overload=overload,
            duration=float(duration), max_samples=int(max_samples),
            stack_depth=int(stack_depth)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "CALLERS_FAILED"})


@server.tool()
@logged()
def java_hook_hint(serial: str, pid: int, query: str = "", package: str = "",
                   method: str = "", include_network: bool = True,
                   limit: int = 30, max_scan_classes: int = 3000,
                   count_seconds: float = 0.0,
                   all_loaders: bool = False) -> str:
    """**不知道该 hook 谁时的罗盘**：给模糊线索，返回排好序的候选清单。

    (1) 第一次修改（2026-11-13）：新增。

    ## 它解决的场景

    你 hook 了 `CommentRealApi` 全类 0 命中，然后**不知道该换哪个类**。
    `java_find_classes` 只能给一串类名，不知道该先看哪个；
    `java_hook` 一次试一个要十几秒。本工具把"像它的类"一次列出并**排序**。

    ## 四个线索维度（可组合）

        query          类名片段（"CommentRealApi" / "Interceptor"），
                       也接受正则（自动判断，与 java_find_classes 同一套语义）
        package        包名前缀
        method         方法名片段 —— **按"含这个方法"找类，比类名更能
                       锁定真正在干活的类**
        include_network 一并返回网络层通用候选（默认 True，见下）

    ## 关于 include_network（重点）

    返回的 `network[]` 是 **Android / okhttp / JDK 标准 API 的常识清单**，
    不是某个 App 的特征。当你问"谁在给 HTTP 请求加 header"时，它直接给出
    通用的可挂点：

        · okhttp 的 Interceptor 实现（method=intercept）
        · okhttp3.Request$Builder 的 addHeader / header
        · java.net.HttpURLConnection 的 setRequestProperty

    每条带 `how` 字段，说明"下一步该挂哪里、看什么"。

    ## 排序依据

        1.00  类名完全相同
        ~0.95 一方是另一方的子串（CommentApi ⊂ CommentRealApi）
        ~0.7  共享有信息量的词元（Comment helper/manager）
        ~0.42 只共享 api/util 这类通用后缀（**不算证据，压到后面**）

    ## count_seconds > 0：顺手做一次低成本验证

    猜完之后可以立刻验证：它会临时挂一批**只计数**的 hook
    （不取栈、不转参数，单次命中只加一个整数），跑 N 秒后卸载。
    返回里每个候选带上 `call_count`，并按真实调用次数重排。
    **默认 0 = 完全不 hook，纯只读查询。**

    ## 返回

        candidates[]  {class, score, method_count, hookable,
                      is_interface, is_abstract, superclass,
                      methods_sample[], call_count}
        network[]     网络层通用候选（含 how）
        verdict       下一步建议

    ## 典型流程

        # ① 完全没方向：先问网络层
        java_hook_hint(serial, pid, include_network=True)     # 只读，秒回

        # ② 有线索：按类名找 + 顺手计数验证
        java_hook_hint(serial, pid, query="Comment", count_seconds=5)

        # ③ 按方法找（比类名更硬）
        java_hook_hint(serial, pid, method="setRequestProperty", count_seconds=5)

    ## 已知边界（如实标注）

        · 只覆盖**已加载**的类。懒加载的类要用之前先触发一次功能
        · 反射扫描受 max_scan_classes 限制，达到上限会标 scan_capped
        · score 是启发式排序，**不是判定**——它只负责把像的排前面
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "java_hook_hint")
    if err:
        return _j(err)
    try:
        return _j(mod.java_hook_hint(
            serial, int(pid), query=query, package=package, method=method,
            include_network=bool(include_network), limit=int(limit),
            max_scan_classes=int(max_scan_classes),
            all_loaders=bool(all_loaders),
            count_seconds=float(count_seconds)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_HINT_FAILED"})


@server.tool()
@logged()
def java_count_calls(serial: str, pid: int, classes: list,
                     method: str = "", seconds: float = 3.0,
                     max_methods_per_class: int = 60) -> str:
    """**不抓任何数据，只统计方法被调了几次** —— 低成本探查。

    (1) 第一次修改（2026-11-13）：新增。

    ## 它为什么存在

    `java_hook` 的每次命中都要取 Java 栈（遍历整个栈并构造
    StackTraceElement）再对每个参数 toString，实测单次 0.5~3 毫秒。
    探查阶段挂整类几十个方法时，这会明显拖慢目标，还容易触发
    java_hook 自己的自动降级——最后看到的数据已经是降级后的了。

    本工具反过来：**只累加一个整数**。不取栈、不碰参数、不构造记录对象，
    单次命中的成本是一个闭包调用 + 一次加法。

    ## 典型用法（探查 → 定向，不是盲试）

        # ① 先便宜地看谁在干活
        java_count_calls(serial, pid, classes=["com.x.CommentApi",
                                               "com.x.CommentHelper"], seconds=5)
        → [{"class": "com.x.CommentHelper", "call_count": 42, ...},
           {"class": "com.x.CommentApi",    "call_count": 0,  ...}]

        # ② 确认了再上 java_hook 抓参数
        java_hook(serial, pid, class_name="com.x.CommentHelper", method="add")

    ## 参数

        classes              要计数的类（全限定名列表）
        method               只计这些方法名（支持通配符，空 = 该类的所有方法）
        seconds              采集秒数
        max_methods_per_class 每类最多挂多少个方法（默认 60，防一次挂几千个）

    ## 返回

        classes[]   {class, call_count, hooked_methods, error}，按次数降序
        total_calls 合计
        note        一句话结论；0 次时会提示"先触发功能再重试"

    ## 失败如实报（不粉饰）

        · 系统类（java.lang.* 等）会被跳过并写明原因
        · **接口**会被跳过——接口的声明方法没有实现体，挂了也不会命中。
          这是最容易白跑一轮的原因，所以直接报到 error 字段里
        · 单个方法挂不上不影响其他方法
        · 与所有 Java hook 一样：被 JIT 内联的方法会漏
    """
    mod, err = _load_dyn_module("server.dyn.java_bridge", "_java_count_calls")
    if err:
        return _j(err)
    if not classes:
        return _j({"ok": False, "implemented": True, "code": "NEED_CLASSES",
                   "error": "至少要给一个类名",
                   "hint": "不知道给哪些类时，先用 java_hook_hint 拿候选清单"})
    try:
        return _j(mod._java_count_calls(
            serial, int(pid), list(classes), method=method,
            seconds=float(seconds),
            max_methods_per_class=int(max_methods_per_class)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_COUNT_FAILED"})


@server.tool()
@logged()
def perf_watch_probe(serial: str) -> str:
    """检查**硬件观察点**这条路径在本设备是否可用（不设观察点）。

    这条路**不经过 frida**，用内核的 perf_event 硬件断点。

    ## 与 trace_write 的区别（关键）

        trace_write    hook libc 内存函数（memcpy/memset…）
                       → **编译器内联的 str/stp 抓不到**
        perf_watch     CPU 硬件触发
                       → **任何指令都能抓**，且不停线程、不可检测、开销极低

    能力有限制：watchpoint 只有 **4 个槽位**，长度只能 1/2/4/8 字节。

    返回：{ok, max_slots, max_len, helper, note}
    """
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch_probe")
    if err:
        return _j(err)
    try:
        return _j(mod.perf_watch_probe(serial))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_PROBE_FAILED"})


@server.tool()
@logged()
def perf_watch(serial: str, pid: int, addr: str, size: int = 8,
               watch_type: str = "w", tid: int = 0, duration: float = 3.0,
               max_hits: int = 32) -> str:
    """在指定地址上设**硬件观察点**，抓「谁访问了这块内存」。

    这是回答「这块数据是谁生成的」最直接的手段，**不依赖 frida**。

    ## 为什么不用 trace_write

    `trace_write` hook 的是 libc 的 memcpy/memset 等函数，
    **编译器内联的直接 `str`/`stp` 完全抓不到**。而 perf_watch 是
    CPU 硬件触发，任何指令都能抓，且不停线程、目标无感知。

    ## 参数

        addr        运行时绝对地址。带 ARM64 tag（0xb4...）也行，内部自动脱
        size        观察字节数，只有 1/2/4/8（内核限制）
        watch_type  "w" 写 / "r" 读 / "rw" 读写 / "x" 执行
        tid         观察哪个线程。0 = 整个进程。
                    **但观察点按线程生效**，写入往往只在某个特定线程，
                    抓不到时先换写线程的 tid
        duration    采集秒数
        max_hits    最多返回多少条

    ## 返回

        count / hits[] / distinct_pcs
        hits[]: {ip, pid, tid, ts_ms, regs:{x0,x1,x2,lr}}

    ## 0 命中的排查顺序（工具会自动提示）

        ① tid 不对（最常见）
        ② 地址在窗口内没被写
        ③ 该线程槽位已满（NO_SLOT）
        ④ 写入不在观察窗口内

    ## 典型用法（抓「首次写入」）

        perf_watch(serial, pid, addr="0xb400007d8780a000", size=8,
                   watch_type="w", duration=5, max_hits=1)

    ## 已知边界

        · 只有 4 个槽位，第 5 个地址要先清掉一个
        · 部分进程主线程返回 NO_SLOT，换非主线程
        · 只给**写指令的 pc**，不给调用栈；
          要调用栈用返回的 ip 到 frida 侧下断点补
    """
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch")
    if err:
        return _j(err)
    try:
        return _j(mod.perf_watch(serial, int(pid), addr, size=int(size),
                                 watch_type=watch_type, tid=int(tid),
                                 duration=float(duration),
                                 max_hits=int(max_hits)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_WATCH_FAILED"})


@server.tool()
@logged()
def perf_watch_daemon(serial: str, pid: int, addr: str, slot: int = 0,
                      size: int = 8, watch_type: str = "w", tid: int = 0,
                      duration: float = 0) -> str:
    """起一个**常驻**硬件观察点：提前设好，等目标自己来写。

    ## 为什么需要它（这是本工具最重要的用途）

    实测反复踩到的坑：**「在 hook 里拿到地址，再回头设观察点」时，数据已经写完了**。
    一次 adb+su+helper 启动至少 109ms，而写操作发生在几十毫秒内，必然错过。

    `perf_watch` 是「设点 → 等 N 秒 → 返回」，窗口固定，错过就没了。
    `perf_watch_daemon` 是「设点 → 一直盯着 → 随时取」，**不丢事件**。

    **正确用法**：在 buffer 刚分配、还是空的时候就设好，
    然后不管多久之后被写都能抓到。实测验证：设点后 8 秒才写入，仍然捕获。

    ## 参数

        slot     0..3（硬件只有 4 个槽位）
        addr/size/watch_type/tid   同 perf_watch
        duration 0 = 无限期常驻；>0 表示这么多秒后自动退出

    ## 配套工具

        perf_watch_poll(serial, slot)    取命中（可反复调，看新增）
        perf_watch_list(serial)          列出所有常驻观察点
        perf_watch_stop(serial, slot)    停掉并清理

    ## 关于 tid（实测关键）

    观察点**按线程生效**，必须指向真正执行写的那个线程。
    不指定（tid=0）时本工具会**自动避开主线程**——因为
    frida 的 Interceptor 常占用主线程的 debug 寄存器，导致 NO_SLOT。
    """
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch_daemon")
    if err:
        return _j(err)
    try:
        got = mod.perf_watch_daemon(
            serial, int(pid), addr, slot=int(slot), size=int(size),
            watch_type=watch_type, tid=int(tid), duration=float(duration))
        # 记下这个槽位盯的是哪个进程：poll/stop 靠它判断目标是否在前台
        if isinstance(got, dict) and got.get("ok"):
            try:
                mod.remember_slot_pid(serial, int(slot), int(pid))
            except Exception:                             # noqa: BLE001
                pass
        return _j(got)
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_DAEMON_FAILED"})


@server.tool()
@logged()
def perf_watch_poll(serial: str, slot: int = 0, limit: int = 200) -> str:
    """取一个常驻观察点的当前结果（可反复调用，看新增命中）。

    返回：ok / active / total_hits / count / hits[] / distinct_pcs / verdict
    hits[]: {ip, pid, tid, ts_ms, age_ms, regs:{x0,x1,x2,lr}}
    """
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch_poll")
    if err:
        return _j(err)
    try:
        return _j(mod.perf_watch_poll(serial, slot=int(slot), limit=int(limit)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_POLL_FAILED"})


@server.tool()
@logged()
def perf_watch_stop(serial: str, slot: int = 0) -> str:
    """停掉一个常驻观察点并清理设备上的状态文件。"""
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch_stop")
    if err:
        return _j(err)
    try:
        return _j(mod.perf_watch_stop(serial, slot=int(slot)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_STOP_FAILED"})


@server.tool()
@logged()
def perf_watch_list(serial: str) -> str:
    """列出所有常驻硬件观察点及其状态（含各自已采集的命中数）。"""
    mod, err = _load_dyn_module("server.dyn.perfwatch", "perf_watch_list")
    if err:
        return _j(err)
    try:
        return _j(mod.perf_watch_list(serial))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PERF_LIST_FAILED"})


# ---------------- VM 层分析 ----------------
#
# 动态加载 VM 的分析难点：所有 handler 各自内联了同一段派发尾，
# 而且 VM 代码区是 malloc 出来的，与 so 模块不在一处。
# 这组工具用「派发点」作为统一落点，绕开每个 op handler 的寄存器约定差异。


@server.tool()
@logged()
def find_vm_dispatch_points(so_name: str, pattern_hex: str = "750700f9",
                            limit: int = 2000) -> str:
    """扫描 so 里所有 **VM 派发点**的位置。

    ## 什么是派发点

    VM 解释器里，每条字节码执行完后都会走同一段「保存 VM pc → 跳到下一个 handler」：

        ldr  x2,  [x23, x5, lsl #3]   ; 查 handler 表
        str  x21, [x27, #8]           ; 保存 VM pc   ← 特征在这里
        br   x2                       ; 派发

    在这段上拦一次，就能在**每条 VM 指令执行前**拿到完整 VM 状态，
    不需要理解任何单个 op 的寄存器约定（那是逐个校准的地狱）。

    ## 特征选择（实测教训）

    默认特征 `750700f9` = `str x21, [x27, #8]`。

    **不要用 `br x2`（40001fd6）当特征**：实测派发寄存器完全不固定
    （x7/x17/x3/x15/x6/x4/x13/x19/x20/x11 都在用），用 br x2 只能扫到
    42/805 处。而 str x21,[x27,#8] 是 805/805 = 100% 命中。

    ## 返回

        count     找到多少个派发点
        points[]  {offset, offset_hex}
    """
    mod, err = _load_dyn_module("server.dyn.vmbreak", "find_dispatch_points")
    if err:
        return _j(err)
    try:
        so = _pick_so_by_name(_session, so_name)
        return _j(mod.find_dispatch_points(so_name, so=so,
                                           pattern_hex=pattern_hex,
                                           limit=int(limit)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "VM_SCAN_FAILED"})


@server.tool()
@logged()
def vm_regs_snapshot(serial: str, pid: int, so_name: str,
                     dispatch_offset: str = "0x76024",
                     pattern_hex: str = "750700f9",
                     capture_regs: int = 32, wait: float = 5.0,
                     reg_base_reg: str = "x25", reg_base_offset: int = 0,
                     ctx_reg: str = "x27", ctx_expr: str = "",
                     ip_mode: str = "ctx", ip_reg: str = "x21",
                     ip_offset: int = 8, opcode_expr: str = "",
                     vm_reg_count: int = 32) -> str:
    """在 VM 派发点抓一次快照：当前 VM pc、VM 寄存器堆、VM 栈。

    **用途**：还不知道要断哪条指令时，先用它看 VM 现在跑到哪些 idx。
    它也是**验证结构配置对不对**的最快手段——改参数后先跑它。

    ## (5) 第五次修改（2026-11-16）：结构布局参数化

    原实现的寄存器约定全写死在函数体里，换 VM 时用户**无从告知**工具。
    现在四个取值点都可以指定（不传即等于原行为）：

        ctx_reg / ctx_expr               ctx 来源
        ip_mode / ip_reg / ip_offset     VM pc 来源（ctx / reg / none）
        reg_base_offset / reg_base_reg   寄存器堆来源（偏移>0 时优先）
        opcode_expr                      opcode 来源（"sp+8" / "x8"）

    例：实测 metasec_ml.so 的形态

        vm_regs_snapshot(..., dispatch_offset="0x261820",
                         ctx_reg="x20", opcode_expr="sp+8",
                         reg_base_offset=0x6070)

    ## 返回

        vm_pc        当前 VM 指令指针（下一条要执行的）
        ip_source    它是怎么取到的（ctx+0x8 / reg:x21 / none）
        ctx          VM 上下文指针
        ctx_source   ctx 的来源
        reg_base     VM 寄存器堆基址
        reg_base_source  寄存器堆来源（ctx+0x6070 / reg:x25）
        regs         {r0..r31}  ← **这就是 VM 寄存器堆**
        opcode       按 opcode_expr 取到的值（没配就是 null）
        stack_hex    native 栈快照

    ## 注意

    单次快照只能看到「此刻」。VM 在多个 prog 之间来回跳，
    要多采几次才能看到全貌。
    """
    mod, err = _load_dyn_module("server.dyn.vmbreak", "vm_regs_snapshot")
    if err:
        return _j(err)
    try:
        return _j(mod.vm_regs_snapshot(
            serial, int(pid), so_name, dispatch_offset=dispatch_offset,
            pattern_hex=pattern_hex,
            capture_regs=int(capture_regs), wait=float(wait),
            reg_base_reg=(reg_base_reg or ""),
            reg_base_offset=int(reg_base_offset),
            ctx_reg=(ctx_reg or ""), ctx_expr=ctx_expr,
            ip_mode=ip_mode, ip_reg=(ip_reg or ""),
            ip_offset=int(ip_offset), opcode_expr=opcode_expr,
            vm_reg_count=int(vm_reg_count)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "VM_SNAPSHOT_FAILED"})


@server.tool()
@logged()
def vm_breakpoint(serial: str, pid: int, so_name: str, target_idx: int = -1,
                  code_base: str = "", dispatch_offset: str = "0x76024",
                  pattern_hex: str = "750700f9",
                  slot_size: int = 16, vm_pc_bytes: int = 64,
                  max_hits: int = 1, wait: float = 10.0,
                  capture_regs: int = 32, stack_bytes: int = 256,
                  hold: bool = True,
                  reg_base_reg: str = "x25", reg_base_offset: int = 0,
                  ctx_reg: str = "x27", ctx_expr: str = "",
                  ip_mode: str = "ctx", ip_reg: str = "x21",
                  ip_offset: int = 8, opcode_expr: str = "",
                  vm_reg_count: int = 32,
                  prog_base_p1_offset: int = 0x240,
                  prog_base_p2_offset: int = 0x1A0) -> str:
    """在**某条 VM 指令**上设断点，停下时给出 VM 寄存器堆与 VM 栈。

    这是「按 VM 层思考」的核心工具：不用管单个 op 的寄存器约定，
    直接说「我要停在第 N 条 VM 指令」。

    ## idx 是怎么算出来的（关键，已修正）

        data_base = *(*(ctx + 0x240) + 0x1a0)   ← 这是**数据区**基址
        vm_pc     = *(ctx + 8)                  ← 下一条要执行的指令
        vm_idx    = (vm_pc - code_base) / 16    ← 必须你显式给 code_base

    **data_base 不是 code_base。** 它的推导链末端是 `add host_var, base, imm`
    ——加完得到 host 变量地址，说明它指向数据区。拿它减 vm_pc 算出来的数
    只是碰巧落在某个范围，**不代表指令序号**（真机实测：按它算出的 idx
    去查镜像，得到 op=4 A=28，不是合法指令边界）。

    所以要按 idx 过滤，必须传 `code_base`（VM 字节码数组起点）。

    ## 不知道 code_base 怎么办

    不传即可：此时 `vm_idx` 返回 **null**（工具不会编一个看起来合理的数），
    同时返回 `vm_pc_bytes` —— vm_pc 处原始字节码。你拿它去比对镜像：

        ① 在镜像里搜这段字节，命中位置就是该指令的偏移
        ② code_base = vm_pc - 命中偏移
        ③ 下次调用把 code_base 传进来，就能按 idx 精确过滤

    ## 参数

        target_idx      目标 VM 指令序号；**-1 = 不过滤，采所有遇到的**
                        （给了 target_idx 却没给 code_base 时无法过滤，
                         工具会明确返回 0 命中而不是假装过滤）
        code_base       字节码区基址，"0x..." 或十进制。**给了才算 vm_idx**
        dispatch_offset 挂哪个派发点（默认 0x76024，op491 handler 尾部）
        slot_size       每条 VM 指令字节数
        vm_pc_bytes     在 vm_pc 处回读多少字节原始字节码（默认 64）
        max_hits        最多命中几次
        wait            等多久（秒）
        capture_regs    抓多少个 VM 寄存器
        stack_bytes     抓多少字节栈

    ## (5) 第五次修改（2026-11-16）：结构布局全部参数化

    下面这些参数是**每个 VM 都可能不同**的，默认值只是一类壳的实测值。
    换目标时必须按实测填，否则会表现成"命中了但取不到值"：

        ctx_reg         ctx 在哪个寄存器（默认 x27）
        ctx_expr        更精确写法："x20" / "sp+0x10" / "x20+0x8"（覆盖 ctx_reg）
        ip_mode         VM pc 取法：ctx（读 [ctx+ip_offset]）/ reg / none
        ip_reg          ip_mode=reg 时用哪个寄存器
        ip_offset       ip_mode=ctx 时 vm_pc 在 ctx 里的偏移（默认 8）
        reg_base_offset 寄存器堆相对 **ctx** 的偏移（如 0x6070）。
                        **非 0 时优先**于 reg_base_reg（结构体内嵌场景）
        reg_base_reg    否则从该寄存器取寄存器堆（默认 x25）
        opcode_expr     opcode 取法："sp+8"（栈）/ "x8"（寄存器）/
                        "ctx+0x100"（结构体字段）；默认空 = 不取

    ## 返回

        hits[]  {vm_idx, vm_idx_source, vm_pc, ip_source, opcode,
                 opcode_source, vm_pc_bytes, data_base, regs{r0..r31},
                 ctx, ctx_source, reg_base, reg_base_source, stack_hex}
        verdict

        vm_idx_source: "code_base"（可信）/ "unavailable"（没给 code_base）

    ## 0 命中怎么办

    派发点有几百个，**只挂一个点就只能看到经过它的指令**。
    先用 `vm_regs_snapshot` 看当前 VM 跑到哪，再挑合适的点。

    若报「会话已失效」，说明进程还在但 frida 会话是旧的（旧进程残留）：
    确认目标进程是新起的，再重试。

    ## 实测（真机）

        vm_breakpoint(target_idx=-1)
        → 命中 7 次，每次给 vm_pc + 32 个 VM 寄存器 + 128 字节栈
    """
    mod, err = _load_dyn_module("server.dyn.vmbreak", "vm_breakpoint")
    if err:
        return _j(err)
    try:
        return _j(mod.vm_breakpoint(
            serial, int(pid), so_name, target_idx=int(target_idx),
            code_base=(code_base or None),
            vm_pc_bytes=int(vm_pc_bytes),
            dispatch_offset=dispatch_offset, slot_size=int(slot_size),
            max_hits=int(max_hits), wait=float(wait),
            pattern_hex=pattern_hex, hold=bool(hold),
            capture_regs=int(capture_regs), stack_bytes=int(stack_bytes),
            # (5) 第五次修改（2026-11-16）：结构布局参数下传。
            # bug 原因：dyn 层这些参数已参数化，MCP 层不暴露的话调用方
            #           **根本传不进来**（schema 里不存在），dyn 单测再绿也没用。
            # 解决方案：全部透传，默认值取 dyn 层 VM_DEFAULTS 的同一组，
            #           保证不传时行为与之前完全一致。
            reg_base_reg=(reg_base_reg or ""),
            reg_base_offset=int(reg_base_offset),
            ctx_reg=(ctx_reg or ""),
            ctx_expr=ctx_expr,
            ip_mode=ip_mode,
            ip_reg=(ip_reg or ""),
            ip_offset=int(ip_offset),
            opcode_expr=opcode_expr,
            vm_reg_count=int(vm_reg_count),
            prog_base_p1_offset=int(prog_base_p1_offset),
            prog_base_p2_offset=int(prog_base_p2_offset)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "VM_BREAK_FAILED"})


@server.tool()
@logged()
def vm_trace(serial: str, pid: int, so_name: str,
             dispatch_offset: str = "", ctx_reg: str = "x0",
             opcode_expr: str = "", reg_base_offset: int = 0,
             count_offset: int = 0x194, array_offset: int = 0x1A0,
             count_size: int = 8,
             max_ops: int = 1000, duration: float = 10.0,
             ip_mode: str = "ctx", ip_offset: int = 8, ip_reg: str = "",
             reg_base_reg: str = "", ctx_expr: str = "",
             slot_size: int = 16, code_base: str = "",
             prog_base_p1_offset: int = 0x240,
             prog_base_p2_offset: int = 0x1A0,
             max_rows: int = 0, idx_from: int = 0, idx_to: int = 0,
             record_regs: bool = False, reg_count: int = 8,
             with_bytes: bool = False, bytes_len: int = 16,
             pattern_hex: str = "") -> str:
    """采集 **VM 执行轨迹**：连续记录跑过的每条 VM 指令（opcode / pc / 寄存器）。

    **所有结构偏移都是参数，没有任何写死的假设。** 这是它与
    `vm_breakpoint` / `dump_vm_state` 的根本区别：后两者就算参数齐了，
    也仍然假设「计数 + 指令数组」那种结构；本工具改成**按表达式取值**，
    结构再怎么变都能描述。

    ## 参数（只填你实测到的那几个）

    派发点（必须给一个来源）：
        dispatch_offset   派发点静态偏移，"0x261820" 或十进制
        pattern_hex       或者给派发段特征字节，让工具自动扫第一个匹配

    上下文 / VM pc：
        ctx_reg           ctx 在哪个寄存器（**默认 x0 只是占位**，
                          实测目标常见 x20 / x27，务必按实际填）
        ctx_expr          更精确写法："x20" / "sp+0x10" / "x20+0x8"
        ip_mode           VM pc 取法：ctx（读 [ctx+ip_offset]）/ reg / none
        ip_reg            ip_mode=reg 时的寄存器
        ip_offset         ip_mode=ctx 时 vm_pc 在 ctx 里的偏移

    opcode（**支持两种形态**）：
        opcode_expr       "sp+8"        从栈读（opcode 在栈上的 VM）
                          "x8"          从寄存器读
                          "ctx+0x100"   从结构体字段读
                          空 = 不取（返回 null，**不编造**）

    VM 寄存器堆：
        reg_base_offset   相对 **ctx** 的偏移（如 0x6070）。非 0 时优先
        reg_base_reg      否则从该寄存器取

    容量 / 过滤：
        max_ops           最多记多少条（**默认 1000，到顶立即 detach**，
                          不 hold、不阻塞目标）
        max_rows          旧参数名，>0 时等价于 max_ops（向后兼容）
        duration          采集多少秒
        idx_from/idx_to   只看该 idx 段（要算 idx 需给 code_base）
        code_base         字节码区基址，"0x..." 或十进制
        prog_base_p1_offset / prog_base_p2_offset
                          idx 的**另一种**算法：不靠 code_base，而是两跳解引用
                          *(*(ctx+p1)+p2) 得到基址。默认 0x240/0x1A0 是**某一
                          类壳的实测值**，换 VM 必须改；传 -1 关掉这条路径
        record_regs       **默认关**。打开会每步读 N 个指针，是主要开销。
        reg_count         record_regs=True 时记几个寄存器
        with_bytes        回读 pc 处原始字节（反推 code_base 用）
        bytes_len         回读多少字节（默认 16）
        count_size        计数字段宽度（兼容旧接口，原样回显）

    count_offset / array_offset 是**兼容旧接口**保留的形参：本工具按
    opcode_expr 取 opcode，不再依赖「计数 + 指令数组」那种结构，这两个值
    会原样回显在返回里，方便从 dump_vm_state 迁移的调用方对照。

    ## 返回

        ops[]        每条 {seq, ts, tid, opcode, opcode_source, pc,
                          ip_source, idx, idx_source, ctx, regs?, pc_bytes?}
        count        实际采到多少条
        truncated    是否因 max_ops 截断
        stop_reason  max_ops / duration / requested
        distinct_idx / idx_distribution
        ctx_fail / ip_fail
                     **非 0 说明结构配置不符，不是 VM 没跑**（见下）

    ## 关键：0 条结果要分清两种原因

    如果派发点根本没执行 → 换个 dispatch_offset。
    如果执行了但取不到 ctx / VM pc → `ctx_fail`/`ip_fail` 会非 0，
    返回的 verdict 会直接指明「这是结构配置不符」并告诉你改哪个参数。
    这两种情况在旧工具里是同一个"0 命中"，本工具把它们分开了。

    ## 典型用法（实测 metasec_ml.so 的形态）

        vm_trace(serial, pid, "libmetasec_ml.so",
                 dispatch_offset="0x261820", ctx_reg="x20",
                 opcode_expr="sp+8", reg_base_offset=0x6070,
                 max_ops=200, duration=5)

        → ops[] 里每条带 opcode 与 pc；opcode_source="sp+8" 证明取对了位置

    ## 已知边界

        · 只挂**一个**派发点，只能看到经过它的指令
        · 采完才返回，不能边跑边看（边看会把目标拖死，实测过）
        · 不知道寄存器堆在哪时先别开 record_regs：opcode + pc 通常就够用了
    """
    mod, err = _load_dyn_module("server.dyn.vmtrace", "vm_trace")
    if err:
        return _j(err)
    try:
        return _j(mod.vm_trace(
            serial, int(pid), so_name,
            dispatch_offset=dispatch_offset,
            ctx_reg=(ctx_reg or ""),
            opcode_expr=opcode_expr,
            reg_base_offset=int(reg_base_offset),
            count_offset=int(count_offset),
            array_offset=int(array_offset),
            count_size=int(count_size),
            max_ops=int(max_ops),
            duration=float(duration),
            max_rows=int(max_rows),
            ip_mode=ip_mode,
            ip_offset=int(ip_offset),
            ip_reg=(ip_reg or ""),
            reg_base_reg=(reg_base_reg or ""),
            ctx_expr=ctx_expr,
            slot_size=int(slot_size),
            code_base=(code_base or None),
            prog_base_p1_offset=int(prog_base_p1_offset),
            prog_base_p2_offset=int(prog_base_p2_offset),
            idx_from=int(idx_from),
            idx_to=int(idx_to),
            record_regs=bool(record_regs),
            reg_count=int(reg_count),
            with_bytes=bool(with_bytes),
            bytes_len=int(bytes_len),
            pattern_hex=pattern_hex))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "VM_TRACE_FAILED"})
# ---------------- 内存快照 diff ----------------
#
# 为什么必须用设备端 helper（实测数据）：
#   adb shell + dd 读 /proc/<pid>/mem：4MB 耗时 37,000 ms
#   设备端 native pread 直接读：       4MB 耗时 6.4 ms
#   **差 5786 倍**。快照动辄几十 MB，走 shell 完全不可行。


@server.tool()
@logged()
def mem_snapshot(serial: str, pid: int, max_mb: int = 64,
                 key: str = "default") -> str:
    """在设备上拍一份**内存快照**（只取可写匿名段），供后续 diff。

    ## 用途

    「某个东西从无到有」这类问题，正向追很难（不知道起点），
    但两次快照一 diff，新增的块就直接浮出来了。

        mem_snapshot(key="r98")        # t1
        # ... 触发目标功能 ...
        mem_diff(key="r98", min_size=90, max_size=110)
        → 直接列出新增的 90~110 字节块

    ## 参数

        max_mb  最多读多少 MB（默认 64）
        key     快照名，diff 时用同一个

    ## 返回

        segments / bytes / file

    ## 段选择策略（实测教训）

    **小段优先**。大段优先时，1GB 的 dalvik region space 一次就吃光预算，
    而真正会出现「新增 98 字节块」的是几 MB 的小段——
    结果 diff 永远返回 0，看起来像「没有变化」，实际是「根本没读到」。
    小段优先后同样预算能覆盖 3000+ 段而不是 2 段。

    ## 注意

    快照**留在设备上**（`/data/local/tmp/mda_snap_<key>.bin`），不传回本机。
    diff 也在设备上算，只把变化的块传回来。

    ## 风控提醒

    读 `/proc/<pid>/mem` 是加固 App 典型的风控检测点（内存 dump 行为）。
    对阿里系等加固目标，**建议单次不要超过 16MB，且不要连续多轮**。
    """
    mod, err = _load_dyn_module("server.dyn.memdiff", "mem_snapshot")
    if err:
        return _j(err)
    try:
        return _j(mod.mem_snapshot(serial, int(pid), max_mb=int(max_mb),
                                   key=key))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "MEM_SNAPSHOT_FAILED"})


@server.tool()
@logged()
def mem_diff(serial: str, pid: int, key: str = "default", min_size: int = 1,
             max_size: int = 0, max_report: int = 100) -> str:
    """再拍一份快照并对比，找出**新增/变化的块**。

    ## 参数

        min_size   只看至少这么大的块
        max_size   只看至多这么大的（**0 = 不限**）——
                   **找「新的 98 字节块」时设 90~110 最有效**
        max_report 最多报多少块

    ## 返回

        changed[]  {addr, size, sample_hex}
        count / total_bytes

    ## 实测性能（systemui，870 段 / 16MB）

        snap : 0.3 秒
        diff : 0.04 秒

    ## 拿到地址之后

    用 `perf_watch_daemon` 观察「谁写了它」。
    """
    mod, err = _load_dyn_module("server.dyn.memdiff", "mem_diff")
    if err:
        return _j(err)
    try:
        return _j(mod.mem_diff(serial, int(pid), key=key,
                               min_size=int(min_size),
                               max_size=int(max_size),
                               max_report=int(max_report)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "MEM_DIFF_FAILED"})


@server.tool()
@logged()
def mem_snapshot_clear(serial: str, key: str = "default",
                       pid: int = 0) -> str:
    """删掉设备上的快照文件，释放空间。"""
    mod, err = _load_dyn_module("server.dyn.memdiff", "mem_snapshot_clear")
    if err:
        return _j(err)
    try:
        return _j(mod.mem_snapshot_clear(serial, key=key))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "MEM_CLEAR_FAILED"})


# ---------------- 模块卸载 / 内存释放 ----------------
#
# 为什么需要：实测 2.9MB 的 so 加载后占 14.7MB（约 5 倍），每函数约 5KB。
# 加载 6 个模块、18.6 万函数时占用接近 1GB。


@server.tool()
@logged()
def unload_so(so_name: str) -> str:
    """卸载一个模块，**释放 mda 进程内的静态分析结果**。

    ## 释放的是什么

    只清 mda 里的解析结果（函数表、反汇编缓存、引用图），
    **不影响设备上正在运行的进程**，也不会让 App 崩溃。

    ## 为什么卸载了 RSS 不一定立刻降

    Python 的内存分配器倾向于把释放的块留在自己的池子里复用，
    不马上归还操作系统。所以看到 RSS 没降**不代表没释放**。

    验证方式：卸载后再加载同样的模块，占用会明显小于第一次
    （实测：首次 24MB，第二次只涨 13MB）。

    返回：{ok, so, freed_estimate_mb, remaining}
    """
    from server.mcp_server.tools import get_session

    try:
        return _j(get_session().unload(so_name))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "UNLOAD_FAILED"})


@server.tool()
@logged()
def clear_modules(keep: list | None = None) -> str:
    """批量卸载模块，可指定保留哪些。

    ## 用法

        clear_modules()                          # 全清
        clear_modules(keep=["libil2cpp.so"])     # 只留这个

    返回：{ok, freed[], freed_count, est_total_mb, remaining}
    """
    from server.mcp_server.tools import get_session

    try:
        return _j(get_session().clear(keep=keep))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "CLEAR_FAILED"})


@server.tool()
@logged()
def module_memory() -> str:
    """查看各模块占用的内存（估算），用来决定该清哪个。

    返回：{count, modules[{so, functions, exports, est_mb}], est_total_mb}

    ## 估算依据

    实测：2.9MB 的 so（3012 个函数）加载后占 14.7MB，即**每函数约 5KB**。
    按这个比例估算，足够用来做清理决策。
    """
    from server.mcp_server.tools import get_session

    try:
        return _j(get_session().memory_usage())
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "MEMORY_QUERY_FAILED"})


# ---------------- App 行为监控 ----------------
#
# 实现方式：frida 注入（运行时 attach），**不需要 Xposed**。
# 原理：hook Java 标准 API 入口，算法名是 App 自己通过
#       getInstance("MD5") 告诉我们的，不是特征识别。


@server.tool()
@logged()
def behavior_monitor_start(serial: str, pid: int, crypto: bool = True,
                           file: bool = True, activity: bool = True,
                           assets: bool = True, shell: bool = False,
                           duration: float = 0, max_events: int = 3000) -> str:
    """启动 **App 行为监控**：算法 / 文件 / Activity / assets / Shell。

    ## 它怎么实现的（不是识别算法）

    hook Java 标准 API 的入口。App 调 `MessageDigest.getInstance("MD5")` 时
    **自己把算法名告诉了我们**，不需要任何特征匹配。
    再 hook `digest()` / `doFinal()` 拿输入输出，就得到完整的
    「算法 + 明文 + 密文 + 调用栈」。

    ## 参数（每类独立开关，按需最小化）

        crypto   哈希/加解密/密钥哈希（MessageDigest / Cipher / Mac）
        file     文件读写（FileInputStream / FileOutputStream）
        activity Activity 生命周期
        assets   assets 资源加载
        shell    **执行 shell 命令**，默认关（反调试最敏感的点之一）
        duration 采集秒数（**0 = 常驻**，之后用 poll / stop）

    ## 返回

        installed[]        实际挂上的 hook
        events[]           事件列表（cat / kind / 各类字段 / stack）
        counts{}           各类事件计数
        algorithms_seen[]  用到的算法名（去重）
        verdict            一句话结论

    ## 实测样例

        behavior_monitor_start(pid=..., duration=8)
        → installed: [MessageDigest, Cipher, Mac, FileInputStream, ...]
          algorithms_seen: ["MD5"]
          [crypto] digest_algo: MD5
            调用栈: com.miui.systemui.util.Md5.getMd5Digest(Md5.java:11)

    ## 覆盖边界（重要）

        ✅ 用标准 API 的 App（绝大多数）
        ❌ 自研 VM / 自己实现的算法 —— 不调 MessageDigest，hook 抓不到

    ## 风控提醒

    每多开一类监控，被检测概率就上升。实测教训（2026-11-09）：
    批量 hook 是最强信号，一次挂 317 个方法后阿里系 App 直接拒绝访问。
    **建议按需最小化开启。**
    """
    mod, err = _load_dyn_module("server.dyn.behavior", "behavior_monitor_start")
    if err:
        return _j(err)
    try:
        return _j(mod.behavior_monitor_start(
            serial, int(pid), crypto=bool(crypto), file=bool(file),
            activity=bool(activity), assets=bool(assets), shell=bool(shell),
            duration=float(duration), max_events=int(max_events)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "BEHAVIOR_START_FAILED"})


@server.tool()
@logged()
def behavior_monitor_poll(serial: str = "", pid: int = 0) -> str:
    """取常驻行为监控的当前结果（可反复调用，看新增事件）。"""
    mod, err = _load_dyn_module("server.dyn.behavior", "behavior_monitor_poll")
    if err:
        return _j(err)
    try:
        return _j(mod.behavior_monitor_poll(serial, int(pid or 0)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "BEHAVIOR_POLL_FAILED"})


@server.tool()
@logged()
def behavior_monitor_stop(serial: str = "", pid: int = 0) -> str:
    """停掉常驻行为监控，返回最终汇总结果。"""
    mod, err = _load_dyn_module("server.dyn.behavior", "behavior_monitor_stop")
    if err:
        return _j(err)
    try:
        return _j(mod.behavior_monitor_stop(serial, int(pid or 0)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "BEHAVIOR_STOP_FAILED"})


# ---------------- App 进程全貌 ----------------
#
# 为什么不注入也能查：全部走 adb + /proc，目标完全无感知。
# 这解决了「抓包抓不到」最常见的误判——网络根本不在主进程里。


@server.tool()
@logged()
def list_app_processes(serial: str, package: str,
                       detect_network: bool = True) -> str:
    """列出一个 App 包名下的**所有进程**，并判断哪个在跑网络。

    ## 为什么需要它

    抓包抓不到，很多时候不是工具不行，而是**网络根本不在你以为的那个进程里**。

    实测 com.taobao.idlefish：

        pid=31182  主进程                31 个 socket
        pid=970    :normal_render_proc0  13 个 socket
        pid=31204  :channel               6 个 socket
        pid=31975  :windowChannel         3 个 socket

    四个进程都在跑网络。只 hook 主进程必然漏掉其余三个的流量。

    ## 参数

        package         包名，如 "com.taobao.idlefish"
        detect_network  是否探测各进程网络活动

    ## 返回

        count / processes[] / main_pid / network_pids[] / verdict
        processes[]: {pid, ppid, name, suffix, role, sockets, loaded_so_count, is_main}

    ## 判定依据（通用，不依赖任何特定库名）

        sockets  = /proc/<pid>/fd 里 socket 型 fd 的数量
        role     = 按 Android 通用命名规律（:channel / :push / :remote…）推断

    **注意**：`/proc/<pid>/net/tcp` 是网络命名空间级的，
    对所有进程返回值相同，**不能**用来区分进程——所以不用它判定。

    ## 完全无感知

    纯读 /proc，不 attach、不注入，不会被风控感知。
    """
    mod, err = _load_dyn_module("server.dyn.appproc", "list_app_processes")
    if err:
        return _j(err)
    try:
        return _j(mod.list_app_processes(serial, package,
                                         detect_network=bool(detect_network)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "LIST_APP_PROCESSES_FAILED"})


@server.tool()
@logged()
def probe_network_processes(serial: str, package: str) -> str:
    """专门回答「**哪个进程在跑网络**」，给抓包/注入选目标用。

    比 `list_app_processes` 更聚焦：只列有网络活动的进程，并给出注入建议顺序。

    返回：{ok, candidates[], recommend[], total_processes, verdict}

    ## 典型用法

        抓包抓不到 → probe_network_processes("com.xxx")
        → 发现 :channel 也在跑网络 → 对那几个 pid 分别处理
    """
    mod, err = _load_dyn_module("server.dyn.appproc", "probe_network_processes")
    if err:
        return _j(err)
    try:
        return _j(mod.probe_network_processes(serial, package))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "PROBE_NET_FAILED"})


# ---------------------------------------------------------------- 设备 UI 操作
# 为什么加这一组：mda 原有能力都在 so 层面（反汇编、hook、内存）。
# 但很多问题必须先让设备走到某个界面才能复现（登录态、某设置项、滑到第几屏）。
# 没有 UI 操作，这些前置步骤只能靠人手点，AI 完全帮不上。
#
# 实现全部在 server/dyn/ui.py：纯 adb + uiautomator，不注入目标进程，
# 因此对加固 App 不构成 hook 类风控信号。这里只做「参数校验 + 错误转成
# 结构化 JSON」这一层薄封装，不在工具层重复实现逻辑。
#
# 设计：不硬编码任何 App 的包名/控件 id/文案，全部从参数来；
#       失败一律带 code 如实返回，不返回空结果冒充成功。


def _ui_call(fn, **kwargs):
    """统一把 ui 模块的异常转成结构化 JSON。

    为什么统一：ui.py 全部抛 DynError(code, message)，工具层每次
    写 try/except 会有十几份重复代码，且容易漏掉某个分支让异常裸抛出去
    （MCP 框架会吞成无信息量的 "Error executing tool X"）。
    """
    from server.dyn.adb import DynError

    try:
        return _j(fn(**kwargs))
    except DynError as exc:
        return _j({"error": str(exc), "code": getattr(exc, "code", "") or "UI_ERROR"})
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "UI_FAILED"})


@server.tool()
@logged()
def ui_dump(serial: str, simplify: bool = True, detail: bool = False) -> str:
    """读取 Android 当前界面的结构（uiautomator XML → 结构化 JSON）。

    这是 UI 操作的第一步：先看清屏幕上有什么，再决定点哪里。

        ui_dump(serial="xxx")                  只看有意义的节点（默认，紧凑）
        ui_dump(serial="xxx", detail=True)     每节点完整字段（含 bounds/enabled 等）
        ui_dump(serial="xxx", simplify=False)  完整树（节点多，慎用）

    默认**紧凑格式**：空字段不输出、布尔只输出 true、class 去掉包前缀。
    实测一个 97 节点的界面从 1.9 万字符压到约 2 千——不压缩的话 AI 读不完。

    每个节点带 text / resource_id / class / content_desc / bounds /
    center（点击用）/ clickable。**可点击节点常常是布局容器，文本在子节点里**，
    所以 simplify=true 时会保留有文本的容器并带上 label。

    纯 adb + uiautomator，**不注入目标进程**，对加固 App 无 hook 类风控信号。
    """
    from server.dyn.ui import ui_dump as _impl

    return _ui_call(_impl, serial=serial, simplify=simplify, detail=detail)


@server.tool()
@logged()
def ui_find(serial: str, text: str = "", resource_id: str = "",
            content_desc: str = "", cls: str = "",
            exact: bool = False, clickable_only: bool = False,
            limit: int = 20) -> str:
    """在当前界面按条件找控件，返回 bounds 与中心点坐标。

    多个条件是 **AND**；默认**子串**匹配（人通常只记得半截文案）。

        ui_find(serial="xxx", text="登录")
        ui_find(serial="xxx", clickable_only=True)     这屏能点哪些

    找不到时明确说明并给排查建议，不返回空数组了事
    （空数组会被读成"界面为空"或"成功但没匹配"，两种误读都会点错地方）。
    """
    from server.dyn.ui import ui_find as _impl

    return _ui_call(_impl, serial=serial, text=text, resource_id=resource_id,
                    content_desc=content_desc, cls=cls, exact=exact,
                    clickable_only=clickable_only, limit=limit)


@server.tool()
@logged()
def ui_click(serial: str, x: int | None = None, y: int | None = None,
             text: str = "", resource_id: str = "", content_desc: str = "",
             cls: str = "", exact: bool = False, index: int = 0,
             wait: float = 0.0) -> str:
    """点击界面。给坐标，或给查找条件（内部先找再点中心）。

        ui_click(serial="xxx", text="登录")
        ui_click(serial="xxx", x=540, y=1200)
        ui_click(serial="xxx", text="登录", wait=1.5)   点完等 1.5 秒

    坐标与查找条件**二选一**，同时给会报错。

    匹配到多个控件时：若它们在同一行（竖向区间重叠），自动挑可点击的那个
    直接点——这是 Android 列表的普遍结构（可点行容器 + 内层容器 + 文字），
    不把这种当成歧义。只有命中真的分散在不同行时才报 AMBIGUOUS 并列候选，
    此时用 index 指定要点第几个，或加更精确的条件。

    wait：点完后等待的秒数（默认 0，不等）。界面切换/网络请求需要时间，
    要立刻看到结果时可以给 1~2。
    """
    from server.dyn.ui import ui_click as _impl

    return _ui_call(_impl, serial=serial, x=x, y=y, text=text,
                    resource_id=resource_id, content_desc=content_desc,
                    cls=cls, exact=exact, index=index, wait=wait)


@server.tool()
@logged()
def ui_input(serial: str, content: str, text: str = "",
             resource_id: str = "", content_desc: str = "", cls: str = "",
             exact: bool = False, index: int = 0,
             clear_first: bool = True) -> str:
    """向输入框输入文本。

        ui_input(serial="xxx", content="hello", text="用户名")
        ui_input(serial="xxx", content="abc", cls="EditText")

    **只支持 ASCII**：实测 `input text '你好'` 在设备侧直接抛
    NullPointerException（KeyCharacterMap 返回 null），不是转义没做好；
    é / ü / 日本語 / emoji 同样不行。这里如实报
    UI_INPUT_UNSUPPORTED_CHARS 并列出具体字符，不静默丢字符、不假装成功。
    空格会自动转成 %s（实测不转的话只有第一个词被送出）。

    clear_first：先发 50 次 delete 清空再输入（默认开）。
    """
    from server.dyn.ui import ui_input as _impl

    return _ui_call(_impl, serial=serial, content=content, text=text,
                    resource_id=resource_id, content_desc=content_desc,
                    cls=cls, exact=exact, index=index,
                    clear_first=clear_first)


@server.tool()
@logged()
def ui_swipe(serial: str, direction: str = "",
             x1: int | None = None, y1: int | None = None,
             x2: int | None = None, y2: int | None = None,
             duration_ms: int = 300) -> str:
    """滑动。给方向（up/down/left/right）自动算距离，或给两点坐标。

        ui_swipe(serial="xxx", direction="up")     向上滑（看下面的内容）

    按方向滑时距离取屏幕 1/3：太小不触发翻页，太大容易误触。
    """
    from server.dyn.ui import ui_swipe as _impl

    return _ui_call(_impl, serial=serial, direction=direction,
                    x1=x1, y1=y1, x2=x2, y2=y2, duration_ms=duration_ms)


@server.tool()
@logged()
def ui_key(serial: str, key: str) -> str:
    """按一个系统键：back / home / enter / del / up / down / recent 等。

        ui_key(serial="xxx", key="back")

    也接受数字 keycode（如 4 = back）。
    """
    from server.dyn.ui import ui_key as _impl

    return _ui_call(_impl, serial=serial, key=key)



@server.tool()
@logged()
def uprobe_probe(serial: str) -> str:
    """体检 **uprobe 内存分配追踪**这条路径在本设备是否可用（只读探测）。

    检查项：tracefs 挂载点（`/sys/kernel/tracing` 与 `/sys/kernel/debug/tracing`
    两个都试）、`uprobe_events` 是否可写、当前已注册了哪些探针。

    探测用的临时探针会立刻删掉，**不在系统里留任何东西**。
    本工具不改目标进程、也不启用采样，随时可以安全调用。

    返回：{ok, tracefs, writable, existing_probes, tracing_on, note}
    """
    mod, err = _load_dyn_module("server.dyn.uprobe", "uprobe_probe")
    if err:
        return _j(err)
    try:
        return _j(mod.uprobe_probe(serial))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "UPROBE_PROBE_FAILED"})
