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

from version import __version__

from core.session import Session

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
        ev = {"type": "goto", "so_name": so, "addr": int(addr), "why": "disassemble"}
    elif tool == "decompile" and so and addr is not None:
        ev = {"type": "goto", "so_name": so, "addr": int(addr), "why": "decompile", "tab": "伪代码"}
    elif tool == "call_chain" and so and addr is not None:
        ev = {"type": "goto", "so_name": so, "addr": int(addr), "why": "call_chain", "tab": "伪代码"}
    elif tool == "list_functions" and so:
        ev = {"type": "filter_funcs", "so_name": so, "keyword": args.get("keyword", ""),
              "why": "list_functions"}
    elif tool == "list_strings" and so:
        ev = {"type": "show_strings", "so_name": so, "keyword": args.get("keyword", "")}
    elif tool == "xrefs_to" and so and addr is not None:
        ev = {"type": "show_xrefs", "so_name": so, "addr": int(addr)}
    elif tool == "imports" and so:
        ev = {"type": "show_tab", "tab": "导入"}
    elif tool == "exports" and so:
        ev = {"type": "show_tab", "tab": "导出"}
    elif tool == "rename_function" and so:
        ev = {"type": "renamed", "so_name": so, "addr": int(args.get("addr", 0)),
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
        from core.plugins import PluginManager

        _plugin_mgr = PluginManager(_session, log=lambda t: print(t, flush=True))
        _plugin_mgr.scan_and_load()
    return _plugin_mgr


import functools


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
            t0 = time.time()
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
            from mcp_server import link

            if link.should_forward():
                fw = link.forward(name, call_args)
                if fw is not None:
                    ms = (time.time() - t0) * 1000
                    parts = [
                        f"{k}={str(v)[:60]}"
                        for k, v in call_args.items()
                        if v not in (None, "")
                    ]
                    _activity(name, call_args, ", ".join(parts) or "-", ms)
                    return fw

            try:
                result = fn(*args, **kwargs)
                ms = (time.time() - t0) * 1000
                parts = [
                    f"{k}={str(v)[:60]}"
                    for k, v in call_args.items()
                    if v not in (None, "")
                ]
                _activity(name, call_args, ", ".join(parts) or "-", ms)
                return result
            except Exception as e:
                ms = (time.time() - t0) * 1000
                import traceback

                tb = traceback.format_exc()
                _activity(name, call_args, f"✗ {type(e).__name__}: {str(e)[:80]}", ms)
                # 透传真实异常给 AI（isError 标记 + 类型/消息/堆栈尾行）
                from mcp.types import CallToolResult, TextContent

                return CallToolResult(
                    content=[TextContent(
                        text=json.dumps({
                            "error": f"{type(e).__name__}: {e}",
                            "tool": name,
                            "traceback_tail": tb.strip().splitlines()[-3:],
                        }, ensure_ascii=False)
                    )],
                    is_error=True,  # mcp 2.x 字段名（isError 是 1.x 的）
                )
        return wrapper
    return deco


def _j(obj) -> str:
    """统一 JSON 输出，dataclass 自动转 dict。"""
    return json.dumps(obj, ensure_ascii=False, indent=2, default=lambda o: o.__dict__)


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


@server.tool()
@logged()
def load_so(path: str) -> str:
    """加载一个 so 文件到分析会话。path 为绝对路径。

    加载成功后广播 UI 同步事件：GUI 的模块树/函数表/Output
    立即显示新模块，与 AI 看到的一致。
    """
    so = _session.add(path)
    get_plugins().emit("after_load", {"so_name": so.name})
    _notify_ui({"type": "so_loaded", "so_name": so.name, "functions": len(so.functions), "path": path})
    out = {"loaded": so.name, "functions": len(so.functions)}
    if getattr(so, "renamed_from", None):
        out["renamed_from"] = so.renamed_from  # BUG-14：同名自动改名提示
    return _j(out)


@server.tool()
@logged()
def list_modules() -> str:
    """列出当前会话已加载的全部 so 及概况。"""
    return _j(_session.summary())


@server.tool()
@logged()
def list_functions(so_name: str, keyword: str = "", limit: int = 200) -> str:
    """列出某 so 的函数。keyword 过滤函数名（大小写不敏感）。"""
    so = _session.get(so_name)
    fns = so.functions.values()
    kw = keyword.lower()
    items = [
        {"addr": f.addr, "name": f.name or f"sub_{f.addr:x}", "size": f.size, "by": f.discovered_by}
        for f in fns
        if not kw or kw in (f.name or "").lower()
    ]
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
    out = {"count": len(items), "functions": items[:limit]}
    if hint:
        out["hint"] = hint
    return _j(out)


@server.tool()
@logged()
def disassemble(so_name: str, addr: int, size: int = 64) -> str:
    """反汇编指定地址。addr 为静态虚拟地址（十进制）。"""
    d = _session._xrefs[so_name].disasm
    insns = d.disasm_range(addr, size)
    return _j([
        {
            "addr": i.addr,
            "text": i.text,
            "call": i.call_target if i.is_call else None,
            "ref": i.ref_addr,
        }
        for i in insns
    ])


@server.tool()
@logged()
def decompile(so_name: str, addr: int) -> str:
    """输出函数的结构化伪代码（非真反编译，控制流归类）。addr 为函数入口。"""
    from core.pseudocode import PseudocodeGenerator

    so = _session.get(so_name)
    d = _session._xrefs[so_name].disasm
    gen = PseudocodeGenerator(so, d)
    return gen.generate(addr)


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
    hits = [
        {"addr": f.addr, "name": f.name or f"sub_{f.addr:x}", "size": f.size,
         "export": f.is_export}
        for f in sorted(so.functions.values(), key=lambda x: x.addr)
        if f.name and kw in f.name.lower()
    ]
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
    _session.comments[(so_name, addr)] = comment
    get_plugins().emit("after_comment", {"so_name": so_name, "addr": addr, "comment": comment})
    return _j({"commented": hex(addr), "comment": comment})


@server.tool()
@logged()
def get_comments(so_name: str) -> str:
    """列出该 so 的全部注释。"""
    items = [
        {"addr": hex(a), "comment": c}
        for (n, a), c in sorted(_session.comments.items(), key=lambda kv: kv[0][1])
        if n == so_name
    ]
    return _j(items)


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
        out.append({"site": site, "function": fn.name if fn and fn.name else f"sub_{fn.addr:x}" if fn else None})
    return _j({"string": ref.value, "refs": out})


@server.tool()
@logged()
def build_xrefs(so_name: str, aggressive: bool = False) -> str:
    """显式构建某 so 的全量引用图（首次调用较慢，之后有缓存）。

    构建前会先做**递归函数发现**：扫描 bl 目标，把 FDE（.eh_frame）
    漏掉、但带标准序言的函数入口补进函数表。加固样本实测可补 1814 个
    （6047 → 7861）；健康 NDK 库通常为 0（FDE 完整，无误报）。

    aggressive=True 时额外把「终止指令后紧跟序言」的地址也建成函数，
    能捞到跳转表分发的 handler（如 SIGN handler 0xB9DA4），
    但会把 switch 的 case 块一并切开（实测 libbase 386 → 557 全是误报），
    只在明确需要细粒度 handler 时开启。

    同时把数据引用归并到字符串的 referenced_by，
    使 string_refs 可用——string_refs 依赖此步骤。
    """
    x = _session.ensure_xrefs(so_name, aggressive=aggressive)
    so = _session.get(so_name)
    return _j({
        "functions": len(so.functions),
        "call_edges": sum(len(v) for v in x.calls_to.values()),
        "data_refs": len(x.data_refs),
    })


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
    from dyn.adb import Adb

    return _j([{"serial": d.serial, "state": d.state} for d in Adb.list_devices()])


@server.tool()
@logged()
def list_processes(serial: str, keyword: str = "") -> str:
    """列出设备进程。keyword 过滤进程名。"""
    from dyn.adb import Adb

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
    from dyn.adb import Adb

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
    from dyn.frida_server import ensure_server

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
    from dyn.adb import Adb

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
    from dyn.adb import Adb

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
    from dyn.service import get_dyn

    try:
        return _j(get_dyn().remove_breakpoint(str(bp_id)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": getattr(exc, "code", "REMOVE_FAILED")})


@server.tool()
@logged()
def hits(serial: str, pid: int, bp_id: str = "", limit: int = 0,
         since_seq: int = 0, include_context: bool = True,
         include_backtrace: bool = True, include_stack: bool = True) -> str:
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
    from dyn.service import get_dyn

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

    # 汇总所有命中的调用栈，找出没符号化的模块
    all_frames: list = []
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
    from dyn.service import get_dyn

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
    from dyn.adb import Adb

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
    from dyn.adb import Adb

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
    from dyn.service import get_dyn

    return _j(get_dyn().modules(serial, pid, keyword))


@server.tool()
@logged()
def set_breakpoint(serial: str, pid: int, so_name: str, static_addr: int, hold: bool = False) -> str:
    """在目标进程的某 so 静态地址上下断点。

    hold=False 命中即继续（只记录）；hold=True 挂起等待，
    调用 wait_hits 拿到命中后分析，再调 resume 放行。
    """
    # (1) 第一次修改
    # bug 原因：原实现既不保存 dbg 也不 detach，函数一返回脚本就被回收，
    #           实测连续调用 attach=3 / detach=0，既泄漏又查不到断点。
    # (2) 第二次修改：改走 DynSession 注册表，断点由单例持有 → 真正持久。
    #     契约：保留 set 字段，新增 id/runtime_addr/persistent 等。
    from dyn.service import get_dyn

    bp = get_dyn().set_breakpoint(serial, pid, so_name, static_addr, hold=hold)
    return _j({"set": True, "persistent": True, **bp})


@server.tool()
@logged()
def read_process_memory(serial: str, pid: int, so_name: str, static_addr: int, size: int = 32) -> str:
    """按 so 静态地址读取目标进程内存（自动完成 ASLR 换算）。"""
    # (1) 第一次修改：size 越界与空结果都显式报错，不伪装成功（细节见 dyn/service.py）。
    # (2) 第二次修改：改走 DynSession 注册表，复用已附加的会话。
    from dyn.service import get_dyn

    try:
        data = get_dyn().read_memory(serial, pid, so_name, static_addr, size)
    except Exception as exc:                      # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}"})
    return _j({
        "static_addr": hex(data["static_addr"]),
        "runtime_addr": hex(data["runtime_addr"]),
        "hex": data["hex"],
        "size": data["size"],
    })


@server.tool()
@logged()
def wait_hits(serial: str, pid: int, timeout: float = 10.0) -> str:
    """等待断点命中（阻塞到超时或出现新命中）。

    必须先用 set_breakpoint 下断；hold=True 的断点会挂住目标线程，
    拿到命中后用 resume 放行。
    """
    from dyn.service import get_dyn

    return _j({"hits": get_dyn().wait_hits(serial, pid, timeout=timeout)})


@server.tool()
@logged()
def resume(serial: str, pid: int) -> str:
    """放行 hold 策略下挂起的线程（重复调用无副作用）。"""
    from dyn.service import get_dyn

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
    try {
        addrs = Thread.backtrace(t.context, Backtracer.ACCURATE)
            .map(function (a) { return a.toString(); });
    } catch (e) {
        send({err: "取调用栈失败: " + String(e)});
        return;
    }
    send({tid: t.id, frames: addrs.slice(0, limit)});
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
    from core.addr import parse_addr

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


def _strip_version_tag(name: str) -> str:
    """去掉文件名里的版本号尾巴，返回"核心名"。

    (12) 第十二次修改（2026-11-06）：新增。
        bug 原因：加固样本的设备模块名普遍带版本号
                  （libsgmainso-6.7.260202.so、libxxx-1.2.3.so），
                  而分析时本地文件常被改成短名（libsgmainso.so）。
                  原名匹配全失败，导致断点报 MODULE_NOT_LOADED、
                  调用栈符号化退化成 "so+偏移"。
        解决方案：抽出核心名再比对。只剥离**形如 -x.y.z / -123456 的尾巴**，
                  不碰正常名字，避免误伤。

    剥离规则（宁可少剥，不可错剥）：
        libsgmainso-6.7.260202.so   -> libsgmainso.so
        libsgmainso.so              -> libsgmainso.so（不变）
        libc++_shared.so            -> libc++_shared.so（++ 和 _ 不动）
        libutils-1.so / libutils-2.so -> 都变成 libutils.so（见下方说明）
        my-lib.so                   -> my-lib.so（纯字母段不剥）

    注意：libutils-1 / libutils-2 剥完同名，这**不是**缺陷——它们本来就是
    同一个库的不同版本；真要区分由调用方用完整名指定，本函数只在
    "精确匹配失败"时才作为**末级兜底**，且要求候选唯一。
    """
    import re as _re

    base = str(name or "").rsplit("/", 1)[-1]
    if not base:
        return ""
    # 已带 .so / .dylib 后缀的：在扩展名前剥版本
    m = _re.match(r"^(?P<core>.+?)(?P<ver>-\d+(?:\.\d+)*)(?P<ext>\.so(?:\..+)?|\.dylib)?$",
                  base)
    if m:
        ext = m.group("ext") or ""
        return m.group("core") + ext
    return base


def _pick_so_by_name(session, raw_name: str):
    """按多级候选在会话里找 SoFile，找不到返回 None。

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
    """
    mods = getattr(session, "modules", {}) or {}
    if not mods or not raw_name:
        return None
    name = str(raw_name)
    # 1) 全名精确
    so = mods.get(name)
    if so is not None:
        return so
    # 2) basename（真机常带路径）
    base = name.rsplit("/", 1)[-1]
    if base and base != name:
        so = mods.get(base)
        if so is not None:
            return so
    # 3) 去常见壳前缀（_t1_ / lib 前缀差异）后比对
    def _norm(t: str) -> str:
        t = t.rsplit("/", 1)[-1].lower()
        for pfx in ("_t1_", "_t2_", "_t0_"):
            if t.startswith(pfx):
                t = t[len(pfx):]
        return t

    target = _norm(name)
    for key, cand in mods.items():
        if _norm(key) == target:
            return cand
    # 4) 去版本号后比对（唯一命中才采用）
    core = _strip_version_tag(_norm(name))
    if core:
        ver_hits = [cand for key, cand in mods.items()
                    if _strip_version_tag(_norm(key)) == core]
        if len(ver_hits) == 1:
            return ver_hits[0]
    # 5) 尾部后缀匹配：仅当唯一命中时才采用，多于一个视为不确定
    hits = [cand for key, cand in mods.items()
            if _norm(key).endswith(target) or target.endswith(_norm(key))]
    if len(hits) == 1:
        return hits[0]
    return None


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
    from dyn.service import get_dyn

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
    from dyn.service import get_dyn

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
            from dyn.adb import Adb

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


@server.tool()
@logged()
def get_callstack(serial: str, pid: int, thread_id: int = 0, limit: int = 32) -> str:
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
    """
    from dyn.service import get_dyn

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
    js = (_JS_CALLSTACK
          .replace("__TID__", str(tid))
          .replace("__LIMIT__", str(limit)))
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
    """列出当前所有断点（AI 与界面共用同一份）。"""
    from dyn.service import get_dyn

    return _j({"breakpoints": get_dyn().list_breakpoints()})


# ---------------- 新能力：内存解释 / 单步规划 / trace 聚合 / 静动打通 ----------------
#
# 本区块对应 dyn/memread.py、dyn/stepper.py、dyn/tracer.py、dyn/bridge.py，
# 这四个模块由并行开发提供，可能比本文件晚落地，因此一律**调用期惰性导入**：
# 模块缺失只让对应工具报不可用，不会拖垮整个 MCP 服务。
#
# 统一约定（四条，AI 依赖它判断结果含义）：
#   1. 占位能力（需真机 frida 但本轮留空）返回 implemented=false 的结构，
#      **原样透传**，不包装成看起来成功的结果、也不当异常 catch 掉。
#   2. 静态能力（读 so 文件、规划落点、按函数聚合）完全离线，不连设备。
#   3. 任何降级都在 notes / diagnostics 里说明，不静默丢信息。
#   4. 失败统一 {"error": ..., "code": ...}，code 机器可判定。


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

    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:            # noqa: BLE001 - 模块内任何错误都算"不可用"
        return None, {
            "error": f"{module_path} 尚不可用：{type(exc).__name__}: {exc}",
            "code": "MODULE_UNAVAILABLE",
            "available": False,
            "module": module_path,
            "hint": "该模块由并行开发提供，落地后本工具自动生效，无需改动 tools.py",
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


def _so_for_static_read(so_name: str):
    """取静态 so 对象；未加载时给明确错误（不静默返回空）。"""
    try:
        return _session.get(so_name), None
    except KeyError as exc:
        return None, {
            "error": str(exc),
            "code": "SO_NOT_LOADED",
            "loaded": list(_session.modules),
        }


def _backtrace_hints(frames, tool_hint: str = "") -> list[str]:
    """从符号化后的栈帧里找出"只有模块+偏移、没有函数名"的模块，给 AI 提示。

    (18) 第十八次修改（2026-11-05）：新增。
        bug 原因：符号化失败时栈帧会退化成 `libc++.so+0x4ce58` 这种形式，
                  不报错、也不提示，AI 很容易以为"分析到这一步了"，
                  而实际上函数名一个都没解析出来。实测把 libc++.so 存成
                  libcxx_lib64.so 时就是这样，改成原名后立刻变成
                  `libc++.so!_Znwm+0x20`。
        解决方案：扫描栈帧，把"有 +0x 但没有 !"的模块名收集起来，
                  由调用方拼一条可执行的提示（去 load_so 载入这些 so）。
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

    (12) 第十二次修改（2026-11-03）：新增本函数。
        背景：frida-server 已对齐 17.23.3，memread 的 source="runtime" 已实现，
        但 MCP 层此前没把 Rebase 传下去，导致工具仍在走留空分支。
        这里复用 dyn.service 的单例会话语义（已 attach 则复用，避免重复 attach
        造成的抖动与句柄泄漏）。
    """
    if not serial or not pid:
        return None, {
            "error": "source='runtime' 需要 serial 与 pid（指向已 attach 的目标进程）",
            "code": "NEED_TARGET",
        }
    try:
        from dyn.service import get_dyn

        tgt = get_dyn().attach(serial, pid)
    except Exception as exc:                              # noqa: BLE001 - DynError 带 code
        return None, {"error": str(exc), "code": getattr(exc, "code", "ATTACH_FAILED")}
    rb = getattr(tgt, "rb", None)
    if rb is None:
        return None, {"error": "该目标没有 Rebase（rb 为空）", "code": "NO_RB"}
    return rb, None


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


def _snapshot_service_events() -> tuple[list, str]:
    """取动态服务里已有的断点命中事件快照，供 trace_aggregate(events=None) 使用。

    为什么读私有队列：service 没有"列出全部历史事件"的公开接口
    （poll_events 需要 serial+pid 且会推进游标）。这里**只读拷贝**，
    不改游标、不发任何 frida 请求，与 state() 一样属于旁观。

    只保留带地址的事件：attached / breakpoint_set 一类没有地址，聚合不了。
    """
    try:
        from dyn.service import get_dyn

        svc = get_dyn()
    except Exception as exc:            # noqa: BLE001 - 服务不可用不该让聚合崩
        return [], f"动态服务不可用：{type(exc).__name__}: {exc}"
    queue = getattr(svc, "_events", None)
    if queue is None:
        return [], "动态服务没有可读的事件队列，请改用 events 参数显式传入事件"
    snap = []
    for ev in list(queue):
        if not isinstance(ev, dict):
            continue
        if ev.get("runtime_addr") is None and ev.get("addr") is None:
            continue
        snap.append(dict(ev))
    return snap, ""


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
    from core.addr import parse_addr
    from dyn.service import get_dyn

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
    from core.addr import parse_addr
    from dyn.service import get_dyn

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
    mod, err = _load_dyn_module("dyn.memread", "read_typed", "MemReadError")
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
    mod, err = _load_dyn_module("dyn.memread", "read_string", "MemReadError")
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
    mod, err = _load_dyn_module("dyn.memread", "read_pointer", "MemReadError")
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
    mod, err = _load_dyn_module(
        "dyn.stepper", "plan_step_over", "plan_step_out",
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
    from dyn.stepper import (
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
        from dyn.service import get_dyn

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
    mod, err = _load_dyn_module("dyn.tracer", "aggregate_by_function")
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
    mod, err = _load_dyn_module("dyn.bridge", "locate_static")
    if err:
        return _j(err)
    from dyn.service import get_dyn

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
def hit_analysis(serial: str, pid: int, build_xrefs: bool = False) -> str:
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
    mod, err = _load_dyn_module("dyn.bridge", "hit_context")
    if err:
        return _j(err)
    from dyn.service import get_dyn

    svc = get_dyn()
    try:
        hits = svc.hits(serial, pid)
    except Exception as exc:            # noqa: BLE001 - DynError 带 code
        return _j({"error": f"{type(exc).__name__}: {exc}", "code": "NOT_ATTACHED"})
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
    result["hits_total"] = len(hits)
    return _j(result)


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
    mod, err = _load_dyn_module("dyn.bridge", "suggest_breakpoints")
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
    mod, err = _load_dyn_module("dyn.bridge", "trace_to_timeline")
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
    mod, err = _load_dyn_module("dyn.bridge", "module_load_timeline")
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
    mod, err = _load_dyn_module("dyn.tracer", "start_trace_module_load")
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
    mod, err = _load_dyn_module("dyn.tracer", "trace_app_startup")
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
    mod, err = _load_dyn_module("dyn.tracer", "start_trace_code")
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
    mod, err = _load_dyn_module("dyn.tracer", "start_trace_read")
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
    mod, err = _load_dyn_module("dyn.tracer", "start_trace_write")
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
        from dyn.service import get_dyn

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
    from scripting.runner import run_in_session

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
    from scripting.idc import run_idc as _run

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

    from scripting.idc import run_idc as _run

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
    mod, err = _load_dyn_module("dyn.tracer", "watch_module")
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
    mod, err = _load_dyn_module("dyn.tracer", "verify_breakpoint")
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
    mod, err = _load_dyn_module("dyn.bridge", "resolve_br")
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
                  instr_size: int = 16, max_instr: int = 200) -> str:
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

    ## 已知边界

    位域解析（opcode=bits[4:1]、func=bits[8:5]）是**经验规则**，
    不同壳版本可能不同；返回里会说明规则来源。
    """
    from core.addr import parse_addr

    mod, err = _load_dyn_module("dyn.memread", "dump_vm_state")
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
                                    max_instr=int(max_instr)))
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
    mod, err = _load_dyn_module("dyn.memread", "read_memory_batch")
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
               duration: float = 5.0) -> str:
    """**纯计数探针**：只统计某地址被进入多少次，不挂起、不依赖 hold。

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
    mod, err = _load_dyn_module("dyn.tracer", "probe_hits")
    if err:
        return _j(err)
    try:
        return _j(mod.probe_hits(serial, int(pid), so_name,
                                 int(static_addr), duration=float(duration)))
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
    mod, err = _load_dyn_module("dyn.bridge", "read_jump_table")
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
                       max_candidates: int = 40) -> str:
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
    """
    mod, err = _load_dyn_module("dyn.memread", "probe_vm_from_hits")
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
        from dyn.service import get_dyn

        svc = get_dyn()
        hit_list = svc.hits(serial, int(pid)) or []
    except Exception as exc:                              # noqa: BLE001
        hits_error = f"{type(exc).__name__}: {exc}"
        try:
            from dyn.service import get_dyn as _gd

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
            max_candidates=int(max_candidates)))
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
    mod, err = _load_dyn_module("dyn.tracer", "trace_call_tree")
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
    mod, err = _load_dyn_module("dyn.memread", "decode_runtime_insn")
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
    from dyn.adb import Adb

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
    mod, err = _load_dyn_module("dyn.jni", "find_jni_registrations")
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
    mod, err = _load_dyn_module("dyn.dispatch", "find_dispatch_tables")
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
    mod, err = _load_dyn_module("dyn.java_bridge", "bridge_status")
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
    mod, err = _load_dyn_module("dyn.java_bridge", "java_list_methods")
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
                      limit: int = 200) -> str:
    """在**已加载的类**里按正则搜索全限定类名。

    加固 app 会动态加载大量类，静态看不到。本工具枚举运行时的全部 Class
    再正则筛选——是摸清一个 app 内部结构的起点。

    ## 参数

        pattern   正则（大小写不敏感），空则返回前 limit 个
        limit     最多返回多少个（1..2000）

    ## 返回

        classes[]  全限定类名
        total      枚举到的类总数（不受 limit 影响）
        matched    匹配数
        note       匹配数超过本页时明确说明

    ## 典型用法

        java_find_classes(pattern="Security|Sign|Guard")
        → 找出所有与签名/安全相关的已加载类
    """
    mod, err = _load_dyn_module("dyn.java_bridge", "java_find_classes")
    if err:
        return _j(err)
    try:
        return _j(mod.java_find_classes(serial, int(pid), pattern,
                                        limit=int(limit)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_FIND_FAILED"})


@server.tool()
@logged()
def java_hook(serial: str, pid: int, class_name: str, method: str,
              overload: str = "", duration: float = 5.0, max_calls: int = 200,
              include_stack: bool = True, stack_depth: int = 8) -> str:
    """hook 一个 Java 方法，记录每次调用的**参数、返回值、调用栈**。

    这是 mda 从「只看 native」跨到「Java 层可见」的关键能力。

    ## 参数

        class_name    全限定类名
        method        方法名
        overload      重载签名（可选），如 "(Ljava/lang/String;)V"；
                      不传则 hook **所有**同名重载
        duration      采集秒数
        max_calls     最多记录多少次（防高频方法打爆内存，上限 5000）
        include_stack 是否抓 Java 调用栈
        stack_depth   栈深度

    ## 返回

        hooked       实际 hook 上的重载签名列表
        calls[]      {seq, ts, thread, args[], ret, stack[], threw?}
        call_count   调用次数（可能 > len(calls)，被 max_calls 截断）
        truncated    是否因 max_calls 截断
        verdict      一句话结论：区分「hook 上但没被调」与「调了多少次」

    ## 已知边界（如实标注）

        · 参数按 `String(v)` 转字符串并截断 200 字符——**对象只给摘要**
        · ART 的 JIT 内联可能让 hook 失效（已知限制）
        · 加固 app 可能阻断 `Java.perform`，这时返回 NOT_READY 并说明

    ## 典型用法

        java_hook(class_name="com.taobao.security.Sign", method="doCommand",
                  duration=8)
        → 期间操作 app，回来就能看到每次调用的参数和返回值
    """
    mod, err = _load_dyn_module("dyn.java_bridge", "java_hook")
    if err:
        return _j(err)
    try:
        return _j(mod.java_hook(serial, int(pid), class_name, method,
                                overload=overload, duration=float(duration),
                                max_calls=int(max_calls),
                                include_stack=bool(include_stack),
                                stack_depth=int(stack_depth)))
    except Exception as exc:                              # noqa: BLE001
        return _j({"error": f"{type(exc).__name__}: {exc}",
                   "code": "JAVA_HOOK_FAILED"})
