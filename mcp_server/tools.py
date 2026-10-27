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
    hits = []
    for sec in so.sections:
        if not sec.is_exec and sec.addr == 0:
            continue
        data = so.read(sec.addr, sec.size)
        if not data:
            continue
        for m in pattern.finditer(data):
            hits.append({"addr": hex(sec.addr + m.start()), "section": sec.name})
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    return _j({"count": len(hits), "matches": hits})


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
    """以 root 启动设备端 frida-server（须已 push 对应版本）。"""
    from dyn.adb import Adb

    ok = Adb(serial).start_frida()
    return _j({"running": ok})


@server.tool()
@logged()
def runtime_modules(serial: str, pid: int, keyword: str = "") -> str:
    """列出目标进程加载的模块及运行时基址。keyword 过滤模块名。"""
    from dyn.rebase import Rebase

    rb = Rebase.attach(serial, pid)
    try:
        mods = rb.refresh_modules()
        kw = keyword.lower()
        return _j([
            {"name": m.name, "base": hex(m.base), "size": hex(m.size), "path": m.path}
            for m in mods
            if not kw or kw in m.name.lower()
        ][:200])
    finally:
        rb.detach()


@server.tool()
@logged()
def set_breakpoint(serial: str, pid: int, so_name: str, static_addr: int, hold: bool = False) -> str:
    """在目标进程的某 so 静态地址上下断点。

    hold=False 命中即继续（只记录）；hold=True 挂起等待，
    调用 wait_hits 拿到命中后分析，再调 resume 放行。
    """
    from dyn.debugger import Debugger
    from dyn.rebase import Rebase

    rb = Rebase.attach(serial, pid)
    dbg = Debugger(rb)
    ok = dbg.set_breakpoint(so_name, static_addr, policy="hold" if hold else "resume")
    return _j({"set": ok})


@server.tool()
@logged()
def read_process_memory(serial: str, pid: int, so_name: str, static_addr: int, size: int = 32) -> str:
    """按 so 静态地址读取目标进程内存（自动完成 ASLR 换算）。"""
    from dyn.rebase import Rebase

    rb = Rebase.attach(serial, pid)
    try:
        mod = rb.find_module(so_name)
        if mod is None:
            return _j({"error": f"{so_name} not loaded in process {pid}"})
        data = rb.read_memory(rb.to_runtime(static_addr, mod), size)
        return _j({"static_addr": hex(static_addr), "runtime_addr": hex(rb.to_runtime(static_addr, mod)), "hex": data.hex()})
    finally:
        rb.detach()


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
