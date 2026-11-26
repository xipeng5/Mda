"""frida 脚本输出终端（控制台用）。

## 解决什么问题

这块界面是**真·frida 终端**：脚本 `console.log()` / `send()` 打印什么，
屏幕上就逐行原样显示什么——和你在 frida 命令行里跑脚本看到的一样。
不是"工具调用参数的 JSON 查看器"。

## 只显示用户执行的脚本，不掺工具内部数据（2026-11-20 用户纠正）

曾经做过一版"全局 hook"，包装 frida 的 create_script 把**所有**工具脚本的
send 旁路进终端，想法是"AI 调的 frida 工具输出也该能看到"。实测结果是灾难：
工具的 send 是**内部数据传输**，不是脚本输出——
`set_breakpoint` 一次 send 整个模块列表（几百个 JSON 对象），
用户手敲一句 `console.log("hello")` 后，终端里跟着吐出一大坨模块数据，
用户原话："这他妈的是什么"。

结论：**这个终端只显示用户在这个输入框里执行的脚本产生的输出。**
AI 调工具的返回走 MCP 给 AI 读，与本终端无关。不要再接旁路。

## 关键实测结论（2026-11-19，真机 3e2ff172 验证，不是猜的）

1. `console.log()` 的输出**不走 frida 的 message 回调**！
   实测脚本里 `console.log("LINE-LOG: hello")` 只打到 frida-server 的 stdout，
   Python 侧 `script.on("message")` 完全收不到。只有 `send()` 走回调。
   ⇒ 想让脚本的 console.log 出现在终端里，必须在脚本最前面注入一段
     重定向：把 console.log 改写成 send({__log: ...})。
2. 重定向后实测能收到所有打印：
   console.log("hello")        → {'type':'send','payload':{'__log':'hello'}}
   console.log("第二行", 123)  → {'__log':'第二行 123'}
   send("DIRECT")              → {'type':'send','payload':'DIRECT'}
   ⇒ 输出统一按"纯文本行"处理：字符串直接显示，对象 JSON 化。

## 两种模式（由调用方显式指定，不做内容推断）

  once   执行 → 收集该次脚本打印的全部输出行 → unload。适合主动查询
         （`Process.enumerateModules()`、`Memory.scanSync(...)` 这类）。
  keep   执行后**保持脚本存活**，后续每次 `console.log()` / `send()` 都推给终端，
         直到调用 `stop()`。适合 `Interceptor.attach` 这类需要持续观测的场景。

为什么不让模块自己看脚本内容判断：
    "脚本里有 Interceptor.attach 就算常驻" 是内容启发式，会误判
    （把 attach 写在条件分支里、或只是定义一个函数但没调用）。
    语义由调用方声明，模块只负责执行——这样行为可预测。

## 能力边界（诚实说明）

  · 只在**已附加的目标**里跑，不负责 attach/detach
    （attach 由 DynamicService 管理，避免同一进程出现两个 frida 会话——
     实测 frida 16 上"同一 client 进程第二次 attach"会无限期阻塞）
  · 不做脚本沙箱：这是本机已授权能力，与既有 run_script / run_idc 同级
  · 目标无响应时按超时如实返回，不把"没收到载荷"说成"执行成功"
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field

from server.dyn.rebase import unload_script_async

# (3) 第三次修改（2026-11-26）
# bug 原因：模块顶部残留重复矛盾的"两种模式"文档段落，以及全局旁路删除后不再使用的
#           _local 与 _jsonable 死代码。
# 解决方案：合并清理文档，移除未使用的 _local 与 _jsonable，引入公共异步卸载辅助函数。

# 常驻脚本表：key = (serial, pid) -> list[ConsoleScript]
# 同一进程允许多个常驻脚本（用户可能先后挂两个不同 hook），每个可单独停。
_scripts: dict[tuple[str, int], list["ConsoleScript"]] = {}
_lock = threading.RLock()

# 控制台事件环形缓冲：手动执行的脚本 send 出来的东西也进这条流，
# 与 AI 调用记录在前端混在一起按时间排序，这才是"像终端一样"的体验。
_EVENT_MAX = 300
_events: list[dict] = []
_ev_lock = threading.Lock()

# 每个脚本收到多少条输出（script_id -> 条数）。
# 为什么单独一张表而不是写在脚本对象里：脚本对象在 "keep" 分支才创建，
# 而 _on_message 回调在那之前就注册好了——回调闭包里拿不到脚本对象。
# 这张表在回调里就能安全累加，list_scripts 直接读它，二者同源不漂移。
_counts: dict[int, int] = {}

# 注入到每段脚本最前面的 console.log 重定向。
# 为什么必须重定向：实测 frida 的 console.log 不走 message 回调（只打到
# frida-server stdout），Python 收不到——用户就看不到脚本的打印。
# 重定向后所有 console.log 都变成 send({__log: ...})，统一走回调。
# 保留原始 console.log 引用，万一脚本自己覆盖也能用。
_JS_REDIRECT = r"""
(function(){
  var _realLog = console.log;
  console.log = function(){
    var a = Array.prototype.slice.call(arguments);
    var s = a.map(function(x){
      if (typeof x === 'string') return x;
      try { return JSON.stringify(x); } catch(e) { return String(x); }
    }).join(' ');
    send({__log: s});
  };
  console.error = console.log;
  console.warn = console.log;
})();
"""


def _line_text(payload) -> str:
    """把一条 frida 消息载荷变成终端里的一行文本。

    **只做最小转换，不加任何自己的包装**（2026-11-19 用户纠正：
    "我要返回结果，不是你自己包装的结果"）。

      · console.log 重定向来的 {__log:"..."} → 取出原文本（这一层是 frida
        消息通道所必需：console.log 不走回调，只能靠 send 带出来）
      · 其余一律原样：字符串直接显示，对象用 json.dumps 保留原始结构
        （不裁剪、不摘要、不改字段名）
    """
    if isinstance(payload, dict) and set(payload.keys()) == {"__log"}:
        return str(payload["__log"])
    if isinstance(payload, str):
        return payload
    if payload is None:
        return "null"
    try:
        return json.dumps(payload, ensure_ascii=False, default=str)
    except Exception:                                      # noqa: BLE001
        return str(payload)


def _emit(kind: str, **fields) -> None:
    """记录一条控制台事件（供前端轮询/WS 推送）。"""
    ev = {"kind": kind, "ts": time.strftime("%H:%M:%S"),
          "t": time.time(), **fields}
    with _ev_lock:
        _events.append(ev)
        if len(_events) > _EVENT_MAX:
            del _events[: len(_events) - _EVENT_MAX]


def recent_events(after: float = 0.0) -> list[dict]:
    """取 t > after 的控制台事件（前端用游标增量拉取）。"""
    with _ev_lock:
        return [e for e in _events if e.get("t", 0) > after]


@dataclass
class ConsoleScript:
    """一个已在目标进程里存活的 frida 脚本。"""

    script_id: int
    serial: str
    pid: int
    frida_script: object
    mode: str = "keep"
    created: float = field(default_factory=time.time)
    messages: int = 0
    last_error: str = ""
    stop_reason: str = ""

    # (4) 第四次修改（2026-11-26）
    # bug 原因：stop() 同步调用 frida_script.unload()，在 frida 17.23.3 上可能永久阻塞，
    #           且原 stop_js 在持有 _lock 时调 stop() 会与 _on_message 形成 AB-BA 死锁。
    # 解决方案：改用带有限超时的异步卸载 unload_script_async，不阻塞调用方。
    def stop(self) -> None:
        """卸载脚本（带超时守护线程，防 frida 同步 unload 卡死）。"""
        try:
            unload_script_async(self.frida_script, timeout=2.0)
            self.stop_reason = self.stop_reason or "stopped"
        except Exception as exc:                           # noqa: BLE001
            self.stop_reason = f"unload_failed: {exc}"
        _emit("stop", script_id=self.script_id, serial=self.serial,
              pid=self.pid, reason=self.stop_reason)


_next_id = 0


def _new_id() -> int:
    global _next_id
    with _lock:
        _next_id += 1
        return _next_id


def run_js(serial: str, pid: int, js: str, mode: str = "once",
           timeout: float = 5.0) -> dict:
    """在已附加的目标里执行一段 frida JS。

    参数：
        serial  设备序列号（必填，拒绝"用最近那个"这类隐式兜底）
        pid     目标进程（必填）
        js      要执行的脚本源码
        mode    once（等一次 send 就卸载）/ keep（常驻，直到 stop）
        timeout once 模式下等待首个载荷的秒数

    返回：{ok, script_id?, lines?: str[], error?, code?, ms}
    lines 是脚本 console.log / send 打印出来的**纯文本行**，终端原样显示。
    失败一律带 code，便于前端区分"参数错"与"脚本跑错"。
    """
    if not serial or not pid:
        return {"ok": False, "code": "NEED_TARGET",
                "error": "需要 serial 与 pid（不做隐式兜底：注错进程的代价太高）"}
    js = (js or "").strip()
    if not js:
        return {"ok": False, "code": "EMPTY_SCRIPT", "error": "脚本为空"}

    # 复用已附加的会话：不自己 attach。
    # 为什么：frida 16 实测"同一 client 进程第二次 attach"会无限期阻塞，
    #        而 DynamicService 已经持有该 pid 的 Rebase/dbg 会话，直接复用。
    try:
        from server.dyn.service import get_dyn

        svc = get_dyn()
        tgt = svc.attach(serial, int(pid))
    except Exception as exc:                               # noqa: BLE001
        return {"ok": False, "code": "ATTACH_FAILED",
                "error": f"附加失败：{exc}"}

    session = getattr(getattr(tgt, "rb", None), "session", None)
    if session is None:
        return {"ok": False, "code": "NO_SESSION",
                "error": "目标已附加但拿不到 frida 会话"}

    # (5) 第五次修改（2026-11-26）
    # bug 原因：① mode == "keep" 常驻脚本每次输出仍无限向闭包局部 box["lines"] append，
    #             且永不释放，高频日志下必然 OOM；
    #           ② box["lines"] 在 frida 回调线程写入、主线程读取，缺少锁保护；
    #           ③ mode == "once" 结束后未清理 _counts[sid]，长期调用会泄漏字典项；
    #           ④ once 结束同步调用 script.unload() 存在卡死风险。
    # 解决方案：keep 模式不向 box["lines"] 追加（仅走有界 _emit 缓冲）；用局部 box_lock
    #           保护 box 读写；once 结束异步 unload 并在 finally 中清理 _counts[sid]。
    sid = _new_id()
    is_keep = (mode == "keep")
    # 预先登记计数槽，stop_js / once 结束摘除后迟到消息不会再把 sid 重新塞回 _counts 造成泄漏
    with _lock:
        _counts[sid] = 0
    # box["lines"] 仅在 once 模式下存纯文本行，keep 模式只走有界 _emit 环形缓冲
    box: dict = {"lines": [], "error": ""}
    box_lock = threading.Lock()
    done = threading.Event()

    def _on_message(msg, data=None):
        if not isinstance(msg, dict):
            return
        mtype = msg.get("type")
        if mtype == "error":
            err_msg = (msg.get("description") or "").strip() or str(msg)
            if not is_keep:
                with box_lock:
                    box["error"] = err_msg
            _emit("error", script_id=sid, error=err_msg,
                  stack=msg.get("stack"))
            done.set()
            return
        if mtype == "log":
            # frida 原生 log（少数版本会走这条），直接当文本行
            text = str(msg.get("payload") or "")
            if not is_keep:
                with box_lock:
                    box["lines"].append(text)
            with _lock:
                if sid in _counts:
                    _counts[sid] += 1
            _emit("line", script_id=sid, text=text)
            done.set()
            return
        if mtype != "send":
            return
        # 每条输出变成一行纯文本——终端里 console.log/send 打印什么就显示什么
        text = _line_text(msg.get("payload"))
        if not is_keep:
            with box_lock:
                box["lines"].append(text)
        with _lock:
            if sid in _counts:
                _counts[sid] += 1
        _emit("line", script_id=sid, serial=serial, pid=int(pid), text=text)
        done.set()

    # 只注入 console.log 重定向（frida 消息通道所必需），原样执行脚本不套包装。
    full_js = _JS_REDIRECT + "\n" + js

    try:
        script = session.create_script(full_js)
        script.on("message", _on_message)
        script.load()
    except Exception as exc:                               # noqa: BLE001
        with _lock:
            _counts.pop(sid, None)
        err = str(exc)
        _emit("error", script_id=sid, error=err)
        return {"ok": False, "code": "LOAD_FAILED", "error": err,
                "hint": "脚本语法错误或调用了当前 frida 版本不存在的 API"}

    t0 = time.monotonic()

    if is_keep:
        cs = ConsoleScript(script_id=sid, serial=serial, pid=int(pid),
                           frida_script=script, mode="keep")
        with _lock:
            _scripts.setdefault((serial, int(pid)), []).append(cs)
        _emit("start", script_id=sid, serial=serial, pid=int(pid), mode="keep")
        return {"ok": True, "script_id": sid, "mode": "keep",
                "ms": round((time.monotonic() - t0) * 1000, 1),
                "hint": "常驻中：脚本每次 send() 都会出现在这条控制台流里，"
                        "用完点「停止」或调 stop 释放"}

    # once：等首个输出（或错误），超时就如实报告没有输出
    try:
        got = done.wait(timeout=max(float(timeout), 0.1))
        # 首行到达后再给 0.15s 收集同一批后续输出
        with box_lock:
            has_err = bool(box["error"])
        if got and not has_err:
            time.sleep(0.15)
        ms = round((time.monotonic() - t0) * 1000, 1)
        unload_script_async(script, timeout=2.0)
        with box_lock:
            err_text = box["error"]
            lines = list(box["lines"])
    finally:
        with _lock:
            _counts.pop(sid, None)

    if err_text:
        return {"ok": False, "code": "SCRIPT_ERROR", "error": err_text,
                "script_id": sid, "ms": ms, "lines": lines}
    if not got or not lines:
        return {"ok": False, "code": "NO_OUTPUT",
                "error": f"等待 {timeout}s 内脚本没有打印任何内容"
                         f"（脚本可能正常执行完了，但没有 console.log/send；"
                         f"要持续观测请用 mode=keep）",
                "script_id": sid, "ms": ms, "lines": []}
    return {"ok": True, "script_id": sid, "mode": "once", "ms": ms,
            "lines": lines}


# (6) 第六次修改（2026-11-26）
# bug 原因：原 stop_js 在持有 _lock 期间直接调用 cs.stop() -> frida_script.unload()，
#           而 frida 回调线程的 _on_message 需要获取 _lock 更新 _counts，形成典型 AB-BA 死锁。
# 解决方案：在 _lock 内仅摘除要停止的 ConsoleScript 列表并清理对应 _counts，
#           完全释放 _lock 之后再逐个调用 cs.stop() 执行异步卸载。
def stop_js(script_id: int | None = None, serial: str = "",
            pid: int = 0) -> dict:
    """停止常驻脚本。给 script_id 停单个；否则停该 (serial,pid) 下全部。"""
    to_stop: list[ConsoleScript] = []
    with _lock:
        if script_id:
            for key, lst in list(_scripts.items()):
                kept = []
                for cs in lst:
                    if cs.script_id == script_id:
                        to_stop.append(cs)
                    else:
                        kept.append(cs)
                if kept:
                    _scripts[key] = kept
                else:
                    _scripts.pop(key, None)
        elif serial and pid:
            to_stop = list(_scripts.pop((serial, int(pid)), []))
        else:
            for lst in _scripts.values():
                to_stop.extend(lst)
            _scripts.clear()
        for cs in to_stop:
            _counts.pop(cs.script_id, None)
    if not to_stop:
        return {"ok": False, "code": "NOT_FOUND",
                "error": "没有匹配的常驻脚本（可能已经停止或 id 不对）"}
    stopped: list[int] = []
    for cs in to_stop:
        cs.stop()
        stopped.append(cs.script_id)
    return {"ok": True, "stopped": stopped, "count": len(stopped)}


def list_scripts() -> list[dict]:
    """当前存活的常驻脚本（界面用它渲染"正在观测什么"）。

    (1) 第一次修改（2026-11-19）
    bug 原因：messages 原本读 ConsoleScript.messages 字段，但那个字段只在
              构造时赋值一次，之后的 send 不会更新它——列表里恒为 0，
              属于**假数据**（用户会误以为脚本没有产出）。
    解决方案：改为在 _emit("send") 时按 script_id 计数，这里读计数器。
              计数与"控制台里实际看到多少条"同源，不会再漂移。
    """
    out = []
    with _lock:
        for (serial, pid), lst in _scripts.items():
            for cs in lst:
                out.append({
                    "script_id": cs.script_id,
                    "serial": serial,
                    "pid": pid,
                    "mode": cs.mode,
                    "age_s": round(time.time() - cs.created, 1),
                    "messages": _counts.get(cs.script_id, 0),
                })
    return out
