"""控制台功能自检（不碰设备、不连前端）。

覆盖三件事，都是 2026-11-19 新增的：
  1. 工具返回值能一路走到 WS 广播载荷（控制台"输出"侧的核心链路）
  2. 超长结果被截断且**如实标注**（静默截断比不给看更糟）
  3. 手动 frida 执行的参数校验与错误码

跑法：.venv/bin/python tests/test_console.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server.api as api                                            # noqa: E402
from server.mcp_server import tools                                 # noqa: E402


def _make_capture():
    """拦掉真正的 WS 广播，只记录载荷。

    为什么不在测试里起真 WS：控制台的正确性取决于**载荷内容**，
    而不是传输层；传输层已有既有的 /api/events 覆盖。
    """
    captured = []

    def _on_ai(entry):
        # 复刻 api.py lifespan 里注册的 _on_ai 载荷结构
        captured.append({
            "type": "ai", "tool": entry.get("tool", ""),
            "summary": entry.get("summary", ""), "args": entry.get("args", {}),
            "ts": entry.get("ts", ""), "t": entry.get("t", 0),
            "ms": entry.get("ms", 0), "ok": entry.get("ok", True),
            "result": entry.get("result", ""),
            "result_truncated": bool(entry.get("result_truncated")),
            "result_bytes": int(entry.get("result_bytes") or 0),
        })

    return captured, _on_ai


def test_result_reaches_broadcast():
    """工具返回结果必须出现在广播载荷里（改前完全没有）。"""
    captured, cb = _make_capture()
    tools.on_activity(cb)
    try:
        tools._activity("set_breakpoint", {"serial": "ABC", "pid": 123},
                        "serial=ABC", 12.5, result={"bp_id": "x:y:z", "ok": True})
    finally:
        tools._log_listeners.remove(cb)

    assert captured, "没有捕获到任何广播"
    p = captured[-1]
    assert p["type"] == "ai"
    assert p["result"], "result 为空——控制台输出侧仍然是空白（改动未生效）"
    assert "x:y:z" in p["result"], "result 内容丢失"
    # 输入侧必须是完整 dict，不能被 summary 那套 60 字符截断影响
    assert p["args"] == {"serial": "ABC", "pid": 123}, "args 被改动"
    # 排序键必须是真实 epoch，否则 AI 调用与手动事件无法混排
    assert p["t"] > 1.7e9, "t 不是真实 epoch 时间戳"


def test_long_result_truncated_visibly():
    """超长结果被截断，且截断标记与原始长度都在载荷里。"""
    captured, cb = _make_capture()
    tools.on_activity(cb)
    try:
        tools._activity("hits", {"pid": 1}, "big", 1.0,
                        result={"x": "y" * 50000})
    finally:
        tools._log_listeners.remove(cb)

    p = captured[-1]
    assert p["result_truncated"] is True, "超长结果没有被标截断"
    assert p["result_bytes"] > len(p["result"]), "截断后长度应小于原始长度"
    assert len(p["result"]) <= tools._RESULT_MAX_CHARS


def test_failure_marked():
    """失败调用必须 ok=False 且带错误内容，不能被当成成功。"""
    captured, cb = _make_capture()
    tools.on_activity(cb)
    try:
        tools._activity("bad_tool", {}, "✗ X", 1.0,
                        result={"error": "boom"}, ok=False)
    finally:
        tools._log_listeners.remove(cb)

    p = captured[-1]
    assert p["ok"] is False
    assert "boom" in p["result"]


def test_activity_log_bounded():
    """_activity_log 必须有上界：加了 result 之后无界会吃爆内存。"""
    for i in range(tools._activity_log.maxlen + 50):
        tools._activity("fill", {}, str(i), 0.1, result={"i": i})
    log = tools.get_activity_log(0)
    assert len(log) == tools._activity_log.maxlen, \
        f"上界失效：{len(log)} != {tools._activity_log.maxlen}"
    # 切片式调用（GUI 历史端点用）不能因为 deque 不支持切片而抛异常
    assert len(tools.get_activity_log(10)) == 10


def test_frida_js_param_guard():
    """手动执行必须显式给目标，且缺参时给明确错误码。"""
    from server.dyn.console import run_js, stop_js

    r = run_js("", 0, "1+1")
    assert r["ok"] is False and r["code"] == "NEED_TARGET", r

    r = run_js("ABC", 1, "   ")
    assert r["ok"] is False and r["code"] == "EMPTY_SCRIPT", r

    r = stop_js(999999)
    assert r["ok"] is False and r["code"] == "NOT_FOUND", r


def test_line_text_plain():
    """终端语义：脚本打印什么就显示什么，必须是纯文本行。

    (1) 第一次修改（2026-11-19）
    bug 原因：最初实现把 send 的对象做缩进 JSON 美化、套"结果"标题，
              返回的 payload 是原始对象——那不是终端，是 JSON 查看器。
              用户明确："脚本打印什么就显示什么"。
    解决方案：_line_text 统一产出纯文本行：
      · console.log 重定向来的 {__log:"..."} → 原样文本
      · send 字符串                          → 原样文本
      · send 对象                            → 紧凑单行 JSON
    """
    from server.dyn.console import _JS_REDIRECT, _line_text

    assert _line_text({"__log": "hello 世界"}) == "hello 世界"
    assert _line_text("plain string") == "plain string"
    assert _line_text(None) == "null"
    # 对象：保留完整结构（不再压成紧凑单行——那是"我自己加工"的产物）
    obj_text = _line_text({"a": 1, "b": "x"})
    assert '"a"' in obj_text and '"b"' in obj_text, obj_text
    assert "1" in obj_text and "x" in obj_text
    # console.log 重定向前缀必须存在，否则 Python 收不到脚本打印
    assert "console.log" in _JS_REDIRECT and "send" in _JS_REDIRECT


def test_output_is_raw_not_wrapped():
    """输出必须是 frida 原样内容，不能被我加工/摘要/包装。

    (1) 第一次修改（2026-11-19）
    bug 原因：此前做了两件"加工"：
              ① 给脚本套 eval() 包装，结果变成我算的 {__result:...}
              ② 给工具输出做摘要（数组压成"数组 N 项: 前3项…"）
              用户明确："我要返回结果，不是你自己包装的结果"。
    解决方案：全部删除。_line_text 只做最小转换（__log 取原文本、
              其余 json.dumps 保留完整结构），不裁剪不改名。
    本测试锁死这个契约，防止将来又"优化"成摘要。
    """
    from server.dyn.console import _line_text

    # 对象必须完整保留所有字段与层级，一个字都不能少
    big = [{"name": f"lib{i}.so", "base": "0x1234", "size": i} for i in range(50)]
    text = _line_text(big)
    assert "lib49.so" in text, "大数组被裁剪了（用户要原样输出）"
    assert "数组 50 项" not in text, "不该出现我自己造的摘要文案"
    assert text.startswith("["), "对象结构必须保留"

    # 长文本不截断
    long_text = "x" * 1000
    assert _line_text(long_text) == long_text, "长文本被截断了"

    # console.log 文本原样取出（这层是 frida 消息通道所必需，不算加工）
    assert _line_text({"__log": "hello"}) == "hello"

    # 不能残留 eval 包装的痕迹。
    # 只看**代码行**（去掉注释与文档字符串），否则注释里提到这个名字会误报。
    import inspect
    import re

    import server.dyn.console as mod

    code_lines = []
    for line in inspect.getsource(mod).splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        code_lines.append(line)
    code_only = "\n".join(code_lines)
    # 去掉三引号内的说明文字干扰：检查真实的赋值/调用形态
    assert not re.search(r"^\s*_JS_RESULT_WRAPPER\s*=", code_only, re.M), \
        "eval wrapper 定义又回来了（用户反对我自己算结果）"
    assert "__CODE__" not in code_only, \
        "脚本又被塞进 eval 占位符了（用户要 frida 原样执行）"


def test_no_global_bypass():
    """终端不得再安装全局旁路 hook（会把工具内部数据灌进终端）。

    (1) 第一次修改（2026-11-20）
    bug 原因：曾包装 frida.core.Session.create_script，把所有工具脚本的
              send 旁路进终端。工具的 send 是内部数据传输（set_breakpoint
              一次 send 整个模块列表），用户手敲一句 console.log 后跟着
              吐出一大坨模块 JSON，用户明确反对。
    解决方案：整套旁路删除。本测试锁死：console 模块里不许再有
              install_global_hook / _bypass_emit / set_tool 这些名字。
    """
    import inspect

    import server.dyn.console as mod

    src = inspect.getsource(mod)
    code_lines = [
        ln for ln in src.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    code_only = "\n".join(code_lines)
    for banned in ("def install_global_hook", "def _bypass_emit", "def set_tool"):
        assert banned not in code_only, f"全局旁路又回来了：{banned}"
    # 也不许再 monkeypatch frida 的 create_script
    assert "sess_cls.create_script" not in code_only, "又 monkeypatch 了 create_script"


def main() -> int:
    tests = [
        test_result_reaches_broadcast,
        test_long_result_truncated_visibly,
        test_failure_marked,
        test_activity_log_bounded,
        test_frida_js_param_guard,
        test_line_text_plain,
        test_output_is_raw_not_wrapped,
        test_no_global_bypass,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
