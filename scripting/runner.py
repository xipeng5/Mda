"""AI 脚本执行器。

AI 通过 MCP 的 run_script 提交 Python 片段，在受限命名空间里
操作当前 Session。不做沙箱隔离——调用方是本机可信的 AI 助手，
但要控制执行时长与输出体积。

依赖 core.session。
"""
from __future__ import annotations

import io
import json
import contextlib

from core.session import Session

# 单次脚本输出上限，避免撑爆 MCP 响应
_MAX_OUTPUT = 64 * 1024


def run_in_session(session: Session, code: str) -> str:
    """在给定会话上执行脚本，返回 print 输出与 result 变量。"""
    buf = io.StringIO()
    globs: dict = {
        "session": session,
        "json": json,
        "__builtins__": __builtins__,
    }
    result = None
    try:
        with contextlib.redirect_stdout(buf):
            compiled = compile(code, "<mda-script>", "exec")
            exec(compiled, globs)  # noqa: S102  设计如此：AI 脚本通道
            result = globs.get("result")
    except Exception as e:  # 脚本错误要完整回传给 AI 便于自纠
        return json.dumps({"error": f"{type(e).__name__}: {e}", "stdout": buf.getvalue()}, ensure_ascii=False)

    out = buf.getvalue()
    if len(out) > _MAX_OUTPUT:
        out = out[:_MAX_OUTPUT] + f"\n...[输出截断，原长 {len(out)}]"
    try:
        result_json = json.dumps(result, ensure_ascii=False, default=str) if result is not None else None
    except Exception:
        result_json = repr(result)
    return json.dumps({"stdout": out, "result": result_json}, ensure_ascii=False)
