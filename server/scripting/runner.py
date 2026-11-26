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
import threading

from server.core.session import Session

# 单次脚本输出上限，避免撑爆 MCP 响应
_MAX_OUTPUT = 64 * 1024
# 保护全局 sys.stdout 重定向，避免多线程并发执行脚本时输出串流/竞态恢复
_STDOUT_LOCK = threading.Lock()


def _truncate(text: str, limit: int = _MAX_OUTPUT) -> str:
    """超过长度上限时截断并附原长说明。"""
    if len(text) > limit:
        return text[:limit] + f"\n...[输出截断，原长 {len(text)}]"
    return text


# (1) 第一次修改（2026-11-26）
# bug 原因：① contextlib.redirect_stdout 修改全局 sys.stdout，多线程并发调用时会互相覆盖输出；
#           ② 异常分支的 error/stdout 与正常分支的 result_json 未受 _MAX_OUTPUT 限制，
#           大返回值或长报错会撑爆 MCP 响应。
# 解决方案：使用模块级 _STDOUT_LOCK 串行化 stdout 重定向，并对 stdout、error 与 result 统一截断。
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
        with _STDOUT_LOCK:
            with contextlib.redirect_stdout(buf):
                compiled = compile(code, "<mda-script>", "exec")
                exec(compiled, globs)  # noqa: S102  设计如此：AI 脚本通道
                result = globs.get("result")
    except Exception as e:  # 脚本错误要完整回传给 AI 便于自纠
        err_msg = _truncate(f"{type(e).__name__}: {e}")
        return json.dumps({"error": err_msg, "stdout": _truncate(buf.getvalue())}, ensure_ascii=False)

    out = _truncate(buf.getvalue())
    try:
        result_json = json.dumps(result, ensure_ascii=False, default=str) if result is not None else None
    except Exception:
        result_json = repr(result)
    if result_json is not None:
        result_json = _truncate(result_json)
    return json.dumps({"stdout": out, "result": result_json}, ensure_ascii=False)
