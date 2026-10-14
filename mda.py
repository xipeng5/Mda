"""mda 命令行入口。

用法：
  mda mcp                     启动 MCP 服务（优先代理到运行中的 GUI，实现人机同会话）
  mda analyze <so...>         静态分析并打印概况（自检用）
  mda chain <so> <addr>       打印跨 so 调用链
"""
from __future__ import annotations

import sys


def _cmd_mcp(_args: list[str]) -> int:
    """启动 MCP 服务。

    优先代理到运行中的 GUI（AI 操作可视化 + 共享同一分析会话）；
    GUI 未运行时降级为内置 stdio 服务（离线可用，界面不同步）。
    """
    from mcp_server.proxy import run

    return run()


def _cmd_analyze(args: list[str]) -> int:
    from core.session import Session

    s = Session()
    for p in args:
        so = s.add(p)
        x = s.ensure_xrefs(so.name)
        strs = s.strings(so.name)
        print(f"{so.name}: arch={so.arch.name} 函数={len(so.functions)} "
              f"导出={len(so.exports)} 导入={len(so.imports)} "
              f"调用边={sum(len(v) for v in x.calls_to.values())} 字符串={len(strs.all_strings())}")
    return 0


def _cmd_chain(args: list[str]) -> int:
    if len(args) < 2:
        print("用法: mda chain <so路径...> <函数名或0x地址>")
        return 2
    addr = int(args[-1], 0)
    from core.session import Session

    s = Session()
    for p in args[:-1]:
        s.add(p)
    so_name = args[-2].rsplit("/", 1)[-1]
    print(s.call_chain(so_name, addr, depth=4).as_text())
    return 0


_COMMANDS = {
    "mcp": _cmd_mcp,
    "analyze": _cmd_analyze,
    "chain": _cmd_chain,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in _COMMANDS:
        print(__doc__)
        return 2
    return _COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
