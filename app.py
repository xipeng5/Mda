"""GUI 应用入口。

用法：
  app.py [so路径...]     启动图形界面（内置 MCP 自动监听 127.0.0.1:8765）
  app.py --mcp-stdio    以 stdio 启动 MCP，供只支持 stdio 的 AI 客户端拉起；
                        若 GUI 正在运行会自动代理过去，从而共享同一会话
                        （打包成 .app 后同样支持，配置里写可执行文件 + 本参数）
"""
import sys


def main() -> int:
    if "--mcp-stdio" in sys.argv:
        from mcp_server.proxy import run

        return run()
    from ui.main_window import run_gui

    run_gui()  # run_gui 内部 sys.exit，不会返回
    return 0


if __name__ == "__main__":
    sys.exit(main())
