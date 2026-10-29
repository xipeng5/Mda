"""应用入口：启动 Web 界面（React + TS）+ 本地分析服务。

用法：
  app.py                启动界面：本地服务（127.0.0.1:8766）+ 原生窗口
  app.py --mcp-stdio    以 stdio 启动 MCP，供只支持 stdio 的 AI 客户端拉起；
                        若界面正在运行会自动代理过去，从而共享同一会话
                        （打包成 .app 后同样支持，配置里写可执行文件 + 本参数）

界面来自 web/ 的构建产物（web/dist），未构建时先执行：
  cd web && npm install && npm run build
"""
import sys


def main() -> int:
    if "--mcp-stdio" in sys.argv:
        from mcp_server.proxy import run

        return run()

    # (1) 第一次修改：新增 Web UI 入口（默认）
    #     改动原因：用户要求"UI 走 web + TS，直接 web 版本，抛弃原来的"。
    #     解决方案：入口改为启动 web_app（API + 静态托管 + 原生窗口）。
    # (2) 第二次修改：默认值从空改回 web
    #     改动原因：上一版保守地保留 Qt 为默认，与"直接 web 版本"的要求不一致。
    #     解决方案：未设 MDA_UI 时即为 web。
    # (3) 第三次修改：删除 Qt 界面分支
    #     bug 原因：ui/ 已按用户确认删除，保留 Qt 分支会在 MDA_UI=qt 时 ImportError。
    #     解决方案：入口只剩 Web；命令行多余参数给出明确提示而不是静默忽略。
    extra = [a for a in sys.argv[1:] if not a.startswith("-")]
    if extra:
        print("[MDA] Web 版暂不支持用命令行指定 so，请在界面里打开（后续补）。")

    from web_app import main as web_main

    web_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
