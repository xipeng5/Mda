"""MDA Web 版一键启动：起 API（同时托管前端构建产物）+ 打开窗口。

启动优先级：
  1. 装了 pywebview → 原生窗口（macOS 上是系统 WKWebView，不打包 Chromium）
  2. 没装 → 直接用系统默认浏览器打开（不报错、不阻塞）

用法（项目规范：不接命令行参数）：
    .venv/bin/python web_app.py

前提：先构建前端
    cd web && npm run build
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
import webbrowser

from server.api import API_HOST, API_PORT, app

# 加缓存破坏参数：pywebview 会缓存页面，改了前端不重启窗口看不到变化。
# 用静态索引文件的 mtime 当版本号，内容变了 URL 就变，浏览器必然重新拉。
import os as _os
import time as _time

# (1) 第一次修改（2026-11-13）：
#     bug 原因：本文件从仓库根目录移到了 server/ 下，而这一行仍按
#               「本文件所在目录 / web/dist」拼路径，移动后指向 server/web/dist，
#               前端产物根本不存在 → 窗口打不开。
#     解决方案：往上退一级再拼（server/ → 仓库根）。
_dist_dir = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "web", "dist"
)

def _dist_version() -> int:
    """dist 里最新文件的 mtime —— 任何产物变了都会变，避免旧缓存。"""
    newest = 0.0
    for root, _dirs, files in _os.walk(_dist_dir):
        for f in files:
            try:
                newest = max(newest, _os.path.getmtime(_os.path.join(root, f)))
            except OSError:
                pass
    return int(newest) if newest else int(_time.time())

_ver = _dist_version()
# (2) 第二次修改（2026-11-26）
# bug 原因：① URL 硬编码 localhost 而 HEALTH 用 API_HOST，导致 API_HOST=127.0.0.1 时两者主机名错配，
#              API_HOST=0.0.0.0 时 HEALTH 指向 0.0.0.0 无法探测；
#           ② _serve 使用 uvicorn.run() 无法在窗口关闭时优雅停机（lifespan 不执行、MCP 端口残留）；
#           ③ pick_so 使用已弃用的 webview.OPEN_DIALOG；
#           ④ webview.start() 仅在 private_mode=True 时传参，因 pywebview 默认值为 True，
#              导致 MDA_WEB_PRIVATE=0 完全无效。
# 解决方案：① 统一用 _CLIENT_HOST（0.0.0.0/:: 时归为 127.0.0.1）拼 URL 与 HEALTH；
#           ② 持有 uvicorn.Server 实例，退出时置 should_exit=True 并 join 等待优雅停机；
#           ③ 优先用 webview.FileDialog.OPEN 并向后回退 webview.OPEN_DIALOG；
#           ④ 显式传递 private_mode=bool(...)。
_CLIENT_HOST = "127.0.0.1" if API_HOST in ("0.0.0.0", "::", "") else API_HOST
# 每次启动都用唯一 URL：同一进程内 _ver 不变，WKWebView 会把整个文档
# （含服务端内联的 __MDA_BOOT__）缓存住，后端后加的模块就进不去。
URL = f"http://{_CLIENT_HOST}:{API_PORT}/?v={_ver}.{int(_time.time() * 1000)}&theme=light"
# 健康检查必须用**不带查询参数**的基础地址。
# 之前这里写成 URL + "api/health"，而 URL 带 ?v=...，拼出来是无效地址，
# 返回 index.html → 永远判定"未就绪"。
HEALTH = f"http://{_CLIENT_HOST}:{API_PORT}/api/health"
_uvicorn_server = None


def _wait_ready(timeout: float = 45.0) -> bool:
    """等 API 真正起来再开窗口，避免打开一个 404 页面。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH, timeout=0.5) as r:
                if json.loads(r.read().decode("utf-8")).get("ok"):
                    return True
        except Exception:                      # noqa: BLE001 - 未就绪继续等
            pass
        time.sleep(0.25)
    return False


def _serve() -> None:
    """在后台线程里跑 uvicorn.Server（持有实例以支持优雅停机）。

    失败必须打出来：线程里的异常默认被吞掉，主线程只会看到
    「未就绪」，根本不知道真实原因（端口占用、导入失败、权限……）。
    """
    global _uvicorn_server
    import traceback

    try:
        print("[API] _serve 线程已启动，准备 uvicorn.Server", flush=True)
        import uvicorn

        config = uvicorn.Config(app, host=API_HOST, port=API_PORT, log_level="info")
        server = uvicorn.Server(config)
        # 后台线程不能注册主线程信号处理器，停机由主线程显式置 should_exit=True 触发
        server.install_signal_handlers = lambda: None
        _uvicorn_server = server
        server.run()
    except Exception:                                  # noqa: BLE001
        print("[API] 启动失败，真实原因如下：")
        traceback.print_exc()


def _shutdown_server(srv_thread: threading.Thread, timeout: float = 5.0) -> None:
    """通知后台 uvicorn 优雅退出并等待线程结束，确保 lifespan 正常清理 MCP 与后台任务。"""
    srv = _uvicorn_server
    if srv is not None:
        srv.should_exit = True
    if srv_thread.is_alive():
        srv_thread.join(timeout=timeout)


class JsApi:
    """暴露给前端的原生能力（目前只有文件选择）。

    为什么放在窗口壳里而不是 HTTP：macOS 的文件对话框必须在主线程弹，
    后端 API 跑在 uvicorn 线程里，只能由 pywebview 的 js_api 桥接。
    """

    def copy_text(self, text: str) -> bool:
        """把文本写入系统剪贴板。

        为什么不用浏览器 API：WKWebView 里 navigator.clipboard 常被拒，
        execCommand("copy") 在非用户手势链路里也失败，用户实测"复制失败"。
        macOS 直接写 NSPasteboard 最可靠（pyobjc 随 pywebview 一起装好）。
        """
        try:
            from AppKit import NSPasteboard, NSPasteboardTypeString

            pb = NSPasteboard.generalPasteboard()
            pb.clearContents()
            return bool(pb.setString_forType_(text, NSPasteboardTypeString))
        except Exception:                       # noqa: BLE001 - 非 macOS 或没 pyobjc
            return False

    def pick_so(self) -> str:
        """弹出系统文件对话框，返回选中的绝对路径；取消返回空串。"""
        import webview

        if not webview.windows:
            return ""
        file_dialog = getattr(webview, "FileDialog", None)
        open_mode = (
            getattr(file_dialog, "OPEN", None)
            if file_dialog is not None
            else getattr(webview, "OPEN_DIALOG", 10)
        )
        result = webview.windows[0].create_file_dialog(
            open_mode,
            allow_multiple=False,
            file_types=("Shared library (*.so)", "ELF (*.elf)", "All files (*.*)"),
        )
        return result[0] if result else ""


def _open_window() -> bool:
    """有 pywebview 就用原生窗口；没有则返回 False 由调用方退回浏览器。"""
    try:
        import webview                        # type: ignore[import-not-found]
    except ImportError:
        return False
    window = webview.create_window(
        "MDA — Multi-so Disassembly Analyzer",
        URL,
        width=1500,
        height=940,
        background_color="#f4f5f5",
        js_api=JsApi(),
    )

    def _on_loaded() -> None:
        # 打印一行日志：用于确认窗口真的加载了页面（而不是开了个白窗）
        print("[webview] 页面已加载：", window.get_current_url())

    window.events.loaded += _on_loaded
    # 显式传递 private_mode=bool(...)：pywebview >= 4 默认 private_mode=True，
    # 不显式传 False 会导致 MDA_WEB_PRIVATE=0 无法生效。
    private_mode = os.environ.get("MDA_WEB_PRIVATE", "0") == "1"
    webview.start(private_mode=bool(private_mode))
    return True


def main() -> None:
    srv_thread = threading.Thread(target=_serve, daemon=True)
    srv_thread.start()
    try:
        if not _wait_ready():
            # 不 return：uvicorn 可能只是慢（MCP/插件初始化很重）。
            # 真起不来时窗口里会显示连不上，比静默退出更容易排查。
            print("API 在 45 秒内未就绪，仍尝试开窗口：", API_PORT,
                  "| 健康检查地址:", HEALTH, flush=True)

        if _open_window():
            return
        print(f"未安装 pywebview，用默认浏览器打开：{URL}")
        webbrowser.open(URL)
        # 浏览器模式下进程常驻，Ctrl+C 结束
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    finally:
        _shutdown_server(srv_thread)


if __name__ == "__main__":
    main()
