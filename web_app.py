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
import threading
import time
import urllib.request
import webbrowser

from server.api import API_HOST, API_PORT, app

URL = f"http://{API_HOST}:{API_PORT}/"
HEALTH = URL + "api/health"


def _wait_ready(timeout: float = 15.0) -> bool:
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
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="warning")


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
        result = webview.windows[0].create_file_dialog(
            webview.OPEN_DIALOG,
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
        background_color="#0b0c0d",
        js_api=JsApi(),
    )

    def _on_loaded() -> None:
        # 打印一行日志：用于确认窗口真的加载了页面（而不是开了个白窗）
        print("[webview] 页面已加载：", window.get_current_url())

    window.events.loaded += _on_loaded
    webview.start()
    return True


def main() -> None:
    threading.Thread(target=_serve, daemon=True).start()
    if not _wait_ready():
        print("API 未在 15 秒内就绪，请检查端口占用：", API_PORT)
        return

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


if __name__ == "__main__":
    main()
