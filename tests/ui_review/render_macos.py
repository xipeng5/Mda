"""UI 评审取证：用**原生 macOS 样式**渲染真实主窗口（widget.grab，不依赖屏幕录制权限）。

与 render_current.py 的区别：
  - render_current.py 用 offscreen 平台（样式为默认 Fusion/offscreen，不含 macOS 原生 tab 槽等）
  - 本脚本用 cocoa 平台 + macOS 原生 style，grab() 直接把窗口渲染成 pixmap，
    从而复现用户截图里的原生控件表现（如 QTabBar 的灰色槽）。
  - 为避免副作用：MCP HTTP 服务被替换为空实现（不占 8765 端口），不调用 adb。

用法（避免命令行传参，按有效性用环境变量）：
  MDA_PROTO=current .venv/bin/python tests/ui_review/render_macos.py   # 当前态
  MDA_PROTO=fix     .venv/bin/python tests/ui_review/render_macos.py   # 应用修复
输出：docs/ui-review/ui-designer/{current,fix}-macos.png（2x -> 1x 缩放）
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "ui_review"))

OUT = os.path.join(ROOT, "docs", "ui-review", "ui-designer")
os.makedirs(OUT, exist_ok=True)
SAMPLE = os.path.join(ROOT, "samples", "libbase.so")
VARIANT = os.environ.get("MDA_PROTO", "current").strip() or "current"


def patch_services() -> None:
    """把会自动起端口/调 adb 的部分替换成空实现，保证渲染无副作用。"""
    from mcp_server import service as svc

    svc.McpService.start_http = lambda self: None
    svc.McpService.status = lambda self: "（评审渲染，MCP 未启动）"
    svc.McpService.stop = lambda self: None


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from ui.theme import STYLE

    patch_services()
    app = QApplication(sys.argv)
    qss = STYLE
    if VARIANT in ("fix", "v2"):
        from tests.ui_review.theme_v2_proto import build_qss

        qss = build_qss()
    app.setStyleSheet(qss)

    from ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1680, 980)
    win.show()
    for _ in range(5):
        app.processEvents()

    # 真实样本（不造假数据）：同步加载 + 展示一个导出函数
    name = None
    try:
        info = MainWindow._do_load(SAMPLE)
        name = info["name"]
        win.refresh_modules()
        win.show_so(name)
        so = win.session.get(name)
        fns = sorted(so.functions.values(), key=lambda f: f.addr)
        pick = next((f for f in fns if f.is_export), fns[0])
        win.show_function(name, pick.addr)
    except Exception as e:
        print("sample load failed:", e)
    for _ in range(20):
        app.processEvents()

    if VARIANT in ("fix", "v2"):
        from theme_v2_proto import apply_layout_fixes

        apply_layout_fixes(win)

    for _ in range(20):
        app.processEvents()

    shot = win.grab()
    raw = os.path.join(OUT, f"{VARIANT}-macos@2x.png")
    shot.save(raw)
    from PySide6.QtCore import QSize, Qt

    half = shot.scaled(QSize(shot.width() // 2, shot.height() // 2),
                       Qt.KeepAspectRatio, Qt.SmoothTransformation)
    png = os.path.join(OUT, f"{VARIANT}-macos.png")
    half.save(png)
    print("saved", png, "\n  2x:", raw, shot.size())

    # ---- 取证：控件几何 + 关键区域取色 ----
    from PySide6.QtGui import QColor

    from PySide6.QtWidgets import QDockWidget, QToolBar

    tb = win.findChildren(QToolBar)
    docks = {d.windowTitle(): d for d in win.findChildren(QDockWidget)}
    rep = {
        "variant": VARIANT,
        "platform": app.platformName(),
        "style": app.style().objectName(),
        "dpr": app.devicePixelRatio(),
        "qss_len": len(qss),
        "window": win.size().toTuple(),
        "toolbar_h": tb[0].height() if tb else None,
        "nav_h": win.nav.height(),
        "tabs_docmode": win.tabs.documentMode(),
        "tabbar_h": win.tabs.tabBar().height(),
        "tab_rects": [win.tabs.tabBar().tabRect(i).getRect() for i in range(win.tabs.count())],
        "left_dock_w": win.func_dock.width(),
        "right_dock_w": docks.get("模块 / 字符串").width() if docks.get("模块 / 字符串") else None,
        "bottom_dock_h": win.out_dock.height(),
        "central_h": win.centralWidget().height(),
        "table_header_h": win.func_tbl.table.horizontalHeader().height(),
        "table_row_h": win.func_tbl.table.rowHeight(0) if win.func_tbl.table.rowCount() else None,
        "disasm_row_h": win.disasm.sizeHintForRow(0),
        "fonts": {
            "disasm": (win.disasm.font().family(), win.disasm.font().pixelSize()),
            "table": (win.func_tbl.table.font().family(), win.func_tbl.table.font().pixelSize()),
            "app_pt": app.font().pointSizeF(),
        },
        "colors": {
            "page_bg": QColor("#f5f6f5").name(),
            "sample_page": QColor(shot.toImage().pixelColor(20, 400)).name(),
            "sample_tabbar": QColor(shot.toImage().pixelColor(2400, 380)).name(),
            "sample_band": QColor(shot.toImage().pixelColor(1600, 300)).name(),
        },
    }
    with open(os.path.join(OUT, f"{VARIANT}-geometry.json"), "w") as f:
        json.dump(rep, f, indent=2, ensure_ascii=False)
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
