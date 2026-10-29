"""UI 评审用取证脚本：离屏渲染当前主窗口，输出 PNG 供设计诊断。

用途（只读诊断，不改业务逻辑）：
  - 以真实代码（ui/theme.py 的 STYLE + ui/main_window.py 的布局）离屏渲染，
    避免依赖 macOS 截屏权限，也避免与正在运行的实例抢 8765 端口。
  - 输出：当前态截图 + 关键控件几何/颜色采样数据。

用法： .venv/bin/python tests/ui_review/render_current.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

OUT = os.path.join(ROOT, "docs", "ui-review", "ui-designer")
sys.path.insert(0, os.path.join(ROOT, "tests", "ui_review"))
VARIANT = os.environ.get("MDA_PROTO", "current").strip() or "current"
os.makedirs(OUT, exist_ok=True)

SAMPLE = os.path.join(ROOT, "samples", "libbase.so")


def main() -> int:
    from ui.theme import STYLE
    from ui.main_window import MainWindow

    qss = STYLE
    fix = None
    if VARIANT == "fix":
        from theme_v2_proto import apply_layout_fixes, build_qss

        qss, fix = build_qss(), apply_layout_fixes

    app = QApplication([])
    app.setStyleSheet(qss)
    win = MainWindow()
    win.resize(1680, 980)
    win.show()
    app.processEvents()

    # 同步加载样本（绕开 Worker 线程，保证渲染时数据已就绪）
    try:
        info = MainWindow._do_load(SAMPLE)
        win.refresh_modules()
        win.show_so(info["name"])
        so = win.session.get(info["name"])
        fns = sorted(so.functions.values(), key=lambda f: f.addr)
        pick = next((f for f in fns if f.is_export), fns[0])
        win.show_function(info["name"], pick.addr)
    except Exception as e:  # 样本加载失败也要能出图
        print("sample load failed:", e)
    for _ in range(30):
        app.processEvents()

    if fix is not None:
        fix(win)
        for _ in range(10):
            app.processEvents()

    # ---- 截图 ----
    shot = win.grab()
    png = os.path.join(OUT, f"{VARIANT}-offscreen.png")
    shot.save(png)
    print("saved", png, shot.size())

    # ---- 几何与颜色取证 ----
    def geo(w):
        g = w.geometry()
        return {"x": g.x(), "y": g.y(), "w": g.width(), "h": g.height(),
                "visible": w.isVisible(), "fg": w.frameGeometry().getRect()}

    from PySide6.QtWidgets import QDockWidget, QFrame, QToolBar

    report = {
        "dpr": app.devicePixelRatio(),
        "font": {"app": app.font().family(), "size": app.font().pointSizeF()},
        "window": geo(win),
    }
    # 逐控件量测（用真实控件引用，比 findChild 可靠）
    items = {
        "central": win.centralWidget(),
        "card": win.centralWidget().findChild(QFrame, "card"),
        "nav": win.nav,
        "tabs": win.tabs,
        "func_dock": win.func_dock,
        "func_tbl": win.func_tbl,
        "module_tree": win.module_tree,
        "str_tbl": win.str_tbl,
        "out_dock": win.out_dock,
        "dynamic": win.dynamic,
        "status": win.statusBar(),
    }
    for name, w in items.items():
        if w is not None:
            report[name] = geo(w)

    tb = win.findChildren(QToolBar)
    report["toolbars"] = [geo(t) for t in tb]
    report["toolbar_actions"] = [a.text() for a in (tb[0].actions() if tb else [])]
    report["toolbar_widget_geos"] = [
        {"type": type(c).__name__, "text": getattr(c, "text", lambda: "")(),
         "geo": geo(c)}
        for c in (tb[0].children() if tb else [])
        if hasattr(c, "geometry") and c.isWidgetType()
    ]
    report["dock_areas"] = {d.windowTitle(): str(win.dockWidgetArea(d))
                           for d in win.findChildren(QDockWidget)}
    report["tabbar"] = {"h": win.tabs.tabBar().height(),
                        "rects": [win.tabs.tabBar().tabRect(i).getRect() for i in range(win.tabs.count())]}
    report["header_h"] = win.func_tbl.table.horizontalHeader().height()
    report["row_h"] = win.func_tbl.table.rowHeight(0) if win.func_tbl.table.rowCount() else None
    report["disasm_row_h"] = win.disasm.sizeHintForRow(0)
    report["disasm_font"] = {"family": win.disasm.font().family(), "px": win.disasm.font().pixelSize(),
                             "pt": win.disasm.font().pointSizeF()}
    report["table_font"] = {"family": win.func_tbl.table.font().family(),
                            "px": win.func_tbl.table.font().pixelSize(),
                            "pt": win.func_tbl.table.font().pointSizeF()}
    with open(os.path.join(OUT, f"{VARIANT}-offscreen-geometry.json"), "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False)[:3000])

    # 停服务，避免残留 8765 端口；等后台线程收尾再退出
    try:
        win._shutdown_services()
    except Exception:
        pass
    for _ in range(400):
        app.processEvents()
        if not [w for w in win._workers if w.isRunning()]:
            break
        __import__("time").sleep(0.02)
    QTimer.singleShot(0, app.quit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
