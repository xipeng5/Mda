"""组件库视觉样张：用 v2 QSS 渲染各组件的默认外观（高保真设计稿的一部分）。

只渲染**真实控件**（不用图片/假图），因此样张与落地效果一致。
输出：docs/ui-review/ui-designer/component-sheet.png
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "ui_review"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication, QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget,
)

from theme_v2_proto import TOKENS as T  # noqa: E402
from theme_v2_proto import build_qss  # noqa: E402

OUT = os.path.join(ROOT, "docs", "ui-review", "ui-designer")


def _caption(text: str, hint: str = "") -> QLabel:
    lab = QLabel(text)
    lab.setStyleSheet(
        f"color:{T['text3']};font-size:{T['fs_micro']}px;font-weight:600;"
        f"font-family:{T['font_ui']};background:transparent;"
    )
    lab.setToolTip(hint)
    return lab


def _card(title: str, body: QWidget) -> QFrame:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(12, 10, 12, 12)
    lay.setSpacing(8)
    lay.addWidget(_caption(title))
    lay.addWidget(body)
    lay.addStretch(1)
    return f


def buttons() -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(8)
    b1 = QPushButton("默认")
    b1.setAutoDefault(False)
    b2 = QPushButton("主要动作")
    b2.setObjectName("primary")
    b3 = QPushButton("禁用")
    b3.setEnabled(False)
    for b in (b1, b2, b3):
        lay.addWidget(b)
    lay.addStretch(1)
    return w


def inputs() -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(8)
    e = QLineEdit()
    e.setPlaceholderText("过滤…（输入即时过滤）")
    f = QLineEdit("0x5020")
    f.setFocus()
    c = QComboBox()
    c.addItems(["libbase.so", "liblog.so"])
    lay.addWidget(e)
    lay.addWidget(f)
    lay.addWidget(c)
    return w


def tabs() -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    t = QTabWidget()
    t.setDocumentMode(True)
    for name in ("反汇编", "伪代码", "Hex", "导入", "导出", "交叉引用"):
        t.addTab(QLabel(f"  {name} 视图  "), name)
    lay.addWidget(t)
    return w


def table() -> QWidget:
    t = QTableWidget(4, 3)
    t.setHorizontalHeaderLabels(["函数", "地址", "来源"])
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
    t.setColumnWidth(1, 92)
    t.setColumnWidth(2, 56)
    rows = [
        ("sub_12000", "0x12000", "fde", T["func"]),
        ("JNI_OnLoad", "0x12020", "export", T["export"]),
        ("__android_log_print", "0x12110", "plt", T["import"]),
        ("ro.build.version", "0xb362", "string", T["string"]),
    ]
    for r, (name, addr, src, color) in enumerate(rows):
        a = QTableWidgetItem(name)
        a.setForeground(QColor(color))
        b = QTableWidgetItem(addr)
        b.setForeground(QColor(T["addr"]))
        b.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        c = QTableWidgetItem(src)
        c.setForeground(QColor(T["text3"]))
        t.setItem(r, 0, a)
        t.setItem(r, 1, b)
        t.setItem(r, 2, c)
    t.selectRow(1)
    t.setFixedHeight(140)
    return t


def badges() -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    for text, fg, bg in (
        ("FDE", T["text2"], T["sunken"]),
        ("导出", T["export"], T["accent_soft"]),
        ("PLT", T["import"], T["warn_soft"]),
        ("字符串", T["string"], T["ok_soft"]),
        ("风险", T["danger"], T["danger_soft"]),
    ):
        lab = QLabel(text)
        lab.setStyleSheet(
            f"color:{fg};background:{bg};border-radius:{T['r_small']}px;"
            f"padding:2px 6px;font-size:{T['fs_micro']}px;font-weight:600;"
        )
        lay.addWidget(lab)
    lay.addStretch(1)
    return w


def empty_state() -> QWidget:
    f = QFrame()
    f.setObjectName("card-flat")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 18, 16, 18)
    lay.setSpacing(4)
    t1 = QLabel("还没有加载 so 文件")
    t1.setStyleSheet(f"color:{T['text1']};font-size:{T['fs_title']}px;font-weight:600;background:transparent;")
    t2 = QLabel("拖入 .so 或按 ⌘O 打开；加载后这里显示函数、字符串与交叉引用。")
    t2.setStyleSheet(f"color:{T['text3']};font-size:{T['fs_micro']}px;background:transparent;")
    t2.setWordWrap(True)
    for lab in (t1, t2):
        lay.addWidget(lab)
    return f


def statusbar() -> QWidget:
    f = QFrame()
    f.setObjectName("card-flat")
    lay = QHBoxLayout(f)
    lay.setContentsMargins(10, 6, 10, 6)
    left = QLabel("libbase.so 已加载  ·  386 函数")
    left.setStyleSheet(f"color:{T['text3']};font-size:{T['fs_micro']}px;background:transparent;")
    right = QLabel("0x12020   ·   MCP 127.0.0.1:8765")
    right.setStyleSheet(
        f"color:{T['text2']};font-size:{T['fs_micro']}px;background:transparent;"
        f"font-family:{T['font_mono']};"
    )
    lay.addWidget(left)
    lay.addStretch(1)
    lay.addWidget(right)
    return f


def navband() -> QWidget:
    from ui.nav_band import NavBand

    import theme_v2_proto as proto

    for k, v in proto.BAND_COLORS.items():
        import ui.nav_band as nb

        nb._BAND_COLORS[k] = QColor(v)
    n = NavBand()
    n.setFixedHeight(8)
    n.set_ranges([(0, 6000, "code"), (6000, 8000, "data"), (8000, 9000, "string"),
                  (9000, 12000, "code"), (12000, 20000, "unmapped")])
    n.set_cursor(7000)
    return n


def main() -> int:
    app = QApplication([])
    qss = build_qss().replace(
        "QMainWindow, QDialog {{ background: {bg}; }}", ""
    )
    app.setStyleSheet(qss + "\n#sheetRoot {{ background: #f3f5f4; }}")

    root = QWidget()
    root.setObjectName("sheetRoot")
    grid = QGridLayout(root)
    grid.setContentsMargins(16, 16, 16, 16)
    grid.setSpacing(12)

    grid.addWidget(_card("按钮 · 默认 / 主要 / 禁用", buttons()), 0, 0)
    grid.addWidget(_card("输入 · 常规 / 聚焦 / 下拉", inputs()), 0, 1)
    grid.addWidget(_card("状态徽章 · 4 类 + 风险", badges()), 0, 2)
    grid.addWidget(_card("标签页 · 下划线式（选中 = 2px accent 线）", tabs()), 1, 0, 1, 2)
    grid.addWidget(_card("导航缩略图 · 8px 中性色（当前位 = 竖线）", navband()), 1, 2)
    grid.addWidget(_card("数据表 · 三列 + 类型着色 + 地址右对齐", table()), 2, 0)
    grid.addWidget(_card("空状态 · 主标题 + 一行指引", empty_state()), 2, 1)
    grid.addWidget(_card("状态栏 · 左信息 / 右等宽定位", statusbar()), 2, 2)
    root.resize(1120, 620)
    root.show()
    for _ in range(10):
        app.processEvents()
    pm = root.grab()
    png = os.path.join(OUT, "component-sheet.png")
    pm.save(png)
    print("saved", png, pm.size())
    return 0


if __name__ == "__main__":
    sys.exit(main())
