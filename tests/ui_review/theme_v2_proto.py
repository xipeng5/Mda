"""MDA UI 视觉系统 v2 —— 评审用「高保真设计稿」的可执行版本（提案，不改业务逻辑）。

本文件是 `ui/theme.py` 的直接替换提案：
  build_qss()           -> 与 ui/theme.py 的 STYLE 同构的 QSS 字符串（纯样式，无逻辑）
  TOKENS                -> 设计 token（颜色/字号/间距/圆角/高度），落地到 QSS 或代码常量
  apply_layout_fixes()  -> 与样式解耦的**最小布局/几何调整**（原型验证用；
                           正式落地时对应 ui/main_window.py 的几行改动，见评审文档）

约束：只用 QSS 支持的属性子集（无 box-shadow / flex / gap / letter-spacing）。
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# 1) Token 层
# ---------------------------------------------------------------------------
TOKENS = {
    # 中性色（冷灰略偏绿，与 teal 同源但彩度极低，避免"五颜六色"）
    "bg_app": "#f3f5f4",
    "surface": "#ffffff",
    "sunken": "#f7f9f8",
    "hover": "#f0f4f2",
    "border": "#dfe4e2",
    "border_strong": "#c9d2cf",
    "divider": "#edf0ee",
    # 文本（全部对白底 >= 4.5:1）
    "text1": "#1b201e",     # 15.3:1
    "text2": "#4f5a56",     # 7.2:1
    "text3": "#6b7571",     # 4.6:1
    "text_disabled": "#a6afab",
    # 强调色：teal 只做"一个"强调用途
    "accent": "#0e8f83",        # 填充/图标（白字对比 3.98，仅用于 >=14px 粗体或非文字）
    "accent_fill": "#0b7c72",   # 主按钮填充（白字 5.07:1）
    "accent_text": "#0a6e65",   # 小字号强调文本（6.1:1）
    "accent_soft": "#e8f2ef",   # 选中底
    "accent_line": "#12a898",   # 焦点环 / 当前项标条
    # 语义色（均 >=4.5:1，替代原来 2.1~2.5:1 的 emerald/amber）
    "ok": "#0f7a53",
    "ok_soft": "#e9f6ef",
    "warn": "#8a5a00",
    "warn_soft": "#fdf4e3",
    "danger": "#b3261e",
    "danger_soft": "#fdecea",
    # 数据类型色（反汇编/表格分段着色，全部 >=4.5:1）
    "addr": "#2c6bb0",      # 5.5:1
    "string": "#0b6b4a",    # 6.5:1
    "import": "#8a5300",    # 6.3:1
    "func": "#1b201e",
    "export": "#0a6e65",
    "note": "#6b7571",
    # 导航色带（中性为主，只保留一个强调标记）
    "band_unmapped": "#edf1f0",
    "band_data": "#dde4e2",
    "band_code": "#c9d8d4",
    "band_string": "#d9cfae",
    "band_func": "#0e8f83",
    # 尺寸（px）
    "r_panel": 8,
    "r_control": 6,
    "r_small": 4,
    "h_control": 26,
    "h_panel_title": 30,
    "h_tab": 30,
    "h_status": 24,
    "row_table": 24,
    "row_table_header": 26,
    "row_disasm": 22,
    # 字号
    "fs_micro": 11,
    "fs_body": 12,
    "fs_title": 13,
    "font_mono": "Menlo, SF Mono, Consolas, monospace",
    "font_ui": "-apple-system, 'PingFang SC', 'Helvetica Neue', sans-serif",
}

T = TOKENS
FONT_MONO = T["font_mono"]

# 供其它模块引用（保持与旧 theme.py 同名，便于最小改动替换）
C_PRIMARY = T["accent_fill"]
C_PRIMARY_DIM = T["accent_text"]
C_PRIMARY_SOFT = T["accent_soft"]
C_BG = T["bg_app"]
C_CARD = T["surface"]
C_BORDER = T["border"]
C_FG = T["text1"]
C_MUTED = T["text2"]
C_FAINT = T["text3"]
C_OK = T["ok"]
C_WARN = T["warn"]
C_DEAD = T["danger"]
C_ADDR = T["addr"]
C_FUNC = T["func"]
C_EXPORT = T["export"]
C_STR = T["string"]
C_IMPORT = T["import"]
C_NOTE = T["note"]
C_SELECT = T["accent_soft"]
RADIUS = T["r_panel"]
RADIUS_SM = T["r_control"]

# 导航色带新配色（ui/nav_band.py 的 _BAND_COLORS 替换值）
BAND_COLORS = {
    "code": T["band_code"],
    "func": T["band_func"],
    "data": T["band_data"],
    "string": T["band_string"],
    "import": T["band_data"],
    "unmapped": T["band_unmapped"],
}


# ---------------------------------------------------------------------------
# 2) QSS
# ---------------------------------------------------------------------------
def build_qss() -> str:
    return f"""
/* ===== 基础 ===== */
QMainWindow, QDialog {{ background: {T['bg_app']}; }}
QWidget {{
    background: transparent;
    color: {T['text1']};
    font-family: {T['font_ui']};
    font-size: {T['fs_body']}px;
}}
QLabel {{ background: transparent; }}
QToolTip {{
    background: #ffffff; color: {T['text1']};
    border: 1px solid {T['border_strong']}; border-radius: {T['r_small']}px;
    padding: 4px 6px; font-size: {T['fs_micro']}px;
}}

/* ===== 面板（卡片 / 停靠窗），唯一的高程语言：1px 边框 + 8px 圆角 ===== */
QFrame#card, QFrame#card-flat {{
    background: {T['surface']};
    border: 1px solid {T['border']};
    border-radius: {T['r_panel']}px;
}}
QDockWidget {{
    background: {T['surface']};
    border: 1px solid {T['border']};
    border-radius: {T['r_panel']}px;
    color: {T['text2']};
    font-size: {T['fs_micro']}px;
    font-weight: 600;
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}
QDockWidget::title {{
    background: {T['surface']};
    border-bottom: 1px solid {T['divider']};
    border-top-left-radius: {T['r_panel']}px;
    border-top-right-radius: {T['r_panel']}px;
    padding: 0 8px;
    min-height: {T['h_panel_title'] - 1}px;
    text-align: left;
}}
QDockWidget > QWidget {{ background: {T['surface']}; }}

/* ===== 工具栏：不是卡片，是一条 40px 的应用栏 ===== */
QToolBar {{
    background: {T['surface']};
    border: none;
    border-bottom: 1px solid {T['border']};
    spacing: 4px; padding: 6px 10px;
}}
QToolBar::separator {{
    background: {T['divider']}; width: 1px; margin: 8px 6px;
}}
QToolButton {{
    background: transparent; border: 1px solid transparent;
    border-radius: {T['r_control']}px; padding: 4px 8px;
    color: {T['text1']}; font-weight: 500;
    min-height: 20px;
}}
QToolButton:hover {{ background: {T['hover']}; }}
QToolButton:pressed {{ background: {T['accent_soft']}; color: {T['accent_text']}; }}
QToolButton:checked {{ background: {T['accent_soft']}; color: {T['accent_text']}; }}

/* ===== 标签页：IDE 式下划线，彻底摆脱 macOS 原生灰槽 ===== */
QTabWidget::pane {{ border: none; background: transparent; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: {T['text2']};
    padding: 6px 12px;
    min-height: {T['h_tab'] - 14}px;
    margin-right: 2px;
    font-weight: 500;
}}
QTabBar::tab:hover {{ color: {T['text1']}; background: {T['hover']}; }}
QTabBar::tab:selected {{
    color: {T['text1']}; font-weight: 600;
    border-bottom: 2px solid {T['accent_line']};
    background: transparent;
}}

/* ===== 数据视图 ===== */
QTreeView, QListView, QTableView, QPlainTextEdit, QTextEdit {{
    background: {T['surface']};
    border: none;
    color: {T['text1']};
    font-family: {FONT_MONO};
    font-size: {T['fs_body']}px;
    selection-background-color: {T['accent_soft']};
    selection-color: {T['text1']};
    outline: none;
}}
QTableView, QTreeView {{ alternate-background-color: transparent; gridline-color: {T['divider']}; }}
QTreeView::item, QListView::item, QTableView::item {{
    min-height: {T['row_table']}px;
    border: none;
    padding: 0 6px;
}}
QTableView::item:hover, QTreeView::item:hover, QListView::item:hover {{
    background: {T['hover']};
}}
QHeaderView {{ background: {T['sunken']}; }}
QHeaderView::section {{
    background: {T['sunken']};
    color: {T['text3']};
    border: none;
    border-bottom: 1px solid {T['border']};
    padding: 0 6px;
    min-height: {T['row_table_header'] - 1}px;
    font-size: {T['fs_micro']}px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {T['sunken']}; border: none; }}

/* ===== 输入 ===== */
QLineEdit, QComboBox, QSpinBox {{
    background: {T['sunken']};
    border: 1px solid {T['border']};
    border-radius: {T['r_control']}px;
    padding: 3px 8px;
    min-height: {T['h_control'] - 10}px;
    color: {T['text1']};
    selection-background-color: {T['accent_soft']};
    selection-color: {T['text1']};
}}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{ border-color: {T['border_strong']}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
    background: {T['surface']}; border-color: {T['accent']};
}}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox::down-arrow {{ image: none; border: none; }}
QComboBox QAbstractItemView {{
    background: {T['surface']}; border: 1px solid {T['border_strong']};
    border-radius: {T['r_control']}px; padding: 4px;
    selection-background-color: {T['accent_soft']}; selection-color: {T['text1']};
}}

/* ===== 按钮 ===== */
QPushButton {{
    background: {T['surface']};
    border: 1px solid {T['border']};
    border-radius: {T['r_control']}px;
    padding: 4px 12px;
    min-height: {T['h_control'] - 10}px;
    color: {T['text1']}; font-weight: 500;
}}
QPushButton:hover {{ background: {T['hover']}; border-color: {T['border_strong']}; }}
QPushButton:pressed {{ background: {T['sunken']}; }}
/* 注意：macOS 上 QPushButton 默认 autoDefault=true，`:default` 会命中多个按钮，
   所以主按钮用 objectName="primary"，不要用 :default 选择器。 */
QPushButton#primary {{
    background: {T['accent_fill']}; border-color: {T['accent_fill']}; color: #ffffff;
}}
QPushButton#primary:hover {{
    background: {T['accent_text']}; border-color: {T['accent_text']};
}}
QPushButton[state="focus"] {{
    background: {T['surface']}; border-color: {T['accent']};
}}
QPushButton:disabled {{ color: {T['text_disabled']}; background: {T['sunken']}; border-color: {T['divider']}; }}

/* ===== 菜单 ===== */
QMenu, QMenuBar {{
    background: {T['surface']}; border: 1px solid {T['border']};
    border-radius: {T['r_control']}px; padding: 4px;
}}
QMenuBar {{ border: none; border-bottom: 1px solid {T['border']}; border-radius: 0; }}
QMenu::item {{ border-radius: {T['r_small']}px; padding: 5px 18px; }}
QMenu::item:selected {{ background: {T['accent_soft']}; color: {T['accent_text']}; }}
QMenu::separator {{ height: 1px; background: {T['divider']}; margin: 4px 8px; }}

/* ===== 状态栏：一条 24px 的信息条 ===== */
QStatusBar {{
    background: {T['surface']};
    border-top: 1px solid {T['border']};
    color: {T['text3']};
    font-size: {T['fs_micro']}px;
    min-height: {T['h_status']}px;
}}
QStatusBar::item {{ border: none; }}
QStatusBar QLabel {{ color: {T['text3']}; padding: 0 8px; }}

/* ===== 滚动条 ===== */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {T['border_strong']}; min-height: 28px; border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{ background: {T['accent']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {T['border_strong']}; min-width: 28px; border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{ background: {T['accent']}; }}

QSplitter::handle {{ background: transparent; width: 6px; height: 6px; }}
QSplitter::handle:hover {{ background: {T['accent_soft']}; }}
"""


# ---------------------------------------------------------------------------
# 3) 最小布局/几何调整（原型验证；正式落地为 main_window.py 的少量改动）
# ---------------------------------------------------------------------------
def apply_layout_fixes(win) -> None:
    """把"样式"与"布局"分开：这里只动几何/结构，不碰业务逻辑。"""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDockWidget, QFrame, QToolBar

    import ui.nav_band as nb

    # (1) 导航色带：36px 高饱和色块 -> 8px 中性缩略图（配色见 BAND_COLORS）
    for k, v in BAND_COLORS.items():
        nb._BAND_COLORS[k] = __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(v)
    win.nav.setFixedHeight(8)

    # (2) 卡片内边距：内容不再顶到 8px 圆角上（原 card_lay margins=0）
    card = win.centralWidget().findChild(QFrame, "card")
    if card and card.layout():
        card.layout().setContentsMargins(8, 8, 8, 8)
        card.layout().setSpacing(6)

    # (3) 标签页：macOS 的 QMacStyle 在 documentMode=False 时会把 tab 居中
    #     (SH_TabBar_Alignment=AlignCenter)，所以保留 documentMode=True 以保持左对齐；
    #     灰槽由 QSS 里显式的 QTabBar { background: transparent } 消除。
    import os as _os
    _doc = _os.environ.get("MDA_DOCMODE", "1") != "0"
    win.tabs.setDocumentMode(_doc)
    win.tabs.tabBar().setDrawBase(False)
    win.tabs.tabBar().setExpanding(False)

    # (4) 停靠窗：宽度给够，表格三列不再被裁；内容加 6px 内边距
    for dock in win.findChildren(QDockWidget):
        body = dock.widget()
        if body is not None and body.layout() is not None:
            body.layout().setContentsMargins(6, 6, 6, 6)
            body.layout().setSpacing(4)
    win.func_dock.setMinimumWidth(300)
    win.dockWidgetArea  # 保持引用，无副作用

    # (5) 左表：地址列右对齐 + 收窄；来源列固定窄（避免表头被裁成"来"）
    t = win.func_tbl.table
    t.horizontalHeader().setMinimumSectionSize(56)
    t.setColumnWidth(1, 92)
    t.setColumnWidth(2, 56)
    for r in range(t.rowCount()):
        it = t.item(r, 1)
        if it is not None:
            it.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    s = win.str_tbl.table
    s.horizontalHeader().setMinimumSectionSize(56)
    s.setColumnWidth(1, 92)
    s.setColumnWidth(2, 56)

    # (6) 底部日志：从 358px 收到 200px（信息密度让给主视图）
    win.resizeDocks([win.out_dock], [200], Qt.Vertical)

    # (7) 反汇编/伪代码行委托：选中底色由 palette 外浅蓝 #cde8ff 改为主题 accent_soft
    _patch_rail_delegate(win)

    # (8) 工具栏：去掉 emoji 图标（保留文字），统一为纯文字应用栏
    tb = win.findChildren(QToolBar)
    if tb:
        for act in tb[0].actions():
            txt = act.text()
            if txt[:1] in "📂⛓📋⟳●↻":
                act.setText(txt[1:].lstrip())


def _patch_rail_delegate(win) -> None:
    """用 token 配色重绘行（对应正式改动：ui/disasm_view.py:60-100 的颜色常量）。

    RailDelegate.paint() 里硬编码了选中色 #cde8ff 与斑马色 #fafbfa，
    与 teal 主题不同源；这里在原型中替换为委托子类，验证视觉一致性。
    正式落地建议：把这两个颜色提到 ui/theme.py 的 token（C_SELECT / C_ROW_ALT）。
    """
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QColor, QFontMetricsF, QPainter
    from PySide6.QtWidgets import QStyle, QStyledItemDelegate

    from ui.disasm_view import ROLE_RAIL, ROLE_SEG

    sel_bg = QColor(T["accent_soft"])
    sel_rail = QColor(T["accent_line"])
    row_text = QColor(T["text1"])

    class _ThemedDelegate(QStyledItemDelegate):
        RAIL_W = 3
        PAD = 8

        def __init__(self, view):
            super().__init__(view)
            self.view = view

        def paint(self, painter, option, index) -> None:
            segs = index.data(ROLE_SEG)
            p = painter
            p.save()
            rect = option.rect
            selected = bool(option.state & QStyle.State_Selected)
            hovered = bool(option.state & QStyle.State_MouseOver)
            if selected:
                p.fillRect(rect, sel_bg)
            elif hovered:
                p.fillRect(rect, QColor(T["hover"]))
            rail = index.data(ROLE_RAIL)
            if rail:
                p.fillRect(rect.x(), rect.y(), self.RAIL_W, rect.height(), QColor(rail))
            if selected:
                p.fillRect(rect.x(), rect.y(), 2, rect.height(), sel_rail)
            fm = QFontMetricsF(self.view.font())
            x = rect.x() + self.PAD
            baseline = rect.y() + (rect.height() + fm.ascent() - fm.descent()) / 2
            hover = getattr(self.view, "_hover", None)
            for text, color, link in segs or []:
                f = p.font()
                f.setUnderline(bool(link) and hover is not None and hover[0] == index.row())
                p.setFont(f)
                p.setPen(QColor(color) if color else row_text)
                p.drawText(QPointF(x, baseline), text)
                x += fm.horizontalAdvance(text)
            p.restore()

        def sizeHint(self, option, index):
            size = super().sizeHint(option, index)
            segs = index.data(ROLE_SEG)
            if segs:
                fm = QFontMetricsF(self.view.font())
                total = sum(fm.horizontalAdvance(t) for t, _, _ in segs)
                size.setWidth(total + self.PAD * 2 + 20)
            size.setHeight(max(size.height(), 22))
            return size

    win.disasm.setItemDelegate(_ThemedDelegate(win.disasm))
    if hasattr(win, "pseudo"):
        win.pseudo.setItemDelegate(_ThemedDelegate(win.pseudo))
