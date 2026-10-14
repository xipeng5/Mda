"""清爽卡片风主题（参照 kiro.rs Admin UI 设计语言）。

设计变量来源（kiro.rs v0.9.1 二进制内嵌前端实测提取）：
  主色   --theme-hue:174 (青绿 teal), chroma 24%
  背景   --background 96% 亮度浅灰 / 卡片纯白 --card 0 0% 100%
  前景   --foreground 220 12% 16% / 次级 --muted-foreground 220 8% 43%
  圆角   --radius .5rem, 组件大量 rounded-xl (12px)
  状态   emerald(ok) / amber(warn) / orange(cool) / red(dead)
  特色   console-rail 行左侧 3px 状态色条、rounded-full 胶囊徽章
"""
from __future__ import annotations

# ---- 核心色板（teal 174 hue 推导的 HSL 落地值）----
C_PRIMARY = "#0f9b8e"        # teal 174 72% 34%
C_PRIMARY_DIM = "#0b7c72"    # hover 深
C_PRIMARY_SOFT = "#e6f5f3"   # 主色淡底（选中/徽章底）

C_BG = "#f5f6f5"             # 背景浅灰（96% 亮度）
C_CARD = "#ffffff"           # 卡片纯白
C_BORDER = "#e4e7e6"         # 细边框
C_FG = "#222625"             # 主文本 (220 12% 16%)
C_MUTED = "#6b7370"          # 次级文本 (220 8% 43%)
C_FAINT = "#9aa3a0"          # 三级文本

# ---- 状态色（emerald/amber/orange/red）----
C_OK = "#10b981"
C_OK_SOFT = "#ecfdf5"
C_WARN = "#f59e0b"
C_WARN_SOFT = "#fffbeb"
C_COOL = "#f97316"
C_COOL_SOFT = "#fff7ed"
C_DEAD = "#ef4444"
C_DEAD_SOFT = "#fef2f2"

# ---- 语义复用（兼容旧代码引用）----
C_ADDR = "#3b7dd8"           # 地址蓝（保持可读性）
C_FUNC = C_FG                # 函数名黑
C_EXPORT = C_PRIMARY         # 导出函数 = 主色 teal
C_STR = "#0d7a4f"            # 字符串 emerald 深
C_IMPORT = "#b45309"         # 导入 amber 深
C_NOTE = C_MUTED             # 注释灰
C_SELECT = C_PRIMARY_SOFT    # 选中底

FONT_MONO = "Menlo"
RADIUS = 12                  # rounded-xl
RADIUS_SM = 8                # rounded-lg


STYLE = f"""
QMainWindow, QWidget {{ background: {C_BG}; color: {C_FG}; font-size: 12px; }}

/* ---- 卡片容器 ---- */
QFrame#card {{
    background: {C_CARD};
    border: 1px solid {C_BORDER};
    border-radius: {RADIUS}px;
}}
QFrame#card-flat {{
    background: {C_CARD};
    border: 1px solid {C_BORDER};
    border-radius: {RADIUS_SM}px;
}}

/* ---- 数据视图：白底无边框（卡片已提供边框）---- */
QTreeView, QListView, QTableView, QPlainTextEdit, QTextEdit {{
    background: transparent; color: {C_FG};
    font-family: '{FONT_MONO}';
    border: none; selection-background-color: {C_PRIMARY_SOFT};
    selection-color: {C_FG};
}}
QTableView {{ alternate-background-color: #fafbfa; gridline-color: transparent; }}
QListView {{ alternate-background-color: #fafbfa; }}
QTreeView::item, QListView::item, QTableView::item {{ min-height: 24px; border: none; }}

QHeaderView::section {{
    background: transparent; color: {C_MUTED};
    border: none; border-bottom: 1px solid {C_BORDER};
    padding: 5px 8px; font-size: 11px; font-weight: 600;
}}

/* ---- 标签页：胶囊式 ---- */
QTabBar::tab {{
    background: transparent; color: {C_MUTED};
    padding: 5px 14px; border: none; margin-right: 2px;
    border-radius: {RADIUS_SM}px;
}}
QTabBar::tab:selected {{ background: {C_PRIMARY_SOFT}; color: {C_PRIMARY_DIM}; font-weight: 600; }}
QTabBar::tab:hover {{ color: {C_FG}; }}
QTabWidget::pane {{ border: none; }}

/* ---- 工具栏：白色胶囊条 ---- */
QToolBar {{
    background: {C_CARD}; border: 1px solid {C_BORDER};
    border-radius: {RADIUS}px; spacing: 2px; padding: 3px;
}}
QToolButton {{
    background: transparent; border: none;
    border-radius: {RADIUS_SM}px; padding: 4px 10px; color: {C_FG};
}}
QToolButton:hover {{ background: {C_PRIMARY_SOFT}; color: {C_PRIMARY_DIM}; }}
QToolButton:pressed {{ background: {C_PRIMARY}; color: #fff; }}

/* ---- 输入控件：大圆角 ---- */
QLineEdit, QComboBox, QSpinBox {{
    background: {C_CARD}; border: 1px solid {C_BORDER};
    border-radius: {RADIUS_SM}px; padding: 4px 10px; color: {C_FG};
}}
QLineEdit:hover, QComboBox:hover {{ border-color: #cbd5d2; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {C_PRIMARY}; }}

QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {C_CARD}; border: 1px solid {C_BORDER};
    border-radius: {RADIUS_SM}px; selection-background-color: {C_PRIMARY_SOFT};
    selection-color: {C_FG};
}}

QPushButton {{
    background: {C_CARD}; border: 1px solid {C_BORDER};
    border-radius: {RADIUS_SM}px; padding: 4px 14px; color: {C_FG}; font-weight: 500;
}}
QPushButton:hover {{ border-color: {C_PRIMARY}; color: {C_PRIMARY_DIM}; background: {C_PRIMARY_SOFT}; }}
QPushButton:pressed {{ background: {C_PRIMARY}; color: #fff; }}

/* ---- 停靠窗：无边框卡片感 ---- */
QDockWidget {{ color: {C_MUTED}; font-size: 11px; font-weight: 600; }}
QDockWidget::title {{
    background: transparent; padding: 5px 8px;
    border-bottom: 1px solid {C_BORDER};
}}

QStatusBar {{ background: transparent; color: {C_MUTED}; border: none; }}
QStatusBar::item {{ border: none; }}

QMenu {{
    background: {C_CARD}; border: 1px solid {C_BORDER};
    border-radius: {RADIUS_SM}px; padding: 4px;
}}
QMenu::item {{ border-radius: 6px; padding: 5px 20px; }}
QMenu::item:selected {{ background: {C_PRIMARY_SOFT}; color: {C_PRIMARY_DIM}; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #d3d9d6; min-height: 28px; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: {C_PRIMARY}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #d3d9d6; min-width: 28px; border-radius: 5px; }}
QScrollBar::handle:horizontal:hover {{ background: {C_PRIMARY}; }}

QSplitter::handle {{ background: transparent; width: 6px; height: 6px; }}
"""
