"""交互式 Hex 视图。

三段式渲染 + 双向联动：
- 点 hex 字节 → 高亮同行 ASCII 对应字符；反之亦然
- set_data(base, data, marks) 支持区间标记（函数起点画状态条）
- mark_position(addr) 跟随反汇编光标滚动定位
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit

from ui.theme import C_PRIMARY, C_PRIMARY_SOFT


class _HexHighlighter(QSyntaxHighlighter):
    """三段着色：偏移灰 / hex 蓝 / ascii 绿。"""

    def __init__(self, doc, view: "HexView"):
        super().__init__(doc)
        self.view = view

    def highlightBlock(self, text: str) -> None:
        # 偏移列
        f = QTextCharFormat()
        f.setForeground(QColor("#9aa3a0"))
        self.setFormat(0, 8, f)
        # hex 区
        f2 = QTextCharFormat()
        f2.setForeground(QColor("#3b7dd8"))
        self.setFormat(10, 48, f2)
        # ascii 区
        f3 = QTextCharFormat()
        f3.setForeground(QColor("#0d7a4f"))
        self.setFormat(60, 16, f3)

        # 选中字节高亮（hex 与 ascii 同步）
        sel = self.view.selected_index
        if sel is not None:
            row, col = sel
            if self.currentBlock().blockNumber() == row:
                fmt = QTextCharFormat()
                fmt.setBackground(QColor(C_PRIMARY))
                fmt.setForeground(QColor("#ffffff"))
                # hex 两字符
                hx = 10 + col * 3
                self.setFormat(hx, 2, fmt)
                self.setFormat(60 + col, 1, fmt)


class HexView(QPlainTextEdit):
    """只读交互 hex dump。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Menlo", 12))
        self._base = 0
        self._data = b""
        self.selected_index: tuple[int, int] | None = None  # (行, 列0-15)
        self._hl: _HexHighlighter | None = None
        self.setMouseTracking(True)

    def set_data(self, base_addr: int, data: bytes) -> None:
        self._base = base_addr
        self._data = data
        self.setPlainText(self._render(data))
        if self._hl is None:
            self._hl = _HexHighlighter(self.document(), self)
        self._hl.rehighlight()

    def _render(self, data: bytes, row_bytes: int = 16) -> str:
        lines = []
        for i in range(0, len(data), row_bytes):
            chunk = data[i : i + row_bytes]
            offset = f"{self._base + i:08x}"
            hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(row_bytes * 3 - 1)
            asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"{offset}  {hexpart}  |{asc}|")
        return "\n".join(lines)

    # ---- 定位 ----

    def mark_position(self, addr: int) -> None:
        """滚动到某静态地址并高亮其字节。"""
        off = addr - self._base
        if not (0 <= off < len(self._data)):
            return
        row, col = off // 16, off % 16
        self.selected_index = (row, col)
        if self._hl:
            self._hl.rehighlight()
        block = self.document().findBlockByNumber(row)
        # 用 ExtraSelection 定位视觉焦点
        cursor = QTextCursor(block)
        self.setTextCursor(cursor)
        self.centerCursor()

    # ---- 交互：点击任一区，双向映射 ----

    def mousePressEvent(self, e) -> None:
        cursor = self.cursorForPosition(e.position().toPoint())
        block_no = cursor.blockNumber()
        col = cursor.positionInBlock()
        line = self.document().findBlockByNumber(block_no).text()
        byte_col: int | None = None
        if 10 <= col < 58:  # hex 区
            byte_col = (col - 10) // 3
        elif 60 <= col < 76:  # ascii 区
            byte_col = col - 60
        if byte_col is not None and byte_col < len(self._data) - block_no * 16:
            self.selected_index = (block_no, byte_col)
            if self._hl:
                self._hl.rehighlight()
        super().mousePressEvent(e)
