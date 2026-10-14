"""交互式伪代码视图。

不再是无链接 txt：标识符/字符串/调用名渲染为带链接的分段文本，
双击跳到对应函数或反汇编行。行结构由 MainWindow 构建：
    {"segments": [(text, color, link|None)], "rail": color|""}
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetricsF
from PySide6.QtWidgets import QAbstractItemView, QListWidget, QListWidgetItem, QMenu

from ui.disasm_view import RailDelegate, ROLE_RAIL, ROLE_SEG


class PseudoView(QListWidget):
    """伪代码列表（逐行渲染，支持链接）。"""

    link_activated = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFont("Menlo", 12))
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setUniformItemSizes(False)
        self.setItemDelegate(RailDelegate(self))
        self.setMouseTracking(True)
        self._hover = None
        self._rows: list[dict] = []
        self.doubleClicked.connect(self._on_double)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def set_rows(self, rows: list[dict]) -> None:
        self._rows = rows
        self.clear()
        for row in rows:
            segs = row["segments"]
            item = QListWidgetItem("".join(t for t, _, _ in segs))
            item.setData(ROLE_SEG, segs)
            item.setData(ROLE_RAIL, row.get("rail", ""))
            self.addItem(item)

    # ---- 链接命中（与 DisasmView 同逻辑，抽出会过度抽象，保留两份小实现）----

    def _hit(self, pos):
        idx = self.indexAt(pos)
        if not idx.isValid():
            return None
        fm = QFontMetricsF(self.font())
        cw = fm.horizontalAdvance("0")
        rect = self.visualItemRect(self.item(idx.row()))
        return idx.row(), int((pos.x() - rect.x() - RailDelegate.PAD) / cw)

    def _link_at(self, row: int, char_idx: int) -> str | None:
        if not (0 <= row < len(self._rows)):
            return None
        pos = 0
        for text, _, link in self._rows[row]["segments"]:
            if link and pos <= char_idx < pos + len(text):
                return link
            pos += len(text)
        return None

    def mouseMoveEvent(self, e) -> None:
        hit = self._hit(e.position().toPoint())
        if hit != self._hover:
            self._hover = hit
            link = self._link_at(*hit) if hit else None
            self.setCursor(Qt.PointingHandCursor if link else Qt.ArrowCursor)
        super().mouseMoveEvent(e)

    def leaveEvent(self, e) -> None:
        self._hover = None
        super().leaveEvent(e)

    def _on_double(self, _i) -> None:
        hit = self._hover or (self.currentRow(), 0)
        if hit:
            link = self._link_at(*hit)
            if link:
                self.link_activated.emit(link)

    def _menu(self, pos) -> None:
        hit = self._hit(pos)
        if not hit:
            return
        link = self._link_at(*hit)
        if link:
            m = QMenu(self)
            a = m.addAction(f"跳转 {link}")
            if m.exec(self.mapToGlobal(pos)) is a:
                self.link_activated.emit(link)
