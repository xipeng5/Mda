"""IDA View-A 风格反汇编视图。

与纯文本列表的本质区别：
1. 分区着色——地址/机器码/助记符/操作数/注释各自独立着色
2. 可点击链接——地址、函数名、导入名、字符串都是链接，双击/回车跳转
3. XREF 注释行——函数头部列出引用者（; CODE XREF: caller+0xC ↑j），可点击回跳
4. 行首状态条（console-rail）——teal=调用 amber=跳转 orange=返回

行数据结构（由 MainWindow 构建，本视图只负责渲染与命中测试）：
    {"addr": int, "rail": "#0f9b8e"|None,
     "segments": [(text, color|None, link|None), ...], "tooltip": str}
link 为目标静态地址；annotation 行的 addr 为 None。
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView, QListWidget, QListWidgetItem, QMenu, QStyle, QStyledItemDelegate,
)

from ui.theme import C_BORDER, C_MUTED

ROLE_ADDR = Qt.UserRole
ROLE_SEG = Qt.UserRole + 1
ROLE_RAIL = Qt.UserRole + 2


class RailDelegate(QStyledItemDelegate):
    """绘制：左状态条 + 分区着色文本 + 悬停链接下划线。"""

    RAIL_W = 4
    PAD = 8

    def __init__(self, view: "DisasmView"):
        super().__init__(view)
        self.view = view

    def paint(self, painter: QPainter, option, index) -> None:
        # bug 原因：super().paint() 会用默认前景色再画一遍 item 文本，
        # 与分段绘制叠加成重影。解决：只借用它画选中/悬停底色（清空文本源），
        # 文本完全由分段绘制接管。
        segs = index.data(ROLE_SEG)
        p = painter
        p.save()
        rect = option.rect

        # 背景：选中/交替
        bg = option.palette.base() if not (option.state & QStyle.State_Selected) else option.palette.highlight()
        if option.state & QStyle.State_Selected:
            p.fillRect(rect, QColor("#cde8ff"))
        elif index.row() % 2 == 1:
            p.fillRect(rect, QColor("#fafbfa"))

        rail = index.data(ROLE_RAIL)
        if rail:
            p.fillRect(rect.x(), rect.y(), self.RAIL_W, rect.height(), QColor(rail))

        fm = QFontMetricsF(self.view.font())
        x = rect.x() + self.PAD
        baseline = rect.y() + (rect.height() + fm.ascent() - fm.descent()) / 2
        hover = self.view._hover
        for text, color, link in segs:
            f = p.font()
            f.setUnderline(bool(link) and hover is not None and hover[0] == index.row())
            p.setFont(f)
            p.setPen(QColor(color) if color else QColor("#222625"))
            p.drawText(QPointF(x, baseline), text)
            x += fm.horizontalAdvance(text)
        p.restore()

    def sizeHint(self, option, index) -> object:
        segs = index.data(ROLE_SEG)
        size = super().sizeHint(option, index)
        if segs:
            fm = QFontMetricsF(self.view.font())
            total = sum(fm.horizontalAdvance(t) for t, _, _ in segs)
            size.setWidth(total + self.PAD * 2 + 20)
        size.setHeight(max(size.height(), 22))
        return size


class DisasmView(QListWidget):
    """反汇编主视图。"""

    # 双击链接/回车：携带 "jmp:0x..." 风格的链接串
    link_activated = Signal(str)
    # 双击无链接行：携带行地址（旧行为兼容）
    addr_activated = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFont("Menlo", 12))
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setUniformItemSizes(False)
        self.setAlternatingRowColors(False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerItem)
        self.setItemDelegate(RailDelegate(self))
        self.setMouseTracking(True)
        self._hover: tuple[int, int] | None = None  # (row, char_index)
        self._rows: list[dict] = []
        self.doubleClicked.connect(self._on_double)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    # ---------- 数据 ----------

    def set_rows(self, rows: list[dict]) -> None:
        self._rows = rows
        self.clear()
        for row in rows:
            segs = row["segments"]
            plain = "".join(t for t, _, _ in segs)
            item = QListWidgetItem(plain)
            item.setData(ROLE_ADDR, row.get("addr"))
            item.setData(ROLE_SEG, segs)
            item.setData(ROLE_RAIL, row.get("rail", ""))
            item.setToolTip(row.get("tooltip", ""))
            self.addItem(item)

    def jump_to(self, addr: int) -> None:
        """精确跳转到该地址所在行。"""
        for i in range(self.count()):
            if self.item(i).data(ROLE_ADDR) == addr:
                self.setCurrentRow(i)
                self.scrollToItem(self.item(i), QAbstractItemView.PositionAtCenter)
                return

    def jump_to_containing(self, addr: int) -> None:
        """跳转到 addr 所在（地址 ≤ addr 的最后一条）指令行。"""
        best = -1
        for i in range(self.count()):
            a = self.item(i).data(ROLE_ADDR)
            if isinstance(a, int) and a <= addr:
                best = i
            elif isinstance(a, int) and a > addr and best >= 0:
                break
        if best >= 0:
            self.setCurrentRow(best)
            self.scrollToItem(self.item(best), QAbstractItemView.PositionAtCenter)

    def current_addr(self) -> int | None:
        it = self.currentItem()
        return it.data(ROLE_ADDR) if it else None

    # ---------- 命中测试 ----------

    def _char_metrics(self):
        fm = QFontMetricsF(self.font())
        return fm, fm.horizontalAdvance("0")

    def _hit(self, pos):
        """返回 (row, char_index) 或 None。"""
        idx = self.indexAt(pos)
        if not idx.isValid():
            return None
        fm, cw = self._char_metrics()
        rect = self.visualItemRect(self.item(idx.row()))
        char = int((pos.x() - rect.x() - RailDelegate.PAD) / cw)
        return idx.row(), char

    def _link_at(self, row: int, char_idx: int) -> str | None:
        if not (0 <= row < len(self._rows)):
            return None
        pos = 0
        for text, _, link in self._rows[row]["segments"]:
            if link and pos <= char_idx < pos + len(text):
                return link
            pos += len(text)
        return None

    # ---------- 交互 ----------

    def mouseMoveEvent(self, e) -> None:
        hit = self._hit(e.position().toPoint())
        if hit != self._hover:
            old = self._hover
            self._hover = hit
            for r in {*(x[0] for x in (old, hit) if x)}:
                if 0 <= r < self.count():
                    self.update(self.indexFromItem(self.item(r)))
            link = self._link_at(*hit) if hit else None
            self.setCursor(Qt.PointingHandCursor if link else Qt.ArrowCursor)
        super().mouseMoveEvent(e)

    def leaveEvent(self, e) -> None:
        self._hover = None
        self.setCursor(Qt.ArrowCursor)
        super().leaveEvent(e)

    def _follow(self, row: int, char_idx: int) -> None:
        link = self._link_at(row, char_idx)
        if link:
            self.link_activated.emit(link)
        else:
            addr = self.item(row).data(ROLE_ADDR)
            if isinstance(addr, int):
                self.addr_activated.emit(addr)

    def _on_double(self, _index) -> None:
        hit = self._hover or (self.currentRow(), 0)
        if hit and 0 <= hit[0] < self.count():
            self._follow(*hit)

    def keyPressEvent(self, e) -> None:
        if e.key() in (Qt.Key_Return, Qt.Key_Enter):
            row = self.currentRow()
            char = self._hover[1] if self._hover and self._hover[0] == row else 0
            if row >= 0:
                self._follow(row, char)
            return
        super().keyPressEvent(e)

    def _menu(self, pos) -> None:
        hit = self._hit(pos)
        m = QMenu(self)
        act = None
        if hit:
            link = self._link_at(*hit)
            if link:
                act = m.addAction(f"跳转到 {link}")
        act_copy = m.addAction("复制当前行地址")
        chosen = m.exec(self.mapToGlobal(pos))
        if chosen is act and hit:
            self._follow(*hit)
        elif chosen is act_copy:
            addr = self.current_addr()
            if addr is not None:
                from PySide6.QtWidgets import QApplication

                QApplication.clipboard().setText(hex(addr))
