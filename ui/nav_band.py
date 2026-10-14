"""导航色带（Navigation Band）。

IDA 顶部的彩色横条：按地址顺序把整个文件着色，
蓝=代码、灰=数据、黄=字符串区、绿=函数起点标记、黑=未映射。
点击可跳转到对应地址，拖动可平移浏览。
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QWidget

from ui.theme import C_BG

# 区间类型 -> 颜色（teal 主题系，对齐 kiro.rs 设计语言）
_BAND_COLORS = {
    "code": QColor("#7fc8bf"),      # 代码 teal 浅
    "func": QColor("#0f9b8e"),      # 函数主色 teal
    "data": QColor("#d7dcd9"),      # 数据浅灰
    "string": QColor("#e0c96a"),    # 字符串黄
    "import": QColor("#e093c4"),    # 导入粉
    "unmapped": QColor("#2e3331"),  # 未映射深灰
}


class NavBand(QWidget):
    """可点击/拖动的导航色带。"""

    # 携带点击处的静态地址
    addr_clicked = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(36)
        self.setMouseTracking(True)
        # 区间列表: (start, end, kind)，按地址排序
        self._ranges: list[tuple[int, int, str]] = []
        self._span: tuple[int, int] = (0, 1)  # 整个色带覆盖的地址范围
        self._cursor_addr: int | None = None  # 当前视图中心，画竖线标记
        self._hover_x: int | None = None

    # ---------- 数据 ----------

    def set_ranges(self, ranges: list[tuple[int, int, str]]) -> None:
        """设置全部区间并自动计算地址跨度。"""
        self._ranges = sorted(ranges, key=lambda r: r[0])
        if self._ranges:
            lo = min(r[0] for r in self._ranges)
            hi = max(r[1] for r in self._ranges)
            self._span = (lo, max(hi, lo + 1))
        else:
            self._span = (0, 1)
        self.update()

    def set_cursor(self, addr: int) -> None:
        """标记当前浏览位置（画青色竖线）。"""
        self._cursor_addr = addr
        self.update()

    # ---------- 绘制 ----------

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C_BG))
        lo, hi = self._span
        width = max(1, self.width())

        def to_x(addr: int) -> int:
            return int((addr - lo) / (hi - lo) * width)

        # 先画未映射底色
        p.fillRect(0, 0, width, self.height(), _BAND_COLORS["unmapped"])

        # 再画各个区间（重叠时后画的覆盖）
        for start, end, kind in self._ranges:
            x1, x2 = to_x(start), to_x(end)
            color = _BAND_COLORS.get(kind, _BAND_COLORS["data"])
            p.fillRect(x1, 0, max(1, x2 - x1), self.height(), color)

        # 当前位置竖线（主色 teal）
        if self._cursor_addr is not None and lo <= self._cursor_addr <= hi:
            x = to_x(self._cursor_addr)
            p.setPen(QColor("#0f9b8e"))
            p.drawLine(x, 0, x, self.height())

        # 悬停位置提示线
        if self._hover_x is not None:
            p.setPen(QColor("#ffffff"))
            p.drawLine(self._hover_x, 0, self._hover_x, self.height())
        p.end()

    # ---------- 交互 ----------

    def _addr_at(self, x: int) -> int:
        lo, hi = self._span
        return int(lo + x / max(1, self.width()) * (hi - lo))

    def mousePressEvent(self, e) -> None:
        self.addr_clicked.emit(self._addr_at(int(e.position().x())))

    def mouseMoveEvent(self, e) -> None:
        self._hover_x = int(e.position().x())
        self.update()

    def leaveEvent(self, _e) -> None:
        self._hover_x = None
        self.update()
