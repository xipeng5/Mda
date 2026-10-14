"""可搜索表格基类：函数表/字符串表/导入导出表的公共能力。

IDA 函数列表顶部有过滤框，输入即时过滤——这是高频操作，
统一在此实现，避免每个表各写一遍。
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QLineEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ui.theme import FONT_MONO


class FilterTable(QWidget):
    """过滤框 + 表格。子类/调用方实现 fill(rows) 与 on_activate。"""

    def __init__(self, headers: list[str], parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("过滤…（输入即时过滤）")
        self.filter_edit.textChanged.connect(self._apply_filter)
        lay.addWidget(self.filter_edit)

        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 首列可伸展但设下限，避免函数名被过滤框挤压成 "_Z..."
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setMinimumSectionSize(90)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 80)
        self.table.setFont(QFont(FONT_MONO, 11))
        self.table.doubleClicked.connect(self._on_double)
        lay.addWidget(self.table)

        # 全量数据与行->data 映射，过滤时重建视图
        self._rows: list[list[tuple[str, QColor | None, object]]] = []

    # ---------- 数据 ----------

    def set_rows(self, rows: list[list[tuple[str, QColor | None, object]]]) -> None:
        """rows: 每行是 [(文本, 颜色, 隐藏data), ...]；过滤重建。"""
        self._rows = rows
        self._apply_filter(self.filter_edit.text())

    def _apply_filter(self, text: str) -> None:
        kw = text.strip().lower()
        self.table.setRowCount(0)
        for row in self._rows:
            if kw and not any(kw in cell[0].lower() for cell in row):
                continue
            r = self.table.rowCount()
            self.table.insertRow(r)
            for col, (text_c, color, data) in enumerate(row):
                it = QTableWidgetItem(text_c)
                if color:
                    it.setForeground(QColor(color))
                if data is not None:
                    it.setData(Qt.UserRole, data)
                it.setToolTip(text_c)
                self.table.setItem(r, col, it)

    def _on_double(self, index) -> None:
        it = self.table.item(index.row(), 0)
        if it is not None:
            self.on_activate(it.data(Qt.UserRole))

    # 子类覆盖
    def on_activate(self, data) -> None:
        pass
