"""后台工作线程。

分析大 so 可能数秒，直接在主线程跑会冻结 UI。
统一用 QThread 包装，完成/失败以信号回主线程。
"""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    """执行 fn(*args, **kwargs)，finished 携带返回值，error 携带异常文本。"""

    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args, parent=None, **kwargs):
        super().__init__(parent)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished_ok.emit(result)
        except Exception as e:  # 线程内异常必须显式回传，否则静默吞掉
            import traceback

            self.failed.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")
