"""动态分析面板：设备-进程-断点命中流。

布局：
  设备行： [刷新] 设备下拉 [frida 启停]
  进程行： 进程搜索框 [枚举] 进程下拉 [附加]
  命中区： 断点输入(so:0xaddr) [下断] 命中日志（实时滚动）
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QDockWidget, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QVBoxLayout, QWidget,
)

from core.session import Session
from ui.theme import C_ADDR, C_FUNC, C_STR
from ui.workers import Worker


class DynamicPanel(QDockWidget):
    """底部动态面板。所有耗时操作走 Worker 线程。"""

    hit_arrived = Signal(object)  # BreakpointHit

    def __init__(self, session: Session):
        # QDockWidget 第二参数是 parent QWidget，不能把 Session 传进去
        super().__init__("动态分析")
        self.session = session
        self.setAllowedAreas(Qt.BottomDockWidgetArea | Qt.TopDockWidgetArea)
        self._device: object | None = None  # frida Device
        self._debugger = None
        self._workers: list = []

        root = QWidget()
        lay = QVBoxLayout(root)
        lay.setContentsMargins(4, 4, 4, 4)

        # 设备行
        row1 = QHBoxLayout()
        self.btn_dev = QPushButton("刷新设备")
        self.btn_dev.clicked.connect(self.refresh_devices)
        self.dev_combo = QComboBox()
        self.btn_frida = QPushButton("启动 frida-server")
        self.btn_frida.clicked.connect(self._start_frida)
        row1.addWidget(self.btn_dev)
        row1.addWidget(self.dev_combo, 1)
        row1.addWidget(self.btn_frida)
        lay.addLayout(row1)

        # 进程行
        row2 = QHBoxLayout()
        self.proc_edit = QLineEdit()
        self.proc_edit.setPlaceholderText("进程名过滤，如 browser / settings")
        self.btn_proc = QPushButton("枚举进程")
        self.btn_proc.clicked.connect(self.refresh_processes)
        self.proc_combo = QComboBox()
        self.proc_combo.addItem("（先枚举进程）", None)
        row2.addWidget(self.proc_edit, 1)
        row2.addWidget(self.btn_proc)
        row2.addWidget(self.proc_combo, 2)
        lay.addLayout(row2)

        # 断点行
        row3 = QHBoxLayout()
        self.bp_edit = QLineEdit()
        self.bp_edit.setPlaceholderText("断点: so名:静态地址，如 liblog.so:0x65a4")
        self.btn_bp = QPushButton("下断点")
        self.btn_bp.clicked.connect(self._set_breakpoint)
        row3.addWidget(self.bp_edit, 1)
        row3.addWidget(self.btn_bp)
        lay.addLayout(row3)

        # 命中日志
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        lay.addWidget(self.log, 1)
        self.hit_arrived.connect(self._on_hit)

        self.setWidget(root)

    # ---------- 工具 ----------

    def _run(self, fn, *args, on_done=None, on_fail=None) -> None:
        """后台执行 fn。失败默认写日志，可传 on_fail 覆盖。"""
        w = Worker(fn, *args)
        if on_done:
            w.finished_ok.connect(on_done)
        # 表达式形式的 connect 难读，此处显式分支
        if on_fail is None:
            w.failed.connect(lambda msg: self._log(f"[错误] {msg.splitlines()[0]}"))
        else:
            w.failed.connect(on_fail)
        self._workers.append(w)
        w.start()

    def _log(self, text: str, color: str = "") -> None:
        if color:
            self.log.append(f'<span style="color:{color}">{text}</span>')
        else:
            self.log.append(text)

    # ---------- 设备 ----------

    def refresh_devices(self) -> None:
        from dyn.adb import Adb

        def job():
            return [(d.serial, d.state) for d in Adb.list_devices() if d.state == "device"]

        self._run(job, on_done=self._fill_devices)

    def _fill_devices(self, devs: list) -> None:
        self.dev_combo.clear()
        for serial, state in devs:
            self.dev_combo.addItem(f"{serial} ({state})", serial)
        self._log(f"设备 {len(devs)} 台", C_ADDR)

    def _start_frida(self) -> None:
        serial = self.dev_combo.currentData()
        if not serial:
            self._log("无设备")
            return
        from dyn.adb import Adb

        self._run(lambda: Adb(serial).start_frida(), on_done=lambda ok: self._log(f"frida-server: {'运行中' if ok else '启动失败'}", C_FUNC if ok else ""))

    # ---------- 进程 ----------

    def refresh_processes(self) -> None:
        serial = self.dev_combo.currentData()
        if not serial:
            self._log("无设备")
            return
        from dyn.adb import Adb

        kw = self.proc_edit.text().strip().lower()

        def job():
            procs = Adb(serial).processes()
            if kw:
                procs = [p for p in procs if kw in p.name.lower()]
            return [(p.pid, p.name) for p in procs][:300]

        self._run(job, on_done=self._fill_processes)

    def _fill_processes(self, procs: list) -> None:
        self.proc_combo.clear()
        for pid, name in procs:
            self.proc_combo.addItem(f"{pid:6} {name}", pid)
        self._log(f"进程 {len(procs)} 个", C_ADDR)

    # ---------- 断点 ----------

    def _set_breakpoint(self) -> None:
        pid = self.proc_combo.currentData()
        serial = self.dev_combo.currentData()
        text = self.bp_edit.text().strip()
        if not (pid and serial and ":" in text):
            self._log("需要：设备 + 进程 + so:0x地址")
            return
        so_name, _, addr_text = text.partition(":")
        static_addr = int(addr_text, 0)

        def job():
            from dyn.debugger import Debugger
            from dyn.rebase import Rebase

            rb = Rebase.attach(serial, pid)
            dbg = Debugger(rb)
            ok = dbg.set_breakpoint(
                so_name, static_addr, policy="resume",
                on_hit=lambda hit: self.hit_arrived.emit(hit),
            )
            return ok

        self._run(job, on_done=lambda ok: self._log(
            f"断点 {text} @ pid={pid}: {'已设置' if ok else '失败(so 未加载?)'}",
            C_FUNC if ok else C_STR,
        ))

    def _on_hit(self, hit) -> None:
        self._log(
            f"命中 {hit.so_name}!{hit.static_addr:#x} 运行时={hit.runtime_addr:#x} "
            f"tid={hit.thread_id} lr={hit.context.get('lr')} | {hit.backtrace[0] if hit.backtrace else ''}",
            C_STR,
        )
        self.show()
        self.raise_()
