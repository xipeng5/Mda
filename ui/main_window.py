"""IDA 风格主窗口（v2 重做）。

对照 IDA 布局：
  顶部：工具栏（打开/加载/动态操作）+ 导航色带
  中部：多标签页 —— 反汇编 / 伪代码 / Hex / 导入 / 导出 / 交叉引用
  左侧：函数列表（可过滤）
  右侧：模块树 + 字符串列表
  底部：Output 日志（加载/分析过程信息）
"""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QApplication, QDockWidget, QFileDialog, QLabel, QLineEdit, QMainWindow,
    QPlainTextEdit, QSplitter, QStatusBar, QTabWidget, QToolBar, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.session import Session
from ui.disasm_view import DisasmView
from ui.filter_table import FilterTable
from ui.hex_view import HexView
from ui.nav_band import NavBand
from ui.pseudo_view import PseudoView
from ui.theme import (
    C_ADDR, C_EXPORT, C_FAINT, C_FG, C_FUNC, C_IMPORT, C_MUTED, C_NOTE,
    C_OK, C_COOL, C_STR, C_WARN, FONT_MONO, STYLE,
)
from ui.workers import Worker


def _has_str(segs: list) -> bool:
    """判断分段里是否已包含字符串链接（避免注释重复）。"""
    return any(l and l.startswith("str:") for _, _, l in segs)

_MONO = QFont(FONT_MONO, 12)


class MainWindow(QMainWindow):
    """主窗口。"""
    # AI 活动信号：MCP 工作线程 → 主线程的可靠投递（queued 自动）
    aiActivity = Signal(dict)
    uiSync = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MDA — Multi-so DisAssembly Analyzer")
        self.resize(1680, 980)
        from mcp_server.tools import get_session

        self.session: Session = get_session()
        self.current_so: str | None = None
        self.current_func: int | None = None
        # 加载串行化（bug 7 修复）
        self._workers: list[Worker] = []
        self._load_queue: list[tuple[Worker, str]] = []
        self._loading = False
        # 正在后台构建引用图的模块（防重复触发；完成后自动刷新视图）
        self._xref_building: set[str] = set()
        # MCP 服务（GUI 内开关）
        from mcp_server.service import McpService

        self.mcp = McpService(log=self._log_safe)
        # 订阅 AI 活动日志：MCP 工具调用实时显示在 Output
        from mcp_server.tools import on_activity, get_activity_log, on_ui_sync

        on_activity(self.aiActivity.emit)   # 线程安全：emit 跨线程自动排队
        on_ui_sync(self.uiSync.emit)
        self.aiActivity.connect(self._render_ai_entry)   # queued 到主线程
        self.uiSync.connect(self._on_ui_sync)
        # 补看 GUI 启动前 AI 已发生的操作
        for entry in get_activity_log()[-20:]:
            self._render_ai_entry(entry)
        # 插件管理器（与 MCP 共享单例）
        from mcp_server.tools import get_plugins

        self.plugins = get_plugins()

        self._build_toolbar()
        self._build_body()
        self._build_docks()
        self._build_status()
        self._fill_plugin_menu()
        self._log("MDA 启动完成。加载 so 开始分析。")
        self._log(f"[插件] 已加载 {len(self.plugins.plugins)} 个: {list(self.plugins.plugins)}")
        # 默认自动启动 MCP 接口（AI 客户端随时可连）
        self.mcp.start_http()
        self.act_mcp.setText(f"● MCP 运行中  {self.mcp.status()}")

    def _log_safe(self, text: str) -> None:
        """线程安全的日志入口（MCP 线程回调用）。"""
        QTimer.singleShot(0, lambda: self._log(text))

    # ---------- 生命周期：UI 关闭 → 后台服务随之关闭 ----------

    def _shutdown_services(self) -> None:
        """停止后台服务（MCP HTTP）。

        幂等：closeEvent 与 aboutToQuit 都会调用，重复调用无害。
        """
        try:
            if getattr(self, "mcp", None) is not None and self.mcp.running:
                self.mcp.stop()
        except Exception:
            pass

    def closeEvent(self, event) -> None:
        """窗口关闭：先停服务再放行，避免残留占用端口的后台线程。"""
        self._shutdown_services()
        super().closeEvent(event)

    def _on_ai_activity(self, entry: dict) -> None:
        """AI 经 MCP 调用工具时触发（MCP 工作线程）。

        bug 原因：QTimer.singleShot 的 lambda 闭包捕获 entry，
        在高并发 MCP 调用下偶发未派发；且 Output 面板若在后台标签，
        内容更新了用户也看不见。
        解决：1) 改用 InvokeMethod 风格的显式队列投递（保序）
              2) 收到 AI 活动时若 Output 在后台标签则闪标题提醒
        """
        # QTimer.singleShot(0,...) 在非 GUI 线程调用时要求目标线程有事件循环；
        # MCP 的 uvicorn 线程有，但闭包捕获偶发丢失。改用直接queued连接语义。
        QTimer.singleShot(0, lambda e=dict(entry): self._render_ai_entry(e))
        # 标签提醒：Output 不在前台时标题加 •
        if self.out_dock and not self.out_dock.isVisible():
            self.out_dock.setWindowTitle(f"Output • {entry.get('tool', '')}")

    def _on_ui_sync(self, event: dict) -> None:
        """AI 的操作 → GUI 视图等价联动（"AI 像人一样操作 MDA"）。

        人工点开某函数会看到什么，AI 调用时就同步看到什么：
        disassemble → 跳转定位、list_functions → 过滤函数表、
        show_xrefs → 交叉引用面板、show_tab → 切换标签页。
        """
        etype = event.get("type")

        def do():
            try:
                if etype == "so_loaded":
                    self._log(f"[AI 加载] {event['so_name']}: {event['functions']} 函数（AI 经 MCP 加载）")
                    self.refresh_modules()
                    self.show_so(event["so_name"])

                elif etype == "goto":
                    so_name, addr = event.get("so_name"), event.get("addr")
                    if so_name not in self.session.modules:
                        return
                    fn = self.session.get(so_name).function_at(addr)
                    self.show_function(so_name, fn.addr if fn else addr)
                    if fn:
                        self.disasm.jump_to_containing(addr)
                    tab = event.get("tab")
                    if tab:
                        for i in range(self.tabs.count()):
                            if self.tabs.tabText(i) == tab:
                                self.tabs.setCurrentIndex(i)
                                break
                    self._log(f"[AI 定位] {so_name}!{addr:#x}  ({event.get('why', '')})")

                elif etype == "filter_funcs":
                    so_name = event.get("so_name")
                    if so_name in self.session.modules:
                        # bug 原因：此前只在 current_so != so_name 时调 show_so
                        # 重建 _rows。若 AI 改了函数名（IDC/rename）后又过滤，
                        # 模块没变 → _rows 仍是改名前的旧快照 → 过滤结果为空
                        #（实测：AI 跑完 IDC 再过滤 Java_aesEncrypt 命中 0 行）。
                        # 解决：过滤前总是重建数据，保证反映最新名字。
                        self.show_so(so_name)
                        kw = event.get("keyword", "")
                        self.func_tbl.filter_edit.setText(kw)
                        self.func_dock.raise_()
                        self._log(f'[AI 过滤] 函数列表 ← "{kw}"（{self.func_tbl.table.rowCount()} 条命中）')

                elif etype == "show_strings":
                    so_name = event.get("so_name")
                    if so_name in self.session.modules:
                        if self.current_so != so_name:
                            self.show_so(so_name)
                        self.str_tbl.filter_edit.setText(event.get("keyword", ""))
                        self._log(f"[AI 检索] 字符串 ← \"{event.get('keyword', '')}\"")

                elif etype == "show_xrefs":
                    so_name, addr = event.get("so_name"), event.get("addr")
                    if so_name in self.session.modules:
                        # 同 filter_funcs：总是重建数据，避免 AI 改名后用过期的 _rows
                        self.show_so(so_name)
                        self.show_xrefs_to(addr)
                        self.tabs.setCurrentWidget(self.xref_tbl)
                        self._log(f"[AI 查引用] {so_name}!{addr:#x} → {self.xref_tbl.table.rowCount()} 处")

                elif etype == "show_tab":
                    for i in range(self.tabs.count()):
                        if self.tabs.tabText(i) == event.get("tab"):
                            self.tabs.setCurrentIndex(i)
                            break

                elif etype == "data_changed":
                    # AI 批量改数据（IDC 脚本改名/建函数/注释）→ 全量刷新视图
                    so_name = event.get("so_name")
                    if so_name in self.session.modules:
                        self.refresh_modules()
                        self.show_so(so_name)
                        if self.current_func:
                            self.show_function(so_name, self.current_func)
                        self._log(f"[AI 数据更新] {so_name} ← {event.get('why', '')}")

                elif etype == "renamed":
                    so_name, addr = event.get("so_name"), event.get("addr", 0)
                    self._log(f"[AI 改名] {so_name}:{addr:#x} → {event.get('new', '')}")
                    if self.current_so == so_name:
                        self.show_so(so_name)
                        if self.current_func == addr:
                            self.show_function(so_name, addr)
            except Exception as e:
                self._log(f"[AI 回放异常] {etype}: {type(e).__name__}: {e}")

        QTimer.singleShot(0, do)

    def _render_ai_entry(self, e: dict) -> None:
        """AI 活动渲染成 IDA Output 风格日志行。"""
        mark = "✗" if str(e.get("summary", "")).startswith("✗") else "→"
        self._log(f"[AI {e.get('ts','')}] {mark} {e.get('tool')}({e.get('summary','-')})  [{e.get('ms',0)}ms]")

    def _toggle_mcp(self) -> None:
        if self.mcp.running:
            self.mcp.stop()
            self.act_mcp.setText("● MCP 未启动")
        else:
            self.mcp.start_http()
            self.act_mcp.setText(f"● MCP 运行中  {self.mcp.status()}")

    def _fill_plugin_menu(self) -> None:
        """把每个插件挂成菜单项，点击弹输入框要 JSON 参数。"""
        for info in self.plugins.describe():
            act = QAction(f"{info['name']} — {info['description']}", self)
            act.triggered.connect(lambda _=False, n=info['name'], u=info['usage']: self._run_plugin_dialog(n, u))
            self.menu_plugins.addAction(act)

    def _run_plugin_dialog(self, name: str, usage: str) -> None:
        from PySide6.QtWidgets import QInputDialog

        text, ok = QInputDialog.getText(self, f"运行插件 {name}", f"参数 JSON（{usage}）:")
        if not ok:
            return
        w = Worker(self.plugins.run, name, _parse_json_or_empty(text))
        w.finished_ok.connect(lambda r: self._log(f"[插件 {name}] 结果: {r}"))
        w.failed.connect(lambda m: self._log(f"[插件 {name}] 失败: {m.splitlines()[0]}"))
        self._workers.append(w)
        w.start()

    def _reload_plugins(self) -> None:
        from mcp_server.tools import get_plugins

        self.plugins = get_plugins()
        loaded = self.plugins.scan_and_load()
        self._fill_plugin_menu()
        self._log(f"[插件] 重载完成: {loaded}")

    # ---------- 工具栏 ----------

    def _build_toolbar(self) -> None:
        import os

        tb = QToolBar("主工具栏")
        tb.setMovable(False)
        self.addToolBar(tb)

        # 品牌 logo（工具栏左侧，纯展示不可点）；资源缺失时跳过
        logo_file = asset_path("logo_512.png")
        if os.path.exists(logo_file):
            lbl = QLabel()
            lbl.setPixmap(
                QPixmap(logo_file).scaled(
                    28, 28, Qt.KeepAspectRatio, Qt.SmoothTransformation
                )
            )
            lbl.setToolTip("MDA — Multi-so Disassembly Analyzer")
            lbl.setContentsMargins(6, 0, 10, 0)
            tb.addWidget(lbl)
            tb.addSeparator()

        act_open = QAction("📂 打开 so", self)
        act_open.setShortcut(QKeySequence.Open)
        act_open.triggered.connect(self._open_dialog)
        tb.addAction(act_open)

        act_reload = QAction("↻ 刷新", self)
        act_reload.triggered.connect(self._reload_current)
        tb.addAction(act_reload)

        tb.addSeparator()
        # 跳转输入框：输入 0x5020 或函数名回车跳转
        self.jump_edit = _JumpEdit(self)
        self.jump_edit.setPlaceholderText("跳转到地址或函数名…")
        self.jump_edit.setMaximumWidth(260)
        tb.addWidget(self.jump_edit)

        tb.addSeparator()
        act_chain = QAction("⛓ 跨 so 调用链", self)
        act_chain.triggered.connect(self._show_call_chain)
        tb.addAction(act_chain)

        tb.addSeparator()
        self.dev_label = QLabel(" 设备: 未连接 ")
        tb.addWidget(self.dev_label)
        act_dev = QAction("⟳ 设备", self)
        act_dev.triggered.connect(self._refresh_device)
        tb.addAction(act_dev)

        tb.addSeparator()
        # MCP 开关：AI 客户端接入点（对齐 ida-pro-mcp 插件的体验）
        self.act_mcp = QAction("● MCP 未启动", self)
        self.act_mcp.triggered.connect(self._toggle_mcp)
        tb.addAction(self.act_mcp)

        tb.addSeparator()
        # 插件菜单：动态列出
        self.menu_plugins = self.menuBar().addMenu("插件(&P)")
        act_reload_plug = QAction("重载插件", self)
        act_reload_plug.triggered.connect(self._reload_plugins)
        self.menu_plugins.addAction(act_reload_plug)
        self.menu_plugins.addSeparator()

    # ---------- 主体 ----------

    def _build_body(self) -> None:
        from PySide6.QtWidgets import QFrame

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(8, 8, 8, 4)
        lay.setSpacing(6)

        # 主体装进白卡片（kiro.rs 的 card 体系）
        card = QFrame()
        card.setObjectName("card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(0, 0, 0, 0)
        card_lay.setSpacing(0)

        # 导航色带（卡片顶部）
        self.nav = NavBand()
        self.nav.addr_clicked.connect(self._on_nav_click)
        card_lay.addWidget(self.nav)

        # 多标签页
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        card_lay.addWidget(self.tabs, 1)
        lay.addWidget(card, 1)

        # 1) 反汇编
        self.disasm = DisasmView()
        self.disasm.link_activated.connect(self._on_disasm_link)
        self.disasm.addr_activated.connect(lambda a: self._log(f"位置 {a:#x}"))
        self.tabs.addTab(self.disasm, "反汇编")

        # 2) 伪代码（交互式）
        self.pseudo = PseudoView()
        self.pseudo.link_activated.connect(self._on_pseudo_link)
        self.tabs.addTab(self.pseudo, "伪代码")

        # 3) Hex
        self.hex = HexView()
        self.tabs.addTab(self.hex, "Hex")

        # 4) 导入表
        self.imports_tbl = FilterTable(["符号", "类型", "被引用于 PLT"])
        self.imports_tbl.on_activate = self._on_import_activate
        self.tabs.addTab(self.imports_tbl, "导入")

        # 5) 导出表
        self.exports_tbl = FilterTable(["符号", "地址", "大小"])
        self.exports_tbl.on_activate = self._on_export_activate
        self.tabs.addTab(self.exports_tbl, "导出")

        # 6) 交叉引用
        self.xref_tbl = FilterTable(["地址", "所属函数", "类型"])
        self.xref_tbl.on_activate = self._on_xref_activate
        self.tabs.addTab(self.xref_tbl, "交叉引用")

        self.setCentralWidget(central)

    # ---------- 停靠窗 ----------

    def _build_docks(self) -> None:
        # 左：函数列表
        self.func_dock = QDockWidget("函数", self)
        self.func_tbl = FilterTable(["函数", "地址", "来源"])
        self.func_tbl.on_activate = self._on_func_activate
        self.func_dock.setWidget(self.func_tbl)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.func_dock)

        # 右：模块树 + 字符串
        right = QDockWidget("模块 / 字符串", self)
        split = QSplitter(Qt.Vertical)
        self.module_tree = QTreeWidget()
        self.module_tree.setHeaderLabels(["so", "函数数"])
        self.module_tree.itemClicked.connect(self._on_tree_click)
        split.addWidget(self.module_tree)
        self.str_tbl = FilterTable(["字符串", "地址", "引用数"])
        self.str_tbl.on_activate = self._on_str_activate
        split.addWidget(self.str_tbl)
        split.setSizes([400, 400])
        right.setWidget(split)
        self.addDockWidget(Qt.RightDockWidgetArea, right)

        # 底：Output 日志
        # bug 原因：Output 与动态面板同在 Bottom 区，Qt 把两个 dock 上下堆叠时
        # Output 的 setFixedHeight(120) 导致只显示一半，下半被动态面板的白底盖住。
        # 解决：两个 dock 用 tabify 合并为标签页（可切换、互不遮挡），并提高初始高度。
        out_dock = QDockWidget("Output", self)
        self.out_view = _PlainView()
        out_dock.setWidget(self.out_view)
        out_dock.setMinimumHeight(220)
        out_dock.setFeatures(
            QDockWidget.DockWidgetClosable
            | QDockWidget.DockWidgetMovable
            | QDockWidget.DockWidgetFloatable
        )
        self.addDockWidget(Qt.BottomDockWidgetArea, out_dock)

        # 底 2：动态面板（与 Output 标签化并排）
        from ui.dynamic_panel import DynamicPanel

        self.dynamic = DynamicPanel(self.session)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.dynamic)
        # tabify：Output 与动态面板同一位置切换显示
        self.tabifyDockWidget(out_dock, self.dynamic)
        out_dock.raise_()  # 默认显示 Output（AI 日志在这里）
        self.out_dock = out_dock

    def _build_status(self) -> None:
        st = QStatusBar()
        self.setStatusBar(st)
        self.addr_label = QLabel("  -  ")
        self.addr_label.setFont(_MONO)
        st.addPermanentWidget(self.addr_label)

    # ---------- 日志 ----------

    def _log(self, text: str) -> None:
        self.out_view.append(text)
        self.statusBar().showMessage(text[:120], 8000)

    # ---------- 加载 ----------

    def _open_dialog(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "加载 so 文件", "", "Shared Object (*.so);;所有文件 (*)")
        for p in paths:
            self.load_so(p)

    def load_so(self, path: str) -> None:
        self._log(f'Loading file to: {path.rsplit("/", 1)[-1]} as Shared Object...')
        w = Worker(self._do_load, path, self._log_safe)
        w.finished_ok.connect(self._on_loaded)
        w.failed.connect(lambda m: self._log(f"[错误] {m.splitlines()[0]}"))
        w.finished.connect(lambda: self._cleanup_worker(w))
        self._workers.append(w)
        if self._loading:
            self._load_queue.append((w, path))
            return
        self._loading = True
        w.start()

    @staticmethod
    def _do_load(path: str, progress=None):
        """加载 so。progress 回调对齐 IDA 的加载输出（分阶段日志）。

        性能：**不**在加载时全量构建引用图。
        libAPSE 级样本（6047 函数 / 86 万条指令）全量要 20-30 秒，
        多模块启动就会卡住窗口。引用图改为按需构建：
        脚本/查询首次访问某函数时只解该函数（ensure_function），
        需要全库引用时由用户显式点工具栏或调 build_xrefs。
        """
        from mcp_server.tools import get_session

        def log(msg: str) -> None:
            if progress:
                progress(msg)

        s = get_session()
        log(f'Input MD5  : {__import__("hashlib").md5(open(path, "rb").read()).hexdigest().upper()}')
        so = s.add(path)
        log(f'Format: ELF64 for {"AARCH64" if int(so.arch) == 183 else so.arch.name} (Shared object), PIE={so.is_pie}')
        log(f'Sections: {len(so.sections)}  Exports: {len(so.exports)}  Imports: {len(so.imports)}')
        log(f'Function discovery (.eh_frame FDE): {len(so.functions)} functions')
        log(f'PLT stubs resolved: {len(so.plt_map)}')
        log('Xref graph: 按需构建（首次查询某函数时惰性解码，全库引用请用「构建引用图」）')
        n_str = len(s.strings(so.name).all_strings())
        log(f'Strings extracted: {n_str}')
        from mcp_server.tools import get_plugins

        get_plugins().emit("after_load", {"so_name": so.name})
        return {"name": so.name, "functions": len(so.functions),
                "call_edges": 0, "strings": n_str}

    def _on_loaded(self, info: dict) -> None:
        self._log(f"已加载 {info['name']}: {info['functions']} 函数, {info['strings']} 字符串")
        self.refresh_modules()
        self.show_so(info["name"])
        self._refresh_device()

    def _cleanup_worker(self, w: Worker) -> None:
        if w in self._workers:
            self._workers.remove(w)
        self._loading = False
        if self._load_queue:
            nxt, _ = self._load_queue.pop(0)
            self._loading = True
            nxt.start()

    def _reload_current(self) -> None:
        if self.current_so:
            self.show_so(self.current_so)

    # ---------- 模块/函数/字符串填充 ----------

    def refresh_modules(self) -> None:
        self.module_tree.clear()
        for name, so in self.session.modules.items():
            QTreeWidgetItem(self.module_tree, [name, str(len(so.functions))])

    def _on_tree_click(self, item: QTreeWidgetItem, _col: int) -> None:
        self.show_so(item.text(0))

    def show_so(self, name: str) -> None:
        self.current_so = name
        so = self.session.get(name)
        # 不调 ensure_xrefs：函数/字符串列表只需 so.functions 与 strings，
        # 而全量引用图对 6000+ 函数的样本要 20-30 秒——点一下模块树就卡住。
        # 引用图由 show_function/查询按需惰性构建。
        strs = self.session.strings(name)

        # 函数列表（IDA 风格：地址升序，导出函数紫色）
        rows = []
        for fn in sorted(so.functions.values(), key=lambda f: f.addr):
            color = C_EXPORT if fn.is_export else C_FUNC
            rows.append([(fn.name or f"sub_{fn.addr:x}", color, fn.addr),
                         (hex(fn.addr), C_ADDR, fn.addr),
                         (fn.discovered_by, C_MUTED, None)])
        self.func_tbl.set_rows(rows)

        # 字符串列表
        srows = []
        for st in strs.all_strings():
            srows.append([(st.value[:100], C_STR, st.addr),
                          (hex(st.addr), C_ADDR, st.addr),
                          (str(len(st.referenced_by)), None, None)])
        self.str_tbl.set_rows(srows)

        # 导入表
        irows = []
        for name2, sym in sorted(so.imports.items()):
            plt_addr = next((a for a, n in so.plt_map.items() if n == name2), None)
            irows.append([(name2, C_IMPORT, name2),
                          ("func" if sym.is_func else "obj", C_MUTED, None),
                          (hex(plt_addr) if plt_addr else "-", C_ADDR, plt_addr)])
        self.imports_tbl.set_rows(irows)

        # 导出表
        erows = []
        for name2, sym in sorted(so.exports.items(), key=lambda kv: kv[1].addr):
            erows.append([(name2, C_FUNC, sym.addr),
                          (hex(sym.addr), C_ADDR, sym.addr),
                          (str(sym.size), C_MUTED, None)])
        self.exports_tbl.set_rows(erows)

        # 导航色带：导入 PLT 粉 -> 字符串区黄 -> 函数代码蓝（后画覆盖前，优先级递增）
        ranges = []
        for sec in so.sections:
            if sec.name == ".rodata":
                ranges.append((sec.addr, sec.end, "string"))
            elif not sec.is_exec:
                ranges.append((sec.addr, sec.end, "data"))
        for fn in so.functions.values():
            ranges.append((fn.addr, fn.end, "code"))
        for a in so.plt_map:
            ranges.append((a, a + 16, "import"))
        self.nav.set_ranges(ranges)
        self._log(f"当前模块 {name}")

    # ---------- 视图联动 ----------

    def ensure_xrefs_async(self, so_name: str) -> None:
        """后台线程构建引用图（不阻塞 UI）。

        「谁调用了本函数」必须扫描全库——6000+ 函数的样本要 20-30 秒。
        同步做会冻结窗口，因此放后台，完成后刷新当前视图。
        """
        if so_name in self._xref_building:
            return
        x = self.session.xref(so_name)
        if x._built:
            return
        self._xref_building.add(so_name)
        self._log(f"[引用图] {so_name} 后台构建中…（完成后自动刷新，不阻塞操作）")

        def job():
            return self.session.ensure_xrefs(so_name)

        w = Worker(job)
        w.finished_ok.connect(lambda _x, n=so_name: self._on_xref_built(n))
        w.failed.connect(lambda m, n=so_name: self._on_xref_failed(n, m))
        self._workers.append(w)
        w.start()

    def _on_xref_built(self, so_name: str) -> None:
        self._xref_building.discard(so_name)
        x = self.session.xref(so_name)
        # 构建已完成，直接读内部存储（避免属性触发重复的构建检查）
        edges = sum(len(v) for v in x._calls_to.values())
        self._log(f"[引用图] {so_name} 构建完成：{edges} 条调用边")
        # 若用户仍停在该模块，刷新视图以显示 XREF
        if self.current_so == so_name and self.current_func:
            self.show_function(so_name, self.current_func)

    def _on_xref_failed(self, so_name: str, msg: str) -> None:
        self._xref_building.discard(so_name)
        self._log(f"[引用图] {so_name} 构建失败: {msg.splitlines()[0]}")

    def show_function(self, so_name: str, addr: int) -> None:
        self.current_so = so_name
        self.current_func = addr
        so = self.session.get(so_name)
        x = self.session.xref(so_name)
        dis = x.disasm
        fn = so.function_at(addr)
        if fn is None:
            self._log(f"地址 {addr:#x} 不在任何函数内")
            return
        # 惰性：先只解本函数（毫秒级），保证反汇编立即可见
        x.ensure_function(fn.addr)
        # 入向 XREF 需要全库；未构建则后台补，完成后自动刷新
        self.ensure_xrefs_async(so_name)
        insns = fn.instructions or dis.disasm_function(addr)

        self.disasm.set_rows(self._build_disasm_rows(so_name, fn, insns))
        self.disasm.jump_to(addr)
        self.tabs.setCurrentIndex(0)

        self._build_pseudo(so_name, fn, insns)

        # Hex: 函数体全部字节（上限 4KB 防卡顿）
        data = so.read(fn.addr, min(fn.size, 4096))
        self.hex.set_data(fn.addr, data)
        self.hex.mark_position(addr)

        self.show_xrefs_to(addr)
        self.nav.set_cursor(addr)
        self.addr_label.setText(f" {so_name}!{fn.name or hex(fn.addr)}  @  {fn.addr:#x}  ({fn.size:#x} bytes) ")

    # ---------- IDA View-A 风格行构建 ----------

    def _name_segments(self, so_name: str, target: int) -> list[tuple[str, str | None, str | None]]:
        """把调用目标渲染为 [(文本, 颜色, 链接)]。"""
        so = self.session.get(so_name)
        plt = so.plt_name(target)
        if plt:
            # 跨 so 解析出真实落点则标注 so 名
            resolved = self.session.resolve_import(so_name, plt)
            label = f"{resolved[0]}!{plt}" if resolved else plt
            return [(label, C_IMPORT, f"func:{so_name}:{target}")]
        fn2 = so.function_at(target)
        if fn2:
            name = fn2.name or f"sub_{fn2.addr:x}"
            return [(name, C_EXPORT if fn2.is_export else C_FUNC, f"func:{so_name}:{fn2.addr}")]
        return [(hex(target), C_ADDR, f"jmp:{so_name}:{target}")]

    def _build_disasm_rows(self, so_name: str, fn, insns) -> list[dict]:
        """生成 IDA View-A 风格行：函数头 XREF 注释 + 分区着色指令行。"""
        so = self.session.get(so_name)
        x = self.session.xref(so_name)
        rows: list[dict] = []

        # 函数头
        fname = fn.name or f"sub_{fn.addr:x}"
        rows.append({
            "addr": None, "rail": "",
            "segments": [(f"; ── {so_name}!{fname} @ {fn.addr:#x} ({fn.size:#x} bytes)", C_MUTED, None)],
            "tooltip": "函数头",
        })
        # OUTGOING 跨 so 调用摘要行（本函数调用了哪些外部 so 的符号）
        # 注：calls_to 只有被调用者视角；函数自身的对外调用从 called_by 取
        # 单函数快速路径：UI 线程绝不能触发全量构建（会冻结窗口 15s+）
        outgoing: dict[str, list[int]] = {}
        for callee in x.callees_of_fn(fn.addr):
            plt = so.plt_name(callee)
            if plt:
                resolved = self.session.resolve_import(so_name, plt)
                if resolved and resolved[0] != so_name:
                    outgoing.setdefault(resolved[0], []).append(callee)
        if outgoing:
            for tgt_so, callees in sorted(outgoing.items()):
                names = sorted({so.plt_map[c] for c in callees if c in so.plt_map})
                first = names[0]
                rows.append({
                    "addr": None, "rail": "",
                    "segments": [
                        (f";   CROSS-SO → {tgt_so}!{first}", C_IMPORT, f"func:{tgt_so}:" + str(self._symbol_addr(tgt_so, first))),
                        (f"  (+{len(names)-1} more)" if len(names) > 1 else "", C_MUTED, None),
                    ],
                })
        # XREF 注释行（谁调用本函数），IDA 风格 "; CODE XREF: caller+off ↑j"
        callers = x.callers_of_fn(fn.addr)
        # 跨 so 调用者：本函数是导出符号时，查其他 so 的 PLT 调用
        if fname and not callers:
            for other_name, other in self.session.modules.items():
                if other_name == so_name:
                    continue
                other_x = self.session.xref(other_name)
                for stub_addr, stub_name in other.plt_map.items():
                    if stub_name != fname:
                        continue
                    if other_x.callers_of_fn(stub_addr):
                        callers.extend(other_x.callers_of_fn(stub_addr))
                        break
                if callers:
                    # 跨 so 的调用者要在对方 so 坐标系里展示
                    cross_rows = []
                    for site in callers[:4]:
                        cfn = other.function_at(site)
                        if cfn:
                            off = site - cfn.addr
                            cross_rows.append({
                                "addr": None, "rail": "",
                                "segments": [
                                    (f";   CODE XREF: ", C_MUTED, None),
                                    (f"{other_name}!{cfn.name or hex(cfn.addr)}+{off:#x}", C_IMPORT,
                                     f"func:{other_name}:{cfn.addr}"),
                                    (" ↑j", C_MUTED, None),
                                ],
                            })
                    rows.extend(cross_rows)
                    callers = []  # 已消费，避免下方重复渲染
        for site in callers[:8]:
            cfn = so.function_at(site)
            cname = (cfn.name or f"sub_{cfn.addr:x}") if cfn else hex(site)
            off = site - cfn.addr if cfn else 0
            rows.append({
                "addr": None, "rail": "",
                "segments": [
                    (f";   CODE XREF: ", C_MUTED, None),
                    (f"{cname}+{off:#x}", C_NOTE, f"func:{so_name}:{cfn.addr}" if cfn else None),
                    (" ↑j", C_MUTED, None),
                ],
            })
        if len(callers) > 8:
            rows.append({"addr": None, "rail": "",
                         "segments": [(f";   … 共 {len(callers)} 处引用", C_MUTED, None)]})

        for ins in insns:
            rail = ""
            if ins.is_call:
                rail = C_OK
            elif ins.is_jump:
                rail = C_WARN
            elif ins.is_ret:
                rail = C_COOL
            segs: list[tuple[str, str | None, str | None]] = [
                (f"{ins.addr:#08x}", C_ADDR, f"jmp:{so_name}:{ins.addr}"),
                (f"  {ins.bytes.hex(' ')}  ", C_FAINT, None),
                (f"{ins.mnemonic:<8}", C_FG, None),
            ]
            # 操作数：分支/调用目标与数据引用做成链接
            if ins.is_call and ins.call_target is not None:
                segs.append((f"{ins.call_target:#x}", C_ADDR, f"jmp:{so_name}:{ins.call_target}"))
            elif ins.ref_addr is not None:
                st = self.session.strings(so_name).string_starting_at_or_before(ins.ref_addr)
                if st:
                    segs.append((f'"{st.value[:32]}"', C_STR, f"str:{so_name}:{st.addr}"))
                else:
                    segs.append((f"{ins.ref_addr:#x}", C_ADDR, f"jmp:{so_name}:{ins.ref_addr}"))
            else:
                segs.append((ins.op_str, C_FG, None))

            # 尾注释
            if ins.is_call and ins.call_target is not None:
                segs.append(("  ; ", C_MUTED, None))
                segs.extend(self._name_segments(so_name, ins.call_target))
            elif ins.ref_addr is not None and not _has_str(segs):
                segs.append((f"  ; {ins.ref_addr:#x}", C_MUTED, None))

            # 用户/AI 写的注释（IDA 的 ; 注释列，teal 高亮）
            cmt = self.session.comments.get((so_name, ins.addr))
            if cmt:
                segs.append((f"  ; ★ {cmt}", "#0f9b8e", None))

            rows.append({
                "addr": ins.addr, "rail": rail, "segments": segs,
                "tooltip": f"{ins.addr:#x}  {ins.bytes.hex(' ')}",
            })
        return rows

    def _symbol_addr(self, so_name: str, symbol: str) -> int:
        """查符号在某 so 中的导出地址（无则 0）。"""
        so = self.session.modules.get(so_name)
        sym = so.exports.get(symbol) if so else None
        return sym.addr if sym else 0

    def _build_pseudo(self, so_name: str, fn, insns) -> None:
        """伪代码逐行渲染：调用名/字符串/跳转目标全部可点击。"""
        so = self.session.get(so_name)
        rows: list[dict] = []
        fname = fn.name or f"sub_{fn.addr:x}"
        rows.append({"rail": "", "segments": [
            (f"// {so_name}!{fname} @ {fn.addr:#x} ({fn.size:#x} bytes)", C_MUTED, None)]})
        rows.append({"rail": "", "segments": [
            ("void ", "#8250df", None), (fname, C_EXPORT, None), ("() {", C_FG, None)]})

        for ins in insns:
            m = ins.mnemonic
            if m in ("paciasp", "autiasp", "bti") or (m == "mov" and ins.op_str == "x29, sp"):
                continue
            if m in ("stp", "ldp") and "x29" in ins.op_str and "x30" in ins.op_str:
                continue

            segs: list[tuple[str, str | None, str | None]] = [("    ", None, None)]
            if ins.is_call and ins.call_target is not None:
                segs.extend(self._name_segments(so_name, ins.call_target))
                segs.append(("(...);", C_FG, None))
            elif ins.ref_addr is not None:
                st = self.session.strings(so_name).string_starting_at_or_before(ins.ref_addr)
                if st:
                    segs.append((f'"{st.value[:48]}"', C_STR, f"str:{so_name}:{st.addr}"))
                    segs.append((";", C_MUTED, None))
                    segs.append((ins.op_str, C_FAINT, None))
                else:
                    segs.append((ins.op_str, C_FG, None))
                    segs.append((f"  // -> {ins.ref_addr:#x}", C_MUTED, f"jmp:{so_name}:{ins.ref_addr}"))
            elif m == "ret":
                segs.append(("return;", C_FG, None))
            elif ins.is_jump and ins.call_target is not None:
                segs.append((f"goto {ins.call_target:#x}", C_NOTE, f"jmp:{so_name}:{ins.call_target}"))
            else:
                segs.append((f"{m} {ins.op_str}", C_FG, None))
            rail = C_OK if ins.is_call else (C_WARN if ins.is_jump else "")
            rows.append({"rail": rail, "segments": segs})

        rows.append({"rail": "", "segments": [("}", C_FG, None)]})
        self.pseudo.set_rows(rows)

    def _on_pseudo_link(self, link: str) -> None:
        self._follow_link(link)

    def _on_disasm_link(self, link: str) -> None:
        self._follow_link(link)

    def _follow_link(self, link: str) -> None:
        """统一链接协议：func:so:addr / jmp:so:addr / str:so:addr。"""
        try:
            kind, so_name, addr_text = link.split(":", 2)
            addr = int(addr_text, 0)
        except ValueError:
            return
        if kind == "str":
            # 字符串：跳到 xref 面板展示引用者
            st = self.session.strings(so_name).string_starting_at_or_before(addr)
            if st:
                self._on_str_activate(st.addr)
            return
        # func / jmp：反汇编内跳转；目标在别的 so 则切换模块
        fn = self.session.get(so_name).function_at(addr)
        self.show_function(so_name, fn.addr if fn else addr)

    def _annotate(self, so_name: str, ins) -> str:
        """指令右侧注释：调用符号 / 字符串内容。"""
        so = self.session.get(so_name)
        if ins.is_call and ins.call_target is not None:
            name = so.plt_name(ins.call_target)
            if not name:
                fn = so.function_at(ins.call_target)
                name = (fn.name if fn and fn.name else hex(ins.call_target))
            return f"; {name}"
        if ins.ref_addr is not None:
            st = self.session.strings(so_name).string_starting_at_or_before(ins.ref_addr)
            if st:
                return f'; "{st.value[:60]}"'
            return f"; {ins.ref_addr:#x}"
        return ""

    def _resolve(self, so_name: str, target: int):
        link = self.session.resolve_call(so_name, target)
        return (link.callee_so, link.callee, link.callee_addr) if link else None

    def show_xrefs_to(self, addr: int) -> None:
        so_name = self.current_so
        x = self.session.xref(so_name)
        so = self.session.get(so_name)
        # 入向引用依赖全库数据：未构建则后台补（不阻塞）
        self.ensure_xrefs_async(so_name)
        sites = x.xrefs_to(addr)
        rows = []
        for site in sites:
            fn = so.function_at(site)
            rows.append([(hex(site), C_ADDR, site),
                         (fn.name or f"sub_{fn.addr:x}" if fn else "?", C_FUNC, site),
                         ("call", C_MUTED, None)])
        if not rows:
            rows = [[("（无引用）", C_MUTED, None), ("", None, None), ("", None, None)]]
        self.xref_tbl.set_rows(rows)

    # ---------- 激活回调 ----------

    def _on_func_activate(self, data) -> None:
        if isinstance(data, int) and self.current_so:
            self.show_function(self.current_so, data)

    def _on_str_activate(self, data) -> None:
        if not (isinstance(data, int) and self.current_so):
            return
        st = self.session.strings(self.current_so).string_starting_at_or_before(data)
        if st is None:
            return
        so = self.session.get(self.current_so)
        rows = []
        for site in st.referenced_by:
            fn = so.function_at(site)
            rows.append([(hex(site), C_ADDR, site),
                         (fn.name or f"sub_{fn.addr:x}" if fn else "?", C_FUNC, site),
                         ("string", C_STR, None)])
        self.xref_tbl.set_rows(rows or [[("（无引用）", C_MUTED, None), ("", None, None), ("", None, None)]])
        self.tabs.setCurrentWidget(self.xref_tbl)

    def _on_import_activate(self, data) -> None:
        """点击导入符号：跳到它的 PLT stub。"""
        if isinstance(data, int) and data and self.current_so:
            self.show_function(self.current_so, data)

    def _on_export_activate(self, data) -> None:
        if isinstance(data, int) and data and self.current_so:
            self.show_function(self.current_so, data)

    def _on_xref_activate(self, data) -> None:
        if isinstance(data, int) and data and self.current_so:
            self.show_function(self.current_so, data)

    def _on_disasm_activate(self, addr: int) -> None:
        if addr > 0:
            # 跳转到调用目标
            so = self.session.get(self.current_so)
            target_fn = so.function_at(addr)
            if target_fn:
                self.show_function(self.current_so, addr)
            else:
                # PLT stub：显示所在函数（PLT 也在函数表外的场景直接反汇编区间）
                self._log(f"跳转 {addr:#x}")
        else:
            # 负数约定：请求当前行指令的 xref
            self.show_xrefs_to(-addr)
            self.tabs.setCurrentWidget(self.xref_tbl)

    def _on_nav_click(self, addr: int) -> None:
        fn = self.session.get(self.current_so).function_at(addr) if self.current_so else None
        if fn:
            self.show_function(self.current_so, fn.addr)

    # ---------- 跨 so 调用链 ----------

    def _show_call_chain(self) -> None:
        if not (self.current_so and self.current_func):
            self._log("先在函数列表选择一个函数")
            return
        chain = self.session.call_chain(self.current_so, self.current_func, depth=3)
        self.pseudo.setPlainText(chain.as_text())
        self.tabs.setCurrentWidget(self.pseudo)

    # ---------- 设备 ----------

    def _refresh_device(self) -> None:
        from dyn.adb import Adb

        def job():
            return Adb.list_devices()

        w = Worker(job)
        w.finished_ok.connect(self._on_devices)
        self._workers.append(w)
        w.start()

    def _on_devices(self, devs) -> None:
        live = [d for d in devs if d.state == "device"]
        self.dev_label.setText(f" 设备: {live[0].serial if live else '未连接'} ")
        self.dynamic.refresh_devices()

    # ---------- 跳转 ----------

    def jump_to(self, text: str) -> None:
        text = text.strip()
        if not (self.current_so and text):
            return
        try:
            addr = int(text, 0)
        except ValueError:
            # 函数名查找
            so = self.session.get(self.current_so)
            for fn in so.functions.values():
                if fn.name and text.lower() in fn.name.lower():
                    self.show_function(self.current_so, fn.addr)
                    return
            self._log(f"找不到函数: {text}")
            return
        self.show_function(self.current_so, addr)


def asset_path(name: str) -> str:
    """资源文件绝对路径（兼容源码运行与 PyInstaller 打包）。

    打包后 PyInstaller 把 data 解到 sys._MEIPASS；源码运行时用项目根目录。
    """
    import os

    base = getattr(sys, "_MEIPASS", None)
    if base is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", name)


def run_gui() -> None:
    """GUI 入口：命令行参数作为初始 so 预加载。

    生命周期约定：UI 是主、服务是仆——
    窗口关闭时（closeEvent）先停 MCP 服务，再退出进程，
    保证不残留后台 HTTP 服务与占用的 8765 端口。
    """
    import os

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    # 应用图标：窗口 / Dock / 任务栏统一用 logo；文件缺失时静默跳过不影响运行
    icon_file = asset_path("logo_512.png")
    app_icon = QIcon(icon_file) if os.path.exists(icon_file) else None
    if app_icon is not None:
        app.setWindowIcon(app_icon)
    win = MainWindow()
    if app_icon is not None:
        win.setWindowIcon(app_icon)
    win.show()
    for p in sys.argv[1:]:
        win.load_so(p)
    # 兜底：异常退出/被 kill 时也尽量释放端口
    app.aboutToQuit.connect(win._shutdown_services)
    sys.exit(app.exec())


class _PlainView(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(_MONO)

    def append(self, text: str) -> None:
        self.appendPlainText(text)


def _parse_json_or_empty(text: str) -> dict:
    """插件对话框输入转 JSON，空串/非法输入按空参数处理。"""
    import json

    text = text.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class _JumpEdit(QLineEdit):
    """跳转输入框：回车触发主窗口跳转。"""

    def __init__(self, win: "MainWindow"):
        super().__init__()
        self._win = win
        self.returnPressed.connect(lambda: self._win.jump_to(self.text()))
