"""MDA 0.2.1 UI 改后验收（P0 + P0.5）：离屏渲染 + 断言表 + 取证 PNG。

为什么这样做（背景与取舍）：
1. 用户要"看到效果"，而 macOS 截屏有权限门槛、真跑 GUI 又会和正在运行的实例抢
   8765 端口。因此统一用 QT_QPA_PLATFORM=offscreen 离屏渲染真实代码，并把
   McpService.start_http 打桩为空函数（只是不监听端口，不影响任何业务数据）。
2. 断言表直接对应任务书第 4 节验收表；任何一条 FAIL 退出码为 1，便于 CI/复核。
3. "改前"对照图不碰 git（禁止写操作），直接复用设计评审阶段已归档的
   docs/ui-review/ui-designer/current-offscreen.png，与本次渲染图上下拼接。
4. 工程 venv 里只装了 PySide6、没装 Pillow；系统 Python 用户目录里有已装好的
   Pillow 12.1.0（同为 CPython 3.11 ABI）。这里只把 user-site 追加进 sys.path
   复用系统已装版本，**不新增依赖、不 pip install**。若确实找不到 Pillow，
   脚本仍会产出 after PNG，并明确打印"对照图未生成"，不伪造结果。

运行方式（不需要任何命令行参数）：
    QT_QPA_PLATFORM=offscreen .venv/bin/python tests/ui_review/verify_after.py

输出：
    docs/ui-review/after/after-1680.png      本次改后整窗渲染（1680x980）
    docs/ui-review/after/before-after-2.png  上=改前（评审归档图）下=改后
    终端：断言表 + 几何/取色明细 + 退出码

注意：本脚本只读 ui/ 代码，不修改任何文件。
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

OUT_DIR = os.path.join(ROOT, "docs", "ui-review", "after")
BEFORE_PNG = os.path.join(ROOT, "docs", "ui-review", "ui-designer", "current-offscreen.png")
SAMPLE = os.path.join(ROOT, "samples", "libbase.so")
AFTER_PNG = os.path.join(OUT_DIR, "after-1680.png")
COMPARE_PNG = os.path.join(OUT_DIR, "before-after-2.png")

WIN_W, WIN_H = 1680, 980

# ---- Qt 消息收集：任务书要求「stderr 里无 stylesheet 解析告警」----
# qInstallMessageHandler 截获的正是原本打到 stderr 的 Qt 告警，进程内断言比肉眼
# 看终端更可靠；同时把内容原样打印，便于复核。
_qt_messages: list[str] = []


def _qt_message_handler(mode, context, message: str) -> None:
    _qt_messages.append(str(message))


from PySide6.QtCore import QPoint, Qt, qInstallMessageHandler  # noqa: E402

qInstallMessageHandler(_qt_message_handler)

from PySide6.QtGui import QImage  # noqa: E402
from PySide6.QtWidgets import QApplication, QDockWidget, QFrame  # noqa: E402


# ---------------------------------------------------------------------------
# 工具：事件泵 / 取样 / 断言
# ---------------------------------------------------------------------------

def pump(app: QApplication, seconds: float = 0.15) -> None:
    """跑一会儿事件循环，让布局、绘制、跨线程信号都落定。"""
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)


def map_rect(widget, window) -> tuple[int, int, int, int]:
    """控件矩形换算到主窗口坐标（grab() 用的就是这套坐标）。"""
    origin = widget.mapTo(window, QPoint(0, 0))
    return origin.x(), origin.y(), widget.width(), widget.height()


def dominant_colors(image: QImage, rect: tuple[int, int, int, int],
                    scale: float, nx: int = 9, ny: int = 5) -> list[tuple[str, float]]:
    """在矩形内按网格取样，返回 [(#rrggbb, 占比), ...]（占比降序）。

    为什么用"众数 + 占比"而不是单个像素：反汇编/表格里必然夹着文字像素，
    单点取色会因命中字符而误判；取整片背景的众数才代表真实底色。
    """
    x, y, w, h = rect
    counts: dict[str, int] = {}
    total = 0
    for iy in range(ny):
        for ix in range(nx):
            px = int((x + w * (ix + 0.5) / nx) * scale)
            py = int((y + h * (iy + 0.5) / ny) * scale)
            if 0 <= px < image.width() and 0 <= py < image.height():
                name = image.pixelColor(px, py).name()
                counts[name] = counts.get(name, 0) + 1
                total += 1
    if total == 0:
        return []
    return sorted(((c, n / total) for c, n in counts.items()),
                  key=lambda kv: kv[1], reverse=True)


class Report:
    """断言表：每行 = 名称 / 期望 / 实测 / 结果。"""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []

    def check(self, name: str, expected: str, actual, ok: bool) -> None:
        self.rows.append((name, expected, str(actual), bool(ok)))

    def failed(self) -> list[tuple[str, str, str, bool]]:
        return [r for r in self.rows if not r[3]]

    def dump(self) -> None:
        print("\n断言表（任务书第 4 节）")
        print("-" * 96)
        for name, expected, actual, ok in self.rows:
            mark = "PASS" if ok else "FAIL"
            print(f"[{mark}] {name:<34} 期望={expected:<16} 实测={actual}")
        print("-" * 96)


# ---------------------------------------------------------------------------
# 拼图（Pillow；系统已装，venv 复用 user-site，不新增依赖）
# ---------------------------------------------------------------------------

def _import_pillow():
    try:
        from PIL import Image  # noqa: F401

        return Image
    except ImportError:
        import site

        user_site = site.getusersitepackages()
        if user_site and user_site not in sys.path and os.path.isdir(user_site):
            sys.path.append(user_site)
        from PIL import Image  # noqa: F401

        return Image


def _label_font():
    from PIL import ImageFont

    candidates = (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
    )
    for path in candidates:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, 15)
            except OSError:
                continue
    return ImageFont.load_default()


def compose_before_after() -> tuple[bool, str]:
    """上=旧图（评审归档），下=本次改后图，同宽拼接；返回 (是否成功, 说明)。"""
    if not os.path.exists(BEFORE_PNG):
        return False, f"缺少改前证据图：{BEFORE_PNG}（评审阶段归档），未生成对照图"
    if not os.path.exists(AFTER_PNG):
        return False, f"改后图未生成：{AFTER_PNG}"
    try:
        Image = _import_pillow()
    except ImportError as e:  # 明确报告，不伪造
        return False, f"Pillow 不可用（{e}），未生成对照图"

    from PIL import ImageDraw

    before = Image.open(BEFORE_PNG).convert("RGB")
    after = Image.open(AFTER_PNG).convert("RGB")
    width = before.width
    # 两侧必须在同宽下比较：改后图理论上也是 1680，宽了才缩放（只做等比缩放）
    if after.width != width:
        after = after.resize((width, round(after.height * width / after.width)))

    font = _label_font()
    label_h = 26
    divider_h = 2
    canvas_h = label_h + before.height + divider_h + label_h + after.height
    canvas = Image.new("RGB", (width, canvas_h), (245, 246, 245))
    draw = ImageDraw.Draw(canvas)

    def _strip(y: int, text: str) -> None:
        draw.rectangle([0, y, width, y + label_h], fill=(245, 246, 245))
        draw.text((10, y + 5), text, fill=(34, 38, 37), font=font)

    _strip(0, f"BEFORE  docs/ui-review/ui-designer/current-offscreen.png   {before.width}x{before.height}")
    canvas.paste(before, (0, label_h))
    y2 = label_h + before.height
    draw.rectangle([0, y2, width, y2 + divider_h], fill=(228, 231, 230))
    y3 = y2 + divider_h
    _strip(y3, f"AFTER   docs/ui-review/after/after-1680.png   {after.width}x{after.height}")
    canvas.paste(after, (0, y3 + label_h))
    canvas.save(COMPARE_PNG, "PNG")
    return True, f"{COMPARE_PNG} ({width}x{canvas_h})"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 96)
    print("MDA 0.2.1 UI 改后验收（P0 + P0.5）— offscreen 真实渲染")
    print("=" * 96)

    if not os.path.exists(SAMPLE):
        print(f"[ERROR] 样本缺失：{SAMPLE}")
        return 2

    # 1) 打桩 MCP 服务：只跳过 HTTP 监听，业务与数据全部走真实代码
    from mcp_server.service import McpService

    def _stub_start_http(self, *_args, **_kwargs):  # noqa: ANN001
        return False

    McpService.start_http = _stub_start_http

    import ui.theme as theme
    from ui.main_window import MainWindow

    app = QApplication([])
    app.setStyleSheet(theme.STYLE)  # 与 ui/main_window.py:1047 run_gui 完全一致
    win = MainWindow()
    win.resize(WIN_W, WIN_H)
    win.show()
    pump(app, 0.4)

    # 2) 走真实加载路径（Worker 线程 → _on_loaded → _select_first_function）
    win.load_so(SAMPLE)
    t0 = time.time()
    while time.time() - t0 < 90 and win.current_so is None:
        pump(app, 0.05)
    pump(app, 1.0)  # 等 _on_loaded 后续（自动选中函数、设备刷新）落定
    if win.current_so is None:
        print(f"[ERROR] 样本加载 90s 未完成（worker 可能失败），Output 日志尾部：")
        print(win.out_view.toPlainText()[-1200:])

    # 3) 截图（先 grab，后续几何测量不会影响已渲染像素）
    shot = win.grab()
    image = shot.toImage()
    scale = image.width() / max(1, win.width())  # 兼容 dpr≠1 的环境
    os.makedirs(OUT_DIR, exist_ok=True)
    shot.save(AFTER_PNG, "PNG")

    # 4) 断言与取证
    rep = Report()

    # 4.1 卡片内部：取反汇编页视口（卡片内部最大连续区域）的众数底色
    disasm_vp = win.disasm.viewport()
    card_rect = map_rect(disasm_vp, win) if disasm_vp.isVisible() else map_rect(
        win.centralWidget().findChild(QFrame, "card"), win)
    card_top = dominant_colors(image, card_rect, scale)
    card_color, card_share = (card_top[0] if card_top else ("(取样失败)", 0.0))
    rep.check("卡片内部取样 = #ffffff", "#ffffff",
              f"{card_color} (占比 {card_share:.0%})",
              card_color == "#ffffff" and card_share >= 0.60)

    # 4.2 tab 条背景：取最后一个 tab 右侧的空白区（避开 tab 文字/选中胶囊）
    tabbar = win.tabs.tabBar()
    last_rect = tabbar.tabRect(tabbar.count() - 1)
    tb_x, tb_y, tb_w, tb_h = map_rect(tabbar, win)
    gap_x = tb_x + last_rect.right() + 10
    gap_w = max(1, tb_x + tb_w - gap_x - 8)
    tab_rect = (gap_x, tb_y + int(tb_h * 0.25), gap_w, max(1, int(tb_h * 0.5)))
    tab_top = dominant_colors(image, tab_rect, scale, nx=8, ny=3)
    tab_color, tab_share = (tab_top[0] if tab_top else ("(取样失败)", 0.0))
    tab_colors = [c for c, _ in tab_top]
    groove = [c for c in tab_colors if c.lower() in ("#c5c5c5", "#bebebe")]
    rep.check("tab 条背景 = #ffffff（无灰槽）", "#ffffff",
              f"{tab_color} (占比 {tab_share:.0%}) 灰槽={groove or '无'}",
              tab_color == "#ffffff" and tab_share >= 0.60 and not groove)

    # 4.3 导航色带高度
    rep.check("nav 高 = 8", "8", win.nav.height(), win.nav.height() == 8)

    # 4.4 左函数表行高
    table = win.func_tbl.table
    row_h = table.rowHeight(0) if table.rowCount() else -1
    rep.check("左函数表 rowHeight(0) ≤ 22", "≤22", row_h, 0 < row_h <= 22)

    # 4.5 左函数表横向滚动条
    hbar_visible = table.horizontalScrollBar().isVisible()
    rep.check("左函数表横向滚动条 isVisible=False", "False", hbar_visible, hbar_visible is False)

    # 4.6 底部 dock 高度
    out_h = win.out_dock.height()
    rep.check("底部 dock 高 ≤ 176", "≤176", out_h, out_h <= 176)

    # 4.7 左右 dock 宽度
    left_w = win.func_dock.width()
    right_docks = [d for d in win.findChildren(QDockWidget)
                   if win.dockWidgetArea(d) == Qt.RightDockWidgetArea]
    right_w = right_docks[0].width() if right_docks else -1
    rep.check("左 dock 宽 ≤ 280", "≤280", left_w, left_w <= 280)
    rep.check("右 dock 宽 ≤ 240", "≤240", right_w, right_w <= 240)

    # 4.8 载入后中央区非空（_select_first_function 生效）
    disasm_count = win.disasm.count()
    rep.check("载入后 disasm.count() > 0", ">0", disasm_count, disasm_count > 0)

    # 4.9 Qt 消息里无样式解析告警
    style_msgs = [m for m in _qt_messages
                  if "stylesheet" in m.lower() or "could not parse" in m.lower()]
    rep.check("无 stylesheet 解析告警", "0 条", f"{len(style_msgs)} 条", not style_msgs)

    # 4.10 附加：P0/P0.5 其余硬性要求（不属上表，但任务书写死，这里一并验）
    rep.check("左函数表关闭交替行色", "False", table.alternatingRowColors(),
              table.alternatingRowColors() is False)
    rep.check("tabs.documentMode 保持 True", "True", win.tabs.documentMode(),
              win.tabs.documentMode() is True)
    token_ok = (hasattr(theme, "C_SELECT_BG") and hasattr(theme, "RADIUS_XS")
                and theme.RADIUS == 8 and theme.RADIUS_SM == 6)
    rep.check("theme token C_SELECT_BG/RADIUS_XS/RADIUS=8/RADIUS_SM=6", "齐全",
              f"{hasattr(theme, 'C_SELECT_BG')}/{hasattr(theme, 'RADIUS_XS')}/"
              f"{theme.RADIUS}/{theme.RADIUS_SM}", token_ok)

    rep.dump()

    # 5) 几何与取色明细（复现与复核用）
    print("\n几何 / 取色明细")
    print("-" * 96)
    print(f"窗口           : {win.width()}x{win.height()}  grab={image.width()}x{image.height()} dpr={scale:.2f}")
    print(f"卡片内部取样区 : {card_rect}  众数Top3={card_top[:3]}")
    print(f"tab 条取样区   : {tab_rect}  众数Top3={tab_top[:3]}")
    print(f"nav            : h={win.nav.height()} abs={map_rect(win.nav, win)}")
    print(f"左函数表       : rows={table.rowCount()} row_h={row_h} header_h="
          f"{table.horizontalHeader().height()} viewport_w={table.viewport().width()} "
          f"cols={[table.columnWidth(i) for i in range(3)]} hbar={hbar_visible}")
    print(f"停靠窗         : left_w={left_w} right_w={right_w} out_h={out_h}")
    print(f"右 dock 标题   : {[d.windowTitle() for d in right_docks]}")
    print(f"disasm         : count={disasm_count} current_so={win.current_so} "
          f"当前 tab={win.tabs.tabText(win.tabs.currentIndex())}")
    print(f"底部 dock 下限 : dynamic.minimumSizeHint={win.dynamic.minimumSizeHint().toTuple()} "
          f"out_dock.minimumSize={win.out_dock.minimumSize().toTuple()}")
    print(f"Qt 消息        : 共 {len(_qt_messages)} 条（样式相关 {len(style_msgs)} 条）")
    for m in _qt_messages[:8]:
        print(f"  · {m}")

    # 6) 对照图
    ok, detail = compose_before_after()
    print("\n证据输出")
    print("-" * 96)
    print(f"改后整窗图     : {AFTER_PNG} ({image.width()}x{image.height()})")
    print(f"改前/改后对照  : {'OK  ' + detail if ok else '未生成 — ' + detail}")

    failed = rep.failed()
    print("\n合计: {} PASS / {} FAIL".format(len(rep.rows) - len(failed), len(failed)))
    if failed:
        print("未通过项:")
        for name, expected, actual, _ in failed:
            print(f"  - {name}: 期望 {expected}，实测 {actual}")
    print("=" * 96)

    # 7) 收尾：停服务、等 worker 收尾，避免 QThread 运行中析构
    try:
        win._shutdown_services()
    except Exception:
        pass
    deadline = time.time() + 5
    while time.time() < deadline:
        app.processEvents()
        if not [w for w in win._workers if w.isRunning()]:
            break
        time.sleep(0.02)
    win.close()
    pump(app, 0.2)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
