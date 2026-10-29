"""诊断：逐段启用 QSS，定位导致渲染极慢/卡住的规则（结果写 JSON 文件，避免被缓冲）。"""
import json
import signal
import sys
import time

sys.path.insert(0, ".")
sys.path.insert(0, "tests/ui_review")

RESULTS = []


class Timeout(Exception):
    pass


def _alarm(_s, _f):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def probe(label: str, qss: str) -> None:
    """在独立进程里跑不了，这里用子进程递归；本函数只在子进程中执行。"""
    from PySide6.QtWidgets import QApplication, QLabel, QTabWidget

    t0 = time.time()
    app = QApplication([])
    app.setStyleSheet(qss)
    w = QTabWidget()
    w.setDocumentMode(label.endswith("doc1"))
    for t in ["反汇编", "伪代码", "Hex"]:
        w.addTab(QLabel(t), t)
    w.resize(600, 200)
    w.show()
    for _ in range(5):
        app.processEvents()
    pm = w.grab()
    img = pm.toImage()
    RESULTS.append({
        "label": label,
        "ms": round((time.time() - t0) * 1000),
        "trough_right": img.pixelColor(560, 10).name(),
        "trough_tab": img.pixelColor(60, 10).name(),
        "tab0_x": w.tabBar().tabRect(0).x(),
    })


def build_partial(part: int) -> str:
    from theme_v2_proto import TOKENS as T

    FONT = "PingFang SC, Helvetica Neue, sans-serif" if part >= 2 else "-apple-system, 'PingFang SC', sans-serif"
    base = f"QWidget {{ background: transparent; color: {T['text1']}; font-family: {FONT}; font-size: {T['fs_body']}px; }}"
    tabrules = (
        f"QTabWidget::pane {{ border: none; background: transparent; }}"
        f"QTabBar {{ background: transparent; }}"
        f"QTabBar::tab {{ background: transparent; border: none; color: {T['text2']}; padding: 6px 12px; }}"
        f"QTabBar::tab:selected {{ color: {T['text1']}; border-bottom: 2px solid {T['accent_line']}; }}"
    )
    if part == 0:
        return base
    if part == 1:
        return base + tabrules
    if part == 2:
        return base + tabrules
    if part == 3:
        return base + tabrules.replace("QTabBar { background: transparent; }", "")
    return base


if __name__ == "__main__":
    import subprocess

    cases = [(0, "baseline-doc1"), (1, "tabrules-doc1"), (2, "font-list-doc1"), (3, "no-tabbar-bg-doc1"), (4, "tabrules-doc0")]
    for part, label in cases:
        code = (
            "import sys; sys.path.insert(0,'.'); sys.path.insert(0,'tests/ui_review');"
            "import diag_qss_bisect as d;"
            f"d.probe({label!r}, d.build_partial({part}));"
            "import json; print(json.dumps(d.RESULTS))"
        )
        try:
            out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=25)
            last = [ln for ln in out.stdout.splitlines() if ln.startswith("[")]
            print(label, "->", last[-1] if last else f"no-json rc={out.returncode} err={out.stderr.strip()[-300:]}")
        except subprocess.TimeoutExpired:
            print(label, "-> TIMEOUT(>25s)")
