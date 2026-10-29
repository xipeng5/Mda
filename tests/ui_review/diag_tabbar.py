"""诊断：documentMode + 新版 QSS 下 QTabBar 的表现（是否卡住 / 槽色 / 对齐）。"""
import faulthandler
import sys

faulthandler.dump_traceback_later(15, repeat=True)
sys.path.insert(0, ".")
sys.path.insert(0, "tests/ui_review")
from PySide6.QtWidgets import QApplication, QLabel, QTabWidget  # noqa: E402

from theme_v2_proto import build_qss  # noqa: E402

app = QApplication(sys.argv)
app.setStyleSheet(build_qss())
for docmode in (True, False):
    w = QTabWidget()
    w.setDocumentMode(docmode)
    for t in ["反汇编", "伪代码", "Hex", "导入", "导出", "交叉引用"]:
        w.addTab(QLabel(t), t)
    w.resize(900, 300)
    w.show()
    for _ in range(5):
        app.processEvents()
    pm = w.grab()
    pm.save(f"docs/ui-review/ui-designer/diag-tab-doc{int(docmode)}.png")
    img = pm.toImage()
    print(f"docmode={docmode} size={pm.size()} rects={[w.tabBar().tabRect(i).getRect() for i in range(w.count())]}")
    print("   band y=10 x=850 color:", img.pixelColor(850, 10).name(),
          " x=20:", img.pixelColor(20, 10).name(),
          " y=20:", img.pixelColor(20, 20).name())
    w.close()
print("done")
