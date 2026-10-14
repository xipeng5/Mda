# -*- mode: python ; coding: utf-8 -*-
"""MDA 打包配置（macOS .app / Windows .exe 通用）。

要点：
  1. assets/ 与 plugins/ 是**运行期按路径读取**的资源（不是 import 进来的），
     必须作为 data 打进包，否则装完没有 logo、插件也扫不到。
     - assets/  由 ui/main_window.py:asset_path() 定位（打包后取 sys._MEIPASS）
     - plugins/ 由 core/plugins.py 按 __file__ 相对定位
  2. uvicorn / mcp 的部分实现是动态导入，显式声明 hiddenimports 才不会漏。
  3. 排除体积巨大且用不到的 Qt 模块（WebEngine 一个就上百 MB）。
"""
import os

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.dirname(SPECPATH)          # 仓库根目录（spec 在 packaging/ 下）

# 版本号唯一来源（version.py），避免 spec 与代码各写一份
_ver_ns = {}
with open(os.path.join(ROOT, "version.py"), encoding="utf-8") as _f:
    exec(_f.read(), _ver_ns)
VERSION = _ver_ns["__version__"]

datas = [
    (os.path.join(ROOT, "assets"), "assets"),
    (os.path.join(ROOT, "plugins"), "plugins"),
]

hiddenimports = (
    collect_submodules("uvicorn")
    # 排除 mcp.cli：那是官方命令行入口，依赖 typer（本项目不用），
    # 且它在 import 期会 sys.exit(1)，会让 collect_submodules 直接失败。
    + collect_submodules("mcp", filter=lambda n: not n.startswith("mcp.cli"))
    + ["anyio._backends._asyncio"]
)

# 未使用的重型 Qt 模块，排除以控制体积
excludes = [
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtQuick",
    "PySide6.QtQml",
    "PySide6.Qt3DCore",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtMultimedia",
    "PySide6.QtNetworkAuth",
    "PySide6.QtPdf",
    "mcp.cli",
    "typer",
    "tkinter",
    "matplotlib",
    "pandas",
    "numpy",
]

a = Analysis(
    [os.path.join(ROOT, "app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MDA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,                        # GUI 程序，不弹终端
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "assets", "icon.icns"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MDA",
)

app = BUNDLE(
    coll,
    name="MDA.app",
    icon=os.path.join(ROOT, "assets", "icon.icns"),
    bundle_identifier="com.xipeng5.mda",
    info_plist={
        "CFBundleName": "MDA",
        "CFBundleDisplayName": "MDA",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
        # 需要访问本地网络（GUI 内置 MCP 服务监听 127.0.0.1）
        "NSLocalNetworkUsageDescription": "MDA 内置 MCP 服务供 AI 客户端连接",
    },
)
