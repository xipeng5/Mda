# -*- mode: python ; coding: utf-8 -*-
"""MDA 打包配置（macOS .app）。

当前形态：Web UI（React + TS）+ Python 内核 + 内置 MCP，窗口用 pywebview（系统 WKWebView）。
所以打包只需要三样东西：
  1. Python 代码：app.py / core / mcp_server / server / dyn / scripting / plugins
  2. 运行期按路径读取的资源：assets/（图标）、plugins/（插件）
  3. 前端构建产物：web/dist（由 server/api.py 静态托管）

注意：
  - 不再依赖 PySide6；若环境里装着也会被 excludes 排掉，体积少一大截。
  - uvicorn / mcp / webview / dyn 有动态导入，必须显式声明 hiddenimports。
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
    (os.path.join(ROOT, "web", "dist"), os.path.join("web", "dist")),   # 前端产物
]

hiddenimports = (
    collect_submodules("uvicorn")
    # mcp.cli 是官方命令行入口，依赖 typer 且 import 期会 sys.exit
    + collect_submodules("mcp", filter=lambda n: not n.startswith("mcp.cli"))
    + collect_submodules("webview")      # pywebview 按平台动态选后端
    + collect_submodules("dyn")          # 动态分析按需 import，静态扫不到
    + ["anyio._backends._asyncio"]
)

# 用不到的重型依赖，排除以控制体积
excludes = [
    "PySide6", "PyQt5", "PyQt6", "shiboken6",
    "mcp.cli", "typer", "tkinter", "matplotlib", "pandas", "numpy",
    "scipy", "IPython", "pytest",
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
