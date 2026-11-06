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

def _scan_pkg_modules(root: str, pkg: str) -> list:
    """扫描某个包目录下的**全部** .py，返回 "pkg.mod" 形式的模块名列表。

    (3) 第三次修改（2026-11-06）：新增。

    为什么不用 collect_submodules：它在 PyInstaller 6.22.3 下会漏模块
    （本仓库已实测三次），而漏掉的模块在打包版里表现为 MODULE_UNAVAILABLE，
    源码环境却完全正常——这类问题极难发现。

    为什么不用硬编码列表：每新增一个文件都要回来改 spec，人一定会忘。

    直接扫目录最可靠：文件在，模块就在。
    """
    import os as _os

    pkg_dir = _os.path.join(root, pkg)
    out = []
    if not _os.path.isdir(pkg_dir):
        return out
    for name in sorted(_os.listdir(pkg_dir)):
        if not name.endswith(".py"):
            continue
        stem = name[:-3]
        if stem in ("__init__", "__main__"):
            continue
        out.append(f"{pkg}.{stem}")
    return out


# frida_tools 的 bridges/*.js 是**数据文件**，必须单独收；
# 只加 hiddenimports 拿不到 js，运行期 open() 会 FileNotFoundError。
_frida_tools_datas = []
try:
    from PyInstaller.utils.hooks import collect_data_files

    _frida_tools_datas = collect_data_files("frida_tools")
except Exception:
    _frida_tools_datas = []

datas = [
    *_frida_tools_datas,
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
    # (2) 第二次修改（2026-11-05）：
    #     bug 原因：collect_submodules("dyn") 在 PyInstaller 6.22.3 下
    #              虽然返回 11 个子模块，但 dyn.tracer / dyn.bridge / dyn.memread
    #              分析阶段被跳过（PYZ 里只有 8 个），导致运行期
    #              trace_* / suggest_breakpoints / read_typed 报 MODULE_UNAVAILABLE。
    #     解决方案：显式声明，不依赖 collect_submodules 的隐式收集。
    #
    # (3) 第三次修改（2026-11-06）：改成**目录扫描**，彻底根治这类问题。
    #     bug 原因：显式列表是"打补丁"——每次新增 dyn 模块都要记得回来加一行，
    #              忘了就漏。实测又漏了 dyn.java_bridge / dyn.dispatch / dyn.jni
    #              三个（新增的 Java 能力在打包版里直接不可用，报
    #              MODULE_UNAVAILABLE，而源码环境完全正常，极难发现）。
    #              同类问题这是第三次（mcp_server.link、dyn.tracer 三件套、
    #              现在这三个），说明"靠人记"的做法本身不可靠。
    #     解决方案：直接扫 dyn/ 目录下的所有 .py，自动生成模块列表。
    #              以后新增文件**不用改 spec**。
    + _scan_pkg_modules(ROOT, "dyn")
    # (4) 第四次修改（2026-11-06）：把 frida_tools 打进去。
    #     bug 原因：Java bridge 的源码由 `frida_tools/bridges/java.js` 提供
    #              （frida 17 起 bridge 不再内置在 server 里）。frida_tools
    #              是**运行期按路径读文件**，PyInstaller 静态分析看不到，
    #              于是打包版里 java_bridge 报 NO_FRIDA_TOOLS，
    #              而源码环境完全正常。
    #     解决方案：collect_submodules 收模块 + collect_data_files 收
    #              bridges/*.js（js 是数据文件，光收模块拿不到它）。
    + collect_submodules("frida_tools")
    # (1) 第一次修改（2026-10-30）：显式声明 mcp_server 子模块。
    #     bug 原因：mcp_server.link 是在工具包装器里用 `from mcp_server import link`
    #               运行期动态导入的，PyInstaller 静态分析扫不到，打包后
    #               该导入失败 →「AI 调用转发到 GUI」的修复在发布版里失效。
    #     解决方案：collect_submodules("mcp_server") 把所有子模块都打进去。
    + collect_submodules("mcp_server")
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
