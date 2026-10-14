"""MCP 配置对话框：一键复制 MDA 的 MCP 配置，粘到 AI 客户端即可用。

为什么需要它：MCP 配置里要写「Python 解释器绝对路径 + mda.py 绝对路径」，
手写容易错（尤其是打包版和源码版路径完全不同）。这里按当前运行形态
自动生成，用户只负责点「复制」。
"""
from __future__ import annotations

import json
import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

# 各客户端配置文件位置（提示用）
_CLIENT_PATHS = [
    ("Claude Desktop", "~/Library/Application Support/Claude/claude_desktop_config.json"),
    ("Cursor", "~/.cursor/mcp.json"),
    ("Claude Code", ".mcp.json（项目根目录）"),
]


def project_root() -> str:
    """项目根目录：打包后取 PyInstaller 的解包目录。"""
    base = getattr(sys, "_MEIPASS", None)
    if base is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return base


def is_frozen() -> bool:
    """是否运行在打包产物里（.app / .exe）。"""
    return bool(getattr(sys, "frozen", False))


def build_config(mode: str, port: int = 8765) -> dict:
    """生成 MCP 配置字典。

    mode:
      stdio —— AI 客户端拉起一个进程。该进程会自动代理到运行中的 GUI，
               因此能共享同一会话、且 AI 的每次调用会驱动界面（推荐）。
      http  —— 直连 GUI 内置的 HTTP 端点，不做代理。
    """
    if mode == "http":
        return {"mcpServers": {"mda": {"url": f"http://127.0.0.1:{port}/mcp"}}}

    if is_frozen():
        # 打包版：用 .app 内的可执行文件 + --mcp-stdio（等价于 mda.py mcp）
        return {"mcpServers": {"mda": {"command": sys.executable, "args": ["--mcp-stdio"]}}}
    # 源码运行：venv 的 python + mda.py
    return {
        "mcpServers": {
            "mda": {
                "command": sys.executable,
                "args": [os.path.join(project_root(), "mda.py"), "mcp"],
            }
        }
    }


def config_text(mode: str, port: int = 8765) -> str:
    return json.dumps(build_config(mode, port), indent=2, ensure_ascii=False)


class McpConfigDialog(QDialog):
    """展示并复制 MCP 配置。"""

    def __init__(self, port: int = 8765, parent=None):
        super().__init__(parent)
        self.port = port
        self.setWindowTitle("MCP 配置 — 复制到 AI 客户端")
        self.resize(680, 520)

        root = QVBoxLayout(self)

        # 接入方式
        row = QHBoxLayout()
        row.addWidget(QLabel("接入方式："))
        self.mode_box = QComboBox()
        mode_items = [
            ("stdio 代理（推荐：共享同一会话，AI 操作会驱动界面）", "stdio"),
            ("HTTP 直连（仅连接，不做代理）", "http"),
        ]
        for label, value in mode_items:
            self.mode_box.addItem(label, value)
        # 打包版默认 HTTP 亦可，但 stdio 体验更完整，故仍默认 stdio
        self.mode_box.currentIndexChanged.connect(self._refresh)
        row.addWidget(self.mode_box, 1)
        root.addLayout(row)

        # 配置正文
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        root.addWidget(self.text, 1)

        # 客户端配置文件位置提示
        tip = QLabel(
            "粘到哪里：\n"
            + "\n".join(f"  · {name}：{path}" for name, path in _CLIENT_PATHS)
            + "\n\n提示：改完要重启对应客户端才会生效。"
        )
        tip.setStyleSheet("color:#666; font-size:12px;")
        tip.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root.addWidget(tip)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color:#ddd;")
        root.addWidget(line)

        # 按钮
        btns = QHBoxLayout()
        self.status = QLabel("")
        self.status.setStyleSheet("color:#0f9b8e; font-weight:600;")
        btns.addWidget(self.status, 1)

        btn_copy = QPushButton("📋 复制配置")
        btn_copy.setDefault(True)
        btn_copy.clicked.connect(self._copy)
        btns.addWidget(btn_copy)

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btns.addWidget(btn_close)
        root.addLayout(btns)

        self._refresh()

    def current_mode(self) -> str:
        return self.mode_box.currentData()

    def _refresh(self) -> None:
        self.text.setPlainText(config_text(self.current_mode(), self.port))

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self.text.toPlainText())
        self.status.setText("✅ 已复制到剪贴板")
