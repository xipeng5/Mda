"""插件系统：plugins/ 目录下的 py 文件自动加载。

对齐 IDA 的插件机制：每个插件是一个 py 文件，实现 Plugin 类：
    class Plugin:
        name = "示例"
        description = "做什么"
        def init(self, session, log): ...   # 加载时调用一次
        def hooks(self) -> dict:            # 订阅事件（可选）
            return {"after_load": self.on_load}
        def run(self, session, args) -> any # 被 MCP 工具 plugin_run 调用

约定优于配置：文件放进去即生效，删掉即失效。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from core.session import Session

PLUGIN_DIR = Path(__file__).parent.parent / "plugins"


class PluginBase:
    """插件基类。继承它写 name/description/run 即可。"""

    name: str = "未命名"
    description: str = ""
    # MCP 暴露为 plugin_run 的参数 schema 提示，供 AI 阅读如何传参
    usage: str = ""

    def init(self, session: Session, log) -> None:
        """插件加载后调用一次。log(text) 用于写 Output。"""

    def hooks(self) -> dict:
        """返回 {事件名: 回调}。支持的事件见 PluginManager.emit。"""
        return {}

    def run(self, session: Session, args: dict):
        """执行插件动作，返回值给 MCP 调用方。"""
        raise NotImplementedError


class PluginManager:
    """扫描、加载、事件分发。"""

    # 事件：插件可订阅的生命周期点
    EVENTS = ("after_load", "after_xref", "before_exit")

    def __init__(self, session: Session, log=None):
        self.session = session
        self.log = log or (lambda text: None)
        self.plugins: dict[str, PluginBase] = {}
        self._hooks: dict[str, list] = {}

    def scan_and_load(self) -> list[str]:
        """加载 plugins/ 目录全部 .py，返回加载的插件名。"""
        loaded = []
        if not PLUGIN_DIR.exists():
            return loaded
        for path in sorted(PLUGIN_DIR.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"mda_plugin_{path.stem}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception as e:
                self.log(f"[插件] 加载失败 {path.name}: {e}")
                continue
            # 约定：模块内定义 Plugin 类
            cls = getattr(mod, "Plugin", None)
            if cls is None:
                continue
            try:
                inst = cls()
                inst.init(self.session, self.log)
                self.plugins[inst.name] = inst
                for event, cb in inst.hooks().items():
                    self._hooks.setdefault(event, []).append(cb)
                loaded.append(inst.name)
                self.log(f"[插件] 已加载: {inst.name} — {inst.description}")
            except Exception as e:
                self.log(f"[插件] 初始化失败 {path.name}: {e}")
        return loaded

    def emit(self, event: str, payload=None) -> None:
        """广播事件给订阅插件。插件异常不阻塞主流程。"""
        for cb in self._hooks.get(event, []):
            try:
                cb(self.session, payload)
            except Exception as e:
                self.log(f"[插件] 事件 {event} 处理出错: {e}")

    def run(self, name: str, args: dict | None = None):
        """按名字执行插件动作（MCP plugin_run 入口）。"""
        plugin = self.plugins.get(name)
        if plugin is None:
            raise KeyError(f"插件不存在: {name}，已加载: {list(self.plugins)}")
        return plugin.run(self.session, args or {})

    def describe(self) -> list[dict]:
        """插件清单，供 MCP 列给 AI 看。"""
        return [
            {"name": p.name, "description": p.description, "usage": p.usage}
            for p in self.plugins.values()
        ]
