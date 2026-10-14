"""静态地址与运行时地址的换算桥。

动态分析的核心难点：ASLR 与重定位使 so 加载到运行时基址，
静态分析得到的地址（如 0x5020）在内存里是 base + 0x5020。
本模块负责两个方向的换算与运行时模块定位。

依赖 frida，可脱离本项目的 core 独立测试。
"""
from __future__ import annotations

import time

import frida


class RuntimeModule:
    """目标进程中的一个已加载 so 的运行时信息。"""

    def __init__(self, name: str, base: int, size: int, path: str):
        self.name = name
        self.base = base
        self.size = size
        self.path = path

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end

    def __repr__(self) -> str:  # 调试用
        return f"RuntimeModule({self.name}, base={hex(self.base)}, size={hex(self.size)})"


class Rebase:
    """单个 so 的静态地址 <-> 运行时地址 换算器。

    用法：
        rb = Rebase.attach(device_id, pid)
        m = rb.find_module("liblog.so")
        runtime_addr = rb.to_runtime(0x5020, m)
        static_addr = rb.to_static(m.base + 0x5020, m)
    """

    def __init__(self, device: frida.core.Device, pid: int):
        self.device = device
        self.pid = pid
        self.session = device.attach(pid)
        self._modules: list[RuntimeModule] = []

    # ---------- 连接管理 ----------

    @classmethod
    def attach(cls, device_id: str, pid: int) -> "Rebase":
        d = frida.get_device(device_id, timeout=10)
        return cls(d, pid)

    def detach(self) -> None:
        self.session.detach()

    # ---------- 运行时模块 ----------

    def refresh_modules(self) -> list[RuntimeModule]:
        """枚举目标进程当前加载的全部模块。

        进程启动时间不同、按需 dlopen 的 so 会出现/消失，因此需要可刷新。
        """
        script = self.session.create_script(
            """
            var mods = Process.enumerateModules().map(function(m) {
                return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            });
            send(mods);
            """
        )
        got: list = []
        done = {"ok": False}
        script.on("message", lambda msg, data: (got.extend(msg.get("payload", [])), done.__setitem__("ok", True)))
        script.load()
        # 消息回调是异步的，轮询等待
        for _ in range(50):
            if done["ok"]:
                break
            time.sleep(0.1)
        script.unload()

        self._modules = [
            RuntimeModule(
                name=m["name"],
                base=int(m["base"], 16),
                size=int(m["size"]),
                path=m["path"],
            )
            for m in got
        ]
        return self._modules

    def find_module(self, name: str) -> RuntimeModule | None:
        """按文件名找运行时模块，未刷新时自动刷新一次。"""
        for m in self._modules:
            if m.name == name or m.name.rsplit("/", 1)[-1] == name:
                return m
        if not self._modules:
            self.refresh_modules()
            for m in self._modules:
                if m.name == name or m.name.rsplit("/", 1)[-1] == name:
                    return m
        return None

    # ---------- 地址换算 ----------

    def to_runtime(self, static_addr: int, module: RuntimeModule) -> int:
        """静态地址 -> 运行时地址。

        静态基址按 0 计算（.so 是 PIE/ET_DYN，链接时基址为 0），
        若静态模型带非零基址需在上层先归零。
        """
        return module.base + static_addr

    def to_static(self, runtime_addr: int, module: RuntimeModule) -> int:
        """运行时地址 -> 静态地址。"""
        return runtime_addr - module.base

    # ---------- 内存读取 ----------

    def read_memory(self, addr: int, size: int) -> bytes:
        """读取目标进程内存。

        bug 原因：frida 17 移除了全局 Memory.readByteArray，需用
        ptr().readByteArray；且 send 二进制经 data 通道返回时在部分
        版本下 data 为 None，故在 JS 端转 hex 字符串走 JSON 通道，稳定。
        解决：JS 内 Uint8Array 转 hex，Python 端 bytes.fromhex 还原。
        """
        script = self.session.create_script(
            f"""
            var buf = ptr({hex(addr)}).readByteArray({size});
            if (buf === null) {{
                send({{err: "unreadable"}});
            }} else {{
                send({{
                    hex: Array.from(new Uint8Array(buf))
                        .map(function(x) {{ return x.toString(16).padStart(2, "0"); }})
                        .join("")
                }});
            }}
            """
        )
        got: list = []
        script.on("message", lambda msg, data: got.append(msg.get("payload", {})))
        script.load()
        for _ in range(50):
            if got:
                break
            time.sleep(0.1)
        script.unload()
        if not got:
            return b""
        payload = got[0]
        if "err" in payload or "hex" not in payload:
            return b""
        return bytes.fromhex(payload["hex"])
