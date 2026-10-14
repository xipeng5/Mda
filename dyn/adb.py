"""adb 设备管理。

职责：设备发现、进程枚举、frida-server 启停、应用启动。
不依赖 frida Python 绑定，可独立测试（adb 二进制即可）。
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

# frida 客户端与设备端 server 的大版本必须一致，否则 ProtocolError
# 本机 pip 安装的 frida 为 17.x，对应此下载地址
FRIDA_SERVER_VERSION = "17.2.14"
FRIDA_DEVICE_PATH = "/data/local/tmp/frida-server-17"


@dataclass
class DeviceInfo:
    serial: str
    state: str
    model: str = ""


@dataclass
class ProcessInfo:
    pid: int
    user: str
    name: str


class Adb:
    """adb 命令的薄封装。"""

    def __init__(self, serial: str | None = None):
        self.serial = serial

    def _cmd(self, *args: str, timeout: int = 30, check: bool = True) -> str:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # bug 原因：pidof 等探测类命令"未找到进程"时返回 rc=1 且无输出，
        # 属正常业务结果而非失败；按 check=False 交给调用方判空处理。
        if r.returncode != 0 and check:
            raise RuntimeError(f"adb {' '.join(args)} 失败: {r.stderr.strip()}")
        return r.stdout

    # ---------- 设备 ----------

    @staticmethod
    def list_devices() -> list[DeviceInfo]:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=15)
        out: list[DeviceInfo] = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                out.append(DeviceInfo(serial=parts[0], state=parts[1]))
        return out

    def model(self) -> str:
        try:
            return self._cmd("shell", "getprop", "ro.product.model").strip()
        except RuntimeError:
            return ""

    # ---------- 进程 ----------

    def processes(self) -> list[ProcessInfo]:
        """枚举设备全部进程（ps -A 的稳定解析）。"""
        out = self._cmd("shell", "ps", "-A")
        result: list[ProcessInfo] = []
        for line in out.splitlines()[1:]:
            f = line.split()
            # USER PID PPID ... NAME，列数因版本略有差异，取首尾
            if len(f) >= 9:
                try:
                    result.append(ProcessInfo(pid=int(f[1]), user=f[0], name=f[-1]))
                except ValueError:
                    continue
        return result

    def find_app_pid(self, package: str) -> int:
        """按包名查运行中的进程 pid，未运行返回 0。"""
        for p in self.processes():
            if p.name == package:
                return p.pid
        return 0

    # ---------- frida-server ----------

    def frida_running(self) -> bool:
        """检查 frida-server 是否已启动。"""
        out = self._cmd("shell", "pidof", "frida-server-17", check=False)
        return bool(out.strip())

    def start_frida(self, wait: float = 2.5) -> bool:
        """以 root 启动 frida-server。设备须已 root。

        返回 True 表示启动成功或本就在运行。
        """
        if self.frida_running():
            return True
        # nohup + & 使其脱离 shell 存活；su -c 包裹获取 root
        self._cmd(
            "shell",
            "su",
            "-c",
            f"nohup {FRIDA_DEVICE_PATH} >/dev/null 2>&1 &",
            timeout=15,
        )
        time.sleep(wait)
        return self.frida_running()

    def stop_frida(self) -> bool:
        self._cmd("shell", "su", "-c", "kill $(pidof frida-server-17)")
        time.sleep(0.5)
        return not self.frida_running()

    # ---------- 应用 ----------

    def launch_app(self, package: str, activity: str = "") -> bool:
        """启动应用（monkey 方式无需知道 activity 名）。"""
        target = activity or package
        if activity:
            self._cmd("shell", "am", "start", "-n", f"{package}/{activity}")
        else:
            self._cmd(
                "shell", "monkey", "-p", package,
                "-c", "android.intent.category.LAUNCHER", "1",
            )
        time.sleep(1.5)
        return self.find_app_pid(package) > 0
