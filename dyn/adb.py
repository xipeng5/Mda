"""adb 设备管理。

职责：设备发现、进程枚举、frida-server 探测与启停、应用启动。
不依赖 frida Python 绑定，可独立测试（adb 二进制即可）。

约定（第一次修改，见各方法注释）：
- 所有可预期失败都抛 DynError(code, message)，错误码供 UI/AI 直接翻译，
  不再裸抛 FileNotFoundError。
- adb 与 frida-server 的路径都可被环境变量覆盖：打包进 .app 后 PATH 精简也不会失效。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass

# frida 客户端与设备端 server 的大版本必须一致，否则 ProtocolError。
# (1) 第一次修改：原写死 17.2.14 / frida-server-17，而设备上实际叫 frida-server，
#     版本也可能不同。改为候选列表 + 环境变量覆盖。
FRIDA_SERVER_VERSION = os.environ.get("MDA_FRIDA_SERVER_VERSION", "17.2.14")
FRIDA_DEVICE_PATH = os.environ.get("MDA_FRIDA_DEVICE_PATH", "").strip()
FRIDA_PATH_CANDIDATES = (
    "/data/local/tmp/frida-server-17",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/fs",
)
# 进程名候选：push 时的文件名与运行时进程名不一定一致
FRIDA_PROCESS_NAMES = ("frida-server-17", "frida-server")

ADB_CANDIDATES = (
    "/opt/homebrew/bin/adb",
    "/usr/local/bin/adb",
    os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
)


class DynError(RuntimeError):
    """动态分析的可预期失败：带机器可读 code，供 UI/AI 翻译成中文。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


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


def resolve_adb() -> str:
    """定位 adb 可执行文件。

    (1) 第一次修改
    bug 原因：原实现直接用裸 "adb"，完全依赖 PATH。打包成 .app 后由 launchd 启动，
              PATH 只有 /usr/bin:/bin，实测抛 FileNotFoundError: 'adb'，
              AI 侧 6 个动态工具全部不可用。
    解决方案：MDA_ADB 环境变量 > PATH 查找 > 常见安装路径，都找不到才报错。
    """
    env = os.environ.get("MDA_ADB", "").strip()
    if env and os.path.isfile(env):
        return env
    found = shutil.which("adb")
    if found:
        return found
    for path in ADB_CANDIDATES:
        if os.path.isfile(path):
            return path
    raise DynError("ADB_NOT_FOUND", "未找到 adb，请安装 Android Platform Tools 或设置 MDA_ADB")


class Adb:
    """adb 命令的薄封装。"""

    def __init__(self, serial: str | None = None):
        self.serial = serial

    def _cmd(self, *args: str, timeout: int = 30, check: bool = True) -> str:
        cmd = [resolve_adb()]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        # bug 原因：pidof 等探测类命令"未找到进程"时返回 rc=1 且无输出，
        # 属正常业务结果而非失败；按 check=False 交给调用方判空处理。
        if r.returncode != 0 and check:
            raise DynError("ADB_COMMAND_FAILED", f"adb {' '.join(args)} 失败: {r.stderr.strip()}")
        return r.stdout

    # ---------- 设备 ----------

    @staticmethod
    def list_devices() -> list[DeviceInfo]:
        r = subprocess.run([resolve_adb(), "devices"], capture_output=True, text=True, timeout=15)
        out: list[DeviceInfo] = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                out.append(DeviceInfo(serial=parts[0], state=parts[1]))
        return out

    def model(self) -> str:
        try:
            return self._cmd("shell", "getprop", "ro.product.model").strip()
        except DynError:
            return ""

    def is_root(self) -> bool:
        """探测设备能否用 su 拿到 root（给 preflight 提供准确降级原因）。"""
        try:
            out = self._cmd("shell", "su", "-c", "id", check=False, timeout=8)
        except Exception:                      # noqa: BLE001 - 探测失败即视为无 root
            return False
        return "uid=0" in out

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

    def resolve_server_path(self) -> str:
        """在设备上找到真实存在的 frida-server 路径。

        (1) 第一次修改
        bug 原因：原实现写死 /data/local/tmp/frida-server-17，设备上实际叫
                  frida-server，导致"按文档 push 也启动不了、还不告诉原因"。
        解决方案：逐条 ls 探测候选路径，都找不到抛 FRIDA_BINARY_MISSING 并列出探测项。
        """
        candidates = (FRIDA_DEVICE_PATH,) if FRIDA_DEVICE_PATH else FRIDA_PATH_CANDIDATES
        for path in candidates:
            out = self._cmd("shell", "ls", path, check=False)
            if out.strip() and "No such file" not in out:
                return path
        raise DynError(
            "FRIDA_BINARY_MISSING",
            "设备上没有 frida-server，已探测：" + "、".join(candidates),
        )

    def _running_name(self) -> str:
        """返回正在运行的 frida-server 进程名，没有则空串。"""
        for name in FRIDA_PROCESS_NAMES:
            if self._cmd("shell", "pidof", name, check=False).strip():
                return name
        return ""

    def frida_running(self) -> bool:
        """检查 frida-server 是否已启动。

        (1) 第一次修改
        bug 原因：原实现只 pidof frida-server-17；设备上跑的是 frida-server
                  或带版本后缀的进程名，实测"明明在跑却判定未运行"。
        解决方案：按多个进程名依次探测。
        """
        return bool(self._running_name())

    def start_frida(self, wait: float = 2.5) -> dict:
        """以 root 启动 frida-server，返回结构化结果。

        (1) 第一次修改
        bug 原因：原实现返回裸 bool，失败时既没有原因也没有探测记录，
                  调用方只能拿到 {"running": false}，无法判断是缺二进制、
                  没 root 还是启动失败。
        解决方案：返回 {running, code, message, path}；code 为空表示成功。
        """
        if self.frida_running():
            return {"running": True, "code": "", "message": "已在运行", "path": ""}

        try:
            path = self.resolve_server_path()
        except DynError as exc:
            return {"running": False, "code": exc.code, "message": exc.message, "path": ""}

        if not self.is_root():
            return {
                "running": False,
                "code": "FRIDA_NO_ROOT",
                "message": "设备未 root，无法以 root 启动 frida-server",
                "path": path,
            }

        self._cmd("shell", "su", "-c", f"nohup {path} >/dev/null 2>&1 &", timeout=15)
        time.sleep(wait)
        ok = self.frida_running()
        return {
            "running": ok,
            "code": "" if ok else "FRIDA_START_FAILED",
            "message": "已启动" if ok else "启动命令已执行但进程未存活（可能是版本或 SELinux 限制）",
            "path": path,
        }

    def stop_frida(self) -> bool:
        name = self._running_name()
        if not name:
            return True
        self._cmd("shell", "su", "-c", f"kill $(pidof {name})", check=False)
        time.sleep(0.5)
        return not self.frida_running()

    # ---------- 汇总探测 ----------

    def preflight(self) -> dict:
        """一次性探测动态分析可用性，供界面直接渲染"为什么不可用"。

        结构：{adb:{ok,path,message}, devices:[...], active:{serial,root}, frida:{running,path,code,message}}
        缺什么就报什么，不猜、不假装可用。
        """
        info: dict = {
            "adb": {"ok": False, "path": "", "message": ""},
            "devices": [],
            "active": None,
            "frida": {"running": False, "path": "", "code": "", "message": ""},
        }
        try:
            info["adb"]["path"] = resolve_adb()
            info["adb"]["ok"] = True
        except DynError as exc:
            info["adb"]["code"] = exc.code
            info["adb"]["message"] = exc.message
            return info

        try:
            info["devices"] = [
                {"serial": d.serial, "state": d.state, "model": self.model() if d.serial == self.serial else ""}
                for d in Adb.list_devices()
            ]
        except DynError as exc:
            info["adb"]["message"] = exc.message
            return info

        if self.serial:
            info["active"] = {"serial": self.serial, "root": self.is_root()}
            info["frida"]["running"] = self.frida_running()
            try:
                info["frida"]["path"] = self.resolve_server_path()
            except DynError as exc:
                info["frida"]["code"] = exc.code
                info["frida"]["message"] = exc.message
        return info

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
