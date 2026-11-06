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

    def server_version(self, path: str = "") -> str:
        """读设备上 frida-server 二进制的版本号（如 "17.23.3"）。

        (2) 第二次修改（2026-11-05）：新增。
        bug 原因：start_frida 原先不做版本校验，设备上无论放的是哪个版本都照起。
                  而 frida 客户端与 server 版本必须一致，minor 不同也会报
                  "ProtocolError: unable to communicate with remote frida-server"，
                  于是表现为"起来了但连不上"，且错误信息看不出是版本问题。
        解决方案：启动前读一次 `--version`，与调用方期望的版本比对，
                  不一致就明确拒绝并把两个版本号都报出来。
        返回空串表示读不到（无执行权限/非 ELF/不存在）。
        """
        target = path
        if not target:
            try:
                target = self.resolve_server_path()
            except DynError:
                return ""
        out = self._cmd("shell", "su", "-c", f"{target} --version 2>&1",
                        check=False, timeout=25)
        text = (out or "").strip().splitlines()[0].strip() if (out or "").strip() else ""
        # 只认形如 17.23.3 / 16.0.19 的版本串，避免把报错信息当版本
        import re as _re

        m = _re.match(r"^(\d+\.\d+\.\d+)", text)
        return m.group(1) if m else ""

    @staticmethod
    def _port_hex(port: int) -> str:
        return f"{port:04X}"

    def listening_port(self, port: int = 27042) -> bool:
        """端口是否处于 LISTEN。

        (3) 第三次修改（2026-11-05）：新增。
        bug 原因：判断"frida 是否在跑"原来只看进程名，而设备上可能同时有多个
                  frida 进程（不同版本、不同端口），按名判断会把"别人的"当成"我们的"。
                  端口才是可靠判据——谁绑了 27042 才是真正对外的那个。
        实现：grep 原始行回本地解析，避免设备端 awk 的 $ 被多层 shell 提前展开
              （实测 awk 版本恒返回空）。
        """
        raw = self._cmd("shell", "su", "-c",
                        f"grep -h -i :{self._port_hex(port)} /proc/net/tcp "
                        f"/proc/net/tcp6 2>/dev/null || true", check=False)
        for line in (raw or "").splitlines():
            parts = line.split()
            # 字段：sl local_address rem_address st ... （st=0A 表示 LISTEN）
            if len(parts) > 9 and parts[3] == "0A":
                return True
        return False

    def listening_pids(self, port: int = 27042) -> list[tuple[int, str]]:
        """返回正在监听指定端口的进程 [(pid, name)]。

        (3) 第三次修改（2026-11-05）：新增。
        用途：启动前先看 27042 被谁占着——如果是别的版本的 frida，
        应当明确报错让用户决定，**不能直接杀掉**（那可能是别人的项目在用的）。

        (4) 第四次修改（2026-11-05）：反查方式改为逐个候选进程精确检查。
            bug 原因：初版用 `ls -l /proc/*/fd | grep inode`，但设备上的 ls
                      对多个目录会输出分组标题（`/proc/123/fd:`），
                      PID 不在内容行里，正则一条都匹配不到（实测恒返回 []）。
            解决方案：先取 LISTEN 的 socket inode，再用 ps 列出所有 frida 进程，
                      对每个候选执行 `ls -l /proc/<pid>/fd | grep -c`，
                      命中数 > 0 即判定为该端口的持有者。候选通常只有 1-3 个，
                      成本可接受且不依赖 ls 的跨目录输出格式。
        """
        raw = self._cmd("shell", "su", "-c",
                        f"grep -h -i :{self._port_hex(port)} /proc/net/tcp "
                        f"/proc/net/tcp6 2>/dev/null || true", check=False)
        inode = ""
        for line in (raw or "").splitlines():
            parts = line.split()
            if len(parts) > 9 and parts[3] == "0A":
                inode = parts[9]
                break
        if not inode:
            return []

        table = self._cmd("shell", "ps", "-A", "-o", "PID,NAME", check=False)
        candidates: list[tuple[int, str]] = []
        for line in (table or "").splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            name = parts[-1]
            low = name.lower()
            # 只查名字里带 frida 的（别的进程不可能监听 frida 的端口）
            if "frida" not in low or "gadget" in low:
                continue
            candidates.append((int(parts[0]), name))

        holders: list[tuple[int, str]] = []
        for pid, name in candidates:
            out = self._cmd(
                "shell", "su", "-c",
                # 必须用 -F：socket:[123] 里的方括号是**字面量**，不用 -F 时
                # grep 会把它当字符类（匹配 "socket:" 后跟一个数字），而实际文本
                # 里方括号是真实字符，导致恒匹配不到（实测全返回 0）。
                f"ls -l /proc/{pid}/fd 2>/dev/null | grep -cF 'socket:[{inode}]'",
                check=False, timeout=30)
            if (out or "").strip() not in ("", "0"):
                holders.append((pid, name))
        return holders

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

    def start_frida(self, wait: float = 2.5, expect_version: str = "") -> dict:
        """以 root 启动 frida-server，返回结构化结果。

        (1) 第一次修改
        bug 原因：原实现返回裸 bool，失败时既没有原因也没有探测记录，
                  调用方只能拿到 {"running": false}，无法判断是缺二进制、
                  没 root 还是启动失败。
        解决方案：返回 {running, code, message, path}；code 为空表示成功。

        (5) 第五次修改（2026-11-05）：加**版本校验**与**端口占用者保护**。
            bug 原因：① 原先不看版本，设备上放的是旧版照样起，起来后连不上，
                        报的是 "ProtocolError"，看不出根因是版本不匹配；
                      ② 原先只看进程名就认为"已在运行"，而设备上可能同时有多个
                        frida 进程（别人的项目在用的、监听别的端口的），
                        会把"别人的"当成"我们的"。
            解决方案：① 传 expect_version 时先读设备二进制的 --version 比对，
                         不一致立即返回 FRIDA_VERSION_MISMATCH 并给出两个版本；
                      ② 先用端口判断 27042 有没有被占；被占时查清楚**是谁**占的，
                         如果是别的程序就返回 FRIDA_PORT_TAKEN 并列出占用者，
                         **绝不擅自杀掉**（那可能是用户别的项目在跑）。
        """
        port = 27042

        # ① 端口已被占：先查清是谁
        if self.listening_port(port):
            holders = self.listening_pids(port)
            try:
                path = self.resolve_server_path()
            except DynError:
                path = ""
            running_ver = self.server_version(path) if path else ""
            # 占用者里包含我们路径对应的进程名 → 认为就是我们的在跑
            names = {n for _, n in holders}
            if path and names and any(n in path or path.endswith("/" + n) for n in names):
                ok_ver = (not expect_version) or (running_ver == expect_version)
                return {
                    "running": True,
                    "code": "" if ok_ver else "FRIDA_VERSION_MISMATCH",
                    "message": (f"已在运行（{running_ver or '版本未知'}）" if ok_ver else
                                f"已在运行但版本不匹配：设备 {running_ver}，"
                                f"客户端 {expect_version}；用 frida_server_align 对齐"),
                    "path": path,
                    "version": running_ver,
                    "holders": [{"pid": p, "name": n} for p, n in holders],
                }
            return {
                "running": True,
                "code": "FRIDA_PORT_TAKEN",
                "message": (f"端口 {port} 已被别的进程占用："
                            + "、".join(f"{n}(pid {p})" for p, n in holders)
                            + "；**未做任何操作**，请确认那是谁再决定"),
                "path": path,
                "holders": [{"pid": p, "name": n} for p, n in holders],
            }

        # ② 没占：找二进制并校验版本
        try:
            path = self.resolve_server_path()
        except DynError as exc:
            return {"running": False, "code": exc.code, "message": exc.message, "path": ""}

        ver = self.server_version(path)
        if expect_version and ver and ver != expect_version:
            return {
                "running": False,
                "code": "FRIDA_VERSION_MISMATCH",
                "message": (f"设备上的 frida-server 是 {ver}，本机客户端是 {expect_version}；"
                            "版本不一致会连不上（ProtocolError）。"
                            "先用 frida_server_align 覆盖成同版本再启动"),
                "path": path,
                "version": ver,
                "expected": expect_version,
            }
        if expect_version and not ver:
            # (8) 第八次修改（2026-11-05）：读不到版本时**不再盲启动**。
            #     bug 原因：原实现 `if expect_version and ver and ...`，当 ver 为空
            #               （二进制无执行权限 / 非 ELF / 已被截断）时整个校验被跳过，
            #               照常启动，又回到"起来了但连不上、报 ProtocolError"的老问题。
            #     解决方案：给了期望版本却读不到设备版本，直接拒绝并说明可能原因。
            return {
                "running": False,
                "code": "FRIDA_VERSION_UNKNOWN",
                "message": (f"读不到设备上 {path} 的版本（--version 无输出或非可执行）；"
                            "无法确认与本机客户端 "
                            f"{expect_version} 是否匹配，故不启动。"
                            "可先 chmod 755，或用 frida_server_align 重新部署"),
                "path": path,
                "version": "",
                "expected": expect_version,
            }

        if not self.is_root():
            return {
                "running": False,
                "code": "FRIDA_NO_ROOT",
                "message": "设备未 root，无法以 root 启动 frida-server",
                "path": path,
            }

        self._cmd("shell", "su", "-c", f"nohup {path} >/dev/null 2>&1 &", timeout=15)
        time.sleep(wait)
        ok = self.listening_port(port) or self.frida_running()
        return {
            "running": ok,
            "code": "" if ok else "FRIDA_START_FAILED",
            "message": ("已启动" if ok else
                        "启动命令已执行但端口未监听、进程也未存活"
                        "（可能是版本不符、SELinux 限制，或端口被临时占用）"),
            "path": path,
            "version": ver,
        }

    def stop_frida(self) -> dict:
        """停掉占用 27042 的 frida-server。

        (6) 第六次修改（2026-11-05）：改为**只按端口**停止，并回报停掉了什么。
            bug 原因：原实现用 `pidof <名字>` 按进程名杀，而设备上可能存在多个
                      frida 进程（别人的项目占用别的端口，如 frida_16019 监听 27100）。
                      按名杀会**误杀别人的进程**——这是很严重的副作用。
            解决方案：只处理监听 27042 的进程（端口是唯一可靠判据），
                      并在返回里逐条列出 pid/名字，让用户清楚我停了什么。
                      没有占用者时直接返回成功，不做多余动作。
        """
        holders = self.listening_pids(27042)
        if not holders:
            return {"stopped": [], "ok": True, "message": "端口 27042 没有监听者"}
        stopped: list[dict] = []
        for pid, name in holders:
            self._cmd("shell", "su", "-c",
                      f"kill {pid} 2>/dev/null; sleep 0.3; kill -9 {pid} 2>/dev/null",
                      check=False)
            stopped.append({"pid": pid, "name": name})
        time.sleep(0.5)
        return {
            "stopped": stopped,
            "ok": not self.listening_port(27042),
            "message": ("已停止：" + "、".join(f"{d['name']}(pid {d['pid']})" for d in stopped)
                        if stopped else "没有需要停止的进程"),
        }

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
            # (7) 第七次修改（2026-11-05）：running 改由**端口**判定，并补版本信息。
            #     bug 原因：原先 running 只看进程名，设备上同时存在别人的 frida
            #               （监听别的端口）时会误报"在运行"；而且没有版本字段，
            #               用户无法从这里看出"起来了但版本不匹配连不上"。
            #     解决方案：running 用 27042 是否有 LISTEN 判定；补 device_version
            #               与 client_version，并给出 version_match 布尔值，
            #               让 preflight 一次把"能不能用"讲清楚。
            info["frida"]["running"] = self.listening_port(27042)
            try:
                info["frida"]["path"] = self.resolve_server_path()
            except DynError as exc:
                info["frida"]["code"] = exc.code
                info["frida"]["message"] = exc.message
            try:
                dev_ver = self.server_version() if info["frida"]["path"] else ""
            except Exception:                             # noqa: BLE001
                dev_ver = ""
            try:
                import frida as _frida

                cli_ver = str(_frida.__version__)
            except Exception:                             # noqa: BLE001
                cli_ver = ""
            info["frida"]["device_version"] = dev_ver
            info["frida"]["client_version"] = cli_ver
            info["frida"]["version_match"] = bool(
                dev_ver and cli_ver and dev_ver == cli_ver)
            if dev_ver and cli_ver and dev_ver != cli_ver:
                info["frida"]["code"] = info["frida"]["code"] or "FRIDA_VERSION_MISMATCH"
                info["frida"]["message"] = (
                    f"版本不匹配：设备 {dev_ver} / 客户端 {cli_ver}；"
                    "用 frida_server_align 对齐后才能通信")
            # 端口被别人占着时也要说清楚
            if info["frida"]["running"]:
                holders = self.listening_pids(27042)
                info["frida"]["holders"] = [
                    {"pid": p, "name": n} for p, n in holders]
        return info

    # ---------- 应用 ----------

    # ---------- 进程冻结 ----------

    def process_status(self, pid: int) -> str:
        """读 /proc/<pid>/stat 的状态字符。

        取值含义（Linux proc(5)）：
            R 运行中   S 可中断睡眠   D 不可中断睡眠   T 已被 SIGSTOP 冻结
            t 被调试器冻结          Z 僵尸           X 已退出

        (9) 第九次修改（2026-11-05）：新增。
            冻结/解冻不能只看"命令执行成功"，必须能读到真实状态，
            否则会出现"以为冻住了其实没有"的假成功。
        """
        out = self._cmd("shell", "su", "-c",
                        f"cat /proc/{pid}/stat 2>/dev/null || echo MISSING",
                        check=False)
        text = (out or "").strip()
        if not text or "MISSING" in text:
            return ""
        # 格式：pid (comm) state ...
        # comm 可能含空格和括号，所以从**最后一个 ')'** 之后取第一个字段
        idx = text.rfind(")")
        if idx < 0:
            return ""
        rest = text[idx + 1:].strip()
        return rest.split()[0] if rest else ""

    def freeze_process(self, pid: int, wait: float = 0.4) -> dict:
        """用 SIGSTOP **冻结整个进程**（所有线程一起停）。

        (9) 第九次修改（2026-11-05）：新增。
            与"断点 hold 住单条线程"是两回事：这里的进程会整体停在原地，
            用来做"某一瞬间的完整快照"——所有线程的栈、所有内存都是同一时刻的，
            不会一边读一边被别的线程改掉。

        注意：冻结期间该进程**不能响应任何 frida RPC**（agent 线程也停了），
        所以取信息要走 adb 侧（/proc），不要发起 frida 调用。
        """
        before = self.process_status(pid)
        if not before:
            return {"ok": False, "code": "NO_SUCH_PROCESS",
                    "message": f"读不到 pid {pid} 的 /proc 状态，可能已退出",
                    "status_before": "", "status_after": ""}

        self._cmd("shell", "su", "-c", f"kill -STOP {pid} 2>/dev/null", check=False)
        time.sleep(wait)
        after = self.process_status(pid)
        ok = after in ("T", "t")
        return {
            "ok": ok,
            "code": "" if ok else "FREEZE_FAILED",
            "message": (f"已冻结（状态 {before} → {after}）" if ok else
                        f"冻结后状态为 {after!r}，未进入 T（可能权限不足或进程已退出）"),
            "status_before": before,
            "status_after": after,
            "hint": ("冻结期间进程整体停止：frida RPC 会阻塞，"
                     "读内存/栈请走 adb 侧（/proc）；分析完务必 unfreeze"),
        }

    def unfreeze_process(self, pid: int, wait: float = 0.4) -> dict:
        """用 SIGCONT 恢复被 SIGSTOP 冻结的进程。"""
        before = self.process_status(pid)
        if not before:
            return {"ok": False, "code": "NO_SUCH_PROCESS",
                    "message": f"读不到 pid {pid} 的 /proc 状态",
                    "status_before": "", "status_after": ""}

        self._cmd("shell", "su", "-c", f"kill -CONT {pid} 2>/dev/null", check=False)
        time.sleep(wait)
        after = self.process_status(pid)
        ok = after not in ("T", "t", "")
        return {
            "ok": ok,
            "code": "" if ok else "UNFREEZE_FAILED",
            "message": (f"已恢复（状态 {before} → {after}）" if ok else
                        f"恢复后状态仍为 {after!r}"),
            "status_before": before,
            "status_after": after,
        }

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

    def probe_process_alive(self, pid: int, serial_ok: bool = True) -> dict:
        """探测目标进程**是否还活着、是否还能被注入**。

        (10) 第十次修改（2026-11-06）：新增。

        bug 原因：probe_hits 返回 0 命中时，verdict 只说"这段代码没被执行"，
                  但**另一种情况**是——进程已经死了/变成僵尸/失去可注入性，
                  这时 frida 抛 ProcessNotFoundError，而调用方看到的是
                  "0 命中"，很容易误判成"签名流程没走"。
                  实测：adb ps 能看到 pid 1495，但 frida 枚举不到它，
                  于是 probe_hits 抛 ProcessNotFoundError —— 两个工具给出
                  互相矛盾的视角，用户无从判断。

        解决方案：提供一个**独立于 frida 的活性探测**，同时用三条证据交叉验证：
            ① adb /proc/<pid> 是否存在（进程在内核里还在不在）
            ② /proc/<pid>/stat 的状态字符（R/S/T/Z/X，Z=僵尸）
            ③ frida 能否枚举到它（能不能注入）
        三者任一异常都在返回里如实说明，让调用方知道"0 命中"到底是
        "代码没跑"还是"进程没了"。

        ## 返回

            alive          进程在内核里是否存在
            status         /proc/<pid>/stat 的状态字符（R/S/D/T/t/Z/X）
            status_meaning 该字符的中文含义
            injectable     frida 能否看到并注入它
            verdict        一句话结论
            next_step      建议怎么做
        """
        result: dict = {
            "pid": int(pid),
            "alive": False,
            "status": "",
            "status_meaning": "",
            "injectable": False,
            "verdict": "",
            "next_step": "",
        }

        # ① /proc/<pid> 是否存在 + ② 状态字符
        try:
            out = self._cmd("shell", "su", "-c",
                            f"cat /proc/{int(pid)}/stat 2>/dev/null || echo MISSING",
                            check=False)
            text = (out or "").strip()
        except Exception:                                 # noqa: BLE001
            text = ""

        if not text or "MISSING" in text:
            result["alive"] = False
            result["verdict"] = f"进程 {pid} 在内核里已不存在（/proc 无此条目）"
            result["next_step"] = ("进程已退出。重新启动 app 后再 attach；"
                                   "注意 pid 会变，不要复用旧 pid")
            return result

        result["alive"] = True
        idx = text.rfind(")")
        status = ""
        if idx > 0:
            rest = text[idx + 1:].strip()
            status = rest.split()[0] if rest else ""
        result["status"] = status
        meanings = {
            "R": "运行中", "S": "可中断睡眠", "D": "不可中断睡眠",
            "T": "被 SIGSTOP 冻结", "t": "被调试器冻结",
            "Z": "僵尸（已退出但未被回收）", "X": "已退出",
            "I": "空闲内核线程",
        }
        result["status_meaning"] = meanings.get(status, f"未知状态 {status!r}")

        # ③ frida 能否看到（能否注入）
        try:
            import frida

            dev = frida.get_device(self.serial, timeout=10)
            seen = any(p.pid == int(pid) for p in dev.enumerate_processes())
            result["injectable"] = bool(seen)
        except Exception as exc:                          # noqa: BLE001
            result["injectable"] = False
            result["frida_error"] = f"{type(exc).__name__}: {exc}"

        # 结论
        if status in ("Z", "X"):
            result["verdict"] = (f"进程 {pid} 已是僵尸/已退出（状态 {status}"
                                 f"={result['status_meaning']}）："
                                 "它还在 /proc 里但不会执行任何代码")
            result["next_step"] = "重新启动 app（pid 会变），不要复用旧 pid"
        elif not result["injectable"]:
            result["verdict"] = (f"进程 {pid} 在内核里存在（状态 {status}="
                                 f"{result['status_meaning']}），但 frida 看不到它："
                                 "**无法注入**，所有断点/探针都不可能生效")
            result["next_step"] = ("该进程已失去可注入性（常见于被加固保护、"
                                   "frida 被检出，或进程正处于崩溃恢复）。"
                                   "重启 app 后重新 attach")
        else:
            result["verdict"] = (f"进程 {pid} 存活且可注入（状态 {status}="
                                 f"{result['status_meaning']}）")
            result["next_step"] = ("进程正常。若探针 0 命中，说明那段代码"
                                   "在当前场景确实没被执行（可用 watch_module 确认）")

        return result
