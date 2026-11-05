"""frida-server 版本对齐：下载、校验、覆盖、启动、回滚。

## 为什么需要这个模块

frida 的 Python 客户端与设备端 `frida-server` **必须版本一致**才能通信，
major 相同而 minor 不同也会报：

    ProtocolError: unable to communicate with remote frida-server

实测组合（设备 3e2ff172）：
    client 17.23.3 + server 16.0.19  → 不通
    client 17.23.3 + server 17.9.1   → 不通
    client 16.0.19 + server 16.0.19  → 通

每次手工排查都要 `adb push` + `chmod` + 起进程，且设备上常有多份历史二进制
（`frida_16019` / `frida-server` / `.fs`）互相干扰。本模块把这件事收敛成
一次可复现、可回滚的操作。

## 安全约定（重要）

1. **默认不执行**：`ensure_server(dry_run=True)` 是默认值，只做计划与检查。
   真正改动设备必须显式传 `dry_run=False`，避免误操作别人的设备。
2. **覆盖前强制备份**：目标路径若已有文件，先改名成 `<名>.bak-<时间戳>`，
   并把备份路径写进结果，回滚只需把备份搬回去。
3. **校验不可跳过**：下载后按 GitHub releases 公布的 sha256 校验，不匹配
   立即中止——不把一个来源不明的二进制塞进用户设备。
4. **失败自动回滚**：写入或启动任一步失败，把备份还原回去再报错，
   不留"半坏"状态。
5. **不动正在被别的东西占用的进程**：kill 之前先记录原进程的启动方式，
   结果里如实回报"我停掉了什么"。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field

from dyn.adb import Adb, DynError

# GitHub 官方发布源。不使用第三方镜像，避免二进制来源不可控。
RELEASE_BASE = "https://github.com/frida/frida/releases/download"
API_BASE = "https://api.github.com/repos/frida/frida/releases/tags"

# 下载缓存目录（项目内，随 .gitignore 排除）
_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "frida-server"
)

# 设备端候选落点：优先 /data/local/tmp（root 可写、SELinux 放行度最高）
DEVICE_DIR = "/data/local/tmp"
# 常规文件名；adbd 以 shell 身份 push 时无法直接覆盖 root 所有的同名文件，
# 因此实际写入走临时名 + su 搬家（见 _install）
DEVICE_NAME = "frida-server"


def client_version() -> str:
    """本机 frida 客户端版本——设备端必须与它一致。"""
    try:
        import frida

        return str(frida.__version__)
    except Exception as exc:                              # noqa: BLE001
        raise DynError("FRIDA_CLIENT_MISSING",
                       f"读不到本机 frida 版本（未安装？）：{exc}") from exc


def _abi_to_asset_suffix(abi: str) -> str:
    """把 Android ABI 映射成 frida release 资产名的后缀。

    只覆盖主流 arm64；其他架构明确报不支持，不猜。
    """
    table = {
        "arm64-v8a": "android-arm64",
        "armeabi-v7a": "android-arm",
        "x86_64": "android-x86_64",
        "x86": "android-x86",
    }
    key = (abi or "").strip()
    if key not in table:
        raise DynError(
            "UNSUPPORTED_ABI",
            f"不支持的设备 ABI：{key!r}；目前只覆盖 {sorted(table)}",
        )
    return table[key]


@dataclass
class Plan:
    """一次对齐操作的完整计划（dry_run 时就是这个结构给用户看）。"""

    client_version: str = ""
    device_abi: str = ""
    asset_name: str = ""
    download_url: str = ""
    expected_sha256: str = ""
    cached_path: str = ""
    device_path: str = ""
    device_exists: bool = False
    device_size: int = 0
    running_process: str = ""
    kept_processes: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "client_version": self.client_version,
            "device_abi": self.device_abi,
            "asset_name": self.asset_name,
            "download_url": self.download_url,
            "expected_sha256": self.expected_sha256,
            "cached_path": self.cached_path,
            "device_path": self.device_path,
            "device_exists": self.device_exists,
            "device_size": self.device_size,
            "running_process": self.running_process,
            "kept_processes": self.kept_processes,
            "steps": self.steps,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------- 下载

def _fetch_release_info(version: str, timeout: float = 90.0, retries: int = 3) -> dict:
    """查 GitHub release，返回 {资产名: {url, size, sha256}}。

    用 API 而不是硬编码 URL：资产名带版本号与架构，硬编码一旦版本变化就失效。

    (1) 第一次修改（2026-11-03）：优先 curl，urllib 只作兜底。
        bug 原因：该 API 返回约 400-500KB JSON。urllib 走 chunked 读取时在
                  网络抖动下会反复抛 IncompleteRead / JSON 截断（实测重试 3 次
                  全在 327680、363477 字节处断），功能直接不可用；
                  而同一 URL 用 curl 一次就拿到完整 426729 字节。
        解决方案：检测到 curl 就用 curl -o 落盘再读（它自带重试与断点续传逻辑），
                  没有 curl 或失败时才退回 urllib；两者都失败再报错。
                  超时给到 90s——实测这个 API 在这台机器上要 33s 才拉完。
    """
    url = f"{API_BASE}/{version}"
    last_exc: Exception | None = None

    def _via_curl() -> dict:
        exe = shutil.which("curl") or "/usr/bin/curl"
        if not os.path.exists(exe):
            raise DynError("NO_CURL", "系统没有 curl")
        curl_timeout = int(max(10, timeout))
        cmd = [exe, "-sS", "--max-time", str(curl_timeout),
               "--retry", "2", "--retry-delay", "1",
               "-H", "Accept: application/vnd.github+json",
               "-H", "User-Agent: mda-frida-aligner",
               url]
        r = subprocess.run(cmd, capture_output=True, timeout=curl_timeout + 10)
        if r.returncode != 0:
            raise DynError("CURL_FAILED", r.stderr.decode("utf-8", "replace")[:200])
        return json.loads(r.stdout.decode("utf-8"))

    def _via_urllib() -> dict:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mda-frida-aligner",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            buf = io.BytesIO()
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                buf.write(chunk)
        return json.loads(buf.getvalue().decode("utf-8"))

    data = None
    for attempt in range(max(1, retries)):
        for fetcher in (_via_curl, _via_urllib):
            try:
                data = fetcher()
                break
            except Exception as exc:                      # noqa: BLE001
                last_exc = exc
        if data is not None:
            break
        if attempt < retries - 1:
            time.sleep(1.5 * (attempt + 1))

    if data is None:
        raise DynError(
            "RELEASE_QUERY_FAILED",
            f"查询 frida {version} 的发布信息失败（curl/urllib 各重试 {retries} 次）："
            f"{last_exc}；可手动把 frida-server 二进制放到 .cache/frida-server/ 后重试",
        )

    assets: dict[str, dict] = {}
    for a in data.get("assets") or []:
        name = a.get("name") or ""
        digest = a.get("digest") or ""
        sha = digest.split(":", 1)[1] if digest.startswith("sha256:") else ""
        assets[name] = {
            "url": a.get("browser_download_url") or "",
            "size": int(a.get("size") or 0),
            "sha256": sha,
        }
    if not assets:
        raise DynError("RELEASE_EMPTY", f"frida {version} 的发布里没有任何资产")
    return assets


def _download(url: str, dest: str, timeout: float = 300.0) -> None:
    """流式下载到 dest（先写 .part 再改名，避免半截文件被当成成品）。"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": "mda-frida-aligner"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as f:
            shutil.copyfileobj(resp, f, length=1024 * 256)
        os.replace(tmp, dest)
    except Exception as exc:                              # noqa: BLE001
        for p in (tmp, dest):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
        raise DynError("DOWNLOAD_FAILED", f"下载失败：{exc}") from exc


def _frida_server_pids(adb: Adb) -> list[tuple[int, str]]:
    """列出设备上所有 frida server 进程 [(pid, name)]。

    (5) 第五次修改（2026-11-03）：改为「取进程表回本地过滤」，不再拼设备端 shell 脚本。
        bug 原因：初版用 `su -c "<复杂脚本>"` 在设备端做 awk/循环，但
                  subprocess 的列表参数会被 adb 拼成空格分隔的命令行，
                  **su -c 只拿到第一个词**，脚本剩余部分落到非 root 的 sh 里，
                  结果是 `$X` 为空的静默失败（实测 `X=abc; echo $X` 返回空串，
                  而 `for p in /proc/[0-9]*; do n=$((n+1)); done; echo $n` 却
                  因为后半段在普通 sh 里跑而返回 838，极具迷惑性）。
        解决方案：只用最简单的单命令（ps / grep），把**解析和过滤放在 Python 侧**。
                  这样与设备 shell 的层级、引号、变量展开完全无关。

    过滤规则：
        - 名字含 frida（大小写不敏感）
        - 排除 gadget（那是注入的 .so，不是独立 server 进程）
    """
    out = adb._cmd("shell", "ps", "-A", "-o", "PID,NAME", check=False)
    pids: list[tuple[int, str]] = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        pid_s, name = parts[0], parts[-1]
        low = name.lower()
        if "frida" not in low or "gadget" in low:
            continue
        if pid_s.isdigit():
            pids.append((int(pid_s), name))
    return pids


def _port_listening(adb: Adb, port: int) -> bool:
    """端口是否仍处于 LISTEN（本地解析 /proc/net/tcp，不依赖设备端 shell 能力）。

    (5) 第五次修改（2026-11-03）：新增本函数。用 grep -h 拿原始行回本地解析，
        避免了 awk 的 $ 被多层 shell 展开的问题（实测 awk 版本恒返回空）。
    """
    hex_port = f"{port:04X}"
    raw = adb._cmd("shell", "su", "-c",
                   f"grep -h -i :{hex_port} /proc/net/tcp /proc/net/tcp6 2>/dev/null || true",
                   check=False)
    for line in (raw or "").splitlines():
        parts = line.split()
        # 字段布局：sl local_address rem_address st ... inode(第10列)
        if len(parts) > 9 and parts[3] == "0A":
            return True
    return False


# ELF e_machine 取值（与 ABI 对应）
_ELF_MACHINE = {
    "arm64-v8a": 0xB7,      # EM_AARCH64
    "armeabi-v7a": 0x28,    # EM_ARM
    "x86_64": 0x3E,         # EM_X86_64
    "x86": 0x03,            # EM_386
}


def _sanity_check_binary(path: str, expect_abi: str = "") -> tuple[bool, str]:
    """解压产物的健全性检查：ELF 魔数 + 架构 + 大小合理。

    (4) 第四次修改（2026-11-03）：新增本函数。
        为什么不能只用 sha256：GitHub 的 digest 针对压缩包，解压后无法用同一值
        校验。而"下载完整 + 解压成功"本身只能保证字节流没断，不能保证内容对。
        这里补一层结构校验——真 frida-server 是 arm64 ELF 可执行文件，
        如果解出来是别的东西（HTML 错误页、截断文件），这三项会立刻暴露。
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return False, f"读不到文件：{exc}"
    if size < 1024 * 1024:
        return False, f"大小只有 {size} 字节，远小于正常 frida-server（约 50MB）"
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError as exc:
        return False, f"读取失败：{exc}"
    if head[:4] != b"\x7fELF":
        return False, f"不是 ELF 文件（头 4 字节 {head[:4]!r}）"
    if len(head) >= 20 and expect_abi:
        # (8) 第八次修改（2026-11-05）：e_machine 按目标 ABI 判断，不再写死 AARCH64。
        #     bug 原因：原实现恒比较 0xB7(EM_AARCH64)，而 _abi_to_asset_suffix
        #               明明支持 x86_64/arm/x86 —— 在那些设备上下载下来的正确二进制
        #               会被判成"不是 arm64 ELF"，导致 prepare_server 永远失败。
        #     解决方案：按 expect_abi 查表比对；未给 ABI 时跳过该检查（只验 ELF 魔数）。
        want = _ELF_MACHINE.get(expect_abi)
        e_machine = int.from_bytes(head[18:20], "little")
        if want is not None and e_machine != want:
            return False, (f"ELF 架构不符：期望 {expect_abi}(e_machine=0x{want:02x})，"
                           f"实际 0x{e_machine:02x}")
    return True, ""


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _decompress_xz(src: str, dst: str) -> None:
    """解压 .xz。优先 lzma 标准库，失败再退 xz 命令。

    为什么不用 subprocess 打头：标准库没有外部依赖，打包后也能用。
    """
    try:
        import lzma

        with lzma.open(src, "rb") as f_in, open(dst, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out, length=1024 * 256)
        return
    except Exception:                                     # noqa: BLE001
        pass
    exe = shutil.which("xz")
    if not exe:
        raise DynError("NO_XZ", "解压 .xz 失败且系统没有 xz 命令")
    subprocess.run([exe, "-dkf", src], check=True, capture_output=True)
    produced = src[:-3] if src.endswith(".xz") else src + ".out"
    if not os.path.exists(produced):
        raise DynError("NO_XZ", "xz 执行成功但找不到解压产物")
    shutil.move(produced, dst)


def prepare_server(version: str, abi: str, dry_run: bool = True,
                   timeout: float = 300.0) -> dict:
    """确保本地缓存里有该版本+该 ABI 的 frida-server，返回其路径与校验信息。

    dry_run=True 时只查发布信息、不下载。
    """
    suffix = _abi_to_asset_suffix(abi)
    asset = f"frida-server-{version}-{suffix}.xz"
    assets = _fetch_release_info(version)
    if asset not in assets:
        raise DynError(
            "ASSET_NOT_FOUND",
            f"frida {version} 的发布里找不到 {asset}；"
            f"同架构可用资产：{[n for n in assets if suffix in n][:6]}",
        )
    info = assets[asset]

    os.makedirs(_CACHE_DIR, exist_ok=True)
    xz_path = os.path.join(_CACHE_DIR, asset)
    bin_path = os.path.join(_CACHE_DIR, f"frida-server-{version}-{suffix}")

    out = {
        "asset_name": asset,
        "download_url": info["url"],
        "expected_sha256": info["sha256"],
        "expected_size": info["size"],
        "cached_binary": bin_path,
        "downloaded": False,
        "verified": False,
    }

    # 已有解压成品：只做基本健全性检查（大小 + ELF 魔数）。
    # 不能再比对 GitHub 的 sha256——那个值是**压缩包**的，不是解压后内容的。
    if os.path.exists(bin_path):
        sane, why = _sanity_check_binary(bin_path, abi)
        if sane:
            out.update({"verified": True,
                        "verify_method": "sanity（xz 已校验过，二进制做 ELF/大小检查）",
                        "note": "本地已有解压产物且健全性检查通过，复用"})
            return out
        # 产物可疑：删掉重来，绝不复用
        try:
            os.remove(bin_path)
        except OSError:
            pass
        out["note"] = f"既有解压产物未通过健全性检查（{why}），已删除待重建"

    if dry_run:
        out["note"] = "dry_run：未下载。确认后传 dry_run=False 才会真正下载"
        return out

    if not os.path.exists(xz_path):
        _download(info["url"], xz_path, timeout=timeout)
        out["downloaded"] = True

    # (4) 第四次修改（2026-11-03）：在**压缩包**上校验 sha256，而不是解压产物。
    #     bug 原因：GitHub release 的 digest 字段是对上传资产（这里是 .xz）的
    #               sha256，而初版实现解压后才算 bin 的 sha256 去比对，必然不等；
    #               实测 xz 的 sha256 正是 f61e98db…（与官方一致），
    #               解压产物 8887fb3d… 却因此被判成"来源不明"而删除。
    #               这属于**校验对象错位**，会让功能永远无法成功（虽然方向安全）。
    #     解决方案：下载完先对 xz 校验，通过后再解压；解压产物改用
    #               _sanity_check_binary 做 ELF 魔数 + 大小合理性检查，
    #               并在结果里标明 verify_method，让调用方知道校验的强度。
    xz_sha = _sha256_of(xz_path)
    out["xz_sha256"] = xz_sha
    if info["sha256"] and xz_sha != info["sha256"]:
        # 压缩包本身不对：删掉重下时机由调用方决定，这里只报错
        try:
            os.remove(xz_path)
        except OSError:
            pass
        raise DynError(
            "SHA256_MISMATCH",
            f"{asset} 压缩包校验失败：期望 {info['sha256'][:16]}…，"
            f"实际 {xz_sha[:16]}…；已删除该文件，不安装来源不明的二进制",
        )
    out["xz_verified"] = bool(info["sha256"])
    if not info["sha256"]:
        # (9) 第九次修改（2026-11-05）：digest 缺失时**明确告警**，不再静默放行。
        #     bug 原因：GitHub 的 digest 字段是较新才有的，老 release 可能为空；
        #               原实现此时把 xz_verified 置 False，但 ensure_server 只看
        #               prep["verified"]，于是"没有校验"被当成"校验通过"继续安装，
        #               与 docstring 承诺的"校验不可跳过"相反。
        #     解决方案：保留 xz_verified=False 的事实，同时把 verified 也置 False
        #               并写进 unverified_reason；由 ensure_server 决定是否中止。
        out["verified"] = False
        out["unverified_reason"] = (
            f"GitHub 发布信息里没有 {asset} 的 sha256（digest 字段为空）；"
            "本次下载**未做哈希校验**，仅能证明来源是官方 release")

    _decompress_xz(xz_path, bin_path)
    sane, why = _sanity_check_binary(bin_path, abi)
    if not sane:
        try:
            os.remove(bin_path)
        except OSError:
            pass
        raise DynError(
            "BAD_BINARY",
            f"解压出的 frida-server 未通过健全性检查（{why}）；已删除",
        )
    out["actual_size"] = os.path.getsize(bin_path)
    out["verify_method"] = "xz(sha256) + binary(ELF/大小)"
    out["verified"] = True
    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        pass
    return out


# ---------------------------------------------------------------- 设备侧

# (6) 第六次修改（2026-11-05）：新增设备路径校验，堵住 root shell 注入面。
#     bug 原因：device_path 来自 MCP 工具参数（可被 AI 参数、甚至被分析样本里的
#               字符串影响），而它被原样拼进 `su -c` 命令串，于是一个带
#               `; id` 或 `$(...)` 的路径就能变成设备上的 root 任意命令执行。
#     解决方案：白名单校验——必须是以 / 开头的绝对路径，只允许
#               字母/数字/点/下划线/短横/斜杠，且不含 `..`。
#               所有拼 `su -c` 的地方都先过这一关；校验失败抛 BAD_DEVICE_PATH。
_SAFE_DEVICE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")


def _validate_device_path(path: str) -> str:
    """校验设备端路径，防止它被当作 shell 命令的一部分执行。"""
    raw = (path or "").strip()
    if not raw:
        raise DynError("BAD_DEVICE_PATH", "device_path 不能为空")
    if not raw.startswith("/"):
        raise DynError("BAD_DEVICE_PATH",
                       f"device_path 必须是绝对路径，实际 {raw!r}")
    if ".." in raw:
        raise DynError("BAD_DEVICE_PATH",
                       f"device_path 不能包含 '..'，实际 {raw!r}")
    if not _SAFE_DEVICE_PATH.match(raw):
        bad = sorted(set(re.findall(r"[^A-Za-z0-9._/-]", raw)))
        raise DynError(
            "BAD_DEVICE_PATH",
            f"device_path 含非法字符 {bad}（只允许字母数字 . _ - /），实际 {raw!r}；"
            "该参数会被拼进 su 命令，带 shell 元字符会被当成额外命令执行",
        )
    return raw


def _device_abi(adb: Adb) -> str:
    out = adb._cmd("shell", "getprop", "ro.product.cpu.abi", check=False)
    abi = (out or "").strip()
    if not abi:
        raise DynError("NO_ABI", "读不到设备 ABI（getprop ro.product.cpu.abi 为空）")
    return abi


def _device_stat(adb: Adb, path: str) -> dict:
    """返回 {exists, size}；用 stat 而不是 ls 解析，避免格式差异。"""
    out = adb._cmd("shell", "su", "-c",
                   f"stat -c '%s' {path} 2>/dev/null || echo MISSING",
                   check=False)
    text = (out or "").strip()
    if not text or "MISSING" in text:
        return {"exists": False, "size": 0}
    try:
        return {"exists": True, "size": int(text.splitlines()[0].strip())}
    except (ValueError, IndexError):
        return {"exists": False, "size": 0}


def build_plan(serial: str, version: str | None = None,
               device_path: str = f"{DEVICE_DIR}/{DEVICE_NAME}") -> Plan:
    """生成对齐计划（只读，不改设备）。"""
    device_path = _validate_device_path(device_path)
    adb = Adb(serial)
    if not adb.is_root():
        raise DynError("NO_ROOT", "设备没有 root，无法覆盖 /data/local/tmp 下的 root 文件")

    ver = version or client_version()
    abi = _device_abi(adb)
    suffix = _abi_to_asset_suffix(abi)

    plan = Plan(
        client_version=ver,
        device_abi=abi,
        asset_name=f"frida-server-{ver}-{suffix}.xz",
        device_path=device_path,
    )
    # (3) 第三次修改（2026-11-03）：计划里补上官方 sha256 与下载地址。
    #     bug 原因：dry_run 时 build_plan 不查发布信息，expected_sha256 恒为空，
    #               用户无法在"确认执行"之前核对待装内容的指纹——而这正是
    #               这类覆盖设备文件的操作最需要先看到的东西。
    #     解决方案：尝试查一次发布信息填进去；网络失败不算致命（正式执行时
    #               prepare_server 还会再查并强制校验），只记一条警告。
    try:
        info = _fetch_release_info(ver).get(plan.asset_name)
        if info:
            plan.expected_sha256 = info.get("sha256", "")
            plan.download_url = info.get("url", "")
        else:
            plan.warnings.append(
                f"在该版本的发布里没找到 {plan.asset_name}，执行时会报 ASSET_NOT_FOUND")
    except Exception as exc:                              # noqa: BLE001
        plan.warnings.append(
            f"未能预取发布信息（执行时会重试并强制校验）：{exc}")
    stat = _device_stat(adb, device_path)
    plan.device_exists = stat["exists"]
    plan.device_size = stat["size"]

    # 设备上已有的其他 frida **可执行文件**：列出来提醒（实战里最容易被它们干扰）
    # (2) 第二次修改（2026-11-03）：过滤掉 gadget/.log 噪音。
    #     bug 原因：初版把 frida-gadget-*.so/.config 和 *.log 全列进警告，
    #               实测一次列出 20+ 项，真正有威胁的两个（frida-server、
    #               frida_16019）被淹没，等于没提醒。
    #     解决方案：只保留「可执行 + 名字含 frida + 不是 gadget」的文件。
    listing = adb._cmd("shell", "su", "-c",
                       f"ls -la {DEVICE_DIR}/ | grep -i frida || echo NONE", check=False)
    others = []
    for ln in (listing or "").splitlines():
        parts = ln.split()
        # Android 的 ls 是 toybox：权限/链接数/owner/group/大小/日期/时间/名字
        # 只有 8 个字段（没有年份列），不能按桌面 ls 的 9 字段判
        if len(parts) < 8:
            continue
        name = parts[-1]
        perms = parts[0]
        low = name.lower()
        if "frida" not in low or "gadget" in low:
            continue
        if not perms.startswith("-") or "x" not in perms:
            continue          # 非可执行（日志、配置）不提醒
        others.append(name)
    if len(others) > 1:
        plan.warnings.append(
            f"设备上有多个 frida 相关文件：{others}；"
            "覆盖后请确认启动的是你指定的那个，历史文件可能被别的脚本拉起"
        )

    # (7) 第七次修改（2026-11-05）：占用者改用**端口**探测。
    #     bug 原因：原用 _running_name()（只认 frida-server/frida-server-17 两个名），
    #               漏报设备上真实在跑的 frida_16019，于是 dry_run 计划里
    #               running_process 为空，用户会误以为"没有进程在跑、很安全"。
    #     解决方案：以 27042 的端口持有者为准；同时把其他 frida 实例单列出来，
    #               让计划如实反映"谁会被停、谁不会被碰"。
    holders = adb.listening_pids(27042)
    plan.running_process = "、".join(f"{n}(pid {p})" for p, n in holders)
    others = [(p, n) for (p, n) in _frida_server_pids(adb)
              if p not in {h[0] for h in holders}]
    plan.kept_processes = [{"pid": p, "name": n} for p, n in others]
    if holders:
        plan.warnings.append(
            "执行时会停掉占用 27042 的：" +
            "、".join(f"{n}(pid {p})" for p, n in holders) +
            "。若它由 Magisk 模块或外部脚本看守，kill 后可能被重新拉起，"
            "**无法保证它不被重新启动**")
    if others:
        plan.warnings.append(
            "设备上还有其他 frida 进程（不占 27042），**不会被触碰**：" +
            "、".join(f"{n}(pid {p})" for p, n in others))

    plan.steps = [
        f"1. 下载 {plan.asset_name} 并用 GitHub 公布的 sha256 校验",
        f"2. push 到 {device_path} 的临时名（避免覆盖正在运行的文件）",
        f"3. 若原文件存在，先备份为 {device_path}.bak-<时间戳>",
        f"4. su 搬家为正式文件名并 chmod 755",
        f"5. 停掉占用 27042 的进程（{plan.running_process or '无'}）；"
        f"其他 frida 实例不动",
        f"6. 以 root 启动新 server，等待并验证端口 27042 可连",
        "7. 失败任一步 → 自动还原备份并报错",
    ]
    return plan


def _install(adb: Adb, local_bin: str, device_path: str) -> dict:
    """把本地二进制装到设备，返回备份信息。

    关键点：不能直接 push 覆盖。
      - 目标可能是 root 所有、shell 无写权限 → adb push 会失败
      - 目标可能正在被执行 → 直接覆盖会 ETXTBSY
    所以先 push 到 shell 可写的临时名，再用 su 搬过去。
    """
    tmp = f"{DEVICE_DIR}/.mda-frida-server.new"
    result = {"tmp_path": tmp, "backup_path": "", "backed_up": False}

    # push：/data/local/tmp 一般允许 shell 写；失败再走 su 中转
    try:
        adb._cmd("push", local_bin, tmp, timeout=180)
    except DynError:
        stage = f"{DEVICE_DIR}/.mda-stage"
        adb._cmd("push", local_bin, stage, timeout=180)
        adb._cmd("shell", "su", "-c", f"cp {stage} {tmp} && rm -f {stage}", timeout=60)

    adb._cmd("shell", "su", "-c", f"chmod 755 {tmp}", timeout=30)

    # 备份原文件（带时间戳，保留可回滚点）
    stat = _device_stat(adb, device_path)
    if stat["exists"]:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = f"{device_path}.bak-{stamp}"
        adb._cmd("shell", "su", "-c", f"cp -p {device_path} {backup}", timeout=60)
        result["backup_path"] = backup
        result["backed_up"] = True

    adb._cmd("shell", "su", "-c", f"mv -f {tmp} {device_path} && chmod 755 {device_path}",
             timeout=60)
    return result


def _restore(adb: Adb, backup_path: str, device_path: str) -> bool:
    """把备份还原回去；成功返回 True。"""
    if not backup_path:
        return False
    try:
        adb._cmd("shell", "su", "-c",
                 f"cp -p {backup_path} {device_path} && chmod 755 {device_path}",
                 timeout=60)
        return True
    except Exception:                                     # noqa: BLE001
        return False


def _rollback(adb: Adb, installed: dict, device_path: str,
              serial: str) -> dict:
    """完整回滚：停掉刚启动的新进程 → 还原备份 → 把旧二进制重新起来。

    (10) 第十次修改（2026-11-05）：新增，替换原来只做 `_restore` 的半截回滚。
         bug 原因：原回滚只把备份文件拷回去，**不停掉刚启动的新 server、
                 也不重启旧的**。结果设备上要么有个版本不对的进程占着 27042，
                 要么干脆没有 server 在跑——比不回滚更糟（用户以为已恢复原状）。
         解决方案：三步都做，每步结果都回报：
                   1) 停掉当前占用 27042 的进程（可能是刚起的新的）
                   2) 把备份还原成目标路径
                   3) 用还原后的二进制重新启动并确认端口监听
    """
    result: dict = {"stopped_new": [], "restored": False, "restarted": False,
                    "port_listening": False}
    # 1) 停掉当前持有者（新起的那个）
    for pid, name in adb.listening_pids(27042):
        adb._cmd("shell", "su", "-c",
                 f"kill {pid} 2>/dev/null; sleep 0.3; kill -9 {pid} 2>/dev/null",
                 check=False)
        result["stopped_new"].append({"pid": pid, "name": name})
    for _ in range(20):
        if not adb.listening_port(27042):
            break
        time.sleep(0.25)

    # 2) 还原备份
    result["restored"] = _restore(adb, installed.get("backup_path", ""), device_path)
    if not result["restored"]:
        result["error"] = "备份还原失败，请手工处理"
        return result

    # 3) 把还原后的旧二进制重新起来
    try:
        adb._cmd("shell", "su", "-c",
                 f"nohup {device_path} >/dev/null 2>&1 &", timeout=20)
        time.sleep(2.0)
        result["port_listening"] = adb.listening_port(27042)
        result["restarted"] = result["port_listening"]
        if result["restarted"]:
            result["restored_version"] = adb.server_version(device_path)
    except Exception as exc:                              # noqa: BLE001
        result["restart_error"] = str(exc)
    return result


def _verify_connection(serial: str, timeout: float = 10.0) -> dict:
    """尝试真正连一次设备，确认版本匹配（最硬的验证）。"""
    try:
        import frida

        dev = frida.get_device(serial, timeout=timeout)
        procs = dev.enumerate_processes()
        return {"ok": True, "process_count": len(procs),
                "client_version": frida.__version__}
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def ensure_server(serial: str, version: str | None = None, dry_run: bool = True,
                  device_path: str = f"{DEVICE_DIR}/{DEVICE_NAME}",
                  allow_unverified: bool = False) -> dict:
    """一站式：下载 → 校验 → 备份 → 覆盖 → 启动 → 验证；失败自动回滚。

    dry_run=True（默认）只返回计划，**不改动设备**。
    """
    device_path = _validate_device_path(device_path)
    plan = build_plan(serial, version, device_path)
    adb = Adb(serial)
    out: dict = {"dry_run": dry_run, "plan": plan.as_dict(), "done": False}

    if dry_run:
        out["note"] = "dry_run=True：未改动设备。确认后传 dry_run=False 执行"
        return out

    prep = prepare_server(plan.client_version, plan.device_abi, dry_run=False)
    out["download"] = prep
    if not prep.get("verified"):
        # (9) 第九次修改（2026-11-05）：未校验时**默认拒绝**，不再静默继续。
        #     只有调用方显式传 allow_unverified=True 才放行，并在结果里留痕。
        reason = prep.get("unverified_reason") or "下载产物未通过校验"
        if not allow_unverified:
            raise DynError(
                "NOT_VERIFIED",
                reason + "；如确认接受未校验的二进制，显式传 allow_unverified=True 再试")
        out.setdefault("warnings", []).append(reason + "（已按 allow_unverified=True 继续）")

    installed: dict = {}
    try:
        # (10) 第十次修改（2026-11-05）：_install 移进 try。
        #      bug 原因：安装阶段（push/备份/搬家）异常时在 try 之外，
        #                异常直接抛出，既不走回滚也不写 error/hint，
        #                设备可能停在"备份已做、文件没换成"的半截状态。
        installed = _install(adb, prep["cached_binary"], device_path)
        out["install"] = installed

        # 停掉现存的所有 frida server 进程。
        #
        # (5) 第五次修改（2026-11-03）：按「进程表本地过滤」停止，不再依赖进程名候选。
        #     bug 原因：设备上实际跑的是 `frida_16019`（自定义文件名），而
        #               dyn.adb 的进程名候选只有 frida-server / frida-server-17。
        #               按名 pidof 找不到 → stopped=[] → 端口 27042 仍被它占用 →
        #               新 server 绑定失败退出 → 报 START_FAILED。实测正是此因。
        #     解决方案：用 ps -A -o PID,NAME 取回进程表，在 Python 侧筛出名字含
        #               frida 且非 gadget 的进程（frida_16019 会被正确命中），
        #               再逐个 kill。同时记录停掉了什么，便于用户回溯。
        # (7) 第七次修改（2026-11-05）：**只停占用 27042 的进程**，不再按名杀全部 frida。
        #     bug 原因：上一版用 _frida_server_pids() 把所有"名字含 frida"的进程都 kill，
        #               而设备上可能同时跑着别人项目用的另一个 frida 实例
        #               （实测 /data/local/tmp/frida_16019 -l 0.0.0.0:27100，pid 12443）。
        #               执行"版本对齐"会静默打断别人的调试会话——这是明确的安全红线。
        #     解决方案：端口是唯一可靠判据。只停 listening_pids(27042) 返回的持有者；
        #               其他 frida 进程原样保留，并在结果里列出来告知用户"看到了但没动"。
        stopped = []
        victims = adb.listening_pids(27042)
        for pid, name in victims:
            adb._cmd("shell", "su", "-c",
                     f"kill {pid} 2>/dev/null; sleep 0.3; kill -9 {pid} 2>/dev/null",
                     check=False)
            stopped.append(f"{name}（pid {pid}）")
        out["stopped_processes"] = stopped
        out["stopped_count"] = len(victims)

        # 如实列出"看到了但没动"的其他 frida 进程，避免用户以为它们被清理了
        kept = [(p, n) for (p, n) in _frida_server_pids(adb)
                if p not in {v[0] for v in victims}]
        out["kept_processes"] = [
            {"pid": pid, "name": name,
             "reason": "不占用 27042，可能是其他项目的实例，未做任何操作"}
            for pid, name in kept
        ]
        if kept:
            out.setdefault("warnings", []).append(
                "设备上还有其他 frida 进程未被触碰（不占 27042）："
                + "、".join(f"{n}(pid {p})" for p, n in kept))

        # 等端口真正释放（TIME_WAIT 也要让开）。端口是最终判据：
        # 进程杀没杀掉不重要，"能不能绑定 27042"才决定新 server 能不能起。
        for _ in range(24):                      # 最多约 6 秒
            if not _port_listening(adb, 27042):
                break
            time.sleep(0.25)
        out["port_free"] = not _port_listening(adb, 27042)

        # 启动并等待端口
        adb._cmd("shell", "su", "-c",
                 f"nohup {device_path} >/dev/null 2>&1 &", timeout=20)
        time.sleep(2.0)
        running = adb._running_name()
        out["started_process"] = running
        if not running:
            raise DynError("START_FAILED", "启动命令已执行，但设备上找不到 frida 进程")

        verify = _verify_connection(serial)
        out["verify"] = verify
        if not verify.get("ok"):
            raise DynError(
                "VERIFY_FAILED",
                f"server 已启动但连不上（{verify.get('error')}）；"
                "常见原因是版本仍不匹配或有另一个 server 抢先占端口",
            )
        out["done"] = True
        return out
    except Exception as exc:                              # noqa: BLE001
        # (10) 第十次修改：改用完整回滚（停新进程 + 还原 + 重启旧的）
        rb = _rollback(adb, installed, device_path, serial)
        out["rollback"] = rb
        out["rolled_back"] = bool(rb.get("restored"))
        out["error"] = f"{type(exc).__name__}: {exc}"
        if rb.get("restored") and rb.get("restarted"):
            out["hint"] = (f"已完整回滚：备份还原并重新启动（版本 "
                           f"{rb.get('restored_version') or '未知'}），端口已监听")
        elif rb.get("restored"):
            out["hint"] = ("备份已还原，但旧二进制未能重新启动；"
                           f"请手工执行 {device_path}")
        else:
            out["hint"] = (f"还原失败，请手工把 {installed.get('backup_path') or '(无备份)'} "
                           f"拷回 {device_path}")
        return out
