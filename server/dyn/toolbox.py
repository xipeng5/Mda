"""Android 设备常用工具箱与本地设置持久化（解耦模块，供 Web 设置页与 MCP 工具共用）。

包含三类真实设备操作（零模拟/零假数据，全部走真实 adb / su 命令）：
  1. 手机系统全局代理与 mitmproxy 系统证书管理（开/关代理、状态体检、装/卸 Magisk + 即时系统证书）
  2. App 冻结与解冻（pm suspend / pm unsuspend，防止浏览器深链跳转，保留登录态）
  3. App 强制停止、清理数据与可选延迟重启（am force-stop / su pm clear / monkey LAUNCHER）

以及设置页的本地 JSON 配置持久化（绝不把个人包名、IP 等硬编码进代码）。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import glob
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from typing import Any

from server.dyn.adb import Adb, DynError, resolve_adb

# 只写 http_proxy 在部分 ROM（如 MIUI/HyperOS）上不生效，必须整组读写这四个键
PROXY_KEYS = (
    "http_proxy",
    "global_http_proxy_host",
    "global_http_proxy_port",
    "global_http_proxy_exclusion_list",
)
HOST_IFACES = ("en0", "en1", "en2", "en3")
DEFAULT_CERT_PATH = "~/.mitmproxy/mitmproxy-ca-cert.pem"
MODULE_ID = "mitmproxy-ca"
MODULE_DIR = f"/data/adb/modules/{MODULE_ID}"
SYS_CACERTS = "/system/etc/security/cacerts"

_PKG_RE = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")
_SETTINGS_LOCK = threading.Lock()
_LABEL_LOCK = threading.Lock()
_LABEL_CACHE: dict[tuple[str, str], str] = {}
_LABEL_CACHE_LOADED = False

DEFAULT_SETTINGS: dict[str, Any] = {
    "serial": "",
    "proxy_host": "",
    "proxy_port": 8080,
    "cert_path": DEFAULT_CERT_PATH,
    "favorite_apps": [],
    "suspend_packages": [],
    "reset_package": "",
    "reset_wait_sec": 2.0,
    "reset_relaunch": True,
}


# ---------------------------------------------------------------- 本地配置持久化


def _settings_dir() -> str:
    """返回可写的配置目录（与 api._cache_root 保持一致，打包冻结后落用户目录）。"""
    env = os.environ.get("MDA_CACHE_DIR", "").strip()
    if env:
        return env
    if getattr(sys, "frozen", False):
        return os.path.expanduser("~/Library/Application Support/MDA")
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, ".cache")


def settings_file_path() -> str:
    """本地设置 JSON 路径。"""
    return os.path.join(_settings_dir(), "settings.json")


def _clean_packages(raw: Any) -> list[str]:
    """清洗并去重合法包名列表，非法项静默跳过。"""
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        pkg = str(item or "").strip()
        if pkg and _PKG_RE.match(pkg) and pkg not in seen:
            seen.add(pkg)
            out.append(pkg)
    return out


def _clean_favorite_apps(raw: Any) -> list[dict[str, str]]:
    """清洗并去重常用 App 列表（每项保留真实包名 package 与可读名称 name）。"""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            pkg = item.strip()
            name = ""
        elif isinstance(item, dict):
            pkg = str(item.get("package") or "").strip()
            name = str(item.get("name") or "").strip()[:80]
        else:
            continue
        if pkg and _PKG_RE.match(pkg) and pkg not in seen:
            seen.add(pkg)
            out.append({"name": name, "package": pkg})
    return out


def load_settings() -> dict[str, Any]:
    """读取本地持久化设置，缺失字段补默认值并兼容旧版 suspend_packages 迁移。"""
    data = dict(DEFAULT_SETTINGS)
    path = settings_file_path()
    with _SETTINGS_LOCK:
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    saved = json.load(fh)
                if isinstance(saved, dict):
                    data.update(saved)
            except Exception:                             # noqa: BLE001
                pass
    # 类型归一，避免损坏文件影响前端
    data["serial"] = str(data.get("serial") or "").strip()
    data["proxy_host"] = str(data.get("proxy_host") or "").strip()
    try:
        p = int(data.get("proxy_port", 8080))
        data["proxy_port"] = p if 1 <= p <= 65535 else 8080
    except (TypeError, ValueError):
        data["proxy_port"] = 8080
    data["cert_path"] = str(data.get("cert_path") or DEFAULT_CERT_PATH).strip() or DEFAULT_CERT_PATH

    favs = _clean_favorite_apps(data.get("favorite_apps"))
    legacy_susp = _clean_packages(data.get("suspend_packages"))
    seen_pkgs = {it["package"] for it in favs}
    for pkg in legacy_susp:
        if pkg not in seen_pkgs:
            seen_pkgs.add(pkg)
            favs.append({"name": "", "package": pkg})
    data["favorite_apps"] = favs
    data["suspend_packages"] = [it["package"] for it in favs]

    rp = str(data.get("reset_package") or "").strip()
    data["reset_package"] = rp if (not rp or _PKG_RE.match(rp)) else ""
    try:
        ws = float(data.get("reset_wait_sec", 2.0))
        data["reset_wait_sec"] = max(0.0, min(15.0, ws))
    except (TypeError, ValueError):
        data["reset_wait_sec"] = 2.0
    data["reset_relaunch"] = bool(data.get("reset_relaunch", True))
    return data


def save_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """局部合并并持久化设置到本地 JSON（原子替换写盘）。"""
    cur = load_settings()
    if not isinstance(patch, dict):
        return cur
    if "serial" in patch:
        cur["serial"] = str(patch.get("serial") or "").strip()
    if "proxy_host" in patch:
        host = str(patch.get("proxy_host") or "").strip()
        if host:
            validate_ip(host)
        cur["proxy_host"] = host
    if "proxy_port" in patch:
        cur["proxy_port"] = validate_port(patch.get("proxy_port"))
    if "cert_path" in patch:
        cur["cert_path"] = str(patch.get("cert_path") or DEFAULT_CERT_PATH).strip() or DEFAULT_CERT_PATH
    if "favorite_apps" in patch:
        favs = _clean_favorite_apps(patch.get("favorite_apps"))
        cur["favorite_apps"] = favs
        cur["suspend_packages"] = [it["package"] for it in favs]
    elif "suspend_packages" in patch:
        pkgs = _clean_packages(patch.get("suspend_packages"))
        old_names = {it["package"]: it["name"] for it in cur.get("favorite_apps", [])}
        cur["favorite_apps"] = [{"name": old_names.get(p, ""), "package": p} for p in pkgs]
        cur["suspend_packages"] = pkgs
    if "reset_package" in patch:
        rp = str(patch.get("reset_package") or "").strip()
        if rp:
            validate_package(rp)
        cur["reset_package"] = rp
    if "reset_wait_sec" in patch:
        try:
            ws = float(patch.get("reset_wait_sec"))
        except (TypeError, ValueError) as exc:
            raise ValueError("reset_wait_sec 必须是数字") from exc
        cur["reset_wait_sec"] = max(0.0, min(15.0, ws))
    if "reset_relaunch" in patch:
        cur["reset_relaunch"] = bool(patch.get("reset_relaunch"))

    path = settings_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with _SETTINGS_LOCK:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    return cur


# ---------------------------------------------------------------- 参数与设备辅助


def validate_package(pkg: str) -> str:
    """严格校验 Android 包名格式，杜绝 shell 注入。"""
    val = str(pkg or "").strip()
    if not val or not _PKG_RE.match(val):
        raise ValueError(f"非法 Android 包名：{val!r}")
    return val


def validate_ip(host: str) -> str:
    """严格校验 IPv4/IPv6 地址，杜绝 shell 注入。"""
    val = str(host or "").strip()
    try:
        ipaddress.ip_address(val)
    except ValueError as exc:
        raise ValueError(f"非法代理 IP 地址：{val!r}") from exc
    return val


def validate_port(port: Any) -> int:
    """严格校验端口号（1~65535）。"""
    try:
        val = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法端口号：{port!r}") from exc
    if not (1 <= val <= 65535):
        raise ValueError(f"端口号超出 1~65535：{val}")
    return val


def pick_serial(serial: str = "") -> str:
    """选定目标在线 ADB 设备：显式指定优先，否则唯一在线自动选中，多台报错提示。"""
    req = str(serial or "").strip()
    devices = [d for d in Adb.list_devices() if d.state == "device"]
    if not devices:
        raise DynError("NO_DEVICE", "未检测到已连接的在线 adb 设备，请检查 USB 连接与调试授权")
    if req:
        if not any(d.serial == req for d in devices):
            online = ", ".join(d.serial for d in devices)
            raise DynError("DEVICE_OFFLINE", f"设备 {req} 未在线；当前在线设备：{online}")
        return req
    if len(devices) > 1:
        online = ", ".join(d.serial for d in devices)
        raise DynError("MULTI_DEVICE", f"检测到 {len(devices)} 台在线设备，请明确指定 serial：{online}")
    return devices[0].serial


def detect_host_ip() -> str:
    """自动检测本机局域网 IPv4（macOS 优先查 en0~en3，再走路由 socket 兜底）。"""
    for iface in HOST_IFACES:
        try:
            r = subprocess.run(
                ["ipconfig", "getifaddr", iface],
                capture_output=True, text=True, timeout=3,
            )
            ip = (r.stdout or "").strip()
            if r.returncode == 0 and ip:
                ipaddress.IPv4Address(ip)
                return ip
        except Exception:                                 # noqa: BLE001
            continue
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        finally:
            sock.close()
    except Exception:                                     # noqa: BLE001
        pass
    return ""


def _foreground_of(adb: Adb) -> str:
    """查询指定设备当前前台 App 包名（只读 dumpsys）。"""
    try:
        out = adb._cmd("shell", "dumpsys", "activity", "activities", check=False, timeout=8) or ""
        m = re.search(r"mResumedActivity.*?u0 ([\w.]+)/", out)
        if m:
            return m.group(1)
        out2 = adb._cmd("shell", "dumpsys", "window", check=False, timeout=8) or ""
        m2 = re.search(r"mCurrentFocus=Window\{[^\}]+\s+([\w.]+)/", out2)
        return m2.group(1) if m2 else ""
    except Exception:                                     # noqa: BLE001
        return ""


def _find_aapt() -> str:
    """定位本机 Android build-tools 的 aapt 或 aapt2，用于解析真实 APK 应用名。"""
    for name in ("aapt", "aapt2"):
        p = shutil.which(name)
        if p:
            return p
    sdk_roots = [
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
        os.path.expanduser("~/Library/Android/sdk"),
    ]
    for root in sdk_roots:
        if not root:
            continue
        for name in ("aapt", "aapt2"):
            hits = sorted(glob.glob(os.path.join(root, "build-tools", "*", name)), reverse=True)
            if hits:
                return hits[0]
    return ""


def _label_cache_path() -> str:
    """应用名磁盘缓存路径，避免每次打开重复解压 APK 清单。"""
    return os.path.join(_settings_dir(), "app_labels.json")


def _ensure_label_cache_loaded() -> None:
    """首次访问时从本地磁盘加载已缓存的 (serial, package) -> 应用名映射。"""
    global _LABEL_CACHE_LOADED
    with _LABEL_LOCK:
        if _LABEL_CACHE_LOADED:
            return
        _LABEL_CACHE_LOADED = True
        path = _label_cache_path()
        if not os.path.isfile(path):
            return
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                for k, v in raw.items():
                    if isinstance(k, str) and "|" in k and isinstance(v, str) and v.strip():
                        ser, pkg = k.split("|", 1)
                        _LABEL_CACHE[(ser, pkg)] = v.strip()
        except Exception:                                 # noqa: BLE001
            pass


def _persist_label_cache() -> None:
    """将内存中的应用名缓存原子写回磁盘。"""
    path = _label_cache_path()
    with _LABEL_LOCK:
        snap = {f"{s}|{p}": v for (s, p), v in _LABEL_CACHE.items() if v}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:                                     # noqa: BLE001
        pass


def resolve_app_label(serial: str, package: str, persist: bool = True) -> str:
    """快速读取真机上指定 App 的真实显示名称（仅提取 Manifest+resources.arsc，不拉整包 APK）。"""
    pkg = validate_package(package)
    ser = pick_serial(serial)
    _ensure_label_cache_loaded()
    cache_key = (ser, pkg)
    with _LABEL_LOCK:
        cached = _LABEL_CACHE.get(cache_key)
    if cached:
        return cached

    aapt = _find_aapt()
    if not aapt:
        return ""
    adb_bin = resolve_adb()
    try:
        path_out = Adb(ser)._cmd("shell", "pm", "path", pkg, check=False, timeout=8) or ""
        apks = [
            ln.split(":", 1)[1].strip()
            for ln in path_out.splitlines()
            if ln.strip().startswith("package:")
        ]
        if not apks:
            return ""
        base_apk = next((p for p in apks if p.endswith("/base.apk")), apks[0])

        # 只在设备端解压 AndroidManifest.xml 与 resources.arsc（通常 < 1MB，百兆游戏也只需 ~0.5 秒）
        r_m = subprocess.run(
            [adb_bin, "-s", ser, "exec-out", "unzip", "-p", base_apk, "AndroidManifest.xml"],
            capture_output=True, timeout=10,
        )
        r_r = subprocess.run(
            [adb_bin, "-s", ser, "exec-out", "unzip", "-p", base_apk, "resources.arsc"],
            capture_output=True, timeout=12,
        )
        if r_m.returncode != 0 or not r_m.stdout:
            return ""

        with tempfile.TemporaryDirectory() as td:
            mini = os.path.join(td, "mini.apk")
            with zipfile.ZipFile(mini, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("AndroidManifest.xml", r_m.stdout)
                if r_r.returncode == 0 and r_r.stdout:
                    zf.writestr("resources.arsc", r_r.stdout)
            r_dump = subprocess.run(
                [aapt, "dump", "badging", mini],
                capture_output=True, text=True, timeout=10,
            )
            labels: dict[str, str] = {}
            for ln in (r_dump.stdout or "").splitlines():
                m = re.match(r"^(application-label(?:-[A-Za-z0-9_-]+)?):'(.*)'$", ln.strip())
                if m and m.group(2).strip():
                    labels[m.group(1)] = m.group(2).strip()
            picked = (
                labels.get("application-label-zh-CN")
                or labels.get("application-label-zh_CN")
                or labels.get("application-label-zh")
                or labels.get("application-label")
                or next(iter(labels.values()), "")
            )
            if picked:
                with _LABEL_LOCK:
                    _LABEL_CACHE[cache_key] = picked
                if persist:
                    _persist_label_cache()
            return picked
    except Exception:                                     # noqa: BLE001
        return ""


def resolve_app_labels_batch(serial: str, packages: list[str]) -> dict[str, str]:
    """多线程并发读取一批包名的真实显示名称，并统一落盘缓存。"""
    ser = pick_serial(serial)
    _ensure_label_cache_loaded()
    clean = [validate_package(p) for p in (packages or []) if str(p or "").strip() and _PKG_RE.match(str(p).strip())]
    if not clean:
        return {}
    out: dict[str, str] = {}
    todo: list[str] = []
    with _LABEL_LOCK:
        for p in clean:
            v = _LABEL_CACHE.get((ser, p))
            if v:
                out[p] = v
            else:
                todo.append(p)
    if todo:
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(resolve_app_label, ser, p, False): p for p in todo[:40]}
            changed = False
            for fut, p in futs.items():
                try:
                    lbl = fut.result()
                except Exception:                         # noqa: BLE001
                    lbl = ""
                if lbl:
                    out[p] = lbl
                    changed = True
            if changed:
                _persist_label_cache()
    return out


def _resolve_target_package(target: str) -> str:
    """支持传入包名或已保存常用 App 名称，统一解析为合法 Android 包名。"""
    raw = str(target or "").strip()
    if raw and _PKG_RE.match(raw):
        return raw
    cfg = load_settings()
    if raw:
        low = raw.lower()
        for it in cfg.get("favorite_apps", []):
            if it.get("name", "").strip().lower() == low:
                return validate_package(it["package"])
    fallback = cfg.get("reset_package", "")
    if fallback:
        return validate_package(fallback)
    return validate_package(raw)


def list_online_devices(include_packages_for: str = "") -> dict[str, Any]:
    """列出所有已连接设备真实信息（机型、Root 状态、前台包名与名称），可选附带第三方已安装包。"""
    try:
        adb_bin = resolve_adb()
    except DynError as exc:
        return {"ok": False, "code": exc.code, "error": exc.message, "devices": [], "host_ip": detect_host_ip()}

    items: list[dict[str, Any]] = []
    for d in Adb.list_devices():
        row: dict[str, Any] = {
            "serial": d.serial,
            "state": d.state,
            "model": "",
            "root": False,
            "foreground": "",
            "foreground_label": "",
        }
        if d.state == "device":
            adb = Adb(d.serial)
            row["model"] = adb.model()
            row["root"] = adb.is_root()
            fg = _foreground_of(adb)
            row["foreground"] = fg
            if fg:
                row["foreground_label"] = resolve_app_label(d.serial, fg)
        items.append(row)

    packages: list[str] = []
    installed_apps: list[dict[str, str]] = []
    if include_packages_for:
        try:
            _ensure_label_cache_loaded()
            ser = pick_serial(include_packages_for)
            raw = Adb(ser)._cmd("shell", "pm", "list", "packages", "-3", check=False, timeout=15) or ""
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("package:"):
                    pkg = line[len("package:"):].strip()
                    if _PKG_RE.match(pkg):
                        packages.append(pkg)
            packages.sort()
            with _LABEL_LOCK:
                installed_apps = [
                    {"package": p, "name": _LABEL_CACHE.get((ser, p), "")}
                    for p in packages
                ]
        except Exception:                                 # noqa: BLE001
            packages = []
            installed_apps = []

    return {
        "ok": True,
        "adb_path": adb_bin,
        "host_ip": detect_host_ip(),
        "devices": items,
        "packages": packages,
        "installed_apps": installed_apps,
    }


# ---------------------------------------------------------------- 功能 2：手机全局代理 + mitmproxy 系统证书


def _check_local_port_listener(port: int) -> str:
    """检查本机 TCP 端口监听进程（非阻塞、无 shell 拼接）。"""
    try:
        r = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{int(port)}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=4,
        )
        lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 2:
                return f"{parts[0]} pid={parts[1]}"
    except Exception:                                     # noqa: BLE001
        pass
    return ""


def _cert_subject_hash(cert_path: str) -> str:
    """用 openssl 计算 Android 系统证书目录要求的旧式 subject hash（8 位十六进制）。"""
    real = os.path.expanduser(cert_path or DEFAULT_CERT_PATH)
    if not os.path.isfile(real):
        raise DynError("CERT_NOT_FOUND", f"找不到证书文件：{real}（请先运行一次 mitmproxy 生成根证书）")
    r = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout", "-in", real],
        capture_output=True, text=True, timeout=10,
    )
    h = (r.stdout or "").strip()
    if r.returncode != 0 or not _HASH_RE.match(h):
        raise DynError("CERT_HASH_FAILED", f"解析证书 hash 失败：{r.stderr.strip() or h}")
    return h


def proxy_status(
    serial: str = "",
    port: int = 8080,
    cert_path: str = DEFAULT_CERT_PATH,
) -> dict[str, Any]:
    """读取手机代理键值、wlan0 IP、本机 IP、端口监听与 mitmproxy 系统证书状态。"""
    ser = pick_serial(serial)
    port_i = validate_port(port)
    adb = Adb(ser)

    keys: dict[str, str] = {}
    for k in PROXY_KEYS:
        val = (adb._cmd("shell", "settings", "get", "global", k, check=False, timeout=8) or "").replace("\r", "").strip()
        keys[k] = val

    # 判定代理是否处于开启状态
    hp = keys.get("http_proxy", "")
    gh = keys.get("global_http_proxy_host", "")
    gp = keys.get("global_http_proxy_port", "")
    enabled = bool(
        (hp and hp not in ("null", ":0"))
        or (gh and gh != "null" and gp and gp not in ("null", "0"))
    )
    active_proxy = hp if (hp and hp not in ("null", ":0")) else (f"{gh}:{gp}" if (gh and gh != "null" and gp and gp not in ("null", "0")) else "")

    # 手机 wlan0 IP
    wlan_raw = (adb._cmd("shell", "ip", "-f", "inet", "addr", "show", "wlan0", check=False, timeout=8) or "").replace("\r", "")
    m_ip = re.search(r"inet\s+([0-9./]+)", wlan_raw)
    phone_ip = m_ip.group(1) if m_ip else ""

    host_ip = detect_host_ip()
    listener = _check_local_port_listener(port_i)

    # 系统证书与 Magisk 模块状态
    expanded_cert = os.path.expanduser(cert_path or DEFAULT_CERT_PATH)
    cert_info: dict[str, Any] = {
        "src": expanded_cert,
        "exists": os.path.isfile(expanded_cert),
        "hash": "",
        "installed": False,
        "magisk_module": False,
        "error": "",
    }
    if cert_info["exists"]:
        try:
            h = _cert_subject_hash(expanded_cert)
            cert_info["hash"] = h
            chk_sys = (adb._cmd("shell", "ls", f"{SYS_CACERTS}/{h}.0", check=False, timeout=8) or "").strip()
            cert_info["installed"] = bool(chk_sys and "No such file" not in chk_sys)
            chk_mod = (adb.su_shell(f"ls -d {shlex.quote(MODULE_DIR)} 2>/dev/null", check=False, timeout=8) or "").strip()
            chk_rm = (adb.su_shell(f"ls {shlex.quote(MODULE_DIR + '/remove')} 2>/dev/null", check=False, timeout=8) or "").strip()
            cert_info["magisk_module"] = bool(chk_mod and "No such file" not in chk_mod and not chk_rm)
        except Exception as exc:                          # noqa: BLE001
            cert_info["error"] = str(exc)

    return {
        "ok": True,
        "serial": ser,
        "enabled": enabled,
        "active_proxy": active_proxy,
        "keys": keys,
        "phone_ip": phone_ip,
        "host_ip": host_ip,
        "port": port_i,
        "port_listening": bool(listener),
        "port_listener": listener,
        "cert": cert_info,
    }


def proxy_set(
    serial: str = "",
    enable: bool = True,
    host: str = "",
    port: int = 8080,
    cert_path: str = DEFAULT_CERT_PATH,
) -> dict[str, Any]:
    """开启或关闭手机系统全局代理，返回最新完整状态。"""
    ser = pick_serial(serial)
    port_i = validate_port(port)
    adb = Adb(ser)

    if enable:
        ip = str(host or "").strip() or detect_host_ip()
        if not ip:
            raise DynError("HOST_IP_NOT_FOUND", "无法自动检测本机局域网 IP，请在设置中手动填写代理 IP")
        ip = validate_ip(ip)
        adb._cmd("shell", "settings", "put", "global", "http_proxy", f"{ip}:{port_i}")
        adb._cmd("shell", "settings", "put", "global", "global_http_proxy_host", ip)
        adb._cmd("shell", "settings", "put", "global", "global_http_proxy_port", str(port_i))
        adb._cmd("shell", "settings", "put", "global", "global_http_proxy_exclusion_list", '""')
        msg = f"已开启手机全局代理 → {ip}:{port_i}"
    else:
        adb._cmd("shell", "settings", "put", "global", "http_proxy", ":0")
        for k in ("global_http_proxy_host", "global_http_proxy_port", "global_http_proxy_exclusion_list"):
            adb._cmd("shell", "settings", "delete", "global", k, check=False)
        msg = "已清除手机全局代理，恢复直连"

    st = proxy_status(serial=ser, port=port_i, cert_path=cert_path)
    st["message"] = msg
    return st


def proxy_cert_install(
    serial: str = "",
    cert_path: str = DEFAULT_CERT_PATH,
    port: int = 8080,
) -> dict[str, Any]:
    """把 mitmproxy 根证书装成手机系统证书（Magisk 持久化 + tmpfs 即时生效免重启）。

    (1) 第一次修改（2026-11-27）
    bug 原因：原 shell 脚本在 post-fs-data.sh 中已将 SELinux 上下文修正为
              u:object_r:system_security_cacerts_file:s0，但免重启即时安装路径仍误用
              u:object_r:system_file:s0，导致部分 Android 13+ 系统在重启前不认该证书。
    解决方案：Magisk 模块目录与实时挂载写入处统一使用 u:object_r:system_security_cacerts_file:s0。
    """
    ser = pick_serial(serial)
    adb = Adb(ser)
    if not adb.is_root():
        raise DynError("NO_ROOT", "安装系统证书需要设备 Root（Magisk su）权限")

    real_cert = os.path.expanduser(cert_path or DEFAULT_CERT_PATH)
    h = _cert_subject_hash(real_cert)
    tmp_cert = f"/data/local/tmp/{h}.0"
    tmp_prop = "/data/local/tmp/mda_mitm_module.prop"
    tmp_post = "/data/local/tmp/mda_mitm_post.sh"

    # 1) 推送证书到临时路径（使用标准 adb push 避免 shell 转义问题）
    adb._cmd("push", real_cert, tmp_cert, timeout=20)

    # 2) 写 Magisk 模块元数据与 post-fs-data.sh（重启后持续生效）
    prop_text = (
        f"id={MODULE_ID}\n"
        "name=mitmproxy CA Certificate\n"
        "version=v1.0\n"
        "versionCode=1\n"
        "author=local\n"
        "description=Inject mitmproxy CA into system CA store for HTTPS capture.\n"
    )
    post_text = (
        "#!/system/bin/sh\n"
        "MODDIR=${0%/*}\n"
        "chown -R 0:0 ${MODDIR}/system/etc/security/cacerts\n"
        "chmod 644 ${MODDIR}/system/etc/security/cacerts/*\n"
        "chcon -R u:object_r:system_security_cacerts_file:s0 ${MODDIR}/system/etc/security/cacerts\n"
    )
    adb_bin = resolve_adb()
    for content, dst in ((prop_text, tmp_prop), (post_text, tmp_post)):
        r = subprocess.run(
            [adb_bin, "-s", ser, "shell", f"cat > {shlex.quote(dst)}"],
            input=content, text=True, capture_output=True, timeout=15,
        )
        if r.returncode != 0:
            raise DynError("ADB_WRITE_FAILED", f"写入 {dst} 失败：{r.stderr.strip()}")

    # 3) 构建 Magisk 模块并清除可能残留的 remove 标记
    se_ctx = "u:object_r:system_security_cacerts_file:s0"
    setup_cmd = " && ".join([
        f"mkdir -p {MODULE_DIR}/system/etc/security/cacerts",
        f"rm -f {MODULE_DIR}/remove",
        f"cp -f {tmp_cert} {MODULE_DIR}/system/etc/security/cacerts/{h}.0",
        f"mv -f {tmp_prop} {MODULE_DIR}/module.prop",
        f"mv -f {tmp_post} {MODULE_DIR}/post-fs-data.sh",
        f"chmod 755 {MODULE_DIR}/post-fs-data.sh",
        f"chown -R 0:0 {MODULE_DIR}",
        f"chmod 644 {MODULE_DIR}/system/etc/security/cacerts/{h}.0",
        f"chcon -R {se_ctx} {MODULE_DIR}/system/etc/security/cacerts",
    ])
    adb.su_shell(setup_cmd, timeout=25)

    # 4) 即时写入当前 cacerts 挂载点（尽量做到免重启当场生效）
    live_cmd = (
        f"mount -o remount,rw {SYS_CACERTS} 2>/dev/null || true; "
        f"cp -f {tmp_cert} {SYS_CACERTS}/{h}.0 && "
        f"chown 0:0 {SYS_CACERTS}/{h}.0 && "
        f"chmod 644 {SYS_CACERTS}/{h}.0 && "
        f"(chcon {se_ctx} {SYS_CACERTS}/{h}.0 2>/dev/null || true); "
        f"mount -o remount,ro {SYS_CACERTS} 2>/dev/null || true; "
        f"rm -f {tmp_cert}"
    )
    adb.su_shell(live_cmd, check=False, timeout=25)

    st = proxy_status(serial=ser, port=port, cert_path=real_cert)
    if st["cert"].get("installed"):
        st["message"] = (
            f"系统证书 {h}.0 已安装并即时生效，Magisk 模块 {MODULE_ID} 已就绪（重启保留）。"
            "提示：已在运行的 App 若缓存了旧证书列表，强制停止后重开即可。"
        )
    elif st["cert"].get("magisk_module"):
        st["message"] = (
            f"Magisk 模块 {MODULE_ID}（{h}.0）已写入，但当前只读 {SYS_CACERTS} 未支持直接重挂，"
            "重启手机后系统证书即可生效。"
        )
    else:
        st["ok"] = False
        st["error"] = f"证书写入 {SYS_CACERTS} 失败，请检查 Root 授权或分区只读状态"
    return st


def proxy_cert_remove(
    serial: str = "",
    cert_path: str = DEFAULT_CERT_PATH,
    port: int = 8080,
) -> dict[str, Any]:
    """移除已安装的 mitmproxy 系统证书并标记卸载 Magisk 模块。"""
    ser = pick_serial(serial)
    adb = Adb(ser)
    if not adb.is_root():
        raise DynError("NO_ROOT", "移除系统证书需要设备 Root（Magisk su）权限")

    real_cert = os.path.expanduser(cert_path or DEFAULT_CERT_PATH)
    h = _cert_subject_hash(real_cert)
    rm_cmd = (
        f"mount -o remount,rw {SYS_CACERTS} 2>/dev/null || true; "
        f"rm -f {SYS_CACERTS}/{h}.0; "
        f"mount -o remount,ro {SYS_CACERTS} 2>/dev/null || true; "
        f"[ -d {MODULE_DIR} ] && touch {MODULE_DIR}/remove || true"
    )
    adb.su_shell(rm_cmd, check=False, timeout=20)

    st = proxy_status(serial=ser, port=port, cert_path=real_cert)
    st["message"] = f"系统证书 {h}.0 已移除；Magisk 模块 {MODULE_ID} 已标记待卸载（重启后彻底清除）"
    return st


# ---------------------------------------------------------------- 功能 3：App 冻结 / 解冻（pm suspend）


def _is_pkg_suspended(adb: Adb, pkg: str) -> bool:
    """读取 dumpsys package 判断指定包当前是否处于 suspended=true。"""
    out = (adb._cmd("shell", "dumpsys", "package", pkg, check=False, timeout=12) or "").replace("\r", "")
    return "suspended=true" in out


def app_suspend_action(
    serial: str = "",
    action: str = "status",
    packages: list[str] | None = None,
) -> dict[str, Any]:
    """执行 App 冻结（pm suspend）、解冻（pm unsuspend）或状态查询。"""
    act = str(action or "status").strip().lower()
    alias = {"suspend": "freeze", "unsuspend": "unfreeze"}
    act = alias.get(act, act)
    if act not in ("freeze", "unfreeze", "status"):
        raise ValueError(f"不支持的操作：{action!r}（仅支持 freeze / unfreeze / status）")

    cfg = load_settings()
    if packages:
        pkgs = [_resolve_target_package(p) for p in packages]
    else:
        favs = cfg.get("favorite_apps", [])
        pkgs = [it["package"] for it in favs] if favs else cfg.get("suspend_packages", [])
    if not pkgs:
        raise ValueError("未提供任何包名，请传入 packages 或先在设置页添加常用 App")

    ser = pick_serial(serial)
    adb = Adb(ser)
    results: list[dict[str, Any]] = []

    for pkg in pkgs:
        out_text = ""
        if act == "freeze":
            out_text = (adb._cmd("shell", "pm", "suspend", pkg, check=False, timeout=15) or "").replace("\r", "").strip()
        elif act == "unfreeze":
            out_text = (adb._cmd("shell", "pm", "unsuspend", pkg, check=False, timeout=15) or "").replace("\r", "").strip()
        susp = _is_pkg_suspended(adb, pkg)
        ok_item = (susp is True) if act == "freeze" else ((susp is False) if act == "unfreeze" else True)
        results.append({
            "package": pkg,
            "suspended": susp,
            "ok": ok_item,
            "output": out_text,
        })

    all_ok = all(r["ok"] for r in results)
    verb = {"freeze": "冻结", "unfreeze": "解冻", "status": "状态查询"}[act]
    return {
        "ok": all_ok,
        "serial": ser,
        "action": act,
        "items": results,
        "message": f"{verb}完成（共 {len(results)} 个包，成功 {sum(1 for r in results if r['ok'])} 个）",
    }


# ---------------------------------------------------------------- 功能 4：强制停止 + 清理数据 + 重启


def app_reset(
    serial: str = "",
    package: str = "",
    clear_data: bool = True,
    relaunch: bool = True,
    wait_sec: float = 2.0,
) -> dict[str, Any]:
    """强制停止 App，可选以 Root 清理应用数据并在延时后重新启动（支持传包名或常用 App 名称）。"""
    pkg = _resolve_target_package(package)
    try:
        wait = max(0.0, min(15.0, float(wait_sec)))
    except (TypeError, ValueError) as exc:
        raise ValueError("wait_sec 必须是数字") from exc

    ser = pick_serial(serial)
    adb = Adb(ser)

    # 1) 强制停止
    adb._cmd("shell", "am", "force-stop", pkg, timeout=15)
    stopped = True

    # 2) 可选清理应用数据（优先 su pm clear，无 root 回退 shell pm clear）
    cleared = False
    clear_out = ""
    if clear_data:
        if adb.is_root():
            clear_out = (adb.su_shell(f"pm clear {shlex.quote(pkg)}", check=False, timeout=20) or "").replace("\r", "").strip()
        else:
            clear_out = (adb._cmd("shell", "pm", "clear", pkg, check=False, timeout=20) or "").replace("\r", "").strip()
        cleared = "Success" in clear_out

    # 3) 可选等待并重新拉起
    relaunched = False
    pid = 0
    if relaunch:
        if wait > 0:
            time.sleep(wait)
        adb._cmd(
            "shell", "monkey", "-p", pkg,
            "-c", "android.intent.category.LAUNCHER", "1",
            check=False, timeout=20,
        )
        time.sleep(1.2)
        pid = adb.find_app_pid(pkg)
        relaunched = pid > 0

    parts = [f"已强制停止 {pkg}"]
    if clear_data:
        parts.append("数据已清理" if cleared else f"清数据返回：{clear_out or '未确认 Success'}")
    if relaunch:
        parts.append(f"已重启（pid {pid}）" if relaunched else "已发送启动指令（未检测到新进程）")

    return {
        "ok": stopped and (not clear_data or cleared),
        "serial": ser,
        "package": pkg,
        "stopped": stopped,
        "cleared": cleared,
        "clear_output": clear_out,
        "relaunched": relaunched,
        "pid": pid,
        "message": "；".join(parts),
    }
