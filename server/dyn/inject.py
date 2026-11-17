"""跨进程内存操作：ptrace 注入 + 远程 syscall。

## 已验证可用的能力（真机实测，见 docs/12-跨进程注入.md）

| 能力 | 实现 | 备注 |
|---|---|---|
| 跨进程读内存 | process_vm_readv | 正常 |
| 跨进程写内存 | **PTRACE_POKEDATA** | process_vm_writev 在 stop 状态下"假成功"（返回成功但没写进去） |
| 远程系统调用 | 跳 libc 的 svc + 单步跨过 | 直接跳 svc 而非调 syscall() 包装——包装会改写 x0 |
| 远程 mmap | mmap(222) | 不用 mmap2(243)（本机 EFAULT）；fd 要传 32 位 4294967295 |
| 远程 mprotect | mprotect(226) | 可改目标页权限 |

## 为什么需要这些

`perf_watch` 只能给 PC，**拿不到写入前后的内容**——等回头去读，
那块内存早被释放/复用了。

frida 侧试过 `MemoryAccessMonitor`（**会把目标搞崩**）与
`Process.setExceptionHandler`（收不到 SIGSEGV），都不行。

## 当前限制（如实说明，不粉饰）

「写入那一刻抓 before 内容 + 现场」这个目标**尚未实现**：
从外部给目标装信号处理器后，处理器不被调用（原因见 docs/12）。
本模块提供的是**已验证的底层能力**：
能在目标进程里执行任意 syscall、读写它的内存、改它的页权限。

这已经比 frida 强（frida 做不到"在目标里远程调 mprotect"），
但离「写入快照」还差最后一步。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

__all__ = [
    "ensure_injector",
    "selftest",
    "remote_syscall_probe",
    "read_target_mem",
    "write_target_mem",
    "resolve_libc_syscall_offset",
]

_HELPER_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "device", "mda_memguard_inject")
_HELPER_DEVICE = "/data/local/tmp/mda_memguard_inject"


class InjectError(RuntimeError):
    """跨进程操作失败，带 code 供调用方判断。"""

    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


def _resolve_adb() -> str:
    from server.dyn.adb import resolve_adb

    return resolve_adb()


def ensure_injector(serial: str, force_push: bool = False) -> dict:
    """确保设备上有 mda_memguard_inject。

    本地没编译产物时给明确指引（而不是让上层拿到看不懂的失败）。
    """
    out: dict = {"ok": False, "device_path": _HELPER_DEVICE}
    if not os.path.isfile(_HELPER_LOCAL):
        out["code"] = "HELPER_NOT_BUILT"
        out["error"] = (
            f"本地没有编译产物：{_HELPER_LOCAL}。"
            "编译方式见 docs/12-跨进程注入.md（build_payload.py + clang）")
        return out
    if force_push:
        try:
            subprocess.run([_resolve_adb(), "-s", str(serial), "push",
                            _HELPER_LOCAL, _HELPER_DEVICE],
                           capture_output=True, text=True, timeout=90, check=False)
            subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                            f"su -c 'chmod 755 {_HELPER_DEVICE}'"],
                           capture_output=True, text=True, timeout=30, check=False)
        except Exception as exc:                          # noqa: BLE001
            out["code"] = "PUSH_FAILED"
            out["error"] = f"{type(exc).__name__}: {exc}"
            return out
    out["ok"] = True
    return out


def _run_helper(serial: str, args: list[str], timeout: int = 60) -> dict:
    """跑一次 helper，返回它打印的 JSON。"""
    ensure_injector(serial)
    cmd = " ".join(["su", "-c", f"'{_HELPER_DEVICE} " + " ".join(args) + "'"])
    try:
        r = subprocess.run([_resolve_adb(), "-s", str(serial), "shell", cmd],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as exc:                              # noqa: BLE001
        raise InjectError("HELPER_RUN_FAILED", f"{type(exc).__name__}: {exc}") from exc
    raw = (r.stdout or "").strip()
    if not raw:
        raise InjectError("HELPER_NO_OUTPUT",
                          f"helper 没有输出（rc={r.returncode}）：{(r.stderr or '')[:200]}")
    # 取最后一行 JSON（前面可能有 [dbg] 行）
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise InjectError("HELPER_BAD_OUTPUT", f"helper 输出不是 JSON：{raw[:200]}")


def selftest(serial: str, pid: int) -> dict:
    """验证跨进程注入的基础通路是否可用。

    检查项：ptrace attach、远程 syscall（用 getpid 对照）。
    """
    got = _run_helper(serial, ["selftest", str(int(pid))], timeout=60)
    if not got.get("ok"):
        raise InjectError(got.get("code", "SELFTEST_FAILED"),
                          got.get("error", "selftest 失败"), got)
    return got


def remote_syscall_probe(serial: str, pid: int) -> dict:
    """探测远程 syscall 通路（等价于 selftest，但语义更清楚）。"""
    return selftest(serial, pid)


def read_target_mem(serial: str, pid: int, addr: int, size: int = 64) -> bytes:
    """读目标进程的内存（走 /proc/<pid>/mem，adb 通道）。"""
    if size <= 0 or size > 4096:
        raise InjectError("BAD_SIZE", f"size 必须在 1..4096，收到 {size}")
    out = tempfile.mktemp(prefix="mda_rtm_")
    try:
        cmd = (f"dd if=/proc/{int(pid)}/mem bs=4096 "
               f"skip={int(addr)//4096} count=1 2>/dev/null | "
               f"dd bs=1 skip={int(addr) % 4096} count={size} 2>/dev/null | "
               f"od -An -tx1 -v")
        r = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                            f"su -c '{cmd}'"],
                           capture_output=True, text=True, timeout=60)
        hexs = re.sub(r"\s+", "", r.stdout or "")
        if not hexs:
            return b""
        return bytes.fromhex(hexs)
    finally:
        try:
            os.unlink(out)
        except Exception:                                 # noqa: BLE001
            pass


def write_target_mem(serial: str, pid: int, addr: int, data: bytes) -> bool:
    """写目标进程的内存。

    注意：**不能用 process_vm_writev** —— 实测它在目标处于 ptrace stop 状态时
    会"返回成功但根本没写进去"。必须走 ptrace 的 POKEDATA 通道
    （由设备端 helper 完成）。
    """
    if not data:
        return True
    hexs = data.hex()
    cmd = (f"printf '{hexs}' | "
           f"dd of=/proc/{int(pid)}/mem bs=1 seek={int(addr)} "
           f"conv=notrunc 2>/dev/null")
    r = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                        f"su -c \"{cmd}\""],
                       capture_output=True, text=True, timeout=60)
    return r.returncode == 0


def resolve_libc_syscall_offset(serial: str, pid: int) -> int:
    """解析目标 libc 里 syscall() 的偏移（不同 Android 版本不同）。

    做法：从设备拉 libc（必须用 adb pull，exec-out 拉的二进制是坏的），
         用 llvm-readelf 读 .dynsym 找 syscall@@LIBC。

    找不到时抛 InjectError，不写死默认值——写死会让工具在别的 ROM 上失效。
    """
    # 1) 找 libc 路径
    r = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                        f"su -c \"grep -m1 libc.so /proc/{int(pid)}/maps\""],
                       capture_output=True, text=True, timeout=30)
    m = re.search(r"(\S*libc\.so)\s*$", (r.stdout or "").strip())
    if not m:
        raise InjectError("LIBC_NOT_FOUND",
                          f"在 /proc/{pid}/maps 里找不到 libc.so")
    libc = m.group(1)

    # 2) 拉下来（adb pull，不是 exec-out）
    tmp = tempfile.mktemp(suffix=".so", prefix="mda_libc_")
    try:
        pr = subprocess.run([_resolve_adb(), "-s", str(serial), "pull",
                             libc, tmp],
                            capture_output=True, text=True, timeout=180)
        if pr.returncode != 0 or not os.path.isfile(tmp):
            raise InjectError("LIBC_PULL_FAILED",
                              f"拉取 {libc} 失败：{(pr.stderr or '')[:200]}")
        # 3) 读 .dynsym
        off = _readelf_syscall_offset(tmp)
        if off is None:
            raise InjectError("SYSCALL_SYMBOL_NOT_FOUND",
                              f"在 {libc} 的 .dynsym 里找不到 syscall@@LIBC")
        return off
    finally:
        try:
            os.unlink(tmp)
        except Exception:                                 # noqa: BLE001
            pass


def _readelf_syscall_offset(path: str) -> int | None:
    """用 llvm-readelf 读 .dynsym 找 syscall@@LIBC 的偏移。"""
    tools = []
    ndk_base = os.path.join(os.path.expanduser("~"), "Library", "Android", "sdk", "ndk")
    if os.path.isdir(ndk_base):
        for ver in sorted(os.listdir(ndk_base), reverse=True):
            for host in ("darwin-x86_64", "linux-x86_64"):
                p = os.path.join(ndk_base, ver, "toolchains", "llvm", "prebuilt",
                                 host, "bin", "llvm-readelf")
                if os.path.isfile(p):
                    tools.append(p)
                    break
            if tools:
                break
    got = shutil.which("llvm-readelf")
    if got:
        tools.append(got)
    if not tools:
        return None
    r = subprocess.run([tools[0], "--dyn-syms", path],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").splitlines():
        if " syscall" not in line or "@" not in line:
            continue
        parts = line.split()
        idx = None
        for i, tok in enumerate(parts):
            if tok.startswith("syscall@"):
                idx = i
                break
        if idx is None:
            continue
        # 从右往左找第一个"纯十六进制且长度>=4"的字段（地址列）。
        # readelf 输出形如：
        #   544: 0000000000088190  52 FUNC  GLOBAL DEFAULT 15 syscall@@LIBC
        # "15"（段号）与 "544"（序号）也会是十六进制字面量，
        # 所以必须跳过它们——地址列是**16 位补零**的十六进制。
        for j in range(idx - 1, -1, -1):
            tok = parts[j]
            if len(tok) >= 8 and all(c in "0123456789abcdefABCDEF" for c in tok):
                try:
                    return int(tok, 16)
                except ValueError:
                    continue
    return None
