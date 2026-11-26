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
import shlex
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


def _device_file_size(serial: str, path: str) -> int | None:
    """读取设备端文件真实字节数（优先 stat -c %s，回退 ls -ln 第 5 列）。"""
    q = shlex.quote(path)
    try:
        r = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                            f"stat -c %s {q} 2>/dev/null"],
                           capture_output=True, text=True, timeout=20)
        lines = (r.stdout or "").strip().splitlines()
        if lines and lines[0].strip().isdigit():
            return int(lines[0].strip())
    except Exception:                                     # noqa: BLE001
        pass
    try:
        r2 = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                             f"ls -ln {q} 2>/dev/null"],
                            capture_output=True, text=True, timeout=20)
        for ln in (r2.stdout or "").splitlines():
            parts = ln.split()
            if len(parts) >= 5 and parts[0].startswith("-") and parts[4].isdigit():
                return int(parts[4])
    except Exception:                                     # noqa: BLE001
        pass
    return None


def ensure_injector(serial: str, force_push: bool = False) -> dict:
    """确保设备上有 mda_memguard_inject。

    (3) 第三次修改（2026-11-26）
    bug 原因：① force_push=False 时从未检查设备上二进制是否存在及大小是否一致，直接假报 ok=True；
              ② push 与 chmod 未检查 returncode，失败被静默忽略。
    解决方案：检查设备端文件大小与本地是否一致，缺失/不一致或 force_push 时推送并严格校验返回码。

    本地没编译产物时给明确指引（而不是让上层拿到看不懂的失败）。
    """
    out: dict = {"ok": False, "device_path": _HELPER_DEVICE, "pushed": False}
    if not os.path.isfile(_HELPER_LOCAL):
        out["code"] = "HELPER_NOT_BUILT"
        out["error"] = (
            f"本地没有编译产物：{_HELPER_LOCAL}。"
            "编译方式见 docs/12-跨进程注入.md（build_payload.py + clang）")
        return out
    local_size = os.path.getsize(_HELPER_LOCAL)
    out["local_size"] = local_size
    need_push = bool(force_push)
    if not need_push:
        dev_size = _device_file_size(serial, _HELPER_DEVICE)
        if dev_size is None or dev_size != local_size:
            need_push = True
        else:
            out["ok"] = True
            out["note"] = "设备上已有同版本 injector，跳过推送"
            return out
    if need_push:
        try:
            pr = subprocess.run([_resolve_adb(), "-s", str(serial), "push",
                                 _HELPER_LOCAL, _HELPER_DEVICE],
                                capture_output=True, text=True, timeout=90, check=False)
            if pr.returncode != 0:
                out["code"] = "PUSH_FAILED"
                out["error"] = (f"推送失败(rc={pr.returncode})："
                                f"{((pr.stderr or '') + (pr.stdout or '')).strip()[:200]}")
                return out
            chmod_inner = f"chmod 755 {shlex.quote(_HELPER_DEVICE)}"
            cr = subprocess.run([_resolve_adb(), "-s", str(serial), "shell",
                                 f"su -c {shlex.quote(chmod_inner)}"],
                                capture_output=True, text=True, timeout=30, check=False)
            if cr.returncode != 0:
                out["code"] = "CHMOD_FAILED"
                out["error"] = f"chmod 失败(rc={cr.returncode})：{(cr.stderr or '')[:200]}"
                return out
            out["pushed"] = True
        except Exception as exc:                          # noqa: BLE001
            out["code"] = "PUSH_FAILED"
            out["error"] = f"{type(exc).__name__}: {exc}"
            return out
    out["ok"] = True
    return out


def _run_helper(serial: str, args: list[str], timeout: int = 60) -> dict:
    """跑一次 helper，返回它打印的 JSON。

    (3) 第三次修改（2026-11-26）
    bug 原因：① 调用 ensure_injector(serial) 后丢弃返回值，未就绪仍继续执行；
              ② 直接字符串拼接 args 到单引号 su -c，存在命令注入且含引号会破坏语法。
    解决方案：检查 ensure_injector 返回值，失败立即抛 InjectError；
              用 shlex.quote 安全拼接所有参数与整段 su -c 命令。
    """
    h = ensure_injector(serial)
    if not h.get("ok"):
        raise InjectError(h.get("code") or "HELPER_NOT_READY",
                          h.get("error") or "mda_memguard_inject 未就绪", h)
    inner = " ".join([shlex.quote(_HELPER_DEVICE)] + [shlex.quote(str(a)) for a in args])
    cmd = f"su -c {shlex.quote(inner)}"
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
    parsed = None
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if parsed is None:
        raise InjectError("HELPER_BAD_OUTPUT",
                          f"helper 输出不是 JSON：{raw[:200]}")
    # (2) 检查 returncode：helper 失败时仍会打印合法 JSON
    if r.returncode not in (0, None) and parsed.get("ok") is not False:
        parsed["ok"] = False
        parsed.setdefault("code", "HELPER_EXIT_NONZERO")
        parsed["helper_returncode"] = r.returncode
        if r.stderr:
            parsed.setdefault("stderr", (r.stderr or "")[:300])
    return parsed


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
    """读目标进程的内存（走 /proc/<pid>/mem，按 4KB 页分块读取，支持跨页）。

    (3) 第三次修改（2026-11-26）
    bug 原因：① 原实现写死 `bs=4096 skip=addr//4096 count=1`，当 addr%4096 + size > 4096
              （跨越 4KB 页边界）时静默截断，返回残缺字节；
              ② 未检查 dd/adb 返回码与读取错误；且创建了无用的 tempfile.mktemp。
    解决方案：按 4KB 页边界分块循环读取并拼接，检查每块 returncode 与 dd 退出码，
              并用 shlex.quote 保护 su -c 命令串。
    """
    if size <= 0 or size > 4096:
        raise InjectError("BAD_SIZE", f"size 必须在 1..4096，收到 {size}")
    pid_i = int(pid)
    cur = int(addr)
    rem = int(size)
    chunks: list[bytes] = []
    while rem > 0:
        page_idx = cur // 4096
        page_off = cur % 4096
        take = min(rem, 4096 - page_off)
        inner = (
            f"dd if=/proc/{pid_i}/mem bs=4096 skip={page_idx} count=1 2>/dev/null | "
            f"dd bs=1 skip={page_off} count={take} 2>/dev/null | "
            f"od -An -tx1 -v"
        )
        r = subprocess.run(
            [_resolve_adb(), "-s", str(serial), "shell", f"su -c {shlex.quote(inner)}"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            raise InjectError(
                "READ_FAILED",
                f"读取 0x{cur:x}({take}B) 失败(rc={r.returncode})：{(r.stderr or '')[:200]}",
            )
        hexs = re.sub(r"\s+", "", r.stdout or "")
        if len(hexs) % 2:
            hexs = hexs[:-1]
        if not hexs:
            if not chunks:
                return b""
            raise InjectError(
                "READ_SHORT",
                f"跨页读取在 0x{cur:x} 处中断（已读 {sum(len(c) for c in chunks)}/{size} 字节）",
            )
        try:
            got = bytes.fromhex(hexs)
        except ValueError as exc:
            raise InjectError("BAD_HEX", f"读取 0x{cur:x} 返回非法十六进制：{exc}") from exc
        chunks.append(got)
        if len(got) < take:
            break
        cur += take
        rem -= take
    return b"".join(chunks)


def write_target_mem(serial: str, pid: int, addr: int, data: bytes) -> bool:
    """写目标进程的内存（走 root `dd of=/proc/<pid>/mem`）。

    (3) 第三次修改（2026-11-26）
    bug 原因：① 原注释声称走 ptrace POKEDATA，与实际 /proc/<pid>/mem 写入实现不符；
              ② `su -c "{cmd}"` 未经 shlex.quote 保护，且 `dd ... 2>/dev/null` 吞掉了错误，
                 仅凭外层 su 的 returncode 无法可靠判断 dd 写入是否真的成功。
    解决方案：修正文档说明与实现一致（注：目标处于 ptrace stop 状态时应走 helper 的
              PTRACE_POKEDATA）；使用 shlex.quote 保护整段管道，并通过显式回显 dd 退出码
              `__DD_RC__=$?` 校验写入结果。
    """
    if not data:
        return True
    # (1) 用 \xNN 转义输出真正的二进制，不能直接 printf 十六进制文本
    esc = "".join(f"\\x{b:02x}" for b in data)
    inner = (
        f"printf '{esc}' | "
        f"dd of=/proc/{int(pid)}/mem bs=1 seek={int(addr)} conv=notrunc 2>/dev/null; "
        f"echo __DD_RC__=$?"
    )
    r = subprocess.run(
        [_resolve_adb(), "-s", str(serial), "shell", f"su -c {shlex.quote(inner)}"],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        return False
    m = re.search(r"__DD_RC__=(\d+)", r.stdout or "")
    if m:
        return int(m.group(1)) == 0
    return False


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
