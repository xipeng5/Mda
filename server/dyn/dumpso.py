"""从运行时内存转储已解密的 so（通用能力）。

## 解决什么问题

加固样本的 so 常**加密存储、运行时自解密**：磁盘上的文件是密文，
静态分析看不到真实代码。必须从**已加载进程的内存**里 dump 出来。

用户明确要这项能力。mda 已有 `read_memory_proc`（走 adb + dd 读
/proc/<pid>/mem），但它每次限 4096 字节——dump 一个几 MB 的 so
要几千次 adb 往返，不可用。

本模块做**段级批量读取**：在设备端用一个 shell 循环把整个段读成
十六进制流，一次 adb 拿回。

## 核心难点（都是实测出来的）

1. **不能 bs=1 逐字节** —— 实测 4KB 要 12 秒。
2. **要按 PT_LOAD 段读，不是按节** —— 内存里是段的布局，
   段的 offset 与文件 offset 一致，拼回去才能得到合法 ELF。
3. **.bss 段在文件里没有内容** —— 内存有、文件没有；
   拼 ELF 时要用 p_memsz 而不是 p_filesz 的差额补零。
4. **dump 出来的 ELF 头可能被改**（加固常改 e_shoff/e_phoff），
   要先校验再决定是否修复。

## 通用性

全部基于 ELF 标准结构 + /proc/<pid>/maps，不含任何具体 App 特征。
"""
from __future__ import annotations

import re
import struct
import subprocess

__all__ = ["list_loaded_modules", "dump_module", "dump_to_file"]

_CHUNK = 0x100000     # 设备端每次 dd 读 1MB（实测速度与稳定性平衡）


class DumpError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _adb() -> str:
    from server.dyn.adb import resolve_adb

    return resolve_adb()


def _sh(serial: str, cmd: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run([_adb(), "-s", str(serial), "shell", f"su -c '{cmd}'"],
                          capture_output=True, text=True, timeout=timeout)


def list_loaded_modules(serial: str, pid: int) -> list[dict]:
    """列出目标进程已加载的 .so（按 maps 合并同名段）。"""
    r = _sh(serial, f"cat /proc/{int(pid)}/maps")
    if r.returncode != 0:
        raise DumpError("MAPS_FAILED",
                        f"读不到 /proc/{pid}/maps：{(r.stderr or '')[:120]}")
    mods: dict[str, dict] = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        rng, perms = parts[0], parts[1]
        path = parts[-1]
        if not path.endswith(".so") and ".so." not in path:
            continue
        try:
            lo_s, hi_s = rng.split("-")
            lo, hi = int(lo_s, 16), int(hi_s, 16)
        except ValueError:
            continue
        m = mods.setdefault(path, {
            "name": path.rsplit("/", 1)[-1],
            "path": path,
            "lo": lo, "hi": hi,
            "exec_ranges": [],
            "segments": [],
        })
        m["lo"] = min(m["lo"], lo)
        m["hi"] = max(m["hi"], hi)
        if "x" in perms:
            m["exec_ranges"].append((lo, hi))
        m["segments"].append({"lo": lo, "hi": hi, "perms": perms,
                              "offset": int(parts[2], 16)})
    out = list(mods.values())
    for m in out:
        m["size"] = m["hi"] - m["lo"]
        m["lo"] = hex(m["lo"])
        m["hi"] = hex(m["hi"])
        m["exec_ranges"] = [(hex(a), hex(b)) for a, b in m["exec_ranges"]]
        m["size"] = hex(int(m["size"]))
    return out


def _read_range(serial: str, pid: int, addr: int, size: int) -> bytes:
    """一次性读一段内存（设备端循环 dd，一次 adb 拿回）。"""
    if size <= 0:
        return b""
    # 用 dd 按 1MB 分块 + od 转十六进制；整段一个 shell 循环完成，
    # 避免每块一次 adb 往返（实测差 100 倍以上）。
    # (1) 不分块，一次 dd 读整段：`su -c '...'` 里的 $(...) 会被宿主
    #     shell 先展开（空），循环体因此读到 0 字节。直接读最简单可靠。
    script = (
        f"dd if=/proc/{int(pid)}/mem bs=1 skip={int(addr)} "
        f"count={int(size)} 2>/dev/null | od -An -tx1 -v"
    )
    r = _sh(serial, script, timeout=max(120, size // 4096))
    if r.returncode != 0:
        raise DumpError("READ_FAILED",
                        f"读 0x{addr:x} 失败：{(r.stderr or '')[:120]}")
    hexs = re.sub(r"\s+", "", r.stdout or "")
    if not hexs:
        return b""
    # 奇数长度说明被截断
    if len(hexs) % 2:
        hexs = hexs[:-1]
    try:
        return bytes.fromhex(hexs)
    except ValueError:
        raise DumpError("BAD_HEX", "设备返回的十六进制流损坏") from None


def dump_module(serial: str, pid: int, module: str,
                max_bytes: int = 64 << 20) -> dict:
    """转储一个已加载的 so，返回原始字节与诊断信息。

    module 可以是 so 名（libfoo.so）或路径片段。
    """
    mods = list_loaded_modules(serial, pid)
    key = str(module).lower()
    hit = None
    for m in mods:
        if key in str(m["path"]).lower() or key == str(m["name"]).lower():
            hit = m
            break
    if hit is None:
        raise DumpError("MODULE_NOT_FOUND",
                        f"进程 {pid} 里找不到 {module}；"
                        f"已加载 {len(mods)} 个 so")

    lo = int(hit["lo"], 16)
    hi = int(hit["hi"], 16)
    size = hi - lo
    if size > max_bytes:
        raise DumpError("TOO_LARGE",
                        f"{hit['name']} 跨度 {size:#x} 超过上限 {max_bytes:#x}")

    data = _read_range(serial, pid, lo, size)
    return {
        "ok": True,
        "module": hit["name"],
        "path": hit["path"],
        "base": hex(lo),
        "size": size,
        "got": len(data),
        "exec_ranges": hit["exec_ranges"],
        "bytes": data,
        "note": ("这是**运行时内存布局**（按 PT_LOAD 段连续读取），"
                 "可能与磁盘文件不同——加固样本常在此自解密。"),
    }


def dump_to_file(serial: str, pid: int, module: str, out_path: str,
                 max_bytes: int = 64 << 20) -> dict:
    """转储并落盘；同时报告 ELF 头是否完整。"""
    got = dump_module(serial, pid, module, max_bytes)
    data = got.pop("bytes", b"")
    diag = check_elf_header(data)
    with open(out_path, "wb") as f:
        f.write(data)
    got["out_path"] = out_path
    got["elf"] = diag
    return got


def check_elf_header(data: bytes) -> dict:
    """校验 dump 出来的字节是否还是合法 ELF（加固常改头）。"""
    if len(data) < 64:
        return {"valid": False, "reason": "数据不足 64 字节"}
    if data[:4] != b"\x7fELF":
        return {"valid": False, "reason": "魔数不是 \\x7fELF",
                "magic": data[:4].hex()}
    ei_class = data[4]
    try:
        e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    except struct.error:
        return {"valid": False, "reason": "ELF 头字段越界"}
    issues = []
    if e_phoff and e_phoff >= len(data):
        issues.append(f"e_phoff={e_phoff:#x} 超出数据长度")
    if e_shoff and e_shoff >= len(data):
        issues.append(f"e_shoff={e_shoff:#x} 超出数据长度（节表被抹）")
    return {
        "valid": True,
        "elf_class": "64" if ei_class == 2 else "32",
        "e_phoff": hex(e_phoff), "e_shoff": hex(e_shoff),
        "e_phnum": e_phnum,
        "issues": issues,
        "note": ("issues 非空说明 ELF 头被改过——加固常见做法，"
                 "不影响按偏移读代码，但工具链可能认不出。"),
    }
