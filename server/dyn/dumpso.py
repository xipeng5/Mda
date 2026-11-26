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
import shlex
import struct
import subprocess

__all__ = ["list_loaded_modules", "dump_module", "dump_to_file"]

_CHUNK = 0x100000     # 设备端每次 dd 读 1MB（实测速度与稳定性平衡）
_PAGE_SIZE = 4096


class DumpError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _adb() -> str:
    from server.dyn.adb import resolve_adb

    return resolve_adb()


def _sh(serial: str, cmd: str, timeout: int = 180) -> subprocess.CompletedProcess:
    # (2) 第二次修改（2026-11-26）：用 shlex.quote 保护 su -c 参数，防止引号截断与注入
    return subprocess.run([_adb(), "-s", str(serial), "shell",
                           f"su -c {shlex.quote(cmd)}"],
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
    """按 4KB 页对齐分块读一段内存（bs=4096 批量读取，兼容头尾未对齐地址）。

    (2) 第二次修改（2026-11-26）
    bug 原因：原实现用 `bs=1 skip={addr} count={size}` 逐字节读（4KB 就要 12 秒，
              MB 级 so 必然超时），与文件顶部注释“不能 bs=1 逐字节”相违背。
    解决方案：将 [addr, addr+size) 向上下对齐到 4KB 页边界，按每次最多 256 页(1MB)
              用 `dd bs=4096` 分批读取，最后裁剪头尾未对齐部分返回精确字节。
    """
    if size <= 0:
        return b""
    pid_i = int(pid)
    addr_i = int(addr)
    size_i = int(size)
    aligned_start = (addr_i // _PAGE_SIZE) * _PAGE_SIZE
    lead = addr_i - aligned_start
    total_pages = (lead + size_i + _PAGE_SIZE - 1) // _PAGE_SIZE
    pages_per_batch = max(1, _CHUNK // _PAGE_SIZE)

    buf = bytearray()
    page_offset = 0
    while page_offset < total_pages:
        batch_pages = min(pages_per_batch, total_pages - page_offset)
        skip_pages = (aligned_start // _PAGE_SIZE) + page_offset
        script = (
            f"dd if=/proc/{pid_i}/mem bs={_PAGE_SIZE} skip={skip_pages} "
            f"count={batch_pages} 2>/dev/null | od -An -tx1 -v"
        )
        r = _sh(serial, script, timeout=max(60, batch_pages // 2))
        if r.returncode != 0:
            raise DumpError("READ_FAILED",
                            f"读 0x{aligned_start + page_offset * _PAGE_SIZE:x} 失败："
                            f"{(r.stderr or '')[:120]}")
        hexs = re.sub(r"\s+", "", r.stdout or "")
        if len(hexs) % 2:
            hexs = hexs[:-1]
        if not hexs:
            # 该批页不可读：补零保持偏移对齐，或若首批全空直接返回已读部分
            buf.extend(b"\x00" * (batch_pages * _PAGE_SIZE))
        else:
            try:
                chunk_bytes = bytes.fromhex(hexs)
            except ValueError:
                raise DumpError("BAD_HEX", "设备返回的十六进制流损坏") from None
            buf.extend(chunk_bytes)
            expected = batch_pages * _PAGE_SIZE
            if len(chunk_bytes) < expected:
                buf.extend(b"\x00" * (expected - len(chunk_bytes)))
        page_offset += batch_pages

    return bytes(buf[lead:lead + size_i])


def dump_module(serial: str, pid: int, module: str,
                max_bytes: int = 64 << 20) -> dict:
    """转储一个已加载的 so，返回原始字节与诊断信息。

    (2) 第二次修改（2026-11-26）
    bug 原因：原实现把模块首段 lo 到末段 hi 当成一整块连续内存一次性读取，
              遇到段间未映射空洞或不可读保护页（---p）时触发 EIO 导致转储截断。
    解决方案：按 /proc/<pid>/maps 中每个实际可读映射段分别读取并按相对偏移落位，
              段间未映射空洞和不可读页自动补零。

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

    buf = bytearray(size)
    segments = sorted(hit.get("segments") or [], key=lambda s: int(s["lo"]))
    bytes_read = 0
    segments_read = 0
    skipped_segments: list[dict] = []
    for seg in segments:
        seg_lo = int(seg["lo"])
        seg_hi = int(seg["hi"])
        perms = str(seg.get("perms") or "")
        seg_len = seg_hi - seg_lo
        rel = seg_lo - lo
        if seg_len <= 0 or rel < 0 or rel >= size:
            continue
        if "r" not in perms:
            skipped_segments.append({"lo": hex(seg_lo), "hi": hex(seg_hi),
                                     "perms": perms, "reason": "不可读保护段，已补零"})
            continue
        want = min(seg_len, size - rel)
        try:
            part = _read_range(serial, pid, seg_lo, want)
        except DumpError as exc:
            skipped_segments.append({"lo": hex(seg_lo), "hi": hex(seg_hi),
                                     "perms": perms, "reason": exc.message})
            continue
        buf[rel:rel + len(part)] = part
        bytes_read += len(part)
        segments_read += 1

    data = bytes(buf)
    out = {
        "ok": True,
        "module": hit["name"],
        "path": hit["path"],
        "base": hex(lo),
        "size": size,
        "got": len(data),
        "bytes_read": bytes_read,
        "segments_read": segments_read,
        "exec_ranges": hit["exec_ranges"],
        "bytes": data,
        "note": ("这是**运行时内存布局**（按 /proc/<pid>/maps 各实际映射段分别读取，段间空洞补零），"
                 "可能与磁盘文件不同——加固样本常在此自解密。"),
    }
    if skipped_segments:
        out["skipped_segments"] = skipped_segments
    return out


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
    """校验 dump 出来的字节是否还是合法 ELF（加固常改头）。

    (2) 第二次修改（2026-11-26）
    bug 原因：原实现无视 EI_CLASS，对 ELF32 也按 ELF64 偏移 0x20/0x28/0x38 解包，
              导致 32 位 so 的 e_phoff / e_shoff / e_phnum 全错且 52 字节头被误拒。
    解决方案：根据 EI_CLASS 分别按 ELF32（52B，偏移 0x1c/0x20/0x2c）与
              ELF64（64B，偏移 0x20/0x28/0x38）解析，并兼容字节序 EI_DATA。
    """
    if len(data) < 52:
        return {"valid": False, "reason": "数据不足 52 字节"}
    if data[:4] != b"\x7fELF":
        return {"valid": False, "reason": "魔数不是 \\x7fELF",
                "magic": data[:4].hex()}
    ei_class = data[4]
    endian = ">" if data[5] == 2 else "<"
    try:
        if ei_class == 2:
            if len(data) < 64:
                return {"valid": False, "reason": "ELF64 数据不足 64 字节"}
            e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
            cls_label = "64"
        elif ei_class == 1:
            e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x2C)[0]
            cls_label = "32"
        else:
            return {"valid": False, "reason": f"未知 EI_CLASS={ei_class}"}
    except struct.error:
        return {"valid": False, "reason": "ELF 头字段越界"}
    issues = []
    if e_phoff and e_phoff >= len(data):
        issues.append(f"e_phoff={e_phoff:#x} 超出数据长度")
    if e_shoff and e_shoff >= len(data):
        issues.append(f"e_shoff={e_shoff:#x} 超出数据长度（节表被抹）")
    return {
        "valid": True,
        "elf_class": cls_label,
        "e_phoff": hex(e_phoff), "e_shoff": hex(e_shoff),
        "e_phnum": e_phnum,
        "issues": issues,
        "note": ("issues 非空说明 ELF 头被改过——加固常见做法，"
                 "不影响按偏移读代码，但工具链可能认不出。"),
    }
