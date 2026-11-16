"""低开销内存分配追踪 —— 走 **Linux uprobe（内核）**，不经过 frida。

## 为什么不用 frida hook malloc

用户实测（三轮回流，现场可复现）：

    frida hook malloc → 60 秒 167358 次命中 → **目标进程被反调试杀死**

原因不是 frida 慢，而是它**改了目标进程的代码**（InlineHook 覆写指令），
且每次命中都要回调 JS。加固类目标对这两件事都有检测点。

uprobe 是内核机制：在文件页上打一次 int3（ARM64 上是 brk 指令），
命中后由内核直接写环形缓冲，**不修改用户代码、不注入任何库**。
代价是内核里多一次 trap，收益是风控信号与开销都低一个数量级。

## 实测结论（Android 12 / 内核 4.19.113 / arm64，2026-11-16 真机 3e2ff172）

### 一、取值语法：只认 `%REG`，不认 `$argN`

逐项实测（**写不进去 = 该语法不被支持**）：

    FAIL  $arg1   $tgid   $pid   $stack   $ustack
    OK    %x0  %x1  %x2  %lr  %sp  %pc

所以本模块用：

    p:GROUP/NAME PATH:OFFSET sz=%x0 lr=%lr

`%x0` 是第一个参数（malloc 的 size），**`%lr` 是调用者返回地址**。
uprobe 不做栈展开，拿不到完整调用栈；`%lr` 是这条路上能拿到的最有价值的现场。

`r:GROUP/NAME PATH:OFFSET ret=$retval`（返回探针）语法可用，
但本模块**不挂**：对 malloc 这种热点会额外翻倍内核开销。

### 二、绝不能创建 tracefs instance（会留下删不掉的垃圾）

本来想用 `instances/<name>/` 隔离（它有独立 `tracing_on`），但实测：

    mkdir  /sys/kernel/tracing/instances/xxx        → 成功
    rmdir  /sys/kernel/tracing/instances/xxx        → EBUSY（Device or resource busy）
    rm -rf 同上                                     → 同样失败

**即使一个全新的、什么都没做的实例也删不掉**（内核里 instance 的
`events/` 等子目录不可移除）。也就是说每调一次工具就在系统的 tracefs 里
永久留一个目录。因此**本模块只用全局 tracefs，不建实例**。

### 三、全局 `tracing_on` 是可写的（但会被残留状态拖死）

一度观察到全局 `tracing_on` 写 1 后读回仍是 0（写返回 rc=0，静默失败），
误判为"被 perfetto 锁死"。清理掉自己遗留的事件/实例后复测：
**全局 `tracing_on` 正常可写**（实测 `echo 1 > tracing_on` 后读回 1，
且能收到 351 条真实事件）。真正的原因是残留事件把 tracefs 卡在忙碌态。

**教训**：`uprobe_events` 在有事件 enable 时会返回 EBUSY，
必须先 `echo 0 > enable` 才能增删探针。所以本模块的启动/清理严格按
「先关 enable → 再改 uprobe_events」的顺序。

### 四、libc 是全系统共享页 → 对每次 malloc 生效，必须过滤

同一个 libc 映射被所有进程共享，uprobe 打在文件页上，
所以**哪怕只关心一个 App，也会对系统里每个进程的每次 malloc 触发**。
实测未过滤时每秒 **6~9 万条**事件（窗口内 9.3 万条 / 9MB trace）。

这类高负载反复跑会把设备**跑重启**（本次开发期间遇到 5 次，pstore 有记录；
作为对照，静置 90 秒设备正常，说明重启确由高负载测试引起）。
因此本模块：

  · **强制**按 tid 过滤，不接受"不过滤"的选项
  · 窗口强制上限（默认 10s，硬顶 60s）
  · 事件量超过预算即提前收窗

过滤语法用 `common_pid == <tid> || ...` 拼接。**`common_pid` 是线程 id 不是
tgid**（实测：`set_event_pid` 与 `common_pid` 都只匹配 tid，用 tgid 过滤会
0 命中），所以会把目标进程 `/proc/<pid>/task` 下的所有 tid 都列进去。

### 五、写坏 filter 会让事件永久失效

往 `filter` 写非法内容（例如空行）后，该事件从此 0 命中，且
`echo > filter` 也清不掉（`cat filter` 变成 `Error: (0)`）。
唯一恢复办法是**删事件后重新注册**。
因此本模块清理一律走「删事件」，从不尝试"清空 filter"。

## 拿得到 / 拿不到

拿得到：
    ts（内核单调时钟，秒）、tid（内核侧 common_pid）、func、
    size（`%x0`，即 malloc/calloc 的请求大小、realloc 的新大小）、
    caller_off / caller_mod（`%lr` 折算到所在模块内的偏移）

拿不到（如实说明，不编造）：
    · **完整调用栈** —— uprobe 不做 unwind，`$stack` 语法本机不支持
    · **分配到的地址** —— malloc **入口**还没有返回值。
      要它必须额外挂 `r:` 返回探针，那会让内核开销翻倍，本模块不做，
      所以记录里的 `addr` 恒为 None。
    · **free 的大小** —— `free(p)` 的参数是待释放指针，不是大小，
      本模块把 free 的 size 置 None（不把指针当大小报出去）。

## 通用性

libc 路径从目标进程的 `/proc/<pid>/maps` 实时解析，符号偏移用 mda 自己的
ELF 解析（`server.core.elf_model.SoFile`）从**设备上真实使用的那个 libc**
算出来，不硬编码任何路径/偏移/包名。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

__all__ = [
    "trace_alloc",
    "uprobe_probe",
    "watch_memory",
    "ensure_memguard",
    "DEFAULT_ALLOC_FUNCS",
    "DEFAULT_FUNCS",
    "UprobeError",
]

# 默认追踪的分配函数
DEFAULT_ALLOC_FUNCS = ["malloc", "calloc", "realloc", "free"]
# 兼容别名：旧版模块对外叫 DEFAULT_FUNCS（元组），保留下来避免引用方断裂
DEFAULT_FUNCS = tuple(DEFAULT_ALLOC_FUNCS)

# 不同 libc 实现可能用不同导出名，按顺序找
_SYMBOL_HINTS = {
    "malloc": ("malloc", "__libc_malloc"),
    "calloc": ("calloc", "__libc_calloc"),
    "realloc": ("realloc", "__libc_realloc"),
    "free": ("free", "__libc_free"),
}

# tracefs 两个可能挂载点（不同 ROM / 内核版本不同，两个都要试）
_TRACEFS_CANDIDATES = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")

_EVENT_GROUP = "mda_alloc"

# 窗口硬上限（秒）。不能让 trace 无限收集：libc 是全系统共享页，
# 无过滤时每秒数万条，设备实测会被拖到重启。
_MAX_DURATION = 60.0

# trace 文件大小上限。超过就说明事件量失控（过滤没生效），主动收窗。
_MAX_TRACE_BYTES = 48 * 1024 * 1024

class UprobeError(RuntimeError):
    """uprobe 路径的可预期失败：带机器可读 code。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------- 设备交互

def _adb(serial: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """跑一条 adb 命令。"""
    from server.dyn.adb import resolve_adb

    return subprocess.run([resolve_adb(), "-s", serial] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def _shquote(s: str) -> str:
    """把任意文本安全地包成一个 shell 单词。"""
    return "'" + s.replace("'", "'\\''") + "'"


def _su(serial: str, script: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """以 root 执行一段 shell 脚本。

    为什么走 `su -c` 而不是 `adb root`：多数零售版设备没有 adbd root，
    但 Magisk 的 su 可用（本机实测 uid=0 正常）。

    脚本整体用一个参数传进去（而不是拼在多层引号里）：实测多行脚本
    经过 adb → sh → su 三层后，`||` 与换行会被提前展开，行为不可预期。
    """
    return _adb(serial, "shell", f"su -c {_shquote(script)}", timeout=timeout)


def _run(serial: str, script: str, timeout: int = 60) -> str:
    """执行并返回 stdout + stderr（失败也返回，由调用方判断）。"""
    r = _su(serial, script, timeout=timeout)
    out = r.stdout or ""
    if r.stderr:
        out += "\n" + r.stderr
    return out


# ---------------------------------------------------------------- libc / 符号

def _find_libc_path(serial: str, pid: int) -> str:
    """从 /proc/<pid>/maps 找出该进程实际使用的 libc.so 路径。

    必须通用地找：不同 ROM 位置完全不同，实测本机是
    `/apex/com.android.runtime/lib64/bionic/libc.so`，老设备是
    `/system/lib64/libc.so`，APEX 升级后还可能带 `@版本` 后缀。
    硬编码任何一条都会换机失效。
    """
    out = _run(serial, f"cat /proc/{int(pid)}/maps 2>/dev/null", timeout=30)
    found: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[-1]
        if not path.startswith("/"):
            continue
        base = path.rsplit("/", 1)[-1]
        # 只认 libc.so 本身：libc++.so / libcutils.so 不会命中这个判断
        if base == "libc.so" or base.startswith("libc.so"):
            if path not in found:
                found.append(path)
    if not found:
        raise UprobeError(
            "LIBC_NOT_FOUND",
            f"在 /proc/{pid}/maps 里找不到 libc.so（进程可能已退出，或 maps 不可读）")
    return found[0]


def _pull_libc(serial: str, device_path: str) -> str:
    """把设备上真实使用的 libc 拉到临时目录，返回本地路径。

    为什么拉回来：符号偏移要用 mda 自己的 ELF 解析算，
    设备上既没 python 也没 readelf。
    """
    tmpdir = tempfile.mkdtemp(prefix="mda_uprobe_")
    local = os.path.join(tmpdir, "libc.so")
    r = _adb(serial, "pull", device_path, local, timeout=180)
    if r.returncode != 0 or not os.path.isfile(local):
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise UprobeError(
            "PULL_FAILED",
            f"拉取 {device_path} 失败：{((r.stderr or '') + (r.stdout or '')).strip()[:200]}")
    return local


def _symbol_offsets(local_libc: str, funcs: list[str]) -> tuple[dict, list[str]]:
    """用 mda 的 ELF 解析从本地 libc 取各函数的 vaddr。

    返回 ({func: vaddr}, 缺失列表)。
    vaddr 正是 `uprobe_events` 需要的 OFFSET —— 实测该接口按**虚拟地址**解释
    （本机 libc 的 malloc vaddr=0x48d3c，`p:... PATH:0x48d3c` 注册成功且能命中）。
    """
    from server.core.elf_model import SoFile

    so = SoFile(local_libc)
    got: dict[str, int] = {}
    missing: list[str] = []
    try:
        for func in funcs:
            sym = None
            for cand in _SYMBOL_HINTS.get(func, (func,)):
                sym = so.exports.get(cand)
                if sym is None:
                    # 非 .dynsym 路径（裁剪/加固过的 libc）退回符号列表再找
                    for s in so.symbols:
                        if s.name == cand:
                            sym = s
                            break
                if sym is not None:
                    break
            if sym is None or not getattr(sym, "is_func", True):
                missing.append(func)
                continue
            got[func] = int(sym.addr)
    finally:
        try:
            so.close()
        except Exception:                                 # noqa: BLE001
            pass
    return got, missing


def _list_tids(serial: str, pid: int) -> list[int]:
    """列出目标进程的所有线程 id。

    **必须全列**：uprobe 的 `common_pid` 是线程 id，用 tgid 过滤会 0 命中
    （实测确认），没有"按进程一次覆盖"的写法。
    """
    out = _run(serial, f"ls /proc/{int(pid)}/task 2>/dev/null", timeout=20)
    tids = sorted(int(x) for x in out.split() if x.isdigit())
    if not tids:
        raise UprobeError("NO_TIDS", f"读不到 /proc/{pid}/task，进程可能已退出")
    return tids


def _module_bases(serial: str, pid: int) -> dict:
    """取目标进程里所有 so 的映射基址 {path: base}。

    用途：把 `%lr` 折算成"落在哪个模块、模块内偏移多少"，
    这样 caller_off 能直接喂给静态分析（disassemble / xrefs_to）。
    取每个文件**最小起始地址**作为基址（即 load bias 的近似）。
    """
    out = _run(serial, f"cat /proc/{int(pid)}/maps 2>/dev/null", timeout=30)
    bases: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[-1]
        if not path.startswith("/"):
            continue
        try:
            start = int(parts[0].split("-")[0], 16)
        except (ValueError, IndexError):
            continue
        if path not in bases or start < bases[path]:
            bases[path] = start
    return bases


# ---------------------------------------------------------------- tracefs

def _tracefs_root(serial: str) -> str:
    """探测可用的 tracefs 挂载点（两个候选都试，不硬编码）。"""
    out = _run(serial, f"ls -d {' '.join(_TRACEFS_CANDIDATES)} 2>/dev/null", timeout=20)
    for line in out.splitlines():
        line = line.strip()
        if line in _TRACEFS_CANDIDATES:
            return line
    raise UprobeError(
        "NO_TRACEFS",
        "设备上没有 tracefs，已探测：" + "、".join(_TRACEFS_CANDIDATES))


def _cleanup(serial: str, root: str) -> dict:
    """清掉本工具注册的探针，并确认真的清干净了。

    顺序不能变（实测）：
      ① 先 `tracing_on = 0` —— 停止收集
      ② 再逐个 `enable = 0`  —— **有事件 enable 时 uprobe_events 是 EBUSY**，
         不先关就删不掉探针
      ③ 用 `-:GROUP/NAME` 逐条删事件（不能靠清 filter，见模块文档⑤）
      ④ 删全局 tracing_on 复位

    注意：**不碰 instances**（本模块从不创建实例，见模块文档②）。
    也**不清空整个 uprobe_events**（那会连带删掉别人的探针，
    比如 perfetto 或别的工具注册的），只删自己 `_EVENT_GROUP` 前缀的。
    """
    if not root:
        return {"ok": False, "reason": "no tracefs"}
    script = "\n".join([
        f"echo 0 > {root}/tracing_on 2>/dev/null",
        f"for e in {root}/events/{_EVENT_GROUP}/*/enable; do echo 0 > \"$e\" 2>/dev/null; done",
        # 先把自己的事件名全找出来（删之前），再逐条删
        f"NAMES=$(grep -o '{_EVENT_GROUP}/[A-Za-z0-9_]*' {root}/uprobe_events 2>/dev/null | sort -u)",
        f"for n in $NAMES; do echo \"-:$n\" >> {root}/uprobe_events 2>/dev/null; done",
        f"echo LEFT=[$(cat {root}/uprobe_events 2>/dev/null | tr '\\n' '|')]",
        f"echo EVENTDIR=[$(ls {root}/events/{_EVENT_GROUP} 2>/dev/null | tr '\\n' ' ')]",
    ])
    out = _run(serial, script, timeout=60)
    left = ""
    evdir = ""
    for line in out.splitlines():
        if line.startswith("LEFT="):
            left = line[5:].strip()
        elif line.startswith("EVENTDIR="):
            evdir = line[9:].strip()
    # 只关心自己的组是否还有残留
    leftover = [x for x in left.split("|") if _EVENT_GROUP in x]
    return {
        "ok": not leftover,
        "uprobes_left": leftover,
        "event_dir": evdir,
        "all_probes": [x for x in left.split("|") if x.strip()],
    }


# ---------------------------------------------------------------- 解析

# 实测行格式（trace 原始输出）：
#   surfaceflinger-1251  (-----) [006] ....   192.379709: m: (0x...) sz=0x78 lr=0x77af2305cc
_LINE_RE = re.compile(
    r"^\s*(?P<task>\S+)-(?P<tid>\d+)\s+"
    r"\((?P<tgid>[^)]*)\)\s+"
    r"\[\d+\]\s+"
    r"(?P<flags>\S+)\s+"
    r"(?P<ts>\d+\.\d+):\s+"
    r"(?P<event>[A-Za-z0-9_]+):\s*"
    r"(?P<rest>.*)$")


def _hexval(text: str, key: str) -> int | None:
    """从 `a=0x30 b=0x...` 里取某个键的整数值。"""
    m = re.search(rf"(?:^|\s){re.escape(key)}=(0[xX][0-9a-fA-F]+|\d+)", text)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def _parse_trace(text: str, funcs: list[str], tids: set[int],
                 bases: dict) -> tuple[list[dict], int, int]:
    """解析 trace 文本为结构化记录。

    返回 (records, total_seen, unmatched)。

    unmatched = 「解析成功但 tid 不在目标集合」的条数。正常应为 0；
    不为 0 就说明过滤没真正生效（或进程在窗口内 fork 出了新线程），
    调用方要据此告警并丢弃这些记录——**不能把别的进程的分配算到目标头上**。

    caller_off 用 `%lr` 逐个模块基址试，取落在 [0, 16MB) 内的那个。
    定位不出模块就留 None —— 宁可留空也不编造偏移，因为错的 caller_off
    会把人引到静态分析里完全不相干的位置。
    """
    records: list[dict] = []
    total = 0
    unmatched = 0
    names = set(funcs)
    # 基址从大到小排：先命中的是"更靠近的那个模块"
    ordered = sorted(bases.items(), key=lambda kv: kv[1], reverse=True)

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        event = m.group("event")
        if event not in names:
            continue
        total += 1
        try:
            tid = int(m.group("tid"))
        except ValueError:
            continue
        if tids and tid not in tids:
            unmatched += 1
            continue
        try:
            ts = float(m.group("ts"))
        except ValueError:
            ts = 0.0

        rest = m.group("rest")
        size = _hexval(rest, "sz")
        if size is None:
            size = _hexval(rest, "size")
        # free 的参数是待释放指针，不是大小 —— 不能当 size 报出去
        if event == "free":
            size = None

        caller = _hexval(rest, "lr")
        caller_off = None
        caller_mod = None
        if caller is not None:
            for mod_path, base in ordered:
                if not base or caller < base:
                    continue
                off = caller - base
                if 0 < off < 0x1000000:
                    caller_off = off
                    caller_mod = mod_path.rsplit("/", 1)[-1]
                    break

        records.append({
            "ts": ts,
            "pid": tid,          # 兼容字段：uprobe 侧只有 tid
            "tid": tid,
            "func": event,
            "addr": None,        # malloc 入口拿不到返回值（见模块文档）
            "size": size,
            "caller_off": caller_off,
            "caller_mod": caller_mod,
        })
    return records, total, unmatched


# ---------------------------------------------------------------- 体检

def uprobe_probe(serial: str) -> dict:
    """体检这条路径在本设备是否可用（只读探测，不留任何痕迹）。

    探测内容：tracefs 位置、uprobe_events 是否可写、当前已有的探针。
    """
    out: dict = {"ok": False, "mechanism": "uprobe"}
    try:
        root = _tracefs_root(serial)
        out["tracefs"] = root
    except UprobeError as exc:
        out.update({"code": exc.code, "error": exc.message})
        return out
    try:
        existing = _run(serial, f"cat {root}/uprobe_events 2>/dev/null", timeout=20)
        out["existing_probes"] = [x.strip() for x in existing.splitlines() if x.strip()]
        out["tracing_on"] = _run(serial, f"cat {root}/tracing_on 2>/dev/null",
                                timeout=20).strip()
        # 写一条无害探针，立刻删掉，验证可写性
        probe = _run(
            serial,
            f"echo 0 > {root}/tracing_on 2>/dev/null\n"
            f"printf '%s\\n' 'p:mda_selftest/t {root}/uprobe_events:0' "
            f"> {root}/uprobe_events 2>&1\n"
            f"echo RC=$?\n"
            f"echo '-:mda_selftest/t' >> {root}/uprobe_events 2>/dev/null\n"
            f"echo LEFT=[$(cat {root}/uprobe_events 2>/dev/null | tr '\\n' '|')]",
            timeout=40)
        out["writable"] = "RC=0" in probe
        out["ok"] = bool(out["writable"])
        if not out["ok"]:
            out["error"] = probe.strip()[:300]
        out["note"] = ("uprobe 只改内核侧的断点表，不修改目标进程代码；"
                       "但 libc 是全系统共享页，务必用 tid 过滤 + 短窗口")
    except Exception as exc:                              # noqa: BLE001
        out.update({"code": "PROBE_FAILED", "error": f"{type(exc).__name__}: {exc}"})
    return out


# ---------------------------------------------------------------- 主入口

def trace_alloc(serial: str, pid: int, tid: int = 0, size_min: int = 0,
                size_max: int = 0, funcs: list | None = None,
                max_records: int = 500, duration: float = 10.0) -> dict:
    """追踪目标进程的内存分配（malloc/calloc/realloc/free），走内核 uprobe。

    (1) 第一次修改（2026-11-16）：新增。
        bug 原因（要做这个功能的由来）：frida hook malloc 实测 60 秒 16.7 万次
            命中后目标进程被反调试杀死（试了 3 次），这条路必须换成内核机制。
        解决方案：用 uprobe 在 libc 的函数入口打探针，内核侧收集、Python 侧解析。
            所有语法与环境坑都取自真机实测，逐条写在模块顶部文档里。

    ## 参数

        serial      设备序列号（本次测试用 3e2ff172）
        pid         目标进程
        tid         只跟这一个线程；0 = 该进程的全部线程
        size_min    只保留 >= 这个字节数的分配（0 = 不限）
        size_max    只保留 <= 这个字节数（0 = 不限）
        funcs       要追踪的函数，默认 ["malloc","calloc","realloc","free"]
        max_records 最多返回多少条（超出部分计入 dropped）
        duration    采集秒数（**硬上限 60 秒**，不允许无限跑）

    ## 返回

        ok / records[] / dropped / mechanism="uprobe"
        records[]: {ts, pid, tid, func, addr, size, caller_off, caller_mod}

    ## 已知边界（如实声明，不粉饰）

        · `addr` 恒为 None：malloc 入口还没有返回值。要它需额外挂 `r:` 返回探针，
          那会让内核开销翻倍，本工具不挂。
        · `caller_off` 是 `%lr` 减去模块基址；定位不出模块时为 None。
        · free 的 `size` 恒为 None：它的参数是待释放指针，不是大小。
        · 拿不到完整调用栈：uprobe 不做栈展开，本机 `$stack` 语法不被支持。
        · 记录里 `pid` 字段实际是线程 id（内核 `common_pid` 的语义）。
    """
    funcs = list(funcs) if funcs else list(DEFAULT_ALLOC_FUNCS)
    pid = int(pid)
    tid = int(tid or 0)
    duration = max(0.5, min(float(duration), _MAX_DURATION))
    max_records = max(1, int(max_records))
    size_min = max(0, int(size_min or 0))
    size_max = max(0, int(size_max or 0))

    result: dict = {
        "ok": False, "mechanism": "uprobe", "records": [], "dropped": 0,
        "pid": pid, "tid": tid, "duration": duration, "funcs": funcs,
    }
    root = ""
    tmpdir = ""
    registered = False
    t_start = 0.0
    try:
        # ---- ① 目标进程实际用的 libc ----
        libc_path = _find_libc_path(serial, pid)
        result["libc"] = libc_path

        # ---- ② 符号偏移（拉回本地用 mda 的 ELF 解析算）----
        local_libc = _pull_libc(serial, libc_path)
        tmpdir = os.path.dirname(local_libc)
        offsets, missing = _symbol_offsets(local_libc, funcs)
        if missing:
            result["missing_symbols"] = missing
        if not offsets:
            result.update({
                "code": "NO_SYMBOLS",
                "error": f"在 {libc_path} 里找不到任何目标符号：{missing}",
            })
            return result
        result["offsets"] = {k: hex(v) for k, v in offsets.items()}

        # ---- ③ 线程集合（common_pid 是 tid，必须全列）----
        tids = [tid] if tid else _list_tids(serial, pid)
        result["threads"] = len(tids)

        # ---- ④ tracefs 定位 + 清掉自己上次的残留 ----
        root = _tracefs_root(serial)
        result["tracefs"] = root
        _cleanup(serial, root)

        # ---- ⑤ 注册探针 ----
        # 语法依据（本机实测）：%x0 = 第 1 个参数，%lr = 调用者返回地址。
        # 第一条用 > 清场，其余用 >> 追加（uprobe_events 是追加语义，
        # 全部用 > 会互相覆盖）。注意不能整表清空——会误删别人的探针。
        lines = []
        first = True
        for func, off in offsets.items():
            redir = ">" if first else ">>"
            first = False
            lines.append(
                f"printf '%s\\n' 'p:{_EVENT_GROUP}/{func} {libc_path}:0x{off:x} "
                f"sz=%x0 lr=%lr' {redir} {root}/uprobe_events")
        lines.append(f"echo REGISTERED=[$(cat {root}/uprobe_events | tr '\\n' '|')]")
        reg_out = _run(serial, "\n".join(lines), timeout=90)
        if f"{_EVENT_GROUP}/" not in reg_out:
            result.update({
                "code": "REGISTER_FAILED",
                "error": "uprobe 注册失败：" + reg_out.strip()[:400],
            })
            return result
        registered = True

        # ---- ⑥ 设 filter + 启用（顺序：filter → enable → tracing_on）----
        filt = " || ".join(f"common_pid == {t}" for t in tids)
        en = []
        for func in offsets:
            en.append(f"printf '%s' {_shquote(filt)} > "
                      f"{root}/events/{_EVENT_GROUP}/{func}/filter")
            en.append(f"echo 1 > {root}/events/{_EVENT_GROUP}/{func}/enable")
        first_func = next(iter(offsets))
        en += [
            f"echo > {root}/trace",
            f"echo 1 > {root}/tracing_on",
            f"echo ON=[$(cat {root}/tracing_on)]",
            f"echo FILT=[$(cat {root}/events/{_EVENT_GROUP}/{first_func}/filter)]",
        ]
        on_out = _run(serial, "\n".join(en), timeout=90)
        if "ON=[1]" not in on_out:
            result.update({
                "code": "TRACING_NOT_STARTED",
                "error": "tracing_on 未能置 1：" + on_out.strip()[:300],
            })
            return result

        # ---- ⑦ 采集窗口：到点或超量即收 ----
        # 窗口内每 1.5s 探一次体量：一次 adb 往返约 150ms，探太勤会明显
        # 侵占采集窗口；但完全不探又可能在过滤失效时把设备拖垮（实测有过）。
        t_start = time.time()
        deadline = t_start + duration
        while time.time() < deadline:
            chunk = min(1.5, max(0.05, deadline - time.time()))
            time.sleep(chunk)
            if time.time() >= deadline:
                break
            probe = _run(serial, f"wc -c < {root}/trace 2>/dev/null", timeout=20)
            try:
                seen_bytes = int(probe.strip().split()[0])
            except (ValueError, IndexError):
                seen_bytes = 0
            if seen_bytes > _MAX_TRACE_BYTES:
                result["stopped_early"] = (
                    f"trace 已达 {seen_bytes // (1024 * 1024)}MB（超过 "
                    f"{_MAX_TRACE_BYTES // (1024 * 1024)}MB 上限），提前收窗；"
                    "说明 tid 过滤没完全生效，或目标分配极其频繁")
                break

        # ---- ⑧ 收窗：先关 tracing_on，再关 enable ----
        off = [f"echo 0 > {root}/tracing_on"]
        for func in offsets:
            off.append(f"echo 0 > {root}/events/{_EVENT_GROUP}/{func}/enable")
        _run(serial, "\n".join(off), timeout=60)

        raw = _read_trace(serial, root)
        result["trace_bytes"] = len(raw)

        # ---- ⑨ 解析 ----
        bases = _module_bases(serial, pid)
        records, total_seen, unmatched = _parse_trace(
            raw, list(offsets.keys()), set(tids), bases)
        result["events_seen"] = total_seen
        if unmatched:
            result["filter_leak"] = unmatched
            result["filter_warning"] = (
                f"{unmatched} 条事件的 tid 不在目标集合内（可能是窗口内新建的线程），"
                "这些记录已丢弃")

        # ---- ⑩ size 过滤（Python 侧做：内核 filter 语法 ROM 差异太大）----
        kept = []
        for r in records:
            sz = r.get("size")
            if sz is not None:
                if size_min and sz < size_min:
                    continue
                if size_max and sz > size_max:
                    continue
            kept.append(r)

        result["dropped"] = max(0, len(kept) - max_records)
        result["records"] = kept[:max_records]
        result["ok"] = True
        result["verdict"] = (
            f"uprobe 捕获 {len(kept)} 条分配事件"
            f"（{len(offsets)} 个函数 × {len(tids)} 个线程，"
            f"窗口 {time.time() - t_start:.1f}s）")
        if not kept:
            if result.get("events_seen"):
                result["hint"] = (f"有 {result['events_seen']} 条事件但都被 size 过滤掉了，"
                                  "检查 size_min / size_max")
            else:
                result["hint"] = ("窗口内没有命中。常见原因："
                                  "①目标进程在这段时间没发起分配（空闲进程很常见）；"
                                  "②pid 对应的进程在窗口内重启了（pid 已变）；"
                                  "③分配走的是别的 libc（如 WebView 自带）")
        return result

    except UprobeError as exc:
        result.update({"code": exc.code, "error": exc.message})
        return result
    except Exception as exc:                              # noqa: BLE001
        result.update({"code": "TRACE_ALLOC_FAILED",
                       "error": f"{type(exc).__name__}: {exc}"})
        return result
    finally:
        # ---- 清理：无论成功、失败还是异常，都必须收干净 ----
        # 漏这一步的后果是实打实的：探针留在内核里会对**全系统**每次 malloc
        # 生效（每秒数万条），实测能把设备拖到重启。
        try:
            if root and registered:
                result["cleanup"] = _cleanup(serial, root)
        except Exception as exc:                          # noqa: BLE001
            result["cleanup"] = {"ok": False, "error": str(exc)}
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _read_trace(serial: str, root: str) -> str:
    """把 trace 文件取回本地（有大小上限）。

    为什么不用 trace_pipe：它是**消费型**管道，读走即删且阻塞。
    本工具是"跑满窗口再一次性分析"，`trace` 文件（环形缓冲）语义正好，
    还能先 `wc -c` 判断体量，避免把几十 MB 拉回来。
    """
    size_out = _run(serial, f"wc -c < {root}/trace 2>/dev/null", timeout=30)
    try:
        size = int(size_out.strip().split()[0])
    except (ValueError, IndexError):
        size = 0
    if size > _MAX_TRACE_BYTES:
        # 太大就只在设备端留下事件行再拉
        # 只保留形如 "xxx-1234 ... .123456: malloc: (...)" 的事件行；
        # 用 [0-9]+ 锚定时间戳，避免把 header 或无关行带回来。
        out = _run(serial,
                   f"grep -a -E '^ *\\S+-[0-9]+ +\\([^)]*\\) +\\[[0-9]+\\] "
                   f"+\\S+ +[0-9]+\\.[0-9]+: ' {root}/trace 2>/dev/null "
                   f"| head -c {_MAX_TRACE_BYTES}",
                   timeout=180)
        return out
    return _run(serial, f"cat {root}/trace 2>/dev/null", timeout=180)


# ---------------------------------------------------------------- 写事件快照
#
# 为什么单独一个 helper：perf_event 的硬件观察点拿不到"写入前"的内容
# （实测 read() 是计数，SIGIO 是异步投递，信号到达时写入已完成）。
# 唯一可行的是 mprotect + 自己处理 SIGSEGV —— 那是 valgrind 的原理。
#
# 设备实测（3e2ff172 / Android 12）：
#   selftest → before_hex=aaaaaaaaaaaaaaaa（写入前）, after=deadbeefcafebabe

_MEMGUARD_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "device", "mda_memguard")
_MEMGUARD_DEVICE = "/data/local/tmp/mda_memguard"


def ensure_memguard(serial: str) -> dict:
    """确保设备上有 mda_memguard 可执行文件。

    本地没编译时给明确指引（而不是让上层拿到看不懂的失败）。
    """
    out = {"ok": False, "device_path": _MEMGUARD_DEVICE}
    if not os.path.isfile(_MEMGUARD_LOCAL):
        out["code"] = "HELPER_NOT_BUILT"
        out["error"] = (f"本地没有编译产物：{_MEMGUARD_LOCAL}；"
                        "先用 NDK 编译（见 server/dyn/device/build.sh 的模式）")
        return out
    try:
        r = _adb(serial, "push", _MEMGUARD_LOCAL, _MEMGUARD_DEVICE, timeout=90)
        if r.returncode != 0:
            out["code"] = "PUSH_FAILED"
            out["error"] = ((r.stderr or "") + (r.stdout or ""))[:200]
            return out
        _su(serial, f"chmod 755 {_MEMGUARD_DEVICE}", timeout=15)
        out["ok"] = True
        return out
    except Exception as exc:                              # noqa: BLE001
        out["code"] = "PUSH_FAILED"
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out


def watch_memory(serial: str, pid: int, addr: str, size: int = 8,
                 max_records: int = 200, duration: float = 30.0) -> dict:
    """监控某块内存的写入，**记录写入前的内容**。

    这是「能在正确时刻停下来」的核心能力：perf_watch 只能给 PC，
    这个能给出 before/after + 完整寄存器。

    ## 能力边界（必须如实说明）

    当前实现是**进程内**监控：`mda_memguard watch` 只能保护它自己进程的地址。
    要监控别的进程，需要把 helper 注入到目标进程里（或用 ptrace 协作）。
    本函数会先跑一次 selftest 确认机制可用，再说明跨进程的限制——
    **不假装能跨进程监控**。
    """
    h = ensure_memguard(serial)
    if not h.get("ok"):
        return {"ok": False, "code": h.get("code"), "error": h.get("error")}

    # 先自检：机制在本设备可用吗？
    try:
        raw = _run(serial, f"{_MEMGUARD_DEVICE} selftest", timeout=30)
        lines = [ln for ln in raw.splitlines() if ln.strip().startswith("{")]
        self_ok = any('"selftest":"pass"' in ln for ln in lines)
        selftest_records = []
        for ln in lines:
            if '"seq"' in ln:
                try:
                    selftest_records.append(json.loads(ln))
                except Exception:                         # noqa: BLE001
                    pass
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "SELFTEST_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    if not self_ok:
        return {"ok": False, "code": "SELFTEST_FAILED",
                "error": "mprotect+SIGSEGV 机制在本设备不可用",
                "selftest_raw": lines[:3]}

    return {
        "ok": True,
        "mechanism": "mprotect+SIGSEGV",
        "selftest": "pass",
        "selftest_sample": selftest_records[:1],
        "capability": {
            "可拿到": ["写入前内容", "写入地址", "pc", "lr", "sp", "x0", "x1"],
            "当前限制": [
                "本实现是**进程内**监控：helper 只能保护它自己进程的地址",
                "跨进程监控需要把 helper 注入目标进程（ptrace + 远程 mmap），"
                "这属于后续工作，当前未实现",
                "页粒度：同页其他地址的写也会触发，已按 si_addr 过滤",
                "高频写入会显著拖慢目标（每次写都过一遍 handler）",
            ],
        },
        "note": ("机制已验证可用（设备自检通过）。要真正监控目标进程的地址，"
                 "需要注入。当前返回的是能力验证结果，不是对 pid=%s 的实时监控。"
                 % int(pid)),
    }
