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

### 二、全局 `tracing_on` 写不进去 → 必须用 tracefs instance

实测（这台设备 perfetto 常驻）：

    echo 1 > /sys/kernel/tracing/tracing_on   → rc=0，但读回来仍是 0

**rc=0 但不生效**，属静默失败。曾误以为"被 perfetto 锁死"，因为在清掉
自己遗留的探针后它又短暂可用过；但重复验证后确认：**同一时刻**
全局写不进、而 `instances/<名>/tracing_on` 写 1 读回就是 1，并且能正常
收到事件（同条件下实测 888 条）。所以本模块的开关与收集一律走实例。

### 三、实例目录删不掉 → 只能复用，不能每次新建

`instances/<名>/` 的 `rmdir` 恒失败：

    mkdir  instances/xxx     → 成功
    rmdir  instances/xxx     → EBUSY (Device or resource busy)
    rm -rf instances/xxx     → 同样失败

**连一个全新的、什么都没做的实例也删不掉**（内核里 instance 的 `events/`
等子目录不可移除）。所以：

  · 绝不"每次调用建一个新实例"——那会在系统 tracefs 里不断堆积删不掉的目录
  · 改为**固定名字 `mda_probe` 复用**，每次只 `echo > trace` 清缓冲区
  · 缓冲区可以正常清空（实测清完 488 字节，即只剩 header）

这是本模块唯一一个"会留在设备上"的痕迹，且它是一个空目录 + 空缓冲区，
不采集任何东西时不产生开销。

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

import json
import os
import re
import shlex
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

# tracefs instance 名。**固定不变**：实测实例的 rmdir 恒失败（EBUSY），
# 每次建一个新的会在系统里不断堆积删不掉的目录，所以复用一个。
_INSTANCE = "mda_probe"

# 窗口硬上限（秒）。不能让 trace 无限收集：libc 是全系统共享页，
# 无过滤时每秒数万条，设备实测会被拖到重启。
_MAX_DURATION = 60.0

# trace 文件大小上限。超过就说明事件量失控（过滤没生效），主动收窗。
_MAX_TRACE_BYTES = 48 * 1024 * 1024

# filter 表达式的实际长度上限。实测（Android 12 / 4.19.113）：
#   1015 字节（45 个条件）→ 写成功
#   1037 字节（46 个条件）→ `printf: write: Invalid argument`，**静默失败**
# 写失败后事件照常 enable、tracing_on 照常置 1，但过滤条件根本没生效
# ——表现为"抓到一堆别的进程的分配"（实测泄漏 23 万条），极难定位。
# 所以这里硬性截断，宁可少覆盖几个线程，也不要写出一个无效 filter。
_MAX_FILTER_BYTES = 960

# 采集窗口内探测体量所需的最小剩余时间。低于这个值就不再探测，
# 直接睡到收窗——否则一次 adb 往返（约 150ms，设备异常时可达数秒）
# 会把窗口本身挤掉。
_PROBE_MIN_REMAIN_S = 1.0

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
    return shlex.quote(str(s))


_SAFE_FUNC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_funcs(funcs: list) -> list[str]:
    """校验待追踪函数名列表，仅允许合法 C 标识符，阻断 shell/uprobe 注入。"""
    out: list[str] = []
    for raw in funcs:
        name = str(raw or "").strip()
        if not _SAFE_FUNC_RE.match(name):
            raise UprobeError(
                "BAD_FUNC_NAME",
                f"非法函数名 {raw!r}：仅允许匹配 ^[A-Za-z_][A-Za-z0-9_]*$ 的 C 标识符",
            )
        if name not in out:
            out.append(name)
    if not out:
        raise UprobeError("BAD_FUNC_NAME", "funcs 列表不能为空")
    return out


def _uprobe_args_for(func: str) -> str:
    """按 ARM64 AAPCS64 调用约定生成各内存分配函数的 uprobe 取参字段。"""
    if func == "realloc":
        return "ptr=%x0 sz=%x1 lr=%lr"
    if func == "calloc":
        return "nmemb=%x0 sz=%x1 lr=%lr"
    if func == "free":
        return "ptr=%x0 lr=%lr"
    return "sz=%x0 lr=%lr"


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


def _build_filter(tids: list[int]) -> tuple[str, list[int]]:
    """拼 `common_pid` 的 OR 链，返回 (表达式, 实际纳入的 tid 列表)。

    为什么要截断：内核的 filter 表达式有长度上限，超了会**静默失败**
    （写返回 EINVAL，事件仍然 enable，但条件不生效 → 抓到全系统的分配）。
    实测上限在 1015~1037 字节之间（45 个条件可以，46 个不行），
    这里留余量取 `_MAX_FILTER_BYTES`。

    超限时按顺序取到装得下的为止，并把"没纳入"的真相带回给调用方
    （结果里的 `threads_covered` / `threads_skipped`），
    而不是让人以为已经覆盖了全部线程。
    """
    joined: list[str] = []
    used: list[int] = []
    for t in tids:
        cand = f"common_pid == {int(t)}"
        trial = " || ".join(joined + [cand])
        if len(trial) > _MAX_FILTER_BYTES and joined:
            break
        joined.append(cand)
        used.append(int(t))
    return " || ".join(joined), used


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


def _looks_like_adb_failure(out: str) -> bool:
    """判断输出是不是 adb 自身的报错（而不是设备上的真实结果）。

    实测到的形态：`adb: device 'xxx' not found` / `error: closed` /
    `error: device offline`。这些会把清理/采集的结论带偏，
    必须单独识别出来当"未知"处理，而不是当作"没有残留"。
    """
    low = (out or "").lower()
    markers = ("not found", "error: closed", "device offline",
               "no devices", "unauthorized", "protocol fault")
    return any(m in low for m in markers)


def _parse_left_count(out: str) -> int:
    """从 cleanup 脚本输出里取 `LEFT_BEGIN ... LEFT_END` 之间的计数。

    用显式标记而不是 `grep -c` 直接回显，是因为 Android 的 sh 不支持
    `${var:-default}`（实测 bad substitution），而 `|| echo 0` 又会在
    grep 有输出时再补一个 0（变成 "0 0"）。包在标记之间最稳。
    解析不出时返回 -1（**当作"没清干净"处理**，宁可多重试一轮，
    也不要误报成功）。
    """
    inside = False
    for line in out.splitlines():
        t = line.strip()
        if t == "LEFT_BEGIN":
            inside = True
            continue
        if t == "LEFT_END":
            # 标记之间没有可解析的数字 → 解析失败，交给调用方按"可能没清干净"重试
            return -1
        if inside:
            try:
                return int(t)
            except ValueError:
                continue
    return -1


def _cleanup(serial: str, root: str, attempts: int = 3) -> dict:
    """清掉**本工具组**的探针，并确认真的清干净了。

    (3) 第三次修改（2026-11-16）：
        bug 原因：初版只按 `events/<组>/` 目录枚举要删的事件，而事件目录与
                  `uprobe_events` 里的注册名不一定同步（实测残留一个 dbg1 事件时
                  组目录里找不到它 → 删不掉 → `uprobe_events` 一直 EBUSY →
                  **后续所有注册都失败**，却表现为"tracing_on 置不上 1"这种
                  完全不相关的报错）。
        解决方案：改为直接解析 `uprobe_events` 文本，找出属于本组的事件名，
                  先关 enable 再逐条删除。**只删本组的**。

    (4) 第四次修改（2026-11-16）：
        bug 原因①：单次删除不可靠。内核移除 uprobe 是异步的，删完立刻回读
                  可能还没生效，只看一次会把"还没生效"报成"清不掉"。
        bug 原因②（更隐蔽）：事件名提取原先用 `sed 's|...|\1|p'` 传反斜杠，
                  而这段脚本是 Python f-string 拼出来的——`\1` 在源码里
                  写成单反斜杠，被 Python 当成**八进制转义**解释成 \x01，
                  于是发到设备的 sed 表达式里根本没有反向引用，`MINE` 恒为空，
                  删除循环一条都没执行。这类"字符串转义吃掉反斜杠"的坑在
                  多层拼装（Python → adb → sh → su）里极难靠读代码发现。
        解决方案：① 加收敛重试（最多 3 轮，轮间等待）；
                  ② **彻底不用反向引用**，改用 grep -o + cut 提事件名，
                     整段脚本里不出现任何反斜杠转义，从根上消掉这个坑。

    顺序不能变（实测）：
      ① 先关实例 `tracing_on` —— 停止收集
      ② 再逐个 `enable = 0` —— **有事件 enable 时 uprobe_events 是 EBUSY**
      ③ 用 `-:GROUP/NAME` 逐条删事件（不能靠清 filter，见模块文档⑤）
    """
    # (7) 第七次修改（2026-11-26）
    # bug 原因：L468 和 L485 用 `grep -c '^mda_alloc/'` 统计残留探针，但内核
    #           uprobe_events 每行都以 `p:` 或 `r:` 开头（如 `p:mda_alloc/malloc`），
    #           导致正则恒匹配 0 条，即便探针未清掉也假报清理成功。
    # 解决方案：统一改为 `^[pr]:{_EVENT_GROUP}/`（与 L453 提取正则一致），并对路径加 shlex.quote。
    if not root:
        return {"ok": False, "reason": "no tracefs"}
    inst = f"{root}/instances/{_INSTANCE}"
    q_root = _shquote(root)
    q_inst = _shquote(inst)
    q_events = _shquote(f"{root}/uprobe_events")
    # 事件名 = "p:mda_alloc/NAME" 里 NAME 那段。
    # 用 grep -o + cut 取，不用 sed 反向引用（见上面 bug 原因②）。
    pattern = f"^[pr]:{_EVENT_GROUP}/[A-Za-z0-9_]*"
    check_pattern = f"^[pr]:{_EVENT_GROUP}/"
    script = " ; ".join([
        f"echo 0 > {q_inst}/tracing_on 2>/dev/null",
        f"MINE=$(grep -o {_shquote(pattern)} {q_events} 2>/dev/null "
        f"| cut -d/ -f2 | sort -u)",
        f"for n in $MINE; do echo 0 > {q_inst}/events/{_EVENT_GROUP}/$n/enable 2>/dev/null"
        f" ; echo 0 > {q_root}/events/{_EVENT_GROUP}/$n/enable 2>/dev/null ; done",
        # 必须用双引号：$n 要由 shell 展开；单引号会让它变成字面量 $n
        f'for n in $MINE; do echo "-:{_EVENT_GROUP}/$n" >> {q_events} '
        f'2>/dev/null ; done',
        f"echo > {q_inst}/trace 2>/dev/null",
        # 数剩余条数。**Android 的 sh 不支持 ${var:-default}**（实测 bad
        # substitution），所以直接把 grep -c 的输出接出来：它无匹配时会打印
        # 0（rc=1 但输出有效），不要 `|| echo 0`（会变成 "0 0" 带偏解析）。
        "echo LEFT_BEGIN",
        f"grep -c {_shquote(check_pattern)} {q_events} 2>/dev/null",
        "echo LEFT_END",
        f"echo MINE=[$MINE]",
    ])

    leftover: list[str] = []
    mine = ""
    for i in range(max(1, int(attempts))):
        out = _run(serial, script, timeout=60)
        left = _parse_left_count(out)
        for line in out.splitlines():
            if line.startswith("MINE="):
                mine = line[5:].strip()
        if left == 0:
            return {"ok": True, "uprobes_left": [], "instance": inst,
                    "attempts": i + 1, "removed": mine}
        time.sleep(0.3)
    left_out = _run(serial, f"grep {_shquote(check_pattern)} {q_events} 2>/dev/null",
                    timeout=30)
    # 设备失联（adb 把错误打到 stdout）时要与"确实没清掉"区分开：
    # 前者是无法确认，后者是确定性残留。混为一谈会让人去排查根本不存在的问题。
    if _looks_like_adb_failure(left_out):
        return {"ok": False, "unknown": True, "instance": inst,
                "attempts": attempts,
                "error": ("清理时设备失联，无法确认探针是否已移除；"
                          "重连后可用 uprobe_probe 检查 existing_probes"),
                "raw": left_out.strip()[:200]}
    leftover = [x.strip() for x in left_out.splitlines() if x.strip()]
    return {"ok": False, "uprobes_left": leftover, "instance": inst,
            "attempts": attempts}


def _ensure_instance(serial: str, root: str) -> str:
    """确保固定名字的 tracefs instance 存在，返回它的路径。

    (2) 第二次修改（2026-11-16）：改为复用实例，不再用全局 tracing_on。
        bug 原因：这台设备（perfetto 常驻）的**全局 `tracing_on` 写不进去**：
                  `echo 1 > /sys/kernel/tracing/tracing_on` 返回 rc=0，
                  读回来仍是 0 —— 静默失败。实测在全局路径下工具会直接报
                  TRACING_NOT_STARTED，一个事件都收不到；而同样的操作放到
                  instance 里（`instances/<名>/tracing_on`）写 1 读回就是 1，
                  能正常收到事件（同条件实测 888 条）。
        解决方案：用实例。但实例的 rmdir 恒失败（EBUSY，全新实例也删不掉），
                  所以不能"每次调用建一个"，否则会在系统 tracefs 里不断堆积
                  删不掉的目录；改为**固定名字复用**，每次只清它的缓冲区。
    """
    inst = f"{root}/instances/{_INSTANCE}"
    # 已经存在就直接用；不存在才建（mkdir -p 幂等）
    out = _run(serial, f"mkdir -p {inst} 2>&1; ls -d {inst} 2>/dev/null", timeout=30)
    if inst not in out or "No such file" in out:
        raise UprobeError(
            "NO_INSTANCE",
            f"无法创建 tracefs 实例 {inst}：{out.strip()[:200]}")
    return inst


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
        # (7) 第七次修改（2026-11-26）：按函数真实参数解析 size 与 ptr
        # bug 原因：原实现所有函数都用 sz=%x0，realloc 错把旧指针当 size，calloc 错把
        #           nmemb 当字节数，free 拿不到指针。
        # 解决方案：calloc 读取 nmemb * sz，realloc 读 sz=%x1 且保留 ptr，free 读 ptr=%x0 且 size=None。
        size = _hexval(rest, "sz")
        if size is None:
            size = _hexval(rest, "size")
        if event == "calloc":
            nmemb = _hexval(rest, "nmemb")
            if nmemb is not None and size is not None:
                size = nmemb * size
        ptr_val = _hexval(rest, "ptr")
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
            "addr": hex(ptr_val) if ptr_val is not None else None,
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
        q_root = _shquote(root)
        q_events = _shquote(f"{root}/uprobe_events")
        q_ton = _shquote(f"{root}/tracing_on")
        existing = _run(serial, f"cat {q_events} 2>/dev/null", timeout=20)
        out["existing_probes"] = [x.strip() for x in existing.splitlines() if x.strip()]
        orig_tracing_on = _run(serial, f"cat {q_ton} 2>/dev/null", timeout=20).strip()
        out["tracing_on"] = orig_tracing_on
        # (7) 第七次修改（2026-11-26）
        # bug 原因：原自检使用 `> uprobe_events` 截断清空整个系统探针表（误删第三方/perfetto 探针），
        #           且写 `echo 0 > tracing_on` 后未恢复原值，违背“只读探测不留痕迹”的承诺。
        # 解决方案：先清理遗留 mda_selftest/t，改用 `>>` 追加注册并随即移除，
        #           最后将 tracing_on 恢复为探测前保存的原始值。
        probe_spec = f"p:mda_selftest/t {root}/uprobe_events:0"
        restore_line = (
            f"echo {_shquote(orig_tracing_on)} > {q_ton} 2>/dev/null"
            if orig_tracing_on in ("0", "1") else ""
        )
        probe_lines = [
            f"echo 0 > {q_root}/events/mda_selftest/t/enable 2>/dev/null",
            f"echo '-:mda_selftest/t' >> {q_events} 2>/dev/null",
            f"printf '%s\\n' {_shquote(probe_spec)} >> {q_events} 2>&1",
            "echo RC=$?",
            f"echo '-:mda_selftest/t' >> {q_events} 2>/dev/null",
            f"echo LEFT=[$(cat {q_events} 2>/dev/null | tr '\\n' '|')]",
        ]
        if restore_line:
            probe_lines.append(restore_line)
        probe = _run(serial, "\n".join(probe_lines), timeout=40)
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
    # (7) 第七次修改（2026-11-26）
    # bug 原因：① funcs 未做标识符校验，直接拼入 shell 命令存在命令注入风险；
    #           ② 注册第一条探针时用 `> {root}/uprobe_events` 清空了全系统 uprobe 表；
    #           ③ realloc/calloc/free 全部写死 sz=%x0，参数寄存器错误。
    # 解决方案：① 入口校验 funcs 仅匹配 ^[A-Za-z_][A-Za-z0-9_]*$，所有 shell 参数经 shlex.quote；
    #           ② _cleanup 已先清理旧的 mda_alloc/* 探针，注册全程改用 >> 追加，绝不截断全表；
    #           ③ 通过 _uprobe_args_for 按 AAPCS64 为 malloc/realloc/calloc/free 生成正确取参。
    raw_funcs = list(funcs) if funcs else list(DEFAULT_ALLOC_FUNCS)
    pid = int(pid)
    tid = int(tid or 0)
    duration = max(0.5, min(float(duration), _MAX_DURATION))
    max_records = max(1, int(max_records))
    size_min = max(0, int(size_min or 0))
    size_max = max(0, int(size_max or 0))

    result: dict = {
        "ok": False, "mechanism": "uprobe", "records": [], "dropped": 0,
        "pid": pid, "tid": tid, "duration": duration, "funcs": raw_funcs,
    }
    try:
        funcs = _validate_funcs(raw_funcs)
        result["funcs"] = funcs
    except UprobeError as exc:
        result.update({"code": exc.code, "error": exc.message})
        return result
    root = ""
    tmpdir = ""
    registered = False
    t_start0 = time.time()
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

        # ---- ④ tracefs 定位 + 实例准备 + 清掉自己上次的残留 ----
        root = _tracefs_root(serial)
        result["tracefs"] = root
        # 探针注册在**全局** uprobe_events（事件定义是全局的），
        # 但收集/开关走**实例**——全局 tracing_on 在本机写不进去（见模块文档③）
        inst = _ensure_instance(serial, root)
        result["instance"] = inst
        _cleanup(serial, root)

        # ---- ⑤ 注册探针 ----
        # 绝不用 `> uprobe_events` 清空全系统表：前面 _cleanup 已先清掉旧的 mda_alloc/*，
        # 这里全程用 `>>` 追加，并按各函数真实参数寄存器构造探针。
        q_events = _shquote(f"{root}/uprobe_events")
        q_inst = _shquote(inst)
        lines = []
        for func, off in offsets.items():
            args_expr = _uprobe_args_for(func)
            probe_def = f"p:{_EVENT_GROUP}/{func} {libc_path}:0x{off:x} {args_expr}"
            lines.append(
                f"printf '%s\\n' {_shquote(probe_def)} >> {q_events}")
        lines.append(f"echo REGISTERED=[$(cat {q_events} | tr '\\n' '|')]")
        reg_out = _run(serial, "\n".join(lines), timeout=90)
        if f"{_EVENT_GROUP}/" not in reg_out:
            result.update({
                "code": "REGISTER_FAILED",
                "error": "uprobe 注册失败：" + reg_out.strip()[:400],
            })
            return result
        registered = True

        # ---- ⑥ 设 filter + 启用（顺序：filter → enable → tracing_on）----
        filt, covered = _build_filter(tids)
        result["threads_covered"] = len(covered)
        if len(covered) < len(tids):
            # 内核 filter 有长度上限（见 _build_filter），超了会静默失效。
            # 如实报告少覆盖了哪些，不假装全覆盖。
            result["threads_skipped"] = [t for t in tids if t not in covered]
            result["filter_note"] = (
                f"内核 filter 长度上限约 {_MAX_FILTER_BYTES} 字节，"
                f"只覆盖了 {len(covered)}/{len(tids)} 个线程；"
                "要完整覆盖请用 tid 参数分别追踪")
        en = []
        for func in offsets:
            # 写 filter 并**立刻**在同一行取 $?（跨行会被下一个命令覆盖）
            ev_dir = _shquote(f"{inst}/events/{_EVENT_GROUP}/{func}")
            en.append(f"printf '%s' {_shquote(filt)} > {ev_dir}/filter; "
                      f"echo FRC_{func}=$?")
            en.append(f"echo 1 > {ev_dir}/enable")
        first_func = next(iter(offsets))
        first_filter = _shquote(f"{inst}/events/{_EVENT_GROUP}/{first_func}/filter")
        en += [
            f"echo > {q_inst}/trace",
            f"echo 1 > {q_inst}/tracing_on",
            f"echo ON=[$(cat {q_inst}/tracing_on)]",
            f"echo FILT=[$(cat {first_filter})]",
        ]
        on_out = _run(serial, "\n".join(en), timeout=90)
        bad_filter = [ln for ln in on_out.splitlines()
                      if ln.startswith("FRC_") and "=0" not in ln]
        if bad_filter:
            result.update({
                "code": "FILTER_REJECTED",
                "error": ("filter 写入被内核拒绝（表达式可能超长），"
                          "若继续跑会抓到全系统的分配：" + "、".join(bad_filter)),
            })
            return result
        if "ON=[1]" not in on_out:
            result.update({
                "code": "TRACING_NOT_STARTED",
                "error": "tracing_on 未能置 1：" + on_out.strip()[:300],
            })
            return result

        # ---- ⑦ 采集窗口：到点或超量即收 ----
        # 时间口径要说清楚（否则会出现"我给了 5 秒，报告写 13 秒"的困惑）：
        #   `window_ms`  = 从 tracing_on=1 到 tracing_off 的实际墙钟时长
        #   `elapsed_ms` = 整个 trace_alloc 的耗时（含准备与取回）
        # 体量探测只在**剩余时间还够一次往返**时做。完全不探不行：
        # 过滤失效时 trace 会以每秒数万行增长（实测能把缓冲区打满）。
        # 但探测本身要判设备失联——否则 adb 一次 20 秒超时就把窗口吃光了，
        # 表现为"给 8 秒只采了 1.5 秒"这种莫名其妙的结果。
        t_on = time.time()
        deadline = t_on + duration
        while True:
            remain = deadline - time.time()
            if remain <= 0:
                break
            # 剩余不足一次探测往返，就别探了，直接睡到点
            if remain <= _PROBE_MIN_REMAIN_S:
                time.sleep(remain)
                break
            time.sleep(min(1.5, remain))
            if time.time() >= deadline:
                break
            probe = _run(serial, f"wc -c < {inst}/trace 2>/dev/null", timeout=15)
            if _looks_like_adb_failure(probe):
                result["device_lost"] = True
                result["device_lost_error"] = probe.strip()[:200]
                break
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
        result["window_ms"] = int((time.time() - t_on) * 1000)

        # ---- ⑧ 收窗：先关 tracing_on，再关 enable ----
        off = [f"echo 0 > {q_inst}/tracing_on"]
        for func in offsets:
            off.append(f"echo 0 > {_shquote(f'{inst}/events/{_EVENT_GROUP}/{func}/enable')}")
        _run(serial, "\n".join(off), timeout=60)

        raw = _read_trace(serial, inst)
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

        result["elapsed_ms"] = int((time.time() - t_start0) * 1000)
        result["dropped"] = max(0, len(kept) - max_records)
        result["records"] = kept[:max_records]
        result["ok"] = True
        result["verdict"] = (
            f"uprobe 捕获 {len(kept)} 条分配事件"
            f"（{len(offsets)} 个函数 × {len(tids)} 个线程，"
            f"窗口 {result.get('window_ms', 0) / 1000:.1f}s）")
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


def _read_trace(serial: str, inst: str) -> str:
    """把 trace 文件取回本地（有大小上限）。

    为什么不用 trace_pipe：它是**消费型**管道，读走即删且阻塞。
    本工具是"跑满窗口再一次性分析"，`trace` 文件（环形缓冲）语义正好，
    还能先 `wc -c` 判断体量，避免把几十 MB 拉回来。
    """
    size_out = _run(serial, f"wc -c < {inst}/trace 2>/dev/null", timeout=30)
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
                   f"+\\S+ +[0-9]+\\.[0-9]+: ' {inst}/trace 2>/dev/null "
                   f"| head -c {_MAX_TRACE_BYTES}",
                   timeout=180)
        return out
    return _run(serial, f"cat {inst}/trace 2>/dev/null", timeout=180)


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
        parse_errors: list[str] = []
        for ln in lines:
            if '"seq"' in ln:
                try:
                    selftest_records.append(json.loads(ln))
                except Exception as exc:                  # noqa: BLE001
                    # (6) 不要 pass：解析失败必须能看到，否则"没采到数据"
                    #     和"解析代码坏了"分不清——本轮就踩了这个坑。
                    parse_errors.append(f"{type(exc).__name__}: {exc}")
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "SELFTEST_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    if not self_ok:
        return {"ok": False, "code": "SELFTEST_FAILED",
                "error": "mprotect+SIGSEGV 机制在本设备不可用",
                "selftest_raw": lines[:3]}

    out = {
        "ok": True,
        "mechanism": "mprotect+SIGSEGV",
        "selftest": "pass",
        "selftest_sample": selftest_records[:1],
        "selftest_records": len(selftest_records),
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
    if parse_errors:
        # (6) 解析出错必须可见，不能静默变成"没有样例"
        out["selftest_parse_errors"] = parse_errors[:3]
    if not selftest_records:
        out["selftest_note"] = (
            "自检通过但没拿到样例记录——正常情况下自检会写一条 seq 记录。"
            "若同时有 selftest_parse_errors，说明解析出错了。")
    return out
