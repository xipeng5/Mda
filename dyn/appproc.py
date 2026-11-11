"""App 进程全貌 —— 把「一个包名下的所有进程」看清。

## 为什么需要它

抓包抓不到，很多时候不是抓包工具不行，而是**网络根本不在你以为的那个进程里**。

实测（com.taobao.idlefish）：

    pid=31182  com.taobao.idlefish              31 个 socket + libtnet.so
    pid=31204  com.taobao.idlefish:channel       6 个 socket + libtnet.so
    pid=31975  com.taobao.idlefish:windowChannel 3 个 socket
    pid=970    ...:normal_render_proc0          13 个 socket

主进程和 `:channel`（ACCS 长连接）都在跑网络，只 hook 主进程必然漏。

## 能回答的问题

    ① 这个 App 一共有几个进程？
    ② 每个进程在干什么（有没有 socket / 加载了什么网络库）
    ③ 哪个进程才是真正发请求的
    ④ 进程之间什么关系（父子、主进程是哪个）

## 实现

全部走 adb + /proc，**不注入、不 attach**，所以完全无感、不会被风控感知。
这是它相对 frida 方案的最大优势。
"""

from __future__ import annotations

import re

__all__ = ["list_app_processes", "probe_network_processes"]

# (1) 第一次修改（2026-11-11）：
#     bug 原因：原来这里写死了一串库名（libtnet / libaccs / libmtopsdk...），
#               那些全是阿里系样本里的名字。换个 App（微信、抖音、任何自研 so）
#               就完全匹配不到——这是「为特定样本特调」，违反通用原则。
#     解决方案：不再猜库名，改为**客观指标**：
#               ① /proc/<pid>/fd 里 socket 型 fd 的数量（任何进程都适用）
#               ② /proc/<pid>/net/tcp|udp 的连接数（内核视角，不依赖库名）
#               ③ 进程名后缀（Android 的通用命名规律，:xxx 形式对所有 App 通用）
#               库名只作为「附加线索」原样列出，不参与是否算网络进程的判定。
#
# 进程名后缀 → 用途的通用规律（:xxx 是 Android 标准命名，不是某个 App 特有）
def _role_of_suffix(suffix: str) -> str:
    """按 Android 通用命名规律推断进程用途。

    只依据后缀的**词形语义**，不依赖具体 App。
    """
    low = suffix.lower()
    if not suffix:
        return "主进程"
    table = (
        ("push", "推送"), ("channel", "长连接/通道"),
        ("remote", "远程服务（常被用作独立网络进程）"),
        ("render", "渲染"), ("sandbox", "沙箱"), ("service", "后台服务"),
        ("daemon", "守护"), ("tools", "工具"), ("worker", "工作线程进程"),
        ("webview", "WebView"), ("mini", "小程序容器"),
        ("widget", "小组件"), ("sync", "同步"), ("download", "下载"),
        ("upload", "上传"), ("proxy", "代理"), ("media", "多媒体"),
    )
    for key, desc in table:
        if key in low:
            return desc
    return "未知用途"



def _adb(shell_cmd: str, serial: str, timeout: int = 30):
    """以 root 执行一条设备命令。"""
    from dyn.perfwatch import _shell_root

    return _shell_root(serial, shell_cmd, timeout=timeout)


_SOCK_INODE_RE = re.compile(r"socket:\[(\d+)\]")
_NET_INODE_CACHE: dict = {}


def _proc_socket_inodes(serial: str, pid: int) -> set[int]:
    """取某进程 fd 里所有 socket 的 inode 集合。

    只让 shell 原样输出 ls 的结果，解析全在 Python 侧做——
    避免 su -c '...' 里嵌套引号 / $变量被外层 shell 抢先展开的坑。
    """
    r = _adb(f"ls -l /proc/{int(pid)}/fd 2>/dev/null", serial, timeout=20)
    return {int(m) for m in _SOCK_INODE_RE.findall(r.stdout or "")}


def _net_ns_inodes(serial: str) -> set[int]:
    """取整个网络命名空间里已建立/监听的 inet socket inode 集合。

    /proc/net/tcp 等是 namespace 级的，所以**一次取回、缓存 3 秒**，
    不必每个进程都读一遍（那样既慢又没意义）。

    (6) 第六次修改（2026-11-11）：
        bug 原因：原来按「行尾最后一个纯数字字段」提取 inode，但实测
                  /proc/net/tcp 每行有 17 个字段，行尾是各种标志位
                  （"100 0 0 10 0"），提取到的是 0/2/4/7/10 这种垃圾值，
                  交集恒为空 → inet_conns 全 0。
        解决方案：实测该格式的 inode 固定在**第 9 列**（0-indexed）：
                  sl local rem st tx:rx tr:tm retrnsmt uid timeout **inode**
                  按固定列取，并校验是数字。
        """
    import time as _t

    now = _t.time()
    hit = _NET_INODE_CACHE.get(serial)
    if hit and now - hit[0] < 3.0:
        return hit[1]

    r = _adb("cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 "
             "2>/dev/null", serial, timeout=20)
    out: set[int] = set()
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        # 表头行只有 1 个字段，直接跳过
        if len(parts) < 10:
            continue
        # 实测第 9 列是 inode（sl local rem st tx:rx tr:tm retrnsmt uid timeout inode）
        tok = parts[9]
        if tok.isdigit():
            out.add(int(tok))
    _NET_INODE_CACHE[serial] = (now, out)
    return out


def list_app_processes(serial: str, package: str,
                       detect_network: bool = True) -> dict:
    """列出一个 App 包名下的**所有进程**。

    不注入、不 attach，纯读 /proc，目标完全无感知。

    ## 参数

        package         包名，如 "com.taobao.idlefish"
        detect_network  是否探测各进程的网络活动（多花一点时间，但很值）

    ## 返回

        count           进程数
        processes[]     {pid, name, role, sockets, net_libs[], is_main}
        main_pid        主进程 pid（名字正好等于包名的那个）
        network_pids[]  有网络活动的进程（socket 数 > 0 或加载了网络库）
        verdict         一句话结论

    ## 典型用法：抓包抓不到时先跑这个

        list_app_processes("com.taobao.idlefish")
        → 发现 :channel 也在跑网络 → 就知道要同时 hook 那个进程
    """
    pkg = str(package or "").strip()
    if not pkg:
        return {"ok": False, "code": "NO_PACKAGE", "error": "必须给 package"}

    # (2) 第二次修改（2026-11-11）：
    #     bug 原因：命令里用了 `grep -E ' pkg(:|$)'`，但整个命令是包在
    #               `su -c '...'` 的单引号里传下去的。正则里的 `(` 被系统 shell
    #               当成子 shell 语法，报 "syntax error: unexpected '('"，
    #               输出为空 → 被误判成「App 没在运行」。
    #     解决方案：先取**全部**进程列表回来，在 Python 里过滤。
    #               不在 shell 里拼正则，彻底避开引号与特殊字符的坑
    #               （包名里也可能含特殊字符）。
    try:
        r = _adb("ps -A -o PID,PPID,NAME", serial)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "PS_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    prefix = pkg + ":"
    rows: list[dict] = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        name = parts[2]
        # 精确匹配：正好是包名（主进程），或以「包名:」开头（子进程）
        if name != pkg and not name.startswith(prefix):
            continue
        rows.append({"pid": pid, "ppid": ppid, "name": name})

    if not rows:
        return {"ok": False, "code": "NO_PROCESS",
                "error": f"没有找到 {pkg} 的进程（App 是否在运行？）",
                "hint": "先用 probe_process 确认 App 活着"}

    # 逐个补信息
    out_rows: list[dict] = []
    for row in rows:
        pid = row["pid"]
        name = row["name"]
        suffix = name[len(pkg):] or ""
        info: dict = {
            "pid": pid,
            "ppid": row["ppid"],
            "name": name,
            "suffix": suffix or "(主进程)",
            "is_main": suffix == "",
            "role": _role_of_suffix(suffix),
        }

        if detect_network:
            # ① socket 型 fd 数量：unix / inet socket 都算，反映真实网络活动
            try:
                rs = _adb(f"ls -l /proc/{pid}/fd 2>/dev/null | grep -c socket",
                          serial, timeout=20)
                info["sockets"] = int((rs.stdout or "0").strip() or 0)
            except Exception:                             # noqa: BLE001
                info["sockets"] = None

            # ② 真正的 inet 连接数（进程级准确）
            #
            # (3) 第三次修改（2026-11-11）：
            #     bug 原因：原来用 `cat /proc/<pid>/net/tcp | grep -vc sl` 统计连接数，
            #               实测四个不同进程拿到的**都是 48**——因为
            #               /proc/<pid>/net/tcp 是**网络命名空间级**的视图，
            #               同一 namespace 下所有进程看到的完全一样，毫无区分度。
            #     解决方案：改用 /proc/<pid>/fd 里 socket 的 **目标地址** 判断：
            #               遍历 fd，读 socket:[inode]，再去 /proc/net/tcp 里对
            #               inode 找匹配——这个才是进程级准确的。
            #               不过那样要做多次 shell 往返，太慢。
            #               折中：只统计 socket fd 总数（含 unix），
            #               并额外给出 inet 连接数（用 fd 的 socket inode 与
            #               /proc/<pid>/net/tcp 的 inode 求交集，一次 shell 完成）。
            # (4) 第四次修改（2026-11-11）：
            #     bug 原因：review 指出 net_pids 用「所有 socket fd > 0」判定，
            #               把 unix socket 也算成「在跑网络」——而这个工具最核心的
            #               答案恰恰是「谁在发请求」，口径不能糊。
            #     解决方案：做**进程级准确的 inet 连接数**：
            #               取 /proc/<pid>/fd 里的 socket inode，与
            #               /proc/net/tcp|tcp6|udp|udp6 的 inode 求交集。
            #
            # (5) 第五次修改（2026-11-11）：
            #     bug 原因：第一次实现把交集写进 shell（awk '{print $10}' + comm），
            #               但命令是包在 su -c '...' 单引号里传下去的，
            #               awk 里的单引号和 $10 被外层 shell 抢先展开，
            #               结果恒为 None（实测 4 个进程 inet_conns 全是 None）。
            #     解决方案：**shell 只负责原样输出，不许解析**——
            #               ls 的输出整体取回，在 Python 里用正则提 inode。
            #               完全不涉及嵌套引号与字段展开。
            try:
                inodes = _proc_socket_inodes(serial, pid)
                info["inet_conns"] = len(inodes & _net_ns_inodes(serial)) \
                    if inodes else 0
            except Exception:                             # noqa: BLE001
                info["inet_conns"] = None

            # ③ 已加载的 so 模块数——只作附加信息，不参与「是否跑网络」的判定。
            #    用最简单的 grep -c，避免多层引号嵌套（实测复杂的管道在
            #    su -c 里会被系统 shell 吃掉）。
            try:
                rm = _adb(f"grep -c '\\.so' /proc/{pid}/maps 2>/dev/null",
                          serial, timeout=20)
                txt = (rm.stdout or "").strip()
                info["loaded_so_count"] = int(txt) if txt.isdigit() else None
            except Exception:                             # noqa: BLE001
                info["loaded_so_count"] = None
        out_rows.append(info)

    # 排序：主进程在前，然后按 socket 数降序
    out_rows.sort(key=lambda x: (not x.get("is_main"),
                                 -(x.get("sockets") or 0)))

    main_pid = next((r["pid"] for r in out_rows if r["is_main"]), None)
    # (4) 判定「在跑网络」用 **inet_conns**（与 /proc/net/* 求交集的真实连接数），
    #     而不是"所有 socket"——后者会把只用 unix socket 的进程也误报成在跑网络。
    #     拿不到 inet_conns（权限/命令失败）时，退回 socket 数并明确标注口径。
    net_pids = [r["pid"] for r in out_rows if (r.get("inet_conns") or 0) > 0]
    basis = "inet_conns"
    if not net_pids:
        # 兜底：拿不到 inet 时就退回 socket 口径，但**明确标注**这是宽口径
        net_pids = [r["pid"] for r in out_rows if (r.get("sockets") or 0) > 0]
        basis = "sockets_only"

    result: dict = {
        "ok": True,
        "package": pkg,
        "count": len(out_rows),
        "processes": out_rows,
        "main_pid": main_pid,
        "network_pids": net_pids,
        "network_basis": basis,
    }

    # 结论：直接告诉调用方「该 hook 哪几个」
    if basis == "sockets_only":
        result["basis_note"] = ("没能取到进程级的 inet 连接数，"
                                "退回到「所有 socket」的宽口径——"
                                "结果里可能包含只用 unix socket 的进程。")
    if len(net_pids) > 1:
        names = [r["name"].split(":")[-1] if ":" in r["name"] else "主进程"
                 for r in out_rows if r["pid"] in net_pids]
        result["verdict"] = (
            f"{pkg} 有 {len(out_rows)} 个进程，其中 **{len(net_pids)} 个在跑网络**"
            f"（{', '.join(names)}）。只 hook 主进程会漏掉其余进程的流量。")
        result["hint"] = ("抓包抓不到时先看这里：网络可能不在主进程。"
                          "对每个 network_pids 里的进程分别 attach。")
    elif len(net_pids) == 1:
        result["verdict"] = (f"{pkg} 有 {len(out_rows)} 个进程，"
                             f"网络集中在 pid={net_pids[0]}")
    else:
        result["verdict"] = (f"{pkg} 有 {len(out_rows)} 个进程，"
                             "暂未探测到网络活动（App 可能空闲）")
    return result


def probe_network_processes(serial: str, package: str) -> dict:
    """专门回答「哪个进程在跑网络」，给抓包/注入选目标用。

    比 list_app_processes 更聚焦：只关心网络，输出更精简。

    返回：{ok, candidates[{pid, name, sockets, net_libs}], recommend[]}
    """
    full = list_app_processes(serial, package, detect_network=True)
    if not full.get("ok"):
        return full

    procs = full.get("processes") or []
    basis = full.get("network_basis")
    if basis == "inet_conns":
        cands = [p for p in procs if (p.get("inet_conns") or 0) > 0]
    else:
        cands = [p for p in procs if (p.get("sockets") or 0) > 0]
    cands.sort(key=lambda p: -((p.get("inet_conns") or 0) * 10
                               + (p.get("sockets") or 0)))

    return {
        "ok": True,
        "package": package,
        "total_processes": len(procs),
        "candidates": cands,
        "recommend": [p["pid"] for p in cands],
        "verdict": (f"共 {len(procs)} 个进程，{len(cands)} 个有网络活动；"
                    f"建议按顺序注入：{[p['name'].split(':')[-1] if ':' in p['name'] else '主进程' for p in cands]}"
                    if cands else "没探测到网络活动"),
        "network_basis": basis,
        "note": ("inet_conns = 进程 fd 里的 socket inode 与 "
                 "/proc/net/tcp|tcp6|udp|udp6 的 inode 求交集，"
                 "**进程级准确**，代表真实的网络连接数。"
                 "sockets = 所有 socket fd 数（含 unix socket），只是宽口径参考。"
                 "注：/proc/<pid>/net/tcp 是 namespace 级的，"
                 "对所有进程返回值相同，不能用来区分进程。"),
    }
