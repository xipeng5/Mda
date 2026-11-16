"""运行环境感知：告诉 AI「你正在操作谁、它现在在不在前台」。

## 为什么需要这个模块（而不是散在工具里）

mda 的动态工具都直接作用于设备上的某个 App。但 **AI 看不到屏幕**：

- 它调 `set_breakpoint` / `java_hook` / `perf_watch` 时，不知道目标是不是在前台
- 目标在后台时，渲染 / 网络 / 生命周期相关代码可能根本不会执行，
  断点装上了也永远不命中 —— AI 会误判成「代码没跑到」或「钩子失效」
- 它也无法感知用户刚切走了 App

把环境信息塞进**每次动态调用的返回值**，AI 读到结果的同时就知道现场状态，
不需要额外一次来回问。这是「不占轮次的自检」。

## 三个设计决定（都是踩出来的）

1. **不缓存**。用户切 App 是随时发生的，而 AI 没有任何办法主动要求刷新。
   缓存不命中的那一刻恰恰是「最需要知道真相」的时刻。
   成本约 200ms（一次 adb 往返），动态工具本身以秒计，这个代价必须付。

2. **挂在中介层而不是逐个工具改**。新增动态工具应自动获得，
   否则每加一个工具就要记得回来补 —— 那种事一定会漏。

3. **失败不阻断**。环境信息是附加价值，探测失败就如实说明探测失败，
   绝不能让工具调用本身失败。

## 【硬规则】所有工具都必须经过本模块

**反查 app 是必须的，不是可选的。**

新增任何工具，一律加 `@logged()` 装饰器 —— 它会自动调用 `inject_env`：

    @server.tool()
    @logged()
    def your_new_tool(serial: str, pid: int, ...) -> str:
        ...

不这么做的后果：那个工具返回里没有 `env`，AI 就不知道自己在操作谁、
目标在不在前台，可能在一个**后台 App** 上做了半天分析还以为是代码没跑到。

判定"目标是谁"的优先级（`resolve_target`）：
  1. 参数里的 `pid`（>0 才算）
  2. 参数里的 `package` —— **必须反查**它的主进程 pid，不能跳过
  3. 都没有 —— 只报告「当前前台是谁」，`probe` 标为 `no-target`

`ui_*` 系列是屏幕级操作，作用对象就是当前前台界面本身，
自动标 `target_relation="is-foreground"`（不存在"目标在后台"这回事）。

## 返回里的 probe 字段怎么读

  · `resolved`  —— 查到了目标，`target_in_foreground` 是确定结论
  · `no-target` —— 这个工具不针对具体 App（不知道对象就无从判断）
  · `failed`    —— 探测本身失败（adb 不通 / 读不到前台），看 `warning`

**AI 必须区分这三种**：把 `failed` 当成"没关系"会导致误判。
"""
from __future__ import annotations

__all__ = [
    "env_facts",
    "inject_env",
    "resolve_target",
]

# 哪些工具的返回值值得注入 env：只要带 serial 就算动态工具。
# 静态工具（load_so / disassemble / xrefs_to ...）不碰设备，注入只是噪音。
_ENV_KEY = "env"


def resolve_target(call_args: dict) -> tuple[int | None, str]:
    """从工具参数里推断「这次操作的目标是谁」。

    返回 (pid, package)。两者都没有时返回 (None, "")。

    优先级：显式 pid > 显式 package > 无。

    注意：perf_watch_* 按 slot 管理观察点，pid 只存在于设备侧守护进程的
    命令行里，Python 侧没有记录 —— 所以它无法自动推断，需要调用方给 pid
    或 package。不给就只报告「当前前台是谁」，不做是否判断。
    """
    pid = call_args.get("pid")
    pkg = str(call_args.get("package") or "").strip()

    # pid 可能是 0（表示"自动取前台"），这种等同于没给
    try:
        pid_int = int(pid) if pid is not None else 0
    except (TypeError, ValueError):
        pid_int = 0

    if pid_int > 0:
        return pid_int, pkg

    # perf_watch_* 系列：只有 slot，pid 从启动时记下的映射里取
    slot = call_args.get("slot")
    if slot is not None:
        try:
            from server.dyn.perfwatch import lookup_slot_pid

            got = lookup_slot_pid(str(call_args.get("serial") or ""), int(slot))
            if got:
                return int(got), pkg
        except Exception:                                 # noqa: BLE001
            pass

    # keyword 像一个完整包名时，等价于给了 package
    if not pkg:
        kw = str(call_args.get("keyword") or "").strip()
        if kw and "." in kw and " " not in kw and kw.islower():
            pkg = kw

    # 只给了 package：**必须**反查它的主进程 pid。
    # 反查是硬要求——不知道对象就无从判断"在不在前台"，
    # 而"目标是否在前台"直接决定 AI 的操作会不会白做。
    if pkg:
        try:
            from server.dyn.adb import Adb

            adb = Adb(str(call_args.get("serial") or ""))
            got = adb.find_app_pid(pkg)
            if got:
                return int(got), pkg
        except Exception:                                 # noqa: BLE001
            pass

    return None, pkg


# 屏幕级工具：它们操作的是「当前前台界面」本身，不存在目标在后台的情况。
_SCREEN_TOOL_PREFIX = ("ui_",)


def _is_screen_tool(tool_name: str) -> bool:
    """这是不是一个「操作对象就是前台」的工具。

    ui_* 点的是屏幕本身，不存在"目标在后台"这回事 —— 前台是谁，
    操作的就是谁。这种情形要给明确结论，不能留 null 让人以为判断失败。

    用工具名前缀判断而不是靠调用方传标记：新增 ui_ 工具自动获得，
    不需要每个都记得加参数。
    """
    return str(tool_name or "").startswith(_SCREEN_TOOL_PREFIX)


def env_facts(serial: str, pid=None, package: str = "") -> dict:
    """当前运行环境：前台是谁、你操作的是谁、两者是否一致。

    **每次调用都实时读，不缓存**（见模块头注释）。

    返回字段：
      foreground            {package, pid} —— 此刻在前台的 App
      target_package        被操作对象的包名（由 pid 反推或参数直给）
      target_pid            被操作对象的 pid（拿不到为 None）
      target_in_foreground  True/False；**None 表示探测失败或不知道对象**，
                            不是"不在前台"
      target_relation       人话说明：same / background / sibling / unknown
      warning               需要提醒时的明确文案；一致或无法判断时为 None
    """
    out: dict = {
        "foreground": None,
        "target_package": "",
        "target_pid": None,
        "target_in_foreground": None,
        "target_relation": "unknown",
        # probe 说明这次到底查没查、查成了没有。AI 必须能区分
        # 「查过了，目标在前台」与「根本没查成」，否则会把
        # 探测失败当成"没关系"。
        #   resolved —— 查到了目标，且已判定
        #   no-target —— 没有可判定的对象（工具不针对具体 App）
        #   failed   —— 探测本身失败（adb 不通 / 读不到前台）
        "probe": "no-target",
        "warning": None,
    }
    if not serial:
        return out

    try:
        from server.dyn.appproc import probe_env, package_of_pid

        ev = probe_env(str(serial), pid)
        if not ev.get("ok"):
            out["probe"] = "failed"
            out["warning"] = ("读不到当前前台 App（"
                              + (ev.get("error") or "未知原因")
                              + "）；无法判断目标是否在前台")
            return out

        fg_pkg = ev.get("fg_package") or ""
        fg_pid = ev.get("fg_pid")
        out["foreground"] = {"package": fg_pkg, "pid": fg_pid}
        out["target_package"] = (ev.get("target_package") or "") or str(package or "")

        tpid = None
        if pid is not None:
            try:
                tpid = int(pid)
            except (TypeError, ValueError):
                tpid = None
        if tpid is None or tpid <= 0:
            # 只知道包名时，用前台包名直接比
            if out["target_package"] and fg_pkg:
                same = (out["target_package"] == fg_pkg)
                out["target_in_foreground"] = same
                out["target_relation"] = "same" if same else "background"
                out["probe"] = "resolved"
                if not same:
                    out["warning"] = (
                        f"你正在操作 {out['target_package']}，但当前前台是 {fg_pkg}。"
                        "目标不在前台时，渲染/网络/生命周期相关代码可能根本不会执行——"
                        "断点或 hook 装上了也可能永远不命中。")
            return out

        out["target_pid"] = tpid
        out["probe"] = "resolved"
        if not out["target_package"]:
            try:
                out["target_package"] = package_of_pid(str(serial), tpid)
            except Exception:                             # noqa: BLE001
                pass

        if fg_pid is not None:
            same_pid = (int(fg_pid) == tpid)
            same_pkg = bool(out["target_package"] and fg_pkg
                            and out["target_package"] == fg_pkg)
            # 同 App 的另一个进程（如 :push）也算"在用这个 App"
            if same_pid or same_pkg:
                out["target_in_foreground"] = True
                out["target_relation"] = "same" if same_pid else "sibling"
            else:
                out["target_in_foreground"] = False
                out["target_relation"] = "background"
        elif fg_pkg and out["target_package"]:
            same = (out["target_package"] == fg_pkg)
            out["target_in_foreground"] = same
            out["target_relation"] = "same" if same else "background"

        if out["target_in_foreground"] is False:
            target = out["target_package"] or f"(pid {tpid})"
            out["warning"] = (
                f"你正在操作 {target}(pid {tpid})，但当前前台是 {fg_pkg}"
                f"(pid {fg_pid if fg_pid is not None else '?'})。"
                "目标不在前台时，渲染/网络/生命周期相关代码可能根本不会执行——"
                "断点或 hook 装上了也可能永远不命中。确认这是预期的再继续。")
    except Exception:                                     # noqa: BLE001
        pass
    return out


def inject_env(result, call_args: dict, tool_name: str = ""):
    """把 env 塞进工具返回值。供 `@logged()` 统一调用。

    只在同时满足时生效：
      · 调用带了 serial（动态工具的特征）
      · 返回值是 JSON 对象字符串（错误结果、纯文本不动）
      · 还没注入过（转发链上会被调两次）

    任何一步失败都原样返回 —— 环境信息绝不能把工具调用本身弄挂。
    """
    serial = call_args.get("serial")
    if not serial or not isinstance(result, str):
        return result

    # 快速排除：绝大多数静态工具返回里没有 env 需求，先看有没有 serial 已足够
    try:
        import json

        data = json.loads(result)
    except Exception:                                     # noqa: BLE001
        return result
    if isinstance(data, list):
        # 裸数组（如 list_processes）也要带 env：包一层，原数据完整保留。
        # 这些工具恰恰是 AI 定位目标的第一步，最需要知道前台是谁。
        try:
            import json

            pid, pkg = resolve_target(call_args)
            env = env_facts(str(serial), pid, package=pkg)
            if _is_screen_tool(tool_name) and env.get("foreground"):
                env["target_package"] = env["foreground"]["package"]
                env["target_pid"] = env["foreground"]["pid"]
                env["target_in_foreground"] = True
                env["target_relation"] = "is-foreground"
                env["probe"] = "resolved"
            return json.dumps({"items": data, _ENV_KEY: env},
                              ensure_ascii=False, indent=2,
                              default=lambda o: o.__dict__)
        except Exception:                                 # noqa: BLE001
            return result
    if not isinstance(data, dict):
        return result
    if _ENV_KEY in data:                                  # 已注入过
        return result

    try:
        import json

        pid, pkg = resolve_target(call_args)
        env = env_facts(str(serial), pid, package=pkg)
        # ui_* 这类屏幕级操作：前台是谁就操作谁，天然一致
        if _is_screen_tool(tool_name) and env.get("foreground"):
            env["target_package"] = env["foreground"]["package"]
            env["target_pid"] = env["foreground"]["pid"]
            env["target_in_foreground"] = True
            env["target_relation"] = "is-foreground"
            env["probe"] = "resolved"      # 已查到并给出确定结论，不是"没查"
            env["note"] = ("这是屏幕级操作，作用对象就是当前前台界面"
                           f"（{env['foreground']['package']}）；不存在'目标在后台'的情况")
        data[_ENV_KEY] = env
        return json.dumps(data, ensure_ascii=False, indent=2,
                          default=lambda o: o.__dict__)
    except Exception:                                     # noqa: BLE001
        return result
