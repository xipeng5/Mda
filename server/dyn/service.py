"""动态分析会话注册表（DynSession）。

为什么需要它：
    frida 的 session/script 是有生命周期的进程内对象。原实现每个 MCP 工具都
    `Rebase.attach()` 再 detach，函数一返回断点就随脚本回收，导致"下断点→再查"
    永远查不到，且每次调用都重新 attach（抖动、重复 hook）。

职责边界：
    - 只持有状态：谁 attach 了、有哪些断点、命中了什么、还有哪些事件没人取。
    - 不碰静态分析（core/），不做传输（server/），不做展示（web/）。
    - MCP 与 HTTP 共用这一个单例，所以"AI 下的断点"和"界面上看到的断点"是同一批。

(1) 第一次修改
bug 原因：本模块原来只有"断点表 + 命中计数"两种状态：
    ① Target 没有会话状态概念，AI 无法判断目标是 running 还是在等放行；
    ② wait_hits 是阻塞式，AI 一调就被卡住，也没法只取"新增的"命中；
    ③ state() 信息太少（只有 breakpoints 和 hits 计数）；
    ④ remove_breakpoint 只删记录，注释自认"frida 侧无法单点撤销"，
       对调用方却返回 True，属于假成功；
    ⑤ resume 无脑返回 True，目标根本没 paused 也报"已放行"。
解决方案：引入 Target.state（attached/paused/detached）+ 服务级全局自增
    seq 的事件队列（poll_events 非阻塞优先取事件），resume/remove_breakpoint
    改为如实回报（不是 paused 就 not_paused；debugger 没有真撤销接口就 partial）。
    老方法签名与返回字段保持不变，wait_hits 用 poll_events 重实现，老调用方不受影响。
"""
from __future__ import annotations

import inspect
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from server.dyn.adb import DynError

# 目标会话状态：attach 上来 = attached；hold 断点命中 = paused（等放行）；
# 显式 detach = detached（墓碑，查询能看出"它被断开了"，再次 attach 会重建会话）。
STATE_ATTACHED = "attached"
STATE_PAUSED = "paused"
STATE_DETACHED = "detached"

_EVENT_LOG_MAX = 2000   # 全局事件环形缓冲上限，超出丢最旧（seq 只增不减，不会复用）
_POLL_INTERVAL = 0.05   # poll_events 带 timeout 时的轮询粒度（秒）

# 命中对象序列化后的固定字段，_hit_dict 与事件转换共用，避免两处各写一遍
_HIT_FIELDS = ("so_name", "static_addr", "runtime_addr", "thread_id",
               "context", "backtrace", "ts")
# (2) 第二次修改（2026-11-02）：命中必须透出 debugger 侧的真实挂起状态。
#     bug 原因：_hit_dict 只保留上面 7 个字段，把 BreakpointHit 已有的
#               held/token 丢掉了；_sync_hits 只能靠「断点记录里 hold=True」
#               反推 paused。任何绕过断点表登记的 hold（例如 stepper 直接调
#               dbg.set_breakpoint，或同一地址被短名/全路径各登记一次），
#               都会让 service 认为目标在跑，resume() 返回 not_paused 拒绝
#               放行，而线程实际正阻塞在 recv().wait() 里——**永久挂起且没有
#               任何 API 能救**，只能杀进程。
#     解决方案：held/token 作为可选字段一并透出，_sync_hits 以 debugger 的
#               真实状态为准（bp.hold 仅作兜底）。token 属内部实现细节，
#               不放进对 AI 暴露的事件里，仍由 resume() 统一放行。
# (23) 第二十三次修改（2026-11-26）
# bug 原因：_HIT_OPTIONAL_FIELDS 未包含 "seq"，导致 _hit_dict() 丢弃 BreakpointHit.seq，
#           上层 tools.py:hits(since_seq=...) 与 group_by="seq" 均拿不到命中序号；
#           同时不能无条件补 0，否则会破坏无 seq 字段的旧单测断言。
# 解决方案：将 "seq" 加入可选字段表，仅在命中对象/字典真实带有 seq 时原样保留。
_HIT_OPTIONAL_FIELDS = ("held", "token", "seq")

# (13) 第十三次修改（2026-11-06）：断点机制名，供 set_breakpoint 如实回报。
#     目前 dyn/debugger.py 的 set_breakpoint 只走 frida 的 Interceptor.attach
#     这一条路径，所以只会是 "Interceptor"。
#     **未实现**：hw_breakpoint（ARMv8 硬件观察点，仅 4 个槽位且按线程生效）、
#               soft_bp（把目标指令改成 BRK 的软断点）。
#     将来 debugger 真支持了，应改由 debugger 回报实际机制，而不是在这里加常量。
BREAKPOINT_MECHANISM = "Interceptor"


@dataclass
class Target:
    """一个已附加的目标进程。"""

    serial: str
    pid: int
    rb: object
    dbg: object
    breakpoints: dict[str, dict] = field(default_factory=dict)

    # ---- 以下字段是 (1) 第一次修改新增的会话状态 ----
    state: str = STATE_ATTACHED   # attached / paused / detached
    polled_seq: int = 0           # 该目标已被取走事件的最大 seq（poll 游标）
    hit_cursor: int = 0           # dbg.hits 里已转成事件的下标（兼容无 seq 的假 debugger）
    last_synced_seq: int = 0      # 已同步进事件流的最大命中单调序号（2000 满队列不失效）

    @property
    def key(self) -> str:
        return f"{self.serial}:{self.pid}"


class DynamicService:
    """进程内单例：断点与命中状态的唯一持有者。"""

    def __init__(self) -> None:
        self._targets: dict[str, Target] = {}
        self._lock = threading.RLock()
        # ---- (1) 第一次修改新增：全局事件队列与自增 seq ----
        # 事件放在服务级而不是 Target 级：detach 后事件仍可查，且 seq 全局唯一，
        # AI 可以直接说"给我 seq > 100 的事件"。
        self._events: deque[dict] = deque(maxlen=_EVENT_LOG_MAX)
        self._seq: int = 0
        # (21) 第二十一次修改（2026-11-16）：自动放行定时器表。
        #      key = (target.key, token) → {"timer", "deadline", "bp_id", "ms"}
        #      为什么要 token 粒度而不是 target 粒度：hold 断点命中可能同时挂住
        #      多个线程（不同 token），每个命中的 deadline 不同，必须各管各的，
        #      否则一个 token 到点就把别的还没到点的线程一起放行了。
        self._auto_resume: dict[tuple[str, str], dict] = {}

    # ---------- 生命周期 ----------

    def attach(self, serial: str, pid: int) -> Target:
        """附加到进程；同一 (serial,pid) 重复调用返回同一个会话（幂等）。"""
        key = f"{serial}:{pid}"
        with self._lock:
            tgt = self._targets.get(key)
            # (1) 第一次修改
            # bug 原因：原实现只要 key 在表里就复用，detach 后留下的墓碑
            #           会被当成活会话返回（rb/dbg 其实已关闭）。
            # 解决方案：只有状态不是 detached 才复用，否则重建会话。
            if tgt is not None and tgt.state != STATE_DETACHED:
                return tgt
            from server.dyn.debugger import Debugger
            from server.dyn.rebase import Rebase

            try:
                rb = Rebase.attach(serial, pid)
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                raise DynError("ATTACH_FAILED", _explain(exc)) from exc
            # (24) 第二十四次修改（2026-11-26）
            # bug 原因：attach 创建 Debugger 后未注册主动命中回调，调用方不 poll 时
            #           tgt.state 不会即时进入 paused，auto_resume 定时器也不会触发。
            # 解决方案：通过 dbg.set_on_hit 注册 _on_debugger_hit，在命中到达瞬间
            #           即时同步 paused 状态并调度 auto_resume。
            dbg = Debugger(rb)
            # polled_seq 从当前 seq 起算：新会话只看新事件，不翻旧账
            tgt = Target(serial=serial, pid=pid, rb=rb, dbg=dbg,
                         polled_seq=self._seq)
            if hasattr(dbg, "set_on_hit"):
                dbg.set_on_hit(lambda hit, _t=tgt: self._on_debugger_hit(_t, hit))
            self._targets[key] = tgt
            self._emit(tgt, "attached")
            return tgt

    def detach(self, serial: str, pid: int) -> bool:
        """断开目标；返回是否真的断开（重复 detach 返回 False）。"""
        key = f"{serial}:{pid}"
        with self._lock:
            tgt = self._targets.get(key)
            if tgt is None or tgt.state == STATE_DETACHED:
                return False
            # 先置 detached 再关资源：并发调用方看到的状态与实际一致
            tgt.state = STATE_DETACHED
            self._emit(tgt, "detached")
        # (21) 第二十一次修改（2026-11-16）：detach 必须清掉自动放行定时器。
        #      bug 原因：定时器在守护线程里调 resume()，而 resume 要 post 到
        #                frida 脚本；会话已经关闭时 post 会抛异常，异常落在
        #                守护线程里被静默吞掉——排查时只看到"有时多一条日志"。
        #      解决方案：detach 一开始（状态已置 detached 后）取消该目标全部定时器。
        cancelled = self._cancel_auto_resume(tgt)
        if cancelled:
            self._emit(tgt, "auto_resume_cancelled", count=cancelled,
                       reason="detached")
        try:
            tgt.dbg.close()
        except Exception:                                  # noqa: BLE001
            pass
        try:
            tgt.rb.detach()
        except Exception:                                  # noqa: BLE001
            pass
        return True

    # (25) 第二十五次修改（2026-11-26）
    # bug 原因：Wi-Fi ADB 设备 serial 形如 "192.168.1.2:5555"，key 为 "ip:port:pid"，
    #           用 partition(":") 会从第一个冒号切分导致 pid 解析成 "5555:1234" 失败。
    # 解决方案：改用 rpartition(":") 从右侧最后一个冒号切分 serial 与 pid。
    def close_all(self) -> None:
        """退出时清理，避免留下 hook 或占用设备。"""
        for key in list(self._targets):
            serial, _, pid = key.rpartition(":")
            try:
                self.detach(serial, int(pid))
            except Exception:                              # noqa: BLE001
                pass
        with self._lock:
            self._targets.clear()   # 进程要退出了，墓碑没有意义

    # ---------- 查询 ----------

    def state(self) -> dict:
        """把"现在能干什么"一次答清楚（AI 一次调用即可判断要不要 resume）。

        (1) 第一次修改
        bug 原因：原返回只有 breakpoints 与 hits 计数，AI 判断不出目标是在跑、
                  在等放行，还是已经断开；也看不出有没有没取走的事件。
        解决方案：每个目标补 state / dbg_state / pending_events / last_seq，
                  顶层补 seq（当前全局序号，AI 用它做增量拉取的水位线）。
        """
        with self._lock:
            for tgt in self._targets.values():
                if tgt.state != STATE_DETACHED:
                    self._sync_hits(tgt)   # 只读同步，不推进 poll 游标
            targets = []
            for tgt in self._targets.values():
                targets.append({
                    "key": tgt.key,
                    "serial": tgt.serial,
                    "pid": tgt.pid,
                    "state": tgt.state,
                    "dbg_state": _dbg_state(tgt.dbg),
                    "pending_events": self._pending_locked(tgt),
                    "last_seq": tgt.polled_seq,
                    "breakpoints": list(tgt.breakpoints.values()),
                    "hits": len(_dbg_hits(tgt.dbg)),
                    # (21) 第二十一次修改（2026-11-16）：透出还有几个自动放行
                    #      定时器在等。调用方据此判断"我现在不管它安全吗"。
                    "auto_resume_pending": sum(
                        1 for (k, _t) in self._auto_resume if k == tgt.key),
                })
            return {"targets": targets, "seq": self._seq}

    def list_breakpoints(self) -> list[dict]:
        """列出全部断点，并标出**重复登记**（同一运行时地址多条记录）。

        (20) 为什么标出来：别名写法曾让同一块内存出现多条记录，
             删一条另一条残留。现在 bp_id 已改用规范名，但**旧记录可能还在**，
             调用方需要能看到并清理。
        """
        with self._lock:
            all_bps = [dict(bp) for tgt in self._targets.values()
                       for bp in tgt.breakpoints.values()]

        # 统计每个运行时地址出现几次（只统计能算出来的）
        count: dict[int, int] = {}
        for bp in all_bps:
            rt = int(bp.get("runtime_addr") or -1)
            if rt > 0:
                count[rt] = count.get(rt, 0) + 1

        for bp in all_bps:
            rt = int(bp.get("runtime_addr") or -1)
            if rt > 0 and count.get(rt, 0) > 1:
                bp["duplicate"] = True
                bp["duplicate_note"] = (
                    f"该运行时地址有 {count[rt]} 条断点记录（别名写法导致），"
                    "建议 remove_breakpoint 掉多余的")
        return all_bps

    def modules(self, serial: str, pid: int, keyword: str = "") -> list[dict]:
        tgt = self.attach(serial, pid)
        mods = tgt.rb.refresh_modules()
        kw = keyword.lower()
        return [
            {"name": m.name, "base": hex(m.base), "size": hex(m.size), "path": m.path}
            for m in mods
            if not kw or kw in m.name.lower()
        ][:200]

    # ---------- 断点 ----------

    def set_breakpoint(self, serial: str, pid: int, so_name: str,
                       static_addr: int, hold: bool = False,
                       auto_resume_after_ms: int = 0) -> dict:
        """下断点并持有它的脚本，返回断点 id（同一地址重复下返回既有 id）。

        (11) 第十一次修改（2026-11-06）：增加 **4 字节对齐校验**。
            bug 原因：AArch64 是**定长指令集**，所有指令必须 4 字节对齐、
                      且低 2 位恒为 0。原来对 static_addr 不做任何校验，
                      在 0x5bc49 这种地址下断点会返回 set=True（看起来成功），
                      但这块内存根本不是一个指令起点，断点必然永远不命中——
                      用户会以为是"断点失效"或"代码没执行"，属于最难排查的一类假成功。
            解决方案：下断点前校验 `static_addr % 4 == 0`，不满足直接抛 BAD_ALIGNMENT，
                      把问题挡在最前面。硬断点（BRK 指令）和 Interceptor 都受此约束。

        (21) 第二十一次修改（2026-11-16）：新增 auto_resume_after_ms。
            bug 原因：hold=True 之后如果调用方忘了 resume，被挂住的线程会一直阻塞
                      在 JS 的 recv().wait() 里，目标进程最终被系统 ANR 杀掉。
                      这不是"用错了"就能避免的——AI 可能一次下十几个 hold 断点，
                      中间被别的调用打断，忘掉一两个是常态；
                      而且 commit 里已有先例（debugger.py 里那条"永久挂起且没有
                      任何 API 能救，只能杀进程"的注释）。
            解决方案：hold 且给了 auto_resume_after_ms>0 时，在**每个命中**上起一个
                      守护定时器；到点自动调 resume() 放行，并在事件流里写一条
                      `auto_resumed`（绝不静默自动放行，否则用户会看不懂
                      "我没调 resume 为什么它自己跑了"）。
                      边界处理：
                        ① 手动 resume 成功的同一次放行会取消对应定时器，
                           不会重复 post（重复 post 会让 JS 侧收到不存在的 token）。
                        ② 定时器到点时目标已不是 paused / 已 detach → 定时器
                           自己退出并记 `auto_resume_skipped`，不报假成功。
                        ③ 同一个 token 只登记一次（_sync_hits 可能重复扫描）。
                        ④ detach_target 时清空全部定时器，避免对已关闭会话 post。
            返回里标 auto_resume_ms（0 表示不自动放行）。
        """
        try:
            auto_ms = int(auto_resume_after_ms or 0)
        except (TypeError, ValueError) as exc:
            raise DynError("BAD_REQUEST",
                           "auto_resume_after_ms 必须是毫秒整数") from exc
        if auto_ms < 0:
            raise DynError("BAD_REQUEST", "auto_resume_after_ms 不能为负数")
        if auto_ms > 0 and not hold:
            # 不 hold 就没有线程被挂住，自动放行没有意义。这里**不静默忽略**——
            # 静默会让调用方以为自己受到了保护，实际没有。
            raise DynError(
                "BAD_REQUEST",
                f"auto_resume_after_ms={auto_ms} 需要 hold=True；"
                "hold=False 时命中即继续，没有线程需要放行")
        if int(static_addr) % 4 != 0:
            raise DynError(
                "BAD_ALIGNMENT",
                f"断点地址 {int(static_addr):#x} 不是 4 字节对齐；"
                "AArch64 是定长指令集，指令起点必须 4 字节对齐，"
                f"最近的合法地址是 {int(static_addr) - int(static_addr) % 4:#x} "
                f"或 {int(static_addr) - int(static_addr) % 4 + 4:#x}")
        # (20) 先解析模块，拿到运行时真实名——bp_id 必须用它，
        #      否则别名写法会各造一条记录（同一块内存对应多个 bp_id）。
        tgt = self.attach(serial, pid)
        try:
            _mod = self._require_module(tgt, so_name)
            _canon = getattr(_mod, "name", "") or so_name
            _runtime = tgt.rb.to_runtime(int(static_addr), _mod)
        except Exception:                                 # noqa: BLE001
            # 模块解析失败：保持旧行为，让后续流程给出明确的 MODULE_NOT_LOADED
            _canon = so_name
            _runtime = None

        bp_id = f"{serial}:{pid}:{_canon}:{static_addr:x}"   # 不含 '#'，可直接进 URL
        # (14) 第十四次修改（2026-11-13）：
        # bug 原因：旧实现在**下发 policy 之前**就早退——只要 bp_id 已在断点表里
        #          就直接 `return {...记录, existing: True}`。于是「先 hold=False
        #          下断点，再 hold=True 调一次」返回的仍是 hold=False，而且真正的
        #          `dbg.set_breakpoint(policy="hold")` 从未执行过，debugger 侧的
        #          hooks 表里那条记录还是 resume。使用者实测报
        #          「set_breakpoint(hold=true) 返回 hold: false」，命中也照跑不停，
        #          属于**静默的策略失效**：接口说成了，实际没成。
        # 解决方案：早退只保留给「hold 值与记录相同」的情形（保持幂等，不重复下钩）；
        #          值不同则继续往下走，重新向 debugger 下发 policy，成功后才把新
        #          hold 写回记录并返回，返回的 hold 恒为最终生效值。
        #          下发失败时抛 BREAKPOINT_FAILED，记录保持旧值，不装成功。
        # (26) 第二十六次修改（2026-11-26）
        # bug 原因：按运行时地址复用旧别名断点并改策略写入新规范 bp_id 时，未删除旧别名键，
        #           导致 tgt.breakpoints 中同时残留旧别名与新规范名两条重复记录。
        # 解决方案：复用旧记录时记下 old_bid，落库新 bp_id 时一并 pop(old_bid, None)。
        old_bid: str | None = None
        with self._lock:
            rec = tgt.breakpoints.get(bp_id)
            # (20) 别名防护：bp_id 用规范名后，正常情况不会再有同址多条记录。
            #      但为兼容**旧版本留下的记录**（它们用的是别名拼的 bp_id），
            #      这里再按运行时地址查一次，命中就复用。
            if rec is None and _runtime is not None:
                for _bid, _rec in tgt.breakpoints.items():
                    if int(_rec.get("runtime_addr") or -1) == int(_runtime):
                        rec = _rec
                        old_bid = _bid
                        break
        if rec is not None and bool(rec.get("hold")) == bool(hold):
            # (21) 第二十一次修改（2026-11-16）：幂等早退也要处理自动放行---
            #      早退只针对"钩子不用重下"，但 auto_resume_ms 是记录上的策略，
            #      调用方这次改了这个值就必须落库，否则返回的那个数会骗人。
            if auto_ms != int(rec.get("auto_resume_ms") or 0):
                with self._lock:
                    rec["auto_resume_ms"] = auto_ms
                self._emit(tgt, "breakpoint_policy", bp_id=bp_id,
                           so_name=so_name, static_addr=static_addr,
                           hold=bool(hold), auto_resume_ms=auto_ms)
            return {**rec, "existing": True, "policy_changed": False,
                    "auto_resume_ms": int(rec.get("auto_resume_ms") or 0)}
        mod = self._require_module(tgt, so_name)
        runtime_addr = tgt.rb.to_runtime(static_addr, mod)
        # (10) 第十次修改（2026-11-06）：
        # bug 原因：下断点时把**用户传入的本地名**（sg_real.so）传给 debugger，
        #          而 debugger 内部又用它去 rb.find_module 二次解析；名字对不上时
        #          即使 service 层已经靠指纹找到了模块，debugger 那一步照样失败，
        #          最终报 BREAKPOINT_FAILED。
        # 解决方案：把**解析出来的真实运行时模块名**传下去（mod.name），
        #          保证 debugger 侧一定能找到同一个模块。断点记录里同时保留
        #          原始名，方便用户按自己习惯的名字检索。
        real_name = getattr(mod, "name", so_name) or so_name
        ok = tgt.dbg.set_breakpoint(real_name, static_addr,
                                    policy="hold" if hold else "resume")
        if not ok:
            raise DynError("BREAKPOINT_FAILED", f"{so_name}+{static_addr:#x} 下断点失败")

        # 假成功防护：debugger 说 ok 不代表钩子真的在那个模块上。
        # 用运行时真实地址反查一次钩子表，确认不到就不许报成功。
        # 只在 debugger 真的维护钩子表时校验（fake/mock 实现没有这张表，
        # 不能因此把它们判成假成功——那会把单元测试全打挂）
        hooks = getattr(tgt.dbg, "_hooks", None)
        if hooks is not None and runtime_addr not in hooks:
            # 列出名字相近的模块，直接告诉调用方该用哪个名字
            want = so_name.rsplit("/", 1)[-1].lower().replace("lib", "").replace(".so", "")
            cands = []
            for m in getattr(tgt.rb, "_modules", []) or []:
                nm = getattr(m, "name", "") or ""
                if want and want in nm.lower().replace("lib", ""):
                    cands.append(nm)
            hint = ("；进程内相近的模块：" + "、".join(sorted(set(cands))[:6])) if cands else ""
            raise DynError(
                "MODULE_NOT_LOADED",
                f"{so_name} 在进程里找不到对应模块，钩子未真正安装（拒绝假成功）{hint}")
        # (13) 第十三次修改（2026-11-06）：断点记录补 mechanism / armed。
        #     为什么：调用方只能看到 set=True，既不知道这次下断用的是哪种机制，
        #             也分不清"请求被接受"与"钩子真的装上"。verify_breakpoint
        #             这类工具正需要这两个字段做判断。
        #     mechanism 必须如实反映实现：目前 dyn/debugger.py 只有 Interceptor
        #     一种路径（Interceptor.attach），hw_breakpoint（硬件断点）与
        #     soft_bp（BRK 指令软断点）**都尚未实现**，因此这里固定 "Interceptor"。
        #     将来若新增机制，须由 debugger 回报真实值，不能在此处猜。
        #     armed 恒为 True：能走到这一行说明 dbg.set_breakpoint 已返回 ok=True
        #     （否则上面已 raise BREAKPOINT_FAILED），即钩子安装请求成功。
        bp = {
            **(rec or {}),          # 已存在的断点：保留原记录字段，只更新本次改的
            "id": bp_id,
            "serial": serial,
            "pid": pid,
            # (20) so_name 用规范名（与 bp_id 一致），original_name 保留调用方写法
            "so_name": _canon,
            "original_name": so_name,
            "static_addr": static_addr,
            "runtime_addr": runtime_addr,
            "hold": bool(hold),
            "mechanism": BREAKPOINT_MECHANISM,
            "armed": True,
            # (21) 自动放行毫秒数（0=不自动放行）。记录里保留，命中时按它起定时器。
            "auto_resume_ms": auto_ms,
        }
        with self._lock:
            if old_bid is not None and old_bid != bp_id:
                tgt.breakpoints.pop(old_bid, None)
            tgt.breakpoints[bp_id] = bp
        # 已有断点只是改策略时，事件类型仍是 breakpoint_set（钩子与记录都还在），
        # 但带上 policy_changed=True，让事件流能区分"新下断"与"改了 hold"。
        self._emit(tgt, "breakpoint_set", bp_id=bp_id, so_name=so_name,
                   static_addr=static_addr, hold=bool(hold),
                   mechanism=BREAKPOINT_MECHANISM, armed=True,
                   policy_changed=rec is not None,
                   auto_resume_ms=auto_ms)
        return {**bp, "existing": rec is not None,
                # 记录本来就有、只是这次把 hold 改了：明确告知调用方策略被重下发，
                # 避免把"改了策略"误读成"重复下断被忽略"。
                "policy_changed": rec is not None,
                "auto_resume_ms": auto_ms}

    def remove_breakpoint(self, bp_id: str) -> dict:
        """撤销断点：真的调 debugger 的撤销接口，撤不掉就如实说 partial。

        (1) 第一次修改
        bug 原因：原实现只从内存表里 pop 掉记录，frida 侧 Interceptor 仍在，
                  断点照样命中，函数却返回 True——AI 会以为已经撤掉了。
        解决方案：优先调用 dbg.remove_breakpoint(so_name, static_addr)（真撤销）；
                  该方法不存在时降级为"只删记录"并在返回里标 partial=True +
                  中文说明；debugger 明确返回失败时保留记录、返回 removed=False，
                  不装成功。
        """
        with self._lock:
            hit = None
            for tgt in self._targets.values():
                if bp_id in tgt.breakpoints:
                    hit = (tgt, tgt.breakpoints[bp_id])
                    break
            # (20) 按 bp_id 没找到时，尝试从 bp_id 里解出 (so, addr) 反查：
            #      防止调用方拿着旧写法（别名/带版本号）的 bp_id 删不掉。
            if hit is None:
                try:
                    _parts = str(bp_id).rsplit(":", 2)
                    if len(_parts) == 3:
                        _so = _parts[1]
                        _addr = int(_parts[2], 16)
                        for tgt in self._targets.values():
                            for _bid, _rec in tgt.breakpoints.items():
                                if (int(_rec.get("static_addr") or -1) == _addr
                                        and (str(_rec.get("so_name")) == _so
                                             or str(_rec.get("original_name")) == _so)):
                                    hit = (tgt, _rec)
                                    break
                            if hit:
                                break
                except Exception:                         # noqa: BLE001
                    pass
        if hit is None:
            # 老接口返回 False 表示"没有这个断点"；这里不抛异常，保持可预期
            return _result("removed", {"id": bp_id, "removed": False,
                                       "partial": False, "reason": "not_found",
                                       "message": f"断点 {bp_id} 不存在"})
        # (27) 第二十七次修改（2026-11-26）
        # bug 原因：按别名反查命中后，删除记录仍用传入的别名 bp_id 而非实际存储键 bp["id"]，
        #           导致真实记录留在 tgt.breakpoints 中删不掉。
        # 解决方案：统一按实际键 real_id = bp.get("id") or bp_id 删除（若与别名不同则两者一并清理）。
        tgt, bp = hit
        real_id = str(bp.get("id") or bp_id)
        fn = getattr(tgt.dbg, "remove_breakpoint", None)
        if not callable(fn):
            # 降级：脚本侧无法单点撤销，只能删记录（等重建会话时才真正消失）
            with self._lock:
                tgt.breakpoints.pop(real_id, None)
                if real_id != bp_id:
                    tgt.breakpoints.pop(bp_id, None)
            self._emit(tgt, "breakpoint_removed", bp_id=real_id,
                       partial=True, reason="debugger_no_unhook")
            return _result("removed", {
                "id": real_id,
                "removed": True,
                "partial": True,
                "reason": "debugger_no_unhook",
                "message": ("当前 debugger 没有 remove_breakpoint()，已删除记录但 "
                            "frida 侧 hook 仍在：该地址仍会命中，彻底撤销需 detach 后重新 attach"),
            })
        try:
            raw = fn(bp["so_name"], bp["static_addr"])
        except Exception as exc:                          # noqa: BLE001 - frida 异常类型不稳定
            raise DynError("REMOVE_FAILED",
                           f"撤销 {bp['so_name']}+{bp['static_addr']:#x} 失败：{exc}") from exc
        # 兼容 debugger 的三种返回：False/None/True 或 {"removed"/"ok": bool}。
        # 只有明确 False 才算失败，None 按成功处理（frida 侧常见"无返回值"）。
        if isinstance(raw, dict):
            ok = bool(raw.get("removed", raw.get("ok", True)))
        else:
            ok = True if raw is None else bool(raw)
        if not ok:
            # 记录保留：hook 还在，删了记录就等于骗人
            self._emit(tgt, "breakpoint_remove_failed", bp_id=real_id,
                       reason="debugger_rejected")
            return _result("removed", {
                "id": real_id,
                "removed": False,
                "partial": False,
                "reason": "debugger_rejected",
                "message": "debugger 拒绝撤销，断点记录已保留（hook 仍生效）",
            })
        with self._lock:
            tgt.breakpoints.pop(real_id, None)
            if real_id != bp_id:
                tgt.breakpoints.pop(bp_id, None)
        self._emit(tgt, "breakpoint_removed", bp_id=real_id,
                   partial=False, reason="")
        return _result("removed", {"id": real_id, "removed": True,
                                   "partial": False, "reason": ""})

    # ---------- 事件 / 命中 ----------

    def poll_events(self, serial: str, pid: int, timeout: float = 0.0,
                    limit: int = 200, after_seq: int | None = None) -> list[dict]:
        """取事件：非阻塞优先（timeout=0 立即返回，没有就空列表）。

        每条事件固定带 type / seq / ts（秒级 time.time），外加 key/serial/pid
        与事件自身字段（如 breakpoint_hit 带 so_name/static_addr/context/backtrace）。

        after_seq 三档语义：
            None（默认）→ 从本目标的游标继续取，只给"没取过的新事件"；
            0           → 显式从头重放（排查现场用）；
            N           → 只要 seq > N（AI 说"给我 seq > 100 的事件"）。

        (1) 第一次修改
        bug 原因：原来只有阻塞的 wait_hits，AI 想"看一眼有没有新命中"就得赌超时，
                  多个目标时更没法轮流看。
        解决方案：新增本方法取代阻塞模型——先查已有事件，timeout>0 才轮询等待；
                  seq 全局自增且单调，AI 用它判断"有没有新事件"。
        (2) 第二次修改
        bug 原因：after_seq 默认 0，于是"不带参数再 poll 一次"会把取过的事件
                  又吐一遍，游标形同虚设（自测里连续 poll 拿到 seq 1,2,3 重复）。
        解决方案：默认改成 None = 用该目标的 polled_seq 游标；要重放必须显式传 0。
        """
        tgt = self._target(serial, pid)
        try:
            limit = int(limit)
            wait_s = max(float(timeout or 0.0), 0.0)
        except (TypeError, ValueError) as exc:
            raise DynError("BAD_REQUEST", "timeout/limit/after_seq 类型不对") from exc
        if not (1 <= limit <= 1000):
            raise DynError("BAD_REQUEST", "limit 必须在 1..1000")
        try:
            floor = tgt.polled_seq if after_seq is None else max(int(after_seq), 0)
        except (TypeError, ValueError) as exc:
            raise DynError("BAD_REQUEST", "after_seq 必须是整数") from exc
        deadline = time.monotonic() + wait_s
        # 显式给了 after_seq 属于"只读回溯"，不该改变增量水位线
        advance = after_seq is None
        while True:
            self._sync_hits(tgt)                 # dbg.hits -> 事件队列
            events = self._collect(tgt, floor, limit, advance=advance)
            if events:
                return events
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []                        # timeout=0 时到这里立即返回
            time.sleep(min(_POLL_INTERVAL, remaining))

    def wait_hits(self, serial: str, pid: int, timeout: float = 10.0) -> list[dict]:
        """阻塞等待断点命中（老接口，保持"返回该目标全部命中"的既有语义）。

        (1) 第一次修改
        bug 原因：原实现直接调 dbg.wait_hits 死等，AI 被卡住；且命中存在
                  debugger 内部，与事件队列是两份数据，容易对不上。
        解决方案：内部走 poll_events（非阻塞优先 + 超时等待）把事件补齐，
                  再统一由 hits() 返回全部命中列表，老调用方无需改动。
        """
        self.poll_events(serial, pid, timeout=timeout, limit=200)
        return self.hits(serial, pid)

    def hits(self, serial: str, pid: int) -> list[dict]:
        tgt = self._target(serial, pid)
        return [_hit_dict(h) for h in _dbg_hits(tgt.dbg)]

    # (28) 第二十八次修改（2026-11-26）
    # bug 原因：上层 MCP 工具直接读取私有字段 svc._events / dbg._hits / dbg._events
    #           缺少线程锁保护且容易破坏内部状态（如游标或挂起 token）。
    # 解决方案：提供线程安全的只读快照 snapshot_events() 与安全清理 clear_target_hits()，
    #           不推进 poll 游标且清理前按需先放行挂起线程。
    def snapshot_events(self, serial: str = "", pid: int = 0) -> list[dict]:
        """线程安全地返回事件队列只读快照（不推进任何目标的 poll 游标）。"""
        want_serial = str(serial or "").strip()
        want_pid = int(pid or 0)
        want_key = f"{want_serial}:{want_pid}" if (want_serial and want_pid) else ""
        with self._lock:
            targets_to_sync = []
            for tgt in self._targets.values():
                if tgt.state == STATE_DETACHED:
                    continue
                if want_key and tgt.key != want_key:
                    continue
                if want_serial and not want_pid and tgt.serial != want_serial:
                    continue
                if want_pid and not want_serial and tgt.pid != want_pid:
                    continue
                targets_to_sync.append(tgt)
        for tgt in targets_to_sync:
            self._sync_hits(tgt)
        with self._lock:
            out: list[dict] = []
            for ev in self._events:
                if want_key and ev.get("key") != want_key:
                    continue
                if want_serial and not want_pid and ev.get("serial") != want_serial:
                    continue
                if want_pid and not want_serial and ev.get("pid") != want_pid:
                    continue
                out.append(dict(ev))
            return out

    def clear_target_hits(self, serial: str, pid: int,
                          release_held: bool = True) -> dict:
        """线程安全地清空指定目标的命中缓存（不影响已下断点与单调序号）。"""
        tgt = self._target(serial, pid)
        dbg = getattr(tgt, "dbg", None)
        resumed = None
        if release_held:
            need_resume = (tgt.state == STATE_PAUSED
                           or _dbg_state(dbg) == STATE_PAUSED
                           or bool(getattr(dbg, "_pending_tokens", None)))
            if need_resume:
                resumed = self.resume(serial, pid)
        cleared = 0
        clear_fn = getattr(dbg, "clear_hits", None)
        if callable(clear_fn):
            cleared = int(clear_fn() or 0)
        else:
            dbg_lock = getattr(dbg, "_lock", None)
            if dbg_lock is not None:
                with dbg_lock:
                    hits_obj = getattr(dbg, "_hits", None)
                    if hits_obj is not None and hasattr(hits_obj, "clear"):
                        cleared = len(hits_obj)
                        hits_obj.clear()
                    ev_obj = getattr(dbg, "_events", None)
                    if ev_obj is not None and hasattr(ev_obj, "clear"):
                        ev_obj.clear()
            else:
                hits_obj = getattr(dbg, "_hits", None)
                if hits_obj is None:
                    raw_hits = getattr(dbg, "hits", None)
                    if isinstance(raw_hits, list):
                        hits_obj = raw_hits
                if hits_obj is not None and hasattr(hits_obj, "clear"):
                    cleared = len(hits_obj)
                    hits_obj.clear()
                ev_obj = getattr(dbg, "_events", None)
                if ev_obj is not None and hasattr(ev_obj, "clear"):
                    ev_obj.clear()
        with self._lock:
            tgt.hit_cursor = 0
            # 移除该目标旧的 breakpoint_hit 事件，避免 poll_events(after_seq=0) 或 timeline 翻出旧命中
            kept = deque(
                (ev for ev in self._events
                 if not (ev.get("key") == tgt.key and ev.get("type") == "breakpoint_hit")),
                maxlen=self._events.maxlen,
            )
            self._events = kept
        out: dict = {
            "ok": True,
            "cleared": cleared,
            "note": "只清命中记录，断点仍然有效",
        }
        if resumed is not None:
            out["resumed_before_clear"] = dict(resumed) if isinstance(resumed, dict) else resumed
        return out

    def timeline(self, serial: str, pid: int, duration: float = 10.0,
                 limit: int = 500) -> dict:
        """把**断点命中 + 事件流**合并成一条按时间排序的统一时间线。

        (21) 第二十一次修改（2026-11-16）：新增。
            解决什么问题：同时 hook 好几个点（不同 so 的不同地址）时，
            事件分散在 hits 与 poll_events 两个来源里，只能靠人拿 ts 手动
            对齐；而 ts 是各自打印的墙钟，误差几十毫秒，根本分不出先后。

        ## 精度从哪来，能到多少（真机实测，不猜）

        所有时间戳的来源是**设备侧 frida 消息到达 Python 的那一刻**
        （debugger._on_message 里的 BreakpointHit.ts 就是 time.time()），
        真实**命中时刻在设备侧**，两者之间隔着一次 IPC。因此：

          · 设备侧单调时钟本身的分辨率约 **6µs**（CLOCK_MONOTONIC 实测），
            不是瓶颈；
          · 真正的误差是**设备→主机的单向传输延迟**，实测一次 frida RPC
            往返中位数 **2.8ms**（p90 4.6ms，最大 13.9ms），单向约 **1.4ms**；
          · 命中载荷比一次空 RPC 大（36 个寄存器 + 24 帧 + 256 字节栈），
            所以实际单向误差按 **~2ms** 估计是稳妥的。

        结论：**同一条时间线上的相对间隔可信到毫秒级（约 ±2ms 量级），
        不是"几十毫秒"。** 但两个**不同来源**（断点命中 vs 内存写入）
        之间还多一层，见下。

        ## 排序用的键：单调时钟，不是墙钟

        所有事件先按 ts（墙钟秒）收集，再按 (ts, seq) 排序。墙钟会被 NTP
        校时，但同一台主机的两次 time.time() 之间若发生跳变，间隔会变成
        负数——这里用 time.monotonic() 做一次**合理性校正**：
        详见 _order_events 的说明。**不假装纳秒级精确**，返回里一律标 precision。

        参数：
            duration  只取"最后 duration 秒"内的命中（0/负数 = 不按时间过滤）。
                      为什么要有它：hits 缓冲保留最近 2000 条，长会话里
                      最早的那些和当前操作无关，混进来会把时间轴撑得很长。
            limit     最多返回多少条（按时间取最新的 limit 条）。

        返回：见 _build_timeline。
        """
        tgt = self._target(serial, pid)
        # 先把还没转成事件的命中同步进来（不推进 poll 游标，纯只读）
        self._sync_hits(tgt)
        hits = [_hit_dict(h) for h in _dbg_hits(tgt.dbg)]
        events = [dict(ev) for ev in self._events if ev.get("key") == tgt.key]
        return _build_timeline(tgt, hits, events,
                               duration=float(duration or 0.0),
                               limit=int(limit or 500))

    def hit_count_for(self, serial: str, pid: int, so_name: str = "",
                      static_addr: int = -1) -> dict:
        """按 (static_addr[, so_name]) 统计某个目标的命中次数（只读）。

        给 dyn/tracer.py 的 verify_breakpoint 用：它需要回答"这个断点到底进没进过"，
        而 bp_id 在 debugger 侧没有对应关系，只能靠静态地址回查命中缓存。

        (13) 第十三次修改（2026-11-06）：新增本方法。
             为什么：verify_breakpoint 早先自己摸 svc._targets 再拼地址字符串
                     （`int(bp_id.rsplit(":", 1)[-1], 16)`）来算命中数，
                     既依赖私有字段、又把"取 bp_id 里的地址"这种易错解析
                     散在调用方。收敛到这里，签名稳定、只读、不建立新会话。

        参数：
            so_name      非空时除地址外再按模块名过滤；为空则只按地址统计
            static_addr  >= 0 按地址精确匹配；< 0 表示"不按地址过滤"（统计全部）

        返回：
            ok=False 只有一种原因——该目标当前未 attach（或已 detach），
            此时 hits 为 None，并给出中文 reason；**不返回 0 冒充"没命中过"**，
            因为"取不到"与"确实是 0 次"是两件不同的事。
            discarded 取 debugger 的 _hits_discarded（因保留上限被丢弃的旧命中数），
            debugger 没提供时为 None（表示"不知道"，同样不编 0）。
        """
        tgt = self._targets.get(f"{serial}:{pid}")
        # 已 detach 的墓碑不能当活会话：dbg 已关闭，命中缓存不再有意义
        if tgt is None or tgt.state == STATE_DETACHED:
            return {"ok": False, "code": "NOT_ATTACHED", "hits": None,
                    "reason": "该目标当前未 attach"}
        dbg = getattr(tgt, "dbg", None)
        if dbg is None:
            return {"ok": False, "code": "NOT_ATTACHED", "hits": None,
                    "reason": "该目标当前未 attach（debugger 不可用）"}
        all_hits = _dbg_hits(dbg)
        want_addr = int(static_addr)
        want_so = (so_name or "").strip()

        def _match_so(h) -> bool:
            """命中记录的模块名是否与请求的一致（全路径或 basename 任一匹配）。"""
            h_so = getattr(h, "so_name", "") or ""
            if not want_so:
                return True
            return h_so == want_so or h_so.rsplit("/", 1)[-1] == want_so

        cnt = 0
        addr_only = 0
        so_matched = 0
        for h in all_hits:
            # 地址优先：<0 表示不按地址过滤，只按模块名
            if want_addr >= 0:
                try:
                    if int(getattr(h, "static_addr", -1)) != want_addr:
                        continue
                except (TypeError, ValueError):
                    continue
                addr_only += 1
            if want_so and not _match_so(h):
                continue
            so_matched += 1
            cnt += 1

        # (15) 第十五次修改（2026-11-06）：
        #      bug 原因：调用方传的常常是**本地文件名**（sg_real.so），而命中缓存里
        #                记的是**设备上的真实模块名**（libsgmainso-6.7.260202.so），
        #                两者字符串对不上 → 明明有命中却统计成 0，
        #                看起来像"断点没命中"，实际是过滤条件把结果筛没了。
        #      解决方案：模块名一条都没匹配上、但按地址**确有**命中时，
        #                退回到"只按地址"的计数，并用 so_name_matched=false
        #                如实标注"这次统计没有按模块名过滤"，
        #                让调用方知道这个数的口径，而不是被一个 0 误导。
        used_addr_only = False
        if want_so and so_matched == 0 and addr_only > 0:
            cnt = addr_only
            used_addr_only = True

        out = {
            "ok": True,
            "hits": cnt,
            "total_hits": len(all_hits),
            # getattr 兜底：debugger 没有该字段时给 None（"不知道"），不伪造 0
            "discarded": getattr(dbg, "_hits_discarded", None),
        }
        if want_so:
            out["so_name_matched"] = not used_addr_only
            if used_addr_only:
                out["match_note"] = (
                    f"命中缓存里没有模块名为 {want_so!r} 的记录，"
                    "已退回到只按地址统计；若同时存在多个 so 的同一偏移，"
                    "这个数可能包含它们")
        return out

    # ---------- 放行 ----------

    # (29) 第二十九次修改（2026-11-26）
    # bug 原因：① 原实现未先同步命中/核对 debugger 真实状态，若调用方未先 poll 便直接
    #             resume，即使目标已 paused 也会误报 not_paused 拒绝放行；
    #           ② L771 误写 getattr(dbg, "state", "") 触发 NameError（应为 tgt.dbg）；
    #           ③ 自动放行触发时无条件全量放行，可能越权唤醒其他无关断点的挂起线程。
    # 解决方案：① 检查 paused 前先同步 _sync_hits 并核对 _dbg_state(tgt.dbg)；
    #           ② 修正 tgt.dbg 引用；
    #           ③ 支持可选 token 参数，优先走 dbg.resume_token(token) 或 dbg.resume(token=token)
    #              精准放行单个挂起线程，其余挂起线程仍保持 paused 与各自定时器。
    def resume(self, serial: str, pid: int, token: str | None = None) -> dict:
        """放行 paused 的目标；未 paused 时如实回 not_paused。

        (1) 第一次修改
        bug 原因：原实现无论如何都 return True，目标根本没 paused 也报"已放行"，
                  AI 无法判断到底有没有线程真的在等它。
        解决方案：只有 state==paused 才真放行；否则返回
                  {"resumed": False, "reason": "not_paused"}，不装成功。
        """
        tgt = self._target(serial, pid)
        if tgt.state != STATE_PAUSED:
            self._sync_hits(tgt)
        with self._lock:
            if tgt.state != STATE_PAUSED:
                if tgt.state != STATE_DETACHED and _dbg_state(tgt.dbg) == STATE_PAUSED:
                    tgt.state = STATE_PAUSED
                else:
                    return _result("resumed", {"resumed": False, "reason": "not_paused",
                                               "state": tgt.state})
        fn = getattr(tgt.dbg, "resume", None)
        fn_token = getattr(tgt.dbg, "resume_token", None) if token else None
        if not callable(fn) and not callable(fn_token):
            raise DynError("NOT_IMPLEMENTED", "当前 debugger 未提供 resume()")
        # (3) 第三次修改（2026-11-02）：必须尊重 debugger 的放行结果。
        #     bug 原因：旧实现 fn() 之后无条件写 {"resumed": True}，把 debugger
        #               返回的 {"resumed": False, ...} 直接丢弃。debugger 明确拒绝
        #               放行时 service 却报成功，调用方以为线程已恢复、实际仍卡在
        #               recv().wait() 里——假成功，且掩盖了"线程永久挂起"的现场。
        #               这正是本文件头注释第 ④ 条要消灭的行为。
        #     解决方案：把 fn() 的返回值当作事实来源，支持 bool / dict 两种形态；
        #               明确拒绝时保持 paused 状态并原样上报原因，不谎报成功。
        single_token = False
        try:
            if token and callable(fn_token):
                single_token = True
                raw = fn_token(token)
            elif token and callable(fn) and _accepts_token_arg(fn):
                single_token = True
                raw = fn(token=token)
            else:
                raw = fn()
        except Exception as exc:                          # noqa: BLE001 - frida 异常类型不稳定
            raise DynError("RESUME_FAILED", f"放行 {tgt.key} 失败：{exc}") from exc

        ok, detail = _resume_verdict(raw)
        if not ok:
            # 没放行成功：状态保持 paused（线程可能仍挂住），如实上报
            with self._lock:
                still = tgt.state
            self._emit(tgt, "resume_failed", reason=detail or "debugger_rejected")
            return _result("resumed", {"resumed": False,
                                       "reason": detail or "debugger_rejected",
                                       "state": still})

        # (7) 第七次修改（2026-11-05）：以 debugger 返回的**真实状态**为准，
        #     不再只凭一个 True 就置 attached。
        #     bug 原因：部分线程 post 失败时 resumed=True 但 state 仍 paused、
        #               _pending_tokens 非空；此时若标成 attached，那些线程会
        #               永久阻塞在 recv().wait()，而调用方以为已经在跑。
        #     解决方案：failed>0 或 state=='paused' 一律判为"部分放行失败"：
        #               状态保持 paused，返回 resumed=False 并透出剩余数量，
        #               调用方可再次 resume 或据此排查。
        facts = _resume_facts(raw)
        if single_token:
            # 单 token 精准放行：仅当 failed>0 才算部分失败；
            # 若 state 仍为 paused（其他无关线程仍挂起），则保持 paused 但本次 token 放行成功。
            if facts.get("failed", 0) > 0:
                with self._lock:
                    cur = tgt.state
                if cur != STATE_PAUSED and str(getattr(tgt.dbg, "state", "")) == "paused":
                    cur = STATE_PAUSED
                    with self._lock:
                        tgt.state = STATE_PAUSED
                self._emit(tgt, "resume_partial", reason="token_resume_failed")
                return _result("resumed", {
                    "resumed": False,
                    "reason": "partial_resume",
                    "state": cur,
                    "failed": facts.get("failed", 0),
                    "woken": facts.get("woken", 0),
                    "pending": facts.get("pending"),
                })
            still_held = (facts.get("state") == "paused")
            with self._lock:
                if tgt.state != STATE_DETACHED:
                    tgt.state = STATE_PAUSED if still_held else STATE_ATTACHED
                state_after = tgt.state
                item = self._auto_resume.pop((tgt.key, str(token)), None)
            if item is not None:
                try:
                    item["timer"].cancel()
                except Exception:                         # noqa: BLE001
                    pass
            self._emit(tgt, "resumed", token=str(token), woken=facts.get("woken"))
            out = {"resumed": True, "reason": "", "state": state_after,
                   "woken": facts.get("woken"), "token": str(token)}
            if still_held:
                out["other_threads_paused"] = True
            return _result("resumed", out)

        still_paused = (facts.get("state") == "paused"
                        or facts.get("failed", 0) > 0)
        if still_paused:
            with self._lock:
                cur = tgt.state
            if cur != STATE_PAUSED and str(getattr(tgt.dbg, "state", "")) == "paused":
                cur = STATE_PAUSED
                with self._lock:
                    tgt.state = STATE_PAUSED
            self._emit(tgt, "resume_partial", reason="some_threads_still_held")
            return _result("resumed", {
                "resumed": False,
                "reason": "partial_resume",
                "state": cur,
                "failed": facts.get("failed", 0),
                "woken": facts.get("woken", 0),
                "pending": facts.get("pending"),
                "detail": ("部分线程未被唤醒，仍阻塞在 recv().wait()；"
                           "状态保持 paused，请再调一次 resume 或检查那些线程"),
            })

        with self._lock:
            tgt.state = STATE_ATTACHED
        # (21) 第二十一次修改（2026-11-16）：手动放行成功 → 取消该目标全部自动放行
        #      定时器。不取消就会在 N 毫秒后再 post 一次，而那时的 token 早已
        #      被消费掉，JS 侧收到一个不存在的 token 只会空转；更糟的是事件流里
        #      会出现一条让人看不懂的 auto_resumed（明明是我手动放的）。
        cancelled = self._cancel_auto_resume(tgt)
        self._emit(tgt, "resumed")
        out = {"resumed": True, "reason": "", "state": tgt.state,
               "woken": facts.get("woken")}
        if cancelled:
            out["auto_resume_cancelled"] = cancelled
        return _result("resumed", out)

    # ---------- 自动放行（hold 的兜底） ----------

    def _schedule_auto_resume(self, tgt: "Target", bp: dict,
                              token: str | None, delay_ms: int) -> bool:
        """为一个被挂住的 token 起守护定时器，到点自动放行。

        (21) 第二十一次修改（2026-11-16）：新增。
            bug 原因：hold=True 忘了 resume，线程永久阻塞在 recv().wait()，
                      目标进程最终 ANR 被杀（debugger.py 里已有同类事故记录）。
            解决方案：每个命中一个 threading.Timer（守护线程），到点调本类的
                      resume()。所有放行逻辑复用 resume()，不另写一套——
                      否则"自动放行"会绕过 R3/R7 那一堆状态机判据，
                      变成第二个真值来源。

        返回是否真的登记了定时器。以下情形**不登记**（都已经没有可放行的东西）：
          · token 为空（debugger 没给 token，说明没挂住，没什么可放）
          · 目标已 detach（墓碑不能复活）
          · 同一个 token 已登记过（_sync_hits 可能重复扫描同一批命中）
        """
        if not token or tgt.state == STATE_DETACHED:
            return False
        key = (tgt.key, str(token))
        with self._lock:
            if key in self._auto_resume:
                return False
            delay_s = max(0.0, float(delay_ms) / 1000.0)
            timer = threading.Timer(delay_s, self._auto_resume_fire,
                                    args=(tgt.key, str(token), tgt))
            timer.daemon = True      # 进程要退出时不阻塞
            timer.name = f"mda-auto-resume-{tgt.key}"
            self._auto_resume[key] = {
                "timer": timer,
                "deadline": time.monotonic() + delay_s,
                "bp_id": (bp or {}).get("id"),
                "ms": int(delay_ms),
            }
        timer.start()
        # 登记成功也要进事件流：用户事后复盘时得看到"这里被自动放行保护过"
        self._emit(tgt, "auto_resume_armed", token=str(token),
                   bp_id=(bp or {}).get("id"), delay_ms=int(delay_ms))
        return True

    def _auto_resume_fire(self, target_key: str, token: str,
                          tgt: "Target") -> None:
        """定时器到点：真的放行，并把结果如实写进事件流。

        (21) 第二十一次修改（2026-11-16）：新增。

        边界（每条都会出现在返回/事件里，不静默）：
          · 用户已经手动 resume 过 → 定时器已被取消，正常走不到这里；
            万一走到（竞态），resume() 会返回 not_paused，事件记 skipped。
          · 到期但目标不再是 paused（例如另一条线程先被放行）→ skipped。
          · 放行本身失败（partial_resume 等）→ 事件记 auto_resume_failed，
            并把 reason 透出；**不重试**（重试会在目标卡死时无限 post）。
        """
        # (30) 第三十次修改（2026-11-26）
        # bug 原因：① target_key.partition(":") 遇到 Wi-Fi ADB "ip:port:pid" 切分失败，
        #             int(pid_text) 抛 ValueError 静默退出，自动放行彻底失效；
        #           ② self.resume(serial, pid) 未传 token，会越权放行其他无关断点的挂起线程。
        # 解决方案：改用 rpartition(":") 正确切分 serial/pid，并透传 token=token 做单 token 精准放行。
        key = (target_key, token)
        with self._lock:
            self._auto_resume.pop(key, None)
        serial, _, pid_text = target_key.rpartition(":")
        try:
            pid = int(pid_text)
        except (TypeError, ValueError):
            return
        if tgt.state == STATE_DETACHED:
            return
        try:
            res = self.resume(serial, pid, token=token)
        except Exception as exc:                          # noqa: BLE001 - 定时器线程不能炸
            self._emit(tgt, "auto_resume_failed", token=token,
                       reason=f"{type(exc).__name__}: {exc}")
            return
        if dict.get(res, "resumed"):
            self._emit(tgt, "auto_resumed", token=token,
                       woken=res.get("woken"),
                       note="命中后到点自动放行（set_breakpoint auto_resume_after_ms）")
        else:
            self._emit(tgt, "auto_resume_skipped", token=token,
                       reason=res.get("reason") or "not_paused",
                       state=res.get("state"))

    def _cancel_auto_resume(self, tgt: "Target") -> int:
        """取消某目标的全部自动放行定时器，返回取消个数。

        (21) 第二十一次修改（2026-11-16）：新增。
            手动 resume / detach / remove_breakpoint 都要清，否则定时器
            事后还会 post 一次（对已关闭会话 post 会抛异常，而它跑在守护线程里，
            异常只会静默打日志，排查起来很难）。
        """
        with self._lock:
            keys = [k for k in self._auto_resume if k[0] == tgt.key]
            items = [self._auto_resume.pop(k) for k in keys]
        for item in items:
            try:
                item["timer"].cancel()
            except Exception:                             # noqa: BLE001
                pass
        return len(items)

    def auto_resume_state(self, serial: str, pid: int) -> dict:
        """只读：该目标还有几个自动放行定时器在等、分别什么时候到点。

        (21) 第二十一次修改（2026-11-16）：新增。
            为什么需要：调用方要能判断"我现在不 resume 安全吗"。
            只报**还剩多久**（剩余毫秒），不泄漏 token 原文。
        """
        key = f"{serial}:{pid}"
        now = time.monotonic()
        with self._lock:
            rows = []
            for (tkey, _tok), item in self._auto_resume.items():
                if tkey != key:
                    continue
                rows.append({"bp_id": item.get("bp_id"),
                             "delay_ms": item.get("ms"),
                             "remaining_ms": max(0, int(
                                 (item["deadline"] - now) * 1000))})
        return {"count": len(rows), "pending": rows}

    # ---------- 内存 ----------

    def read_memory(self, serial: str, pid: int, so_name: str,
                    static_addr: int, size: int = 32) -> dict:
        if not (1 <= size <= 4096):
            raise DynError("BAD_REQUEST", "size 必须在 1..4096")
        tgt = self.attach(serial, pid)
        mod = self._require_module(tgt, so_name)
        runtime = tgt.rb.to_runtime(static_addr, mod)
        data = tgt.rb.read_memory(runtime, size)
        if not data:
            raise DynError("READ_FAILED", f"地址 {runtime:#x} 不可读或超时")
        return {"static_addr": static_addr, "runtime_addr": runtime,
                "hex": data.hex(), "size": len(data)}

    def read_runtime(self, serial: str, pid: int, runtime_addr: int,
                     size: int = 32) -> dict:
        """按**运行时绝对地址**读内存。

        (6) 第六次修改（2026-11-05）：新增。
            bug 原因：原有 read_memory 只接受「静态地址 + so 名」，内部再 base+static
                      换算。但断点命中现场的 x0 / lr / sp 都是**运行时绝对地址**，
                      而且常常指向堆上的对象（不在任何 so 里），
                      调 read_memory 会报 "addr 必须是静态地址"，根本读不到。
            解决方案：直接把运行时地址交给 rb.read_memory（它内部就是 ptr(addr)），
                      不做任何换算；地址合法性只做基本校验，读不到如实报错。

        为什么可以放心在 hold 挂起时调用：rb.read_memory 每次新建独立脚本，
        不走被 recv().wait() 挂住的调试脚本，实测挂起期间读 16 字节耗时 0.02s。
        """
        if not (1 <= size <= 4096):
            raise DynError("BAD_REQUEST", "size 必须在 1..4096")
        addr = int(runtime_addr)
        if addr <= 0:
            raise DynError("BAD_ADDRESS", f"运行时地址必须为正：{runtime_addr!r}")
        tgt = self.attach(serial, pid)

        # (19) 先走 adb /proc/<pid>/mem：这条链路与 frida 无关，
        #      hold 把线程挂住时照样能读（实测 16 字节 0.13s / 4KB 0.17s）。
        data = b""
        via = ""
        try:
            data = tgt.rb.read_memory_proc(serial, int(pid), addr, int(size))
            if data:
                via = "proc_mem"
        except Exception:                                 # noqa: BLE001
            data = b""

        if not data:
            # 回退 frida：正常（未挂起）情况下它更快
            try:
                data = tgt.rb.read_memory(addr, size)
                if data:
                    via = "frida"
            except Exception as exc:                      # noqa: BLE001
                if not data:
                    raise DynError(
                        "READ_FAILED",
                        f"运行时地址 {addr:#x} 读取失败：adb 与 frida 两条链路都没读到"
                        f"（frida 报 {type(exc).__name__}: {exc}）。"
                        "常见原因：地址未映射、进程已退出、或 hold 挂起时 frida session 已失效"
                        "（此时 adb 链路本应可用，说明该地址确实不可读）") from exc

        if not data:
            raise DynError("READ_FAILED",
                           f"运行时地址 {addr:#x} 不可读或超时（可能未映射或权限不足）")
        return {"runtime_addr": addr, "hex": data.hex(), "size": len(data),
                "via": via}

    def read_runtime_string(self, serial: str, pid: int, runtime_addr: int,
                            max_length: int = 256) -> dict:
        """按**运行时绝对地址**读一个 C 字符串（遇 \0 截止）。

        分块读而不是一次性读满：目标字符串可能紧贴页边界，一次性读会整段失败；
        分块时某一页读不到就停在那里，把已读到的部分返回（并标 truncated）。
        """
        limit = max(1, min(int(max_length), 4096))
        addr = int(runtime_addr)
        if addr <= 0:
            raise DynError("BAD_ADDRESS", f"运行时地址必须为正：{runtime_addr!r}")
        tgt = self.attach(serial, pid)
        # (31) 第三十一次修改（2026-11-26）
        # bug 原因：原循环读满 limit 且未遇到 \x00 正常结束时，truncated 保持 False，
        #           返回 terminated=True, truncated=False，谎报字符串已正确终止。
        # 解决方案：单独记录 found_nul，循环结束仍未见 \x00 时将 truncated 置 True、terminated 置 False。
        chunk = 64
        buf = bytearray()
        truncated = False
        found_nul = False
        readable_until = 0
        while len(buf) < limit:
            want = min(chunk, limit - len(buf))
            try:
                data = tgt.rb.read_memory(addr + len(buf), want)
            except Exception:                             # noqa: BLE001 - 读失败按截断处理
                data = b""
            if not data:
                # 这一段读不到：如果还没读到任何字节，说明地址本身无效
                if not buf:
                    raise DynError("READ_FAILED",
                                   f"运行时地址 {addr:#x} 不可读（未映射或权限不足）")
                truncated = True
                break
            nul = data.find(b"\x00")
            if nul >= 0:
                buf.extend(data[:nul])
                readable_until = addr + len(buf)
                found_nul = True
                break
            buf.extend(data)
            readable_until = addr + len(buf)
            if len(data) < want:
                truncated = True
                break
        if not found_nul:
            truncated = True
        raw = bytes(buf)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        return {
            "runtime_addr": addr,
            "string": text,
            "length": len(raw),
            "raw_hex": raw.hex(),
            "terminated": found_nul,
            "truncated": truncated,
            "end_addr": readable_until,
        }

    # ---------- 内部 ----------

    def _target(self, serial: str, pid: int) -> Target:
        tgt = self._targets.get(f"{serial}:{pid}")
        if tgt is None:
            raise DynError("NOT_ATTACHED", f"尚未附加到 {serial}:{pid}（先调 attach）")
        # (1) 第一次修改：detach 后的墓碑不能再被当成活会话使用
        if tgt.state == STATE_DETACHED:
            raise DynError("BAD_STATE",
                           f"{serial}:{pid} 会话已 detach，请重新 attach 后操作")
        return tgt

    def _require_module(self, tgt: Target, so_name: str):
        """按名字取运行时模块；名字对不上时用**字节指纹**反查。

        (7) 第七次修改（2026-11-06）：
            bug 原因：本地分析的 so 常被改名（sg_real.so），与设备上的
                      libsgmainso-6.7.260202.so 毫无字面关系，任何名字规范化
                      都救不回来，set_breakpoint 只能报 MODULE_NOT_LOADED。
                      这不是某个 app 的特例——凡是从 APK 抽出 so 后重命名、
                      或分析多个版本并存的情况都会撞上。
            解决方案：名字匹配失败后，用 mda 里该 so 的函数表取一个函数的
                      **原始机器码**，在目标进程各已加载模块的同偏移处比对字节，
                      命中即认定为同一模块。不命中就如实报错，绝不猜。
        """
        mod = tgt.rb.find_module(so_name)
        if mod is not None:
            return mod

        # 指纹反查
        try:
            from server.mcp_server.tools import _pick_so_by_name, _strip_version_tag

            sess = getattr(self, "_session_obj", None)
            so = None
            try:
                from server.mcp_server.tools import get_session

                so = _pick_so_by_name(get_session(), so_name)
            except Exception:                             # noqa: BLE001
                so = None
            if so is not None:
                fp = self._module_fingerprint(tgt, so)
                if fp is not None:
                    return fp
        except Exception:                                 # noqa: BLE001
            pass

        raise DynError("MODULE_NOT_LOADED",
                       f"{so_name} 未加载到进程 {tgt.pid}（先调 modules() 确认；"
                       "若本地文件名与设备名不同，确认该 so 已在 mda 里 load_so）")

    def _module_fingerprint(self, tgt: Target, so):
        """用字节指纹为目标进程里的模块做反查，命中返回 RuntimeModule。

        (7) 第七次修改（2026-11-06）：新增，配合 _require_module 使用。
            取 so 里第一个函数的入口 16 字节作为指纹，与进程内各模块同偏移处
            内存逐一比对。**命中即认定**，全不命中返回 None——绝不猜。

        (8) 第八次修改（2026-11-06）：改成**一个脚本一次读完**。
            bug 原因：初版对每个模块各调一次 rb.read_memory，而它每次调用都
                      create_script；370 个模块就是 370 次脚本往返，实测超过 60 秒。
            解决方案：把「模块基址 + 指纹偏移」列表一次性交给 JS 循环读回，
                      只建一个脚本。模块枚举也复用 rb 已有缓存。
        """
        import json as _json
        import time as _time

        try:
            from server.dyn.tracer import _read_static_bytes

            fns = getattr(so, "functions", {}) or {}
            vals = fns.values() if isinstance(fns, dict) else list(fns)
            offs = sorted({int(getattr(f, "addr", 0) or 0) for f in vals})[:2]
            fps = []
            for off in offs:
                try:
                    raw = _read_static_bytes(so, off, 16)
                except Exception:                         # noqa: BLE001
                    raw = b""
                if raw and len(raw) == 16:
                    fps.append((off, raw.hex()))
            if not fps:
                return None

            off0, want0 = fps[0]
            # (9) 第九次修改（2026-11-06）：优先用 Rebase 的**已有缓存**。
            #     bug 原因：每次都 refresh_modules() 会新建脚本重新枚举 370 个模块，
            #               叠加指纹读取后整个 set_breakpoint 要 50 秒。
            #     解决方案：缓存非空就直接用（这些模块在进程生命周期内基本不变），
            #               缓存为空才枚举一次。
            cache = list(getattr(tgt.rb, "_modules", []) or [])
            mods = [m for m in (cache or tgt.rb.refresh_modules())
                    if int(getattr(m, "size", 0) or 0) > off0]
            if not mods:
                return None

            # (32) 第三十二次修改（2026-11-26）
            # bug 原因：64 位地址以整数序列化给 JS ptr(...) 会受 float64 53 位精度限制，
            #           导致 ARM64 TBI 高位地址（0xb4...）被截断读歪。
            # 解决方案：统一转为 hex(int(...)) 字符串传给 JS ptr(...) 无损解析。
            addrs = [hex(int(m.base) + off0) for m in mods]
            js = (
                "var A = " + _json.dumps(addrs) + ";"
                "var out = [];"
                "for (var i = 0; i < A.length; i++) {"
                "  try { var b = ptr(A[i]).readByteArray(16);"
                "    out.push(b === null ? null : Array.from(new Uint8Array(b))"
                ".map(function(x){return x.toString(16).padStart(2,'0');}).join(''));"
                "  } catch (e) { out.push(null); }"
                "}"
                "send(out);"
            )
            sess = tgt.rb.session
            script = sess.create_script(js)
            got: list = []
            script.on("message", lambda m, d: got.extend(m.get("payload") or []))
            script.load()
            t0 = _time.time()
            while not got and _time.time() - t0 < 10.0:
                _time.sleep(0.02)
            for i, hexval in enumerate(got):
                if hexval and hexval == want0 and i < len(mods):
                    return mods[i]
            return None
        except Exception:                                 # noqa: BLE001
            return None

    # (33) 第三十三次修改（2026-11-26）
    # bug 原因：① _sync_hits 仅按列表下标 hit_cursor 切片，当 dbg._hits 环形缓冲满 2000 条后
    #             len(hits) 恒为 2000，hits[2000:] 永远为空，后续所有命中被静默丢失；
    #           ② 缺少主动命中回调入口，不 poll 时 hold 命中无法即时迁移 paused 和调度 auto_resume；
    #           ③ _hit_dict 保留 "seq" 后若直接 **payload 传给 _emit，会覆盖全局事件 seq。
    # 解决方案：拆出单条入队逻辑 _ingest_hit_locked 与主动回调 _on_debugger_hit；
    #           真实带单调 seq 的命中按 seq > tgt.last_synced_seq 增量同步，无 seq 的假 debugger
    #           兼容回退到 hit_cursor；入队事件时剥离 "seq"（另存 hit_seq）保护全局事件序号。
    def _on_debugger_hit(self, tgt: Target, hit) -> None:
        """Debugger 主动推送的单条命中回调：即时同步状态并调度自动放行。"""
        with self._lock:
            if tgt.state == STATE_DETACHED:
                return
            self._ingest_hit_locked(tgt, hit)

    def _ingest_hit_locked(self, tgt: Target, hit) -> bool:
        """在持有 self._lock 的前提下把单条命中写入事件流并更新目标状态（幂等去重）。"""
        seq = _hit_seq(hit)
        last_seq = int(getattr(tgt, "last_synced_seq", 0) or 0)
        if seq > 0:
            if seq <= last_seq:
                return False
            tgt.last_synced_seq = seq
        d = _hit_dict(hit)
        bp = _match_bp(tgt, d.get("so_name"), d.get("static_addr"))
        held = _resolve_held(d, bp)
        # (4) 第四次修改（2026-11-02）：墓碑状态不可被迟到的命中消息复活。
        if held and tgt.state != STATE_DETACHED:
            tgt.state = STATE_PAUSED
        # token 属内部实现，不进对 AI 暴露的事件；
        # seq 若透传进 **payload 会覆盖 _emit 生成的全局事件 seq，因此剥离后另存 hit_seq。
        payload = {k: v for k, v in d.items()
                   if k not in ("ts", "token", "held", "seq")}
        if "seq" in d:
            payload["hit_seq"] = d["seq"]
        self._emit(tgt, "breakpoint_hit", ts=d.get("ts"), hold=held,
                   held=held, bp_id=(bp or {}).get("id"), **payload)
        # (21) 第二十一次修改（2026-11-16）：hold 命中且断点记录要求自动放行时起守护定时器。
        if held and bp is not None and int(bp.get("auto_resume_ms") or 0) > 0:
            self._schedule_auto_resume(tgt, bp, d.get("token"),
                                       int(bp.get("auto_resume_ms") or 0))
        return True

    def _sync_hits(self, tgt: Target) -> int:
        """把 dbg.hits 里尚未转成事件的新命中补成 breakpoint_hit 事件。

        hold 断点命中即把目标标记为 paused（线程在等 resume）。返回本次新增事件数。
        """
        # (13) 第十三次修改（2026-11-06）：改走 _dbg_hits，兼容 hits 为
        #      property / 方法 / 裸 list 三种形态（debugger 正被重写）。
        hits = _dbg_hits(tgt.dbg)
        with self._lock:
            last_seq = int(getattr(tgt, "last_synced_seq", 0) or 0)
            has_seq = bool(hits) and _hit_seq(hits[-1]) > 0
            if has_seq:
                fresh = [h for h in hits if _hit_seq(h) > last_seq]
            else:
                # 兼容未带 seq 的单元测试假 debugger：按旧下标游标切片
                start = tgt.hit_cursor if tgt.hit_cursor <= len(hits) else 0
                fresh = hits[start:]
            added = 0
            for hit in fresh:
                if self._ingest_hit_locked(tgt, hit):
                    added += 1
            tgt.hit_cursor = len(hits)
            return added

    def _collect(self, tgt: Target, floor: int, limit: int,
                 advance: bool = True) -> list[dict]:
        """取该目标 seq > floor 的事件（按 seq 升序，最多 limit 条）。

        (5) 第五次修改（2026-11-02）：新增 advance 开关。
            bug 原因：调用方显式传 after_seq 时（回溯历史 / 只要某段），
                      旧实现仍把 polled_seq 推到取到的最大 seq。于是
                      "先 after_seq=2 看一眼"会把游标推进到 3，随后不传参的
                      poll() 从 4 开始，seq 3 以前的未读事件**永久丢失**——
                      读者以为自己在回溯，实际把增量读的位置弄坏了。
            解决方案：只有走默认游标（after_seq=None）时才推进 polled_seq；
                      显式指定 after_seq 属"只读回溯"，不改变增量水位线。
        """
        with self._lock:
            picked = [ev for ev in self._events
                      if ev["key"] == tgt.key and ev["seq"] > floor]
            picked.sort(key=lambda ev: ev["seq"])
            picked = picked[:limit]
            if picked and advance:
                tgt.polled_seq = max(tgt.polled_seq, picked[-1]["seq"])
            # 返回副本：调用方改事件不该污染内部记录
            return [dict(ev) for ev in picked]

    def _pending_locked(self, tgt: Target) -> int:
        """该目标还有多少事件是"取过之后才产生"的（需持锁调用）。"""
        return sum(1 for ev in self._events
                   if ev["key"] == tgt.key and ev["seq"] > tgt.polled_seq)

    def _emit(self, tgt: Target, etype: str, ts: float | None = None, **fields) -> dict:
        """写一条事件：seq 全局自增且单调，AI 可据此判断有没有新事件。"""
        with self._lock:
            self._seq += 1
            ev = {
                "seq": self._seq,
                "type": etype,
                "ts": time.time() if ts is None else float(ts),
                "key": tgt.key,
                "serial": tgt.serial,
                "pid": tgt.pid,
            }
            ev.update(fields)
            self._events.append(ev)   # deque 到上限自动丢最旧
            return ev


class _Result(dict):
    """dict 结果 + 布尔语义。

    老接口 resume/remove_breakpoint 返回 bool，调用方可能写 `if svc.resume(...)`。
    直接返回 dict 会让 `if` 恒真（非空 dict 是真值），这里把真值重新绑定到
    "是否真的生效"上。_truth_key 是实例属性，不会出现在 JSON 里。
    """

    _truth_key = "ok"

    def __bool__(self) -> bool:
        return bool(dict.get(self, self._truth_key, False))


def _result(truth_key: str, data: dict) -> _Result:
    """构造带布尔语义的结果字典。"""
    out = _Result(data)
    out._truth_key = truth_key
    return out


def _event_kind(ev: dict) -> str | None:
    """把一条内部事件映射成时间线里的 kind；与时间先后无关的事件返回 None。

    (21) 第二十一次修改（2026-11-16）：新增。
        为什么需要映射而不是原样输出：内部事件类型是给"状态机"用的
        （attached / breakpoint_set / resumed / resume_partial ...），
        时间线关心的是"发生了什么有观测意义的事"。两类混在一起，
        时间轴会被大量状态迁移淹没，真正要看的命中反而找不到。

    映射规则（只保留有观测意义的）：
        breakpoint_hit        → bp       命中了一次断点
        auto_resumed          → auto     自动放行（用户要知道这件事发生过）
        auto_resume_armed     → auto     自动放行定时器已布防
        auto_resume_skipped   → auto     到点了但没东西可放（如实保留）
        auto_resume_failed    → auto     自动放行失败
        resumed/resume_*      → auto     手动放行也算时间线里的一次事件
        其余（attached/detached/breakpoint_set/...）→ None，不进时间线
    """
    t = str(ev.get("type") or "")
    if t == "breakpoint_hit":
        return "bp"
    if t in ("auto_resumed", "auto_resume_armed", "auto_resume_skipped",
             "auto_resume_failed", "resumed", "resume_partial",
             "resume_failed"):
        return "auto"
    return None


def _describe_event(kind: str, ev: dict) -> str:
    """给一条时间线事件写一句人能读的 detail（英文键值，不写死任何 App 特征）。"""
    if kind == "bp":
        addr = ev.get("static_addr")
        try:
            addr_text = f"{int(addr):#x}"
        except (TypeError, ValueError):
            addr_text = str(addr)
        parts = [f"hit {ev.get('so_name') or '?'}+{addr_text}",
                 f"tid={ev.get('thread_id')}"]
        if ev.get("held"):
            parts.append("held")
        return " ".join(parts)
    t = str(ev.get("type") or "")
    if t == "auto_resumed":
        return (f"auto-resumed after {ev.get('delay_ms') or '?'}ms"
                if ev.get("delay_ms") else
                f"auto-resumed (woken={ev.get('woken')})")
    if t == "auto_resume_armed":
        return f"auto-resume armed: {ev.get('delay_ms')}ms"
    if t == "auto_resume_skipped":
        return f"auto-resume skipped: {ev.get('reason')}"
    if t == "auto_resume_failed":
        return f"auto-resume failed: {ev.get('reason')}"
    if t == "resumed":
        return f"resumed manually (woken={ev.get('woken')})"
    if t == "resume_partial":
        return f"resume partial: {ev.get('reason')}"
    if t == "resume_failed":
        return f"resume failed: {ev.get('reason')}"
    return t


def _build_timeline(tgt: "Target", hits: list[dict], events: list[dict],
                    duration: float = 0.0, limit: int = 500) -> dict:
    """把命中列表与事件流合并成一条按时间排序的统一时间线。

    (21) 第二十一次修改（2026-11-16）：新增。

    ## 为什么不用"再采一次"，而是合并已有数据

    断点命中（debugger._hits）与事件流（service._events）是两份独立数据：
    命中带完整现场（36 寄存器 + 栈），事件流带状态迁移与 seq。时间线要回答
    的是"谁先发生"，那正好需要两者都在同一条轴上——重新采一遍反而会丢掉
    已经发生过的现场（hold 命中被放行后现场就没了）。

    ## 时间键与精度（这是本函数最需要如实交代的地方）

    每个事件有一个 ts（墙钟秒，time.time()）。墙钟会被 NTP/手动校时改动，
    所以同一批数据里可能出现"后面的比前面的 ts 还小"。用 ts 直接排序会
    把因果顺序排反。

    处理方式：
      ① 主排序键是 **(ts, seq)**：seq 是服务级自增序号，严格反映**入队顺序**，
         所以当 ts 出现回退时，seq 仍然给出真实的先后；
      ② 回退了多大，用 `wall_clock_backwards_ms` 如实报出来，不隐藏；
      ③ t_rel_ms 一律用"相对第一条"的差值，负值保留（它本身就是墙钟跳变的证据）。

    精度上限（真机实测，见 tests/manual_timeline_clock.py 与
    tests/manual_timeline_precision.py）：
      · 设备 CLOCK_MONOTONIC 分辨率 ≈ 6µs —— 不是瓶颈
      · frida RPC 往返中位数 2.8ms / p90 4.6ms → 单向约 1.4ms
      · 命中载荷更大（寄存器 + 栈），单向按 ~2ms 估
      · 所以**同源事件之间的相对间隔可信到毫秒级（±2ms 量级）**
      · **不同来源**（断点命中 vs 内存写入）不能直接混排：
        内存写入的时间戳来自设备侧 helper（CLOCK_MONOTONIC，相对 daemon
        启动），要落回墙钟轴必须用"读状态文件的墙钟 - age_ms"反推，
        而状态文件约 1s 才刷新一次 → 该来源的绝对时刻误差可达 **1 秒量级**。
        因此本函数**只合并同源（都来自 frida 消息）的事件**，
        内存写入由调用方另行处理并在返回里明示（见 precision.sources）。
    """
    # ---- ① 收集：命中 + 有观测意义的事件 ----
    #
    # (22) 第二十二次修改（2026-11-16）：**不能把命中与 breakpoint_hit 事件都收**。
    #      bug 原因：_sync_hits 会把每条命中**同时**放进 debugger._hits 和
    #                service._events（type=breakpoint_hit）。两处都收就等于
    #                每条命中在时间线上出现两次——实测 2 条命中给出 count=4，
    #                间隔被算成 0（两条重复项时间完全一样），
    #                使用者会以为"断点命中了两次"而去看错误的方向。
    #      解决方案：命中以**事件流里的 breakpoint_hit** 为准（它带 seq，
    #                排序更可靠），只在事件流里**还没有**任何 breakpoint_hit
    #                时才退回用 hits（例如 debugger 直接写入 hits 而未走
    #                service 事件通道的旧路径）。
    event_addrs = {(ev.get("static_addr"), ev.get("thread_id"))
                   for ev in events if ev.get("type") == "breakpoint_hit"}
    has_hit_events = any(ev.get("type") == "breakpoint_hit" for ev in events)
    rows: list[dict] = []
    for idx, h in enumerate(hits):
        addr = h.get("static_addr")
        tid = h.get("thread_id")
        if has_hit_events and (addr, tid) in event_addrs:
            continue          # 已由事件流覆盖，避免重复
        ts = _safe_float(h.get("ts"))
        rows.append({
            "kind": "bp",
            "ts": ts,
            "seq": 0,                     # 命中没有事件 seq，靠列表下标兜底排序
            "_tie": idx,
            "so": h.get("so_name") or "",
            "addr": _hex_or_none(addr),
            "tid": tid,
            "detail": f"hit {h.get('so_name') or '?'}+"
                      f"{_hex_or_none(addr)} tid={tid}"
                      + (" held" if h.get("held") else ""),
            "_src": "hit",
        })
    for ev in events:
        kind = _event_kind(ev)
        if kind is None:
            continue
        rows.append({
            "kind": kind,
            "ts": _safe_float(ev.get("ts")),
            "seq": int(ev.get("seq") or 0),
            "_tie": 0,
            "so": ev.get("so_name") or "",
            "addr": _hex_or_none(ev.get("static_addr")),
            "tid": ev.get("thread_id") or ev.get("tid"),
            "detail": _describe_event(kind, ev),
            "_src": "event",
        })

    # ---- ② 时间窗过滤（duration>0 时只留最后 duration 秒） ----
    dropped_by_window = 0
    if duration and duration > 0 and rows:
        t_latest = max(r["ts"] for r in rows)
        floor = t_latest - float(duration)
        kept = [r for r in rows if r["ts"] >= floor]
        dropped_by_window = len(rows) - len(kept)
        rows = kept

    # ---- ③ 排序：(ts, seq) ----
    rows.sort(key=lambda r: (r["ts"], r["seq"], r["_tie"]))
    # 截断到最新的 limit 条（时间线通常只关心最近发生的事）
    truncated = 0
    if limit and len(rows) > limit:
        truncated = len(rows) - int(limit)
        rows = rows[-int(limit):]

    # ---- ④ 量化墙钟回退（有回退就说明 ts 不可全信，seq 才是真值） ----
    #
    # (22) 第二十二次修改（2026-11-16）：必须在**到达顺序**上量回退，
    #      不能在排序后的结果上量。
    #      bug 原因：排序键是 (ts, seq)，排完之后 ts 必然非降——
    #                在这个结果上找"后面的 ts 比前面小"永远找不到，
    #                于是墙钟明明跳过（NTP 校时）也报 wall_clock_backwards_ms=0，
    #                使用者会把 t_rel_ms 当成真值，而被跳变污染的那段间隔是错的。
    #      解决方案：先按**seq（即事件入队顺序）**复现一遍原始时间序列，
    #                在它上面找回退；没有 seq 的命中（seq=0）按列表顺序参与。
    backwards_ms = 0.0
    arrival = sorted(rows, key=lambda r: (r["seq"] or 0, r["_tie"]))
    prev = None
    for r in arrival:
        if prev is not None and r["ts"] < prev:
            backwards_ms = max(backwards_ms, (prev - r["ts"]) * 1000.0)
            prev = r["ts"]          # 回退后以新的（更小的）为基准继续比
        else:
            prev = r["ts"] if prev is None else max(prev, r["ts"])

    # ---- ⑤ 相对时间与输出 ----
    t0 = rows[0]["ts"] if rows else 0.0
    out_events = []
    for r in rows:
        item = {
            "t_rel_ms": round((r["ts"] - t0) * 1000.0, 3),
            "kind": r["kind"],
            "so": r["so"],
            "addr": r["addr"],
            "tid": r["tid"],
        }
        if r["detail"]:
            item["detail"] = r["detail"]
        if r["seq"]:
            item["seq"] = r["seq"]
        item["ts"] = round(r["ts"], 6)
        out_events.append(item)

    precision = {
        "basis": "device frida message arrival time (wall clock) ordered with "
                 "service seq; monotonic sequence is authoritative",
        "same_source_resolution_ms": 2.0,
        "same_source_note": ("measured on-device: CLOCK_MONOTONIC granularity ~6us; "
                             "frida RPC round-trip median 2.8ms (p90 4.6ms) "
                             "=> one-way ~1.4ms; hit payload is larger, ~2ms is a "
                             "safe estimate for same-source ordering"),
        "cross_source_note": ("memory-write events (perfwatch helper) carry a "
                              "device-monotonic ts relative to daemon start and need "
                              "the ~1s-cadence state file to map back to wall clock, "
                              "so their absolute error can reach the second level; "
                              "they are NOT mixed into this timeline"),
        "sources": sorted({r["_src"] for r in rows}),
        "wall_clock_backwards_ms": round(backwards_ms, 3),
    }
    if backwards_ms > 0:
        precision["wall_clock_warning"] = (
            f"检测到墙钟回退 {backwards_ms:.1f}ms（NTP/校时）。"
            "t_rel_ms 已按 (ts, seq) 排序，顺序仍可信，但该段差值含跳变量")

    return {
        "ok": True,
        "count": len(out_events),
        "events": out_events,
        "target": tgt.key,
        "duration": float(duration or 0),
        "dropped_by_window": dropped_by_window,
        "truncated_by_limit": truncated,
        "precision": precision,
    }


def _safe_float(value, default: float = 0.0) -> float:
    """把可能是字符串/None 的时间戳转成 float；转不了给默认值（不抛）。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _hex_or_none(value):
    """把可能是 int/字符串/None 的地址转成 "0x..." 文本；转不了原样转字符串。"""
    if value is None:
        return None
    try:
        return f"{int(value):#x}"
    except (TypeError, ValueError):
        return str(value)


def _match_bp(tgt: Target, so_name, static_addr) -> dict | None:
    """按 (so_name, static_addr) 找登记的断点，用于判断命中是否 hold。"""
    if so_name is None or static_addr is None:
        return None
    for bp in tgt.breakpoints.values():
        if bp.get("so_name") == so_name and bp.get("static_addr") == static_addr:
            return bp
    return None


def _hit_seq(hit) -> int:
    """提取命中记录的单调序号（无 seq 或非正整数返回 0）。"""
    raw = hit.get("seq") if isinstance(hit, dict) else getattr(hit, "seq", None)
    try:
        val = int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        val = 0
    return val if val > 0 else 0


def _accepts_token_arg(fn) -> bool:
    """判断 debugger.resume() 是否接受 token 关键字参数。"""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for name, param in sig.parameters.items():
        if name == "token" or param.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return False


def _hit_dict(hit) -> dict:
    """把一次命中统一成 dict（7 个固定字段 + 可选的 held/token）。

    (1) 第一次修改：debugger 正在被重写，命中可能是 dataclass 也可能是 dict，
        这里两种都收，避免上层因 debugger 换实现而炸；字段名保持不变。
    (2) 第二次修改（2026-11-02）：补出 held/token。
        bug 原因：只透 7 个字段导致 service 无法知道 debugger 是否真的把线程
                 挂住了，只能靠断点记录反推，绕过登记的 hold 会永久挂起。
        解决方案：held/token 作为**可选字段**输出——debugger 没提供时整个键
                 不出现，这样「不知道」与「明确没挂起(False)」可区分，
                 不再把缺失当成 False 处理。
    """
    out: dict = {}
    if isinstance(hit, dict):
        for k in _HIT_FIELDS:
            out[k] = hit.get(k)
        for k in _HIT_OPTIONAL_FIELDS:
            if k in hit:
                out[k] = hit.get(k)
        out["context"] = out.get("context") or {}
        out["backtrace"] = out.get("backtrace") or []
        out["ts"] = out["ts"] if out["ts"] is not None else time.time()
        return out
    # getattr 带默认值：debugger 新版本少给某个字段时不至于抛 AttributeError
    out = {
        "so_name": getattr(hit, "so_name", ""),
        "static_addr": getattr(hit, "static_addr", 0),
        "runtime_addr": getattr(hit, "runtime_addr", 0),
        "thread_id": getattr(hit, "thread_id", 0),
        "context": getattr(hit, "context", {}) or {},
        "backtrace": getattr(hit, "backtrace", []) or [],
        # (11) 第十一次修改（2026-11-06）：把栈内存快照一起带出去。
        #      为什么：寄存器只有"指针 + 长度"，真正的内容在栈上；
        #      没有它，AI 拿到 sp 也读不出东西。
        "stack_hex": getattr(hit, "stack_hex", "") or "",
        # (12) 第十二次修改（2026-11-06）：一并带出结构化栈。
        #      为什么：stack_hex 是裸字节串，看不出起始地址；
        #      stack 明确给出 [{addr, bytes_hex, size}]，AI 才知道
        #      这段字节对应哪段内存。
        "stack": getattr(hit, "stack", []) or [],
        "ts": getattr(hit, "ts", None) or time.time(),
    }
    for k in _HIT_OPTIONAL_FIELDS:
        # 只有属性真实存在才输出，缺失时不写假值
        if hasattr(hit, k):
            out[k] = getattr(hit, k)
    return out


def _resume_facts(raw) -> dict:
    """从 debugger.resume() 的返回值里取出"真实放行情况"。

    (7) 第七次修改（2026-11-05）：新增本函数。
        bug 原因：`service.resume` 只读 bool 型的"是否成功"，拿到 True 就无条件
                  把状态置成 attached。而 Debugger.resume 在**部分线程 post 失败**时
                  返回 resumed=True、state 仍为 paused、_pending_tokens 仍非空
                  ——那些没被唤醒的线程会永久阻塞在 recv().wait()，
                  而所有上层 API 都以为目标在跑（正是 R1/R3 想消灭的那类永久挂起）。
        解决方案：把 state / failed / woken / pending 一并取出来，交给调用方
                  以 debugger 的真实状态为准，而不是只信一个布尔。
    """
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    st = raw.get("state")
    if isinstance(st, str) and st:
        out["state"] = st
    for key in ("failed", "woken", "pending"):
        v = raw.get(key)
        if isinstance(v, int) and not isinstance(v, bool):
            out[key] = v
    return out


def _resume_verdict(raw) -> tuple[bool, str]:
    """把 debugger.resume() 的返回值翻译成 (是否放行成功, 原因)。

    (3) 第三次修改（2026-11-02）：新增本函数。
        bug 原因：旧实现丢弃返回值，debugger 拒绝放行时仍报成功。
        解决方案：兼容三种形态——
                  · None            → 老实现无返回值，按成功处理（frida 侧常见）
                  · bool            → 直接采用
                  · dict            → 读 resumed 键；有 reason 就透传
                  只有明确否定的信号才判失败，避免把"没返回"误判成失败。
    """
    if raw is None:
        return True, ""
    if isinstance(raw, dict):
        val = raw.get("resumed")
        reason = str(raw.get("reason") or raw.get("message") or "")
        if val is None:
            # 没给 resumed 键：看有没有等价的失败信号
            if raw.get("ok") is False:
                return False, reason or "debugger_rejected"
            return True, reason
        return bool(val), reason
    if isinstance(raw, bool):
        return raw, "" if raw else "debugger_rejected"
    # 其他类型（如对象带 __bool__）：按真值处理，保持宽容
    try:
        return bool(raw), "" if bool(raw) else "debugger_rejected"
    except Exception:                                     # noqa: BLE001
        return True, ""


def _resolve_held(hit_dict: dict, bp: dict | None) -> bool:
    """判定一次命中当前是否真的把线程挂住了。

    (2) 第二次修改（2026-11-02）：新增本函数。
        bug 原因：原先只看 bp["hold"]，与 debugger 的真实状态脱钩，
                 绕过断点登记的 hold 会导致线程永久挂起。
        解决方案：三级优先——
                  ① debugger 明确 held=True  → 挂住了（宁可多让人 resume 一次，
                     也不能漏判成"在跑"，那会永久卡死）
                  ② debugger 明确 held=False → 没挂住，此时**不采信** bp["hold"]
                  ③ debugger 未提供 held      → 老实现，退回 bp["hold"] 兜底
    """
    if "held" in hit_dict:
        # 显式值优先；注意 None 表示"不确定"，仍按挂起处理（安全侧）
        return hit_dict.get("held") is not False
    return bool(bp and bp.get("hold"))


def _dbg_hits(dbg) -> list:
    """安全取 debugger 的命中列表，兼容三种形态（返回 list，取不到给 []）。

    (13) 第十三次修改（2026-11-06）：新增本函数。
         bug 原因：debugger.py 正被重写，`hits` 在版本之间换过形态——
                   裸 list 属性 → @property → 普通方法。原代码统一写
                   `getattr(dbg, "hits", [])`，一旦它变成方法，拿到的就是
                   **绑定方法对象**而不是列表：len() 会抛 TypeError，
                   遍历会抛 "method is not iterable"。这类错误发生在
                   state()/hits()/命中统计等热路径上，表现为工具整体不可用。
         解决方案：集中一处取数——拿到值后若是 callable 就调用一次，
                   再要求结果可迭代，否则退回 []。异常一律吞掉给 []，
                   绝不返回假数据（[] 表示"确实取不到"）。
    (14) 第十四次修改（2026-11-06）：getattr 本身也要包进 try。
         bug 原因：上一版把 `getattr(dbg, "hits", None)` 写在 try 外面，
                   但当 hits 是 **会抛异常的 property**（例如 debugger 内部
                   状态损坏、或重写期间命中了未初始化字段）时，异常在
                   getattr 取值那一刻就抛出来了，根本没机会进 try，
                   于是 state()/hits()/hit_count_for 全部连带崩掉。
                   这与本函数注释承诺的"异常一律吞掉"自相矛盾。
         解决方案：把整个取值（含 getattr）放进同一个 try，任何异常都退回 []。
    """
    try:
        val = getattr(dbg, "hits", None)
        if callable(val):
            val = val()
        if val is None:
            return []
        return list(val)
    except Exception:                                  # noqa: BLE001 - debugger 形态不定
        return []


def _dbg_state(dbg) -> str:
    """读出 debugger 侧状态；老 debugger 没有 state 时退化到命中信号。"""
    val = getattr(dbg, "state", None)
    if callable(val):
        try:
            val = val()
        except Exception:                                  # noqa: BLE001
            val = None
    if isinstance(val, str) and val:
        return val
    pending = getattr(dbg, "_pending", None)
    if pending is not None and callable(getattr(pending, "is_set", None)):
        return "hit_pending" if pending.is_set() else "idle"
    return "unknown"


def _explain(exc: Exception) -> str:
    """把 frida 的英文异常翻译成下一步该干什么。"""
    text = str(exc)
    if "unable to communicate with remote frida-server" in text:
        return ("连不上设备端 frida-server：请确认 frida-server 已启动，"
                "且与本机 frida 客户端大版本一致（dyn/adb.py 的 FRIDA_SERVER_VERSION）")
    if "Failed to spawn" in text or "permission" in text.lower():
        return f"附加被拒绝（可能未 root 或目标有反调试）：{text}"
    return text


# 模块级单例：MCP 与 HTTP 都从这里取，保证"AI 下的断点 = 界面看到的断点"
_service: DynamicService | None = None
_service_lock = threading.Lock()


def get_dyn() -> DynamicService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = DynamicService()
    return _service
