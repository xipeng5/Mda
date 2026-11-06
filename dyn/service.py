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

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from dyn.adb import DynError

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
_HIT_OPTIONAL_FIELDS = ("held", "token")

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
    hit_cursor: int = 0           # dbg.hits 里已转成事件的下标（避免重复入队）

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
            from dyn.debugger import Debugger
            from dyn.rebase import Rebase

            try:
                rb = Rebase.attach(serial, pid)
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                raise DynError("ATTACH_FAILED", _explain(exc)) from exc
            # polled_seq 从当前 seq 起算：新会话只看新事件，不翻旧账
            tgt = Target(serial=serial, pid=pid, rb=rb, dbg=Debugger(rb),
                         polled_seq=self._seq)
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
        try:
            tgt.dbg.close()
        except Exception:                                  # noqa: BLE001
            pass
        try:
            tgt.rb.detach()
        except Exception:                                  # noqa: BLE001
            pass
        return True

    def close_all(self) -> None:
        """退出时清理，避免留下 hook 或占用设备。"""
        for key in list(self._targets):
            serial, _, pid = key.partition(":")
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
                })
            return {"targets": targets, "seq": self._seq}

    def list_breakpoints(self) -> list[dict]:
        with self._lock:
            return [bp for tgt in self._targets.values() for bp in tgt.breakpoints.values()]

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
                       static_addr: int, hold: bool = False) -> dict:
        """下断点并持有它的脚本，返回断点 id（同一地址重复下返回既有 id）。

        (11) 第十一次修改（2026-11-06）：增加 **4 字节对齐校验**。
            bug 原因：AArch64 是**定长指令集**，所有指令必须 4 字节对齐、
                      且低 2 位恒为 0。原来对 static_addr 不做任何校验，
                      在 0x5bc49 这种地址下断点会返回 set=True（看起来成功），
                      但这块内存根本不是一个指令起点，断点必然永远不命中——
                      用户会以为是"断点失效"或"代码没执行"，属于最难排查的一类假成功。
            解决方案：下断点前校验 `static_addr % 4 == 0`，不满足直接抛 BAD_ALIGNMENT，
                      把问题挡在最前面。硬断点（BRK 指令）和 Interceptor 都受此约束。
        """
        if int(static_addr) % 4 != 0:
            raise DynError(
                "BAD_ALIGNMENT",
                f"断点地址 {int(static_addr):#x} 不是 4 字节对齐；"
                "AArch64 是定长指令集，指令起点必须 4 字节对齐，"
                f"最近的合法地址是 {int(static_addr) - int(static_addr) % 4:#x} "
                f"或 {int(static_addr) - int(static_addr) % 4 + 4:#x}")
        bp_id = f"{serial}:{pid}:{so_name}:{static_addr:x}"   # 不含 '#'，可直接进 URL
        tgt = self.attach(serial, pid)
        with self._lock:
            if bp_id in tgt.breakpoints:
                return {**tgt.breakpoints[bp_id], "existing": True}
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
            "id": bp_id,
            "serial": serial,
            "pid": pid,
            "so_name": so_name,
            "static_addr": static_addr,
            "runtime_addr": runtime_addr,
            "hold": bool(hold),
            "mechanism": BREAKPOINT_MECHANISM,
            "armed": True,
        }
        with self._lock:
            tgt.breakpoints[bp_id] = bp
        self._emit(tgt, "breakpoint_set", bp_id=bp_id, so_name=so_name,
                   static_addr=static_addr, hold=bool(hold),
                   mechanism=BREAKPOINT_MECHANISM, armed=True)
        return {**bp, "existing": False}

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
        if hit is None:
            # 老接口返回 False 表示"没有这个断点"；这里不抛异常，保持可预期
            return _result("removed", {"id": bp_id, "removed": False,
                                       "partial": False, "reason": "not_found",
                                       "message": f"断点 {bp_id} 不存在"})
        tgt, bp = hit
        fn = getattr(tgt.dbg, "remove_breakpoint", None)
        if not callable(fn):
            # 降级：脚本侧无法单点撤销，只能删记录（等重建会话时才真正消失）
            with self._lock:
                tgt.breakpoints.pop(bp_id, None)
            self._emit(tgt, "breakpoint_removed", bp_id=bp_id,
                       partial=True, reason="debugger_no_unhook")
            return _result("removed", {
                "id": bp_id,
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
            self._emit(tgt, "breakpoint_remove_failed", bp_id=bp_id,
                       reason="debugger_rejected")
            return _result("removed", {
                "id": bp_id,
                "removed": False,
                "partial": False,
                "reason": "debugger_rejected",
                "message": "debugger 拒绝撤销，断点记录已保留（hook 仍生效）",
            })
        with self._lock:
            tgt.breakpoints.pop(bp_id, None)
        self._emit(tgt, "breakpoint_removed", bp_id=bp_id,
                   partial=False, reason="")
        return _result("removed", {"id": bp_id, "removed": True,
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

    def resume(self, serial: str, pid: int) -> dict:
        """放行 paused 的目标；未 paused 时如实回 not_paused。

        (1) 第一次修改
        bug 原因：原实现无论如何都 return True，目标根本没 paused 也报"已放行"，
                  AI 无法判断到底有没有线程真的在等它。
        解决方案：只有 state==paused 才真放行；否则返回
                  {"resumed": False, "reason": "not_paused"}，不装成功。
        """
        tgt = self._target(serial, pid)
        with self._lock:
            if tgt.state != STATE_PAUSED:
                return _result("resumed", {"resumed": False, "reason": "not_paused",
                                           "state": tgt.state})
        fn = getattr(tgt.dbg, "resume", None)
        if not callable(fn):
            raise DynError("NOT_IMPLEMENTED", "当前 debugger 未提供 resume()")
        # (3) 第三次修改（2026-11-02）：必须尊重 debugger 的放行结果。
        #     bug 原因：旧实现 fn() 之后无条件写 {"resumed": True}，把 debugger
        #               返回的 {"resumed": False, ...} 直接丢弃。debugger 明确拒绝
        #               放行时 service 却报成功，调用方以为线程已恢复、实际仍卡在
        #               recv().wait() 里——假成功，且掩盖了"线程永久挂起"的现场。
        #               这正是本文件头注释第 ④ 条要消灭的行为。
        #     解决方案：把 fn() 的返回值当作事实来源，支持 bool / dict 两种形态；
        #               明确拒绝时保持 paused 状态并原样上报原因，不谎报成功。
        try:
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
        still_paused = (facts.get("state") == "paused"
                        or facts.get("failed", 0) > 0)
        if still_paused:
            with self._lock:
                cur = tgt.state
            if cur != STATE_PAUSED and str(getattr(dbg, "state", "")) == "paused":
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
        self._emit(tgt, "resumed")
        return _result("resumed", {"resumed": True, "reason": "",
                                   "state": tgt.state,
                                   "woken": facts.get("woken")})

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
        data = tgt.rb.read_memory(addr, size)
        if not data:
            raise DynError("READ_FAILED",
                           f"运行时地址 {addr:#x} 不可读或超时（可能未映射或权限不足）")
        return {"runtime_addr": addr, "hex": data.hex(), "size": len(data)}

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
        chunk = 64
        buf = bytearray()
        truncated = False
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
                break
            buf.extend(data)
            readable_until = addr + len(buf)
            if len(data) < want:
                truncated = True
                break
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
            "terminated": not truncated,
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
            from mcp_server.tools import _pick_so_by_name, _strip_version_tag

            sess = getattr(self, "_session_obj", None)
            so = None
            try:
                from mcp_server.tools import get_session

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
            from dyn.tracer import _read_static_bytes

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

            addrs = [int(m.base) + off0 for m in mods]
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

    def _sync_hits(self, tgt: Target) -> int:
        """把 dbg.hits 里尚未转成事件的新命中补成 breakpoint_hit 事件。

        hold 断点命中即把目标标记为 paused（线程在等 resume）。返回本次新增事件数。

        (2) 第二次修改（2026-11-02）：paused 的判定依据改为 debugger 的真实状态。
            bug 原因：原实现 `held = bool(bp and bp.get("hold"))` 只认断点记录，
                      而 debugger 的 held/token 才是线程是否真被挂住的事实。
                      两者不一致时（绕过登记的 hold、同址重复登记、policy
                      中途改过），service 判定「在跑」→ resume() 拒绝放行 →
                      线程永久阻塞，且无任何 API 能救。
            解决方案：优先级改为
                      ① 命中自带 held=True（debugger 亲口说挂住了）→ paused
                      ② 命中显式 held=False（debugger 说没挂）→ 不信 bp.hold
                      ③ 命中没给 held（老 debugger）→ 退回 bp.hold 兜底
                      这样「明确没挂」不会被误判为挂起，「没说明」才靠记录猜。
        """
        # (13) 第十三次修改（2026-11-06）：改走 _dbg_hits，兼容 hits 为
        #      property / 方法 / 裸 list 三种形态（debugger 正被重写）。
        hits = _dbg_hits(tgt.dbg)
        with self._lock:
            # debugger 若清空过 hits，游标要跟着回退，否则会漏事件
            start = tgt.hit_cursor if tgt.hit_cursor <= len(hits) else 0
            fresh = hits[start:]
            for hit in fresh:
                d = _hit_dict(hit)
                bp = _match_bp(tgt, d.get("so_name"), d.get("static_addr"))
                held = _resolve_held(d, bp)
                # (4) 第四次修改（2026-11-02）：墓碑状态不可被迟到的命中消息复活。
                #     bug 原因：detach 之后若仍有命中消息在途（frida 侧 send 已发出、
                #               脚本尚未卸载完），这里会把 state 从 detached 改回
                #               paused。实测确实出现 detached → paused，于是墓碑
                #               守卫（_target 里拒绝已 detach 的目标）失效，后续
                #               resume 会去操作一个已关闭的会话。
                #     解决方案：detached 是终态，任何事件都不再改变它；事件本身
                #               照常记录，仅不迁移状态。
                if held and tgt.state != STATE_DETACHED:
                    tgt.state = STATE_PAUSED
                # token 属内部实现，不进对 AI 暴露的事件；
                # held 也可能已在 payload 里（来自 _hit_dict），故从 payload 剔除后
                # 再由参数显式传入，避免 "got multiple values for 'held'"。
                payload = {k: v for k, v in d.items()
                           if k not in ("ts", "token", "held")}
                self._emit(tgt, "breakpoint_hit", ts=d.get("ts"), hold=held,
                           held=held, bp_id=(bp or {}).get("id"), **payload)
            tgt.hit_cursor = len(hits)
            return len(fresh)

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


def _match_bp(tgt: Target, so_name, static_addr) -> dict | None:
    """按 (so_name, static_addr) 找登记的断点，用于判断命中是否 hold。"""
    if so_name is None or static_addr is None:
        return None
    for bp in tgt.breakpoints.values():
        if bp.get("so_name") == so_name and bp.get("static_addr") == static_addr:
            return bp
    return None


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
