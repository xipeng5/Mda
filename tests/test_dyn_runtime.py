"""动态层单元测试：会话状态机、事件流、错误语义。

运行：.venv/bin/python tests/test_dyn_runtime.py

为什么离线：
    真机联调需要一台接好 frida-server 的 Android 设备，而本机环境
    并不总是具备（用户手机上常有别的工具占用 frida-server）。
    故这里用 tests/fake_frida.py 的假实现覆盖纯逻辑，保证这些
    不变量在无设备时也能被验证。

本轮不覆盖的部分（需要真机集成测试）：
    - Interceptor 是否真的阻断线程
    - JS 侧 recv().wait() 的实际唤醒时序
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from fake_frida import FakeModule, FakeRebase, make_breakpoint_payload  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [通过] {name}")
    else:
        FAIL += 1
        print(f"  [失败] {name} {detail}")


# ---------------------------------------------------------------- 假 Debugger

class StubDebugger:
    """最小假 Debugger，形状对齐 dyn/debugger.Debugger 的公开面。"""

    def __init__(self):
        self.hits = []
        self.state = "attached"
        self.resumed_count = 0
        self.closed = False
        self.removed: list[tuple] = []
        self.has_remove = True

    def resume(self):
        self.resumed_count += 1
        self.state = "attached"

    def set_breakpoint(self, so_name, static_addr, policy="resume", on_hit=None):
        self.bps = getattr(self, "bps", [])
        self.bps.append((so_name, static_addr, policy))
        return True

    def close(self):
        self.closed = True

    def wait_hits(self, timeout=10.0):
        return list(self.hits)

    def remove_breakpoint(self, so_name, static_addr):
        if not self.has_remove:
            raise AttributeError("no such method")
        self.removed.append((so_name, static_addr))
        return True


class StubHit:
    def __init__(self, addr=0x1234, tid=1):
        self.so_name = "libtarget.so"
        self.static_addr = addr
        self.runtime_addr = 0x7000000000 + addr
        self.thread_id = tid
        self.context = {"x0": "0x1", "pc": "0x7000001234"}
        self.backtrace = ["0x7000001234"]
        self.ts = time.time()


def build_service():
    """构造一个不连设备的 DynamicService，替换 attach 的真实实现。"""
    from dyn.service import DynamicService

    svc = DynamicService()
    stub_dbg = StubDebugger()
    rb = FakeRebase([FakeModule("libtarget.so", 0x7000000000, 0x10000)])

    class _Tgt:
        pass

    def fake_attach(serial, pid):
        key = f"{serial}:{pid}"
        if key in svc._targets:
            return svc._targets[key]
        from dyn.service import Target

        t = Target(serial=serial, pid=pid, rb=rb, dbg=stub_dbg)
        svc._targets[key] = t
        return t

    svc.attach = fake_attach          # type: ignore[method-assign]
    return svc, stub_dbg


def main() -> int:
    serial, pid = "fake", 4242
    S, dbg = build_service()
    S.attach(serial, pid)          # 建立假会话（内部走被替换过的 attach）

    print("== 事件流 ==")
    # 造一次命中，再同步进事件流
    dbg.hits = [StubHit(0x1000), StubHit(0x2000)]
    ev1 = S.poll_events(serial, pid, timeout=0)
    check("timeout=0 能返回事件", len(ev1) >= 2, f"实际 {len(ev1)}")
    check("事件带 seq", all("seq" in e for e in ev1))
    check("事件带 type", all("type" in e for e in ev1))
    check("seq 单调递增",
          [e["seq"] for e in ev1] == sorted(e["seq"] for e in ev1))

    t0 = time.time()
    ev2 = S.poll_events(serial, pid, timeout=0)
    dt = time.time() - t0
    check("无新事件时不重放", len(ev2) == 0, f"实际 {len(ev2)}")
    check("timeout=0 不阻塞(<0.1s)", dt < 0.1, f"耗时 {dt:.3f}s")

    ev3 = S.poll_events(serial, pid, timeout=0, after_seq=0)
    check("after_seq=0 显式重放", len(ev3) >= 2, f"实际 {len(ev3)}")

    ev4 = S.poll_events(serial, pid, timeout=0, after_seq=ev1[0]["seq"])
    check("after_seq 能过滤", all(e["seq"] > ev1[0]["seq"] for e in ev4))

    print("== resume 语义 ==")
    S.resume(serial, pid)  # 先确保 attached
    dbg.state = "attached"
    r = S.resume(serial, pid)
    ok = False
    try:
        ok = (r.get("resumed") is False and r.get("reason") == "not_paused")
    except AttributeError:
        ok = False
    check("非 paused 时拒绝放行", ok, f"实际 {r!r}")
    check("非 paused 时未真的调用 dbg.resume", dbg.resumed_count == 0,
          f"实际调用 {dbg.resumed_count} 次")

    # 造一个 paused 状态
    tgt = S._targets[f"{serial}:{pid}"]
    from dyn.service import STATE_PAUSED

    tgt.state = STATE_PAUSED
    r2 = S.resume(serial, pid)
    check("paused 时放行成功", bool(r2) is True and r2.get("resumed") is True,
          f"实际 {r2!r}")
    check("paused 时真的调用 dbg.resume", dbg.resumed_count == 1,
          f"实际 {dbg.resumed_count}")

    print("== 状态机 ==")
    st = S.state()
    check("state 顶层带 seq 水位线", "seq" in st, str(st.keys())[:120])
    row = st["targets"][0]
    check("目标行带 state", "state" in row)
    check("目标行带 dbg_state", "dbg_state" in row)
    check("目标行带 pending_events", "pending_events" in row)

    print("== remove_breakpoint 三档 ==")
    bp = S.set_breakpoint(serial, pid, "libtarget.so", 0x1234, hold=False)
    check("断点有 id", "id" in bp)
    rm = S.remove_breakpoint(bp["id"])
    check("有撤销接口时 partial=False",
          rm.get("removed") is not False and not rm.get("partial"),
          f"实际 {rm!r}")
    check("真的调到 dbg.remove_breakpoint", len(dbg.removed) == 1,
          f"实际 {dbg.removed}")

    # (3) 第三次修改（2026-11-06）：0x2345 -> 0x2344。
    #     bug 原因：service 新增了 AArch64 的 4 字节对齐校验，0x2345 会被
    #               BAD_ALIGNMENT 拒绝。本处只是"再下一个断点"的上下文，
    #               对齐与否不影响被测语义，改成对齐地址即可。
    bp2 = S.set_breakpoint(serial, pid, "libtarget.so", 0x2344, hold=False)

    class _NoRemove(StubDebugger):
        """模拟「debugger 尚未实现撤销接口」：属性真的不存在。

        注意不能靠 remove_breakpoint 内部抛异常来模拟——那是「有接口但撤销
        失败」，service 会走 REMOVE_FAILED 分支，与「没有接口」是两种语义。
        """

        def __init__(self):
            super().__init__()
            self._hide_remove = True

    nob = _NoRemove()
    # 用 delattr 真正移除实例上的方法查找路径
    class _Bare:
        def __init__(self, base):
            self.hits = base.hits
            self.state = base.state

        def set_breakpoint(self, *a, **k):
            return True

        def resume(self):
            pass

        def close(self):
            pass

        def wait_hits(self, timeout=10.0):
            return list(self.hits)

    bp3 = S.set_breakpoint(serial, pid, "libtarget.so", 0x3454, hold=False)
    S._targets[f"{serial}:{pid}"].dbg = _Bare(dbg)
    rm3 = S.remove_breakpoint(bp3["id"])
    check("无撤销接口时标注 partial", rm3.get("partial") is True,
          f"实际 {rm3!r}")
    check("partial 时给出中文原因/说明",
          bool(rm3.get("reason") or rm3.get("message")),
          str(rm3.get("reason") or rm3.get("message"))[:80])

    print("== 错误语义 ==")
    for name, fn in (
        ("未 attach 时 poll_events", lambda: S.poll_events("nope", 1)),
        ("未 attach 时 resume", lambda: S.resume("nope", 1)),
        ("未 attach 时 wait_hits", lambda: S.wait_hits("nope", 1)),
    ):
        try:
            fn()
            check(name, False, "未抛异常")
        except Exception as e:            # noqa: BLE001
            check(name, type(e).__name__ == "DynError", type(e).__name__)

    print("== 兼容性 ==")
    S2, dbg2 = build_service()
    S2.attach(serial, pid)
    dbg2.hits = [StubHit(0xAA)]
    wh = S2.wait_hits(serial, pid, timeout=0)
    check("wait_hits 仍返回列表", isinstance(wh, list), type(wh).__name__)
    # (1) 第一次修改（2026-11-06）：字段数从 7 变成 8。
    #     bug 原因：新增了 stack_hex（命中瞬间抓 sp..sp+0x100 的原始字节），
    #               用于"参数是 指针+长度、内容在栈上"的场景；
    #               旧的 7 字段断言因此失败——这是预期变化，不是回归。
    #     解决方案：把 stack_hex 加进期望集合。
    # (2) 第二次修改（2026-11-06）：字段数 8 -> 9。
    #     bug 原因：新增了结构化 stack（[{addr, bytes_hex, size}]），
    #               与 stack_hex 并存——前者带起始地址，后者是裸字节。
    #     解决方案：把 stack 加进期望集合。
    check("wait_hits 元素含 9 字段（新增 stack）", wh and set(wh[0]) == {
        "so_name", "static_addr", "runtime_addr", "thread_id",
        "context", "backtrace", "stack_hex", "stack", "ts",
    }, str(set(wh[0]) if wh else "空"))

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
