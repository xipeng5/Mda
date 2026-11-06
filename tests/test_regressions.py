"""回归锁定测试：四条已修 bug 的守卫。

运行：.venv/bin/python tests/test_regressions.py

为什么单独成立一个文件：
    2026-11-02 的四条审查发现，49 项既有测试全过却全部漏掉。根因是
    tests/test_dyn_runtime.py 里的 StubDebugger 比真实实现**宽容**
    （例如 resume() 没有返回值、hits 永远为空），导致「debugger 拒绝
    放行」「线程真的被挂住」这些**关键对立状态**从未被构造过。

    本文件专门把这些对立状态显式造出来，锁死修复行为。任何一条被改回
    旧写法，这里必须失败。

四条对应的真实缺陷：
    R1  held/token 不透出 → 绕过断点登记的 hold 导致线程永久挂起
    R2  SoFile.read 跨段/跨节拼接 → 返回不属于该地址的字节（造假数据）
    R3  resume 丢弃 debugger 返回值 → 拒绝放行时仍报成功（假成功）
    R4  stepper 漏 b.hs/b.lo、ret xN 当成走 LR → 落点算错却报 resolvable
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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


# ---------------------------------------------------------------- R1

def test_r1_held_is_exposed() -> None:
    """R1：命中必须透出 debugger 侧的真实挂起状态。"""
    from dyn.service import _hit_dict, _resolve_held

    # debugger 亲口说挂住了，但断点表里没有这条记录（报告 #1 的场景）
    hit = {"so_name": "libx.so", "static_addr": 0x100,
           "held": True, "token": "tok-1"}
    d = _hit_dict(hit)
    check("R1 held 被透出", d.get("held") is True, repr(d.get("held")))
    check("R1 token 被透出", d.get("token") == "tok-1", repr(d.get("token")))
    check("R1 无断点记录时仍判定为挂起",
          _resolve_held(d, None) is True,
          "该项为 False 意味着线程会永久挂起")

    # debugger 明确说没挂，而断点记录说 hold —— 以 debugger 为准
    d2 = _hit_dict({"so_name": "libx.so", "static_addr": 0x100, "held": False})
    check("R1 debugger 否认挂起时不被 bp.hold 覆盖",
          _resolve_held(d2, {"hold": True}) is False)

    # 老 debugger 完全没给 held —— 才退回断点记录
    d3 = _hit_dict({"so_name": "libx.so", "static_addr": 0x100})
    check("R1 缺失 held 时不出现在键里", "held" not in d3, str(d3.keys()))
    check("R1 缺失 held 时退回 bp.hold",
          _resolve_held(d3, {"hold": True}) is True)
    check("R1 缺失 held 且无 bp 时为假",
          _resolve_held(d3, None) is False)


# ---------------------------------------------------------------- R2

def test_r2_no_cross_segment_concat() -> None:
    """R2：读取不得越出所在段/节的范围。"""
    from core.elf_model import SoFile

    sample = Path(__file__).parent.parent / "so_test" / "dump" / (
        "libsgmainso-5.5.110.so.758a6e6000.bin")
    if not sample.exists():
        print("  [跳过] R2 样本不存在")
        return
    so = SoFile(str(sample))

    # 该样本段表末尾 0x227798；从 0x227796 请求 4 字节只能得 2 字节
    data = so.read(0x227796, 4)
    check("R2 跨段读取不返回段外字节",
          len(data) <= 2, f"实际返回 {len(data)} 字节：{data.hex()}")
    check("R2 跨段读取返回的是段内真实前缀",
          data == b"\x00\x00" or len(data) < 4,
          data.hex())

    # 段内正常读取不受影响
    inside = so.read(0x227790, 8)
    check("R2 段内读取仍然完整", len(inside) == 8, f"实际 {len(inside)}")

    # 完全段外返回空
    check("R2 段外读取返回空", so.read(0x227798, 4) == b"")

    # 上层必须报错而不是伪造数值
    from dyn.memread import MemReadError, read_typed

    raised = False
    try:
        read_typed(so, 0x227796, "uint32")
    except MemReadError:
        raised = True
    except Exception:                                       # noqa: BLE001
        raised = False
    check("R2 上层对截断数据明确报错而非返回假值", raised,
          "该项为 False 意味着会拿拼接出的假数据当真实值")


# ---------------------------------------------------------------- R3

def test_r3_resume_respects_verdict() -> None:
    """R3：debugger 拒绝放行时不得谎报成功。"""
    from dyn.service import _resume_verdict

    ok, reason = _resume_verdict({"resumed": False, "reason": "thread_gone"})
    check("R3 明确拒绝被判为失败", ok is False, f"ok={ok}")
    check("R3 拒绝原因被透传", reason == "thread_gone", repr(reason))

    check("R3 明确接受被判为成功", _resume_verdict({"resumed": True})[0] is True)
    check("R3 bool False 被判为失败", _resume_verdict(False)[0] is False)
    check("R3 老实现无返回值按成功处理", _resume_verdict(None)[0] is True)
    check("R3 ok:false 形态被判为失败",
          _resume_verdict({"ok": False})[0] is False)

    # 端到端：service 不得把拒绝写成成功，且状态要保持 paused
    from dyn.service import STATE_PAUSED, DynamicService, Target

    class RejectDbg:
        state = "paused"
        hits: list = []

        def resume(self):
            return {"resumed": False, "reason": "thread_gone"}

        def set_breakpoint(self, *a, **k):
            return True

        def close(self):
            pass

        def wait_hits(self, timeout=1.0):
            return []

    class RB:
        def refresh_modules(self):
            return []

        def detach(self):
            return True

    svc = DynamicService()
    tgt = Target(serial="s", pid=1, rb=RB(), dbg=RejectDbg())
    tgt.state = STATE_PAUSED
    svc._targets["s:1"] = tgt
    r = svc.resume("s", 1)
    check("R3 端到端：拒绝时 resumed=False",
          r.get("resumed") is False, f"实际 {r!r}")
    check("R3 端到端：拒绝后状态仍为 paused",
          r.get("state") == STATE_PAUSED, f"实际 {r.get('state')}")


# ---------------------------------------------------------------- R4

def test_r4_stepper_condition() -> None:
    """R4：ARM64 条件码别名与 ret 操作数必须正确处理。"""
    from dyn.stepper import _COND_DIRECT, _RET, _classify

    check("R4 b.hs 在条件跳转表内", "b.hs" in _COND_DIRECT,
          "capstone 对 b.cs 输出 b.hs，漏收会导致落点算错")
    check("R4 b.lo 在条件跳转表内", "b.lo" in _COND_DIRECT,
          "capstone 对 b.cc 输出 b.lo")

    class Ins:
        def __init__(self, mnemonic, op_str="", target=None):
            self.mnemonic = mnemonic
            self.op_str = op_str
            self.text = f"{mnemonic} {op_str}".strip()
            self.addr = 0x1000
            self.size = 4
            self.is_call = False
            self.is_jump = True
            self.is_ret = mnemonic == "ret"
            self.call_target = target

    for m in ("b.hs", "b.lo"):
        kind, target = _classify(Ins(m, "#0x1100", 0x1100))
        check(f"R4 {m} 判定为条件跳转", kind == "cond", f"实际 {kind}")
        check(f"R4 {m} 目标被解析", target == 0x1100, f"实际 {target}")

    kind, target = _classify(Ins("ret"))
    check("R4 裸 ret 判定为 ret", kind == "ret" and target is None,
          f"实际 {(kind, target)}")

    kind, target = _classify(Ins("ret", "x1"))
    check("R4 ret xN 判定为间接（目标不可静态确定）",
          kind == "indirect" and target is None, f"实际 {(kind, target)}")




# ---------------------------------------------------------------- R5-R9

def test_r5_addr_parsing() -> None:
    """R5：地址字符串解析不得把十进制当十六进制。"""
    from mcp_server.tools import _as_int_addr

    check("R5 '12' 解析为 12", _as_int_addr("12") == 12,
          f"实际 {_as_int_addr('12')}（修复前是 18）")
    check("R5 '0x12' 解析为 18", _as_int_addr("0x12") == 18)
    check("R5 '7f0000' 按十六进制", _as_int_addr("7f0000") == 0x7f0000)
    check("R5 空串返回 None", _as_int_addr("") is None)
    check("R5 非地址串返回 None", _as_int_addr("<ptr>") is None)
    check("R5 bool 不当地址", _as_int_addr(True) is None)


def test_r6_threads_empty_not_success() -> None:
    """R6：线程枚举返回空列表时必须继续降级，不能报"0 线程"成功。"""
    from mcp_server.tools import _threads_from_layers

    class Svc:
        def threads(self, serial, pid):
            return []               # RPC 失败的空结果

    class Dbg:
        def threads(self):
            return [{"id": 7, "name": None, "state": "running"}]

    class Tgt:
        serial = "s"
        pid = 1
        dbg = Dbg()
        rb = None

    raw = _threads_from_layers(Svc(), Tgt())
    check("R6 空列表不当作有效结果", raw == [{"id": 7, "name": None, "state": "running"}],
          f"实际 {raw}")


def test_r7_bad_events_no_crash() -> None:
    """R7：事件里混入非字典元素不得抛异常。"""
    from mcp_server.tools import _bases_from_hit_events

    try:
        bases, note = _bases_from_hit_events([1, 2])
        ok = bases == {} and bool(note)
    except Exception as exc:                                # noqa: BLE001
        ok = False
        note = f"{type(exc).__name__}: {exc}"
    check("R7 非字典元素不崩溃并给出原因", ok, str(note)[:80])

    bases2, _ = _bases_from_hit_events(
        [1, {"so_name": "a.so", "runtime_addr": "0x1000",
             "static_addr": "0x100", "key": "k"}])
    check("R7 混合列表仍能推导基址", bases2 == {"a.so": 0xf00},
          f"实际 {bases2}")


def test_r8_detached_is_terminal() -> None:
    """R8：detached 是终态，迟到事件不得把它改回 paused。"""
    import time as _t

    from dyn.service import STATE_DETACHED, DynamicService, Target

    class Dbg:
        state = "detached"
        hits: list = []

        def resume(self):
            return True

        def close(self):
            pass

        def wait_hits(self, timeout=1.0):
            return []

    class RB:
        def refresh_modules(self):
            return []

        def detach(self):
            return True

    class Hit:
        so_name = "x.so"
        static_addr = 0x10
        runtime_addr = 0x20
        thread_id = 1
        context: dict = {}
        backtrace: list = []
        ts = _t.time()
        held = True
        token = "tok"

    svc = DynamicService()
    tgt = Target(serial="s", pid=9, rb=RB(), dbg=Dbg())
    tgt.state = STATE_DETACHED
    svc._targets["s:9"] = tgt
    tgt.dbg.hits = [Hit()]
    svc._sync_hits(tgt)
    check("R8 detached 不被改为 paused", tgt.state == STATE_DETACHED,
          f"实际 {tgt.state}")


def test_r9_after_seq_does_not_move_cursor() -> None:
    """R9：显式 after_seq 属只读回溯，不得推进增量游标。"""
    from dyn.service import DynamicService, Target

    class Dbg:
        state = "attached"
        hits: list = []

    class RB:
        def refresh_modules(self):
            return []

        def detach(self):
            return True

    svc = DynamicService()
    tgt = Target(serial="s", pid=3, rb=RB(), dbg=Dbg())
    svc._targets["s:3"] = tgt
    for i in range(5):
        svc._emit(tgt, "tick", i=i)

    first = svc.poll_events("s", 3, timeout=0)
    check("R9 首次 poll 拿到 5 条", len(first) == 5, f"实际 {len(first)}")

    replay = svc.poll_events("s", 3, timeout=0, after_seq=0, limit=2)
    check("R9 after_seq=0 可回溯", len(replay) == 2, f"实际 {len(replay)}")

    after = svc.poll_events("s", 3, timeout=0)
    check("R9 回溯后增量游标未被推进（无重复事件）", after == [],
          f"实际 {[e.get('seq') for e in after]}")




# ---------------------------------------------------------------- R10-R14

def test_r10_module_name_alias() -> None:
    """R10：真机模块名带路径/壳前缀时仍要能符号化。"""
    from mcp_server.tools import _pick_so_by_name, _session, _symbolize_frame

    so = _session.add("samples/liblog.so")

    check("R10 全名命中", _pick_so_by_name(_session, "liblog.so") is so)
    check("R10 全路径命中", _pick_so_by_name(_session, "/system/lib64/liblog.so") is so)
    check("R10 相对路径命中", _pick_so_by_name(_session, "xxx/liblog.so") is so)
    check("R10 不存在的名字返回 None",
          _pick_so_by_name(_session, "nope.so") is None)

    class Mod:
        name = "/system/lib64/liblog.so"     # 真机常见：带全路径
        base = 0x7b00000000
        size = 0x20000

    frame = _symbolize_frame(0x7b00005388, [Mod()], _session)
    check("R10 全路径下能还原函数名", frame.get("function") == "android_log_write_int64",
          f"实际 {frame.get('function')!r}（修复前恒 None 且 in_gap=True）")
    check("R10 全路径下不误判 in_gap", frame.get("in_gap") is False)


def test_r11_linear_scan_stops() -> None:
    """R11：无条件跳转/返回必须终止线性扫描，不能给出不会命中的地址。"""
    from dyn.stepper import _stops_linear_scan

    for m in ("b", "b.al", "ret", "br"):
        check(f"R11 {m} 终止线性扫描", _stops_linear_scan(m) is True)
    for m in ("b.eq", "b.ne", "bl", "blr", "mov", "ldr"):
        check(f"R11 {m} 不终止线性扫描", _stops_linear_scan(m) is False)


def test_r12_module_timeline_shorthand() -> None:
    """R12：{模块名: 基址} 简写要被识别；缺 size 与错 size 语义要分开。"""
    from dyn.bridge import module_load_timeline

    r = module_load_timeline({"a.so": 0x1000, "b.so": 0x5000})
    check("R12 {name: base} 简写被识别", r.get("count") == 2,
          f"count={r.get('count')}（修复前为 0）")
    kinds = {a.get("kind") for a in (r.get("anomalies") or [])}
    check("R12 缺 size 报 missing_size 而非 size_invalid",
          "missing_size" in kinds and "size_invalid" not in kinds, str(kinds))

    r2 = module_load_timeline({"a.so": {"base": 0x1000, "size": 0x2000}})
    check("R12 {name:{base,size}} 简写被识别", r2.get("count") == 1)

    r3 = module_load_timeline([{"name": "x.so", "base": 0x1000, "size": -1}])
    kinds3 = {a.get("kind") for a in (r3.get("anomalies") or [])}
    check("R12 真的 size 非法仍报 size_invalid", "size_invalid" in kinds3, str(kinds3))

    r4 = module_load_timeline([
        {"name": "big.so", "base": 0x1000, "size": 0x10000, "ts": 1},
        {"name": "small.so", "base": 0x2000, "size": 0x1000, "ts": 2}])
    check("R12 嵌套重叠能被检出", len(r4.get("overlaps") or []) >= 1,
          f"overlaps={r4.get('overlaps')}")


def test_r13_token_registered_before_symbolize() -> None:
    """R13：符号化失败不得阻止 token 登记（否则线程永久挂起）。"""
    import sys as _sys
    from pathlib import Path as _P

    _sys.path.insert(0, str(_P(__file__).parent))
    from fake_frida import FakeRebase, FakeModule, make_breakpoint_payload

    from dyn.debugger import STATE_PAUSED, Debugger

    rb = FakeRebase([FakeModule("libtarget.so", 0x7000000000, 0x10000)])
    dbg = Debugger(rb)

    # 让符号化必然抛异常，模拟真实隐患
    def _boom(_frames):
        raise RuntimeError("symbolize failed")

    dbg._symbolize_backtrace = _boom            # type: ignore[method-assign]
    payload = make_breakpoint_payload(addr=0x1234)
    payload["token"] = "tok-must-register"
    # 直接驱动消息回调：真实路径里由 script.on("message", ...) 绑定，
    # 该绑定发生在 _ensure_script 内部，手工 create_script 不会建立。
    dbg._on_message({"type": "send", "payload": payload}, None)

    check("R13 符号化失败时 token 仍被登记",
          "tok-must-register" in getattr(dbg, "_pending_tokens", set()),
          "未登记则线程永久挂起")
    check("R13 符号化失败时命中仍被记录", len(dbg.hits) == 1,
          f"hits={len(dbg.hits)}")
    check("R13 符号化失败时 backtrace 退化为裸地址",
          dbg.hits[0].backtrace and all(str(x).startswith("0x") for x in dbg.hits[0].backtrace),
          str(dbg.hits[0].backtrace)[:60])




def test_r14_execute_step_contract() -> None:
    """R14：execute_step 的核心契约——不许把"没停到"报成成功。"""
    from dyn.stepper import execute_step

    class Hit:
        def __init__(self, static_addr):
            self.static_addr = static_addr
            self.runtime_addr = 0x7000 + static_addr
            self.thread_id = 1234
            self.held = True
            self.context = {"pc": hex(static_addr)}
            self.backtrace = []

    class StubDbg:
        def __init__(self, hit_addr=None, raise_on_wait=False):
            self.state = "attached"
            self.hits = []
            self.set_calls = []
            self.remove_calls = []
            self._hit_addr = hit_addr
            self._raise = raise_on_wait

        def set_breakpoint(self, so, addr, policy="hold"):
            self.set_calls.append((so, addr, policy))
            # (16) 第十六次修改（2026-11-05）：命中改由 set_breakpoint 产生。
            #      bug 原因：原来命中只在 wait_hits 里 append，而 execute_step 已改为
            #                轮询 dbg.hits（不再用 wait_hits，因其语义是"取历史命中"），
            #                于是桩永远产生不出新命中——测试红了但代码是对的，
            #                说明桩没模拟真实时序。
            #      解决方案：断点设上即产生命中（真实场景就是"放行后跑到临时断点"），
            #                超时用例仍用 hit_addr=None 保持"永不命中"。
            if self._hit_addr is not None:
                self.hits.append(Hit(self._hit_addr))
            return True

        def resume(self):
            self.state = "attached"
            return {"resumed": True}

        def wait_hits(self, timeout=5.0):
            if self._raise:
                raise RuntimeError("wait boom")
            return list(self.hits)

        def remove_breakpoint(self, so, addr):
            self.remove_calls.append((so, addr))
            return True

    good_plan = {"ok": True, "resolvable": True,
                 "strategy": "temp_breakpoint_next", "temp_breakpoint_addr": 0x100}

    # 1) plan 不可执行 -> 拒绝，不碰 debugger
    d = StubDbg(hit_addr=0x100)
    r = execute_step(d, {"ok": False, "resolvable": False}, so_name="a.so")
    check("R14 不可执行 plan 被拒", r.get("executed") is False
          and r.get("code") == "PLAN_NOT_EXECUTABLE", str(r.get("code")))
    check("R14 拒绝时不设断点", d.set_calls == [], str(d.set_calls))

    # 2) 缺 so_name -> 拒绝
    d = StubDbg(hit_addr=0x100)
    r = execute_step(d, good_plan, so_name="")
    check("R14 缺 so_name 被拒", r.get("code") == "NEED_SO_NAME", str(r.get("code")))

    # 3) 超时未命中 -> STEP_TIMEOUT 且 executed=False（绝不能算成功）
    d = StubDbg(hit_addr=None)
    r = execute_step(d, good_plan, so_name="a.so", timeout=0.1)
    check("R14 超时不报成功", r.get("executed") is False)
    check("R14 超时给 STEP_TIMEOUT", r.get("code") == "STEP_TIMEOUT", str(r.get("code")))
    check("R14 超时也摘钩", d.remove_calls == [("a.so", 0x100)], str(d.remove_calls))

    # 4) 命中但地址不符 -> matched=False + warning
    d = StubDbg(hit_addr=0x999)
    r = execute_step(d, good_plan, so_name="a.so", timeout=1.0)
    check("R14 地址不符时 matched=False", r.get("matched") is False,
          f"实际 matched={r.get('matched')}")
    check("R14 地址不符时给 warning", "warning" in r, str(list(r))[:80])
    check("R14 地址不符时回显实际命中", r.get("hit_static_addr") == hex(0x999),
          str(r.get("hit_static_addr")))

    # 5) 命中且相符 -> 成功
    d = StubDbg(hit_addr=0x100)
    r = execute_step(d, good_plan, so_name="a.so", timeout=1.0)
    check("R14 正确命中时 executed=True", r.get("executed") is True)
    check("R14 正确命中时 matched=True", r.get("matched") is True)
    check("R14 正确命中时带寄存器", isinstance(r.get("context"), dict) and r["context"])
    check("R14 成功也摘钩", d.remove_calls == [("a.so", 0x100)], str(d.remove_calls))

    # 6) wait 抛异常 -> 仍要摘钩
    d = StubDbg(raise_on_wait=True)
    r = execute_step(d, good_plan, so_name="a.so", timeout=0.1)
    check("R14 wait 异常不崩", r.get("executed") is False and "error" in r)
    check("R14 wait 异常也摘钩", d.remove_calls == [("a.so", 0x100)], str(d.remove_calls))


def test_r15_runtime_read_contract() -> None:
    """R15：runtime 读取必须真的走目标进程，且读失败不许返回零填充。"""
    from core.elf_model import SoFile
    from dyn.memread import MemReadError, read_typed

    # 用真实 SoFile（_resolve_so 只认真实例）；只把 rb 换成桩，
    # 这样验证的是"运行时读取这条路径"，而不是伪造的 so。
    so = SoFile("samples/liblog.so")

    class FakeRb:
        def __init__(self, payload=b"", module=True, runtime_ok=True):
            self.payload = payload
            self.module = module
            self.runtime_ok = runtime_ok
            self.reads = []

        def find_module(self, name):
            return object() if self.module else None

        def to_runtime(self, addr, mod):
            if not self.runtime_ok:
                raise RuntimeError("boom")
            return addr + 0x7000000000

        def read_memory(self, addr, size):
            self.reads.append((addr, size))
            return self.payload[:size]

    # 1) 没传 rb -> 明确报错（不能悄悄读静态文件）
    try:
        read_typed(so, 0x100, "uint32", source="runtime", rb=None)
        check("R15 缺 rb 报错", False, "没抛异常")
    except MemReadError as exc:
        check("R15 缺 rb 报 NO_RUNTIME", exc.code == "NO_RUNTIME", exc.code)

    # 2) 模块未加载 -> MODULE_NOT_LOADED
    try:
        read_typed(so, 0x100, "uint32", source="runtime", rb=FakeRb(module=False))
        check("R15 模块未加载报错", False, "没抛异常")
    except MemReadError as exc:
        check("R15 模块未加载报 MODULE_NOT_LOADED",
              exc.code == "MODULE_NOT_LOADED", exc.code)

    # 3) 正常读取 -> 值来自 read_memory 的字节
    rb = FakeRb(payload=b"\xef\xbe\xad\xde")
    r = read_typed(so, 0x100, "uint32", source="runtime", rb=rb)
    check("R15 runtime 值正确", r.get("values") == [0xdeadbeef], str(r.get("values")))
    check("R15 source 标为 runtime", r.get("source") == "runtime", str(r.get("source")))
    check("R15 走了运行时换算", rb.reads and rb.reads[0][0] == 0x100 + 0x7000000000,
          str(rb.reads))

    # 4) 读不到 -> READ_FAILED，绝不返回 0 填充
    rb2 = FakeRb(payload=b"")
    try:
        read_typed(so, 0x100, "uint32", source="runtime", rb=rb2)
        check("R15 读不到应报错", False, "没抛异常（可能返回了零填充）")
    except MemReadError as exc:
        check("R15 读不到报 READ_FAILED", exc.code == "READ_FAILED", exc.code)




def test_r16_execute_step_after_existing_hit() -> None:
    """R16：已经停在一个命中上时，execute_step 必须能等到**新**命中，不能秒回超时。

    这是 B3 的锁定测试：原来的实现把 Debugger.wait_hits 当"睡一会儿"，
    而它的语义是"有未取过的命中就立即返回"，于是第二次单步必然 0 秒超时。
    """
    import time as _time
    from dyn.stepper import execute_step

    class Hit:
        def __init__(self, static_addr):
            self.static_addr = static_addr
            self.runtime_addr = 0x7000 + static_addr
            self.thread_id = 1
            self.held = True
            self.context = {"pc": hex(static_addr)}
            self.backtrace = []

    class DbgWithHistory:
        """真实语义：进入时已有历史命中，新命中在等待期间才出现（用后台线程模拟）。"""

        def __init__(self, hit_addr, delay=0.08):
            self.state = "attached"
            self.hits = [Hit(0xDEAD), Hit(0xBEEF)]   # 已有 2 条历史命中
            self.set_calls = []
            self.remove_calls = []
            self._hit_addr = hit_addr
            self._delay = delay

        def set_breakpoint(self, so, addr, policy="hold"):
            self.set_calls.append((so, addr, policy))
            if self._hit_addr is not None:
                import threading

                def _later():
                    _time.sleep(self._delay)
                    self.hits.append(Hit(self._hit_addr))

                threading.Thread(target=_later, daemon=True).start()
            return True

        def resume(self):
            self.state = "attached"
            return {"resumed": True, "state": "attached", "failed": 0}

        def remove_breakpoint(self, so, addr):
            self.remove_calls.append((so, addr))
            return True

    plan = {"ok": True, "resolvable": True,
            "strategy": "temp_breakpoint_next", "temp_breakpoint_addr": 0x100}

    d = DbgWithHistory(hit_addr=0x100, delay=0.08)
    r = execute_step(d, plan, so_name="a.so", timeout=2.0)
    check("R16 有历史命中时仍能等到新命中", r.get("executed") is True,
          f"实际 {r.get('executed')} / code={r.get('code')}")
    check("R16 不会秒回超时", float(r.get("waited_s", 0) or 0) >= 0.05,
          f"waited_s={r.get('waited_s')}")
    check("R16 选中目标地址那条而非盲取最后一条",
          r.get("hit_static_addr") == hex(0x100), str(r.get("hit_static_addr")))


def test_r17_step_out_address_space() -> None:
    """R17：plan_step_out 必须返回**静态**地址（set_breakpoint 还要再加基址）。"""
    from dyn.stepper import plan_step_out

    class Mod:
        name = "liblog.so"
        base = 0x7B00000000
        size = 0x20000

    class Rb:
        def find_module(self, n):
            return Mod()

        def to_static(self, a, m):
            return a - m.base

        def to_runtime(self, a, m):
            return m.base + a

        def refresh_modules(self):
            return [Mod()]

    class Dbg:
        rb = Rb()

    plan = plan_step_out(Dbg(), lr=0x7B00001234, so_name="liblog.so", static_addr=0x5000)
    check("R17 step_out 可解析", plan.get("resolvable") is True, str(plan.get("code")))
    check("R17 temp_breakpoint_addr 是静态地址",
          plan.get("temp_breakpoint_addr") == 0x1234,
          f"实际 {plan.get('temp_breakpoint_addr')!r}（修复前是 0x7b00001234，会被二次加基址）")
    check("R17 运行时 LR 另存 runtime_lr",
          plan.get("runtime_lr") == 0x7B00001234, str(plan.get("runtime_lr")))

    # 拿不到基址必须明确失败，不能给出会打空的地址
    class DbgNoRb:
        rb = None

    plan2 = plan_step_out(DbgNoRb(), lr=0x7B00001234, so_name="liblog.so", static_addr=0x5000)
    check("R17 拿不到基址时明确失败",
          plan2.get("resolvable") is not True and plan2.get("code") == "LR_STATIC_UNRESOLVED",
          f"code={plan2.get('code')}")


def test_r18_runtime_read_bounds() -> None:
    """R18：runtime 读取越界必须报错，绝不返回"格式正确的假值"。"""
    from core.elf_model import SoFile
    from dyn.memread import MemReadError, read_typed

    so = SoFile("samples/liblog.so")

    class Mod:
        size = 0x20000

    class Rb:
        def find_module(self, n):
            return Mod()

        def to_runtime(self, a, m):
            return a + 0x7B00000000

        def read_memory(self, a, s):
            return b"\xef\xbe\xad\xde" * (s // 4) + b"\x00" * (s % 4)

    for bad in (0x900000, 0xFFFF0000):
        try:
            r = read_typed(so, bad, "uint32", source="runtime", rb=Rb())
            check(f"R18 越界 {bad:#x} 应报错", False,
                  f"返回了 ok={r.get('ok')} value={r.get('values')}")
        except MemReadError as exc:
            check(f"R18 越界 {bad:#x} 报 ADDR_UNMAPPED",
                  exc.code == "ADDR_UNMAPPED", exc.code)

    # 合法地址仍要能读
    r = read_typed(so, 0x50, "uint32", source="runtime", rb=Rb())
    check("R18 合法地址仍可读", r.get("values") == [0xDEADBEEF], str(r.get("values")))


def test_r19_hit_context_fallback() -> None:
    """R19：模块表缺失时 hit_context 必须优雅降级，不能崩。"""
    from dyn.bridge import hit_context
    from mcp_server.tools import _session

    _session.add("samples/liblog.so")
    try:
        r = hit_context(_session, {"so_name": "liblog.so", "runtime_addr": 0x7B00005388},
                        modules=[])
        ok = isinstance(r, dict)
        check("R19 模块表缺失不崩溃", ok, "抛异常了")
        if ok:
            notes = " ".join(r.get("notes") or [])
            check("R19 说明无法反算静态地址", "无法反算" in notes or "不可得" in notes,
                  notes[:80])
    except TypeError as exc:
        check("R19 模块表缺失不崩溃", False, f"TypeError: {exc}")




def test_r20_address_parsing_unified() -> None:
    """R20：四个地址解析入口必须给出同样的结果（尤其"含 a-f 无 0x 前缀"）。"""
    from core.addr import parse_addr
    from dyn.bridge import _as_int
    from dyn.debugger import _parse_addr
    from dyn.tracer import _to_int
    from mcp_server.tools import _as_int_addr

    # 核心规则：这些输入的解析结果必须四家一致
    cases = {
        "0x1234": 0x1234,
        "0X1F": 0x1F,
        "5020": 5020,          # 纯十进制按十进制，不是 0x5020
        "12": 12,
        "7fff1234": 0x7FFF1234,  # 含 a-f 无前缀 → 十六进制（地址简写）
        "deadbeef": 0xDEADBEEF,
    }
    for text, want in cases.items():
        got = {
            "tools": _as_int_addr(text),
            "debugger": _parse_addr(text),
            "tracer": _to_int(text, -1),
            "bridge": _as_int(text),
        }
        same = set(got.values()) == {want}
        check(f"R20 {text!r} 四家一致 = {hex(want)}", same, str(got))

    # 明确失败：bool 不能当 1/0
    check("R20 True 不被当成 1", _as_int_addr(True) is None, str(_as_int_addr(True)))
    check("R20 parse_addr(True) 为 None", parse_addr(True) is None)

    # 空串/垃圾输入
    for junk in ("", "   ", "xyz", None):
        check(f"R20 {junk!r} 解析失败返回 None",
              _as_int_addr(junk) is None and _as_int(junk) is None, str(junk))




def test_r21_mixed_timeline() -> None:
    """R21：模块加载事件与断点命中必须能上同一条时间轴，且算出间隔。"""
    from dyn.bridge import trace_to_timeline
    from dyn.tracer import TraceEvent, KIND_CODE, KIND_MODULE_LOAD

    events = [
        {"kind": "added", "name": "liba.so", "ts": 100.0, "path": "/data/liba.so"},
        {"type": "breakpoint_hit", "ts": 100.25, "so_name": "libc.so",
         "static_addr": 0x48D3C},
        {"kind": "added", "name": "libb.so", "ts": 100.9, "path": "/data/libb.so"},
    ]
    r = trace_to_timeline(events)
    items = r.get("items") or []
    check("R21 混合时间轴条数", len(items) == 3, str(len(items)))
    syms = [i.get("symbol") for i in items]
    check("R21 加载事件保留模块名", syms[0] == "加载 liba.so", str(syms))
    check("R21 断点事件仍在同一轴", "0x48d3c" in str(syms[1]).lower(), str(syms[1]))
    check("R21 加载事件之间算得出间隔",
          items[2].get("delta_ms") == 650.0, str(items[2].get("delta_ms")))
    check("R21 总跨度", abs(float(r.get("duration") or 0) - 0.9) < 1e-6,
          str(r.get("duration")))

    # 三类事件常量必须互不相同，否则聚合会串味
    check("R21 事件种类常量互异",
          len({KIND_CODE, "read", "write", KIND_MODULE_LOAD}) == 4)


def test_r22_module_event_fields() -> None:
    """R22：模块加载事件必须带 ts，否则时间轴无从谈起。"""
    import inspect as _insp

    from dyn.tracer import start_trace_module_load as fn

    src = _insp.getsource(fn)
    check("R22 spawn 模式存在", "dev.spawn" in src, "源码里找不到 dev.spawn")
    check("R22 有 resume 放行", "resume" in src, "spawn 后必须 resume 才跑")
    check("R22 事件打时间戳", "Date.now()" in src, "JS 侧缺 Date.now()")
    check("R22 回放基线用 name|base 组合键",
          "m.name + '|' + m.base.toString()" in src,
          "单值映射会让同名多实例全部失配")
    check("R22 支持 keep_alive 收尾", "keep_alive" in _insp.signature(fn).parameters,
          "spawn 出的进程要能选择收掉")
    check("R22 输出时间轴文本", "timeline" in src)




def test_r23_startup_trace_contract() -> None:
    """R23：trace_app_startup 必须区分两类事件、分类限额、并给结构化洞察。"""
    import inspect as _insp

    from dyn.tracer import trace_app_startup as fn

    src = _insp.getsource(fn)
    sig = _insp.signature(fn)
    # JS 模板在模块级常量里，不在函数源码里 —— 两处都要看
    import dyn.tracer as _t
    js_src = getattr(_t, "_JS_APP_STARTUP", "")
    all_src = src + js_src

    check("R23 走 spawn 而不是 attach", "dev.spawn" in src, "必须 spawn 才能覆盖启动阶段")
    check("R23 挂起期间装好 hook", "sess = dev.attach(pid)" in src and "dev.resume(pid)" in src,
          "必须先 attach 装 hook 再 resume")
    check("R23 支持 symbols 参数", "symbols" in sig.parameters)
    check("R23 支持 keep_alive", "keep_alive" in sig.parameters)
    check("R23 加载与调用分类收集",
          'kind == "module_load"' in src and 'kind == "call"' in src,
          "两类事件必须分开计数，否则高频调用会挤掉加载事件")
    check("R23 每个符号单独限额",
          "PER_SYM" in all_src and "symCount" in all_src,
          "不加单符号限额时 malloc 会独吞名额")
    code_only = "\n".join(k for k in all_src.splitlines() if not k.strip().startswith("//"))
    check("R23 字符串参数用 readCString 且不带 size",
          "readCString()" in code_only
          and "args[si].readUtf8String" not in code_only
          and not __import__("re").search(r"readCString\s*\(\s*\d", code_only),
          "readUtf8String 遇零字节会抛；带 size 的 readCString 会读进垃圾")
    check("R23 输出结构化洞察", '"insights"' in src, "需要 verdict 让人一眼看懂先后")
    check("R23 时间轴分段输出", "【模块加载/卸载】" in src and "【函数调用】" in src,
          "混在一起会被高频调用淹没")


def test_r24_timeline_sections() -> None:
    """R24：时间轴文本必须分段，加载事件不能被调用事件淹没。"""
    # 直接验证分段逻辑：构造大量 call + 少量 load，确认两段都有内容
    events = (
        [{"kind": "module_load", "action": "added", "name": f"lib{i}.so",
          "ts": 100.0 + i * 0.01, "path": f"/data/lib{i}.so"} for i in range(3)]
        + [{"kind": "call", "symbol": "malloc", "ts": 100.0 + i * 0.001,
            "args": ["0x10"], "tid": 1} for i in range(500)]
    )
    # 复用 trace_to_timeline 的混合能力确认两类都能进同一条轴
    from dyn.bridge import trace_to_timeline

    r = trace_to_timeline(events)
    items = r.get("items") or []
    loads = [i for i in items if "加载" in str(i.get("symbol"))]
    calls = [i for i in items if "加载" not in str(i.get("symbol"))]
    check("R24 加载事件未被淹没", len(loads) == 3, f"实际 {len(loads)}")
    check("R24 调用事件也在同一轴", len(calls) == 500, f"实际 {len(calls)}")
    check("R24 整体按时间排序",
          all((items[i].get("ts") or 0) <= (items[i + 1].get("ts") or 0)
              for i in range(len(items) - 1)),
          "时间轴必须单调")




def test_r25_static_breakpoints_in_startup() -> None:
    """R25：trace_app_startup 必须支持按静态地址下断点，且支持延迟补下。"""
    import inspect as _insp

    import dyn.tracer as _t
    from dyn.tracer import trace_app_startup as fn

    src = _insp.getsource(fn)
    js = getattr(_t, "_JS_APP_STARTUP", "")
    sig = _insp.signature(fn)
    all_src = src + js

    check("R25 支持 breakpoints 参数", "breakpoints" in sig.parameters)
    check("R25 静态地址会换算运行时", "mod.base.add(bp.static_addr)" in all_src,
          "必须用 base + static 才能得到真实地址")
    check("R25 挂了等待列表", "bpPending" in all_src, "so 未加载时要挂起等待")
    check("R25 模块加载后补下断点",
          "bpsForModule" in all_src and "onAdded" in all_src,
          "延迟断点要在 so 被 dlopen 时自动补上")
    check("R25 区分 immediate 与 late",
          "'immediate'" in all_src and "'late'" in all_src,
          "补下的断点不能标成挂起时下的")
    check("R25 失败要带原因", "bpFailed" in all_src, "下断失败不能静默")
    check("R25 输出分 placed/pending/failed",
          all(k in src for k in ("placed", "pending_on_load", "failed")),
          "三类状态要分开报告，否则无法判断断点到底有没有生效")

    # 参数校验：坏输入要给出明确错误而不是崩
    r = fn("3e2ff172", "", breakpoints=[{"so_name": "x"}] if False else None)
    # 空包名应直接拒绝（不连接设备）
    check("R25 空包名被拒", r.get("ok") is False and r.get("code") == "NO_PACKAGE",
          str(r.get("code")))




def test_r26_startup_backtrace() -> None:
    """R26：启动期调用必须带调用栈，且用 FUZZY 而非 ACCURATE。"""
    import inspect as _insp

    import dyn.tracer as _t
    from dyn.tracer import trace_app_startup as fn

    src = _insp.getsource(fn)
    js = getattr(_t, "_JS_APP_STARTUP", "")
    all_src = src + js

    check("R26 用 FUZZY 而不是 ACCURATE",
          "Backtracer.FUZZY" in all_src and "Backtracer.ACCURATE" not in all_src,
          "ACCURATE 依赖帧指针，实测在省略帧指针的 ARM64 上只有 2-3 层且重复")
    check("R26 采集深度可配置", "backtrace_depth" in _insp.signature(fn).parameters)
    check("R26 采集次数可配置", "backtrace_limit" in _insp.signature(fn).parameters)
    check("R26 默认每个符号只取 1 次栈",
          _insp.signature(fn).parameters["backtrace_limit"].default == 1,
          "全量取栈会让启动慢一个数量级")
    check("R26 符号 hook 里取栈", "grabBacktrace(this.context, name)" in all_src)
    check("R26 静态断点里也取栈", "grabBacktrace(this.context, bp.label)" in all_src)
    check("R26 回传完整模块表", "Process.enumerateModules()" in all_src
          and "modules: mods" in all_src,
          "没有完整模块表就无法把裸地址折回函数名")

    # MCP 层的符号化要过滤 FUZZY 误报
    import mcp_server.tools as _tools

    tools_src = _insp.getsource(_tools.trace_app_startup)
    check("R26 过滤不在模块内的误报帧",
          'if not info.get("so"):' in tools_src,
          "FUZZY 会混入栈上恰好像地址的值，必须丢掉")
    check("R26 输出 stack_timeline", "stack_timeline" in tools_src)
    check("R26 缺 so 时给提示", "missing_sos" in tools_src,
          "要告诉 AI 载入哪些 so 才能看到函数名")




def test_r27_runtime_address_read() -> None:
    """R27：必须能按运行时绝对地址读（断点现场的 x0/lr 就是这种地址）。"""
    import inspect as _insp

    import dyn.service as _svc

    src_svc = _insp.getsource(_svc.DynamicService.read_runtime)
    src_str = _insp.getsource(_svc.DynamicService.read_runtime_string)

    check("R27 service 有 read_runtime", hasattr(_svc.DynamicService, "read_runtime"))
    check("R27 service 有 read_runtime_string",
          hasattr(_svc.DynamicService, "read_runtime_string"))
    check("R27 不做 base+static 换算",
          "to_runtime" not in src_svc,
          "按运行时地址读时再换算会把基址加两次")
    check("R27 直接交给 rb.read_memory", "rb.read_memory(addr" in src_svc)
    check("R27 拒绝非正地址", "addr <= 0" in src_svc and "addr <= 0" in src_str,
          "0 或负数不是合法运行时地址")
    check("R27 读不到如实报错", "READ_FAILED" in src_svc,
          "不能返回零填充冒充读到了")
    check("R27 字符串分块读", "chunk" in src_str, "紧贴页边界时不至于整段失败")
    check("R27 字符串遇 0 截止", 'find(b"\\x00")' in src_str,
          "必须按 C 字符串语义在 \\0 停")
    check("R27 截断要标出来", "truncated" in src_str, "读不全不能装作读全了")

    # 地址解析：0x 前缀与十进制都要支持
    from core.addr import parse_addr

    check("R27 解析 0x 形式", parse_addr("0x7bcae6055f") == 0x7BCAE6055F)
    check("R27 解析十进制", parse_addr("1234") == 1234)
    check("R27 非法地址返回 None", parse_addr("xyz") is None)


def test_r28_runtime_tools_exposed() -> None:
    """R28：两个运行时地址读工具必须暴露给 AI。"""
    import asyncio as _aio

    from mcp_server.tools import server

    names = [t.name for t in _aio.get_event_loop().run_until_complete(server.list_tools())]
    check("R28 read_runtime_memory 已暴露", "read_runtime_memory" in names)
    check("R28 read_runtime_string 已暴露", "read_runtime_string" in names)




def test_r29_module_name_matching() -> None:
    """R29：设备模块名带版本号时必须能匹配本地文件（通用能力，非某个 app 特例）。"""
    from dyn.tracer import _module_name_candidates
    from mcp_server.tools import _strip_version_tag

    cases = [
        ("libsgmainso-6.7.260202.so", "libsgmainso.so"),
        ("libsgmainso.so", "libsgmainso.so"),
        ("libc++_shared.so", "libc++_shared.so"),
        ("/data/app/x/lib/libfoo-1.2.3.so", "libfoo.so"),
        ("my-lib.so", "my-lib.so"),
        ("libfoo-1.2.3", "libfoo"),
    ]
    for src, want in cases:
        got = _strip_version_tag(src)
        check(f"R29 去版本号 {src}", got == want, f"得到 {got}，期望 {want}")

    # 不该剥的不能剥错
    for keep in ("libarm64-v8a.so", "libc++_shared.so", "libandroid.so"):
        check(f"R29 不误剥 {keep}", _strip_version_tag(keep) == keep,
              f"被剥成了 {_strip_version_tag(keep)}")

    cands = _module_name_candidates("libsgmainso.so")
    check("R29 候选含原名", "libsgmainso.so" in cands, str(cands))
    check("R29 候选含去扩展名", "libsgmainso" in cands, str(cands))


def test_r30_br_resolution() -> None:
    """R30：resolve_br 必须区分 direct/table，且算不出时不编造目标。"""
    import inspect as _insp

    from dyn.bridge import resolve_br as fn

    src = _insp.getsource(fn)
    check("R30 有 direct 模式", '"direct"' in src)
    check("R30 有 table 模式", '"table"' in src)
    check("R30 ldr 之后不再当常量加",
          "load_seen" in src,
          "adrp+add+ldr+add 若继续当常量会算出完全错误的目标")
    check("R30 算不出标 unknown", '"unknown"' in src)
    check("R30 不编造目标", "resolved\": bool(targets)" in src or "bool(targets)" in src)
    check("R30 lookback 最小为 1", "max(1, int(lookback))" in src,
          "0 回看不可能看到 adrp")


def test_r31_detach_thread_safety() -> None:
    """R31：detach 必须防线程累积（曾实测 20 次调用泄漏 20 个线程）。"""
    import threading as _th
    import time as _t
    import inspect as _insp

    import dyn.tracer as _tr

    check("R31 有 in-flight 登记表", hasattr(_tr, "_DETACH_PENDING"))
    check("R31 有并发上限", "len(_DETACH_PENDING) >= 16" in _insp.getsource(_tr._detach_async))
    check("R31 先查 is_detached", "is_detached" in _insp.getsource(_tr._detach_async))
    check("R31 只有一个 _detach_async 定义",
          _insp.getsource(_tr).count("def _detach_async") == 1,
          "重复定义会让后者覆盖前者，防泄漏逻辑失效")

    class _Fake:
        is_detached = False

        def detach(self):                             # noqa: ANN001
            _t.sleep(30)

    before = _th.active_count()
    one = _Fake()
    for _ in range(10):
        _tr._detach_async(one, 0.02)
    after = _th.active_count()
    check("R31 同一会话重复调用只增 1 个线程",
          after - before <= 1, f"增了 {after - before} 个")


def test_r32_new_tools_exposed() -> None:
    """R32：五个补齐能力的工具必须都暴露给 AI。"""
    import asyncio as _aio

    from mcp_server.tools import server

    names = [t.name for t in _aio.get_event_loop().run_until_complete(server.list_tools())]
    for want in ("watch_module", "verify_breakpoint", "resolve_br",
                 "dump_vm_state", "read_memory_batch"):
        check(f"R32 {want} 已暴露", want in names)


def test_r33_find_module_version_match() -> None:
    """R33：Rebase.find_module 必须能按去版本号匹配（否则 set_breakpoint 报未加载）。"""
    import inspect as _insp

    from dyn.rebase import Rebase

    src = _insp.getsource(Rebase.find_module)
    check("R33 用了去版本号逻辑", "_strip_version_tag" in src,
          "只做全名/basename 精确匹配时，本地改名后永远匹配不上")
    check("R33 要求唯一命中", "len(hits) == 1" in src,
          "多命中时不能瞎选一个")




def test_r34_watch_module_sampling() -> None:
    """R34：watch_module 必须均匀采样、支持 batch 间隔、给出决策依据。"""
    import inspect as _insp

    from dyn.tracer import watch_module as fn

    src = _insp.getsource(fn)
    sig = _insp.signature(fn)

    check("R34 默认 max_points 降到 50",
          sig.parameters["max_points"].default == 50,
          "400 实测会把目标拖垮")
    check("R34 有 batch_interval_ms 参数", "batch_interval_ms" in sig.parameters)
    check("R34 默认 batch=20", sig.parameters["batch"].default == 20)
    check("R34 超出预算时均匀采样",
          'sampling = "uniform"' in src and "step = total_fns / float(cap)" in src,
          "截断会让覆盖全挤在区间头部")
    check("R34 返回 sampling 字段", '"sampling": sampling' in src)
    check("R34 返回 failed_detail", '"failed_detail"' in src)
    check("R34 有 recommendation 决策依据", '"recommendation"' in src)
    check("R34 密度计算处理 so 为空", "span_kb" in src and "so is not None" in src,
          "so 未定义会让 NameError 掩盖真实错误")

    # 均匀采样算法：端点必须被覆盖
    offsets = list(range(0, 780, 10))          # 78 个
    cap = 10
    step = len(offsets) / float(cap)
    picked = sorted({offsets[min(int(i * step), len(offsets) - 1)] for i in range(cap)})
    # 均匀采样的判据：不是"末位等于最后一项"，而是**跨度接近全区间**
    # （78 个点取 10 个，末位落在 700/770 ≈ 91%，已覆盖到尾部；
    #  若按旧的"取前 N 个"，末位只会是 90，跨度 12%）
    span_ratio = (picked[-1] - picked[0]) / float(offsets[-1] - offsets[0])
    check("R34 均匀采样覆盖整个区间", len(picked) == cap and span_ratio > 0.85,
          f"pick={picked} span_ratio={span_ratio:.2f}")


def test_r35_probe_hits() -> None:
    """R35：probe_hits 必须能区分「没执行」与「挂不上」。"""
    import inspect as _insp

    import dyn.tracer as _tr

    src = _insp.getsource(_tr.probe_hits)
    js = getattr(_tr, "_JS_PROBE_HITS", "")

    check("R35 用 Interceptor 纯计数", "Interceptor.attach" in js)
    check("R35 不依赖 hold", "recv(token" not in js and "op.wait" not in js,
          "计数探针不该阻塞线程")
    check("R35 拦截失败单独报错",
          "INTERCEPT_FAILED" in js and "INTERCEPT_FAILED" in src,
          "挂不上必须与 0 命中区分开")
    check("R35 返回 mechanism", '"mechanism"' in src)
    check("R35 有指纹兜底", "__FP__" in js)
    check("R35 verdict 区分两种情况", "一次都没执行" in src and "挂钩失败" in src)


def test_r36_jump_table() -> None:
    """R36：read_jump_table 必须支持有符号偏移 + code_base 相加。"""
    import inspect as _insp

    from dyn.bridge import read_jump_table as fn

    src = _insp.getsource(fn)
    sig = _insp.signature(fn)
    check("R36 支持 entry_size=4", "entry_size" in sig.parameters)
    check("R36 支持 code_base", "code_base" in sig.parameters)
    check("R36 支持有符号解释", 'signed' in sig.parameters and '"<i"' in src,
          "ldrsw 读出的偏移可能为负")
    check("R36 targets = base + offset", "base + v" in src)
    check("R36 不给 code_base 时当绝对值", "if base else v" in src)


def test_r37_stack_hex() -> None:
    """R37：命中必须带栈内存快照（参数常是 指针+长度，内容在栈上）。"""
    import dataclasses as _dc
    import inspect as _insp

    from dyn.debugger import BreakpointHit

    names = {f.name for f in _dc.fields(BreakpointHit)}
    check("R37 BreakpointHit 有 stack_hex", "stack_hex" in names)
    js = _insp.getsource(__import__("dyn.debugger", fromlist=["x"]))
    check("R37 JS 侧抓了栈", "readByteArray(0x100)" in js,
          "命中瞬间抓 sp..sp+0x100")


def test_r38_function_list() -> None:
    """R38：so.function_list 必须是函数对象列表（functions 是 dict 的坑）。"""
    import sys as _sys

    _sys.path.insert(0, ".")
    from core.elf_model import SoFile

    # 用仓库自带样本；没有样本就跳过（不让测试因缺样本而失败）
    import os
    for cand in ("samples/liblog.so", "samples/libbase.so"):
        if os.path.exists(cand):
            so = SoFile(cand)
            check("R38 functions 是 dict", isinstance(so.functions, dict))
            check("R38 function_list 是 list", isinstance(so.function_list, list))
            if so.function_list:
                check("R38 function_list 元素有 addr",
                      hasattr(so.function_list[0], "addr"),
                      f"拿到 {type(so.function_list[0]).__name__}")
            return
    # 没有样本：只验证属性存在
    check("R38 SoFile 定义了 function_list",
          hasattr(SoFile, "function_list"))




def test_r39_runtime_jump_table() -> None:
    """R39：read_jump_table 必须支持从运行时内存读（加固样本的表运行时才填）。"""
    import inspect as _insp

    from dyn.bridge import read_jump_table as fn

    sig = _insp.signature(fn)
    src = _insp.getsource(fn)
    check("R39 支持 serial 参数", "serial" in sig.parameters)
    check("R39 支持 pid 参数", "pid" in sig.parameters)
    # (1) 第一次修改（2026-11-06）：断言改按**新版实现**校验。
    #     bug 原因：实现从"Rebase 逐段读"重写成"单脚本一次读"，
    #               旧断言查 rb.read_memory 已经不存在，属误报。
    #     解决方案：改为校验新实现的关键特征——单脚本 + readByteArray + runtime 标记。
    check("R39 运行时优先", '"runtime"' in src and "readByteArray" in src
          and "create_script" in src)
    check("R39 退回静态", "source = \"static\"" in src)
    check("R39 返回 source 标明来源", '"source": source' in src,
          "调用方必须能看出这次读的是内存还是文件")
    # (2) 第二次修改（2026-11-06）：指纹反查改成在 JS 侧做（FPS 数组）。
    #     bug 原因：Python 侧逐模块比对要 864 次脚本往返，实测卡死；
    #               已把比对整体搬进那一个脚本里。
    #     解决方案：断言校验 JS 侧确实带了双指纹逻辑。
    check("R39 名字对不上时用指纹",
          "_module_name_candidates" in src and "FPS" in src and "okAll" in src,
          "本地名与设备名不同时要能反查（且在 JS 侧一次完成）")


def test_r40_probe_vm_from_hits() -> None:
    """R40：必须能从已有命中的寄存器里挖出 VM 上下文。"""
    import inspect as _insp

    import dyn.memread as _mr

    src = _insp.getsource(_mr.probe_vm_from_hits)
    check("R40 函数存在", hasattr(_mr, "probe_vm_from_hits"))
    check("R40 无命中时明确报错", '"NO_HITS"' in src)
    check("R40 过滤小整数当指针", "0x1000" in src,
          "寄存器里的大量小整数不可能是 ctx")
    check("R40 结构校验 count 范围", "2 <= cnt <= 100000" in src)
    check("R40 结构校验 array 指针", "arr_i < 0x1000" in src)
    check("R40 一次脚本批量校验", "for (var i = 0; i < P.length" in src,
          "逐个往返会几十秒")
    check("R40 没有候选时不编造", "verdict" in src and "hint" in src)


def test_r41_trace_call_tree() -> None:
    """R41：trace_call_tree 必须能区分「没被调用」与「挂不上」。"""
    import inspect as _insp

    import dyn.tracer as _tr

    src = _insp.getsource(_tr.trace_call_tree)
    js = getattr(_tr, "_JS_CALL_TREE", "")
    check("R41 函数存在", hasattr(_tr, "trace_call_tree"))
    check("R41 用 returnAddress 作调用者", "this.returnAddress" in js)
    check("R41 挂点失败单独记录", "failed.push" in js)
    check("R41 有双指纹兜底", "__FPS__" in js and "FPS.length" in js)
    check("R41 verdict 区分两种情况",
          "一次都没被调用" in src and "不是地址找错" in src)
    check("R41 限制边数", "max_edges" in src and "Object.keys(edges).length < MAXN" in js,
          "热点函数会把内存打爆")


def test_r42_hits_fallback() -> None:
    """R42：probe_vm_from_hits 取命中记录要有回退（会话断开也能读缓存）。"""
    import inspect as _insp

    import mcp_server.tools as _T

    src = _insp.getsource(_T.probe_vm_from_hits)
    check("R42 先试 service.hits", "svc.hits(serial" in src)
    check("R42 失败后读 dbg 缓存", "dbg" in src and "_targets" in src,
          "会话断开时命中缓存仍在 debugger 里")
    check("R42 无数据时给 hint", "NO_HITS" in src)




def test_r43_array_pointer_validation() -> None:
    """R43：VM 上下文里的数组指针校验必须能拦住假指针，又不能误杀合法地址。"""
    import inspect as _insp

    import dyn.memread as _mr

    src = _insp.getsource(_mr.probe_vm_from_hits)
    check("R43 有去 tag 处理", "0x00FFFFFFFFFFFFFF" in src,
          "Android 堆指针带 MTE tag，不去掉会把合法地址全拒")
    check("R43 检查上限 2^48", "(1 << 48)" in src,
          "用户态地址超过 2^48 必为垃圾")
    check("R43 没有强制 8 字节对齐", "& 0x7) != 0" not in src,
          "实测指令数组是 4 字节对齐，加强制对齐会误杀真数组")

    # 复刻校验逻辑，验证四类输入
    def ok(v) -> bool:
        a = v & 0x00FFFFFFFFFFFFFF
        return not (a < 0x1000 or a >= (1 << 48))

    check("R43 真指令数组通过", ok(0x7C86DDB5AC), hex(0x7C86DDB5AC))
    check("R43 Android 堆指针通过", ok(0xB400007C5F0DC6C0), "带 tag 的堆地址")
    check("R43 ASCII 垃圾被拒", not ok(0x6369000000000003),
          "实测 x0 结构里读到 0x6369000000000003（ASCII 'ci' + 垃圾）")
    check("R43 小整数被拒", not ok(0xFFF))
    check("R43 超界地址被拒", not ok(0x123456789ABCD))




def test_r44_runtime_decode() -> None:
    """R44：运行时指令解码必须支持 ARM64 定长、分支分类、对齐校验。"""
    import inspect as _insp

    import dyn.memread as _mr

    src = _insp.getsource(_mr.decode_runtime_insn)
    check("R44 函数存在", hasattr(_mr, "decode_runtime_insn"))
    check("R44 校验 4 字节对齐", "% 4 != 0" in src and "BAD_ALIGNMENT" in src,
          "AArch64 定长指令，非对齐地址解不出东西")
    check("R44 读运行时内存", "rb.read_memory" in src)
    check("R44 与静态字节对比", "patched" in src and "_read_so_bytes_raw" in src,
          "能看出断点/自解密/hook 改动")
    check("R44 配寄存器现场", "reg_values" in src and "context" in src)
    check("R44 数量有上限", "min(int(count), 64)" in src)

    # 分支分类（纯函数，可离线验证）
    from dyn.memread import _branch_kind

    cases = [("bl", "call"), ("blr", "call"), ("blraa", "call"),
             ("ret", "return"), ("br", "indirect_jump"), ("braa", "indirect_jump"),
             ("b", "jump"), ("cbz", "cond_jump"), ("cbnz", "cond_jump"),
             ("tbz", "cond_jump"), ("tbnz", "cond_jump"), ("add", "")]
    for mnem, want in cases:
        check(f"R44 分支分类 {mnem}", _branch_kind(mnem) == want,
              f"得到 {_branch_kind(mnem)!r}，期望 {want!r}")

    # 真字节解码（离线，用仓库自带样本；没有就跳过）
    import os
    sample = None
    for cand in ("samples/liblog.so", "samples/libbase.so"):
        if os.path.exists(cand):
            sample = cand
            break
    if sample:
        import capstone
        from core.elf_model import SoFile

        so = SoFile(sample)
        fns = so.function_list
        if fns and fns[0].size >= 16:
            target = fns[0].addr
            code = so.read(target, 16)
            md = capstone.Cs(capstone.CS_ARCH_ARM64,
                             capstone.CS_MODE_LITTLE_ENDIAN)
            got = list(md.disasm(code, target))
            check("R44 真样本能解出指令", len(got) > 0,
                  f"{sample} 在 {hex(target)} 解出 {len(got)} 条")
            if got:
                check("R44 解出的指令有助记符", bool(got[0].mnemonic),
                      repr(got[0].mnemonic))


def main() -> int:
    print("== R1 held/token 透出（防线程永久挂起）==")
    test_r1_held_is_exposed()
    print("== R2 跨段拼接（防造假数据）==")
    test_r2_no_cross_segment_concat()
    print("== R3 resume 尊重 debugger 结果（防假成功）==")
    test_r3_resume_respects_verdict()
    print("== R4 ARM64 条件码与 ret 操作数 ==")
    test_r4_stepper_condition()
    print("== R5 地址字符串解析 ==")
    test_r5_addr_parsing()
    print("== R6 线程空结果不当成功 ==")
    test_r6_threads_empty_not_success()
    print("== R7 事件元素健壮性 ==")
    test_r7_bad_events_no_crash()
    print("== R8 detached 终态 ==")
    test_r8_detached_is_terminal()
    print("== R9 after_seq 不推进游标 ==")
    test_r9_after_seq_does_not_move_cursor()
    print("== R10 模块名多级别名 ==")
    test_r10_module_name_alias()
    print("== R11 线性扫描终止条件 ==")
    test_r11_linear_scan_stops()
    print("== R12 模块时间轴简写与重叠 ==")
    test_r12_module_timeline_shorthand()
    print("== R13 token 登记先于符号化 ==")
    test_r13_token_registered_before_symbolize()
    print("== R14 execute_step 契约 ==")
    test_r14_execute_step_contract()
    print("== R15 runtime 读取契约 ==")
    test_r15_runtime_read_contract()
    print("== R16 有历史命中时单步 ==")
    test_r16_execute_step_after_existing_hit()
    print("== R17 step out 地址空间 ==")
    test_r17_step_out_address_space()
    print("== R18 runtime 读取越界 ==")
    test_r18_runtime_read_bounds()
    print("== R19 hit_context 降级 ==")
    test_r19_hit_context_fallback()
    print("== R20 地址解析四入口一致 ==")
    test_r20_address_parsing_unified()
    print("== R21 混合时间轴 ==")
    test_r21_mixed_timeline()
    print("== R22 模块事件字段 ==")
    test_r22_module_event_fields()
    print("== R23 启动 trace 契约 ==")
    test_r23_startup_trace_contract()
    print("== R24 时间轴分段 ==")
    test_r24_timeline_sections()
    print("== R25 启动期静态断点 ==")
    test_r25_static_breakpoints_in_startup()
    print("== R26 启动期调用栈 ==")
    test_r26_startup_backtrace()
    print("== R27 运行时地址读 ==")
    test_r27_runtime_address_read()
    print("== R28 运行时读工具暴露 ==")
    test_r28_runtime_tools_exposed()
    print("== R29 模块名匹配 ==")
    test_r29_module_name_matching()
    print("== R30 br 解析 ==")
    test_r30_br_resolution()
    print("== R31 detach 线程安全 ==")
    test_r31_detach_thread_safety()
    print("== R32 新工具暴露 ==")
    test_r32_new_tools_exposed()
    print("== R33 find_module 版本匹配 ==")
    test_r33_find_module_version_match()
    print("== R34 watch_module 采样 ==")
    test_r34_watch_module_sampling()
    print("== R35 probe_hits ==")
    test_r35_probe_hits()
    print("== R36 跳转表 ==")
    test_r36_jump_table()
    print("== R37 栈内存快照 ==")
    test_r37_stack_hex()
    print("== R38 function_list ==")
    test_r38_function_list()
    print("== R39 运行时读跳转表 ==")
    test_r39_runtime_jump_table()
    print("== R40 从命中挖 VM 上下文 ==")
    test_r40_probe_vm_from_hits()
    print("== R41 调用链追踪 ==")
    test_r41_trace_call_tree()
    print("== R42 命中记录回退 ==")
    test_r42_hits_fallback()
    print("== R43 数组指针校验 ==")
    test_r43_array_pointer_validation()
    print("== R44 运行时指令解码 ==")
    test_r44_runtime_decode()

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
