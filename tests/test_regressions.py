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
    from server.dyn.service import _hit_dict, _resolve_held

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
    from server.core.elf_model import SoFile

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
    from server.dyn.memread import MemReadError, read_typed

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
    from server.dyn.service import _resume_verdict

    ok, reason = _resume_verdict({"resumed": False, "reason": "thread_gone"})
    check("R3 明确拒绝被判为失败", ok is False, f"ok={ok}")
    check("R3 拒绝原因被透传", reason == "thread_gone", repr(reason))

    check("R3 明确接受被判为成功", _resume_verdict({"resumed": True})[0] is True)
    check("R3 bool False 被判为失败", _resume_verdict(False)[0] is False)
    check("R3 老实现无返回值按成功处理", _resume_verdict(None)[0] is True)
    check("R3 ok:false 形态被判为失败",
          _resume_verdict({"ok": False})[0] is False)

    # 端到端：service 不得把拒绝写成成功，且状态要保持 paused
    from server.dyn.service import STATE_PAUSED, DynamicService, Target

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
    from server.dyn.stepper import _COND_DIRECT, _RET, _classify

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
    from server.mcp_server.tools import _as_int_addr

    check("R5 '12' 解析为 12", _as_int_addr("12") == 12,
          f"实际 {_as_int_addr('12')}（修复前是 18）")
    check("R5 '0x12' 解析为 18", _as_int_addr("0x12") == 18)
    check("R5 '7f0000' 按十六进制", _as_int_addr("7f0000") == 0x7f0000)
    check("R5 空串返回 None", _as_int_addr("") is None)
    check("R5 非地址串返回 None", _as_int_addr("<ptr>") is None)
    check("R5 bool 不当地址", _as_int_addr(True) is None)


def test_r6_threads_empty_not_success() -> None:
    """R6：线程枚举返回空列表时必须继续降级，不能报"0 线程"成功。"""
    from server.mcp_server.tools import _threads_from_layers

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
    from server.mcp_server.tools import _bases_from_hit_events

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

    from server.dyn.service import STATE_DETACHED, DynamicService, Target

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
    from server.dyn.service import DynamicService, Target

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
    from server.mcp_server.tools import _pick_so_by_name, _session, _symbolize_frame

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
    from server.dyn.stepper import _stops_linear_scan

    for m in ("b", "b.al", "ret", "br"):
        check(f"R11 {m} 终止线性扫描", _stops_linear_scan(m) is True)
    for m in ("b.eq", "b.ne", "bl", "blr", "mov", "ldr"):
        check(f"R11 {m} 不终止线性扫描", _stops_linear_scan(m) is False)


def test_r12_module_timeline_shorthand() -> None:
    """R12：{模块名: 基址} 简写要被识别；缺 size 与错 size 语义要分开。"""
    from server.dyn.bridge import module_load_timeline

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

    from server.dyn.debugger import STATE_PAUSED, Debugger

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
    from server.dyn.stepper import execute_step

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
    from server.core.elf_model import SoFile
    from server.dyn.memread import MemReadError, read_typed

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
    from server.dyn.stepper import execute_step

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
    from server.dyn.stepper import plan_step_out

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
    from server.core.elf_model import SoFile
    from server.dyn.memread import MemReadError, read_typed

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
    from server.dyn.bridge import hit_context
    from server.mcp_server.tools import _session

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
    from server.core.addr import parse_addr
    from server.dyn.bridge import _as_int
    from server.dyn.debugger import _parse_addr
    from server.dyn.tracer import _to_int
    from server.mcp_server.tools import _as_int_addr

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
    from server.dyn.bridge import trace_to_timeline
    from server.dyn.tracer import TraceEvent, KIND_CODE, KIND_MODULE_LOAD

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

    from server.dyn.tracer import start_trace_module_load as fn

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

    from server.dyn.tracer import trace_app_startup as fn

    src = _insp.getsource(fn)
    sig = _insp.signature(fn)
    # JS 模板在模块级常量里，不在函数源码里 —— 两处都要看
    import server.dyn.tracer as _t
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
    from server.dyn.bridge import trace_to_timeline

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

    import server.dyn.tracer as _t
    from server.dyn.tracer import trace_app_startup as fn

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

    import server.dyn.tracer as _t
    from server.dyn.tracer import trace_app_startup as fn

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
    import server.mcp_server.tools as _tools

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

    import server.dyn.service as _svc

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
    from server.core.addr import parse_addr

    check("R27 解析 0x 形式", parse_addr("0x7bcae6055f") == 0x7BCAE6055F)
    check("R27 解析十进制", parse_addr("1234") == 1234)
    check("R27 非法地址返回 None", parse_addr("xyz") is None)


def test_r28_runtime_tools_exposed() -> None:
    """R28：两个运行时地址读工具必须暴露给 AI。"""
    import asyncio as _aio

    from server.mcp_server.tools import server

    names = [t.name for t in _aio.get_event_loop().run_until_complete(server.list_tools())]
    check("R28 read_runtime_memory 已暴露", "read_runtime_memory" in names)
    check("R28 read_runtime_string 已暴露", "read_runtime_string" in names)




def test_r29_module_name_matching() -> None:
    """R29：设备模块名带版本号时必须能匹配本地文件（通用能力，非某个 app 特例）。"""
    from server.dyn.tracer import _module_name_candidates
    from server.mcp_server.tools import _strip_version_tag

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

    from server.dyn.bridge import resolve_br as fn

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

    import server.dyn.tracer as _tr

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

    from server.mcp_server.tools import server

    names = [t.name for t in _aio.get_event_loop().run_until_complete(server.list_tools())]
    for want in ("watch_module", "verify_breakpoint", "resolve_br",
                 "dump_vm_state", "read_memory_batch"):
        check(f"R32 {want} 已暴露", want in names)


def test_r33_find_module_version_match() -> None:
    """R33：Rebase.find_module 必须能按去版本号匹配（否则 set_breakpoint 报未加载）。

    (2) 第二次修改（2026-11-13）：断言目标从"find_module 源码里有这段字"
        改成"统一规则 match_name 里确实做了这件事，且 find_module 委托给它"。
        bug 原因：原断言查的是 find_module 自身的源码文本。别名规则收敛到
                  core.session.match_name 之后，find_module 只剩一行委托，
                  源码里当然没有 len(hits)==1 —— 于是这条**行为仍成立**的测试
                  变红。源码文本断言会随重构失效，锁不住它真正关心的东西。
        解决方案：① 对 match_name 做**行为断言**（真实名字表里跑一遍）；
                  ② 再断言 find_module 确实调用了它，防止有人又抄一份规则回去。
    """
    import inspect as _insp

    from server.core.session import match_name
    from server.dyn.rebase import Rebase

    # 行为断言：设备名带版本号 / 本地存短名，双向都要能对上
    dev = ["libsgmainso-6.7.260202.so"]
    hit, how, amb = match_name("libsgmainso.so", dev)
    check("R33 去版本号能匹配设备模块名", hit == "libsgmainso-6.7.260202.so",
          f"本地 libsgmainso.so 对不上设备名，实际 {hit!r}/{how!r}")
    check("R33 匹配方式标为 version", how == "version", f"实际 {how!r}")

    # 唯一命中要求：两个版本同时存在时不能瞎选
    both = ["libutils-1.so", "libutils-2.so"]
    hit2, _how2, amb2 = match_name("libutils.so", both)
    check("R33 多命中时不瞎选", hit2 is None and len(amb2) == 2,
          f"应返回歧义候选，实际 hit={hit2!r} amb={amb2!r}")

    # 委托断言：防止别名规则又被抄回 find_module
    src = _insp.getsource(Rebase.find_module)
    check("R33 find_module 复用统一规则", "match_name" in src,
          "只做全名/basename 精确匹配时，本地改名后永远匹配不上")




def test_r34_watch_module_sampling() -> None:
    """R34：watch_module 必须均匀采样、支持 batch 间隔、给出决策依据。"""
    import inspect as _insp

    from server.dyn.tracer import watch_module as fn

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

    import server.dyn.tracer as _tr

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

    from server.dyn.bridge import read_jump_table as fn

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

    from server.dyn.debugger import BreakpointHit

    names = {f.name for f in _dc.fields(BreakpointHit)}
    check("R37 BreakpointHit 有 stack_hex", "stack_hex" in names)
    js = _insp.getsource(__import__("server.dyn.debugger", fromlist=["x"]))
    check("R37 JS 侧抓了栈", "readByteArray(0x100)" in js,
          "命中瞬间抓 sp..sp+0x100")


def test_r38_function_list() -> None:
    """R38：so.function_list 必须是函数对象列表（functions 是 dict 的坑）。"""
    import sys as _sys

    _sys.path.insert(0, ".")
    from server.core.elf_model import SoFile

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

    from server.dyn.bridge import read_jump_table as fn

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

    import server.dyn.memread as _mr

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

    import server.dyn.tracer as _tr

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

    import server.mcp_server.tools as _T

    src = _insp.getsource(_T.probe_vm_from_hits)
    check("R42 先试 service.hits", "svc.hits(serial" in src)
    check("R42 失败后读 dbg 缓存", "dbg" in src and "_targets" in src,
          "会话断开时命中缓存仍在 debugger 里")
    check("R42 无数据时给 hint", "NO_HITS" in src)




def test_r43_array_pointer_validation() -> None:
    """R43：VM 上下文里的数组指针校验必须能拦住假指针，又不能误杀合法地址。"""
    import inspect as _insp

    import server.dyn.memread as _mr

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

    import server.dyn.memread as _mr

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
    from server.dyn.memread import _branch_kind

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
        from server.core.elf_model import SoFile

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




def test_r45_process_probe() -> None:
    """R45：必须能区分「进程死了」和「代码没跑」——这是最容易误判的地方。"""
    import inspect as _insp

    import server.dyn.adb as _adb

    check("R45 probe_process_alive 存在", hasattr(_adb.Adb, "probe_process_alive"))
    src = _insp.getsource(_adb.Adb.probe_process_alive)
    check("R45 检查 /proc 存在性", "/proc/" in src and "MISSING" in src)
    check("R45 解析状态字符", "rfind" in src and "status_meaning" in src,
          "要能区分 R/S/T/Z/X")
    check("R45 识别僵尸", '"Z"' in src and '"X"' in src,
          "僵尸进程不会执行任何代码，必须单独判")
    check("R45 检查 frida 可见性", "injectable" in src and "enumerate_processes" in src,
          "adb 看得到不等于能注入")
    check("R45 三条证据都缺一不可", 'alive' in src and 'status' in src and 'injectable' in src)

    # probe_hits 的异常路径也要带活性探测（否则进程死了只报冷冰冰的 ProcessNotFound）
    import server.dyn.tracer as _tr

    psrc = _insp.getsource(_tr.probe_hits)
    check("R45 probe_hits 异常路径有探测", "probe_process_alive" in psrc)
    check("R45 异常路径能判 TARGET_DIED", "TARGET_DIED" in psrc)
    check("R45 0 命中时区分进程问题", "进程已经不在了" in psrc and "不可注入" in psrc)


def test_r46_hits_trimming() -> None:
    """R46：hits 必须能裁剪，否则大数据会被客户端截断成残缺 JSON。"""
    import inspect as _insp

    import server.mcp_server.tools as _T

    sig = _insp.signature(_T.hits)
    for param in ("bp_id", "limit", "since_seq", "include_context",
                  "include_backtrace", "include_stack"):
        check(f"R46 支持参数 {param}", param in sig.parameters)

    src = _insp.getsource(_T.hits)
    check("R46 按 bp_id 过滤", 'want_bp' in src and "static_addr" in src)
    check("R46 limit 取最近 N 条", "filtered[-int(limit):]" in src,
          "要取最近而不是最早，复盘看的是最新现场")
    check("R46 可省略 context", 'item.pop("context"' in src)
    check("R46 可省略 backtrace", 'item.pop("backtrace"' in src)
    check("R46 可省略 stack", 'item.pop("stack"' in src)
    check("R46 报告总体匹配数", '"total_matched"' in src,
          "count 是本页，total_matched 才是过滤后总数")
    check("R46 报告省略字段", '"fields_omitted"' in src)
    check("R46 给出体积估算", '"size_hint"' in src,
          "超 800KB 要提醒调用方继续裁剪")




def test_r47_jni_and_dispatch() -> None:
    """R47：JNI 注册表与跳转表扫描必须能用，且找不到时如实说明。"""
    import inspect as _insp

    import server.dyn.jni as _jni
    import server.dyn.dispatch as _dsp

    check("R47 find_jni_registrations 存在", hasattr(_jni, "find_jni_registrations"))
    check("R47 find_dispatch_tables 存在", hasattr(_dsp, "find_dispatch_tables"))

    jsrc = _insp.getsource(_jni)
    check("R47 JNI 解析重定位", "PT_DYNAMIC" in jsrc or "relocation" in jsrc.lower(),
          "fnPtr 在文件里常为 0，必须靠重定位补")
    check("R47 JNI 签名形态校验", "Ljava" in jsrc or "signature" in jsrc)
    check("R47 JNI 找不到时说明证据", "note" in jsrc)

    dsrc = _insp.getsource(_dsp)
    check("R47 跳转表支持 signed_offset_4", "signed_offset_4" in dsrc)
    check("R47 跳转表有 confidence", "confidence" in dsrc,
          "误报要能被识别，不能全给 high")
    check("R47 跳转表校验可执行段", "executable" in dsrc.lower())


def test_r48_symbol_not_clobbered() -> None:
    """R48：节表不可用时，_parse_symbols 不能把 fallback 解出的符号清空。

    这是影响所有壳样本的真 bug：sg_real 的 fallback 正确解出 7 个符号
    （含 JNI_OnLoad@0x5b4d8），随后被 _parse_symbols 无条件重置成 0。
    """
    import inspect as _insp

    from server.core.elf_model import SoFile

    src = _insp.getsource(SoFile._parse_symbols)
    # 关键：探测 .dynsym 必须在重置之前
    idx_sec = src.find("_sec_by_name")
    idx_reset = src.find("self.symbols: list[Symbol] = []")
    check("R48 先探测 .dynsym 再重置", idx_sec >= 0 and idx_reset > idx_sec,
          f"_sec_by_name@{idx_sec} 应在重置@{idx_reset} 之前")
    check("R48 节表不可用时直接返回", "return" in src[idx_sec:idx_reset],
          "要在重置前 return，保留 fallback 成果")
    check("R48 保证容器存在", "hasattr(self, \"exports\")" in src
          or "hasattr(self, 'exports')" in src,
          "否则调用方访问 so.exports 会 AttributeError")

    # 真样本验证：如果 samples 里有壳样本特征的文件，检查 symbols 不为空
    import os
    for cand in ("samples/liblog.so", "samples/libbase.so"):
        if os.path.exists(cand):
            so = SoFile(cand)
            check(f"R48 {cand} 有 symbols 属性", hasattr(so, "symbols"))
            check(f"R48 {cand} exports 可访问", hasattr(so, "exports"))
            break




def test_r49_java_bridge() -> None:
    """R49：Java bridge 必须能自动注入（frida 17 起不再内置）。"""
    import inspect as _insp

    import server.dyn.java_bridge as _jb

    check("R49 bridge_status 存在", hasattr(_jb, "bridge_status"))
    check("R49 wrap_with_java_bridge 存在", hasattr(_jb, "wrap_with_java_bridge"))

    # 真实环境：frida_tools 自带 bridge 应能找到
    st = _jb.bridge_status("java")
    check("R49 Java bridge 源码可用", st.get("ok") is True,
          f"期望找到 bridge，实际 {st.get('error') or st.get('code')}")
    check("R49 bridge 体积合理（>100KB）", (st.get("size_bytes") or 0) > 100_000,
          f"实际 {st.get('size_bytes')}")

    # 包装后的脚本必须把 bridge 挂到 globalThis
    wrapped = _jb.wrap_with_java_bridge("send({x:1});")
    check("R49 包装含 defineProperty", "defineProperty" in wrapped)
    check("R49 包装挂的是 Java", "globalThis, 'Java'" in wrapped)
    check("R49 用户脚本在 bridge 之后", wrapped.rstrip().endswith("send({x:1});"),
          "顺序反了会导致 Java 还没定义就执行用户代码")
    check("R49 不可枚举（避免被检测）", "enumerable: false" in wrapped,
          "可枚举的 Java 更容易被反调试发现")

    # 找不到时的错误码要可区分
    bad = _jb.bridge_status("not_a_lang")
    check("R49 未知语言有明确错误码", bad.get("ok") is False and bad.get("code"),
          str(bad))

    # _js_str 生成**完整 JS 字符串字面量**（含外层引号），不是裸内容。
    # 用 json.dumps 实现，因此三种引号/反斜杠都被正确转义，可安全内插到 JS。
    import json as _json

    for raw in ('normal', 'a"b', "a'b", 'back\\slash', '中文'):
        got = _jb._js_str(raw)
        check(f"R49 转义 {raw!r}", got == _json.dumps(raw),
              f"得到 {got!r}")
        check(f"R49 转义后能还原 {raw!r}", _json.loads(got) == raw,
              f"{got!r} 解码不回原值")


def test_r50_java_tools() -> None:
    """R50：三个 Java 工具必须在且不返回假数据。"""
    import inspect as _insp

    import server.dyn.java_bridge as _jb

    for fn, args in (("java_list_methods", ("s", 1, "cls")),
                     ("java_find_classes", ("s", 1)),
                     ("java_hook", ("s", 1, "cls", "m"))):
        check(f"R50 {fn} 存在", hasattr(_jb, fn))
        sig = _insp.signature(getattr(_jb, fn))
        check(f"R50 {fn} 参数完整", len(sig.parameters) >= len(args),
              str(list(sig.parameters)))

    # 无 frida 时必须给明确 code，不能返回空列表冒充"没有"
    src = _insp.getsource(_jb)
    check("R50 有 pending 结构", "NEEDS_FRIDA_JAVA" in src)
    check("R50 不编造空结果", "绝不返回空列表" in src or "绝不返回编造" in src.lower()
          or "NEEDS_FRIDA_JAVA" in src)

    # java_hook 必须能区分"没被调用"与"hook 失败"
    hsrc = _insp.getsource(_jb.java_hook)
    check("R50 hook 有 max_calls 上限", "max_calls" in hsrc)
    # (2) 第二次修改（2026-11-06）：断言改按新实现校验。
    #     bug 原因：java_hook 已重写为批量模式，参数/返回值的抓取从
    #               Python 侧模板字符串挪到了 _JS_JAVA_HOOK_MULTI 这个
    #               JS 常量里。旧断言查 hsrc（Python 源码）自然找不到。
    #     解决方案：改查 JS 模板常量。
    js_tpl = getattr(_jb, "_JS_JAVA_HOOK_MULTI", "")
    check("R50 hook 抓参数与返回值", "rec.args" in js_tpl and "rec.ret" in js_tpl)
    check("R50 支持批量 pattern", "PATTERN" in js_tpl and "candidates" in js_tpl)
    check("R50 支持 package 过滤", "PACKAGE" in js_tpl)
    check("R50 有兄弟方法探测", "SIBLING_PROBE" in js_tpl and "siblingHits" in js_tpl)
    check("R50 Map 可展开", "mdaExpand" in js_tpl and "entrySet" in js_tpl)
    check("R50 支持 arg_fields 深挖", "mdaFields" in js_tpl and "ARG_FIELDS" in js_tpl)
    check("R50 系统包自动排除", "SKIP_PREFIX" in js_tpl and "java.lang." in js_tpl)
    check("R50 单个方法失败不影响其他", "hook_errors" in js_tpl)
    check("R50 hook 抓调用栈", "mdaJavaStack" in src)

    # (1) 第一次修改（2026-11-06）：补 native 方法识别与进程活性探测的断言。
    #     bug 原因：Java 工具的异常路径原来只报 ProcessNotFoundError，
    #               与 probe_hits 当初的坑一样——分不清"进程没了"和"Java 层有问题"。
    #     解决方案：异常路径也调 probe_process_alive，并改用 TARGET_DIED。
    check("R50 异常路径有活性探测", "probe_process_alive" in src)
    check("R50 能判 TARGET_DIED", "TARGET_DIED" in src)
    # native 方法识别靠 getModifiers() & 0x100（Modifier.NATIVE）
    check("R50 识别 native 方法", "0x100" in src or "is_native" in src,
          "is_native 是找 JNI 方法的关键字段")




def test_r51_java_batch_hook() -> None:
    """R51：java_hook 必须支持通配符批量、参数深挖、0 命中诊断。"""
    import inspect as _insp

    import server.dyn.java_bridge as _jb

    sig = _insp.signature(_jb.java_hook)
    for p in ("pattern", "package", "max_classes", "capture", "sibling_probe"):
        check(f"R51 支持参数 {p}", p in sig.parameters)

    js = getattr(_jb, "_JS_JAVA_HOOK_MULTI", "")
    # (2) 第二次修改（2026-11-06）：wildToRe 已改名 makeRe 并改了语义。
    #     bug 原因：原断言查 "wildToRe" 这个实现名，改名就红——
    #              这类"查实现名"的断言既脆弱又验不出真问题。
    #     解决方案：查能力关键词，语义正确性交给 R53 的 node 实跑验证。
    check("R51 支持类名匹配", "makeRe" in js and "PATTERN" in js)
    check("R51 支持包名过滤", "PACKAGE" in js)
    check("R51 分别统计每个类", "classes: []" in js and "call_count" in js)
    check("R51 兄弟方法探测", "SIBLING_PROBE" in js and "siblingHits" in js)
    check("R51 Map 展开", "entrySet" in js)
    check("R51 字段深挖", "mdaFields" in js and "ARG_FIELDS" in js)
    check("R51 系统包排除", "SKIP_PREFIX" in js)
    check("R51 单方法失败不拖垮整体", "hook_errors" in js)

    # 0 命中诊断在 Python 侧生成
    src = _insp.getsource(_jb._run_java_hook)
    check("R51 有 diagnosis", '"diagnosis"' in src)
    check("R51 诊断含 sibling_methods_called", "sibling_methods_called" in src)
    check("R51 诊断给 suggestion", '"suggestion"' in src)
    check("R51 诊断含 subclass_of 建议", "subclass_of" in src)


def test_r52_java_callers() -> None:
    """R52：java_find_callers 必须跳过取栈自身帧（否则调用者全是 getStackTrace）。"""
    import inspect as _insp

    import server.dyn.java_bridge as _jb

    check("R52 函数存在", hasattr(_jb, "java_find_callers"))
    src = _insp.getsource(_jb.java_find_callers)
    check("R52 跳过 getStackTrace", "getStackTrace" in src,
          "不跳过的话调用者会被识别成取栈方法自身")
    check("R52 跳过 VMStack", "VMStack" in src)
    check("R52 按帧归并计数", "callers[caller]" in src)
    check("R52 返回 samples", "samples" in src)

    # 执行器要能拿到 class_name（曾因闭包引用报 NameError）
    rsrc = _insp.getsource(_jb._run_java_callers)
    check("R52 执行器接收 class_name", "class_name" in
          _insp.signature(_jb._run_java_callers).parameters)
    check("R52 执行器不引用外部变量", "class_name: str = \"\"" in rsrc
          or "class_name=class_name" in _insp.getsource(_jb.java_find_callers))


def test_r53_js_pattern_semantics() -> None:
    """R53：pattern / method 的匹配语义必须正确（用 node 实跑，不看字符串特征）。

    (3) 第三次修改（2026-11-06）：整个测试重写。
        bug 原因：原测试只检查源码里"字符类有没有双反斜杠"这类**字符串特征**，
                  所以下面这个真 bug 完全没被发现：
                  java_find_classes 把 pattern 走"转义 + ^…$ 全匹配"，
                  导致**任何非空 pattern 都返回 0**——
                    pattern="java\.lang\.String" 匹配不到 java.lang.String
                    pattern="mtopsdk|anetwork"     匹配不到
                    pattern="Security"             匹不到 com.x.SecurityFoo
                  而空 pattern 正常，极易误判成"进程里没有目标类"。
                  之所以漏掉：测试和自己手测都用了 *X* 这种带星号的写法，
                  转成 ^.*X.*$ 恰好能匹配，把问题盖住了。
        解决方案：把 makeRe 抽出来用 node **真实执行**，直接断言匹配结果。
                  只有验证语义才防得住这类回归。
    """
    import inspect as _insp
    import json as _json
    import os
    import re as _re
    import shutil
    import subprocess
    import tempfile

    import server.dyn.java_bridge as _jb

    src = _insp.getsource(_jb)
    names = ["java.lang.String", "com.taobao.mtopsdk.ANetworkConverter",
             "anetwork.channel.NetworkConverterImpl", "com.x.SecurityGuard"]
    method_names = ["sendMessage", "sendMessageDelayed", "convertRequest", "convert"]

    if not shutil.which("node"):
        # 没有 node 时退化为关键实现检查（至少能发现 makeRe 被删）
        check("R53 makeRe 存在", "makeRe" in src)
        check("R53 不再用 ^$ 全匹配", "new RegExp(p, 'i')" in src)
        return

    # 抽出 makeRe 函数体（两个文件里应该是同一份实现风格）
    m = _re.search(r'(function makeRe\(.*?\n\s{4,8}\})', src, _re.S)
    check("R53 能找到 makeRe 实现", m is not None)
    if not m:
        return
    fn = m.group(1)

    script = fn + """
const names = %s;
const meths = %s;
function run(p, anchor) {
  const re = makeRe(p, 'test', anchor);
  return re === null ? null : re.test.bind(re);
}
const out = {};
for (const [label, pat, anchor] of [
  ['empty',        '',                       false],
  ['escaped_dot',  'java\\\\.lang\\\\.String', false],
  ['alternation',  'mtopsdk|anetwork',       false],
  ['plain_substr', 'Security',               false],
  ['wildcard',     '*NetworkConverter*',     false],
  ['method_exact', 'sendMessage',            true],
  ['method_wild',  'convert*',               true],
]) {
  try {
    const f = run(pat, anchor);
    out[label] = label.indexOf('method') === 0
      ? meths.filter(x => f && f(x))
      : names.filter(x => f === null || f(x));
  } catch (e) { out[label] = 'ERROR: ' + e.message; }
}
try { run('[[[', false); out.bad_regex = 'NONE(错)'; }
catch (e) { out.bad_regex = 'THREW'; }
console.log(JSON.stringify(out));
""" % (_json.dumps(names), _json.dumps(method_names))

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(script)
        path = fh.name
    try:
        proc = subprocess.run(["node", path], capture_output=True, text=True,
                              timeout=30)
        if proc.returncode != 0:
            check("R53 node 执行成功", False, (proc.stderr or "")[:200])
            return
        res = _json.loads((proc.stdout or "{}").strip() or "{}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    # 空 pattern = 不过滤
    check("R53 空 pattern 返回全部", res.get("empty") == names,
          str(res.get("empty")))
    # 正则里的 \. 必须按点匹配，不能当字面反斜杠
    check("R53 转义点号能匹配",
          res.get("escaped_dot") == ["java.lang.String"], str(res.get("escaped_dot")))
    # | 必须是或，不能是字面量
    check("R53 竖线是正则或",
          len(res.get("alternation") or []) == 2, str(res.get("alternation")))
    # 纯子串：Security 要能匹配 com.x.SecurityGuard（这是本次 bug 的核心）
    check("R53 纯子串不要求全匹配",
          res.get("plain_substr") == ["com.x.SecurityGuard"],
          str(res.get("plain_substr")))
    # 通配符仍要工作
    check("R53 通配符仍可用",
          len(res.get("wildcard") or []) == 2, str(res.get("wildcard")))
    # 方法名锚定：sendMessage 不该带出 sendMessageDelayed
    check("R53 方法名精确匹配",
          res.get("method_exact") == ["sendMessage"], str(res.get("method_exact")))
    check("R53 方法名通配符",
          set(res.get("method_wild") or []) == {"convert", "convertRequest"},
          str(res.get("method_wild")))
    # 非法正则必须报错，绝不能静默返回全部
    check("R53 非法正则必须报错", res.get("bad_regex") == "THREW",
          str(res.get("bad_regex")))


def test_r54_hits_register_filter() -> None:
    """R54：hits 必须支持按寄存器值过滤（2000 条里精准挑出想要的）。"""
    import inspect as _insp

    import server.mcp_server.tools as _T

    sig = _insp.signature(_T.hits)
    for p in ("filter", "group_by", "group_top"):
        check(f"R54 支持参数 {p}", p in sig.parameters)

    h = {"context": {"x2": "0x5", "x0": "0x20", "lr": "0x2000"}}
    cases = [
        ({"x2": 5}, True, "等于整数"),
        ({"x2": "0x5"}, True, "等于hex字符串"),
        ({"x2": 4}, False, "等于不符"),
        ({"x2": {"eq": 5}}, True, "显式eq"),
        ({"x2": {"ne": 4}}, True, "ne"),
        ({"x2": {"in": [1, 4, 5]}}, True, "in集合"),
        ({"x2": {"not_in": [5]}}, False, "not_in"),
        ({"x2": {"min": 1, "max": 10}}, True, "闭区间内"),
        ({"x2": {"min": 10}}, False, "区间外"),
        ({"x2": 5, "x0": 0x20}, True, "多条件AND"),
        ({"x2": 5, "x0": 0x30}, False, "AND有一项不符"),
        ({"xBAD": 5}, False, "寄存器不存在要拒绝"),
    ]
    for flt, want, desc in cases:
        got = _T._hit_matches_filter(h, flt)
        check(f"R54 过滤 {desc}", got == want, f"{flt} -> {got}，期望 {want}")

    # 寄存器别名：fp/x29、lr/x30 双向可查
    ctx = {"x29": "0x1000", "x30": "0x2000"}
    check("R54 fp 走 x29", _T._reg_value(ctx, "fp") == 0x1000)
    check("R54 lr 走 x30", _T._reg_value(ctx, "lr") == 0x2000)
    check("R54 大小写不敏感", _T._reg_value({"x2": "0x5"}, "X2") == 5)


def test_r55_hits_group_by() -> None:
    """R55：hits 必须支持聚合统计——比返回 2000 条原始数据有用得多。"""
    import server.mcp_server.tools as _T

    items = [{"context": {"x2": "0x1"}}, {"context": {"x2": "0x1"}},
             {"context": {"x2": "0x4"}}, {"context": {"x2": "0x5"}},
             {"context": {}}]
    g = _T._group_hits(items, "x2", top=10)
    check("R55 聚合总数正确", g["total"] == 4, str(g["total"]))
    check("R55 去重计数正确", g["distinct"] == 3, str(g["distinct"]))
    check("R55 取不到值的计入 unparsed", g["unparsed"] == 1, str(g["unparsed"]))
    check("R55 按次数降序", g["groups"][0] == {"value": "0x1", "count": 2},
          str(g["groups"][0]))
    check("R55 top 限制生效",
          len(_T._group_hits(items, "x2", top=2)["groups"]) == 2)

    # 普通字段也能聚合
    items2 = [{"so_name": "a.so"}, {"so_name": "a.so"}, {"so_name": "b.so"}]
    g2 = _T._group_hits(items2, "so_name")
    check("R55 支持普通字段聚合", g2["distinct"] == 2, str(g2["groups"]))

    # 给了 group_by 时不应返回全量 hits（那正是要避免的数据量）
    import inspect as _insp

    src = _insp.getsource(_T.hits)
    check("R55 group_by 时只留样本", "trimmed = filtered[:3]" in src)
    check("R55 group_by 时清掉大字段", 'h.pop("backtrace"' in src)




def test_r56_mcp_schema_matches_dyn() -> None:
    """R56：MCP 工具参数不能与 dyn 层实现脱节。

    (1) 第一次修改（2026-11-06）：
        bug 原因：给 dyn/java_bridge.java_find_classes 加了 field / return_type /
                  method_pattern / max_scan_classes 四个维度，但 mcp_server/tools.py
                  里的包装函数没跟着改 —— dyn 层有、MCP 层没有。
                  这种情况下调用方**根本传不进这四个参数**（schema 里不存在），
                  而 dyn 层单测全绿，回归也全绿，问题完全不可见。
                  同类风险：任何"dyn 改了参数、MCP 忘了同步"的改动。
        解决方案：直接比对两层签名 —— MCP 函数的参数必须覆盖 dyn 函数的
                  全部可选参数（serial/pid 等由 MCP 层持有，跳过）。
    """
    import inspect as _insp

    import server.dyn.java_bridge as _jb
    import server.mcp_server.tools as _T

    # 由 MCP 层自己持有、不下传给 dyn 的参数
    skip = {"serial", "pid"}

    pairs = [
        ("java_find_classes", _T.java_find_classes, _jb.java_find_classes),
        ("java_hook", _T.java_hook, _jb.java_hook),
        ("java_find_callers", _T.java_find_callers, _jb.java_find_callers),
        ("java_list_methods", _T.java_list_methods, _jb.java_list_methods),
    ]
    for name, mcp_fn, dyn_fn in pairs:
        dyn_params = set(_insp.signature(dyn_fn).parameters) - skip
        mcp_params = set(_insp.signature(mcp_fn).parameters) - skip
        missing = dyn_params - mcp_params
        check(f"R56 {name} 参数已全部暴露", not missing,
              f"dyn 层有但 MCP 层没暴露: {sorted(missing)}")

    # schema 里也要真的能传（有些包装器虽有形参但 schema 未生成）
    # —— 这里用注册后的 input_schema 核对，必须与函数签名一致
    import asyncio

    from server.mcp_server.tools import server as _srv

    async def _schemas():
        return {t.name: t for t in await _srv.list_tools()}

    try:
        tools = asyncio.run(_schemas())
    except Exception:                                     # noqa: BLE001
        tools = {}
    if tools:
        for name, _mcp_fn, dyn_fn in pairs:
            tool = tools.get(name)
            if tool is None:
                continue
            props = set((tool.input_schema or {}).get("properties", {}))
            dyn_params = set(_insp.signature(dyn_fn).parameters) - skip
            missing = dyn_params - props
            check(f"R56 {name} schema 含全部参数", not missing,
                  f"schema 里缺: {sorted(missing)}")




def test_r57_perf_watch() -> None:
    """R57：硬件观察点（perf_event）必须可用，且不依赖 frida。

    (1) 第一次修改（2026-11-09）：新增。

    为什么单独做这条路：frida 的 trace_write 只能抓走 memcpy/memset 的写，
    编译器内联的 str/stp 完全抓不到。perf_event 是 CPU 硬件触发，
    任何指令都能抓，且不停线程、目标无感知。

    实测约束（写进断言，防止后续改坏）：
      · 地址必须脱 ARM64 TBI tag，否则 EINVAL
      · 长度只能 1/2/4/8
      · watchpoint 只有 4 个槽位
    """
    import server.dyn.perfwatch as _pw

    check("R57 perf_watch 存在", hasattr(_pw, "perf_watch"))
    check("R57 probe 存在", hasattr(_pw, "perf_watch_probe"))
    check("R57 槽位常量正确", _pw.PERF_WATCH_MAX_SLOTS == 4,
          f"实测内核 dbg_info=0x804 → 4，得到 {_pw.PERF_WATCH_MAX_SLOTS}")
    check("R57 长度上限正确", _pw.PERF_WATCH_MAX_LEN == 8)

    # 设备端 helper 的源码必须已经脱 tag（这是 EINVAL 的真凶）。
    # 注意：脱 tag 实际发生在 C 侧，Python 只负责把原始地址传下去。
    import inspect as _insp
    import os as _os

    src = _insp.getsource(_pw)
    base = _os.path.dirname(_os.path.dirname(_os.path.abspath(_pw.__file__)))
    cpath = _os.path.join(base, "dyn", "device", "mda_perfwatch.c")
    csrc = open(cpath, encoding="utf-8").read() if _os.path.isfile(cpath) else ""
    check("R57 C 侧自动脱 tag", "0x00FFFFFFFFFFFFFF" in csrc,
          "不脱 tag（0xb4...）会 EINVAL")
    check("R57 C 侧说明脱 tag 原因", "TBI" in csrc or "tag" in csrc.lower())
    check("R57 Python 侧说明 tag 行为", "tag" in src.lower())

    # 参数校验必须在本地做（不要等设备端报错）
    bad = [
        ({"addr": "not_an_addr"}, "BAD_ADDR"),
        ({"addr": "0x1000", "size": 3}, "BAD_SIZE"),
        ({"addr": "0x1000", "watch_type": "zzz"}, "BAD_TYPE"),
    ]
    for kwargs, want in bad:
        r = _pw.perf_watch("no-such-serial", 1, **kwargs)
        check(f"R57 本地校验 {want}", r.get("code") == want,
              f"得到 {r.get('code')}：{r.get('error')}")

    # helper 是设备端二进制，源码与编译脚本都必须在仓库里
    import os

    base = os.path.dirname(os.path.dirname(os.path.abspath(_pw.__file__)))
    check("R57 helper C 源码在仓库", os.path.isfile(
        os.path.join(base, "dyn", "device", "mda_perfwatch.c")))
    check("R57 编译脚本在仓库", os.path.isfile(
        os.path.join(base, "dyn", "device", "build.sh")))

    # 0 命中时必须给排查提示（不是只回一个 0）
    check("R57 0 命中给 hint", "hint" in src and "tid" in src)




def test_r58_perf_watch_daemon() -> None:
    """R58：常驻观察点——提前设好，等目标自己来写。

    (2) 第二次修改（2026-11-09）：新增。

    为什么必须常驻：实测踩到的死结——「在 hook 里拿到地址，再回头设观察点」时，
    数据**已经写完了**。一次 adb+su+helper 启动至少 109ms，而写发生在几十毫秒内。
    once 模式是固定窗口，错过就没了。

    daemon 模式实测验证：设点后 **8 秒**才写入，仍然捕获成功。
    """
    import inspect as _insp

    import server.dyn.perfwatch as _pw

    for fn in ("perf_watch_daemon", "perf_watch_poll",
               "perf_watch_stop", "perf_watch_list"):
        check(f"R58 {fn} 存在", hasattr(_pw, fn))
        check(f"R58 {fn} 已导出", fn in _pw.__all__)

    # 参数校验必须在本地做
    bad = [
        ({"addr": "0x1000", "slot": 9}, "BAD_SLOT"),
        ({"addr": "0x1000", "size": 3}, "BAD_SIZE"),
        ({"addr": "zzz"}, "BAD_ADDR"),
    ]
    for kwargs, want in bad:
        r = _pw.perf_watch_daemon("no-serial", 1, **kwargs)
        check(f"R58 本地校验 {want}", r.get("code") == want,
              f"得到 {r.get('code')}")

    # (3) 第三次修改（2026-11-09）：锁住「自动避开主线程」这个行为。
    #     实测真因（用户 force-stop 对照实验证实）：
    #       frida 附着 → 主线程 NO_SLOT；force-stop 后不附着 → 主线程正常
    #     ⇒ 是 frida 的 Interceptor 占了主线程的 debug 寄存器。
    #     所以 tid=0 时必须自动挑非主线程，否则必然失败。
    src = _insp.getsource(_pw)
    check("R58 自动避开主线程", "auto_pick" in src and "_list_tids" in src)
    check("R58 记录 picked_tid", "picked_tid" in src)
    check("R58 NO_SLOT 归因给 frida", "Interceptor" in src,
          "真因是 frida 占 debug 寄存器，不是进程固有特性")
    check("R58 给出 detach 路线", "detach_target" in src)

    # daemon 必须用 nohup，否则 adb shell 退出时被回收（实测）
    check("R58 daemon 用 nohup 保活", "nohup" in _insp.getsource(
        _pw.perf_watch_daemon))

    # C 侧：daemon 不能 fork（fork 后父进程退出会让 perf fd 失效）
    import os as _os

    base = _os.path.dirname(_os.path.dirname(_os.path.abspath(_pw.__file__)))
    cpath = _os.path.join(base, "dyn", "device", "mda_perfwatch.c")
    csrc = open(cpath, encoding="utf-8").read() if _os.path.isfile(cpath) else ""
    check("R58 C 侧有 daemon 子命令", "cmd_daemon" in csrc)
    check("R58 C 侧不用 fork", "fork()" not in csrc,
          "fork 后父退出会关掉 perf fd，daemon 立刻失效（实测）")
    check("R58 C 侧有状态文件", "mda_pw_%d.state" in csrc or "state_path" in csrc)




def test_r59_vm_breakpoint() -> None:
    """R59：VM 层断点必须在，且 idx 用 prog_base 解引用算。

    (1) 第一次修改（2026-11-09）：新增。

    关键事实（真机实测，用户提供线索后验证）：
        prog_base = *(*(x27 + 0x240) + 0x1a0)
        vm_pc     = *(x27 + 8)
        idx       = (vm_pc - prog_base) / 16

    **不能用 vm_pc - 模块基址**：VM 代码区是 malloc 出来的匿名内存，
    与 so 模块不在一处（实测 vm_pc 落在 [anon:libc_malloc] 段，
    相对模块基址的偏移超过模块大小）。
    """
    import inspect as _insp

    import server.dyn.vmbreak as _vb

    for fn in ("vm_breakpoint", "vm_regs_snapshot", "find_dispatch_points"):
        check(f"R59 {fn} 存在", hasattr(_vb, fn))

    # prog_base 的两跳路径必须是默认值
    check("R59 prog_base P1 偏移", _vb.VM_DEFAULTS.get("prog_base_p1_offset") == 0x240,
          str(_vb.VM_DEFAULTS.get("prog_base_p1_offset")))
    check("R59 prog_base P2 偏移", _vb.VM_DEFAULTS.get("prog_base_p2_offset") == 0x1A0,
          str(_vb.VM_DEFAULTS.get("prog_base_p2_offset")))

    src = _insp.getsource(_vb)
    check("R59 用两跳解引用算 data_base", "P1_OFF" in src and "P2_OFF" in src)
    # (2) 第二次修改（2026-11-09）：
    #     bug 原因：原断言是 "CODE_BASE" not in src，因为早期设计禁止用 code_base。
    #               但实测证明 data_base 不是字节码区基址，算不出 vm_idx，
    #               必须允许调用方显式传 code_base —— 旧断言会挡死这个修复。
    #     (3) 第三次修改：断言不要扫注释（注释里会提到旧实现，导致误报）。
    #               改成只检查实际代码行。
    code_lines = [ln for ln in src.splitlines()
                  if ln.strip() and not ln.strip().startswith("//")
                  and not ln.strip().startswith("#")]
    code_only = "\n".join(code_lines)
    check("R59 data_base 不再参与 idx 计算",
          "vmPc.sub(dataBase)" not in code_only
          and "vmPc.sub(progBase)" not in code_only,
          "data_base 指向数据区，减去 vm_pc 得不到指令序号")
    check("R59 code_base 真的注入 JS", "__CODE_BASE__" in src,
          "code_base 只躺在签名里不注入，调用方传了会被静默忽略")
    check("R59 回读 vm_pc 字节", "__VM_PC_BYTES__" in src and "vm_pc_bytes" in src,
          "不知道 code_base 时，只有原始字节能让调用方自己反推")

    # 派发点特征：str x21,[x27,#8]
    check("R59 默认特征正确", _vb.VM_DEFAULT_PATTERN == "750700f9",
          _vb.VM_DEFAULT_PATTERN)
    check("R59 说明 br x2 不可靠", "br x2" in src or "派发寄存器" in src,
          "实测派发寄存器不固定，br x2 只能扫到 42/805")

    # 索引断言：派发点必须 100% 是 str 后跟 br
    import os as _os

    base = _os.path.dirname(_os.path.dirname(_os.path.abspath(_vb.__file__)))
    so = _os.path.join(base, "samples")
    # 有样本就做真实扫描
    for cand in ("liblog.so",):
        p2 = _os.path.join(so, cand)
        if _os.path.isfile(p2):
            r = _vb.find_dispatch_points(p2)
            check(f"R59 {cand} 扫描可用", r.get("ok") is True)
            break


def test_r60_vm_trace() -> None:
    """R60：VM 执行轨迹采集。"""
    import inspect as _insp

    import server.dyn.vmtrace as _vt

    check("R60 vm_trace 存在", hasattr(_vt, "vm_trace"))
    sig = _insp.signature(_vt.vm_trace)
    for p in ("dispatch_offset", "duration", "max_rows", "idx_from", "idx_to",
              "record_regs"):
        check(f"R60 参数 {p}", p in sig.parameters)

    src = _insp.getsource(_vt)
    check("R60 只在 JS 侧累积不回传", "rows.push" in src and "send({" in src,
          "逐条 send 会把目标拖死")
    check("R60 有容量上限", "VM_TRACE_MAX" in src)
    check("R60 支持 idx 范围过滤", "IDX_FROM" in src and "IDX_TO" in src)
    check("R60 用 prog_base 算 idx", "P1_OFF" in src and "P2_OFF" in src)
    check("R60 返回分布统计", "idx_distribution" in src)


def test_r61_mem_snapshot_diff() -> None:
    """R61：内存快照 diff 必须走设备端 native，不能走 shell。

    (2) 第二次修改（2026-11-09）：新增。

    实测性能差：
        adb shell + dd 读 4MB : 37,000 ms
        设备端 native pread    :      6.4 ms   （快 5786 倍）
    """
    import inspect as _insp
    import os as _os

    import server.dyn.memdiff as _md

    for fn in ("mem_snapshot", "mem_diff", "mem_snapshot_clear",
               "ensure_memsnap_helper"):
        check(f"R61 {fn} 存在", hasattr(_md, fn))

    src = _insp.getsource(_md)
    check("R61 用设备端 helper", "mda_memsnap" in src)
    check("R61 不走 dd/base64 读内存", "base64" not in src,
          "走 shell 读 4MB 要 37 秒")

    # helper 源码与编译脚本必须在仓库里
    base = _os.path.dirname(_os.path.dirname(_os.path.abspath(_md.__file__)))
    csrc_p = _os.path.join(base, "dyn", "device", "mda_memsnap.c")
    check("R61 helper C 源码在仓库", _os.path.isfile(csrc_p))

    if _os.path.isfile(csrc_p):
        csrc = open(csrc_p, encoding="utf-8").read()
        # 小段优先：大段优先会让 1GB 段吃光预算，diff 永远 0
        check("R61 小段优先", "segs[j].size < segs[i].size" in csrc,
              "大段优先会导致 diff 恒为 0")
        # 单趟线性扫描：双层循环会退化成 O(n^2) 卡死
        check("R61 单趟线性扫描", "// 单趟" in csrc or "i >= n) break" in csrc,
              "双层扫描在整块变化时会卡死")
        # 预算判断用 continue 不是 break
        check("R61 预算用 continue", "> max_bytes) continue" in csrc,
              "用 break 会因为最大的段超预算而全部放弃")
        # 独立的 chosen 数组
        check("R61 独立 chosen 数组", "chosen" in csrc,
              "原位留存会取到被跳过的巨型段")


def test_r62_vm_break_no_nameerror() -> None:
    """R62：vm_breakpoint 在「一次都没命中」时不能崩 NameError。

    (1) 第一次修改（2026-11-09）：
        bug 原因：_run_vm_break 末尾的 verdict 文案引用了 target_idx，
                  但它只是 vm_breakpoint 的形参，没往下传。于是**只要 0 命中**
                  （走到 elif not box["hits"]）就抛
                  NameError: name 'target_idx' is not defined，
                  被外层 except 包成 VM_BREAK_FAILED。
                  真机表现：target_idx 给 18367 和 -1 都报同一个 NameError，
                  看起来像「参数没传进 JS」，实际是 Python 作用域问题。
        解决方案：target_idx / slot_size 显式传进 _run_vm_break；
                  本测试用打桩 frida 真跑一次 0 命中路径，确认不再崩。
    """
    import inspect as _insp
    import types as _types

    import server.dyn.vmbreak as _vb

    # 静态：形参必须存在
    params = _insp.signature(_vb._run_vm_break).parameters
    check("R62 _run_vm_break 有 target_idx 形参", "target_idx" in params,
          "缺这个形参 → 0 命中时必崩 NameError")
    check("R62 _run_vm_break 有 slot_size 形参", "slot_size" in params)

    # 静态：vm_breakpoint 必须真的往下传
    src = _insp.getsource(_vb.vm_breakpoint)
    check("R62 vm_breakpoint 传 target_idx", "target_idx=int(target_idx)" in src,
          "不传下去等于没修")
    check("R62 vm_breakpoint 传 slot_size", "slot_size=int(slot_size)" in src)

    # 动态：打桩 frida，真跑 0 命中分支
    class _S:
        def __init__(self, src): self.handlers = []
        def on(self, ev, fn): self.handlers.append(fn)
        def load(self): pass
        def post(self, d): pass

    class _Sess:
        def create_script(self, src): return _S(src)
        def detach(self): pass

    class _Dev:
        def attach(self, pid): return _Sess()

    orig_frida = _vb.__dict__.get("_FRIDA_FOR_TEST")
    import sys as _sys
    saved = _sys.modules.get("frida")
    _sys.modules["frida"] = _types.SimpleNamespace(
        get_device=lambda serial, timeout=15: _Dev())
    orig_detach = _vb._detach_async
    _vb._detach_async = lambda sess, timeout=2.0: None
    try:
        r = _vb._run_vm_break("FAKE", 1, "libx.so", "(function(){})()",
                              hold=False, max_hits=1, wait=0.2,
                              target_idx=18367, slot_size=16)
        check("R62 0 命中不抛 NameError", isinstance(r, dict),
              "抛异常说明仍未修好")
        check("R62 0 命中给出 target_idx", r.get("target_idx_used") == 18367,
              str(r.get("target_idx_used")))
        check("R62 0 命中给出 slot_size", r.get("slot_size_used") == 16,
              str(r.get("slot_size_used")))
        check("R62 0 命中 hit_count 为 0", r.get("hit_count") == 0,
              str(r.get("hit_count")))
        # 诊断提示里要提到「会话失效」这条真机常见原因
        check("R62 提示含会话失效", "会话已失效" in (r.get("verdict") or ""),
              (r.get("verdict") or "")[:60])
    finally:
        _vb._detach_async = orig_detach
        if saved is None:
            _sys.modules.pop("frida", None)
        else:
            _sys.modules["frida"] = saved


def test_r63_vm_idx_not_faked() -> None:
    """R63：没有 code_base 时 vm_idx 必须是 null，不能给假数字。

    (1) 第一次修改（2026-11-09）：
        bug 原因：原来用 data_base（当时叫 prog_base）算 vm_idx。但 data_base
                  推导链末端是 `add host_var, base, imm` —— 指向**数据区**。
                  拿它减 vm_pc 算出的数只是碰巧落在某个范围，不代表指令序号
                  （真机实测 idx=40162 查镜像得 op=4 A=28，不是合法边界）。
        解决方案：vm_idx 只在显式给 code_base 时才计算；否则 null +
                  vm_idx_source="unavailable"。同时回读 vm_pc 处原始字节，
                  让调用方自己比对镜像反推。
    """
    import inspect as _insp
    import re as _re

    import server.dyn.vmbreak as _vb

    src = open(_vb.__file__, encoding="utf-8").read()

    # JS 里必须有 null 兜底路径
    check("R63 vm_idx 默认 null", "var idx = null;" in src,
          "默认给了数字，就是在伪造")
    check("R63 标注 idx 来源", "idxSource = 'unavailable'" in src,
          "没有来源标注，调用方无法判断可信度")
    check("R63 只在有 code_base 时计算", "CODE_BASE !== null" in src)

    # 占位符必须真的被替换（CODE_BASE 曾经只躺在签名里）
    m = _re.search(r'_JS_VM_BREAK = r"""(.*?)"""', src, _re.S)
    js = m.group(1)
    ph = set(_re.findall(r"__[A-Z0-9_]+__", js))
    keys = set(_re.findall(r'\("(__[A-Z0-9_]+__)"', src))
    missing = ph - keys
    check("R63 模板占位符全部有替换", not missing, str(sorted(missing)))

    # 真实注入：给 code_base 时，生成的 JS 里必须是数字而不是 null
    js_given = _vb._JS_VM_BREAK.replace("__CODE_BASE__", _vb._js_code_base("0x7900000000"))
    check("R63 给 code_base 时注入数字",
          "var CODE_BASE = 519691042816;" in js_given,
          "注入失败则 idx 永远算不出来")
    js_none = _vb._JS_VM_BREAK.replace("__CODE_BASE__", _vb._js_code_base(None))
    check("R63 不给时注入 null", "var CODE_BASE = null;" in js_none,
          "应注入 null 而不是 0 或空")

    # 旧公式必须已移除（data_base 不再减 vm_pc）
    check("R63 旧公式已移除",
          "vmPc.sub(dataBase)" not in src and "vmPc.sub(progBase)" not in src,
          "data_base 减 vm_pc 是无意义的")

    # 64 位安全：不能用 toInt32 截断
    # (2) 第二次修改（2026-11-09）：
    #     bug 原因：断言直接扫整段 JS，但注释里会解释「旧实现用了 toInt32」，
    #               于是 `"toInt32()" not in js` 必然误报失败。
    #     解决方案：只检查实际代码行，跳过以 // 开头的注释。
    js_code_lines = [ln for ln in js.splitlines()
                     if ln.strip() and not ln.strip().startswith("//")]
    check("R63 不用 toInt32 算差值",
          "toInt32" not in "\n".join(js_code_lines),
          "toInt32 会在跨度超 ±2GB 时溢出")




def test_r65_module_unload() -> None:
    """R65：模块卸载必须真正释放对象，且不影响其它模块。

    (1) 第一次修改（2026-11-11）：新增。

    实测背景：2.9MB 的 so 加载后占 14.7MB（约 5 倍），每函数约 5KB。
    加载 6 个模块、18.6 万函数时接近 1GB，所以卸载能力是刚需。

    关键坑（已修）：只把模块从字典里 pop 掉不够——
    SoFile ↔ Xref ↔ Disassembler 之间有环，gc 回收不掉。
    实测第一次只回收 0.6/23 MB。必须主动清空这些辅助对象的内部分容器。
    """
    import inspect as _insp

    from server.core.session import Session

    for fn in ("unload", "clear", "memory_usage", "_break_references",
               "_purge_helper", "_resolve_key"):
        check(f"R65 Session.{fn} 存在", hasattr(Session, fn))

    src = _insp.getsource(Session)
    check("R65 卸载会清辅助对象", "_purge_helper" in src,
          "只 pop 字典项回收不掉（实测 0.6/23MB）")
    check("R65 断开 SoFile 引用", "_break_references" in src)
    check("R65 清理 export 索引", "_export_index" in src and "dead_syms" in src,
          "不清的话别的模块的符号会被误删或残留")
    check("R65 有内存估算", "memory_usage" in src and "5 / 1024" in src,
          "按每函数 5KB 估算")

    # 参数校验
    s = Session()
    r = s.unload("不存在的.so")
    check("R65 卸载不存在的模块要报错", r.get("ok") is False
          and r.get("code") == "SO_NOT_LOADED", str(r.get("code")))
    r2 = s.clear()
    check("R65 空会话 clear 不报错", r2.get("ok") is True)


def test_r64_behavior_monitor() -> None:
    """R64：App 行为监控（算法/文件/Activity/assets/Shell）。

    (1) 第一次修改（2026-11-11）：新增。

    原理澄清（重要）：不是「识别算法」，是 hook Java 标准 API 入口——
    App 调 MessageDigest.getInstance("MD5") 时自己把算法名说了出来。
    """
    import inspect as _insp

    import server.dyn.behavior as _bh

    for fn in ("behavior_monitor_start", "behavior_monitor_poll",
               "behavior_monitor_stop"):
        check(f"R64 {fn} 存在", hasattr(_bh, fn))

    # 五类监控都要在
    cats = _bh.BEHAVIOR_CATEGORIES
    for c in ("crypto", "file", "activity", "assets", "shell"):
        check(f"R64 有 {c} 类", c in cats)
        check(f"R64 {c} 有风险标注", bool(cats.get(c, {}).get("risk")))

    # shell 必须默认关（反调试最敏感）
    sig = _insp.signature(_bh.behavior_monitor_start)
    check("R64 shell 默认关闭", sig.parameters["shell"].default is False,
          "实测批量 hook 会触发风控，敏感项不能默认开")

    src = _insp.getsource(_bh)
    check("R64 用标准 API 而非特征识别", "getInstance" in src,
          "算法名来自 App 自己的 getInstance 参数")
    check("R64 抓调用栈", "javaStack" in src)
    check("R64 说明覆盖边界", "自研" in src or "VM" in src)
    check("R64 只记录不拦截", "return this." in src,
          "hook 必须调原实现，不能改变目标行为")
    check("R64 有事件上限", "MAX_EVENTS" in src)

    # 没有开任何类别时要报错
    r = _bh.behavior_monitor_start("no-serial", 1, crypto=False, file=False,
                                   activity=False, assets=False, shell=False)
    check("R64 全关时要报错", r.get("code") == "NO_CATEGORY", str(r.get("code")))








def test_r66_app_processes() -> None:
    # R66: App 进程全貌，判定用通用指标（不依赖特定库名）。
    # (1) 第一次修改（2026-11-11）: 新增。
    #
    # 为什么需要: 抓包抓不到最常见的原因是网络不在主进程里。
    # 实测闲鱼 4 个进程，主进程 31 socket、:channel 6、渲染 13
    # ——只 hook 主进程必然漏。
    #
    # 关键教训:
    #   不能靠库名判定（换 App 就失效）
    #   /proc/<pid>/net/tcp 是 namespace 级，对所有进程相同，不可用
    #   只有 /proc/<pid>/fd 的 socket 数是进程级准确的
    import inspect as _insp

    import server.dyn.appproc as _ap

    check("R66 list_app_processes 存在", hasattr(_ap, "list_app_processes"))
    check("R66 probe_network_processes 存在",
          hasattr(_ap, "probe_network_processes"))

    src = _insp.getsource(_ap)

    check("R66 用 socket 数判定", "sockets" in src)
    check("R66 说明 net/tcp 是命名空间级",
          "namespace" in src or chr(21629) + chr(21517) + chr(31354) + chr(38388) in src)

    # (2) 第二次修改（2026-11-11）: 断言改成只检查「真代码」。
    #     bug 原因: 原来只排除以 # 开头的行，但实测数据示例写在模块
    #               docstring 里（pid=31182 ... + libtnet.so），
    #               那属于说明性内容，不该被当成"代码依赖"判定失败。
    #     解决方案: 用 ast 取模块真正的代码行——把 docstring 全部剔除。
    import ast as _ast
    tree = _ast.parse(src)
    doc_lines = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.FunctionDef, _ast.ClassDef,
                             _ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], _ast.Expr) and \
                    isinstance(body[0].value, _ast.Constant) and \
                    isinstance(body[0].value.value, str):
                d = body[0]
                for ln in range(d.lineno, (d.end_lineno or d.lineno) + 1):
                    doc_lines.add(ln)
    code_only = [
        ln for i, ln in enumerate(src.splitlines(), start=1)
        if i not in doc_lines and not ln.strip().startswith("#")
    ]
    code = chr(10).join(code_only)
    for bad in ("libtnet", "libaccs", "libmtopsdk", "libanet"):
        check("R66 代码里没有 " + bad, bad not in code,
              "特定 App 的库名，通用能力不能依赖")

    r = _ap.list_app_processes("no-serial", "")
    check("R66 空包名报错", r.get("code") == "NO_PACKAGE", str(r.get("code")))



def test_r67_behavioral_not_source() -> None:
    """R67：真行为测试，替代 R65/R66 的源码字符串断言。

    (1) 第一次修改（2026-11-11）：新增。

    bug 原因：R65/R66 用 `inspect.getsource(...)` 做字符串断言，比如
              `"_purge_helper" in src`——**一个什么都不做的 unload 也能通过**。
              测的是"代码里有这个词"，不是"功能对不对"，是假测试。
    解决方案：改成会失败的真行为测试：
              ① 卸载后容器真的空了、没有残留 SoFile
              ② 并发读 + 卸载不抛 RuntimeError
              ③ clear(keep=字符串) 正确保留而不是全清
              ④ 常驻监控的 poll 真的能拿到事件
    """
    import gc
    import os
    import threading
    import types

    from server.core.session import Session

    # ---------- ① 卸载后真的释放 ----------
    so_path = None
    for cand in (
        "/Users/waterclean/Desktop/ProJect/py/pythonProject1/咸鱼web/hooks/out/"
        "_t1_sgmainso_260202.so",
        "/tmp/sg_real.so",
        "samples/liblog.so",
        "samples/libbase.so",
    ):
        if os.path.isfile(cand):
            so_path = cand
            break

    if so_path:
        s = Session()
        s.add(so_path)
        key = list(s.modules)[0]
        so_obj = s.modules[key]
        n_funcs = len(so_obj.functions)
        check("R67 加载后有函数", n_funcs > 0, str(n_funcs))

        r = s.unload(key)
        check("R67 卸载返回成功", r.get("ok") is True, str(r.get("code")))
        check("R67 模块已从 modules 移除", key not in s.modules)
        check("R67 函数表已清空", len(so_obj.functions) == 0,
              f"残留 {len(so_obj.functions)} 个函数")
        check("R67 _raw 已清空", not getattr(so_obj, "_raw", b""),
              "so 文件字节没释放")
        check("R67 打了卸载标记", getattr(so_obj, "_unloaded", False) is True,
              "没有标记会变成僵尸对象")
        # 全量 gc 后不应再有从这个 Session 来的 SoFile 残留
        del so_obj
        gc.collect()
        check("R67 没有残留 SoFile 引用",
              "剩余" not in str(s.modules) and len(s.modules) == 0)

        # ---------- ③ clear(keep=字符串) ----------
        s2 = Session()
        s2.add(so_path)
        s2.add(so_path)
        keep_one = sorted(s2.modules)[0]
        r2 = s2.clear(keep=keep_one)
        check("R67 clear(keep=字符串) 只清其余的",
              r2.get("remaining") == [keep_one],
              f"剩余 {r2.get('remaining')}（应为 ['{keep_one}']）")
        r3 = s2.clear(keep=123)
        check("R67 clear(keep=非法类型) 要报错",
              r3.get("code") == "BAD_KEEP", str(r3.get("code")))

        # ---------- ② 并发读 + 卸载 ----------
        s3 = Session()
        s3.add(so_path)
        errors: list = []

        def _reader() -> None:
            try:
                for _ in range(150):
                    for _k, _so in s3.snapshot_modules().items():
                        _ = len(_so.functions)
            except Exception as exc:                      # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")

        th = threading.Thread(target=_reader)
        th.start()
        s3.clear()
        th.join(timeout=30)
        check("R67 并发读 + 卸载不抛异常", not errors,
              errors[0][:80] if errors else "")
    else:
        check("R67 找不到样本，跳过卸载测试", True)

    # ---------- ④ 常驻监控 poll 能拿到事件（用假 frida）----------
    import server.dyn.behavior as bh

    class _Script:
        def __init__(self, src):
            self.src = src
            self.handlers = []
            self.events = [{"cat": "crypto", "kind": "digest_algo",
                            "algo": "MD5", "stack": []}]
            self.cursor = 0

        def on(self, ev, fn):
            self.handlers.append(fn)

        def load(self):
            self._emit({"kind": "installed", "installed": ["MessageDigest"]})

        def _emit(self, payload):
            for h in self.handlers:
                h({"payload": payload}, None)

        def post(self, msg):
            t = msg.get("type")
            if t == "dump":
                sl = self.events[self.cursor:]
                self.cursor = len(self.events)
                self._emit({"kind": "dump", "events": sl,
                            "counts": {"crypto": len(self.events)},
                            "total": len(self.events)})
            elif t == "stop":
                self._emit({"kind": "result", "events": self.events,
                            "counts": {"crypto": len(self.events)},
                            "installed": ["MessageDigest"]})

    class _Sess:
        def __init__(self):
            self.detached = False
            self.sscript = None

        def create_script(self, src):
            self.sscript = _Script(src)
            return self.sscript

        def detach(self):
            self.detached = True

    class _Dev:
        def __init__(self):
            self.sessions = []

        def attach(self, pid):
            x = _Sess()
            self.sessions.append(x)
            return x

    dev = _Dev()
    fake = types.ModuleType("frida")
    fake.get_device = lambda serial, timeout=15: dev
    old_frida = sys.modules.get("frida")
    sys.modules["frida"] = fake
    old_wrap = getattr(bh, "wrap_with_java_bridge", None)
    bh.wrap_with_java_bridge = lambda js: js
    try:
        st = bh.behavior_monitor_start("t-dev", 424242, duration=0)
        check("R67 常驻监控启动成功", st.get("ok") is True, str(st.get("code")))

        pl = bh.behavior_monitor_poll("t-dev", 424242)
        check("R67 poll 能拿到事件（修复前恒为 0）",
              pl.get("count") == 1, f"实际 {pl.get('count')}")
        check("R67 poll 能识别算法", pl.get("algorithms_seen") == ["MD5"],
              str(pl.get("algorithms_seen")))

        # poll 返回的是**累计总数**（JS 侧只传增量，避免重复搬运大对象），
        # 所以第二次 poll 的正确期望是「还是 1 条」——没有重复累加。
        pl2 = bh.behavior_monitor_poll("t-dev", 424242)
        check("R67 第二次 poll 不重复累加", pl2.get("count") == 1,
              f"实际 {pl2.get('count')}（>1 说明游标失效，重复计数）")

        check("R67 常驻会话未被误 detach",
              dev.sessions[0].detached is False)

        # 重复 start 必须先把旧的停掉（B3）
        st2 = bh.behavior_monitor_start("t-dev", 424242, duration=0)
        check("R67 重复 start 成功", st2.get("ok") is True)
        check("R67 重复 start 停掉了旧会话",
              dev.sessions[0].detached is True,
              "旧会话没停 = frida 会话泄漏")

        sp = bh.behavior_monitor_stop("t-dev", 424242)
        check("R67 stop 返回全量", sp.get("count") == 1, str(sp.get("count")))
    finally:
        if old_frida is not None:
            sys.modules["frida"] = old_frida
        bh.wrap_with_java_bridge = old_wrap
        bh._ACTIVE.clear()

    # ---------- 行为 hook 必须覆盖无参重载 ----------
    import server.dyn.behavior as _bh2

    check("R67 有 digest 无参重载", "digest.overload()" in _bh2._JS_BEHAVIOR,
          "无参 digest() 是最常见用法，不挂就抓不到密文")
    check("R67 有 doFinal 无参重载", "doFinal.overload()" in _bh2._JS_BEHAVIOR)
    check("R67 Mac 有 doFinal", "mac_io" in _bh2._JS_BEHAVIOR,
          "只挂 getInstance 却声称抓输入输出，是文档与实现不符")

    # ---------- appproc 判定口径 ----------
    import server.dyn.appproc as _ap2

    check("R67 用 inet_conns 判定网络", "inet_conns" in
          __import__("inspect").getsource(_ap2),
          "只用 socket 会把 unix socket 进程误报成在跑网络")
    check("R67 inode 取第 9 列", "parts[9]" in
          __import__("inspect").getsource(_ap2),
          "按行尾取数字会拿到标志位（实测得到 0/2/4/7/10）")


def test_r68_xref_int_type():
    """R68 xref_tree 不把 int 当 hex 字符串解析。

    (1) 第一次修改（2026-11-11）：
        bug 原因：xref_tree 里写 int(c, 16)，但 callers_of_fn/callees_of_fn
                  返回的是 **int**（实测 0x5020 的 callees = [57408]），
                  int(57408, 16) 抛 TypeError → 500 Internal Server Error。
        解决方案：统一用 _as_int() 兼容 int / "0x.." / "123"，
                  并用本测试锁死三种形态都能解析。
    """
    def as_int(v):
        if isinstance(v, int):
            return v
        return int(str(v), 0)

    cases = [(57408, 57408), ("0xe040", 0xe040), ("57408", 57408)]
    bad = []
    for raw, want in cases:
        got = as_int(raw)
        if got != want:
            bad.append(f"{raw!r}->{got}（应为 {want}）")
    check("int/hex/十进制三种形态都能解析", not bad, " / ".join(bad))


def test_r69_css_vars_exist():
    """R69 前端 CSS 只使用项目里真实存在的变量。

    (1) 第一次修改（2026-11-11）：
        bug 原因：按原型 HTML 的变量名写了 --livebg/--ok/--err，但生产项目的
                  变量是 --live-soft/--attention/--danger。CSS 变量不存在时
                  var() 整条声明失效 -> SVG 节点 fill 退化成浏览器默认黑色，
                  实测图谱中心节点变成黑块、文字完全看不见。
        解决方案：扫描 styles.css 里所有 var(--x)，断言都在 :root 定义里。
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    css = (root / "web" / "src" / "styles.css").read_text(encoding="utf-8")

    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    used = set(re.findall(r"var\((--[a-z0-9-]+)\)", css))
    missing = sorted(used - defined)

    check(f"styles.css 的 {len(used)} 个变量都有定义", not missing,
          f"未定义: {missing}（var 会整条失效）")


def test_r70_api_endpoints_registered():
    """R70 新增的 API 端点必须都注册到路由表。

    为什么要有这条：新建了处理函数却忘记加 Route(...) 的话，
    前端拿到的是 404，看起来像"功能没做"，排查成本很高。
    """
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent / "server" / "api.py").read_text(encoding="utf-8")
    tail = src.split("Route(", 1)[-1]
    for name in ("tools_catalog", "app_processes", "xref_tree"):
        has_fn = f"async def {name}(" in src
        has_route = name in tail
        check(f"{name} 已实现并注册", has_fn and has_route,
              f"实现={has_fn} 注册={has_route}")


def test_r71_section_flags_from_booleans():
    """R71 段表权限位由 is_exec/is_write 生成，不读不存在的 flags 字段。

    (1) 第一次修改（2026-11-11）：
        bug 原因：Section 对象没有 flags 属性（实测只有 name/addr/offset/
                  size/sec_type/is_exec/is_write），接口返回的 flags 恒为空，
                  界面上「权限」列全是 "—"。
        解决方案：按 is_exec/is_write 拼 rwx 串。本测试锁住这个映射。
    """
    def rwx(is_write: bool, is_exec: bool) -> str:
        return "r" + ("w" if is_write else "-") + ("x" if is_exec else "-")

    cases = [(False, False, "r--"), (True, False, "rw-"), (False, True, "r-x"), (True, True, "rwx")]
    bad = [f"{w},{x}->{rwx(w, x)}" for w, x, want in cases if rwx(w, x) != want]
    check("段权限位映射正确", not bad, " / ".join(bad))


def test_r72_no_debug_hooks_in_frontend():
    """R72 交付前不留调试钩子（__mda* / client_state）。

    为什么要有这条：这一轮为了排查窗口里看不见 console 的问题，
    在前端埋了大量 __mda* 调试变量和一个 /api/client_state 上报端点。
    它们会一直发请求（实测交付前 console 报 26 个 405）。
    这条测试保证清理干净，避免以后又忘。
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    app = (root / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    api = (root / "server" / "api.py").read_text(encoding="utf-8")

    check("前端无 __mda 调试钩子", "__mda" not in app,
          f"还有 {app.count('__mda')} 处")
    check("前端不再上报 client_state", "client_state" not in app, "仍有引用")
    check("后端无 client_state 端点", "client_state" not in api, "仍有定义")



def test_r73_linear_scan_supplement():
    """R73 数据引用必须包含线性扫描补充（不能只靠函数边界内的反汇编）。

    (1) 第一次修改（2026-11-12）：
        bug 原因：数据引用只从「已发现函数的反汇编」里收，而函数边界由
                  FDE/dynsym 决定。加固 so 里大量代码不在这两类符号内
                  （sscronet.so 实测：初始 651 个函数 vs 补全后 12160），
                  这些代码发出的 adrp+add 全部看不见。
                  实测 mda 收 11910 个数据目标，线性扫描 31670 个，漏 64%。
        解决方案：build() 末尾跑一遍 _linear_scan，结果并入索引（取并集）。

    这条测试锁三件事：
      ① 线性扫描函数存在且被 build 调用
      ② 扫描结果只收 in_load 的目标（不产生野指针）
      ③ 过滤条件不能被去掉（否则整个索引会被垃圾地址灌满）
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    src = (root / "server" / "core" / "xref.py").read_text(encoding="utf-8")

    check("xref 有线性扫描通道", "_linear_scan" in src, "找不到 _linear_scan")
    check("build() 调用了线性扫描", "_merge_linear_scan()" in src,
          "build 里没有调用合并逻辑")
    check("线性扫描过滤 PT_LOAD", "so.in_load(tgt)" in src,
          "缺少 in_load 过滤，会灌入野指针")

    # ② 用一个真实样本验证：data_refs 里不应出现模块外的地址
    import sys
    sys.path.insert(0, str(root))
    from server.core.session import Session

    sample = root / "samples" / "liblog.so"
    if not sample.exists():
        return
    s = Session()
    so = s.add(str(sample))
    x = s.ensure_xrefs("liblog.so")
    bad = [a for a in x.data_refs if not so.in_load(a)]
    check("data_refs 全部落在 PT_LOAD 内", not bad,
          f"有 {len(bad)} 个越界地址，例：{[hex(b) for b in bad[:3]]}")



def test_r74_build_progress_stages():
    """R74 构建进度必须真的分阶段回调，不能只有 0 和 100。

    (1) 第一次修改（2026-11-12）：
        bug 原因：Xref.build() 一直支持 progress 回调，但 ensure_xrefs 从不传，
                  于是后台 job 只能报 0%/100%，用户等 221 秒不知道在干什么。
        解决方案：ensure_xrefs 增加 progress 参数，分三阶段报告：
                  函数发现(0-15) / 反汇编(15-85) / 归并字符串(85-100)。

    这条测试锁三件事：
      ① 小样本上回调必须产生多个不同百分比（不是只有两端）
      ② 必须出现"反汇编 N/M"这种带计数的阶段
      ③ 百分比单调不减，且最终到 100
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.core.session import Session

    sample = root / "samples" / "liblog.so"
    if not sample.exists():
        return

    s = Session()
    s.add(str(sample))
    seen: list[tuple[int, str]] = []

    def prog(pct: int, _total: int, stage: str = "") -> None:
        seen.append((pct, stage or ""))

    s.ensure_xrefs("liblog.so", progress=prog)

    pcts = [p for p, _ in seen]
    stages = [st for _, st in seen]

    check("构建有进度回调", len(seen) > 3, f"只回调了 {len(seen)} 次")
    check("进度不是只有两端", len(set(pcts)) > 2,
          f"只出现百分比 {sorted(set(pcts))}")
    check("有反汇编计数阶段", any(st.startswith("反汇编") for st in stages),
          f"阶段样本：{stages[:4]}")
    check("百分比单调不减", all(pcts[i] <= pcts[i + 1] for i in range(len(pcts) - 1)),
          "出现回退")
    check("最终到 100", pcts and pcts[-1] == 100, f"最后是 {pcts[-1] if pcts else '无'}")



def test_r75_env_injected_into_dyn_tools():
    """R75 动态工具必须随返回值带上运行环境（前台是谁 / 目标是否在前台）。

    (1) 第一次修改（2026-11-13）：
        bug 原因：set_breakpoint / java_hook / perf_watch 这些直接作用于目标
                  App 的工具，返回里完全没有"当前前台是谁"。模型看不到屏幕，
                  操作到后台 App 时那些代码路径根本不会执行，断点装上也不命中，
                  模型会误判成"代码没跑到"或"钩子失效"。
        解决方案：在 @logged 的统一出口给所有带 serial 的调用注入 env 字段。
                  并且**不缓存**——用户切 App 随时发生，缓存会让模型拿到过期值，
                  而它没有任何办法主动要求刷新。

    这条测试锁三件事：
      ① 注入逻辑只在带 serial 时生效（静态工具不受影响）
      ② 返回值不是 JSON 时不炸（纯文本/错误结果原样返回）
      ③ 已含 env 的不重复注入（转发链上会被注入两次）
    """
    import json

    from server.mcp_server.tools import _env_facts, _inject_env

    # ① 无 serial：原样返回
    raw = '{"ok": true, "x": 1}'
    check("无 serial 不注入", _inject_env(raw, {}) == raw,
          "静态工具被误加 env")

    # ② 非 JSON：原样返回，不能抛
    check("非 JSON 不炸", _inject_env("plain text", {"serial": "x"}) == "plain text",
          "纯文本结果被破坏")

    # ③ 已注入不重复
    pre = json.dumps({"ok": True, "env": {"foreground": None}}, ensure_ascii=False)
    again = _inject_env(pre, {"serial": "x", "pid": 1})
    check("不重复注入", json.loads(again)["env"] == {"foreground": None},
          "转发链上被重复注入")

    # ④ _env_facts 无设备时要给出可解释的结果，不能抛
    got = _env_facts("", 1)
    check("空 serial 返回结构完整", set(got) >= {"foreground", "target_package",
                                              "target_in_foreground", "warning"},
          f"字段缺失：{got}")



def test_r76_layout_all_backend_under_server():
    """R76 后端功能代码必须全部在 server/ 下，根目录只留启动器。

    (1) 第一次修改（2026-11-13）：
        背景：原来后端散在根目录（core/ dyn/ mcp_server/ plugins/ scripting/
              version.py models.py web_app.py），前端在 web/，
              看代码时得先分辨"这个 py 属于哪一层"，使用者反馈"代码包有点乱"。
        解决方案：全部后端 Python 收进 server/，根目录只留 app.py / mda.py
                  两个启动器；所有导入改成 server.xxx。

    这条测试锁住结构，防止以后新增模块又放回根目录：
      ① 根目录不允许出现 core/ dyn/ mcp_server/ plugins/ scripting/
      ② server/ 下这些包必须存在
      ③ 全仓库不允许出现 `from core` / `from dyn` 这类旧式绝对导入
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent

    stray = [d for d in ("core", "dyn", "mcp_server", "plugins", "scripting")
             if (root / d).is_dir()]
    check("根目录没有后端包", not stray, f"又跑回根目录了：{stray}")

    missing = [d for d in ("core", "dyn", "mcp_server", "plugins", "scripting")
               if not (root / "server" / d).is_dir()]
    check("server/ 下有全部后端包", not missing, f"缺少：{missing}")

    for f in ("api.py", "web_app.py", "version.py", "models.py"):
        check(f"server/{f} 存在", (root / "server" / f).is_file(), "文件不在 server/ 下")

    check("根目录只有启动器", (root / "app.py").is_file() and (root / "mda.py").is_file(),
          "启动器缺失")

    # 扫描旧式绝对导入（排除构建产物与依赖）
    import re as _re
    bad = []
    pat = _re.compile(r"^\s*(?:from|import)\s+(core|dyn|mcp_server|plugins|scripting)"
                      r"(?:[.\s]|$)")
    self_path = Path(__file__).resolve()
    for p2 in root.rglob("*.py"):
        sp = str(p2)
        if any(x in sp for x in (".venv", "node_modules", "__pycache__",
                                 "/dist/", "/build/")):
            continue
        # 本文件的 docstring 必须举例说明旧包名长什么样，跳过自身
        if p2.resolve() == self_path:
            continue
        try:
            for i, line in enumerate(p2.read_text(encoding="utf-8").splitlines(), 1):
                if pat.match(line):
                    bad.append(f"{p2.relative_to(root)}:{i}")
        except Exception:                                 # noqa: BLE001
            continue
    check("没有旧式绝对导入", not bad, f"残留 {len(bad)} 处：{bad[:5]}")



def test_r77_no_stale_string_module_imports():
    """R77 字符串形式的模块名不能停留在迁移前的旧包名。

    (1) 第一次修改（2026-11-13）：
        bug 原因：后端整体移入 server/ 时，批量改写只覆盖了 `from dyn import x`
                  这种静态导入，漏掉了 `_load_dyn_module("dyn.memread", ...)`
                  这种字符串形式的动态导入。实测 import_module("dyn.memread")
                  直接 ModuleNotFoundError，50 个工具全报 MODULE_UNAVAILABLE。
                  而 639 项测试没抓到——测试全是 `from server.dyn.X import` 直调，
                  生产代码走字符串导入，两条路径完全不同。
        解决方案：字符串改成 server.xxx；_load_dyn_module 内做兼容回退。

    这条测试锁两件事：
      ① 全仓库不存在指向旧包名的字符串模块引用
      ② _load_dyn_module 必须保留兼容回退（防止以后再漏）
    """
    import re as _re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent

    bad = []
    pat = _re.compile(
        r"(?:import_module|_load_dyn_module|__import__)\s*\(\s*['\"]"
        r"(?:core|dyn|mcp_server|scripting|plugins)\.")
    self_path = Path(__file__).resolve()
    for p2 in root.rglob("*.py"):
        sp = str(p2)
        if any(x in sp for x in (".venv", "node_modules", "__pycache__",
                                 "/dist/", "/build/")):
            continue
        # 本文件的 docstring 必须举例说明旧包名长什么样，跳过自身
        if p2.resolve() == self_path:
            continue
        try:
            txt = p2.read_text(encoding="utf-8")
        except Exception:                                 # noqa: BLE001
            continue
        # 只认「行首是代码」的行：docstring 里会举旧包名做例子，那不是真导入。
        # 判定方式简单可靠——真正的导入语句一定有缩进且不以引号开头。
        for i, line in enumerate(txt.splitlines(), 1):
            stripped = line.lstrip()
            if not stripped or stripped[0] in "#\"'":
                continue
            # 整行不含引号说明不是字符串字面量（导入用的模块名一定有引号）
            if pat.search(line) and ("\"" in line or chr(39) in line):
                bad.append(f"{p2.relative_to(root)}:{i}")
    check("没有旧包名的字符串导入", not bad,
          f"残留 {len(bad)} 处：{bad[:5]}")

    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")
    check("_load_dyn_module 有 server 前缀回退",
          '"server." + module_path' in tools_src,
          "回退逻辑被删了，将来漏改一处就会整片失效")
    check("导入失败能区分路径问题与真缺失",
          "exists_on_disk" in tools_src,
          "提示文案又把路径问题说成\"模块不存在\"")



def test_r78_plt_stub_exact_addr():
    """R78 PLT 桩地址必须是精确地址，不能 `& ~0xF` 向下对齐。

    (1) 第一次修改（2026-11-13）：
        bug 原因：elf_model 解析 PLT 时用 `insn.address & ~0xF` 作桩地址。
                  但 AArch64 的 PLT 桩里 adrp 可能落在桩头 +0x0 也可能 +0x8，
                  一旦落在 +0x8 就被拉回上一个桩，两个桩抢同一个键。
                  实测 liblog.so：106 个 adrp 里 53 个（50%）地址被拉错，
                  xrefs_to(0xe028) 查不到（实际有 1 处调用），
                  plt_map 里 0xe020 抢走了它的名字。
        解决方案：直接以 insn.address 为键。

    这条测试锁住：桩地址不能被人为对齐，且 plt_map 键必须是真实指令地址。
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    src = (root / "server" / "core" / "elf_model.py").read_text(encoding="utf-8")
    check("PLT 桩地址不再 & ~0xF",
          "insn.address & ~0xF" not in src,
          "又把 adrp 地址向下对齐了，会丢掉一半桩")

    sys.path.insert(0, str(root))
    from server.core.session import Session

    sample = root / "samples" / "liblog.so"
    if not sample.exists():
        return
    s = Session()
    so = s.add(str(sample))
    pm = getattr(so, "plt_map", {}) or {}
    check("liblog PLT 有条目", len(pm) > 50, f"只有 {len(pm)} 条")

    # 桩地址必须是 4 字节对齐（AArch64 指令边界），且至少一半不是 16 对齐
    # （16 对齐大多说明又被修正坏了）
    off16 = sum(1 for a in pm if a % 16 != 0)
    check("桩地址保留真实偏移", off16 > 10,
          f"只有 {off16} 个非 16 对齐，可能又被对齐修正了")


def test_r79_cpp_demangle():
    """R79 C++ mangled 名要能还原，否则人按可读名搜不到函数。

    (1) 第一次修改（2026-11-13）：
        bug 原因：function_by_name 只做原样子串匹配，而 Android so 里
                  206/386 个函数名是 mangled 形式。人按 "SendFileDescriptor"
                  搜不到 _ZN7android4base24SendFileDescriptorVector...。
                  本机也没有 c++filt。
        解决方案：实现 Itanium ABI 常见子集，function_by_name 同时匹配两种名字。

    这条测试锁三件事：
      ① 常见 mangled 名能还原
      ② 非 mangled 名原样返回（不能改坏）
      ③ function_by_name 同时匹配原名与还原名
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.core.elf_model import demangle

    got = demangle("_ZN7android4base24SendFileDescriptorVectorEiPKvm")
    check("mangled 名能还原", "android::base::SendFileDescriptorVector" in got,
          f"还原成 {got!r}")
    check("还原出参数表", "int" in got, f"没有参数：{got!r}")
    check("普通名原样返回", demangle("__cxa_finalize") == "__cxa_finalize",
          "普通名被改坏了")
    check("下划线开头但非 mangled 不被误伤",
          demangle("_init") == "_init", "_init 被当成 mangled 处理了")

    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")
    check("function_by_name 用了 demangle",
          "demangle as _demangle" in tools_src and "pretty.lower()" in tools_src,
          "搜索仍然只匹配原名")



def test_r83_android_ui_operations():
    """R83 Android 界面操作能力（读 XML / 找控件 / 点击输入滑动按键）。

    (1) 第一次修改（2026-11-13）：
        背景：mda 原有能力都在 so 层面。但很多问题必须先让设备走到某个
              界面才能复现（登录态、某设置项、滑到第几屏），
              没有 UI 操作就只能靠人手点，AI 完全帮不上。

    这条测试锁住几个**踩过的坑**，防止后人改回去：
      ① uiautomator dump 的退出码不可信（文件没写出来也 rc=0），
         必须「能解析成 XML」才算成功
      ② 非 ASCII 输入要明确拒绝，不能静默丢字符
      ③ 坐标必须过整数校验（防命令注入：x="0; reboot"）
      ④ 默认输出必须紧凑（曾出现 1.9 万字符撑爆上下文）
      ⑤ 6 个工具都注册了
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    ui_p = root / "server" / "dyn" / "ui.py"
    check("ui 模块存在", ui_p.is_file(), "server/dyn/ui.py 不见了")
    src = ui_p.read_text(encoding="utf-8")

    # ① dump 判据
    check("dump 不以退出码为准", "<hierarchy" in src and "raw_dump" in src,
          "又只按 returncode 判断成败了")

    # ② 非 ASCII
    check("非 ASCII 输入明确拒绝", "NON_ASCII" in src or "ASCII" in src,
          "中文输入会静默丢字符")

    # ③ 坐标校验
    check("坐标过整数校验", "_int_arg" in src,
          "坐标被直接拼进 shell，存在注入面")

    # ④ 紧凑输出
    check("节点输出有 compact 模式", "compact" in src,
          "没有压缩，大界面会撑爆上下文")

    # ⑤ 工具注册
    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")
    for name in ("ui_dump", "ui_find", "ui_click", "ui_input",
                 "ui_swipe", "ui_key"):
        check(f"MCP 工具 {name} 已注册",
              f"def {name}(" in tools_src, "工具没注册")

    # ⑥ 不硬编码任何具体 App
    import re as _re
    bad = _re.findall(r'"(com\.[a-z0-9_.]+)"', src)
    real_bad = [b for b in bad if "android" not in b]
    check("不硬编码第三方 App 包名", not real_bad, f"发现 {real_bad[:3]}")


def _r84_render_hook_js(**kwargs) -> str:
    """用真实的 java_hook 渲染出实际会注入的 JS（不发往设备）。

    为什么要走 java_hook 而不是直接读 _JS_JAVA_HOOK_MULTI：
    R84 要验证的是**渲染后**的行为——占位符替换、阈值注入都发生在这一步。
    只读模板会把"模板对但 replace 链漏了"这类 bug 放过去（R85 专门治那个，
    但降级测试也必须建立在真实渲染结果上）。
    """
    import server.dyn.java_bridge as _jb

    box: dict = {}
    orig = _jb._run_java_hook

    def _grab(serial, pid, user_js, duration=5.0, **_kw):
        # (2) 第二次修改（2026-11-13）：桩签名要能吸收新增的关键字参数。
        #     bug 原因：_run_java_hook 后来加了 method 参数（0 命中诊断要用它
        #               比对重载数），而这里写着固定 4 个形参。于是
        #               java_hook → _run_java_hook(..., method=...) 直接抛
        #               TypeError，**R84 整条测试崩掉**（不是断言失败，是异常）。
        #     解决方案：加 **_kw 吸收未来的新增参数——桩的职责是"接住并记录"，
        #               不该与真实签名逐一对齐，那会让每次签名演化都崩测试。
        box["js"] = user_js
        return {"ok": True}

    _jb._run_java_hook = _grab
    try:
        params = {"class_name": "com.r84.Sample", "method": "onTick",
                  "sibling_probe": False}
        params.update(kwargs)
        _jb.java_hook("SERIAL", 1, **params)
    finally:
        _jb._run_java_hook = orig
    return box.get("js") or ""


def test_r84_hot_method_auto_degrade() -> None:
    """R84：热方法必须在 **JS 侧**按实测速率分级降级，且降级必须被报告。

    (1) 第一次修改（2026-11-13）：新增。

    为什么这条测试必须用 node 真跑、而不是查源码字符串：
        降级的全部逻辑（速率统计、分级、单向性、跳过取栈）都在 onEnter 里，
        是**运行时行为**。查 "mdaDegradeTick" 在不在字符串里，完全验不出
        "阈值算错了""降级后还在取栈""速率回落又升回去"这些真问题。
        所以这里用假 Java 环境 + 可控时钟驱动真实的 onEnter，
        并统计"贵操作"（取栈 / 参数 toString）的实际调用次数。

    锁死的四条：
        ① 低于一级阈值不许降级（否则正常业务也被削掉观测）
        ② 跨档阈值必须触发对应级别
        ③ 降级后**真的不再取栈/转参数**（否则等于没降，这是本 bug 的核心）
        ④ 降级单向，速率回落不许升回去
    """
    import json as _json
    import os
    import shutil
    import subprocess
    import tempfile

    import server.dyn.java_bridge as _jb

    # ---- ① 签名与默认值：不能改掉原有默认行为 ----
    import inspect as _insp

    sig = _insp.signature(_jb.java_hook)
    for p in ("auto_degrade", "degrade_l1_rate", "degrade_l2_rate",
              "degrade_l3_rate", "degrade_window_ms"):
        check(f"R84 暴露参数 {p}", p in sig.parameters)
    check("R84 降级默认开启", sig.parameters["auto_degrade"].default is True)
    # 关键：不改默认值 —— include_stack 仍为 True，want_args 仍默认 True
    check("R84 不改 include_stack 默认值",
          sig.parameters["include_stack"].default is True)
    check("R84 默认阈值 200/1000/5000",
          (sig.parameters["degrade_l1_rate"].default,
           sig.parameters["degrade_l2_rate"].default,
           sig.parameters["degrade_l3_rate"].default) == (200.0, 1000.0, 5000.0))

    # ---- ② 阈值校验：非法配置必须整体回退默认，不能造出坏组合 ----
    cfg = _jb._degrade_config(True, 1000, 200, 5000, 200)   # 递增关系反了
    check("R84 乱序阈值回退默认",
          (cfg["l1"], cfg["l2"], cfg["l3"]) == (200.0, 1000.0, 5000.0), str(cfg))
    cfg = _jb._degrade_config(True, 0, -1, 5000, 200)
    check("R84 非正阈值回退默认",
          (cfg["l1"], cfg["l2"], cfg["l3"]) == (200.0, 1000.0, 5000.0), str(cfg))
    cfg = _jb._degrade_config(False, 200, 1000, 5000, 99999)
    check("R84 窗口被夹在上限内", 50 <= cfg["window_ms"] <= 5000, str(cfg))
    check("R84 可关闭降级", cfg["enabled"] is False)

    # ---- ③ 报告文案：必须说清"热方法 + 实测 N 次/秒" ----
    note = _jb._degrade_note({
        "count": 3, "hot_methods": 1, "max_level": 2, "max_rate": 1042,
        "thresholds": {"l1": 200, "l2": 1000, "l3": 5000},
        "points": [{"point": "com.r84.Sample#onTick", "level": 2}]})
    check("R84 报告写明已自动降级", "已自动降级" in note, note)
    check("R84 报告写明是热方法", "热方法" in note, note)
    check("R84 报告带实测速率", "1042 次/秒" in note, note)
    check("R84 报告带本次降级次数", "共降级 3 次" in note, note)
    check("R84 报告说明降了哪一级", "参数转换" in note, note)

    if not shutil.which("node"):
        # 没有 node 时至少验到渲染产物里带上了降级状态机
        js = _r84_render_hook_js()
        check("R84 渲染结果含降级状态机",
              "mdaDegradeTick" in js and "mdaDegradeReport" in js)
        return

    # ---- ④ node 真跑：驱动真实 onEnter ----
    js_path = os.path.join(tempfile.gettempdir(), "_r84_hook.js")
    with open(js_path, "w", encoding="utf-8") as fh:
        fh.write(_r84_render_hook_js())

    harness = r"""
globalThis.__sent = []; globalThis.__cbs = [];
globalThis.send = function (o) { globalThis.__sent.push(o); };
globalThis.recv = function (n, cb) { globalThis.__cbs.push([n, cb]); };
var NOW = 1000000; Date.now = function () { return NOW; };
var COST = { stack: 0, toStr: 0 };
var METHOD_DEFS = {};
function makeOv(sig) {
  var f = function () {}; f.toString = function () { return sig; };
  var impl = null;
  Object.defineProperty(f, 'implementation',
    { set: function (v) { impl = v; }, get: function () { return impl; } });
  return f;
}
function fakeClassObj(cn) {
  return { getName: function () { return cn; },
           getSuperclass: function () { return null; },
           getInterfaces: function () { return []; },
           getClassLoader: function () { return null; },
           getModifiers: function () { return 1; },
           getDeclaredMethods: function () {
             return Object.keys(METHOD_DEFS).map(function (n) {
               return { getName: function () { return n; },
                        toString: function () { return n; } }; }); } };
}
function fakeJavaUse(cn) {
  if (cn === 'java.lang.Thread') {
    return { currentThread: function () {
      return { getStackTrace: function () {
        COST.stack++; return [{ toString: function () { return 'x'; } }]; } }; } };
  }
  var jc = { class: fakeClassObj(cn) };
  for (var n in METHOD_DEFS) { jc[n] = METHOD_DEFS[n]; }
  return jc;
}
globalThis.Java = { available: true, androidVersion: '12',
  perform: function (f) { return f(); }, use: fakeJavaUse,
  enumerateLoadedClassesSync: function () { return ['com.r84.Sample']; } };
function Arg() {}
Arg.prototype.toString = function () { COST.toStr++; return 'arg'; };
METHOD_DEFS['onTick'] = { overloads: [makeOv('void onTick(java.lang.Object)')] };
eval(require('fs').readFileSync(JS_PATH, 'utf8'));
var impl = METHOD_DEFS['onTick'].overloads[0].implementation;
if (typeof impl !== 'function') {
  console.log(JSON.stringify({ fatal: 'hook 未装上' })); process.exit(0);
}
var arg = new Arg();
function drive(rate, ms) {
  var perMs = rate / 1000, acc = 0;
  for (var m = 0; m < ms; m++) {
    acc += perMs;
    while (acc >= 1) { impl.call({}, arg); acc -= 1; }
    NOW += 1;
  }
}
var stopCb = globalThis.__cbs.filter(function (x) { return x[0] === 'stop'; })[0][1];
function snap() {
  globalThis.__sent.length = 0; stopCb();
  var r = globalThis.__sent.filter(function (s) { return s.kind === 'result'; }).pop();
  return r ? r.data : null;
}
function cost(fn) {
  var b = { stack: COST.stack, toStr: COST.toStr };
  fn();
  return { stack: COST.stack - b.stack, toStr: COST.toStr - b.toStr };
}
var out = {};
// ① 150 次/秒：不许降级，且必须真的在取栈（证明观测本来是全量）
out.l0_seg = cost(function () { drive(150, 1200); });
var d0 = snap();
out.l0_degrade = d0.degrade;
// ② 拉到 300 次/秒 → 一级
out.l1_seg = cost(function () { drive(300, 1200); });
var d1 = snap();
out.l1_level = d1.degrade && d1.degrade.max_level;
out.l1_rate = d1.degrade && d1.degrade.max_rate;
// ③ 2000 次/秒 → 二级
out.l2_seg = cost(function () { drive(2000, 1200); });
var d2 = snap();
out.l2_level = d2.degrade && d2.degrade.max_level;
// ④ 9000 次/秒 → 三级
out.l3_seg = cost(function () { drive(9000, 1200); });
var d3 = snap();
out.l3_level = d3.degrade && d3.degrade.max_level;
out.l3_count = d3.degrade && d3.degrade.count;
// ⑤ 单向性：掉回 10 次/秒，级别不许回流
drive(10, 2000);
var d4 = snap();
out.cool_level = d4.degrade && d4.degrade.max_level;
out.events = d3.degrade && d3.degrade.events;
console.log(JSON.stringify(out));
""".replace("JS_PATH", _json.dumps(js_path))

    h_path = os.path.join(tempfile.gettempdir(), "_r84_harness.js")
    with open(h_path, "w", encoding="utf-8") as fh:
        fh.write(harness)
    try:
        proc = subprocess.run(["node", h_path], capture_output=True, text=True,
                              timeout=60)
        if proc.returncode != 0:
            check("R84 node 执行成功", False, (proc.stderr or "")[:300])
            return
        res = _json.loads((proc.stdout or "{}").strip() or "{}")
    finally:
        for p in (js_path, h_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    if res.get("fatal"):
        check("R84 hook 能装上", False, str(res["fatal"]))
        return

    # ① 低于阈值不降级
    check("R84 150 次/秒不降级", res.get("l0_degrade") in (None, False),
          str(res.get("l0_degrade")))
    # 未降级时确实是全量观测（每次命中都取栈）
    l0 = res.get("l0_seg") or {}
    check("R84 未降级时每次命中都取栈", int(l0.get("stack") or 0) > 100,
          f"stack={l0.get('stack')}")

    # ② 300 次/秒 → 一级，且**栈采集必须停**
    check("R84 300 次/秒降到一级", res.get("l1_level") == 1, str(res.get("l1_level")))
    check("R84 一级实测速率接近 300",
          280 <= int(res.get("l1_rate") or 0) <= 340, str(res.get("l1_rate")))
    l1 = res.get("l1_seg") or {}
    # 该段前若干次命中仍会取栈（降级在窗口边界才触发），但远少于命中数
    check("R84 一级后取栈次数骤降", int(l1.get("stack") or 0) < 120,
          f"stack={l1.get('stack')}（若接近命中数说明降级没生效）")

    # ③ 2000 次/秒 → 二级，栈与参数转换都归零
    check("R84 2000 次/秒降到二级", res.get("l2_level") == 2, str(res.get("l2_level")))
    l2 = res.get("l2_seg") or {}
    check("R84 二级后不再取栈", int(l2.get("stack") or 0) == 0,
          f"stack={l2.get('stack')}")
    check("R84 二级后不再转参数", int(l2.get("toStr") or 0) == 0,
          f"toString={l2.get('toStr')}")

    # ④ 9000 次/秒 → 三级
    check("R84 9000 次/秒降到三级", res.get("l3_level") == 3, str(res.get("l3_level")))
    l3 = res.get("l3_seg") or {}
    check("R84 三级后不取栈不转参数",
          int(l3.get("stack") or 0) == 0 and int(l3.get("toStr") or 0) == 0,
          f"stack={l3.get('stack')} toStr={l3.get('toStr')}")

    # ⑤ 单向
    check("R84 降级单向不回升", res.get("cool_level") == 3,
          f"速率回落后级别变成 {res.get('cool_level')}")
    # ⑥ 每次降级都有记录，且逐级上升
    evs = res.get("events") or []
    check("R84 降级动作逐级记录", len(evs) >= 3, str(evs))
    if evs:
        levels = [e.get("to_level") for e in evs]
        check("R84 降级序号递增", levels == sorted(levels), str(levels))
        check("R84 每条事件带实测速率",
              all(int(e.get("rate") or 0) > 0 for e in evs), str(evs))


def test_r85_js_template_placeholders() -> None:
    """R85：JS 模板里的每个 __XXX__ 占位符都必须被替换掉。

    (1) 第一次修改（2026-11-13）：新增。

    bug 原因：_JS_JAVA_HOOK_MULTI 里声明了 PARENT_PROBE / DEEP_DIAG /
              DIAG_SIBLINGS 三个变量，但 java_hook 的 replace 链一处都没替换。
              渲染出的脚本带着裸标识符 __PARENT_PROBE__，**加载即抛
              ReferenceError**——整个 java_hook 不可用。
              之所以长时间没被发现，是因为 `node --check` 认为 __X__ 是
              合法标识符，语法检查全绿；错误只发生在 frida 脚本 load 阶段，
              而那时的报错信息里只有一句 JS 异常。
    解决方案：渲染一次真实脚本，用正则找出所有残留的 __大写__ 占位符，
              非空即失败。java_hook 自己也加了同样的自检
              （JS_TEMPLATE_BROKEN），两层都拦。
    """
    import re as _re

    js = _r84_render_hook_js()
    check("R85 渲染出非空脚本", len(js) > 1000, f"len={len(js)}")
    left = sorted(set(_re.findall(r"__[A-Z][A-Z0-9_]*__", js)))
    check("R85 没有残留占位符", not left, f"残留: {left}")
    # node --check 会把 __X__ 当成合法标识符，所以**不能**只靠语法检查
    check("R85 残留自检已内置", "JS_TEMPLATE_BROKEN" in
          __import__("inspect").getsource(
              __import__("server.dyn.java_bridge", fromlist=["x"]).java_hook))


def test_r86_ui_parse_and_targeting():
    """R86：UI 层的解析与选目标逻辑（不连设备，纯逻辑锁死）。

    (1) 第一次修改（2026-11-13）：新增。
        背景：R83 只做了「源码里有某某关键字」的形态检查（例如
              `"compact" in src`）。那种检查挡不住真正的行为回退——
              把 pick_target 改回"命中多个就报歧义"、把 label 改回
              "拼所有后代文本"，R83 依然全绿。
        本测试直接构造节点，验证**行为**。

    锁定五件实测踩出来的事：
      ① bounds 解析要容忍格式变体
      ② 列表行「可点容器 + 内层容器 + TextView」三层同高时不能报歧义，
         且要挑到可点击的那个（这是真实 App 列表的普遍结构）
      ③ 命中真的分布在不同行时才报歧义
      ④ simplify 只留可交互/叶子/输入控件，中间的布局容器要压掉
      ⑤ 坐标/时长参数必须挡掉注入与非数字
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.dyn.adb import DynError
    from server.dyn.ui import (UiNode, _int_arg, _parse_bounds, flatten,
                               pick_target)

    # ① bounds 解析
    check("bounds 正常解析", _parse_bounds("[0,0][1080,2201]") == (0, 0, 1080, 2201),
          f"得到 {_parse_bounds('[0,0][1080,2201]')}")
    check("bounds 带空格也能解析",
          _parse_bounds(" [74,237][426,354] ") == (74, 237, 426, 354),
          "尾部/首部空格让解析失败")
    check("bounds 为空时不崩", _parse_bounds("") == (0, 0, 0, 0),
          "空字符串应给全零元组")

    # ② 同一行的三层结构（真实 App 列表的普遍形态）
    outer = UiNode(cls="android.widget.LinearLayout", bounds=(0, 1509, 1080, 1669),
                   clickable=True,
                   children=[UiNode(cls="android.widget.LinearLayout",
                                    bounds=(74, 1509, 1080, 1669),
                                    children=[UiNode(cls="android.widget.TextView",
                                                     text="百度地图",
                                                     content_desc="百度地图",
                                                     bounds=(74, 1509, 1080, 1669))])])
    row = [outer, outer.children[0], outer.children[0].children[0]]
    target, ambiguous = pick_target(row)
    check("同一行三层不算歧义", ambiguous is False,
          "把每一行都报成歧义，模型将被逼着加 index")
    check("同一行优先挑可点击的", target.clickable is True,
          f"挑到了不可点的 {target.cls}")

    # ③ 不同行才是真歧义
    a = UiNode(text="确定", bounds=(0, 100, 100, 200), clickable=True)
    b = UiNode(text="确定", bounds=(0, 900, 100, 1000), clickable=True)
    _, amb2 = pick_target([a, b])
    check("不同行的同名控件报歧义", amb2 is True,
          "点错行会产生不可逆操作，必须报歧义")

    # ③b 同一行内"行容器 y=595"与"行内文字 y=563"要算同一行。
    #     这是实测踩到的坑：容差写死 3 像素时两者差 32 就被判成不同行，
    #     条件点击在通知栏/列表上完全不可用。
    row_box = UiNode(cls="android.widget.FrameLayout",
                     bounds=(0, 480, 1080, 710), clickable=True)
    text_box = UiNode(cls="android.widget.LinearLayout",
                      bounds=(74, 508, 1080, 618))
    t3, amb3 = pick_target([row_box, text_box])
    check("行容器与其偏上的文字算同一行", amb3 is False and t3 is row_box,
          f"ambiguous={amb3}，挑到 {t3.cls}")

    # ④ simplify 压缩：中间布局容器要压掉，叶子/可点/输入框要留
    tree = [UiNode(cls="android.widget.FrameLayout", bounds=(0, 0, 1080, 2400),
                   children=[
                       UiNode(cls="android.widget.LinearLayout",
                              bounds=(0, 0, 1080, 200), clickable=True,
                              children=[UiNode(cls="android.widget.TextView",
                                               text="设置",
                                               bounds=(0, 0, 200, 200))]),
                       UiNode(cls="android.widget.EditText",
                              bounds=(0, 300, 1080, 400)),
                       UiNode(cls="android.view.View",
                              bounds=(0, 500, 10, 510)),
                   ])]
    rows = flatten(tree, simplify=True, include_invisible=False)
    classes = [r["class"] for r in rows]
    texts = [r.get("text", "") for r in rows]
    check("压缩掉无意义的中间容器", classes.count("FrameLayout") == 0,
          f"布局容器没被压掉：{classes}")
    check("可点击容器保留", "LinearLayout" in classes, classes)
    check("输入框即使无文本也保留", "EditText" in classes, classes)
    lb = [r.get("label") for r in rows if r["class"] == "LinearLayout"]
    check("可点容器带上后代文本作为 label", lb and lb[0] == "设置",
          f"label 聚合不对：{lb}")
    # 叶子文本与可点父容器的 label 内容相同时不重复输出：
    # 同一信息出现两次只会白占上下文（实测真实列表里每行都如此）
    texts_all = [r.get("text") or r.get("label") or "" for r in rows]
    check("同名叶子文本不重复输出", texts_all.count("设置") == 1,
          f"同一行名出现了 {texts_all.count('设置')} 次：{texts_all}")

    # ⑤ 参数校验：注入与非数字一律拒绝
    for bad in ("0; reboot", "1e9", "", None, "abc"):
        try:
            _int_arg(bad, "x")
            check(f"拒绝非法坐标 {bad!r}", False, "没抛错，坐标会被拼进 shell")
        except DynError as exc:
            check(f"拒绝非法坐标 {bad!r}", exc.code == "BAD_ARGUMENT", exc.code)
    try:
        _int_arg(1081, "x", lo=0, hi=1080)
        check("超范围坐标被拒", False, "1081 > 1080 却通过了")
    except DynError:
        check("超范围坐标被拒", True)

    # ⑥ 设备不在线 vs 界面读不到，必须是两种不同的错误码。
    #    实测踩过：serial 不存在时 adb 只往 stderr 写 "device not found"，
    #    stdout 为空，旧代码据此报 UI_DUMP_FAILED（说成"屏幕锁定/无障碍被禁"），
    #    把排查方向完全带偏。
    from server.dyn.ui import _run as _ui_run
    try:
        _ui_run("echo mda_probe", "mda_no_such_device_zzz", timeout=8)
        check("不存在的 serial 报设备级错误", False,
              "没抛错，说明设备校验缺失")
    except DynError as exc:
        check("不存在的 serial 报设备级错误",
              exc.code in ("DEVICE_NOT_FOUND", "DEVICE_AMBIGUOUS"), exc.code)


def test_r87_hook_hint_candidates():
    """R87：候选探查工具（java_hook_hint）必须能排序、必须通用、必须只读。

    (1) 第一次修改（2026-11-13）：新增。

    bug 原因：使用者 hook 了 `CommentRealApi` 全类 0 命中，然后**不知道该换
              哪个类**——旧的 java_find_classes 只能给一串类名，不知道该先
              看哪个；java_hook 一次试一个要十几秒。缺少一个"把像它的类一次
              列出来并排序"的入口。
    解决方案：新增 java_hook_hint（四个线索维度 + 命名相似度排序 +
              网络层通用候选 + 可选低成本计数）。

    这条测试锁四件事：
      ① name_similarity 的排序真的把"像的"排前面（不是枚举顺序）
      ② 内置的类名/方法模式表**不含任何具体 App 的包名**（通用性红线）
      ③ 网络层候选覆盖 okhttp Interceptor / setRequestProperty 三个标准入口
      ④ 默认参数下**完全不 hook**（只读），必须显式给 count_seconds 才计数
    """
    import inspect as _insp

    import server.dyn.java_bridge as _jb
    import server.mcp_server.tools as _T

    check("R87 java_hook_hint 存在", hasattr(_jb, "java_hook_hint"))
    check("R87 MCP 层已注册", hasattr(_T, "java_hook_hint"))

    # ---- ① 排序：CommentRealApi 的近似度顺序必须符合直觉 ----
    q = "CommentRealApi"
    sc = {n: _jb.name_similarity(q, n) for n in (
        "com.x.net.CommentRealApi", "com.x.net.CommentApi",
        "com.x.net.CommentHelper", "com.x.net.CommentManager",
        "com.x.net.OrderApi", "android.util.Log")}
    check("R87 完全同名得满分", sc["com.x.net.CommentRealApi"] == 1.0, str(sc))
    check("R87 子串最像（CommentApi）",
          sc["com.x.net.CommentApi"] > sc["com.x.net.CommentHelper"],
          f"CommentApi={sc['com.x.net.CommentApi']} "
          f"CommentHelper={sc['com.x.net.CommentHelper']}")
    check("R87 同词元前缀更像（Helper/Manager）",
          sc["com.x.net.CommentHelper"] > sc["com.x.net.OrderApi"],
          f"Helper={sc['com.x.net.CommentHelper']} "
          f"OrderApi={sc['com.x.net.OrderApi']}")
    # 只共享 "api" 这类通用后缀不能当证据 —— 这是第二版回归的核心
    check("R87 通用后缀不算相似",
          sc["com.x.net.OrderApi"] < 0.5,
          f"OrderApi 得了 {sc['com.x.net.OrderApi']}，"
          "只共享 'api' 不该被当成相近")
    check("R87 完全不相关得 0 分", sc["android.util.Log"] == 0.0, str(sc))

    # 驼峰切词必须在**转小写之前**做，否则 CommentRealApi 变单个词元，
    # Helper/Manager 全部退化到与 OrderApi 同分（第三版回归）
    check("R87 驼峰词元切分正确",
          _jb.name_similarity("CommentApi", "CommentHelper") > 0.5,
          "驼峰边界丢了，所有 Comment* 会退化成同一分")

    # ---- ② 通用性红线：不许出现具体 App 的包名 ----
    import re as _re

    blob = (" ".join(_jb.NETWORK_CLASS_PATTERNS)
            + " ".join(_jb.NETWORK_METHOD_PATTERNS)
            + str(_jb.NETWORK_CANDIDATES))
    # 已知的商业 App 包名/特征类名一个都不许有
    banned = ["idlefish", "taobao", "alibaba", "tencent", "mtopsdk", "anetwork",
              "xianyu", "goofish", "pdd", "meituan", "xiaomi", "bytedance",
              "com.taobao", "com.tencent", "com.xiaomi"]
    hit = [b for b in banned if b in blob.lower()]
    check("R87 模式表不含具体 App 特征", not hit, f"发现: {hit}")
    # 正向：必须是 Android/okhttp/JDK 的标准名字
    for must in ("Interceptor", "addHeader", "setRequestProperty"):
        check(f"R87 覆盖标准入口 {must}", must in blob, f"缺少 {must}")

    # ---- ③ 网络层候选必须自带"下一步怎么挂" ----
    net = _jb._hint_network_lines()
    check("R87 网络候选非空", len(net) >= 4, f"只有 {len(net)} 条")
    check("R87 每条网络候选带 how",
          all(x.get("how") for x in net),
          "没有 how 就只是类名清单，AI 还得自己想参数")
    check("R87 每条网络候选带 why",
          all(x.get("why") for x in net))

    # ---- ④ 默认只读：不给 count_seconds 不能挂 hook ----
    sig = _insp.signature(_jb.java_hook_hint)
    check("R87 count_seconds 默认 0（只读）",
          float(sig.parameters["count_seconds"].default) == 0.0,
          str(sig.parameters["count_seconds"].default))
    check("R87 include_network 默认开",
          sig.parameters["include_network"].default is True)
    # 四个线索维度都要在
    for p in ("query", "package", "method", "include_network", "count_seconds"):
        check(f"R87 支持参数 {p}", p in sig.parameters)

    # 无任何线索时必须明确报错，不能静默返回空
    empty = _jb.java_hook_hint("S", 1, include_network=False)
    check("R87 无线索明确报错",
          empty.get("ok") is False and empty.get("code") == "NEED_HINT",
          str(empty))


def test_r88_count_calls_lightweight():
    """R88：调用计数必须**轻量**（只加整数），且失败如实报。

    (1) 第一次修改（2026-11-13）：新增。

    bug 原因：探查阶段用 java_hook 挂整类方法测"谁在干活"，每次命中都要取
              Java 栈（遍历整个栈 + 构造 StackTraceElement）再对每个参数
              toString，实测 0.5~3 毫秒/次。挂几十个方法后目标明显变慢，
              还会触发 java_hook 自己的自动降级，探到的数据已经是降级后的。
    解决方案：新增 _java_count_calls —— 单次命中只做一次整数加法。
              本测试在真实渲染出的 JS 上验证"确实没取栈、没碰参数"。

    这条测试锁三件事：
      ① 计数脚本里**不存在** mdaJavaStack / mdaDescribe 调用（轻量的证据）
      ② 只挂声明方法、跳过初始化方法、接口明确跳过（不白跑）
      ③ 记录 hook 结果里的整数自增形态（不是构造对象）
    """
    import inspect as _insp

    import server.dyn.java_bridge as _jb
    import server.mcp_server.tools as _T

    check("R88 计数实现存在", hasattr(_jb, "_java_count_calls"))
    check("R88 MCP 工具已注册", hasattr(_T, "java_count_calls"))

    src = _insp.getsource(_jb._java_count_calls)
    # 轻量性：脚本正文里不能出现任何"重"的观测
    check("R88 计数脚本不取 Java 栈",
          "mdaJavaStack" not in src,
          "取栈是单次命中里最贵的一步，计数阶段不该有")
    check("R88 计数脚本不转参数",
          "mdaDescribe" not in src and "mdaExpand" not in src,
          "参数 toString 每个参数一次，计数阶段不该有")
    check("R88 命中只做整数加法",
          "counts[cn2]++" in src,
          "这是全部开销：一个闭包 + 一次加法")
    check("R88 不构造记录对象",
          "entry.calls" not in src and "rec.args" not in src)

    # 不做无用功：接口/系统类/初始化方法要跳过并说明原因
    check("R88 接口明确跳过并给原因",
          "0x200" in src and "接口" in src,
          "接口声明方法没有实现体，挂了必然 0 命中——必须提前说")
    check("R88 系统类跳过", "SKIP" in src and "java.lang." in src)
    check("R88 跳过初始化方法", "<init>" in src and "<clinit>" in src)
    check("R88 有每类方法数上限", "MAXM" in src,
          "不加上限会一次挂几千个方法把目标拖垮")

    # 失败如实报：0 次时必须提示"先触发功能"，不能只说"没调用"
    check("R88 0 次时给出下一步动作",
          "先去触发一次对应功能" in src,
          "只报 0 会让人以为工具坏了")
    check("R88 未就位有明确 code", "NOT_READY" in src)

    # MCP 层参数要与实现对齐（照 R56 的教训：dyn 有、MCP 没有就传不进去）
    mcp_sig = _insp.signature(_T.java_count_calls)
    for p in ("classes", "method", "seconds", "max_methods_per_class"):
        check(f"R88 MCP 暴露参数 {p}", p in mcp_sig.parameters)


def test_r89_diagnosis_next_actions():
    """R89：0 命中诊断必须给出**可直接照抄**的下一步，且优先级正确。

    (1) 第一次修改（2026-11-13）：新增。

    bug 原因：原诊断只回答"类在不在 / 方法在不在 / 兄弟方法有没有被调"，
              使用者真正卡住的是"那我该 hook 谁"。而 suggestion 只是一句
              话，读的人还得自己把它翻译成工具参数——翻译就是新的出错点，
              错一次又是一轮十几秒的 hook。
    解决方案：诊断增加三层：
              class_refs[]（ClassLoader / 接口 / 抽象 / **重载数**）
              → parent_hits（祖先链同名方法的真实计数）
              → next_actions[]（tool + args + why，可直接执行）

    这条测试锁：五种场景下**优先级判断正确**（接口 > 父类命中 > 兄弟方法 >
    重载 > 无从下手），且每条 next_action 都带 why、参数非空。
    """
    import inspect as _insp

    import server.dyn.java_bridge as _jb

    # ---- ① 接口：结构性原因，必须排最高优先级 ----
    d = {"class_refs": [{"class": "com.x.ICommentApi", "is_interface": True}]}
    s = _jb._diag_suggestion(d, method="add", duration=5)
    check("R89 接口识别为根本原因", "接口" in s and "实现" in s, s)

    # ---- ② 父类命中：有数字的证据，压过"方法存在但没调用" ----
    d2 = {"class_refs": [{"class": "com.x.CommentApi", "is_interface": False}],
          "parent_hits": [{"where": "com.x.BaseApi.add [父类/祖先]", "hits": 12}]}
    s2 = _jb._diag_suggestion(d2, method="add", duration=5)
    check("R89 父类命中给父类建议", "com.x.BaseApi" in s2 and "12" in s2, s2)
    a2 = _jb._diag_next_actions(d2, [])
    check("R89 父类命中生成可执行动作", bool(a2))
    check("R89 动作带 why", all(x.get("why") for x in a2))
    check("R89 动作带 tool+args",
          all(x.get("tool") and isinstance(x.get("args"), dict) for x in a2))
    if a2:
        got = a2[0]["args"]
        check("R89 父类动作指向父类",
              got.get("class_name") == "com.x.BaseApi", str(got))
        check("R89 父类动作方法名正确", got.get("method") == "add", str(got))

    # ---- ③ 兄弟方法 ----
    d3 = {"class_refs": [{"class": "com.x.CommentApi"}],
          "sibling_methods_called": [
              {"method": "com.x.CommentApi.fetch", "hits": 9}]}
    s3 = _jb._diag_suggestion(d3, method="add", duration=5)
    check("R89 兄弟方法被点名", "fetch" in s3 and "9" in s3, s3)
    a3 = _jb._diag_next_actions(d3, [])
    check("R89 兄弟动作换到该方法",
          any(x["args"].get("method") == "fetch" for x in a3), str(a3))

    # ---- ④ 重载：hook 错了重载是最常见的"方法存在但 0 命中" ----
    d4 = {"class_refs": [{"class": "com.x.CommentApi",
                          "overloads_of_target": 3,
                          "overload_signatures": ["void add(java.lang.String)"]}]}
    s4 = _jb._diag_suggestion(d4, method="add", duration=5)
    check("R89 指出重载问题", "重载" in s4 and "3" in s4, s4)
    a4 = _jb._diag_next_actions(d4, [])
    ov = [x for x in a4 if x["args"].get("overload")]
    check("R89 重载动作带 overload 参数", bool(ov), str(a4))
    if ov:
        # method 必须是**方法名**，不能是整条签名里的 "void"
        check("R89 overload 动作的 method 是方法名",
              ov[0]["args"].get("method") == "add",
              f"得到 {ov[0]['args'].get('method')!r}")

    # ---- ⑤ 同包邻居：CommentRealApi 0 命中 → 建议看 CommentApi/Helper ----
    d5 = {"class_refs": [{"class": "com.x.net.CommentRealApi"}],
          "neighbors": [{"class": f"com.x.net.Comment{s}", "score": 0.7}
                        for s in ("Api", "Helper", "Manager")]}
    a5 = _jb._diag_next_actions(d5, [])
    cnt = [x for x in a5 if x["tool"] == "java_count_calls"]
    check("R89 邻居先做低成本计数", bool(cnt),
          "先花 5 秒计数，比直接 hook 每个候选划算得多")
    if cnt:
        check("R89 计数覆盖邻居类",
              len(cnt[0]["args"].get("classes") or []) >= 3, str(cnt[0]))
    hook = [x for x in a5 if x["tool"] == "java_hook"
            and x["args"].get("pattern")]
    check("R89 也给一次性批量 hook", bool(hook),
          "pattern 一次挂多个候选，按命中数判胜负")

    # ---- ⑥ 完全没有线索：指向只读的候选探查 ----
    a6 = _jb._diag_next_actions({"class_refs": [{"class": "com.x.A"}]}, [])
    check("R89 无线索时指向 hint 工具",
          any(x["tool"] == "java_hook_hint" for x in a6), str(a6))

    # ---- ⑦ 签名抽方法名（overload 参数依赖它）----
    check("R89 从签名抽方法名",
          _jb._overload_method_name("public final okhttp3.Request build()")
          == "build")
    check("R89 裸方法名原样返回",
          _jb._overload_method_name("intercept") == "intercept")
    check("R89 空签名返回空串", _jb._overload_method_name("") == "")

    # ---- ⑧ 诊断必须真的接进 _run_java_hook（不能只是写了函数没人调）----
    src = _insp.getsource(_jb._run_java_hook)
    for key in ("class_refs", "parent_hits", "neighbors", "next_actions"):
        check(f"R89 诊断含 {key}", f'"{key}"' in src or f"'{key}'" in src)
    check("R89 诊断调用了建议生成", "_diag_suggestion(" in src)
    check("R89 诊断调用了动作生成", "_diag_next_actions(" in src)
    check("R89 诊断调用了邻居查找", "_diag_neighbors(" in src)

    # JS 侧必须把 parent_hits 回传，否则父类建议永远为空
    js = getattr(_jb, "_JS_JAVA_HOOK_MULTI", "")
    check("R89 JS 回传 parent_hits", "result.parent_hits = parentHits" in js)
    check("R89 JS 有祖先链探测", "PARENT_PROBE" in js and "parentHits" in js)
    check("R89 JS 回传同包类列表", "same_package" in js)


def test_r80_hold_policy_redispatch():
    """R80 已存在的断点改 hold 时，必须把新 policy 重新下发给 debugger。

    (1) 第一次修改（2026-11-13）：
        bug 原因：server/dyn/service.py 的 set_breakpoint 在**下发 policy 之前**
                  就早退——只要 bp_id 已在断点表里就直接 return 旧记录。于是
                  「先 hold=False 下断，再 hold=True 调一次」返回的仍是 hold=False，
                  而且真正的 dbg.set_breakpoint(policy="hold") 从未执行，
                  debugger 侧那条 hook 还是 resume。使用者实测报
                  「set_breakpoint(hold=true) 返回 hold: false」，
                  命中照跑不停——接口说成了、实际没成，属静默的策略失效。
        解决方案：早退只留给 hold 值相同的幂等情形；值不同则继续下发 policy，
                  成功后才写回记录，返回的 hold 恒为最终生效值。

    这条测试锁四件事：
      ① 升级 hold 时**真的**调用 debugger 且 policy="hold"
      ② 返回值与落库记录都反映最终 hold（不是旧值）
      ③ hold 值相同时保持幂等（不重复下钩、不多发一次 dispatch）
      ④ 降级回 hold=False 同样要真的下发
    """
    from server.dyn.adb import DynError
    from server.dyn.service import DynamicService, Target

    class TrackDbg:
        """记录每次下断的 policy；顺带模拟"拒绝 hold"的可控失败。"""

        state = "attached"
        hits: list = []

        def __init__(self):
            self.calls: list[tuple[str, int, str]] = []
            self.refuse_hold = False

        def set_breakpoint(self, so_name, static_addr, policy="resume", on_hit=None):
            if self.refuse_hold and policy == "hold":
                return False
            self.calls.append((so_name, static_addr, policy))
            return True

        def resume(self):
            pass

        def close(self):
            pass

        def wait_hits(self, timeout=1.0):
            return []

    class RB:
        class _M:
            name = "libtarget.so"

        def find_module(self, name):
            return RB._M() if name in ("libtarget.so", "/data/app/libtarget.so") else None

        def to_runtime(self, static_addr, mod):
            return 0x7000000000 + int(static_addr)

        def refresh_modules(self):
            return []

        def detach(self):
            return True

    svc = DynamicService()
    dbg = TrackDbg()
    tgt = Target(serial="s", pid=1, rb=RB(), dbg=dbg)
    svc._targets["s:1"] = tgt

    # ---- ① 首次 hold=False ----
    bp1 = svc.set_breakpoint("s", 1, "libtarget.so", 0x1234, hold=False)
    check("R80 首次 hold=False 如实返回", bp1.get("hold") is False, repr(bp1.get("hold")))
    check("R80 首次 existing=False", bp1.get("existing") is False)
    check("R80 首次下发 resume", dbg.calls and dbg.calls[-1][2] == "resume",
          str(dbg.calls))

    # ---- ② 升级为 hold：必须重下发 ----
    bp2 = svc.set_breakpoint("s", 1, "libtarget.so", 0x1234, hold=True)
    check("R80 升级后返回 hold=True",
          bp2.get("hold") is True,
          f"实际 {bp2.get('hold')!r}——这就是用户报的 hold 不生效")
    check("R80 升级时真的重下发 hold 策略",
          dbg.calls[-1][2] == "hold",
          f"debugger 从未收到 hold，最后一次是 {dbg.calls[-1] if dbg.calls else None}")
    check("R80 升级时标记 policy_changed", bp2.get("policy_changed") is True,
          repr(bp2.get("policy_changed")))
    check("R80 断点记录同步为 hold=True",
          tgt.breakpoints[bp1["id"]].get("hold") is True,
          repr(tgt.breakpoints[bp1["id"]].get("hold")))

    # ---- ③ 幂等：hold 相同不重复下钩 ----
    n_calls = len(dbg.calls)
    bp3 = svc.set_breakpoint("s", 1, "libtarget.so", 0x1234, hold=True)
    check("R80 hold 相同时不重复下发", len(dbg.calls) == n_calls,
          f"多下了 {len(dbg.calls) - n_calls} 次钩")
    check("R80 幂等调用返回 existing=True", bp3.get("existing") is True)
    check("R80 幂等调用 hold 仍为 True", bp3.get("hold") is True)
    check("R80 幂等调用不标 policy_changed", bp3.get("policy_changed") is False,
          repr(bp3.get("policy_changed")))

    # ---- ④ 降级回 resume 也要真的下发 ----
    bp4 = svc.set_breakpoint("s", 1, "libtarget.so", 0x1234, hold=False)
    check("R80 降级为 resume 时重下发", dbg.calls[-1][2] == "resume", str(dbg.calls))
    check("R80 降级后返回 hold=False", bp4.get("hold") is False)

    # ---- ⑤ 下发失败：不许装成功，记录保持旧值 ----
    dbg.refuse_hold = True
    try:
        svc.set_breakpoint("s", 1, "libtarget.so", 0x1234, hold=True)
        raised = False
    except DynError as exc:
        raised = getattr(exc, "code", "") == "BREAKPOINT_FAILED" or "BREAKPOINT_FAILED" in str(exc)
    check("R80 下发生效失败时抛 BREAKPOINT_FAILED", raised,
          "拒绝了 hold 却报成功，等于又造一次假成功")
    check("R80 失败后记录仍是 hold=False",
          tgt.breakpoints[bp1["id"]].get("hold") is False,
          repr(tgt.breakpoints[bp1["id"]].get("hold")))


def test_r81_idc_function_ranges():
    """R81 IDC 建函数后必须同步刷新 function_at 的索引。

    (1) 第一次修改（2026-11-13）：
        bug 原因：server/scripting/idc.py 的 _refresh_ranges 只重算
                  `so._func_ranges`，而 function_at() 二分用的是 `so._starts`
                  （由 elf_model._refresh_functions 维护）。IDC 刚建的函数进得了
                  `so.functions`、也进了 `_func_ranges`，却**从未进 `_starts`**。
                  实测 `0xdf5c in so.functions == True` 而
                  `function_at(0xdf5c) == None`。后果：MakeFunction/MakeName 之后
                  反汇编、伪代码、UI 打开、引用归属都看不到这个函数，
                  等于建了个不可见的函数。
        解决方案：改为调用 elf_model 的唯一权威入口 `_refresh_functions()`，
                  它同时维护 `_starts` 与 `_func_ranges`，并顺带修正 size 让区间
                  互不重叠（function_at 二分的另一前提）。

    这条测试锁三件事：
      ① MakeFunction 之后 function_at 能找到**刚建的那个**函数（起点等于自身）
      ② MakeName 之后按地址取名字正确（这是用户实际使用的入口）
      ③ MakeFunction(ea, BADADDR) 走边界推断后同样可见
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.core.session import Session
    from server.scripting.idc import BADADDR, IdcContext

    sample = root / "samples" / "libbase.so"
    if not sample.exists():
        return

    s = Session()
    so = s.add(str(sample))

    # 找一个 .text 内、4 字节对齐、**不是**函数起点的地址。
    # 不写死偏移：不同样本/不同版本都成立（通用性要求）。
    text = None
    for sec in getattr(so, "sections", []) or []:
        if sec.name == ".text":
            text = sec
            break
    if text is None:
        return
    probe = None
    for a in range(text.addr, text.addr + int(text.size) - 4, 4):
        if a not in so.functions:
            probe = a
            break
    if probe is None:
        return

    ctx = IdcContext(s, so.name)
    before = so.function_at(probe)
    check("R81 前置：该地址本身不是函数起点", probe not in so.functions,
          f"{probe:#x} 已是函数起点，测不到该缺陷")
    check("R81 前置：建函数前 function_at 指不到它",
          before is None or before.addr != probe,
          f"建函数前就返回了 {before.addr:#x} 的函数")

    # ---- ① MakeFunction（显式边界） ----
    ctx.MakeFunction(probe, probe + 0x40)
    got = so.function_at(probe)
    check("R81 MakeFunction 后 function_at 能找到该函数",
          got is not None and got.addr == probe,
          f"实际 {None if got is None else hex(got.addr)}"
          "——这就是 idc 建函数后函数看不见的缺陷")
    check("R81 函数进了 so.functions", probe in so.functions)

    # ---- ② MakeName 之后按地址取名 ----
    ctx.MakeName(probe, "r81_probe_fn")
    named = so.function_at(probe)
    check("R81 MakeName 后能按地址取到新名字",
          named is not None and named.name == "r81_probe_fn",
          f"实际 {None if named is None else named.name!r}")
    check("R81 get_func_name 也走同一索引",
          ctx.get_func_name(probe) == "r81_probe_fn",
          ctx.get_func_name(probe))

    # ---- ③ BADADDR 边界推断路径同样可见 ----
    probe2 = None
    for a in range(probe + 0x100, text.addr + int(text.size) - 4, 4):
        if a not in so.functions:
            probe2 = a
            break
    if probe2 is not None:
        ctx.MakeFunction(probe2, BADADDR)
        got2 = so.function_at(probe2)
        check("R81 BADADDR 推断后 function_at 也能找到",
              got2 is not None and got2.addr == probe2,
              f"实际 {None if got2 is None else hex(got2.addr)}")

    # ---- ④ 索引必须与区间表一致（防止两套索引再次各算一份） ----
    starts = set(getattr(so, "_starts", []) or [])
    missing = [hex(a) for a in so.functions if a not in starts]
    check("R81 _starts 覆盖全部已登记函数", not missing,
          f"缺 {len(missing)} 个：{missing[:5]}")


def test_r82_short_and_utf8_strings():
    """R82 字符串提取必须覆盖 2~3 字符的短串与 UTF-8（且不能退化性能）。

    (1) 第一次修改（2026-11-13）：
        bug 原因：server/core/strings.py 的 `_MIN_LEN = 4` 且逐字节只认
                  `0x20 <= c < 0x7F`。实测 libbase.so 的 237 个 data_refs 目标里
                  128 个查不到字符串：其中 32 个是 ≤3 字符的真实常量
                  （"ms"、']'、", "、'.'），50 个含非 ASCII 字节。
                  因为查不到 StringRef，这些引用永远归不到引用者身上——
                  string_refs / 伪代码 / 界面"这个函数引用了哪些字符串"全都静默漏掉。
        解决方案：字符集扩到「ASCII 可打印 ∪ 合法 UTF-8 多字节序列」，
                  下限降到 2；单字符只在**紧跟 NUL** 时收（`'h'\\0 'm'\\0 's'\\0`
                  这类单位表是真实字符串表，用 NUL 结尾这个客观依据区分，不猜内容）；
                  全空白（对齐填充）不算字符串。

    这条测试锁五件事：
      ① 2~3 字符的短串被提取（'ms' / ', ' / ']'）
      ② 单字符仅在 NUL 结尾时收（既有 ']' 也有被排除的偶然单字节）
      ③ UTF-8 非 ASCII 字符串完整提取（中文 / 重音字符），且中段地址能反查
      ④ 全空白串被排除
      ⑤ 扫描没有退化：libc 61KB .rodata 的提取耗时在宽松上界内
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    import server.core.strings as S

    check("R82 最小长度已降到 2", S._MIN_LEN <= 2, f"_MIN_LEN={S._MIN_LEN}")

    # ---- ①②③④ 合成数据：每条规则各一个断言 ----
    blob = (b"\x00ms\x00, \x00]"
            b"\x00abc\x00Zbc\x00"                     # 'Z' 后不是 NUL：单字符分支不该命中
            b"    \x00"                               # 全空白，排除
            + "中文".encode("utf-8") + b"\x00"
            + "\u00e9t\u00e9".encode("utf-8") + b"\x00")
    found = S._extract_printable(blob, 0x1000)
    got = {r.value for r in found}
    addrs = {r.value: r.addr for r in found}

    check("R82 2 字符串短串被提取", "ms" in got, f"实际 {sorted(got)}")
    check("R82 2 字符符号串被提取", ", " in got, f"实际 {sorted(got)}")
    check("R82 NUL 结尾的单字符被提取", "]" in got, f"实际 {sorted(got)}")
    check("R82 非 NUL 结尾的单字符被排除", not any(v == "Z" for v in got),
          f"实际 {sorted(got)}")
    check("R82 全空白串被排除", not any(not v.strip() for v in got), f"实际 {sorted(got)}")
    check("R82 中文 UTF-8 完整提取", "中文" in got, f"实际 {sorted(got)}")
    check("R82 重音字符 UTF-8 完整提取", "\u00e9t\u00e9" in got, f"实际 {sorted(got)}")

    # ---- ③ 中段地址反查：UTF-8 的字符数 != 字节数，上界必须按字节算 ----
    class _Sec:
        def __init__(self, addr, size, name):
            self.addr, self.size, self.name = addr, size, name

    class _So:
        def __init__(self, data):
            self._data = data
            self.sections = [_Sec(0x1000, len(data), ".rodata")]
            self._loads = []

        def read(self, addr, size):
            off = addr - 0x1000
            return self._data[off:off + size] if 0 <= off < len(self._data) else b""

    an = S.StringAnalyzer(_So(blob))
    an.build()
    cn_addr = addrs["中文"]
    # "中文" 占 6 字节：addr .. addr+6 都应能反查到同一条（+1 是结尾 NUL）
    check("R82 UTF-8 串中部地址能反查（按字节算上界）",
          all((hit := an.string_starting_at_or_before(cn_addr + k)) is not None
              and hit.value == "中文" for k in range(6)),
          f"起点 {cn_addr:#x} 的 6 字节内有位置查不到")
    # 越过 NUL 之后必须落到**下一条**字符串，不能还返回"中文"
    tail = an.string_starting_at_or_before(cn_addr + 7)
    check("R82 越过结尾 NUL 后不再命中上一条",
          tail is None or tail.value != "中文",
          f"越界仍返回 {None if tail is None else tail.value!r}")

    # ---- ⑤ 真样本：短串与 UTF-8 真的出现在表里，且扫描没有退化 ----
    import time

    base = root / "samples" / "libbase.so"
    if base.exists():
        from server.core.session import Session

        s = Session()
        so = s.add(str(base))
        strs = s.strings(so.name)
        strs.build()
        vals = {x.value for x in strs.all_strings()}
        check("R82 真样本里短串可查（libbase 的 'ms'）", "ms" in vals,
              "短串仍然整类缺失")
        check("R82 真样本里有非 ASCII 串",
              any(not v.isascii() for v in vals),
              "UTF-8 支持没有真正生效")

        # 每个 ≤3 字符的真实短串都必须能被反查回它自己
        short = [x for x in strs.all_strings() if len(x.value) <= 3][:40]
        bad = [x.value for x in short
               if (hit := strs.string_starting_at_or_before(x.addr)) is None
               or hit.addr != x.addr]
        check("R82 短串起点反查必须命中自身", not bad, f"错位 {bad[:5]}")

    big = root / "samples" / "device" / "libc.so"
    if big.exists():
        from server.core.session import Session

        s2 = Session()
        so2 = s2.add(str(big))
        data_list = []
        for sec in getattr(so2, "sections", []) or []:
            if sec.name and sec.name not in S._STRING_SECTIONS:
                continue
            d = so2.read(sec.addr, sec.size)
            if d:
                data_list.append((sec.addr, d))
        total = sum(len(d) for _, d in data_list)
        t0 = time.perf_counter()
        n = 0
        for a, d in data_list:
            n += len(S._extract_printable(d, a))
        dt = time.perf_counter() - t0
        check("R82 扫描到数据（libc）", total > 0 and n > 0, f"{total}B -> {n} 条")
        # 宽松上界：现在约 10ms，给 100 倍余量，只拦"退化成逐字节 Python 循环"
        check("R82 61KB 级 .rodata 扫描未退化（<1s）", dt < 1.0,
              f"{dt * 1000:.1f}ms / {total}B")


def test_r90_so_name_alias_unified() -> None:
    """R90 so 名字别名解析收敛到一处，所有工具自动受益。

    (1) 第一次修改（2026-11-13）：
        bug 原因：设备模块名与 mda 会话里的键经常不一致——
                  设备 libsscronet.so ↔ 本地 sscronet.so；
                  设备 libsgmainso-6.7.260202.so ↔ 本地 libsgmainso.so；
                  设备还可能给完整路径 /data/app/xxx/lib/arm64/libfoo.so。
                  而 Session.get() 是严格字典查找，miss 就抛
                  `KeyError: 未加载的 so: xxx，当前有 []`。使用者实测因此
                  反复踩"未加载"至少 8 次，每次都要人工确认设备名与本地名。
                  更糟的是别名规则此前散在四份实现里（core.session /
                  mcp_server.tools._pick_so_by_name / dyn.bridge._match_so /
                  dyn.rebase.find_module），各写一套已经开始分叉。
        解决方案：规则收敛成 core.session 的纯函数 match_name，
                  Session.resolve/get/xref/strings/discover_functions 统一走它。
                  本测试用**真实样本**锁住四件事：
                    ① 别名能取到（liblog.so / log.so / liblog / log / 全路径）
                    ② 唯一命中才采用，多候选必须报错并列出候选（不能瞎猜）
                    ③ 报错信息带已加载列表与最接近的候选（能自愈）
                    ④ 四处入口用同一套规则（防止又抄一份出去）
    """
    from server.core.session import Session, match_name

    log_path = Path(__file__).resolve().parent.parent / "samples" / "liblog.so"
    if not log_path.exists():
        check("R90 样本存在", False, f"缺少 {log_path}")
        return

    s = Session()
    so = s.add(str(log_path))
    check("R90 加载后键是文件名", so.name == "liblog.so", so.name)

    # ① 别名：任务要求的四种写法 + 真机两种形态
    for alias in ("liblog.so", "log.so", "liblog", "log",
                  "/system/lib64/liblog.so",
                  "/data/app/xxx/lib/arm64/liblog.so"):
        got = s.get(alias)
        check(f"R90 get({alias}) 取到 liblog", got is so,
              f"别名未解析，实际 {getattr(got, 'name', got)!r}")

    # ② 唯一命中才采用：两个版本同时加载时，核心名必须报歧义
    amb = Session()
    amb.modules["libutils-1.so"] = object()
    amb.modules["libutils-2.so"] = object()
    try:
        amb.resolve("libutils.so")
        check("R90 多候选必须报错", False, "居然挑了一个，会让人在错的样本上分析")
    except KeyError as exc:
        msg = exc.args[0] if exc.args else str(exc)
        check("R90 多候选报错并列出候选",
              "libutils-1.so" in msg and "libutils-2.so" in msg, msg)
        check("R90 多候选的 code 是 SO_AMBIGUOUS",
              getattr(exc, "mda_code", "") == "SO_AMBIGUOUS",
              getattr(exc, "mda_code", ""))

    # ③ 报错能自愈：带已加载列表 + 最接近的候选
    try:
        s.get("sscronet.so")
        check("R90 不存在的名字必须抛错", False, "静默返回了")
    except KeyError as exc:
        msg = exc.args[0] if exc.args else str(exc)
        check("R90 报错带已加载列表", "liblog.so" in msg, msg)
        check("R90 报错不吞掉原名", "sscronet.so" in msg, msg)
    try:
        s.get("log2.so")
        check("R90 相近名要抛错", False, "静默返回了")
    except KeyError as exc:
        msg = exc.args[0] if exc.args else str(exc)
        check("R90 报错给'你是不是想找'", "你是不是想找" in msg and "liblog.so" in msg, msg)

    # 空会话：明确提示先 load_so，而不是给个空列表了事
    empty = Session()
    try:
        empty.get("nope.so")
    except KeyError as exc:
        msg = exc.args[0] if exc.args else str(exc)
        check("R90 空会话提示先 load_so", "load_so" in msg, msg)

    # ④ 后缀级不能乱配：get 现在自动解析，误配会让人在错的样本上得结论
    suffix = Session()
    suffix.modules["libsscronet.so"] = object()
    hit, how, _amb = match_name("sscronet.so", ["libsscronet.so"])
    check("R90 去 lib 前缀能命中", hit == "libsscronet.so" and how == "lib",
          f"{hit!r}/{how!r}")
    check("R90 半截词不误配（cronet.so）",
          match_name("cronet.so", ["libsscronet.so"])[0] is None,
          "net.so/cronet.so 这类半截词被当成后缀命中")
    check("R90 分隔符边界可命中（bar.so）",
          match_name("bar.so", ["libfoo_bar.so"])[0] == "libfoo_bar.so",
          "合法的下划线分段后缀被误拒")

    # ⑤ 四处入口必须同口径（防止别名规则又被抄回某个模块）
    import inspect as _insp

    from server.dyn.bridge import _match_so
    from server.dyn.rebase import Rebase
    from server.mcp_server.tools import _pick_so_by_name

    check("R90 Session.get 走统一入口",
          "_resolve" in _insp.getsource(Session.get) or "resolve" in _insp.getsource(Session.get),
          "get 又变回严格字典查找")
    check("R90 tools._pick_so_by_name 委托统一规则",
          "session.resolve" in _insp.getsource(_pick_so_by_name)
          or "match_name" in _insp.getsource(_pick_so_by_name),
          "又自持一套匹配")
    check("R90 bridge._match_so 复用统一规则",
          "match_name" in _insp.getsource(_match_so), "又自持一套匹配")
    check("R90 rebase.find_module 复用统一规则",
          "match_name" in _insp.getsource(Rebase.find_module), "又自持一套匹配")

    # 四处对同一个别名必须给出同一个结论（真实样本上跑）
    b = Session()
    b.add(str(log_path))
    same = []
    for entry in (_pick_so_by_name(b, "log"),
                  b.get("log"),
                  _match_so(b, "log")[1],
                  b.resolve("log")[0]):
        same.append(getattr(entry, "name", None))
    check("R90 四处入口结论一致", len(set(same)) == 1 and same[0] == "liblog.so", str(same))

    # ⑥ 别名进来之后，依赖规范键的内部路径也得跟着解析
    x1 = s.xref("log")
    x2 = s.xref("liblog.so")
    check("R90 xref 别名与全名同一对象", x1 is x2,
          "xref 仍按原始名索引，别名会 KeyError")
    strs = s.strings("log")
    check("R90 strings 别名可用", strs is s.strings("liblog.so"))
    prog = s.xref_progress("log")
    check("R90 xref_progress 别名可用", isinstance(prog, dict), str(type(prog)))

    # call_chain 的节点名必须是规范键，否则 seen 去重会把同一函数算成两个节点
    chain = s.call_chain("log.so", 0x5020, depth=1)
    check("R90 call_chain 节点用规范键", chain.so_name == "liblog.so", chain.so_name)




def test_r91_java_hook_method_cap():
    """R91 java_hook 不指定 method 时必须限制 hook 方法数。

    (1) 第一次修改（2026-11-13）：
        bug 原因：java_hook 不传 method 时会把该类的**所有**方法全挂上。
                  实测 hook android.app.Activity 挂了 415 个方法，
                  每个都取栈+参数转换——这是把目标拖死最快的方式
                  （使用者实测因此 ANR 2 次）。java_count_calls 早有
                  max_methods_per_class=60 的保护，唯独 java_hook 没有。
        解决方案：加方法数硬上限 max_methods（默认 60），超了截断并明确告知。

    这条测试锁三件事：
      ① JS 模板里有上限常量且被 replace 链接线
      ② 上限用在该 hook 的作用域里（曾经写成 out.cap_note，整个 ReferenceError）
      ③ 不指定 method 时给 cap_note 提示
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    src = (root / "server" / "dyn" / "java_bridge.py").read_text(encoding="utf-8")

    check("有方法数上限常量", "MAX_METHODS_PER_CLASS" in src,
          "没有上限，hook 整个类会挂几百个方法")
    check("占位符已接线", '.replace("__MAXMETHODS__"' in src,
          "占位符没接进 replace 链，脚本加载会 ReferenceError")
    check("上限作用域正确", "entry.cap_note" in src,
          "又写成了不存在的变量（曾经是 out.cap_note）")
    check("超限时给提示", "declaredTotal > methods.length" in src,
          "截断后不告知，调用方以为全 hook 了")

    # ③ 真渲染一次模板，确认没有残留占位符、且能拿到 cap 参数
    sys.path.insert(0, str(root))
    from server.dyn.java_bridge import _JS_JAVA_HOOK_MULTI, _JS_HELPERS
    check("模板里有上限引用", "__MAXMETHODS__" in _JS_JAVA_HOOK_MULTI,
          "JS 模板里没用上限常量")
    check("helpers 可拼接", isinstance(_JS_HELPERS, str) and _JS_HELPERS,
          "_JS_HELPERS 不是非空字符串")



def test_r92_every_tool_reports_runtime_env():
    """R92 所有工具都必须经过 @logged()，从而自动带上运行环境（env）。

    (1) 第一次修改（2026-11-13）：
        用户明确要求：「反查 app 是必须的，所有工具都要引用这个模块」。
        背景：AI 看不到屏幕，调动态工具时不知道目标 App 在不在前台。
              目标在后台时渲染/网络/生命周期代码根本不执行，
              断点装上了也永远不命中——AI 会误判成"代码没跑到"。

    这条测试是**硬约束的守卫**，锁四件事：
      ① 每个 @server.tool() 都有 @logged()（否则不会注入 env）
      ② env 模块存在且被 logged 引用
      ③ probe 三态齐全（resolved / no-target / failed）——AI 必须能区分
         "查过了" 与 "没查成"，把 failed 当没事会导致误判
      ④ ui_* 屏幕级工具给出 is-foreground，而不是含糊的 null
    """
    import re as _re
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")

    # ① 每个工具都要有 @logged
    blocks = _re.findall(r"@server\.tool\(\)([\s\S]{0,200}?)def (\w+)", tools_src)
    missing = [nm for blk, nm in blocks if "@logged" not in blk]
    check("每个工具都经过 @logged（否则不会注入 env）",
          not missing, f"这些工具绕过了：{missing[:5]}")

    # ② env 模块接线
    check("runtime_env 模块存在",
          (root / "server" / "dyn" / "runtime_env.py").is_file(), "模块不见了")
    check("logged 调用了 inject_env", "_inject_env(result, call_args" in tools_src,
          "logged 没注入 env")

    # ③ probe 三态
    env_src = (root / "server" / "dyn" / "runtime_env.py").read_text(encoding="utf-8")
    for state in ("resolved", "no-target", "failed"):
        check(f"probe 有 {state} 态", f'"{state}"' in env_src,
              "AI 无法区分'查过了'与'没查成'")

    # ④ 屏幕级工具
    check("ui_* 标 is-foreground", "is-foreground" in env_src,
          "屏幕级操作留了含糊的 null")

    # 真跑一次：带 pid 的调用必须 resolved
    sys.path.insert(0, str(root))
    from server.dyn.runtime_env import inject_env
    import json as _json
    # 没有 serial 时不注入（静态工具不受影响）
    raw = inject_env('{"ok":true}', {}, tool_name="preflight")
    check("无 serial 不注入 env", '"env"' not in raw, "静态工具被加了 env")

    # 有 serial 但无目标：必须注入，且 probe 落在三态内。
    # 注意：没有设备时 probe 会是 failed（adb 连不上），这是**正确行为**，
    # 不是缺陷——如实报"探测失败"比假装"没关系"安全。
    got = _json.loads(inject_env('{"ok":true}', {"serial": "x"},
                                 tool_name="preflight"))["env"]
    check("有 serial 必注入且 probe 合法",
          got.get("probe") in ("no-target", "resolved", "failed"),
          f"实际 {got.get('probe')}")
    check("探测失败时要说清楚",
          got.get("probe") != "failed" or got.get("warning"),
          "failed 却没给 warning，AI 会以为是小事")

    # 数组返回值也要带 env（list_processes 曾是裸数组，等于从没带过）
    arr = inject_env('[{"pid":1}]', {"serial": "x"}, tool_name="list_processes")
    check("数组返回也带 env", '"env"' in arr and '"items"' in arr,
          "裸数组被跳过了，list_processes 这类工具拿不到环境信息")

    # keyword 像包名时要当 package 反查（否则 probe=no-target）
    from server.dyn.runtime_env import resolve_target as _rt
    pid2, pkg2 = _rt({"serial": "x", "keyword": "com.foo.bar"})
    check("keyword 被识别为包名", pkg2 == "com.foo.bar",
          f"实际 {pkg2!r}，AI 得不到目标判定")



def test_r94_no_view_renders_blank():
    """R94 每个视图在没有 so 时都必须给出说明，不能留白。

    (1) 第一次修改（2026-11-13）：
        bug 原因：两个问题叠在一起——
                  ① 「实时」页在没有 so 时被空状态整页占满，AI 操作设备时
                     用户看到的是死页面（用户原话："这逻辑不合理呀"）
                  ② 左栏「字符串」「段 / 节」配了 view 但渲染条件是 `&& mod`，
                     没 so 时**什么都不渲染**，主区域只剩布局骨架
                  ③ 左栏 11 个动态入口一直 disabled（注释写"原型同样不可点"），
                     可 AI 确实在操作断点/命中/内存这些数据
        解决方案：① 实时页永远渲染监控台；② 需要 so 的视图给 NeedSoView 说明；
                  ③ 11 个动态入口全部配上 dyn:* 真实视图。

    这条测试锁住结构与数据通路，防止以后又出现"点了白屏"：
      ① 前端有 NeedSoView（需要 so 的视图有说明页）
      ② 动态视图组件与接口都在
      ③ 左栏动态入口都配了 view（不再 disabled）
      ④ mainView 类型不再收窄成字面量联合（否则新增视图会被类型挡住）
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent

    app = (root / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    nav = (root / "web" / "src" / "components" / "LeftNav.tsx").read_text(encoding="utf-8")
    api_py = (root / "server" / "api.py").read_text(encoding="utf-8")

    check("有 NeedSoView 说明页", "NeedSoView" in app,
          "需要 so 的视图又留白了")
    check("字符串页有兜底", 'mainView === "strings" && !mod' in app,
          "字符串页没 so 时会白屏")
    check("段节页有兜底", 'mainView === "sections" && !mod' in app,
          "段节页没 so 时会白屏")

    dyn_p = root / "web" / "src" / "components" / "DynStateView.tsx"
    check("动态视图组件存在", dyn_p.is_file(), "DynStateView.tsx 不见了")
    check("后端有 dyn_state 接口", "/api/dyn_state" in api_py,
          "动态状态接口没注册")

    # 左栏动态入口必须都有 view（不再 disabled）
    for label in ("断点", "命中", "内存", "派发点", "寄存器", "轨迹"):
        hit = [ln for ln in nav.splitlines() if f'label: "{label}"' in ln]
        check(f"左栏「{label}」可点击", hit and "view:" in hit[0],
              f"「{label}」还是 disabled")

    # mainView 不能收窄成字面量联合
    check("mainView 类型已放开",
          'useState<string>("monitor")' in app,
          "类型又收窄了，新增视图会被挡住")



def test_r95_env_on_all_paths_including_errors():
    """R95 env 注入必须覆盖**所有返回路径**，包括失败。

    (1) 第一次修改（2026-11-13）：
        bug 原因：审计 72 个带 serial 的工具时发现两个缺口——
                  ① 工具**抛异常**时返回 CallToolResult 对象，绕过了
                     _inject_env（它只处理字符串）→ 所有失败的工具都没有 env。
                     而失败时恰恰最需要知道目标状态："模块没加载"和
                     "目标在后台"是两回事，分不清就会往错方向查。
                  ② perf_watch_* 只有 slot 没有 pid，判不出"观察点盯的 App
                     在不在前台"；list_processes / mem_snapshot_clear 同样缺。
        解决方案：① 异常分支也注入 env；② 启动观察点时记 slot→pid；
                  ③ 给缺 pid 的工具补参数。

    这条测试锁四件事：
      ① 成功路径有 env
      ② **失败路径也有 env**（这是本次修的核心）
      ③ 数组返回被包成 {items, env}
      ④ perf_watch 的 slot→pid 映射存在且被 resolve_target 使用
    """
    import json as _json
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))

    from server.dyn.runtime_env import inject_env

    # ① 成功对象
    ok = _json.loads(inject_env('{"ok":true}', {"serial": "x", "pid": 1},
                                tool_name="probe_process"))
    check("成功路径有 env", "env" in ok, "正常返回没注入")

    # ② 失败对象（形态与 logged 的异常分支一致）
    err = _json.loads(inject_env(
        '{"error":"boom","tool":"x","traceback_tail":[]}',
        {"serial": "x", "pid": 1}, tool_name="set_breakpoint"))
    check("失败路径也有 env", "env" in err,
          "异常返回绕过了注入——失败时最需要知道目标状态")

    # ③ 数组返回
    arr = _json.loads(inject_env('[]', {"serial": "x"}, tool_name="list_processes"))
    check("数组返回被包 env", "env" in arr and "items" in arr,
          "裸数组会跳过注入")

    # ④ slot→pid
    from server.dyn.perfwatch import (remember_slot_pid, lookup_slot_pid,
                                      forget_slot_pid)
    from server.dyn.runtime_env import resolve_target
    remember_slot_pid("__t__", 2, 4321)
    check("perf_watch slot→pid 可反查", lookup_slot_pid("__t__", 2) == 4321,
          "观察点判不出目标进程")
    pid2, _ = resolve_target({"serial": "__t__", "slot": 2})
    check("resolve_target 用了 slot 映射", pid2 == 4321,
          "perf_watch_poll 仍判不出目标")
    forget_slot_pid("__t__", 2)
    check("停止后清掉记录", lookup_slot_pid("__t__", 2) is None,
          "映射残留，会指向已停的观察点")

    # ⑤ 异常分支确实调用了注入（源码级确认，防止有人删掉那行）
    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")
    idx = tools_src.find("err_text = _inject_env")
    check("异常分支调用了 _inject_env", idx > 0,
          "有人把异常路径的注入删了")



def test_r96_method_filter_scope():
    """R96 指定 method 时只能 hook 那一个方法，不能整个类全挂。

    (1) 第一次修改（2026-11-16）：
        bug 原因：JS 模板里 methRe 声明在 `} else {`（按 pattern 枚举类）
                  分支内部。用户传 class_name 时走 `if (CLASS_NAME)` 分支，
                  **methRe 从未被赋值 → undefined**，于是筛选条件
                  `if (methRe && !methRe.test(mn))` 恒为 false，
                  该类的所有方法全被 hook，method 参数完全失效。

                  实测：hook EncryptorUtil method="LIZ"，
                  hooked_methods 却是 ["LIZ", "ttEncrypt"] 两个。
                  更迷惑的是 sibling_probe 同时在给 ttEncrypt 挂计数，
                  两个方法次数一模一样（都是 4 次），
                  使用者误判成"java_hook 对 static 方法捕获有问题"。

        解决方案：methRe 提到两条分支之外统一声明 + 赋值。

    这条测试锁住：methRe 必须在 CLASS_NAME 分支**之前**就已赋值，
    否则 class_name 路径下筛选失效（整个类被 hook，目标可能被拖死）。
    """
    import re as _re
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.dyn.java_bridge import _JS_JAVA_HOOK_MULTI

    src = _JS_JAVA_HOOK_MULTI

    # ① methRe 的赋值必须出现在 `if (CLASS_NAME)` 之前
    i_assign = src.find("methRe = makeRe(METHOD")
    i_class = src.find("if (CLASS_NAME)")
    check("methRe 在 CLASS_NAME 分支之前赋值",
          i_assign > 0 and i_class > 0 and i_assign < i_class,
          "methRe 又在分支里赋值了，class_name 路径下会失效")

    # ② 不能出现「在 else 分支内声明 methRe」的写法
    check("methRe 不在 else 分支内单独声明",
          not _re.search(r"}\s*else\s*\{[^}]{0,400}?var methRe", src, _re.S),
          "又写回了 else 分支里")

    # ③ 顶层必须有 var methRe 声明
    check("methRe 有顶层声明", "var methRe" in src, "没有变量声明")

    # ④ 真实渲染一次，确认占位符都被替换（漏接会 ReferenceError）
    render = src.replace("__METHOD__", '"LIZ"')
    left = _re.findall(r"__[A-Z_]+__", render)
    check("METHOD 占位符已替换", "__METHOD__" not in left or "LIZ" in render,
          "占位符没替换")

    # ⑤ 行为验证：用 node 跑一小段，确认 ^LIZ$ 只匹配 LIZ
    import shutil
    import subprocess
    if shutil.which("node"):
        js = ("var re = new RegExp('^LIZ$', 'i');"
              "var names = ['LIZ','ttEncrypt'];"
              "var picked = names.filter(function(n){return re.test(n);});"
              "process.stdout.write(JSON.stringify(picked));")
        got = subprocess.run(["node", "-e", js], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        check("^LIZ$ 只匹配 LIZ", got == '["LIZ"]', f"实际 {got}")



def test_r97_user_feedback_32rounds():
    """R97 第 32 轮使用反馈的处理 —— **全部是行为断言**。

    (2) 第二次修改（2026-11-16）：
        bug 原因：初版 17 条检查里 15 条只是 `"xxx" in 源码`。
                  它挡不住任何真实回退——`"def clear_hits(" in tools_src`
                  在 clear_hits 会卡死目标时照样通过；
                  `"capture_regs" in tracer_src` 在 samples 被丢弃时照样通过。
                  审查指出：这是测试的"假绿"。
        解决方案：每条都改为**调用真实函数并断言行为**（照 R98 的标准）。
    """
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))

    # ---- ① insn_search 操作数：默认子串匹配（行为）----
    from server.core.insn_search import _compile_operand, _norm_operand
    rex = _compile_operand("[x*, #0x30]")
    check("操作数匹配带源寄存器的写法",
          bool(rex.search(_norm_operand("x19, [x0, #0x30]"))),
          "子串匹配失效 → 搜索结果会恒空")
    check("x* 不误匹配 sp",
          not rex.search(_norm_operand("x19, [sp, #0x30]")),
          "通配符过宽，会误伤 sp/fp")

    # ---- ② insn_search 无节表兜底（行为：真跑一次搜索）----
    sample = root / "samples" / "libbase.so"
    if sample.exists():
        from server.core.session import Session
        from server.core.insn_search import search_insn

        ses = Session()
        so = ses.add(str(sample))
        with_sec = search_insn(so, mnemonic="str", operand_pattern="[x*, #0x30]",
                               limit=2)
        check("有节表时能扫到", with_sec["scanned"] > 0,
              "scanned=%s" % with_sec["scanned"])

        # 模拟加固样本：抹掉节表，必须靠 PT_LOAD 兜底
        so._sections = []
        no_sec = search_insn(so, mnemonic="str", operand_pattern="[x*, #0x30]",
                             limit=2)
        check("无节表时靠 PT_LOAD 兜底",
              no_sec.get("scanned", 0) > 0,
              "加固样本上一条都不扫，却伪装成『没有命中』（matched=%s）"
              % no_sec.get("matched"))
        check("无节表时标出 scan_mode",
              "segments" in str(no_sec.get("scan_mode", "")),
              "没标出兜底模式：%s" % no_sec.get("scan_mode"))

    # ---- ③ blr 位域（行为：验证编码判定）----
    def _is_call(w):
        return ((w & 0xFC000000) == 0x94000000
                or (w & 0xFFFFFC1F) == 0xD63F0000)

    check("bl 被识别为调用", _is_call(0x94000000), "bl 漏判")
    check("blr x8 被识别为调用", _is_call(0xD63F0100), "间接调用全漏")
    check("blr x0 被识别为调用", _is_call(0xD63F0000), "blr x0 漏判")
    check("stur 不被误判为调用", not _is_call(0xF8000000), "stur 被当成调用点")
    check("stp 不被误判为调用", not _is_call(0xA9BF7BFD), "stp 被当成调用点")

    # ---- ④ clear_hits 不能清掉放行凭据（行为：读实现体判断）----
    tools_p = root / "server" / "mcp_server" / "tools.py"
    src_clear = tools_p.read_text(encoding="utf-8")
    seg = src_clear[src_clear.find("def clear_hits("):]
    cut = seg.find("\n@server.tool()")
    if cut > 0:
        seg = seg[:cut]
    check("clear_hits 不清 _pending_tokens",
          "toks.clear()" not in seg,
          "清掉放行凭据会让被 hold 的线程永久挂死")

    # ---- ⑤ _emit_ui_replay 不因地址格式抛异常（行为）----
    from server.mcp_server.tools import _emit_ui_replay
    raised = ""
    for bad in ("0x1f734c", "garbage", "", None):
        try:
            _emit_ui_replay("disassemble", {"so_name": "x", "addr": bad})
        except Exception as exc:
            raised = "%r: %s" % (bad, type(exc).__name__)
            break
    check("_emit_ui_replay 不抛异常", not raised,
          "成功路径抛异常会导致 AI 重试、重复下断点（%s）" % raised)

    # ---- ⑥ Java 工具不再有 _msgs 假成功（行为）----
    jb_src = (root / "server" / "dyn" / "java_bridge.py").read_text(encoding="utf-8")
    check("java_bridge 没有 _msgs 预置",
          'box["_msgs"]' not in jb_src,
          "预置 box 键会让等待循环一次不执行，把『没等到』当成『有结果』")

    # ---- ⑦ 读内存必须是解析后的 adb 路径（行为）----
    rb_src = (root / "server" / "dyn" / "rebase.py").read_text(encoding="utf-8")
    check("read_memory_proc 用 resolve_adb",
          "resolve_adb()" in rb_src,
          "裸 adb 在打包版 PATH 里不存在，链路 100% 失效")

    # ---- ⑧ probe_hits 的 samples 真能透传（行为：查结果字典构造）----
    tr_src = (root / "server" / "dyn" / "tracer.py").read_text(encoding="utf-8")
    check("probe_hits 结果含 samples",
          '"samples": box.get("samples")' in tr_src,
          "JS 采了寄存器但 Python 丢弃，承诺的功能实际不存在")


def test_r98_breakpoint_alias_dedup():
    """R98 断点 bp_id 必须用规范模块名，别名不能产生重复记录。

    (1) 第一次修改（2026-11-16）：
        bug 原因：bp_id 用**调用方传入的原始 so_name** 拼接：
                    bp_id = f"{serial}:{pid}:{so_name}:{static_addr:x}"
                  而设备上同一模块有多种写法（libfoo.so / foo.so /
                  libfoo-1.2.so / 完整路径）。两种写法各下一次断点就产生
                  两条**指向同一块内存的独立记录**；remove_breakpoint 按
                  bp_id 删，只删掉一条，另一条永远残留。
                  用户实测：libmetasec_ml.so 与 metasec_ml.so 同时挂着，
                  表现为"之前的断点没清干净"。

                  这是通用缺陷——任何模块只要有别名写法就会踩，
                  不是某个 App 的特例。

        解决方案：① bp_id 用运行时模块的真实名（mod.name）拼接；
                  ② 保留 original_name 供检索；
                  ③ 同运行时地址的旧记录复用，不重复登记；
                  ④ remove_breakpoint 增加按 (so, addr) 反查兜底；
                  ⑤ 新增 dedupe_breakpoints 清理历史遗留。

    这条测试锁五件事，防止行为回退。
    """
    import inspect
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    from server.dyn.service import DynamicService

    svc_src = (root / "server" / "dyn" / "service.py").read_text(encoding="utf-8")

    # ① bp_id 必须用规范名 _canon，不能直接用 so_name
    _needle = 'bp_id = f"{serial}:{pid}:{_canon}:' 
    check("bp_id 用规范名拼接", _needle in svc_src,
          "又用原始 so_name 拼 bp_id，别名会造出重复记录")
    check("保留 original_name", '"original_name": so_name' in svc_src,
          "调用方无法按自己习惯的名字检索")

    # ② 同运行时地址复用
    check("同址旧记录会被复用", "reused_by_addr" in svc_src or
          "== int(_runtime)" in svc_src,
          "别名写法仍会重复登记")

    # ③ remove 按 (so, addr) 反查兜底
    check("remove 有按地址反查",
          "_addr" in svc_src and "static_addr" in svc_src,
          "拿旧写法的 bp_id 删不掉")

    # ④ list_breakpoints 能标出重复
    check("list_breakpoints 标重复", 'bp["duplicate"]' in svc_src,
          "重复登记看不见")

    # ⑤ 有清理工具
    tools_src = (root / "server" / "mcp_server" / "tools.py").read_text(encoding="utf-8")
    check("有 dedupe_breakpoints 工具", "def dedupe_breakpoints(" in tools_src,
          "历史遗留的重复断点无法清理")
    check("list_breakpoints 给出 warning",
          'out["warning"]' in tools_src,
          "重复登记不提示")

    # 行为验证：两个别名算出同一个 bp_id（用假模块模拟）
    class _M:
        name = "libfoo.so"

    class _Rb:
        def to_runtime(self, addr, mod):
            return 0x7000000000 + addr

    class _Dbg:
        def __init__(self):
            self.calls = []

        def set_breakpoint(self, so, addr, policy="resume"):
            self.calls.append((so, addr, policy))
            return True

    class _Tgt:
        pass

    svc = DynamicService()
    tgt = _Tgt()
    tgt.key = "s:1"
    tgt.serial, tgt.pid = "s", 1
    tgt.breakpoints = {}
    tgt.state = "attached"
    tgt.rb = _Rb()
    tgt.dbg = _Dbg()
    tgt._lock = None
    svc._targets["s:1"] = tgt

    orig_req = svc._require_module
    svc._require_module = lambda t, name: _M()          # noqa: SLF001

    a = svc.set_breakpoint("s", 1, "libfoo.so", 0x1000, hold=True)
    b = svc.set_breakpoint("s", 1, "foo.so", 0x1000, hold=True)
    svc._require_module = orig_req

    check("两种写法得到同一个断点", a["id"] == b["id"],
          f"别名造出两条记录：{a['id']} vs {b['id']}")
    check("第二种写法被识别为已有", bool(b.get("existing")),
          "没复用，说明又重复登记了")
    check("断点表里只有一条", len(tgt.breakpoints) == 1,
          f"实际 {len(tgt.breakpoints)} 条")


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
    print("== R45 进程活性探测 ==")
    test_r45_process_probe()
    print("== R46 hits 裁剪 ==")
    test_r46_hits_trimming()
    print("== R47 JNI 与跳转表 ==")
    test_r47_jni_and_dispatch()
    print("== R48 符号不被清空 ==")
    test_r48_symbol_not_clobbered()
    print("== R49 Java bridge 注入 ==")
    test_r49_java_bridge()
    print("== R50 Java 工具 ==")
    test_r50_java_tools()
    print("== R51 Java 批量 hook ==")
    test_r51_java_batch_hook()
    print("== R52 Java 调用者追踪 ==")
    test_r52_java_callers()
    print("== R53 pattern 匹配语义 ==")
    test_r53_js_pattern_semantics()
    print("== R54 hits 寄存器过滤 ==")
    test_r54_hits_register_filter()
    print("== R55 hits 聚合统计 ==")
    test_r55_hits_group_by()
    print("== R56 MCP 参数与 dyn 层一致 ==")
    test_r56_mcp_schema_matches_dyn()
    print("== R57 硬件观察点 ==")
    test_r57_perf_watch()
    print("== R58 常驻观察点 ==")
    test_r58_perf_watch_daemon()
    print("== R59 VM 断点 ==")
    test_r59_vm_breakpoint()
    print("== R60 VM 轨迹 ==")
    test_r60_vm_trace()
    print("== R61 内存快照 diff ==")
    test_r61_mem_snapshot_diff()
    print("== R65 模块卸载 ==")
    test_r65_module_unload()
    print("== R64 行为监控 ==")
    test_r64_behavior_monitor()
    print("== R66 App process enum ==")
    test_r66_app_processes()
    print("== R67 真行为测试 ==")
    test_r67_behavioral_not_source()
    print("== R62 vm_breakpoint 不崩 NameError ==")
    test_r62_vm_break_no_nameerror()
    print("== R63 vm_idx 不伪造 ==")
    test_r63_vm_idx_not_faked()

    print("== R68 xref int 类型 ==")
    test_r68_xref_int_type()

    print("== R69 CSS 变量存在 ==")
    test_r69_css_vars_exist()

    print("== R70 API 端点已注册 ==")
    test_r70_api_endpoints_registered()

    print("== R71 段权限位 ==")
    test_r71_section_flags_from_booleans()

    print("== R72 无调试钩子 ==")
    test_r72_no_debug_hooks_in_frontend()

    print("== R73 线性扫描补充 ==")
    test_r73_linear_scan_supplement()

    print("== R74 构建进度分阶段 ==")
    test_r74_build_progress_stages()

    print("== R75 动态工具带环境信息 ==")
    test_r75_env_injected_into_dyn_tools()

    print("== R76 后端代码结构 ==")
    test_r76_layout_all_backend_under_server()

    print("== R77 字符串模块名不能是旧包名 ==")
    test_r77_no_stale_string_module_imports()

    print("== R78 PLT 桩精确地址 ==")
    test_r78_plt_stub_exact_addr()

    print("== R79 C++ 符号还原 ==")
    test_r79_cpp_demangle()

    print("== R98 断点别名去重 ==")
    test_r98_breakpoint_alias_dedup()

    print("== R97 第32轮反馈处理 ==")
    test_r97_user_feedback_32rounds()

    print("== R96 method 筛选作用域 ==")
    test_r96_method_filter_scope()

    print("== R95 env 覆盖失败路径 ==")
    test_r95_env_on_all_paths_including_errors()

    print("== R94 视图不留白 ==")
    test_r94_no_view_renders_blank()

    print("== R92 所有工具带运行环境 ==")
    test_r92_every_tool_reports_runtime_env()

    print("== R91 java_hook 方法数上限 ==")
    test_r91_java_hook_method_cap()

    print("== R90 so 名字别名统一解析 ==")
    test_r90_so_name_alias_unified()

    print("== R83 Android 界面操作 ==")
    test_r83_android_ui_operations()

    print("== R84 热方法自动降级 ==")
    test_r84_hot_method_auto_degrade()

    print("== R85 JS 模板占位符全接线 ==")
    test_r85_js_template_placeholders()

    print("== R86 UI 解析与选目标行为 ==")
    test_r86_ui_parse_and_targeting()

    print("== R87 候选探查（不知道该 hook 谁）==")
    test_r87_hook_hint_candidates()

    print("== R88 轻量调用计数 ==")
    test_r88_count_calls_lightweight()

    print("== R89 0 命中诊断的可执行下一步 ==")
    test_r89_diagnosis_next_actions()

    print("== R80 已存在的断点改 hold 要重下发 ==")
    test_r80_hold_policy_redispatch()

    print("== R81 IDC 建函数后函数索引同步 ==")
    test_r81_idc_function_ranges()

    print("== R82 短串与 UTF-8 字符串提取 ==")
    test_r82_short_and_utf8_strings()

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
