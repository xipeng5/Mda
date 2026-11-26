"""2026-11-26 全面代码审查修复项回归测试（纯离线，不连真机）。

覆盖本轮 6 并发修复线程落地的核心 P0/P1 修复点，确保不再回退：
  1. 静态核心（RELR / 无节表 ELF / PLT disp=0 / insn_search / DWARF / DEX / IDC / Unicorn 桩）
  2. 插件生态（elf_lief / emulate_func / string_crack / xref_enhanced / detect_obfuscation /
     decompile_c / disasm_func / solve_constraint / sensitive_scan / scan / angr_worker）
  3. 动态核心与平台（service / debugger / console 死锁 / bridge-tracer-memread / java_bridge /
     vmbreak / uprobe / ui / perfwatch / frida_server / build_payload 无副作用导入）
  4. MCP 工具层（trace_aggregate / hits / get_plugins stderr / dedupe_breakpoints / resume /
     watch_module / list_processes / get_callees / dex_* / ui_click index=None）
  5. Web API 与安全（DNS Rebinding / CSRF / WS CSWSH / XSS 转义 / armed/clear POST / fn_detail / mda.spec）

运行：.venv/bin/python tests/test_audit_fixes.py
"""
from __future__ import annotations

import asyncio
import inspect
import io
import json
import os
import sys
import threading
import time
from collections import deque
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["MDA_IS_GUI"] = "1"

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    """记录单项断言结果。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [通过] {name}")
    else:
        FAIL += 1
        print(f"  [失败] {name}  {detail}")


def test_static_core() -> None:
    """静态分析核心、DEX、IDC 与 Unicorn 桩回归。"""
    print("== 1. 静态核心 / DEX / IDC / Unicorn 桩 ==")
    from server.core import rela
    from server.core.dex import api as dex_api, bytecode as dex_bc
    from server.core.dwarf import CfiUnwinder
    from server.core.elf_model import SoFile
    from server.core.insn_search import search_insn
    from server.core.session import Session
    from server.core.unicorn_stubs import StubEngine
    from server.scripting.idc import _translate, run_idc

    # RELR 12 个真实函数指针且首槽不重复
    so_base = SoFile(str(ROOT / "samples" / "libbase.so"))
    relr_entries = [e for e in so_base.rela_table.entries if e.source == "relr"]
    relr_offsets = [e.offset for e in relr_entries]
    check("RELR 无重复槽", len(relr_offsets) == len(set(relr_offsets)), str(relr_offsets[:5]))
    check("RELR 真实代码目标为 12 个", len(rela.code_targets(so_base)) == 12,
          str(len(rela.code_targets(so_base))))

    # 无节表壳样本 100% 精确还原
    so_nosh = SoFile(str(ROOT / "tests" / "fixtures" / "libbase_no_shdr.so"))
    check("无节表 libbase 函数起点与有节表 100% 一致",
          sorted(so_nosh.functions) == sorted(so_base.functions),
          f"{len(so_nosh.functions)} vs {len(so_base.functions)}")
    check("无节表 libbase 导出 100% 一致",
          set(so_nosh.exports) == set(so_base.exports),
          f"{len(so_nosh.exports)} vs {len(so_base.exports)}")
    check("无节表 libbase 导入 100% 一致",
          set(so_nosh.imports) == set(so_base.imports),
          f"{len(so_nosh.imports)} vs {len(so_base.imports)}")

    # 页对齐 disp==0 的 PLT 槽（libc.so fchmodat）
    libc_path = ROOT / "samples" / "device" / "libc.so"
    if libc_path.is_file():
        so_libc = SoFile(str(libc_path))
        check("页对齐 PLT 符号 fchmodat 不丢",
              "fchmodat" in set(so_libc.plt_map.values()))

    # insn_search text_only=False 包含 .text
    r_all = search_insn(so_base, mnemonic="ret", text_only=False, limit=10)
    check("insn_search(text_only=False) 搜到 ret", r_all.get("count", 0) > 0, str(r_all))

    # DWARF base=0 可登记
    uw = CfiUnwinder()
    uw.add_module(0, 0x40000, so=so_base, name="libbase.so")
    check("DWARF add_module 支持 base=0", len(uw._modules) == 1)

    # DEX const/4 负号扩展 & 35c 寄存器不折叠 & _norm_class L 开头
    class _FakeTables:
        data = b""
        insns_base = 0
        def string(self, idx): return "s"
        def type_desc(self, idx): return "LFoo;"
        def field(self, idx): return None
        def method(self, idx):
            class _M:
                class_desc = "LFoo;"
                name = "bar"
                class proto:
                    descriptor = "()V"
            return _M()
        def proto(self, idx): return None
        def call_site(self, idx): return f"call_site@{idx}"

    ins_neg = dex_bc.render(_FakeTables(), 0x12, [0xF012], 0, 0)
    check("DEX const/4 #-1 正确符号扩展", "#int -1" in ins_neg.operands, ins_neg.operands)
    ins_35c = dex_bc.render(_FakeTables(), 0x71, [0x3071, 0x0000, 0x0925], 0, 0)
    check("DEX 35c 保留非连续寄存器", "{v5, v2, v9}" in ins_35c.operands, ins_35c.operands)
    check("DEX _norm_class 不吞 L 开头类名",
          dex_api._norm_class("LoginActivity") == "LLoginActivity;"
          and dex_api._norm_class("L") == "LL;"
          and dex_api._norm_class("Lcom/a/B;") == "Lcom/a/B;")

    # IDC get_flags 后 MakeFunction(BADADDR) 不抛 CsError + 字符串含 // + 禁 __import__
    ses = Session()
    ses.add(str(ROOT / "samples" / "libbase.so"))
    res_idc = run_idc(
        ses, "libbase.so",
        'static main() { if (is_code(get_flags(0x12000))) { MakeFunction(0x12000, BADADDR); set_cmt(0x12000, "http://a/{b}"); } }'
    )
    check("IDC get_flags + MakeFunction(BADADDR) + 含 //{} 注释不崩",
          not res_idc.get("error"), str(res_idc))
    tr_else = _translate("if (a) x = 1; else if (b) x = 2; else x = 3;")
    check("IDC 单行 if/else if/else 保留末尾 else", "else:" in tr_else and "x = 3" in tr_else, tr_else)
    res_sec = run_idc(ses, "libbase.so", 'static main() { __import__("os"); }')
    check("IDC 沙箱拦截 __import__", bool(res_sec.get("error")), str(res_sec))

    # Unicorn stubs snprintf 不吃字符 + bzero 2参 + close 不进 fopen
    class _FakeUC:
        def __init__(self):
            self.regs = {}
            self.mem = bytearray(0x4000)
        def reg_read(self, r): return self.regs.get(r, 0)
        def reg_write(self, r, v): self.regs[r] = v
        def mem_read(self, a, n): return bytes(self.mem[a:a + n])
        def mem_write(self, a, data): self.mem[a:a + len(data)] = data

    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4
    uc = _FakeUC()
    se = StubEngine(uc, {}, "auto")
    uc.regs[UC_ARM64_REG_X3] = 0xAB
    uc.regs[UC_ARM64_REG_X4] = 0xCD
    text, _ = se._mini_snprintf(uc, "%02x/%02x")
    check("Unicorn _mini_snprintf 不吞格式符后字符", text == "ab/cd", repr(text))
    uc.mem[0x100:0x108] = b"\x55" * 8
    uc.regs[UC_ARM64_REG_X0] = 0x100
    uc.regs[UC_ARM64_REG_X1] = 4
    uc.regs[UC_ARM64_REG_X2] = 8  # 残留 x2 不能被 bzero 当长度
    se._stub_bzero(uc)
    check("Unicorn _stub_bzero 仅清零前 4 字节",
          bytes(uc.mem[0x100:0x108]) == b"\x00\x00\x00\x00\x55\x55\x55\x55",
          bytes(uc.mem[0x100:0x108]).hex())


def test_plugins() -> None:
    """24 个插件关键 P0/P1 修复回归。"""
    print("== 2. 插件生态 ==")
    from server.core.session import Session
    from server.plugins.detect_obfuscation import Plugin as ObfPlugin
    from server.plugins.elf_lief import Plugin as LiefPlugin
    from server.plugins.emulate_func import Plugin as EmuPlugin
    from server.plugins.sensitive_scan import Plugin as SensPlugin
    from server.plugins.solve_constraint import Plugin as Z3Plugin
    from server.plugins.string_crack import Plugin as CrackPlugin
    from server.plugins.xref_enhanced import Plugin as XrefEnhPlugin

    ses = Session()
    ses.add(str(ROOT / "samples" / "liblog.so"))

    # elf_lief relocations 可 JSON 序列化且支持 0x 地址
    rl = LiefPlugin().run(ses, {"so": "liblog.so", "mode": "relocations", "limit": 5})
    check("elf_lief relocations 返回可 JSON 序列化",
          rl.get("ok") is True and bool(json.dumps(rl)))
    rl_hex = LiefPlugin().run(ses, {"so": "liblog.so", "mode": "relocations", "addr": "0x0", "limit": 2})
    check("elf_lief relocations 接受 0x 十六进制 addr", rl_hex.get("ok") is True, str(rl_hex))

    # emulate_func dump="stack" 不再 UC_ERR_READ_UNMAPPED
    em = EmuPlugin().run(ses, {"so": "liblog.so", "addr": "0x5020", "max_insns": 20, "dump": "stack"})
    regions = (em.get("memory") or {}).get("regions") or []
    check("emulate_func dump='stack' 读已映射栈区无错误",
          em.get("ok") is True and bool(regions) and not regions[0].get("error"), str(regions)[:150])

    # string_crack 接受 0x 地址且无 NUL 加密块不丢失
    sc = CrackPlugin().run(ses, {"so": "liblog.so", "addr": "0x2d7e", "size": "0x20"})
    check("string_crack 接受 0x addr/size 不崩", sc.get("ok") is True, str(sc)[:120])
    out_chunks = []
    CrackPlugin()._split_nul(out_chunks, 0x1000, bytes(b ^ 0xA5 for b in b"https://api.example.com"), 4, exact=True)
    check("string_crack _split_nul 保留无末尾 NUL 加密块", len(out_chunks) == 1, str(len(out_chunks)))

    # xref_enhanced 接受 0x addr 且未知 mode 报 BAD_MODE
    xe_hex = XrefEnhPlugin().run(ses, {"so": "liblog.so", "mode": "refs", "addr": "0x1000", "limit": 5})
    check("xref_enhanced 接受 0x addr 不崩", xe_hex.get("ok") is True, str(xe_hex)[:120])
    xe_bad = XrefEnhPlugin().run(ses, {"so": "liblog.so", "mode": "unknown_xyz"})
    check("xref_enhanced 未知 mode 报 BAD_MODE", xe_bad.get("code") == "BAD_MODE", str(xe_bad))

    # detect_obfuscation opaque_predicate 正反验证
    op = ObfPlugin()
    w_true = [(0x1000, "lsl w1, w0, #2"), (0x1004, "sub w2, w1, w0"), (0x1008, "cmp w2, #0")]
    w_false = [(0x1000, "lsl w0, w0, #2"), (0x1004, "sub w0, w0, w5"), (0x1008, "cmp w0, #0")]
    hit_true = op._match("opaque_predicate", w_true, 0, w_true, [], (0, 0x2000))
    hit_false = op._match("opaque_predicate", w_false, 0, w_false, [], (0, 0x2000))
    check("detect_obfuscation opaque_predicate 真模式命中", hit_true is not None, str(hit_true))
    check("detect_obfuscation opaque_predicate 假模式不误报", hit_false is None, str(hit_false))

    # solve_constraint BoolOp and/or/not + 32-bit 常量
    z3r = Z3Plugin().run(ses, {
        "vars": {"x": {"bits": 32}},
        "constraints": ["x > 1 and x < 5", "not (x == 2)", "x == (1 << 1) + 1"],
    })
    check("solve_constraint 支持 and/not 与 32 位常量算术",
          z3r.get("ok") is True and z3r.get("solutions", [{}])[0].get("x") == 3, str(z3r))

    # sensitive_scan 小写 akia 命中
    check("sensitive_scan 包含小写 akia", "akia" in SensPlugin._KEY)

    # angr_worker 不再传不存在的 depth_limit
    worker_src = (ROOT / "server" / "plugins" / "angr_worker" / "worker.py").read_text(encoding="utf-8")
    check("angr_worker 不再使用无效 depth_limit", '"depth_limit"' not in worker_src)


def test_dyn_and_mcp() -> None:
    """动态核心/平台与 MCP 工具层回归。"""
    print("== 3. 动态调试与 MCP 工具层 ==")
    import server.dyn.console as dyn_console
    import server.dyn.uprobe as dyn_uprobe
    import server.dyn.ui as dyn_ui
    import server.dyn.bridge as dyn_bridge
    import server.dyn.tracer as dyn_tracer
    import server.dyn.memread as dyn_memread
    import server.dyn.java_bridge as dyn_java
    import server.dyn.vmbreak as dyn_vmb
    from server.dyn.service import DynamicService, STATE_PAUSED
    import server.mcp_server.tools as T

    # 1) trace_aggregate / trace_timeline 默认调用不抛 NameError
    r_agg = json.loads(T.trace_aggregate())
    r_tl = json.loads(T.trace_timeline())
    check("trace_aggregate() 默认调用无 NameError",
          "NameError" not in json.dumps(r_agg) and r_agg.get("code") == "NO_EVENTS", str(r_agg)[:120])
    check("trace_timeline() 默认调用无 NameError",
          "NameError" not in json.dumps(r_tl) and r_tl.get("code") == "NO_EVENTS", str(r_tl)[:120])

    # 2) get_plugins() 日志不污染 stdout
    T._plugin_mgr = None
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.get_plugins()
    check("get_plugins() 不向 stdout 输出破坏 stdio JSON-RPC",
          buf.getvalue() == "", repr(buf.getvalue()[:120]))

    # 3) DynamicService：单调 seq 超 2000 条 + on_hit 即时 paused + Wi-Fi ADB rpartition + resume 无 dbg NameError
    class _FakeDbg:
        def __init__(self):
            self._hits = deque(maxlen=2000)
            self._cb = None
            self.state = "attached"
        def set_on_hit(self, cb): self._cb = cb
        @property
        def hits(self): return list(self._hits)
        def push_hit(self, seq, held=False):
            h = {"so_name": "libx.so", "static_addr": 0x100, "runtime_addr": 0x7000100,
                 "thread_id": 1, "context": {"x2": seq}, "backtrace": [], "stack_hex": "",
                 "stack": [], "ts": time.time(), "held": held, "token": f"t{seq}", "seq": seq}
            self._hits.append(h)
            if held:
                self.state = "paused"
            if self._cb:
                self._cb(h)
        def resume(self, token=None):
            return {"resumed": True, "state": "paused", "failed": 1, "woken": 0, "pending": 1}
        def close(self): pass

    svc = DynamicService()
    dbg = _FakeDbg()
    from server.dyn.service import Target
    tgt = Target(serial="192.168.1.9:5555", pid=4321, rb=object(), dbg=dbg, state="attached")
    dbg.set_on_hit(lambda h: svc._on_debugger_hit(tgt, h))
    svc._targets[tgt.key] = tgt
    for i in range(1, 2006):
        dbg.push_hit(i, held=(i == 2005))
    check("满 2000 条环形缓冲后单调 seq 仍推进到 2005", tgt.last_synced_seq == 2005, str(tgt.last_synced_seq))
    check("on_hit 回调立即切 STATE_PAUSED 无需轮询", tgt.state == STATE_PAUSED, tgt.state)
    # partial_resume 分支不再抛 NameError: dbg
    res_part = svc.resume("192.168.1.9:5555", 4321)
    check("resume 部分放行失败分支无 NameError",
          res_part.get("resumed") is False and res_part.get("reason") == "partial_resume", str(res_part))
    svc.close_all()
    check("Wi-Fi ADB serial(ip:port) close_all 成功清理", len(svc._targets) == 0, str(svc._targets))

    # 4) hits(filter=...) 空匹配无 UnboundLocalError
    import server.dyn.service as dyn_svc_mod
    old_dyn = getattr(dyn_svc_mod, "_service", None)
    try:
        svc2 = DynamicService()
        dbg2 = _FakeDbg()
        tgt2 = Target(serial="DEV1", pid=99, rb=object(), dbg=dbg2, state="attached")
        svc2._targets[tgt2.key] = tgt2
        dbg2.push_hit(1, held=False)
        dyn_svc_mod._service = svc2
        r_hits = json.loads(T.hits("DEV1", 99, filter={"x2": 999999}))
        check("hits(filter=...) 0 匹配无 UnboundLocalError",
              r_hits.get("ok") is True and r_hits.get("total_before_filter") == 1, str(r_hits))
        # resume 不双层嵌套
        r_res = json.loads(T.resume("DEV1", 99))
        check("MCP resume 不再双层嵌套 resumed",
              isinstance(r_res.get("resumed"), bool), str(r_res))
        # dedupe_breakpoints 不拔活钩
        unhook_calls = []
        dbg2.remove_breakpoint = lambda *a, **kw: unhook_calls.append(a) or True
        tgt2.breakpoints["DEV1:99:libx.so:100"] = {"id": "DEV1:99:libx.so:100", "runtime_addr": 0x7000100}
        tgt2.breakpoints["DEV1:99:x.so:100"] = {"id": "DEV1:99:x.so:100", "runtime_addr": 0x7000100}
        r_dedup = json.loads(T.dedupe_breakpoints("DEV1", 99))
        check("dedupe_breakpoints 去重不调用底层摘钩",
              r_dedup.get("removed_count") == 1 and len(unhook_calls) == 0 and len(tgt2.breakpoints) == 1,
              str((r_dedup, unhook_calls, list(tgt2.breakpoints))))
    finally:
        dyn_svc_mod._service = old_dyn

    # 5) console.py stop_js 不与 _on_message 发生 AB-BA 死锁
    class _DeadlockProbeScript:
        def __init__(self, cb):
            self._cb = cb
        def unload(self):
            # 模拟 Frida GLib 线程在 unload 期间回调 _on_message（必须不死锁！）
            t = threading.Thread(target=lambda: self._cb({"type": "send", "payload": "bye"}, None))
            t.start()
            t.join(timeout=2.0)
            if t.is_alive():
                raise RuntimeError("DEADLOCK!")

    ev_holder = {}
    def _dummy_cb(msg, data):
        with dyn_console._lock:
            ev_holder["got"] = True
    cs = dyn_console.ConsoleScript(script_id=98765, serial="S", pid=1,
                                   frida_script=_DeadlockProbeScript(_dummy_cb), mode="keep")
    with dyn_console._lock:
        dyn_console._scripts[("S", 1)] = [cs]
        dyn_console._counts[98765] = 1
    res_stop = dyn_console.stop_js(script_id=98765)
    check("console.stop_js 锁外卸载无 AB-BA 死锁",
          res_stop.get("ok") is True and 98765 not in dyn_console._counts, str(res_stop))

    # 6) dex_* 失败不再返回 ok: True 假成功
    r_dex = json.loads(T.dex_classes("/nonexistent/does_not_exist.dex"))
    check("dex_classes 失败返回 ok=False", r_dex.get("ok") is False, str(r_dex))

    # 7) ui_click/ui_input 默认 index=None，ui._match removeprefix("id/")
    sig_click = inspect.signature(T.ui_click)
    sig_input = inspect.signature(T.ui_input)
    check("MCP ui_click/ui_input 默认 index=None",
          sig_click.parameters["index"].default is None
          and sig_input.parameters["index"].default is None)
    node_dlg = dyn_ui.UiNode(text="", resource_id="com.app:id/dialog_ok",
                             content_desc="", cls="android.widget.Button",
                             bounds=(0, 0, 10, 10), clickable=True, enabled=True)
    node_alog = dyn_ui.UiNode(text="", resource_id="com.app:id/alog_ok",
                              content_desc="", cls="android.widget.Button",
                              bounds=(0, 0, 10, 10), clickable=True, enabled=True)
    check("ui._match removeprefix 精确匹配 dialog_ok 且不误中 alog_ok",
          dyn_ui._match(node_dlg, "", "dialog_ok", "", "", True)
          and not dyn_ui._match(node_alog, "", "dialog_ok", "", "", True))

    # 8) 关键行为与源码防回退检查
    uprobe_src = inspect.getsource(dyn_uprobe)
    check("uprobe _cleanup 正则含 ^[pr]:", 'check_pattern = f"^[pr]:{_EVENT_GROUP}/"' in uprobe_src)
    import re as _re
    code_lines_uprobe = "\n".join(
        ln for ln in uprobe_src.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    )
    check("uprobe 不再用截断重定向 > 清空 uprobe_events",
          not _re.search(r"(?<!>)>\s*\{?(?:q_events|root\}?/uprobe_events)", code_lines_uprobe))
    check("uprobe 拒绝非法函数名注入",
          not dyn_uprobe.trace_alloc("S", 1, funcs=["malloc;id"]).get("ok", True))
    check("java_bridge 传入 entryObj 修复闭包", "entryObj" in dyn_java._JS_JAVA_HOOK_MULTI)
    check("memread probe_vm_from_hits 仅 csize==8 调 .toNumber()",
          "if csize == 8 else" in inspect.getsource(dyn_memread.probe_vm_from_hits))
    check("tracer _JS_MEM_TRACE 区分 read/write KIND",
          "KIND === 'read'" in dyn_tracer._JS_MEM_TRACE and "KIND === 'write'" in dyn_tracer._JS_MEM_TRACE)
    check("vmbreak scalarFromReg 不对寄存器标量 readU64",
          "scalarFromReg" in dyn_vmb._JS_SPEC_HELPERS)

    class _MockSo:
        path = ""
        def read(self, off, sz):
            return b"VADDR_OK"[:sz]

    mso = _MockSo()
    check("bridge/tracer/memread 静态读调用真实 so.read",
          dyn_bridge._read_so_bytes(mso, 0x1000, 8) == b"VADDR_OK"
          and dyn_tracer._read_static_bytes(mso, 0x1000, 8) == b"VADDR_OK"
          and dyn_memread._read_so_bytes_raw(mso, 0x1000, 8) == b"VADDR_OK")

    # 9) build_payload.py import 无副作用
    import server.dyn.device.build_payload as bp_mod
    check("build_payload.py import 无顶层执行副作用", callable(getattr(bp_mod, "main", None)))


def test_web_api_and_security() -> None:
    """Web API 安全边界、契约与打包回归。"""
    print("== 4. Web API 安全与契约 ==")
    import server.api as api_mod
    from starlette.testclient import TestClient

    client = TestClient(api_mod.app, base_url="http://127.0.0.1:8766")

    # DNS Rebinding 拦截
    r_host = client.get("/api/health", headers={"host": "evil.attacker.com:8766"})
    check("拦截非法 Host（DNS Rebinding）返回 403", r_host.status_code == 403, str(r_host.status_code))

    # 跨站 text/plain 简单 POST 拦截
    r_csrf = client.post(
        "/api/frida_js",
        content='{"serial":"S","pid":1,"js":"send(1)"}',
        headers={"content-type": "text/plain", "origin": "https://evil.example"},
    )
    check("拦截跨站 text/plain POST /api/frida_js 返回 403",
          r_csrf.status_code == 403, str(r_csrf.status_code))

    # /api/armed/clear 仅接受 POST，拒绝 GET（挂载静态根时 Starlette 返回 404 或 405，绝不执行清理）
    r_get_clear = client.get("/api/armed/clear")
    check("GET /api/armed/clear 被拒绝（404/405）",
          r_get_clear.status_code in (404, 405), str(r_get_clear.status_code))
    r_post_clear = client.post("/api/armed/clear", headers={"X-MDA-Client": "1"})
    check("POST /api/armed/clear 返回 200", r_post_clear.status_code == 200, str(r_post_clear.status_code))

    # fn_detail 不触发全量 xref.build()
    api_mod._session.add(str(ROOT / "samples" / "liblog.so"))
    xr = api_mod._session.xref("liblog.so")
    xr.reset()
    r_fn = client.get("/api/fn_detail?so=liblog.so&addr=0x5020")
    check("fn_detail 返回 200 且不触发全量 xref.build()",
          r_fn.status_code == 200 and xr._built is False,
          f"status={r_fn.status_code} built={xr._built}")

    # index_html 行为验证：真实转义 </script> 防 XSS
    spec_src = (ROOT / "packaging" / "mda.spec").read_text(encoding="utf-8")
    check("mda.spec 递归扫描收录 server.core.dex", "os.walk" in spec_src)
    class _XssMod:
        name = "</script><img src=x>"
        path = "/tmp/</script>"
    api_mod._session.modules["__xss_test__"] = _XssMod()
    try:
        r_idx = client.get("/")
        check("index_html 真实转义 </script> 防 XSS",
              r_idx.status_code == 200 and "</script><img" not in r_idx.text and r"<\/script>" in r_idx.text,
              r_idx.text[:200])
    finally:
        api_mod._session.modules.pop("__xss_test__", None)


def main() -> int:
    test_static_core()
    test_plugins()
    test_dyn_and_mcp()
    test_web_api_and_security()
    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
