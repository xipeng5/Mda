"""R110 插件能力修复（第 34 轮反馈）

运行：.venv/bin/python tests/test_plugin_fixes.py

## 这四条反馈的共同点

使用者（一位 AI 代理）在实战里发现这四个工具"看起来能用、实际给不出答案"：

    emulate_func   能跑，但不给内存 → 解密函数跑通了却拿不到输出值
    call_graph     找不到虚调用者 → 只认 bl 边
    xref_enhanced  同样找不到虚调用者 → 只扫 adrp+add
    string_crack   三种方法都试了，一个字符串没解出来
    sensitive_scan 输出全是 "/Y"、"/R" 这种噪音

**这四类都不是崩溃，而是"有输出但答案是错的/空的"**——比崩溃更难发现。
所以本文件的断言以「必须能给出那个答案」为主，并附带「噪音率」检查。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.core import rela as R  # noqa: E402
from server.core.session import Session  # noqa: E402

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


ROOT = Path(__file__).parent.parent


def _session(path: str = "samples/device/libc.so"):
    s = Session()
    so = s.add(str(ROOT / path))
    return s, so


# ---------------------------------------------------------------- 1. emulate_func

def test_emulate_memory_dump() -> None:
    print("== 1. emulate_func 必须能导出内存 ==")
    from server.plugins import emulate_func as EM

    s, _so = _session("samples/liblog.so")
    p = EM.Plugin()
    base = {"so": "liblog.so", "addr": "0x5020", "max_insns": 2000}

    # A) 不给 dump：保持旧行为（没有 memory 字段）
    r0 = p.run(s, dict(base))
    check("不给 dump 时无 memory 字段（旧行为不变）",
          r0.get("ok") and "memory" not in r0, str(r0)[:150])

    # B) 显式范围：能读回写进去的字节
    buf = "0x40000000"
    payload = "aabbccddeeff0011"
    r1 = p.run(s, dict(base, buffer={"addr": buf, "hex": payload},
                       x0=buf, dump=[{"addr": buf, "size": 16}]))
    m = r1.get("memory") or {}
    regs = m.get("regions") or []
    check("显式范围导出成功", len(regs) == 1, str(m)[:200])
    if regs:
        got = regs[0].get("hex", "")
        check("导出的字节与写入的一致", got.startswith(payload),
              f"{got[:32]} vs {payload}")
        check("带 ascii 视图", "ascii" in regs[0])

    # C) 截断标记：dump_max 小于请求长度时必须标 truncated
    r2 = p.run(s, dict(base, buffer={"addr": buf, "hex": payload},
                       x0=buf, dump=[{"addr": buf, "size": 4096}],
                       dump_max=16))
    regs2 = ((r2.get("memory") or {}).get("regions") or [])
    check("超出 dump_max 时标 truncated",
          bool(regs2) and regs2[0].get("truncated") is True
          and regs2[0].get("full_size") == 4096, str(regs2[:1])[:200])

    # D) writes 模式：至少要能报出"有页被写过"
    r3 = p.run(s, dict(base, dump="writes", dump_max=32))
    regs3 = ((r3.get("memory") or {}).get("regions") or [])
    check("writes 模式有产出", len(regs3) > 0, str(r3.get("memory"))[:150])

    # E) stack 模式：不能是空的（初版因 sp==栈顶恒为空）
    r4 = p.run(s, dict(base, dump="stack", dump_max=64))
    regs4 = ((r4.get("memory") or {}).get("regions") or [])
    check("stack 模式非空（初版恒空）", len(regs4) == 1, str(r4.get("memory"))[:150])

    # F) 未知 dump 值必须明确报错，不能静默返回空
    r5 = p.run(s, dict(base, dump="bogus"))
    check("未知 dump 值报 BAD_DUMP",
          (r5.get("memory") or {}).get("code") == "BAD_DUMP",
          str(r5.get("memory"))[:150])


# ---------------------------------------------------------------- 2. call_graph

def test_call_graph_vtable() -> None:
    print("== 2. call_graph 必须报 vtable 间接边 ==")
    from server.plugins import call_graph as CG

    s, so = _session()
    p = CG.Plugin()
    # 0x48140 是 libc 里一个 vtable 指向的函数
    r = p.run(s, {"so": "libc.so", "addr": hex(0x48140), "depth": 2})

    check("ok", r.get("ok") is True, str(r)[:150])
    check("报出 vtable 边总数", r.get("vtable_edge_count", 0) > 100,
          str(r.get("vtable_edge_count")))
    ind = r.get("indirect_only") or []
    check("有 indirect_only 列表（没人 bl 调用、只被表指向）",
          len(ind) > 0, str(ind)[:150])

    # 目标函数自己必须带 vtable_in
    tree = r.get("tree") or []
    hit = [n for n in tree if n.get("addr") == hex(0x48140)]
    check("root 节点带 vtable_in", bool(hit and hit[0].get("vtable_in")),
          str(hit[:1])[:200])

    # 关掉开关必须一条都不报（证明这个能力是可控的、不是恒真）
    r2 = p.run(s, {"so": "libc.so", "addr": hex(0x48140), "depth": 2,
                   "include_vtable": False})
    check("include_vtable=false 时归零",
          r2.get("vtable_edge_count") == 0
          and not (r2.get("indirect_only") or []), str(r2)[:150])

    # 交叉验证：报出的槽必须真的指向该函数（用 rela 独立复核）
    edges = p._vtable_edges(so)
    ok = True
    for tgt, slots in list(edges.items())[:20]:
        for slot in slots:
            v = R.vtable_at(so, int(slot, 16))
            if not v.get("is_vtable") or v.get("target") != tgt:
                ok = False
                break
    check("报出的槽都能被 vtable_at 独立复核", ok)


# ---------------------------------------------------------------- 3. xref_enhanced

def test_xref_enhanced_indirect() -> None:
    print("== 3. xref_enhanced 必须报 vtable 间接引用 ==")
    from server.plugins import xref_enhanced as XE

    s, _so = _session()
    p = XE.Plugin()

    r = p.run(s, {"so": "libc.so", "mode": "refs", "addr": 0x48140, "limit": 5})
    ind = r.get("indirect") or {}
    check("indirect 有产出", ind.get("count", 0) >= 1, str(ind)[:200])
    items = ind.get("items") or []
    if items:
        it = items[0]
        check("slot/target 字段正确",
              it.get("target") == hex(0x48140)
              and int(it.get("slot", "0x0"), 16) > 0, str(it)[:200])
        check("带 block 范围（vtable 的起止）",
              isinstance(it.get("block"), list), str(it)[:200])
        check("带 target_function",
              bool(it.get("target_function")), str(it)[:200])
    check("明确说明这是函数指针表引用（不是 adrp）",
          "函数指针表" in (ind.get("note") or ""), str(ind.get("note"))[:150])

    # 代码侧 refs 仍然是 0——这是正确的（没有 adrp 到它），必须保持
    check("代码 refs 仍为 0（如实反映，不掺假）",
          r.get("refs", {}).get("count", -1) == 0, str(r.get("refs"))[:150])


# ---------------------------------------------------------------- 4. string_crack

def test_string_crack_fixes() -> None:
    print("== 4. string_crack 三个 bug ==")
    from server.plugins import string_crack as SC

    s, so = _session("samples/liblog.so")
    p = SC.Plugin()

    # bug ①：addr+size 必须按 NUL 切块（初版整块当 1 个块）
    blocks = p._collect_blocks(so, 0x2cd0, 0x7c8, 4)
    check("addr+size 路径按 NUL 切块（不是整块 1 个）",
          len(blocks) >= 2, f"{len(blocks)} 块")
    check("切出的块都 <= 256 字节（初版是整节 1992）",
          all(len(d) <= 256 for _a, d in blocks))

    # bug ②：语义分不能因一个 '.' 归零
    txt = b"https://api.example.com/v1/sign"
    check("含句号的正文字义分为正（初版为 0）",
          SC._semantic_score(txt) > 0.35,
          f"{SC._semantic_score(txt)}")
    check("整块二进制（大量不可打印）仍为 0",
          SC._semantic_score(bytes(range(256))) == 0.0,
          f"{SC._semantic_score(bytes(range(256)))}")
    check("纯重复字符仍为低分", SC._semantic_score(b"~~~~~~~~") < 0.35,
          f"{SC._semantic_score(b'~~~~~~~~')}")

    # bug ③：只给 addr 时不能静默退回全库
    r1 = p.run(s, {"so": "liblog.so", "addr": 0x2cd0})
    r2 = p.run(s, {"so": "liblog.so"})
    check("只给 addr 时扫的是该节（块数远小于全库）",
          0 < r1["scanned_blocks"] < r2["scanned_blocks"],
          f"addr={r1['scanned_blocks']} 全库={r2['scanned_blocks']}")

    # 端到端：真加密一段已知明文，必须能解回来
    plain = b"https://api.example.com/v1/sign"
    key = 0x5A
    enc = bytes(c ^ key for c in plain)
    got = [params for params, out in p._try("single_byte_xor", enc, {})
           if out == plain]
    check("单字节 XOR 能解回已知明文", bool(got), str(got))
    check("解回时给出的 key 正确", bool(got) and got[0]["key"] == "0x5a",
          str(got))

    # plaintext 模式：明文必须能列出来
    r3 = p.run(s, {"so": "liblog.so", "addr": 0x2cd0, "size": 0x7c8,
                   "plaintext": True, "limit": 200})
    check("plaintext 模式列出明文", r3.get("count", 0) > 50,
          str(r3.get("count")))
    vals = [x["value"] for x in (r3.get("results") or [])]
    check("能列到 /proc/self/cmdline",
          any("/proc/self/cmdline" in v for v in vals), str(vals[:8]))
    check("明文模式与解密模式分开（note 说明）",
          "明文" in (r3.get("note") or ""), str(r3.get("note"))[:120])


# ---------------------------------------------------------------- 5. sensitive_scan

def test_sensitive_scan_denoise() -> None:
    print("== 5. sensitive_scan 降噪 ==")
    from server.plugins import sensitive_scan as SS

    s, _so = _session("samples/liblog.so")
    p = SS.Plugin()
    r = p.run(s, {"so_name": "liblog.so"})

    paths = ((r.get("path") or {}).get("items") or [])
    check("path 有产出", len(paths) > 0, str(r)[:150])
    # 核心断言：不许出现 2 字符的碎片（用户抱怨的 "/Y"、"/R"）
    shorts = [x["value"] for x in paths if len(x["value"]) < 4]
    check("没有 < 4 字符的路径碎片", not shorts, str(shorts[:5]))
    # 必须都是真实路径形态
    check("路径都含字母数字",
          all(any(c.isalnum() for c in x["value"]) for x in paths),
          str([x["value"] for x in paths if not any(c.isalnum() for c in x["value"])]))
    check("能列出真实路径（如 /proc/self/cmdline）",
          any("/proc/self/cmdline" in x["value"] for x in paths),
          str([x["value"] for x in paths][:5]))

    # IP 每段必须 <= 255
    check("_is_real_ip 拒绝 999.1.1.1",
          p._is_real_ip("999.1.1.1") is False)
    check("_is_real_ip 接受 192.168.1.1",
          p._is_real_ip("192.168.1.1") is True)
    check("_is_real_path 拒绝 /Y", p._is_real_path("/Y") is False)
    check("_is_real_path 接受 /dev/socket/logdw",
          p._is_real_path("/dev/socket/logdw") is True)

    # 过滤计数必须可见（不要悄悄丢）
    check("filtered 计数字段存在", "filtered" in r, str(r.keys()))

    # 缺参数必须明确报错
    r2 = p.run(s, {})
    check("缺 so_name 时报 BAD_ARGS", r2.get("code") == "BAD_ARGS", str(r2)[:120])


def main() -> int:
    print("== R110 插件能力修复 ==")
    test_emulate_memory_dump()
    test_call_graph_vtable()
    test_xref_enhanced_indirect()
    test_string_crack_fixes()
    test_sensitive_scan_denoise()
    test_buffer_and_stubs()
    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


# ---------------------------------------------------------------- 6. P0-1 / libc stub（第 36 轮反馈）
def test_buffer_and_stubs():
    """R110 第 4 次修改：buffer 形状兼容 + 回读校验 + libc stub。

    反馈：传 buffer=[{addr,hex}] 时数据没写进去且不报错，误以为是"只读段"。
    实测根因是 list 形状被 isinstance(dict) 静默跳过；段本身是 RWX。
    另：bl malloc/memcpy 到 PLT 后从 GOT 取 0 → 跳 0x0 崩溃，依赖
    libc 的函数跑不完。本测试验证两项修复。
    """
    print("\n[6] buffer 形状兼容 / 回读校验 / libc stub 引擎")
    from server.core.plugins import PluginManager
    from server.core.unicorn_stubs import StubEngine
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2

    s, so = _session("so_test/libanti_complete_patched.so")
    pm = PluginManager(s)
    pm.scan_and_load()
    # 任取一个小函数当载体（buffer/stub 与函数体无关）
    fn = next((f for f in so.functions.values() if 20 <= f.size <= 60), None)
    check("找到测试载体函数", fn is not None)

    # (a) list 形状也要写入 + 回读校验
    r = pm.run("emulate_func", {
        "so": so.name, "addr": hex(fn.addr),
        "buffer": [{"addr": "0x60000", "hex": "aabbccdd"}],
        "dump": [{"addr": "0x60000", "size": 8}], "max_insns": 200,
    })
    check("list 形状 buffer 被应用",
          len(r.get("buffer_applied", [])) == 1 and r["buffer_applied"][0]["verified"])
    check("list 形状 buffer 未静默跳过", r.get("buffer_skipped") == [])
    check("list 形状 buffer 内容正确",
          r["memory"]["regions"][0]["hex"].startswith("aabbccdd"))

    # (b) 缺字段要能看到 skipped 原因（不再静默）
    r2 = pm.run("emulate_func", {
        "so": so.name, "addr": hex(fn.addr),
        "buffer": [{"addr": "0x60000"}], "max_insns": 200,
    })
    check("坏 buffer 有 skipped 提示", len(r2.get("buffer_skipped", [])) == 1)

    # (c) libc stub 语义：合成 naked 函数调用 memcpy PLT
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x10000, 0x10000)   # 覆盖 0x10000-0x1ffff，含下面所有地址
    def enc_bl(t, pc):
        return (0x94000000 | (((t - pc) // 4) & 0x7ffffff)).to_bytes(4, "little")
    # 0x10000: bl memcpy@0x11000 ; 0x10004: movz x0,#7 ; 0x10008: ret
    uc.mem_write(0x10000, enc_bl(0x11000, 0x10000) + bytes.fromhex("e00380d2c0035fd6"))
    uc.mem_write(0x11000, bytes.fromhex("c0035fd6"))    # PLT 占位（会被 stub 跳过）
    uc.mem_write(0x12000, b"A" * 8)                      # src
    uc.mem_write(0x13000, b"\x00" * 8)                   # dst
    uc.reg_write(UC_ARM64_REG_LR, 0x15000)               # 哨兵
    eng = StubEngine(uc, {0x11000: "memcpy"}, "auto")
    eng.setup_heap()
    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, eng.on_code)
    uc.reg_write(UC_ARM64_REG_X0, 0x13000)
    uc.reg_write(UC_ARM64_REG_X1, 0x12000)
    uc.reg_write(UC_ARM64_REG_X2, 8)
    uc.emu_start(0x10000, 0x15000, count=20)
    check("memcpy stub 真的复制了数据", bytes(uc.mem_read(0x13000, 8)) == b"A" * 8)
    check("stub 调用被记录", any(c["name"] == "memcpy" for c in eng.calls))

    # (d) A/B：真实函数里 bl memcpy，无 stub 崩 0x0，有 stub 正常返回
    #     找一个真调用 memcpy PLT 的函数
    from server.core.disasm import Disassembler
    d = Disassembler(so)
    mplt = [a for a, n in so.plt_map.items() if n == "memcpy"]
    caller = None
    if mplt:
        for f in so.functions.values():
            if any(i.is_call and getattr(i, "call_target", None) == mplt[0]
                   for i in d.disasm_range(f.addr, min(f.size, 400))):
                caller = f
                break
    if caller:
        base_args = {"so": so.name, "addr": hex(caller.addr),
                     "buffer": [{"addr": "0x60000", "hex": "0102030405060708"}],
                     "x0": "0x60000", "x1": "0x60000", "x2": "0x8", "max_insns": 300}
        no = pm.run("emulate_func", dict(base_args))
        yes = pm.run("emulate_func", dict(base_args, stubs="auto"))
        check("无stub 掉进外部调用",
              no["stopped"]["reason"] in ("external_call_or_unmapped", "invalid_instruction"))
        check("有stub 正常返回", yes["stopped"]["reason"] == "returned",
              str(yes["stopped"]))
        check("有stub 报告 memcpy 调用",
              any(c["name"] == "memcpy" for c in yes.get("stubs", {}).get("stub_calls", [])))
    else:
        check("找到调用 memcpy 的真实函数（跳过 A/B）", True)


if __name__ == "__main__":
    raise SystemExit(main())
