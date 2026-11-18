"""R108 伪代码源地址注释 + 覆盖统计 + 截断检测（第 33 轮反馈）

运行：.venv/bin/python tests/test_pseudocode_addr.py

## 这些测试为什么必须存在

2026-11-18 的实战反馈里，最卡人的一条是：**扁平化状态机的 26 个分支
全部 `b.ne` 回同一个分发器**，伪代码里 26 行文本一模一样，无法对回
源指令，只能回字节码一条条数。

第二条更隐蔽：使用者发现「真实 17 个 bl，伪代码只显示 16 个」，以为
是渲染层吞了指令。**真实原因是 `disasm_function` 只解码 `fn.size`
字节，而 FDE 给的 size 被截短了**——那条 `bl __stack_chk_fail` 根本
没进入解码范围。渲染层无法自证，使用者也无法区分"工具吞了"和"范围
不够"，整条分析线就此卡住。

所以本文件锁死三件事：
  A. 每行都有 `// 0x地址`（可对回字节码）
  B. 头部有覆盖统计（把"框架指令被省略"与"没解码到"分成两个数）
  C. 末条不是合法收尾时**必须**告警，且告警率在正常样本上接近 0
     （初版判据有 43%~70% 假警报，一旦成噪音，真截断那次就没人看了）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.core.pseudocode import PseudocodeGenerator  # noqa: E402
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


SAMPLES = {
    "liblog.so": "samples/liblog.so",
    "libbase.so": "samples/libbase.so",
    "libcutils.so": "samples/libcutils.so",
}
ROOT = Path(__file__).parent.parent


def _gen(path: str):
    """建一个临时会话并返回 (so, 伪代码生成器)。"""
    s = Session()
    so = s.add(str(ROOT / path))
    d = s.xref(so.name).disasm
    return s, so, PseudocodeGenerator(so, d)


# ---------------------------------------------------------------- A. 源地址注释

def test_addr_comment_on_every_line() -> None:
    print("== A1 每行带源地址注释 ==")
    _s, so, gen = _gen(SAMPLES["liblog.so"])
    out = gen.generate(0x5020)          # create_android_logger
    lines = out.splitlines()

    body = [ln for ln in lines if ln.startswith("    ")]
    check("函数体非空", len(body) > 5, f"实际 {len(body)}")
    check("每个函数体行都以 `// 0x` 开头",
          all(ln.strip().startswith("// 0x") for ln in body),
          f"异常行: {[ln for ln in body if not ln.strip().startswith('// 0x')][:2]}")

    # 地址必须落在函数区间内，且是 4 字节对齐
    addrs = [int(ln.strip().split()[1], 16) for ln in body]
    check("所有地址 4 字节对齐", all(a % 4 == 0 for a in addrs))
    check("所有地址落在函数区间内",
          all(so.function_at(0x5020).addr <= a < so.function_at(0x5020).end
              for a in addrs),
          f"越界: {[hex(a) for a in addrs if not so.function_at(0x5020).addr <= a < so.function_at(0x5020).end][:3]}")
    check("地址严格递增", addrs == sorted(addrs) and len(set(addrs)) == len(addrs))

    # 同一地址必须能在反汇编里找到对应的原始指令
    ins_by_addr = {i.addr: i for i in so.function_at(0x5020).instructions}
    check("地址能回查原始指令", all(a in ins_by_addr for a in addrs))


def test_addr_off_is_backward_compatible() -> None:
    print("== A2 with_addr=False 退回旧格式 ==")
    _s, _so, gen = _gen(SAMPLES["liblog.so"])
    out = gen.generate(0x5020, with_addr=False)
    check("关闭后不出现地址注释", "// 0x" not in out.split("void ")[1])
    check("关闭后仍有调用名", "calloc(...)" in out)


def test_same_text_lines_are_distinguishable() -> None:
    print("== A3 相同文本的分支可区分（本轮核心痛点）==")
    _s, so, gen = _gen(SAMPLES["libbase.so"])
    d = gen.disasm
    # 找一个「同一 b.* 目标出现多次」的函数——这就是扁平化状态机的形态
    best = None
    for a in list(so.functions)[:200]:
        try:
            insns = d.disasm_function(a)
        except Exception:                                  # noqa: BLE001
            continue
        jumps = [i for i in insns if i.mnemonic.startswith("b.") and i.call_target]
        targets = [i.call_target for i in jumps]
        dup = {t for t in targets if targets.count(t) >= 3}
        if dup and (best is None or len(jumps) > best[1]):
            best = (a, len(jumps), dup)
    check("样本里找到扁平化分支形态", best is not None, "200 个函数内没找到重复跳转目标")
    if best is None:
        return
    fn_addr, _n, dup = best
    out = gen.generate(fn_addr)
    body = [ln for ln in out.splitlines() if ln.startswith("    ")]
    # 同一目标地址的行，其「源地址前缀」必须互不相同
    tgt = hex(next(iter(dup)))
    same_target = [ln for ln in body if tgt in ln]
    check(f"同一跳转目标 {tgt} 出现多次", len(same_target) >= 3, f"实际 {len(same_target)}")
    prefixes = [ln.strip().split()[1] for ln in same_target]
    check("这些行的源地址前缀互不相同（可区分）",
          len(set(prefixes)) == len(prefixes),
          f"重复前缀: {[p for p in prefixes if prefixes.count(p) > 1][:3]}")


# ---------------------------------------------------------------- B. 覆盖统计

def test_coverage_stats() -> None:
    print("== B1 头部覆盖统计 ==")
    _s, so, gen = _gen(SAMPLES["liblog.so"])
    out = gen.generate(0x5020)
    head = out.splitlines()[1]
    check("含 insns 计数", "insns" in head, head)
    check("含 bl 计数", " bl," in head, head)
    check("含 shown 计数", "shown" in head, head)
    check("含 skipped 计数", "skipped" in head, head)

    fn = so.function_at(0x5020)
    real_bl = sum(1 for i in fn.instructions if i.is_call and i.call_target is not None)
    # 声明值必须等于真实值——否则这个统计自己就不可信
    check("声明的 bl 数等于真实 bl 数", f"{real_bl} bl" in head, f"真实 {real_bl}, 头: {head}")

    # 关键：伪代码里实际出现的 bl 行数 == 声明的 bl 数（一条都不能丢）
    body = [ln for ln in out.splitlines() if ln.startswith("    ")]
    shown_bl = sum(1 for ln in body if "bl " in ln or "(...);" in ln)
    check("伪代码里出现的调用行数 >= 声明的 bl 数",
          shown_bl >= real_bl, f"显示 {shown_bl} < 声明 {real_bl}")


def test_skipped_only_frame() -> None:
    print("== B2 skipped 只统计无语义框架指令 ==")
    _s, so, gen = _gen(SAMPLES["libbase.so"])
    skipped_kinds = {"stp", "ldp", "mov", "paciasp", "autiasp", "bti", "nop"}
    bad = []
    for a in list(so.functions)[:120]:
        insns = gen.disasm.disasm_function(a)
        for ins in insns:
            if gen._render(ins, None) is None and ins.mnemonic not in skipped_kinds:
                bad.append((hex(ins.addr), ins.mnemonic))
    check("被跳过的指令只有框架类", not bad, f"异常: {bad[:5]}")
    check("bl 永远不会被跳过",
          not any(m == "bl" for _a, m in bad))


# ---------------------------------------------------------------- C. 截断检测

def test_no_false_alarm_on_healthy_samples() -> None:
    print("== C1 正常样本上零假警报 ==")
    for name, path in SAMPLES.items():
        _s, so, gen = _gen(path)
        total = warn = 0
        for a in list(so.functions):
            insns = gen.disasm.disasm_function(a)
            if not insns:
                continue
            total += 1
            if not gen._is_legal_tail(insns[-1]):
                warn += 1
        # 初版判据在这里是 43%~70%，必须压到 0
        check(f"{name} 无假警报（{total} 个函数）", warn == 0, f"实际 {warn} 个")


def test_truncation_is_detected() -> None:
    print("== C2 真截断必须告警（人为缩短 size）==")
    _s, so, gen = _gen(SAMPLES["liblog.so"])
    fn = so.function_at(0x5020)
    real_size = fn.size
    real_insns = fn.instructions
    try:
        fn.size = 0x40          # 0x50 → 0x40，末条落在 stp 上，不在收尾
        fn.instructions = []
        out = gen.generate(0x5020)
        check("截短后出现 WARNING", "WARNING" in out, out.splitlines()[:3])
        check("WARNING 指出了末条地址", "0x505c" in out, out.splitlines()[:3])
        check("WARNING 给出下一步工具", "disassemble" in out or "export_disasm" in out)
    finally:
        fn.size = real_size
        fn.instructions = real_insns


def test_legal_tail_rules() -> None:
    print("== C3 收尾判定的四种证据 ==")
    _s, so, gen = _gen(SAMPLES["liblog.so"])

    # ③ 末条 bl 且下一条正好是函数入口 → 合法（libcutils 0xe57c 的形态）
    cand = None
    for a in list(so.functions):
        insns = gen.disasm.disasm_function(a)
        if not insns:
            continue
        t = insns[-1]
        if t.mnemonic == "bl" and so.functions.get(t.addr + t.size) is not None:
            cand = (a, t)
            break
    if cand is not None:
        check("判据③：bl 后紧邻函数入口 → 判为合法收尾",
              gen._is_legal_tail(cand[1]), f"{hex(cand[0])} {cand[1].text}")
    else:
        check("判据③：样本里能找到该形态", False, "liblog 里未找到，改用别样本")

    # ② noreturn 名单
    found_noreturn = False
    for a in list(so.functions):
        insns = gen.disasm.disasm_function(a)
        if not insns:
            continue
        t = insns[-1]
        if t.mnemonic == "bl" and gen._is_legal_tail(t) and "ret" not in t.text:
            nm = so.plt_name(t.call_target) or ""
            if "__stack_chk_fail" in nm or "abort" in nm or "__throw_" in nm:
                found_noreturn = True
                break
    check("判据②：noreturn 调用被认作合法收尾", found_noreturn)


# ---------------------------------------------------------------- D. .start 别名

def test_function_start_alias() -> None:
    print("== D1 Function.start 是 addr 的只读别名 ==")
    _s, so, _gen_ = _gen(SAMPLES["liblog.so"])
    fn = so.function_at(0x5020)
    check(".start 存在且等于 .addr", fn.start == fn.addr == 0x5020)
    check(".end 仍等于 addr+size", fn.end == fn.addr + fn.size)
    check(".start 不在 dataclass 字段里（不会破坏序列化）",
          "start" not in fn.__dataclass_fields__)
    try:
        fn.start = 0x1234
        check(".start 不可写", False, "竟然赋值成功了")
    except AttributeError:
        check(".start 不可写", True)


def main() -> int:
    print("== R108 伪代码源地址 + 覆盖统计 + 截断检测 ==")
    test_addr_comment_on_every_line()
    test_addr_off_is_backward_compatible()
    test_same_text_lines_are_distinguishable()
    test_coverage_stats()
    test_skipped_only_frame()
    test_no_false_alarm_on_healthy_samples()
    test_truncation_is_detected()
    test_legal_tail_rules()
    test_function_start_alias()
    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
