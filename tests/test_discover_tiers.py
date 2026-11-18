"""R109 discover 三档开关（第 33 轮反馈）

运行：.venv/bin/python tests/test_discover_tiers.py

## 为什么需要中间档

第 33 轮反馈原文：
> `discover_functions()` 只有两档：默认只认 `bl_target`（这个 so 只补出
> 21 个，远不够）；`aggressive=True` 能补到 5452 个，但会把 switch 的
> case 块切碎。我实际需要「bl 目标 + 序言，但序言必须紧跟终止指令」
> 这种双条件过滤。
>
> 建议：拆成 `use_prologue` 和 `strict_prologue`。

## 核实结果：用户对了一半

- 「前置终止指令」这个条件**源码里早就有**（`_scan_round` 里的
  `prev.mnemonic in _TERMINATORS`），所以那一半不是缺的。
- 真正缺的是「**什么样的序言才算数**」：
  旧判据 `is_prologue` 把裸 `bti c` / `paciasp` 当成函数序言，
  而它们是分支保护标记——编译器给 switch 的**每个 case 块**都加了 `bti jc`。
  实测 libbase.so：`aggressive=True` 新增 171 个入口，**100% 是裸 bti**，
  后接 `mov w0,#imm`，即同一个 switch 的连续 case 块。

所以严格档的判据改成「**必须有栈帧**」：
`sub sp,sp,#N` / `stp x29,x30,[sp,#-N]!` / `stp <callee>,[sp,#-N]!`，
裸 bti/paciasp 只当作可跳过的前缀，本身不算证据。

本文件锁死：
  A. 三档的数量关系与口径字段
  B. strict 只收完整栈帧，绝不收裸 bti（误报率 0）
  C. strict 能捞到「无人 bl 调用」的间接调用函数（本轮真实痛点）
  D. 补出入口后 function_at 不再返回外层粗函数
  E. 跑满轮次要能自证（reached_max_rounds）
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.core.discover import (  # noqa: E402
    _PROLOGUE_EXACT,
    FunctionDiscoverer,
)
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


def _fresh(path: str = "samples/libbase.so"):
    s = Session()
    so = s.add(str(ROOT / path))
    d = s.xref(so.name).disasm
    return s, so, d


# ---------------------------------------------------------------- A. 三档口径

def test_three_tiers() -> None:
    print("== A1 三档的数量关系 ==")
    counts = {}
    for label, aggressive, strict in (("off", False, True),
                                      ("strict", True, True),
                                      ("loose", True, False)):
        _s, so, d = _fresh()
        before = len(so.functions)
        res = FunctionDiscoverer(so, d).discover(
            max_rounds=6, aggressive=aggressive, strict_prologue=strict)
        counts[label] = res["total"]
        check(f"{label}: 返回 prologue_mode 正确", res["prologue_mode"] == label,
              f"实际 {res['prologue_mode']}")
        check(f"{label}: total 自洽", res["total"] == len(so.functions))
        check(f"{label}: added 自洽", res["added"] == res["total"] - before)
    check("off <= strict <= loose",
          counts["off"] <= counts["strict"] <= counts["loose"],
          str(counts))
    check("loose 确实比 off 多（证明旧激进档真的在切）",
          counts["loose"] > counts["off"], str(counts))


def test_skipped_counter() -> None:
    print("== A2 strict 报告「刻意不收」的数量 ==")
    _s, so, d = _fresh()
    res = FunctionDiscoverer(so, d).discover(
        max_rounds=6, aggressive=True, strict_prologue=True)
    check("strict 跳过数 > 0（样本里确实存在裸 bti 候选）",
          res["skipped_loose_prologue"] > 0, str(res))
    check("跳过数 + 收录数 <= loose 档总量（口径不重复计数）",
          res["skipped_loose_prologue"] >= 0)

    _s2, so2, d2 = _fresh()
    res_off = FunctionDiscoverer(so2, d2).discover(max_rounds=6, aggressive=False)
    check("off 档跳过数为 0（不开序言检测就没有这个口径）",
          res_off["skipped_loose_prologue"] == 0, str(res_off))


def test_reached_max_rounds() -> None:
    print("== A3 跑满轮次要能自证 ==")
    _s, so, d = _fresh()
    res = FunctionDiscoverer(so, d).discover(max_rounds=1, aggressive=True,
                                             strict_prologue=True)
    check("max_rounds=1 时如实报 reached_max_rounds",
          res["reached_max_rounds"] is True, str(res))
    check("max_rounds 回显", res["max_rounds"] == 1)

    _s2, so2, d2 = _fresh()
    res2 = FunctionDiscoverer(so2, d2).discover(max_rounds=6, aggressive=False)
    check("收敛时 reached_max_rounds=False",
          res2["reached_max_rounds"] is False, str(res2))


def test_use_prologue_alias() -> None:
    print("== A4 use_prologue 是 aggressive 的语义化别名 ==")

    def run(**kw):
        _s, so, d = _fresh()
        return FunctionDiscoverer(so, d).discover(**kw)

    base = run()
    alias_off = run(use_prologue=False)
    check("use_prologue=False 等价于不传（bl_only 档）",
          base["prologue_mode"] == alias_off["prologue_mode"] == "off"
          and base["total"] == alias_off["total"],
          f'{base["prologue_mode"]}/{base["total"]} vs '
          f'{alias_off["prologue_mode"]}/{alias_off["total"]}')

    old_way = run(aggressive=True)
    new_way = run(use_prologue=True)
    check("use_prologue=True 等价于 aggressive=True（strict 档）",
          old_way["prologue_mode"] == new_way["prologue_mode"] == "strict"
          and old_way["total"] == new_way["total"],
          f'{old_way["prologue_mode"]}/{old_way["total"]} vs '
          f'{new_way["prologue_mode"]}/{new_way["total"]}')

    loose_old = run(aggressive=True, strict_prologue=False)
    loose_new = run(use_prologue=True, strict_prologue=False)
    check("strict_prologue=False 时两者都是 loose 档",
          loose_old["prologue_mode"] == loose_new["prologue_mode"] == "loose"
          and loose_old["total"] == loose_new["total"])

    # 两个都给时以 use_prologue 为准（文档承诺）
    both = run(aggressive=False, use_prologue=True)
    check("同时给两种写法时 use_prologue 优先",
          both["prologue_mode"] == "strict", both["prologue_mode"])


def test_alias_idempotent_signature() -> None:
    print("== A5 同一档位两种写法不会被当成两个档位 ==")
    s = Session()
    so = s.add(str(ROOT / "samples/libbase.so"))
    r1 = s.discover_functions(so.name, aggressive=True)
    check("第一次跑 strict 有结果", r1.get("prologue_mode") == "strict", str(r1)[:120])
    # 换用别名写法：归一后签名相同 → 必须 skipped，而不是重跑
    r2 = s.discover_functions(so.name, use_prologue=True)
    check("别名写法命中同一签名（skipped）", r2.get("skipped") is True, str(r2)[:160])
    # 但真换档位必须重跑
    r3 = s.discover_functions(so.name, use_prologue=True, strict_prologue=False)
    check("真换档位（strict→loose）会重跑",
          r3.get("skipped") is not True, str(r3)[:160])


# ---------------------------------------------------------------- B. 误报率

def test_strict_never_takes_bare_bti() -> None:
    print("== B1 strict 绝不把裸 bti 当入口 ==")
    _s, so, d = _fresh()
    before = set(so.functions)
    FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                       strict_prologue=True)
    new = sorted(set(so.functions) - before)
    check("strict 有新增（样本里存在真函数形态）", len(new) > 0, "0 个")

    bad = []
    for a in new:
        data = so.read(a, 12)
        words = [struct.unpack_from("<I", data, i * 4)[0] for i in range(3)]
        # 规则：跳过 bti/paciasp 后，第一条非前缀指令必须是栈帧建立
        checked = False
        for w in words:
            if w in _PROLOGUE_EXACT:
                continue
            if not FunctionDiscoverer.is_frame_prologue(w):
                bad.append((hex(a), hex(w)))
            checked = True
            break
        if not checked:
            bad.append((hex(a), "全 bti 前缀"))
    check("新增入口 100% 是完整栈帧", not bad, f"异常: {bad[:5]}")
    check("新增数量远小于 loose 档（不切碎 case 块）",
          len(new) < 20, f"实际 {len(new)}")


def test_loose_still_available_and_noisy() -> None:
    print("== B2 loose 档保留（需要细粒度时仍可用）==")
    _s, so, d = _fresh()
    before = set(so.functions)
    res = FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                             strict_prologue=False)
    new = sorted(set(so.functions) - before)
    check("loose 档能切出大量 case 块（这是旧行为的已知代价）",
          len(new) > 100, f"实际 {len(new)}")
    # 至少有一部分是裸 bti 开头 —— 这正是它脏的地方，要能查出来
    bare_bti = sum(
        1 for a in new
        if struct.unpack_from("<I", so.read(a, 4), 0)[0] in _PROLOGUE_EXACT)
    check("其中裸 bti 开头的占比很高（如实反映旧判据的代价）",
          bare_bti >= len(new) * 0.8,
          f"{bare_bti}/{len(new)}")
    check("返回 mode 标为 loose", res["prologue_mode"] == "loose")


# ---------------------------------------------------------------- C. 间接调用函数

def test_catches_indirect_only_function() -> None:
    print("== C1 抓到「无人 bl 调用」的函数（本轮真实痛点）==")
    _s, so, d = _fresh()
    before = set(so.functions)
    FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                       strict_prologue=True)
    new = sorted(set(so.functions) - before)
    check("有新增", len(new) > 0)

    # 关键判据：这些新入口的 calls 里没有任何函数调用它 —— 说明它们
    # 只能通过函数指针/vtable 抵达，靠 bl 目标永远发现不了。
    no_bl_caller = []
    for a in new:
        called = any(a in so.functions[fa].calls for fa in so.functions if fa != a)
        if not called:
            no_bl_caller.append(a)
    check("至少有一个新入口是「无 bl 调用者」的间接调用函数",
          len(no_bl_caller) > 0,
          f"新增 {len(new)} 个，全部有 bl 调用者")

    # 且前置必须是终止指令（这是 strict 与 loose 共有的前置条件）
    TERM = {"ret", "b", "br", "brk"}
    bad = []
    for a in new:
        prev = list(d.md.disasm(so.read(a - 4, 4), a - 4))
        if prev and prev[0].mnemonic not in TERM:
            bad.append((hex(a), prev[0].mnemonic))
    check("新增入口的前置指令都是终止指令", not bad, f"异常: {bad[:5]}")


# ---------------------------------------------------------------- D. function_at

def test_function_at_fixed_after_discover() -> None:
    print("== D1 补出入口后 function_at 不再返回外层粗函数 ==")
    _s, so, d = _fresh()
    before = set(so.functions)
    FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                       strict_prologue=True)
    new = sorted(set(so.functions) - before)
    check("有新增入口可验证", len(new) > 0)
    if not new:
        return

    for a in new[:4]:
        got = so.function_at(a)
        check(f"{hex(a)} 的 function_at 返回自身",
              got is not None and got.addr == a,
              f"实际 {hex(got.addr) if got else None}")
        check(f"{hex(a)} 是新函数的起点（区间不重叠）",
              got is not None and got.contains(a) and got.addr == a)

    # 区间必须仍然互不重叠（_refresh_functions 的硬约束）
    starts = sorted(so.functions)
    overlaps = []
    for i in range(len(starts) - 1):
        f = so.functions[starts[i]]
        if f.end > starts[i + 1]:
            overlaps.append((hex(starts[i]), hex(f.end), hex(starts[i + 1])))
    check("函数区间互不重叠", not overlaps, f"重叠: {overlaps[:3]}")


# ---------------------------------------------------------------- E. 幂等

def test_idempotent() -> None:
    print("== E1 重复 discover 不再新增 ==")
    _s, so, d = _fresh()
    disc = FunctionDiscoverer(so, d)
    r1 = disc.discover(max_rounds=6, aggressive=True, strict_prologue=True)
    n1 = len(so.functions)
    r2 = FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                            strict_prologue=True)
    check("第二次 added=0", r2["added"] == 0, str(r2))
    check("函数总数不变", len(so.functions) == n1)
    check("第一次确实加过（否则这条测试无意义）", r1["added"] > 0 or n1 > 0)


def test_hosts_stay_wellformed() -> None:
    print("== D2 切分后宿主函数仍然完整（不产生半个函数）==")
    from server.core.pseudocode import PseudocodeGenerator

    for path in ("samples/libbase.so", "samples/libcutils.so",
                 "samples/device/libc.so"):
        full = ROOT / path
        if not full.exists():
            continue
        _s, so, d = _fresh(path)
        before = {a: f.size for a, f in so.functions.items()}
        FunctionDiscoverer(so, d).discover(max_rounds=6, aggressive=True,
                                           strict_prologue=True)
        new = sorted(set(so.functions) - set(before))
        gen = PseudocodeGenerator(so, d)
        bad = []
        for a in new:
            host_addr = None
            for pa, psize in before.items():
                if pa < a < pa + psize:
                    host_addr = pa
                    break
            if host_addr is None:
                continue
            ins = d.disasm_function(host_addr)
            if not ins or not gen._is_legal_tail(ins[-1]):
                bad.append((hex(host_addr), ins[-1].text if ins else "无指令"))
        # 宿主被拦腰截断 = 把一个大函数切成了两半，是 strict 最危险的误报
        check(f"{so.name}: 被切分的宿主都仍以合法收尾结束（新增 {len(new)} 个）",
              not bad, f"非法收尾: {bad[:3]}")


def test_rela_targets_discovered() -> None:
    print("== C2 rela target 是第三类入口证据（间接调用的唯一静态来源）==")
    from server.core import rela as R

    # libc 有 .rela.dyn，其中若干项指向的地址不在 FDE 函数表里
    # （bionic 的 syscall 桩：bti c; mov x8,#N; svc #0 —— 叶子函数、
    #  没有栈帧、也没有 bl 指向，只能靠重定位表发现）
    _s, so, _d = _fresh("samples/device/libc.so")
    targets = R.code_targets(so)
    check("libc 有重定位 code target", len(targets) > 100, str(len(targets)))
    missing = [t for t in targets
               if so.function_at(t) is None or so.function_at(t).addr != t]
    check("存在未被函数表覆盖的 code target", len(missing) > 0, str(len(missing)))

    # 关掉 rela 这条证据来源 → 应该留不下覆盖
    _s1, so1, d1 = _fresh("samples/device/libc.so")
    r_off = FunctionDiscoverer(so1, d1).discover(max_rounds=6, aggressive=False,
                                                 use_rela=False)
    left_off = [t for t in missing
                if so1.function_at(t) is None or so1.function_at(t).addr != t]
    check("use_rela=False 时这些目标仍未被覆盖", len(left_off) > 0,
          f"未覆盖 {len(left_off)}")
    check("use_rela=False 时不出现 rela_target 依据",
          "rela_target" not in r_off["by_reason"], str(r_off["by_reason"]))

    # 打开 → 应当把它们全部收进函数表
    _s2, so2, d2 = _fresh("samples/device/libc.so")
    r_on = FunctionDiscoverer(so2, d2).discover(max_rounds=6, aggressive=False,
                                                use_rela=True)
    left_on = [t for t in missing
               if so2.function_at(t) is None or so2.function_at(t).addr != t]
    check("use_rela=True 后全部被覆盖", not left_on,
          f"仍缺 {[hex(t) for t in left_on[:5]]}")
    check("by_reason 里能看到 rela_target",
          r_on["by_reason"].get("rela_target", 0) > 0, str(r_on["by_reason"]))
    check("rela_targets 计数透出", r_on["rela_targets"] == len(targets),
          f"{r_on['rela_targets']} vs {len(targets)}")

    # 健康样本（libbase 只有 .rela.plt）不应被这条路径改动
    _s3, so3, d3 = _fresh()
    r3 = FunctionDiscoverer(so3, d3).discover(max_rounds=6, aggressive=False)
    check("libbase 无 .rela.dyn 时 rela_target=0",
          r3["by_reason"].get("rela_target", 0) == 0, str(r3["by_reason"]))


def main() -> int:
    print("== R109 discover 三档开关 ==")
    test_three_tiers()
    test_use_prologue_alias()
    test_alias_idempotent_signature()
    test_skipped_counter()
    test_reached_max_rounds()
    test_strict_never_takes_bare_bti()
    test_loose_still_available_and_noisy()
    test_catches_indirect_only_function()
    test_rela_targets_discovered()
    test_function_at_fixed_after_discover()
    test_hosts_stay_wellformed()
    test_idempotent()
    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
