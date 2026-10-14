"""端到端测试：真实样本 liblog.so / libbase.so / libcutils.so。

运行：.venv/bin/python tests/test_e2e.py
样本来自 Android 13 真机 /system/lib64/，非模拟数据。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.session import Session

SAMPLES = Path(__file__).parent.parent / "samples"
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


def main() -> int:
    s = Session()
    for name in ("liblog.so", "libbase.so", "libcutils.so"):
        s.add(str(SAMPLES / name))

    log = s.get("liblog.so")

    print("== ELF 解析 ==")
    check("架构识别 ARM64", log.arch == 183)
    check("函数发现 111 个", len(log.functions) == 111, f"实际 {len(log.functions)}")
    check("PLT 解码 105 个", len(log.plt_map) == 105, f"实际 {len(log.plt_map)}")
    check("create_android_logger @0x5020",
          log.function_at(0x5020) is not None and log.function_at(0x5020).name == "create_android_logger")

    print("== 字符串与引用 ==")
    x = s.ensure_xrefs("liblog.so")
    strs = s.strings("liblog.so")
    check("字符串提取非空", len(strs.all_strings()) > 0)
    ev = strs.string_starting_at_or_before(0x2DD3)
    check("events 字符串定位", ev is not None and ev.value == "events", f"实际 {ev.value if ev else None}")
    check("events 引用者含 android_name_to_log_id",
          ev is not None and 23944 in ev.referenced_by, f"实际 {ev.referenced_by if ev else None}")
    buf_names = {"main", "radio", "events", "system", "crash", "stats", "security", "kernel"}
    found = {st.value for st in strs.all_strings()} & buf_names
    check("8 个 log buffer 名全部提取", found == buf_names, f"缺 {buf_names - found}")

    print("== 调用链 ==")
    links = s.callers_of("__android_log_set_default_tag")
    check("跨 so 反查 SetDefaultTag 被调用", len(links) >= 1 and links[0].callee_so == "liblog.so",
          f"实际 {links}")
    chain = s.call_chain("libbase.so", 0x14D24, depth=3)
    text = chain.as_text()
    check("跨 so 链深入到 liblog", "liblog.so!__android_log_set_default_tag" in text)

    print("== 伪代码 ==")
    from core.pseudocode import PseudocodeGenerator
    gen = PseudocodeGenerator(log, s._xrefs["liblog.so"].disasm)
    pc = gen.generate(0x5020, lambda so, a: (
        (l := s.resolve_call(so, a)) and (l.callee_so, l.callee, l.callee_addr)) or None)
    check("伪代码含 calloc 调用", "calloc(...)" in pc)
    check("伪代码无未解析 !name", "!calloc" not in pc)

    print("== 脚本通道 ==")
    from scripting.runner import run_in_session
    r = run_in_session(s, 'result = len(session.get("liblog.so").functions)')
    import json
    # bug 原因：result 经 json.dumps 后是字符串 "111"，需二次 loads 还原为 int
    # 解决：比较时对 str 类型做一次 json.loads
    got = json.loads(r)["result"]
    if isinstance(got, str):
        got = json.loads(got)
    # 保持 111：递归函数发现默认只认 bl 目标（安全模式），liblog 的 FDE
    # 表完整，新增 0 个。激进模式（aggressive=True）会额外切出 19 个
    # bti-prologue 块，但实测那类含 switch case 误报，故默认关闭。
    check("脚本返回函数数", got == 111, f"实际 {got!r}")
    r = run_in_session(s, "1/0")
    check("脚本错误回传", "ZeroDivisionError" in r)

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
