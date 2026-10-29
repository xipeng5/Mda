"""把真实 so 的函数/反汇编导出成 HTML 原型用的数据文件。

用途：给「函数球」界面原型（docs/ui-review/proto/index.html）供真实数据，
避免原型里出现编造的函数名或地址。现在支持多个 so（原型要多 so 面板）。

输出：docs/ui-review/proto/data.js（window.MDA_DATA = {modules:[...]}），
用 <script src> 加载，file:// 直接双击也能打开（fetch 会被 CORS 拦）。

用法（项目内固定路径，不接命令行参数）：
    .venv/bin/python tests/ui_review/dump_sphere_data.py
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.disasm import Disassembler  # noqa: E402
from core.session import Session  # noqa: E402

SO_PATHS = ["so_test/libanti_complete_patched.so", "samples/libbase.so"]
OUT_PATH = "docs/ui-review/proto/data.js"
DISASM_SAMPLES = 120        # 每个模块给代码视图准备的真实反汇编样本数
MAX_INSNS_PER_SAMPLE = 40


def _ref_counts(session: Session, name: str) -> dict[int, int]:
    """构建全量引用图并统计每个函数被调用次数（热度）。

    引用图构建是昂贵操作（N 个函数全量反汇编），失败时退回空表而不是瞎编。
    """
    t0 = time.time()
    try:
        session.ensure_xrefs(name)
        # 注意：Xref.called_by 是 defaultdict 属性（不是方法），直接取 len 即可
        called_by = session.xref(name).called_by
        print(f"[xref] {name} 构建耗时 {time.time() - t0:.1f}s，{len(called_by)} 个函数有调用者")
        return {addr: len(v) for addr, v in called_by.items()}
    except Exception as exc:                      # noqa: BLE001 - 原型脚本，缺数据就退化为无热度
        print(f"[xref] {name} 构建失败（{type(exc).__name__}: {exc}），热度退化为 0")
        return {}


def _build_module(session: Session, path: str) -> dict:
    so = session.add(path)
    print(f"[load] {so.name}: 函数 {len(so.functions)}，导出 {len(so.exports)}")

    refs = _ref_counts(session, so.name)
    disasm = Disassembler(so)

    funcs = []
    for fn in sorted(so.functions.values(), key=lambda f: f.addr):
        funcs.append({
            "n": fn.name or f"sub_{fn.addr:x}",
            "a": fn.addr,
            "s": fn.size,
            "e": 1 if fn.is_export else 0,
            "r": refs.get(fn.addr, 0),
        })

    # 反汇编样本：优先取被引用最多的函数，保证代码视图一打开就有内容
    ranked = sorted(so.functions.values(), key=lambda f: (-refs.get(f.addr, 0), f.addr))
    samples = {}
    for fn in ranked[:DISASM_SAMPLES]:
        rows = []
        for ins in disasm.disasm_function(fn.addr)[:MAX_INSNS_PER_SAMPLE]:
            rows.append({
                "a": ins.addr,
                "b": bytes(ins.bytes).hex(),
                "t": (ins.mnemonic + (" " + ins.op_str if ins.op_str else "")).strip(),
                "c": 1 if ins.is_call else 0,
                "r": 1 if ins.is_ret else 0,
            })
        if rows:
            samples[str(fn.addr)] = rows
    print(f"[disasm] {so.name} 样本函数 {len(samples)} 个")

    # 调用关系边（供球上画关系线）：每个函数最多保留 8 个调用者/被调者，控制文件体积
    called_by = session.xref(so.name).called_by or {}
    callers: dict[str, list[int]] = {}
    callees: dict[str, list[int]] = {}
    for addr, srcs in called_by.items():
        uniq = sorted(set(srcs))[:8]
        if not uniq:
            continue
        callers[str(addr)] = uniq
        for src in uniq:
            callees.setdefault(str(src), []).append(int(addr))
    print(f"[edges] {so.name}: {sum(len(v) for v in callers.values())} 条调用边")

    return {
        "so": so.name,
        "path": path,
        "size": os.path.getsize(path),
        "sections": [{"n": s.name, "a": s.addr, "s": s.size} for s in so.sections],
        "funcs": funcs,
        "disasm": samples,
        "callers": callers,
        "callees": callees,
    }


def main() -> int:
    session = Session()
    modules = [_build_module(session, p) for p in SO_PATHS]
    payload = {"modules": modules}

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write("// 由 tests/ui_review/dump_sphere_data.py 生成，数据来自真实 so，勿手改\n")
        fh.write("window.MDA_DATA = ")
        json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write(";\n")
    print(f"[out] {OUT_PATH}  {os.path.getsize(OUT_PATH) / 1024:.0f} KB，模块 {len(modules)} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
