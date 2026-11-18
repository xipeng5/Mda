"""angr 分析 worker —— 在独立 Python 环境里运行。

## 为什么需要独立进程

angr 的 Rust 扩展（rustylib.abi3.so）是**按 Python 版本编译**的：
mda 用 3.11，而 angr 10.x 只提供 3.12 wheel（3.11 只能装 9.2.x，
但 9.2.x 会降级 capstone 到 5.0.3，破坏 mda 现有反汇编）。

所以不能在同一进程内 import angr。本 worker 由 mda 用
**独立 venv 的 python 解释器**以子进程方式启动，
stdin 收 JSON 任务、stdout 回 JSON 结果。

## 通用性

纯 angr API 封装 + JSON 协议，不含任何具体 so/函数特征。
"""
import json
import sys


def main():
    raw = sys.stdin.read()
    try:
        task = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        print(json.dumps({"ok": False, "code": "BAD_JSON",
                          "error": str(exc)}))
        return 1

    mode = task.get("mode", "project_info")
    path = task.get("path")
    if not path:
        print(json.dumps({"ok": False, "code": "NO_PATH"}))
        return 1

    try:
        import angr
    except ImportError as exc:
        print(json.dumps({"ok": False, "code": "ANGR_NOT_INSTALLED",
                          "error": str(exc)}))
        return 1

    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as exc:                              # noqa: BLE001
        print(json.dumps({"ok": False, "code": "LOAD_FAILED",
                          "error": f"{type(exc).__name__}: {exc}"}))
        return 1

    base = int(proj.loader.main_object.mapped_base)

    if mode == "project_info":
        print(json.dumps({"ok": True, "arch": str(proj.arch),
                          "entry": hex(proj.entry),
                          "angr_base": hex(base),
                          "angr_version": angr.__version__}))
        return 0

    if mode == "cfg":
        cfg = proj.analyses.CFGFast(normalize=True)
        limit = int(task.get("limit", 50))
        funcs = []
        for addr, fn in list(cfg.functions.items())[:limit]:
            funcs.append({"addr": hex(addr - base), "name": fn.name,
                          "size": fn.size})
        print(json.dumps({"ok": True, "function_count": len(cfg.functions),
                          "functions": funcs, "angr_base": hex(base)}))
        return 0

    if mode == "decompile":
        want = task.get("addr", 0)
        cfg = proj.analyses.CFGFast(normalize=True)
        fn = cfg.functions.get(want + base) or cfg.functions.get(want)
        if fn is None:
            cands = [f for ad, f in cfg.functions.items() if ad <= want + base]
            if cands:
                fn = max(cands, key=lambda f: f.addr)
        if fn is None:
            print(json.dumps({"ok": False, "code": "NO_FUNC",
                              "error": f"0x{want:x} 不在 CFG 函数表"}))
            return 0
        try:
            dec = proj.analyses.Decompiler(fn)
            code = dec.codegen.text if dec.codegen else ""
        except Exception as exc:                          # noqa: BLE001
            print(json.dumps({"ok": False, "code": "DECOMP_FAILED",
                              "error": f"{type(exc).__name__}: {exc}"}))
            return 0
        print(json.dumps({"ok": True, "addr": hex(fn.addr - base),
                          "function": fn.name, "size": fn.size,
                          "pseudocode": code}))
        return 0

    if mode == "symbolic":
        entry = task.get("addr", 0)
        find = task.get("find")
        if find is None:
            print(json.dumps({"ok": False, "code": "BAD_ARGS"}))
            return 0
        state = proj.factory.blank_state(addr=entry + base)
        simgr = proj.factory.simgr(state)
        simgr.explore(find=find + base)
        reached = bool(simgr.found)
        print(json.dumps({"ok": True, "reached": reached,
                          "find": hex(find)}))
        return 0

    print(json.dumps({"ok": False, "code": "BAD_MODE",
                      "error": mode}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
