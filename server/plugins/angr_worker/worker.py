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
        # (1) 第一次修改（2026-11-18）
        #     bug 原因：原 symbolic 模式只做 blank_state→explore→返回 reached:bool，
        #               无符号变量注入、无具体参数、无约束求解，无法"解出 x19"。
        #     解决方案：注入 concrete 具体寄存器、symbolic 符号寄存器（按位宽建 BVS），
        #               explore 加 depth_limit/avoid，到 find 后读输出、加约束求解，
        #               用 solver.eval 解出符号变量值；失败如实返回 reason，不编造。
        #               保留 reached 字段兼容旧调用方；不做全 so CFG（cfg 模式已超时）。
        entry = task.get("addr", 0)
        find = task.get("find")
        if find is None:
            print(json.dumps({"ok": False, "code": "BAD_ARGS",
                              "error": "symbolic 模式需要 find 地址"}))
            return 0
        try:
            import claripy
        except ImportError as exc:
            print(json.dumps({"ok": False, "code": "CLARIPY_NOT_INSTALLED",
                              "error": str(exc)}))
            return 1

        state = proj.factory.blank_state(addr=entry + base)

        # 具体寄存器：state.regs.x0 = 0x...
        for reg, val in (task.get("concrete") or {}).items():
            try:
                num = int(str(val), 16) if isinstance(val, str) and \
                    str(val).lower().startswith("0x") else int(val)
                setattr(state.regs, str(reg).lower(), num)
            except (ValueError, AttributeError):
                pass

        # 符号寄存器：claripy.BVS('x19', 32/64)，按 symbolic_32/symbolic_64 定位宽
        sym_vars: dict = {}
        for reg, spec in (task.get("symbolic") or {}).items():
            spec_s = str(spec).lower()
            bits = 32 if "32" in spec_s else 64
            var = claripy.BVS(str(reg).lower(), bits)
            sym_vars[str(reg).lower()] = var
            setattr(state.regs, str(reg).lower(), var)

        simgr = proj.factory.simgr(state)
        max_depth = int(task.get("max_depth") or 60)
        avoid = task.get("avoid")
        explore_kw = {"find": find + base, "depth_limit": max_depth}
        if avoid is not None:
            av = (int(str(avoid), 16)
                  if isinstance(avoid, str) and str(avoid).lower().startswith("0x")
                  else int(avoid))
            explore_kw["avoid"] = av + base
        try:
            simgr.explore(**explore_kw)
        except Exception as exc:                          # noqa: BLE001
            print(json.dumps({"ok": True, "reached": False, "solved": None,
                              "reason": f"explore 异常：{type(exc).__name__}: {exc}",
                              "find": hex(find)}))
            return 0

        reached = bool(simgr.found)
        if not reached:
            print(json.dumps({"ok": True, "reached": False, "solved": None,
                              "reason": "explore 未到达 find（深度上限/路径不可达）",
                              "find": hex(find)}))
            return 0

        found_state = simgr.found[0]
        constraint = task.get("constraint")
        constraint_satisfied = False
        solved: dict = {}
        try:
            if constraint:
                # 约定：output==0x... 从 regs.x0 读；xN==0x... 从对应寄存器读
                lhs, rhs = str(constraint).split("==", 1)
                lhs, rhs = lhs.strip().lower(), rhs.strip()
                num = (int(rhs, 16) if rhs.lower().startswith("0x")
                       else int(rhs))
                out_expr = (found_state.regs.x0 if lhs == "output"
                            else getattr(found_state.regs, lhs))
                found_state.solver.add(out_expr == num)
            constraint_satisfied = bool(found_state.solver.satisfiable())
            if constraint_satisfied and sym_vars:
                for reg, var in sym_vars.items():
                    solved[reg] = hex(found_state.solver.eval(var))
        except Exception as exc:                          # noqa: BLE001
            print(json.dumps({"ok": True, "reached": True, "solved": None,
                              "constraint_satisfied": False,
                              "reason": f"求解失败：{type(exc).__name__}: {exc}",
                              "find": hex(find)}))
            return 0

        if constraint and not constraint_satisfied:
            print(json.dumps({"ok": True, "reached": True, "solved": None,
                              "constraint_satisfied": False,
                              "reason": "约束不可满足", "find": hex(find)}))
            return 0

        print(json.dumps({
            "ok": True, "reached": True,
            "solved": solved if sym_vars else None,
            "constraint_satisfied": constraint_satisfied if constraint else None,
            "find": hex(find),
        }))
        return 0

    print(json.dumps({"ok": False, "code": "BAD_MODE",
                      "error": mode}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
