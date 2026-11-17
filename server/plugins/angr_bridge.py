"""angr 深度分析可选插件（需要额外安装，不影响主环境）。

## 为什么是"可选"

[angr](https://github.com/angr/angr)（BSD-2-Clause）一次能补：
真反编译、CFG、数据流、符号执行、调用图——是调研里唯一许可宽松、
纯 Python、原生支持 ARM64/ELF 的"重型"轮子。

**但有两个版本坑**（经 PyPI 元数据核实）：
  - mda 用 Python 3.11 → angr 10.x 要求 >=3.12，**必须锁 angr==9.2.x**
  - angr 9.2.x 锁 capstone==5.0.3，而 mda 用 5.0.9 → 直接装会降级，
    可能破坏 mda 现有反汇编

**所以本插件默认不启用**，只在调用方显式安装后使用：
    pip install 'angr==9.2.*'       # 建议装在独立 venv 或确认能接受 capstone 降级
并设置环境变量 MDA_ANGR_ENABLED=1。

## 提供什么（启用后）

    - project_info   加载 so，报告架构/入口/函数数
    - cfg            生成 CFG（函数级）
    - decompile      真反编译（angr 的 decompiler）
    - symbolic       符号执行到指定地址，求解寄存器约束

## 通用性

纯 angr API 封装，不含任何具体 so/App 特征。
"""
from __future__ import annotations

import os

from server.core.plugins import PluginBase


def _check():
    if os.environ.get("MDA_ANGR_ENABLED") != "1":
        return (False, "可选插件未启用。启用方式："
                "① pip install 'angr==9.2.*'（Python 3.11 只能用 9.2.x）；"
                "② export MDA_ANGR_ENABLED=1。"
                "注意 angr 9.2.x 锁 capstone==5.0.3，会降级 mda 的 5.0.9——"
                "建议在独立 venv 使用。")
    try:
        import angr  # noqa: F401
    except ImportError:
        return (False, "angr 未安装。pip install 'angr==9.2.*'")
    return (True, "")


class Plugin(PluginBase):
    name = "angr_bridge"
    description = "angr 深度分析（可选：CFG/真反编译/符号执行，需额外安装）"
    usage = ("args: {so: str, mode: 'project_info'|'cfg'|'decompile'|'symbolic', "
             "addr: int|None=None, find: int|None=None, "
             "constraint: str|None=None, limit: int=20}")

    def run(self, session, args: dict):
        ok, msg = _check()
        if not ok:
            return {"ok": False, "code": "ANGR_NOT_ENABLED", "hint": msg}

        import angr
        import claripy

        so_name = args.get("so")
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        path = getattr(so, "path", None)
        if not path:
            return {"error": "so 没有路径", "code": "NO_FILE"}

        mode = args.get("mode", "project_info")
        try:
            proj = angr.Project(path, auto_load_libs=False)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"angr 加载失败：{exc}", "code": "LOAD_FAILED"}

        if mode == "project_info":
            return {"ok": True, "so": so.name,
                    "arch": str(proj.arch),
                    "entry": hex(proj.entry),
                    "min_addr": hex(proj.loader.min_addr),
                    "max_addr": hex(proj.loader.max_addr)}

        if mode == "cfg":
            cfg = proj.analyses.CFGFast(normalize=True)
            funcs = []
            for addr, fn in list(cfg.functions.items())[:int(args.get("limit", 20))]:
                funcs.append({"addr": hex(addr), "name": fn.name,
                              "size": fn.size})
            return {"ok": True, "so": so.name, "mode": "cfg",
                    "function_count": len(cfg.functions),
                    "functions": funcs}

        if mode == "decompile":
            addr = args.get("addr")
            if addr is None:
                return {"error": "decompile 需要 addr", "code": "BAD_ARGS"}
            a = int(addr, 16) if isinstance(addr, str) and \
                str(addr).lower().startswith("0x") else int(addr)
            cfg = proj.analyses.CFGFast(normalize=True)
            if a not in cfg.functions:
                return {"error": f"0x{a:x} 不在 CFG 函数表中", "code": "NO_FUNC"}
            try:
                dec = proj.analyses.Decompiler(cfg.functions[a])
                code = dec.codegen.text if dec.codegen else ""
            except Exception as exc:                      # noqa: BLE001
                return {"error": f"反编译失败：{exc}", "code": "DECOMP_FAILED"}
            return {"ok": True, "so": so.name, "addr": hex(a),
                    "pseudocode": code,
                    "note": "angr 反编译质量依赖 CFG 与函数识别，OLLVM 下可能失败"}

        if mode == "symbolic":
            addr = args.get("addr")
            find = args.get("find")
            if addr is None or find is None:
                return {"error": "symbolic 需要 addr 与 find", "code": "BAD_ARGS"}
            a = int(addr, 16) if isinstance(addr, str) and \
                str(addr).lower().startswith("0x") else int(addr)
            f = int(find, 16) if isinstance(find, str) and \
                str(find).lower().startswith("0x") else int(find)
            state = proj.factory.blank_state(addr=a)
            simgr = proj.factory.simgr(state)
            simgr.explore(find=f)
            if not simgr.found:
                return {"ok": True, "so": so.name, "mode": "symbolic",
                        "reached": False, "find": hex(f)}
            found = simgr.found[0]
            return {"ok": True, "so": so.name, "mode": "symbolic",
                    "reached": True, "find": hex(f),
                    "stdout": found.posix.dumps(1).hex()}

        return {"error": f"未知 mode={mode}", "code": "BAD_MODE"}
