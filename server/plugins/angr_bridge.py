"""angr 深度分析（子进程桥接，通用能力）。

## 为什么用子进程而不是直接 import

angr 的 Rust 扩展（`rustylib.abi3.so`）**按 Python 版本编译**：
  · mda 用 Python 3.11
  · angr 10.x 只提供 3.12 的 wheel
  · angr 9.2.x 虽支持 3.11，但会把 capstone 降到 5.0.3，
    破坏 mda 现有反汇编（mda 用 5.0.9）

实测：把 3.12 的 angr 加进 3.11 的 PYTHONPATH 会
`ImportError: dlopen(...rustylib.abi3.so)`。

所以本插件**不 import angr**，而是用探测到的独立 Python 解释器
启动 `angr_runner/worker.py` 子进程，通过 stdin/stdout 传 JSON。

## 检测顺序

1. 环境变量 `MDA_ANGR_PYTHON`（显式指定解释器路径）
2. 常见位置探测（/tmp/angr_venv、~/.angr-venv 等）
3. 都找不到 → 返回 `ANGR_NOT_FOUND` 并给出安装命令

## 提供的能力

    project_info   架构/入口/基址
    cfg            函数级 CFG（函数数通常比 mda 多，因为 angr 做递归下降）
    decompile      **真反编译**（会推断结构体与局部变量类型）
    symbolic      探索性符号执行（到指定地址）

## 通用性

纯 angr API 封装 + 子进程协议，不含任何具体 so/函数特征。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from server.core.addr import parse_addr
from server.core.plugins import PluginBase

_WORKER = Path(__file__).resolve().parent / "angr_worker" / "worker.py"

# 常见候选位置（按优先级）
_CANDIDATES = [
    "/tmp/angr_venv/bin/python",
    str(Path.home() / ".angr-venv" / "bin" / "python"),
    str(Path.home() / "angr_venv" / "bin" / "python"),
    "/opt/homebrew/bin/python3.12",
    "/usr/local/bin/python3.12",
]

# 模块级缓存：按 MDA_ANGR_PYTHON 值缓存已验证可用的 (解释器路径, 说明)
_PYTHON_CACHE: dict[str, tuple[str, str]] = {}


def _probe_angr_python(py_path: str) -> str | None:
    """校验给定解释器是否可导入 angr，成功返回版本号，否则返回 None。"""
    if not py_path or not os.path.isfile(py_path):
        return None
    try:
        r = subprocess.run([py_path, "-c", "import angr;print(angr.__version__)"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return r.stdout.strip() or "unknown"
    except Exception:                                     # noqa: BLE001
        return None
    return None


# (2) 第二次修改（2026-11-26）
# bug 原因：1) MDA_ANGR_PYTHON 仅判断文件存在，未校验能否 import angr；
#           2) 每次调用都反复起子进程探测候选解释器，造成额外开销。
# 解决方案：统一通过 _probe_angr_python 校验 MDA_ANGR_PYTHON 与候选路径，
#           并对已找到的解释器做模块级缓存。
def _find_python() -> tuple[str | None, str]:
    """找一个装了 angr 的解释器。返回 (路径, 说明)。"""
    env = os.environ.get("MDA_ANGR_PYTHON") or ""
    cached = _PYTHON_CACHE.get(env)
    if cached and os.path.isfile(cached[0]):
        return cached

    if env:
        ver = _probe_angr_python(env)
        if ver is not None:
            res = (env, f"来自 MDA_ANGR_PYTHON（angr {ver}）")
            _PYTHON_CACHE[env] = res
            return res

    for cand in _CANDIDATES:
        ver = _probe_angr_python(cand)
        if ver is not None:
            res = (cand, f"自动探测（angr {ver}）")
            _PYTHON_CACHE[env] = res
            return res
    return None, ""


class Plugin(PluginBase):
    name = "angr_bridge"
    description = "angr 深度分析：真反编译/CFG/符号执行（子进程桥接独立 Python）"
    usage = (
        "args: {so: str, mode: 'project_info'|'cfg'|'decompile'|'symbolic', "
        "addr: int|None=None, find: int|None=None, limit: int=50, "
        "symbolic: dict={'x19':'symbolic_32'} ——符号寄存器及位宽, "
        "concrete: dict={'x0':'0x1234'} ——具体寄存器值, "
        "constraint: str='output==0x...' 或 'x0==0x...' ——求解约束, "
        "max_depth: int=60 ——符号执行深度上限, "
        "avoid: int|None=None ——避免到达的地址}"
    )

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        path = getattr(so, "path", None)
        if not path or not Path(path).exists():
            return {"error": f"找不到 so 文件：{path}", "code": "NO_FILE"}

        py, why = _find_python()
        if not py:
            return {
                "error": "找不到装了 angr 的 Python 解释器。",
                "code": "ANGR_NOT_FOUND",
                "why": ("angr 的 Rust 扩展按 Python 版本编译——mda 用 3.11，"
                        "angr 10.x 只有 3.12 wheel；angr 9.2.x 会把 capstone "
                        "降到 5.0.3 破坏 mda。所以要用独立环境。"),
                "how_to_fix": [
                    "python3.12 -m venv /tmp/angr_venv",
                    "/tmp/angr_venv/bin/pip install angr",
                    "（mda 会自动探测 /tmp/angr_venv；"
                    "或用 MDA_ANGR_PYTHON 指定解释器路径）",
                ],
            }

        mode = args.get("mode", "project_info")
        task = {"mode": mode, "path": str(path),
                "limit": int(args.get("limit", 50))}
        # (3) 第三次修改（2026-11-26）
        # bug 原因：addr/find/avoid 直接用 int() 解析，非法字符串会抛出未捕获 ValueError。
        # 解决方案：统一通过 parse_addr 解析地址参数，非法值返回 BAD_ADDR 错误。
        for addr_key in ("addr", "find", "avoid"):
            if args.get(addr_key) is not None:
                parsed = parse_addr(args[addr_key])
                if parsed is None:
                    return {"ok": False, "code": "BAD_ADDR",
                            "error": f"非法地址参数 {addr_key}={args[addr_key]!r}"}
                task[addr_key] = parsed

        # (1) 第一次修改（2026-11-18）
        #     bug 原因：symbolic 模式只返回 reached:bool，无法注入符号/具体寄存器、
        #               无法给约束求解，用户要"解出 x19"却没有参数通路。
        #     解决方案：把 symbolic/concrete/constraint/max_depth/avoid/find 透传给
        #               worker task；其余参数兼容旧版（上面已处理 addr/find/limit）。
        for key in ("symbolic", "concrete"):
            if isinstance(args.get(key), dict):
                task[key] = args[key]
        if args.get("constraint") is not None:
            task["constraint"] = str(args["constraint"])
        if args.get("max_depth") is not None:
            task["max_depth"] = int(args["max_depth"])

        try:
            r = subprocess.run([py, str(_WORKER)],
                               input=json.dumps(task),
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"error": "angr 分析超时（300s）",
                    "code": "TIMEOUT",
                    "note": "大函数或 OLLVM 加固样本上可能极慢"}
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"启动 worker 失败：{exc}",
                    "code": "WORKER_FAILED"}

        raw = (r.stdout or "").strip()
        if not raw:
            return {"error": "worker 无输出",
                    "code": "NO_OUTPUT",
                    "stderr": (r.stderr or "")[-400:]}
        try:
            got = json.loads(raw.splitlines()[-1])
        except json.JSONDecodeError:
            return {"error": f"worker 输出不是 JSON：{raw[:200]}",
                    "code": "BAD_OUTPUT"}

        got["python_used"] = py
        got["detected_by"] = why
        got["so"] = so.name
        return got
