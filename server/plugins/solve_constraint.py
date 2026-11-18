"""基于 z3 的约束求解插件（通用能力）。

## 解决什么问题

逆向时反复卡在同一种困境：
    已知  输出 = f(输入)，输出是抓到的实际值
    求    输入 = ?

人肉只能"猜一个输入 → 算一遍 → 不对 → 再猜"。本插件把这件事交给
z3 求解器：调用方描述等式，它直接解出未知数。

## 与"符号执行"的区别（重要）

本插件**不**做全函数符号执行（那是 angr 的活，重且慢）。
它做的是**定向约束求解**：调用方给出等式与范围，工具解出未知数。

这类问题在实际逆向里占绝大多数，而且快得多：
    反解混淆用的异或补偿值、常数偏移、简单线性变换的输入。

## 用法

```python
plugin_run(name="solve_constraint", args={
    "vars": {"x24": {"bits": 64, "lo": 0, "hi": 2**48}},
    "constraints": [
        "(0xdccf58 ^ x24) + 0x10 == 0x1f74e0"
    ],
    "max_solutions": 3,
})
```

表达式支持（通用，非样本特征）：
    + - *  /  %  & | ^ ~ << >>  以及 == != < <= > >=
    十六进制/十进制字面量、变量名、括号

## 诚实边界

  · 表达式必须是**调用方提供**的——本插件不会"看懂"汇编自动建模
  · 无解时会明确报 unsat，不编造一个答案
  · 非线性/加密哈希（如 MD5 输出反解输入）在可接受时间内不可解，
    会按 timeout 返回 unknown，不假装成功
"""
from __future__ import annotations

import ast
import re

from server.core.plugins import PluginBase

# 允许的 AST 节点（白名单，防注入）
_ALLOWED = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.Invert, ast.USub, ast.UAdd, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.And, ast.Or, ast.Constant, ast.Name, ast.Load,
)


class Plugin(PluginBase):
    name = "solve_constraint"
    description = "用 z3 解约束：给等式与变量范围，反解未知数（定向求解，非全函数符号执行）"
    usage = ("args: {constraints: list[str], vars: {name: {bits:int, "
             "lo:int|None, hi:int|None}} 或 {name: {bits:int}}, "
             "max_solutions: int=1, timeout_ms: int=10000}")

    def run(self, session, args: dict):
        try:
            import z3
        except ImportError:
            return {"error": "z3-solver 未安装。pip install z3-solver（MIT）",
                    "code": "Z3_NOT_INSTALLED"}

        exprs = args.get("constraints") or []
        var_defs = args.get("vars") or {}
        if not exprs or not var_defs:
            return {"error": "需要 constraints 与 vars", "code": "BAD_ARGS"}
        if isinstance(exprs, str):
            exprs = [exprs]

        # ---- 建 z3 变量 ----
        env: dict = {}
        for name, spec in var_defs.items():
            if not re.match(r"^[A-Za-z_]\w*$", str(name)):
                return {"error": f"变量名非法：{name}", "code": "BAD_VAR_NAME"}
            bits = int((spec or {}).get("bits", 64))
            if bits not in (8, 16, 32, 64, 128):
                return {"error": f"{name} 的 bits 必须是 8/16/32/64/128",
                        "code": "BAD_BITS"}
            env[name] = z3.BitVec(str(name), bits)

        solver = z3.Solver()
        timeout_ms = int(args.get("timeout_ms", 10000))
        solver.set("timeout", timeout_ms)

        # ---- 变量范围约束 ----
        for name, spec in var_defs.items():
            v = env[name]
            spec = spec or {}
            if spec.get("lo") is not None:
                solver.add(z3.UGE(v, z3.BitVecVal(int(spec["lo"]), v.size())))
            if spec.get("hi") is not None:
                solver.add(z3.ULE(v, z3.BitVecVal(int(spec["hi"]), v.size())))

        # ---- 编译表达式 ----
        translated = []
        for raw in exprs:
            try:
                node = ast.parse(str(raw), mode="eval")
            except SyntaxError as exc:
                return {"error": f"表达式语法错：{raw}（{exc}）",
                        "code": "BAD_EXPR"}
            for sub in ast.walk(node):
                if not isinstance(sub, _ALLOWED):
                    return {"error": f"表达式含不允许的语法：{type(sub).__name__}",
                            "code": "UNSAFE_EXPR"}
            try:
                zexpr = self._to_z3(node.body, env, z3)
            except Exception as exc:                      # noqa: BLE001
                return {"error": f"表达式转换失败：{raw}（{exc}）",
                        "code": "CONV_FAILED"}
            solver.add(zexpr)
            translated.append(str(raw))

        # ---- 求解 ----
        want = max(1, int(args.get("max_solutions", 1)))
        solutions = []
        for _ in range(want):
            r = solver.check()
            if r == z3.sat:
                m = solver.model()
                sol = {}
                for name, v in env.items():
                    val = m.eval(v, model_completion=True)
                    sol[name] = int(val.as_long())
                    sol[name + "_hex"] = hex(int(val.as_long()))
                solutions.append(sol)
                # 排除这一组再求下一组
                solver.add(z3.Or(*[v != m.eval(v, model_completion=True)
                                   for v in env.values()]))
            elif r == z3.unknown:
                return {"ok": False, "code": "UNKNOWN",
                        "reason": (f"求解超时或无法判定（{timeout_ms}ms）。"
                                   "加密哈希类问题通常需要专门的求解技术，"
                                   "不是本工具的适用范围。"),
                        "constraints": translated}
            else:
                break

        if not solutions:
            return {"ok": False, "code": "UNSAT",
                    "reason": "约束无解。检查等式是否写错，或变量范围是否过窄。",
                    "constraints": translated,
                    "vars": {k: dict(v or {}) for k, v in var_defs.items()}}

        return {
            "ok": True,
            "solutions": solutions,
            "solution_count": len(solutions),
            "constraints": translated,
            "vars": {k: dict(v or {}) for k, v in var_defs.items()},
            "note": ("这是**定向约束求解**，不是全函数符号执行。"
                     "解出的值满足你给的等式；等式不完整时解不唯一。"),
        }

    class _IntLit(int):
        """标记"这是字面量"，用于延迟决定位宽。"""

    def _bits_of(self, v):
        """取一个 z3 表达式的位宽；字面量返回 None。"""
        if isinstance(v, int) and not hasattr(v, "size"):
            return None
        try:
            return v.size()
        except Exception:                                 # noqa: BLE001
            return None

    def _coerce(self, a, b, z3):
        """把两侧对齐到同一位宽（字面量跟随另一侧）。"""
        ba, bb = self._bits_of(a), self._bits_of(b)
        if ba is None and bb is None:
            return z3.BitVecVal(int(a), 64), z3.BitVecVal(int(b), 64)
        if ba is None:
            a = z3.BitVecVal(int(a), bb)
        if bb is None:
            b = z3.BitVecVal(int(b), ba)
        return a, b

    def _to_z3(self, node, env, z3):
        """把 AST 节点转成 z3 表达式。"""
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, int):
                # (1) 字面量先保持 Python int，等与变量运算时再定位宽
                return int(v)
            raise ValueError(f"不支持的常量类型：{type(v).__name__}")
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise ValueError(f"未定义的变量：{node.id}")
            return env[node.id]
        if isinstance(node, ast.BinOp):
            l = self._to_z3(node.left, env, z3)
            r = self._to_z3(node.right, env, z3)
            op = node.op
            mapping = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.BitAnd: lambda a, b: a & b,
                ast.BitOr: lambda a, b: a | b,
                ast.BitXor: lambda a, b: a ^ b,
                ast.LShift: lambda a, b: a << b,
                ast.RShift: lambda a, b: z3.LShR(a, b),
                ast.Div: lambda a, b: z3.UDiv(a, b),
                ast.FloorDiv: lambda a, b: z3.UDiv(a, b),
                ast.Mod: lambda a, b: z3.URem(a, b),
            }
            if type(op) not in mapping:
                raise ValueError(f"不支持的运算符：{type(op).__name__}")
            l, r = self._coerce(l, r, z3)
            return mapping[type(op)](l, r)
        if isinstance(node, ast.UnaryOp):
            v = self._to_z3(node.operand, env, z3)
            if isinstance(node.op, ast.Invert):
                return ~v
            if isinstance(node.op, ast.USub):
                return -v
            if isinstance(node.op, ast.UAdd):
                return v
            raise ValueError(f"不支持的一元运算符：{type(node.op).__name__}")
        if isinstance(node, ast.Compare):
            left = self._to_z3(node.left, env, z3)
            result = None
            for op, comparator in zip(node.ops, node.comparators):
                right = self._to_z3(comparator, env, z3)
                cmp = {
                    ast.Eq: lambda a, b: a == b,
                    ast.NotEq: lambda a, b: a != b,
                    ast.Lt: lambda a, b: z3.ULT(a, b),
                    ast.LtE: lambda a, b: z3.ULE(a, b),
                    ast.Gt: lambda a, b: z3.UGT(a, b),
                    ast.GtE: lambda a, b: z3.UGE(a, b),
                }.get(type(op))
                if cmp is None:
                    raise ValueError(f"不支持的比较：{type(op).__name__}")
                left, right = self._coerce(left, right, z3)
                c = cmp(left, right)
                result = c if result is None else z3.And(result, c)
                left = right
            return result
        raise ValueError(f"不支持的节点：{type(node).__name__}")
