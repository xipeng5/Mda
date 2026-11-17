"""符号执行能力边界说明（不是符号执行器）。

## 为什么不实现符号执行

使用者最想要的能力是："我告诉你 tail 是什么，你告诉我 x24 该是多少"。
这需要真正的 SMT 求解器（z3）或符号执行引擎（angr/Triton）。

本项目约束：
  - 不引入外部工具桥接
  - 不装第三方大型依赖（angr 需要 z3 + claripy + 一堆原生库）
  - 遵守"通用能力、精简解耦"原则

在这些约束下，**实现一个假符号执行器比没有更糟**——它会给出
看似正确实则错误的解，把使用者引向错误方向。

## 这个插件提供什么

一个**诚实的边界说明**：告诉调用方
  1. mda 当前不做符号执行
  2. 要反解运行时值，需要什么前提（真实样本 + 外部求解器）
  3. 用现有的什么工具能部分替代（data_flow 追来源、const_fingerprint 认算法、
     string_crack 解密字符串）

## 为什么不静默返回"不支持"

因为使用者会把"工具没返回错误"当成"能力存在但没找到解"。
明确说出来，才能避免误导。
"""
from __future__ import annotations

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "symbolic_boundary"
    description = "符号执行能力边界说明（明确 mda 不做什么、替代方案是什么）"
    usage = "args: {}  # 无参数，返回能力说明"

    def run(self, session, args: dict):
        return {
            "ok": True,
            "capability": "symbolic_execution",
            "available": False,
            "reason": ("mda 是精简的 Python 静态+动态分析器，"
                       "已内置 z3-solver（MIT）作为约束求解底座，"
                       "但不内置完整符号执行引擎（angr 需用户显式启用）。"
                       "没有真实样本时不会给出假解——"
                       "本插件说明边界，具体求解由调用方提供约束。"),
            "what_you_need_to_solve_runtime_values": [
                "一次真实的请求样本（URL/body/device/ts/scene + 对应的 tail）",
                "SMT 求解器已内置（z3-solver）；复杂符号执行可启用 angr_bridge 插件",
                "把目标算法建模成约束（可用 const_fingerprint 认出算法后手工建模）",
            ],
            "honest_warning": ("没有真实样本时，符号执行会给出无穷多组解，"
                               "数学上有解、实际上不可用。"
                               "工具再强也给不出那次请求的输入。"),
            "mda_alternatives": [
                {"tool": "z3 (已内置) / angr_bridge (可选)",
                 "use": "约束求解：给等式反解未知数"},
                {"tool": "data_flow", "use": "追踪未知寄存器的来源（不求解）"},
                {"tool": "const_fingerprint", "use": "识别算法常量，确定建模对象"},
                {"tool": "string_crack", "use": "解密字符串池，拿到参数模板/密钥"},
                {"tool": "disasm_func / decompile_c", "use": "看控制流与数据流结构"},
            ],
        }
