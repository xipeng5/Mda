"""惰性能力占位：需要真机 frida 但本轮不实现的功能，统一从这里返回。

## 为什么要有这个模块

用户明确要求：**全部做，但凡是需要连接 frida 才能跑的部分先空着**。
如果不做统一约定，各模块会各自编造"暂时不可用"的返回形状，
AI 侧看到的结构不一致，也会有人误以为自己拿到了数据。

## 设计原则

1. **绝不返回假数据**：宁可明确报错，也不返回 `[]`、`None` 或全 0，
   避免下游把"没实现"误判成"确实没有"。
2. **可被程序判定**：固定 `error` + `code` + `implemented` 三个字段，
   调用方（AI 或前端）能稳定区分"功能未实现"与"执行失败"。
3. **说明下一步**：`hint` 写清要补哪一段、依赖哪个前置条件。
4. **纯静态能力不受影响**：同一批工具里凡是能离线完成的，
   依然走真实实现，不因这个占位而退化。
"""
from __future__ import annotations

# 未实现能力的固定错误码前缀，便于上层用 startswith 过滤
CODE_PREFIX = "NEEDS_FRIDA"


class NotImplementedYet(Exception):
    """能力已规划但本轮未实现（依赖真机 frida 会话）。

    与 NotImplementedError 的区别：这是**计划内的留空**，不是编码遗漏，
    故单独一个类型，方便上层区分并给出友好提示。
    """

    def __init__(self, feature: str, reason: str = "", hint: str = "",
                 code: str = ""):
        self.feature = feature
        self.reason = reason or "该能力依赖真机 frida 会话，本轮按要求未实现"
        self.hint = hint or "需要设备空闲时补做真机联调后再启用"
        self.code = code or f"{CODE_PREFIX}:{feature}"
        super().__init__(f"{feature} 未实现：{self.reason}（{self.code}）")

    def as_dict(self) -> dict:
        """统一的占位返回结构。

        字段含义：
          error       —— 人类可读的错误描述（AI 直接转述即可）
          code        —— 机器可判定的错误码，形如 NEEDS_FRIDA:<feature>
          implemented —— 恒为 False，明确"这不是执行失败而是没做"
          feature     —— 能力名，便于上层按名排查
          reason      —— 为什么没做
          hint        —— 下一步该怎么做
          requires    —— 该能力依赖的前置条件清单
        """
        return {
            "error": str(self),
            "code": self.code,
            "implemented": False,
            "feature": self.feature,
            "reason": self.reason,
            "hint": self.hint,
            "requires": ["frida 已连接设备", "目标进程已 attach"],
        }


def pending(feature: str, reason: str = "", hint: str = "") -> dict:
    """便捷函数：直接拿到占位结构。"""
    return NotImplementedYet(feature, reason, hint).as_dict()


def is_pending(result) -> bool:
    """判断某个返回值是不是占位结果（供上层统一处理）。"""
    return (isinstance(result, dict)
            and result.get("implemented") is False
            and str(result.get("code", "")).startswith(CODE_PREFIX))
