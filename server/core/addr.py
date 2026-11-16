"""地址与整数解析的唯一入口。

## 为什么要单独抽出来

同一套"把各种来源的地址串变成 int"的逻辑，项目里先后写了四份：

    dyn/debugger._parse_addr      动态层读 JS 回传的地址
    mcp_server.tools._as_int_addr MCP 入参
    dyn/tracer._to_int            trace 事件字段
    dyn/bridge._as_int            静态/动态桥接层

四者在"纯数字串怎么解释"上并不一致，最典型的分歧是**没有 0x 前缀但含 a-f**
的写法（如 ``"7fff1234"``，地址的常见简写）：

    tools._as_int_addr  → 含 a-f 就按十六进制    ✅
    debugger._parse_addr→ 先试十进制，失败返回 0  ❌ 解析不出来
    tracer._to_int      → 先试十进制，失败返回 0  ❌
    bridge._as_int      → 先试十进制，失败返回 None ❌

于是同一个 ``"7fff1234"`` 在不同入口会得到 0、None 或 3415878964 三种结果。
调用点靠"我记得这个函数怎么解析"来保证正确，长期必然出现新的不一致。

本模块把规则收口为一处，其余位置一律转调这里。

## 解析规则（唯一口径）

    value 形态              解释
    ----------------------  --------------------------------------------
    None / bool             → default（bool 是 int 子类，必须显式排除）
    int                     → 原值
    float                   → int()（负值保留符号，不做无符号假设）
    "0x..." / "0X..."       → 按十六进制
    "deadbeef"（含 a-f）     → 按十六进制（地址简写）
    "5020"                  → 按十进制（人类与 JSON 的默认语义）
    "" / 其他不可解析        → default

``"5020"`` 按十进制是刻意的：它更像人类输入的编号（线程 id、序号），
而地址通常带 0x 或含 a-f。这条规则曾在实测中救过一次——
把线程 id ``"12"`` 当十六进制会静默取到线程 18 的调用栈，且失败后自动
退回第一条线程，使用者完全察觉不到取错了。
"""
from __future__ import annotations

__all__ = ["parse_addr", "parse_int"]


def _is_hex_digits(text: str) -> bool:
    """纯十六进制数字且含字母（不含 0x 前缀）——地址简写的判定。"""
    if not text:
        return False
    has_alpha = False
    for ch in text:
        if ch.isdigit():
            continue
        low = ch.lower()
        if low in "abcdef":
            has_alpha = True
            continue
        return False
    return has_alpha


def parse_addr(value, default=None):
    """把地址/整数形态归一成 int；解析不出来返回 default（默认 None）。

    返回 None 而不是 0 是刻意的：调用方需要区分"没有地址"与"地址是 0"，
    用 0 兜底会让"取不到"被误读成"地址确实是 0"。
    确实需要 0 兜底的调用点（如动态层的寄存器快照）显式传 ``default=0``。
    """
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # 负值保留：调用方通常会自己判非法，这里不替它决定
        return int(value)

    text = str(value).strip()
    if not text:
        return default

    low = text.lower()
    if low.startswith("0x"):
        try:
            return int(text, 16)
        except (TypeError, ValueError):
            return default
    # frida 有时把地址包成 "<ptr 0x...>" 之类；只在明确形如地址时兜底
    if low.startswith("<") and "0x" in low:
        inner = low[low.index("0x"):].rstrip(">").strip()
        try:
            return int(inner, 16)
        except (TypeError, ValueError):
            return default

    # 含 a-f 的纯字母数字串按十六进制（"7fff1234"、"deadbeef"）
    if _is_hex_digits(text):
        try:
            return int(text, 16)
        except (TypeError, ValueError):
            return default

    try:
        return int(text, 10)
    except (TypeError, ValueError):
        return default


def parse_int(value, default: int = 0) -> int:
    """同 :func:`parse_addr`，但用整数 default 兜底（给"必须有值"的调用点用）。"""
    got = parse_addr(value, default)
    return default if got is None else int(got)
