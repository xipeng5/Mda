"""指令级模式搜索：按「指令语义」找代码，而不是按字节。

## 为什么需要它（用户实测反馈）

逆向时最常见的动作是「我知道一个结构体偏移 / 一个常量 / 一个寄存器用法，
帮我找出所有访问它的指令」。

在这之前，mda 只有 `search_bytes`（按字节模式搜），它做不到这件事：
  · 「所有 `str` 到 `[x?, #0x1100]` 的指令」 —— 字节模式要写一堆变体
  · 「所有把 x0 传给 bl 的调用点」 —— 字节层面完全无法表达

用户自己写 capstone 脚本扫 `str x?, [x?, #0x1100]`，一步定位到了
前面 20 多轮都没找到的 `TTConfigManager`。这个能力必须内置。

## 设计

输入是**结构化的指令条件**（助记符 + 操作数模式），不是裸正则：
  · 助记符支持通配（`str*` 覆盖 str/strb/strh/strsw）
  · 操作数模式用简化通配：
        `[x*, #0x1100]`   任意基址寄存器 + 立即数 0x1100
        `x0, [x1, #*]`    x0 写到 x1 指向的任意偏移
        `w*, w0, #*`      寄存器运算

不要求用户懂正则，也不要求记 ARM64 编码——那是工具该做的事。

## 实现策略（性能是关键）

全库扫 12160 个函数、几十万条指令，用 capstone 逐条解码约 10-20 秒。
优化：
  1. 只扫可执行段，按 4 字节步进（AArch64 定长）
  2. **先用助记符做快速预筛**：capstone 解码后立刻比 mnemonic，
     不匹配就 continue，避免构造操作数字符串（那是最贵的一步）
  3. 结果带上所在函数，用户不用再查一次
"""
from __future__ import annotations

import re

__all__ = ["search_insn", "InsnMatch"]

# 助记符 → 是否可执行段的判断交给调用方；这里只管匹配
_MAX_RESULTS = 2000


class InsnMatch:
    """一条命中的指令（轻量结构，避免 dataclass 开销）。"""

    __slots__ = ("addr", "mnemonic", "op_str", "func_entry", "func_name", "offset")

    def __init__(self, addr: int, mnemonic: str, op_str: str,
                 func_entry: int | None, func_name: str, offset: int | None):
        self.addr = addr
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.func_entry = func_entry
        self.func_name = func_name
        self.offset = offset

    def to_dict(self) -> dict:
        d = {"addr": self.addr, "addr_hex": hex(self.addr),
             "text": f"{self.mnemonic} {self.op_str}".strip()}
        if self.func_entry is not None:
            d["function"] = self.func_name
            d["function_entry"] = hex(self.func_entry)
            d["offset"] = hex(self.offset or 0)
        else:
            d["function"] = None
            d["note"] = "不在任何已知函数内（可能是数据/填充，或函数未被发现）"
        return d


def _compile_mnemonic(p: str) -> re.Pattern | None:
    """助记符模式 → 正则。`str*` 覆盖 str/strb/strh，`*` 表示不限制。"""
    if not p or p == "*":
        return None
    if "*" in p or "?" in p:
        esc = re.escape(p).replace(r"\*", ".*").replace(r"\?", ".")
        return re.compile(rf"^{esc}$", re.I)
    return re.compile(rf"^{re.escape(p)}$", re.I)


# 操作数模式里会被当作语法字符的符号
_OP_ARITY = {
    # 只把明显的分隔符拆开，不解析 ARM64 详细语法
}


def _compile_operand(p: str) -> re.Pattern | None:
    """操作数模式 → 正则。

    约定（对用户友好，不用写正则）：
      *     任意字符序列（不跨空白也可）
      x*    任意 x 开头寄存器（x0..x30）
      w*    任意 w 开头寄存器
      #*    任意立即数
      [..]  内存操作数，内部同样支持上面三种

    实现：把模式里**只有** `*` 和 `?` 当通配，其余字符一律字面匹配。
    这避免了「用户写的 . 被当正则元字符」的意外。
    """
    if not p:
        return None
    out = []
    i = 0
    while i < len(p):
        ch = p[i]
        if ch == "*":
            out.append(r"[^,\s\]\[]*")
        elif ch == "?":
            out.append(r"[^,\s]")
        else:
            out.append(re.escape(ch))
        i += 1
    # 允许模式里空格数量有弹性（capstone 输出格式在不同版本下略有差异）
    body = "".join(out).replace(r"\ ", r"\s*")

    # 锚定语义由用户显式指定的 ^ / $ 决定，默认**子串匹配**：
    # 用户写 `[x*, #0x1100]` 是"操作数里存在这个内存操作数"，
    # 而 op_str 是 "x19, [sp, #0x30]" 这种完整列表，精确匹配永远失败。
    anchor_start = p.startswith("^")
    anchor_end = p.endswith("$")
    if anchor_start and body.startswith(r"\^"):
        body = body[2:]
    if anchor_end and body.endswith(r"\$"):
        body = body[:-2]
    pre = "^" if anchor_start else ""
    suf = "$" if anchor_end else ""
    return re.compile(rf"{pre}{body}{suf}", re.I)


def _norm_operand(s: str) -> str:
    """归一化操作数文本，让匹配不受空格影响。"""
    s = re.sub(r"\s+", " ", s.strip())
    s = s.replace(", ", ",").replace(" ,", ",")
    return s


def search_insn(so, mnemonic: str = "", operand_pattern: str = "",
                limit: int = 100, text_only: bool = True,
                func_filter: str = "") -> dict:
    """在 so 的可执行段里按指令模式搜索。

    参数：
        so                SoFile 对象（已加载的模块）
        mnemonic          助记符，支持通配：`str` / `str*` / `bl` / `*`
        operand_pattern   操作数模式，支持 `*` 与 `?`：
                            `[x*, #0x1100]`
                            `x0, [x1, #*]`
                            `w*, w0, #*`
        limit             最多返回多少条
        text_only         只扫可执行段（默认 True）
        func_filter       只搜函数名匹配该子串的函数（缩小范围，提速）

    返回：
        {count, scanned, matched, truncated, results[{addr_hex, text, function, offset}]}

    注意：`scanned` 是**反汇编过的指令数**，用来判断搜索代价；
    `matched` 是匹配数（可能 > count，被 limit 截断时 truncated=True）。
    """
    import capstone

    mre = _compile_mnemonic(mnemonic)
    ore = _compile_operand(operand_pattern)

    # 需要知道每条指令属于哪个函数 → 用 starts 二分
    starts = getattr(so, "_starts", None)
    if starts is None:
        starts = sorted(so.functions.keys())

    def _func_of(addr: int):
        """返回 (函数入口, 函数对象)；不在函数内返回 (None, None)。"""
        if not starts:
            return None, None
        # bisect 手写：starts 是排好序的 list
        lo, hi = 0, len(starts) - 1
        idx = -1
        while lo <= hi:
            mid = (lo + hi) // 2
            if starts[mid] <= addr:
                idx = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if idx < 0:
            return None, None
        entry = starts[idx]
        fn = so.functions.get(entry)
        if fn is None:
            return None, None
        # 落在函数范围外（数据/对齐填充）
        end = entry + (fn.size or 0)
        if fn.size and addr >= end:
            return None, None
        return entry, fn

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False          # 不用 detail：我们只比文本，detail 会慢一倍

    results: list[dict] = []
    scanned = 0
    matched = 0

    # (3) 函数名过滤的区间与"函数不存在"判断只做一次（不要放进 section 循环，
    #     否则每个段重算一遍，且会因为某段没数据而推迟报错）。
    ranges = None
    if func_filter:
        kw = func_filter.lower()
        ranges = []
        for a in starts:
            fn = so.functions.get(a)
            if fn is None or not fn.size:
                continue
            nm = (fn.name or f"sub_{a:x}").lower()
            if kw in nm:
                ranges.append((a, a + fn.size))
        if not ranges:
            # 函数表里没有这个函数：不能静默返回 0 条
            # （那会被读成"函数里没有匹配指令"，实际是"函数还没被发现"）
            return {
                "error": (f"函数表里没有名字匹配 {func_filter!r} 的函数"
                          f"（当前函数表只有 {len(starts)} 个）。"),
                "code": "FUNC_NOT_FOUND",
                "count": 0, "matched": 0, "scanned": 0,
                "truncated": False, "results": [],
                "hint": ("① 传 discover=true 补全函数表（大样本约 40 秒）；"
                         "② 或先调 build_xrefs；"
                         "③ 或去掉 func_filter 全库搜，用返回的 function 字段自己筛"),
            }

    # (4) 段表兜底：加固样本常无节表。PT_LOAD 里 flags bit0 = X（可执行）。
    #      没有这一步时 sections 为空会让整个搜索一次都不执行，
    #      却返回 matched=0 伪装成"没有命中"。
    scan_ranges: list[tuple[int, int]] = []
    for sec in getattr(so, "sections", []):
        if text_only and not sec.is_exec:
            continue
        if not text_only and sec.is_exec:
            continue
        scan_ranges.append((sec.addr, sec.size))

    section_mode = bool(scan_ranges)
    if not scan_ranges:
        # 退到 PT_LOAD：只取可执行段
        for vaddr, end, _off, flags in getattr(so, "_loads", []) or []:
            if text_only and not (int(flags) & 0x1):
                continue
            if end > vaddr:
                scan_ranges.append((int(vaddr), int(end) - int(vaddr)))

    if not scan_ranges:
        return {
            "error": ("这个 so 既没有可用的节表，也没有可执行的 PT_LOAD 段——"
                      "搜不到任何指令。"),
            "code": "NO_SCANNABLE_SEGMENT",
            "count": 0, "matched": 0, "scanned": 0,
            "truncated": False, "results": [],
            "hint": "检查该 so 是否被完整 dump（可能被截断或加密）",
        }

    for _range_addr, _range_size in scan_ranges:
        sec_addr, sec_size = _range_addr, _range_size
        try:
            data = so.read(sec_addr, sec_size)
        except Exception:                                 # noqa: BLE001
            continue
        if not data:
            continue

        off = 0
        total = len(data)
        while off + 4 <= total:
            cur = sec_addr + off
            if ranges is not None and not any(s <= cur < e for s, e in ranges):
                off += 4
                continue
            # capstone 逐条解码：一次给 4 字节，保证不会跨指令
            insn = next(md.disasm(data[off:off + 4], cur), None)
            if insn is None:
                off += 4
                continue
            scanned += 1
            ok = True
            if mre is not None and not mre.match(insn.mnemonic):
                ok = False
            if ok and ore is not None:
                # 子串匹配必须用 search（match 强制从开头比对，
                # 会把 "x19, [sp, #0x30]" 里的内存操作数漏掉）
                if not ore.search(_norm_operand(insn.op_str or "")):
                    ok = False
            if ok:
                matched += 1
                if len(results) < min(int(limit or 100), _MAX_RESULTS):
                    entry, fn = _func_of(cur)
                    results.append(InsnMatch(
                        cur, insn.mnemonic, insn.op_str or "",
                        entry,
                        (fn.name or f"sub_{entry:x}") if entry is not None else "",
                        (cur - entry) if entry is not None else None,
                    ).to_dict())
            off += 4

    # (4) 一条都没扫到时明确报错——绝不能伪装成"没有命中"
    if scanned == 0:
        return {
            "error": (f"扫描了 {len(scan_ranges)} 个可执行区间，"
                      "但一条指令都没解码出来。这通常不是『没有命中』，"
                      "而是扫描范围或解码出了问题。"),
            "code": "NOTHING_SCANNED",
            "count": 0, "matched": 0, "scanned": 0,
            "truncated": False, "results": [],
            "scan_mode": "segments" if not section_mode else "sections",
            "hint": "检查该 so 是否被完整 dump；或先用 metadata 确认段表可读",
        }

    return {
        "count": len(results),
        "matched": matched,
        "scanned": scanned,
        "scan_mode": "sections" if section_mode else "segments(PT_LOAD)",
        "truncated": matched > len(results),
        "mnemonic": mnemonic,
        "operand_pattern": operand_pattern,
        "results": results,
        "hint": ("没有命中时：① 确认助记符写法（str* 能覆盖 str/strb/strh）；"
                 "② 操作数模式里 `#0x1100` 要带 0x；"
                 "③ 立即数可能被拆成 adrp+add，试着搜 `add` 而不是 `str`"
                 ) if not results else "",
    }
