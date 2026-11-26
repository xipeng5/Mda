"""IDC 脚本直译执行器。

覆盖真实逆向脚本的 API 面（用户脚本统计：MakeName/MakeFunction/set_cmt/
Message/MakeCode/is_code/get_flags/del_items 为全部调用量）。

语法转换策略：词法级翻译而非逐行正则——
  1. 剥 #include 与 // 注释
  2. 函数定义  static [type] name(args) {  →  def name(args):
  3. auto 声明行删除
  4. 控制流  if(...) / while(...) / else / return 保留（Python 兼容），
     去掉条件外层括号、行尾分号、! → not
  5. 单行体  if (x) stmt;  →  if x: stmt（缩进展开）
  6. BADADDR 常量替换
"""
from __future__ import annotations

import bisect
import re

from server.core.session import Session

BADADDR = 0xFFFFFFFFFFFFFFFF
# IDC 常量（用户脚本真实用到的）
DELIT_SIMPLE = 0
DELIT_EXPAND = 1
DELIT_DELNAMES = 2
SN_NOCHECK = 0
SN_NOWARN = 0x80

# (2) 第二次修改（2026-11-26）
# bug 原因：run_idc 执行 IDC 脚本时直接把完整 __builtins__ 暴露给 exec，
#           脚本可经 __import__/open/eval/exec 越权读写任意文件或执行任意命令。
# 解决方案：收窄为最小安全内置集合，仅开放基础类型与纯计算函数。
_SAFE_BUILTINS: dict = {
    "int": int, "float": float, "str": str, "bool": bool,
    "len": len, "range": range, "hex": hex, "oct": oct, "bin": bin,
    "ord": ord, "chr": chr, "abs": abs, "min": min, "max": max,
    "sum": sum, "round": round, "divmod": divmod, "pow": pow,
    "list": list, "dict": dict, "set": set, "tuple": tuple,
    "enumerate": enumerate, "zip": zip, "sorted": sorted,
    "reversed": reversed, "any": any, "all": all,
    "isinstance": isinstance, "print": print,
    "True": True, "False": False, "None": None,
}


class IdcError(Exception):
    pass


class IdcContext:
    """IDC API 的 Python 实现，直接操作 Session。"""

    def __init__(self, session: Session, so_name: str):
        self.session = session
        if hasattr(session, "resolve"):
            self.so, self.so_name = session.resolve(so_name)
        else:
            self.so_name = so_name
            self.so = session.get(so_name)
        self.messages: list[str] = []

    # ---- 内部 ----

    def _func_at(self, ea: int):
        return self.so.function_at(ea)

    def _ensure_func(self, ea: int):
        """取/建函数对象。IDA 语义：MakeFunction 对已有函数内部地址是无效的。

        BUG-2 修复（关键）：旧实现用 function_at(ea)，若 ea 落在某已存在
        函数**内部**（非起点）会返回那个外层函数，随后 MakeName 就把名字
        写到外层函数上——用户实测「0x48b48 应为 Java_aesEncrypt，实得
        Java_clearCrashInfo」「32 个只活 5 个且名字错位」即此因。
        解决：仅当 ea 严格等于某函数起点时复用，否则以 ea 为起点新建独立
        函数；边界取「下一个函数起点」，绝不吞并已存在的函数。
        """
        from server.models import Function

        fn = self.so.functions.get(ea)  # 仅按起点精确匹配
        if fn is not None:
            return fn
        starts = sorted(a for a in self.so.functions if a > ea)
        nxt = starts[0] if starts else ea + 0x100
        size = max(0x10, min(nxt - ea, 0x10000))
        fn = Function(addr=ea, size=size, discovered_by="idc", so_name=self.so_name)
        self.so.functions[ea] = fn
        self._refresh_ranges()
        self._invalidate_caches(ea)
        return fn

    def _invalidate_caches(self, ea: int) -> None:
        """函数边界或名称变化后使反汇编缓存与引用指令缓存失效。"""
        xrefs = getattr(self.session, "_xrefs", None) or {}
        x = xrefs.get(self.so_name)
        targets = {ea}
        starts = getattr(self.so, "_starts", None) or sorted(self.so.functions)
        idx = bisect.bisect_left(starts, ea)
        if idx > 0:
            targets.add(starts[idx - 1])
        for a in targets:
            fn = self.so.functions.get(a)
            if fn is not None:
                fn.instructions = []
            if x is not None:
                dis = getattr(x, "disasm", None)
                if dis is not None and hasattr(dis, "invalidate_cache"):
                    dis.invalidate_cache(a)
                if hasattr(x, "_insn_cache"):
                    x._insn_cache.pop(a, None)

    def _refresh_ranges(self) -> None:
        """重建函数区间索引，并**同步**刷新 function_at 用的起点表。

        (1) 第一次修改（2026-11-13）：
        bug 原因：旧实现只重算了 `so._func_ranges`，而 function_at() 用的是
                  `so._starts`（由 elf_model._refresh_functions 维护）做二分。
                  于是 IDC 刚建好的函数进得了 `so.functions`、也进了
                  `_func_ranges`，却**从未进 `_starts`**——实测
                  `0xdf5c in so.functions == True` 而 `function_at(0xdf5c) == None`。
                  后果：MakeFunction/MakeName 之后，反汇编、伪代码、UI 打开、
                  引用归属全都看不到这个函数，等于建了个不可见的函数。
        解决方案：改为调用 elf_model 的唯一权威入口 `_refresh_functions()`，
                  它同时维护 `_starts`、`_func_ranges`，并顺带修正 size 让区间
                  互不重叠（这是 function_at 二分的前提）。不再自己拼一份区间表，
                  避免两套索引各算一份、迟早再次不同步。
        """
        refresh = getattr(self.so, "_refresh_functions", None)
        if callable(refresh):
            refresh()
            return
        # 兜底：没有 elfw 维护口的极简 SoFile（测试替身）仍需一份可用区间表
        self.so._func_ranges = sorted((f.addr, f.end) for f in self.so.functions.values())

    # ---- IDC API ----

    def Message(self, fmt: str, *args) -> None:
        try:
            self.messages.append(fmt % args)
        except TypeError:
            self.messages.append(fmt)

    def get_flags(self, ea: int) -> int:
        # bug 原因：用 function_at 判定"是否代码"——对新地址（无 FDE/未
        # MakeFunction）恒为 0，导致脚本里 is_code 分支永不进入，mk() 类
        # 函数全走 "no func" 分支。用户 APSE_scp_handlers 11/33 即此因。
        # 解决：IDA 的 is_code 语义是"该地址可解码为指令"——用 capstone
        # 试解码 4 字节，成功即视为代码。
        data = self.so.read(ea, 4)
        if not data or len(data) < 4:
            return 0
        # (2) 第二次修改（2026-11-26）
        # bug 原因：get_flags 创建 self._probe_md 时未设 detail=True，若脚本先调 get_flags
        #           再调 MakeFunction(ea, BADADDR)，_infer_end 复用该 _probe_md 访问 insn.operands
        #           会直接抛出 capstone.CsError（Details are disabled）。
        # 解决方案：在 get_flags 创建 _probe_md 时即设置 detail=True，并在 _infer_end 兜底确认。
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            if not hasattr(self, "_probe_md"):
                self._probe_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
                self._probe_md.detail = True
            first = next(self._probe_md.disasm(data, ea), None)
            return 1 if first is not None else 0
        except Exception:
            return 0

    def is_code(self, flags: int) -> bool:
        return bool(flags & 1)

    def MakeCode(self, ea: int) -> None:
        # IDA 语义：MakeCode 失败只是返回/忽略，不抛异常打断脚本
        # （用户 IDC 里 MakeCode 后有 is_code 重查，失败走 else 分支）
        if not self.so.read(ea, 4):
            self.messages.append(f"!! MakeCode: 地址不可读 {ea:#x}")
            return

    def del_items(self, ea: int, _flags: int = 0, _size: int = 0) -> None:
        pass  # 按需解码模型无持久 item

    def MakeFunction(self, ea: int, ea_end: int = BADADDR) -> int:
        """建立函数。ea_end 为 BADADDR 时按 IDA 语义"自动推断边界"。

        BUG-2 修复（关键）：旧实现对 BADADDR 不做任何处理，函数体沿用
        _ensure_func 猜的 size；而当年 _ensure_func 用 function_at 找外层
        函数，导致 MakeFunction(ea, BADADDR) 把名字/边界写到外层函数，
        吞并中间所有函数（用户实测 @0x48b48 size=56324 覆盖 8 个 JNI 函数，
        最后一个名字获胜）。
        现在 BADADDR 走**返回指令扫描**：从 ea 起线性反汇编，遇到 ret 即停，
        边界不超过下一个已存在函数起点——与 IDA 的自动推断一致。
        """
        try:
            fn = self._ensure_func(ea)
            if ea_end not in (None, BADADDR) and ea_end > ea:
                fn.size = ea_end - ea
            elif ea_end == BADADDR:
                inferred = self._infer_end(ea)
                if inferred > ea:
                    fn.size = inferred - ea
            self._refresh_ranges()
            self._invalidate_caches(ea)
            return 1
        except IdcError:
            return 0

    def _infer_end(self, ea: int) -> int:
        """BADADDR 边界推断：扫描到第一条 ret，或下一个函数起点，取较小者。"""
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

        starts = sorted(a for a in self.so.functions if a > ea)
        hard_limit = starts[0] if starts else ea + 0x10000
        limit = min(hard_limit, ea + 0x10000)
        md = getattr(self, "_probe_md", None)
        if md is None:
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            md.detail = True  # 访问 operands 必须开 detail，否则 CS_ERR_DETAIL
            self._probe_md = md
        elif not md.detail:
            md.detail = True
        code = self.so.read(ea, limit - ea)
        if not code:
            return ea
        pos = 0
        while pos < len(code):
            insn = next(md.disasm(code[pos:], ea + pos, count=1), None)
            if insn is None:
                break
            m = insn.mnemonic
            ops = insn.operands
            pos += insn.size
            if m == "ret":
                return ea + pos
            if m == "b" and ops and ops[0].type == 2:
                # 无条件跳转视为函数尾（尾调用）
                tgt = ops[0].imm
                if not (ea <= tgt < ea + pos):
                    return ea + pos
        return min(ea + pos, limit)

    def MakeName(self, ea: int, name: str) -> None:
        fn = self._ensure_func(ea)
        fn.name = name
        self.session._export_index.setdefault(name, []).append((self.so_name, ea))
        self._invalidate_caches(ea)

    def set_cmt(self, ea: int, cmt: str, _rep: int = 0) -> None:
        self.session.comments[(self.so_name, ea)] = cmt

    def get_func_name(self, ea: int) -> str:
        fn = self._func_at(ea)
        return (fn.name if fn and fn.name else f"sub_{ea:x}")

    def Dword(self, ea: int) -> int:
        import struct

        d = self.so.read(ea, 4)
        return struct.unpack("<I", d)[0] if len(d) == 4 else 0

    def Word(self, ea: int) -> int:
        import struct

        d = self.so.read(ea, 2)
        return struct.unpack("<H", d)[0] if len(d) == 2 else 0

    def Byte(self, ea: int) -> int:
        d = self.so.read(ea, 1)
        return d[0] if d else 0

    def patch_byte(self, ea: int, val: int) -> None:
        self.session.patches[(self.so_name, ea)] = val & 0xFF


# ---------------- 语法转换 ----------------

_KW = ("if", "while", "for", "else", "return", "static", "auto")


def _split_top(s: str, sep: str = ",") -> list[str]:
    """按顶层分隔符切分（忽略括号与双/单引号字符串内部）。"""
    parts, depth, cur, i = [], 0, "", 0
    quote: str | None = None
    while i < len(s):
        c = s[i]
        if quote is not None:
            cur += c
            if c == "\\" and i + 1 < len(s):
                cur += s[i + 1]
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'"):
            quote = c
            cur += c
            i += 1
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(cur)
            cur = ""
            i += 1
            continue
        cur += c
        i += 1
    if cur.strip():
        parts.append(cur)
    return parts


def _strip_parens(s: str) -> str:
    """去掉条件表达式最外层括号。"""
    s = s.strip()
    if s.startswith("(") and s.endswith(")"):
        return s[1:-1].strip()
    return s


def _split_cond_body(raw: str) -> tuple[str, str]:
    """把 'if (cond) body' 或 'while (cond) {' 切成 (cond, body)。

    bug 原因：正则 `\\((.*)\\)` 贪婪匹配，'if (a != "") set_cmt(...)' 里
    body 的 ')' 被当作条件结束，产生 'cmt != "") set_cmt(...' 破损语法。
    解决：从左扫描找与首个 '(' 配对的 ')'，其后才是 body。
    """
    raw = raw.strip()
    if not raw.startswith("("):
        return raw, ""
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(raw):
        c = raw[i]
        if quote is not None:
            if c == "\\" and i + 1 < len(raw):
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'"):
            quote = c
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return raw[1:i], raw[i + 1:].strip()
        i += 1
    return raw, ""


def _preprocess_idc(src: str) -> str:
    """单遍词法预处理：剥离 // 与 /* */ 注释并将 { } 拆行，严格跳过字符串字面量内部。"""
    out: list[str] = []
    i, n = 0, len(src)
    quote: str | None = None
    while i < n:
        ch = src[i]
        if quote is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if src.startswith("//", i):
            nl = src.find("\n", i + 2)
            if nl < 0:
                break
            out.append("\n")
            i = nl + 1
            continue
        if src.startswith("/*", i):
            end = src.find("*/", i + 2)
            if end < 0:
                break
            i = end + 2
            continue
        if ch in ("{", "}"):
            out.append(f"\n{ch}\n")
            i += 1
            continue
        out.append(ch)
        i += 1
    text = "".join(out)
    return re.sub(r"^\s*#include.*$", "", text, flags=re.M)


def _expr(s: str) -> str:
    """表达式翻译：! → not、&& → and、|| → or、BADADDR（跳过字符串字面量内部）。"""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(s)
    quote: str | None = None

    def _flush() -> None:
        if not buf:
            return
        seg = "".join(buf)
        buf.clear()
        seg = re.sub(r"!(?=[A-Za-z_0-9(])", "not ", seg)
        seg = seg.replace("&&", " and ").replace("||", " or ")
        seg = re.sub(r"\bBADADDR\b", str(BADADDR), seg)
        out.append(seg)

    while i < n:
        ch = s[i]
        if quote is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            _flush()
            quote = ch
            out.append(ch)
            i += 1
            continue
        buf.append(ch)
        i += 1
    _flush()
    return "".join(out)


# (2) 第二次修改（2026-11-26）
# bug 原因：① 注释剥离与 `{`/`}` 拆分此前直接跑全局正则，破坏字符串内的 URL（"http://..."）、
#           "/*...*/" 及 "{...}" 模板；② `auto x = 0x1000;` 被整行删除导致后续变量 NameError；
#           ③ 单行 `if (a) x=1; else if (b) x=2; else x=3;` 在遇到首条 else 时只取了当前片段
#           `body = p2` 而丢弃了 `parts[pi+1:]`，导致后续 else 分支静默丢失。
# 解决方案：① 改用 _preprocess_idc 词法扫描跳过双/单引号字符串；② auto 声明按顶层逗号拆分，
#           保留带 "=" 的初始化赋值语句；③ 抽取单行体链展开逻辑，将 `parts[pi:]` 完整拼接回送循环。
def _translate(src: str) -> str:
    src = _preprocess_idc(src)
    lines = [l.strip() for l in src.splitlines() if l.strip()]

    out: list[str] = []
    depth = 0

    def ind() -> str:
        return "    " * depth

    def _emit_inline_chain(body: str) -> None:
        """展开单行条件后的语句体及可能串联的 else if / else 尾巴。"""
        nonlocal depth
        while body:
            body = body.rstrip(";").strip()
            if not body:
                break
            em = re.match(r"^else\s+if\s*(.*)$", body, re.S)
            if em:
                cond2, body2 = _split_cond_body(em.group(1).strip())
                out.append(f"{ind()}elif {_expr(_strip_parens(cond2))}:")
                body = body2.strip()
                continue
            if re.match(r"^else(?:\b|\s|$)", body):
                tail2 = body[4:].strip().rstrip(";").strip()
                out.append(f"{ind()}else:")
                if tail2 and tail2 != "{":
                    depth += 1
                    out.append(ind() + _stmt(tail2))
                    depth -= 1
                body = ""
                continue
            parts = _split_top(body, ";")
            consumed_all = True
            for pi, part in enumerate(parts):
                p2 = part.strip()
                if not p2:
                    continue
                if re.match(r"^else(?:\b|\s|$)", p2):
                    body = "; ".join(p.strip() for p in parts[pi:] if p.strip())
                    consumed_all = False
                    break
                depth += 1
                out.append(ind() + _stmt(p2))
                depth -= 1
            if consumed_all:
                body = ""

    i = 0
    while i < len(lines):
        ln = lines[i]
        i += 1

        if ln == "{":
            depth += 1
            continue
        if ln == "}":
            depth = max(0, depth - 1)
            continue

        # 函数定义: static [type] name(args) [+ {]
        m = re.match(r"^(?:static\s+)?(?:int|void|auto|long|string|object)?\s*"
                     r"([A-Za-z_]\w*)\s*\((.*)\)\s*(\{)?$", ln)
        if m and not ln.startswith(("if", "while", "for", "else", "return")):
            params = ", ".join(
                re.sub(r"^(?:auto|int|long|string|object)\s+", "", p.strip()).split()[-1]
                for p in _split_top(m.group(2)) if p.strip()
            )
            out.append(f"{ind()}def {m.group(1)}({params}):")
            if not m.group(3):
                # 下一行应是 {
                if i < len(lines) and lines[i] == "{":
                    i += 1
            depth += 1
            continue

        # auto 声明：无初值声明删除（auto n, r;），带初值转为赋值（auto x = 0x1000; -> x = 0x1000）
        if re.match(r"^auto\s+", ln):
            rest = re.sub(r"^auto\s+", "", ln).strip().rstrip(";").strip()
            for decl in _split_top(rest, ","):
                d = decl.strip()
                if "=" in d:
                    out.append(ind() + _stmt(d))
            continue

        # return
        if re.match(r"^return(?:\b|\s|;|$)", ln):
            body = ln[len("return"):].strip().rstrip(";").strip()
            out.append(f"{ind()}return {_expr(body)}" if body else f"{ind()}return")
            continue

        # else / else if
        if ln.startswith("} else") or re.match(r"^else(?:\b|\s|$)", ln):
            rest = re.sub(r"^[\}\s]*else\s*", "", ln).strip()
            if re.match(r"^if(?:\s*\(|\b)", rest):
                cond2, body2 = _split_cond_body(rest[2:].strip())
                out.append(f"{ind()}elif {_expr(_strip_parens(cond2))}:")
                _emit_inline_chain(body2.strip())
                continue
            out.append(f"{ind()}else:")
            tail = rest.rstrip(";").strip()
            if tail and tail != "{":
                depth += 1
                out.append(ind() + _stmt(tail))
                depth -= 1
            elif tail == "{":
                depth += 1
            continue

        # if / while 单行或块
        m = re.match(r"^(if|while)\s*\((.*)\)\s*(\{)?(.*)$", ln)
        if m:
            raw = ln[len(m.group(1)):].strip()
            cond_s, body_s = _split_cond_body(raw)
            out.append(f"{ind()}{m.group(1)} {_expr(_strip_parens(cond_s))}:")
            _emit_inline_chain(body_s.strip())
            if not body_s.strip() and m.group(3):
                depth += 1
            continue

        # 普通语句
        out.append(ind() + _stmt(ln))
    return "\n".join(out)


def _stmt(s: str) -> str:
    """单条语句翻译。"""
    s = s.strip().rstrip(";").strip()
    s = _expr(s)
    return s


def run_idc(session: Session, so_name: str, source: str) -> dict:
    """执行 IDC 脚本。返回消息与转换结果。"""
    py = _translate(source)
    ctx = IdcContext(session, so_name)
    globs: dict = {
        "__builtins__": dict(_SAFE_BUILTINS),
        **{k: getattr(ctx, k) for k in dir(ctx) if not k.startswith("_")},
        "BADADDR": BADADDR,
        "DELIT_SIMPLE": DELIT_SIMPLE,
        "DELIT_EXPAND": DELIT_EXPAND,
        "DELIT_DELNAMES": DELIT_DELNAMES,
        "SN_NOCHECK": SN_NOCHECK,
        "SN_NOWARN": SN_NOWARN,
        "ctx": ctx,
        "session": session,
    }
    try:
        exec(compile(py, "<idc>", "exec"), globs)  # noqa: S102
        # IDC 语义：文件加载后自动执行 main()（IDA 的 Script file 行为）
        if "main" in globs and callable(globs["main"]):
            globs["main"]()
    except SyntaxError as e:
        return {"error": f"IDC 转换失败: {e}", "converted": py}
    except IdcError as e:
        return {"error": f"IDC 语义错误: {e}", "messages": ctx.messages}
    # (6) 第六次修改（2026-11-26）
    # bug 原因：IDC 运行期抛出的 NameError/TypeError 等异常（如被沙箱拦截的 __import__）
    #          未被 run_idc 捕获，会直接穿透到调用方导致未处理崩溃。
    # 解决方案：兜底捕获 Exception 转为结构化 error 字段返回，保留已输出 messages。
    except Exception as e:  # noqa: BLE001
        return {"error": f"IDC 运行错误: {type(e).__name__}: {e}", "messages": ctx.messages}
    named = sum(1 for f in session.get(so_name).functions.values() if f.name)
    return {"messages": ctx.messages, "named_functions": named, "converted_python": py}
