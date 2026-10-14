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

import re

from core.session import Session

BADADDR = 0xFFFFFFFFFFFFFFFF
# IDC 常量（用户脚本真实用到的）
DELIT_SIMPLE = 0
DELIT_EXPAND = 1
DELIT_DELNAMES = 2
SN_NOCHECK = 0
SN_NOWARN = 0x80


class IdcError(Exception):
    pass


class IdcContext:
    """IDC API 的 Python 实现，直接操作 Session。"""

    def __init__(self, session: Session, so_name: str):
        self.session = session
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
        from models import Function

        fn = self.so.functions.get(ea)  # 仅按起点精确匹配
        if fn is not None:
            return fn
        starts = sorted(a for a in self.so.functions if a > ea)
        nxt = starts[0] if starts else ea + 0x100
        size = max(0x10, min(nxt - ea, 0x10000))
        fn = Function(addr=ea, size=size, discovered_by="idc", so_name=self.so_name)
        self.so.functions[ea] = fn
        self._refresh_ranges()
        return fn

    def _refresh_ranges(self) -> None:
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
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            if not hasattr(self, "_probe_md"):
                self._probe_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
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
    """按顶层逗号切分（忽略括号/字符串内）。"""
    parts, depth, cur, i = [], 0, "", 0
    instr = False
    while i < len(s):
        c = s[i]
        if c == '"' and (i == 0 or s[i - 1] != "\\"):
            instr = not instr
        if not instr:
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
    instr = False
    for i, c in enumerate(raw):
        if c == '"' and (i == 0 or raw[i - 1] != "\\"):
            instr = not instr
        if instr:
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return raw[1:i], raw[i + 1:].strip()
    return raw, ""


def _expr(s: str) -> str:
    """表达式翻译：! → not、&& → and、|| → or。"""
    s = re.sub(r"!(?=[A-Za-z_0-9(])", "not ", s)
    s = s.replace("&&", " and ").replace("||", " or ")
    s = s.replace("BADADDR", str(BADADDR))
    return s


def _translate(src: str) -> str:
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"^\s*#include.*$", "", src, flags=re.M)

    # 词法拆行：把 { 和 } 拆成独立行（字符串内的不动）
    src = re.sub(r"\{", "\n{\n", src)
    src = re.sub(r"\}", "\n}\n", src)
    lines = [l.strip() for l in src.splitlines() if l.strip()]

    out: list[str] = []
    depth = 0

    def ind() -> str:
        return "    " * depth

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

        # auto 声明：删除（多变量声明 auto n, r;）
        if re.match(r"^auto\s", ln):
            continue

        # return
        if ln.startswith("return"):
            body = ln[len("return"):].strip().rstrip(";").strip()
            out.append(f"{ind()}return {_expr(body)}" if body else f"{ind()}return")
            continue

        # else / else if
        if ln.startswith("} else") or ln.startswith("else"):
            rest = re.sub(r"^[\}\s]*else\s*", "", ln).strip()
            if rest.startswith("if"):
                # BUG-15 修复：else if 行也用 _split_cond_body 精确切分条件与单行体
                #（旧实现 rest.find(")") 找第一个括号，嵌套调用时错位产生非法行）
                cond2, body2 = _split_cond_body(rest[2:].strip())
                out.append(f"{ind()}elif {_expr(_strip_parens(cond2))}:")
                tail = body2.strip().rstrip(";").strip()
                if tail and tail != "{":
                    depth += 1
                    out.append(ind() + _stmt(tail))
                    depth -= 1
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
        # BUG-15 修复：if 单行体可能自带 "else if ..." / "else ..." 尾巴
        #（IDC 惯用 if (a) x=1; else if (b) x=2; 单行链）。递归处理尾巴，
        # 避免生成 "elif (0) ok = 2:" 这类非法 Python。
        m = re.match(r"^(if|while)\s*\((.*)\)\s*(\{)?(.*)$", ln)
        if m:
            raw = ln[len(m.group(1)):].strip()
            cond_s, body_s = _split_cond_body(raw)
            out.append(f"{ind()}{m.group(1)} {_expr(_strip_parens(cond_s))}:")
            self_depth = depth
            body = body_s.strip()
            while body:
                body = body.rstrip(";").strip()
                if not body:
                    break
                # 尾巴是 else / else if → 同级续写
                em = re.match(r"^else\s+if\s*(.*)$", body, re.S)
                if em:
                    # 保留 "(cond) body" 完整结构交给 _split_cond_body
                    # （此前剥掉 "(" 导致 "(0) ok = 2" 变 "0) ok = 2"，条件切分错位）
                    cond2, body2 = _split_cond_body(em.group(1).strip())
                    out.append(f"{ind()}elif {_expr(_strip_parens(cond2))}:")
                    body = body2.strip()
                    continue
                if body.startswith("else"):
                    tail2 = body[4:].strip().rstrip(";").strip()
                    out.append(f"{ind()}else:")
                    if tail2 and tail2 != "{":
                        depth += 1
                        out.append(ind() + _stmt(tail2))
                        depth -= 1
                    body = ""
                    continue
                # 普通单行体：按顶层分号切分（单行可能含 "stmt1; stmt2"）
                # BUG-15 伴生修复：切分后若后续段以 else 开头，回送循环继续处理
                from scripting.idc import _split_top as _st
                parts = _st(body, ";")
                consumed_all = True
                for pi, part in enumerate(parts):
                    p2 = part.strip()
                    if not p2:
                        continue
                    if p2.startswith("else"):
                        body = p2
                        consumed_all = False
                        break
                    depth += 1
                    out.append(ind() + _stmt(p2))
                    depth -= 1
                if consumed_all:
                    body = ""
            if not body and m.group(3) and not body_s.strip():
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
        "__builtins__": __builtins__,
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
    named = sum(1 for f in session.get(so_name).functions.values() if f.name)
    return {"messages": ctx.messages, "named_functions": named, "converted_python": py}
