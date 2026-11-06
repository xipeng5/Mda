"""静态分析与动态分析的桥接层：把运行时地址 / 命中事件落回 mda 的静态模型。

为什么需要这一层（这是本项目区别于 unidbg 那类模拟器的护城河）：
    模拟器有完整的运行时视角，却没有静态分析层——它知道"执行到了哪个地址"，
    但说不清"这个地址属于哪个函数、谁调用它、它的伪代码长什么样"。
    mda 反过来：函数表 / xref / 伪代码 / 字符串齐全，但不知道运行时发生了什么。
    本模块把两边对上，全部是**纯本地计算**。

纯本地，不碰设备：
    本模块不 attach、不连接设备、不 import frida（dyn/rebase.py 顶层 import frida，
    这里刻意不引它——离线环境也必须能跑）。运行时模块表由调用方从
    dyn/service.py 或 dyn/rebase.py 取来后传进来；也接受 FakeRebase 与
    裸 dict 列表，便于离线单测（见 tests/fake_frida.py）。

对外约定：
    - 地址一律 hex() 字符串；需要一个整数去喂 mda 其它接口（decompile /
      list_functions / xrefs_to 这些接 int 的）时用同名的 *_int 字段。
    - 信息不足时**明确标注**而不是编造：
        * 运行时模块名匹配不上 mda 里的 so → loaded_in_mda=False，
          但仍给出 so（运行时名）+ static_addr，不丢信息；
        * 地址在模块内但没有函数覆盖 → in_gap=True、function=None，
          绝不拿邻近函数或 sub_xxx 冒充。

公开接口：
    locate_static(session, runtime_addr, modules=None)         运行时地址 → 静态定位
    hit_context(session, hit, modules=None, build_xrefs=False) 断点命中 → 完整静态上下文
    trace_to_timeline(events, session=None, modules=None)      事件流 → 函数级时间轴
    suggest_breakpoints(session, function_name_or_addr, so_name=None, limit=200)
    module_load_timeline(load_events)                          模块加载事件 → 加载时间轴
"""
from __future__ import annotations

import re

from core.disasm import Disassembler
from core.pseudocode import PseudocodeGenerator

# ---------------- 常量 ----------------

_INSN_SIZE = 4  # ARM64 定长指令，offset // 4 即"第几条指令"

_DISASM_WINDOW = 8  # hit_context 在命中点前后各展示多少条指令

# 引用图自动构建的函数数上限。inbound 调用者天然需要全库扫描
# （xref.calls_to），大样本要 20-30 秒；小模块（liblog 级 111 个函数）几十毫秒。
# 超过上限时不自动构建，转而如实报告"可能不全"，让调用方显式要完整结果。
_AUTO_BUILD_MAX_FUNCS = 500

_MAX_PSEUDOCODE_LINES = 400  # 伪代码截断行数（避免单条命中输出兆级文本）
_MAX_SUGGESTIONS = 200       # 建议断点默认上限
_MAX_CANDIDATES = 12         # 函数名歧义时列出的候选数

# 壳加在模块名前的前缀，如 _t1_liblog.so / _x2_libc.so
_PREFIX_RE = re.compile(r"^_[a-z0-9]{1,4}_", re.IGNORECASE)

_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


# ---------------- 基础工具（纯函数） ----------------


def _find_so(session, name: str):
    """在会话里按名字找 SoFile（复用 MCP 层的多级别名匹配，含去版本号）。"""
    try:
        from mcp_server.tools import _pick_so_by_name

        return _pick_so_by_name(session, name)
    except Exception:                                     # noqa: BLE001
        return (getattr(session, "modules", {}) or {}).get(name)


def _read_so_bytes(so, offset: int, size: int) -> bytes:
    """读 so 静态文件的原始字节（按段把虚拟地址换算成文件偏移）。

    (10) 第十次修改（2026-11-06）：新增。
        为什么需要：resolve_br 要从文件里读指针表；虚拟地址 ≠ 文件偏移，
                    直接 seek 会读错位置（尤其 BSS 之前的段对齐差异）。
    """
    fn = getattr(so, "read_bytes", None)
    if callable(fn):
        try:
            data = fn(int(offset), int(size))
            if data:
                return bytes(data)
        except Exception:                                 # noqa: BLE001
            pass
    path = getattr(so, "path", "") or ""
    if not path:
        return b""
    try:
        with open(path, "rb") as fh:
            for seg in (getattr(so, "_segments", None) or []):
                va = int(getattr(seg, "vaddr", 0) or 0)
                memsz = int(getattr(seg, "memsz", 0) or 0)
                if va <= offset < va + max(memsz, 1):
                    fh.seek(int(getattr(seg, "offset", 0) or 0) + (offset - va))
                    return fh.read(int(size))
            fh.seek(int(offset))
            return fh.read(int(size))
    except Exception:                                     # noqa: BLE001
        return b""


def _as_int(value) -> int | None:
    """把各种来源的地址值归一成 int。

    (8) 第八次修改（2026-11-05）：规则收口到 core.addr（原实现与其它三处不一致）。
    归一失败返回 None——**不用 0 兜底**，否则"取不到地址"会被误读成"地址是 0"。
    """
    from core.addr import parse_addr

    return parse_addr(value)

def _as_float(value) -> float | None:
    """时间戳归一（秒）。取不到返回 None，不伪造当前时间。"""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_addr(value) -> str | None:
    """int 地址 → hex 字符串；取不到返回 None。"""
    v = _as_int(value)
    return hex(v) if v is not None else None


def _pick(seq, **fields):
    """从 dict / dataclass / 普通对象里按字段名取值（先 dict 后属性）。"""
    for name in fields.values():
        if isinstance(seq, dict):
            if name in seq and seq[name] is not None:
                return seq[name]
        else:
            value = getattr(seq, name, None)
            if value is not None:
                return value
    return None


def _function_label(so_name: str, fn, addr: int | None = None, offset: int | None = None) -> str:
    """统一的符号写法：so!func+0xNN。

    与 dyn/debugger.py 的 _symbolize_backtrace 同形，避免同一函数
    在栈里和上下文里显示成两种样子。
    """
    if fn is None:
        if addr is not None:
            return f"{so_name}+{addr:#x}"
        return so_name or "?"
    name = fn.name or f"sub_{fn.addr:x}"
    off = offset if offset is not None else 0
    return f"{so_name}!{name}+{off:#x}"


def _norm_name(name: str) -> str:
    """模块名归一：取 basename、小写、去掉壳前缀（_t1_ 这类）。"""
    base = (name or "").rsplit("/", 1)[-1].lower().strip()
    m = _PREFIX_RE.match(base)
    if m and len(base) > m.end():
        base = base[m.end():]
    return base


def _stem(name: str) -> str:
    """去掉 .so 后缀的名字，用于 liblog 与 liblog.so 这类缺扩展名的匹配。"""
    n = _norm_name(name)
    return n[:-3] if n.endswith(".so") else n


# ---------------- 运行时模块表归一 ----------------


def _norm_modules(modules) -> list[dict]:
    """运行时模块表 → [{name, base, size, end, path}]。

    兼容四种形态（调用方从不同层拿到的模块表长得不一样）：
      - None
      - [{name, base, size}, ...]（服务层 JSON / FakeModule）
      - [RuntimeModule(...)]（dyn/rebase.py 的对象，属性访问）
      - Rebase / FakeRebase 实例（读它的 _modules）
    base 取不到的条目直接丢弃（没有基址就无法换算，留着只会误导）。
    """
    if modules is None:
        return []
    if isinstance(modules, dict):
        # 也接受 {name: base} 这种简写；有 size 的按 dict-of-dict
        out = []
        for key, val in modules.items():
            if isinstance(val, dict):
                item = dict(val)
                item.setdefault("name", key)
            else:
                item = {"name": key, "base": val, "size": 0}
            out.append(item)
        modules = out
    else:
        inner = getattr(modules, "_modules", None)
        if inner is None:
            inner = getattr(modules, "modules", None)
        if inner is not None and not isinstance(inner, (list, tuple)):
            inner = None
        modules = inner if inner is not None else modules

    out = []
    for item in modules or []:
        if isinstance(item, dict):
            name = item.get("name") or item.get("path") or ""
            base = _as_int(item.get("base"))
            size = _as_int(item.get("size")) or 0
            path = item.get("path") or ""
        else:
            name = getattr(item, "name", "") or getattr(item, "path", "") or ""
            base = _as_int(getattr(item, "base", None))
            size = _as_int(getattr(item, "size", None)) or 0
            path = getattr(item, "path", "") or ""
        if base is None:
            continue
        out.append({"name": str(name), "base": base, "size": size,
                    "end": base + size, "path": str(path), "size_inferred": False})

    # (4) 第四次修改（2026-11-05）：给 size=0 的模块推断一个上界。
    #     bug 原因：`{模块名: 基址}` 是文档承诺的简写，但简写没有 size，
    #               于是 end == base，而 _module_containing 用 `base <= addr < end`
    #               判断 —— 该模块**永远不可能命中**，一律报"地址不在任何已知模块区间"。
    #               简写因此完全不可用，和文档矛盾。
    #     解决方案：按基址排序后，把 size==0 的模块上界取为"下一个更高基址的模块起点"；
    #               若它是最后一个，用一个保守的默认跨度。同时打 size_inferred=True，
    #               让调用方知道这个上界是推断出来的、不是实测的。
    if out:
        ordered = sorted(out, key=lambda m: m["base"])
        default_span = 0x1000000          # 16MB：足以覆盖绝大多数 so，又不至于离谱
        for i, item in enumerate(ordered):
            if item["size"] > 0:
                continue
            nxt = None
            for later in ordered[i + 1:]:
                if later["base"] > item["base"]:
                    nxt = later["base"]
                    break
            end = nxt if nxt is not None else item["base"] + default_span
            item["end"] = end
            item["size"] = end - item["base"]
            item["size_inferred"] = True
        out = ordered
    return out


def _module_containing(modules: list[dict], addr: int) -> dict | None:
    """地址落在哪个模块内。多模块区间重叠时取最窄的那个（最具体）。"""
    hits = [m for m in modules if m["base"] <= addr < m["end"]]
    if not hits:
        return None
    return min(hits, key=lambda m: m["size"] or (1 << 62))


# ---------------- 运行时模块名 → mda 里的 SoFile ----------------


def _prefer(pairs: list[tuple[str, object]], static_addr: int | None):
    """多个同名候选时挑最可能的一个：能覆盖该静态地址的优先。"""
    if static_addr is not None:
        for key, so in pairs:
            try:
                if so.in_load(static_addr):
                    return key, so
            except Exception:                                # noqa: BLE001
                continue
    return sorted(pairs, key=lambda kv: kv[0])[0]


def _match_so(session, name: str, path: str = "", static_addr: int | None = None):
    """运行时模块名 → (mda 里的 key, SoFile, 匹配方式)。

    降级链（逐级放宽，命中即止）：
      1. exact      名字完全一致
      2. renamed    mda 里同名 so 被自动改名（Session.add 的 liblog.so_2）
      3. normalized 去掉路径/大小写/壳前缀（_t1_）后一致
      4. stem       去 .so 扩展名后一致（liblog vs liblog.so）
      5. suffix     互相后缀包含（_t1_liblog.so ↔ liblog.so）
    全都不中返回 (None, None, None)——调用方据此标 loaded_in_mda=False，
    但**仍然保留 so 名与 static_addr**，不丢信息。
    """
    cands = []
    for n in (name, (path or "").rsplit("/", 1)[-1]):
        n = (n or "").strip()
        if n and n not in cands:
            cands.append(n)
    if not cands:
        return None, None, None

    mods = getattr(session, "modules", {}) or {}

    # 1 精确
    for n in cands:
        if n in mods:
            return n, mods[n], "exact"

    # 2 mda 记录的原名（同名 so 加载两次会被改名成 xxx_2.so）
    for key, so in mods.items():
        if getattr(so, "renamed_from", None) in cands:
            return key, so, "renamed"

    # 3 归一化后同名
    want = {_norm_name(c) for c in cands}
    same = [(k, s) for k, s in mods.items() if _norm_name(k) in want]
    if same:
        key, so = _prefer(same, static_addr)
        return key, so, "normalized" if len(same) == 1 else "normalized(multi)"

    # 4 去扩展名比较
    want_stem = {_stem(c) for c in cands}
    same = [(k, s) for k, s in mods.items() if _stem(k) in want_stem]
    if same:
        key, so = _prefer(same, static_addr)
        return key, so, "stem"

    # 5 后缀互含。名字太短时前缀包含会误匹配（a.so / so），故限长度。
    short = [(k, s) for k, s in mods.items()
             if any(len(_norm_name(k)) >= 5 and len(w) >= 5
                    and (_norm_name(k).endswith(w) or w.endswith(_norm_name(k)))
                    for w in want)]
    if short:
        key, so = _prefer(short, static_addr)
        return key, so, "suffix"
    return None, None, None


def _plt_info(so, static: int) -> tuple[bool, str | None, str | None]:
    """地址是否落在导入跳板区，返回 (是否, 导入符号名, 说明)。

    两条通路都要覆盖（不同样本走不同通路）：
      - 段表模式扫描出的 plt_stubs：只有地址、没有符号名（节表被抹的加固样本）；
      - 有节表时的 .plt 节 + plt_map：能给出真实导入符号名。
    plt_map 的键是桩**起点**，命中桩内部时符号名取不到，此时只说明区域，
    **不猜**是哪一条导入——桩内部无法从地址反推符号。
    """
    try:
        if so.in_plt_stub(static):
            return True, so.plt_name(static), "地址落在 PLT 桩内（外部导入跳板），不是真实函数体"
    except Exception:                                        # noqa: BLE001
        pass
    name = None
    try:
        name = so.plt_name(static)
    except Exception:                                        # noqa: BLE001
        name = None
    if name:
        return True, name, f"地址是 PLT 桩起点，对应导入符号 {name}（外部函数，本 so 无函数体）"
    try:
        sec = so.section_at(static)
    except Exception:                                        # noqa: BLE001
        sec = None
    if sec is not None and sec.name.startswith(".plt"):
        return True, None, f"地址落在 {sec.name} 节（导入跳板区），具体导入符号无法从地址反推"
    return False, None, None


def _static_from_runtime(so, runtime_addr: int, base: int) -> tuple[int, str]:
    """运行时地址 → 静态地址（静态基址按 0 计，同 dyn/rebase.Rebase.to_static）。

    少数 dump 样本的首个 PT_LOAD 不从 0 开始，此时直接相减会把整段地址
    偏到函数表之外；再按首个 PT_LOAD 的 vaddr 归一试一次。
    返回 (静态地址, 归一说明)。
    """
    static = runtime_addr - base
    try:
        in_load = so.in_load(static)
    except Exception:                                        # noqa: BLE001
        in_load = True
    if not in_load:
        try:
            bias = min((m["addr"] for m in so.maps()), default=0)
        except Exception:                                    # noqa: BLE001
            bias = 0
        if bias > 0 and so.in_load(static + bias):
            return static + bias, f"按首个 PT_LOAD 基址 {hex(bias)} 归一"
    return static, ""


# ---------------- 函数名解析 ----------------


def _resolve_function(session, name_or_addr, so_name: str | None = None):
    """函数名或地址 → (so_key, SoFile, Function) 或 (None, None, 错误 dict)。

    支持：int 地址、"0x5020" 十六进制串、"sub_5020"、"foo"、"so!foo"。
    重名且无法消歧时**返回候选列表而不是猜一个**。
    """
    mods = getattr(session, "modules", {}) or {}
    if not mods:
        return None, None, {"error": "会话内没有任何已加载的 so，先 load_so"}

    # 显式给了 so_name：先把它解析成真实 key（容忍 _t1_ 前缀等差异）
    pinned = None
    if so_name:
        key, so, _how = _match_so(session, so_name)
        if key is None:
            return None, None, {
                "error": f"未加载的 so: {so_name}",
                "loaded_modules": list(mods),
            }
        pinned = (key, so)

    # ---- 形态 1：地址 ----
    # (1) 第一次修改
    # bug 原因："so!func" 形式在下面切出 tail 后没有留存，落到形态 2 时
    #           仍拿原始整串去函数表里找，导致 suggest_breakpoints("liblog.so!foo")
    #           恒报"未找到函数"（自测 t4 抓到）。
    # 解决方案：切分结果记到 name_text，形态 2 一律用它。
    name_text = str(name_or_addr or "").strip()
    addr = None
    if isinstance(name_or_addr, int) and not isinstance(name_or_addr, bool):
        addr = name_or_addr
    elif isinstance(name_or_addr, str):
        text = name_text
        if "!" in text:
            head, _, tail = text.partition("!")
            if not so_name:
                key, so, _how = _match_so(session, head)
                if key is not None:
                    pinned = (key, so)
            text = tail.strip()
            name_text = text
        if text.lower().startswith("0x") and _HEX_RE.match(text):
            try:
                addr = int(text, 16)
            except ValueError:
                addr = None
        elif text.lower().startswith("sub_"):
            try:
                addr = int(text[4:], 16)
            except ValueError:
                addr = None
        elif _HEX_RE.match(text) and not re.search(r"[a-fA-F]{4,}", text):
            # 纯数字串按十进制地址处理（GUI/MCP 常直接传十进制）
            try:
                addr = int(text)
            except ValueError:
                addr = None
    if addr is not None:
        scope = [pinned] if pinned else list(mods.items())
        for key, so in scope:
            fn = so.function_at(addr)
            if fn is not None:
                return key, so, fn
        # 地址存在但无函数覆盖：如实说明，不拿邻近函数冒充
        scope_name = pinned[0] if pinned else "全部模块"
        return None, None, {
            "error": f"地址 {addr:#x} 处没有函数覆盖（{scope_name}）",
            "in_gap": True,
            "static_addr": hex(addr),
        }

    # ---- 形态 2：函数名 ----
    want = name_text        # 已剥掉 "so!" 前缀的纯函数名
    if not want:
        return None, None, {"error": "函数名为空"}

    scope = [pinned] if pinned else list(mods.items())
    exact: list[tuple[str, object, object]] = []
    loose: list[tuple[str, object, object]] = []
    lower = want.lower()
    for key, so in scope:
        for fn in so.functions.values():
            fname = fn.name or ""
            if fname == want:
                exact.append((key, so, fn))
            elif fname and fname.lower() == lower:
                loose.append((key, so, fn))
    hits = exact or loose
    if len(hits) == 1:
        return hits[0][0], hits[0][1], hits[0][2]
    if len(hits) > 1:
        return None, None, {
            "error": f"函数名 {want} 在多个 so 里存在，请用 so_name 指定",
            "candidates": [f"{k}!{fn.name} @ {fn.addr:#x}" for k, _so, fn in hits[:_MAX_CANDIDATES]],
        }

    # 没命中：给包含该子串的候选，避免用户盲猜
    similar = []
    for key, so in scope:
        for fn in so.functions.values():
            if fn.name and lower in fn.name.lower():
                similar.append(f"{key}!{fn.name} @ {fn.addr:#x}")
                if len(similar) >= _MAX_CANDIDATES:
                    break
    return None, None, {"error": f"未找到函数: {want}", "candidates": similar}


# ---------------- 引用图（调用者） ----------------


def _xref(session, so_key: str):
    """取该 so 的 Xref；会话里没有（理论上不会）就临时建一个。"""
    try:
        return session.xref(so_key)
    except Exception:                                        # noqa: BLE001
        return None


def _callers(session, so_key: str, fn_addr: int, build_xrefs: bool = False) -> tuple[list, bool, list]:
    """查"谁调用了这个函数"（模块内），返回 (调用点列表, 是否完整, 说明)。

    入向引用天然需要全库反汇编（xref.build）。策略：
      - 已建过：直接用；
      - 未建过且模块足够小（<= _AUTO_BUILD_MAX_FUNCS）：自动建，结果完整；
      - 未建过且模块很大：不自动建（20-30 秒的代价不该藏在一次查询里），
        如实返回"可能不全"以及怎么拿完整结果。
    """
    notes: list[str] = []
    x = _xref(session, so_key)
    if x is None:
        return [], False, ["该 so 没有引用图，调用者信息不可用"]
    built = bool(getattr(x, "_built", False))
    # (2) 第二次修改（2026-11-02）：必须走 session.ensure_xrefs，不能直接 x.build()。
    #     bug 原因：build() 只反汇编「当前函数表里已有的函数」，而壳样本的 FDE
    #               会漏掉大量函数（实测 libAPSE 级样本漏 1457 个）。这些函数
    #               从未被反汇编，它们发出的调用边永远不可见。直接 build() 之后
    #               即便再补 discover 重建，已缓存的空结果也不会回填，于是输出
    #               「该函数没有被任何函数调用」——一个 complete=True 的假结论。
    #               ensure_xrefs(discover=True) 会先补全函数表再 build，边才完整。
    #     解决方案：自动构建时改调 session.ensure_xrefs(so_key, discover=True)；
    #               老 session 没有该方法时退回 x.build()，并在 notes 里明确标注
    #               「未先补全函数表、边可能缺失」，不让调用方误以为结果完整。
    if not built:
        so = session.get(so_key)
        n_fn = len(so.functions)
        if build_xrefs or n_fn <= _AUTO_BUILD_MAX_FUNCS:
            ensure = getattr(session, "ensure_xrefs", None)
            if callable(ensure):
                ensure(so_key, discover=True)
                built = True
                notes.append("引用图为本次查询自动构建（先补全函数表再建，"
                             f"现有 {len(so.functions)} 个函数）")
            else:
                x.build()
                built = True
                notes.append(
                    f"引用图用旧接口 x.build() 构建（{n_fn} 个函数），"
                    "**未先补全函数表**：FDE 未覆盖的函数不会被反汇编，"
                    "其发出的调用边缺失；需要完整结果请先调 session.ensure_xrefs()"
                )
        else:
            notes.append(
                f"引用图未构建且模块函数数 {n_fn} 超过自动构建上限 "
                f"{_AUTO_BUILD_MAX_FUNCS}，调用者可能不全；"
                f"传 build_xrefs=True（或先调 ensure_xrefs）取完整结果"
            )
    sites = sorted(set(x._calls_to.get(fn_addr, [])))

    # (7) 第七次修改（2026-11-05）：本 so 建好图 ≠ 调用者齐全。
    #     bug 原因：`complete` 只反映"本 so 的引用图建了没有"。但一个导出函数
    #               完全可能被**别的 so** 调用，而那条边记在对方的图里；
    #               对方图没建时，它根本不会出现在结果中，于是返回
    #               callers_complete=True + 空列表 —— 等于断言"没人调用它"。
    #               实测 build_xrefs=False 时 libbase._built=False 却仍报 complete=True。
    #     解决方案：complete 为 True 时再检查会话里其他 so 的图是否已建；
    #               有未建的就降级为 False 并写明"跨 so 调用者可能缺失"。
    if built:
        unbuilt = []
        for other_key, other in (getattr(session, "modules", {}) or {}).items():
            if other_key == so_key:
                continue
            try:
                ox = _xref(session, other_key)
            except Exception:                             # noqa: BLE001
                continue
            if not bool(getattr(ox, "_built", False)):
                unbuilt.append(other_key)
        if unbuilt:
            built = False
            shown = "、".join(sorted(unbuilt)[:5])
            more = "" if len(unbuilt) <= 5 else f" 等 {len(unbuilt)} 个"
            notes.append(
                f"本 so 的引用图已建，但还有 {len(unbuilt)} 个 so 未建图"
                f"（{shown}{more}）：跨 so 调用者可能缺失，**不能据此断定"
                "\"没有被任何函数调用\"**；需要完整结果请对这些 so 也建图")
    return sites, built, notes


def _caller_items(session, so_key: str, fn_addr: int, build_xrefs: bool = False) -> tuple[list, bool, list]:
    """调用者列表：本 so 内的调用点 + 其它 so 经 PLT 的跨 so 调用。"""
    so = session.get(so_key)
    sites, complete, notes = _callers(session, so_key, fn_addr, build_xrefs)
    items = []
    for site in sites:
        caller = so.function_at(site)
        items.append({
            "so": so_key,
            "function": (caller.name or f"sub_{caller.addr:x}") if caller else None,
            "function_addr": _as_addr(caller.addr) if caller else None,
            "site": hex(site),
            "via_plt": False,
        })

    # 跨 so：别的模块经 PLT 调到这里。只在对方的引用图已经建好时顺手带出，
    # 绝不为了这个再触发一次全量构建（那是 session.callers_of 的活）。
    fn = so.function_at(fn_addr)
    if fn is not None and fn.name and fn.name != f"sub_{fn.addr:x}":
        for other, ox in (getattr(session, "_xrefs", {}) or {}).items():
            if other == so_key or not getattr(ox, "_built", False):
                continue
            other_so = session.modules.get(other)
            if other_so is None:
                continue
            for stub, sym in other_so.plt_map.items():
                if sym != fn.name:
                    continue
                for site in sorted(set(ox._calls_to.get(stub, []))):
                    caller = other_so.function_at(site)
                    items.append({
                        "so": other,
                        "function": (caller.name or f"sub_{caller.addr:x}") if caller else None,
                        "function_addr": _as_addr(caller.addr) if caller else None,
                        "site": hex(site),
                        "via_plt": True,
                    })
    return items, complete, notes


# ---------------- 伪代码 ----------------


def _resolver(session):
    """给 PseudocodeGenerator 的跨 so 命名回调。

    PseudocodeGenerator._name_of 期望 (so_name, target) -> (so, name, addr)。
    Session.resolve_call 已经是跨 so 解析（PLT -> 导入 -> 目标 so），这里只做形态转换。
    """

    def _resolve(so_name: str, target: int):
        try:
            link = session.resolve_call(so_name, target)
        except Exception:                                    # noqa: BLE001
            return None
        if link is None:
            return None
        return (link.callee_so, link.callee, link.callee_addr)

    return _resolve


def _pseudocode(session, so_key: str, fn_addr: int) -> tuple[str | None, list]:
    """生成函数伪代码（复用 core/pseudocode.py），超长截断。"""
    notes: list[str] = []
    so = session.get(so_key)
    x = _xref(session, so_key)
    disasm = getattr(x, "disasm", None) or Disassembler(so)
    try:
        text = PseudocodeGenerator(so, disasm).generate(fn_addr, resolve=_resolver(session))
    except Exception as exc:                                 # noqa: BLE001
        return None, [f"伪代码生成失败：{type(exc).__name__}: {exc}"]
    if not text:
        return None, notes
    lines = text.splitlines()
    if len(lines) > _MAX_PSEUDOCODE_LINES:
        notes.append(f"伪代码已截断（共 {len(lines)} 行，保留前 {_MAX_PSEUDOCODE_LINES} 行）")
        lines = lines[:_MAX_PSEUDOCODE_LINES] + ["// ... 已截断"]
    return "\n".join(lines), notes


# ---------------- 反汇编窗口 ----------------


def _disasm_window(session, so_key: str, fn, static_addr: int) -> tuple[list, int | None, int]:
    """函数内命中点附近的指令片段。

    返回 (片段, 命中指令下标, 函数指令总数)。下标先按地址精确匹配，
    再退化为 (static - fn.addr) // 4 —— .data 伪指令也是 4 字节，不会错位。
    """
    so = session.get(so_key)
    x = _xref(session, so_key)
    disasm = getattr(x, "disasm", None) or Disassembler(so)
    insns = disasm.disasm_function(fn.addr) if fn is not None else []
    total = len(insns)
    if not insns:
        return [], None, 0
    idx = next((i for i, ins in enumerate(insns) if ins.addr == static_addr), None)
    if idx is None:
        guess = (static_addr - fn.addr) // _INSN_SIZE
        idx = max(0, min(guess, total - 1))
    lo = max(0, idx - _DISASM_WINDOW)
    hi = min(total, idx + _DISASM_WINDOW + 1)
    items = []
    for i in range(lo, hi):
        ins = insns[i]
        items.append({
            "index": i,
            "addr": hex(ins.addr),
            "text": ins.text,
            "is_hit": ins.addr == static_addr,
            "is_call": bool(ins.is_call),
            "is_ret": bool(ins.is_ret),
            "target": _as_addr(ins.call_target) if ins.call_target is not None and ins.call_target >= 0 else None,
            "ref": _as_addr(ins.ref_addr),
        })
    return items, idx, total


# ---------------- 1. 运行时地址 → 静态定位 ----------------


def locate_static(session, runtime_addr, modules=None) -> dict:
    """运行时地址 → 静态定位。

    参数：
        session      core.session.Session
        runtime_addr 运行时地址（int 或 "0x..." 字符串）
        modules      运行时模块表（[{name, base, size}] / RuntimeModule 列表 /
                     Rebase|FakeRebase 实例）；为 None 时退化：只回地址，明确说明缺模块表

    返回字段（地址一律 hex 字符串）：
        so / module_name / module_base / module_size / module_end
        static_addr(+_int) / function / function_addr(+_int) / function_size
        offset(+_int)  命中点相对函数起点的字节偏移
        insn_index     第几条指令（offset // 4），函数未知时为 None
        in_gap         模块内但没有函数覆盖（此时 function=None，不编造）
        in_plt_stub / plt_name  落在 PLT 桩（外部导入跳板）时的说明
        section        所属节名（无节表的样本为 None）
        loaded_in_mda  该模块能否在 mda 会话里找到对应 so
        module_match   名字匹配方式：exact / renamed / normalized / stem / suffix
        notes          降级与异常说明
    """
    ra = _as_int(runtime_addr)
    out = {
        "runtime_addr": _as_addr(ra),
        "so": None,
        "module_name": None,
        "module_base": None,
        "module_size": None,
        "module_end": None,
        "static_addr": None,
        "static_addr_int": None,
        "function": None,
        "function_addr": None,
        "function_addr_int": None,
        "function_size": None,
        "offset": None,
        "offset_int": None,
        "insn_index": None,
        "in_gap": False,
        "in_plt_stub": False,
        "plt_name": None,
        "section": None,
        "loaded_in_mda": False,
        "module_match": None,
        "notes": [],
    }
    if ra is None:
        out["notes"].append("runtime_addr 无法解析为整数地址")
        return out

    mods = _norm_modules(modules)
    if not mods:
        out["notes"].append(
            "未提供运行时模块表（modules），无法确定模块基址；"
            "请从 dyn/service.py 或 dyn/rebase.py 取模块表后传入"
        )
        return out

    mod = _module_containing(mods, ra)
    if mod is None:
        near = sorted(mods, key=lambda m: abs(m["base"] - ra))[:3]
        out["notes"].append("运行时地址不落在任何已知模块区间内")
        out["nearby_modules"] = [
            {"name": m["name"], "base": hex(m["base"]), "end": hex(m["end"])} for m in near
        ]
        return out

    out["module_name"] = mod["name"] or None
    out["module_base"] = hex(mod["base"])
    out["module_size"] = hex(mod["size"])
    out["module_end"] = hex(mod["end"])

    key, so, how = _match_so(session, mod["name"], mod["path"], None)
    out["so"] = key or (mod["name"] or None)   # 匹配不上也保留运行时名，不丢信息
    out["module_match"] = how

    # 静态地址先算出来——即使 mda 没加载该 so，这个信息也是有价值的
    probe_so = so
    if probe_so is not None:
        static, basis = _static_from_runtime(probe_so, ra, mod["base"])
        if basis:
            out["notes"].append(basis)
        out["static_addr"] = hex(static)
        out["static_addr_int"] = static
    else:
        out["static_addr"] = hex(ra - mod["base"])
        out["static_addr_int"] = ra - mod["base"]

    if so is None:
        out["loaded_in_mda"] = False
        out["notes"].append(
            f"mda 会话里没有与运行时模块 {mod['name']!r} 对应的 so；"
            f"已按模块基址换算出静态地址 {out['static_addr']}，"
            f"加载该 so 后即可解析函数名"
        )
        return out

    out["loaded_in_mda"] = True
    static = out["static_addr_int"]

    # 函数归属：先判导入跳板（.plt 节 / 段表扫出的桩），再查函数表。
    # 顺序很重要：跳板区里的地址即使被 FDE 误登记成函数也不能当真实函数报。
    in_stub, plt_name, plt_note = _plt_info(so, static)
    if in_stub:
        out["in_plt_stub"] = True
        out["in_gap"] = True   # 跳板区确实没有函数覆盖，与 in_plt_stub 一起说明原因
        out["plt_name"] = plt_name
        notes_tail = ""
        if plt_name is None and not so.plt_stubs:
            notes_tail = "；符号未知（节表被抹的样本无法恢复导入名）"
        out["notes"].append(plt_note + notes_tail)

    fn = None if in_stub else so.function_at(static)
    if fn is not None:
        off = static - fn.addr
        out["function"] = fn.name or f"sub_{fn.addr:x}"   # 未命名函数的既有约定写法
        out["function_addr"] = hex(fn.addr)
        out["function_addr_int"] = fn.addr
        out["function_size"] = hex(fn.size)
        out["offset"] = hex(off)
        out["offset_int"] = off
        out["insn_index"] = off // _INSN_SIZE
        if off % _INSN_SIZE:
            out["notes"].append(
                f"命中点不在指令边界上（偏移 {off}%4={off % 4}），"
                f"insn_index 按 {off // _INSN_SIZE} 取整"
            )
    elif not in_stub:
        out["in_gap"] = True
        out["notes"].append("地址在模块内但没有函数覆盖（函数空洞或数据区），不猜测函数名")

    sec = None
    try:
        sec = so.section_at(static)
    except Exception:                                        # noqa: BLE001
        sec = None
    out["section"] = sec.name if sec is not None else None
    return out


# ---------------- 2. 断点命中 → 完整静态上下文 ----------------


def _norm_hit(hit, modules) -> tuple[dict, dict | None]:
    """命中对象归一。接受 dict / BreakpointHit dataclass / 它们的列表。

    列表语义：取**最后一个**（最近一次命中），并在说明里标明来源，
    避免调用方以为是"全部命中"。
    """
    meta = {}
    if isinstance(hit, (list, tuple)):
        if not hit:
            return {}, {"note": "传入的命中列表为空"}
        meta["hit_from_list"] = len(hit)
        hit = hit[-1]
    fields = {
        "so_name": _pick(hit, a="so_name", b="so"),
        "static_addr": _as_int(_pick(hit, a="static_addr", b="static")),
        "runtime_addr": _as_int(_pick(hit, a="runtime_addr", b="runtime", c="pc")),
        "thread_id": _as_int(_pick(hit, a="thread_id", b="tid")),
        "ts": _as_float(_pick(hit, a="ts")),
        "seq": _as_int(_pick(hit, a="seq")),
        "type": _pick(hit, a="type"),
        "context": _pick(hit, a="context", b="ctx") or {},
        "backtrace": _pick(hit, a="backtrace", b="bt") or [],
        "token": _pick(hit, a="token"),
        "held": _pick(hit, a="held"),
    }
    fields["so_name"] = str(fields["so_name"] or "")
    if not isinstance(fields["backtrace"], (list, tuple)):
        fields["backtrace"] = [str(fields["backtrace"])]
    fields["backtrace"] = [str(x) for x in fields["backtrace"]]
    return fields, meta


def hit_context(session, hit, modules=None, build_xrefs: bool = False) -> dict:
    """断点命中 → 完整静态上下文（#15 的核心）。

    参数：
        session      core.session.Session
        hit          命中对象：dict 或 dyn/debugger.BreakpointHit，也可以是
                     dyn/service.py poll_events / hits 返回的列表（取最后一条）
        modules      可选运行时模块表。只在 hit 缺 static_addr、需要靠
                     runtime_addr 反算时用到
        build_xrefs  True 时强制构建引用图，保证"调用者"完整（大样本很慢）

    返回：
        hit            命中回显（so_name / static_addr / runtime_addr / thread_id / ts）
        symbol         统一符号：so!func+0xNN
        loaded_in_mda  mda 里是否找到该 so
        function       {name, addr, size}（找不到时为 None，不编造）
        insn_index     命中的是函数第几条指令（offset // 4）
        insn_offset    相对函数起点的字节偏移
        disasm         命中点前后各 _DISASM_WINDOW 条指令（is_hit 标出命中那条）
        pseudocode     整个函数的伪代码（core/pseudocode.py 生成，超长截断）
        callers        调用者列表（模块内 + 已知的跨 so 经 PLT 调用）
        callers_complete  调用者是否完整（引用图未建时为 False，勿当全量）
        notes          降级说明
    """
    fields, meta = _norm_hit(hit, modules)
    notes: list[str] = []
    if meta.get("note"):
        notes.append(meta["note"])
    if meta.get("hit_from_list"):
        notes.append(f"传入的是命中列表（{meta['hit_from_list']} 条），取最后一条分析")

    out = {
        "hit": {
            "so_name": fields.get("so_name") or None,
            "static_addr": _as_addr(fields.get("static_addr")),
            "runtime_addr": _as_addr(fields.get("runtime_addr")),
            "thread_id": fields.get("thread_id"),
            "ts": fields.get("ts"),
            "seq": fields.get("seq"),
            "type": fields.get("type"),
        },
        "symbol": None,
        "so": fields.get("so_name") or None,
        "loaded_in_mda": False,
        "in_gap": False,
        "function": None,
        "insn_index": None,
        "insn_offset": None,
        "insn_offset_int": None,
        "disasm": [],
        "disasm_total": 0,
        "pseudocode": None,
        "callers": [],
        "callers_complete": False,
        "backtrace": fields.get("backtrace") or [],
        "context": fields.get("context") or {},
        "notes": notes,
    }

    # 静态地址：命中对象通常自带（dyn/debugger 已换算好），缺了才靠运行时表反算
    static = fields.get("static_addr")
    if static is None and fields.get("runtime_addr") is not None and modules is not None:
        loc = locate_static(session, fields["runtime_addr"], modules)
        static = loc.get("static_addr_int")
        out["so"] = loc.get("so") or out["so"]
        out["loaded_in_mda"] = bool(loc.get("loaded_in_mda"))
        if loc.get("in_gap"):
            out["in_gap"] = True
        notes.extend(loc.get("notes") or [])
        # (3) 第三次修改（2026-11-05）：反算失败要**立刻返回**，不能继续往下走。
        #     bug 原因：原实现先记一条"已按运行时模块表反算"，却不检查结果是否为 None，
        #               于是后续 hex(static) / in_load(static) / function_at(static)
        #               全部吃到 None，抛
        #               "TypeError: '<' not supported between instances of 'NoneType' and 'int'"。
        #               文档承诺的"模块表缺失时退化为只回地址"因此完全不可用，
        #               MCP 只能回 HIT_CONTEXT_FAILED。
        #     解决方案：static 为 None 就直接把已收集到的信息返回（保留 runtime_addr
        #               与 notes），并在 note 里写明"没能反算出静态地址"及原因。
        if static is None:
            notes.append(
                "运行时地址无法反算成静态地址（模块区间未覆盖该地址或模块表不完整）；"
                "已保留运行时地址，函数上下文不可得")
            out["notes"] = notes
            return out
        notes.append("命中对象缺 static_addr，已按运行时模块表反算")
    elif static is None:
        notes.append("命中对象既无 static_addr 也无可用运行时模块表，无法定位到静态模型")
        return out

    # 命中对象里的 so 名可能与 mda 里的 key 不同（含路径 / _t1_ 前缀），统一匹配
    key = None
    if out["so"]:
        key, so, how = _match_so(session, out["so"])
        if key is None:
            notes.append(
                f"mda 会话里没有与命中 so {out['so']!r} 对应的模块；"
                f"已保留静态地址 {hex(static)}，加载该 so 后即可解析函数"
            )
            out["in_gap"] = True
            return out
        if how not in (None, "exact"):
            notes.append(f"运行时 so 名与 mda 模块名不一致，按 {how} 规则匹配到 {key}")
        out["so"] = key
        out["loaded_in_mda"] = True
    else:
        # 命中没带 so 名：按 static_addr 在已加载模块里找唯一覆盖者
        # (1) 第一次修改
        # bug 原因：该分支只赋了局部 key，没有回填 out["so"]/loaded_in_mda，
        #           自测里"无 so 名的命中"能定位到函数却返回 so=None，
        #           调用方会误判成"未加载"。
        # 解决方案：判定成功后一并回填 out["so"] 与 loaded_in_mda。
        near = [k for k, s in session.modules.items()
                if getattr(s, "in_load", lambda _a: False)(static)]
        if len(near) == 1:
            key = near[0]
            out["so"] = key
            out["loaded_in_mda"] = True
            notes.append(f"命中未带 so 名，按静态地址唯一落在 {key} 判定归属")
        else:
            notes.append("命中既无 so 名也无法按地址唯一确定模块，无法给出函数上下文")
            return out

    so = session.get(key)
    in_stub, plt_name, plt_note = _plt_info(so, static)
    if in_stub:
        notes.append(plt_note)
        if plt_name:
            out["plt_name"] = plt_name
        out["symbol"] = f"{key}!{plt_name}" if plt_name else f"{key}+{static:#x}"
        out["in_gap"] = True
        return out

    fn = so.function_at(static)
    if fn is None:
        out["in_gap"] = True
        out["symbol"] = f"{key}+{static:#x}"
        notes.append("命中地址在该 so 内没有函数覆盖，只给出模块+偏移，不猜测函数名")
        return out

    off = static - fn.addr
    out["function"] = {"name": fn.name or f"sub_{fn.addr:x}",
                       "addr": hex(fn.addr), "addr_int": fn.addr,
                       "size": hex(fn.size)}
    out["insn_offset"] = hex(off)
    out["insn_offset_int"] = off
    out["insn_index"] = off // _INSN_SIZE
    out["symbol"] = _function_label(key, fn, offset=off)

    window, idx, total = _disasm_window(session, key, fn, static)
    out["disasm"] = window
    out["disasm_total"] = total
    if idx is None:
        notes.append("该函数未能反汇编出指令（可能位于数据节）")

    pseudo, pnotes = _pseudocode(session, key, fn.addr)
    out["pseudocode"] = pseudo
    notes.extend(pnotes)

    callers, complete, cnotes = _caller_items(session, key, fn.addr, build_xrefs)
    out["callers"] = callers
    out["callers_complete"] = complete
    notes.extend(cnotes)
    if complete and not callers:
        notes.append("引用图显示该函数没有被本 so 内的任何函数调用（可能是导出入口或回调）")
    return out


# ---------------- 3. 事件流 → 函数级时间轴 ----------------


def _event_symbol(event: dict, session, modules) -> tuple[str | None, dict]:
    """单条事件 → (符号, 定位结果)。

    优先用事件自带的 so_name + static_addr（dyn/service 的命中事件就是这种），
    其次用 runtime_addr 反算，最后才用事件自带的函数名字段（trace 钩子常带）。
    """
    so_name = str(event.get("so_name") or event.get("so") or "")
    static = _as_int(event.get("static_addr") or event.get("static"))
    runtime = _as_int(event.get("runtime_addr") or event.get("runtime")
                      or event.get("addr") or event.get("pc"))
    fn = None
    off = None

    if session is not None and static is not None:
        key, so, _how = _match_so(session, so_name) if so_name else (None, None, None)
        if key is None and not so_name:
            near = [k for k, s in (session.modules or {}).items()
                    if getattr(s, "in_load", lambda _a: False)(static)]
            key = near[0] if len(near) == 1 else None
        if key is not None:
            fn = session.get(key).function_at(static)
            if fn is not None:
                off = static - fn.addr
            return _function_label(key, fn, addr=static, offset=off), {
                "so": key, "function": (fn.name or f"sub_{fn.addr:x}") if fn else None,
                "static_addr": static, "runtime_addr": runtime, "resolved": True,
            }
    if static is not None:
        # mda 未加载该 so：仍然给出 so+偏移，不丢弃信息
        label = f"{so_name}+{static:#x}" if so_name else f"{static:#x}"
        return label, {"so": so_name or None, "function": None,
                       "static_addr": static, "runtime_addr": runtime, "resolved": False}
    if runtime is not None and modules:
        loc = locate_static(session, runtime, modules) if session is not None else None
        if loc is not None:
            static = loc.get("static_addr_int")
            label_fn = loc.get("function")
            fn_addr = loc.get("function_addr_int")
            if label_fn:
                off = (static - fn_addr) if (static is not None and fn_addr is not None) else None
                return f"{loc['so']}!{label_fn}+{off or 0:#x}", {
                    "so": loc.get("so"), "function": label_fn,
                    "static_addr": static, "runtime_addr": runtime, "resolved": True,
                }
            return (f"{loc['so']}+{static:#x}" if static is not None else hex(runtime)), {
                "so": loc.get("so"), "function": None,
                "static_addr": static, "runtime_addr": runtime, "resolved": False,
            }
    # 最后兜底：事件自己带的函数名（例如用户在 frida 侧打的 trace 点）。
    # 注意排除模块加载类事件：它们的 name 是**模块名**不是函数名，
    # 拿来当函数名会给出"liblog.so 被调用"这种错误结论。
    # 判据：没有静态/运行时地址，且带 base/size（模块加载事件的典型字段）。
    looks_like_module = (static is None and runtime is None
                         and (event.get("base") is not None or event.get("size") is not None))
    etype = str(event.get("type") or "").lower()
    if "module" in etype or looks_like_module:
        label = so_name or str(event.get("name") or "") or "?"
        return label, {"so": label or None, "function": None,
                       "static_addr": None, "runtime_addr": None, "resolved": True}
    named = event.get("function") or event.get("func") or event.get("name") or event.get("symbol")
    if named:
        return str(named), {"so": so_name or None, "function": str(named),
                            "static_addr": static, "runtime_addr": runtime, "resolved": True}
    return None, {"so": so_name or None, "function": None,
                  "static_addr": static, "runtime_addr": runtime, "resolved": False}


def trace_to_timeline(events, session=None, modules=None) -> dict:
    """事件流 → 函数级时间轴（#17 的核心：看"先调了 A，再调了 B"）。

    参数：
        events  事件列表。每条可以是 dyn/service.py poll_events 返回的 dict
                （type/seq/ts/so_name/static_addr/runtime_addr/context/backtrace），
                也可以是 dyn/debugger.BreakpointHit 对象
        session 可选 core.session.Session（有它才能把地址落成函数名）
        modules 可选运行时模块表（事件只有 runtime_addr 时用它反算）

    返回：
        count / items / runs / unresolved / ordered_by / duration / notes
        items 每项：index, seq, ts, delta_ms, type, symbol, so, function,
                    function_addr, offset, static_addr, runtime_addr, thread_id
        runs  连续同名事件的压缩视图（同一函数被连续命中 n 次 → 一条 run）

    排序：有 ts 的按 ts 升序，缺 ts 的排在后面并保持输入顺序（稳定排序），
    所以不会因为个别事件没有时间戳就打乱整体顺序。
    """
    items_raw = []
    notes: list[str] = []
    missing_ts = 0
    unresolved = 0

    for pos, ev in enumerate(events or []):
        if isinstance(ev, dict):
            record = dict(ev)
        else:
            record = {
                "so_name": getattr(ev, "so_name", None),
                "static_addr": getattr(ev, "static_addr", None),
                "runtime_addr": getattr(ev, "runtime_addr", None),
                "thread_id": getattr(ev, "thread_id", None),
                "ts": getattr(ev, "ts", None),
                "seq": getattr(ev, "seq", None),
                "type": getattr(ev, "type", None),
                "context": getattr(ev, "context", None),
                "backtrace": getattr(ev, "backtrace", None),
            }
        ts = _as_float(record.get("ts"))
        if ts is None:
            missing_ts += 1
        # (9) 第九次修改（2026-11-05）：支持把**模块加载事件**混进同一条时间轴。
        #     bug 原因：原本只认断点命中事件，模块加载事件（kind=added/removed）
        #               会被 _event_symbol 当成"地址解析失败"处理，直接变成 "?"。
        #               于是"什么时候加载了什么"和"什么时候执行了什么"永远
        #               落在两条互不相通的时间轴上，回答不了"加载完才执行"这类问题。
        #     解决方案：识别 kind=added/removed（或 type=module_load），
        #               以模块名作为 symbol，不参与地址解析；路径与基址放进 info，
        #               与断点事件统一排序、统一算 delta。
        kind = str(record.get("kind") or "").lower()
        # 兼容两种写法：老式 kind=added/removed，新式 kind=module_load + action
        # （trace_app_startup 用的是后者，两者都要能进同一条时间轴）
        if kind in ("added", "removed", "module_load") or \
                str(record.get("type") or "") == "module_load":
            action = kind if kind in ("added", "removed") else \
                str(record.get("action") or "module_load").lower()
            if kind == "module_load":
                kind = action
            items_raw.append({
                "pos": pos,
                "ts": ts,
                "raw": record,
                "symbol": f"{'加载' if kind == 'added' else '卸载'} "
                          f"{record.get('name') or '?'}",
                "info": {
                    "resolved": True, "so": None, "static_addr": None,
                    "function": None, "is_module_event": True,
                    "module_kind": kind or "module_load",
                    "path": record.get("path"),
                    "base": record.get("base"),
                },
            })
            continue
        symbol, info = _event_symbol(record, session, modules)
        if symbol is None:
            symbol = "?"
        if not info["resolved"]:
            unresolved += 1
        items_raw.append({
            "pos": pos,
            "ts": ts,
            "raw": record,
            "symbol": symbol,
            "info": info,
        })

    # 稳定排序：ts 缺失的排在最后，不影响其它事件的相对顺序
    items_raw.sort(key=lambda it: (it["ts"] is None, it["ts"] if it["ts"] is not None else 0.0, it["pos"]))

    items = []
    prev_ts = None
    for i, it in enumerate(items_raw, start=1):
        raw = it["raw"]
        info = it["info"]
        fn = info.get("function")
        fn_addr = None
        if session is not None and info.get("so") in (getattr(session, "modules", {}) or {}):
            try:
                obj = session.get(info["so"]).function_at(info["static_addr"]) if info.get("static_addr") is not None else None
                fn_addr = obj.addr if obj is not None else None
            except Exception:                                # noqa: BLE001
                fn_addr = None
        off = (info["static_addr"] - fn_addr) if (info.get("static_addr") is not None and fn_addr is not None) else None
        delta = (it["ts"] - prev_ts) if (it["ts"] is not None and prev_ts is not None) else None
        # 函数级标识：不带 +偏移。run 压缩必须按它分组——
        # 同一函数内两条不同指令上的命中是"同一个函数被调用两次"，
        # 若按带偏移的 symbol 分组，会退化成按指令计数的"指令时间轴"，
        # 恰好丢掉本功能的意义（用户要看的是"先调了 A，再调了 B"）。
        if info.get("so") and fn:
            function_key = f"{info['so']}!{fn}"
        elif info.get("so") and info.get("static_addr") is not None:
            function_key = None      # 落在函数空洞：没有函数可言，不参与合并
        else:
            function_key = None
        items.append({
            "index": i,
            "seq": _as_int(raw.get("seq")),
            "ts": it["ts"],
            "delta_ms": round(delta * 1000.0, 3) if delta is not None else None,
            "type": str(raw.get("type") or ("breakpoint_hit" if info.get("static_addr") is not None else "event")),
            "symbol": it["symbol"],
            "function_key": function_key,
            "so": info.get("so"),
            "function": fn,
            "function_addr": hex(fn_addr) if fn_addr is not None else None,
            "offset": hex(off) if off is not None else None,
            "static_addr": _as_addr(info.get("static_addr")),
            "runtime_addr": _as_addr(info.get("runtime_addr")),
            "thread_id": _as_int(raw.get("thread_id")),
        })
        if it["ts"] is not None:
            prev_ts = it["ts"]

    # runs：连续同一函数的压缩序列（"先 A 再 A 再 B" → A×2, B×1）
    # 分组键用 function_key（函数级）；非命中类事件（如模块加载）没有函数，
    # 退回用 symbol 分组，避免把它们全挤进一个占位桶。
    runs = []
    for item in items:
        key = item["function_key"] or item["symbol"]
        if runs and runs[-1]["key"] == key:
            runs[-1]["count"] += 1
            runs[-1]["last_index"] = item["index"]
        else:
            runs.append({"key": key, "symbol": key, "count": 1,
                         "first_index": item["index"], "last_index": item["index"]})
    for run in runs:
        run.pop("key", None)

    ts_items = [it for it in items if it["ts"] is not None]
    duration = (ts_items[-1]["ts"] - ts_items[0]["ts"]) if len(ts_items) >= 2 else None
    if missing_ts:
        notes.append(f"{missing_ts} 条事件缺时间戳，已排在末尾并保持输入顺序")
    if unresolved:
        notes.append(f"{unresolved} 条事件无法落到具体函数（见 items 里 function 为 null 的项）")
    ordered_by = "ts" if not missing_ts else ("ts+input" if ts_items else "input")
    return {
        "count": len(items),
        "items": items,
        "runs": runs,
        "unresolved": unresolved,
        "ordered_by": ordered_by,
        "duration": duration,
        "notes": notes,
    }


# ---------------- 4. 静态函数 → 建议断点 ----------------


def suggest_breakpoints(session, function_name_or_addr, so_name=None, limit: int = _MAX_SUGGESTIONS) -> dict:
    """静态选中的函数 → 建议断点位置（#18 的核心）。

    参数：
        session                core.session.Session
        function_name_or_addr  函数名（"foo" / "so!foo"）或地址（int / "0x5020" / "sub_5020"）
        so_name                可选，指定在哪个 so 里找（重名函数必须给）
        limit                  建议条数上限

    建议类型（kind）：
        entry        函数入口：命中时 x0-x7 就是调用方传入的实参
        after_call   每个 bl 之后的返回点：调用已完成，可看返回值 x0 与副作用
        before_ret   ret 之前：可看函数最终返回值与将要恢复的 lr
        data_ref     引用了字符串的指令：可确认走的是哪个分支/哪个文案

    返回：{so, function, suggestions[], count, truncated, notes[]}；
    找不到函数时返回 {"error": ..., "candidates": [...]}，不猜。
    """
    key, so, fn = _resolve_function(session, function_name_or_addr, so_name)
    if key is None:
        return fn  # 已经是错误 dict

    x = _xref(session, key)
    disasm = getattr(x, "disasm", None) or Disassembler(so)
    insns = disasm.disasm_function(fn.addr)
    if not insns:
        return {
            "error": f"函数 {fn.name or hex(fn.addr)} 没有反汇编出指令（可能位于数据节）",
            "so": key, "function_addr": hex(fn.addr),
        }

    name = fn.name or f"sub_{fn.addr:x}"
    notes: list[str] = []
    suggestions = []
    seen: set[tuple[int, str]] = set()

    def _add(addr: int, kind: str, reason: str, ins, **extra):
        if (addr, kind) in seen:
            return
        seen.add((addr, kind))
        item = {
            "addr": hex(addr),
            "addr_int": addr,
            "kind": kind,
            "insn_index": (addr - fn.addr) // _INSN_SIZE,
            "insn": ins.text if ins is not None else None,
            "reason": reason,
        }
        item.update(extra)
        suggestions.append(item)

    # 1) 入口
    _add(fn.addr, "entry",
         "函数入口：命中时 x0-x7 即调用方传入的实参，可据此确认谁以什么参数调用",
         insns[0], symbol=_function_label(key, fn, offset=0))

    # 2) 每个 bl 的返回点 + 3) ret 之前 + 4) 字符串引用
    for ins in insns:
        if ins.is_call and ins.call_target is not None:
            ret_addr = ins.addr + ins.size
            if ret_addr >= fn.end:
                continue  # 尾部调用/函数末尾，没有"之后"
            callee = so.function_at(ins.call_target)
            callee_name = (callee.name or f"sub_{callee.addr:x}") if callee else so.plt_name(ins.call_target)
            if callee_name is None:
                callee_name = hex(ins.call_target) if ins.call_target >= 0 else None
            _add(ret_addr, "after_call",
                 f"{callee_name or '目标'} 的返回点：调用已完成，可看返回值 x0 "
                 f"与它对实参/全局状态的副作用",
                 ins, call_site=hex(ins.addr), callee=callee_name)
        elif ins.is_ret:
            _add(ins.addr, "before_ret",
                 "返回前：可看函数最终返回值 x0，以及即将恢复的 lr（返回去向）",
                 ins)
        elif ins.ref_addr is not None:
            text = _string_at(so, ins.ref_addr)
            if text:
                _add(ins.addr, "data_ref",
                     f'引用了字符串 "{text[:40]}"：命中可确认走的是哪条分支',
                     ins, ref=hex(ins.ref_addr))

    suggestions.sort(key=lambda s: (s["addr_int"], s["kind"]))
    # (6) 第六次修改（2026-11-05）：先留一份完整列表，供后面的"叶子函数"判断用。
    #     bug 原因：截断后用**截断后**的列表判断"有没有 bl"，当 limit=1 且第一条是
    #               entry 时，明明中间有 after_call 也会被判成"该函数没有 bl 调用
    #               （叶子函数）"——一个凭截断产生的假结论。
    #     解决方案：判断一律基于截断前的完整列表。
    _all_suggestions = list(suggestions)
    truncated = False
    try:
        cap = int(limit)
    except (TypeError, ValueError):
        cap = _MAX_SUGGESTIONS
    if cap > 0 and len(suggestions) > cap:
        truncated = True
        notes.append(f"建议数 {len(suggestions)} 超过上限 {cap}，已截断（按地址升序保留前 {cap} 条）")
        suggestions = suggestions[:cap]

    if not any(s["kind"] == "after_call" for s in _all_suggestions):
        notes.append("该函数没有 bl 调用（叶子函数），建议集中在入口与返回点")
    elif truncated:
        notes.append("提示：已按上限截断，可能存在未列出的 after_call 断点")
    return {
        "so": key,
        "function": {"name": name, "addr": hex(fn.addr), "addr_int": fn.addr,
                     "size": hex(fn.size), "instructions": len(insns)},
        "symbol": _function_label(key, fn, offset=0),
        "suggestions": suggestions,
        "count": len(suggestions),
        "truncated": truncated,
        "notes": notes,
    }


def _string_at(so, addr: int) -> str | None:
    """读地址处的可打印字符串（够长才算，避免把代码字节当文案）。"""
    try:
        data = so.read(addr, 64)
    except Exception:                                        # noqa: BLE001
        return None
    if not data:
        return None
    end = data.find(b"\0")
    raw = data[: end if end > 0 else len(data)]
    if len(raw) >= 4 and all(0x20 <= c < 0x7F for c in raw):
        return raw.decode("ascii", "replace")
    return None


# ---------------- 5. 模块加载事件 → 加载时间轴 ----------------


def module_load_timeline(load_events) -> dict:
    """模块加载事件 → 加载顺序时间轴（#14 的静态整理部分）。

    参数：
        load_events  [{name, base, size, ts}]（也接受 path，name 缺失时取 basename）

    返回：
        count / order / overlaps / anomalies / intervals_ok
        order 每项：index, name, base, end, size, ts, delta_from_prev
        anomalies 每项：{kind, detail}，kind ∈ base_zero/base_unaligned/size_invalid/
                                      missing_base/missing_name/missing_ts/duplicate_name

    采集那一步需要 frida（dyn/service.py 的 modules()），但排序、区间、
    重叠判定全是本地计算——本函数不连接设备。
    """
    entries = []
    anomalies: list[dict] = []
    missing_ts = 0

    # (2) 第二次修改（2026-11-02）：支持整表简写 {模块名: 基址} / {模块名: {base,size}}。
    #     bug 原因：旧实现只认 [{name, base, size}]，把 {"a.so": 0x1000} 当成
    #               一条"缺 name 缺 base"的事件，于是输出 count=0 加两条
    #               missing_name/missing_base 异常——调用方以为数据坏了，
    #               实际是自己用了文档认可（且 runtime_modules 风格）的简写。
    #     解决方案：入参是 dict 且**不含 name/base 这类字段**时，判定为整表简写，
    #               展开成标准事件列表再走原有逻辑。展开时保留原顺序（dict 有序），
    #               基址若是 {base,size} 形态则一并取用。
    normalized_input = load_events
    if isinstance(load_events, dict):
        _reserved = {"name", "path", "base", "size", "ts"}
        if not (_reserved & set(load_events.keys())):
            normalized_input = []
            for mod_name, val in load_events.items():
                item = {"name": mod_name}
                if isinstance(val, dict):
                    item["base"] = val.get("base")
                    item["size"] = val.get("size")
                    if val.get("ts") is not None:
                        item["ts"] = val.get("ts")
                    if val.get("path"):
                        item["path"] = val.get("path")
                else:
                    item["base"] = val
                normalized_input.append(item)
        else:
            # 单个事件对象被误传：包成列表，比静默返回 count=0 更有用
            normalized_input = [load_events]

    for pos, raw in enumerate(normalized_input or []):
        if isinstance(raw, dict):
            name = raw.get("name") or ""
            path = raw.get("path") or ""
            base = _as_int(raw.get("base"))
            size = _as_int(raw.get("size"))
            ts = _as_float(raw.get("ts"))
        else:
            name = getattr(raw, "name", "") or ""
            path = getattr(raw, "path", "") or ""
            base = _as_int(getattr(raw, "base", None))
            size = _as_int(getattr(raw, "size", None))
            ts = _as_float(getattr(raw, "ts", None))
        name = str(name or (path.rsplit("/", 1)[-1] if path else ""))
        if not name:
            anomalies.append({"kind": "missing_name", "detail": f"第 {pos} 条事件没有模块名"})
        if base is None:
            anomalies.append({"kind": "missing_base",
                              "detail": f"模块 {name or pos} 没有基址，无法计算区间，已跳过"})
            continue
        if ts is None:
            missing_ts += 1
        if base == 0:
            anomalies.append({"kind": "base_zero",
                              "detail": f"模块 {name} 基址为 0（未重定位/解析失败？）"})
        if base % 0x1000:
            anomalies.append({"kind": "base_unaligned",
                              "detail": f"模块 {name} 基址 {hex(base)} 未按 4KB 对齐"})
        # (3) 第三次修改（2026-11-02）：区分"没给 size"与"给错了 size"。
        #     bug 原因：旧实现 size<=0 一律报 size_invalid（"大小非法"）。
        #               但像 {"a.so": 0x1000} 这种简写本来就不含 size，
        #               说的是"我不知道大小"，不是"大小错了"。混为一谈会让
        #               调用方去排查一个根本不存在的数据错误。
        #     解决方案：没提供 → missing_size（并说明影响：只能给出起点，
        #               无法做重叠判定）；提供了但 <=0 → size_invalid。
        if size is None:
            size = 0
            anomalies.append({
                "kind": "missing_size",
                "detail": f"模块 {name} 未提供大小，只能确定起点 {hex(base)}；"
                          "该条目不参与区间重叠判定",
            })
        elif size <= 0:
            anomalies.append({"kind": "size_invalid",
                              "detail": f"模块 {name} 大小为 {size}，区间无法确定"})
        entries.append({"pos": pos, "name": name, "base": base,
                        "size": size, "end": base + size, "ts": ts})

    # 缺时间戳的排在后面，保持输入顺序
    entries.sort(key=lambda e: (e["ts"] is None, e["ts"] if e["ts"] is not None else 0.0, e["pos"]))

    order = []
    prev_ts = None
    for i, e in enumerate(entries, start=1):
        delta = (e["ts"] - prev_ts) if (e["ts"] is not None and prev_ts is not None) else None
        order.append({
            "index": i,
            "name": e["name"],
            "base": hex(e["base"]),
            "end": hex(e["end"]),
            "size": hex(e["size"]),
            "ts": e["ts"],
            "delta_from_prev": round(delta, 3) if delta is not None else None,
        })
        if e["ts"] is not None:
            prev_ts = e["ts"]

    # (5) 第五次修改（2026-11-05）：重叠判定改为**两两比较**。
    #     bug 原因：原注释写"相邻判断即可覆盖任意重叠"，实际不成立——
    #               大模块 A[0,100) 罩住 B[10,20) 与 C[30,40) 时，排序后相邻对是
    #               A-B（重叠）与 B-C（不重叠，因为 30 > 20），于是 **A-C 的重叠漏报**。
    #               模块数量通常在几百量级，O(n²) 完全可接受。
    #     解决方案：对所有有效区间两两比较；同一对只报一次（按排序后下标 i<j）。
    by_base = sorted(entries, key=lambda e: (e["base"], e["end"]))
    overlaps = []
    for i in range(len(by_base)):
        for j in range(i + 1, len(by_base)):
            a, b = by_base[i], by_base[j]
            # 后面的区间基址只会更大，超过 a.end 就不可能再重叠，可提前剪枝
            if b["base"] >= a["end"]:
                break
            if a["size"] <= 0 or b["size"] <= 0:
                continue
            overlaps.append({
                "a": a["name"], "b": b["name"],
                "overlap_start": hex(b["base"]),
                "overlap_end": hex(min(a["end"], b["end"])),
                "detail": f"{a['name']} [{hex(a['base'])},{hex(a['end'])}) 与 "
                          f"{b['name']} [{hex(b['base'])},{hex(b['end'])}) 重叠",
            })
    for item in overlaps:
        anomalies.append({"kind": "overlap", "detail": item["detail"]})

    # 同名多次出现：卸载后重载，或同一次枚举里出现两条
    by_name: dict[str, list[dict]] = {}
    for e in entries:
        by_name.setdefault(e["name"], []).append(e)
    for name, group in by_name.items():
        if len(group) > 1:
            bases = ", ".join(hex(g["base"]) for g in group)
            anomalies.append({
                "kind": "duplicate_name",
                "detail": f"模块 {name} 出现 {len(group)} 次（base: {bases}）——"
                          f"反复 dlopen 或枚举到重载前后的两条记录",
            })

    notes = []
    if missing_ts:
        notes.append(f"{missing_ts} 条事件缺时间戳，已排在末尾并保持输入顺序")
    if not entries:
        notes.append("没有可用的加载事件（每条都需要 name + base）")
    return {
        "count": len(order),
        "order": order,
        "overlaps": overlaps,
        "anomalies": anomalies,
        "intervals_ok": not overlaps and not anomalies,
        "notes": notes,
    }


# ---------------- br 目标解析：表驱动三段式（table_indexed） ----------------

# 三段式里 br 目标寄存器允许的最长推导链（adr → ldrsw → add → br 共 4 跳，
# 中间可能插无关指令，给到 8 跳仍能在函数体内正常收敛，同时防死循环）
_TI_MAX_CHAIN = 8

# 跨基本块回溯时往 br 之前最多看多少条指令猜索引上界（cmp 通常在十几条内）
_TI_BOUND_LOOKBACK = 64


def _ti_ins_addr(ins) -> int:
    """取指令地址：兼容 capstone 原始对象（address）与 mda 的 Instruction（addr）。"""
    v = getattr(ins, "address", None)
    if v is None:
        v = getattr(ins, "addr", 0)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _ti_reg_name(op: str) -> str:
    """取操作数里的寄存器名并归一（w7 与 x7 视为同一寄存器）。"""
    name = (op or "").strip().split(",")[0].strip()
    return name


def _ti_norm(reg: str) -> str:
    """w0-w30 → x0-x30。AArch64 里 wN 是 xN 的低 32 位，同一个物理寄存器。"""
    r = (reg or "").strip().lower()
    if len(r) >= 2 and r[0] == "w" and r[1:].isdigit():
        return "x" + r[1:]
    return r


def _ti_imm(ins) -> int | None:
    """取 "#0x..." 形式的立即数（capstone 的 op_str 里带 #）。"""
    op = ins.op_str or ""
    if "#" not in op:
        return None
    try:
        return int(op.rsplit("#", 1)[1].strip(), 0)
    except (ValueError, IndexError):
        return None


def _ti_writes(ins, reg: str) -> bool:
    """该指令是否写 reg（含 wN 别名与写 zr 的情况）。"""
    try:
        _r, w = ins.regs_access()
        for idx in w:
            if _ti_norm(ins.reg_name(idx)) == reg:
                return True
    except Exception:                                     # noqa: BLE001
        # capstone 没开 detail 时的兜底：按第一个操作数判断
        return _ti_norm(_ti_reg_name(ins.op_str)) == reg
    return False


def _ti_reads(ins, reg: str) -> bool:
    """该指令是否读 reg（含 wN 别名）。"""
    try:
        r, _w = ins.regs_access()
        for idx in r:
            if _ti_norm(ins.reg_name(idx)) == reg:
                return True
    except Exception:                                     # noqa: BLE001
        return reg in (ins.op_str or "").lower()
    return False


def _ti_mem_base(in_op: str) -> tuple[str, int]:
    """解析 "[xR, xI, lsl #2]" → (基址寄存器, 移位量)。解析不出返回 ("", 0)。"""
    op = in_op or ""
    if "[" not in op or "]" not in op:
        return "", 0
    inner = op[op.index("[") + 1: op.index("]")]
    parts = [p.strip() for p in inner.split(",")]
    base = _ti_norm(parts[0]) if parts else ""
    shift = 0
    for p in parts[1:]:
        low = p.lower()
        if low.startswith("lsl"):
            tail = low.split("#")[-1].strip()
            try:
                shift = int(tail, 0)
            except ValueError:
                shift = 0
    return base, shift


def _ti_analyse(insns, idx: int, so) -> dict | None:
    """识别 `adr + ldrsw + add + br` 表驱动三段式（table_indexed）。

    (13) 第十三次修改（2026-11-06）：新增第三种模式。

    bug 原因（为什么需要它）：
        resolve_br 原来只认 adrp 系列。VM 分发器最要害的形态却是
            adr    x15, #base              ; 基址来自 **ADR**，不是 ADRP
            ldrsw  x16, [x12, x7, lsl #2]  ; 表地址在**另一个**寄存器 x12
            add    x15, x15, x16           ; 基址 + 表项偏移
            br     x15
        两个特征同时超出了旧实现的假设：①ADRP 换成 ADR（旧逻辑只匹配 adrp，
        于是整条链被判 unknown）；②表基址寄存器 ≠ br 寄存器（旧逻辑只回溯
        br 那一个寄存器，看不到 x12 的来历）。结果是这 30 处分发点全部
        resolved=false，跨过 br 的调用关系继续丢失。

    解决方案（四步，全部纯静态）：
        ① 形态匹配：br 前若干条内出现 adr Xb,#imm / ldrsw Xo,[Xr,...] /
           add Xb,Xb,Xo 且 br 的操作数就是 Xb，即判定为三段式。
           **中间容许无关指令**（实测 0x175028 的 adr/ldrsw/add 与 br 之间
           还插了一条 sxtw x22,w23，位置上并不相邻）。
        ② 基址 base_val：ADR 编码的就是本指令地址（capstone 输出绝对地址），
           直接取 `ins.operands[1].imm`，即 0x175018。
        ③ 表地址：从 add 处**往前**扫，找最后一条写表寄存器（x12）的
           adrp/add 组合。adrp 给页基址、add 给页内偏移，累加得 0x30fd8。
           回溯范围：函数体内 → 读不到就降到文件起点（实测 x12 的 adrp/add
           位于 0x174f28/0x174f74，属于**前一个**函数 0x174f00——
           跳转表分发的基本块被 FDE 拆成了两个函数，只在本函数内找必然失败）。
           再往前若还有写同一寄存器的位置，说明取址链可能被覆盖，放弃并标注。
        ④ 表项个数：用 ldrsw 的索引寄存器往前找 `cmp wI,#N`，N+1 即个数
           （实测 cmp w7,#0xd → 14 项）；找不到就先用默认条数，再用
           **目标落在函数内**这一约束剔除越界项（表后面紧邻别的数据，
           多读出来的值多半不落在本函数范围）。

    任何一步不成立都返回 None，由调用方继续走旧逻辑并最终标 unknown，
    **绝不编造目标**。
    """
    if idx < 3 or idx >= len(insns):
        return None
    br = insns[idx]
    if br.mnemonic != "br":
        return None
    target_reg = _ti_norm(_ti_reg_name(br.op_str))
    if not target_reg:
        return None

    # ---- ① 形态匹配（容许中间夹杂无关指令） ----
    # (14) 第十四次修改（2026-11-06）
    #      bug 原因：本 helper 最初用 ins.operands 取操作数，但 resolve_br 建的
    #               capstone 实例**没开 detail**，访问 operands 直接抛
    #               CsError(CS_ERR_DETAIL)。而且 reslove_br 是要被别人复用的，
    #               不能为了这里去改它的 md 构造（会改变旧模式的数值来源）。
    #      解决方案：本模块一律按 op_str 文本解析操作数，不碰 operands，
    #               既不依赖 detail，也不影响旧逻辑的行为。
    adr_ins = ldr_ins = add_ins = None
    for j in range(idx - 1, max(-1, idx - 7), -1):
        ins = insns[j]
        if add_ins is None:
            if ins.mnemonic == "add":
                ops = [p.strip() for p in (ins.op_str or "").split(",")]
                # add Xb, Xb, Xo（三操作数，目标与第一个源都是 br 寄存器）
                if (len(ops) == 3 and _ti_norm(ops[0]) == target_reg
                        and _ti_norm(ops[1]) == target_reg):
                    add_ins = ins
            continue
        if ldr_ins is None:
            if ins.mnemonic in ("ldrsw", "ldr", "ldrsh"):
                if _ti_mem_base(ins.op_str)[0]:
                    ldr_ins = ins
            continue
        if adr_ins is None and ins.mnemonic in ("adr", "adrp"):
            adr_ins = ins
            break
    if adr_ins is None or ldr_ins is None or add_ins is None:
        return None
    # adr 写的必须是 br 的那个寄存器，且 add 的第三操作数是 ldr 的目标寄存器
    if _ti_norm(_ti_reg_name(adr_ins.op_str)) != target_reg:
        return None
    ops = [p.strip() for p in (add_ins.op_str or "").split(",")]
    load_dst = _ti_norm(_ti_reg_name(ldr_ins.op_str))
    if len(ops) != 3 or _ti_norm(ops[2]) != load_dst:
        return None
    # ADR 的立即数就是绝对地址（capstone 已按当前地址算好）；ADRP 给的是页基址
    base_val = _ti_imm(adr_ins)
    if base_val is None or base_val <= 0:
        return None
    if adr_ins.mnemonic == "adrp":
        # ADRP + add 的真实基址要靠 add 补全，这里不猜，直接放弃
        return None
    if not _ti_reads(add_ins, target_reg) or not _ti_reads(add_ins, load_dst):
        return None

    # ---- ③ 表地址：从 add 往前找写"表寄存器"的 adrp/add ----
    table_reg = _ti_mem_base(ldr_ins.op_str)[0]
    if not table_reg or table_reg == target_reg:
        # 表基址就在 br 寄存器自己身上 → 不是三段式（或 base==table，交给旧逻辑）
        return None
    add_pos = insns.index(add_ins)
    table_addr, table_detail, table_certain = _ti_trace_table_base(
        insns, add_pos, table_reg, so)
    if table_addr is None:
        return None

    # ---- ④ 表项个数 ----
    index_reg = _ti_ti_index_reg(ldr_ins.op_str)
    entry_size = 4 if ldr_ins.mnemonic.startswith("ldrsw") or "w" in (ldr_ins.op_str or "") else 8
    if ldr_ins.mnemonic == "ldr":
        # ldr wN 取 4 字节、ldr xN 取 8 字节，看目标寄存器宽度
        entry_size = 8 if load_dst.startswith("x") else 4
    count, bound_detail = _ti_table_count(insns, add_pos, index_reg)

    return {
        "mode": "table_indexed",
        "base_addr": base_val,
        "table_addr": table_addr,
        "entry_size": entry_size,
        "count": count,
        "index_reg": index_reg,
        "certain": table_certain,
        "detail": (f"adr {adr_ins.op_str} ; {ldr_ins.mnemonic} {ldr_ins.op_str} ; "
                   f"add {add_ins.op_str} ; {table_detail}"
                   + (f" ; {bound_detail}" if bound_detail else "")),
    }


def _ti_ti_index_reg(ldr_op: str) -> str:
    """取 `[x12, x7, lsl #2]` 里的索引寄存器（第二个操作数，非立即数那个）。"""
    op = ldr_op or ""
    if "[" not in op or "]" not in op:
        return ""
    inner = op[op.index("[") + 1: op.index("]")]
    parts = [p.strip() for p in inner.split(",")]
    if len(parts) < 2:
        return ""
    cand = parts[1]
    if cand.startswith("#"):
        return ""
    return _ti_norm(cand)


def _ti_trace_table_base(insns, before_idx: int, reg: str, so):
    """从 before_idx 往前回溯，求 reg 的表基址。

    先在本函数指令序列里找；找不到再退到**文件里该地址之前**扫一遍
    （实测的表基址指令属于前一个函数，函数边界在这里没有语义意义——
    跳转表分发的基本块被 FDE 拆开了）。

    (14) 第十四次修改（2026-11-06）
         bug 原因：第一版回溯时要求"先遇到 adrp 才认 add"，可是**往回走**
                  永远先看到 add（add 在 adrp 之后），于是遇到 add 就 break，
                   表基址恒求不出（自测 0x175028 一路走到 unknown）。
         解决方案：改成"按写入顺序累积"——往回只关心**写 reg 的指令**，
                   从最近的一条开始：
                     · add Xr, Xr, #imm  → 累加偏移，继续往前
                     · adrp Xr, #page    → 页基址，与已累加偏移相加即为表地址
                     · adr  Xr, #abs     → 本身就是绝对地址
                     · 其它写 reg 的指令（mov/ldr/and…）→ 数据流屏障，放弃
                   这样 adrp→add 与 add→adrp 两种书写顺序都能正确处理。

    返回 (表地址, 说明, 是否确定)。求不出返回 (None, 说明, False)。
    """
    offset_sum = 0

    def _walk(candidates) -> tuple[int | None, object, str]:
        """在候选指令（应已按"由近及远"排列）里推 base。返回 (base, 命中指令, 原因)。"""
        acc = 0
        for ins in candidates:
            if not _ti_writes(ins, reg):
                continue
            if ins.mnemonic == "add":
                imm = _ti_imm(ins)
                if imm is None:
                    return None, ins, "add 立即数解析失败"
                acc += imm
                continue
            if ins.mnemonic == "adrp":
                page = _ti_imm(ins)
                if page is None:
                    return None, ins, "adrp 立即数解析失败"
                return page + acc, ins, ""
            if ins.mnemonic == "adr":
                absv = _ti_imm(ins)
                if absv is None:
                    return None, ins, "adr 立即数解析失败"
                return absv + acc, ins, ""
            # 其它指令写 reg：取址链被覆盖，静态无法确定
            return None, ins, f"取址链被 {ins.mnemonic} {ins.op_str} 覆盖"
        return None, None, ""

    # ---- 第一段：本函数内该地址之前 ----
    inner = list(reversed(insns[:max(0, before_idx)]))
    base, hit, why = _walk(inner)
    if base is not None:
        return base, f"表基址 {reg}={base:#x}（来源 {hex(_ti_ins_addr(hit))}）", True
    if why:
        return None, why, False

    # ---- 第二段：跨函数/跨块，按文件往更早的代码扫 ----
    if so is None:
        return None, "表基址需跨函数回溯，但拿不到 so 无法扫描", False
    fn_lo = _ti_ins_addr(insns[0]) if insns else 0
    span = 0x4000                                     # 往回最多看 16KB 代码
    lo = max(0, fn_lo - span)
    if lo >= fn_lo:
        return None, "表基址不在本函数内，且没有更早的代码可回溯", False
    earlier = _ti_disasm_range(so, lo, fn_lo - lo)
    if not earlier:
        return None, "跨函数回溯读不到更早的代码", False

    base, hit, why = _walk(reversed(earlier))
    if base is not None:
        return (base,
                f"表基址 {reg}={base:#x}（跨函数回溯，来源 {hex(_ti_ins_addr(hit))}）",
                True)
    return None, why or f"没找到写 {reg} 的 adrp+add 组合（表地址运行时才定）", False


def _ti_disasm_range(so, start: int, size: int) -> list:
    """反汇编一段代码，**能跨数据块继续**。

    (15) 第十五次修改（2026-11-06）
         bug 原因：跨函数回溯最初直接用裸 capstone.disasm()，而 capstone
                   遇到不可解码的字节（内联跳转表、对齐填充）就**停止迭代**：
                   实测回溯区间 [0x170fec,0x174fec) 只解到 0x1726b0（1458 条），
                   后面的 adrp x12 / add x12 根本没被看见，
                   于是表基址恒求不出。mda 的 Disassembler._decode 正是
                   为解决同一个问题写的（按 4 字节跳过数据块后继续批量解码）。
         解决方案：改走 core.disasm.Disassembler.disasm_range（同一份能力，
                   不重复实现），返回统一的 Instruction 列表。
                   它的属性名是 addr 而不是 address，故用 _ti_ins_addr 取。
    """
    try:
        from core.disasm import Disassembler

        return list(Disassembler(so).disasm_range(int(start), int(size)))
    except Exception:                                     # noqa: BLE001
        return []


def _ti_table_count(insns, before_idx: int, index_reg: str) -> tuple[int, str]:
    """猜表项个数：往前找 `cmp wI, #N`，个数 = N + 1。

    找不到返回 (16, "")：调用方会用"目标是否落在函数内"再过滤越界项。
    """
    if not index_reg:
        return 16, ""
    lo = max(0, before_idx - _TI_BOUND_LOOKBACK)
    bound = None
    for j in range(before_idx, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic == "cmp":
            first = _ti_norm(_ti_reg_name(ins.op_str))
            if first != index_reg:
                continue
            imm = _ti_imm(ins)
            if imm is None:
                continue
            bound = imm + 1
            break
        # 索引寄存器被重写，说明看的不是这个分支
        if _ti_writes(ins, index_reg):
            break
    if bound is None:
        return 16, "未找到 cmp 上界，按默认条数读取后用函数范围过滤"
    return bound, f"索引上界来自 cmp #{bound - 1}，表项 {bound} 个"


def _ti_read_targets(so, ti: dict, fn_start: int, fn_size: int,
                     max_targets: int) -> tuple[list[int], str]:
    """按三段式解析结果读表，返回 (目标列表, 补充说明)。

    复用同文件的 read_jump_table（不重复实现表读取），再用两条约束清理结果：
      · 目标必须落在 **PT_LOAD 段内**——表后面往往紧邻别的数据，多读出来的
        值可能是字符串/常量，指到不存在的地址上；
      · 该跳转的 handler 基本都在本函数附近，因此优先保留落在本函数内的项；
        若本函数内一项都没有（函数被 FDE 拆开的情况），退回 PT_LOAD 过滤。
    两条过滤都只做**剔除**，绝不补造目标。
    """
    raw = read_jump_table(
        getattr(so, "name", "") or "",
        int(ti["table_addr"]),
        entry_size=int(ti["entry_size"]),
        count=max(1, min(int(ti.get("count") or 16), 4096)),
        code_base=int(ti["base_addr"]),
        signed=True,
        so=so,
    )
    if not raw.get("ok"):
        return [], f"读表失败：{raw.get('error') or raw.get('code')}"
    targets = [int(t, 16) if isinstance(t, str) else int(t)
               for t in (raw.get("targets") or [])]
    if not targets:
        return [], "表内为 0 或密文（运行时才填充），静态不可知"

    # (16) 第十六次修改（2026-11-06）
    #      bug 原因：第二版把"目标必须落在本函数内"当成首选约束，可 VM 分发器
    #               的 handler 恰恰是**本函数之外**的独立基本块：实测 14 个表项
    #               里只有 0x17502c/0x175064 恰好在 [0x174fec,0x175094) 内，
    #               其余 12 个（如 0x1750a0、0x177608）都被当成"越界"剔掉，
    #               结果 target_count=2，与真实的 14 个严重不符。
    #      解决方案：主约束改成"落在可执行段（PT_LOAD 且可执行）内"——
    #               handler 必是代码；只有连可执行段都不在的表项才算脏数据。
    #               另外保留"整张表都是垃圾"的保护：若过滤后一个都不剩，
    #               说明表地址算错了，此时宁可 resolved=false 也不给假目标。
    def _in_exec(v: int) -> bool:
        try:
            for va, end, _off, fl in so.exec_regions():
                if (fl & 1) and va <= v < end:
                    return True
            return False
        except Exception:                                 # noqa: BLE001
            return True

    exec_ok = [v for v in targets if _in_exec(v)]
    dropped = len(targets) - len(exec_ok)
    note = f"已剔除 {dropped} 个不在可执行段的表项" if dropped else ""
    picked = exec_ok
    if len(picked) > int(max_targets):
        note = (note + "；" if note else "") + f"按 max_targets={int(max_targets)} 截断"
        picked = picked[:int(max_targets)]
    return picked, note


def resolve_br(session, so_name: str, addr: int, lookback: int = 8,
               max_targets: int = 64) -> dict:
    """解开 `adrp/ldr/br xN` 这类**间接跳转**，尽可能还原跳转目标表。

    (10) 第十次修改（2026-11-06）：新增。
        bug 原因：加固样本的 VM 分发器到处是 `br x8`，静态 xref 链在这里全断——
                  build_xrefs 能出几万条边，但跨过 br 就接不上了，
                  调用者与被调者之间的关系丢失，等于分析到一半失明。
        解决方案：从 br 往前回溯若干条指令，识别两种常见取址模式：
                  ① adrp + add/ldr + br        → 目标是**常量地址**
                  ② adrp + ldr + ldr + br      → 目标是**指针表**里的值
                  能静态算出就给出 targets；算不出（如运行时才填充）就如实说明。

    ## 参数

        so_name     mda 里已加载的 so 键
        addr        br 指令所在地址（静态偏移）。给函数内任意地址都可以，
                    函数内所有 br 都会被尝试解析
        lookback    从 br 往前最多回溯多少条指令找取址模式。
                    **最小按 1 处理**：0 回看不可能看到 adrp，没有意义，
                    所以传 0 会被抬到 1（而不是返回空结果，避免误以为"没有 br"）
        max_targets 每个 br 最多返回多少个目标

    ## 返回

        branches[]  每个 br 一条：
                    {addr, reg, mode, targets[], detail, resolved}
                    mode: "direct"（算出常量）/ "table"（指针表）/
                          "unknown"（运行时决定，静态不可知）
        resolved / unresolved  计数
        note        说明哪些情况静态不可知

    ## ⚠️ 静态读 vs 运行时读（关键）

    **加固样本的表常常在运行时才被填充**——文件里是密文或占位值。
    实测同一个 so 的两张表：

        0x30fd8  文件 140000004c000000...  运行时 140000004c000000...  ← 静态常量，可直接读
        0x1af810 文件 9e0a1deb429992db...  运行时 7c39c9e07b000000...  ← 运行时才填，静态读出来是垃圾

    所以给了 `serial` + `pid` 时**优先从进程内存读**（runtime 模式），
    这样加固样本的表也能解对。没给则退回读文件（静态模式）并如实标注。

    ## 已知边界（如实标注）

        · 只在**函数体内**回溯，跨函数的取址链不追
        · 静态模式下若表在运行时才填充，读出来可能是密文——返回里 source="static"
          会明确标注，调用方应改用 serial+pid 走 runtime 模式
    """
    from mcp_server.tools import get_session

    sess = session if session is not None else get_session()
    so = None
    try:
        so = _find_so(sess, so_name)
    except Exception:                                     # noqa: BLE001
        so = None
    if so is None:
        return {"ok": False, "code": "SO_NOT_LOADED",
                "error": f"{so_name} 未加载到 mda；先调 load_so"}

    fn = None
    try:
        fn = so.function_at(int(addr))
    except Exception:                                     # noqa: BLE001
        fn = None
    start = int(getattr(fn, "addr", addr)) if fn is not None else int(addr)
    size = int(getattr(fn, "size", 0) or 0) or 0x400

    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_CAPSTONE",
                "error": f"capstone 不可用：{exc}"}

    data = b""
    try:
        data = _read_so_bytes(so, start, size)
    except Exception:                                     # noqa: BLE001
        data = b""
    if not data:
        return {"ok": False, "code": "READ_FAILED",
                "error": f"读不到 {so_name} 在 {start:#x} 的代码"}

    insns = list(md.disasm(data, start))
    branches: list[dict] = []
    resolved = unresolved = 0

    for idx, ins in enumerate(insns):
        if ins.mnemonic not in ("br", "braa", "braaz"):
            continue
        reg = (ins.op_str or "").strip().split(",")[0].strip()
        lo = max(0, idx - max(1, int(lookback)))
        window = insns[lo:idx]

        # 往前找 adrp <reg> 与紧随其后的取址
        # (11) 第十一次修改（2026-11-06）：修正取址模式识别。
        #      bug 原因：第一版把 adrp+add+ldr+add 也归成 "direct" 常量，
        #               而 ldr 之后寄存器里装的是**内存里的值**，不是地址；
        #               继续把随后的 #imm 当常量相加，算出来的
        #               0x1af837 这类"目标"完全是错的（真目标是表里读出的指针）。
        #                错误结论比没有结论更糟——会把人引到错的地址上。
        #      解决方案：把 ldr 作为分水岭：
        #               · adrp + add + br              → direct（常量地址）
        #               · adrp + (add|ldr) + ldr + br  → table（读指针表）
        #               · 出现 ldr 之后只看「最后一个 ldr」的地址，
        #                 之后的 add 只作为表项内的偏移提示，不参与地址计算。
        # (13) 第十三次修改（2026-11-06）：先试表驱动三段式。
        #      bug 原因：adr + ldrsw + add + br 的表地址在**另一个**寄存器，
        #               且基址来自 ADR 而非 ADRP，下面那段只回溯 br 寄存器的
        #               adrp 逻辑对这 30 处分发点恒判 unknown，跨过 br 的
        #               调用关系继续断裂（详见 _ti_analyse 的说明）。
        #      解决方案：在旧逻辑之前调用 _ti_analyse；识别成功就直接产出
        #               table_indexed 结果并跳过旧路径，识别失败（返回 None）
        #               则原样继续走旧逻辑，行为与改动前完全一致。
        ti = _ti_analyse(insns, idx, so)
        if ti is not None:
            ti_targets, ti_note = _ti_read_targets(
                so, ti, start, size, int(max_targets))
            entry = {
                "addr": int(ins.address),
                "addr_hex": hex(int(ins.address)),
                "insn": f"{ins.mnemonic} {ins.op_str}",
                "reg": reg,
                "mode": "table_indexed",
                "table_addr": hex(ti["table_addr"]),
                "base_addr": hex(ti["base_addr"]),
                "entry_size": ti["entry_size"],
                "index_reg": ti.get("index_reg") or None,
                "targets": [hex(t) for t in ti_targets],
                "target_count": len(ti_targets),
                "resolved": bool(ti_targets),
                "detail": ti["detail"] + (f" ; {ti_note}" if ti_note else ""),
            }
            if ti_targets:
                resolved += 1
            else:
                unresolved += 1
            branches.append(entry)
            continue

        base_val = None
        mode = "unknown"
        detail = ""
        table_addr = None
        load_seen = False
        last_add_after_load = 0
        for w in window:
            if w.mnemonic == "adrp" and w.op_str.startswith(reg + ","):
                try:
                    base_val = int(w.op_str.split("#")[-1], 0)
                except (ValueError, IndexError):
                    base_val = None
                detail = f"{w.mnemonic} {w.op_str}"
                load_seen = False
                last_add_after_load = 0
                continue
            if base_val is None:
                continue
            if w.mnemonic == "add" and w.op_str.startswith(reg + ","):
                try:
                    imm = int(w.op_str.split("#")[-1], 0)
                except (ValueError, IndexError):
                    continue
                if load_seen:
                    last_add_after_load += imm      # 表项内偏移，不参与表地址
                else:
                    base_val += imm
                detail += f" ; {w.mnemonic} {w.op_str}"
                continue
            if w.mnemonic == "ldr" and w.op_str.startswith(reg + ","):
                try:
                    inner = w.op_str[w.op_str.index("[") + 1: w.op_str.index("]")]
                    parts = [p.strip() for p in inner.split(",")]
                    off = 0
                    if len(parts) > 1 and parts[1].startswith("#"):
                        off = int(parts[1][1:], 0)
                    table_addr = base_val + off
                    load_seen = True
                    last_add_after_load = 0
                    detail += f" ; {w.mnemonic} {w.op_str}"
                except (ValueError, IndexError):
                    pass
                continue

        if load_seen and table_addr is not None:
            mode = "table"
        elif (not load_seen) and base_val is not None:
            mode = "direct"

        targets: list[int] = []
        if mode == "direct" and base_val is not None:
            targets = [base_val]
            resolved += 1
        elif mode == "table" and table_addr is not None and mode != "unknown":
            # 从静态文件读指针表
            try:
                raw = _read_so_bytes(so, table_addr, 8 * max(1, int(max_targets)))
                import struct as _struct

                for i in range(0, len(raw) - 7, 8):
                    v = _struct.unpack("<Q", raw[i:i + 8])[0]
                    if 0 < v < (1 << 32):
                        targets.append(v)
                    if len(targets) >= int(max_targets):
                        break
            except Exception:                             # noqa: BLE001
                targets = []
            if targets and last_add_after_load:
                # adrp+add+ldr+add+br：读到的指针再加一个表项内偏移
                detail += f" ; 表项内偏移 +{last_add_after_load:#x}"
            if targets:
                resolved += 1
            else:
                unresolved += 1
                detail += " ; 表内为 0 或密文（运行时才填充）"
        else:
            unresolved += 1
            if not detail:
                detail = "未识别出取址模式（可能是参数/返回值传来的寄存器）"

        branches.append({
            "addr": int(ins.address),
            "addr_hex": hex(int(ins.address)),
            "insn": f"{ins.mnemonic} {ins.op_str}",
            "reg": reg,
            "mode": mode,
            "table_addr": hex(table_addr) if table_addr else None,
            "targets": [hex(t) for t in targets[:int(max_targets)]],
            "target_count": len(targets),
            "resolved": bool(targets),
            "detail": detail,
        })

    return {
        "ok": True,
        "implemented": True,
        "so_name": so_name,
        "function": getattr(fn, "name", None) if fn is not None else None,
        "function_addr": hex(start),
        "function_size": hex(size),
        "branches": branches,
        "branch_count": len(branches),
        "resolved": resolved,
        "unresolved": unresolved,
        "note": ("resolved=false 表示静态不可知：目标来自运行时寄存器、"
                 "或指针表在运行时才被填充/解密。这类情况需要动态断点配合"),
    }


def read_jump_table(so_name: str, table_static_addr: int, entry_size: int = 4,
                    count: int = 16, code_base: int = 0, signed: bool = True,
                    so=None, session=None, serial: str = "", pid: int = 0) -> dict:
    """读一张**跳转表**，把表项解析成目标地址。

    (12) 第十二次修改（2026-11-06）：新增。

    解决什么问题：VM 分发器的常见形态是

        adr    x15, #base               ; 基址（ADR 或 ADRP+ADD）
        ldrsw  x16, [x12, x7, lsl #2]   ; 从表里取 4 字节**有符号偏移**
        add    x15, x15, x16            ; 基址 + 偏移
        br     x15

    这种结构里表项存的是**相对基址的偏移**，不是绝对地址。
    单看 `br x15` 那条指令，静态分析算不出目标——必须知道表地址、表项宽度、
    以及基址三者。本工具就是把这个原子操作单独暴露出来。

    ## 参数

        so_name         mda 里的 so 键
        table_static_addr 表的静态地址
        entry_size      每个表项多少字节（4 = ldrsw/ldr w，8 = ldr x）
        count           读多少项
        code_base       加偏移用的基址（通常是 adr/adrp 给出的那个地址）。
                        传 0 表示"表项就是绝对地址，不加偏移"
        signed          表项是否按**有符号**解释（ldrsw → True）。
                        偏移通常是负数（向前跳）或正数，用有符号才对

    ## 返回

        raw       表的原始 hex
        offsets[] 解出的表项值（有符号）
        targets[] 最终目标地址（code_base + offset）
        note      说明

    ## 实测（0x175018 的 br x15 表）

        基址 0x175018，表项 4 字节有符号偏移
        → 解出 13+ 个目标，落在 0x17502c、0x17506c …… 这些真实 handler 上
    """
    import struct as _struct

    so = so or None
    if so is None:
        try:
            from mcp_server.tools import get_session

            so = _find_so(session if session is not None else get_session(), so_name)
        except Exception:                                 # noqa: BLE001
            so = None
    if so is None:
        return {"ok": False, "code": "SO_NOT_LOADED",
                "error": f"{so_name} 未加载到 mda；先调 load_so"}

    es = 8 if int(entry_size) == 8 else 4
    n = max(1, min(int(count), 4096))
    source = "static"
    raw = b""

    # (13) 第十三次修改（2026-11-06）：支持从**运行时内存**读表。
    #      bug 原因：加固样本的跳转表常在运行时才被填入真实指针（实测
    #               0x1af810 文件里是 9e0a1deb... 的密文，运行时是
    #               7c39c9e0... 的真实指针），静态读文件只能得到垃圾，
    #               于是 resolve_br 对这类表永远 resolved=false。
    #      解决方案：给了 serial+pid 就**优先从进程内存读**；拿不到再退回读文件，
    #               并在 source 字段如实说明这次读的是哪一侧。
    if serial and int(pid or 0) > 0:
        # (17) 第十七次修改（2026-11-06）：runtime 读表改为**单脚本一次完成**。
        #      bug 原因：原实现依赖 Rebase.refresh_modules() 枚举模块，
        #               而它新建脚本枚举 432 个模块实测要 **25 秒**；
        #               本函数只需要"找到模块基址 + 读一段内存"，
        #               用整套模块枚举纯属浪费，且慢到不可用。
        #      解决方案：一次 create_script 同时做「枚举模块 + 按候选名/指纹
        #               定位 + 读表」，全程只一次往返。
        #               指纹用**两个函数入口**取交集（单指纹实测会在
        #               libpdfium 上假阳性）。
        try:
            import time as _t
            import json as _json
            import frida as _frida

            dev = _frida.get_device(serial, timeout=15)
            sess0 = dev.attach(int(pid))

            # 准备指纹（两个函数入口）
            fps: list[dict] = []
            try:
                fns = getattr(so, "functions", {}) or {}
                vals = fns.values() if isinstance(fns, dict) else list(fns)
                offs0 = sorted({int(getattr(f, "addr", 0) or 0) for f in vals})[:2]
                for o in offs0:
                    r3 = _read_so_bytes(so, o, 16)
                    if r3 and len(r3) == 16:
                        fps.append({"offset": int(o), "hex": r3.hex()})
            except Exception:                             # noqa: BLE001
                fps = []

            try:
                cands = []
                try:
                    from dyn.tracer import _module_name_candidates

                    cands = _module_name_candidates(so_name)
                except Exception:                         # noqa: BLE001
                    cands = [str(so_name)]

                js = (
                    "var CANDS = " + _json.dumps(cands) + ";"
                    "var FPS = " + _json.dumps(fps) + ";"
                    "var TBL = " + str(int(table_static_addr)) + ","
                    "    N = " + str(es * n) + ";"
                    "function findMod() {"
                    "  var mods = Process.enumerateModules();"
                    "  for (var i = 0; i < mods.length; i++) {"
                    "    var m = mods[i], bn = m.name.split('/').pop();"
                    "    if (CANDS.indexOf(m.name) >= 0 || CANDS.indexOf(bn) >= 0) return m;"
                    "  }"
                    "  if (FPS.length) {"
                    "    var need = 0;"
                    "    for (var q = 0; q < FPS.length; q++) if (FPS[q].offset > need) need = FPS[q].offset;"
                    "    for (var i = 0; i < mods.length; i++) {"
                    "      var c = mods[i];"
                    "      if (need >= c.size) continue;"
                    "      var okAll = true;"
                    "      for (var q = 0; q < FPS.length; q++) {"
                    "        try {"
                    "          var b = c.base.add(FPS[q].offset).readByteArray(16);"
                    "          if (b === null) { okAll = false; break; }"
                    "          var hx = Array.from(new Uint8Array(b))"
                    "              .map(function(x){return x.toString(16).padStart(2,'0')}).join('');"
                    "          if (hx !== FPS[q].hex) { okAll = false; break; }"
                    "        } catch (e) { okAll = false; break; }"
                    "      }"
                    "      if (okAll) return c;"
                    "    }"
                    "  }"
                    "  return null;"
                    "}"
                    "var mod = findMod();"
                    "if (mod === null) { send({ok: false, code: 'MODULE_NOT_LOADED'}); }"
                    "else {"
                    "  try {"
                    "    var b = mod.base.add(TBL).readByteArray(N);"
                    "    send({ok: true, base: mod.base.toString(), name: mod.name,"
                    "          hex: b === null ? null : Array.from(new Uint8Array(b))"
                    "              .map(function(x){return x.toString(16).padStart(2,'0')}).join('')});"
                    "  } catch (e) { send({ok: false, code: 'READ_FAILED', err: String(e)}); }"
                    "}"
                )
                sc = sess0.create_script(js)
                box: dict = {}
                sc.on("message", lambda m, d: box.update(m.get("payload") or {}))
                sc.load()
                t1 = _t.time()
                while not box and _t.time() - t1 < 20.0:
                    _t.sleep(0.02)
                if box.get("ok") and box.get("hex"):
                    raw = bytes.fromhex(box["hex"])
                    source = "runtime"
                    _rb_base_used = box.get("base")
                else:
                    raw = b""
            finally:
                # (18) 第十八次修改（2026-11-06）：detach 放守护线程。
                #      bug 原因：session.detach() 在该设备上会永久阻塞
                #               （已多次实测），写在 finally 里等于每次调用
                #               都卡死。rebase.py 早就用守护线程绕开了，
                #               这里遗漏。
                try:
                    import threading as _th2

                    _th2.Thread(target=lambda: sess0.detach(), daemon=True).start()
                except Exception:                         # noqa: BLE001
                    pass
        except Exception:                                 # noqa: BLE001
            raw = b""

    if not raw:
        raw = _read_so_bytes(so, int(table_static_addr), es * n)
        source = "static"
    if not raw:
        return {"ok": False, "code": "READ_FAILED",
                "error": f"读不到表 {int(table_static_addr):#x}"}

    offsets: list[int] = []
    targets: list[int] = []
    base = int(code_base)
    for i in range(len(raw) // es):
        chunk = raw[i * es:(i + 1) * es]
        if es == 4:
            v = _struct.unpack("<i" if signed else "<I", chunk)[0]
        else:
            v = _struct.unpack("<q" if signed else "<Q", chunk)[0]
        offsets.append(v)
        targets.append(base + v if base else v)

    return {
        "ok": True,
        "implemented": True,
        "so_name": so_name,
        "table_addr": hex(int(table_static_addr)),
        "entry_size": es,
        "count": len(offsets),
        "code_base": hex(base) if base else None,
        "source": source,
        "raw": raw.hex(),
        "offsets": offsets,
        "targets": [hex(t) for t in targets],
        "note": ("表项按偏移解释（signed=%s）；targets = code_base + offset%s；"
                 "数据来源=%s"
                 % (signed, "" if base else "（未给 code_base，直接当绝对值）",
                    "运行时内存" if source == "runtime" else "静态文件")),
    }
