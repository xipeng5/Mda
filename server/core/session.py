"""多 so 会话：全局符号索引与跨 so 调用链。

这是本项目区别于单文件反汇编工具的核心：
- 同时加载多个 so，建立 全局导出符号表
- liba.so 调用 libb.so 的 foo() 时，能沿 PLT -> 导入符号 -> 目标 so 的导出函数
  解析出真实落点，从而给出跨 so 调用链
- 人工在 GUI 里看结果，AI 通过 MCP/脚本通道调用同一套接口

依赖 core.elf_model / core.disasm / core.xref / core.strings。
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from server.core.disasm import Disassembler
from server.core.elf_model import SoFile
from server.core.strings import StringAnalyzer
from server.core.xref import Xref


# ---------------- 模块名归一与别名匹配（全项目唯一一套规则） ----------------
#
# (4) 第四次修改（2026-11-13）：新增本节。
#
# bug 原因：设备上的模块名与 mda 会话里的键**经常不一致**——
#           设备叫 libsscronet.so、本地文件存成 sscronet.so；
#           设备叫 libsgmainso-6.7.260202.so、本地存成 libsgmainso.so；
#           设备还可能直接给完整路径 /data/app/xxx/lib/arm64/libfoo.so。
#           而 Session.get() 是严格 `self.modules.get(name)`，miss 就抛
#           KeyError —— 用户实测因此反复踩"未加载的 so"至少 8 次，
#           每次都要人工确认设备名与本地名怎么对应。
#           更糟的是这套别名规则此前**散落在三处**：
#             mcp_server.tools._pick_so_by_name（全名/basename/归一/版本/后缀）
#             dyn.bridge._match_so            （exact/renamed/normalized/stem/suffix）
#             dyn.rebase.find_module          （全名/basename/版本/去 lib）
#           三套实现互不一致，同一个名字在不同路径上结论可能不同。
#
# 解决方案：把规则收敛成**纯函数**（本节），供 Static 侧（SoFile）与
#           设备侧（RuntimeModule 名）共用：
#             _so_name_core      basename + 小写 + 去壳前缀
#             _so_name_stem      再去 .so / .dylib 扩展名
#             _strip_version_tag 去掉 -1.2.3 这类版本尾巴
#             match_name         在一组候选名里按 7 级依次匹配
#           `match_name` 只在**唯一命中**时返回结果，多候选一律返回歧义列表，
#           由调用方决定报错——绝不"看起来差不多就挑一个"。

# 版本尾巴：只认 -数字(.数字)* 这种形态，纯字母段不剥（libarm64-v8a.so 不动）
_VERSION_SUFFIX_RE = re.compile(
    r"^(?P<core>.+?)(?P<ver>-\d+(?:\.\d+)*)(?P<ext>\.so(?:\..+)?|\.dylib)?$")
# 壳前缀：_t1_ / _ab_ 这类。设备侧加固样本普遍带，不是某个 app 特例
_SHELL_PREFIX_RE = re.compile(r"^_[a-z0-9]{1,4}_", re.IGNORECASE)


def _so_name_core(name: str) -> str:
    """把模块名归一成可比形式：basename + 小写 + 去壳前缀。

    只做**无损规范化**（去路径 / 统一大小写 / 去已知壳前缀），
    不做编辑距离、不做模糊猜测——避免把 liba.so 错配成 libb.so。
    """
    base = str(name or "").rsplit("/", 1)[-1].strip().lower()
    if not base:
        return ""
    m = _SHELL_PREFIX_RE.match(base)
    if m and len(base) > m.end():
        base = base[m.end():]
    return base


def _strip_version_tag(name: str) -> str:
    """去掉文件名里的版本号尾巴，返回"核心名"。

    这条函数原先在 mcp_server.tools 里，现迁到本模块作为**唯一实现**；
    tools 侧保留同名导入以免打断既有调用方（R29 回归测试直接用它）。

    剥离规则（宁可少剥，不可错剥）：
        libsgmainso-6.7.260202.so   -> libsgmainso.so
        libsgmainso.so              -> libsgmainso.so（不变）
        libc++_shared.so            -> libc++_shared.so（++ 和 _ 不动）
        libfoo-1.2.3                -> libfoo
        my-lib.so                   -> my-lib.so（纯字母段不剥）
    """
    base = str(name or "").rsplit("/", 1)[-1]
    if not base:
        return ""
    m = _VERSION_SUFFIX_RE.match(base)
    if m:
        return m.group("core") + (m.group("ext") or "")
    return base


def _so_name_stem(name: str) -> str:
    """归一后再去掉 .so / .dylib 扩展名，用于 liblog 与 liblog.so 的互认。"""
    n = _so_name_core(name)
    for ext in (".dylib", ".so"):
        if n.endswith(ext):
            return n[: -len(ext)]
    return n


def _so_name_no_lib(name: str) -> str:
    """末级归一：去版本号 + 去扩展名 + 去 lib 前缀。

    与 `_so_name_stem` 的区别是**前缀方向双向**：liblog ↔ log 都归到 log。
    只剥开头的 lib，不动中间，避免把 libc++_shared 之类改坏。
    """
    n = _so_name_stem(_strip_version_tag(_so_name_core(name)))
    return n[3:] if n.startswith("lib") and len(n) > 3 else n


def match_name(want: str, names) -> tuple[str | None, str | None, list[str]]:
    """在一组候选名里找 `want` 对应项。**纯函数，不碰任何会话状态**。

    返回 (命中的候选名, 匹配方式, 歧义候选)：
        命中       (name, how, [])          how ∈ exact/basename/normalized/
                                                stem/version/lib/suffix
        候选不唯一 (None, None, [a, b, ...]) —— 调用方必须报错，不能挑一个
        没找到     (None, None, [])

    七级顺序是「越靠前越确定」排的，命中即止：
        1 exact      名字完全一致
        2 basename   只差路径（设备常给 /data/app/xxx/lib/arm64/libfoo.so）
        3 normalized 小写 + 去壳前缀后一致（_t1_libfoo.so ↔ libfoo.so）
        4 stem       再去 .so 扩展名一致（liblog ↔ liblog.so）
        5 version    再去版本号一致（libsgmainso-6.7.260202.so ↔ libsgmainso.so）
        6 lib        再去 lib 前缀一致（libsscronet.so ↔ sscronet.so）
        7 suffix     尾部互相包含（唯一命中且两边都 ≥5 字符才采用）
    """
    names = [n for n in (names or []) if n]
    if not want or not names:
        return None, None, []
    w = str(want)

    # 1) 全名精确
    if w in names:
        return w, "exact", []

    # 2) basename 精确（大小写敏感；大小写差异留给第 3 级统一处理）
    base = w.rsplit("/", 1)[-1]
    if base and base != w and base in names:
        return base, "basename", []

    wc = _so_name_core(w)
    if not wc:
        return None, None, []

    # 3) 归一化后相同
    same = [n for n in names if _so_name_core(n) == wc]
    if len(same) == 1:
        return same[0], "normalized", []
    if same:
        return None, None, same

    # 4) 去扩展名后相同
    ws = _so_name_stem(w)
    if ws:
        same = [n for n in names if _so_name_stem(n) == ws]
        if len(same) == 1:
            return same[0], "stem", []
        if same:
            return None, None, same

    # 5) 去版本号后相同（本地 libsgmainso.so ↔ 设备 libsgmainso-6.7.260202.so）
    wv = _so_name_stem(_strip_version_tag(wc))
    if wv:
        same = [n for n in names if _so_name_stem(_strip_version_tag(_so_name_core(n))) == wv]
        if len(same) == 1:
            return same[0], "version", []
        if same:
            return None, None, same

    # 6) 忽略 lib 前缀后相同（libsscronet.so ↔ sscronet.so）
    wl = _so_name_no_lib(w)
    if wl:
        same = [n for n in names if _so_name_no_lib(n) == wl]
        if len(same) == 1:
            return same[0], "lib", []
        if same:
            return None, None, same

    # 7) 尾部后缀互含：末级兜底，条件放得最严
    #
    # 为什么这一级最危险：前缀/版本/lib 都是**结构化的**（知道自己在剥什么），
    # 而后缀只是一种"看起来像"。不加约束时实测 net.so -> libsscronet.so
    # 也会唯一命中——因为 get() 现在自动解析，这种误配会让人在**错的样本**上
    # 得出结论，比直接报错危险得多。
    # 约束：① 两边归一后都 ≥5 字符（a.so / so 这类短名不参与）；
    #       ② 命中点必须落在**分隔边界**（更长那个的名字在命中处前一个字符
    #          不是字母数字）。于是 sscronet.so 仍能被 lib 级拦下，
    #          而 net.so -> libsscronet.so 这种半截词匹配被拒掉。
    if len(wc) >= 5:
        same = [n for n in names if _suffix_at_boundary(_so_name_core(n), wc)]
        if len(same) == 1:
            return same[0], "suffix", []
        if same:
            return None, None, same

    return None, None, []


def _suffix_at_boundary(long_name: str, short_name: str) -> bool:
    """`short_name` 是否作为**完整词**出现在 `long_name` 尾部。

    (4) 第四次修改（2026-11-13）：新增，给后缀级加安全边界。
        当 short 比 long 长时按反向同样判断（后缀互含本来就是双向的）。
        判定点：截断处前一个字符必须是分隔符（- _ . 等），或正好是开头。
    """
    if not long_name or not short_name:
        return False
    a, b = _so_name_core(long_name), _so_name_core(short_name)
    if not a or not b:
        return False
    # 谁更长谁当 long；两边一样长时说明前面几级就该命中了，这里直接 True
    if len(a) < len(b):
        a, b = b, a
    if len(b) < 5 or not a.endswith(b):
        return False
    if len(a) == len(b):
        return True
    prev = a[-len(b) - 1]
    return not prev.isalnum()



@dataclass
class CallLink:
    """调用链上的一跳。caller/callee 均为跨 so 归一后的表示。"""

    caller_so: str
    caller: str  # 函数名或 sub_xxx
    caller_addr: int
    callee_so: str  # 空串表示未解析的外部导入
    callee: str
    callee_addr: int
    via_plt: bool = False  # 是否经 PLT 间接调用

    def as_text(self) -> str:
        left = f"{self.caller_so}!{self.caller}"
        right = f"{self.callee_so}!{self.callee}" if self.callee_so else f"{self.callee} (未解析)"
        arrow = " ~~> " if self.via_plt else " --> "
        return left + arrow + right


@dataclass
class CallChain:
    """从起点函数出发的调用树。"""

    so_name: str
    func: str
    addr: int
    depth: int = 0
    children: list["CallChain"] = field(default_factory=list)
    truncated: bool = False  # 节点预算耗尽，子树未完整展开

    def count_nodes(self) -> int:
        return 1 + sum(c.count_nodes() for c in self.children)

    def as_text(self, indent: int = 0) -> str:
        pad = "  " * indent
        lines = [f"{pad}{self.so_name}!{self.func} @ {self.addr:#x}"]
        for c in self.children:
            lines.append(c.as_text(indent + 1))
        return "\n".join(lines)


class Session:
    """多 so 分析会话。一个 Session 对应一个工作区。

    (1) 第一次修改（2026-11-11）：加锁。

    bug 原因：server/api.py 的 functions/disasm 等工作在**线程池**里跑，
              而 /api/unload、/api/clear_modules 直接在事件循环里调用
              unload()，它会清空 so.functions 等容器。正在迭代的线程会抛
              "dictionary changed size during iteration"，实测可复现；
              最坏情况是 build_xrefs（20-30 秒）跑到一半被清空，
              返回残缺结果或直接失败。
    解决方案：用 RLock（可重入，因为 add/unload 内部会互相调用），
              并显式提供 locked_dict 快照方法给长读路径用。
              清理动作本身也放到线程池里跑，避免 gc.collect() 卡住事件循环。
    """

    def __init__(self):
        import threading as _threading

        # 可重入锁：add/unload 内部会调 ensure_* 之类的方法，不能自锁死
        self._lock = _threading.RLock()
        self.modules: dict[str, SoFile] = {}  # so 短名 -> 模块
        self._xrefs: dict[str, Xref] = {}
        self._strings: dict[str, StringAnalyzer] = {}
        # 已完成递归函数发现的 (模块, 档位) 签名。
        # (1) 第一次修改（2026-11-18）：从 set[str] 改为 set[tuple]。
        #     bug 原因：只按模块名记忆，导致"先用 off 档跑过、再想换
        #               strict 档"永远返回 skipped——使用者以为工具
        #               不肯跑，实际是被自己的幂等记忆挡住。
        #     解决方案：签名带上 (aggressive, strict_prologue)，
        #               不同档位各跑一次，同档位仍幂等。
        self._discovered: set[tuple[str, bool, bool, bool]] = set()
        self._export_index: dict[str, list[tuple[str, int]]] = {}  # 符号名 -> [(so, addr)]
        self._import_edges: dict[str, list[tuple[str, str]]] = {}  # 导入符号名 -> [(使用方so, plt名)]
        # 用户标注（AI/GUI 写入）：(so_name, addr) -> 注释文本
        self.comments: dict[tuple[str, int], str] = {}
        # 内存 patch（不回写文件）：(so_name, addr) -> byte
        self.patches: dict[tuple[str, int], int] = {}

    # ---------- 加载 ----------

    def add(self, path: str) -> SoFile:
        with self._lock:
            return self._add_locked(path)

    def _add_locked(self, path: str) -> SoFile:
        so = SoFile(path)
        key = so.name
        # 重名 so：后加载的加后缀区分，避免覆盖
        n = 2
        renamed_from = None
        while key in self.modules:
            stem, _, ext = so.name.rpartition(".")
            key = f"{stem}_{n}.{ext}" if ext else f"{so.name}_{n}"
            n += 1
        if key != so.name:
            renamed_from = so.name  # BUG-14 修复：同名自动改名需返回提示
        self.modules[key] = so
        so.name = key
        so.renamed_from = renamed_from

        for name, sym in so.exports.items():
            if sym.is_func and sym.addr > 0:
                self._export_index.setdefault(name, []).append((key, sym.addr))

        self._xrefs[key] = Xref(so, Disassembler(so))
        self._strings[key] = StringAnalyzer(so)
        return so

    def get(self, name: str) -> SoFile:
        """按名字取模块。**名字走统一别名解析**（见 resolve）。

        (4) 第四次修改（2026-11-13）：改为经 resolve 解析。
            bug 原因：原来是严格 `self.modules.get(name)`，设备名与本地文件名
                      有任何差异就抛 KeyError。用户实测因此反复踩
                      "未加载的 so" 至少 8 次（libsscronet.so ↔ sscronet.so、
                      libsgmainso-6.7.260202.so ↔ libsgmainso.so、设备给全路径）。
            解决方案：见 resolve 的说明——选**方案 A**，让 get 内部自动解析。

        为什么这**不会**掩盖"真的没加载"：解析只在**当前已加载的模块**里
        找唯一匹配。命中不了照样抛 KeyError，且错误信息里带已加载列表与
        最接近的候选。也就是说它只改变"用哪个别名找已加载的模块"，
        不改变"模块到底在不在"。
        """
        so, _key = self.resolve(name)
        return so

    def key(self, name: str) -> str:
        """按名字返回**会话内部规范键**（别名解析后的 key）。

        用途：内部字典（_xrefs / _strings / comments / patches）都以规范键
        索引。调用方拿到 SoFile 之后若还要用键，必须先换成规范键，
        否则别名（log.so）在这里又会 KeyError 一次。
        """
        _so, key = self.resolve(name)
        return key

    def resolve(self, name: str) -> tuple[SoFile, str]:
        """统一的别名解析入口：返回 (SoFile, 会话内部规范键)。

        (4) 第四次修改（2026-11-13）：新增，全项目**唯一**的模块名解析入口。

        bug 原因：设备模块名与 mda 键经常不一致（sscronet.so / libsscronet.so、
                  带版本号、带完整路径）。别名规则此前散落在
                  mcp_server.tools._pick_so_by_name、dyn.bridge._match_so、
                  dyn.rebase.find_module 三处，各写一套，容易不一致；
                  且大多数工具直接 `_session.get(so_name)` 就抛 KeyError。
        解决方案：规则收敛到模块级纯函数 match_name，本方法只做两件事：
                  ① 调 match_name 拿唯一命中；
                  ② 失败时抛出**能自愈**的 KeyError —— 带已加载列表、
                     已加载键列表、以及"你是不是想找 xxx"的最接近候选。

        为什么不静默挑一个：多候选说明名字本身有歧义（例如同时加载了
        libutils-1.so 与 libutils-2.so 再问 libutils），此时猜错会让人
        在**错误的样本上**得出结论，比直接报错危险得多。故列出候选让人选。
        """
        mods = self.modules
        if not name:
            raise KeyError(self._missing_msg(name, mods))
        if name in mods:
            return mods[name], name

        # 取快照再匹配：add/unload 可能发生在别的线程（api.py 的线程池）。
        # 直接迭代 live 字典会撞上 "dictionary changed size during iteration"，
        # 而本方法是**所有工具**的入口，失败面比原来只影响 get() 时大得多。
        with self._lock:
            snapshot = dict(mods)
        if not snapshot:
            raise self._missing_exc(name, {}, None)

        hit, _how, amb = match_name(name, list(snapshot))
        if hit is not None:
            return snapshot[hit], hit

        raise self._missing_exc(name, snapshot, amb)

    def _missing_exc(self, name: str, mods: dict, ambiguous) -> KeyError:
        """构造带结构化字段的 KeyError（工具层直接读，不必解析文本）。

        (4) 第四次修改（2026-11-13）：新增。
            为什么挂在异常对象上：报错文本是给人看的，工具层要的是
            code/loaded/candidates 这些字段。让异常自己带上，比让每个
            调用点再查一次 session 干净。
        """
        exc = KeyError(self._missing_msg(name, mods, ambiguous=ambiguous))
        exc.mda_code = "SO_AMBIGUOUS" if ambiguous else "SO_NOT_LOADED"
        exc.mda_loaded = list(mods)
        exc.mda_candidates = [] if ambiguous else self._near_names(name, list(mods))
        return exc


    def _missing_msg(self, name: str, mods: dict, ambiguous=None) -> str:
        """拼"找不到/有歧义"的报错文本，目标是让人**一眼知道下一步做什么**。

        (4) 第四次修改（2026-11-13）：新增。
            bug 原因：原报错只有 `未加载的 so: xxx，当前有 []`——没有候选、
                      没有相似名，用户只能自己回去翻设备上到底叫什么。
            解决方案：① 有歧义 → 列出候选并说明必须用完整名指定；
                      ② 没命中 → 列出已加载名，并给"最接近的候选"；
                      ③ 一个都没加载时直接说先 load_so。
        """
        loaded = list(mods)
        if ambiguous:
            head = f"so 名字有歧义: {name}，同时匹配到 {ambiguous}"
            return (head + f"，当前已加载: {loaded}。"
                    "请用完整名（带版本号/路径）指定是哪一个。")
        if not loaded:
            return (f"未加载的 so: {name}，当前一个都没有。"
                    "先用 load_so 加载 so 文件。")

        near = self._near_names(name, loaded)
        if near:
            # 首个候选单独 "你是不是想找 X？"，其余作为补充列表；标点只留一个句号
            tail = f"你是不是想找 {near[0]}？"
            if len(near) > 1:
                tail += f"（相近候选: {near}）"
            return f"未加载的 so: {name}，{tail}当前已加载: {loaded}"
        return f"未加载的 so: {name}。当前已加载: {loaded}"

    @staticmethod
    def _near_names(name: str, loaded: list[str], limit: int = 3) -> list[str]:
        """给"最接近的候选"：先按归一化名字的相似度，再退到字符相似度。

        (4) 第四次修改（2026-11-13）：新增。
            为什么不只报"没有"：用户已经知道没有——他要的是**该写什么**。
            归一化（去路径/去 lib/去版本/去扩展名）后的相似度比分数字符更像
            人的直觉（sscronet ↔ libsscronet.so 应当排第一）。
        """
        want = _so_name_no_lib(name) or _so_name_core(name)
        if not want:
            return []
        scored: list[tuple[float, str]] = []
        for key in loaded:
            cand = _so_name_no_lib(key) or _so_name_core(key)
            # 双向包含直接给满分：它就是人心里想的那一个
            if cand and (cand == want or cand in want or want in cand):
                score = 1.0
            else:
                score = difflib.SequenceMatcher(None, want, cand).ratio()
            if score >= 0.5:
                scored.append((score, key))
        scored.sort(key=lambda t: (-t[0], t[1]))
        return [k for _s, k in scored[:limit]]

    def xref(self, name: str) -> Xref:
        """取**引用图对象**（Xref 实例），不是引用列表，也**不**自动全量构建。

        (1) 第一次修改（2026-11-06）：
            bug 原因：返回值类型容易误解——调用方常以为 `session.xref(so)`
                      返回"这个 so 的引用列表"或"某个函数对象"，实际返回的是
                      Xref 图对象；直接 print 会看到对象地址，无法判断怎么用。
                      另外传入未加载的名字时只抛 KeyError，信息量不足。
            解决方案：① docstring 写清"返回 Xref 对象"及典型用法；
                      ② 未加载时抛**带解释的** KeyError（列出可用名字）；
                      ③ 补 use 示例，说明"只查单个函数用 ensure_function"。

        ## 返回的是什么

        `Xref` 是**某个 so 的引用图**，常用方法：
            xref.xrefs_to(addr)      -> list[int]   谁引用了这个地址
            xref.xrefs_from(fn_addr) -> list[Instruction]  这个函数引用了谁
            xref.progress()          -> dict        构建进度

        ## 三种用法（按成本从低到高）

            session.xref(so).xrefs_to(addr)            # 已建好图时，直接查
            session.ensure_function(so, addr)          # 只补一个函数，O(该函数)
            session.ensure_xrefs(so)                   # 全量构建，20-30 秒

        ## 注意

        直接调 `xref()` **不会**触发构建。图还没建时查 xrefs_to 可能返回空，
        这时先用 ensure_function 或 ensure_xrefs 补数据——**空结果不等于没有引用**。

        (4) 第四次修改（2026-11-13）：名字改走统一别名解析。
            bug 原因：`self._xrefs` 以**规范键**索引。调用方传别名
                      （log.so / 设备全路径 / 带版本号）时，
                      `_session.get(name)` 已经能解析出来了，但紧接着的
                      `_session.xref(name)` 又拿原始名去 `_xrefs` 里查，
                      于是同一个调用里**前半段成功、后半段 KeyError**。
            解决方案：先用 key(name) 换成规范键，再索引。
        """
        _so, key = self.resolve(name)
        if key not in self._xrefs:
            raise KeyError(
                f"未加载的 so: {name}。当前已加载: {list(self._xrefs)}。"
                "先用 session.load(path) 加载，再调 xref(name)")
        return self._xrefs[key]

    def strings(self, name: str) -> StringAnalyzer:
        """取字符串分析器。名字走统一别名解析（同 xref）。"""
        _so, key = self.resolve(name)
        s = self._strings[key]
        s.build()
        return s

    def ensure_function(self, so_name: str, addr: int) -> Xref:
        """确保某函数的引用已收集（惰性，供 BFS / 单点查询）。"""
        x = self.xref(so_name)
        x.ensure_function(addr)
        return x

    def xref_progress(self, so_name: str) -> dict:
        """引用图构建进度（供脚本/MCP 判断是否需要等全量）。"""
        return self.xref(so_name).progress()

    def ensure_xrefs(self, name: str, discover: bool = True,
                     aggressive: bool = False, progress=None,
                     strict_prologue: bool = True,
                     use_rela: bool = True,
                     use_prologue: bool | None = None) -> Xref:
        """确保引用图与字符串引用归并都完成，返回引用图（**显式全量**，昂贵）。

        字符串的 referenced_by 依赖引用图数据，二者必须一起构建。
        大样本（6000+ 函数）耗时 20-30 秒，建议只在确实需要全库引用时调用；
        查单个函数的引用请用 ensure_function()。

        discover=True 时先做递归函数发现（P2 修复）：
        必须在 build 前补全函数表，否则 calls_to/called_by 虽显示 100% 覆盖，
        实际缺边——因为 FDE 漏掉的函数从未被反汇编，它们发出的调用不可见。

        (4) 第四次修改（2026-11-13）：内部改用规范键。
            bug 原因：`_strings[name]` 与 `discover_functions(name)` 都用原始名，
                      别名进来时会在构建的最后一步（字符串归并）才炸。
            解决方案：方法开头一次性换成规范键，后续全部用 key。
        """
        _so, key = self.resolve(name)
        x = self.xref(key)
        if discover:
            # 阶段一：递归函数发现（0-15%）。这一步会明显改变函数数，
            # 是"为什么这么慢"的主要来源之一，必须让调用方看见。
            if progress:
                progress(0, 100, "函数发现")
            self.discover_functions(key, aggressive=aggressive,
                                    strict_prologue=strict_prologue,
                                    use_rela=use_rela,
                                    use_prologue=use_prologue)
            if progress:
                progress(15, 100, "函数发现完成")

        # 阶段二：逐函数反汇编收集（15-85%）
        def _bridge(done: int, total: int) -> None:
            if not progress:
                return
            pct = 15 + (70 * done // total if total else 70)
            progress(pct, 100, f"反汇编 {done}/{total}")

        # (1) 第一次修改（2026-11-18）：记录建图所用档位。
        #     bug 原因：build_xrefs 命中 cached 分支时直接返回，完全不看
        #               aggressive——使用者传 aggressive=True 得到 386，
        #               以为"激进模式也没多出函数"，实际是被缓存吞了。
        #     解决方案：把档位挂在 Xref 实例上，让上层能如实对比并提示。
        x.discover_tier = {"aggressive": bool(aggressive),
                          "strict_prologue": bool(strict_prologue),
                          "use_rela": bool(use_rela)}
        x.build(progress=_bridge if progress else None)

        # 阶段三：字符串归并（85-100%）
        if progress:
            progress(88, 100, "归并字符串引用")
        self._strings[key].annotate_refs(x.data_refs)
        if progress:
            progress(100, 100, "完成")
        return x

    def discover_functions(self, name: str, max_rounds: int = 6,
                           aggressive: bool = False,
                           strict_prologue: bool = True,
                           use_rela: bool = True,
                           use_prologue: bool | None = None) -> dict:
        """递归补全函数表（bl 目标 + 跳转表入口 + 标准序言，迭代到不动点）。

        幂等且带记忆：已完成过一次就不再重扫（每轮要遍历全库指令，
        6000+ 函数样本约 2-3 秒；重复调用无收益）。

        (4) 第四次修改（2026-11-13）：内部改用规范键。
            bug 原因：`_discovered` / `_xrefs` 都以规范键索引；别名进来时
                      `self._xrefs[name]` 直接 KeyError，且 `_discovered`
                      会记下一个不存在于 `_xrefs` 的别名，污染后续判断。
            解决方案：开头换成规范键，记忆与索引统一用 key。
        """
        _so, key = self.resolve(name)
        # (1) 第一次修改（2026-11-18）：幂等签名带档位。
        #     bug 原因：只记 key，导致换档位重跑永远 skipped。
        #     解决方案：signature 含 (key, aggressive, strict_prologue)；
        #              返回值里带上签名，调用方能看出这次是哪个口径。
        # use_prologue 是 aggressive 的语义化别名：先归一再算签名，
        # 否则 `aggressive=True` 与 `use_prologue=True` 会被当成两个档位各跑一次。
        if use_prologue is not None:
            aggressive = bool(use_prologue)
        sig = (key, bool(aggressive), bool(strict_prologue), bool(use_rela))
        if sig in self._discovered:
            return {"added": 0, "rounds": 0, "total": len(self.get(key).functions),
                    "skipped": True, "signature": {"aggressive": sig[1],
                                                   "strict_prologue": sig[2],
                                                   "use_rela": sig[3]}}
        so = self.get(key)
        x = self.xref(key)
        from server.core.discover import FunctionDiscoverer

        result = FunctionDiscoverer(so, x.disasm).discover(
            max_rounds=max_rounds, aggressive=aggressive,
            strict_prologue=strict_prologue, use_rela=use_rela,
            use_prologue=use_prologue)
        self._discovered.add(sig)
        result["signature"] = {"aggressive": sig[1], "strict_prologue": sig[2],
                               "use_rela": sig[3]}
        return result

    # ---------- 跨 so 符号解析 ----------

    def resolve_import(self, so_name: str, symbol: str) -> tuple[str, int] | None:
        """解析某 so 的导入符号实际落在哪个 so 的哪个地址。

        返回 (目标 so 名, 函数地址)；索引中无此导出时返回 None
        （目标 so 未加载，属正常情况——真实 app 的依赖图往往不完整）。
        """
        cands = self._export_index.get(symbol)
        if not cands:
            return None
        # 同名导出时优先非本 so 的（调用方通常不会调用自己的导入）
        mine = [c for c in cands if c[0] != so_name]
        return (mine or cands)[0]

    def resolve_call(self, so_name: str, target: int) -> CallLink | None:
        """把 so 内的一个调用目标解析为跨 so 的 CallLink。"""
        so = self.get(so_name)
        fn = so.function_at(target)
        if fn is not None:
            return CallLink(
                caller_so=so_name,
                caller=fn.name or f"sub_{fn.addr:x}",
                caller_addr=fn.addr,
                callee_so=so_name,
                callee=fn.name or f"sub_{fn.addr:x}",
                callee_addr=fn.addr,
            )
        # PLT stub -> 导入符号 -> 其他 so 的导出
        imp = so.plt_name(target)
        if imp:
            link = CallLink(
                caller_so=so_name,
                caller=imp + "@plt",
                caller_addr=target,
                callee_so="",
                callee=imp,
                callee_addr=0,
                via_plt=True,
            )
            resolved = self.resolve_import(so_name, imp)
            if resolved:
                link.callee_so, link.callee_addr = resolved
            return link
        # (2) 第二次修改
        # bug 原因：段表模式下桩没有名字（plt_map 为空），旧代码走到这里
        # 直接 return None，call_chain 遇到 None 就 continue，
        # 导致"调用了外部函数"这条边被**静默丢弃**（实测 children=[]）。
        # 解决方案：识别为未解析的外部导入，名字用地址派生（plt_xxxx），
        # 不臆造真实符号名；callee_addr=0 表示外部，调用方据此可提示未解析。
        if so.in_plt_stub(target):
            return CallLink(
                caller_so=so_name,
                caller="",
                caller_addr=target,
                callee_so="",
                callee=f"plt_{target:x}",
                callee_addr=0,
                via_plt=True,
            )
        return None

    # ---------- 跨 so 调用链 ----------

    def call_chain(
        self,
        so_name: str,
        addr: int,
        depth: int = 4,
        seen: set | None = None,
        budget: list | None = None,
        max_nodes: int = 2000,
    ) -> CallChain:
        """从某函数出发递归展开调用树，跨 so 时继续深入。

        防爆炸措施（用户实测 BFS 深度 4 会产出 MB 级文本并拖垮 MCP）：
        - seen：同一函数只展开一次，杜绝环与重复子树
        - max_nodes：全局节点预算，超出停止展开并在结果里标注截断

        (4) 第四次修改（2026-11-13）：入口处把别名换成规范键。
            bug 原因：递归下去时 `link.callee_so` 用的是规范键，而起点用的是
                      用户传的原始名。seen 以 (so_name, addr) 去重，
                      同一函数经别名和经规范键会算成两个不同节点，
                      环检测失效 → 递归展开量翻倍（正是本方法要防的爆炸）。
            解决方案：入口先 resolve 成规范键，节点名也用规范键，
                      外部看到的 CallChain.so_name 因此是**会话里真实的名字**。
        """
        if seen is None:
            seen = set()
        if budget is None:
            budget = [max_nodes]
        _so_entry, so_name = self.resolve(so_name)
        so = self.get(so_name)
        fn = so.function_at(addr)
        key = (so_name, addr)
        node = CallChain(
            so_name=so_name,
            func=(fn.name if fn and fn.name else f"sub_{addr:x}"),
            addr=addr,
        )
        if fn is None or depth <= 0 or key in seen or budget[0] <= 0:
            return node
        seen.add(key)

        x = self.xref(so_name)
        # 惰性：只确保起点函数已收集（BFS 式展开，成本随树大小而非全库）。
        # 必须用 callees_of_fn（快速访问器）：若读属性 x.called_by 会触发
        # 全量构建，call_chain 就从 0.12s 退化回 15s。
        for callee_addr in sorted(set(x.callees_of_fn(addr))):
            if budget[0] <= 0:
                node.truncated = True  # 预算耗尽，调用方可据此提示"结果被截断"
                break
            budget[0] -= 1
            link = self.resolve_call(so_name, callee_addr)
            if link is None:
                continue
            if link.callee_so and link.callee_addr > 0:
                child = self.call_chain(
                    link.callee_so, link.callee_addr, depth - 1, seen, budget, max_nodes
                )
            else:
                child = CallChain(so_name=so_name, func=link.callee, addr=0)
            node.children.append(child)
        return node

    def callers_of(self, symbol: str) -> list[CallLink]:
        """跨 so 反查：谁（哪个 so 的哪个函数）调用了这个符号。

        用于回答「这个导出函数被哪些模块用到」。
        """
        out: list[CallLink] = []
        target = self._export_index.get(symbol, [])
        # 只为「导入了该符号」的模块构建引用图——
        # 惰性改动后 xref() 不再自动全量，这里必须显式补上，
        # 否则 calls_to 为空导致跨 so 反查恒返回 []（e2e 已捕获该回归）。
        importers = {
            so_name for so_name, so in self.modules.items()
            if symbol in set(so.plt_map.values())
        }
        for so_name in importers:
            self.ensure_xrefs(so_name)
        for so_name in importers or set(self.modules):
            so = self.modules[so_name]
            x = self.xref(so_name)
            for stub_addr, stub_name in so.plt_map.items():
                if stub_name != symbol:
                    continue
                for site in x._calls_to.get(stub_addr, []):
                    caller_fn = so.function_at(site)
                    out.append(
                        CallLink(
                            caller_so=so_name,
                            caller=(caller_fn.name or f"sub_{caller_fn.addr:x}") if caller_fn else f"site_{site:x}",
                            caller_addr=site,
                            callee_so=resolved[0] if (resolved := self.resolve_import(so_name, symbol)) else "",
                            callee=symbol,
                            callee_addr=resolved[1] if (resolved := self.resolve_import(so_name, symbol)) else 0,
                            via_plt=True,
                        )
                    )
        return out

    def snapshot_modules(self) -> dict:
        """线程安全的模块字典快照（浅拷贝）。

        (1) 第一次修改（2026-11-11）：新增。

        长读路径（遍历函数表、构建引用图）应该先取快照再迭代，
        这样即使同时有人卸载，也不会撞上 "dictionary changed size"。
        """
        with self._lock:
            return dict(self.modules)

    def summary(self) -> dict:
        """会话概况，供 MCP/GUI 首屏。"""
        return {
            "modules": [
                {
                    "name": name,
                    "arch": int(so.arch),
                    "functions": len(so.functions),
                    "exports": len(so.exports),
                    "imports": len(so.imports),
                }
                for name, so in self.modules.items()
            ],
            "export_symbols": len(self._export_index),
        }

    # ---------------------------------------------------------------- 卸载
    #
    # 为什么需要卸载：实测 2.9MB 的 so 加载后占 **14.7MB** 内存（约 5 倍），
    # 每个函数约 5KB。加载 6 个模块、18.6 万个函数时占用接近 1GB。
    #
    # 为什么不能只 del：实测 `del so; gc.collect()` 只回收 0.5MB（应回收 14.7MB）。
    # 根因是 SoFile 内部存在循环引用（SoFile ↔ Function ↔ Disassembler 等
    # 互相持有），CPython 的引用计数释放不掉，而它又不足以触发分代回收。
    # 所以卸载必须**主动断开内部引用**，否则等于没卸。

    def unload(self, name: str) -> dict:
        """卸载一个模块并释放内存。

        (1) 第一次修改（2026-11-11）：新增。

        释放的是 **mda 进程内的静态分析结果**，不影响目标设备上的 so，
        也不会让正在跑的 App 崩溃。

        返回 {ok, so, freed_estimate_mb} —— freed 是估算值，
        真实回收量受 Python 内存分配器影响，可能小于它。
        """
        with self._lock:
            return self._unload_locked(name)

    def _unload_locked(self, name: str, do_gc: bool = True) -> dict:
        import gc

        key = self._resolve_key(name)
        if key is None:
            # (4) 第四次修改（2026-11-13）：报错带上"最接近的候选"，与 resolve 同口径。
            #     bug 原因：原来只给 "未加载的 so: xxx" + loaded 列表，
            #               别名写错时仍要人工比对。
            #     解决方案：复用 _near_names，给出"你是不是想找 xxx"。
            near = self._near_names(name, list(self.modules))
            return {"ok": False, "code": "SO_NOT_LOADED",
                    "error": self._missing_msg(name, self.modules),
                    "loaded": list(self.modules),
                    "candidates": near}

        so = self.modules.get(key)
        est_mb = round(len(getattr(so, "functions", {}) or {}) * 5 / 1024, 1)

        # ① 从索引里摘掉这个模块的导出符号
        #    注意不能整体清空 _export_index，别的模块还在用
        dead_syms = []
        for sym, owners in self._export_index.items():
            kept = [o for o in owners if o[0] != key]
            if kept:
                self._export_index[sym] = kept
            else:
                dead_syms.append(sym)
        for sym in dead_syms:
            self._export_index.pop(sym, None)

        # ② 摘掉各类缓存。
        #    (2) 第二次修改（2026-11-11）：
        #        bug 原因：原来只 pop 掉 self._xrefs[key] 就算完事，但 Xref 对象
        #                  内部**持有 so 的引用**（Xref.so），而 Xref 又反过来
        #                  被 so 引用不到——它是个独立的环。pop 掉字典项只是
        #                  少了一个外部引用，Xref ↔ so ↔ Disassembler 这个环
        #                  还在，gc 回收不掉，所以实测卸载后只回收 0.6/23 MB。
        #        解决方案：pop 之前**先把 Xref / StringAnalyzer 内部的大容器清空**，
        #                  再断开它们对 so 的引用，最后才从字典移除。
        xref_obj = self._xrefs.pop(key, None)
        strs_obj = self._strings.pop(key, None)
        self._purge_helper(xref_obj)
        self._purge_helper(strs_obj)

        self.modules.pop(key, None)
        self._import_edges.pop(key, None)
        # (1) 第一次修改（2026-11-18）：签名是元组，逐个档位清除。
        for _sig in [t for t in self._discovered if t[0] == key]:
            self._discovered.discard(_sig)

        # ③ 主动断开 SoFile 内部引用。
        #    这一步是**必须的**：不做的话 gc 回收不掉（实测只回收 0.5/14.7 MB）。
        freed_objs = self._break_references(so)

        # (3) 打上已卸载标记：避免出现"僵尸对象"——
        #     清空容器后 function_at 返回 None，但 read() 还可能从残留缓存读到数据，
        #     行为不一致。有了标记，公开方法可以明确报错。
        try:
            so._unloaded = True
        except Exception:                                 # noqa: BLE001
            pass
        del so
        if do_gc:
            gc.collect()
        return {
            "ok": True,
            "so": key,
            "freed_estimate_mb": est_mb,
            "broken_objects": freed_objs,
            "remaining": list(self.modules),
            "note": ("已释放 mda 内的静态分析结果；"
                     "不影响设备上运行的进程。"),
        }

    def clear(self, keep=None) -> dict:
        """批量卸载，可指定保留哪些。

        (1) 第一次修改（2026-11-11）：新增。

        用法：
            clear()                            # 全清
            clear(keep=["libil2cpp.so"])       # 只留这个
        """
        # (2) 第二次修改（2026-11-11）：
        #     bug 原因：`{str(x) for x in (keep or [])}` 在 keep 传**字符串**时
        #               会按字符拆开——clear(keep="liblog.so") 得到的集合是
        #               {'l','i','b','o','g','.','s'}，于是**一个都不匹配**，
        #               把全部模块都清空了。实测复现：加载 2 个模块，
        #               传 keep="liblog.so" 后剩余 []。这是数据丢失级 bug。
        #     解决方案：① 传 str 视为"单个模块名"（这是调用方最自然的意图）；
        #               ② 传 list 时逐个校验必须是 str，否则直接报错，
        #                  不猜、不静默降级。
        if keep is None:
            keep_list: list[str] = []
        elif isinstance(keep, str):
            keep_list = [keep]
        elif isinstance(keep, (list, tuple, set)):
            keep_list = []
            for x in keep:
                if not isinstance(x, str):
                    return {"ok": False, "code": "BAD_KEEP",
                            "error": f"keep 里必须是字符串，收到 {type(x).__name__}",
                            "hint": "正确写法：keep=['a.so', 'b.so'] 或 keep='a.so'"}
                keep_list.append(x)
        else:
            return {"ok": False, "code": "BAD_KEEP",
                    "error": f"keep 必须是字符串或字符串列表，收到 {type(keep).__name__}"}

        keep_set = set(keep_list)
        with self._lock:
            targets = [k for k in list(self.modules) if k not in keep_set]
        if not targets:
            return {"ok": True, "freed": [], "remaining": list(self.modules),
                    "note": "没有需要清理的模块"}

        # (3) 第三次修改（2026-11-11）：
        #     bug 原因：原来每个模块调一次 unload()，而 unload 内部有一次
        #               gc.collect() —— 批量清理 20 个模块就是 20 次全量 GC。
        #     解决方案：批量时走内部无 GC 的路径，最后统一 gc 一次。
        freed = []
        with self._lock:
            for k in targets:
                r = self._unload_locked(k, do_gc=False)
                if r.get("ok"):
                    freed.append({"so": k,
                                  "est_mb": r.get("freed_estimate_mb")})
        import gc as _gc

        _gc.collect()
        return {
            "ok": True,
            "freed": freed,
            "freed_count": len(freed),
            "est_total_mb": round(sum(f["est_mb"] or 0 for f in freed), 1),
            "remaining": list(self.modules),
        }

    def memory_usage(self) -> dict:
        """估算各模块占用的内存，供用户在清理前判断。

        (1) 第一次修改（2026-11-11）：新增。

        为什么给估算而不是精确值：精确测量要遍历整个对象图（慢且会触发
        完整 gc，反而影响正在进行的分析）。按实测比例
        「每函数约 5KB」估算，误差在可接受范围内，足够用来决策。
        """
        rows = []
        with self._lock:
            items = list(self.modules.items())
        for name, so in items:
            n = len(getattr(so, "functions", {}) or {})
            rows.append({
                "so": name,
                "functions": n,
                "exports": len(getattr(so, "exports", {}) or {}),
                "est_mb": round(n * 5 / 1024, 1),
            })
        rows.sort(key=lambda r: -(r["est_mb"] or 0))
        return {
            "count": len(rows),
            "modules": rows,
            "est_total_mb": round(sum(r["est_mb"] for r in rows), 1),
            "note": ("est_mb 按实测「每函数约 5KB」估算。"
                     "实测 2.9MB 的 so 加载后占约 14.7MB。"),
        }

    def _resolve_key(self, name: str) -> str | None:
        """把用户给的名字（可能是原文件名/短名/重命名后的名字）解析成内部键。

        (4) 第四次修改（2026-11-13）：改为复用统一解析器，只多保留一条
            原逻辑独有的规则——`renamed_from`（同名 so 二次加载被自动改名，
            如 liblog.so -> liblog.so_2，用户仍会按原名 liblog.so 找它）。

        bug 原因：这里原有一份自己的四级匹配（全名 / renamed_from / basename /
                 去扩展名），与 match_name 那套并存。于是 unload("log.so")
                  可能成功，而 get("log.so") 用的另一套规则判为未加载，
                  同一个名字在两个方法上结论不一致。
        解决方案：renamed_from 优先（它只有 Session 知道），其余交给 match_name。
        """
        if not name:
            return None
        if name in self.modules:
            return name
        for key, so in self.modules.items():
            if getattr(so, "renamed_from", None) == name:
                return key
        hit, _how, _amb = match_name(name, list(self.modules))
        return hit

    @staticmethod
    def _purge_helper(obj) -> int:
        """清空 Xref / StringAnalyzer / Disassembler 这类辅助对象内部的大容器。

        (2) 第二次修改（2026-11-11）：新增。

        为什么需要单独处理：这些对象与 SoFile 互相持有引用，形成环。
        只把它们从 session 的字典里 pop 掉，引用计数不会归零，
        gc 也不会主动回收——实测卸载 3 份模块只回收 0.6MB（应回收 23MB）。

        做法：把属性值里「容器类」的清空、指向 so 的引用断开。
        """
        if obj is None:
            return 0
        n = 0
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict):
            for attr, val in list(d.items()):
                try:
                    # 断开对 SoFile 的引用（这是环的关键一环）
                    if type(val).__name__ == "SoFile":
                        d[attr] = None
                        n += 1
                    elif isinstance(val, (dict, list, set)):
                        val.clear()
                        n += 1
                    elif isinstance(val, (bytes, bytearray)):
                        d[attr] = b""
                        n += 1
                except Exception:                         # noqa: BLE001
                    continue
        return n

    @staticmethod
    def _break_references(so) -> int:
        """主动断开 SoFile 的内部引用，让 gc 真正回收。

        (1) 第一次修改（2026-11-11）：新增。

        bug 原因：实测 `del so; gc.collect()` 只回收 0.5MB 而非 14.7MB。
                  SoFile 内部 functions / symbols / sections / 反汇编缓存
                  之间互相引用，形成环；引用计数归零不了，
                  而分代回收不会因为一个从字典里摘掉的对象就立刻动手。
        解决方案：把持有大对象引用的容器逐个清空。
                  只清容器内容（clear()），不递归遍历整图——
                  那样慢且可能踩到半初始化对象。
        """
        # (3) 第三次修改（2026-11-11）：
        #     bug 原因：review 指出漏清 _cache（节数据字节）、_elf、_starts、
        #               _loads、plt_map、plt_stubs、_stub_sorted、_func_ranges。
        #               实测 libbase 带外部引用卸载后仍残留 _cache 24 项，
        #               实际只回收 0.62/1.16 MB——对带节表的大 so 这部分不小。
        #     解决方案：把 SoFile 内部所有持有大对象的容器都列进来。
        n = 0
        for attr in ("functions", "symbols", "sections", "imports",
                     "exports", "strings", "relocations", "plt",
                     "loads", "_raw", "data",
                     # (3) 补漏的字段
                     "_cache", "_elf", "_starts", "_loads",
                     "plt_map", "plt_stubs", "_stub_sorted",
                     "_func_ranges", "_segments", "_phdrs"):
            obj = getattr(so, attr, None)
            if obj is None:
                continue
            try:
                if isinstance(obj, (dict, list, set)):
                    obj.clear()
                    n += 1
                elif isinstance(obj, (bytes, bytearray)):
                    setattr(so, attr, b"")
                    n += 1
                elif hasattr(obj, "clear") and callable(obj.clear):
                    obj.clear()
                    n += 1
            except Exception:                             # noqa: BLE001
                continue
        try:
            sol = getattr(so, "_stream", None)
            if sol is not None:
                sol.close()
                n += 1
        except Exception:                                 # noqa: BLE001
            pass
        return n
