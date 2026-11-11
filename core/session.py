"""多 so 会话：全局符号索引与跨 so 调用链。

这是本项目区别于单文件反汇编工具的核心：
- 同时加载多个 so，建立 全局导出符号表
- liba.so 调用 libb.so 的 foo() 时，能沿 PLT -> 导入符号 -> 目标 so 的导出函数
  解析出真实落点，从而给出跨 so 调用链
- 人工在 GUI 里看结果，AI 通过 MCP/脚本通道调用同一套接口

依赖 core.elf_model / core.disasm / core.xref / core.strings。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.disasm import Disassembler
from core.elf_model import SoFile
from core.strings import StringAnalyzer
from core.xref import Xref


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
        self._discovered: set[str] = set()  # 已完成递归函数发现的模块
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
        so = self.modules.get(name)
        if so is None:
            raise KeyError(f"未加载的 so: {name}，当前有 {list(self.modules)}")
        return so

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
        """
        if name not in self._xrefs:
            raise KeyError(
                f"未加载的 so: {name}。当前已加载: {list(self._xrefs)}。"
                "先用 session.load(path) 加载，再调 xref(name)")
        return self._xrefs[name]

    def strings(self, name: str) -> StringAnalyzer:
        s = self._strings[name]
        s.build()
        return s

    def ensure_function(self, so_name: str, addr: int) -> Xref:
        """确保某函数的引用已收集（惰性，供 BFS / 单点查询）。"""
        x = self._xrefs[so_name]
        x.ensure_function(addr)
        return x

    def xref_progress(self, so_name: str) -> dict:
        """引用图构建进度（供脚本/MCP 判断是否需要等全量）。"""
        return self._xrefs[so_name].progress()

    def ensure_xrefs(self, name: str, discover: bool = True,
                     aggressive: bool = False) -> Xref:
        """确保引用图与字符串引用归并都完成，返回引用图（**显式全量**，昂贵）。

        字符串的 referenced_by 依赖引用图数据，二者必须一起构建。
        大样本（6000+ 函数）耗时 20-30 秒，建议只在确实需要全库引用时调用；
        查单个函数的引用请用 ensure_function()。

        discover=True 时先做递归函数发现（P2 修复）：
        必须在 build 前补全函数表，否则 calls_to/called_by 虽显示 100% 覆盖，
        实际缺边——因为 FDE 漏掉的函数从未被反汇编，它们发出的调用不可见。
        """
        x = self.xref(name)
        if discover:
            self.discover_functions(name, aggressive=aggressive)
        x.build()
        self._strings[name].annotate_refs(x.data_refs)
        return x

    def discover_functions(self, name: str, max_rounds: int = 6,
                           aggressive: bool = False) -> dict:
        """递归补全函数表（bl 目标 + 跳转表入口 + 标准序言，迭代到不动点）。

        幂等且带记忆：已完成过一次就不再重扫（每轮要遍历全库指令，
        6000+ 函数样本约 2-3 秒；重复调用无收益）。
        """
        if name in self._discovered:
            return {"added": 0, "rounds": 0, "total": len(self.get(name).functions),
                    "skipped": True}
        so = self.get(name)
        x = self._xrefs[name]
        from core.discover import FunctionDiscoverer

        result = FunctionDiscoverer(so, x.disasm).discover(
            max_rounds=max_rounds, aggressive=aggressive)
        self._discovered.add(name)
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
        """
        if seen is None:
            seen = set()
        if budget is None:
            budget = [max_nodes]
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
            return {"ok": False, "code": "SO_NOT_LOADED",
                    "error": f"未加载的 so: {name}",
                    "loaded": list(self.modules)}

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
        self._discovered.discard(key)

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
        """把用户给的名字（可能是原文件名/短名/重命名后的名字）解析成内部键。"""
        if not name:
            return None
        if name in self.modules:
            return name
        for key, so in self.modules.items():
            if getattr(so, "renamed_from", None) == name:
                return key
        # 退一步：按 basename 或去扩展名匹配
        import os as _os

        base = _os.path.basename(str(name))
        for key in self.modules:
            if key == base or _os.path.splitext(key)[0] == _os.path.splitext(base)[0]:
                return key
        return None

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
