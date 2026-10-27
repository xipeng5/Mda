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
    """多 so 分析会话。一个 Session 对应一个工作区。"""

    def __init__(self):
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
        """取引用图。**不**自动全量构建（避免每次调用付 20-30 秒）。

        需要全量数据显式调 ensure_xrefs()/build_xrefs()；
        只查单个函数用 ensure_function()，成本从 O(全库) 降到 O(该函数)。
        """
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
