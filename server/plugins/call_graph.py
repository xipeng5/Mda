"""调用图插件（通用能力）。

## 解决什么问题

现有 call_chain 是"给一个地址展开调用树"，没有全局图。
用户想要 "root=0x202ef8 的调用关系树 + 哪些是叶子/枢纽"。

## 做法

    - 从 root 出发 BFS/DFS，复用现有 xref 的调用边
    - 输出树形结构（带深度）
    - 统计：叶子节点、枢纽节点（被调用次数多）

## 为什么是通用能力

纯调用关系遍历，不硬编码任何具体函数。
"""
from __future__ import annotations

from collections import Counter

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "call_graph"
    description = "从 root 展开调用图，标注叶子/枢纽节点"
    usage = ("args: {so: str, addr: str|int, depth: int=3, "
             "max_nodes: int=200}")

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name or args.get("addr") is None:
            return {"error": "需要 so 与 addr", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        a = args["addr"]
        root = int(str(a), 16) if isinstance(a, str) and \
               str(a).lower().startswith("0x") else int(a)
        depth = int(args.get("depth", 3))
        max_nodes = int(args.get("max_nodes", 200))

        # 用 session 的 xref 模型取 callee
        try:
            xr = session.xref(so_name)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"取引用模型失败：{exc}", "code": "NO_XREF"}

        def callees(addr):
            out = []
            try:
                # (1) xrefs_from 返回的是 Instruction 列表，
                #     bl 目标在 .call_target，数据引用在 .ref_addr（这里只要 call）。
                insns = xr.xrefs_from(addr) or []
                for ins in insns:
                    t = getattr(ins, "call_target", None)
                    if t is not None:
                        out.append(int(t))
            except Exception:                             # noqa: BLE001
                pass
            return out

        mod_lo = min([s.addr for s in getattr(so, "sections", [])] or [0])
        mod_hi = max([s.addr + s.size for s in getattr(so, "sections", [])] or [1 << 63])
        cross_so = []
        visited: dict[int, int] = {}
        tree = []

        def walk(addr, d, parent):
            if d > depth or len(visited) >= max_nodes:
                return
            fn = so.function_at(addr)
            name = fn.name if fn and fn.name else f"sub_{addr:x}"
            if addr in visited:
                return
            visited[addr] = len(visited)
            node = {"addr": hex(addr), "name": name, "depth": d,
                    "parent": parent, "callees": []}
            tree.append(node)
            for c in callees(addr):
                node["callees"].append(hex(c))
                if not (mod_lo <= c < mod_hi):
                    cross_so.append({"from": hex(addr), "to": hex(c),
                                     "note": "目标本 so 范围内，可能在其它 so 或 PLT"})
                else:
                    walk(c, d + 1, hex(addr))

        walk(root, 0, None)

        # 枢纽：出现在多个 callees 列表里的节点
        incoming = Counter()
        for node in tree:
            for c in node["callees"]:
                incoming[c] += 1
        hubs = [{"addr": a, "incoming": n} for a, n in incoming.most_common(5)]
        leaves = [n for n in tree if not n["callees"]]

        return {
            "ok": True, "so": so.name,
            "root": hex(root), "depth": depth,
            "node_count": len(tree),
            "leaf_count": len(leaves),
            "leaves": [{"addr": n["addr"], "name": n["name"]} for n in leaves[:20]],
            "hubs": hubs,
            "cross_so": cross_so[:20],
            "java_callers": ("用 java_find_callers(class_name=..., method=...) "
                             "获取 Java 层调用者；本插件只覆盖 native 调用图"),
            "tree": tree[:max_nodes],
            "note": ("调用边来自 mda 的 xref 模型（可能不完整，"
                     "先 build_xrefs 可提高覆盖）。枢纽=被多个节点调用。"),
        }
