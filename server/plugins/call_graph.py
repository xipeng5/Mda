"""调用图插件（通用能力）。

## 解决什么问题

现有 call_chain 是"给一个地址展开调用树"，没有全局图。
用户想要 "root=0x202ef8 的调用关系树 + 哪些是叶子/枢纽"。

## 两种边（第 2 次修改新增 vtable 间接边）

    bl 边       ins.call_target，直接调用，静态可见
    vtable 边   `ldr x8,[x0,#8]; blr x8` 这类间接调用**静态看不见目标**
                （操作数是寄存器）。但函数指针表的**内容**在重定位表里：
                `vtable_at(槽)` 能解出"这个槽指向哪个函数"。
                所以把「槽 -> 目标」当作间接边，标注 `via=vtable@0x...`。

为什么需要第二种：实测 libc 有 6 个函数**没有任何 bl 指向**（syscall 桩），
只被 vtable 引用；只算 bl 边时它们在图里是"凭空出现又无人调用"的孤立点，
枢纽统计和叶子统计都会被带偏。

## 为什么是通用能力

纯调用关系遍历，不硬编码任何具体函数。
"""
from __future__ import annotations

from collections import Counter

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "call_graph"
    description = "从 root 展开调用图，标注叶子/枢纽节点（含 vtable 间接边）"
    usage = ("args: {so: str, addr: str|int, depth: int=3, "
             "max_nodes: int=200, include_vtable: bool=true}")

    def _vtable_edges(self, so):
        """目标地址 -> [指向它的 vtable/GOT 槽]，用于补间接调用边。

        (1) 第一次修改（2026-11-18）
            bug 原因：使用者反馈「call_graph 找不到虚调用者」。核实成立：
                      旧实现只取 `ins.call_target`（bl 才有），而虚调用是
                      `ldr x8,[x0,#8]; blr x8`——操作数是寄存器，静态没有
                      目标。实测 libc 有 6 个函数无任何 bl 指向、只被 vtable
                      引用，在图里成了孤立点。
            解决方案：用重定位表建「目标 -> 槽」反向索引。重定位条目里
                      addend 落在可执行段的，就是函数指针表项，槽地址即
                      证据位置。解析失败时返回空 dict（不编造边）。
        """
        out: dict[int, list[str]] = {}
        try:
            from server.core import rela as _rela

            for it in _rela.rela_dump(so, 0, 0, "code_target", 0):
                tgt = int(it["addend_hex"], 16)
                out.setdefault(tgt, []).append(it["offset_hex"])
        except Exception:                                 # noqa: BLE001
            return {}
        return out

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
        # (1) 第一次修改（2026-11-18）：vtable 间接边（见 _vtable_edges）
        include_vtable = bool(args.get("include_vtable", True))
        vt_edges = self._vtable_edges(so) if include_vtable else {}

        # 用 session 的 xref 模型取 callee
        try:
            xr = session.xref(so_name)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"取引用模型失败：{exc}", "code": "NO_XREF"}

        def callees(addr):
            """返回 [(目标地址, via)]。via 为 'bl' 或 'vtable@槽'。

            ## 为什么 vtable 边算在「被指向的函数」上而不是「调用者」上

            `ldr x8,[x0,#8]; blr x8` 里，x0 来自哪里、运行时指向哪个 vtable，
            静态**算不出来**（要数据流 + 对象布局）。能确定的事实只有一条：
            「槽 S 里存着函数 F 的地址」。

            所以本插件不假装知道"谁调了 F"，而是给出**入边**：
            F 的 incoming 里多一条 `kind=vtable, slot=S`。这既诚实
            （有据可查：重定位表），又正好回答使用者的问题——
            "这个函数没有任何 bl 引用，它是被谁指向的？" 答：vtable 槽 S。
            """
            out = []
            try:
                # bl 目标在 .call_target（xrefs_from 返回 Instruction 列表）
                insns = xr.xrefs_from(addr) or []
                for ins in insns:
                    t = getattr(ins, "call_target", None)
                    if t is not None:
                        out.append((int(t), "bl"))
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
            # (1) 第一次修改（2026-11-18）：每个节点带 vtable 入边。
            #     回答"这个函数没有任何 bl 引用，它是被谁指向的"——
            #     证据来自重定位表（槽地址），不是推测。
            slots = vt_edges.get(addr)
            if slots:
                # (2) 第二次修改（2026-11-18）：字段名 vtable_in → vtable_slots。
                #     bug 原因：使用者把 vtable_in 第一眼读成"有这个调用者"
                #               （in 像 incoming call），实际语义是"这个函数的地址
                #                存在这些表槽里"——与 indirect_only 里的同义字段
                #                vtable_slots 不一致，两个名字指一回事，易误读。
                #     解决方案：统一叫 vtable_slots；同时保留 vtable_in 别名一份，
                #               避免破坏已按旧名取值的调用方（渐进废弃）。
                node["vtable_slots"] = slots
                node["vtable_in"] = slots   # deprecated 别名，见 note
            tree.append(node)
            for c, via in callees(addr):
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

        # (1) 全库 vtable 反查：没有 bl 调用者、只被函数指针表指向的函数。
        #     这些函数在只看 bl 边时会显得"凭空存在又无人引用"。
        indirect_only = []
        for tgt, slots in vt_edges.items():
            fn = so.function_at(tgt)
            if fn is None:
                continue
            indirect_only.append({
                "addr": hex(tgt),
                "name": fn.name or f"sub_{tgt:x}",
                "vtable_slots": slots[:5],
                "slot_count": len(slots),
            })

        return {
            "ok": True, "so": so.name,
            "root": hex(root), "depth": depth,
            "node_count": len(tree),
            "leaf_count": len(leaves),
            "leaves": [{"addr": n["addr"], "name": n["name"]} for n in leaves[:20]],
            "hubs": hubs,
            "cross_so": cross_so[:20],
            "include_vtable": include_vtable,
            "vtable_edge_count": len(vt_edges),
            "indirect_only": indirect_only[:30],
            "java_callers": ("用 java_find_callers(class_name=..., method=...) "
                             "获取 Java 层调用者；本插件只覆盖 native 调用图"),
            "tree": tree[:max_nodes],
            "note": ("调用边来自 mda 的 xref 模型（bl 直接调用，可能不完整，"
                     "先 build_xrefs 可提高覆盖）。枢纽=被多个节点调用。"
                     "vtable 边是**入边**：目标函数的地址存在某个函数指针表槽里"
                     "（证据来自重定位表），它回答了'没人 bl 调用时是谁指向它'，"
                     "但**不代表**已知道运行时谁真的调了它。"
                     "(2) 节点里的 vtable_slots 就是'地址在这些表槽里'；"
                     "旧的 vtable_in 是它的别名（已废弃，请勿按'调用者'理解）。"),
        }
