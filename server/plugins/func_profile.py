"""函数画像插件：给函数做参数寄存器使用统计。

逆向时快速判断某函数"大概怎么调"：x0 是不是指针、
是否用到 x1/x2、是否调 memcpy/strcpy 类危险函数。

## 修改记录

(1) 第一次修改（2026-11-18）：
    bug 原因：原实现只遍历 `so.exports`，加固 so 抹掉导出表后只返回极少画像
              （实测 exports 砍到 1 个 JNI_OnLoad 时只返回 1 条，而 so.functions
              有 1984 个）；且参数名只认 `so_name`，与全项目多数插件用 `so`
              的约定不一致，缺失时走到 `session.get(None)` 抛误导性的
              KeyError「未加载的 so: None」，使用者误以为 so 掉了。
    解决方案：① 同时接受 so/so_name（优先 so），缺失直接返回清晰的 BAD_ARGS；
              ② 改遍历 so.functions，导出/有符号名优先、按大小降序；
              ③ 函数表 < 100 时给出与 load_so 一致的不完整警告；
              ④ 返回结构化 dict，legacy_list=true 时兼容旧的裸 list。
"""
from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "func_profile"
    description = "函数画像：指令数/调用数/引用字符串数/危险函数调用（覆盖全函数表）"
    usage = ('{"so": "liblog.so", "limit": 20}  '
             '// 也接受 so_name；legacy_list=true 时返回裸 list')

    # 常见危险/敏感 libc 函数，命中则在画像中标记（判定保持原样）
    DANGEROUS = ("strcpy", "strcat", "sprintf", "gets", "system", "exec", "memcpy")

    @staticmethod
    def _source_of(fn) -> str:
        """画像来源：export=动态导出 / symbol=有符号名 / discovered=纯发现。"""
        if fn.is_export:
            return "export"
        if fn.name:
            return "symbol"
        return "discovered"

    @classmethod
    def _order_key(cls, fn):
        """排序：导出优先，其次有符号名，最后纯发现；同级按函数大小降序。

        导出函数有明确符号且有真实调用约定，画像最有用；大函数更可能是
        核心逻辑，所以排在前面，保证 limit 较小也能拿到最有价值的目标。
        """
        if fn.is_export:
            tier = 0
        elif fn.name:
            tier = 1
        else:
            tier = 2
        return (tier, -fn.size)

    def _table_warning(self, n: int) -> dict:
        """函数表不完整时的警告（措辞对齐 load_so 的 _so_table_warning）。

        不直接 import server.mcp_server.tools._so_table_warning：那是重量级
        MCP 模块，插件由 PluginManager 动态加载，引入它会拉入整条 MCP 依赖链，
        且存在循环导入风险。这里只复用判定阈值与文案思路。
        """
        if n >= 100:
            return {}
        return {
            "warning": (
                f"函数表只有 {n} 个，可能不完整。"
                "基于它得出的『没有某个符号/函数』这类**否定结论不可信**——"
                "先补全再下结论（曾有人因这一步漏掉，误判某个 so 没有某个导入而"
                "排除了一整个方向）。"),
            "next_step": (
                "调 build_xrefs 或 load_so(auto_discover=True)"
                "（会递归补出 bl 目标与跳转表入口；大样本约 40 秒）"),
        }

    def run(self, session, args: dict):
        # (1) 参数兼容：优先 so，其次 so_name；两者都无则明确报错，
        #     不再走 session.get(None) 产生误导性的 KeyError。
        so_name = args.get("so") or args.get("so_name")
        if not so_name:
            return {
                "error": f"缺少参数 so（也接受 so_name），你给的参数有: {list(args.keys())}",
                "code": "BAD_ARGS",
            }
        limit = int(args.get("limit", 20))
        legacy_list = bool(args.get("legacy_list", False))

        # (2) 第二次修改（2026-11-26）
        # bug 原因：1) 未捕获 session.get() 的 KeyError，so 未加载时直接抛异常而非返 SO_NOT_LOADED；
        #           2) 未先确保单函数 xref（ensure_function），导致未提前 build_xrefs 时 fn.string_refs 恒为 0；
        #           3) 未捕获非 ARM64 架构下创建 xref/Disassembler 抛出的 ValueError。
        # 解决方案：捕获 KeyError 返 SO_NOT_LOADED、捕获 ValueError 返 UNSUPPORTED_ARCH；
        #           遍历函数时优先调用 x.ensure_function(fn.addr) 以填充 string_refs 与指令。
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"ok": False, "error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        # 用规范名取 xref，避免别名在前半段成功、后半段 KeyError
        try:
            x = session.xref(so.name)
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH", "error": str(exc)}

        profiles = []
        # (1) 改遍历整张函数表，而不是被抹掉的导出表
        funcs = sorted(so.functions.values(), key=self._order_key)[:limit]
        for fn in funcs:
            if fn.addr <= 0:
                continue
            if hasattr(x, "ensure_function"):
                x.ensure_function(fn.addr)
            name = fn.name or f"sub_{fn.addr:x}"
            insns = fn.instructions or x.disasm.disasm_function(fn.addr)
            calls = []
            for ins in insns:
                if ins.is_call and ins.call_target is not None:
                    cname = so.plt_name(ins.call_target)
                    if cname:
                        calls.append(cname)
            danger = sorted({c for c in calls if any(d in c for d in self.DANGEROUS)})
            profiles.append({
                "name": name,
                "addr": hex(fn.addr),
                "size": fn.size,
                "source": self._source_of(fn),
                "insns": len(insns),
                "calls": sorted(set(calls))[:10],
                "dangerous": danger,
                "strings": len(fn.string_refs),
            })

        # (1) 兼容旧的裸 list 调用方；默认返回结构化结果
        if legacy_list:
            return profiles
        return {
            "ok": True,
            "so": so.name,
            "function_count": len(so.functions),
            **self._table_warning(len(so.functions)),
            "profiles": profiles,
        }
