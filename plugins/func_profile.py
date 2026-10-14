"""导出函数画像插件：给导出函数做参数寄存器使用统计。

逆向时快速判断某导出函数"大概怎么调"：x0 是不是指针、
是否用到 x1/x2、是否调 memcpy/strcpy 类危险函数。
"""
from core.plugins import PluginBase


class Plugin(PluginBase):
    name = "func_profile"
    description = "导出函数画像：指令数/调用数/引用字符串数/危险函数调用"
    usage = '{"so_name": "liblog.so", "limit": 20}'

    # 常见危险/敏感 libc 函数，命中则在画像中标记
    DANGEROUS = ("strcpy", "strcat", "sprintf", "gets", "system", "exec", "memcpy")

    def run(self, session, args: dict):
        so_name = args.get("so_name")
        limit = int(args.get("limit", 20))
        so = session.get(so_name)
        x = session.xref(so_name)

        profiles = []
        for name, sym in list(so.exports.items())[:limit]:
            if not sym.is_func or sym.addr <= 0:
                continue
            fn = so.function_at(sym.addr)
            if fn is None:
                continue
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
                "insns": len(insns),
                "calls": sorted(set(calls))[:10],
                "dangerous": danger,
                "strings": len(fn.string_refs),
            })
        return profiles
