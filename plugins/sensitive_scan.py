"""敏感信息扫描插件：自动找 URL / IP / 密钥特征的字符串。

演示插件三要素：name/description/run。
"""
from core.plugins import PluginBase


class Plugin(PluginBase):
    name = "sensitive_scan"
    description = "扫描已加载 so 的字符串，提取 URL/IP/文件路径/密钥特征"
    usage = '{"so_name": "liblog.so", "kind": "url|ip|path|key|all"}'

    # 特征前缀，按需扩充
    _URL = ("http://", "https://", "ws://", "wss://")
    _KEY = ("api_key", "apikey", "secret", "token", "passwd", "password", "AKIA")

    def run(self, session, args: dict):
        so_name = args.get("so_name")
        kind = args.get("kind", "all")
        hits = {"url": [], "ip": [], "path": [], "key": []}
        import re

        ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        path_re = re.compile(r"^(/[\w./-]+)$")

        for st in session.strings(so_name).all_strings():
            v = st.value
            if kind in ("all", "url") and v.startswith(self._URL):
                hits["url"].append({"addr": hex(st.addr), "value": v[:200]})
            if kind in ("all", "ip") and ip_re.search(v):
                hits["ip"].append({"addr": hex(st.addr), "value": v[:120]})
            if kind in ("all", "path") and path_re.match(v):
                hits["path"].append({"addr": hex(st.addr), "value": v[:120]})
            if kind in ("all", "key") and any(k in v.lower() for k in self._KEY):
                hits["key"].append({"addr": hex(st.addr), "value": v[:120]})
        return {k: v[:50] for k, v in hits.items() if v}
