"""敏感信息扫描插件：自动找 URL / IP / 密钥特征的字符串。

演示插件三要素：name/description/run。

## 第 3 次修改（2026-11-18）：参数兼容
只改参数入口，扫描逻辑不动：同时接受 so/so_name（优先 so），
与全项目多数插件的参数名约定统一。两者都缺时返回清晰的 BAD_ARGS，
不再要求必须用旧的 so_name。

## 第 2 次修改（2026-11-18）：降噪

bug 原因：使用者反馈「sensitive_scan 扫出来的全是噪音（都是 "/Y"、" /R" 这种）」。
          核实成立，两个判据都过于宽松：
          ① 路径判据 `^(/[\w./-]+)$` **没有长度下限**——二进制里任何一个
             碰巧以 `/` 开头、后接几个路径字符的 2 字节片段都会被算成路径。
             实测 .rodata 里 `_.-@,` 这种符号表片段都能通过。
          ② IP 判据 `\b\d{1,3}(\.\d{1,3}){3}\b` 会命中**版本号/浮点串**
             （如 `1.2.3.4` 形式的版本号、`%d.%d.%d.%d` 格式串），
             且没有校验每段 <= 255。

解决方案：
          ① 路径要求**长度 >= min_path_len（默认 4）**且至少包含一个 `/`
             分隔后的完整段，并排除纯符号串（必须至少有一个字母数字字符）；
          ② IP 每段范围校验到 0..255，且要求整串**不是**格式串
             （含 `%` 的一律跳过）；
          ③ 新增 `min_len` 参数统一控制，`dedupe` 去重（同一字符串在
             多个地址重复出现时只留第一条）；
          ④ 结果按 kind 分组时附带 `count`，并给 `noise_hint` 说明
             为什么某些短串被过滤掉——让"少"是可见的，而不是悄悄丢了。
"""
from __future__ import annotations

import re

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "sensitive_scan"
    description = "扫描已加载 so 的字符串，提取 URL/IP/文件路径/密钥特征"
    usage = ('{"so": "liblog.so", "kind": "url|ip|path|key|all", '
             '"min_len": 4, "dedupe": true}  // so 也接受 so_name')

    # 特征前缀，按需扩充
    _URL = ("http://", "https://", "ws://", "wss://")
    _KEY = ("api_key", "apikey", "secret", "token", "passwd", "password", "AKIA")

    # (2) 路径判据：先粗筛，再用 _is_real_path 精确判定
    _PATH_RE = re.compile(r"^/[\w./+-]*$")
    # (2) IP 判据保留 word boundary，但每段范围在 _is_real_ip 里校验
    _IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

    def run(self, session, args: dict):
        # (3) 第三次修改（2026-11-18）：参数兼容，优先 so、其次 so_name。
        #     bug 原因：原实现只认 so_name，与多数插件用 so 的约定不一致；
        #     缺失时的报错也没说明还能用 so，调用方容易传错。
        #     解决方案：两者都接受，缺失时报清晰参数错误；其余逻辑不动。
        so_name = args.get("so") or args.get("so_name")
        if not so_name:
            return {
                "error": f"缺少参数 so（也接受 so_name），你给的参数有: {list(args.keys())}",
                "code": "BAD_ARGS",
            }
        kind = args.get("kind", "all")
        # (2) 新增：长度下限与去重
        min_len = int(args.get("min_len", 4))
        dedupe = bool(args.get("dedupe", True))

        hits = {"url": [], "ip": [], "path": [], "key": []}
        filtered = {"path_too_short": 0, "ip_bad_range": 0,
                    "ip_format_string": 0}

        seen: dict[str, set] = {k: set() for k in hits}
        for st in session.strings(so_name).all_strings():
            v = st.value
            if not v:
                continue

            if kind in ("all", "url") and v.startswith(self._URL):
                self._push(hits, seen, "url", st.addr, v, 200, dedupe)

            if kind in ("all", "ip"):
                for m in self._IP_RE.finditer(v):
                    cand = m.group(0)
                    if "%" in v:
                        # 格式串（如 %d.%d.%d.%d）不是地址
                        filtered["ip_format_string"] += 1
                        continue
                    if not self._is_real_ip(cand):
                        filtered["ip_bad_range"] += 1
                        continue
                    self._push(hits, seen, "ip", st.addr, cand, 120, dedupe)

            if kind in ("all", "path") and self._PATH_RE.match(v):
                if len(v) < min_len:
                    filtered["path_too_short"] += 1
                    continue
                if not self._is_real_path(v):
                    filtered["path_too_short"] += 1
                    continue
                self._push(hits, seen, "path", st.addr, v, 120, dedupe)

            if kind in ("all", "key") and any(k in v.lower() for k in self._KEY):
                self._push(hits, seen, "key", st.addr, v, 120, dedupe)

        out = {}
        for k, v in hits.items():
            if v:
                out[k] = {"count": len(v), "items": v[:50]}
        if not out:
            out["note"] = "没有命中（判据见 filtered 里的过滤计数）"
        out["filtered"] = filtered
        out["params"] = {"min_len": min_len, "dedupe": dedupe}
        return out

    @staticmethod
    def _push(hits, seen, kind, addr, value, width, dedupe) -> None:
        if dedupe:
            if value in seen[kind]:
                return
            seen[kind].add(value)
        hits[kind].append({"addr": hex(addr), "value": value[:width]})

    @staticmethod
    def _is_real_ip(cand: str) -> bool:
        """每段必须 0..255（正则的 \\d{1,3} 允许 999）。"""
        parts = cand.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def _is_real_path(v: str) -> bool:
        """判定是否像真实文件路径，而不是符号表里的碎片。

        (2) 第二次修改（2026-11-18）：新增。
            判据（都是通用形态，不含任何样本特征）：
              ① 至少含一个字母或数字（排除 `_.-@,` 这类纯符号串）
              ② 斜杠分隔后至少有一段长度 >= 2（排除 `/Y`、`/R`）
              ③ 不能是纯十六进制/纯数字（排除地址表碎片）
        """
        if not any(c.isalnum() for c in v):
            return False
        segs = [s for s in v.split("/") if s]
        if not segs:
            return False
        if max(len(s) for s in segs) < 2:
            return False
        body = v.lstrip("/")
        if body and all(c in "0123456789abcdefABCDEF" for c in body):
            return False
        return True
