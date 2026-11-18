"""基于 YARA 规则的加密算法常量检测（通用能力）。

## 为什么用 YARA

[yara-python](https://pypi.org/project/yara-python/)（Apache-2.0，pip 直装）
是工业级的字节模式匹配引擎。[findcrypt-yara](https://github.com/polymorf/findcrypt-yara)
（BSD-3）的思路是：用 YARA 规则匹配各加密算法的**公开标准常量**，
比手写 Python 扫描更全、更快（C 层匹配）。

本插件不依赖 IDA——只用 findcrypt 的**规则思想**，
规则数据 ourselves 写（公开算法常量，通用无版权问题）。

## 提供什么

    - detect_so_crypto(so)  扫整个 so 文件，报告匹配到的算法常量
    - 每条：规则名 / 匹配的偏移 / 命中的字节

## 通用性

所有规则都是公开算法规范常量（AES S-box、MD5 T 表、SHA K 表、CRC32 表…），
不含任何具体 so/App 特征。
"""
from __future__ import annotations

from pathlib import Path

from server.core.plugins import PluginBase

# 公开算法常量规则（YARA 语法；用 findcrypt 同类思路，数据来自算法规范）
RULES = r"""
rule AES_Sbox {
    meta:
        algo = "AES"
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}
rule AES_Ttable {
    meta:
        algo = "AES (T-table)"
    strings:
        $te0 = { c6 63 63 a5 }
        $te1 = { a5 c6 63 63 }
    condition:
        any of them
}
rule MD5_T {
    meta:
        algo = "MD5"
    strings:
        // (4) 用 math.sin 实算校正（1-based 索引）：
        //     T[7]=0xa8304613 -> 13 46 30 a8
        //     T[8]=0xfd469501 -> 01 95 46 fd
        //     T[9]=0x698098d8 -> d8 98 80 69
        $t1 = { 13 46 30 a8 }
        $t2 = { 01 95 46 fd }
        $t3 = { d8 98 80 69 }
    condition:
        2 of them
}
rule SHA1_K {
    meta:
        algo = "SHA-1"
    strings:
        // (3) 核实后的 LE 字节：K1/K3 原来写错了
        $k1 = { 99 79 82 5a }      // 0x5a827999 LE
        $k2 = { a1 eb d9 6e }      // 0x6ed9eba1 LE
        $k3 = { dc bc 1b 8f }      // 0x8f1bbcdc LE
        $k4 = { d6 c1 62 ca }      // 0xca62c1d6 LE
    condition:
        3 of them
}
rule SHA256_K {
    meta:
        algo = "SHA-256"
    strings:
        $k0 = { 98 2f 8a 42 }      // 0x428a2f98 LE
        $k1 = { 91 44 37 71 }      // 0x71374491 LE
    condition:
        all of them
}
rule CRC32_TABLE {
    meta:
        algo = "CRC32"
    strings:
        $p = { 20 83 b8 ed }       // 0xedb88320 LE (reversed poly)
    condition:
        $p
}
rule XXTEA_DELTA {
    meta:
        algo = "TEA/XXTEA"
    strings:
        $d = { b9 79 37 9e }       // 0x9e3779b9 LE
    condition:
        $d
}
rule RC4_KSA {
    meta:
        algo = "RC4 (possible)"
    strings:
        // x86/arm 常见的 S[i]=i 初始化循环字节模式较弱，仅作线索
        $init = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
    condition:
        $init
}
"""


class Plugin(PluginBase):
    name = "detect_so_crypto"
    description = "基于 YARA 规则扫 so 里的加密算法常量（findcrypt 思想，无需 IDA）"
    usage = "args: {so: str, limit: int=50}"

    def run(self, session, args: dict):
        try:
            import yara
        except ImportError:
            return {
                "error": ("yara-python 不可用。**打包版里这是预期的**——"
                          "yara 自带的 libcrypto.3.dylib 会被 PyInstaller "
                          "全局收集，覆盖系统 OpenSSL 导致 app 启动崩溃，"
                          "因此刻意不打包。"),
                "code": "YARA_NOT_INSTALLED",
                "where_available": "源码环境（.venv）里功能完整",
                "to_enable_in_source": "pip install yara-python",
                "alternative": {
                    "tool": "const_fingerprint",
                    "why": "纯 Python、零第三方依赖、打包版可用，"
                           "覆盖 20+ 常见算法常量（XXTEA/SHA1/SHA256/MD5/CRC32/FNV等）",
                },
            }

        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        path = getattr(so, "path", None)
        if not path or not Path(path).exists():
            return {"error": f"找不到 so 文件：{path}", "code": "NO_FILE"}

        try:
            rules = yara.compile(source=RULES)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"YARA 规则编译失败：{exc}", "code": "BAD_RULES"}

        try:
            matches = rules.match(path)
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"YARA 扫描失败：{exc}", "code": "SCAN_FAILED"}

        out = []
        for m in matches:
            algo = (m.meta or {}).get("algo", m.rule)
            for s in m.strings:
                for inst in s.instances:
                    offs = int(inst.offset)
                    out.append({
                        "rule": m.rule,
                        "algorithm": algo,
                        "offset": hex(offs),
                        "offset_dec": offs,
                        "matched": s.identifier,
                    })
        out.sort(key=lambda x: x["offset_dec"])
        limit = int(args.get("limit", 50))
        return {
            "ok": True, "so": so.name,
            "rules_count": len(self._rule_names()),
            "match_count": len(out),
            "matches": out[:limit],
            "algorithms": sorted({m["algorithm"] for m in out}),
            "note": ("基于公开算法标准常量的 YARA 匹配。"
                     "命中是强线索但不等于证明（常量可能被复用作他途）。"),
        }

    def _rule_names(self):
        return ["AES_Sbox", "AES_Ttable", "MD5_T", "SHA1_K",
                "SHA256_K", "CRC32_TABLE", "XXTEA_DELTA", "RC4_KSA"]
