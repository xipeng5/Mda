"""加密/算法常量指纹库（通用能力）。

## 解决什么问题

看到 `0x9e3779b9` 应该立刻知道是 XXTEA/TEA 的 delta，
看到 `0x67452301` 应该知道是 MD5 初始向量。
使用者以前靠人工记，容易漏。

本插件扫 so 里出现的常量，匹配一个**通用指纹表**（公开算法的标准常量，
不是任何 App 的特征），输出"这个常量属于哪个算法"。

## 为什么是通用能力

指纹表是各算法的**公开标准常量**（来自算法规范），
不含任何具体样本。任何人都能用。
"""
from __future__ import annotations

import struct

from server.core.plugins import PluginBase

# 公开算法的标准常量（来自各算法规范，非样本特征）
FINGERPRINTS = {
    0x9E3779B9: ("TEA/XXTEA delta", "block_cipher"),
    0x9E3779B97F4A7C15: ("SplitMix64 / golden ratio", "hash"),
    0x67452301: ("MD5/SHA1 init A", "hash"),
    0x5A827999: ("SHA-1 K1 (0x5a827999)", "hash"),
    0x6ED9EBA1: ("SHA-1 K2 (0x6ed9eba1)", "hash"),
    0x8F1BBCDC: ("SHA-1 K3 (0x8f1bbcdc)", "hash"),
    0xCA62C1D6: ("SHA-1 K4 (0xca62c1d6)", "hash"),
    0xEB86D391: ("MD5 T64 (0xeb86d391)", "hash"),
    0x428A2F98: ("SHA-256 K[0]", "hash"),
    0x71374491: ("SHA-256 K[1]", "hash"),
    0xB5C0FBCF: ("SHA-256 K[2]", "hash"),
    0xE9B5DBA5: ("SHA-256 K[3]", "hash"),
    0xEFCDAB89: ("MD5 init B", "hash"),
    0x98BADCFE: ("MD5 init C", "hash"),
    0x10325476: ("MD5 init D", "hash"),
    0xC2B2AE3D: ("MurmurHash3 seed mix", "hash"),
    0xCC9E2D51: ("MurmurHash3 c1", "hash"),
    0x1B873593: ("MurmurHash3 c2", "hash"),
    0x5BD1E995: ("MurmurHash2 magic", "hash"),
    0x01000193: ("FNV-1a prime (32)", "hash"),
    0x811C9DC5: ("FNV offset basis (32)", "hash"),
    0x1000193: ("FNV-1a prime (alt)", "hash"),
    0xDEADBEEF: ("common debug/seed value", "marker"),
    0xCAFEBABE: ("common magic/seed value", "marker"),
    0x08088405: ("common LCG multiplier", "prng"),
    0x41C64E6D: ("glibc LCG multiplier", "prng"),
    0x3039: ("common LCG multiplier (12345)", "prng"),
    0x4B1D: ("CRC16-CCITT poly (0x1021 variant)", "crc"),
    0xEDB88320: ("CRC32 reversed poly", "crc"),
    0x104C11DB7: ("CRC32 poly", "crc"),
    0xD765A20C: ("AES S-box related", "cipher"),
}


class Plugin(PluginBase):
    name = "const_fingerprint"
    description = "扫描 so 里的算法常量，标注可能使用的加密/哈希算法"
    usage = "args: {so: str, limit: int=100}"

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        limit = int(args.get("limit", 100))

        hits = []
        # 扫 .rodata / 数据段的 4字节和8字节对齐值
        seen = set()
        # (1) 数据段：无节表时用 PT_LOAD 中**非可执行**段兜底
        ranges = [(sec.addr, sec.size) for sec in getattr(so, "sections", [])
                  if not getattr(sec, "is_exec", False) and getattr(sec, "size", 0)]
        if not ranges:
            for va, end, _off, fl in getattr(so, "_loads", []) or []:
                if not (fl & 1) and end > va:
                    ranges.append((va, end - va))
        for _dva, _dsz in ranges:
            data = so.read(_dva, min(_dsz, 1 << 22))
            for width in (4, 8):
                fmt = "<I" if width == 4 else "<Q"
                for off in range(0, len(data) - width + 1, width):
                    val = struct.unpack_from(fmt, data, off)[0]
                    if val not in FINGERPRINTS:
                        continue
                    addr = _dva + off
                    key = (addr, val)
                    if key in seen:
                        continue
                    seen.add(key)
                    name, kind = FINGERPRINTS[val]
                    hits.append({
                        "addr": hex(addr),
                        "value": hex(val),
                        "algorithm": name,
                        "kind": kind,
                        "width": width,
                    })

        hits.sort(key=lambda h: int(h["addr"], 16))
        return {
            "ok": True, "so": so.name,
            "count": len(hits),
            "hits": hits[:limit],
            "note": ("基于公开算法标准常量匹配。"
                     "命中只是线索（可能是巧合），需结合上下文确认。"),
        }
