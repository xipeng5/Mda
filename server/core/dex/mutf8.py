"""MUTF-8 解码（DEX 字符串体的编码）。

—— 坑 1（本模块存在的理由）——

string_data_item 的结构是：

    string_data_item:
        uleb128 utf16_size      <- **UTF-16 码元数**，不是字节数、不是码点数
        ubyte   data[]          <- MUTF-8 编码的字符串体，以 0x00 结尾

三件必须按官方语义处理的事：

1. utf16_size 是 UTF-16 码元（code unit）计数。补充平面字符（如 emoji）
   在 UTF-16 里占 **2 个码元**，在 MUTF-8 里占 **6 字节**（两个 3 字节序列）。
   所以「读够 utf16_size 个码元」和「读够 utf16_size 字节」差得很远，
   后者会把长字符串截断，进而让 string_id 表整体错位。

2. MUTF-8 里 U+0000 编码为 `\\xC0\\x80`（2 字节），因为单字节 0x00 已被
   用作字符串终止符。若把 `\\xC0\\x80` 当非法序列跳过，含内嵌 NUL 的字符串
   （Kotlin/Java 混淆名里常见）的码元计数就会偏。

3. MUTF-8 **不使用 4 字节形式**（0xF0..0xF7）。补充平面字符一律拆成两个
   3 字节序列，各编码一个 UTF-16 代理项。所以解码过程应当先得到「码元序列」，
   最后再按 UTF-16 组装成 str —— 直接按 UTF-8 解会得到乱码或异常。

本模块的做法：逐字节解出 UTF-16 码元 → 打包成 UTF-16LE 字节流 → 交给
Python 的 utf-16-le 解码器（surrogatepass 容忍孤立代理项）。这样 1 字节/2 字节/
3 字节、代理对、内嵌 NUL 全部自然正确。
"""
from __future__ import annotations

import struct

from .reader import DexError, uleb128


def decode_at(buf: bytes, off: int, utf16_size: int) -> tuple[str, int, bool]:
    """从 off 处的 MUTF-8 体解出字符串。

    返回 (字符串, 结束偏移, 是否正常收尾)。
    「正常收尾」= 恰好读满 utf16_size 个码元且紧跟 0x00 终止符。
    不满足时仍然返回已解出的内容，由上层把它记成 dirty 计数——不编造、也不
    因为个别字符串脏就让整个 dex 解析失败。
    """
    units: list[int] = []
    end = len(buf)
    p = off
    terminated = False
    while len(units) < utf16_size:
        if p >= end:
            break
        b0 = buf[p]
        if b0 == 0:
            # 提前遇到终止符：utf16_size 与真实内容不一致
            break
        if b0 < 0x80:
            units.append(b0)
            p += 1
        elif (b0 & 0xE0) == 0xC0:
            # 2 字节序列，含 U+0000 的 C0 80
            if p + 1 >= end:
                break
            b1 = buf[p + 1]
            if (b1 & 0xC0) != 0x80:
                raise DexError("BAD_MUTF8", f"MUTF-8 2 字节序列续字节非法，偏移 0x{p:x}")
            units.append(((b0 & 0x1F) << 6) | (b1 & 0x3F))
            p += 2
        elif (b0 & 0xF0) == 0xE0:
            # 3 字节序列：一个 UTF-16 码元（代理项也走这里）
            if p + 2 >= end:
                break
            b1 = buf[p + 1]
            b2 = buf[p + 2]
            if (b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80:
                raise DexError("BAD_MUTF8", f"MUTF-8 3 字节序列续字节非法，偏移 0x{p:x}")
            units.append(((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F))
            p += 3
        else:
            # 4 字节形式 / 0xF8+ 不是 MUTF-8 的合法编码
            raise DexError(
                "BAD_MUTF8",
                f"MUTF-8 出现非法首字节 0x{b0:02x}（MUTF-8 不允许 4 字节形式），偏移 0x{p:x}",
            )
    if len(units) == utf16_size and p < end and buf[p] == 0:
        terminated = True
    return units_to_str(units), p, terminated


def units_to_str(units: list[int]) -> str:
    """把 UTF-16 码元序列组装成 str（代理对会被合并成一个码点）。"""
    if not units:
        return ""
    # surrogatepass：允许孤立代理项（畸形 dex 里存在），避免整段解析抛异常
    return struct.pack(f"<{len(units)}H", *units).decode("utf-16-le", "surrogatepass")


def read_string_data(buf: bytes, off: int) -> tuple[str, int, bool]:
    """string_data_item：先 uleb128 的 utf16_size，再 MUTF-8 体。

    返回 (字符串, 字符串体结束偏移, 是否正常收尾)。
    """
    utf16_size, body_off = uleb128(buf, off)
    return decode_at(buf, body_off, utf16_size)


def encode_mutf8(text: str) -> tuple[bytes, int]:
    """生成 MUTF-8 字节体 + UTF-16 码元数（测试与 fixture 用）。

    与 decode_at 严格互逆：U+0000 -> C0 80，补充平面 -> 两个 3 字节代理项。
    """
    out = bytearray()
    utf16_size = 0
    for ch in text:
        cp = ord(ch)
        if cp == 0:
            out += b"\xc0\x80"
            utf16_size += 1
        elif cp < 0x80:
            out.append(cp)
            utf16_size += 1
        elif cp < 0x800:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
            utf16_size += 1
        elif cp < 0x10000:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
            utf16_size += 1
        else:
            # 补充平面：两个代理项，各自 3 字节
            v = cp - 0x10000
            hi = 0xD800 | (v >> 10)
            lo = 0xDC00 | (v & 0x3FF)
            for u in (hi, lo):
                out.append(0xE0 | (u >> 12))
                out.append(0x80 | ((u >> 6) & 0x3F))
                out.append(0x80 | (u & 0x3F))
                utf16_size += 1
    return bytes(out), utf16_size
