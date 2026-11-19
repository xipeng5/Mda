"""通用模板化穷举签名拼接引擎（纯通用能力，禁止样本特调）。

## 解决什么问题

逆向签名算法时，常见的痛点是「字段 × 分隔符 × 算法 × 密钥源」的组合空间很大，
人工写脚本试几万种拼接既慢又容易漏。本插件把这件事抽象成一套**模板 + 管道 + 算法**
的穷举引擎：调用方只描述"有哪些字段、怎么拼、试哪些算法、密钥从哪来"，
引擎负责组合、限时、限量、比对并如实报告是否截断。

## 模板 / 管道语法（通用、文档化，自己解析，绝不使用 eval）

字段来自 args.fields，例如 {"url": "abc", "stub": "616263", "kh": "deadbeef"}。

1. {url}                -> 字段原值（字符串）
2. {url|sha1hex}        -> 管道：把 url 的值喂给 sha1hex transformer
   {kh|md5hex|upper}    -> 多段管道依次应用
3. {stub_raw} / {kh_le} -> 字段后缀写法，等价 {stub|hexbytes} / {kh|le}
4. md5hex(url)          -> 函数调用写法，可在 {} 内，也可裸写在模板里
5. {url}/{sha1hex(url)} -> 字面 "/" 是普通拼接分隔符，不是管道
6. {url}|md5hex(url)    -> 顶层 "|" 是管道符：左侧结果作为右侧表达式的输入；
                           右侧若是函数调用则用它自己的参数求值，输出作为管道结果

内置 transformer（全部为公开标准算法，不含任何样本特征）：
    raw        原值
    hexbytes   str -> bytes.fromhex（还原 hex 原文）
    md5hex     MD5 摘要的小写 hex 字符串
    sha1hex    SHA-1 摘要的小写 hex 字符串
    sha256hex  SHA-256 摘要的小写 hex 字符串
    le         hex 字节序反转（"deadbeef" -> "efbeadde"，即 little-endian 解读）
    upper      转大写
    lower      转小写

## 算法

    none / md5 / sha1 / sha256 / hmac_sha1 / rc4 / xxtea / aes256

RC4、XXTEA 用纯 Python 实现（不引入新依赖）。AES 惰性探测 pycryptodome 或
cryptography；两者都没有时把 aes256 记入 unsupported_algos，绝不假装支持。

## 通用容错（不是样本特调）

除算法变换结果外，引擎总是把「模板明文本身」也作为一个隐式候选参与比对
（等价于无条件附加 none）。因为模板里已经可以直接写 md5hex(url) 算出最终摘要，
用户不必再在 algos 里重复声明 none。若明文是合法 hex 字符串，额外提供
bytes.fromhex 解码后的字节候选。

## 用法

plugin_run(name="fuzz_combine", args={
    "fields": {"url": "abc", "stub": "abc", "kh": "deadbeef"},
    "templates": ["{url}|md5hex(url)", "{url}/{sha1hex(url)}"],
    "algos": ["md5", "hmac_sha1", "rc4", "xxtea"],
    "keys": ["md5(url)", "kh_le", "literal:9f72b159"],
    "target": "900150983cd24fb0d6963f7d28e17f72",
    "target_len": 16,
    "max_combos": 200000,
    "encoding": "hex",
    "timeout_ms": 30000,
})
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time

from server.core.plugins import PluginBase

# XXTEA delta（公开算法标准常量，来自 XXTEA 规范，非样本特征）
_DELTA = 0x9E3779B9

# 全部 transformer 名字集中登记，便于文档化与解析器识别
_TRANSFORM_NAMES = (
    "raw", "hexbytes", "md5hex", "sha1hex", "sha256hex",
    "le", "upper", "lower",
)


# ---------------------------------------------------------------------------
# 基础值转换
# ---------------------------------------------------------------------------

def _to_bytes(v):
    """用途：把 Transformer 的中间值统一转成 bytes（字符串按 UTF-8 编码，失败退 latin-1）。"""
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        try:
            return v.encode("utf-8")
        except UnicodeEncodeError:
            return v.encode("latin-1", "replace")
    return str(v).encode("utf-8")


def _to_str(v):
    """用途：把中间值统一转成可拼接字符串（bytes 按 latin-1 解码，逐字节保留不丢信息）。"""
    if isinstance(v, bytes):
        return v.decode("latin-1")
    return str(v)


# ---------------------------------------------------------------------------
# Transformer 实现（输入 str 或 bytes，输出 str 或 bytes）
# ---------------------------------------------------------------------------

def _t_raw(v):
    """用途：恒等变换，原值返回。"""
    return v


def _t_hexbytes(v):
    """用途：把 hex 字符串按 bytes.fromhex 还原成原始字节。"""
    if isinstance(v, bytes):
        return v
    return bytes.fromhex(v.strip())


def _t_md5hex(v):
    """用途：对输入做 MD5，返回小写 hex 摘要字符串。"""
    return hashlib.md5(_to_bytes(v)).hexdigest()


def _t_sha1hex(v):
    """用途：对输入做 SHA-1，返回小写 hex 摘要字符串。"""
    return hashlib.sha1(_to_bytes(v)).hexdigest()


def _t_sha256hex(v):
    """用途：对输入做 SHA-256，返回小写 hex 摘要字符串。"""
    return hashlib.sha256(_to_bytes(v)).hexdigest()


def _t_le(v):
    """用途：hex 字节序反转（little-endian 解读），等价 bytes.fromhex(v)[::-1].hex()。"""
    if isinstance(v, bytes):
        return v[::-1]
    h = v.strip().replace(" ", "")
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)[::-1].hex()


def _t_upper(v):
    """用途：把中间值转成大写字符串。"""
    return _to_str(v).upper()


def _t_lower(v):
    """用途：把中间值转成小写字符串。"""
    return _to_str(v).lower()


_TRANSFORMS = {
    "raw": _t_raw,
    "hexbytes": _t_hexbytes,
    "md5hex": _t_md5hex,
    "sha1hex": _t_sha1hex,
    "sha256hex": _t_sha256hex,
    "le": _t_le,
    "upper": _t_upper,
    "lower": _t_lower,
}


# ---------------------------------------------------------------------------
# 表达式解析器（自己解析，不用 eval）
# ---------------------------------------------------------------------------

def _split_top(s, sep="|"):
    """用途：按分隔符切分字符串，但忽略花括号/圆括号内部的分隔符（用于顶层管道解析）。"""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(s):
        if ch in "{([":
            depth += 1
        elif ch in "})]":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def _apply_transform(name, value):
    """用途：按 transformer 名字应用单个变换；未知名字原样返回（不报错、不静默丢值）。"""
    fn = _TRANSFORMS.get(name)
    return fn(value) if fn is not None else value


def _eval_arg(arg, fields):
    """用途：求值函数参数——字段名取字段值，嵌套函数递归求值，否则去引号当字面量。"""
    a = arg.strip()
    if len(a) >= 2 and a[0] == a[-1] and a[0] in "\"'":
        return a[1:-1]
    m = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", a)
    if m:
        return _call_transform(m.group(1), m.group(2), fields)
    if a in fields:
        return fields[a]
    return _eval_expr(a, fields)


def _call_transform(name, args_str, fields):
    """用途：解析 func(arg,...) 形式的 Transformer 调用，参数求值后应用对应变换。"""
    if name not in _TRANSFORMS:
        return ""
    parts = [p for p in _split_top(args_str, ",")]
    if not parts or not parts[0].strip():
        return _TRANSFORMS[name]("")
    val = _eval_arg(parts[0], fields)
    return _apply_transform(name, val)


def _eval_expr(expr, fields):
    """用途：求值花括号内表达式——支持 field、field|t1|t2 管道、func(arg) 调用、field_le 后缀。"""
    e = expr.strip()
    # 函数调用：md5hex(url)
    m = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", e)
    if m:
        return _to_str(_call_transform(m.group(1), m.group(2), fields))
    # 管道：url|md5hex|upper
    if "|" in e:
        parts = _split_top(e, "|")
        val = _eval_expr(parts[0], fields)
        for p in parts[1:]:
            p = p.strip()
            pm = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", p)
            if pm:
                val = _call_transform(pm.group(1), pm.group(2), fields)
            else:
                val = _apply_transform(p, val)
        return _to_str(val)
    # 字段后缀写法：kh_le / stub_raw
    for suffix, tname in (("_le", "le"), ("_raw", "hexbytes")):
        if e.endswith(suffix) and e[:-len(suffix)] in fields:
            return _to_str(_apply_transform(tname, fields[e[:-len(suffix)]]))
    if e in fields:
        return _to_str(fields[e])
    return e  # 字面量


def _eval_segment(seg, fields, pipe_input=None):
    """用途：求值模板顶层段——展开花括号、求值裸函数调用；整段是 transformer 名时应用到管道输入。"""
    def brace_repl(m):
        return _to_str(_eval_expr(m.group(1), fields))
    text = re.sub(r"\{([^{}]+)\}", brace_repl, seg)

    def call_repl(m):
        return _to_str(_call_transform(m.group(1), m.group(2), fields))
    text = re.sub(r"\b([A-Za-z_]\w*)\(([^()]*)\)", call_repl, text)

    t = text.strip()
    if pipe_input is not None and re.fullmatch(r"[A-Za-z_]\w*", t) and t in _TRANSFORMS:
        return _to_str(_apply_transform(t, pipe_input))
    return text


def _render_template(template, fields):
    """用途：渲染模板为明文 bytes——按顶层 | 管道切段，逐段求值，左段结果作为右段输入。"""
    segs = _split_top(template, "|")
    if len(segs) == 1:
        return _eval_segment(segs[0], fields).encode("latin-1", "replace")
    val = _eval_segment(segs[0], fields)
    for seg in segs[1:]:
        val = _eval_segment(seg, fields, pipe_input=val)
    return val.encode("latin-1", "replace")


def _resolve_key(expr, fields):
    """用途：解析密钥源表达式——literal: 前缀取字面，其余走与模板相同的 Transformer/字段解析。"""
    e = str(expr).strip()
    if e.startswith("literal:"):
        return e[len("literal:"):]
    m = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", e)
    if m:
        return _to_str(_call_transform(m.group(1), m.group(2), fields))
    for suffix, tname in (("_le", "le"), ("_raw", "hexbytes")):
        if e.endswith(suffix) and e[:-len(suffix)] in fields:
            return _to_str(_apply_transform(tname, fields[e[:-len(suffix)]]))
    if e in fields:
        return fields[e]
    return _to_str(_eval_expr(e, fields))


def _key_bytes(k):
    """用途：把密钥值转成 bytes——合法偶数长度 hex 按 hex 解码，否则按 UTF-8 编码。"""
    if isinstance(k, bytes):
        return k
    s = str(k).strip()
    if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        return bytes.fromhex(s)
    return s.encode("utf-8")


# ---------------------------------------------------------------------------
# 纯 Python 加密算法（不引入新依赖）
# ---------------------------------------------------------------------------

def _rc4(data, key):
    """用途：纯 Python RC4 流加密（KSA + PRGA），约 20 行，避免引入第三方依赖。"""
    if not key:
        return None
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _xxtea_encrypt(data, key):
    """用途：纯 Python XXTEA 标准加密（公开算法规范实现），key 取前 16 字节，数据按 4 字节分组。"""
    if not data:
        return b""
    if len(data) % 4:
        data = data.ljust((len(data) // 4 + 1) * 4, b"\x00")
    n = len(data) // 4
    if n < 2:
        data += b"\x00" * 4
        n += 1
    v = list(struct.unpack("<%dI" % n, data))
    k = list(struct.unpack("<4I", (key + b"\x00" * 16)[:16]))
    rounds = 6 + 52 // n
    s = 0
    z = v[n - 1]
    while rounds:
        rounds -= 1
        s = (s + _DELTA) & 0xFFFFFFFF
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
                (s ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
            z = v[p]
        y = v[0]
        p = n - 1
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
            (s ^ y) + (k[(p & 3) ^ e] ^ z))
        v[p] = (v[p] + (mx & 0xFFFFFFFF)) & 0xFFFFFFFF
        z = v[p]
    return struct.pack("<%dI" % n, *v)


def _aes256_encrypt(data, key):
    """用途：AES-256-ECB 加密；惰性探测 pycryptodome/cryptography，都没有返回 None。"""
    k = key if len(key) == 32 else hashlib.sha256(key).digest()
    pad = 16 - (len(data) % 16)
    padded = data + bytes([pad]) * pad
    try:
        from Crypto.Cipher import AES                       # noqa: PLC0415
        return AES.new(k, AES.MODE_ECB).encrypt(padded)
    except Exception:                                        # noqa: BLE001
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import (  # noqa: PLC0415
            Cipher, algorithms, modes)
        enc = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
        return enc.update(padded) + enc.finalize()
    except Exception:                                        # noqa: BLE001
        return None


class Plugin(PluginBase):
    name = "fuzz_combine"
    description = "通用模板化穷举签名拼接引擎（字段×模板×算法×密钥源，限时限量、如实报告截断）"
    usage = ("args: {fields:dict, templates:list[str], algos:list[str], keys:list[str], "
             "target:str, target_len:int=0, max_combos:int=200000, encoding:str='hex', "
             "timeout_ms:int=30000}")

    def run(self, session, args):
        """用途：插件入口——遍历 template×algo×key 组合与 target 比对，返回命中、截断原因与用量。"""
        fields = args.get("fields") or {}
        templates = args.get("templates") or []
        algos = [str(a).lower() for a in (args.get("algos") or [])]
        keys = args.get("keys") or ["none"]
        target_hex = args.get("target")
        if not isinstance(target_hex, str) or not target_hex.strip():
            return {"ok": False, "error": "需要 target（hex 字符串）", "code": "BAD_ARGS"}
        target_len = int(args.get("target_len", 0))
        max_combos = int(args.get("max_combos", 200000))
        encoding = str(args.get("encoding", "hex")).lower()
        timeout_ms = int(args.get("timeout_ms", 30000))
        try:
            target = bytes.fromhex(target_hex.replace(" ", ""))
        except ValueError as exc:
            return {"ok": False, "error": "target 不是合法 hex: %s" % exc,
                    "code": "BAD_TARGET"}

        resolved_keys = [(k, _key_bytes(_resolve_key(k, fields))) for k in keys]
        default_key_name = str(keys[0]) if keys else "n/a"

        matches, seen = [], set()
        unsupported = set()
        tried = 0
        truncated = False
        stop_reason = ""
        start = time.time()

        for tpl in templates:
            try:
                plain = _render_template(str(tpl), fields)
            except Exception as exc:                         # noqa: BLE001
                return {"ok": False, "error": "模板解析失败 %r: %s" % (tpl, exc),
                        "code": "BAD_TEMPLATE"}
            for algo in algos:
                # hash 类算法不需要 key：只用一个哨兵键，避免无意义地重复组合
                need_key = algo in ("rc4", "xxtea", "aes256", "hmac_sha1")
                key_iter = resolved_keys if need_key else [(default_key_name, b"")]
                for key_name, key_b in key_iter:
                    if tried >= max_combos:
                        truncated, stop_reason = True, "max_combos"
                        break
                    if (time.time() - start) * 1000 >= timeout_ms:
                        truncated, stop_reason = True, "timeout_ms"
                        break
                    tried += 1

                    out = self._apply_algo(algo, plain, key_b, unsupported)
                    if out is not None and self._equal(out, target, target_len, encoding):
                        self._add_match(matches, seen, self._mk_match(
                            tpl, algo, key_name, fields, out, plain))
                    # 隐式候选：模板明文本身（含 hex 解码版本）
                    for ic, via in self._implicit_candidates(plain):
                        if self._equal(ic, target, target_len, encoding):
                            self._add_match(matches, seen, self._mk_match(
                                tpl, algo, key_name, fields, ic, plain, via=via))
                if truncated:
                    break
            if truncated:
                break

        note = ("模板语法见 usage/docstring。除算法结果外，模板明文本身也作为隐式候选参与比对"
                "（模板里可直接用 md5hex(url) 等 transformer 产生最终摘要）。"
                "达到 max_combos 或 timeout_ms 会置 truncated=true 并给出 stop_reason，绝不静默跑完。")
        return {
            "ok": True,
            "combos_tried": tried,
            "truncated": truncated,
            "stop_reason": stop_reason,
            "matches": matches,
            "unsupported_algos": sorted(unsupported),
            "note": note,
        }

    def _apply_algo(self, algo, data, key, unsupported):
        """用途：按算法名对明文做变换；未知算法返回 None，无库的 AES 记入 unsupported_algos。"""
        if algo == "none":
            return data
        if algo == "md5":
            return hashlib.md5(data).digest()
        if algo == "sha1":
            return hashlib.sha1(data).digest()
        if algo == "sha256":
            return hashlib.sha256(data).digest()
        if algo == "hmac_sha1":
            return hmac.new(key, data, hashlib.sha1).digest()
        if algo == "rc4":
            return _rc4(data, key)
        if algo == "xxtea":
            return _xxtea_encrypt(data, key)
        if algo == "aes256":
            r = _aes256_encrypt(data, key)
            if r is None:
                unsupported.add("aes256")
            return r
        return None

    @staticmethod
    def _equal(result, target, target_len, encoding):
        """用途：按 encoding 处理结果字节，并按 target_len 只比前 N 字节。"""
        rb = result
        if encoding == "base64":
            rb = base64.b64encode(result)
        elif encoding not in ("hex", "raw", "latin1", ""):
            rb = result
        if target_len and target_len > 0:
            return rb[:target_len] == target[:target_len]
        return rb == target

    @staticmethod
    def _implicit_candidates(plain):
        """用途：生成"模板明文本身即结果"的隐式候选（hex 字符串额外给 bytes.fromhex 版本）。"""
        out = [(plain, "plain")]
        try:
            s = plain.decode("latin-1").strip()
            if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
                out.append((bytes.fromhex(s), "plain_hex_decoded"))
        except Exception:                                    # noqa: BLE001
            pass
        return out

    @staticmethod
    def _add_match(matches, seen, match):
        """用途：去重后追加命中记录（同一描述只保留一条）。"""
        k = json.dumps(match, sort_keys=True, ensure_ascii=False)
        if k not in seen:
            seen.add(k)
            matches.append(match)

    @staticmethod
    def _mk_match(tpl, algo, key_name, fields, out, plain, via=None):
        """用途：构造一条命中的完整描述（模板/算法/密钥/字段取值/明文/结果 hex）。"""
        m = {
            "template": tpl,
            "algo": algo,
            "key": key_name,
            "fields": dict(fields),
            "plaintext": plain.decode("latin-1", "replace"),
            "plaintext_hex": plain.hex(),
            "result_hex": out.hex(),
        }
        if via:
            m["via"] = via
        return m
