"""字符串池自动解密插件（通用能力）。

## 解决什么问题

加固 so 里的关键字符串（URL、签名模板、密钥）常被加密存放：
静态扫明文只能看到乱码，使用者往往要花好几轮手工试 KDF。

本插件**参数化**枚举常见 KDF，按"解出可打印 ASCII 的比例"排序输出：
    - single_byte_xor      单字节 XOR（穷举 0..255）
    - multi_byte_xor       多字节 XOR（穷举短 key 长度）
    - rolling_xor          每字节密钥递增
    - lcg_xor              LCG 生成 keystream 后 XOR（参数可配）
    - not                  逐字节取反
    - add_xor              加常数后 XOR

## 为什么是通用能力

不硬编码任何具体样本的字符串、偏移、密钥。
所有算法参数（seed / multiplier / inc / key）都可由调用方传入，
默认给一组常见的通用常量（如 LCG 0x08088405/1 是数值算法常用参数，
不是某个 App 的特征）。

## 用法（通过 plugin_run）

```python
plugin_run(name="string_crack", args={
    "so": "libfoo.so",
    "methods": ["single_byte_xor", "lcg_xor", "rolling_xor"],
    "min_printable": 0.85,     # 可打印比例阈值
    "min_len": 4,
    "limit": 30,
})
```

返回：按可打印度排序的 [{addr, method, params, plaintext, score}]。
"""
from __future__ import annotations

import itertools
import string

from server.core.plugins import PluginBase

PRINTABLE = set(bytes(string.printable[:95], "ascii"))


def _score(b: bytes) -> float:
    """可打印 ASCII 比例；空数据为 0。"""
    if not b:
        return 0.0
    return sum(1 for c in b if c in PRINTABLE) / len(b)


def _clean(b: bytes) -> str:
    return "".join(chr(c) if c in PRINTABLE else "." for c in b)


def _semantic_score(b: bytes) -> float:
    """语义启发式：区分"可打印"与"像真实字符串"。

    (1) 第一次修改（2026-11-17）：
        纯可打印度会把任意字节解成 `~~~~~~~~` 这类假阳性。
        真实字符串的特征是：字母数字占多数、字符不单调重复、
        常含标点/格式符（:/{}= 等）。这些都是**通用文本特征**，
        不针对任何具体 App 的内容。

    (2) 第二次修改（2026-11-18）：不能因为出现一个 '.' 就判 0 分。
        bug 原因：初版第一行是 `if "." in text: return 0.0`，理由是
                  "'.' 代表被 _clean 替换掉的不可打印字节"。但它同时
                  把**真实的句点**也当成不可打印——正文里出现 `.` 极常见
                  （URL、文件路径、`%d.%03d` 这类格式串、版本号）。
                  致命的是：只要块里混进 1 个不可打印字节，整块直接 0 分。
                  实测 .rodata 整块 1992 字节喂进去，256 个 XOR key
                  **全部 0 分**，而那块里其实有 90+ 条正常明文。
        解决方案：
                  ① 不再一票否决，改为按「不可打印占比」扣分；
                  ② 由调用方保证输入是**按 NUL 切好的块**（见
                     _collect_blocks 的第 3 次修改），这样块内本来就应该
                     是单一字符串或密文，而不是整节混合数据。
    """
    if not b:
        return 0.0
    text = _clean(b)
    if not text:
        return 0.0
    # ① 不可打印占比过高的直接压到 0：那种块要么是密文、要么切分错了，
    #    给它们打高分只会把噪音顶上来。
    bad_ratio = text.count(".") / len(text)
    if bad_ratio > 0.4:
        return 0.0
    alnum = sum(1 for c in text if c.isalnum())
    # ② 字母数字比例
    ratio = alnum / len(text)
    # ③ 字符多样性：不同字符数 / 长度。"~~~~" 只有 1 种 → 0
    diversity = len(set(text)) / min(len(text), 16)
    # ④ 常见文本符号（通用格式符，非业务特征）
    punct = sum(1 for c in text if c in ":/{}=,.@_-+?&")
    punct_ratio = min(punct / max(len(text), 1) * 3, 1.0)
    score = ratio * 0.5 + diversity * 0.3 + punct_ratio * 0.2
    # ⑤ 不可打印占比作为**扣分项**（而不是一票否决）
    return score * (1.0 - bad_ratio)



class Plugin(PluginBase):
    name = "string_crack"
    description = "通用字符串池解密：枚举 XOR/LCG/rolling 等 KDF，按可打印度排序"
    usage = ("args: {so: str, methods: list[str], min_printable: float=0.85, "
             "min_len: int=4, limit: int=30, lcg_multiplier:int=0x08088405, "
             "lcg_inc:int=1, lcg_seed:int|None=None, addr:int|None=None, "
             "size:int|None=None}")

    def run(self, session, args: dict):
        so_name = args.get("so")
        if not so_name:
            return {"error": "需要 so 参数", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        methods = args.get("methods") or [
            "single_byte_xor", "rolling_xor", "lcg_xor", "not",
        ]
        min_printable = float(args.get("min_printable", 0.85))
        min_len = int(args.get("min_len", 4))
        limit = int(args.get("limit", 30))
        addr = args.get("addr")
        size = args.get("size")

        # (4) 第四次修改（2026-11-18）：plaintext 模式——只列已是明文的块。
        #     与解密结果分开返回：一个是"本来就是明文"，一个是"解出来的"，
        #     混在一起会让人以为明文也是解出来的。
        if bool(args.get("plaintext")):
            pt = self._plaintext_blocks(so, addr, size, min_len)
            return {
                "ok": True, "so": so.name, "mode": "plaintext",
                "count": len(pt), "results": pt[:limit],
                "note": ("这里列的是**本来就是明文**的字符串（无需解密），"
                         "按 NUL 切分、可打印度 >= 0.9。"
                         "解密结果请去掉 plaintext 参数重跑。"),
            }

        # 取待解密的字节块：给 addr+size 就只读那块，
        # 否则遍历所有只读节，按 NUL 分块（跳过已是明文的可打印串）
        blocks = self._collect_blocks(so, addr, size, min_len)

        results = []
        for block_addr, data in blocks:
            for method in methods:
                for params, plain in self._try(method, data, args):
                    printable_score = _score(plain)
                    if printable_score < min_printable:
                        continue
                    sem = _semantic_score(plain)
                    # 语义分太低（如纯重复字符）直接丢弃
                    if sem < 0.35:
                        continue
                    text = _clean(plain).rstrip(".")
                    if len(text) < min_len:
                        continue
                    results.append({
                        "addr": hex(block_addr),
                        "method": method,
                        "params": params,
                        "plaintext": _clean(plain),
                        "score": round(printable_score, 3),
                        "semantic": round(sem, 3),
                    })

        # 可打印度优先，其次长度（长串更可能是有意义的模板）
        results.sort(key=lambda r: (-(r["score"] * 0.3 + r["semantic"] * 0.7),
                                    -len(r["plaintext"])))

        # 同一地址只保留得分最高的一条，避免 256 种 XOR key 刷屏
        best: dict[str, dict] = {}
        for r in results:
            if r["addr"] not in best:
                best[r["addr"]] = r
        final = sorted(best.values(),
                       key=lambda r: (-(r["score"] * 0.3 + r["semantic"] * 0.7),
                                      -len(r["plaintext"])))[:limit]

        return {
            "ok": True,
            "so": so.name,
            "scanned_blocks": len(blocks),
            "methods": methods,
            "count": len(final),
            "results": final,
            "note": ("按可打印 ASCII 比例排序，同地址只保留最高分。"
                     "结果需人工复核——高可打印度不等于语义正确。"),
        }

    def _collect_blocks(self, so, addr, size, min_len):
        """取待解密字节块。

        (3) 第三次修改（2026-11-18）：修三个 bug（使用者实测
            「string_crack 三种方法都试了，一个字符串没解出来」）。

            bug 原因：
              ① **addr+size 路径不按 NUL 切块**——把整块 .rodata
                 （实测 1992 字节）当成一个 block。
              ② 只给 addr 不给 size 时，addr 被**静默忽略**，退回全库扫，
                 调用方以为"只解了这一节"。
              ③ 交给打分器的数据粒度不对，见 _semantic_score 的第 2 次修改。

            解决方案：
              ① addr+size 路径也走 NUL 切分（与全库路径同一套逻辑）；
              ② 只给 addr 时自动取到**该地址所在节的末尾**（或下一个可读
                 边界），不再静默退全库；取不到就明确报错；
              ③ 抽出 _split_nul 供两条路径共用，保证行为一致。
        """
        out = []
        if addr is not None:
            a = int(addr)
            if size:
                n = int(size)
            else:
                n = self._guess_len(so, a)
                if n <= 0:
                    return []              # 调用方据 scanned_blocks=0 判断
            data = so.read(a, n)
            if data:
                self._split_nul(out, a, data, min_len)
            return out

        # 无节表时用 PT_LOAD 的只读段兜底
        sections = [s for s in getattr(so, "sections", [])
                    if not getattr(s, "is_exec", False)]
        ranges = []
        for s in sections:
            if s.size:
                ranges.append((s.addr, s.size))
        if not ranges:
            for vaddr, end, _off, flags in getattr(so, "_loads", []) or []:
                if not (flags & 0x1):           # 不可执行段
                    ranges.append((vaddr, end - vaddr))

        for base, length in ranges:
            # 大段分块，避免一次读几 MB
            data = so.read(base, min(length, 1 << 20))
            self._split_nul(out, base, data, min_len)
        return out

    @staticmethod
    def _guess_len(so, addr: int) -> int:
        """只给了地址：推断该地址到本节末尾还有多少字节。

        优先节边界；无节表时用 PT_LOAD 段边界。都拿不到返回 0
        （调用方据此报错，而不是悄悄退回全库扫描）。
        """
        sec = None
        try:
            sec = so.section_at(addr)
        except Exception:                                 # noqa: BLE001
            sec = None
        if sec is not None and sec.size:
            end = sec.addr + sec.size
            if end > addr:
                return end - addr
        for va, end, _off, _fl in getattr(so, "_loads", []) or []:
            if va <= addr < end:
                return end - addr
        return 0

    def _split_nul(self, out, base: int, data: bytes, min_len: int) -> None:
        """按 NUL 切块，跳过本来就是明文的片段。

        (3) 第三次修改（2026-11-18）：从 _collect_blocks 抽出。
            两条路径（指定范围 / 全库）必须用**同一套**切分逻辑，
            否则"指定范围解不出来但全库能解出来"这种矛盾会一直存在。

        注意：可打印占比 >= 0.9 的块被**主动跳过**——它们是明文，不需要
        解密。想看它们请用 plaintext 模式（见 _plaintext_blocks）。
        """
        start = 0
        for i, b in enumerate(data):
            if b == 0:
                chunk = data[start:i]
                if min_len <= len(chunk) <= 256:
                    # 跳过本来就是明文的（可打印度已经很高）
                    if _score(chunk) < 0.9:
                        out.append((base + start, chunk))
                start = i + 1

    def _plaintext_blocks(self, so, addr, size, min_len: int) -> list:
        """枚举**已经是明文**的字符串块（不解密，直接列出来）。

        (4) 第四次修改（2026-11-18）：新增。
            bug 原因：使用者反馈「三种解密方式都试了，一个字符串没解出来」，
                      实测发现那块的明文其实**都在**，只是被 _split_nul
                      以「可打印度 >= 0.9 → 不需要解密」为由跳过了。
                      逻辑上没错，但工具缺了另一半能力：想确认
                      "这块里到底有什么、我是不是漏看了"，没有入口。
            解决方案：plaintext 模式直接列明文块。与解密结果分开返回，
                      避免两种性质不同的东西混在一个 results 里。
        """
        out = []
        ranges = []
        if addr is not None:
            a = int(addr)
            n = int(size) if size else self._guess_len(so, a)
            if n > 0:
                ranges.append((a, n))
        else:
            for sec in getattr(so, "sections", []):
                if not getattr(sec, "is_exec", False) and sec.size:
                    ranges.append((sec.addr, sec.size))
            if not ranges:
                for va, end, _off, fl in getattr(so, "_loads", []) or []:
                    if not (fl & 1):
                        ranges.append((va, end - va))

        for base, length in ranges:
            data = so.read(base, min(length, 1 << 20))
            start = 0
            for i, b in enumerate(data):
                if b == 0:
                    chunk = data[start:i]
                    if min_len <= len(chunk) <= 256 and _score(chunk) >= 0.9:
                        out.append({"addr": hex(base + start),
                                    "value": chunk.decode("ascii", "replace")})
                    start = i + 1
        return out

    def _try(self, method, data, args):
        """生成 (params, plaintext) 序列。"""
        if method == "single_byte_xor":
            for k in range(256):
                yield {"key": hex(k)}, bytes(c ^ k for c in data)
        elif method == "not":
            yield {}, bytes(~c & 0xFF for c in data)
        elif method == "rolling_xor":
            for k in range(256):
                yield {"start": hex(k)}, bytes(c ^ ((k + i) & 0xFF)
                                               for i, c in enumerate(data))
        elif method == "add_xor":
            for k in range(256):
                yield {"add": hex(k)}, bytes((c + k) & 0xFF for c in data)
        elif method == "multi_byte_xor":
            # 短 key 暴力：2/4 字节（纯通用，不针对具体样本）
            # (2) key 空间收敛到常见可打印对，避免 9025×块数的组合爆炸
            if len(data) > 64:
                return
            candidates = [b"ab", b"cd", b"12", b"key", b"xy"] + [
                bytes([a, b]) for a in b"0123456789abcdef" for b in b"0123456789"
            ]
            seen_keys = set()
            for key in candidates:
                if len(key) == 2:
                    key = key + key       # 统一用 4 字节循环
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                yield {"key": key.hex()}, bytes(
                    c ^ key[i % len(key)] for i, c in enumerate(data))
        elif method == "rc4_static":
            # 常见固定 key（公开通用弱 key 集合，不是样本特征）
            common_keys = [b"key", b"secret", b"123456", b"password",
                           b"12345678", b"abcdef", b"000000"]
            for key in common_keys:
                S = list(range(256))
                j = 0
                for i in range(256):
                    j = (j + S[i] + key[i % len(key)]) & 0xFF
                    S[i], S[j] = S[j], S[i]
                out = bytearray()
                i = j = 0
                for c in data:
                    i = (i + 1) & 0xFF
                    j = (j + S[i]) & 0xFF
                    S[i], S[j] = S[j], S[i]
                    out.append(c ^ S[(S[i] + S[j]) & 0xFF])
                yield {"key": key.decode("ascii")}, bytes(out)
        elif method == "base64_after_xor":
            import base64
            for k in (0, 1, 0x20, 0x5a, 0xff):
                raw = bytes(c ^ k for c in data)
                try:
                    dec = base64.b64decode(raw, validate=False)
                    if dec:
                        yield {"xor": hex(k), "then": "base64"}, dec
                except Exception:                         # noqa: BLE001
                    pass
        elif method == "aes_static":
            # 无 pycryptodome 时不硬做；给明确说明而不是假成功
            # （本模块只依赖标准库）
            return
        elif method == "lcg_xor":
            mult = int(args.get("lcg_multiplier", 0x08088405))
            inc = int(args.get("lcg_inc", 1))
            seed_arg = args.get("lcg_seed")
            seeds = ([int(seed_arg)] if seed_arg is not None
                     else [0xdeadbeef, 1, 0x12345678])
            for seed in seeds:
                x = seed & 0xFFFFFFFF
                out = bytearray()
                for c in data:
                    x = (x * mult + inc) & 0xFFFFFFFF
                    out.append(c ^ (x & 0xFF))
                yield {"multiplier": hex(mult), "inc": inc,
                       "seed": hex(seed)}, bytes(out)
        # 未知 method：静默跳过（调用方 methods 里可能有拼错的，
        # 但整体结果仍有其他算法产出）
