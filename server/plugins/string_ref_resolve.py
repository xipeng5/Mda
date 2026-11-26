"""解密串引用反查插件（通用能力）。

## 解决什么问题

string_crack 解密出字符串后（如 "%s/%s%s"、".msfs_"），使用者不知道
哪个函数用它。静态 xref 指向**密文地址**而非解密结果，所以拿明文
直接查引用必然落空。

本插件做一座桥：
  模式一 cipher_addr  —— 调用方已知密文地址：xrefs_to(密文地址) 折回函数。
  模式二 cipher_hex   —— 只有明文 + 密文字节：在 so 原始字节里搜密文，
                          用 ELF 段映射把文件偏移换算成虚拟地址，再走模式一。
  模式三 只有 plaintext —— **不猜**：直接返回 NEED_CIPHER_LOC，说明静态
                          xref 指向密文地址，必须给 cipher_addr / cipher_hex。

## 为什么是通用能力

三种模式都只用标准接口：xref 图、so._raw 字节搜索、_loads 段表映射。
不硬编码任何具体字符串、密文地址或偏移；string_crack 结果里的
source_addr 就是模式一要的 cipher_addr，只是把这条路径自动化。

## 诚实边界（写进 note）

静态 xref 看不到反射调用、JIT 生成代码、运行时拼接字符串后再使用的场景；
0 引用可能是「真没人用」也可能是「xref 图未全量构建」。
"""
from __future__ import annotations

from server.core.addr import parse_addr
from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "string_ref_resolve"
    description = "解密串反查：密文地址/密文字节 → 引用函数（静态 xref 桥）"
    usage = ("args: {so: str, plaintext: str, cipher_addr: str|int|None=None, "
             "cipher_hex: str|None=None, limit: int=50}")

    def _parse_int(self, value):
        """用途：兼容 '0x...' 字符串与 int 的地址入参，失败抛 ValueError。"""
        parsed = parse_addr(value)
        if parsed is None:
            raise ValueError(f"非法地址：{value!r}")
        return parsed

    def _parse_cipher_hex(self, text):
        """用途：把调用方给的十六进制字节串解析成 bytes，容忍空格与 '0x' 前缀。

        容错有限：奇数长度 / 非 hex 字符视为 BAD_ARGS，不静默丢字节
        （丢一个字节会让模式二搜错密文，得出假引用）。
        """
        s = str(text).replace("0x", "").replace("0X", "")
        s = "".join(s.split())  # 去所有空白（支持 "de ad be ef"）
        if len(s) % 2:
            raise ValueError("cipher_hex 长度为奇数")
        return bytes.fromhex(s)

    def _file_off_to_vaddr(self, so, off):
        """用途：把文件偏移按 ELF PT_LOAD 段映射成虚拟地址（可多个）。

        段表项 (vaddr, end, off, flags) 中 vaddr-off 在同一段内是常量。
        命中条件：off 落在 [seg_off, seg_off + (end-vaddr)) 内。
        返回所有命中段的虚拟地址列表——同一文件偏移理论上可被多个段映射，
        不擅自挑一个（挑错会把引用归到错误地址）。
        """
        out = []
        for va, end, seg_off, _fl in getattr(so, "_loads", []) or []:
            if seg_off <= off < seg_off + (end - va):
                out.append(va + (off - seg_off))
        return out

    def _search_cipher_vaddrs(self, so, needle):
        """用途：在 so 原始字节里搜 cipher_hex 的全部出现位置，换算成虚拟地址。

        用 bytes.find 循环（不 import re），返回 (vaddrs, scanned_bytes, offs)：
          vaddrs       去重后的虚拟地址（升序），供逐地址查 xref
          scanned_bytes _raw 总长度——0 命中时区分「so 里根本没这段字节」
          offs         命中的文件偏移（诊断用，不编造）
        只在有 _raw 时搜；没有原始字节时 scanned_bytes=0 并明确说明无法搜索。
        """
        raw = getattr(so, "_raw", None)
        if not raw:
            return [], 0, []
        offs = []
        start = 0
        while True:
            pos = raw.find(needle, start)
            if pos < 0:
                break
            offs.append(pos)
            start = pos + 1  # +1 而非 +len：允许重叠出现
            if len(offs) >= 4096:  # 防御性上限：极短模式在全 0 区可能爆炸
                break
        vaddrs = set()
        for off in offs:
            vaddrs.update(self._file_off_to_vaddr(so, off))
        return sorted(vaddrs), len(raw), offs

    # (1) 第一次修改（2026-11-26）
    # bug 原因：1) _refs_of 直接调 xr.xrefs_to(addr) 未先调用 xr.build()，未手动 build_xrefs 时恒返回空引用；
    #           2) hint 写错字段名 source_addr（string_crack 实际字段为 addr）；
    #           3) cipher_addr 解析失败返 BAD_ARGS 而非统一 BAD_ADDR，且未捕获非 ARM64 的 ValueError。
    # 解决方案：在 _refs_of 中先确保 xr.build() 并使用规范名 so.name；修正 hint 为 addr；
    #           cipher_addr 非法返 BAD_ADDR；捕获非 ARM64 返 UNSUPPORTED_ARCH。
    def _refs_of(self, session, so, so_name, addr, limit):
        """用途：查一个密文地址的静态引用者，折回所在函数（模式一/二共用）。"""
        out = []
        try:
            xr = session.xref(so.name)
            if hasattr(xr, "build"):
                xr.build()
            sites = xr.xrefs_to(addr) or []
        except ValueError as exc:
            return {"ok": False, "code": "UNSUPPORTED_ARCH",
                    "addr": hex(addr), "refs": [], "error": str(exc)}
        except Exception as exc:                          # noqa: BLE001
            return {"addr": hex(addr), "refs": [], "error": f"xref 查询失败：{exc}"}
        for site in sites[:limit]:
            site = int(site)
            fn = so.function_at(site)
            name = fn.name if fn and fn.name else (f"sub_{fn.addr:x}" if fn else None)
            insn_text = None
            try:
                # xrefs_from 只返回带引用的指令，按地址匹配；命中不到就留 None
                for ins in (xr.xrefs_from(fn.addr) if fn else []) or []:
                    if int(getattr(ins, "addr", -1)) == site:
                        insn_text = ins.text
                        break
            except Exception:                             # noqa: BLE001
                pass
            out.append({"site": hex(site), "function": name, "insn": insn_text})
        return {"addr": hex(addr), "refs": out}

    def run(self, session, args: dict):
        # 用途：按是否给出密文位置分三种模式；只有明文时明确报错，不猜。
        so_name = args.get("so")
        plaintext = args.get("plaintext")
        if not so_name:
            return {"error": "需要 so 参数", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}
        try:
            limit = int(args.get("limit", 50))
        except (ValueError, TypeError):
            return {"error": "limit 必须是整数", "code": "BAD_ARGS"}

        note = (
            "静态 xref 只覆盖已收录的 bl 调用与 adrp+add 数据引用："
            "反射调用、JIT 生成代码、运行时拼接字符串后再使用都看不到；"
            "0 引用可能是『真没人用』也可能是『xref 图未全量构建』"
            "（可先 session.ensure_xrefs 提高覆盖）。"
        )
        cipher_addr = args.get("cipher_addr")
        cipher_hex = args.get("cipher_hex")

        # 模式三：只有明文，没有密文位置——不猜，明确让用户补参数。
        if cipher_addr is None and cipher_hex is None:
            return {
                "error": ("仅给 plaintext 无法反查静态引用（静态 xref 指向"
                          "密文地址，不是解密结果）。请给 cipher_addr 或 cipher_hex。"),
                "code": "NEED_CIPHER_LOC",
                "hint": "string_crack 的结果里应有 addr",
                "so": so.name,
                "plaintext": plaintext,
                "note": note,
            }

        # 模式一：调用方给了密文地址，直接查引用者。
        if cipher_addr is not None:
            addr = parse_addr(cipher_addr)
            if addr is None:
                return {"ok": False, "error": f"cipher_addr 解析失败：{cipher_addr!r}",
                        "code": "BAD_ADDR"}
            res = self._refs_of(session, so, so.name, addr, limit)
            if res.get("code") == "UNSUPPORTED_ARCH":
                return res
            res.update({
                "ok": True,
                "mode": "cipher_addr",
                "so": so.name,
                "plaintext": plaintext,
                "searched_addrs": 1,
                "note": note,
            })
            return res

        # 模式二：给了密文字节，先在 so 字节里搜出所有虚拟地址，再逐个查引用。
        try:
            needle = self._parse_cipher_hex(cipher_hex)
        except (ValueError, TypeError) as exc:
            return {"error": f"cipher_hex 解析失败：{exc}", "code": "BAD_ARGS"}
        if not needle:
            return {"error": "cipher_hex 解析出 0 字节", "code": "BAD_ARGS"}
        vaddrs, scanned_bytes, file_offs = self._search_cipher_vaddrs(so, needle)
        refs = []
        for va in vaddrs[:limit]:
            one = self._refs_of(session, so, so.name, va, limit)
            if one.get("code") == "UNSUPPORTED_ARCH":
                return one
            refs.extend(one["refs"])
        return {
            "ok": True,
            "mode": "search_cipher",
            "so": so.name,
            "plaintext": plaintext,
            "cipher_hex": str(cipher_hex),
            "cipher_vaddrs": [hex(v) for v in vaddrs[:limit]],
            "file_offsets": [hex(o) for o in file_offs[:limit]],
            "scanned_bytes": scanned_bytes,
            "searched_addrs": len(vaddrs),
            "refs": refs[:limit],
            "note": note + " cipher_hex 搜索基于 so 原始字节（不解密）；"
                    "同一字节串多处出现时给出全部虚拟地址，按需逐个核对。",
        }
