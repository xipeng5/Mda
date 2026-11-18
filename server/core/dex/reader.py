"""DEX 字节层读取。

职责：只有两件事——
  1. 原始字节的定长/变长整数解码（u1/u2/u4/u8、ULEB128、SLEB128），带边界检查；
  2. 「给一个路径，把它里面的每个 dex 字节块按顺序拿出来」（.dex 单文件，
     或 .apk/.jar/.zip 里的 classes*.dex）。
不含任何 DEX 语义：表结构在 header.py，class_data/code_item 在 code.py。

错误处理约定：一切解析失败抛 DexError(code, message)。
code 是给上层直接塞进 error 字段的短标识（如 BAD_ULEB128 / NOT_A_DEX），
message 是给人看的中文说明。**不返回编造的数据**。
"""
from __future__ import annotations

import os
import struct
import zipfile

# DEX 里 uleb128 最多 5 字节（35 bit），dlebs128 同理
_MAX_LEB_BYTES = 5


class DexError(Exception):
    """DEX 解析错误。上层 API 捕获后转成 error 字段，不向调用方抛。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def uleb128(buf: bytes, off: int) -> tuple[int, int]:
    """解 ULEB128，返回 (值, 新偏移)。

    DEX 的 string_data_item 开头就是它——注意它是**字符数（UTF-16 码元数）**，
    不是字节数，见 mutf8.py。
    """
    result = 0
    shift = 0
    start = off
    for _ in range(_MAX_LEB_BYTES):
        if off >= len(buf):
            raise DexError("BAD_ULEB128", f"ULEB128 越界，起始偏移 0x{start:x}")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
    raise DexError("BAD_ULEB128", f"ULEB128 超过 {_MAX_LEB_BYTES} 字节，起始偏移 0x{start:x}")


def sleb128(buf: bytes, off: int) -> tuple[int, int]:
    """解 SLEB128（带符号），返回 (值, 新偏移)。"""
    result = 0
    shift = 0
    start = off
    b = 0
    for _ in range(_MAX_LEB_BYTES):
        if off >= len(buf):
            raise DexError("BAD_SLEB128", f"SLEB128 越界，起始偏移 0x{start:x}")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            # 符号扩展：最后一字节的最高有效位是符号位
            if shift < 64 and (b & 0x40):
                result -= 1 << shift
            return result, off
    raise DexError("BAD_SLEB128", f"SLEB128 超过 {_MAX_LEB_BYTES} 字节，起始偏移 0x{start:x}")


class DexBuffer:
    """一段 dex 字节 + 带边界检查的读取原语。

    所有读取都过 need()，越界立刻抛 DexError —— 坏 dex 的典型症状是某个
    offset 字段被壳写成垃圾值，静默截断会产出看似正常的垃圾表。
    """

    __slots__ = ("data", "display", "path")

    def __init__(self, data: bytes, display: str, path: str = ""):
        self.data = data
        self.display = display  # 展示名，如 "汽水音乐6.2.apk!classes.dex"
        self.path = path

    def __len__(self) -> int:
        return len(self.data)

    def need(self, off: int, size: int, what: str) -> None:
        """检查 [off, off+size) 是否落在文件内。"""
        if off < 0 or size < 0 or off + size > len(self.data):
            raise DexError(
                "OUT_OF_RANGE",
                f"{what} 越界：偏移 0x{off:x} 长度 {size}，文件只有 0x{len(self.data):x} 字节"
                f"（{self.display}）",
            )

    def u1(self, off: int, what: str = "u1") -> int:
        self.need(off, 1, what)
        return self.data[off]

    def u2(self, off: int, what: str = "u2") -> int:
        self.need(off, 2, what)
        return struct.unpack_from("<H", self.data, off)[0]

    def u4(self, off: int, what: str = "u4") -> int:
        self.need(off, 4, what)
        return struct.unpack_from("<I", self.data, off)[0]

    def u8(self, off: int, what: str = "u8") -> int:
        self.need(off, 8, what)
        return struct.unpack_from("<Q", self.data, off)[0]

    def raw(self, off: int, size: int, what: str = "bytes") -> bytes:
        self.need(off, size, what)
        return self.data[off:off + size]


def _dex_entry_order(name: str) -> int:
    """classes.dex -> 1，classes2.dex -> 2 …… 多 dex 的合并顺序就是它。"""
    base = name.rsplit("/", 1)[-1]
    if not (base.startswith("classes") and base.endswith(".dex")):
        return 1 << 30
    mid = base[len("classes"):-len(".dex")]
    if mid == "":
        return 1
    if mid.isdigit():
        return int(mid)
    return 1 << 30


class DexSource:
    """一个路径里的全部 dex。

    .dex 直接读；.apk/.jar/.zip 走 zipfile，只取 classes*.dex 并按编号排序。
    字节块按需读取（不一次性把 9 个 dex 全读进内存），由上层做 LRU。
    """

    def __init__(self, path: str):
        self.path = path
        self.basename = os.path.basename(path) or path
        self._zip: zipfile.ZipFile | None = None
        self._dex_bytes: bytes | None = None
        self.entries: list[str] = []
        self._open()

    # ---------- 打开 ----------

    def _open(self) -> None:
        if not os.path.exists(self.path):
            raise DexError("FILE_NOT_FOUND", f"文件不存在：{self.path}")
        if os.path.isdir(self.path):
            raise DexError("NOT_A_FILE", f"这是目录，不是 dex/apk 文件：{self.path}")
        try:
            with open(self.path, "rb") as f:
                head = f.read(8)
        except OSError as exc:
            raise DexError("FILE_NOT_FOUND", f"打不开文件 {self.path}：{exc}") from exc
        if head.startswith(b"dex\n"):
            # 单个 dex 文件：只记路径，字节在 read() 时读
            self.entries = [self.basename]
            return
        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            self._open_zip()
            return
        raise DexError(
            "NOT_A_DEX",
            f"既不是 dex（magic 应为 dex\\n）也不是 zip/apk，实际头 8 字节：{head.hex()}",
        )

    def _open_zip(self) -> None:
        try:
            zf = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise DexError("NOT_A_DEX", f"zip 打不开：{self.path}：{exc}") from exc
        names = [
            n for n in zf.namelist()
            if n.rsplit("/", 1)[-1].startswith("classes")
            and n.endswith(".dex")
            and _dex_entry_order(n) < (1 << 30)
        ]
        if not names:
            zf.close()
            raise DexError(
                "NO_DEX_IN_ZIP",
                f"{self.basename} 里没有 classes*.dex（共 {len(zf.namelist())} 个条目）",
            )
        names.sort(key=lambda n: (_dex_entry_order(n), n))
        self._zip = zf
        self.entries = names

    # ---------- 读取 ----------

    def read(self, entry: str) -> bytes:
        """读出某个 dex 的字节。"""
        if self._zip is None:
            if self._dex_bytes is None:
                try:
                    with open(self.path, "rb") as f:
                        self._dex_bytes = f.read()
                except OSError as exc:
                    raise DexError("FILE_NOT_FOUND", f"读不了 {self.path}：{exc}") from exc
            data = self._dex_bytes
        else:
            try:
                data = self._zip.read(entry)
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                raise DexError("BAD_DEX_BLOB", f"读 zip 条目 {entry} 失败：{exc}") from exc
        if not data.startswith(b"dex\n"):
            raise DexError(
                "NOT_A_DEX",
                f"{entry} 的 magic 不是 dex\\n，实际 {data[:8].hex()}",
            )
        return data

    def display_of(self, entry: str) -> str:
        """展示名：zip 里带 apk 名，单 dex 就只有文件名。"""
        if self._zip is None:
            return self.basename
        return f"{self.basename}!{entry}"

    def entry_size(self, entry: str) -> int:
        if self._zip is None:
            try:
                return os.path.getsize(self.path)
            except OSError:
                return -1
        try:
            return self._zip.getinfo(entry).file_size
        except KeyError:
            return -1

    def close(self) -> None:
        if self._zip is not None:
            try:
                self._zip.close()
            except Exception:
                pass
            self._zip = None
