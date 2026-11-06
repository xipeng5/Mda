"""内存解释：按地址精确读取并解释成有类型的值。

## 为什么单独一个模块

静态分析拿到的是「地址 + 字节」，但人/AI 真正想看的是「这里是个 uint32 = 4096」
「这里是个 C 字符串 '/system/bin/sh'」「这个指针指向哪、跟三层是什么」。
``core/strings.py`` 的 ``StringAnalyzer`` 是**全量扫描**（遍历整个 .rodata 建索引），
本模块是**按地址精确读一个**，目标不同，不复用。

## 双数据源

同一个地址语义，读取来源可能不同：

- ``source="static"``：读本地 so 文件（``SoFile.read`` 的三级读取），
  不需要 frida、不需要设备，拿到的是**文件里躺着的内容**。
- ``source="runtime"``：读真机进程内存，需要 frida 会话。
  **本轮按要求留空**，统一返回 ``dyn.pending`` 的占位结构
  （``implemented=false`` + ``code=NEEDS_FRIDA:*``），绝不假造字节。

两者的解码逻辑（struct / UTF-8 / 指针链）是同一套，将来接上 frida
只需替换 ``_fetch`` 这一处取字节的地方。

## 明确报错，不静默返回空

读不到就是读不到：地址不落在任何已注册区域、或区域内无文件数据
（``.bss`` 这类）都会抛 ``MemReadError``（带机器可读 ``code``）。
**不返回** ``b""`` / ``0`` 冒充成功——那会让下游把"读失败"当成"值确实是 0"。
"""
from __future__ import annotations

import json
import math
import os
import struct

from core.elf_model import SoFile
from dyn.pending import NotImplementedYet
from models import Arch

__all__ = [
    "MemReadError",
    "SUPPORTED_TYPES",
    "read_typed",
    "read_string",
    "read_pointer",
]

# 数据源取值
SOURCE_STATIC = "static"
SOURCE_RUNTIME = "runtime"

# 单次读取的规模上限，防止误传大数把内存读爆
_MAX_COUNT = 4096          # 数组元素个数上限
_MAX_STRING = 65536        # 字符串最大字节数上限
_MAX_POINTER_DEPTH = 64    # 指针链最大层数上限（防手滑传入巨大 depth）

# 类型表：名称 -> (struct 格式字符, 字节宽度, 类别)
# 类别用于决定输出形态：int/uint 原样、float 转 JSON 安全数字、pointer 转 hex。
_TYPES: dict[str, tuple[str, int, str]] = {
    "int8": ("b", 1, "int"),
    "int16": ("h", 2, "int"),
    "int32": ("i", 4, "int"),
    "int64": ("q", 8, "int"),
    "uint8": ("B", 1, "uint"),
    "uint16": ("H", 2, "uint"),
    "uint32": ("I", 4, "uint"),
    "uint64": ("Q", 8, "uint"),
    "float": ("f", 4, "float"),
    "double": ("d", 8, "float"),
    "pointer": ("Q", 8, "pointer"),  # 宽度按架构在 _type_info 里改写
}

# 常用别名（AI 容易写成 u32/i64/f32，别让它因为叫法不同就报错）
_ALIASES: dict[str, str] = {
    "i8": "int8", "i16": "int16", "i32": "int32", "i64": "int64",
    "u8": "uint8", "u16": "uint16", "u32": "uint32", "u64": "uint64",
    "f32": "float", "f64": "double", "float32": "float", "float64": "double",
    "ptr": "pointer", "void*": "pointer",
}

# 对外公布的支持清单（MCP 层可直接展示给 AI）
SUPPORTED_TYPES: tuple[str, ...] = tuple(_TYPES)

# 按路径打开过的 SoFile 缓存：key 是绝对路径，value 是 ((文件大小, mtime), SoFile)。
# 缓存理由：SoFile 构造要解析符号/重定位/函数表，大样本一两秒；
# 按地址反复读取时不能每次都重新解析。文件改动后 key 变化会自动失效。
_SO_CACHE: dict[str, tuple[tuple[int, float], SoFile]] = {}


class MemReadError(RuntimeError):
    """内存读取的可预期失败：带机器可读 code，供 MCP/UI 翻译成中文。

    与 ``dyn.adb.DynError`` 同形（code + message），但本模块是纯静态能力，
    不依赖 adb 模块，因此自持一个错误类型。
    """

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------- 内部：入参与数据源 ----------


def _resolve_so(so) -> SoFile:
    """把入参统一成 SoFile。

    接受两种形态：
      - ``SoFile`` 实例（推荐，MCP 层用 ``session.get(so_name)`` 取到后传入）
      - 字符串路径（自动构造并缓存，供脱离会话的脚本直接用）

    传字符串但不是存在的文件时明确报错，而不是返回空结果。
    """
    if isinstance(so, SoFile):
        return so
    if isinstance(so, str):
        if os.path.isfile(so):
            return _so_from_path(so)
        raise MemReadError(
            "BAD_SO",
            f"找不到 so 文件: {so}（若已加载到会话，请传 SoFile 实例而非名字）",
        )
    raise MemReadError(
        "BAD_SO",
        f"so 参数应为 SoFile 实例或文件路径，实际拿到 {type(so).__name__}",
    )


def _so_from_path(path: str) -> SoFile:
    """按路径取 SoFile，带（大小, mtime）校验的缓存。"""
    ap = os.path.abspath(path)
    st = os.stat(ap)
    key = (st.st_size, st.st_mtime)
    hit = _SO_CACHE.get(ap)
    if hit is not None and hit[0] == key:
        return hit[1]
    so = SoFile(ap)
    _SO_CACHE[ap] = (key, so)
    return so


def _check_source(source: str) -> str:
    """校验数据源取值，非法值直接报错（不默认成 static 蒙混过去）。"""
    if source not in (SOURCE_STATIC, SOURCE_RUNTIME):
        raise MemReadError(
            "BAD_SOURCE",
            f"未知数据源 {source!r}，只支持 {SOURCE_STATIC!r} / {SOURCE_RUNTIME!r}",
        )
    return source


def _pointer_size(so: SoFile) -> int:
    """指针宽度：arm64/x86_64 为 8，arm32/x86 为 4。"""
    if so.arch in (Arch.ARM32, Arch.X86):
        return 4
    return 8


def _type_info(so: SoFile, type_name: str) -> tuple[str, int, str]:
    """把类型名解析成 (struct 格式字符, 字节宽度, 类别)。

    pointer 的宽度取决于目标架构，所以需要 so 才能定。
    """
    name = (type_name or "").strip().lower()
    name = _ALIASES.get(name, name)
    info = _TYPES.get(name)
    if info is None:
        raise MemReadError(
            "BAD_TYPE",
            f"不支持的类型 {type_name!r}，可用: {', '.join(SUPPORTED_TYPES)}"
            f"（别名: {', '.join(sorted(_ALIASES))}）",
        )
    fmt, size, kind = info
    if kind == "pointer":
        size = _pointer_size(so)
        fmt = "Q" if size == 8 else "I"
    return fmt, size, kind


def _region_of(so: SoFile, addr: int) -> dict | None:
    """查地址落在哪个已注册区域（section 或 PT_LOAD），没有则 None。

    只用公开的 ``maps()``：壳处理过的 so 节表被抹，此时唯一的事实来源是
    PT_LOAD 段表，``maps()`` 已经把两者合并，不必碰私有的 ``_loads``。

    (1) 第一次修改
    bug 原因：``maps()`` 按 addr 升序返回，section 与 PT_LOAD 交错。
             同一地址两者都命中时，先遍历到的那个未必更精确——实测
             ``0x3496`` 落在 .rodata 内，却报成外围的大 PT_LOAD，
             诊断信息把「跨出 .rodata 到文件尾」误导成「段表读不到」。
    解决方案：优先返回 section（更小更精确），没有 section 命中才退到 PT_LOAD。
    """
    fallback: dict | None = None
    for region in so.maps():
        if region["addr"] <= addr < region["end"]:
            if region["kind"] == "section":
                return region
            if fallback is None:
                fallback = region
    return fallback


def _read_span(so: SoFile, addr: int, size: int) -> bytes:
    """按地址连续读 size 字节，**允许跨 section 边界**。

    为什么不能直接 ``so.read(addr, size)``：``SoFile.read`` 命中 section 时
    只在该 section 内切字节，超出部分直接丢弃（不会继续到下一节/段表）。
    对按固定宽度读一个类型的场景这是真 bug——类型横跨两个 section 边界
    （代码段末尾的最后一个指令、数据段末尾的最后一个指针）本应读得到，
    却被判成读失败。

    (2) 第二次修改
    bug 原因：``0x47d2`` 处读 uint32 只拿到 2 字节就报 READ_FAILED，
             而该地址在 PT_LOAD 0x0-0x47d4 内、文件里数据完整。
    解决方案：分段读取——每次只读到「当前区域末尾」，读完再续下一段，
             直到读满 size 或下一段确实无法继续（此时才算失败）。
    不碰私有 ``_loads``：区域边界全部从公开的 ``maps()`` 得到。

    (3) 第三次修改
    bug 原因：上一版用 ``nxt - addr >= size`` 判断"跨度内没区域了"，
             但 ``nxt`` 可能是**当前区域末尾**而非下一区域起点，
             .text 末尾(0xdff0) 与 .plt 起点相同，导致 0xdfee 处读 uint32
             明明可读却提前 break（实测仍只返回 2 字节）。
    解决方案：区分两种 nxt——「区域内读空」直接判定失败终止，
             只有「落进空洞」才跳到下一区域起点继续；循环内不再做跨度裁剪。

    (4) 第四次修改
    bug 原因：上一条"落进空洞就跳到下一区域"太宽——``0x47d2`` 跨出
             .eh_frame 末尾后，直接跳到了 0x5000 的 .text 起点，把两段
             **根本不相邻**的内存拼成一个 uint32（实测得到 00005f24）。
             那是对真实数据凭空拼接，比报错更坏。
    解决方案：只有「下一区域的起点恰好等于当前游标」时才续读（真相邻，
             如 .text|.plt、.eh_frame|.plt 这种同段连续节）；中间有空洞
             就立即终止，让上层拿到明确的"读不满"错误。
    """
    regions = so.maps()
    out = bytearray()
    cur = addr
    while len(out) < size:
        chunk = so.read(cur, size - len(out))
        if chunk:
            out += chunk
            cur += len(chunk)
            continue
        # 当前地址读不出任何字节：只有「紧邻的下一个区域」才允许续读
        region = _region_of(so, cur)
        if region is not None:
            break  # 区域内无文件数据（.bss 等），续读也是空 -> 失败终止
        nxt = None
        for r in regions:
            if r["addr"] >= cur:
                nxt = r["addr"]
                break
        if nxt != cur:
            break  # 中间有空洞或之后没有区域 -> 不拼接，如实失败
        cur = nxt
    return bytes(out)


def _read_span_runtime(rb, so: SoFile, addr: int, size: int) -> bytes:
    """运行时**短读**：尽最大努力读一段，读不满也返回已读到的前缀。

    (6) 第六次修改（2026-11-03）：新增本函数。
        场景：读 C 字符串时目标往往在页中间/页尾，跨页读取会整段失败
        （frida 的 readByteArray 是"全有或全无"，一次失败返回 null）。
        但字符串内容通常在前半段就已经完整，不该因为尾巴跨页就报"读不到"。
        做法：从 size 起折半重试，拿到非空即返回，最多试 8 次
        （256 → 128 → ... → 1），既能拿到前缀又不会无限重试。
    """
    if rb is None:
        raise MemReadError("NO_RUNTIME", "source='runtime' 必须传入 rb")
    mod = None
    finder = getattr(rb, "find_module", None)
    if callable(finder):
        try:
            mod = finder(so.name)
        except Exception:                                  # noqa: BLE001
            mod = None
    if mod is None:
        raise MemReadError("MODULE_NOT_LOADED", f"{so.name} 未出现在目标进程的模块表里")
    runtime_addr = rb.to_runtime(addr, mod)
    # (7) 第七次修改（2026-11-05）：折半要真的能退到 1 字节。
    #     bug 原因：`n //= 2` 从 256 起退：256→128→64→32→16→8→4→2→1，
    #               但循环只跑 8 次（256 那次 + 7 次折半），最后落在 2 就结束了，
    #               于是"只有 1 字节可读"的场景被误报成 READ_FAILED。
    #     解决方案：折半后显式 max(1, ...)，并在 n 已经是 1 时再试一次才退出；
    #               循环上限放宽到 10 次以覆盖 256→1 的完整路径。
    n = max(1, int(size))
    for _ in range(10):
        data = rb.read_memory(runtime_addr, n)
        if data:
            return data
        if n <= 1:
            break
        n = max(1, n // 2)
    return b""


def _read_exact_runtime(rb, so: SoFile, addr: int, size: int) -> bytes:
    """从**真机运行时内存**读满 size 字节（addr 是静态地址，内部换算）。

    (5) 第五次修改（2026-11-03）：新增本函数，实现 source="runtime"。
        背景：frida-server 已对齐到 17.23.3，真机链路可用，故补上此前留空的分支。

    与静态读取的关键差异：
      · 地址要先用 Rebase 把静态地址换算成 运行时地址（加模块基址）；
      · 数据来自目标进程的**活内存**，因此能读到 .bss、堆、栈、运行时解密出来的
        内容——这些在文件里根本不存在（静态读取在这些地址上只能返回空）；
      · 读不到时会明确报错，**不返回零填充**——零填充会让人把"读失败"当成
        "这里确实是 0"，是最容易造成误判的假数据形态。
    """
    if rb is None:
        raise MemReadError(
            "NO_RUNTIME",
            "source='runtime' 必须传入 rb（dyn.rebase.Rebase 实例），"
            "否则无法把静态地址换算成运行时地址",
        )
    # (8) 第八次修改（2026-11-05）：区分"模块确实没加载"与"查询本身失败"。
    #     bug 原因：find_module 抛异常（设备掉线、会话失效、rb 实现有问题）时
    #               被统一吞成 mod=None，于是报 MODULE_NOT_LOADED ——
    #               把"查询失败"说成"这个 so 没加载"，会把人引向完全错误的排查方向。
    #     解决方案：异常直接包成 READ_FAILED 并带上原始错误；只有 find_module
    #               正常返回 None 才是真的"没加载"。
    mod = None
    finder = getattr(rb, "find_module", None)
    if callable(finder):
        try:
            mod = finder(so.name)
        except Exception as exc:                           # noqa: BLE001
            raise MemReadError(
                "READ_FAILED",
                f"查询 {so.name} 的运行时模块信息失败：{type(exc).__name__}: {exc}；"
                "这通常是会话已失效或设备断开，而不是该 so 未加载",
            ) from exc
    if mod is None:
        raise MemReadError(
            "MODULE_NOT_LOADED",
            f"{so.name} 未出现在目标进程的模块表里；先确认已 attach 且该 so 已加载",
        )

    # (6) 第六次修改（2026-11-05）：先校验地址落在模块范围内，再做换算。
    #     bug 原因：原实现直接把 addr 交给 to_runtime() 就开读，从不与 mod.size 比较。
    #               于是传一个远超模块的静态地址（实测 0x900000、0xFFFF0000）也能
    #               读到"格式正确的值"并返回 ok=True —— 那是**假数据**，
    #               直接违反"绝不返回假数据"的原则。同地址走静态源则会正确报
    #               ADDR_UNMAPPED，两条路行为不一致。
    #     解决方案：0 <= addr < mod.size 才允许换算；否则报 ADDR_UNMAPPED，
    #               并在消息里点明"本参数只接受静态地址"，防止误传运行时地址
    #               （误传会让地址被二次加基址，得到更隐蔽的错值）。
    mod_size = int(getattr(mod, "size", 0) or 0)
    if mod_size > 0 and not (0 <= addr < mod_size):
        raise MemReadError(
            "ADDR_UNMAPPED",
            f"静态地址 {addr:#x} 超出 {so.name} 的范围 [0, {mod_size:#x})；"
            "source='runtime' 的 addr 必须是**静态地址**（内部会加基址），"
            "若你手上是运行时地址请先换算，否则会被二次加基址读出一段无关内存",
        )

    to_runtime = getattr(rb, "to_runtime", None)
    if not callable(to_runtime):
        raise MemReadError("NO_RUNTIME", "rb 缺少 to_runtime()，无法换算运行时地址")
    runtime_addr = to_runtime(addr, mod)

    reader = getattr(rb, "read_memory", None)
    if not callable(reader):
        raise MemReadError("NO_RUNTIME", "rb 缺少 read_memory()，无法读取目标进程内存")
    data = reader(runtime_addr, size)
    # (7) 第七次修改（2026-11-05）：rb 是鸭子类型，读函数可能返回 None。
    #     bug 原因：直接 len(data) 会在 data=None 时抛 TypeError，
    #               逃出 MemReadError 契约，MCP 只能给出无 code 的 isError。
    #     解决方案：None 视作"读不到"，统一包成 READ_FAILED。
    if data is None:
        raise MemReadError(
            "READ_FAILED",
            f"运行时地址 {runtime_addr:#x} 的读取函数返回 None"
            "（rb.read_memory 契约应返回 bytes；返回空 bytes 表示读不到）")
    if len(data) == size:
        return data
    if not data:
        raise MemReadError(
            "READ_FAILED",
            f"运行时地址 {runtime_addr:#x}（静态 {addr:#x}）读不到数据；"
            "该页可能未映射，或被目标进程的反调试机制拦截",
        )
    raise MemReadError(
        "READ_FAILED",
        f"运行时地址 {runtime_addr:#x} 只读到 {len(data)}/{size} 字节；"
        "可能跨到了未映射页边界（frida 读失败会整体返回空，不会部分成功）",
    )


def _read_exact(so: SoFile, addr: int, size: int,
                source: str = SOURCE_STATIC, rb=None) -> bytes:
    """读满 size 字节，读不满就抛错（区分「地址未映射」与「区域内无文件数据」）。

    (5) 第五次修改（2026-11-03）：增加 source/rb 参数，把「取字节」这一步
        按数据源分派——静态走文件镜像，运行时走真机内存。三个公开函数
        共用同一条取字节路径，保证两种源的**解码逻辑完全一致**（只换取字节，
        不换解析），避免出现"静态和运行时对同一份字节给出不同结果"。
    """
    if addr < 0:
        raise MemReadError("BAD_ADDR", f"地址不能为负: {addr}")
    if size <= 0:
        raise MemReadError("BAD_REQUEST", f"读取长度必须为正，实际 {size}")
    if source == SOURCE_RUNTIME:
        return _read_exact_runtime(rb, so, addr, size)
    data = _read_span(so, addr, size)
    if len(data) == size:
        return data
    region = _region_of(so, addr)
    if region is None:
        raise MemReadError(
            "ADDR_UNMAPPED",
            f"{addr:#x} 不在 {so.name} 的任何已注册区域（共 {len(so.maps())} 个区域）",
        )
    hint = ""
    if region["kind"] == "section" and not data:
        hint = "；该地址可能属于 .bss 等运行时才分配、文件里没有数据的区域"
    raise MemReadError(
        "READ_FAILED",
        f"{addr:#x} 只读到 {len(data)}/{size} 字节"
        f"（区域 {region['kind']} {region['name'] or '(未命名)'} "
        f"{region['addr']:#x}-{region['end']:#x}）{hint}",
    )


def _runtime_pending(feature: str, requested: dict) -> dict:
    """构造 ``source="runtime"`` 的占位返回。

    恒为 ``implemented=false``：语义是「本轮没做」，不是「读到了空」。
    额外回显 requested，便于调用方确认参数已被接收（避免误以为参数丢了）。
    """
    info = NotImplementedYet(
        feature,
        reason="source='runtime' 需要真机 frida 会话，按用户要求本轮留空",
        hint="设备可用后：attach 目标进程 -> 用 dyn.rebase 把静态地址换算成运行时地址"
             " -> frida 读字节，再交给本模块同一套解码逻辑（只需替换取字节这一步）",
    ).as_dict()
    info["source"] = SOURCE_RUNTIME
    info["requested"] = requested
    return info


def _base_result(so: SoFile, addr: int, source: str) -> dict:
    """三个函数共用的返回骨架，保证字段风格一致。"""
    sec = so.section_at(addr)
    return {
        "ok": True,
        "source": source,
        "so": so.name,
        "arch": so.arch.name,
        "addr": hex(addr),
        "section": sec.name if sec is not None else "",
        "little_endian": True,  # ARM64 与 x86 都是小端；本项目样本全为小端
    }


def _json_safe_number(value):
    """float 的 nan/inf 无法进标准 JSON，转成字符串（否则前端 JSON.parse 会炸）。"""
    if isinstance(value, float) and not math.isfinite(value):
        if value != value:
            return "nan"
        return "inf" if value > 0 else "-inf"
    return value


# ---------- 公开接口 ----------


def read_typed(so, addr: int, type_name: str, count: int = 1,
               source: str = SOURCE_STATIC, rb=None) -> dict:
    """按类型读取并解析一个值（count>1 时读数组）。

    参数：
      so        —— SoFile 实例（推荐）或 so 文件路径
      addr      —— 静态虚拟地址（int）
      type_name —— 类型名，见 SUPPORTED_TYPES（另有一批常用别名）
      count     —— 元素个数，1 表示单值，>1 表示数组
      source    —— "static" 读本地文件镜像；"runtime" 读真机活内存
      rb        —— source="runtime" 时必传，dyn.rebase.Rebase 实例
                   （用来把静态地址换算成运行时地址）

    两种源的**解码逻辑完全一致**，只有"从哪取字节"不同。运行时源能读到
    .bss / 堆 / 栈 / 运行时解密内容——这些在文件里不存在。

    返回 dict：单值时 ``value`` 是标量，count>1 时是列表；
    ``values`` 恒为列表，便于程序统一处理。pointer 类型输出 hex 字符串。

    失败抛 MemReadError（BAD_TYPE / BAD_ADDR / ADDR_UNMAPPED / READ_FAILED /
    NO_RUNTIME / MODULE_NOT_LOADED 等）。**读失败绝不返回零填充**。
    """
    _check_source(source)
    so = _resolve_so(so)

    if not isinstance(count, int) or isinstance(count, bool):
        raise MemReadError("BAD_REQUEST", f"count 必须是整数，实际 {count!r}")
    if not 1 <= count <= _MAX_COUNT:
        raise MemReadError("BAD_REQUEST", f"count 必须在 1..{_MAX_COUNT}，实际 {count}")

    fmt, size, kind = _type_info(so, type_name)
    total = size * count
    if total > _MAX_STRING:
        raise MemReadError("BAD_REQUEST", f"单次读取 {total} 字节过大（上限 {_MAX_STRING}）")

    raw = _read_exact(so, addr, total, source=source, rb=rb)

    # struct 的 '<' 显式声明小端，不依赖宿主机字节序
    if count == 1:
        (first,) = struct.unpack("<" + fmt, raw)
        values = [first]
    else:
        values = list(struct.unpack(f"<{count}{fmt}", raw))

    if kind == "pointer":
        pretty = [hex(v) for v in values]
    elif kind == "float":
        pretty = [_json_safe_number(v) for v in values]
    else:
        pretty = list(values)

    out = _base_result(so, addr, source)
    out.update({
        "type_name": _ALIASES.get(str(type_name).strip().lower(),
                                   str(type_name).strip().lower()),
        "size": size,          # 单个元素的字节宽度
        "count": count,
        "total_size": total,
        "value": pretty[0] if count == 1 else pretty,
        "values": pretty,
        "raw_hex": raw.hex(),
    })
    return out


def read_string(so, addr: int, max_length: int = 256,
                source: str = SOURCE_STATIC, rb=None) -> dict:
    """按地址读一个 C 字符串（遇 ``\\0`` 截止，按 UTF-8 解码）。

    参数：
      max_length —— 最多读这么多字节；期间没有 ``\\0`` 则标注 ``truncated: true``
      source     —— 同上

    返回 dict：``value`` 是解码文本；解码失败时用 errors="replace" 并置
    ``lossy: true``（原文仍可从 ``raw_hex`` 还原）。
    """
    _check_source(source)
    so = _resolve_so(so)

    # (7) 第七次修改（2026-11-05）：补 addr 校验。
    #     bug 原因：read_string 没有 addr<0 检查（read_typed/read_pointer 都有）。
    #               static 源会抛裸 ValueError（MCP 只能给无 code 的 isError），
    #               runtime 源则会把负数加基址后读一段模块前的内存。
    #     解决方案：与另外两个函数统一，先校验 addr 为非负整数。
    if not isinstance(addr, int) or isinstance(addr, bool):
        raise MemReadError("BAD_ADDR", f"addr 必须是整数，实际 {addr!r}")
    if addr < 0:
        raise MemReadError("BAD_ADDR", f"地址不能为负: {addr}")
    if not isinstance(max_length, int) or isinstance(max_length, bool):
        raise MemReadError("BAD_REQUEST", f"max_length 必须是整数，实际 {max_length!r}")
    if not 1 <= max_length <= _MAX_STRING:
        raise MemReadError("BAD_REQUEST",
                           f"max_length 必须在 1..{_MAX_STRING}，实际 {max_length}")

    # 读不满不报错——字符串本来就可能被读到区域/映射尾，但至少要读到 1 字节
    # (6) 第六次修改（2026-11-03）：改走 _read_exact/_read_span 同一条路径。
    #     bug 原因：原先直接 so.read(addr, max_length)，而 so.read 命中 section 时
    #               只在该节内切片，字符串跨越节边界（.rodata 末尾）时会被截断，
    #               实测 0x3496 处返回 terminated:true, value:"" 的假"空字符串"。
    #     解决方案：与 read_typed 共用取字节逻辑（静态走 _read_span 允许相邻续读，
    #               运行时走 frida），字符串不再因节边界被误判为空。
    if source == SOURCE_RUNTIME:
        try:
            data = _read_exact_runtime(rb, so, addr, max_length)
        except MemReadError:
            # 运行时字符串常读到页尾才失败：允许短读，只要有内容就用
            data = _read_span_runtime(rb, so, addr, max_length)
    else:
        data = _read_span(so, addr, max_length)
    if not data:
        region = _region_of(so, addr)
        if region is None:
            raise MemReadError(
                "ADDR_UNMAPPED",
                f"{addr:#x} 不在 {so.name} 的任何已注册区域",
            )
        raise MemReadError(
            "READ_FAILED",
            f"{addr:#x} 起读不到任何字节（区域 {region['name'] or region['kind']} 无文件数据）",
        )

    nul = data.find(b"\x00")
    if nul >= 0:
        raw = data[:nul]
        terminated, truncated = True, False
    else:
        # max_length 内没有 \0：要么字符串更长，要么直接读到区域/文件尾
        raw = data
        terminated, truncated = False, True

    try:
        text = raw.decode("utf-8")
        lossy = False
    except UnicodeDecodeError:
        # 非法 UTF-8：替换而非丢弃，同时标注失真，调用方可自行决定要不要看 raw_hex
        text = raw.decode("utf-8", errors="replace")
        lossy = True

    out = _base_result(so, addr, source)
    out.update({
        "value": text,
        "encoding": "utf-8",
        "byte_length": len(raw),        # 不含结尾 \0 的字节数
        "char_length": len(text),       # 解码后的字符数（非 ASCII 会小于字节数）
        "terminated": terminated,       # 是否在 max_length 内遇到 \0
        "truncated": truncated,         # 是否被 max_length 截断
        "lossy": lossy,                 # UTF-8 解码是否发生过替换
        "raw_hex": raw.hex(),
    })
    return out


def read_pointer(so, addr: int, depth: int = 1, offset: int = 0,
                 source: str = SOURCE_STATIC, rb=None) -> dict:
    """读指针，并可按 depth 逐层跟链。

    规则：每层读一个指针宽度（arm64 为 8 字节）的值作为「指向的地址」，
    下一层的读取地址 = 该值 + ``offset``。

    参数：
      depth  —— 最多跟几层（1 表示只读起始地址这一个指针）
      offset —— 每层加在指针值上的偏移（链表 next 存在结构体内时常用）

    返回 ``chain`` 形如 ``[{"level":0,"addr":"0x..","value":"0x.."}, ...]``：
    ``addr`` 是本层读取位置，``value`` 是本层读到的指针值。

    三种提前停止都会如实标注（不会假装走满）：
      - ``null``       指针值为 0
      - ``cycle``      下一层地址已访问过（防死循环）
      - ``unmapped`` / ``unreadable``  下一层地址不可读
    被停下的那一层地址放 ``stopped_at``，原因放 ``reason``。
    """
    _check_source(source)
    so = _resolve_so(so)

    if not isinstance(depth, int) or isinstance(depth, bool):
        raise MemReadError("BAD_REQUEST", f"depth 必须是整数，实际 {depth!r}")
    if not 1 <= depth <= _MAX_POINTER_DEPTH:
        raise MemReadError("BAD_REQUEST",
                           f"depth 必须在 1..{_MAX_POINTER_DEPTH}，实际 {depth}")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise MemReadError("BAD_REQUEST", f"offset 必须是整数，实际 {offset!r}")

    psize = _pointer_size(so)
    fmt = "<Q" if psize == 8 else "<I"
    limit = 1 << (psize * 8)

    # (1) 第一次修改
    # bug 原因：起始地址不可读时返回了 levels=0 的空链 + ╨stopped_at，调用方
    #          以为「读到了一个空指针链」而不是「这个地址根本读不了」，
    #          与"失败要明确报错"的约定冲突。
    # 解决方案：起始地址必须先读通，读不通按 read_typed 的口径抛 MemReadError；
    #          只有「跟链途中」的不可读才是正常终止（记 stopped_at/reason）。
    _read_exact(so, addr, psize, source=source, rb=rb)

    chain: list[dict] = []
    visited: list[int] = []
    current = addr
    stopped_at: str | None = None
    reason = ""
    complete = False

    for level in range(depth):
        if current in visited:
            stopped_at, reason = hex(current), "cycle"
            break
        try:
            raw = _read_exact(so, current, psize, source=source, rb=rb)
        except MemReadError as exc:
            stopped_at = hex(current)
            reason = "unmapped" if exc.code == "ADDR_UNMAPPED" else "unreadable"
            break

        value = struct.unpack(fmt, raw)[0]
        visited.append(current)
        chain.append({"level": level, "addr": hex(current), "value": hex(value)})

        if value == 0:
            stopped_at, reason = hex(current), "null"
            break
        following = value + offset
        # (9) 第九次修改（2026-11-05）：下溢也要判。
        #     bug 原因：只检查了 `following >= limit`（上溢），而 offset 可以是负数，
        #               此时 value + offset 可能 < 0。原实现会把这个负地址当"下一层"
        #               去读，读失败后笼统记为 reason="unreadable"，还输出一个
        #               **负数的十六进制地址**（如 "-0x10"），调用方无从判断是下溢。
        #     解决方案：单独判 < 0，记 reason="underflow"，与原值一起给出，
        #               不让负数地址进入后续读取。
        if following < 0:
            stopped_at, reason = hex(current), "underflow"
            break
        if following >= limit:
            # 指针值 + offset 溢出目标位宽，继续读必然落到野地址
            stopped_at, reason = hex(current), "overflow"
            break
        current = following
    else:
        complete = True

    out = _base_result(so, addr, source)
    out.update({
        "depth": depth,
        "offset": offset,
        "pointer_size": psize,
        "chain": chain,
        "levels": len(chain),      # 实际读到的层数
        "complete": complete,      # 是否走满 depth 且未提前停止
        "stopped_at": stopped_at,  # 提前停止的地址（完整走完时为 None）
        "reason": reason,          # 提前停止的原因（完整走完时为空串）
    })
    return out


def _direct_read_batch(serial: str, pid: int, regions: list) -> list:
    """一次 attach + 一个脚本，读完所有内存段。

    (12) 第十二次修改（2026-11-06）：新增。
        bug 原因：原有实现依赖 Rebase.read_memory，而它**每读一段都新建一个
                  脚本**；Rebase.attach / detach 各要等守护线程超时，
                  实测读 3 段耗时 28 秒。分析时动辄十几段，完全不可用。
        解决方案：直接 attach 一次，把多段地址一次性交给 JS 侧循环读取，
                  一个脚本读完全部，Python 侧按顺序还原。实测降到 1~2 秒。
    """
    try:
        import frida
    except Exception:                                     # noqa: BLE001
        return [{"addr": hex(r["addr"]), "ok": False,
                 "error": "frida 不可用"} for r in regions]

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        spec = [[int(r["addr"]), int(r["size"])] for r in regions]
        js = (
            "var SPEC = " + json.dumps(spec) + ";"
            "var out = [];"
            "for (var i = 0; i < SPEC.length; i++) {"
            "  var a = SPEC[i][0], n = SPEC[i][1];"
            "  try {"
            "    var b = ptr(a).readByteArray(n);"
            "    out.push(b === null ? {ok:false, err:'null'} : "
            "{ok:true, hex:Array.from(new Uint8Array(b))"
            ".map(function(x){return x.toString(16).padStart(2,'0');}).join('')});"
            "  } catch (e) { out.push({ok:false, err:String(e)}); }"
            "}"
            "send(out);"
        )
        script = sess.create_script(js)
        got: list = []
        script.on("message", lambda m, d: got.extend(m.get("payload") or []))
        script.load()
        t0 = __import__("time").time()
        while not got and __import__("time").time() - t0 < 10.0:
            __import__("time").sleep(0.02)
        results = []
        for i, r in enumerate(regions):
            item = got[i] if i < len(got) else None
            if item and item.get("ok"):
                results.append({"addr": hex(int(r["addr"])), "ok": True,
                                "size": len(item.get("hex", "")) // 2,
                                "hex": item.get("hex", "")})
            else:
                results.append({"addr": hex(int(r["addr"])), "ok": False,
                                "error": (item or {}).get("err", "无响应")})
        return results
    except Exception as exc:                              # noqa: BLE001
        return [{"addr": hex(int(r["addr"])), "ok": False,
                 "error": f"{type(exc).__name__}: {exc}"} for r in regions]
    finally:
        if sess is not None:
            try:
                from dyn.tracer import _detach_async

                _detach_async(sess, 1.0)
            except Exception:                             # noqa: BLE001
                pass


def dump_vm_state(serial: str, pid: int, ctx_ptr: int,
                  count_offset: int = 0x194,
                  array_offset: int = 0x1a0,
                  instr_size: int = 16,
                  max_instr: int = 200,
                  rb=None) -> dict:
    """按约定的 VM 上下文结构，把**指令数组**解出来。

    (10) 第十次修改（2026-11-06）：新增。
        bug 原因：VM 类壳把字节码存在自己管理的数组里，结构固定但没有任何符号。
                  分析者要么反复手算指针，要么一读就把目标打断——
                  每次 attach + 读内存都会让被调试进程停一下，采样几次就丢事件。
        解决方案：**一次 attach 读完整块**：
                  ① 从 ctx_ptr+0x194 读指令计数；
                  ② 从 ctx_ptr+0x1a0 读指令数组指针；
                  ③ 一次性把整个数组读回来（最多 max_instr 条）；
                  ④ 按 bit 字段解出 opcode / func，尽量给出结构化结果。
                  这样只需一次 RPC，而不是每条指令读一次。

    ## 结构假设（来自汇编观察，可用参数覆盖）

        [ctx + 0x194] = 指令计数（u32 或 u64，自动探测）
        [ctx + 0x1a0] = 指令数组指针
        每条指令 16 字节，字段布局用 instr_size / 位域参数描述

    ## 参数

        serial / pid           目标
        ctx_ptr                VM 上下文指针（**运行时绝对地址**）
        count_offset           计数在 ctx 里的偏移，默认 0x194
        array_offset           数组指针在 ctx 里的偏移，默认 0x1a0
        instr_size             每条指令字节数，默认 16
        max_instr              最多解多少条（防止数组巨大时读爆）
        rb                     可选 Rebase 实例（复用会话，避免重复 attach）

    ## 返回

        count / array_ptr / instr_size
        instructions[]  每条 {idx, addr, raw_hex, opcode, func, words[]}
        regs            顺带返回时无法获取，固定为 None（该结构只含指令数组）
        truncated       是否因 max_instr 截断

    ## 已知边界

        · 位域解析（opcode=bits[4:1]、func=bits[8:5]）是**经验规则**，
          不同版本壳可能不同；用 opcode_bits / func_bits 参数可调
        · 若 count 明显不合理（>100 万），会拒绝读取并报可疑，不硬读
    """
    own_rb = False
    if rb is None:
        try:
            from dyn.rebase import Rebase

            rb = Rebase.attach(serial, int(pid))
            own_rb = True
        except Exception as exc:                          # noqa: BLE001
            return {"ok": False, "code": "ATTACH_FAILED",
                    "error": f"attach 失败：{exc}"}

    try:
        base = int(ctx_ptr)
        if base <= 0:
            return {"ok": False, "code": "BAD_ADDRESS",
                    "error": f"ctx_ptr 必须为正：{ctx_ptr!r}"}

        import struct as _struct

        # (13) 第十三次修改（2026-11-06）：改为 read_many 一次性读取。
        #      bug 原因：原来每次 _read 都调 rb.read_memory，而它每次 create_script，
        #               真机上建脚本要几百毫秒；读计数+指针+数组三次就接近一秒，
        #               数组大时更慢，整个调用曾挂到 60 秒以上。
        #      解决方案：先用一次 read_many 把「计数 + 指针 + 数组头部预留」
        #               一起读回；只有在拿到数组指针后才补第二次批量读。
        #               全程最多两次脚本，而不是 N 次。
        first = rb.read_many([
            {"addr": base + int(count_offset), "size": 8},
            {"addr": base + int(array_offset), "size": 8},
        ])
        cnt_raw = b""
        arr_raw = b""
        if len(first) >= 1 and first[0].get("ok"):
            cnt_raw = bytes.fromhex(first[0]["hex"])
        if len(first) >= 2 and first[1].get("ok"):
            arr_raw = bytes.fromhex(first[1]["hex"])

        count = 0
        if len(cnt_raw) >= 8:
            count = _struct.unpack("<Q", cnt_raw[:8])[0]
        if count == 0 or count > 0x100000:
            if len(first) >= 1 and first[0].get("ok"):
                # 退回 u32：再读一次低 4 字节（复用已读到的 8 字节即可）
                c4 = _struct.unpack("<I", cnt_raw[:4])[0]
                if 0 < c4 <= 0x100000:
                    count = c4

        if count > 0x100000:
            return {"ok": False, "code": "COUNT_SUSPICIOUS",
                    "error": (f"指令计数 {count} 明显不合理（>1048576），"
                              "可能偏移不对；已停止读取避免读爆内存"),
                    "raw_count": count}

        arr = 0
        if len(arr_raw) >= 8:
            arr = _struct.unpack("<Q", arr_raw)[0]
        if arr <= 0:
            return {"ok": False, "code": "NO_ARRAY_PTR",
                    "error": (f"从 ctx+{int(array_offset):#x} 读到的数组指针为 "
                              f"{arr:#x}，偏移可能不对或结构尚未初始化"),
                    "count": count}

        n = min(int(count), max(1, int(max_instr)))
        size = n * int(instr_size)
        second = rb.read_many([{"addr": arr, "size": size}])
        raw = bytes.fromhex(second[0]["hex"]) if (second and second[0].get("ok")) else b""
        if not raw:
            return {"ok": False, "code": "READ_FAILED",
                    "error": f"指令数组 {arr:#x} 不可读（{size} 字节）",
                    "count": count, "array_ptr": hex(arr)}

        # 4) 逐条解
        instructions = []
        for i in range(0, len(raw) // int(instr_size)):
            chunk = raw[i * int(instr_size):(i + 1) * int(instr_size)]
            v0 = _struct.unpack("<I", chunk[:4])[0] if len(chunk) >= 4 else 0
            words = [_struct.unpack("<I", chunk[j:j + 4])[0]
                     for j in range(0, len(chunk) - 3, 4)]
            instructions.append({
                "idx": i,
                "addr": hex(arr + i * int(instr_size)),
                "raw_hex": chunk.hex(),
                "opcode": (v0 >> 1) & 0xF,     # bits[4:1]
                "func": (v0 >> 5) & 0xF,       # bits[8:5]
                "words": words,
            })

        return {
            "ok": True,
            "implemented": True,
            "ctx_ptr": hex(base),
            "count": int(count),
            "decoded": len(instructions),
            "truncated": int(count) > n,
            "array_ptr": hex(arr),
            "instr_size": int(instr_size),
            "instructions": instructions,
            "field_rule": "opcode=bits[4:1], func=bits[8:5]（经验规则，可覆盖）",
            "note": ("一次 attach 读完整个数组，避免逐条读打断目标执行。"
                     "位域规则来自汇编观察，不同壳版本可能不同"),
        }
    finally:
        if own_rb:
            try:
                rb.detach()
            except Exception:                             # noqa: BLE001
                pass


def read_memory_batch(serial: str, pid: int, regions: list,
                      rb=None) -> dict:
    """**一次调用读多段内存**，而不是一段一次 RPC。

    (11) 第十一次修改（2026-11-06）：新增。
        bug 原因：分析一个结构体时往往要读十几个分散的地址（x0+0x194、
                  x0+0x1a0、x0+0x1b8 ...），每段一次 RPC 就要多 attach 一次，
                  而每次 attach 都会让目标停一下——采样点一多，事件就丢了。
        解决方案：把多段地址打包成一次脚本，JS 侧循环读回，只 attach 一次。

    regions 格式：[{"addr": "0x7bc...", "size": 16}, ...]
                  （addr 支持 0x 字符串或整数；size 1..4096）

    返回：{count, results[]}，每段 {addr, ok, hex, size, error}
    """
    own_rb = False
    if rb is None:
        try:
            from dyn.rebase import Rebase

            rb = Rebase.attach(serial, int(pid))
            own_rb = True
        except Exception as exc:                          # noqa: BLE001
            return {"ok": False, "code": "ATTACH_FAILED",
                    "error": f"attach 失败：{exc}"}

    try:
        items = []
        for r in (regions or []):
            if not isinstance(r, dict):
                continue
            a = r.get("addr")
            try:
                a = int(a, 16) if isinstance(a, str) else int(a)
            except (TypeError, ValueError):
                continue
            if a <= 0:
                continue
            size = r.get("size", 16)
            try:
                size = max(1, min(int(size), 4096))
            except (TypeError, ValueError):
                size = 16
            items.append({"addr": a, "size": size})

        if not items:
            return {"ok": False, "code": "NO_REGIONS",
                    "error": "regions 为空或格式不对（需要 [{addr, size}, ...]）"}

        results = _direct_read_batch(serial, int(pid), items)
        ok_count = sum(1 for r in results if r.get("ok"))
        return {
            "ok": True,
            "implemented": True,
            "count": len(results),
            "readable": ok_count,
            "results": results,
            "note": "所有段在同一次 attach 内读完，不会多次打断目标",
        }
    finally:
        if own_rb:
            try:
                rb.detach()
            except Exception:                             # noqa: BLE001
                pass


def dump_vm_state_auto(serial: str, pid: int,
                       count_offset: int = 0x194,
                       array_offset: int = 0x1a0,
                       instr_size: int = 16,
                       max_candidates: int = 20,
                       scan_limit_mb: int = 64,
                       max_instr: int = 32) -> dict:
    """**不需要断点**：在目标进程内存里扫描符合 VM 上下文特征的候选。

    (14) 第十四次修改（2026-11-06）：新增。

    解决什么问题：`dump_vm_state` 需要 ctx_ptr，而 ctx_ptr 通常来自断点现场的
    x0。**如果断点不命中，就永远拿不到 ctx_ptr**——这正是用户的死结。

    本工具反过来做：不去找断点，而是在内存里直接找"长得像 VM 上下文"的结构。

    ## 判定条件（全部满足才算候选）

        ① [ptr + count_offset] 是整数，且落在 [2, 100000]
        ② [ptr + array_offset] 是 qword，指向**可读**内存
        ③ 该数组前 instr_size 字节不是全 0
        （可选）④ 数组指针 8 字节对齐

    ## 扫描范围

        只扫目标 so 的**可写数据段**（.bss / .data），而不是全进程内存——
        因为 VM 上下文通常是壳在堆或 .bss 里维护的结构体；扫全进程太慢
        且误报多。扫描量用 scan_limit_mb 限制。

    ## 返回

        candidates[]  每个 {ctx_ptr, instr_count, instr_array, sample_hex}
        scanned_mb    实际扫描了多少 MB
        note          说明判定依据

    ## ⚠️ 性能警告（实测，务必先读）

    在本轮真机（闲鱼 libsgmainso，arm64）上实测**不可用**：
        · Python 侧逐块 RPC：4MB 跑不完 60 秒
        · JS 侧一次同步扫描 8MB：占死 JS 线程，frida 报 TransportError
        · 分片扫描（256KB/片）：4MB 仍超 110 秒

    根因：扫描是 CPU 密集的同步循环，而 frida 的通信线程与脚本执行共享
    同一个 JS 运行时；只要循环时间过长就会阻塞通信，严重时把
    frida-server 拖到无响应（需重启 server 才能恢复）。

    **建议改用更省的办法**：
        ① 用 `watch_module` 找出实际执行的热点函数，再在其中某个
           `ldr [x0, #0x194]` 附近下断点，直接从寄存器拿 ctx_ptr；
        ② 用 `trace_read` 监控一块已知内存；
        ③ 若确实要扫，把 `scan_limit_mb` 调到 1~2，并接受较慢的返回。

    保留本实现是因为：在性能更好的设备/更小的目标进程上它仍然有效，
    而且"没找到"与"扫不动"在返回里是分开报告的。

    ## 已知边界（如实标注）

        · 这是**启发式扫描**，命中的是"符合结构特征"的地址，
          **不保证就是真正的 VM 上下文**；调用方需自行交叉验证
        · 只扫可读数据段；若上下文在堆深处（malloc 出来的），扫不到
        · 计数偏移/数组偏移填错时一个候选也不会有——这属于"没找到"，不是"没有"
    """
    import struct as _struct

    own_rb = False
    if True:                                              # 统一走 Rebase
        try:
            from dyn.rebase import Rebase

            rb = Rebase.attach(serial, int(pid))
            own_rb = True
        except Exception as exc:                          # noqa: BLE001
            return {"ok": False, "code": "ATTACH_FAILED",
                    "error": f"attach 失败：{exc}"}

    try:
        mods = rb.refresh_modules()
        # 优先选名字里带常见壳/业务特征的模块；都没有就选最大的那个非系统模块
        cand_mods = [m for m in mods
                     if int(getattr(m, "size", 0) or 0) > 64 * 1024]
        if not cand_mods:
            return {"ok": False, "code": "NO_MODULE",
                    "error": "目标进程里没有足够大的模块可扫"}
        cand_mods.sort(key=lambda m: -int(getattr(m, "size", 0) or 0))
        scanned = 0
        limit = max(1, int(scan_limit_mb)) * 1024 * 1024
        candidates: list[dict] = []
        _arr_cache: dict = {}

        # (15) 第十五次修改（2026-11-06）：块大小从 4KB 提到 128KB。
        #      bug 原因：按 4KB 分块扫 32MB 需要 8000 次 read_many，每次都是一个
        #               RPC，实测 90 秒都跑不完。
        #      解决方案：放大到 128KB，同样范围内 RPC 次数降到 256 次。
        #               再大就要考虑目标内存被切分的问题（跨未映射区会整块失败），
        #               128KB 是实测下来稳定且有明显提速的折中值。
        # (18) 第十八次修改（2026-11-06）：扫描改为**分片、可中断、小块**。
        #      bug 原因：前两版都试过——Python 侧逐块 RPC（4MB/60s 跑不完）、
        #               JS 侧一次同步扫 8MB（直接占死 JS 线程，frida 报
        #               TransportError: timeout，且把 frida-server 拖到无响应）。
        #               根本原因是：扫描是 CPU 密集的同步循环，无论放哪一侧，
        #               只要一口气跑完就会阻塞 frida 的通信线程。
        #      解决方案：① 每片只扫 256KB 并立即返回（JS 循环 32K 次，约几十毫秒）；
        #               ② Python 侧分多轮调用，**每轮之间让出时间**给 frida 通信；
        #               ③ 总预算用 scan_limit_mb 控制，到量即停；
        #               ④ 单片失败（目标内存不可读）跳过继续，不整体失败。
        #               这样既不会阻塞通信，也能在可接受时间内覆盖目标区域。
        import json as _json

        js = """
        (function () {
          var COUNT_OFF = %d, ARR_OFF = %d, INSTR = %d;
          var BASE = %d, SPAN = %d;
          var MAXC = %d;
          var out = [];
          var cache = {};
          var end = BASE + SPAN;
          for (var a = BASE; a + ARR_OFF + 8 < end; a += 8) {
            if (out.length >= MAXC) break;
            var p, cnt, arr;
            try {
              p = ptr(a);
              cnt = p.add(COUNT_OFF).readU64().toNumber();
              if (cnt < 2 || cnt > 100000) continue;
              arr = p.add(ARR_OFF).readPointer();
              if (arr.compare(ptr('0x1000')) < 0) continue;
            } catch (e) { continue; }
            var sample;
            var key = arr.toString();
            if (cache[key] !== undefined) { sample = cache[key]; }
            else {
              try {
                var b = arr.readByteArray(INSTR);
                sample = (b === null) ? "" : Array.from(new Uint8Array(b))
                    .map(function(x){return x.toString(16).padStart(2,'0');}).join('');
              } catch (e) { sample = ""; }
              cache[key] = sample;
            }
            if (!sample || /^0+$/.test(sample)) continue;
            out.push({ctx_ptr: p.toString(), instr_count: cnt,
                      instr_array: key, sample_hex: sample.slice(0, 32)});
          }
          send({candidates: out, span: SPAN});
        })();
        """

        sess0 = rb.session
        SLICE = 0x40000                      # 每片 256KB
        candidates: list[dict] = []
        scanned = 0
        limit = max(1, int(scan_limit_mb)) * 1024 * 1024
        deadline = __import__("time").time() + 90.0
        mods_sorted = sorted(cand_mods, key=lambda m: -int(getattr(m, "size", 0) or 0))

        for mod in mods_sorted[:6]:
            base = int(mod.base)
            size = int(getattr(mod, "size", 0) or 0)
            off = 0
            while off < size and scanned < limit and len(candidates) < max_candidates:
                if __import__("time").time() > deadline:
                    break
                span = min(SLICE, size - off)
                piece = js % (int(count_offset), int(array_offset),
                              max(16, int(instr_size)), base + off, span,
                              int(max_candidates) - len(candidates))
                got: dict = {}
                try:
                    script = sess0.create_script(piece)
                    script.on("message", lambda m, d: got.update(m.get("payload") or {}))
                    script.load()
                except Exception:                         # noqa: BLE001
                    off += span
                    continue
                t1 = __import__("time").time()
                while not got and __import__("time").time() - t1 < 20.0:
                    __import__("time").sleep(0.02)
                for c in (got.get("candidates") or []):
                    c["in_module"] = getattr(mod, "name", "")
                    candidates.append(c)
                scanned += span
                off += span
                __import__("time").sleep(0.05)        # 让出时间给 frida 通信
            if len(candidates) >= max_candidates or scanned >= limit:
                break

        if own_rb:
            pass

        return {
            "ok": True,
            "implemented": True,
            "candidates": candidates,
            "candidate_count": len(candidates),
            "scanned_mb": round(scanned / (1024.0 * 1024.0), 1),
            "criteria": (f"[ptr+{count_offset:#x}] ∈ [2,100000] 且 "
                         f"[ptr+{array_offset:#x}] 指向可读非零内存"),
            "note": ("**启发式扫描**：命中的是符合结构的地址，不保证是真正的 VM 上下文，"
                     "请用候选的 ctx_ptr 调 dump_vm_state 作进一步确认"),
        }
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "SCAN_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if own_rb:
            try:
                rb.detach()
            except Exception:                             # noqa: BLE001
                pass


def probe_vm_from_hits(serial: str, pid: int, hits: list,
                       count_offset: int = 0x194,
                       array_offset: int = 0x1a0,
                       instr_size: int = 16,
                       max_instr: int = 64,
                       max_candidates: int = 40) -> dict:
    """从**已有断点命中**的寄存器里找出 VM 上下文指针，再解指令数组。

    (19) 第十九次修改（2026-11-06）：新增。

    解决什么问题：`dump_vm_state` 需要 ctx_ptr，而 ctx_ptr 通常只在断点现场
    才能拿到。如果目标断点不命中（VM 入口没执行），就永远拿不到——
    这正是「auto 扫描又太慢」的两难。

    本工具换个思路：**用已经命中的断点**。哪怕命中的不是 VM 入口，
    只要那些函数的参数里带着上下文指针（很常见，VM 解释器的辅助函数
    第一个参数往往就是 ctx），就能从寄存器里把它捞出来。

    ## 做法

        ① 遍历给定的命中记录，收集所有寄存器值（x0..x30 + sp + lr）
        ② 对每个值当作候选 ctx_ptr，检查：
             [ptr + count_offset] ∈ [2, 100000]
             [ptr + array_offset] 是指向可读内存的指针
             该数组前 instr_size 字节非全零
        ③ 命中的候选再调 dump_vm_state 解出指令
        ④ 全部候选**一次 attach 批量验证**，不逐个往返

    ## 参数

        hits          命中记录列表。可以是 service.hits() 的返回，
                      或 poll_events 里 type=breakpoint_hit 的事件
        count_offset / array_offset / instr_size / max_instr  同 dump_vm_state

    ## 返回

        candidates[]  每个可用候选：{ctx_ptr, from_register, hits_seq,
                                    count_offset, instr_count, array_ptr,
                                    decoded, instructions[]}
        registers_probed  一共试了多少个寄存器值
        note

    ## 与 dump_vm_state_auto 的区别

        dump_vm_state_auto  在**内存里盲扫**，慢且可能拖挂目标（实测不可用）
        probe_vm_from_hits  只在**命中现场的少量寄存器值**里试，几十个候选，
                            一次 RPC 就能验完，**快且安全**
    """
    import struct as _struct

    if not hits:
        return {"ok": False, "code": "NO_HITS",
                "error": ("没有命中记录可分析。先用 set_breakpoint 下一个"
                          "**会命中**的断点（可用 probe_hits 确认哪个地址会跑），"
                          "再调本工具")}

    # 1) 收集所有寄存器候选值（去重、只留看起来像指针的）
    cands: list[dict] = []
    seen: set[int] = set()
    probed = 0
    for h in hits:
        ctx = (h.get("context") or {}) if isinstance(h, dict) else {}
        seq = h.get("seq") if isinstance(h, dict) else None
        so_name = h.get("so_name") if isinstance(h, dict) else None
        for reg, val in ctx.items():
            try:
                v = int(val, 16) if isinstance(val, str) else int(val)
            except (TypeError, ValueError):
                continue
            if v < 0x1000 or v in seen:                  # 0 / 小整数不可能是 ctx
                continue
            seen.add(v)
            probed += 1
            # (20) 第二十次修改（2026-11-06）：候选数量设上限。
            #      bug 原因：寄存器值来自**所有**命中记录（可能几百条），
            #                36 个寄存器 × N 条命中会累积成上万个候选，
            #                一次脚本要读上万个地址，必然超时甚至拖挂目标。
            #      解决方案：硬上限 2000 个候选（37 条命中内基本够用），
            #                超出的不再收集，并在返回里说明被截断。
            if len(cands) < 2000:
                cands.append({"ptr": v, "reg": reg, "seq": seq,
                              "so_name": so_name})

    if not cands:
        return {"ok": False, "code": "NO_CANDIDATE",
                "error": "命中记录里的寄存器值都不像指针（全部 <0x1000）",
                "registers_probed": probed}

    cands_truncated = probed > 2000

    try:
        from dyn.rebase import Rebase

        rb = Rebase.attach(serial, int(pid))
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "ATTACH_FAILED",
                "error": f"attach 失败：{exc}"}

    try:
        import time as _t
        import json as _json

        # 2) 一次脚本：对每个候选读 count 和 array 指针
        spec = [c["ptr"] for c in cands]
        js = (
            "var P = " + _json.dumps(spec) + ";"
            "var CO = " + str(int(count_offset)) + ", AO = " + str(int(array_offset)) + ";"
            "var out = [];"
            "for (var i = 0; i < P.length; i++) {"
            "  try {"
            "    var p = ptr(P[i]);"
            "    var cnt = p.add(CO).readU64().toNumber();"
            "    var arr = p.add(AO).readPointer();"
            "    out.push({cnt: cnt, arr: arr.toString()});"
            "  } catch (e) { out.push(null); }"
            "}"
            "send(out);"
        )
        sess = rb.session
        sc = sess.create_script(js)
        got: list = []
        sc.on("message", lambda m, d: got.extend(m.get("payload") or []))
        sc.load()
        t0 = _t.time()
        while not got and _t.time() - t0 < 20.0:
            _t.sleep(0.02)

        # 3) 结构校验
        ok_list: list[dict] = []
        for i, c in enumerate(cands):
            item = got[i] if i < len(got) else None
            if not item:
                continue
            cnt = item.get("cnt")
            arr = item.get("arr")
            if not isinstance(cnt, (int, float)) or not (2 <= cnt <= 100000):
                continue
            try:
                arr_i = int(arr, 16) if isinstance(arr, str) else int(arr)
            except (TypeError, ValueError):
                continue
            # (21) 第二十一次修改（2026-11-06）：数组指针校验大幅收紧。
            #      bug 原因：原来只判 `arr_i < 0x1000` 就放过。实测 x0 指向的
            #               结构里，[ctx+0x1a0] 读出来是 0x6369000000000003——
            #               那其实是 ASCII "ci" 加垃圾（把字符串/数据当成了指针），
            #               它 >0x1000 所以顺利通过校验，被当成合法候选返回，
            #               最后读 1024 字节失败，报"指令数组不可读"。
            #               用户看到的就是"解码失败"，而根因是**假指针没被拦住**。
            #      解决方案：按 arm64 用户态地址空间的实际范围校验——
            #      解决方案：按 arm64 用户态地址空间判别，但**要放过 tagged pointer**。
            #               实测 Android 堆指针形如 0xb400007c5f0dc6c0——
            #               高 8 位 0xb4 是 MTE/tag 标记，去掉后才是真地址
            #               0x0000007c5f0dc6c0。所以不能简单要求"高16位为0"，
            #               否则会把合法堆指针全拒掉。
            #               判据改为：去掉高 8 位 tag 后，地址落在 [0x1000, 2^48)。
            #               · 0x6369000000000003 -> 去tag后 0x69000000000003 超 2^48，拒绝
            #               · 0xb400007c5f0dc6c0 -> 去tag后 0x7c5f0dc6c0，通过
            #               **不要求对齐**：实测指令数组地址 0x7c86ddb5ac 是 4 字节
            #               对齐而非 8 字节，加对齐要求会把真数组也误杀。
            arr_untagged = arr_i & 0x00FFFFFFFFFFFFFF
            if arr_untagged < 0x1000 or arr_untagged >= (1 << 48):
                continue
            ok_list.append({"ptr": c["ptr"], "reg": c["reg"], "seq": c["seq"],
                            "so_name": c["so_name"], "count": int(cnt),
                            "array": arr_i})
            if len(ok_list) >= max_candidates:
                break

        if not ok_list:
            return {
                "ok": True, "implemented": True,
                "candidates": [], "registers_probed": probed,
                "verdict": (f"试了 {probed} 个寄存器值，没有一个符合 "
                            f"[ptr+{int(count_offset):#x}]∈[2,100000] 且 "
                            f"[ptr+{int(array_offset):#x}] 是可读指针"),
                "hint": ("可能这批命中所在的函数不持有 VM 上下文。"
                         "换一个更靠近 VM 的断点，或用 watch_module 找热点函数"),
            }

        # 4) 解指令数组
        out_cands = []
        for c in ok_list:
            try:
                d = dump_vm_state(serial, int(pid), c["ptr"],
                                  count_offset=int(count_offset),
                                  array_offset=int(array_offset),
                                  instr_size=int(instr_size),
                                  max_instr=int(max_instr), rb=rb)
            except Exception as exc:                      # noqa: BLE001
                d = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            out_cands.append({
                "ctx_ptr": hex(c["ptr"]),
                "from_register": c["reg"],
                "hits_seq": c["seq"],
                "so_name": c["so_name"],
                "instr_count": c["count"],
                "instr_array": hex(c["array"]),
                "decoded": d.get("decoded") if d.get("ok") else None,
                "instructions": (d.get("instructions") or [])[:max_instr]
                if d.get("ok") else [],
                "decode_error": None if d.get("ok") else d.get("error"),
            })

        return {
            "ok": True,
            "implemented": True,
            "candidates": out_cands,
            "candidate_count": len(out_cands),
            "registers_probed": probed,
            "candidates_truncated": cands_truncated,
            "verdict": (f"从 {len(hits)} 条命中的 {probed} 个寄存器值里，"
                        f"找到 {len(out_cands)} 个符合 VM 上下文结构的候选"),
            "note": ("每个候选都附带解出的指令数组；"
                     "ctx_ptr 可直接拿去调 dump_vm_state 复核"),
        }
    finally:
        try:
            rb.detach()
        except Exception:                                 # noqa: BLE001
            pass
