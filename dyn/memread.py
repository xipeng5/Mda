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
