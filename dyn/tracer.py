"""trace（执行轨迹）能力的数据层与逻辑层。

## 边界：什么留空了、什么做实了

真机 trace 采集依赖 frida：

- 指令级：``Stalker.follow`` + 编译期回调
- 内存读写：``Thread.setHardwareWatchpoint``（frida 17.x 才有）
- 模块加载：``Process.attachModuleObserver``（frida 16.7+ 才有）

以上按用户要求**本轮留空**，统一从 ``dyn.pending`` 返回占位结构
（``implemented: false`` + ``code: NEEDS_FRIDA:*``），**绝不假造采集结果**——
宁可明确报错，也不返回 ``[]`` / 全 0 让下游误以为"确实没有事件"。

但 trace 真正难的不是"采"，是"看"：

- 指令级 trace 动辄上千万行，直接倒给人只会让人迷失；
- trace 里的地址是**运行时地址**（ASLR 后），离开模块基址无法解释；
- mda 有静态模型（``SoFile.function_at``），能把运行时地址折回静态函数——
  这是 unidbg 一类纯模拟器做不到的（它没有静态层）。

因此本模块把"采"留空，把"采到之后怎么用"做实：
``TraceEvent`` / ``TraceBuffer`` / ``aggregate_by_function`` / ``summarize``。
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from dyn.pending import NotImplementedYet

__all__ = [
    "KIND_CODE",
    "KIND_READ",
    "KIND_WRITE",
    "KIND_MODULE_LOAD",
    "KINDS",
    "TraceEvent",
    "TraceBuffer",
    "aggregate_by_function",
    "summarize",
    "start_trace_code",
    "start_trace_read",
    "start_trace_write",
    "start_trace_module_load",
]

# ---------- 事件类型 ----------
# 只用这四种：够表达"执行到哪"与"访问了哪"，多了前端与 AI 都要多记一套。
KIND_CODE = "code"                # 执行到某条指令
KIND_READ = "read"                # 读取了某段内存
KIND_WRITE = "write"              # 写入了某段内存
KIND_MODULE_LOAD = "module_load"  # 动态加载了一个 so
KINDS: tuple[str, ...] = (KIND_CODE, KIND_READ, KIND_WRITE, KIND_MODULE_LOAD)

_DEFAULT_CAPACITY = 10000  # 环形缓冲默认容量
_GAP_LABEL = "<gap>"       # 落在函数空洞（不属于任何已知函数）时的显示名
_UNRESOLVED_LABEL = "<unresolved>"  # 地址不属于任何已加载 so 时的显示名
_MAX_TOP = 50              # summarize 的 Top N 上限


# ==================== 事件结构 ====================


def _to_int(value, default: int = 0) -> int:
    """把地址/尺寸统一成 int。

    (9) 第九次修改（2026-11-05）：规则收口到 core.addr（原实现与其它三处不一致：
        含 a-f 无 0x 前缀的地址会被当作十进制解析失败，静默落回 default）。
    """
    from core.addr import parse_int

    return parse_int(value, default)

@dataclass
class TraceEvent:
    """一条 trace 事件。

    字段刻意做成"宽事件"（kind + 通用字段），而不是每种 kind 一个类：
    trace 数据量很大，统一结构才能共用环形缓冲、统一排序与序列化。

    - seq       事件序号（由 TraceBuffer 统一分配，单调递增）
    - ts        采集时刻（time.time() 秒）
    - kind      code / read / write / module_load
    - thread_id 线程号（0 表示未知）
    - addr      对于 code 是**运行时指令地址**；对于 read/write 是**被访问的
                内存地址**；对于 module_load 是模块加载基址
    - size      该事件涉及的字节数（写访问的宽度 / 模块镜像大小；code 为指令宽度）
    - extra     各 kind 的附加信息（模块名、寄存器快照、命中原因等），不裁剪

    注意 addr 是**运行时地址**：要折回静态函数必须经过 aggregate_by_function，
    它负责用模块基址做换算。
    """

    seq: int = 0
    ts: float = field(default_factory=time.time)
    kind: str = KIND_CODE
    thread_id: int = 0
    addr: int = 0
    size: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """序列化成可直接 JSON 化的 dict（地址保持 int，交给上层决定显示格式）。"""
        return {
            "seq": int(self.seq),
            "ts": float(self.ts),
            "kind": self.kind,
            "thread_id": int(self.thread_id),
            "addr": int(self.addr),
            "size": int(self.size),
            "extra": dict(self.extra or {}),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "TraceEvent":
        """从 dict 还原（MCP 层把事件以 JSON 传回时可复用同一套聚合逻辑）。"""
        if not isinstance(raw, dict):
            raise TypeError(f"TraceEvent.from_dict 需要 dict，实际是 {type(raw).__name__}")
        ts = float(raw.get("ts") or 0.0)
        # addr 缺失时退回 runtime_addr：断点命中记录（dyn.service.poll_events）
        # 就是"执行到某个运行时地址"，本质上等价于一条 kind=code 事件。
        # 但这种记录**不自带 kind**，若它的 addr 来自 runtime_addr，
        # 调用方必须同时给 runtime_bases，否则会被当成静态地址解析。
        addr = raw.get("addr")
        if addr is None:
            addr = raw.get("runtime_addr")
        return cls(
            seq=_to_int(raw.get("seq")),
            ts=ts if ts > 0 else time.time(),
            kind=str(raw.get("kind") or KIND_CODE),
            thread_id=_to_int(raw.get("thread_id")),
            addr=_to_int(addr),
            size=_to_int(raw.get("size")),
            extra=dict(raw.get("extra") or {}),
        )


def _events_as_list(events) -> list[TraceEvent]:
    """把任意可迭代的事件源统一成 TraceEvent 列表。

    聚合与摘要都要遍历两遍，所以先落地成列表；遇到不认识的类型直接抛错，
    不做"跳过未知元素"的静默容错——**静默丢事件正是 trace 最危险的 bug**。
    """
    out: list[TraceEvent] = []
    for item in events or ():
        if isinstance(item, TraceEvent):
            out.append(item)
        elif isinstance(item, dict):
            out.append(TraceEvent.from_dict(item))
        else:
            raise TypeError(
                f"事件元素必须是 TraceEvent 或 dict，实际是 {type(item).__name__}"
            )
    return out


# ==================== 环形缓冲 ====================


class TraceBuffer:
    """有界环形缓冲：trace 事件量的天然上限防线。

    为什么必须有界：Stalker 每秒能吐几十万条，无界队列会先把内存吃光再让
    整个进程失联。挤掉最旧的一条是必要之恶，但**丢了多少必须记账**
    （``dropped`` / ``stats()``），否则调用方会把"缓冲转了一圈"误读成
    "这段时间没有事件"。

    线程安全：采集线程 append、AI/前端线程 poll，必须加锁。
    """

    def __init__(self, capacity: int = _DEFAULT_CAPACITY):
        capacity = _to_int(capacity, _DEFAULT_CAPACITY)
        if capacity <= 0:
            raise ValueError("capacity 必须是正整数")
        self._capacity = capacity
        self._items: deque[TraceEvent] = deque(maxlen=capacity)  # maxlen 自动挤掉最旧
        self._lock = threading.Lock()
        self._seq = 0            # 已分配的最大 seq
        self._total = 0          # 累计入队条数（含已被挤掉的）
        self._dropped = 0        # 因容量满而被挤掉的条数
        self._poll_cursor = 0    # poll(after_seq=None) 的默认起点

    # ---------- 只读状态 ----------

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def count(self) -> int:
        """当前缓冲里还有多少条。"""
        with self._lock:
            return len(self._items)

    @property
    def dropped(self) -> int:
        """累计被挤掉的条数（>0 说明有数据没保留下来）。"""
        with self._lock:
            return self._dropped

    @property
    def total(self) -> int:
        """累计入队条数。"""
        with self._lock:
            return self._total

    # ---------- 写入 ----------

    def append(self, event: TraceEvent | dict) -> int:
        """入队一条事件，返回它被分配的 seq。

        满了自动挤掉最旧一条并把 ``dropped`` +1——**计数是唯一让调用方
        知道"有数据丢了"的途径**，不允许静默丢。

        seq 由本缓冲统一分配（覆盖事件自带的 seq）：环形缓冲是 seq 的唯一
        权威，否则外部传入的乱序/重复 seq 会破坏 poll 的增量语义。
        """
        ev = event if isinstance(event, TraceEvent) else TraceEvent.from_dict(event)
        with self._lock:
            if len(self._items) == self._capacity:
                self._dropped += 1
            self._seq += 1
            ev.seq = self._seq
            if not ev.ts:
                ev.ts = time.time()
            self._items.append(ev)
            self._total += 1
            return self._seq

    # ---------- 读取 ----------

    def poll(
        self,
        after_seq: int | None = None,
        limit: int = 200,
        kind: str | tuple | list | None = None,
    ) -> list[TraceEvent]:
        """按 seq 增量取事件（返回按 seq 升序的列表）。

        after_seq 三档语义（与 ``DynamicService.poll_events`` 保持一致）：
            None → 从游标继续，只给"没取过的新事件"；
            0    → 显式从头重放（排查现场用）；
            N    → 只要 seq > N。

        kind 可为单个类型或类型集合，None 表示不过滤。

        游标只增不减：显式 replay 不会把游标往回拨，避免"重放一次之后
        增量游标失效"。

        返回的是缓冲内的事件对象引用，**调用方不要原地修改**；
        要序列化请用 ``event.to_dict()``。
        """
        floor = self._poll_cursor if after_seq is None else max(_to_int(after_seq), 0)
        limit = _to_int(limit, 200)
        if limit <= 0:
            raise ValueError("limit 必须是正整数")
        kinds = _kind_set(kind)
        # (4) 第四次修改（2026-11-05）：只有"取全部且未指定游标"时才推进共享游标。
        #     bug 原因：原实现无论是否传 after_seq、无论有没有 kind 过滤，只要取到
        #               结果就把 _poll_cursor 推到最大 seq。于是——
        #               · 带 kind 过滤取走 read 事件时，被过滤掉的 code 事件
        #                 位置也被跳过了，下次按游标取就**永久丢失**；
        #               · 显式传 after_seq 做"重放/回看"时，也会污染共享游标，
        #                 影响其他按默认游标取事件的调用方。
        #               这与 service._collect 第五次修改的正确做法相反。
        #     解决方案：advance = (after_seq is None and kinds is None)，
        #               只有"完整的顺序消费"才推进游标；其余一律只读不推进。
        advance = (after_seq is None and kinds is None)
        with self._lock:
            # deque 内的插入顺序就是 seq 升序，无需再排序
            picked = [
                ev for ev in self._items
                if ev.seq > floor and (kinds is None or ev.kind in kinds)
            ][:limit]
            if advance and picked:
                self._poll_cursor = max(self._poll_cursor, picked[-1].seq)
            return picked

    def stats(self) -> dict:
        """缓冲统计：总条数、丢弃数、最早/最晚 seq。

        字段含义：
          count      当前缓冲条数
          capacity   容量上限
          total      累计入队条数（含已被挤掉的）
          dropped    被挤掉的条数（>0 表示有事件没保留）
          first_seq  当前缓冲里最早事件的 seq（空缓冲为 0）
          last_seq   最新事件的 seq（空缓冲为 0）
          next_seq   下一条将被分配的 seq
          poll_cursor poll(after_seq=None) 的当前游标
        """
        with self._lock:
            first = self._items[0].seq if self._items else 0
            last = self._items[-1].seq if self._items else 0
            return {
                "count": len(self._items),
                "capacity": self._capacity,
                "total": self._total,
                "dropped": self._dropped,
                "first_seq": first,
                "last_seq": last,
                "next_seq": self._seq + 1,
                "poll_cursor": self._poll_cursor,
            }


def _kind_set(kind) -> set[str] | None:
    """把 kind 参数统一成集合；None 表示不过滤。"""
    if kind is None:
        return None
    if isinstance(kind, str):
        return {kind}
    return {str(k) for k in kind}


# ==================== 运行时地址 -> 静态函数 ====================


def _exec_spans(so) -> list[tuple[int, int]]:
    """取 so 的可执行区间列表（跳过无 exec_regions 的假实现对象）。"""
    try:
        spans = so.exec_regions()
    except Exception:  # noqa: BLE001 - 假 so / 特殊模型不该让聚合整体失败
        return []
    out = []
    for item in spans or ():
        try:
            start, end = int(item[0]), int(item[1])
        except (IndexError, TypeError, ValueError):
            continue
        if start < end:
            out.append((start, end))
    return out


def _image_ranges(so) -> list[tuple[int, int]]:
    """取 so 的镜像映射区间（含数据段），用于判断"地址是否属于本模块"。

    优先 ``so.maps()``（section + PT_LOAD 合并视图，壳样本也能给全）；
    拿不到就退回可执行段——**但没有映射信息时绝不能返回"整块地址空间"**，
    那样任何野地址都会被算成"模块内的空洞"，把 module_unresolved 吞成
    function_gap（自测里就抓到过这个错判）。
    """
    try:
        maps = so.maps()
    except Exception:  # noqa: BLE001 - 假 so / 特殊模型
        maps = None
    out: list[tuple[int, int]] = []
    for item in maps or ():
        try:
            start, end = int(item["addr"]), int(item["end"])
        except (KeyError, TypeError, ValueError):
            continue
        if start < end:
            out.append((start, end))
    if not out:
        # 退化：只有代码段信息时，模块边界收紧到代码段
        out = _exec_spans(so)
    return sorted(out)


def _span_has(spans: list[tuple[int, int]], addr: int) -> bool:
    """addr 是否落在任一 [start, end) 内（区间不多，线性足够）。"""
    return any(start <= addr < end for start, end in spans)


class _ModuleResolver:
    """事件地址 -> (so 名, 静态地址, 所属函数)。

    两条解析路径，按证据强弱选择：

    1. **运行时模式**（有模块基址表，真机 trace 的正常情形）
       base <= addr < base+size → static = addr - base。这是唯一无歧义的路径，
       上层应通过 ``runtime_bases`` 或 ``session.runtime_modules`` 提供基址。

    2. **静态模式**（离线/事后分析，没有基址表）
       直接认为 addr 就是静态地址。但 ET_DYN 的 so 静态地址全都从 0 起，
       多个 so 的区间必然重叠——所以**多个候选无法唯一判定时返回未解析**，
       不猜。只有一个 so 时无歧义，可用于离线验证与单 so 样本分析。

    所有未命中都不静默丢弃：调用方会把它们归进 in_gap / unresolved 桶。
    """

    def __init__(self, session, runtime_bases=None):
        self.session = session
        self.modules = dict(getattr(session, "modules", {}) or {})
        # 别名表：运行时模块名（通常是 basename）-> session.modules 的键
        # 同名 so 出现多个不同基址的键（归因有歧义，不静默采用其中一个）
        self.ambiguous: set[str] = set()
        self._alias: dict[str, str] = {}
        for key, so in self.modules.items():
            self._alias.setdefault(key, key)
            name = getattr(so, "name", "") or ""
            if name:
                self._alias.setdefault(name, key)
            path = getattr(so, "path", "") or ""
            base_name = path.rsplit("/", 1)[-1]
            if base_name:
                self._alias.setdefault(base_name, key)
        self._spans: dict[str, list[tuple[int, int]]] = {
            key: _exec_spans(so) for key, so in self.modules.items()
        }
        # 静态模式下"地址是否属于本模块"的判据：整份镜像映射（含数据段），
        # 不是只看可执行段——否则模块内数据地址会被误判成"模块外"。
        self._images: dict[str, list[tuple[int, int]]] = {
            key: _image_ranges(so) for key, so in self.modules.items()
        }
        self.bases = self._normalize_bases(runtime_bases)
        # 同一地址在循环里会重复出现几百万次，函数归属的 memo 是聚合能跑动的前提
        self._memo: dict[int, tuple[str, int, int, str, bool, str]] = {}

    # ---------- 基址表 ----------

    def _static_span(self, key: str) -> int:
        """该 so 静态地址的上界（基址表只给了 base、没给 size 时兜底）。"""
        spans = self._spans.get(key) or []
        return max((end for _s, end in spans), default=0)

    def _normalize_bases(self, runtime_bases) -> dict[str, tuple[int, int]]:
        """把各种形态的模块基址表统一成 {so 键: (base, size)}。

        支持：``{名: base}``、``{名: {"base","size"}}``、对象列表
        （带 .name/.base/.size，即 ``dyn.rebase.RuntimeModule``）、dict 列表；
        以及 ``session.runtime_modules``（属性或方法）作为兜底来源。
        """
        raw = runtime_bases
        if raw is None:
            attr = getattr(self.session, "runtime_modules", None)
            if callable(attr):
                try:
                    raw = attr()
                except Exception:  # noqa: BLE001 - 拿不到基址就退回静态模式
                    raw = None
            elif attr is not None:
                raw = attr
        table: dict[str, tuple[int, int]] = {}
        # (5) 第五次修改（2026-11-05）：同名 so 出现多个基址时**不许静默覆盖**。
        #     bug 原因：`table[key] = (base, size)` 是后写覆盖。同一个 so 被 dlopen
        #               两次（或 app 自带一份 + 系统一份）时，两个实例的基址只剩最后
        #               一个，于是 A 实例的执行为被换算到 B 实例的地址上，
        #               记到错误的函数里，而且**没有任何诊断**。
        #     解决方案：记下发生冲突的 key（不同 base 视为冲突）；冲突的模块
        #               不参与精确归属，改标 module_ambiguous，让调用方知道
        #               "这个名字有歧义，别信这层归因"。
        for name, base, size in _iter_module_bases(raw):
            key = self._alias.get(name, name)
            if key not in self.modules:
                # 未在 session 里加载的模块：基址仍可用于"地址属于该模块"的判定
                key = name
            if not size:
                size = self._static_span(key)
            prev = table.get(key)
            if prev is not None and prev[0] != int(base):
                self.ambiguous.add(key)
            table[key] = (int(base), int(size))
        return table

    # ---------- 解析 ----------

    def resolve(self, addr: int) -> tuple[str, int, int, str, bool, str]:
        """返回 ``(so 名, 静态地址, 函数起点, 函数名, 是否空洞, 空洞原因)``。

        so 名为空表示地址不属于任何已知模块（unresolved）。
        """
        hit = self._memo.get(addr)
        if hit is not None:
            return hit
        result = self._resolve_uncached(addr)
        self._memo[addr] = result
        return result

    def _resolve_uncached(self, addr: int):
        key, static = self._locate(addr)
        if not key:
            return ("", 0, 0, _UNRESOLVED_LABEL, True, "module_unresolved")
        # (5) 第五次修改（2026-11-05）：同名多实例的模块，归因不可靠，明确标出来。
        #     不做静默归属：保留 so 名与静态地址（仍有参考价值），但把结果标成
        #     "空洞 + module_ambiguous"，调用方据此可以决定不信这一层。
        if key in self.ambiguous:
            return (key, static, 0, _GAP_LABEL, True, "module_ambiguous")
        so = self.modules.get(key)
        fn = None
        if so is not None:
            try:
                fn = so.function_at(static)
            except Exception:  # noqa: BLE001 - 坏样本不该让整批聚合失败
                fn = None
        if fn is None:
            # so 已确定但该地址不属于任何函数（FDE 空洞 / PLT 桩 / 未发现区域）
            return (key, static, 0, _GAP_LABEL, True, "function_gap")
        name = getattr(fn, "name", "") or f"sub_{int(fn.addr):x}"
        return (key, static, int(fn.addr), name, False, "")

    def _locate(self, addr: int) -> tuple[str, int]:
        """定位 addr 所属模块，返回 (so 键, 静态地址)；找不到返回 ("", 0)。

        (1) 第一次修改（自测发现）
            bug 原因：静态模式下只有 1 个 so 时，初版直接 ``return (该 so, addr)``，
                      于是"根本不属于任何模块"的野地址（如 0x7adeadbeef）也被
                      归进这个 so，最终算成 function_gap。语义上它应该是
                      module_unresolved——两者一个是"so 内空洞"、一个是
                      "压根不在已知模块里"，混在一起会误导排查方向。
            解决方案：即使只有 1 个 so，也要求地址落在该模块的镜像映射内；
                      不在映射内就是未解析，如实报 module_unresolved。
        """
        addr = int(addr)
        if self.bases:
            for key, (base, size) in self.bases.items():
                if base <= addr < base + size:
                    return (key, addr - base)
            return ("", 0)
        # 静态模式：ET_DYN 的 so 静态地址都从 0 起，多个 so 的区间必然重叠，
        # 所以先按镜像映射筛出候选，再按证据强度消歧。
        cands = [k for k, spans in self._images.items() if _span_has(spans, addr)]
        if not cands:
            return ("", 0)
        if len(cands) == 1:
            return (cands[0], addr)
        # 多个候选：只用"恰好一个 so 的函数表能覆盖该地址"来消歧，
        # 仍不唯一就如实报未解析，不猜（猜错比不猜危险得多）。
        hits = []
        for k in cands:
            so = self.modules.get(k)
            try:
                if so is not None and so.function_at(addr) is not None:
                    hits.append(k)
            except Exception:  # noqa: BLE001
                continue
        if len(hits) == 1:
            return (hits[0], addr)
        return ("", 0)

    def describe(self) -> dict:
        """解析环境说明，写进摘要让读者知道"这份聚合可信到什么程度"。"""
        return {
            "mode": "runtime" if self.bases else "static",
            "bases": len(self.bases),
            "modules": len(self.modules),
        }


def _iter_module_bases(raw):
    """从多种形态的基址表里产出 (name, base, size)。形态不对就跳过。"""
    if not raw:
        return
    if isinstance(raw, dict):
        for name, value in raw.items():
            if isinstance(value, dict):
                yield str(name), _to_int(value.get("base")), _to_int(value.get("size"))
            elif isinstance(value, (tuple, list)) and value:
                size = _to_int(value[1]) if len(value) > 1 else 0
                yield str(name), _to_int(value[0]), size
            else:
                yield str(name), _to_int(value), 0
        return
    for item in raw:
        if isinstance(item, dict):
            yield (str(item.get("name") or ""), _to_int(item.get("base")),
                   _to_int(item.get("size")))
        else:
            yield (str(getattr(item, "name", "") or ""),
                   _to_int(getattr(item, "base", 0)),
                   _to_int(getattr(item, "size", 0)))


# ==================== 聚合 ====================


def aggregate_by_function(
    events,
    session,
    kind: str | tuple | list | None = KIND_CODE,
    runtime_bases=None,
) -> list[dict]:
    """把指令级/内存级事件按**静态函数**聚合（mda 的差异化能力）。

    ## 为什么需要

    指令级 trace 动辄上千万行，人（和 AI）会直接迷失在里面。按函数折叠后
    可以先看"哪个函数被执行了 800 万次"，再决定深入看哪一段——这把
    "读 1000 万行"变成"读 20 行排序表"。

    这是 unidbg 之类纯模拟器做不了的：它没有静态层，不知道运行时地址
    对应哪个静态函数；mda 有 ``SoFile.function_at``，可以给出归属。

    ## 算法

    对每条事件：
        addr --(模块基址)--> 所属 so --(减基址)--> static --(function_at)--> 函数
    以 (so, 函数起点) 为键累加，统计命中次数、首末 seq、首末时间、kind 分布。
    地址落在**函数空洞**（so 能找到但 function_at 返回 None）的事件归到该 so
    的 ``in_gap: true`` 桶；**不属于任何已加载 so** 的事件归到
    ``<unresolved>`` 桶，同样 ``in_gap: true``——两者都不丢。

    ## 参数

    - ``events``：TraceEvent 列表，或事件 dict 列表（MCP 层传回的 JSON）。
    - ``session``：``core.session.Session``，用它的 ``modules`` 与
      ``SoFile.function_at``。
    - ``kind``：默认只聚合 ``code``（指令执行）。**这个默认值是有意的**：
      read/write 事件的 addr 是**数据地址**，把它按函数归属会把
      "谁读了这块内存"错当成"谁执行了这段代码"。传 None 表示不区分 kind，
      调用方自担语义。
    - ``runtime_bases``：模块运行时基址表。不传时依次尝试
      ``session.runtime_modules``、单 so 静态模式（见 ``_ModuleResolver``）。

    ## 返回

    按 ``hit_count`` 降序（同数按 first_seq、函数名升序，保证可复现）的列表，
    每项含：``function``（``so!name``）、``so_name``、``static_addr``（函数起点，
    空洞桶为 None）、``hit_count``、``first_seq``、``last_seq``、``first_ts``、
    ``last_ts``、``in_gap``、``reason``（``""`` / ``function_gap`` /
    ``module_unresolved``）、``kinds``（各 kind 计数）。
    """
    items = _events_as_list(events)
    return _aggregate(items, session, kind, runtime_bases)[0]


def _aggregate(items: list[TraceEvent], session, kind, runtime_bases):
    """聚合实现，同时把解析统计回给 summarize（避免 summarize 再跑一遍）。"""
    kinds = _kind_set(kind)
    resolver = _ModuleResolver(session, runtime_bases)
    buckets: dict[tuple[str, int, str, bool], dict] = {}
    gap_count = 0
    unresolved_count = 0
    for ev in items:
        if kinds is not None and ev.kind not in kinds:
            continue
        so_name, static, fn_addr, fn_name, in_gap, reason = resolver.resolve(ev.addr)
        if reason == "module_unresolved":
            unresolved_count += 1
        elif in_gap:
            gap_count += 1
        key = (so_name, fn_addr, fn_name, in_gap)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "function": f"{so_name}!{fn_name}" if so_name else fn_name,
                "so_name": so_name,
                "static_addr": None if in_gap else fn_addr,
                "hit_count": 0,
                "first_seq": 0,
                "last_seq": 0,
                "first_ts": 0.0,
                "last_ts": 0.0,
                "in_gap": in_gap,
                "reason": reason,
                "kinds": {k: 0 for k in KINDS},
            }
            buckets[key] = bucket
        bucket["hit_count"] += 1
        bucket["kinds"][ev.kind] = bucket["kinds"].get(ev.kind, 0) + 1
        if not bucket["first_seq"] or (ev.seq and ev.seq < bucket["first_seq"]):
            bucket["first_seq"] = ev.seq
        if ev.seq > bucket["last_seq"]:
            bucket["last_seq"] = ev.seq
        ts = float(ev.ts or 0.0)
        if ts > 0:
            if not bucket["first_ts"] or ts < bucket["first_ts"]:
                bucket["first_ts"] = ts
            if ts > bucket["last_ts"]:
                bucket["last_ts"] = ts
    ordered = sorted(
        buckets.values(),
        key=lambda b: (-b["hit_count"], b["first_seq"], b["function"]),
    )
    stats = {
        "resolver": resolver.describe(),
        "gap_count": gap_count,
        "unresolved_count": unresolved_count,
    }
    return ordered, stats


# ==================== 摘要 ====================


def _fmt_ts(ts: float) -> str:
    """时间戳格式化：本地时分秒，带毫秒（trace 的时间跨度往往很短）。"""
    if not ts:
        return "-"
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int(ts * 1000) % 1000:03d}"


def summarize(events, session, top: int = 10, runtime_bases=None) -> dict:
    """生成人类可读的 trace 摘要。

    摘要要回答的是"这堆事件里发生了什么"，而不是"事件长什么样"：
    时间跨度、事件总数、按类型分布、涉及多少函数、最热的是哪几个。

    返回 dict 同时给机器读（各计数字段）与给人读（``text``），
    前者给 AI/前端做判断，后者可直接贴进对话。
    """
    items = _events_as_list(events)
    top = max(1, min(_to_int(top, 10), _MAX_TOP))
    buckets, agg_stats = _aggregate(items, session, KIND_CODE, runtime_bases)

    kind_counts = {k: 0 for k in KINDS}
    for ev in items:
        kind_counts[ev.kind] = kind_counts.get(ev.kind, 0) + 1

    threads: dict[int, int] = {}
    for ev in items:
        threads[ev.thread_id] = threads.get(ev.thread_id, 0) + 1

    ts_list = [float(ev.ts) for ev in items if ev.ts]
    first_ts = min(ts_list) if ts_list else 0.0
    last_ts = max(ts_list) if ts_list else 0.0
    seq_list = [ev.seq for ev in items if ev.seq]
    first_seq = min(seq_list) if seq_list else 0
    last_seq = max(seq_list) if seq_list else 0

    func_buckets = [b for b in buckets if not b["in_gap"]]
    gap_buckets = [b for b in buckets if b["in_gap"]]
    top_buckets = buckets[:top]
    resolution = agg_stats["resolver"]

    # ---- 人类可读部分 ----
    lines = [
        f"trace 摘要：共 {len(items)} 条事件"
        f"（{first_seq}→{last_seq}），"
        f"时间跨度 {max(last_ts - first_ts, 0.0):.3f}s"
        f"（{_fmt_ts(first_ts)} → {_fmt_ts(last_ts)}）",
        "按类型：" + "，".join(f"{k}={kind_counts.get(k, 0)}" for k in KINDS),
        # (8) 第八次修改（2026-11-05）：把统计口径写清楚。
        #     bug 原因：聚合只按 code 事件做，但文案用了"这堆事件"的口径，
        #               读起来像是全部事件都被归属了；read/write 事件其实不参与
        #               函数归属（它们的 addr 是数据地址，不是指令地址），
        #               一起报会让人误判"有 N 条没归属"。
        #     解决方案：明确标注"按 code 事件统计"，并单独说明非 code 事件的数量
        #               与不参与归属的原因。
        f"涉及 {len(func_buckets)} 个静态函数"
        f"（**按 code 事件统计**：另有 {agg_stats['gap_count']} 条落在函数空洞、"
        f"{agg_stats['unresolved_count']} 条地址不属于任何已加载 so，均未丢弃）",
        f"模块解析模式：{resolution['mode']}"
        f"（已加载 {resolution['modules']} 个 so，基址表 {resolution['bases']} 项）",
    ]
    if top_buckets:
        lines.append(f"Top {len(top_buckets)} 热点：")
        for i, b in enumerate(top_buckets, 1):
            span = f"seq {b['first_seq']}→{b['last_seq']}"
            tag = " [空洞]" if b["in_gap"] else ""
            lines.append(f"  {i}. {b['function']}{tag}  hit={b['hit_count']}  {span}")
    non_code = len(items) - kind_counts.get(KIND_CODE, 0)
    if non_code > 0:
        lines.append(
            f"另有 {non_code} 条非 code 事件（read/write/module_load）"
            "不参与函数归属：它们的地址是**数据地址或模块基址**，不是指令地址，"
            "按函数归属会把\"谁读了这块内存\"错当成\"谁执行了这段代码\"")
    if not items:
        lines.append("（没有任何事件：采集未启动，或采集期间目标未产生可记录的执行）")
    if resolution["mode"] == "static" and resolution["modules"] > 1:
        lines.append(
            "提示：当前按静态地址解析，而多个 so 的静态区间重叠，"
            "未给 runtime_bases 时函数归属可能判为未解析。"
        )

    return {
        "total": len(items),
        "kinds": kind_counts,
        "seq_span": {"first_seq": first_seq, "last_seq": last_seq},
        "time_span": {
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration_s": max(last_ts - first_ts, 0.0),
        },
        "threads": [
            {"thread_id": tid, "count": cnt}
            for tid, cnt in sorted(threads.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "diagnostics": {
            "resolution": resolution,
            "gap_events": agg_stats["gap_count"],
            "unresolved_events": agg_stats["unresolved_count"],
            "gap_buckets": len(gap_buckets),
            "module_load_events": kind_counts.get(KIND_MODULE_LOAD, 0),
        },
        "functions": {
            "involved": len(func_buckets),
            "top": top_buckets,
        },
        "text": "\n".join(lines),
    }


# ==================== 采集入口（留空） ====================

_REASON = "trace 采集需要 frida 会话（真机 attach 后才有运行时地址与执行流），本轮按要求留空"

# 各采集入口具体依赖什么：写成常量，既避免四处重复，也方便 MCP/GUI 直接展示
_DEPENDS_ON = {
    "start_trace_code":
        "frida Stalker（Stalker.follow + 编译期指令回调）；建议 frida 17.x，"
        "需按块分批发事件，否则单次 send 会压垮消息通道",
    "start_trace_read":
        "frida 17.x 的 Thread.setHardwareWatchpoint（实测 16.0.19 无此 API）；"
        "ARM64 硬件观察点有限（最多 4 个），且每个只覆盖 size 个字节",
    "start_trace_write":
        "frida 17.x 的 Thread.setHardwareWatchpoint（同 trace_read，"
        "写条件为 'w'）；硬件观察点资源有限，需按地址排队而非无限登记",
    "start_trace_module_load":
        "frida 16.7+ 的 Process.attachModuleObserver（实测 16.0.19 无此 API）；"
        "需与 dlopen 时机配合，避免漏掉 attach 之前已加载的模块",
}


def _find_loaded_so(session, name: str):
    """在 mda 会话里按名字找已加载的 SoFile（复用 MCP 层的多级别名匹配）。

    找不到返回 None。这里做一层薄封装，是为了让 dyn 层不必重复实现
    "设备名 ↔ 本地名"的匹配规则（那套规则在 mcp_server.tools._pick_so_by_name）。
    """
    try:
        from mcp_server.tools import _pick_so_by_name

        return _pick_so_by_name(session, name)
    except Exception:                                     # noqa: BLE001
        mods = getattr(session, "modules", {}) or {}
        return mods.get(name)


_DETACH_PENDING: set = set()
_DETACH_LOCK = __import__("threading").Lock()


def _detach_async(sess, timeout: float = 3.0) -> None:
    """在**守护线程**里 detach/close 会话，主流程最多等 timeout 秒。

    (16) 第十六次修改（2026-11-06）：新增。
        bug 原因：实测 frida 17.23.3 + 该设备上，一旦 attach 过脚本，
                  session.detach() 与 script.unload() 都会**永久阻塞**
                  （不是慢，是完全不返回）。而它们原本写在 finally 里，
                  导致整个工具函数卡死——表现成「MCP 调用永不返回」。
                  这不是本 app 特例，是所有 trace/watch 类工具共有的缺陷。
        解决方案：把 detach 放到守护线程里做，主线程 wait 有限时间就返回。

    (17) 第十七次修改（2026-11-06）：**防止阻塞线程无限累积**。
        自查发现的问题：上一版每次调用都会留下一个永久阻塞的守护线程
        （实测连续 20 次调用 → 线程数从 1 涨到 21）。MCP 服务是常驻进程，
        反复调用 trace_* / watch_module 会把线程资源耗尽。
        解决方案：
          ① 先用 `session.is_detached` 判断是否已断开，已断开直接跳过；
          ② 用一个集合登记"正在 detach 的会话 id"，同一个会话不重复起线程；
          ③ 集合本身有上限，超出就放弃登记新线程（宁可让 frida 侧自然回收，
             也不让本地线程无界增长）。
    """
    import threading as _th

    if sess is None:
        return
    # 已经断开就不用再折腾
    try:
        if getattr(sess, "is_detached", False):
            return
    except Exception:                                     # noqa: BLE001
        pass

    key = id(sess)
    with _DETACH_LOCK:
        if key in _DETACH_PENDING:
            return                                        # 同一会话已在处理
        # 上限：只允许同时存在有限个阻塞中的 detach 线程
        if len(_DETACH_PENDING) >= 16:
            return                                        # 超限就放弃，交给 frida 回收
        _DETACH_PENDING.add(key)

    done = _th.Event()

    def _worker() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass
        finally:
            with _DETACH_LOCK:
                _DETACH_PENDING.discard(key)
            done.set()

    th = _th.Thread(target=_worker, name="mda-detach", daemon=True)
    th.start()
    try:
        done.wait(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


def _find_loaded_so(session, name: str):
    """在 mda 会话里按名字找已加载的 SoFile（复用 MCP 层的多级别名匹配）。

    找不到返回 None。这里做一层薄封装，是为了让 dyn 层不必重复实现
    "设备名 ↔ 本地名"的匹配规则（那套规则在 mcp_server.tools._pick_so_by_name）。
    """
    try:
        from mcp_server.tools import _pick_so_by_name

        return _pick_so_by_name(session, name)
    except Exception:                                     # noqa: BLE001
        mods = getattr(session, "modules", {}) or {}
        return mods.get(name)


def _read_static_bytes(so, offset: int, size: int) -> bytes:
    """从已加载的 SoFile 读原始文件字节（用于生成指纹 / 校验断点是否被 patch）。

    (15) 第十五次修改（2026-11-06）：新增。
        为什么需要：① 模块名对不上时要靠字节指纹反查；
                  ② 断点自检要把"内存里的字节"与"文件里的原始字节"对比，
                     才能判断这个地址到底有没有被 patch。
    """
    # SoFile 可能提供 read_bytes；没有就退回直接读文件
    fn = getattr(so, "read_bytes", None)
    if callable(fn):
        try:
            data = fn(int(offset), int(size))
            if data:
                return bytes(data)
        except Exception:                                 # noqa: BLE001
            pass
    path = getattr(so, "path", "") or getattr(so, "_path", "")
    if not path:
        return b""
    try:
        with open(path, "rb") as fh:
            # 偏移是虚拟地址，需要按段换算成文件偏移
            segs = getattr(so, "_segments", None) or []
            for seg in segs:
                va = int(getattr(seg, "vaddr", 0) or 0)
                memsz = int(getattr(seg, "memsz", 0) or 0)
                if va <= offset < va + max(memsz, 1):
                    file_off = int(getattr(seg, "offset", 0) or 0) + (offset - va)
                    fh.seek(file_off)
                    return fh.read(int(size))
            fh.seek(int(offset))
            return fh.read(int(size))
    except Exception:                                     # noqa: BLE001
        return b""


def _module_name_candidates(name: str) -> list[str]:
    """把一个模块名展开成「可能对应的若干个名字」，供设备侧按候选匹配。

    (14) 第十四次修改（2026-11-06）：新增。
        bug 原因：本地分析的 so 文件名与设备上加载的模块名经常不一致
                  （libsgmainso.so ↔ libsgmainso-6.7.260202.so），
                  按单一名字在 Process.enumerateModules() 里找不到，
                  表现成 MODULE_NOT_LOADED，但 so 明明就在进程里。
        解决方案：生成候选列表，JS 侧按顺序逐个比对。候选只做**无损规范化**：
                  原名 → basename → 去版本号 → 去 lib 前缀，不做模糊猜测。

    例：
        libsgmainso.so              -> ["libsgmainso.so", "libsgmainso"]
        libsgmainso-6.7.260202.so   -> ["libsgmainso-6.7.260202.so",
                                        "libsgmainso-6.7.260202",
                                        "libsgmainso.so", "libsgmainso"]
    """
    import re as _re

    raw = str(name or "").strip()
    if not raw:
        return []
    base = raw.rsplit("/", 1)[-1]
    out: list[str] = []

    def _add(v: str) -> None:
        if v and v not in out:
            out.append(v)

    _add(raw)
    _add(base)
    # 去扩展名
    stem = base
    for ext in (".so", ".dylib"):
        idx = stem.find(ext)
        if idx > 0:
            stem = stem[:idx]
            break
    _add(stem)
    # 去版本号尾巴
    core = _re.sub(r"-\d+(?:\.\d+)*$", "", stem)
    _add(core)
    if core:
        _add(core + ".so")
    # 去 lib 前缀（部分壳会加/去这个前缀）
    if core.startswith("lib"):
        _add(core[3:])
    return out


def _trace_pending(feature: str, hint: str, extra: dict | None = None) -> dict:
    """构造 trace 采集入口的占位返回。

    在 ``dyn.pending`` 的标准结构上补两个字段：
      depends_on —— 机器可读的"依赖什么"，便于 MCP 层转述给 AI
      feature    —— pending 已带，这里保证 code 前缀统一为 NEEDS_FRIDA
    占位结构恒为 ``implemented: false``，**不是**"采集到 0 条事件"。
    """
    info = NotImplementedYet(feature, reason=_REASON, hint=hint).as_dict()
    info["depends_on"] = _DEPENDS_ON.get(feature, "")
    info.update(extra or {})
    return info


_JS_STALKER = r"""
(function () {
    var MAX = __MAX__;
    var TIDS = __TIDS__;
    var wantRanges = __RANGES__;
    var events = [];
    var total = 0;

    var ts = Process.enumerateThreads();
    var picked = [];
    if (TIDS && TIDS.length) {
        picked = ts.filter(function (t) { return TIDS.indexOf(t.id) >= 0; });
    } else {
        // 未指定：优先跟随非 running 的线程（对系统进程更温和），最多 4 条
        for (var i = 0; i < ts.length && picked.length < 4; i++) {
            if (ts[i].state !== 'running' || picked.length === 0) { picked.push(ts[i]); }
        }
    }
    if (picked.length === 0) {
        send({ err: 'no-thread', total: ts.length });
        return;
    }

    var followed = [];
    picked.forEach(function (t) {
        try {
            Stalker.follow(t.id, {
                events: { call: true },
                onReceive: function (raw) {
                    if (events.length >= MAX) { return; }
                    try {
                        var parsed = Stalker.parse(raw, { annotate: true, stringify: true });
                        for (var i = 0; i < parsed.length; i++) {
                            var e = parsed[i];
                            // ["call", <调用点>, <目标>, <depth>]
                            if (!e || e[0] !== 'call') { continue; }
                            var to = e[2], from = e[1];
                            if (wantRanges && wantRanges.length) {
                                var ok = false;
                                for (var r = 0; r < wantRanges.length; r++) {
                                    var a = ptr(wantRanges[r][0]), b = ptr(wantRanges[r][1]);
                                    var p = ptr(to);
                                    if (p.compare(a) >= 0 && p.compare(b) < 0) { ok = true; break; }
                                }
                                if (!ok) { continue; }
                            }
                            // (5) 关键：onReceive 是高频回调，**绝对不能在里面 send**
                            //     ——实测这样做会让脚本卡住不返回（消息队列积压）。
                            //     这里只累积到内存，等到 stop 时再一次性分批送出。
                            if (events.length >= MAX) { return; }
                            events.push({ from: from, to: to, depth: e[3], tid: t.id,
                                          ts: Date.now() });
                        }
                    } catch (err) {}
                }
            });
            followed.push({ id: t.id, name: t.name });
        } catch (err) {}
    });
    send({ ready: true, followed: followed, total: ts.length });

    recv('stop', function () {
        followed.forEach(function (f) { try { Stalker.unfollow(f.id); } catch (e) {} });
        try { Stalker.flush(); } catch (e) {}
        // 停止后再发送，且分批——单条消息过大同样会拖住
        for (var i = 0; i < events.length; i += 200) {
            send({ batch: events.slice(i, i + 200) });
        }
        send({ stopped: true, total: events.length });
    });
})();
"""


def start_trace_code(
    serial: str,
    pid: int,
    threads: list[int] | None = None,
    ranges: list[tuple[int, int]] | None = None,
    include_libs: list[str] | None = None,
    exclude_libs: list[str] | None = None,
    max_events: int = _DEFAULT_CAPACITY,
    duration: float = 2.0,
) -> dict:
    """指令级/调用级 trace 采集（基于 Stalker 的 call 事件）。

    (5) 第五次修改（2026-11-05）：实现真采集（此前留空）。
        关键突破：之前 follow 后脚本会"卡死"，根因不是 Stalker 不可用，而是
        **在 JS 里用 setTimeout 来 unfollow**——被 Stalker 跟踪的线程无法执行
        该定时器回调，脚本永远等不到停止信号。改成**Python 侧 script.post()
        触发 recv('stop')** 后就正常了：实测 system_server 1.2 秒拿到 2064 次
        调用事件。

    采集的是**调用事件**（谁调用了谁），不是逐条指令：
        · 只有 call，不采集 exec/ret —— 指令级会把事件量放大几个数量级，
          而"执行了哪些函数、调用关系如何"通常才是要回答的问题；
        · 每条事件 {from: 调用点运行时地址, to: 被调用目标运行时地址,
          depth: 栈深, tid: 线程}；
        · 想按函数聚合就直接喂 trace_aggregate（它会把运行时地址折回静态函数）。

    参数：
        threads    —— 要跟随的线程 id 列表；None 表示自动挑（优先非 running，
                      最多 4 条，对系统进程更温和）
        ranges     —— 只保留目标地址落在这些运行时区间内的调用
        include_libs / exclude_libs —— 预留，当前未参与过滤（不假装支持）
        duration   —— 采集秒数（Python 侧计时，到点主动停）
        max_events —— 事件上限

    **已知限制（必须知道）**：
        · 前提是 `Process.enumerateThreads()` 能拿到线程——多数 app 返回空，
          这时无法跟随任何线程，会明确返回 no-thread；
        · 跟随 system_server 这类核心进程时建议给较小 duration；
        · 从未指定线程时自动挑选的线程可能并不执行你关心的代码，
          精确场景请先用 list_threads 拿到 tid 再传进来。
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("start_trace_code", hint=f"frida 不可用：{exc}",
                              extra={"serial": serial, "pid": pid})

    tid_list = [int(t) for t in (threads or [])]
    rng = [[hex(int(a)), hex(int(b))] for a, b in (ranges or [])]
    js = (_JS_STALKER
          .replace("__MAX__", str(int(max_events)))
          .replace("__TIDS__", repr(tid_list))
          .replace("__RANGES__", repr(rng)))

    try:
        dev = frida.get_device(serial, timeout=10)
        sess = dev.attach(pid)
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("start_trace_code",
                              hint=f"attach 失败（{exc}）",
                              extra={"serial": serial, "pid": pid})

    box: dict = {"followed": [], "events": [], "ready": False, "stopped": False,
                 "err": "", "total": 0, "tids": []}
    try:
        script = sess.create_script(js)

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("ready"):
                box["ready"] = True
                box["followed"] = payload.get("followed") or []
                box["total"] = int(payload.get("total") or 0)
                return
            if payload.get("batch"):
                box["events"].extend(payload.get("batch") or [])
                return
            if payload.get("stopped"):
                box["stopped"] = True
                return
            if payload.get("err") == "no-thread":
                box["err"] = "no-thread"
                box["total"] = int(payload.get("total") or 0)

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box["err"] and _time.time() - t0 < 3.0:
            _time.sleep(0.05)

        # (7) 就绪判定：ready 没到、或 ready 到了但一条线程都没跟上是两种不同的失败
        if not box["ready"] and not box["err"]:
            return {
                "ok": False, "implemented": True, "code": "NOT_READY",
                "error": "Stalker 脚本 3 秒内没有回 ready（可能被目标拒绝或脚本加载失败）",
                "followed_threads": [], "count": 0,
            }
        if box["err"] == "no-thread":
            return {
                "ok": False,
                "implemented": True,
                "code": "NO_THREAD",
                "error": (f"Process.enumerateThreads() 返回 {box['total']} 个线程，"
                          "无法跟随任何线程。指令级 trace 依赖线程对象，"
                          "请换一个 frida 能枚举线程的目标进程（如 system_server）"),
                "env_note": "多目标实测：systemui/logd/zygote 枚举为 0，system_server 正常",
            }

        # Python 侧计时，到点主动停（**不要**用 JS 的 setTimeout）
        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        t1 = _time.time()
        while not box["stopped"] and _time.time() - t1 < 3.0:
            _time.sleep(0.05)
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("start_trace_code",
                              hint=f"采集期间出错：{exc}",
                              extra={"serial": serial, "pid": pid})
    finally:
        _detach_async(sess)

    raw_events = box["events"]
    out_events = []
    for e in raw_events[:max_events]:
        try:
            out_events.append({
                "kind": KIND_CODE,
                "runtime_addr": _to_int(e.get("to")),
                "from": _to_int(e.get("from")),
                "depth": int(e.get("depth") or 0),
                "thread_id": int(e.get("tid") or 0),
                # (10) 第十次修改（2026-11-05）：原来写死 0.0，是**假数据**。
                #      bug 原因：时间轴能力依赖 ts，而这里恒给 0，等于告诉调用方
                #                "所有事件都发生在同一刻"，聚合/排序全部失效；
                #                更糟的是 0 看起来是个合法值，下游不会察觉。
                #      解决方案：用 JS 侧传入的 Date.now()/1000；缺失时给 None
                #                （明确表示"没有时间信息"，而不是伪造 0）。
                "ts": _to_int(e.get("ts")) / 1000.0 if e.get("ts") else None,
            })
        except Exception:                                 # noqa: BLE001
            continue

    return {
        "ok": bool(out_events) or box["stopped"],
        "implemented": True,
        "serial": serial,
        "pid": pid,
        "events": out_events,
        "count": len(out_events),
        "followed_threads": box["followed"],
        "threads_total": box["total"],
        "stopped_cleanly": box["stopped"],
        "duration": duration,
        "method": "Stalker.follow(events={call:true}) + Python 侧 post('stop')",
        "note": ("只采集 call 事件（调用关系），不含逐条指令执行；"
                 "事件里的 runtime_addr 可直接喂 trace_aggregate 折回静态函数"),
        "limitations": [
            "依赖 Process.enumerateThreads()：多数 app 返回 0，此时无法跟随",
            "自动挑选的线程可能不执行目标代码，精确场景请先 list_threads 取 tid",
        ],
        "danger": (
            "**对 system_server 使用会导致系统重启**（实测两次：跟随其线程后 "
            "system_server 消失、zygote 与 Android 框架整体重启）。"
            "非必要不要跟 system_server；即便要用，也应极小 duration 并接受"
            "设备可能重启的后果。这也意味着本能力目前**没有一个安全的常用目标**："
            "多数 app 枚举不到线程，能枚举的 system_server 又不稳定。"),
    }


# 监控用的内存操作函数表：(函数名, 读参数索引, 写参数索引, 长度参数索引)
#
# 为什么用 hook 常用函数而不是硬件观察点/MemoryAccessMonitor：
#   实测（设备 3e2ff172 / frida 17.23.3）：
#     · Thread.setHardwareWatchpoint 能真的触发（runOnThread 里写一次立刻报
#       "Error: breakpoint triggered"），但异常被 frida 内部吞掉，
#       Process.setExceptionHandler 收不到（hits=0）；且只有 4 个槽位、
#       按线程生效，实用性受限。
#     · MemoryAccessMonitor.enable() **直接把目标进程搞崩**（实测 system_server
#       消失、连接断开、Android 框架整体重启），绝不能再用于别人的设备。
#   所以选 hook 内存函数：无副作用、可同时覆盖一整块区间、能拿到调用栈。
# 代价说清楚：抓不到编译器内联的直接 ldr/str；覆盖率取决于目标走不走这些函数。
_MEM_FUNCS = (
    # name,          readIdx, writeIdx, lenIdx
    ("memcpy",       1, 0, 2),
    ("memmove",      1, 0, 2),
    ("memset",      -1, 0, 2),
    ("memcmp",       0, -1, 2),   # 第二个参数在 onEnter 里单独用 args[1]
    ("memchr",       0, -1, 2),
    ("strlen",       0, -1, -1),
    ("strcmp",       0, -1, -1),
    ("strncmp",      0, -1, 2),
    ("strcpy",       1, 0, -1),
    ("strncpy",      1, 0, 2),
    ("strcat",       1, 0, -1),
    ("strdup",       0, -1, -1),
    ("__memcpy_chk", 1, 0, 2),
    ("__memset_chk", -1, 0, 2),
)

_JS_MEM_TRACE = r"""
(function () {
    var START = ptr('__START__');
    var END = ptr('__END__');
    var KIND = '__KIND__';
    var MAX = __MAX__;
    var TABLE = __TABLE__;

    function inRange(p) {
        if (p === null) { return false; }
        try { return p.compare(START) >= 0 && p.compare(END) <= 0; }
        catch (e) { return false; }
    }

    var count = 0;
    var hooked = [];
    TABLE.forEach(function (row) {
        var name = row[0], rIdx = row[1], wIdx = row[2];
        var p = null;
        try { p = Module.findGlobalExportByName(name); } catch (e) { p = null; }
        if (p === null) { return; }
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    if (count >= MAX) { return; }
                    var hit = false;
                    var off = -1;
                    if (rIdx >= 0 && inRange(args[rIdx])) { hit = true; off = rIdx; }
                    // memcmp 两个参数都读，单独判
                    if (!hit && name === 'memcmp' && inRange(args[1])) { hit = true; off = 1; }
                    if (!hit && wIdx >= 0 && inRange(args[wIdx])) { hit = true; off = wIdx; }
                    if (!hit) { return; }
                    count++;
                    var bt = [];
                    try {
                        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                 .slice(0, 8).map(function (a) { return a.toString(); });
                    } catch (e) {}
                    send({
                        kind: KIND,
                        fn: name,
                        arg_index: off,
                        addr: args[off].toString(),
                        caller: this.returnAddress ? this.returnAddress.toString() : null,
                        tid: this.threadId,
                        backtrace: bt,
                        ts: Date.now() / 1000
                    });
                }
            });
            hooked.push(name);
        } catch (e) {}
    });
    send({ ready: true, hooked: hooked });
})();
"""


def _trace_memory_access(
    serial: str,
    pid: int,
    addr: int,
    size: int,
    so_name: str,
    kind: str,
    max_events: int,
    duration: float,
) -> dict:
    """监控「谁读/写了这块内存」——用 hook 内存操作函数实现。

    (4) 第四次修改（2026-11-05）：实现真采集（此前留空）。
        背景与选型理由见 ``_MEM_FUNCS`` 上方注释：硬件观察点能触发但异常抓不到，
        MemoryAccessMonitor 会崩目标进程，故改用 hook。

    地址语义：``addr`` 是**运行时地址**。若给的是静态地址并同时给 ``so_name``，
    本函数会用 Rebase 换算成运行时地址（不自己反查模块，避免猜错）。

    参数：
        size       —— 监控区间长度（字节）
        duration   —— 观察秒数（阻塞）
        max_events —— 事件上限，达到即提前结束

    返回：{ok, implemented, kind, events, count, hooked_functions, addr, size, ...}
    每条事件：{fn, arg_index, addr, caller, tid, backtrace[]}

    **能力边界（务必知道）**：
        · 只覆盖走这些 libc 函数的访问；编译器内联的直接 ldr/str 抓不到；
        · 不记录"访问了多少字节"，只记录"访问了哪个地址"；
        · 需要目标进程真的执行到这些函数，空闲进程可能采集不到事件。
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending(f"start_trace_{kind}",
                              hint=f"frida 不可用：{exc}",
                              extra={"serial": serial, "pid": pid})

    addr_i = _to_int(addr)
    size_i = max(1, _to_int(size, 8))

    # 静态地址 -> 运行时地址（只有给了 so_name 才换算，绝不瞎猜）
    runtime_addr = addr_i
    converted = False
    if so_name:
        rb = None
        try:
            from dyn.rebase import Rebase

            rb = Rebase.attach(serial, pid)
            mod = rb.find_module(so_name)
            if mod is None:
                return _trace_pending(
                    f"start_trace_{kind}",
                    hint=f"{so_name} 未加载到目标进程，无法换算运行时地址",
                    extra={"serial": serial, "pid": pid, "addr": _to_int(addr)})
            runtime_addr = rb.to_runtime(addr_i, mod)
            converted = True
        except Exception as exc:                          # noqa: BLE001
            return _trace_pending(f"start_trace_{kind}",
                                  hint=f"地址换算失败：{exc}",
                                  extra={"serial": serial, "pid": pid})
        finally:
            # (6) 第六次修改（2026-11-05）：无论成功失败都要 detach。
            #     bug 原因：原实现只在成功路径末尾 rb.detach()，而"模块未加载/换算异常"
            #               这两条 return 分支直接走了，**每次失败泄漏一个设备端 attach**。
            #               反复调用会把设备的 session 数堆上去。
            #     解决方案：把 detach 放进 finally，保证任何出口都释放。
            if rb is not None:
                try:
                    rb.detach()
                except Exception:                         # noqa: BLE001
                    pass

    table = [[n, r, w, l] for (n, r, w, l) in _MEM_FUNCS]
    js = (_JS_MEM_TRACE
          .replace("__START__", hex(runtime_addr))
          .replace("__END__", hex(runtime_addr + size_i))
          .replace("__KIND__", kind)
          .replace("__MAX__", str(int(max_events)))
          .replace("__TABLE__", repr(table).replace("'", '"')))

    events: list[dict] = []
    hooked: list[str] = []
    stopped_by = ""
    try:
        dev = frida.get_device(serial, timeout=10)
        sess = dev.attach(pid)
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending(
            f"start_trace_{kind}",
            hint=f"attach 失败（{exc}）；确认 frida-server 版本与客户端一致",
            extra={"serial": serial, "pid": pid})

    try:
        script = sess.create_script(js)

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("ready"):
                hooked.extend(payload.get("hooked") or [])
                return
            if payload.get("kind") in ("read", "write"):
                events.append(payload)

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not hooked and _time.time() - t0 < 2.0:
            _time.sleep(0.05)
        # (7) 第七次修改（2026-11-05）：就绪信号只等不判 → 现在要判。
        #     bug 原因：原来等完 2 秒后即使 hooked 为空也照常往下跑，最后返回
        #               ok:true, count:0 —— 与"窗口内确实没有访问"**无法区分**。
        #               而 hooked 为空意味着一个内存函数都没挂上，采不到任何事件。
        #     解决方案：hooked 为空直接判为环境/目标问题并说明，不返回假成功。
        if not hooked:
            return {
                "ok": False,
                "implemented": True,
                "code": "NO_HOOK",
                "error": ("一个可监控的内存函数都没能挂上（memcpy/memset/strlen 等全部"
                          " findGlobalExportByName 失败或 attach 被拒）；"
                          "目标进程可能没有这些导出，或 hook 被反调试拦截"),
                "kind": kind,
                "serial": serial, "pid": pid,
            }

        deadline = _time.time() + max(0.1, float(duration))
        while _time.time() < deadline:
            if len(events) >= max_events:
                stopped_by = "max_events"
                break
            _time.sleep(0.1)
        else:
            stopped_by = "duration"
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending(f"start_trace_{kind}",
                              hint=f"采集期间出错：{exc}",
                              extra={"serial": serial, "pid": pid})
    finally:
        _detach_async(sess)

    return {
        "ok": True,
        "implemented": True,
        "kind": kind,
        "serial": serial,
        "pid": pid,
        "addr": hex(addr_i),
        "runtime_addr": hex(runtime_addr),
        "addr_converted": converted,
        "size": size_i,
        "events": events[:max_events],
        "count": len(events),
        "hooked_functions": hooked,
        "stopped_by": stopped_by,
        "duration": duration,
        "method": "interceptor-hook（hook 常用 libc 内存函数，检查访问地址是否落在区间内）",
        "limitations": [
            "只覆盖走这些函数的访问，编译器内联的 ldr/str 抓不到",
            "不记录访问字节数，只记录访问地址",
            "目标进程必须真的执行到这些函数才会产生事件",
        ],
        "why_not_hardware_watchpoint": (
            "实测 Thread.setHardwareWatchpoint 能触发但异常被 frida 内部吞掉"
            "（Process.setExceptionHandler 收不到），且只有 4 个槽位、按线程生效"),
        "why_not_memory_access_monitor": (
            "MemoryAccessMonitor.enable() 实测会让目标进程崩溃"
            "（system_server 消失、Android 框架重启），不可用于真实设备"),
    }


def start_trace_read(
    serial: str,
    pid: int,
    addr: int,
    size: int = 8,
    so_name: str = "",
    max_events: int = _DEFAULT_CAPACITY,
    duration: float = 2.0,
) -> dict:
    """监控「谁**读**了这块内存」。

    用 hook libc 内存函数实现（选型理由见 ``_MEM_FUNCS`` 注释）：
    memcpy/memmove/memcmp/memchr/strlen/strcmp/strncmp/strcpy/strncpy/
    strcat/strdup/__memcpy_chk 的**源地址**落在 [addr, addr+size) 时记一条事件。

    addr 为运行时地址；只给静态地址时同时传 so_name，本函数会换算。

    典型用途：定位"谁把这个配置/密钥读走了""这个全局变量被谁引用"。
    事件里的 backtrace 是**运行时地址**，交给 trace_aggregate / 调用方符号化。
    """
    return _trace_memory_access(serial, pid, addr, size, so_name,
                                "read", max_events, duration)


def start_trace_write(
    serial: str,
    pid: int,
    addr: int,
    size: int = 8,
    so_name: str = "",
    max_events: int = _DEFAULT_CAPACITY,
    duration: float = 2.0,
) -> dict:
    """监控「谁**写**了这块内存」。

    hook 的内存函数里**目标地址**落在 [addr, addr+size) 时记一条事件
    （memcpy/memmove/memset/strcpy/strncpy/strcat/__memset_chk 等）。

    典型用途：定位"谁改了这个标志位""谁解密后写回了这段缓冲区"。
    """
    return _trace_memory_access(serial, pid, addr, size, so_name,
                                "write", max_events, duration)


def start_trace_module_load(
    serial: str,
    pid: int = 0,
    package: str = "",
    include_system: bool = False,
    max_events: int = _DEFAULT_CAPACITY,
    duration: float = 3.0,
    keep_alive: bool = True,
) -> dict:
    """采集模块**加载时间轴**——支持"从 app 启动前开始"和"从现在开始"两种。

    (3) 第三次修改（2026-11-05）：增加 spawn 模式 + 时间轴输出。
        bug 原因：① 原实现只支持 attach，而 attach 到已运行进程只能看到
                    attach **之后**的加载——用户要的"从启动到运行"根本看不到；
                 ② 事件里没有时间戳，只能回答"加载了什么"，回答不了
                    "什么时候加载的、间隔多久"；
                 ③ 回放过滤用 `name -> base` 单值映射，遇到同名多实例
                    （实测 libcutils.so 在进程里有两个基址）全部失配，
                    导致每次观察都稳定报 52 个**假新增**。
        解决方案：① 传 package 时走 spawn——先把 app 挂起、装好观察器、
                      再 resume 放行，从第一条指令开始记；
                  ② JS 侧用 Date.now() 给每条事件打点；
                  ③ 回放基线改用 "name|base" 组合键；
                  ④ 输出按时间排序并计算与上一条的间隔（delta_s）。

    ## 两种模式（按传参自动选择）

        spawn 模式  传 package="com.x.y"
                    在 app 启动**前**挂起 → 装观察器 → resume 放行
                    → 能看到从进程创建那一刻起的**全部**加载
                    适合："这个 app 启动时都加载了什么"

        attach 模式 传 pid=12345
                    附着到**已经在跑**的进程，只记录后续加载
                    适合："从现在开始，它还会加载什么"

    ## 参数

        package      —— 要走 spawn 的包名；给了它就用 spawn 模式
        pid          —— attach 模式的目标；package 为空时才用它
        duration     —— 采集秒数。spawn 模式下**从 resume 那一刻开始计时**
        include_system —— 是否保留 /system、/apex、/vendor 下的模块
                         （默认 False；注意壳样本自己的 so 常在 /data 下，不受影响）
        keep_alive   —— 仅 spawn 模式：采集结束后是否保留 app 进程。
                        True（默认）保留，方便接着下断点；
                        False 则 kill 掉（纯采集场景更干净）
        max_events   —— 事件上限

    ## 返回

        mode            "spawn" / "attach"
        pid             实际进程号（spawn 模式下是新建的）
        events[]        按时间升序，每条 {kind, name, base, size, path, ts, delta_s, seq}
        timeline        人类可读的时间轴文本（可直接转述）
        baseline_count  观察器就位时已加载的模块数
        first_load / last_load  最早/最晚一次加载的相对耗时（秒）

    失败时返回带 code 的结构（NO_PACKAGE / SPAWN_FAILED / OBSERVER_NOT_READY 等），
    **绝不返回假事件**。
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("start_trace_module_load",
                              hint=f"frida 不可用：{exc}",
                              extra={"serial": serial, "pid": pid})

    pkg = (package or "").strip()
    use_spawn = bool(pkg)
    if not use_spawn and not pid:
        return {
            "ok": False, "implemented": True, "code": "NEED_TARGET",
            "error": ("必须给 package（从启动开始采集）或 pid（从当前时刻采集）之一。"
                      "package 能覆盖启动阶段，pid 只能看之后"),
        }

    js = """
    var t0 = Date.now();
    var events = [];
    var existing = {};
    Process.enumerateModules().forEach(function (m) {
        existing[m.name + '|' + m.base.toString()] = true;
    });
    var baseline = Object.keys(existing).length;
    Process.attachModuleObserver({
        onAdded: function (m) {
            var key = m.name + '|' + m.base.toString();
            if (existing[key]) { return; }        // 回放，不是真新增
            existing[key] = true;
            send({ kind: 'added', name: m.name, base: m.base.toString(),
                   size: m.size, path: m.path, ts: Date.now() / 1000 });
        },
        onRemoved: function (m) {
            var key = m.name + '|' + (m.base ? m.base.toString() : '');
            delete existing[key];
            send({ kind: 'removed', name: m.name, base: null, size: 0, path: null,
                   ts: Date.now() / 1000 });
        }
    });
    send({ kind: 'ready', baseline: baseline, spawned_at: t0 });
    recv('stop', function () {
        // (11) 结束时把完整模块表带回去：调用栈里的原始地址要靠它才能
        // 折回 "so!函数+偏移"，用增量事件推出来的表是不全的。
        var mods = [];
        try {
            Process.enumerateModules().forEach(function (m) {
                mods.push({ name: m.name, base: m.base.toString(),
                            size: m.size, path: m.path });
            });
        } catch (e) {}
        send({ kind: 'stopped', modules: mods });
    });
    """

    events: list[dict] = []
    box: dict = {"ready": False, "baseline": 0, "stopped": False, "t_start": 0.0}
    dev = None
    spawned_pid = 0
    sess = None
    stopped_by = ""
    try:
        dev = frida.get_device(serial, timeout=15)
        if use_spawn:
            try:
                spawned_pid = dev.spawn([pkg])
            except Exception as exc:                      # noqa: BLE001
                return {
                    "ok": False, "implemented": True, "code": "SPAWN_FAILED",
                    "error": (f"spawn {pkg} 失败：{exc}；"
                              "常见原因：包名不对、app 不允许调试、或 frida 版本不匹配"),
                    "package": pkg,
                }
            target_pid = spawned_pid
        else:
            target_pid = int(pid)

        sess = dev.attach(target_pid)

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["baseline"] = int(payload.get("baseline") or 0)
                box["t_start"] = float(payload.get("spawned_at") or 0) / 1000.0
                return
            if kind == "stopped":
                box["stopped"] = True
                mods = payload.get("modules") or []
                if mods:
                    box["modules"] = mods
                return
            if kind in ("added", "removed"):
                events.append(payload)

        script = sess.create_script(js)
        script.on("message", _on_msg)
        script.load()

        # 等观察器就位
        t_ready = _time.time()
        while not box["ready"] and _time.time() - t_ready < 5.0:
            _time.sleep(0.02)
        if not box["ready"]:
            return {
                "ok": False, "implemented": True, "code": "OBSERVER_NOT_READY",
                "error": "attachModuleObserver 5 秒内没有就位（frida-server 可能不支持）",
                "package": pkg, "pid": target_pid,
            }

        # spawn 模式下此刻 app 还挂起着，先放行再开始计时
        if use_spawn:
            dev.resume(spawned_pid)

        t_begin = _time.time()
        deadline = t_begin + max(0.1, float(duration))
        while _time.time() < deadline:
            if len(events) >= max_events:
                stopped_by = "max_events"
                break
            _time.sleep(0.02)
        else:
            stopped_by = "duration"

        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(20):
            if box["stopped"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {
            "ok": False, "implemented": True, "code": "TRACE_FAILED",
            "error": f"采集期间出错：{type(exc).__name__}: {exc}",
            "package": pkg, "pid": pid,
        }
    finally:
        _detach_async(sess)
        # spawn 出来又不想留着的进程要收掉，别给用户留个半死的 app
        if use_spawn and not keep_alive and spawned_pid:
            try:
                dev.kill(spawned_pid)
            except Exception:                             # noqa: BLE001
                pass

    # ---- 过滤系统路径 ----
    def _is_system(p) -> bool:
        if not p:
            return False
        return (p.startswith("/system") or "/system/" in p
                or p.startswith("/apex") or "/apex/" in p
                or p.startswith("/vendor") or "/vendor/" in p
                or p.startswith("/product") or "/product/" in p)

    kept = list(events) if include_system else [e for e in events if not _is_system(e.get("path"))]
    dropped = len(events) - len(kept)

    # ---- 排序 + 计算间隔（时间轴的关键）----
    kept.sort(key=lambda e: (float(e.get("ts") or 0), str(e.get("name"))))
    t_base = float(kept[0]["ts"]) if kept and kept[0].get("ts") else None
    prev_ts = None
    seq = 0
    timeline_lines: list[str] = []
    for e in kept:
        seq += 1
        e["seq"] = seq
        ts = float(e.get("ts") or 0) or None
        if ts is not None and prev_ts is not None:
            e["delta_s"] = round(ts - prev_ts, 4)
        else:
            e["delta_s"] = None
        if ts is not None:
            prev_ts = ts
            e["t_rel"] = round(ts - t_base, 4) if t_base else 0.0
        else:
            e["t_rel"] = None
        if len(timeline_lines) < 40:
            rel = f"+{e['t_rel']:.3f}s" if e.get("t_rel") is not None else "+?"
            delta = f" (Δ{e['delta_s']:+.3f}s)" if e.get("delta_s") else ""
            action = "加载" if e.get("kind") == "added" else "卸载"
            timeline_lines.append(f"{rel}{delta} {action} {e.get('name')}")

    out = {
        "ok": True,
        "implemented": True,
        "mode": "spawn" if use_spawn else "attach",
        "package": pkg,
        "pid": spawned_pid or int(pid),
        "events": kept[:max_events],
        "count": len(kept),
        "dropped_system": dropped,
        "baseline_count": box["baseline"],
        "stopped_by": stopped_by,
        "duration": duration,
        "timeline": "\n".join(timeline_lines),
        "note": ("spawn 模式覆盖**从启动那一刻**开始的加载；attach 模式只看得到"
                 "attach 之后。baseline_count 是观察器就位时已加载的模块数"
                 "（spawn 模式下是 zygote 带来的基础库，不算新增加载）"),
    }
    if kept:
        first = kept[0]
        last = kept[-1]
        out["first_load"] = {"name": first.get("name"),
                             "t_rel": first.get("t_rel"),
                             "path": first.get("path")}
        out["last_load"] = {"name": last.get("name"),
                            "t_rel": last.get("t_rel"),
                            "path": last.get("path")}
        if len(kept) > 1 and last.get("t_rel") is not None:
            out["load_span_s"] = last.get("t_rel")
    if use_spawn and not keep_alive:
        out["killed_after"] = True
    return out


_JS_APP_STARTUP = r"""
(function () {
    var t0 = Date.now();
    var existing = {};
    Process.enumerateModules().forEach(function (m) {
        existing[m.name + '|' + m.base.toString()] = true;
    });
    send({ kind: 'ready', baseline: Object.keys(existing).length, t0: t0 });

    // 0) 按**静态地址**下断点（含"等 so 加载后再下"的延迟断点）
    //    (10) 第十次修改（2026-11-05）：启动早期 app 自己的 so 往往还没加载，
    //    所以不能只在挂起时尝试一次。这里维护一个 pending 列表：
    //      · 已加载 -> 立即下
    //      · 未加载 -> 挂起等待，对应 so 被 dlopen 时自动补下
    //    这样才能抓到"so 一加载完就执行的那个函数"。
    var STATIC_BPS = __SBPS__;
    var bpTotal = STATIC_BPS.length;
    var bpPlaced = [], bpPending = [], bpFailed = [];

    function tryPlaceBp(bp, mod, when) {
        try {
            var target = mod.base.add(bp.static_addr);
            Interceptor.attach(target, {
                onEnter: function (args) {
                    var a = [];
                    for (var k = 0; k < 4; k++) {
                        try { a.push(args[k].toString()); } catch (e) { a.push(null); }
                    }
                    send({ kind: 'call', symbol: bp.label, tid: this.threadId,
                           args: a, str_arg: null, is_static_bp: true,
                           backtrace: grabBacktrace(this.context, bp.label),
                           ts: Date.now() / 1000 });
                }
            });
            bpPlaced.push({ label: bp.label, so: bp.so_name,
                            static_addr: bp.static_addr,
                            runtime: target.toString(), when: when || 'immediate' });
            return true;
        } catch (e) {
            bpFailed.push({ label: bp.label, so: bp.so_name,
                            static_addr: bp.static_addr,
                            error: String(e).slice(0, 120) });
            return false;
        }
    }

    function bpsForModule(name) {
        var rest = [];
        bpPending.forEach(function (bp) {
            if (bp.so_name === name) {
                var mod = Process.findModuleByName(name);
                if (mod && tryPlaceBp(bp, mod, 'late')) { return; }
            }
            rest.push(bp);
        });
        bpPending = rest;
    }

    STATIC_BPS.forEach(function (bp) {
        var mod = null;
        try { mod = Process.findModuleByName(bp.so_name); } catch (e) { mod = null; }
        if (mod) {
            if (!tryPlaceBp(bp, mod, 'immediate')) { /* 已记入 failed */ }
        } else {
            bpPending.push(bp);
        }
    });
    send({ kind: 'bps', placed: bpPlaced, pending: bpPending.map(function(b){
        return {label: b.label, so: b.so_name, static_addr: b.static_addr};
    }), failed: bpFailed, total: bpTotal });

    // 1) 模块加载观察
    Process.attachModuleObserver({
        onAdded: function (m) {
            var key = m.name + '|' + m.base.toString();
            if (existing[key]) { return; }
            existing[key] = true;
            send({ kind: 'module_load', action: 'added', name: m.name,
                   base: m.base.toString(), size: m.size, path: m.path,
                   ts: Date.now() / 1000 });
            // 新模块出现 -> 把等它的延迟断点补上，并如实回报补下结果
            if (bpPending.length) {
                var beforeLen = bpPlaced.length, beforeFail = bpFailed.length;
                bpsForModule(m.name);
                if (bpPlaced.length > beforeLen || bpFailed.length > beforeFail) {
                    send({ kind: 'bps_late',
                           placed: bpPlaced.slice(beforeLen),
                           failed: bpFailed.slice(beforeFail),
                           still_pending: bpPending.map(function(b){
                               return {label: b.label, so: b.so_name}; }),
                           for_module: m.name,
                           ts: Date.now() / 1000 });
                }
            }
        },
        onRemoved: function (m) {
            delete existing[m.name + '|' + (m.base ? m.base.toString() : '')];
            send({ kind: 'module_load', action: 'removed', name: m.name,
                   base: null, size: 0, path: null, ts: Date.now() / 1000 });
        }
    });

    // 2) 按导出符号下 hook（启动早期不知道地址，符号名最实用）
    var SYMS = __SYMS__;
    var PER_SYM = __PER_SYM__;
    // (11) 第十一次修改（2026-11-05）：给调用事件采集**调用栈**。
    //      为什么默认只取前 N 次：backtrace 每次调用都要遍历栈帧并读内存，
    //      而启动阶段 malloc 能调两万多次——全量取栈会让 app 启动慢一个数量级。
    //      "谁第一次调用它"才是最有价值的信息，故默认每个符号只对前 1 次取栈。
    var BT_DEPTH = __BT_DEPTH__;
    var BT_LIMIT = __BT_LIMIT__;
    var btCount = {};
    function grabBacktrace(ctx, name) {
        if (BT_DEPTH <= 0) { return null; }
        var used = btCount[name] || 0;
        if (used >= BT_LIMIT) { return null; }
        btCount[name] = used + 1;
        // (12) 第十二次修改（2026-11-05）：改用 Backtracer.FUZZY。
        //      bug 原因：ACCURATE 依赖 x29 帧指针，而现代 ARM64 代码普遍
        //               -fomit-frame-pointer，实测 malloc/open 只能展开 2-3 层，
        //               而且前几帧地址**完全相同**（等于没有栈信息）。
        //               同一时刻 FUZZY 能展开 16 层且地址各不相同。
        //      解决方案：用 FUZZY（栈扫描）拿深栈；它的代价是可能混入误报，
        //               所以符号化时要过滤掉"不落在任何已加载模块内"的帧。
        try {
            return Thread.backtrace(ctx, Backtracer.FUZZY)
                         .slice(0, BT_DEPTH)
                         .map(function (a) { return a.toString(); });
        } catch (e) { return null; }
    }
    // (7) 第七次修改（2026-11-05）：对"第一个参数是路径/字符串"的常见函数，
    //     直接把参数读成字符串。否则 AI 只看到 open(x0=0x7d1b868587)，
    //     根本不知道打开了哪个文件——而"加载了什么、从哪加载"正是核心诉求。
    var STR_ARG = {
        'open': 0, 'openat': 1, 'fopen': 0, 'opendir': 0, 'access': 0,
        'stat': 0, 'lstat': 0, 'unlink': 0, 'rename': 0, 'mkdir': 0,
        'execve': 0, 'dlopen': 0, 'realpath': 0, 'chmod': 0, 'truncate': 0,
        'mkdirat': 1, 'faccessat': 1, 'stat64': 0
    };
    var symCount = {};
    var hooked = [], failed = [];
    SYMS.forEach(function (name) {
        var p = null;
        try { p = Module.findGlobalExportByName(name); } catch (e) { p = null; }
        if (!p) { failed.push(name); return; }
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    // (5) 第五次修改（2026-11-05）：每个符号单独限额。
                    //     bug 原因：原来所有事件共用 max_events 一个总上限，
                    //               而启动阶段 malloc 能调几万次，瞬间把名额吃光，
                    //               结果 module_load 一条都进不来（实测 load=0）。
                    //     解决方案：每个符号各自计数上限，热门函数不会挤掉
                    //               加载事件和其他符号；被截断的数量单独上报。
                    var c = symCount[name] || 0;
                    if (c >= PER_SYM) { return; }
                    symCount[name] = c + 1;
                    var a = [];
                    for (var i = 0; i < 4; i++) {
                        try { a.push(args[i].toString()); } catch (e) { a.push(null); }
                    }
                    // 路径类函数：把字符串参数读出来（长度上限防越界/卡死）
                    var strArg = null;
                    var si = STR_ARG[name];
                    if (si !== undefined) {
                        // (8) 第八次修改（2026-11-05）：用 readCString 而不是 readUtf8String。
                        //     bug 原因：readUtf8String 按严格 UTF-8 解码，遇到 C 字符串
                        //               结尾的 \0 会直接抛
                        //               "can't decode byte 0x00 in position N"，
                        //               于是所有路径参数一条都读不出来（实测全 null）。
                        //     解决方案：readCString 遇 \0 就停，正是 C 字符串的正确读法；
                        //               再加长度上限防止指针无效时卡死。
                        // (8) 第八次修改（2026-11-05）：readCString **不带 size**。
                        //     bug 原因：readUtf8String 遇 \0 直接抛异常读不出；
                        //               readCString(256) 带长度时行为异常，会把
                        //               后续内存里的字符串一起读进来
                        //               （实测得到 "/proc/self/cmdline�ANDROID_SOCKET_�…"）。
                        //     解决方案：用不带参数的 readCString()，它严格在 \0 停止；
                        //               再加一个长度护栏，防止无效指针读到超长垃圾。
                        try {
                            var sv = args[si].readCString();
                            if (sv !== null && sv.length > 0 && sv.length <= 512) {
                                strArg = sv;
                            }
                        } catch (e) { strArg = null; }
                    }
                    send({ kind: 'call', symbol: name, tid: this.threadId,
                           args: a, str_arg: strArg,
                           backtrace: grabBacktrace(this.context, name),
                           ts: Date.now() / 1000 });
                }
            });
            hooked.push(name);
        } catch (e) { failed.push(name); }
    });
    send({ kind: 'hooked', hooked: hooked, failed: failed,
           per_symbol_cap: PER_SYM });

    recv('stop', function () {
        // (11) 结束时把完整模块表带回去：调用栈里的原始地址要靠它才能
        // 折回 "so!函数+偏移"，用增量事件推出来的表是不全的。
        var mods = [];
        try {
            Process.enumerateModules().forEach(function (m) {
                mods.push({ name: m.name, base: m.base.toString(),
                            size: m.size, path: m.path });
            });
        } catch (e) {}
        send({ kind: 'stopped', modules: mods });
    });
})();
"""


def trace_app_startup(
    serial: str,
    package: str,
    symbols: list[str] | None = None,
    breakpoints: list | None = None,
    backtrace_depth: int = 8,
    backtrace_limit: int = 1,
    duration: float = 3.0,
    include_system: bool = False,
    max_events: int = 2000,
    keep_alive: bool = True,
) -> dict:
    """从**启动第一刻**开始，同时采集「模块加载」与「函数调用」，合成一条时间轴。

    (4) 第四次修改（2026-11-05）：新增本函数——把"加载时间轴"和"执行时间轴"
        真正打通，而不是只让两种事件格式上能混排。

    为什么必须 spawn：attach 到已运行的进程时，启动阶段的 so 加载早已结束、
    关键函数（如 malloc/init/解密）也早就跑过一轮，想抓从零开始的过程只能
    先 spawn 挂起 → 装观察器和 hook → 再 resume 放行。

    ## 参数

        package   要分析的包名（spawn 目标）
        symbols   要 hook 的**导出符号名**列表，如 ["malloc","open","read"]。
                  启动早期拿不到地址，所以这里只接受符号名（不是静态地址）。
                  找不到的符号会列在 failed_symbols 里，不静默忽略。
        duration  从 resume 那一刻开始的采集秒数
        include_system  是否保留 /system、/apex 等系统模块的加载事件
        keep_alive      采集后是否保留 app 进程（True 便于接着交互分析）
        max_events      事件上限

    ## 返回

        mode="spawn" / pid / package
        timeline        人类可读，加载与调用按时间混排，例如：
                          +0.000s 加载 liba.so
                          +0.012s 调用 malloc(x0=0x20)
        events[]        机器可读，两类统一带 ts / t_rel / delta_s
                        kind=module_load: {action, name, base, size, path}
                        kind=call:        {symbol, tid, args[]}
        hooked_symbols / failed_symbols
        stats           各类型计数、首个加载耗时、首个调用耗时
        baseline_count  观察器就位时的已加载模块数

    ## 已知限制（如实标注）

        · spawn 需要 app 允许调试；加固样本可能 spawn 失败（会返回 SPAWN_FAILED）
        · 只 hook 导出符号；内部函数需要先拿静态地址再走 set_breakpoint
        · 事件通过 send 回传，高频函数（如 malloc）会打到 max_events 上限
    """
    import time as _time

    pkg = (package or "").strip()
    if not pkg:
        return {"ok": False, "implemented": True, "code": "NO_PACKAGE",
                "error": "必须给 package（spawn 目标包名）"}
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("trace_app_startup", hint=f"frida 不可用：{exc}",
                              extra={"package": pkg})

    syms = [str(s) for s in (symbols or []) if str(s).strip()]

    # (10) 第十次修改（2026-11-05）：支持按**静态地址**下断点。
    #      为什么要它：symbols 只能 hook 导出符号，而壳/加固样本的关键函数
    #      （解密、校验、VM 分发器）几乎都是内部函数，没有导出名。
    #      格式：[{"so_name":"libx.so","static_addr":0x1234,"label":"可选"}]
    #      注意：启动早期目标 so 可能还没加载，JS 侧会挂起等待它被 dlopen 后再补下。
    sbps: list[dict] = []
    bp_errors: list[str] = []
    for i, bp in enumerate(breakpoints or []):
        if isinstance(bp, dict):
            so_name = str(bp.get("so_name") or bp.get("so") or "").strip()
            raw_addr = bp.get("static_addr", bp.get("addr"))
            label = str(bp.get("label") or "").strip()
        else:
            bp_errors.append(f"第 {i} 个断点不是 dict：{type(bp).__name__}")
            continue
        if not so_name:
            bp_errors.append(f"第 {i} 个断点缺 so_name")
            continue
        addr = _to_int(raw_addr, -1)
        if addr < 0:
            bp_errors.append(f"第 {i} 个断点 static_addr 无效：{raw_addr!r}")
            continue
        sbps.append({
            "so_name": so_name,
            "static_addr": addr,
            "label": label or f"{so_name}+{addr:#x}",
        })

    # 每个符号的单独特额：总预算的 1/4 分给每个符号，至少 50 条，
    # 保证热门函数不会独吞名额（加载事件另算，永不被挤）
    per_sym = max(50, int(max_events) // max(len(syms), 1) // 2) if syms else 0
    js = (_JS_APP_STARTUP
          .replace("__SYMS__", repr(syms).replace("'", '"'))
          .replace("__PER_SYM__", str(per_sym))
          .replace("__SBPS__", json.dumps(sbps).replace("'", '"'))
          .replace("__BT_DEPTH__", str(max(0, min(int(backtrace_depth), 32))))
          .replace("__BT_LIMIT__", str(max(0, int(backtrace_limit)))))

    events: list[dict] = []
    mods: list = []
    box: dict = {"ready": False, "hooked": [], "failed": [], "stopped": False,
                 "modules": [],
                 "baseline": 0, "t0": 0.0,
                 # 分类计数：加载与调用各自限额，避免互相挤占
                 "loads": 0, "calls": 0, "dropped_loads": 0, "dropped_calls": 0,
                 "bp_placed": [], "bp_pending": [], "bp_failed": [], "bp_total": 0,
                 "bp_late": []}
    dev = None
    pid = 0
    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        try:
            pid = dev.spawn([pkg])
        except Exception as exc:                          # noqa: BLE001
            return {"ok": False, "implemented": True, "code": "SPAWN_FAILED",
                    "error": (f"spawn {pkg} 失败：{exc}；常见原因：包名错、"
                              "app 不允许调试、frida 版本不匹配"),
                    "package": pkg}
        sess = dev.attach(pid)

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["baseline"] = int(payload.get("baseline") or 0)
                box["t0"] = float(payload.get("t0") or 0) / 1000.0
                return
            if kind == "hooked":
                box["hooked"] = payload.get("hooked") or []
                box["failed"] = payload.get("failed") or []
                return
            if kind == "bps_late":
                box.setdefault("bp_late", []).append({
                    "for_module": payload.get("for_module"),
                    "placed": payload.get("placed") or [],
                    "failed": payload.get("failed") or [],
                    "still_pending": payload.get("still_pending") or [],
                    "ts": payload.get("ts"),
                })
                # 延迟补下的断点也算已就位
                box["bp_placed"] = list(box.get("bp_placed") or []) + (payload.get("placed") or [])
                box["bp_failed"] = list(box.get("bp_failed") or []) + (payload.get("failed") or [])
                box["bp_pending"] = payload.get("still_pending") or []
                return
            if kind == "bps":
                box["bp_placed"] = payload.get("placed") or []
                box["bp_pending"] = payload.get("pending") or []
                box["bp_failed"] = payload.get("failed") or []
                box["bp_total"] = int(payload.get("total") or 0)
                return
            if kind == "stopped":
                box["stopped"] = True
                mods = payload.get("modules") or []
                if mods:
                    box["modules"] = mods
                return
            if kind == "module_load":
                # (5) 加载事件单独配额，永远不被高频函数挤掉
                if box["loads"] < max_events:
                    box["loads"] = box["loads"] + 1
                    events.append(payload)
                else:
                    box["dropped_loads"] = box["dropped_loads"] + 1
                return
            if kind == "call":
                if box["calls"] < max_events:
                    box["calls"] = box["calls"] + 1
                    events.append(payload)
                else:
                    box["dropped_calls"] = box["dropped_calls"] + 1
                return

        script = sess.create_script(js)
        script.on("message", _on_msg)
        script.load()

        t_ready = _time.time()
        while not (box["ready"] and (box["hooked"] or box["failed"]) 
                   or _time.time() - t_ready > 5.0):
            _time.sleep(0.02)
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "观察器 5 秒内没有就位", "package": pkg, "pid": pid}

        # 挂起期间就已经把 hook 装好了，此刻放行才算"从启动第一刻"开始
        try:
            dev.resume(pid)
            resumed_ok = True
        except Exception as exc:                          # noqa: BLE001
            resumed_ok = False
            box.setdefault("errors", []).append(f"resume 失败：{exc}")

        t_begin = _time.time()
        deadline = t_begin + max(0.1, float(duration))
        while _time.time() < deadline:
            if box["loads"] >= max_events and box["calls"] >= max_events:
                break
            _time.sleep(0.02)
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(20):
            if box["stopped"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "implemented": True, "code": "TRACE_FAILED",
                "error": f"{type(exc).__name__}: {exc}", "package": pkg, "pid": pid}
    finally:
        _detach_async(sess)
        if not keep_alive and pid:
            try:
                dev.kill(pid)
            except Exception:                             # noqa: BLE001
                pass

    # ---- 过滤系统模块 + 排序 + 算间隔 ----
    def _is_system(p) -> bool:
        if not p:
            return False
        s = str(p)
        return (s.startswith("/system") or "/system/" in s
                or s.startswith("/apex") or "/apex/" in s
                or s.startswith("/vendor") or "/vendor/" in s
                or s.startswith("/product") or "/product/" in s)

    kept = []
    dropped = 0
    for e in events:
        if e.get("kind") == "module_load" and not include_system and _is_system(e.get("path")):
            dropped += 1
            continue
        kept.append(e)

    kept.sort(key=lambda e: float(e.get("ts") or 0))
    first_ts = float(kept[0]["ts"]) if kept and kept[0].get("ts") else None
    prev_ts = None
    load_lines: list[str] = []
    call_lines: list[str] = []
    load_count = call_count = 0
    first_load_t = first_call_t = None
    # (6) 第六次修改（2026-11-05）：时间轴改为**分类输出**。
    #     bug 原因：原来把所有事件塞进一个 60 行的列表，而启动早期 malloc 能
    #               瞬间占满前 60 条，导致加载事件**在可读时间轴里完全看不见**
    #               （实测 14 个加载事件一条都没出现在 timeline 文本里）。
    #               数据是全的，但 AI 读到的是"只有 malloc"的假象。
    #     解决方案：加载与调用分别成段，各自限额；加载事件全部列出（通常不多），
    #               调用每个符号取前 20 条代表。两者的**完整时序仍在 events[] 里**。
    per_sym_lines: dict[str, int] = {}
    for i, e in enumerate(kept, start=1):
        e["seq"] = i
        ts = float(e.get("ts") or 0) or None
        e["delta_s"] = round(ts - prev_ts, 4) if (ts and prev_ts) else None
        e["t_rel"] = round(ts - first_ts, 4) if (ts and first_ts) else None
        if ts:
            prev_ts = ts
        rel = f"+{e['t_rel']:.3f}s" if e.get("t_rel") is not None else "+?"
        if e.get("kind") == "module_load":
            load_count += 1
            if e.get("action") == "added" and first_load_t is None:
                first_load_t = e.get("t_rel")
            act = "加载" if e.get("action") == "added" else "卸载"
            path = f"  ← {e.get('path')}" if e.get("path") else ""
            load_lines.append(f"{rel} {act} {e.get('name')}{path}")
        else:
            call_count += 1
            if first_call_t is None:
                first_call_t = e.get("t_rel")
            sym = str(e.get("symbol"))
            n = per_sym_lines.get(sym, 0)
            if n < 20:
                per_sym_lines[sym] = n + 1
                args = e.get("args") or []
                if e.get("str_arg"):
                    a_txt = f'(\"{e.get("str_arg")}\")'
                elif args:
                    a_txt = f"(x0={args[0]})"
                else:
                    a_txt = ""
                call_lines.append(f"{rel} 调用 {sym}{a_txt}")

    sections = []
    if load_lines:
        sections.append("【模块加载/卸载】共 %d 条\n%s" % (len(load_lines), "\n".join(load_lines)))
    else:
        sections.append("【模块加载/卸载】0 条（可能都被 include_system=False 过滤，"
                        "或该 app 启动阶段没有动态加载）")
    if call_lines:
        more = "（每个符号最多列 20 条，完整数据见 events）" if call_count > len(call_lines) else ""
        sections.append("【函数调用】共 %d 条%s\n%s"
                        % (call_count, more, "\n".join(call_lines)))
    lines = "\n\n".join(sections)

    out = {
        "ok": True,
        "implemented": True,
        "mode": "spawn",
        "package": pkg,
        "pid": pid,
        "events": kept[:max_events],
        "count": len(kept),
        "timeline": lines,
        "hooked_symbols": box["hooked"],
        "failed_symbols": box["failed"],
        "modules": box.get("modules") or mods,
        "static_breakpoints": {
            "requested": box["bp_total"],
            "placed": box["bp_placed"],
            "pending_on_load": box["bp_pending"],
            "failed": box["bp_failed"],
            "late_placed": box.get("bp_late") or [],
            "errors": bp_errors,
            "hint": ("pending_on_load 里的断点对应的 so 在挂起时还没加载，"
                     "会在它被 dlopen 后自动补下；所以它们仍可能命中"),
        },
        "baseline_count": box["baseline"],
        "dropped_system": dropped,
        "duration": duration,
        "per_symbol_cap": per_sym,
        "stats": {
            "module_load": load_count,
            "call": call_count,
            "first_load_t_rel": first_load_t,
            "first_call_t_rel": first_call_t,
            "dropped_loads": box["dropped_loads"],
            "dropped_calls": box["dropped_calls"],
        },
        "note": ("两类事件已合并排序：module_load 是 so 加载/卸载，"
                 "call 是 symbol 被调用。t_rel 是距第一条事件的秒数，"
                 "delta_s 是距上一条的秒数"),
    }

    # (9) 第九次修改（2026-11-05）：补结构化洞察，直接回答"加载后多久才有动静"。
    #     为什么需要：events[] 是全量数据，但"首个加载在几毫秒、首次调用比它早还是晚、
    #     每个符号第一次被调是什么时候"这些问题让 AI 自己遍历算，既慢又容易算错。
    #     这里一次算好，AI 直接引用即可。
    insights: dict = {}
    per_sym_first: dict[str, dict] = {}
    for e in kept:
        if e.get("kind") == "call":
            sym = str(e.get("symbol"))
            if sym not in per_sym_first:
                per_sym_first[sym] = {"t_rel": e.get("t_rel"),
                                      "ts": e.get("ts"),
                                      "x0": (e.get("args") or [None])[0],
                                      "str_arg": e.get("str_arg")}
    if per_sym_first:
        insights["per_symbol_first_call"] = per_sym_first

    loads = [e for e in kept if e.get("kind") == "module_load"
             and e.get("action") == "added"]
    if loads:
        insights["first_module_load"] = {
            "name": loads[0].get("name"),
            "t_rel": loads[0].get("t_rel"),
            "path": loads[0].get("path"),
        }
        insights["module_load_count_added"] = len(loads)

    # 关键结论：首次调用 vs 首次加载 谁先谁后
    if loads and per_sym_first:
        load_t = loads[0].get("t_rel")
        first_sym = min(per_sym_first.items(),
                        key=lambda kv: (kv[1].get("t_rel") is None,
                                        kv[1].get("t_rel") or 0))
        call_t = first_sym[1].get("t_rel")
        if load_t is not None and call_t is not None:
            if call_t < load_t:
                insights["verdict"] = (
                    f"首次函数调用（{first_sym[0]}，+{call_t:.3f}s）**早于**首次 so 加载"
                    f"（{loads[0].get('name')}，+{load_t:.3f}s）：说明进程在加载业务 so "
                    "之前就已经在跑基础库代码")
            else:
                insights["verdict"] = (
                    f"首次 so 加载在 +{load_t:.3f}s，之后的第一个调用是 "
                    f"{first_sym[0]}（+{call_t:.3f}s），相隔 {call_t - load_t:.3f}s")
    out["insights"] = insights
    if not keep_alive:
        out["killed_after"] = True
    if box.get("errors"):
        out["errors"] = box["errors"]
    return out


_JS_WATCH_MODULE = r"""
(function () {
    var mod = null;
    var cands = __SO_NAME__;          // 候选名列表，按优先级
    var mods = Process.enumerateModules();
    for (var ci = 0; ci < cands.length && mod === null; ci++) {
        var want = cands[ci];
        for (var mi = 0; mi < mods.length; mi++) {
            var m = mods[mi];
            var bn = m.name.split('/').pop();
            if (m.name === want || bn === want) { mod = m; break; }
        }
    }
    // (15) 第十五次修改（2026-11-06）：候选名全失败时，用**字节指纹**反查真实模块。
    //      bug 原因：本地文件被改名成与设备名毫无关系的名字时（如 sg_real.so），
    //               任何名字规范化都救不回来。此前只能报 MODULE_NOT_LOADED，
    //               用户得先去设备上查真实模块名——等于把通用问题丢回给人。
    //      解决方案：由 Python 侧提供「该 so 里某函数的原始机器码」作为指纹，
    //               在进程内各模块的对应偏移处比对字节，命中即认定是同一个模块。
    //               指纹取 16 字节 + 偏移，碰撞概率极低；不命中就不猜。
    var FINGERPRINTS = __FINGERPRINTS__;
    if (mod === null && FINGERPRINTS.length > 0) {
        var all = Process.enumerateModules();
        for (var fi = 0; fi < FINGERPRINTS.length && mod === null; fi++) {
            var fp = FINGERPRINTS[fi];
            for (var ai = 0; ai < all.length; ai++) {
                var cand = all[ai];
                if (fp.offset >= cand.size) { continue; }
                try {
                    var got = cand.base.add(fp.offset).readByteArray(fp.hex.length / 2);
                    if (got === null) { continue; }
                    var hex = Array.from(new Uint8Array(got))
                        .map(function (x) { return x.toString(16).padStart(2, '0'); })
                        .join('');
                    if (hex === fp.hex) {
                        mod = cand;
                        send({ kind: 'note',
                               message: '按字节指纹匹配到模块 ' + cand.name });
                        break;
                    }
                } catch (e) { /* 该模块不可读，跳过 */ }
            }
        }
    }

    if (mod === null) {
        send({ kind: 'error', code: 'MODULE_NOT_LOADED',
               message: '进程里找不到模块（试过 ' + cands.join(', ')
                        + '；字节指纹比对也未命中）' });
        return;
    }

    // (13) 第十三次修改（2026-11-06）：模块内函数级执行观察。
    //      bug 原因：用户断点下在函数入口却 0 命中，无法判断是「地址错」还是
    //                「这段代码根本没跑」。此前用 765 个探测点做实验，
    //                直接把目标进程搞崩（frida 连接断开、app 退出）。
    //      解决方案：① 只在**函数入口**下点（不按页撒点），密度低一个数量级；
    //                ② 分批 attach（每批之间让出执行权），避免一次性 patch 过多；
    //                ③ 只记录**偏移→次数**，不在 onEnter 里做任何重活；
    //                ④ 硬上限 max_points；超出预算时由 Python 侧**均匀采样**，
    //                   而不是截断（截断会让覆盖全部挤在区间头部）。
    //               ⑤ 每批之间 sleep BATCH_GAP_MS，避免密集 patch 时目标抖动。
    var TARGETS = __TARGETS__;
    var BATCH = __BATCH__;
    var BATCH_GAP_MS = __BATCH_GAP_MS__;
    var counts = {};
    var placed = 0, failed = 0;
    var failedDetail = [];      // 记录每个挂不上的点及原因，便于定位
    var listeners = [];

    function placeBatch(start) {
        var end = Math.min(start + BATCH, TARGETS.length);
        for (var i = start; i < end; i++) {
            var off = TARGETS[i];
            try {
                (function (o) {
                    listeners.push(Interceptor.attach(mod.base.add(o), {
                        onEnter: function () {
                            counts[o] = (counts[o] || 0) + 1;
                        }
                    }));
                })(off);
                placed++;
            } catch (e) {
                failed++;
                if (failedDetail.length < 20) {
                    failedDetail.push({offset: off, error: String(e).slice(0, 120)});
                }
            }
        }
        return end;
    }

    var cursor = 0;
    function step() {
        cursor = placeBatch(cursor);
        if (cursor < TARGETS.length) {
            setTimeout(step, BATCH_GAP_MS);   // 批次间留间隔，避免密集 patch 拖垮目标
        } else {
            send({ kind: 'ready', module: mod.name,
                   base: mod.base.toString(), size: mod.size,
                   placed: placed, failed: failed, total: TARGETS.length,
                   failed_detail: failedDetail });
        }
    }
    step();

    recv('stop', function () {
        listeners.forEach(function (l) {
            try { if (l && typeof l.detach === 'function') { l.detach(); } } catch (e) {}
        });
        send({ kind: 'stopped', counts: counts, placed: placed, failed: failed });
    });
})();
"""


# 目标进程消失时 frida 抛出的异常文本特征（大小写不敏感匹配）。
# 为什么要单列：这类失败与"钩子装不上"是完全不同的两回事——
# 前者说明进程已经没了，重试、换参数都没意义；后者才需要调探针策略。
# 若都归到 WATCH_FAILED，调用方会误以为"还可以再试一次"。
_TARGET_GONE_MARKERS = (
    "ProcessNotFound",
    "process is gone",
    "Process crashed",
    "no such process",
    "terminated",
    "unable to find process",
)


def _is_target_gone(exc: BaseException) -> bool:
    """判断异常是否表示"目标进程已退出/崩溃"。

    同时看异常**类名**与文本：frida 抛的是 ProcessNotFoundError，
    str(exc) 里未必带 "ProcessNotFound"，把类型名一并拼进来才不会漏判。
    """
    text = f"{type(exc).__name__}: {exc}".lower()
    return any(m.lower() in text for m in _TARGET_GONE_MARKERS)


def _summarize_failed(failed_detail: list) -> dict:
    """按错误文本把"挂不上的探针"归类计数。

    为什么需要：failed_detail 是逐点明细，几十条时人眼看不出主要矛盾。
    实测失败大头是 frida 对"函数内部块"报的
    `unable to intercept function ... please file a bug`——这类点根本
    不是真入口，换个区间就能消掉，因此值得单独一个计数。

    只统计明细里出现过的条目；明细被 JS 侧截断（上限 20 条）时，
    这里的和会**小于 failed 总数**，故额外给 detail_count 让调用方看得出差距。
    """
    out = {"intercept_unsupported": 0, "other": 0, "detail_count": 0}
    for item in failed_detail or ():
        err = ""
        if isinstance(item, dict):
            err = str(item.get("error") or "")
        else:
            err = str(item or "")
        out["detail_count"] += 1
        if "unable to intercept" in err.lower():
            out["intercept_unsupported"] += 1
        else:
            out["other"] += 1
    return out


def watch_module(
    serial: str,
    pid: int,
    so_name: str,
    duration: float = 5.0,
    max_points: int = 50,
    offset_range: list | None = None,
    batch: int = 20,
    batch_interval_ms: int = 200,
) -> dict:
    """观察某个 so 里**哪些函数真的被执行过**，回答「代码到底跑没跑到这里」。

    (13) 第十三次修改（2026-11-06）：新增本函数。

    为什么需要它：断点下在函数入口却一次都不命中时，有两种截然不同的原因——
        ① 地址算错了（静态偏移 / 模块基址 / 装错文件）
        ② 这段代码在当前场景下**根本没被执行**
    光看"命中 0 次"分不清是哪一种。本工具在模块内**所有函数入口**下轻量探针，
    直接给出"实际被执行的是哪几个偏移、各多少次"，把①和②区分开。

    ## 与 trace_code 的区别

        trace_code   用 Stalker 跟随线程，采集"谁调用了谁"，开销大、易把目标拖垮
        watch_module 只在函数入口挂 Interceptor，只数次数，**开销小得多**；
                     代价是只看得到"函数级"粒度，看不到具体调用边

    ## 参数

        so_name       模块名（`libfoo.so` 或完整路径都行，按 basename 匹配）
        duration      观察秒数
        max_points    最多下多少个探针（默认 400）。函数特别多时按地址升序取前 N 个
        offset_range  可选 [起始偏移, 结束偏移]，只观察这段地址内的函数
        batch         每批 attach 多少个探针（默认 50）。分批是为了让出执行权，
                      一次性挂几百个探针会把目标拖垮（实测 765 个直接崩进程）

    ## 返回

        hot[]       按次数降序，每条 {offset, offset_hex, hits}
        executed    被执行过的函数数
        placed/failed/total  探针布置情况（**失败数非 0 要当心**）
        verdict     一句话结论：
                    "观察到 N 个函数被执行" / "整段时间内所有探针 0 命中"

    ## 已知限制

        · 只覆盖**函数入口**：只有被调的函数的**第一条指令**会命中；函数内部
          的某段代码被执行不代表入口被执行（尤其 VM 分发器）
        · max_points 截断时，只观察地址最小的那批函数，结论可能不全
        · 探针越多越可能影响目标性能，长 duration 请配合较小 max_points
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("watch_module", hint=f"frida 不可用：{exc}",
                              extra={"so_name": so_name})

    name = str(so_name or "").strip()
    if not name:
        return {"ok": False, "implemented": True, "code": "NO_SO_NAME",
                "error": "必须给 so_name"}
    # (14) 第十四次修改（2026-11-06）：不再要求调用方传「设备上的名字」。
    #      bug 原因：上一版加了 device_name 参数，等于让用户手工填别名——
    #               那是给单个 app 打补丁，换个样本还得再填一次。
    #      解决方案：JS 侧按**候选列表**匹配（原名 + 去版本号名 + 去 lib 前缀名），
    #               与 mcp_server 层的 _pick_so_by_name 同一套思路；
    #               调用方只需给 mda 里的键。
    cand_names = _module_name_candidates(name)

    # 目标偏移从 mda 的静态模型里取（函数入口），比 JS 侧枚举更可靠
    offsets: list[int] = []
    # (19) 第十九次修改（2026-11-06）：so 必须在 try 之外先初始化。
    #      bug 原因：so 原本只在 try 块内赋值，一旦取会话/遍历函数表抛异常，
    #               后面的"函数密度"计算（用到 so.size）就会抛
    #               NameError: name 'so' is not defined——报错信息与真实
    #               原因完全无关，极难排查。
    #      解决方案：进 try 之前先置 None；后续所有对 so 的使用都做 None 判断。
    so = None
    try:
        from mcp_server.tools import get_session

        sess0 = get_session()
        for key, mod in (getattr(sess0, "modules", {}) or {}).items():
            if key == name or key.rsplit("/", 1)[-1] == name.split("/")[-1]:
                so = mod
                break
        if so is not None:
            fns = getattr(so, "functions", {}) or {}
            vals = fns.values() if isinstance(fns, dict) else list(fns)
            offs = sorted({int(getattr(f, "addr", 0) or 0) for f in vals})
            offs = [o for o in offs if o > 0]
            if offset_range and len(offset_range) == 2:
                lo, hi = int(offset_range[0]), int(offset_range[1])
                offs = [o for o in offs if lo <= o < hi]
            offsets = offs
    except Exception:                                     # noqa: BLE001
        offsets = []

    if not offsets:
        return {
            "ok": False, "implemented": True, "code": "NO_FUNCTION_TABLE",
            "error": (f"mda 里没有 {name} 的函数表；先 load_so 载入该 so"
                      "（载入后本工具才知道该在哪些偏移下探针）"),
            "so_name": name,
        }

    total_fns = len(offsets)
    cap = max(1, min(int(max_points), 4000))
    truncated = total_fns > cap

    # (14) 第十四次修改（2026-11-06）：探针点改为**均匀采样**，并支持分批间隔。
    #      bug 原因：① 原实现 `offsets[:cap]` 只取地址最小的 N 个——
    #                  带 offset_range 观察 VM 解释器时，区间里函数极密集
    #                  （实测 12KB 内 78 个入口，平均 92 字节一个），
    #                  取前 N 个会全部挤在区间头部，越靠后越没有覆盖，
    #                  得出的"哪些函数被执行"结论严重偏斜；
    #               ② 一次性 attach 全部探针会让目标抖动，某些 frida 版本
    #                  在密集 patch 时直接崩溃（实测 max_points=400 时崩过）；
    #               ③ 探针点里混入了"函数内部块"（非真正入口），frida 对这类
    #                  地址会报 "unable to intercept function ... please file a bug"，
    #                  本次实测 78 个点里 19 个挂不上。
    #      解决方案：① 超出预算时按**等间隔取样**（保留首尾），而不是截断；
    #                ② 每批之间 sleep batch_interval_ms，给目标喘息；
    #                ③ 记录每个点失败的具体原因，并在返回里如实上报
    #                   placed / failed / failed_detail，让调用方看得见。
    if total_fns > cap:
        step = total_fns / float(cap)
        picked = [offsets[min(int(i * step), total_fns - 1)] for i in range(cap)]
        targets = sorted(set(picked))
        sampling = "uniform"
    else:
        targets = list(offsets)
        sampling = "full"

    # 字节指纹：名字完全对不上时用它反查模块（取前 2 个函数入口的机器码即可）
    fingerprints: list[dict] = []
    if so is not None:
        for off in targets[:2]:
            try:
                raw = _read_static_bytes(so, off, 16)
                if raw and len(raw) == 16:
                    fingerprints.append({"offset": int(off), "hex": raw.hex()})
            except Exception:                             # noqa: BLE001
                continue

    js = (_JS_WATCH_MODULE
          .replace("__SO_NAME__", json.dumps(cand_names))
          .replace("__FINGERPRINTS__", json.dumps(fingerprints))
          .replace("__TARGETS__", json.dumps(targets))
          .replace("__BATCH__", str(max(1, min(int(batch), 200))))
          .replace("__BATCH_GAP_MS__", str(max(0, min(int(batch_interval_ms), 5000)))))

    box: dict = {"ready": False, "stopped": False, "counts": {},
                 "placed": 0, "failed": 0, "module": "", "base": "",
                 "size": 0, "err": "", "failed_detail": []}
    dev = None
    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["placed"] = int(payload.get("placed") or 0)
                box["failed"] = int(payload.get("failed") or 0)
                box["failed_detail"] = payload.get("failed_detail") or []
                box["module"] = payload.get("module") or ""
                box["base"] = payload.get("base") or ""
                box["size"] = payload.get("size") or 0
                return
            if kind == "stopped":
                box["stopped"] = True
                box["counts"] = payload.get("counts") or {}
                return
            if kind == "note":
                box.setdefault("notes", []).append(payload.get("message") or "")
                return
            if kind == "error":
                box["err"] = payload.get("message") or payload.get("code") or "error"

        script = sess.create_script(js)
        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box["err"] and _time.time() - t0 < 20.0:
            _time.sleep(0.02)
        if box["err"]:
            return {"ok": False, "implemented": True, "code": "WATCH_FAILED",
                    "error": box["err"], "so_name": name}
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "探针布置 20 秒内未完成（探针可能过多）",
                    "so_name": name, "placed": box["placed"]}

        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(50):
            if box["stopped"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        # (22) 第二十二次修改（2026-11-06）：区分"目标进程没了"与"钩子装不上"。
        #      bug 原因：采集期间任何异常都返回 WATCH_FAILED，于是目标崩溃/退出
        #                这种**不可重试**的失败，与钩子冲突这类**可重试**的失败
        #                长得一模一样，调用方会拿同一套策略反复重试白费时间。
        #      解决方案：按异常类名+文本判定目标是否已消失，是则返回 TARGET_DIED
        #                并说明"探针随进程消失"；其余仍归 WATCH_FAILED。
        if _is_target_gone(exc):
            return {"ok": False, "implemented": True, "code": "TARGET_DIED",
                    "error": (f"目标进程已退出/崩溃，探针随进程消失："
                              f"{type(exc).__name__}: {exc}"),
                    "so_name": name, "pid": int(pid),
                    "placed": box["placed"], "failed": box["failed"],
                    "failed_detail": box.get("failed_detail") or [],
                    "failed_summary": _summarize_failed(box.get("failed_detail") or []),
                    "hint": "重新 attach 前先确认进程还在（PID 会变）；"
                            "若反复崩溃，多半是探针过多，降低 max_points 或缩小 offset_range"}
        return {"ok": False, "implemented": True, "code": "WATCH_FAILED",
                "error": f"{type(exc).__name__}: {exc}", "so_name": name}
    finally:
        _detach_async(sess)

    counts = box["counts"] or {}
    hot = []
    for k, v in counts.items():
        try:
            off = int(k)
        except (TypeError, ValueError):
            continue
        if v:
            hot.append({"offset": off, "offset_hex": hex(off), "hits": int(v)})
    hot.sort(key=lambda x: -x["hits"])

    executed = len(hot)
    sample_note = "（均匀采样）" if sampling == "uniform" else ""
    if executed:
        verdict = (f"观察到 {executed} 个函数被执行（共下 {box['placed']} 个探针{sample_note}），"
                   f"最热的是 {hot[0]['offset_hex']}（{hot[0]['hits']} 次）")
    else:
        verdict = (f"整段观察期内 {box['placed']} 个函数入口{sample_note}**全部 0 命中**："
                   "要么该模块在当前场景没有执行，要么探针没覆盖到真正跑的代码")

    out = {
        "ok": True,
        "implemented": True,
        "so_name": name,
        "module": box["module"],
        "base": box["base"],
        "size": box["size"],
        "pid": int(pid),
        "duration": duration,
        "placed": box["placed"],
        "failed": box["failed"],
        "total_functions": total_fns,
        "sampling": sampling,
        "truncated": truncated,
        "executed": executed,
        "hot": hot[:200],
        "failed_detail": box.get("failed_detail") or [],
        # (22) 第二十二次修改（2026-11-06）：failed 的聚合分类。
        #      bug 原因：failed_detail 是逐点明细，几十条时看不出主要矛盾；
        #                实测大头是 frida 对"函数内部块"的
        #                "unable to intercept"——这类点不是真入口，
        #                换个区间就能消掉，与其它错误该分开看。
        #      解决方案：按 error 文本归类计数，附 detail_count 说明明细
        #                是否被 JS 侧截断（上限 20 条），避免数量对不上时误解。
        "failed_summary": _summarize_failed(box.get("failed_detail") or []),
        "verdict": verdict,
        "note": ("探针只下在**函数入口**；函数内部某段被执行不代表入口被执行。"
                 "failed 非 0 说明有探针没挂上，结论可能不全"),
    }

    # (22) 第二十二次修改（2026-11-06）：给"部分布上 / 一个都没布上"语义化 code。
    #      bug 原因：原来只返回 ok:True + placed/failed 两个数字，调用方（AI/前端）
    #                看到 ok:True 就当采集成功，容易忽略"80 个点只挂上 12 个"，
    #                据此下结论会错得毫无察觉；而 placed==0 时更是彻底空转，
    #                却与正常成功长得一模一样。
    #      解决方案：成功路径按 placed/failed 分三档——
    #                ① placed>0 且 failed>0 → partial:True + PLACED_PARTIAL
    #                ② placed==0 且 failed>0 → PLACED_NONE（完全失败）
    #                ③ 全成功 → 不加 code，保持与旧调用方兼容
    #                verdict 同步说清"只布上多少、多少失败"，结论不被高估。
    _placed = int(box["placed"] or 0)
    _failed = int(box["failed"] or 0)
    if _placed <= 0 and _failed > 0:
        out["code"] = "PLACED_NONE"
        out["partial"] = True
        verdict = (f"**一个探针都没布上**（{_failed} 个全部失败）：本次没有采到任何执行数据，"
                   "失败明细见 failed_detail / failed_summary。"
                   "多为选中的点不是可挂钩的函数入口，建议缩小 offset_range，"
                   "或先用 probe_hits 逐个验证真入口")
        out["verdict"] = verdict
    elif _failed > 0:
        out["code"] = "PLACED_PARTIAL"
        out["partial"] = True
        verdict = (f"{verdict}。但**只布上 {_placed} 个探针、{_failed} 个失败**，"
                   f"覆盖不全，结论可能遗漏未被观察到的函数")
        out["verdict"] = verdict
    if box.get("notes"):
        out["notes"] = box["notes"]

    # (17) 第十七次修改（2026-11-06）：把"要不要加大探针数"的判断依据交给 AI。
    #      bug 原因：原来 max_points 是个固定默认值，AI 不知道当前这个 so
    #               函数有多密、加多少会崩，只能瞎猜——猜大了崩进程，猜小了没覆盖。
    #      解决方案：返回里附 recommendation：
    #               ① 当前区间的**函数密度**（每 KB 多少个入口）；
    #               ② 失败率（挂不上的比例）——失败率高说明点选得不好或太密；
    #               ③ 一个**安全上限估计**（按密度和失败率推算）；
    #               ④ 明确的下一步建议（缩小 range / 增大 max_points / 保持）。
    #                AI 拿着这些数就能自己决定下一次的 max_points。
    # 密度：分母优先用 offset_range 宽度，其次用 so.size；两者都没有就给 None
    span_kb = None
    if offset_range and len(offset_range) == 2:
        span_kb = max(1e-9, (int(offset_range[1]) - int(offset_range[0])) / 1024.0)
    elif so is not None:
        span_kb = max(1e-9, int(getattr(so, "size", 0) or 0) / 1024.0)
    density = (total_fns / span_kb) if span_kb else None
    fail_rate = (box["failed"] / float(box["placed"] + box["failed"])
                 if (box["placed"] + box["failed"]) else 0.0)
    rec: dict = {
        "function_density_per_kb": round(density, 2),
        "fail_rate": round(fail_rate, 3),
        "placed": box["placed"],
        "failed": box["failed"],
    }
    if fail_rate > 0.15:
        rec["advice"] = (f"失败率 {fail_rate:.0%} 偏高：这些多是被选中但无法挂钩的"
                         "函数内部块。建议缩小 offset_range 到更精确的区间，"
                         "或换用 probe_hits 逐个验证真入口")
        rec["suggested_max_points"] = max(10, int(box["placed"] * 0.8))
    elif truncated:
        step_ms = 1000.0 * (cap * max(1, int(batch_interval_ms)) / 1000.0) / max(1, cap)
        rec["advice"] = (f"已均匀采样（覆盖全区间）。若要在同一区间提高覆盖率，"
                         f"可把 max_points 提到 {min(cap * 4, 1600)}；"
                         "经验上每个探针约增加数百微秒开销，"
                         "密集区间建议配 batch<=20、batch_interval_ms>=200")
        rec["suggested_max_points"] = min(cap * 4, 1600)
    else:
        rec["advice"] = "当前已全覆盖该区间，无需加大 max_points"
        rec["suggested_max_points"] = cap
    out["recommendation"] = rec

    if truncated:
        out["truncated_note"] = (
            f"函数共 {total_fns} 个，按**均匀采样**观察了 {cap} 个"
            "（不是只取地址最小的那些）；用 offset_range 缩小范围可提高针对性")
    return out


_JS_VERIFY_BP = r"""
(function () {
    var RUNTIME = ptr(__RUNTIME__);
    var out = {};
    // 1) 当前内存字节
    try {
        var cur = RUNTIME.readByteArray(16);
        out.current_hex = cur === null ? null : Array.from(new Uint8Array(cur))
            .map(function (x) { return x.toString(16).padStart(2, '0'); }).join('');
    } catch (e) {
        out.current_hex = null;
        out.read_error = String(e);
    }
    // 2) frida 是否真的在这个地址上装了钩子：
    //    用 Interceptor.attach 同一个地址，若能成功即说明地址可挂钩。
    //    更直接的判据是看该地址首字节是否为 frida 的跳转指令（通常被替换）。
    //    但 frida 会"透明"地让我们读到原始字节，所以不能用字节判断，
    //    改为报告 Interceptor 的内部计数：attach 一次再 detach，看是否触发。
    out.probe_ok = true;
    out.runtime = RUNTIME.toString();

    // 3) 该地址是否在 frida 的 hook 表里 —— 通过重新 attach 同名地址的
    //    InvocationListener 观察是否抛 "already attached"
    try {
        var l = Interceptor.attach(RUNTIME, { onEnter: function () {} });
        out.already_hooked = false;
        try { l.detach(); } catch (e) {}
    } catch (e) {
        var msg = String(e);
        out.already_hooked = msg.indexOf('already') >= 0 || msg.indexOf('busy') >= 0;
        out.attach_error = msg;
    }
    send(out);
})();
"""


def verify_breakpoint(serial: str, pid: int, so_name: str, static_addr: int,
                      bp_id: str = "") -> dict:
    """检查一个断点**到底有没有真的生效**，以及它所在位置是否会被执行。

    (17) 第十七次修改（2026-11-06）：新增。
        为什么需要：`set_breakpoint` 返回 `set: true` 只说明"静态地址换算成功、
        frida 接受了挂钩请求"，**不代表断点真的 armed，更不代表那段代码会被执行**。
        实测就出现过：断点返回成功、程序确实在跑，但一次都不命中——
        原因是该地址所在的函数根本没有被执行（VM 分发器的入口桩）。

    ## 返回里每一项的含义

        current_hex     该地址当前的内存字节（用于与文件原始字节对比）
        original_hex    从本地 so 文件读到的原始字节
        bytes_match     两者是否一致。**注意**：frida 会让我们读到"原始字节"，
                        所以一致**不代表没挂钩**，只能说明读到的内容正确
        already_hooked  该地址是否已被装过钩子（frida 报 already attached）
        hits_since_set  这个 bp_id 自设置以来的命中数（0 说明一次都没进）
        executed_hint   结合 watch_module 语境的提示（有 hits 才可能被执行）

    ## 怎么用这个结果判断问题

        hits > 0                        → 断点正常工作
        hits == 0 且 already_hooked     → 钩子装上了，但这段代码没被执行
                                          （用 watch_module 看真正在跑的是哪些偏移）
        hits == 0 且 not already_hooked → 钩子没装上，检查地址/模块是否正确
        bytes_match == false            → 地址对应错了文件（或文件版本不同）

    参数：
        so_name       mda 里的 so 键（支持与设备名自动匹配）
        static_addr   静态偏移
        bp_id         可选，形如 "serial:pid:so:5b76c"；给了就查它的命中数
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("verify_breakpoint", hint=f"frida 不可用：{exc}",
                              extra={"so_name": so_name})

    result: dict = {
        "ok": True, "implemented": True,
        "so_name": so_name, "static_addr": int(static_addr),
        "static_hex": hex(int(static_addr)),
    }

    # 1) 从 mda 静态模型取原始字节
    so = None
    try:
        from mcp_server.tools import get_session

        so = _find_loaded_so(get_session(), so_name)
        raw = _read_static_bytes(so, int(static_addr), 16) if so is not None else b""
        result["original_hex"] = raw.hex() if raw else None
        result["mda_key"] = getattr(so, "name", None) if so is not None else None
    except Exception:                                     # noqa: BLE001
        result["original_hex"] = None

    # 2) 运行时地址
    dev = None
    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        # (18) 第十八次修改（2026-11-06）：模块枚举没有 Python 便捷 API。
        #      bug 原因：先写成 Device.enumerate_modules 又写成
        #               Session.enumerate_modules，两个都不存在（frida 17 里
        #               模块枚举只能在 JS 侧做 Process.enumerateModules()），
        #               导致探测直接抛 AttributeError。
        #      解决方案：复用项目里已经实现好的 dyn.rebase.Rebase——它就是
        #               用 JS 枚举模块的；按候选名 + basename 双向比对。
        # (18) 第十八次修改（2026-11-06）：模块枚举走 JS，不用 Rebase。
        #      bug 原因：先写成 Device.enumerate_modules、又写成
        #               Session.enumerate_modules，两者都不存在；改用 Rebase 后
        #               它内部又 device.attach 一次（本函数已经 attach 过），
        #               双重 attach 让耗时涨到 28 秒。
        #      解决方案：直接在**已建立的会话**里跑 Process.enumerateModules()，
        #               既避免重复 attach，也避免依赖 Rebase 的生命周期。
        mod = None
        cands = _module_name_candidates(so_name)
        sess = dev.attach(int(pid))
        mods_box: dict = {}

        def _list_modules() -> None:
            try:
                sc = sess.create_script(
                    "send(Process.enumerateModules().map(function(m){"
                    "return {name:m.name, base:m.base.toString(), size:m.size};}));")
                got: list = []
                sc.on("message", lambda m, d: got.extend(m.get("payload") or []))
                sc.load()
                t1 = _time.time()
                while not got and _time.time() - t1 < 5.0:
                    _time.sleep(0.02)
                mods_box["list"] = got
            except Exception as exc:                      # noqa: BLE001
                mods_box["error"] = f"{type(exc).__name__}: {exc}"

        _list_modules()
        all_mods = mods_box.get("list") or []

        # (23) 第二十三次修改（2026-11-06）：
        #      bug 原因：目标已被 set_breakpoint 占用会话时，这里再 dev.attach 一次
        #                会在部分 frida 版本上拿不到可用脚本 → 模块列表为空 →
        #                报 MODULE_NOT_LOADED，把"已经下好断点"的现场判成"模块没加载"。
        #                实测：先 set_breakpoint 再 verify_breakpoint 必现。
        #      解决方案：枚举失败时改用 **service 里已有会话**的模块表（rb 里就有缓存），
        #                不依赖新建的第二个 attach；两者都没有才如实报错。
        if not all_mods:
            try:
                from dyn.service import get_dyn

                svc0 = get_dyn()
                tgt0 = svc0._targets.get(f"{serial}:{int(pid)}")   # noqa: SLF001 - 只读
                rb0 = getattr(tgt0, "rb", None) if tgt0 is not None else None
                if rb0 is not None:
                    cached = list(getattr(rb0, "_modules", []) or [])
                    if not cached:
                        cached = rb0.refresh_modules()
                    all_mods = [{"name": getattr(m, "name", ""),
                                 "base": hex(int(getattr(m, "base", 0) or 0)),
                                 "size": int(getattr(m, "size", 0) or 0)}
                                for m in cached]
                    if all_mods:
                        result["modules_from"] = "existing_session"
            except Exception:                             # noqa: BLE001
                pass
        for m in all_mods:
            nm = str(m.get("name") or "")
            bn = nm.rsplit("/", 1)[-1]
            if nm in cands or bn in cands:
                mod = m
                break
        # (19) 第十九次修改（2026-11-06）：名字匹配失败时用**字节指纹**反查。
        #      bug 原因：本地文件被改名成与设备名无关的名字（sg_real.so）时，
        #               _module_name_candidates 生成的候选里根本没有
        #               libsgmainso，名字匹配必然全失败——verify_breakpoint
        #               于是拿不到模块，只能返回 None，表现为"探测什么都没做"。
        #               watch_module 早已有指纹兜底，这里补齐，保持两个工具一致。
        #      解决方案：把该静态偏移处的原始 16 字节，与每个候选模块同偏移处
        #               的内存字节比对，一致即认定为同一模块（不猜、不模糊匹配）。
        # (24) 第二十四次修改（2026-11-06）：指纹比对改为**一次脚本批量读**。
        #      bug 原因：上一版对每个候选模块各 create_script + load 一次，
        #                441 个模块就是 441 次脚本往返，实测超过 60 秒才走完，
        #                实际表现为"验证超时 → 报 MODULE_NOT_LOADED"，
        #                看起来像模块真的没加载，其实是比对太慢。
        #      解决方案：把「所有候选模块基址 + 偏移」打包成一个 JS 脚本一次读完，
        #                在 Python 侧做字节比对；只建一个脚本。
        # (25) 第二十五次修改（2026-11-06）：指纹改为**两个偏移取交集**。
        #      bug 原因：单个 16 字节指纹并不唯一——实测 sg_real.so 在 0x5bc48
        #                处的 16 字节，在 libpdfium.so 的同一偏移处**字节完全相同**，
        #                于是指纹先把错误的模块认了下来，断点验证对着错模块做，
        #                必然得出"找不到模块/字节不匹配"的荒唐结论。
        #      解决方案：取同两个不同函数入口的 16 字节，**两个都命中**才算同一模块。
        #                实测单指纹有 1 个假阳性（libpdfium），双指纹交集只剩
        #                libsgmainso-6.7.260202.so，唯一命中。
        if mod is None and so is not None:
            try:
                fns_all = getattr(so, "functions", {}) or {}
                fvals = fns_all.values() if isinstance(fns_all, dict) else list(fns_all)
                offs = sorted({int(getattr(f, "addr", 0) or 0) for f in fvals})
                offs = [o for o in offs if o > 0][:2]
                fps = []
                for o in offs:
                    r2 = _read_static_bytes(so, o, 16)
                    if r2 and len(r2) == 16:
                        fps.append((o, r2.hex()))
            except Exception:                             # noqa: BLE001
                fps = []
            if fps and all_mods:
                need = max(o for o, _h in fps)
                probes = []
                for m in all_mods:
                    try:
                        m_base = m.get("base")
                        m_base = int(m_base, 16) if isinstance(m_base, str) else int(m_base)
                        m_size = int(m.get("size") or 0)
                    except (TypeError, ValueError):
                        continue
                    if need >= m_size:
                        continue
                    probes.append((m, m_base))
                if probes:
                    try:
                        addrs = []
                        for _m, b in probes:
                            for o, _h in fps:
                                addrs.append(b + o)
                        sc2 = sess.create_script(
                            "var A = " + json.dumps(addrs) + ";"
                            "var out = [];"
                            "for (var i = 0; i < A.length; i++) {"
                            "  try { var b = ptr(A[i]).readByteArray(16);"
                            "    out.push(b === null ? null : Array.from(new Uint8Array(b))"
                            ".map(function(x){return x.toString(16).padStart(2,'0');}).join(''));"
                            "  } catch (e) { out.push(null); }"
                            "}"
                            "send(out);")
                        buf: list = []
                        sc2.on("message", lambda mm, d: buf.extend(mm.get("payload") or []))
                        sc2.load()
                        t2 = _time.time()
                        while not buf and _time.time() - t2 < 10.0:
                            _time.sleep(0.02)
                        nf = len(fps)
                        for idx, _m in enumerate(probes):
                            ok_all = True
                            for k in range(nf):
                                pos = idx * nf + k
                                if pos >= len(buf) or not buf[pos] or buf[pos] != fps[k][1]:
                                    ok_all = False
                                    break
                            if ok_all:
                                mod = probes[idx][0]
                                result["matched_by"] = "fingerprint(multi)"
                                break
                    except Exception:                     # noqa: BLE001
                        pass
        if mod is None:
            result.update({"ok": False, "code": "MODULE_NOT_LOADED",
                           "error": f"进程里找不到模块（试过 {cands}）"})
            return result
        m_base = mod.get("base")
        m_base = int(m_base, 16) if isinstance(m_base, str) else int(m_base)
        runtime = m_base + int(static_addr)
        result["module_name"] = mod.get("name")
        result["module_base"] = hex(m_base)
        result["runtime_addr"] = hex(runtime)

        js = _JS_VERIFY_BP.replace("__RUNTIME__", str(runtime))
        box: dict = {}
        script = sess.create_script(js)
        script.on("message", lambda m, d: box.update(m.get("payload") or {}))
        script.load()
        t0 = _time.time()
        while not box and _time.time() - t0 < 10.0:
            _time.sleep(0.02)
        for key in ("current_hex", "read_error", "already_hooked",
                    "attach_error", "probe_ok"):
            if key in box:
                result[key] = box[key]
    except Exception as exc:                              # noqa: BLE001
        result["probe_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        _detach_async(sess)

    # 3) 字节比对
    cur, orig = result.get("current_hex"), result.get("original_hex")
    if cur and orig:
        result["bytes_match"] = (cur == orig)
    else:
        result["bytes_match"] = None

    # 4) 命中数
    # (20) 第二十次修改（2026-11-06）：命中数改为直接读 debugger 的命中缓存。
    #      bug 原因：原来调 service.poll_events 统计，而它要求**该目标已 attach**；
    #                verify_breakpoint 自身不建立 service 会话，于是必然抛
    #               NOT_ATTACHED，命中数永远是 None，verdict 也就永远说
    #               "未提供 bp_id"。用户明明给了 bp_id。
    #      解决方案：直接读 service 里已有目标的 dbg.hits（只读，不建立新会话）；
    #               没有会话就如实说明"该目标当前未 attach，无法统计命中"。
    #
    # (22) 第二十二次修改（2026-11-06）：改为调用 service.hit_count_for，且**不再要求 bp_id**。
    #      bug 原因：① 上一版仍自己访问 svc._targets 并遍历 dbg.hits——那是私有字段，
    #                  debugger 内部把 hits 改成 @property 后这类写法随时会崩；
    #               ② 不传 bp_id 时完全拿不到命中数，而 (so_name, static_addr)
    #                  本身就足以定位"这个断点命中了几次"。
    #      解决方案：统一走 service.hit_count_for(serial, pid, so_name, static_addr)，
    #                由它负责取缓存与兼容各种 debugger 形态；
    #                bp_id 变成**可选**——给了就额外回报 bp_id 便于对账，
    #                没给也照样按地址统计。
    hits = None
    try:
        from dyn.service import get_dyn

        svc = get_dyn()
        stat = svc.hit_count_for(serial, int(pid), so_name, int(static_addr)) or {}
        if stat.get("ok"):
            hits = int(stat.get("hits") or 0)
            result["hits_since_set"] = hits
            result["hits_scope"] = ("该 (so_name, static_addr) 在本会话命中缓存里的条数")
            if stat.get("total_hits") is not None:
                result["total_hits_all_addrs"] = int(stat["total_hits"])
            if stat.get("discarded") is not None:
                result["hits_discarded"] = int(stat["discarded"])
            if bp_id:
                result["bp_id"] = str(bp_id)
        else:
            # 取不到就说清楚原因，不伪造 0
            result["hits_error"] = stat.get("reason") or stat.get("code") or "取不到命中数"
    except Exception as exc:                              # noqa: BLE001
        result["hits_error"] = f"{type(exc).__name__}: {exc}"

    # 5) 结论
    armed = not result.get("already_hooked")
    if hits is None:
        if result.get("hits_error"):
            # (21) 第二十一次修改（2026-11-06）：命中数取不到时要说**真实原因**。
            #      bug 原因：原来无论为什么取不到，verdict 都写"未提供 bp_id"——
            #               用户明明提供了，却被说成没提供，属于误导性结论。
            #      解决方案：区分"没给 bp_id"与"给了但取不到"，后者直接透传原因。
            verdict = (f"地址可挂钩性已探明，但命中数取不到：{result['hits_error']}")
        elif bp_id:
            verdict = "已探明地址可挂钩；命中数统计失败"
        elif result.get("current_hex"):
            verdict = "已探明地址是否可挂钩；未提供 bp_id，无法统计命中数"
        else:
            verdict = "探测失败，见 probe_error"
    elif hits > 0:
        verdict = f"断点正常工作：已命中 {hits} 次"
    elif result.get("already_hooked"):
        verdict = ("钩子已装在目标地址上，但**一次都没命中**——"
                   "说明这段代码在当前场景下没有执行。"
                   "用 watch_module 看真正在跑的是哪些函数偏移")
    else:
        verdict = ("钩子未装上（frida 未报 already attached），"
                   "检查地址换算或模块是否选错")
    result["armed"] = bool(armed)
    result["verdict"] = verdict
    return result


_JS_PROBE_HITS = r"""
(function () {
    var mod = null;
    var cands = __CANDS__;
    var mods = Process.enumerateModules();
    for (var ci = 0; ci < cands.length && mod === null; ci++) {
        for (var mi = 0; mi < mods.length; mi++) {
            var m = mods[mi], bn = m.name.split('/').pop();
            if (m.name === cands[ci] || bn === cands[ci]) { mod = m; break; }
        }
    }
    // (16) 第十六次修改（2026-11-06）：名字匹配失败时用字节指纹反查。
    //      bug 原因：本地文件名与设备名毫无字面关系时（sg_real.so），
    //               任何候选名都匹配不上，probe_hits 直接报 MODULE_NOT_LOADED，
    //               而 watch_module 早已有指纹兜底——两个工具行为不一致。
    //      解决方案：把该偏移处文件里的原始 16 字节作为指纹，
    //               在各模块同偏移处比对，命中即认定（不猜）。
    var FP = __FP__;
    if (mod === null && FP) {
        var all = Process.enumerateModules();
        for (var ai = 0; ai < all.length && mod === null; ai++) {
            var c = all[ai];
            if (__OFFSET__ >= c.size) { continue; }
            try {
                var got = c.base.add(__OFFSET__).readByteArray(16);
                if (got === null) { continue; }
                var hex = Array.from(new Uint8Array(got))
                    .map(function (x) { return x.toString(16).padStart(2, '0'); })
                    .join('');
                if (hex === FP) {
                    mod = c;
                    send({ kind: 'note', message: '按字节指纹匹配到 ' + c.name });
                }
            } catch (e) {}
        }
    }

    if (mod === null) {
        send({ kind: 'error', code: 'MODULE_NOT_LOADED',
               message: '找不到模块（试过 ' + cands.join(', ') + '；字节指纹也未命中）' });
        return;
    }
    var target = mod.base.add(__OFFSET__);
    var hits = 0, firstTs = null;
    var threads = {};
    var mechanism = 'Interceptor';
    var attached = false;
    try {
        Interceptor.attach(target, {
            onEnter: function () {
                hits++;
                if (firstTs === null) { firstTs = Date.now() / 1000; }
                threads[this.threadId] = (threads[this.threadId] || 0) + 1;
            }
        });
        attached = true;
    } catch (e) {
        send({ kind: 'error', code: 'INTERCEPT_FAILED',
               message: 'Interceptor 挂不上：' + String(e).slice(0, 200),
               runtime: target.toString(), mechanism: 'Interceptor' });
        return;
    }
    send({ kind: 'ready', module: mod.name, base: mod.base.toString(),
           runtime: target.toString(), mechanism: mechanism });
    recv('stop', function () {
        send({ kind: 'stopped', hits: hits, first_hit_ts: firstTs,
               threads: Object.keys(threads).map(Number) });
    });
})();
"""


def probe_hits(serial: str, pid: int, so_name: str, static_addr: int,
               duration: float = 5.0) -> dict:
    """**纯计数探针**：只统计某地址被进入多少次，不挂起、不依赖 hold。

    (15) 第十五次修改（2026-11-06）：新增。

    为什么需要它：`set_breakpoint(hold=True)` 走的是完整断点链路（登记、策略、
    RPC、事件流）。当用户只想回答"这个地址到底跑不跑"时，那条链路太重，
    而且任何一环出问题都会表现为"0 命中"，分不清是没执行还是没挂钩。
    本工具用**最直接的方式**验：一个 Interceptor、一个计数器，成功挂上才谈命中。

    ## 与 verify_breakpoint 的分工

        verify_breakpoint  查"断点有没有真的 armed"（字节、hook 状态）
        probe_hits         查"这段代码到底跑不跑"（纯计数，不挂起）

    ## 返回

        hits            命中次数（0 表示这段时间没执行）
        first_hit_ts    首次命中的时间戳（没有命中为 null）
        threads         命中过该地址的线程 id 列表
        mechanism       实际使用的机制（当前固定 Interceptor）
        runtime         换算出的运行时地址

    ## 关键：拦截失败会明确报错

    frida 对某些地址会抛 `unable to intercept function ... please file a bug`
    （实测同一区间 78 个入口里 19 个挂不上，它们多是函数内部块而非真入口）。
    这种情况返回 INTERCEPT_FAILED，**不会伪装成"0 命中"**。
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("probe_hits", hint=f"frida 不可用：{exc}",
                              extra={"so_name": so_name})

    cands = _module_name_candidates(so_name)
    if not cands:
        return {"ok": False, "implemented": True, "code": "NO_SO_NAME",
                "error": "必须给 so_name"}

    # 指纹：用该偏移处文件里的原始 16 字节（名字对不上时用于反查模块）
    fp_hex = ""
    try:
        so = None
        from mcp_server.tools import get_session

        so = _find_loaded_so(get_session(), so_name)
        if so is not None:
            raw = _read_static_bytes(so, int(static_addr), 16)
            if raw and len(raw) == 16:
                fp_hex = raw.hex()
    except Exception:                                     # noqa: BLE001
        fp_hex = ""

    js = (_JS_PROBE_HITS
          .replace("__CANDS__", json.dumps(cands))
          .replace("__OFFSET__", str(int(static_addr)))
          .replace("__FP__", json.dumps(fp_hex)))

    box: dict = {"ready": False, "stopped": False, "hits": 0,
                 "first_hit_ts": None, "threads": [],
                 "module": "", "runtime": "", "mechanism": "",
                 "err": "", "err_code": ""}
    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["module"] = payload.get("module") or ""
                box["runtime"] = payload.get("runtime") or ""
                box["mechanism"] = payload.get("mechanism") or "Interceptor"
                return
            if kind == "stopped":
                box["stopped"] = True
                box["hits"] = int(payload.get("hits") or 0)
                box["first_hit_ts"] = payload.get("first_hit_ts")
                box["threads"] = payload.get("threads") or []
                return
            if kind == "note":
                box.setdefault("notes", []).append(payload.get("message") or "")
                return
            if kind == "error":
                box["err"] = payload.get("message") or payload.get("code") or "error"
                box["err_code"] = payload.get("code") or "PROBE_FAILED"
                if payload.get("mechanism"):
                    box["mechanism"] = payload["mechanism"]

        script = sess.create_script(js)
        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box["err"] and _time.time() - t0 < 10.0:
            _time.sleep(0.02)
        if box["err"]:
            return {"ok": False, "implemented": True,
                    "code": box["err_code"] or "PROBE_FAILED",
                    "error": box["err"], "so_name": so_name,
                    "static_addr": hex(int(static_addr)),
                    "mechanism": box["mechanism"] or "Interceptor",
                    "hint": ("frida 对某些地址无法安全挂钩（常见于函数内部块）。"
                             "换一个真正的函数入口再试；"
                             "用 watch_module 能看到哪些入口是可挂的")}
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "探针 10 秒内未就位", "so_name": so_name}

        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(50):
            if box["stopped"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        # (26) 第二十六次修改（2026-11-06）：异常路径也要做活性探测。
        #      bug 原因：dev.attach() 遇到死进程会抛 ProcessNotFoundError，
        #               而它发生在**建立会话阶段**——根本走不到后面那段
        #               "0 命中时探测进程"的逻辑。结果是：进程死了，
        #               用户看到的仍然只有一句冷冰冰的 ProcessNotFoundError，
        #               完全看不出"这是进程没了，不是代码没跑"。
        #      解决方案：在异常处理里也调一次 probe_process_alive()，
        #               把三条证据（/proc 存在性 / 状态字符 / frida 可见性）
        #               一并带回，让调用方拿到可判断的信息。
        probe = None
        try:
            from dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception as exc2:                         # noqa: BLE001
            probe = {"verdict": f"活性探测也失败：{type(exc2).__name__}: {exc2}"}
        msg = f"{type(exc).__name__}: {exc}"
        if probe and probe.get("alive") is False:
            msg += f"；并且进程 {pid} 在内核里已不存在（已退出/闪退）"
        elif probe and probe.get("injectable") is False:
            msg += f"；进程 {pid} 仍存在但已不可注入"
        return {"ok": False, "implemented": True,
                "code": ("TARGET_DIED"
                         if (probe or {}).get("alive") is False else "PROBE_FAILED"),
                "error": msg, "so_name": so_name,
                "process_probe": probe}
    finally:
        _detach_async(sess)

    hits = int(box["hits"] or 0)

    # (25) 第二十五次修改（2026-11-06）：0 命中时补一次**进程活性探测**。
    #      bug 原因：原来 0 命中一律判为"这段代码没被执行"，但还有另一种情况——
    #               进程已经死了/变僵尸/失去可注入性。实测 adb ps 还能看到
    #               pid 1495，而 frida 已经枚举不到它，probe_hits 直接抛
    #               ProcessNotFoundError；即便能跑，也可能因进程半死而 0 命中。
    #               这时告诉用户"代码没跑到"是**错误结论**。
    #      解决方案：0 命中时调 adb 层的 probe_process_alive()，用
    #               /proc 存在性 + 状态字符 + frida 可见性三条证据判断，
    #               把"进程没了"和"代码没跑"彻底分开。
    proc_probe = None
    if hits == 0:
        try:
            from dyn.adb import Adb

            proc_probe = Adb(serial).probe_process_alive(int(pid))
        except Exception as exc:                          # noqa: BLE001
            proc_probe = {"verdict": f"活性探测失败：{type(exc).__name__}: {exc}",
                          "alive": None, "injectable": None}

    if hits > 0:
        verdict = f"该地址在 {duration:g}s 内被执行 {hits} 次，断点机制可用"
    elif proc_probe and proc_probe.get("alive") is False:
        verdict = (f"该地址 0 命中，**但进程已经不在了**（{proc_probe.get('verdict')}）："
                   "这个 0 不代表代码没跑，而是根本没机会跑")
    elif proc_probe and proc_probe.get("injectable") is False:
        verdict = (f"该地址 0 命中，**且进程已不可注入**（{proc_probe.get('verdict')}）："
                   "探针挂上与否都无意义，先恢复进程再重试")
    else:
        verdict = (f"该地址在 {duration:g}s 内**一次都没执行**："
                   "不是挂钩失败（已确认 Interceptor 挂上了，且进程存活可注入），"
                   "而是这段代码在当前场景下没有被走到")
    out = {
        "ok": True,
        "implemented": True,
        "so_name": so_name,
        "static_addr": hex(int(static_addr)),
        "module": box["module"],
        "runtime": box["runtime"],
        "mechanism": box["mechanism"] or "Interceptor",
        "duration": duration,
        "hits": hits,
        "first_hit_ts": box["first_hit_ts"],
        "threads": box["threads"],
        "process_probe": proc_probe,
        "verdict": verdict,
    }
    if box.get("notes"):
        out["notes"] = box["notes"]
    return out


_JS_CALL_TREE = r"""
(function () {
    var mod = null;
    var cands = __CANDS__;
    var mods = Process.enumerateModules();
    for (var ci = 0; ci < cands.length && mod === null; ci++) {
        for (var mi = 0; mi < mods.length; mi++) {
            var m = mods[mi], bn = m.name.split('/').pop();
            if (m.name === cands[ci] || bn === cands[ci]) { mod = m; break; }
        }
    }
    // (21) 第二十一次修改（2026-11-06）：名字匹配失败时用**双字节指纹**反查。
    //      bug 原因：本地文件名与设备名毫无字面关系时（sg_real.so vs
    //               libsgmainso-6.7.260202.so），候选名全不命中，直接报
    //               MODULE_NOT_LOADED——但 so 明明就在进程里。
    //      解决方案：与 verify_breakpoint 同一套双指纹（两个偏移取交集），
    //                实测单指纹会在 libpdfium.so 上假阳性，双指纹唯一。
    var FPS = __FPS__;
    if (mod === null && FPS && FPS.length > 0) {
        var all = Process.enumerateModules();
        for (var ai = 0; ai < all.length && mod === null; ai++) {
            var c = all[ai];
            var need = 0;
            for (var q = 0; q < FPS.length; q++) { if (FPS[q].offset > need) need = FPS[q].offset; }
            if (need >= c.size) { continue; }
            var okAll = true;
            for (var q = 0; q < FPS.length; q++) {
                try {
                    var b = c.base.add(FPS[q].offset).readByteArray(16);
                    if (b === null) { okAll = false; break; }
                    var hx = Array.from(new Uint8Array(b))
                        .map(function (x) { return x.toString(16).padStart(2, '0'); })
                        .join('');
                    if (hx !== FPS[q].hex) { okAll = false; break; }
                } catch (e) { okAll = false; break; }
            }
            if (okAll) { mod = c; }
        }
    }

    if (mod === null) {
        send({ kind: 'error', code: 'MODULE_NOT_LOADED',
               message: '找不到模块（试过 ' + cands.join(', ') + '；双指纹也未命中）' });
        return;
    }
    var base = mod.base;
    var ROOTS = __ROOTS__;          // 要追踪的入口偏移
    var MAXN = __MAXN__;
    var edges = {};                 // "from->to" -> count
    var entryHits = {};
    var placed = 0, failed = [];

    // (20) 第二十次修改（2026-11-06）：调用链追踪。
    //      为什么需要：反复出现"某个函数断点不命中，但不知道是上层没调它、
    //      还是地址找错了"。只看单点命中是 0 分不清；看它被谁调用、
    //      调用了几次，才能判断这条路径到底走没走。
    //      做法：在给定入口挂 Interceptor，onEnter 里取返回地址（lr）作为"调用者"，
    //            记录 调用者lr -> 本函数 的边与次数。开销远小于 Stalker。
    function place(off) {
        try {
            Interceptor.attach(base.add(off), {
                onEnter: function () {
                    entryHits[off] = (entryHits[off] || 0) + 1;
                    try {
                        var caller = this.returnAddress;
                        if (caller !== null) {
                            var c = caller.sub(base).toInt32();
                            if (c >= 0) {
                                var key = c + '->' + off;
                                if (Object.keys(edges).length < MAXN) {
                                    edges[key] = (edges[key] || 0) + 1;
                                }
                            }
                        }
                    } catch (e) {}
                }
            });
            placed++;
        } catch (e) {
            if (failed.length < 10) {
                failed.push({offset: off, error: String(e).slice(0, 100)});
            }
        }
    }
    ROOTS.forEach(place);

    send({ kind: 'ready', module: mod.name, base: base.toString(),
           placed: placed, failed: failed, total: ROOTS.length });
    recv('stop', function () {
        send({ kind: 'stopped', entry_hits: entryHits, edges: edges });
    });
})();
"""


def trace_call_tree(serial: str, pid: int, so_name: str,
                    entries: list, duration: float = 5.0,
                    max_edges: int = 500, so_hint=None) -> dict:
    """追踪一组函数入口的**调用者**，回答「这条路径到底有没有被调用」。

    (20) 第二十次修改（2026-11-06）：新增。

    解决什么问题：某函数断点 0 命中时，有两种完全不同的原因——
        · 上层根本没有调用它（这条路在当前场景没走）
        · 地址/模块找错了
    只看"0 命中"分不清。本工具同时给出：**这个函数被调了几次**、
    **是被谁（哪个返回地址）调的**。

    ## 与 watch_module 的区别

        watch_module     在整个 so 的所有函数入口撒点，看"谁被执行了"（广度）
        trace_call_tree  针对**指定的少数几个入口**，看"谁调用了它"（深度）

    ## 参数

        entries       要追踪的函数入口静态偏移列表，如 [0x174F00, 0x175018]
        duration      观察秒数
        max_edges     最多记录多少条调用边（防止热点函数把内存打爆）

    ## 返回

        entry_hits    {offset: 被调用次数}
        edges         [{caller_static, callee_static, count}] 按次数降序
        placed/failed 挂点情况
        verdict       一句话结论

    ## 已知边界

        · 用 `this.returnAddress`（lr）作为调用者，**只能拿到直接调用者的返回地址**；
          经 PLT/尾调用跳转过来的可能落在桩上
        · 调用者地址若不在本 so 内，会标 `caller_in_module=false`
        · 开销远小于 Stalker，但仍建议 duration ≤ 30 秒、entries ≤ 50 个
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _trace_pending("trace_call_tree", hint=f"frida 不可用：{exc}",
                              extra={"so_name": so_name})

    # (22) 第二十二次修改（2026-11-06）：入口数量设上限。
    #      bug 原因：entries 直接原样挂探针，调用方若传上千个（比如把整个函数表
    #                都塞进来），就会在同一瞬间 patch 上千个地址——实测这种
    #                密度会把目标拖垮（watch_module 的教训：765 个直接崩）。
    #      解决方案：硬上限 200 个入口，超出只取前 200 并在返回里声明截断。
    MAX_ENTRIES = 200
    offs = []
    dropped_entries = 0
    for e in (entries or []):
        try:
            v = int(e, 16) if isinstance(e, str) else int(e)
        except (TypeError, ValueError):
            continue
        if len(offs) >= MAX_ENTRIES:
            dropped_entries += 1
            continue
        offs.append(v)
    if not offs:
        return {"ok": False, "implemented": True, "code": "NO_ENTRIES",
                "error": "必须给 entries（函数入口静态偏移列表）"}

    cands = _module_name_candidates(so_name)
    # 双指纹（两个函数入口），名字对不上时用于反查模块
    # (23) 第二十三次修改（2026-11-06）：指纹来源改为**可选参数**。
    #      bug 原因：原来硬编码去取 mcp_server 的全局会话，而 dyn 层被直接调用时
    #               （测试脚本、别的调用方）那个会话可能是空的，于是指纹为空、
    #               模块匹配失败、整个函数返回 None——报错信息还完全不相关。
    #      解决方案：① 新增 so 参数，调用方可直接传 SoFile；
    #                ② 没传才退回全局会话；都拿不到就不做指纹（只按名字匹配），
    #                   并把这一情况体现在失败信息里，而不是静默返回 None。
    fps: list[dict] = []
    try:
        so = so_hint
        if so is None:
            so = _find_loaded_so(
                __import__("mcp_server.tools", fromlist=["x"]).get_session(), so_name)
        if so is not None:
            fns = getattr(so, "functions", {}) or {}
            vals = fns.values() if isinstance(fns, dict) else list(fns)
            offs0 = sorted({int(getattr(f, "addr", 0) or 0) for f in vals})[:2]
            for o in offs0:
                raw = _read_static_bytes(so, o, 16)
                if raw and len(raw) == 16:
                    fps.append({"offset": int(o), "hex": raw.hex()})
    except Exception:                                     # noqa: BLE001
        fps = []
    js = (_JS_CALL_TREE
          .replace("__CANDS__", json.dumps(cands))
          .replace("__FPS__", json.dumps(fps))
          .replace("__ROOTS__", json.dumps(offs))
          .replace("__MAXN__", str(max(10, int(max_edges)))))

    box: dict = {"ready": False, "stopped": False, "module": "", "base": "",
                 "placed": 0, "failed": [], "entry_hits": {}, "edges": {},
                 "err": "", "err_code": ""}
    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["module"] = payload.get("module") or ""
                box["base"] = payload.get("base") or ""
                box["placed"] = int(payload.get("placed") or 0)
                box["failed"] = payload.get("failed") or []
                return
            if kind == "stopped":
                box["stopped"] = True
                box["entry_hits"] = payload.get("entry_hits") or {}
                box["edges"] = payload.get("edges") or {}
                return
            if kind == "error":
                box["err"] = payload.get("message") or "error"
                box["err_code"] = payload.get("code") or "TRACE_FAILED"

        script = sess.create_script(js)
        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box["err"] and _time.time() - t0 < 15.0:
            _time.sleep(0.02)
        if box["err"]:
            return {"ok": False, "implemented": True, "code": box["err_code"],
                    "error": box["err"], "so_name": so_name}
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "追踪点 15 秒内未就位", "so_name": so_name}

        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(50):
            if box["stopped"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "implemented": True, "code": "TRACE_FAILED",
                "error": f"{type(exc).__name__}: {exc}", "so_name": so_name}
    finally:
        _detach_async(sess)

    entry_hits = {}
    for k, v in (box["entry_hits"] or {}).items():
        try:
            entry_hits[hex(int(k))] = int(v)
        except (TypeError, ValueError):
            continue

    edges = []
    for k, v in (box["edges"] or {}).items():
        try:
            caller_s, callee_s = str(k).split("->")
            edges.append({"caller_static": hex(int(caller_s)),
                          "callee_static": hex(int(callee_s)),
                          "count": int(v)})
        except (TypeError, ValueError):
            continue
    edges.sort(key=lambda e: -e["count"])

    total_hits = sum(entry_hits.values())
    if total_hits:
        top = max(entry_hits.items(), key=lambda kv: kv[1])
        verdict = (f"这 {len(entries)} 个入口共被调用 {total_hits} 次，"
                   f"最频繁的是 {top[0]}（{top[1]} 次）")
    else:
        verdict = (f"这 {len(entry_hits) or len(entries)} 个入口在 {duration:g}s 内"
                   "**一次都没被调用**：说明上层路径在当前场景没有走到它们，"
                   "不是地址找错（挂点已成功 " + str(box["placed"]) + " 个）")

    out = {
        "ok": True,
        "implemented": True,
        "so_name": so_name,
        "module": box["module"],
        "base": box["base"],
        "duration": duration,
        "placed": box["placed"],
        "failed": box["failed"],
        "entry_hits": entry_hits,
        "edges": edges[:200],
        "total_hits": total_hits,
        "verdict": verdict,
        "note": ("caller_static 来自 lr（直接调用者的返回地址）；"
                 "若落在桩或 so 外，说明是跨模块/经 PLT 调用"),
    }
    if dropped_entries:
        out["entries_truncated"] = (
            f"入参给了 {len(entries)} 个入口，只挂了前 {MAX_ENTRIES} 个"
            f"（丢弃 {dropped_entries} 个）：一次挂太多会把目标拖垮")
    return out
