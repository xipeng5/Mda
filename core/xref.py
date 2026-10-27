"""交叉引用分析。

职责：对单个 so 建立调用/数据引用图，并支持跨 so 解析导入符号。
跨 so 的核心：本 so 内 bl 到 PLT stub 的调用，最终指向别的 so 的导出函数。

数据结构语义（修复后）：
  calls_to[target]  = [调用点地址...]      谁调用了 target（target 可为函数或 PLT）
  called_by[fn_addr] = [该函数发出的调用目标...]   仅以函数为 key
  data_refs[data_addr] = [引用点指令地址...]

历史 bug（第 3 次修复，2026-10-13）：
  BUG-3 string_refs 遍历全局 data_refs 的 key 而非本函数指令的引用，
        26 条指令的函数报 1246 个引用。根因：按"地址是否像 rodata"过滤
        全库集合，未按"本函数发出的引用"过滤。
  BUG-1 called_by/calls_to 语义命名颠倒，调用方按直觉使用必错。
        （保留键名但修正赋值方向与注释，并去重）
  BUG-2 fn.instructions 由 disasm_function 写回，跨函数调用时残留
        他函数指令 → xrefs_from 返回别的函数的指令。
        解决：指令缓存以函数地址为键，xrefs_from 只用本函数缓存。
"""
from __future__ import annotations

from collections import defaultdict

from core.disasm import Disassembler
from core.elf_model import SoFile
from models import Function, Instruction


class Xref:
    """单个 so 的引用图。"""

    def __init__(self, so: SoFile, disasm: Disassembler):
        self.so = so
        self.disasm = disasm
        # 内部存储：下划线前缀，写入方一律用它（避免属性访问触发递归 build）
        self._calls_to: dict[int, list[int]] = defaultdict(list)
        self._called_by: dict[int, list[int]] = defaultdict(list)
        self._data_refs: dict[int, list[int]] = defaultdict(list)
        # (1) 第一次修改：落到 PLT 桩的调用（外部导入调用），与 _calls_to 分表，
        # 避免导入跳板污染本 so 的扇入统计
        self._plt_calls: dict[int, list[int]] = defaultdict(list)
        # 每函数发出的数据引用：fn_addr -> [被引用的数据地址]（BUG-3 修复的关键）
        self._fn_data_refs: dict[int, list[int]] = defaultdict(list)
        # 指令缓存：fn_addr -> [Instruction]（BUG-2 修复：不再依赖 fn.instructions 回写）
        # 注：此处**只存引用**，实体由 Function.instructions / Disassembler 持有，
        # 避免同一批 Instruction 被复制两份（6110 个函数约 86 万条，重复会多占数百 MB）
        self._insn_cache: dict[int, list[Instruction]] = {}
        self._built = False

    # ---------- 公开索引（访问即构建） ----------
    # 缺陷原因：xref() 改为惰性后，脚本里 `x = session.xref(n)` 直接读
    # calls_to 会拿到**空字典**——用户实测「calls_to[X] 恒空」即此因；
    # 我此前的验证先调了 ensure_xrefs，所以看不出来（验证方法有缺陷）。
    # 解决：改为属性，访问即触发全量构建（有缓存，只付一次）。
    # 需要避开构建的高频单点查询，请用 callees_of_fn() / _calls_to。

    @property
    def calls_to(self) -> dict[int, list[int]]:
        """谁调用了某地址 → 调用点列表（首次访问自动全量构建）。"""
        self.build()
        return self._calls_to

    @property
    def called_by(self) -> dict[int, list[int]]:
        """某函数调用了谁 → 目标列表（首次访问自动全量构建）。"""
        self.build()
        return self._called_by

    @property
    def plt_calls(self) -> dict[int, list[int]]:
        """PLT 桩地址 → 调用点列表（外部导入调用，不计入本 so 扇入）。

        (1) 第一次修改：段表模式下桩已从函数表剔除，
        其调用记录单独存放于此，供"哪些外部函数被大量调用"分析。
        """
        self.build()
        return self._plt_calls

    @property
    def data_refs(self) -> dict[int, list[int]]:
        """数据地址 → 引用点列表（首次访问自动全量构建）。"""
        self.build()
        return self._data_refs

    # ---------- 单函数快速路径（不触发全量构建） ----------

    def callees_of_fn(self, fn_addr: int) -> list[int]:
        """该函数调用了谁（只解这一个函数，毫秒级）。"""
        fn = self.so.function_at(fn_addr)
        key = fn.addr if fn else fn_addr
        self.ensure_function(key)
        return list(self._called_by.get(key, []))

    def callers_of_fn(self, addr: int) -> list[int]:
        """谁调用了 addr（**不触发构建**，只反映已收集的部分）。

        入向引用天然需要全库；要完整结果请访问 calls_to（会构建）。
        供 GUI 等不能阻塞的调用方使用。
        """
        return list(self._calls_to.get(addr, []))

    def data_refs_of_fn(self, fn_addr: int) -> list[int]:
        """该函数引用到的数据地址（只解这一个函数）。"""
        fn = self.so.function_at(fn_addr)
        key = fn.addr if fn else fn_addr
        self.ensure_function(key)
        return list(self._fn_data_refs.get(key, []))

    def build(self, progress=None) -> None:
        """反汇编全部函数并收集引用（显式全量构建）。progress 可选回调 (已完成, 总数)。

        注意：这是**昂贵**操作（libAPSE 级样本约 86 万条指令、20-30 秒）。
        高频单点查询请用 ensure_function()，避免为查一个函数付全量成本。
        """
        if self._built:
            return
        total = len(self.so.functions)
        for i, (addr, fn) in enumerate(self.so.functions.items()):
            self._collect_function(addr)
            if progress and i % 20 == 0:
                progress(i, total)
        self._built = True

    def ensure_function(self, fn_addr: int) -> None:
        """只确保单个函数的引用已收集（惰性、快速）。

        用于 BFS/单点查询等高频路径：不为查一个函数而触发全量 build。
        """
        if fn_addr in self._insn_cache:
            return
        self._collect_function(fn_addr)

    def progress(self) -> dict:
        """构建进度（供 MCP/脚本判断是否需要等待全量）。"""
        total = len(self.so.functions)
        done = len(self._insn_cache)
        return {"total": total, "done": done, "built": self._built,
                "percent": (done * 100 // total) if total else 0}

    def _collect_function(self, fn_addr: int) -> None:
        """收集单个函数的调用与数据引用（幂等，可重复调用）。

        键归一化修复：此前直接拿传入地址当键，导致同一函数经两条路径
        各记一份——ensure_function(内部地址) 记在 0xB9DA4，
        build() 迭代函数表记在起点 0xB9528。于是 called_by 查询结果
        随调用路径变化（实测同一地址时而返回 8 条时而 0 条）。
        统一以**函数真实起点**为键。
        """
        fn = self.so.function_at(fn_addr)
        key = fn.addr if fn is not None else fn_addr
        if key in self._insn_cache:
            return
        insns = self.disasm.disasm_function(key)
        self._insn_cache[key] = insns
        if fn is None:
            return

        calls: list[int] = []
        data: list[int] = []
        for ins in insns:
            # 数据块误识别防护：BUG-4 让反汇编能跨越跳转表继续，但数据字
            # 也会被解码成 bl（实测 libAPSE_loadable 出现 692 个负地址/越界
            # 目标）。落不到 PT_LOAD 的引用一律丢弃，避免野边污染引用图。
            if ins.is_call and ins.call_target is not None:
                if not self.so.in_load(ins.call_target):
                    continue
                # (1) 第一次修改
                # bug 原因：段表模式下 PLT 桩已从函数表剔除，但调用目标仍被
                # 无差别记进 _calls_to，实测桩 0x1a4140 以 1436 次调用霸占
                # 扇入榜首，用户按扇入找枢纽时会被导入跳板误导。
                # 解决方案：落到 PLT 桩的调用记为外部导入调用（_plt_calls），
                # 不进 _calls_to，使其不参与本 so 的扇入统计。
                if self.so.in_plt_stub(ins.call_target):
                    self._plt_calls[ins.call_target].append(ins.addr)
                    calls.append(ins.call_target)
                    continue
                self._calls_to[ins.call_target].append(ins.addr)
                calls.append(ins.call_target)
                # call 目标已由 calls_to 记录，不再重复算作数据引用
                #（此前 ref_addr==call_target 导致同一目标进两个表，
                #  data_refs 被调用目标灌水）
                continue
            if ins.ref_addr is not None and self.so.in_load(ins.ref_addr):
                self._data_refs[ins.ref_addr].append(ins.addr)
                data.append(ins.ref_addr)

        # BUG-1：called_by[fn] = 该函数"发出"的调用目标（caller 视角）
        # BUG-3：string_refs 只取本函数发出的数据引用中"像字符串"的
        self._called_by[key] = sorted(set(calls))
        self._fn_data_refs[key] = sorted(set(data))
        fn.calls = sorted(set(calls))
        fn.string_refs = sorted(a for a in set(data) if self._is_string(a))

    def _is_string(self, addr: int) -> bool:
        """判断地址是否落在只读数据区（字符串大概率在此）。"""
        sec = self.so.section_at(addr)
        if sec is not None:
            return not sec.is_exec and not sec.is_write
        # 段表兜底（无节表的 dump so）：非可写即当数据
        for va, end, _off, fl in getattr(self.so, "_loads", []):
            if va <= addr < end:
                return not (fl & 0x2)
        return False

    # ---------- 查询 ----------

    def xrefs_to(self, addr: int) -> list[int]:
        """谁引用了 addr（调用点 + 数据引用点）。"""
        return sorted(set(self._calls_to.get(addr, []) + self._data_refs.get(addr, [])))

    def xrefs_from(self, fn_addr: int) -> list[Instruction]:
        """某函数发出的全部引用指令。

        BUG-2 修复：只用 _insn_cache 里本函数的指令，杜绝他函数残留。
        """
        fn = self.so.function_at(fn_addr)
        key = fn.addr if fn else fn_addr
        if key not in self._insn_cache:
            self._collect_function(key)
        return [
            ins
            for ins in self._insn_cache.get(key, [])
            if ins.is_call or ins.ref_addr is not None
        ]

    def string_refs_of(self, fn_addr: int) -> list[int]:
        """某函数引用的字符串地址（BUG-3 修复后的正确入口）。"""
        if fn_addr not in self._fn_data_refs:
            self._collect_function(fn_addr)
        return [a for a in self._fn_data_refs.get(fn_addr, []) if self._is_string(a)]

    # ---------- 符号解析 ----------

    def resolve_target(self, target: int) -> tuple[str, int] | None:
        """解析调用目标。

        返回 (符号名, 目标静态地址)。
        目标可能是：本 so 内函数 / PLT stub（外部导入）。
        PLT 的跨 so 解析由 Session 层完成，此处只给导入名。
        """
        fn = self.so.function_at(target)
        if fn is not None:
            return (fn.name or f"sub_{target:x}", target)
        name = self.so.plt_name(target)
        if name:
            return (name, 0)  # 地址 0 表示外部导入，由 Session 解析
        return None
