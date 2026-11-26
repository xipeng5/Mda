"""ARM64 函数模拟执行插件（Unicorn 引擎，通用能力）。

## 解决什么问题

验证一个 so 里的函数到底做什么，现在只有两条路：
  · 真机跑（受反调试干扰，有风控风险）
  · 人肉读汇编（慢）

[Unicorn](https://www.unicorn-engine.org/) 能**在本地模拟执行 ARM64 代码**：
把 so 映射进模拟内存 → 设寄存器/参数 → 跑 → 读返回值。

**完全离线、不碰真机、不受反调试影响。**

## 典型用法

```python
plugin_run(name="emulate_func", args={
    "so": "libfoo.so",
    "addr": "0x1fa650",        # 要跑的函数
    "x0": "0x40000000",        # 参数（指向已映射的缓冲区）
    "buffer": {"addr": "0x40000000", "hex": "00112233"},
    "max_insns": 100000,
})
```

## 能力边界（诚实说明）

  · **只模拟用户态指令**，不模拟系统调用（svc 会停下来报 UNHANDLED_SVC）
  · 外部函数调用（bl 到未映射地址）会停住并返回当时的寄存器现场
  · 需要调用方自己准备内存布局（用 buffer 参数）
  · 浮点/SIMD 只做透传，不保证精确

## 内存导出（dump 参数，第 2 次修改新增）

只给寄存器是不够的：解密/解码函数的**结果写在缓冲区里**，寄存器里往往
只有一个指针。所以本插件支持跑完后导出内存：

    dump: [{addr, size}, ...]   按指定范围导出（最常用）
    dump: "writes"              只导出“运行期间被写过的区域”
    dump: "stack"               导出当前栈上已用部分
    dump: "all"                 导出所有已映射的可写区域（大样本慎用）

`dump_max`（默认 4096）限制**单个范围**的导出字节数，超出截断并标
`truncated`，不会因为一个 100MB 的段把返回撑爆。

"writes" 靠 UC_HOOK_MEM_WRITE 记录**第一个写的字节的页**，再按页导出
——只知道哪页被写过，不精确到字节，所以导出时会给出整页内容并要求
调用方自己按已知结构裁。这样做是因为逐字节记录在循环里开销极大
（实测解密循环 4 次 × 每次几十字节还行，但大循环会拖死模拟）。

## 通用性

纯 Unicorn API 封装 + ELF 段加载，不含任何具体 so/函数特征。
"""
from __future__ import annotations

from pathlib import Path
import struct

from server.core.addr import parse_addr
from server.core.plugins import PluginBase


def _read_pt_loads(raw: bytes, fallback_loads: list) -> list[tuple[int, int, int, int, int]]:
    """从 ELF64 Program Header 读取 PT_LOAD 列表，返回 (vaddr, filesz, memsz, offset, flags)。

    优先直接读原始 ELF 头以保留 p_memsz（包含 .bss 零初始化区）；
    若不是标准 64 位小端 ELF，则回退使用 so._loads。
    """
    if len(raw) >= 0x40 and raw[:4] == b"\x7fELF" and raw[4] == 2 and raw[5] == 1:
        e_phoff, = struct.unpack_from("<Q", raw, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", raw, 0x36)
        if e_phentsize >= 56 and e_phnum > 0 and e_phoff + e_phentsize * e_phnum <= len(raw):
            segs: list[tuple[int, int, int, int, int]] = []
            for i in range(e_phnum):
                pos = e_phoff + i * e_phentsize
                p_type, p_flags = struct.unpack_from("<II", raw, pos)
                p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", raw, pos + 8)
                if p_type == 1 and max(p_memsz, p_filesz) > 0:
                    segs.append((p_vaddr, p_filesz, max(p_memsz, p_filesz), p_offset, p_flags))
            if segs:
                segs.sort(key=lambda x: x[0])
                return segs
    out = []
    for vaddr, vend, off, flags in fallback_loads or []:
        sz = max(0, vend - vaddr)
        if sz > 0:
            out.append((vaddr, sz, sz, off, flags))
    return out


def _pick_heap_base(occupied: list[tuple[int, int]], heap_size: int) -> int:
    """动态挑选一个不与已映射段及栈重叠的堆基址（1MB 对齐）。"""
    align = 0x100000
    so_ends = [b for a, b in occupied if b < 0x700000000000]
    max_so_end = max(so_ends, default=0)
    cand = max(0x400000, ((max_so_end + align + (align - 1)) & ~(align - 1)))
    while True:
        cand_end = cand + heap_size
        conflict = None
        for a, b in occupied:
            if cand < b and a < cand_end:
                conflict = b
                break
        if conflict is None:
            return cand
        cand = (conflict + align + (align - 1)) & ~(align - 1)


class Plugin(PluginBase):
    name = "emulate_func"
    description = "用 Unicorn 本地模拟执行 ARM64 函数（离线、不碰真机）"
    usage = ("args: {so: str, addr: str|int, "
             "x0..x7: str (可选参数), stack_size: int=0x10000, "
             "buffer: {addr, hex} | [{addr, hex}, ...] (可选内存初始化), "
             "max_insns: int=100000, trace: bool=false, "
             "dump: [{addr, size}] | 'writes' | 'stack' | 'all', "
             "dump_max: int=4096, trim_writes: bool=false, "
             "stubs: 'auto'|true|dict|null, vfs: {path: hex}, "
             "heap_base: int=0x400000, heap_size: int=0x100000}")
        # (4) 第四次修改（2026-11-18）：外部函数桩 + buffer 参数形状兼容 + writes 裁剪。
        #     bug 原因：
        #       ① 用户传 buffer=[{addr,hex}]（list）时，旧的 `isinstance(buf, dict)`
        #          直接为 False —— 整段内存初始化被静默跳过，不写、不报错，返回里
        #          也没有任何标记，调用方误以为数据写进去了，据此推理出错误结论。
        #          实测：dict 形状写 0x60000 读回 aabbccdd；list 形状读回文件原值。
        #          注意：不是"只读段写不进去"——mem_map 没传 perms，默认 7=RWX。
        #       ② bl malloc/fopen 到 PLT 后从 GOT 取到 0，跳到 0x0 崩溃，任何依赖
        #          libc 的函数都跑不完 —— 只能验纯算法，拿不到签名函数输出。
        #       ③ "writes" 导出整页 0x1000，尾部几千个 0 浪费返回带宽。
        #     解决方案：
        #       · buffer 同时接受 dict / list，逐个写入，回读校验，返回
        #         buffer_applied + buffer_skipped 让静默失败可见；
        #       · 引入通用 StubEngine（server/core/unicorn_stubs.py），在 PLT 入口
        #         拦截并用 Python 语义实现 malloc/memcpy/strlen/snprintf/fopen 等，
        #         设好返回值后把 PC 拉回 LR 跳过 GOT 链；
        #       · writes 模式加 trim_writes，裁掉尾部连续 0。

    def run(self, session, args: dict):
        try:
            from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
            from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP
        except ImportError:
            return {"error": "unicorn 未安装。pip install unicorn（GPL-2.0，有 wheel）",
                    "code": "UNICORN_NOT_INSTALLED"}

        so_name = args.get("so")
        if not so_name or args.get("addr") is None:
            return {"error": "需要 so 与 addr", "code": "BAD_ARGS"}
        try:
            so = session.get(so_name)
        except KeyError as exc:
            return {"error": str(exc),
                    "code": getattr(exc, "mda_code", "SO_NOT_LOADED")}

        # (5) 第五次修改（2026-11-26）
        # bug 原因：1) 未校验 so.arch == 183，非 ARM64 样本强行按 ARM64 模拟；
        #           2) addr 未统一用 parse_addr，非法地址抛异常；
        #           3) 仅按 so._loads 的 filesz 映射，缺失 .bss（p_memsz > p_filesz）导致读/写全局变量触发未映射异常；
        #           4) stack_size 未做 4KB 对齐与下界保护；
        #           5) L188 f-string `{addr,hex}` 笔误；
        #           6) 启用 stubs 时 heap_base 硬编码 0x400000，>4MB 的 so 会被堆覆写自身代码/数据。
        # 解决方案：校验 arch==183、用 parse_addr 解析所有地址、结合 ELF PHDR 完整映射 memsz(.bss)、
        #           4KB 对齐 stack_size、修正 f-string，并在未显式指定 heap_base 时动态计算无冲突堆基址。
        if getattr(so, "arch", None) != 183:
            return {"ok": False, "code": "UNSUPPORTED_ARCH",
                    "error": f"emulate_func 仅支持 ARM64 (arch=183)，当前 arch={getattr(so, 'arch', None)}"}

        path = getattr(so, "path", None)
        if not path or not Path(path).exists():
            return {"error": f"找不到 so 文件：{path}", "code": "NO_FILE"}

        addr = parse_addr(args["addr"])
        if addr is None:
            return {"ok": False, "code": "BAD_ADDR",
                    "error": f"非法地址参数 addr={args['addr']!r}"}
        max_insns = int(args.get("max_insns", 100000))
        trace = bool(args.get("trace", False))

        # ---- 建模拟器并映射 so 的所有 PT_LOAD 段（含 .bss 的 memsz） ----
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        raw = Path(path).read_bytes()
        loads = _read_pt_loads(raw, getattr(so, "_loads", []) or [])
        if not loads:
            return {"error": "so 没有 PT_LOAD 段信息，无法映射",
                    "code": "NO_LOADSEG"}

        mapped = []
        page_size = 0x1000
        covered: list[tuple[int, int]] = []
        for vaddr, filesz, memsz, off, flags in loads:
            vend = vaddr + memsz
            if memsz <= 0:
                continue
            # (2) 按页对齐映射，且**只映射未覆盖的部分**，避免段间重叠 UC_ERR_MAP
            start = vaddr & ~(page_size - 1)
            end = (vend + page_size - 1) & ~(page_size - 1)
            cur = start
            while cur < end:
                if any(a <= cur < b for a, b in covered):
                    nxt = min([b for a, b in covered if a <= cur < b], default=cur + page_size)
                    cur = nxt
                    continue
                chunk_end = end
                for a, _b in covered:
                    if cur < a < chunk_end:
                        chunk_end = a
                map_size = chunk_end - cur
                try:
                    uc.mem_map(cur, map_size)
                except Exception as exc:                  # noqa: BLE001
                    return {"error": f"映射 0x{cur:x}+0x{map_size:x} 失败：{exc}",
                            "code": "MAP_FAILED"}
                covered.append((cur, chunk_end))
                cur = chunk_end
            if filesz > 0:
                chunk = raw[off:off + filesz] if off + filesz <= len(raw) else raw[off:]
                if chunk:
                    uc.mem_write(vaddr, chunk)
            mapped.append({"vaddr": hex(vaddr), "size": filesz, "memsz": memsz,
                           "flags": hex(flags), "file_off": hex(off)})

        # ---- 栈（向上 4KB 对齐，至少 2 页以容纳哨兵页与栈空间） ----
        raw_stack_size = parse_addr(args.get("stack_size", 0x10000))
        if raw_stack_size is None or raw_stack_size <= 0:
            return {"ok": False, "code": "BAD_ARGS",
                    "error": f"非法 stack_size={args.get('stack_size')!r}"}
        stack_size = (max(raw_stack_size, 0x2000) + page_size - 1) & ~(page_size - 1)
        stack_base = 0x7FFF00000000
        uc.mem_map(stack_base, stack_size)
        sp = stack_base + stack_size - 0x1000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        # (3) LR 指向哨兵页：函数 ret 会跳到哨兵，据此判"正常返回"。
        #     不设的话 LR=0，而 until=0 会把"跳到 0"当成正常结束（实测恒 finished）。
        sentinel = stack_base + 0x100        # 哨兵页（已映射区域内）
        from unicorn.arm64_const import UC_ARM64_REG_LR

        uc.reg_write(UC_ARM64_REG_LR, sentinel)

        # ---- 调用方准备的内存（(4) 兼容 dict / list，写后回读校验） ----
        buf = args.get("buffer")
        # 归一化：None → []；dict → [dict]；list → 原样；其它 → [] 并记录原因
        if buf is None:
            buf_specs = []
            buf_bad = None
        elif isinstance(buf, dict):
            buf_specs = [buf]
            buf_bad = None
        elif isinstance(buf, (list, tuple)):
            buf_specs = list(buf)
            buf_bad = None
        else:
            buf_specs = []
            buf_bad = f"buffer 类型不支持：{type(buf).__name__}（要 dict 或 [{{addr,hex}},...])"
        buffer_applied: list[dict] = []
        buffer_skipped: list[dict] = []
        occupied: list[tuple[int, int]] = list(covered) + [(stack_base, stack_base + stack_size)]
        for spec in buf_specs:
            try:
                if not isinstance(spec, dict) or spec.get("addr") is None \
                        or spec.get("hex") is None:
                    buffer_skipped.append({"spec": str(spec)[:80],
                                           "reason": "缺 addr 或 hex"})
                    continue
                baddr = parse_addr(spec["addr"])
                if baddr is None:
                    buffer_skipped.append({"spec": str(spec)[:80],
                                           "reason": f"非法地址 addr={spec['addr']!r}"})
                    continue
                bdata = bytes.fromhex(str(spec["hex"]).replace(" ", ""))
                bpage = baddr & ~0xFFF
                need = max(page_size, ((baddr - bpage) + len(bdata) + 0xFFF) & ~0xFFF)
                try:
                    uc.mem_map(bpage, need)
                except Exception:                         # noqa: BLE001
                    pass                                  # 已映射就跳过
                occupied.append((bpage, bpage + need))
                uc.mem_write(baddr, bdata)
                # 回读校验：静默失败必须变成可见结果
                readback = bytes(uc.mem_read(baddr, len(bdata)))
                buffer_applied.append({
                    "addr": hex(baddr), "size": len(bdata),
                    "verified": readback == bdata,
                    "readback_hex": readback[:16].hex(),
                })
            except Exception as exc:                      # noqa: BLE001
                buffer_skipped.append({"spec": str(spec)[:80],
                                       "reason": f"{type(exc).__name__}: {exc}"})
        if buf_bad:
            buffer_skipped.append({"spec": str(buf)[:80], "reason": buf_bad})

        # ---- 外部函数桩（(4) 通用 libc 语义；stubs=null/false 时不启用） ----
        stub_engine = None
        stubs_arg = args.get("stubs")
        if stubs_arg not in (None, False):
            try:
                from server.core.unicorn_stubs import StubEngine
                heap_size_val = parse_addr(args.get("heap_size", 0x100000))
                if heap_size_val is None or heap_size_val <= 0:
                    heap_size_val = 0x100000
                heap_size_val = (heap_size_val + page_size - 1) & ~(page_size - 1)
                if args.get("heap_base") is not None:
                    heap_base_val = parse_addr(args.get("heap_base"))
                    if heap_base_val is None:
                        return {"ok": False, "code": "BAD_ADDR",
                                "error": f"非法地址参数 heap_base={args.get('heap_base')!r}"}
                else:
                    heap_base_val = _pick_heap_base(occupied, heap_size_val)
                stub_engine = StubEngine(
                    uc, getattr(so, "plt_map", {}) or {}, stubs_arg,
                    vfs=args.get("vfs"),
                    heap_base=heap_base_val,
                    heap_size=heap_size_val,
                )
                stub_engine.setup_heap()
                from unicorn import UC_HOOK_CODE as _UC_HOOK_CODE
                uc.hook_add(_UC_HOOK_CODE, stub_engine.on_code)
            except Exception as exc:                      # noqa: BLE001
                stub_engine = None
                buffer_skipped.append({"spec": "stubs",
                                       "reason": f"桩引擎初始化失败：{type(exc).__name__}: {exc}"})

        # ---- 参数 ----
        reg_names = [f"x{i}" for i in range(8)]
        for i, rn in enumerate(reg_names):
            v = args.get(rn)
            if v is None:
                continue
            try:
                iv = parse_addr(v)
                if iv is None:
                    continue
                uc.reg_write(getattr(__import__("unicorn.arm64_const",
                                                fromlist=["x"]),
                                    f"UC_ARM64_REG_{rn.upper()}"), iv)
            except Exception:                             # noqa: BLE001
                pass

        # ---- 执行 ----
        uc.reg_write(UC_ARM64_REG_PC, addr)
        trace_log = []
        if trace:
            def hook_code(uc_, address, size, user_data):
                if len(trace_log) < 500:
                    try:
                        insn = uc_.mem_read(address, min(size, 4))
                        trace_log.append({"addr": hex(address),
                                          "bytes": insn.hex()})
                    except Exception:                     # noqa: BLE001
                        pass
            # (3) UC_HOOK_CODE = 4（1 是 UC_HOOK_INTR）
            from unicorn import UC_HOOK_CODE

            uc.hook_add(UC_HOOK_CODE, hook_code)

        # (2) 第二次修改（2026-11-18）：记录“哪些页被写过”。
        #     bug 原因：反馈「emulate_func 虽然能跑，但不给我看内存（只给寄存器
        #               和指令流）——所以拿不到输出值」。解密/解码函数的结果
        #               全在缓冲区里，寄存器通常只留一个指针，等于白跑。
        #     解决方案：dump 参数支持按范围导出 + "writes" 模式。
        #               "writes" 用 UC_HOOK_MEM_WRITE 记页号（不记字节，
        #               逐字节记录会拖死循环里的模拟），导出时给整页。
        written_pages: set[int] = set()
        dump_opt = args.get("dump")
        if dump_opt:
            try:
                from unicorn import UC_HOOK_MEM_WRITE

                def hook_write(uc_, access, address, size, value, user_data):
                    # 只记页号：见方法注释里的取舍说明
                    if len(written_pages) < 4096:
                        written_pages.add(address & ~0xFFF)
                uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
            except Exception:                             # noqa: BLE001
                pass

        stopped = {"reason": "unknown", "at": None}
        try:
            # (3) until=sentinel：只有真跳到哨兵才算正常返回
            uc.emu_start(addr, sentinel, count=max_insns)
            pc_now = uc.reg_read(UC_ARM64_REG_PC)
            if pc_now == sentinel:
                stopped = {"reason": "returned", "at": hex(pc_now)}
            else:
                # 跑满 max_insns 或被其它原因停下——**不能报 finished**
                stopped = {"reason": "instruction_limit_or_unknown",
                           "at": hex(pc_now),
                           "note": f"未返回到哨兵，可能跑满 {max_insns} 条或被阻塞"}
        except Exception as exc:                          # noqa: BLE001
            msg = str(exc)
            pc_now = uc.reg_read(UC_ARM64_REG_PC)
            if "Invalid instruction" in msg:
                stopped = {"reason": "invalid_instruction", "at": hex(pc_now)}
            elif "unmapped" in msg.lower() or "EXCEPTION" in msg:
                # (4) 跳到未映射地址：通常是 bl 到本 so 之外的库函数
                stopped = {
                    "reason": "external_call_or_unmapped",
                    "at": hex(pc_now),
                    "hint": ("目标函数调用了本 so 之外的代码（如 libc），"
                             "或访问了未映射内存。Unicorn 只映射了本 so 的 "
                             "PT_LOAD 段，无法模拟外部依赖。"
                             "可尝试：① 用 buffer 参数预置外部函数桩；"
                             "② 改用真机断点观察。"),
                }
            else:
                stopped = {"reason": msg[:160], "at": hex(pc_now)}

        # ---- 读返回现场 ----
        from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                         UC_ARM64_REG_X2, UC_ARM64_REG_X3)
        regs = {}
        from unicorn.arm64_const import (UC_ARM64_REG_FP, UC_ARM64_REG_LR,
                                         UC_ARM64_REG_SP as _SP)

        for i, reg in enumerate((UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3)):
            try:
                regs[f"x{i}"] = hex(uc.reg_read(reg))
            except Exception:                             # noqa: BLE001
                pass
        # (3) 补 pc/lr/sp/fp：没有这些无法判断"是否真的跑完"
        for nm, reg in (("pc", UC_ARM64_REG_PC), ("lr", UC_ARM64_REG_LR),
                        ("sp", _SP), ("fp", UC_ARM64_REG_FP)):
            try:
                regs[nm] = hex(uc.reg_read(reg))
            except Exception:                             # noqa: BLE001
                pass

        # 尝试读 x0 指向的字符串（很多函数返回 char*）
        out_str = None
        try:
            ret = uc.reg_read(UC_ARM64_REG_X0)
            if 0x1000 < ret < 0x7FFF00000000:
                data = uc.mem_read(ret, 128)
                nul = data.find(b"\x00")
                if nul > 0:
                    cand = bytes(data[:nul])
                    if all(32 <= c < 127 for c in cand):
                        out_str = cand.decode("ascii", "replace")
        except Exception:                                 # noqa: BLE001
            pass

        result = {
            "ok": True, "so": so.name, "entry": hex(addr),
            "mapped_segments": mapped,
            "stopped": stopped,
            "registers": regs,
            # (4) 静默失败可见化：用户传的 buffer 到底生效没有、哪条被跳过
            "buffer_applied": buffer_applied,
            "buffer_skipped": buffer_skipped,
            "note": ("Unicorn 离线模拟：不模拟 syscall，"
                     "遇到 svc/未映射调用会停住并回报现场。"),
        }
        if out_str:
            result["x0_string"] = out_str
        if stub_engine is not None:
            result["stubs"] = stub_engine.summary()

        # (2) 第二次修改（2026-11-18）：导出内存（见类 docstring 的说明）。
        if dump_opt:
            result["memory"] = self._dump_memory(
                uc, dump_opt, written_pages, covered, stack_base, stack_size,
                sp, int(args.get("dump_max", 4096)),
                trim_writes=bool(args.get("trim_writes", False)))

        if trace:
            result["trace"] = trace_log
        return result

    # ---------- 内存导出 ----------

    def _dump_memory(self, uc, dump_opt, written_pages, covered,
                     stack_base, stack_size, sp, dump_max,
                     trim_writes: bool = False):
        """按 dump 参数导出内存内容。

        返回 {regions: [{addr, size, hex, ascii, truncated, why}], note}。
        任何一段读失败都单独标注，**不伪造内容**（读不到就给 error 字段，
        绝不用零填充冒充"这块是空的"）。
        """
        regions: list[dict] = []

        def _one(a: int, size: int, why: str) -> None:
            if size <= 0:
                return
            take = min(size, dump_max)
            item = {"addr": hex(a), "size": take, "why": why}
            if take < size:
                item["truncated"] = True
                item["full_size"] = size
            try:
                data = bytes(uc.mem_read(a, take))
            except Exception as exc:                      # noqa: BLE001
                item["error"] = f"读不到：{exc}"
                regions.append(item)
                return
            item["hex"] = data.hex()
            # ASCII 视图：不可打印显示为 '.'，便于肉眼核对解出的字符串
            item["ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "." for b in data)
            # 顺手找 NUL 分隔的 C 字符串（解密结果几乎都是这种）
            strs = []
            for piece in data.split(b"\x00"):
                if len(piece) >= 4 and all(32 <= c < 127 for c in piece):
                    strs.append(piece.decode("ascii"))
            if strs:
                item["strings"] = strs[:20]
            regions.append(item)

        if isinstance(dump_opt, list):
            # 显式范围（最常用、最精确）
            for spec in dump_opt:
                try:
                    a = parse_addr(spec.get("addr"))
                    if a is None:
                        continue
                    n = int(spec.get("size", 64))
                except Exception:                         # noqa: BLE001
                    continue
                _one(a, n, "explicit")
        elif dump_opt == "stack":
            # (6) 第六次修改（2026-11-26）
            # bug 原因：原代码 low = top - stack_size == stack_base - 0x1000 落在未映射区，
            #           导致 mem_read 必败且即使不越界也会优先读到空栈底而非函数真实栈帧。
            # 解决方案：下界固定为已映射的 stack_base，优先从入口栈顶 top 向下取
            #           [max(stack_base, top - dump_max), top) 以读取真实栈帧。
            top = stack_base + stack_size - 0x1000
            low = stack_base
            start = max(low, top - dump_max)
            _one(start, top - start, "stack")
        elif dump_opt == "all":
            # 导出所有已映射区间。**不按 R/W 过滤**：covered 里没有 flags，
            # 而"只导可写段"需要额外传权限信息；与其用假判据筛掉一段，
            # 不如全给出来让调用方自己看（大样本请配小 dump_max）。
            for a, b in covered:
                _one(a, b - a, "all")
        elif dump_opt == "writes":
            for pg in sorted(written_pages):
                if trim_writes:
                    # (4) 裁尾部的连续 0：逐页导出时尾部几千个 0 纯属浪费。
                    #     从页尾往前找最后一个非零字节，只导出到那里（至少 1 字节）。
                    try:
                        page = bytes(uc.mem_read(pg, 0x1000))
                        nz = len(page.rstrip(b"\x00"))
                        size = max(nz, 1)
                    except Exception:                     # noqa: BLE001
                        size = 0x1000
                    _one(pg, size, "written_page_trimmed")
                else:
                    _one(pg, 0x1000, "written_page")
        else:
            return {"error": f"未知 dump={dump_opt!r}",
                    "code": "BAD_DUMP",
                    "hint": "支持 [{addr,size}] / 'writes' / 'stack' / 'all'"}

        return {
            "regions": regions,
            "note": ("'writes' 模式只精确到页（逐字节记录会拖死模拟），"
                     "导出的是整页；按你已知的结构自己裁。"
                     "字符串列表是按 NUL 切且全可打印的片段。"),
        }

