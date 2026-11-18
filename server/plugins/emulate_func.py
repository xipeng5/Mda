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

## 通用性

纯 Unicorn API 封装 + ELF 段加载，不含任何具体 so/函数特征。
"""
from __future__ import annotations

from pathlib import Path

from server.core.plugins import PluginBase


class Plugin(PluginBase):
    name = "emulate_func"
    description = "用 Unicorn 本地模拟执行 ARM64 函数（离线、不碰真机）"
    usage = ("args: {so: str, addr: str|int, "
             "x0..x7: str (可选参数), stack_size: int=0x10000, "
             "buffer: {addr, hex} (可选内存初始化), "
             "max_insns: int=100000, trace: bool=false}")

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

        path = getattr(so, "path", None)
        if not path or not Path(path).exists():
            return {"error": f"找不到 so 文件：{path}", "code": "NO_FILE"}

        a = args["addr"]
        addr = int(str(a), 16) if isinstance(a, str) and \
            str(a).lower().startswith("0x") else int(a)
        max_insns = int(args.get("max_insns", 100000))
        trace = bool(args.get("trace", False))

        # ---- 建模拟器并映射 so 的所有 PT_LOAD 段 ----
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        raw = Path(path).read_bytes()
        # 用文件的 PT_LOAD 段布局映射（so._loads 是 (vaddr, end, off, flags)）
        loads = getattr(so, "_loads", []) or []
        if not loads:
            return {"error": "so 没有 PT_LOAD 段信息，无法映射",
                    "code": "NO_LOADSEG"}

        mapped = []
        page_size = 0x1000
        covered: list[tuple[int, int]] = []
        for vaddr, vend, off, flags in loads:
            size = vend - vaddr
            if size <= 0:
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
            chunk = raw[off:off + size] if off + size <= len(raw) else raw[off:]
            if chunk:
                uc.mem_write(vaddr, chunk)
            mapped.append({"vaddr": hex(vaddr), "size": size,
                           "flags": hex(flags), "file_off": hex(off)})

        # ---- 栈 ----
        stack_size = int(args.get("stack_size", 0x10000))
        stack_base = 0x7FFF00000000
        uc.mem_map(stack_base, stack_size)
        sp = stack_base + stack_size - 0x1000
        uc.reg_write(UC_ARM64_REG_SP, sp)
        # (3) LR 指向哨兵页：函数 ret 会跳到哨兵，据此判"正常返回"。
        #     不设的话 LR=0，而 until=0 会把"跳到 0"当成正常结束（实测恒 finished）。
        sentinel = stack_base + 0x100        # 哨兵页（已映射区域内）
        from unicorn.arm64_const import UC_ARM64_REG_LR

        uc.reg_write(UC_ARM64_REG_LR, sentinel)

        # ---- 调用方准备的内存 ----
        buf = args.get("buffer")
        if isinstance(buf, dict) and buf.get("addr") and buf.get("hex"):
            baddr = int(str(buf["addr"]), 16) if str(buf["addr"]).lower().startswith("0x") \
                else int(buf["addr"])
            bdata = bytes.fromhex(str(buf["hex"]))
            bpage = baddr & ~0xFFF
            need = ((baddr - bpage) + len(bdata) + 0xFFF) & ~0xFFF
            try:
                uc.mem_map(bpage, need)
            except Exception:                             # noqa: BLE001
                pass                                      # 已映射就跳过
            uc.mem_write(baddr, bdata)

        # ---- 参数 ----
        reg_names = [f"x{i}" for i in range(8)]
        for i, rn in enumerate(reg_names):
            v = args.get(rn)
            if v is None:
                continue
            try:
                iv = int(str(v), 16) if str(v).lower().startswith("0x") else int(v)
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
            "note": ("Unicorn 离线模拟：不模拟 syscall，"
                     "遇到 svc/未映射调用会停住并回报现场。"),
        }
        if out_str:
            result["x0_string"] = out_str
        if trace:
            result["trace"] = trace_log
        return result
