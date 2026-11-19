"""Unicorn 外部函数桩引擎（通用能力，不含任何 so/函数地址特征）。

## 解决什么问题

Unicorn 只把 so 的 PT_LOAD 段映射进模拟内存，**不做动态链接**。
所以 `bl malloc` / `bl memcpy` 会走到 PLT → 从 GOT 取函数地址 →
GOT 在未重定位的 so 文件里是 0 → `br x16` 跳到 0x0 崩溃。
结果就是：任何依赖 libc 的函数都跑不过去，只能验证纯算法。

本模块在 **PLT 入口**拦截，用纯 Python 实现常见 libc 函数的语义，
设好返回值/内存后把 PC 拉回 LR（调用点下一条），跳过整条 GOT 链。

## 拦截原理（实验验证过）

AArch64 的 `bl <plt>` 会把 LR 设成调用点的下一条指令。
在 UC_HOOK_CODE 回调里命中 PLT 地址时：
  1. 按函数语义读写模拟内存、设 x0
  2. `reg_write(UC_ARM64_REG_PC, reg_read(UC_ARM64_REG_LR))`
执行流就回到调用点继续，相当于这个外部函数"返回了"。

## 通用性

函数名 → PLT 地址的映射由调用方提供（`SoFile.plt_map`，格式 {addr: name}）。
本模块只认**通用 libc / C++ ABI 名字**，没有任何具体样本的特征。

## 能力边界（诚实说明）

  · 只拦 PLT 入口。`ldr x16,[got]; blr x16` 这种绕过 PLT 的调用拦不到
  · 不重定位 GOT，只让被 stub 的函数跳过
  · 复杂格式化（%f/宽度/精度）只做最小支持
  · 不是真 libc，不保证与特定 ROM 的实现逐字节一致
"""
from __future__ import annotations

import re

# 通用 libc / C++ ABI 函数 → 默认处理策略。
# 值语义：native=用 Python 实现真实语义；noop=直接返回 0；
#         vfs=走虚拟文件系统；report=报错中止（说明触发了异常路径）。
DEFAULT_STUBS: dict[str, str] = {
    # 堆分配
    "malloc": "native", "calloc": "native", "realloc": "native", "free": "noop",
    "_Znwm": "native", "_ZdlPv": "noop", "_ZdaPv": "noop", "operator new": "native",
    "operator delete": "noop",
    # 内存操作
    "memcpy": "native", "memmove": "native", "memset": "native",
    "memcmp": "native", "memchr": "native", "bcopy": "native", "bzero": "native",
    "__memcpy_chk": "native", "__memset_chk": "native", "__memmove_chk": "native",
    # 字符串
    "strlen": "native", "strnlen": "native", "strcmp": "native",
    "strncmp": "native", "strcpy": "native", "strncpy": "native",
    "strcat": "native", "strncat": "native", "strdup": "native",
    "strchr": "native", "strrchr": "native", "strstr": "native",
    "strtol": "native", "strtoul": "native", "atoi": "native", "atol": "native",
    # 文件 I/O（走 vfs）
    "fopen": "vfs", "freopen": "vfs", "fclose": "vfs", "fread": "vfs",
    "fwrite": "vfs", "fseek": "vfs", "ftell": "vfs", "rewind": "vfs",
    "fgets": "vfs", "fputs": "vfs", "fprintf": "vfs", "fflush": "vfs",
    "open": "vfs", "openat": "vfs", "read": "vfs", "write": "vfs",
    "close": "vfs", "lseek": "vfs", "stat": "vfs", "access": "vfs",
    # 格式化
    "snprintf": "native", "sprintf": "native", "vsnprintf": "native",
    "printf": "noop", "puts": "noop", "putchar": "noop",
    # 线程 / 同步（攻击者常用，直接 noop）
    "pthread_mutex_lock": "noop", "pthread_mutex_unlock": "noop",
    "pthread_mutex_init": "noop", "pthread_mutex_destroy": "noop",
    "pthread_create": "noop", "pthread_join": "noop", "pthread_exit": "noop",
    "pthread_once": "noop", "pthread_getspecific": "noop",
    "pthread_setspecific": "noop", "pthread_key_create": "noop",
    "pthread_self": "noop", "sched_yield": "noop", "usleep": "noop",
    "sleep": "noop",
    # 运行时 / 初始化
    "__stack_chk_fail": "report", "abort": "report", "exit": "report",
    "_exit": "report", "assert": "report", "__assert_fail": "report",
    "__cxa_atexit": "noop", "__cxa_finalize": "noop", "__cxa_begin_catch": "noop",
    "__cxa_end_catch": "noop", "__gxx_personality_v0": "noop",
    "__errno_location": "noop", "errno": "noop",
    "getenv": "noop", "malloc_usable_size": "noop",
    "dlopen": "noop", "dlsym": "noop", "dlclose": "noop",
}


class StubEngine:
    """外部函数桩引擎。由 emulate_func 创建并注册 hook。

    参数：
      uc          Unicorn 实例（已映射好 so 段与栈）
      plt_map     {addr: name}，来自 SoFile.plt_map
      stubs       None=不启用；"auto"=全套默认；dict={函数名或"0x地址": 策略}
      vfs         {路径: hex字符串} 或 {路径: {"hex":..., "pos":int}}
      heap_base   堆基址（默认 0x400000）
      heap_size   堆大小（默认 0x100000）
      auto_fill   stubs 是 dict 时，未列出的已知 libc 函数是否自动补齐（默认 True）
    """

    def __init__(self, uc, plt_map: dict, stubs, vfs=None,
                 heap_base: int = 0x400000, heap_size: int = 0x100000,
                 auto_fill: bool = True):
        self.uc = uc
        self.name_to_addr: dict[str, int] = {}
        self.addr_to_name: dict[int, str] = {}
        for a, n in (plt_map or {}).items():
            try:
                ai = int(a) if not isinstance(a, str) else int(a, 0)
            except (ValueError, TypeError):
                continue
            self.name_to_addr[n] = ai
            self.addr_to_name[ai] = n

        # 汇总最终生效的 stub 表
        table: dict[str, str] = {}
        if stubs == "auto" or stubs is True:
            table = dict(DEFAULT_STUBS)
        elif isinstance(stubs, dict):
            for k, v in stubs.items():
                key = str(k)
                if key.lower().startswith("0x"):
                    # 直接给地址：映射到名字（找不到就用地址本身当 key）
                    nm = self.addr_to_name.get(int(key, 16), key)
                else:
                    nm = key
                table[nm] = str(v).lower()
            if auto_fill:
                for nm, policy in DEFAULT_STUBS.items():
                    table.setdefault(nm, policy)
        elif stubs:
            # 给了无法识别的类型 → 不启用，但把原因留给调用方
            table = {}
        self.table = table
        self.enabled = bool(table)
        self.vfs = self._normalize_vfs(vfs or {})

        self.heap_base = int(heap_base)
        self.heap_size = int(heap_size)
        self.heap_next = self.heap_base
        self.heap_mapped = False
        self._files: dict[int, dict] = {}       # FILE* → {path, pos}
        self.calls: list[dict] = []             # 调用记录
        self.errors: list[str] = []

    # ---------- 初始化 ----------
    def setup_heap(self):
        """映射堆区。已映射（buffer 用了同地址）时不重复映射。"""
        if not self.enabled or self.heap_mapped:
            return
        from unicorn import UC_PROT_ALL
        try:
            self.uc.mem_map(self.heap_base, self.heap_size, UC_PROT_ALL)
            self.heap_mapped = True
        except Exception as exc:                 # noqa: BLE001
            # 已映射视为可用（buffer 可能先占了这段）
            self.heap_mapped = True
            self.errors.append(f"heap 0x{self.heap_base:x} 映射异常（可能已映射）：{exc}")

    @staticmethod
    def _normalize_vfs(vfs: dict) -> dict[str, dict]:
        """把 {path: hex|dict} 归一化成 {path: {"data":bytes,"pos":int}}。"""
        out = {}
        for path, val in vfs.items():
            if isinstance(val, dict):
                h = val.get("hex") or val.get("data") or ""
                pos = int(val.get("pos", 0))
            else:
                h, pos = str(val), 0
            try:
                data = bytes.fromhex(h.replace(" ", "")) if h else b""
            except ValueError:
                data = h.encode("utf-8", "replace")
            out[str(path)] = {"data": data, "pos": pos}
        return out

    # ---------- hook ----------
    def on_code(self, uc, addr, size, user_data):
        """UC_HOOK_CODE 回调：命中 PLT 且被 stub 就执行语义并跳过。"""
        if not self.enabled:
            return
        name = self.addr_to_name.get(addr)
        if name is None:
            # 兼容：用户直接给地址当 key（没对应符号名）
            key = hex(addr)
            if key not in self.table:
                return
            name = key
        policy = self.table.get(name)
        if policy is None:
            return
        try:
            self._dispatch(name, policy, uc)
        except Exception as exc:                 # noqa: BLE001
            self.errors.append(f"stub {name} 失败：{type(exc).__name__}: {exc}")
            # 即使失败也要拉回 PC，否则会掉进 GOT=0 崩在 0x0
            self._write_reg(uc, "x0", 0)
        from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_PC
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _dispatch(self, name: str, policy: str, uc):
        if policy == "report":
            self.errors.append(f"触发异常路径 stub: {name}")
            self._write_reg(uc, "x0", 0)
            return
        if policy == "noop":
            self._write_reg(uc, "x0", 0)
            self.calls.append({"name": name, "policy": "noop", "ret": 0})
            return
        # heap:0x... 形式的 malloc 策略 → 重设堆起点
        if policy.startswith("heap:"):
            try:
                self.heap_base = int(policy.split(":", 1)[1], 0)
                self.heap_next = self.heap_base
                self.heap_mapped = False
                self.setup_heap()
            except ValueError:
                pass
            policy = "native"

        handler = getattr(self, "_stub_" + re.sub(r"[^a-zA-Z0-9_]", "_", name), None)
        if handler is None:
            # vfs 策略兜底；其余按 native 的通用 noop 返回
            if policy == "vfs":
                handler = self._stub_fopen
            else:
                self._write_reg(uc, "x0", 0)
                self.calls.append({"name": name, "policy": policy, "ret": 0,
                                   "note": "无专用语义，返回 0"})
                return
        ret = handler(uc)
        self.calls.append({"name": name, "policy": policy,
                           "ret": hex(ret) if isinstance(ret, int) else ret})

    # ---------- 寄存器/内存小工具 ----------
    @staticmethod
    def _write_reg(uc, name: str, value: int):
        from unicorn.arm64_const import __dict__ as C
        reg = C.get("UC_ARM64_REG_" + name.upper())
        if reg is not None:
            uc.reg_write(reg, value & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def _read_reg(uc, name: str) -> int:
        from unicorn.arm64_const import __dict__ as C
        reg = C.get("UC_ARM64_REG_" + name.upper())
        return uc.reg_read(reg) if reg is not None else 0

    def _cstr(self, uc, addr: int, limit: int = 4096) -> str:
        if not addr:
            return ""
        out = bytearray()
        for i in range(limit):
            try:
                b = bytes(uc.mem_read(addr + i, 1))[0]
            except Exception:                     # noqa: BLE001
                break
            if b == 0:
                break
            out.append(b)
        return out.decode("utf-8", "replace")

    def _alloc(self, size: int, zero: bool = False) -> int:
        if size <= 0 or size > self.heap_size:
            self.errors.append(f"分配大小异常 {size}，返回 0")
            return 0
        addr = (self.heap_next + 15) & ~15
        if addr + size > self.heap_base + self.heap_size:
            self.errors.append("堆耗尽，返回 0")
            return 0
        self.heap_next = addr + size
        if zero:
            self.uc.mem_write(addr, b"\x00" * size)
        return addr

    # ---------- 各函数语义 ----------
    def _stub_malloc(self, uc):
        p = self._alloc(self._read_reg(uc, "x0"))
        self._write_reg(uc, "x0", p)
        return p

    def _stub_calloc(self, uc):
        n, s = self._read_reg(uc, "x0"), self._read_reg(uc, "x1")
        p = self._alloc(n * s, zero=True)
        self._write_reg(uc, "x0", p)
        return p

    def _stub_realloc(self, uc):
        old, size = self._read_reg(uc, "x0"), self._read_reg(uc, "x1")
        # 不知道旧块大小，保守做法：分配新块，尽量复制 min(size, 0x1000)
        p = self._alloc(size)
        if p and old:
            try:
                n = min(size, 0x1000)
                self.uc.mem_write(p, bytes(self.uc.mem_read(old, n)))
            except Exception:                     # noqa: BLE001
                pass
        self._write_reg(uc, "x0", p)
        return p

    def _stub_memcpy(self, uc):
        dst, src, n = (self._read_reg(uc, r) for r in ("x0", "x1", "x2"))
        data = bytes(uc.mem_read(src, n)) if n else b""
        if n:
            uc.mem_write(dst, data)
        self._write_reg(uc, "x0", dst)
        return dst

    _stub_memmove = _stub_memcpy
    _stub___memcpy_chk = _stub_memcpy
    _stub___memmove_chk = _stub_memcpy

    def _stub_memset(self, uc):
        dst, c, n = (self._read_reg(uc, r) for r in ("x0", "x1", "x2"))
        if n:
            uc.mem_write(dst, bytes([c & 0xFF]) * n)
        self._write_reg(uc, "x0", dst)
        return dst

    _stub___memset_chk = _stub_memset
    _stub_bzero = _stub_memset

    def _stub_memcmp(self, uc):
        a, b, n = (self._read_reg(uc, r) for r in ("x0", "x1", "x2"))
        da = bytes(uc.mem_read(a, n)) if n else b""
        db = bytes(uc.mem_read(b, n)) if n else b""
        ret = 0 if da == db else next((x - y for x, y in zip(da, db) if x != y), 1)
        self._write_reg(uc, "x0", ret & 0xFFFFFFFFFFFFFFFF)
        return ret

    def _stub_strlen(self, uc):
        s = self._cstr(uc, self._read_reg(uc, "x0"))
        n = len(s.encode("utf-8", "replace"))
        self._write_reg(uc, "x0", n)
        return n

    def _stub_strnlen(self, uc):
        p, m = self._read_reg(uc, "x0"), self._read_reg(uc, "x1")
        n = 0
        while n < m:
            try:
                if bytes(uc.mem_read(p + n, 1))[0] == 0:
                    break
            except Exception:                     # noqa: BLE001
                break
            n += 1
        self._write_reg(uc, "x0", n)
        return n

    def _stub_strcmp(self, uc):
        a = self._cstr(uc, self._read_reg(uc, "x0"))
        b = self._cstr(uc, self._read_reg(uc, "x1"))
        ret = (a > b) - (a < b)
        self._write_reg(uc, "x0", ret & 0xFFFFFFFFFFFFFFFF)
        return ret

    def _stub_strncmp(self, uc):
        a = self._cstr(uc, self._read_reg(uc, "x0"))
        b = self._cstr(uc, self._read_reg(uc, "x1"))
        n = self._read_reg(uc, "x2")
        ret = (a[:n] > b[:n]) - (a[:n] < b[:n])
        self._write_reg(uc, "x0", ret & 0xFFFFFFFFFFFFFFFF)
        return ret

    def _stub_strcpy(self, uc):
        dst, src = self._read_reg(uc, "x0"), self._read_reg(uc, "x1")
        data = self._cstr(uc, src).encode("utf-8", "replace") + b"\x00"
        uc.mem_write(dst, data)
        self._write_reg(uc, "x0", dst)
        return dst

    def _stub_strncpy(self, uc):
        dst, src, n = (self._read_reg(uc, r) for r in ("x0", "x1", "x2"))
        data = self._cstr(uc, src).encode("utf-8", "replace")[:n]
        if len(data) < n:
            data += b"\x00" * (n - len(data))
        uc.mem_write(dst, data)
        self._write_reg(uc, "x0", dst)
        return dst

    def _stub_fopen(self, uc):
        path = self._cstr(uc, self._read_reg(uc, "x0"))
        # 找 vfs：精确路径 → basename → 第一个
        key = next((k for k in self.vfs if k == path), None)
        if key is None:
            base = path.rsplit("/", 1)[-1]
            key = next((k for k in self.vfs if k.rsplit("/", 1)[-1] == base), None)
        if key is None and self.vfs:
            key = next(iter(self.vfs))
        self.vfs.setdefault(key, {"data": b"", "pos": 0})
        self.vfs[key]["pos"] = 0
        fp = self._alloc(0x20, zero=True)
        if fp:
            self._files[fp] = {"path": key, "pos": 0}
        self._write_reg(uc, "x0", fp)
        return fp

    def _stub_fread(self, uc):
        ptr, size, nmemb, fp = (self._read_reg(uc, r) for r in ("x0", "x1", "x2", "x3"))
        info = self._files.get(fp)
        if info is None:
            self._write_reg(uc, "x0", 0)
            return 0
        v = self.vfs[info["path"]]
        data = v["data"]
        n = min(size * nmemb, max(0, len(data) - info["pos"]))
        if n:
            uc.mem_write(ptr, data[info["pos"]:info["pos"] + n])
            info["pos"] += n
            v["pos"] = info["pos"]
        cnt = n // size if size else 0
        self._write_reg(uc, "x0", cnt)
        return cnt

    def _stub_fwrite(self, uc):
        ptr, size, nmemb, fp = (self._read_reg(uc, r) for r in ("x0", "x1", "x2", "x3"))
        info = self._files.get(fp)
        n = size * nmemb
        if info:
            v = self.vfs[info["path"]]
            v["data"] += bytes(uc.mem_read(ptr, n)) if n else b""
        self._write_reg(uc, "x0", nmemb)
        return nmemb

    def _stub_fclose(self, uc):
        self._files.pop(self._read_reg(uc, "x0"), None)
        self._write_reg(uc, "x0", 0)
        return 0

    def _stub_fseek(self, uc):
        fp, off, whence = (self._read_reg(uc, r) for r in ("x0", "x1", "x2"))
        info = self._files.get(fp)
        if info:
            v = self.vfs[info["path"]]
            base = 0 if whence == 0 else (info["pos"] if whence == 1 else len(v["data"]))
            info["pos"] = max(0, base + off)
            v["pos"] = info["pos"]
        self._write_reg(uc, "x0", 0)
        return 0

    def _stub_ftell(self, uc):
        info = self._files.get(self._read_reg(uc, "x0"))
        pos = info["pos"] if info else 0
        self._write_reg(uc, "x0", pos)
        return pos

    def _fmt_arg(self, uc, idx: int, conv: str) -> str:
        """从 x3..x7 取变参（snprintf 的第4个起），按转换符格式化。"""
        regs = ["x3", "x4", "x5", "x6", "x7"]
        if idx >= len(regs):
            return ""
        v = self._read_reg(uc, regs[idx])
        if conv == "s":
            return self._cstr(uc, v)
        if conv in ("d", "i"):
            return str(v if v < (1 << 63) else v - (1 << 64))
        if conv == "u":
            return str(v)
        if conv in ("x", "X", "p"):
            return (hex(v) if conv == "p" else format(v, conv))
        return str(v)

    def _mini_snprintf(self, uc, fmt: str) -> tuple[str, int]:
        """最小 printf 格式化：%s %d %u %x %X %p %% 及 %02x 这类零填充。"""
        out, i, argi = [], 0, 0
        while i < len(fmt):
            if fmt[i] != "%" or i + 1 >= len(fmt):
                out.append(fmt[i]); i += 1; continue
            if fmt[i + 1] == "%":
                out.append("%"); i += 2; continue
            m = re.match(r"%(-?)(0?)(\d*)([sdiuxXp])", fmt[i:])
            if not m:
                out.append(fmt[i]); i += 1; continue
            _, zero, width, conv = m.groups()
            s = self._fmt_arg(uc, argi, conv)
            if width:
                w = int(width)
                s = s.zfill(w) if zero and not s.startswith("-") else s.rjust(w)
            out.append(s); argi += 1; i += 1 + len(m.group(0))
        text = "".join(out)
        return text, argi

    def _stub_snprintf(self, uc):
        buf, size = self._read_reg(uc, "x0"), self._read_reg(uc, "x1")
        fmt = self._cstr(uc, self._read_reg(uc, "x2"))
        text, _ = self._mini_snprintf(uc, fmt)
        data = text.encode("utf-8", "replace")
        if size:
            uc.mem_write(buf, data[:size - 1] + b"\x00")
        self._write_reg(uc, "x0", len(data))
        return len(data)

    _stub_sprintf = _stub_snprintf
    _stub_vsnprintf = _stub_snprintf

    def summary(self) -> dict:
        """调用方拿来回填 emulate_func 返回结构。"""
        return {
            "stub_enabled": self.enabled,
            "stub_count": len(self.table),
            "stub_calls": self.calls[:200],
            "stub_errors": self.errors[:50],
            "vfs_paths": list(self.vfs),
            "heap": [hex(self.heap_base), hex(self.heap_next)],
        }
