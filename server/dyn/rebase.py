"""静态地址与运行时地址的换算桥。

动态分析的核心难点：ASLR 与重定位使 so 加载到运行时基址，
静态分析得到的地址（如 0x5020）在内存里是 base + 0x5020。
本模块负责两个方向的换算与运行时模块定位。

依赖 frida，可脱离本项目的 core 独立测试。
"""
from __future__ import annotations

import threading
import time

import frida

# (6) 第六次修改（2026-11-13）：设备侧模块名匹配复用全项目唯一那套规则。
# 为什么从 core.session 取而不是再写一份：静态侧（Session.resolve）与
# 设备侧（find_module）一旦用不同规则，就会出现"静态认得、动态不认得"
# 的矛盾现象，而用户看到的是同一句"未加载的 so"。
from server.core.session import match_name

# (7) 第七次修改（2026-11-26）
# bug 原因：frida 17.23.3 上同步调用 script.unload() 可能永久阻塞，
#           同时反复起守护线程又会导致线程泄漏。
# 解决方案：提供带超时和并发上限的公共异步卸载辅助函数 unload_script_async，
#           供 rebase / debugger / console / bridge 共同复用。
_UNLOAD_PENDING: set[int] = set()
_UNLOAD_LOCK = threading.Lock()


def unload_script_async(script, timeout: float = 2.0) -> None:
    """在带超时与并发上限的守护线程里卸载 frida script，避免同步 unload 卡死。"""
    if script is None:
        return
    key = id(script)
    with _UNLOAD_LOCK:
        if key in _UNLOAD_PENDING or len(_UNLOAD_PENDING) >= 16:
            return
        _UNLOAD_PENDING.add(key)

    def _worker() -> None:
        try:
            script.unload()
        except Exception:                                 # noqa: BLE001
            pass
        finally:
            with _UNLOAD_LOCK:
                _UNLOAD_PENDING.discard(key)

    th = threading.Thread(target=_worker, name="mda-script-unload", daemon=True)
    th.start()
    try:
        th.join(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


class RuntimeModule:
    """目标进程中的一个已加载 so 的运行时信息。"""

    def __init__(self, name: str, base: int, size: int, path: str):
        self.name = name
        self.base = base
        self.size = size
        self.path = path

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end

    def __repr__(self) -> str:  # 调试用
        return f"RuntimeModule({self.name}, base={hex(self.base)}, size={hex(self.size)})"


class Rebase:
    """单个 so 的静态地址 <-> 运行时地址 换算器。

    用法：
        rb = Rebase.attach(device_id, pid)
        m = rb.find_module("liblog.so")
        runtime_addr = rb.to_runtime(0x5020, m)
        static_addr = rb.to_static(m.base + 0x5020, m)
    """

    def __init__(self, device: frida.core.Device, pid: int):
        self.device = device
        self.pid = pid
        self.session = device.attach(pid)
        self._modules: list[RuntimeModule] = []
        self._last_error: str = ""

    # ---------- 连接管理 ----------

    @classmethod
    def attach(cls, device_id: str, pid: int) -> "Rebase":
        d = frida.get_device(device_id, timeout=10)
        return cls(d, pid)

    def detach(self, timeout: float = 3.0) -> None:
        """断开会话。**在守护线程里做，最多等 timeout 秒**。

        (2) 第二次修改（2026-11-06）：
            bug 原因：实测 frida 17.23.3 在 Android 上，一旦为某个会话
                      create_script + load 过脚本，session.detach() 会**永久阻塞**
                      （不是慢，是完全不返回）。所有在 finally 里直接调
                      detach 的代码路径（trace_* / watch_module /
                      verify_breakpoint / rebase 自身）都会因此卡死，
                      表现为「MCP 工具调用永不返回」。
            解决方案：把真正的 detach 丢到守护线程，主线程 join 有限时间就返回。
                      守护线程随进程退出；目标进程侧的脚本由 frida 自然回收
                      或在下一次 attach 时被覆盖，不会泄漏到无法恢复。
        """
        import threading as _th

        sess = getattr(self, "session", None)
        if sess is None:
            return

        def _worker() -> None:
            try:
                sess.detach()
            except Exception:                             # noqa: BLE001
                pass

        th = _th.Thread(target=_worker, name="mda-rebase-detach", daemon=True)
        th.start()
        try:
            th.join(max(0.1, float(timeout)))
        except Exception:                                 # noqa: BLE001
            pass

    # ---------- 运行时模块 ----------

    def refresh_modules(self) -> list[RuntimeModule]:
        """枚举目标进程当前加载的全部模块。

        进程启动时间不同、按需 dlopen 的 so 会出现/消失，因此需要可刷新。
        """
        script = self.session.create_script(
            """
            var mods = Process.enumerateModules().map(function(m) {
                return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
            });
            send(mods);
            """
        )
        # (8) 第八次修改（2026-11-26）
        # bug 原因：原回调无条件按 payload=[] 处理并置 done=True，遇到 JS error 消息时
        #           既不记录错误也不抛异常，直接静默返回空列表，上层误以为进程无模块。
        # 解决方案：区分 type=="error" 并记录到 self._last_error 后向上抛出 RuntimeError。
        got: list = []
        err_box: list[str] = []
        done = {"ok": False}

        def _on_msg(msg, data) -> None:
            mtype = msg.get("type") if isinstance(msg, dict) else None
            if mtype == "error":
                desc = msg.get("description") or msg.get("stack") or "JS error"
                err_box.append(str(desc))
                done["ok"] = True
                return
            payload = msg.get("payload", []) if isinstance(msg, dict) else []
            if isinstance(payload, list):
                got.extend(payload)
            done["ok"] = True

        script.on("message", _on_msg)
        script.load()
        # 消息回调是异步的，轮询等待
        for _ in range(50):
            if done["ok"]:
                break
            time.sleep(0.1)
        if err_box:
            self._last_error = err_box[0]
            raise RuntimeError(f"refresh_modules JS error: {err_box[0]}")
        # (5) 第五次修改（2026-11-06）：**不再调用 script.unload()**。
        #     bug 原因：实测 frida 17.23.3 + 该设备上，script.unload() 会
        #               永久阻塞（不是慢，是完全不返回）。refresh_modules
        #               原来每调一次就卡在这里——靠 50×0.1s 的轮询上限
        #               才没彻底挂死，但**每次都是 25 秒**。
        #               同一个操作手写 frida 只要 0.0 秒，对比极其明显。
        #     解决方案：脚本用完不显式 unload，交给会话销毁时自动回收；
        #               本脚本只读一次模块表、无 hook，不 unload 无副作用。
        #               实测去掉后 refresh_modules 从 25.0s 降到 0.0s。

        self._modules = [
            RuntimeModule(
                name=m["name"],
                base=int(m["base"], 16),
                size=int(m["size"]),
                path=m["path"],
            )
            for m in got
        ]
        return self._modules

    def find_module(self, name: str) -> RuntimeModule | None:
        """按文件名找运行时模块，未刷新时自动刷新一次。

        (3) 第三次修改（2026-11-06）：
            bug 原因：原来只做「全名 / basename」两级的**精确**匹配。
                      于是本地文件叫 libsgmainso.so、设备上叫
                      libsgmainso-6.7.260202.so 时永远匹配不上，
                      set_breakpoint 直接报 MODULE_NOT_LOADED——
                      用户明明把 so 载进来了，却被告知"未加载"。
            解决方案：增加「去版本号」一级匹配（唯一命中才采用），
                      与 mcp_server.tools._pick_so_by_name 保持同一口径。
                      这样 set_breakpoint / read_memory / to_runtime 等
                      所有走 find_module 的路径一并受益。

        (6) 第六次修改（2026-11-13）：整套规则改为调用 core.session.match_name。
            bug 原因：这里是与 Session.resolve / tools._pick_so_by_name 并存的
                      **第三套**别名实现（全名/basename/去版本/去 lib）。三处
                      各写一遍，行为已经开始分叉：本地 liblog.so 能匹配设备
                      任意路径下的 liblog.so，但本地存成 log.so 时只有 Session
                      侧认得、rebase 这边不认，于是"静态能取到某个 so，动态
                      却报 MODULE_NOT_LOADED"，用户只能反复试名字。
            解决方案：把设备侧模块名列表交给同一份纯函数 match_name，
                      静态侧与设备侧从此**同一口径**；多候选一律返回 None
                      （动态层没有"歧义报错"的契约，宁可不匹配也不猜）。
                      唯一保留的是「未刷新时先 refresh 一次」这一设备侧行为。
        """
        if not name:
            return None

        def _pick() -> RuntimeModule | None:
            """在当前模块表里按统一规则挑唯一命中，多候选返回 None。"""
            # 设备侧可能给完整路径，match_name 自己会取 basename，无需预处理
            by_key = {m.name: m for m in self._modules}
            hit, _how, _amb = match_name(str(name), list(by_key))
            if hit is not None:
                return by_key[hit]
            # 同一 so 可能在进程里有多个实例（同名不同基址），键会重复。
            # 按基址去重后再匹配一次，保证"唯一命中"的语义不被重复键破坏。
            hit, _how, _amb = match_name(
                str(name), [m.name for m in self._modules])
            if hit is None:
                return None
            cands = [m for m in self._modules if m.name == hit]
            return cands[0] if len(cands) == 1 else None

        got = _pick()
        if got is not None:
            return got
        if not self._modules:
            self.refresh_modules()
            return _pick()
        return None

    def read_many(self, regions: list) -> list:
        """一次脚本读多段内存，返回 [{addr, ok, hex, size, err}]。

        (4) 第四次修改（2026-11-06）：
            bug 原因：read_memory 每次调用都 create_script，而建脚本 + load
                      在真机上要几百毫秒；dump_vm_state 这类需要"读计数、
                      读指针、读数组"三步的场景，光建脚本就占了大头，
                      读十几段时耗时飙升到几十秒，且每次都会打断目标。
            解决方案：提供批量接口，一个脚本读完全部段落，只在最后还原结果。
        """
        import json as _json
        import time as _time

        if not regions:
            return []
        # (9) 第九次修改（2026-11-26）
        # bug 原因：原实现把 64 位地址以整数序列化进 JSON，JS 侧按 IEEE-754 float64
        #           解析时会截断超过 53 位的 ARM64 TBI 指针（如 0xb4...），导致读歪或崩溃。
        # 解决方案：统一序列化为 "0x..." 字符串交给 JS ptr("0x...") 无损解析。
        spec = [[hex(int(r["addr"])), int(r["size"])] for r in regions]
        script = self.session.create_script(
            "var SPEC = " + _json.dumps(spec) + ";"
            "var out = [];"
            "for (var i = 0; i < SPEC.length; i++) {"
            "  try { var b = ptr(SPEC[i][0]).readByteArray(SPEC[i][1]);"
            "    out.push(b === null ? null : Array.from(new Uint8Array(b))"
            ".map(function(x){return x.toString(16).padStart(2,'0');}).join(''));"
            "  } catch (e) { out.push(null); }"
            "}"
            "send(out);"
        )
        got: list = []
        script.on("message", lambda m, d: got.extend(m.get("payload") or []))
        script.load()
        t0 = _time.time()
        while not got and _time.time() - t0 < 10.0:
            _time.sleep(0.02)

        results = []
        for i, r in enumerate(regions):
            val = got[i] if i < len(got) else None
            if val:
                results.append({"addr": int(r["addr"]), "ok": True,
                                "hex": val, "size": len(val) // 2})
            else:
                results.append({"addr": int(r["addr"]), "ok": False,
                                "err": "不可读或超时"})
        return results

    # ---------- 地址换算 ----------

    def to_runtime(self, static_addr: int, module: RuntimeModule) -> int:
        """静态地址 -> 运行时地址。

        静态基址按 0 计算（.so 是 PIE/ET_DYN，链接时基址为 0），
        若静态模型带非零基址需在上层先归零。
        """
        return module.base + static_addr

    def to_static(self, runtime_addr: int, module: RuntimeModule) -> int:
        """运行时地址 -> 静态地址。"""
        return runtime_addr - module.base

    # ---------- 内存读取 ----------

    def read_memory(self, addr: int, size: int) -> bytes:
        """读取目标进程内存。

        bug 原因：frida 17 移除了全局 Memory.readByteArray，需用
        ptr().readByteArray；且 send 二进制经 data 通道返回时在部分
        版本下 data 为 None，故在 JS 端转 hex 字符串走 JSON 通道，稳定。
        解决：JS 内 Uint8Array 转 hex，Python 端 bytes.fromhex 还原。
        """
        # (10) 第十次修改（2026-11-26）
        # bug 原因：① ptr({hex(addr)}) 缺少引号，JS 解析为 float64 数字会截断 ARM64 TBI 64 位指针；
        #           ② 同步调用 script.unload() 在 frida 17.23.3 上会永久阻塞。
        # 解决方案：地址改为带引号字符串 ptr("0x...")；unload 改为带超时的异步卸载 unload_script_async。
        script = self.session.create_script(
            f"""
            try {{
                var buf = ptr("{hex(int(addr))}").readByteArray({int(size)});
                if (buf === null) {{
                    send({{err: "unreadable"}});
                }} else {{
                    send({{
                        hex: Array.from(new Uint8Array(buf))
                            .map(function(x) {{ return x.toString(16).padStart(2, "0"); }})
                            .join("")
                    }});
                }}
            }} catch (e) {{
                send({{err: String(e)}});
            }}
            """
        )
        got: list = []

        def _on_msg(msg, data) -> None:
            if isinstance(msg, dict) and msg.get("type") == "error":
                got.append({"err": msg.get("description") or "JS error"})
                return
            got.append(msg.get("payload", {}) if isinstance(msg, dict) else {})

        script.on("message", _on_msg)
        script.load()
        for _ in range(50):
            if got:
                break
            time.sleep(0.1)
        unload_script_async(script, timeout=2.0)
        if not got:
            return b""
        payload = got[0]
        if "err" in payload or "hex" not in payload:
            return b""
        return bytes.fromhex(payload["hex"])
    # ---------------------------------------------------------------- adb 直读
    def read_memory_proc(self, serial: str, pid: int, addr: int,
                         size: int) -> bytes:
        """直接从 /proc/<pid>/mem 读内存，**完全不经过 frida**。

        (1) 第一次修改（2026-11-16）：
            bug 原因：read_memory 用 create_script 读，而它依赖**同一个 frida
                      session**。当 hold 断点把目标线程挂在 recv().wait() 里时，
                      该 session 会失效，报 "InvalidOperationError: session is gone"。
                      于是「下断点 → 读内存 → 分析」这条最核心的工作流被切断，
                      hold 断点只能用来抓寄存器，价值少一半。
                      而原文档还写着"挂起状态下可以放心调用"——承诺过头了。
            解决方案：新增本方法，走 adb shell + dd 读 /proc/<pid>/mem。
                      这条链路与 frida 完全无关，hold 挂多久都能读。

        实现要点（都是实测出来的）：
          · dd 的 skip 以 bs 为单位。**绝不能用 bs=1 读大块**——
            bs=1 时 skip 是按字节寻址没错，但 count=4096 要 dd 循环 4096 次，
            实测 4KB 要 12 秒。改为 bs=size 时 skip 只能写 1（从头读），不行。
            折中：用 bs=1 但把 count 限制在 512 以内（512 次仍有约 1.5 秒）。
            更好的做法是 bs=4096 + 按页对齐分块，见实现。
          · 地址必须在 maps 里可读，否则 dd 报错或读到空。
          · od 输出是空格分隔的十六进制，跨行需要全部拼接。
        """
        import re
        import subprocess

        if not (1 <= int(size) <= 4096):
            raise ValueError("size 必须在 1..4096")
        addr = int(addr)
        want = int(size)

        # 按页对齐分块读：bs 固定 4096，用 skip=页号，再裁掉页内偏移。
        # 这样每页只付一次 dd 启动开销（约 30ms），4KB 约 100ms。
        out = bytearray()
        cur = addr
        remain = want
        while remain > 0:
            page = cur & ~0xFFF
            in_page = cur - page
            take = min(4096 - in_page, remain)
            hexs = self._dd_page(serial, pid, page, 4096)
            if not hexs:
                break                       # 这一页读不到，停在已读到的位置
            chunk = bytes.fromhex(hexs)
            out.extend(chunk[in_page:in_page + take])
            cur += take
            remain -= take
            if len(chunk) < 4096:
                break                       # 页尾已到可读边界
        return bytes(out)

    def _dd_page(self, serial: str, pid: int, page_addr: int,
                 size: int = 4096) -> str:
        """用 dd 读一页，返回纯 hex 字符串（读不到返回空串）。"""
        import subprocess

        skip = page_addr // 4096
        cmd = (f"dd if=/proc/{int(pid)}/mem bs=4096 skip={skip} count=1 "
               f"2>/dev/null | od -An -tx1 -v")
        try:
            # (2) 必须走 resolve_adb()：打包后 PATH 里没有 homebrew 的 adb，
            #     硬编码裸 "adb" 会让这条链路在发布版里 100% 失效。
            from server.dyn.adb import resolve_adb

            r = subprocess.run(
                [resolve_adb(), "-s", str(serial), "shell",
                 f"su -c {_shq(cmd)}"],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:                                 # noqa: BLE001
            return ""
        raw = (r.stdout or "").strip()
        if not raw:
            return ""
        # od 输出形如 " 61 72 74 0a ..."，跨行要全拼起来
        hexs = "".join(raw.split())
        return hexs if len(hexs) >= 2 else ""


def _shq(s: str) -> str:
    """把命令包成单引号形式，供 su -c 使用（内部单引号转义）。"""
    return "'" + str(s).replace("'", "'\\''") + "'"

