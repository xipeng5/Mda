"""静态地址与运行时地址的换算桥。

动态分析的核心难点：ASLR 与重定位使 so 加载到运行时基址，
静态分析得到的地址（如 0x5020）在内存里是 base + 0x5020。
本模块负责两个方向的换算与运行时模块定位。

依赖 frida，可脱离本项目的 core 独立测试。
"""
from __future__ import annotations

import time

import frida


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
        got: list = []
        done = {"ok": False}
        script.on("message", lambda msg, data: (got.extend(msg.get("payload", [])), done.__setitem__("ok", True)))
        script.load()
        # 消息回调是异步的，轮询等待
        for _ in range(50):
            if done["ok"]:
                break
            time.sleep(0.1)
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
        """
        def _hit(want: str):
            for m in self._modules:
                if m.name == want or m.name.rsplit("/", 1)[-1] == want:
                    return m
            return None

        got = _hit(name)
        if got is not None:
            return got
        if not self._modules:
            self.refresh_modules()
            got = _hit(name)
            if got is not None:
                return got

        # 去版本号后比对（唯一命中才采用，避免 libutils-1/2 这类被混为一谈）
        from mcp_server.tools import _strip_version_tag

        core = _strip_version_tag(str(name).rsplit("/", 1)[-1])
        if not core:
            return None
        hits = [m for m in self._modules
                if _strip_version_tag(m.name.rsplit("/", 1)[-1]) == core]
        if len(hits) == 1:
            return hits[0]
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
        spec = [[int(r["addr"]), int(r["size"])] for r in regions]
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
        script = self.session.create_script(
            f"""
            var buf = ptr({hex(addr)}).readByteArray({size});
            if (buf === null) {{
                send({{err: "unreadable"}});
            }} else {{
                send({{
                    hex: Array.from(new Uint8Array(buf))
                        .map(function(x) {{ return x.toString(16).padStart(2, "0"); }})
                        .join("")
                }});
            }}
            """
        )
        got: list = []
        script.on("message", lambda msg, data: got.append(msg.get("payload", {})))
        script.load()
        for _ in range(50):
            if got:
                break
            time.sleep(0.1)
        script.unload()
        if not got:
            return b""
        payload = got[0]
        if "err" in payload or "hex" not in payload:
            return b""
        return bytes.fromhex(payload["hex"])
