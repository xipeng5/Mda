"""假 frida：供动态层单元测试使用，不连接任何设备。

为什么需要它：
    动态分析的真实验证依赖一台连着 frida-server 的 Android 设备。
    但本机环境并不总是具备该条件（用户手机上常有别的工具占用
    frida-server），而且把单元测试绑死在真机上会让 CI 与日常回归
    都无法执行。故这里用最小可用的假实现覆盖被测代码实际用到的
    接口面，让状态机、事件流、寄存器采集这类纯逻辑可以离线验证。

使用约定：
    - 只实现 dyn/ 下真实代码调用到的成员，不做通用模拟。
    - 时间与线程行为尽量贴近真实语义（例如 recv 会阻塞）。
    - 任何真机专有行为（如 Interceptor 的真实改写）不在此模拟，
      这属于集成测试范畴，不应在单测里伪造。
"""
from __future__ import annotations

import threading


class FakeScript:
    """模拟 frida.core.Script。

    关键语义：
      - post() 把消息投进队列，供 JS 侧的 recv() 消费；
      - exports_sync 提供同步调用入口；
      - load()/unload() 只记录调用，不产生副作用。
    """

    def __init__(self, source: str = "", session: "FakeSession | None" = None):
        self.source = source
        self.session = session
        self.loaded = False
        self.unloaded = False
        self.posted: list[dict] = []
        self._message_handlers: list = []
        self._post_queue: list[dict] = []
        self._post_event = threading.Event()
        self.exports_sync = _FakeExports(self)

    # ---------- 生命周期 ----------

    def load(self) -> None:
        self.loaded = True

    def unload(self) -> None:
        self.unloaded = True

    def detach(self) -> None:
        self.unloaded = True

    # ---------- 消息 ----------

    def on(self, event: str, callback) -> None:
        if event == "message":
            self._message_handlers.append(callback)

    def post(self, message: dict) -> None:
        """Python -> JS 方向：真实 frida 里这会触发 JS 的 recv()。

        测试里只需记录，用于断言 resume 是否真的发出了唤醒消息。
        """
        self.posted.append(message)
        self._post_queue.append(message)
        self._post_event.set()

    def take_posted(self, timeout: float = 1.0) -> dict | None:
        """取出待投递的消息（模拟 JS 侧消费）。"""
        if not self._post_queue and not self._post_event.wait(timeout):
            return None
        if self._post_queue:
            self._post_event.clear()
            return self._post_queue.pop(0)
        return None

    # ---------- 模拟 JS 发消息给 Python ----------

    def emit(self, payload, msg_type: str = "send") -> None:
        """模拟 JS 侧 send()：把消息分发给已注册的处理器。"""
        msg = {"type": msg_type, "payload": payload}
        for cb in list(self._message_handlers):
            cb(msg, None)


class _FakeExports:
    """模拟 script.exports_sync（JS 的 rpc.exports）。

    JS 侧导出名是 camelCase，Python 侧是 snake_case，
    真实 frida 会自动做这层映射，这里保持一致。
    """

    def __init__(self, script: FakeScript):
        self._script = script

    def __getattr__(self, name: str):
        def _call(*args, **kwargs):
            # 记录被调用的导出方法，供测试断言
            self._script.posted.append({"__export__": name, "args": args})
            return None

        return _call


class FakeSession:
    """模拟 frida.core.Session。"""

    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.detached = False
        self.scripts: list[FakeScript] = []

    def create_script(self, source: str = "") -> FakeScript:
        s = FakeScript(source, self)
        self.scripts.append(s)
        return s

    def detach(self) -> None:
        self.detached = True

    def on(self, event: str, callback) -> None:  # 真实 frida 支持，这里空实现
        pass


class FakeModule:
    def __init__(self, name: str, base: int, size: int, path: str = ""):
        self.name = name
        self.base = base
        self.size = size
        self.path = path or f"/data/app/lib/{name}"


class FakeRebase:
    """模拟 dyn.rebase.Rebase（只实现 dyn/debugger.py 与 service 用到的部分）。"""

    def __init__(self, modules: list[FakeModule] | None = None, session: FakeSession | None = None):
        self.session = session or FakeSession()
        self.device = None
        self.pid = self.session.pid
        self._modules = modules or [FakeModule("libtarget.so", 0x7000000000, 0x10000)]
        self.memory: dict[int, bytes] = {}

    def refresh_modules(self) -> list[FakeModule]:
        return list(self._modules)

    def find_module(self, name: str) -> FakeModule | None:
        for m in self._modules:
            if m.name == name or m.name.rsplit("/", 1)[-1] == name:
                return m
        return None

    def to_runtime(self, static_addr: int, module: FakeModule) -> int:
        return module.base + static_addr

    def to_static(self, runtime_addr: int, module: FakeModule) -> int:
        return runtime_addr - module.base

    def read_memory(self, addr: int, size: int) -> bytes:
        """按已登记的稀疏内存返回；未登记返回空（与真实实现一致）。"""
        return self.memory.get(addr, b"")

    def detach(self) -> bool:
        self.session.detached = True
        return True


def make_fake_context(**overrides) -> dict:
    """构造一份贴近真实 frida 的 arm64 context 字典。

    键名用小写（frida 的 this.context 就是小写），
    值用字符串十六进制（真实 frida 里是 NativePointer，转字符串后同形）。
    """
    ctx = {f"x{i}": f"0x{i:02x}" for i in range(29)}
    ctx.update({
        "fp": "0x1d",
        "lr": "0x1e",
        "sp": "0x7ff0000000",
        "pc": "0x7000001234",
        "nzcv": "0x0",
    })
    ctx.update(overrides)
    return ctx


def make_breakpoint_payload(addr: int = 0x1234, tid: int = 1000, **ctx_overrides) -> dict:
    """构造 JS 侧 send({...}) 的载荷，字段与 dyn/debugger.py 的 JS 骨架一致。"""
    return {
        "so": "libtarget.so",
        "static": hex(addr),
        "runtime": hex(0x7000000000 + addr),
        "tid": tid,
        "ctx": make_fake_context(**ctx_overrides),
        "bt": [hex(0x7000001234), hex(0x7000005678)],
    }
