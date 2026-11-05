"""动态调试器：真暂停断点、arm64 全寄存器采集、命中事件流。

基于 frida 的 Interceptor 实现 ARM64 断点。本次重写解决旧实现四个结构性问题
（问题均经通读旧代码确认，不是猜测）：

(1) 第一次修改
bug 原因：旧 set_breakpoint 的 JS 回调 send(...) 之后直接返回，注释写着
          「由 Python 端通过 recv 放行」，但 JS 侧根本没有 recv().wait()；
          resume() 只是 script.post({"type":"resume"})，而 JS 从未注册接收它的
          handler；_hold_policy 赋值后全库没有任何地方读。三者叠加的结果是
          「断点命中后线程照跑」，所谓 hold 是假的。
解决方案：
    1) 真暂停：hold 断点在 onEnter 里执行 recv(token).wait()，命中线程真的阻塞；
       每个挂起分配唯一 token，Python 侧 resume() 用 script.post({"type": token})
       唤醒对应的那一个（frida 按 type 分派，post 早于 recv 到达会排队，天然
       解决「先放行后命中」的竞态）。
    2) 全寄存器：采集 x0..x28 / x29(fp) / x30(lr) / sp / pc / nzcv，同时保留旧键
       x0/x1/x2/x8/lr/sp/pc，旧调用方按旧键取值不受影响。
    3) 单脚本多断点：整个会话只创建一个 script，内部 hooks 表按运行时地址分派；
       remove_breakpoint 走 InvocationListener.detach()，是真摘钩而非删记录。
    4) 事件流：命中同时进 hits（兼容旧接口）与有界 deque（poll_events 读取），
       全部由 threading.Lock 保护，frida 消息线程与调用方线程并发安全。
    5) 状态机：idle -> attached -> paused -> attached / detached；resume() 在非
       paused 状态返回结构化失败信息，不再静默成功。

约束：本轮不连接真机，行为验证走 tests/fake_frida.py 的假实现与纯逻辑自测。
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from dyn.rebase import Rebase, RuntimeModule

# 命中后的动作
ACTION_RESUME = "resume"
ACTION_HOLD = "hold"  # 挂起等待，由人工/AI 分析后显式放行

# 会话状态：service 层直接读 Debugger.state，取值限定在这四个
STATE_IDLE = "idle"          # 还没下过断点，调试脚本未加载
STATE_ATTACHED = "attached"  # 脚本已加载、断点生效，目标在跑
STATE_PAUSED = "paused"      # 至少一个 hold 命中，目标线程真的被阻塞
STATE_DETACHED = "detached"  # 已 close()，不可再用

_MAX_EVENTS = 2000   # 事件环形缓冲上限，超出丢最旧（seq 只增不减，不会复用）
# 命中历史的保留上限。每条命中含完整寄存器与调用栈（实测约 12KB），
# 2000 条约 24MB，是"够回溯 + 不炸内存"的折中。
_MAX_HITS = 2000
_RPC_TIMEOUT = 5.0   # 单次 RPC 调用最长等待秒数，超时按失败返回，不卡调用方
_CLOSE_RPC_TIMEOUT = 2.0  # close() 里的摘钩 RPC 用更短的超时，保证关闭不被卡住

# 调试脚本源码：整个会话只加载这一个 script。
# 设计要点见模块 docstring；JS 内注释保持精简，细节在 Python 侧说明。
_JS_SOURCE = r"""
(function () {
    'use strict';

    // 幂等：同一会话重复 load 不重复挂钩
    if (globalThis.__mdaDebuggerInstalled) {
        return;
    }
    globalThis.__mdaDebuggerInstalled = true;

    var MAX_BACKTRACE = 24;   // ACCURATE 展开较慢，限制帧数避免挂住目标线程太久
    var hooks = {};           // runtimeKey -> {runtime, staticHex, soName, policy, listener}
    var holdSeq = 0;

    function snapshotContext(ctx) {
        var out = {};
        if (ctx === null || ctx === undefined) {
            return out;
        }
        var keys = [];
        try {
            keys = Object.keys(ctx);
        } catch (e) {
            keys = [];
        }
        var i;
        for (i = 0; i < keys.length; i++) {
            var key = keys[i];
            try {
                var v = ctx[key];
                out[key] = (v === null || v === undefined) ? null : v.toString();
            } catch (e2) {
                out[key] = null;
            }
        }
        if (keys.length === 0) {
            // 兜底：context 不是普通对象时，按 arm64 固定寄存器表逐个取
            var names = ['sp', 'pc', 'nzcv', 'fp', 'lr'];
            for (var n = 0; n <= 28; n++) {
                names.push('x' + n);
            }
            for (i = 0; i < names.length; i++) {
                try {
                    if (ctx[names[i]] !== undefined) {
                        out[names[i]] = ctx[names[i]].toString();
                    }
                } catch (e3) {
                }
            }
        }
        // arm64 的 fp/lr 就是 x29/x30，两套键互为别名，缺一个补一个
        if (out.fp === undefined && out.x29 !== undefined) { out.fp = out.x29; }
        if (out.lr === undefined && out.x30 !== undefined) { out.lr = out.x30; }
        if (out.x29 === undefined && out.fp !== undefined) { out.x29 = out.fp; }
        if (out.x30 === undefined && out.lr !== undefined) { out.x30 = out.lr; }
        return out;
    }

    function safeBacktrace(ctx) {
        var out = [];
        try {
            var frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
            for (var i = 0; i < frames.length && i < MAX_BACKTRACE; i++) {
                try {
                    out.push(DebugSymbol.fromAddress(frames[i]).toString());
                } catch (e) {
                    out.push(frames[i].toString());
                }
            }
        } catch (e2) {
        }
        return out;
    }

    // 只回传裸地址，不做 frida 侧符号解析。
    // (1) 第一次修改（2026-11-02）：
    //     bug 原因：safeBacktrace() 用 DebugSymbol.fromAddress 预先符号化，
    //               但壳处理过的 so 一律被 strip，该 API 只能产出裸地址串；
    //               而同一个调用栈在 get_callstack 工具里却走 mda 静态模型
    //               （function_at）拿到了函数名与偏移。同一个栈两条路径给出
    //               两种质量，且预先字符串化后 Python 端无法再重新符号化。
    //     解决方案：改为只回传裸运行时地址数组，符号化统一放到 Python 端
    //               （mda 静态模型），两条路径从此同源。
    function rawBacktrace(ctx) {
        var out = [];
        try {
            var frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
            for (var i = 0; i < frames.length && i < MAX_BACKTRACE; i++) {
                try {
                    out.push(frames[i].toString());
                } catch (e) {
                    // 单帧取值失败不影响整条栈
                }
            }
        } catch (e2) {
        }
        return out;
    }

    function onHit(hook, ctx) {
        var payload = {
            so: hook.soName,
            static: hook.staticHex,
            runtime: hook.runtime,
            tid: ctx.threadId,
            ctx: snapshotContext(ctx.context),
            bt: rawBacktrace(ctx.context)
        };
        if (hook.policy === 'hold') {
            holdSeq += 1;
            var token = 'mda_resume:' + hook.runtime + ':' + ctx.threadId + ':' + holdSeq;
            payload.token = token;
            // 先登记 recv 再 send：Python 收到载荷后才能 post，注册一定早于放行消息，
            // 不存在「post 先到、recv 还没登记」导致消息丢失、线程永久挂起的窗口。
            var op = recv(token, function () {});
            send(payload);
            // 真暂停：该目标线程在这里阻塞，直到 Python 端 post({"type": token})
            try {
                op.wait();
            } catch (e) {
            }
        } else {
            send(payload);
        }
    }

    function attachHook(hook) {
        var listener = Interceptor.attach(ptr(hook.runtime), {
            onEnter: function () {
                onHit(hook, this);
            }
        });
        // frida 12+ 返回 InvocationListener，可单点 detach 真正摘钩
        hook.listener = (listener && typeof listener.detach === 'function') ? listener : null;
    }

    rpc.exports = {
        addBp: function (runtimeHex, staticHex, soName, policy) {
            var key = ptr(runtimeHex).toString();
            var mode = (policy === 'hold') ? 'hold' : 'resume';
            if (hooks[key] !== undefined) {
                hooks[key].policy = mode;      // 同地址重复下断：只更新策略，不重复挂钩
                return true;
            }
            var hook = {
                runtime: key,
                staticHex: staticHex,
                soName: soName,
                policy: mode,
                listener: null
            };
            hooks[key] = hook;
            try {
                attachHook(hook);
            } catch (e) {
                delete hooks[key];
                throw e;
            }
            return true;
        },
        delBp: function (runtimeHex) {
            var key = ptr(runtimeHex).toString();
            var hook = hooks[key];
            if (hook === undefined) {
                return false;
            }
            delete hooks[key];
            var detached = false;
            try {
                if (hook.listener !== null) {
                    hook.listener.detach();
                    detached = true;
                }
            } catch (e) {
            }
            if (!detached) {
                // 兜底：老版本没有 listener.detach 时，整表重装（先全摘再把剩下的装回去）
                try {
                    Interceptor.detachAll();
                    var rest = Object.keys(hooks);
                    for (var i = 0; i < rest.length; i++) {
                        try {
                            attachHook(hooks[rest[i]]);
                        } catch (e2) {
                            delete hooks[rest[i]];
                        }
                    }
                } catch (e3) {
                }
            }
            return true;
        },
        delAll: function () {
            var keys = Object.keys(hooks);
            for (var i = 0; i < keys.length; i++) {
                delete hooks[keys[i]];
            }
            try {
                Interceptor.detachAll();
            } catch (e) {
            }
            return true;
        },
        threads: function () {
            var out = [];
            try {
                var list = Process.enumerateThreads();
                for (var i = 0; i < list.length; i++) {
                    var t = list[i];
                    var item = {
                        id: t.id,
                        // frida 16 的线程对象没有 name 字段，缺省给 null
                        name: (t.name === undefined ? null : t.name),
                        state: (t.state === undefined ? 'unknown' : t.state)
                    };
                    // 顺带取当前 pc：list_threads 工具要用它和调用栈对照，
                    // 取不到就是 null（线程可能正好不在可读状态），不编造 0
                    try {
                        item.pc = (t.context === undefined || t.context === null)
                            ? null : t.context.pc.toString();
                    } catch (e) {
                        item.pc = null;
                    }
                    out.push(item);
                }
            } catch (e2) {
            }
            return out;
        }
    };
})();
"""


@dataclass
class BreakpointHit:
    """一次断点命中。addr 为静态地址（已换算），便于与静态分析结果对齐。"""

    so_name: str
    static_addr: int  # 断点处的静态地址
    runtime_addr: int
    thread_id: int
    context: dict = field(default_factory=dict)  # x0..x28, fp/lr/sp/pc/nzcv
    backtrace: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    # 以下为本次新增字段：老调用方按名取字段，多出来的不影响
    seq: int = 0         # 事件流序号，从 1 开始单调递增
    held: bool = False   # 该命中是否真的把线程挂住了（hold 策略）
    token: str = ""      # 放行该挂起所用的消息类型，resume() 用它唤醒


# ---------------- 寄存器整理（纯函数，可离线单测） ----------------


def _reg_str(value) -> str | None:
    """寄存器值统一成 "0x..." 字符串。

    旧实现把 this.context.x0.toString() 直接当字符串传，调用方（UI/AI）
    也按字符串取值，这里保持同一形态。空值返回 None 表示「该寄存器不存在」，
    不伪造 0——伪造会让分析方把「架构没有这个寄存器」误读成「值是 0」。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "0x1" if value else "0x0"
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return hex(int(text, 16))
        return hex(int(text, 10))
    except (TypeError, ValueError):
        return text


def _normalize_context(raw: dict) -> dict:
    """把 JS 采到的寄存器字典整理成统一形态。

    - 键统一小写字符串，值统一成 "0x..." 字符串（与旧实现一致）；
    - fp/lr 与 x29/x30 互为别名，缺哪个补哪个，两套键都能取到；
    - 额外寄存器（q0/v0 之类）原样保留，方便以后扩展，不做裁剪。
    """
    ctx: dict = {}
    if not isinstance(raw, dict):
        return ctx
    for key, value in raw.items():
        name = str(key).lower()
        val = _reg_str(value)
        if val is not None:
            ctx[name] = val
    for short, long in (("fp", "x29"), ("lr", "x30")):
        if short in ctx and long not in ctx:
            ctx[long] = ctx[short]
        elif long in ctx and short not in ctx:
            ctx[short] = ctx[long]
    return ctx


def _parse_addr(value) -> int:
    """把 JS 传来的地址（"0x..." 字符串或整数）转成 int，无法解析返回 0。

    (7) 第七次修改（2026-11-05）：规则收口到 core.addr。
        bug 原因：本处原实现"先试十进制、失败返回 0"，与 mcp_server 侧
                  "含 a-f 就按十六进制"不一致，同一串 "7fff1234" 在两边得到
                  0 与 3415878964 两种结果。
        解决方案：转调 parse_addr，本处保留 default=0 的历史约定。
    """
    from core.addr import parse_addr

    return parse_addr(value, 0)

class Debugger:
    """绑定单个进程的动态调试会话。"""

    def __init__(self, rebase: Rebase):
        self.rb = rebase
        self.session = rebase.session
        self._lock = threading.Lock()          # 保护 hits/events/state/pending 等共享状态
        self._hit_cond = threading.Condition(self._lock)  # 新命中通知（复用同一把锁）
        self._script_lock = threading.Lock()   # 串行化脚本创建，避免并发建出两个脚本
        # (6) 第六次修改（2026-11-05）：_hits 加上界，避免长会话/hot 断点 OOM。
        #     bug 原因：_events 有 maxlen=_MAX_EVENTS，但 _hits 是**无界 list**，
        #               而每次命中都会 append 一条完整现场（实测 ~12KB/条：
        #               36 个寄存器 + 调用栈）。5000 次命中约 58MB，
        #               10 万次约 1.2GB；且 hits()/poll_events() 每次都 list() 全量复制。
        #     解决方案：改用 deque(maxlen=_MAX_HITS)。超限时丢最旧的，
        #               并按"丢弃过多少条"暴露 discarded 计数，让调用方知道
        #               自己看到的不是全部（不静默截断）。
        self._hits: deque[BreakpointHit] = deque(maxlen=_MAX_HITS)
        self._hits_discarded = 0               # 因超上限被丢掉的旧命中数
        self._events: deque[BreakpointHit] = deque(maxlen=_MAX_EVENTS)
        self._poll_cursor = 0                  # poll_events 默认游标（只增不减）
        self._wait_cursor = 0                  # wait_hits 专用游标，与 poll 互不干扰
        self._seq = 0                          # 命中序号，从 1 开始
        self._version = 0                      # 命中计数版本号，wait_hits 用它判断「有没有新的」
        self._state = STATE_IDLE
        self._script = None
        # 断点表以**运行时地址**为键：同一地址用不同写法（"libx.so" 与完整路径）
        # 不会重复登记，也不会因为写法差异导致摘错钩子。
        self._hooks: dict[int, dict] = {}          # runtime_addr -> {so_name, static_addr, policy}
        self._callbacks: dict[int, object] = {}    # runtime_addr -> on_hit 回调
        self._pending_tokens: set[str] = set()            # 已命中但还没放行的挂起 token
        self._last_error = ""

    # ---------- 对外只读状态 ----------

    @property
    def hits(self) -> list[BreakpointHit]:
        """命中列表快照。

        (1) 第一次修改：原来 hits 是裸 list，frida 消息线程 append、调用方
        同时切片/清空会出问题。改为加锁返回副本，调用方拿到的是稳定快照。
        """
        with self._lock:
            return list(self._hits)

    @property
    def state(self) -> str:
        """会话状态：idle / attached / paused / detached。"""
        with self._lock:
            return self._state

    @property
    def last_error(self) -> str:
        """最近一次失败原因（中文），成功时不清空，便于事后排查。"""
        with self._lock:
            return self._last_error

    # ---------- 断点 ----------

    def set_breakpoint(
        self,
        so_name: str,
        static_addr: int,
        policy: str = ACTION_RESUME,
        on_hit=None,
    ) -> bool:
        """在某个 so 的静态地址处下断点。

        policy: resume=命中即继续（只记录），hold=命中挂起等待人工/AI 放行。
        on_hit: 可选回调，收到 BreakpointHit。
        返回是否成功（so 须已在该进程内加载）。

        (1) 第一次修改
        bug 原因：旧实现每个断点建一个 script，且 JS 回调不阻塞，policy 只是
                  赋值给 _hold_policy 后没人读；断点之间也无法统一管理。
        解决方案：整个会话只建一个 script，断点登记到 JS 的 hooks 表，
                  policy 随断点下发；重写后同一地址重复下断只更新策略。
        """
        mod = self.rb.find_module(so_name)
        if mod is None:
            self._set_error(f"{so_name} 未加载到进程，无法下断点")
            return False
        if not self._ensure_script():
            return False

        runtime_addr = self.rb.to_runtime(static_addr, mod)
        mode = ACTION_HOLD if policy == ACTION_HOLD else ACTION_RESUME
        ok, value, err = self._rpc_call(
            "add_bp", hex(runtime_addr), hex(int(static_addr)), so_name, mode
        )
        if not ok:
            self._set_error(f"{so_name}+{int(static_addr):#x} 下断点失败：{err}")
            return False
        # 部分 frida 版本的 RPC 没有返回值（None），按成功处理；只有明确 False 才算失败
        if value is False:
            self._set_error(f"{so_name}+{int(static_addr):#x} 下断点被 JS 侧拒绝")
            return False

        with self._lock:
            self._hooks[runtime_addr] = {"so_name": so_name,
                                         "static_addr": int(static_addr),
                                         "policy": mode}
            if on_hit is not None:
                self._callbacks[runtime_addr] = on_hit
            if self._state == STATE_IDLE:
                self._state = STATE_ATTACHED
        return True

    def remove_breakpoint(self, so_name: str, static_addr: int) -> bool:
        """撤销某个静态地址上的断点。

        返回 True 表示真的摘掉了钩子；False 表示没摘掉（调用方应保留记录并标注 partial）。

        (1) 第一次修改（本轮新增）
        bug 原因：旧实现没有撤销能力，service 层只能删记录却对调用方报成功，
                  属于假成功——地址上的钩子还在，照样命中。
        解决方案：JS 侧用 Interceptor.attach 返回的 InvocationListener.detach()
                  单点摘钩；老版本没有 listener 时退化为 detachAll 后重装其余断点，
                  保证「返回 True 就真的不会再有该地址的命中」。
        """
        # 先按静态地址换算回运行时地址再查表：断点表以运行时地址为键，
        # 这样 "libx.so" 与 "/data/app/libx.so" 两种写法能命中同一条记录。
        mod = self.rb.find_module(so_name)
        runtime_addr = None
        if mod is not None:
            runtime_addr = self.rb.to_runtime(int(static_addr), mod)
        with self._lock:
            rec = self._hooks.get(runtime_addr) if runtime_addr is not None else None
            if rec is None:
                # 换算失败时退化为按 (so_name, static_addr) 反查，避免模块名变动导致摘不掉
                for addr, item in self._hooks.items():
                    if item["static_addr"] == int(static_addr) and item["so_name"] == so_name:
                        runtime_addr, rec = addr, item
                        break
            if rec is None:
                return False
        ok, value, err = self._rpc_call("del_bp", hex(runtime_addr))
        if not ok:
            self._set_error(f"撤销 {so_name}+{int(static_addr):#x} 失败：{err}")
            return False
        if value is False:
            return False
        with self._lock:
            self._hooks.pop(runtime_addr, None)
            self._callbacks.pop(runtime_addr, None)
        return True

    def _ensure_script(self) -> bool:
        """确保调试脚本已创建并加载（幂等）。

        (1) 第一次修改（本轮新增）
        bug 原因：旧实现每个断点各自 create_script，无法统一下发策略、无法
                  统一摘钩，resume 也只能靠「给每个脚本各 post 一条」碰运气。
        解决方案：整个会话共用一个脚本，首次下断点时创建；创建过程串行化，
                  且不在持有主锁的情况下 load，避免消息回调重入死锁。
        """
        with self._script_lock:
            with self._lock:
                if self._state == STATE_DETACHED:
                    self._last_error = "会话已 detach，需重新 attach 后新建 Debugger"
                    return False
                if self._script is not None:
                    return True
            script = None
            try:
                script = self.session.create_script(_JS_SOURCE)
                script.on("message", self._on_message)
                script.load()
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                if script is not None:
                    try:
                        script.unload()
                    except Exception:                     # noqa: BLE001
                        pass
                self._set_error(f"调试脚本加载失败：{type(exc).__name__}: {exc}")
                return False
            with self._lock:
                self._script = script
                self._state = STATE_ATTACHED
            return True

    # ---------- 分析等待 / 事件流 ----------

    def wait_hits(self, timeout: float = 30.0) -> list[BreakpointHit]:
        """阻塞等待断点命中（"分析等待"）。返回当前全部命中。

        语义与旧实现对齐：只要还有「没被本方法取过」的命中就立即返回，
        没有才阻塞到 timeout；返回的是全部命中列表，老调用方无需改动。

        (1) 第一次修改
        bug 原因：旧实现靠 threading.Event，一置位就不复位，第二次调用会立刻
                  返回旧结果，调用方分不清有没有新命中；而如果改成「只等版本号
                  变化」又会反过来丢掉「命中已经发生、还没人来取」的即时返回语义。
        解决方案：单独维护 _wait_cursor（与 poll_events 的游标互不干扰，避免
                  本方法把事件从事件流里「吃掉」），先看有没有未取的命中，
                  有就立即返回，没有才在用 Condition 等版本号变化。
        """
        try:
            wait_s = max(float(timeout or 0.0), 0.0)
        except (TypeError, ValueError):
            wait_s = 0.0
        deadline = time.monotonic() + wait_s
        with self._hit_cond:
            while self._version <= self._wait_cursor:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._hit_cond.wait(remaining)
            self._wait_cursor = self._version
            return list(self._hits)

    def poll_events(
        self,
        timeout: float = 0.0,
        limit: int = 200,
        after_seq: int | None = None,
    ) -> list[BreakpointHit]:
        """取命中事件：非阻塞优先，timeout>0 才等。

        after_seq=None 走内部游标（取「没取过的新事件」并推进）；
        after_seq=0 显式从头重放；after_seq=N 只取 seq > N（不推进内部游标）。

        (1) 第一次修改（本轮新增）
        bug 原因：旧实现只有阻塞的 wait_hits，AI 想「看一眼有没有新命中」就得
                  赌超时，放行后也没法按时间轴回看。
        解决方案：命中同时进有界 deque 与 seq 单调的事件流，本方法按 seq 过滤，
                  timeout=0 立即返回空列表，不阻塞调用方。
        """
        try:
            wait_s = max(float(timeout or 0.0), 0.0)
            limit = max(int(limit), 1)
            explicit = after_seq is not None
            floor = max(int(after_seq), 0) if explicit else 0
        except (TypeError, ValueError):
            return []
        deadline = time.monotonic() + wait_s
        with self._hit_cond:
            if not explicit:
                floor = self._poll_cursor
            while True:
                fresh = [e for e in self._events if e.seq > floor][:limit]
                if fresh:
                    if not explicit:
                        self._poll_cursor = fresh[-1].seq
                    return fresh
                # 事件被环形缓冲挤掉时游标要跟着前移，
                # 否则旧 seq 永远追不上，调用方会一直以为「没新事件」
                if not explicit and self._events and self._poll_cursor < self._events[0].seq - 1:
                    self._poll_cursor = self._events[0].seq - 1
                    floor = self._poll_cursor
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._hit_cond.wait(remaining)

    # ---------- 放行 ----------

    def resume(self, token: str | None = None) -> dict:
        """放行被挂起的线程，返回结构化结果而不是静默成功。

        token 为空时放行全部挂起；传 token 只放行那一个（多线程同时挂起时用）。

        (1) 第一次修改
        bug 原因：旧实现只会给每个脚本 post({"type":"resume"})，而 JS 从未注册
                  接收它的 handler，线程根本没被挂住，所以「放行」永远报成功；
                  目标没 paused 时也照样返回，调用方无法判断真假。
        解决方案：按命中时下发的唯一 token 逐条 post（frida 按 type 分派到对应的
                  recv().wait()）；非 paused 状态返回
                  {"resumed": False, "reason": "not_paused"}，不装成功。
        """
        # (2) 第二次修改
        # bug 原因：原来把 script.post() 放在 with self._lock 里。post 是跨进程 IPC，
        #           外部 D-Bus/socket 卡住时会把整把锁一起卡死，连带 poll_events /
        #           set_breakpoint / 消息回调全部阻塞（消息回调本身也要拿这把锁）。
        # 解决方案：锁内只挑出要放行的 token 并从待放行集合里摘掉，post 移到锁外；
        #           发送失败则把 token 放回集合，保证「没真的唤醒」不丢状态。
        with self._lock:
            if self._state == STATE_DETACHED:
                return {"resumed": False, "reason": "detached",
                        "state": self._state, "woken": 0}
            if self._state != STATE_PAUSED:
                return {"resumed": False, "reason": "not_paused",
                        "state": self._state, "woken": 0}
            script = self._script
            if script is None:
                return {"resumed": False, "reason": "no_script",
                        "state": self._state, "woken": 0}
            if token and token not in self._pending_tokens:
                return {"resumed": False, "reason": "token_not_found",
                        "state": self._state, "woken": 0}
            targets = [token] if token else sorted(self._pending_tokens)
            if not targets:
                return {"resumed": False, "reason": "no_pending_hit",
                        "state": self._state, "woken": 0}
            for item in targets:
                self._pending_tokens.discard(item)

        woken = 0
        failed: list[str] = []
        for item in targets:
            try:
                script.post({"type": item})
                woken += 1
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                failed.append(item)
                self._set_error(f"放行消息发送失败：{type(exc).__name__}: {exc}")
        with self._lock:
            # 发送失败的放回去，下次 resume 还能再试；这些线程确实还挂着
            self._pending_tokens.update(failed)
            if not self._pending_tokens and self._state == STATE_PAUSED:
                self._state = STATE_ATTACHED
            state_after = self._state
        return {"resumed": woken > 0,
                "reason": "" if woken else "post_failed",
                "state": state_after,
                "woken": woken,
                "failed": len(failed)}

    # ---------- 线程 ----------

    def threads(self) -> list[dict]:
        """枚举目标进程线程：[{"id": int, "name": str|None, "state": str, "pc": str|None}, ...]。

        (1) 第一次修改（本轮新增）
        bug 原因：项目里没有任何线程枚举实现，AI 无法判断 hold 断点命中的是
                  哪条线程、还剩几条线程在跑。
        解决方案：JS 侧 Process.enumerateThreads() 回传 id/name/state/pc；
                  frida 16 的线程对象没有 name 字段，JS 侧缺省给 null，保证字段
                  恒存在（调用方用「值为 null」判断设备端是否支持线程名，不报错）。
        """
        if not self._ensure_script():
            return []
        ok, value, err = self._rpc_call("threads")
        if not ok:
            self._set_error(f"枚举线程失败：{err}")
            return []
        rows: list[dict] = []
        for item in value or []:
            if not isinstance(item, dict):
                continue
            rows.append({
                "id": _parse_addr(item.get("id")),
                "name": item.get("name"),          # frida 16 没有该字段 → None
                "state": str(item.get("state") or "unknown"),
                "pc": _reg_str(item.get("pc")),    # 取不到保持 None，不填 0
            })
        return rows

    # ---------- 内存与状态 ----------

    def read_memory(self, addr: int, size: int) -> bytes:
        return self.rb.read_memory(addr, size)

    def read_module_memory(self, so_name: str, static_addr: int, size: int) -> bytes:
        """按静态地址读目标进程内存，内部完成换算。"""
        mod = self.rb.find_module(so_name)
        if mod is None:
            return b""
        return self.rb.read_memory(self.rb.to_runtime(static_addr, mod), size)

    def runtime_modules(self) -> list[RuntimeModule]:
        return self.rb.refresh_modules()

    def close(self) -> None:
        """摘掉全部钩子、卸载脚本、断开会话（幂等）。

        (1) 第一次修改
        bug 原因：必然要放行所有挂起线程——脚本一旦 unload，阻塞在 recv().wait()
                  里的线程就没人唤醒了（真实 frida 会让它们随脚本销毁而行为未定义）。
                  旧实现对挂起中的会话直接 unload，属于「关得掉但可能留下卡死的线程」。
        解决方案：顺序固定为「先放行 → 再摘钩 → 再卸载 → 最后标 detached」，
                  每一步都独立 try 兜底；摘钩走带超时的 RPC，JS 侧没响应也不卡死关闭流程。
        """
        # 1) 先放行仍被挂起的线程，否则后面 unload 时它们没有唤醒来源
        try:
            self.resume()
        except Exception:                                 # noqa: BLE001
            pass
        # 2) 摘钩（带超时守卫，JS 侧不响应也不会卡住关闭）
        if self._script is not None:
            try:
                self._rpc_call("del_all", timeout=_CLOSE_RPC_TIMEOUT)
            except Exception:                             # noqa: BLE001
                pass
        # 3) 卸载脚本
        with self._lock:
            script = self._script
            self._script = None
            self._hooks.clear()
            self._callbacks.clear()
            self._pending_tokens.clear()
            self._state = STATE_DETACHED
        if script is not None:
            try:
                script.unload()
            except Exception:                             # noqa: BLE001
                pass
        # 4) 断开会话
        try:
            self.rb.detach()
        except Exception:                                 # noqa: BLE001
            pass

    # ---------- 内部 ----------

    def _symbolize_backtrace(self, frames) -> list[str]:
        """把裸运行时地址数组符号化成 "so!func+0xNN" 形式。

        (1) 第一次修改（2026-11-02）：
            bug 原因：JS 侧原本用 DebugSymbol.fromAddress 预先符号化，壳样本
                      因 stripped 只能得到裸地址；而 get_callstack 工具走
                      mda 静态模型能给出函数名，同一个栈两条路径质量不一。
            解决方案：JS 只回传裸地址，统一在 Python 侧用 mda 的 SoFile
                      （function_at）符号化，与 get_callstack 同源。

        符号化失败（地址不在任何已加载模块内，如 frida trampoline 或
        JIT 匿名段）时保留原始地址串，不伪造函数名。
        """
        out: list[str] = []
        # 惰性导入：避免 dyn 层在纯静态场景下强依赖 core
        try:
            from mcp_server.tools import get_session

            sess = get_session()
        except Exception:                                  # noqa: BLE001
            sess = None
        modules = list(getattr(self.rb, "_modules", []) or [])
        for item in frames:
            text = str(item)
            runtime = _parse_addr(item)
            if runtime == 0 or sess is None or not modules:
                out.append(text)
                continue
            label = None
            for mod in modules:
                try:
                    base, size = int(mod.base), int(mod.size)
                except (TypeError, ValueError):
                    continue
                if not (base <= runtime < base + size):
                    continue
                # (2) 第二次修改（2026-11-02）：模块名多级匹配，不再只认全名。
                #     bug 原因：真机 frida 的 mod.name 常是完整路径或带壳前缀，
                #               而 mda 的键是 load_so 时的短名；精确匹配失败后
                #               整条栈都退化成 "模块名+偏移"，白丢了函数名。
                #     解决方案：复用 mcp_server.tools._pick_so_by_name 的同一套
                #               别名逻辑（全名→basename→去壳前缀→唯一后缀），
                #               保证动态层与 MCP 层符号化口径一致。
                so = None
                try:
                    from mcp_server.tools import _pick_so_by_name

                    so = _pick_so_by_name(sess, getattr(mod, "name", ""))
                except Exception:                          # noqa: BLE001
                    # 跨层导入失败时退回精确匹配，保证基本可用
                    so = getattr(sess, "modules", {}).get(getattr(mod, "name", ""))
                static = runtime - base
                fn = None
                try:
                    fn = so.function_at(static) if so is not None else None
                except Exception:                          # noqa: BLE001
                    fn = None
                if fn is not None:
                    name = fn.name or f"sub_{int(fn.addr):x}"
                    label = f"{mod.name}!{name}+{static - int(fn.addr):#x}"
                else:
                    # 模块内但落在函数空洞（或 mda 未加载该 so）：给出模块+偏移
                    label = f"{mod.name}+{static:#x}"
                break
            out.append(label or text)
        return out

    def _on_message(self, msg, data) -> None:
        """frida 消息回调：把 send 的命中转成 BreakpointHit 并通知等待方。

        (1) 第一次修改
        bug 原因：旧 handler 只在 payload 齐全时默默 append，JS 异常（type=error）
                  被直接丢弃，表现为「断点不命中」而没有任何线索；且回调里不做
                  状态迁移，服务层无从判断目标是否被挂住。
        解决方案：error 消息记进 last_error；命中入 hits 与事件流、递增 seq、
                  有 token 就标记 paused 并登记待放行，最后在锁外执行 on_hit。
        """
        mtype = msg.get("type")
        if mtype == "error":
            desc = msg.get("description") or msg.get("stack") or "JS 异常"
            self._set_error(f"调试脚本异常：{desc}")
            return
        if mtype != "send":
            return
        payload = msg.get("payload")
        if not isinstance(payload, dict):
            return
        token = str(payload.get("token") or "")
        # (3) 第三次修改（2026-11-02）：先登记 token 的"意图"，再做可能失败的加工。
        #     bug 原因：BreakpointHit 构造里调 _symbolize_backtrace，其中 int(fn.addr)
        #               没有兜底。一旦抛异常，控制流直接跳出 _on_message，后面的
        #               _pending_tokens.add(token) 永远不执行 → 线程已阻塞在
        #               recv().wait() 里，却没有任何 token 可放行 → **永久挂起**。
        #               扫描 7296 个真实函数确认 addr 均为 int，故当前不可触发；
        #               但这是靠数据形态兜着的隐患，修法便宜，不该留着。
        #     解决方案：token 只登记一次——放在下方 with self._hit_cond 的正式
        #               位置；这里仅把可能失败的符号化用 try 包住，失败时让
        #               backtrace 退化成裸地址，不影响放行能力。
        backtrace_raw = payload.get("bt") or []
        try:
            backtrace = self._symbolize_backtrace(backtrace_raw)
        except Exception:                                  # noqa: BLE001
            # 符号化是锦上添花，绝不能因此让线程卡死
            backtrace = [str(x) for x in backtrace_raw]
        hit = BreakpointHit(
            so_name=str(payload.get("so") or ""),
            static_addr=_parse_addr(payload.get("static")),
            runtime_addr=_parse_addr(payload.get("runtime")),
            thread_id=_parse_addr(payload.get("tid")),
            context=_normalize_context(payload.get("ctx") or {}),
            backtrace=backtrace,
        )
        hit.held = bool(token)
        hit.token = token
        with self._hit_cond:
            self._seq += 1
            hit.seq = self._seq
            if len(self._hits) == self._hits.maxlen:
                self._hits_discarded += 1      # 即将挤掉最旧的一条
            self._hits.append(hit)
            self._events.append(hit)
            if token:
                self._pending_tokens.add(token)
                self._state = STATE_PAUSED
            self._version += 1
            self._hit_cond.notify_all()
            callback = self._callbacks.get(hit.runtime_addr)
        if callback is None:
            # 运行时地址对不上时（模块重载/地址重新映射）退化为按静态地址找，
            # 保证 on_hit 不会因为 ASLR 换基址就静默失效
            callback = self._find_callback(hit)
        if callback is not None:
            try:
                callback(hit)
            except Exception as exc:                      # noqa: BLE001 - 回调失败不能影响调试
                self._set_error(f"on_hit 回调异常：{type(exc).__name__}: {exc}")

    def _rpc_call(self, name: str, *args, timeout: float | None = None):
        """调用 JS 侧 rpc.exports.<name>，返回 (ok, value, error)。

        (1) 第一次修改（本轮新增）
        bug 原因：hold 断点命中后目标线程在 recv().wait() 里阻塞。若此时 RPC
                  派发因 JS 侧没让出执行权而卡住，调用方（AI/UI）会无限期等下去。
                  frida 的 recv().wait() 会释放执行权，正常情况下不会发生，但不能
                  把「会不会卡死」交给运气。
        解决方案：RPC 放到守护线程执行，主线程最多等 timeout（默认 _RPC_TIMEOUT）
                  秒；超时按失败返回并记录 last_error，宁可报错也不阻塞调用方。
                  close() 用更短的 timeout，保证关闭流程不会被卡住。
        """
        limit = _RPC_TIMEOUT if timeout is None else max(float(timeout), 0.1)
        with self._lock:
            script = self._script
        if script is None:
            return False, None, "调试脚本未加载"
        # frida 16 用 exports_sync，frida 17 两者等价但保留 exports 别名
        exports = getattr(script, "exports_sync", None)
        if exports is None:
            exports = getattr(script, "exports", None)
        if exports is None:
            return False, None, "当前 frida 版本不支持 rpc.exports"
        fn = getattr(exports, name, None)
        if fn is None:
            return False, None, f"JS 侧没有导出 {name}"

        box: dict = {}
        done = threading.Event()

        def runner() -> None:
            try:
                box["value"] = fn(*args)
            except Exception as exc:                      # noqa: BLE001 - frida 异常类型不稳定
                box["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                done.set()

        threading.Thread(target=runner, name=f"mda-rpc-{name}", daemon=True).start()
        if not done.wait(limit):
            return False, None, f"{name} 超过 {limit:g}s 未返回（JS 侧可能仍在等放行）"
        if "error" in box:
            return False, None, box["error"]
        return True, box.get("value"), ""

    def _find_callback(self, hit: BreakpointHit):
        """按静态地址兜底查找 on_hit 回调（运行时地址对不上时用）。"""
        with self._lock:
            for addr, item in self._hooks.items():
                if item["static_addr"] == hit.static_addr:
                    return self._callbacks.get(addr)
        return None

    def _set_error(self, message: str) -> None:
        with self._lock:
            self._last_error = message
