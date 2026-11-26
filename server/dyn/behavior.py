"""App 行为监控 —— 算法 / 文件 / Activity / assets / Shell。

## 它到底怎么实现的（说清楚，避免误解）

**不是「识别」算法，是 hook Java 标准 API 的入口。**

业界工具（算法助手 Pro 等）用的就是这个办法：

    java.security.MessageDigest.getInstance("MD5")      ← 算法名就在参数里
    javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
    javax.crypto.Mac.getInstance("HmacSHA256")

App 调 `getInstance("MD5")` 时**自己把算法名告诉了我们**，不需要任何特征匹配。
然后再 hook `digest()` / `doFinal()` 拿到输入输出，就得到完整的
「算法 + 明文 + 密文 + 密钥 + 调用栈」。

## 覆盖边界（必须说清）

    ✅ 用标准 API 的 App（占绝大多数）
    ❌ 自研 VM / 自己实现算法（比如 libsgmainso 那种字节码 VM）
       —— 它不调 MessageDigest，hook 无从下手

## 为什么不 hook 更多类

批量 hook 系统类是最强的风控信号。实测教训（2026-11-09）：
一次挂 317 个 Java 方法后，阿里系 App 直接弹「访问被拒绝」。

所以本模块的设计原则是：**每类监控独立开关，默认只开低风险的**，
并且用最少的 hook 点实现最多的信息。

## 实现方式

frida 注入（运行时 attach），和 Xposed 的区别：

    Xposed   改 Zygote，App 启动前就挂好 → 能抓启动期，但要刷框架
    frida    运行时 attach → 不需要刷机，但抓不到启动期（除非 spawn）

本模块用 frida attach，不依赖 Xposed。
"""

from __future__ import annotations

import json
import threading
import time

__all__ = [
    "behavior_monitor_start",
    "behavior_monitor_poll",
    "behavior_monitor_stop",
    "BEHAVIOR_CATEGORIES",
]

# 每类监控的说明与风险评估，直接暴露给调用方做决策
BEHAVIOR_CATEGORIES = {
    "crypto": {
        "desc": "哈希/加解密/密钥哈希（MessageDigest / Cipher / Mac）",
        "risk": "中",
        "hooks": ["java.security.MessageDigest", "javax.crypto.Cipher",
                  "javax.crypto.Mac"],
        "captures": "算法名 + 明文 + 密文 + 密钥 + 调用栈",
    },
    "file": {
        "desc": "文件读写（FileInputStream / FileOutputStream / RandomAccessFile）",
        "risk": "低",
        "hooks": ["java.io.FileInputStream", "java.io.FileOutputStream"],
        "captures": "文件路径 + 读写字节数 + 调用栈",
    },
    "activity": {
        "desc": "Activity 生命周期（onCreate / onResume）",
        "risk": "低",
        "hooks": ["android.app.Activity"],
        "captures": "Activity 类名 + 生命周期 + Intent 摘要",
    },
    "assets": {
        "desc": "assets 资源加载（AssetManager.open）",
        "risk": "低",
        "hooks": ["android.content.res.AssetManager"],
        "captures": "资源文件名 + 调用栈",
    },
    "shell": {
        "desc": "执行 shell 命令（Runtime.exec / ProcessBuilder）",
        "risk": "**高**——反调试最敏感的点之一",
        "hooks": ["java.lang.Runtime", "java.lang.ProcessBuilder"],
        "captures": "命令行 + 调用栈",
    },
}

_DEFAULT_CATEGORIES = ["crypto", "file", "activity", "assets"]


def _js_str(s) -> str:
    return json.dumps(str(s))



_DETACH_LOCK = threading.Lock()
_DETACHING: set = set()
_DETACH_MAX = 16
# (6) 第六次修改（2026-11-26）：保护全局常驻监控表 _ACTIVE，防止并发 start/poll/stop 竞态。
_ACTIVE_LOCK = threading.Lock()

_JS_BEHAVIOR = r"""
Java.perform(function () {
    var CFG = __CFG__;
    var MAX_EVENTS = __MAX_EVENTS__;
    var events = [];
    var counts = {};
    var truncated = false;

    // 取 Java 调用栈（跳过前 N 帧，因为前几帧是 hook 自身）
    function javaStack(depth, skip) {
        try {
            var t = Java.use('java.lang.Thread').currentThread();
            var st = t.getStackTrace();
            var out = [];
            for (var i = skip || 1; i < st.length && out.length < (depth || 8); i++) {
                out.push(String(st[i]));
            }
            return out;
        } catch (e) { return []; }
    }

    function record(cat, kind, data) {
        // (3) 第三次修改（2026-11-11）：
        //     bug 原因：javaStack() / hexOf() 在调用 record **之前**求值，
        //               达到上限后每条事件仍然去抓栈、遍历字节——高频哈希路径
        //               会明显拖慢目标，与「只记录、不影响行为」的承诺不符。
        //     解决方案：调用方先问 atLimit()，满了就直接跳过全部求值。
        if (events.length >= MAX_EVENTS) { truncated = true; return; }
        counts[cat] = (counts[cat] || 0) + 1;
        var rec = {cat: cat, kind: kind, ts: Date.now() / 1000};
        for (var k in data) { rec[k] = data[k]; }
        events.push(rec);
    }

    function hexOf(arr, limit) {
        if (!arr) { return ''; }
        try {
            var n = Math.min(arr.length, limit || 48);
            var s = '';
            for (var i = 0; i < n; i++) {
                s += ('0' + (arr[i] & 0xff).toString(16)).slice(-2);
            }
            return s;
        } catch (e) { return '<err>'; }
    }

    // 供调用方在**求值之前**判断是否已达上限
    function atLimit() {
        if (events.length >= MAX_EVENTS) { truncated = true; return true; }
        return false;
    }

    // (6) 第六次修改（2026-11-26）
    // bug 原因：① 全部 crypto 钩子直接读 buf.length / res.length，遇到 null 参数或 null 返回值会抛 TypeError 搞崩 App；
    //           ② atLimit() 虽已定义但从未接入，达到 MAX_EVENTS 后仍继续抓栈与转十六进制拖慢目标；
    //           ③ stop 时未把已挂钩重载恢复为 implementation = null。
    // 解决方案：① 统一对 buf / res / cmd / lst 判空保护；
    //           ② 所有 hook 回调先判 !atLimit() 再求值与记录；
    //           ③ 用 hookedOverloads 收集所有挂钩重载，stop 时统一恢复 implementation = null。
    var hookedOverloads = [];
    function hookOv(ov, fn) {
        ov.implementation = fn;
        hookedOverloads.push(ov);
    }

    function tryHook(label, fn) {
        try { fn(); return true; }
        catch (e) {
            record('_meta', 'hook_error',
                   {target: label, error: String(e).slice(0, 120)});
            return false;
        }
    }

    var installed = [];

    // ---------------- crypto ----------------
    if (CFG.crypto) {
        if (tryHook('MessageDigest', function () {
            var MD = Java.use('java.security.MessageDigest');
            hookOv(MD.getInstance.overload('java.lang.String'), function (algo) {
                var r = this.getInstance(algo);
                if (!atLimit()) {
                    record('crypto', 'digest_algo',
                           {algo: algo, stack: javaStack(6, 2)});
                }
                return r;
            });
            hookOv(MD.digest.overload('[B'), function (buf) {
                var res = this.digest(buf);
                if (!atLimit()) {
                    record('crypto', 'digest_io', {
                        algo: this.getAlgorithm ? this.getAlgorithm() : '?',
                        in_hex: buf ? hexOf(buf) : '',
                        in_len: buf ? buf.length : 0,
                        out: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
            // (3) 第三次修改（2026-11-11）：补无参 digest()。
            //     bug 原因：原来只 hook 了 digest(byte[])，但最常见的用法是
            //               update(byte[]) + digest()（无参）——抓不到密文。
            //     解决方案：同样挂上无参重载，输出长度信息用于识别。
            hookOv(MD.digest.overload(), function () {
                var res = this.digest();
                if (!atLimit()) {
                    record('crypto', 'digest_out', {
                        algo: this.getAlgorithm ? this.getAlgorithm() : '?',
                        out: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
            // update 记录输入（无参 digest 场景下，明文只在这里出现过）
            hookOv(MD.update.overload('[B'), function (buf) {
                if (!atLimit()) {
                    record('crypto', 'digest_update', {
                        algo: this.getAlgorithm ? this.getAlgorithm() : '?',
                        in_hex: buf ? hexOf(buf) : '',
                        in_len: buf ? buf.length : 0
                    });
                }
                return this.update(buf);
            });
        })) { installed.push('MessageDigest'); }

        if (tryHook('Cipher', function () {
            var C = Java.use('javax.crypto.Cipher');
            hookOv(C.getInstance.overload('java.lang.String'), function (t) {
                var r = this.getInstance(t);
                if (!atLimit()) {
                    record('crypto', 'cipher_algo', {transformation: t});
                }
                return r;
            });
            hookOv(C.doFinal.overload('[B'), function (buf) {
                var res = this.doFinal(buf);
                if (!atLimit()) {
                    record('crypto', 'cipher_io', {
                        in_hex: buf ? hexOf(buf) : '',
                        in_len: buf ? buf.length : 0,
                        out_hex: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
            // (3) 第三次修改（2026-11-11）：补无参 doFinal()。
            //     原因同 digest：Cipher 也常用 update()+doFinal() 的分段写法。
            hookOv(C.doFinal.overload(), function () {
                var res = this.doFinal();
                if (!atLimit()) {
                    record('crypto', 'cipher_out', {
                        out_hex: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
        })) { installed.push('Cipher'); }

        if (tryHook('Mac', function () {
            var M = Java.use('javax.crypto.Mac');
            hookOv(M.getInstance.overload('java.lang.String'), function (algo) {
                var r = this.getInstance(algo);
                if (!atLimit()) {
                    record('crypto', 'mac_algo', {algo: algo});
                }
                return r;
            });
            // (3) 第三次修改（2026-11-11）：
            //     bug 原因：Mac 原来只 hook 了 getInstance，没有 doFinal——
            //               但 BEHAVIOR_CATEGORIES 里声称抓「密钥+输入输出」，
            //               实际一条都拿不到。这是文档与实现不符。
            //     解决方案：补 doFinal 两个重载。
            hookOv(M.doFinal.overload('[B'), function (buf) {
                var res = this.doFinal(buf);
                if (!atLimit()) {
                    record('crypto', 'mac_io', {
                        algo: this.getAlgorithm ? this.getAlgorithm() : '?',
                        in_hex: buf ? hexOf(buf) : '',
                        in_len: buf ? buf.length : 0,
                        out: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
            hookOv(M.doFinal.overload(), function () {
                var res = this.doFinal();
                if (!atLimit()) {
                    record('crypto', 'mac_out', {
                        algo: this.getAlgorithm ? this.getAlgorithm() : '?',
                        out: res ? hexOf(res, 64) : '',
                        out_len: res ? res.length : 0,
                        stack: javaStack(5, 2)
                    });
                }
                return res;
            });
        })) { installed.push('Mac'); }
    }

    // ---------------- file ----------------
    if (CFG.file) {
        if (tryHook('FileInputStream', function () {
            var FIS = Java.use('java.io.FileInputStream');
            hookOv(FIS.$init.overload('java.lang.String'), function (p) {
                if (!atLimit()) {
                    record('file', 'open_read', {path: String(p), stack: javaStack(6, 2)});
                }
                return this.$init(p);
            });
        })) { installed.push('FileInputStream'); }

        if (tryHook('FileOutputStream', function () {
            var FOS = Java.use('java.io.FileOutputStream');
            hookOv(FOS.$init.overload('java.lang.String'), function (p) {
                if (!atLimit()) {
                    record('file', 'open_write', {path: String(p), stack: javaStack(6, 2)});
                }
                return this.$init(p);
            });
        })) { installed.push('FileOutputStream'); }
    }

    // ---------------- activity ----------------
    if (CFG.activity) {
        if (tryHook('Activity', function () {
            var A = Java.use('android.app.Activity');
            hookOv(A.onCreate.overload('android.os.Bundle'), function (b) {
                if (!atLimit()) {
                    record('activity', 'onCreate',
                           {cls: this.getClass().getName(), stack: javaStack(6, 2)});
                }
                return this.onCreate(b);
            });
            hookOv(A.onResume, function () {
                if (!atLimit()) {
                    record('activity', 'onResume', {cls: this.getClass().getName()});
                }
                return this.onResume();
            });
        })) { installed.push('Activity'); }
    }

    // ---------------- assets ----------------
    if (CFG.assets) {
        if (tryHook('AssetManager', function () {
            var AM = Java.use('android.content.res.AssetManager');
            hookOv(AM.open.overload('java.lang.String'), function (n) {
                if (!atLimit()) {
                    record('assets', 'open', {name: String(n), stack: javaStack(6, 2)});
                }
                return this.open(n);
            });
        })) { installed.push('AssetManager'); }
    }

    // ---------------- shell ----------------
    if (CFG.shell) {
        if (tryHook('Runtime', function () {
            var R = Java.use('java.lang.Runtime');
            hookOv(R.exec.overload('[Ljava.lang.String;'), function (cmd) {
                if (!atLimit()) {
                    var cstr = cmd ? String(cmd.join ? cmd.join(' ') : cmd) : '';
                    record('shell', 'exec',
                           {cmd: cstr, stack: javaStack(6, 2)});
                }
                return this.exec(cmd);
            });
            hookOv(R.exec.overload('java.lang.String'), function (cmd) {
                if (!atLimit()) {
                    record('shell', 'exec', {cmd: String(cmd), stack: javaStack(6, 2)});
                }
                return this.exec(cmd);
            });
        })) { installed.push('Runtime.exec'); }

        if (tryHook('ProcessBuilder', function () {
            var PB = Java.use('java.lang.ProcessBuilder');
            hookOv(PB.start, function () {
                if (!atLimit()) {
                    var cmd = '';
                    try {
                        var lst = this.command();
                        if (lst) {
                            var arr = [];
                            for (var i = 0; i < lst.size(); i++) { arr.push(String(lst.get(i))); }
                            cmd = arr.join(' ');
                        }
                    } catch (e) {}
                    record('shell', 'start', {cmd: cmd, stack: javaStack(6, 2)});
                }
                return this.start();
            });
        })) { installed.push('ProcessBuilder'); }
    }

    send({kind: 'installed', installed: installed, cfg: CFG});

    // (2) 第二次修改（2026-11-11）：
    //     bug 原因：原来事件只在 recv('stop') 时 send 一次，Python 侧的 poll
    //               只是读内存里的 box["events"]——而那个数组永远是空的。
    //               实测：start(resident) 后已产生 1 条事件，poll 返回 count=0，
    //               还把"没取到"表述成"监控期间没有任何命中"，误导排查方向。
    //     解决方案：加一条 'dump' 协议，按游标只回传**新增**的事件；
    //               frida 的 recv 是一次性的，所以回调里必须**重新注册**。
    //               Python 侧 poll 主动 post({"type":"dump"}) 再等结果。
    var cursor = 0;
    function registerDump() {
        recv('dump', function () {
            var slice = events.slice(cursor);
            cursor = events.length;
            send({kind: 'dump', events: slice, counts: counts,
                  total: events.length, truncated: truncated});
            registerDump();
        });
    }
    registerDump();

    recv('stop', function () {
        for (var hi = 0; hi < hookedOverloads.length; hi++) {
            try { hookedOverloads[hi].implementation = null; } catch (eCl) {}
        }
        hookedOverloads = [];
        send({kind: 'result', events: events, counts: counts,
              truncated: truncated, installed: installed});
    });
});
"""


def _detach_async(sess, timeout: float = 2.0) -> None:
    """守护线程里 detach（本设备同步 detach 会永久阻塞），带**去重与上限**。

    (5) 第五次修改（2026-11-16）：
        bug 原因：本地重写的版本丢掉了 tracer 版本的两个关键保护：
                  ① 按会话 id 去重（同一会话不重复起线程）；
                  ② 登记集合有上限（防线程无界增长）。
                  tracer 里明确记录过「20 次连续调用 → 线程 1→21」，
                  这两处等于把那个已修 BUG 又写回去了。
        解决方案：**保留本地实现**（不能直接转发给 tracer——
                  测试用假 session 对象，tracer 版会走 is_detached 等属性），
                  但把去重与上限两个机制补齐。
    """
    import threading as _th

    if sess is None:
        return
    with _DETACH_LOCK:
        sid = id(sess)
        if sid in _DETACHING:
            return                          # 同一会话已在 detach 中，不重复起线程
        if len(_DETACHING) >= _DETACH_MAX:
            return                          # 上限保护：宁可让 frida 自己回收
        _DETACHING.add(sid)

    def _w() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass
        finally:
            with _DETACH_LOCK:
                _DETACHING.discard(sid)

    t = _th.Thread(target=_w, daemon=True)
    t.start()
    t.join(timeout=timeout)



def behavior_monitor_start(serial: str, pid: int,
                           crypto: bool = True, file: bool = True,
                           activity: bool = True, assets: bool = True,
                           shell: bool = False,
                           duration: float = 0, max_events: int = 3000) -> dict:
    """启动 App 行为监控：算法 / 文件 / Activity / assets / Shell。

    ## 实现方式

    frida 注入（运行时 attach），**不需要 Xposed**。
    hook 的是 Java 标准 API 的入口，所以能直接拿到算法名——
    是 App 自己通过 `getInstance("MD5")` 告诉我们的，不是特征识别。

    ## 参数

        crypto   哈希/加解密/密钥哈希（MessageDigest / Cipher / Mac）
        file     文件读写（FileInputStream / FileOutputStream）
        activity Activity 生命周期
        assets   assets 资源加载
        shell    **执行 shell 命令**。默认关——
                 这是反调试最敏感的点之一，实测批量 hook 会触发风控
        duration 采集秒数（0 = 一直采集，直到调 stop）
        max_events 最多记录多少条事件（防内存爆掉）

    ## 返回

        ok / installed[]（实际挂上的 hook）/ cfg

    ## 覆盖边界（重要）

        ✅ 用标准 API 的 App（绝大多数）
        ❌ 自研 VM / 自己实现的算法 —— 它不调 MessageDigest，hook 抓不到

    ## 风控提醒

    每多开一类监控，被检测的概率就上升。实测教训：批量 hook 是最强信号。
    **建议按需最小化开启，不要图省事全开。**
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "NO_FRIDA", "error": str(exc)}

    # 至少要开一类
    if not any([crypto, file, activity, assets, shell]):
        return {"ok": False, "code": "NO_CATEGORY",
                "error": "至少要开启一类监控",
                "available": list(BEHAVIOR_CATEGORIES)}

    try:
        from server.dyn.java_bridge import JavaBridgeError, wrap_with_java_bridge

        cfg = {"crypto": bool(crypto), "file": bool(file),
               "activity": bool(activity), "assets": bool(assets),
               "shell": bool(shell)}
        js = (_JS_BEHAVIOR
              .replace("__CFG__", json.dumps(cfg))
              .replace("__MAX_EVENTS__", str(max(10, min(int(max_events), 20000)))))
        try:
            full = wrap_with_java_bridge(js)
        except JavaBridgeError as exc:
            return {"ok": False, "code": "NEEDS_FRIDA_JAVA", "error": str(exc)}
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "BUILD_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}

    # (2) 第二次修改（2026-11-11）：
    #     bug 原因：原来 `finally` 里写的是 `if duration: _detach_async(sess)`，
    #               常驻模式（duration=0）下只要 create_script / load 出错，
    #               sess 已经 attach 了却**永远不会 detach** —— 实测
    #               detached=False，每失败一次泄漏一个设备端 attach。
    #               另外同一个 pid 重复 start 会直接覆盖 _ACTIVE[key]，
    #               旧脚本还挂在目标进程里，但 Python 侧已没有句柄，既停不掉
    #               也回收不了（实测第一次会话 detached=False）。
    #     解决方案：① 用 keep_session 标志区分「成功后要保留」和「各种失败」，
    #                  失败路径**一律** detach；
    #               ② 重复 start 前先优雅停掉旧会话并明确告知；
    #               ③ _ACTIVE 的键改成 serial:pid，避免多设备同 pid 串台。
    sess = None
    keep_session = False
    box: dict = {"installed": None, "events": [], "counts": {},
                 "error": None, "done": False, "dumped": False}
    # (3) 这里原本有一行 `cfg: dict = {}`，会把上面组装好的开关覆盖成空字典，
    #     导致 crypto/shell 这类风险差一个数量级的类别在下游看起来完全一样。
    #     直接删掉——上面已经按入参组装好 cfg，不需要重新初始化。
    key = _active_key(serial, int(pid))
    try:
        # ② 重复 start：先停旧的（加锁保护 _ACTIVE）
        with _ACTIVE_LOCK:
            old = _ACTIVE.pop(key, None)
        replaced = False
        if old:
            try:
                old["script"].post({"type": "stop"})
            except Exception:                             # noqa: BLE001
                pass
            _detach_async(old.get("session"))
            replaced = True

        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(full)

        def _on(m, d):
            p = m.get("payload")
            if not isinstance(p, dict):
                if m.get("type") == "error":
                    box["error"] = m.get("description") or "脚本异常"
                return
            if p.get("kind") == "installed":
                box["installed"] = p.get("installed") or []
            elif p.get("kind") == "dump":
                box["events"].extend(p.get("events") or [])
                box["counts"] = p.get("counts") or {}
                box["total"] = p.get("total")
                box["dumped"] = True
            elif p.get("kind") == "result":
                box["events"] = p.get("events") or []
                box["counts"] = p.get("counts") or {}
                box["done"] = True

        script.on("message", _on)
        script.load()

        t0 = time.time()
        while time.time() - t0 < 15 and box["installed"] is None and not box["error"]:
            time.sleep(0.05)
        if box["error"]:
            return {"ok": False, "code": "MONITOR_FAILED",
                    "error": str(box["error"])[:300]}
        if box["installed"] is None:
            # (2) 拿不到 installed 不能当成功——那是"看起来装上了、其实不知道"
            return {"ok": False, "code": "INSTALL_TIMEOUT",
                    "error": ("脚本加载后 15 秒内没有回报已安装的 hook。"
                              "目标可能阻断了 Java hook，或脚本异常。"),
                    "hint": "先调 java_bridge_status 确认 Java bridge 可用"}

        # duration=0 表示常驻
        if not duration:
            with _ACTIVE_LOCK:
                _ACTIVE[key] = {"script": script, "session": sess, "box": box,
                                "cfg": cfg, "started": time.time(),
                                "serial": serial, "pid": int(pid)}
            keep_session = True
            out = {
                "ok": True,
                "mode": "resident",
                "pid": int(pid),
                "installed": box["installed"],
                "cfg": cfg,
                "note": ("监控已常驻。用 behavior_monitor_poll 取事件"
                         "（会主动向脚本要增量），behavior_monitor_stop 结束。"),
            }
            if replaced:
                out["replaced_previous"] = True
                out["note"] += "（已自动停掉该 pid 上先前启动的监控）"
            return out

        time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        t0 = time.time()
        while time.time() - t0 < 10 and not box["done"]:
            time.sleep(0.05)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "MONITOR_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        # 只有「常驻且登记成功」才保留会话，其余一律释放
        if not keep_session:
            _detach_async(sess)

    return _summarize(int(pid), box, duration, cfg)


# 常驻监控："serial:pid" -> {script, session, box, cfg, started}
#
# (2) 第二次修改（2026-11-11）：键从单纯的 pid 改成 serial:pid。
#     bug 原因：多台设备上同一个 pid 很常见（比如都是 systemui），
#               只用 pid 作键会互相覆盖，poll 到的是别的设备的数据。
_ACTIVE: dict = {}


def _active_key(serial: str, pid: int) -> str:
    """常驻监控的键：serial:pid。"""
    return f"{serial or '-'}:{int(pid)}"


def _summarize(pid: int, box: dict, duration: float, cfg: dict) -> dict:
    """把原始事件整理成结论。"""
    events = box.get("events") or []
    counts = box.get("counts") or {}
    out: dict = {
        "ok": True,
        "pid": pid,
        "installed": box.get("installed") or [],
        "cfg": cfg,
        "count": len(events),
        "counts": counts,
        "events": events,
        "duration": duration,
    }

    # 算法摘要：把出现过的算法名去重列出（这是最有用的部分）
    algos = sorted({e.get("algo") or e.get("transformation")
                    for e in events
                    if e.get("cat") == "crypto"
                    and (e.get("algo") or e.get("transformation"))})
    if algos:
        out["algorithms_seen"] = algos

    if not events:
        out["verdict"] = ("监控期间没有任何命中。可能原因："
                          "① 目标这段时间没执行相关操作；"
                          "② 目标用的是自研实现（不调标准 API）；"
                          "③ 加固 App 阻断了 Java hook")
    else:
        parts = [f"{k} {v} 条" for k, v in sorted(counts.items(),
                                                  key=lambda kv: -kv[1])]
        out["verdict"] = f"共 {len(events)} 条事件：" + "，".join(parts)
        if algos:
            out["verdict"] += f"；用到的算法：{', '.join(algos[:8])}"
    return out


def behavior_monitor_poll(serial: str = "", pid: int = 0) -> dict:
    """取常驻监控的当前结果（**会主动向脚本要增量**）。

    (2) 第二次修改（2026-11-11）：
        bug 原因：原来 poll 只是读 Python 内存里的 box["events"]，
                  而那个数组只有在脚本收到 stop 时才会被填充——
                  常驻模式下永远返回 0 条，还把「没取到」说成
                  「监控期间没有任何命中」，误导排查。
        解决方案：poll 主动 post({"type":"dump"})，JS 侧按游标只回传
                  **新增**的事件，Python 侧累积。可以反复调用看增量。
    """
    st, key, err = _pick_active(serial, pid)
    if err:
        return err

    # (6) 第六次修改（2026-11-26）
    # bug 原因：① 原实现用 `total is None` 判超时，只要第一次 poll 成功写入过 total，
    #           后续脚本假死无响应时也会误判成功并返回陈旧事件；
    #           ② post("dump") 前未清零 dumped 标志，可能被残留标志短路。
    # 解决方案：在 post("dump") 前先重置 dumped=False，用本次循环是否收到回应
    #           got_response 精确判定超时，彻底杜绝假成功。
    st["box"]["dumped"] = False
    try:
        st["script"].post({"type": "dump"})
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "code": "POLL_POST_FAILED",
                "error": f"{type(exc).__name__}: {exc}",
                "hint": "脚本可能已经失效，用 behavior_monitor_stop 收尾后重启监控"}

    got_response = False
    t0 = time.time()
    while time.time() - t0 < 3.0:
        if st["box"].get("dumped"):
            st["box"]["dumped"] = False
            got_response = True
            break
        time.sleep(0.05)

    if not got_response:
        return {"ok": False, "code": "POLL_NO_RESPONSE",
                "error": "脚本 3 秒内没有回应 dump 请求",
                "collected_so_far": len(st["box"].get("events") or []),
                "hint": "目标可能已退出，或 hook 已被清除。用 stop 收尾"}

    out = _summarize(int(st.get("pid") or 0), st["box"],
                     round(time.time() - st["started"], 1), st.get("cfg") or {})
    out["mode"] = "resident"
    out["key"] = key
    return out


def behavior_monitor_stop(serial: str = "", pid: int = 0) -> dict:
    """停掉常驻监控并返回最终结果。"""
    st, key, err = _pick_active(serial, pid)
    if err:
        return err

    # 先尝试拿一次增量（stop 的 result 是全量，但万一拿不到也别丢已采集的）
    try:
        st["script"].post({"type": "stop"})
    except Exception:                                     # noqa: BLE001
        pass
    t0 = time.time()
    while time.time() - t0 < 8 and not st["box"].get("done"):
        time.sleep(0.05)

    with _ACTIVE_LOCK:
        _ACTIVE.pop(key, None)
    _detach_async(st.get("session"))

    out = _summarize(int(st.get("pid") or 0), st["box"],
                     round(time.time() - st["started"], 1), st.get("cfg") or {})
    if not st["box"].get("done"):
        out["warning"] = ("8 秒内没收到脚本的最终结果，"
                          "以下是已采集到的事件（可能有少量缺失）")
    return out


def _pick_active(serial: str, pid: int):
    """找出要操作的常驻监控。返回 (记录, key, 错误响应)。

    (6) 第六次修改（2026-11-26）
    bug 原因：① 访问全局 _ACTIVE 无锁保护；
              ② 只传 serial 不传 pid 时忽略了 serial 条件，直接返回别的设备的唯一监控；
              ③ 按 pid 查找 0 命中时误落入 AMBIGUOUS_TARGET，报错“有 0 个监控的 pid 都是 X”。
    解决方案：全程持 _ACTIVE_LOCK；补全仅传 serial 的筛选分支；
              len(hits) == 0 明确返回 NO_ACTIVE_MONITOR。

    明确要求：给了 serial+pid 就精确匹配（不再"随便取第一个"）。
    只给 pid 或只给 serial 时，若恰好只有一个匹配就用它，0 个报未找到，多个报歧义。
    """
    with _ACTIVE_LOCK:
        if not _ACTIVE:
            return None, "", {"ok": False, "code": "NO_ACTIVE_MONITOR",
                              "error": "没有正在运行的监控",
                              "hint": "先用 behavior_monitor_start(duration=0) 启动"}

        if serial and pid:
            key = _active_key(serial, int(pid))
            if key in _ACTIVE:
                return _ACTIVE[key], key, None
            return None, "", {"ok": False, "code": "NO_ACTIVE_MONITOR",
                              "error": f"没有 {key} 的监控",
                              "active": sorted(_ACTIVE)}

        if pid:
            hits = [k for k, v in _ACTIVE.items()
                    if int(v.get("pid") or 0) == int(pid)]
            if len(hits) == 0:
                return None, "", {"ok": False, "code": "NO_ACTIVE_MONITOR",
                                  "error": f"没有找到 pid={pid} 的监控",
                                  "active": sorted(_ACTIVE)}
            if len(hits) == 1:
                return _ACTIVE[hits[0]], hits[0], None
            return None, "", {"ok": False, "code": "AMBIGUOUS_TARGET",
                              "error": f"有 {len(hits)} 个监控的 pid 都是 {pid}，"
                                       "请同时传 serial 来区分",
                              "active": sorted(_ACTIVE)}

        if serial:
            hits = [k for k, v in _ACTIVE.items()
                    if str(v.get("serial") or "") == str(serial)]
            if len(hits) == 0:
                return None, "", {"ok": False, "code": "NO_ACTIVE_MONITOR",
                                  "error": f"设备 {serial} 上没有正在运行的监控",
                                  "active": sorted(_ACTIVE)}
            if len(hits) == 1:
                return _ACTIVE[hits[0]], hits[0], None
            return None, "", {"ok": False, "code": "AMBIGUOUS_TARGET",
                              "error": f"设备 {serial} 上有 {len(hits)} 个监控，"
                                       "请同时指定 pid 来区分",
                              "active": sorted(_ACTIVE)}

        if len(_ACTIVE) == 1:
            k = next(iter(_ACTIVE))
            return _ACTIVE[k], k, None

        return None, "", {"ok": False, "code": "AMBIGUOUS_TARGET",
                          "error": f"当前有 {len(_ACTIVE)} 个监控，"
                                   "请指定 serial 和 pid",
                          "active": sorted(_ACTIVE)}
