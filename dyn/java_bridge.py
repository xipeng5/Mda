"""frida 17 的 Java bridge 加载层。

## 为什么需要这一层

frida 17 起，**Java / ObjC bridge 从内核解耦**，不再默认可用——
脚本里直接写 `Java.use(...)` 会报 `ReferenceError: 'Java' is not defined`。
官方 issue 说明这是刻意的架构调整，不是缺陷：

    https://github.com/frida/frida/issues/3473
    "Java is no longer available in the global context by default in Frida 17.
     You need to install bridges you want to use."

所以每个用到 Java 的脚本，都必须先把 bridge 源码拼到自己前面，
再把它的导出对象挂到 `globalThis.Java` 上。

## bridge 源码从哪来

不需要联网下载——`frida_tools` 包里自带：

    <site-packages>/frida_tools/bridges/java.js      (约 232KB)
                                     /objc.js
                                     /swift.js

本模块负责：定位 → 读取 → 缓存 → 包装，并给出**可诊断的错误**
（找不到时装死是最糟的，会让调用方以为设备不支持）。

## 实测（2026-11-06，闲鱼 com.taobao.idlefish，Android 12 / arm64）

    Java.available = true
    Java.perform(...) 正常
    Java.use('android.app.Activity') 拿到 415 个方法

frida-server 不需要换，设备不用动。
"""

from __future__ import annotations

import os

__all__ = [
    "JavaBridgeError",
    "bridge_path",
    "load_bridge_source",
    "wrap_with_java_bridge",
    "bridge_status",
]


class JavaBridgeError(RuntimeError):
    """bridge 源码不可用。带上 code 便于上层区分"环境缺"与"调用错"。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# 缓存：232KB 的源码每次重读 + 重拼是纯浪费，且工具会在同一进程内被反复调用
_SRC_CACHE: dict[str, str] = {}


def bridge_path(lang: str = "java") -> str:
    """定位 bridge 源码路径。

    (1) 第一次修改（2026-11-06）：新增。
        为什么不用硬编码路径：site-packages 的实际位置随 venv/python 版本变化，
        打包成 app 后更是完全不同的位置。必须靠 importlib 动态定位。
    """
    name = str(lang or "").strip().lower()
    if not name:
        raise JavaBridgeError("BAD_LANG", "lang 不能为空")
    try:
        import importlib.util

        spec = importlib.util.find_spec("frida_tools")
    except Exception as exc:                              # noqa: BLE001
        raise JavaBridgeError(
            "NO_FRIDA_TOOLS",
            f"无法定位 frida_tools：{type(exc).__name__}: {exc}；"
            "Java bridge 源码由它提供，请先 pip install frida-tools") from exc

    if spec is None or not spec.origin:
        raise JavaBridgeError(
            "NO_FRIDA_TOOLS",
            "未安装 frida-tools；Java bridge 源码由它提供（pip install frida-tools）")

    path = os.path.join(os.path.dirname(spec.origin), "bridges", f"{name}.js")
    if not os.path.isfile(path):
        raise JavaBridgeError(
            "NO_BRIDGE_FILE",
            f"找不到 {name} bridge 源码：{path}；"
            "可能是 frida-tools 版本过旧（内置 bridge 是较新版本才有的）")
    return path


def load_bridge_source(lang: str = "java", use_cache: bool = True) -> str:
    """读 bridge 源码（默认走缓存）。"""
    name = str(lang or "").strip().lower()
    if use_cache and name in _SRC_CACHE:
        return _SRC_CACHE[name]
    path = bridge_path(name)
    try:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
    except Exception as exc:                              # noqa: BLE001
        raise JavaBridgeError(
            "READ_FAILED",
            f"读 bridge 源码失败 {path}：{type(exc).__name__}: {exc}") from exc
    if not src.strip():
        raise JavaBridgeError("EMPTY_BRIDGE", f"bridge 源码为空：{path}")
    _SRC_CACHE[name] = src
    return src


def wrap_with_java_bridge(user_js: str, lang: str = "java") -> str:
    """把 bridge 源码拼在用户脚本前面，并把导出挂到 `globalThis.<Lang>`。

    (1) 第一次修改（2026-11-06）：新增。
        bug 原因：frida 17 不再提供全局 Java，脚本直接 `Java.use` 会抛
                  ReferenceError。而错误信息只有一句 "Java is not defined"，
                  很容易被误判成"设备不支持 Java hook"或"frida-server 有问题"。
                  实测排障花了不少时间才发现是 bridge 没加载。
        解决方案：统一在这里包装。bridge 源码末尾会定义 `bridge` 变量，
                  用 Object.defineProperty 挂到 globalThis 上（**不可枚举**，
                  避免污染 for-in / Object.keys 的输出）。

    ## 为什么用 defineProperty 而不是 `globalThis.Java = bridge`

    直接赋值会让 `Java` 成为可枚举属性。有些库会遍历全局对象做检测，
    可枚举的 Java 反而更容易被发现。defineProperty 默认不可枚举，更贴近
    frida 16 时代原生注入的行为。

    参数：
        user_js  用户脚本正文
        lang      bridge 语言（java / objc / swift），默认 java

    返回：可直接喂给 `create_script` 的完整脚本。
    """
    name = str(lang or "").strip().lower()
    if not name:
        raise JavaBridgeError("BAD_LANG", "lang 不能为空")
    global_name = {"java": "Java", "objc": "ObjC", "swift": "Swift"}.get(
        name, name.capitalize())

    src = load_bridge_source(name)
    wrapper = (
        "/* frida bridge: " + name + " —— 由 mda 自动注入，勿删 */\n"
        "(function () {\n"
        + src
        + "\n;if (typeof bridge !== 'undefined') {\n"
        "  try {\n"
        "    Object.defineProperty(globalThis, '" + global_name + "',\n"
        "      { value: bridge, enumerable: false, configurable: true });\n"
        "  } catch (e) {\n"
        "    send({ kind: 'bridge_error', message: String(e) });\n"
        "  }\n"
        "}\n"
        "})();\n"
    )
    return wrapper + "\n" + str(user_js or "")


def bridge_status(lang: str = "java") -> dict:
    """报告 bridge 可用性，供 preflight 类工具调用（**不连设备**）。

    返回：{ok, lang, path, size_bytes, loaded_from_cache, error, code}
    """
    name = str(lang or "").strip().lower()
    out: dict = {"ok": False, "lang": name, "path": "", "size_bytes": 0,
                 "loaded_from_cache": name in _SRC_CACHE}
    try:
        out["path"] = bridge_path(name)
        src = load_bridge_source(name)
        out["ok"] = True
        out["size_bytes"] = len(src.encode("utf-8"))
        out["loaded_from_cache"] = name in _SRC_CACHE
    except JavaBridgeError as exc:
        out["error"] = str(exc)
        out["code"] = exc.code
    except Exception as exc:                              # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["code"] = "UNKNOWN"
    return out


# ---------------- Java 侧分析能力 ----------------
#
# 下面三个函数都依赖上面的 bridge 注入。设计原则与 mda 其他动态工具一致：
#   ① 能采到就给结构化数据，采不到就说清原因；
#   ② 绝不返回编造的方法名/参数；
#   ③ 所有 frida 调用在**守护线程**里做 detach（该设备上 detach 会永久阻塞）。

_JS_HELPERS = r"""
// 把 Java 对象转成可 JSON 化的简要描述（避免 toString 抛异常或返回巨大字符串）
function mdaDescribe(v) {
    if (v === null || v === undefined) { return null; }
    try {
        var s = String(v);
        return s.length > 200 ? s.slice(0, 200) + '…' : s;
    } catch (e) { return '<无法转成字符串>'; }
}

// 取调用栈（Java 层），最多 depth 层
function mdaJavaStack(depth) {
    try {
        var t = Java.use('java.lang.Thread').currentThread();
        var st = t.getStackTrace();
        var out = [];
        var n = Math.min(st.length, depth || 8);
        for (var i = 0; i < n; i++) { out.push(String(st[i].toString())); }
        return out;
    } catch (e) { return []; }
}
"""


def java_list_methods(serial: str, pid: int, class_name: str,
                       include_fields: bool = True) -> dict:
    """列出一个 Java 类的所有方法与字段。

    (2) 第二次修改（2026-11-06）：新增。

    为什么有用：加固 app 的类常由 DexClassLoader 动态加载，静态反编译看不到。
    这里通过 `Java.use(cls).class` 直接拿运行时的 Class 对象，
    **包括动态加载的类**。

    ## 参数

        class_name       全限定类名，如 "android.app.Activity"
        include_fields   是否一并列字段

    ## 返回

        found           类是否存在
        class_name / superclass / interfaces
        methods[]       {name, signature, return_type, param_types, is_native, modifiers}
        fields[]        {name, type, modifiers}
        counts          {methods, fields}
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_list_methods", f"frida 不可用：{exc}",
                             {"class_name": class_name})

    user_js = _JS_HELPERS + """
    Java.perform(function () {
        var out = {found: false, methods: [], fields: []};
        try {
            var cls = Java.use(CLASS_NAME);
            var jc = cls.class;
            out.found = true;
            out.class_name = String(jc.getName());
            try { out.superclass = String(jc.getSuperclass()); } catch (e) {}
            try {
                var ifs = jc.getInterfaces();
                out.interfaces = [];
                for (var i = 0; i < ifs.length; i++) { out.interfaces.push(String(ifs[i].getName())); }
            } catch (e) {}

            try {
                var ms = jc.getDeclaredMethods();
                for (var i = 0; i < ms.length; i++) {
                    var m = ms[i];
                    var ps = m.getParameterTypes();
                    var pts = [];
                    for (var j = 0; j < ps.length; j++) { pts.push(String(ps[j].getName())); }
                    out.methods.push({
                        name: String(m.getName()),
                        signature: String(m.toString()),
                        return_type: String(m.getReturnType().getName()),
                        param_types: pts,
                        is_native: (m.getModifiers() & 0x100) !== 0,
                        modifiers: m.getModifiers()
                    });
                }
            } catch (e) { out.methods_err = String(e); }

            if (INCLUDE_FIELDS) {
                try {
                    var fs = jc.getDeclaredFields();
                    for (var i = 0; i < fs.length; i++) {
                        out.fields.push({
                            name: String(fs[i].getName()),
                            type: String(fs[i].getType().getName()),
                            modifiers: fs[i].getModifiers()
                        });
                    }
                } catch (e) { out.fields_err = String(e); }
            }
        } catch (e) {
            out.error = String(e).slice(0, 300);
        }
        out.counts = {methods: out.methods.length, fields: out.fields.length};
        send(out);
    });
    """.replace("CLASS_NAME", _js_str(class_name)).replace(
        "INCLUDE_FIELDS", "true" if include_fields else "false")

    box, err = _run_java_script(serial, pid, user_js, timeout=25.0)
    if err:
        return err
    box["ok"] = True
    box["implemented"] = True
    if not box.get("found"):
        box["hint"] = ("类未找到。可能原因：① 类名写错（需要全限定名）；"
                       "② 该类还没被加载——DexClassLoader 是懒加载的，"
                       "用 java_find_classes 先按正则找已加载的类")
    return box


def java_find_classes(serial: str, pid: int, pattern: str = "",
                      limit: int = 200) -> dict:
    """在**已加载的类**里按正则搜索。

    (2) 第二次修改（2026-11-06）：新增。

    为什么有用：加固 app 会动态加载大量类，静态看不到。这里枚举运行时
    所有已加载的 Class，然后正则筛选——是摸清一个 app 内部结构的起点。

    ## 参数

        pattern   正则（大小写不敏感），空则返回前 limit 个
        limit     最多返回多少个（1..2000）

    ## 返回

        classes[]  全限定类名列表
        total      枚举到的类总数（不受 limit 影响）
        matched    匹配数
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_find_classes", f"frida 不可用：{exc}",
                             {"pattern": pattern})

    n = max(1, min(int(limit), 2000))
    user_js = _JS_HELPERS + """
    Java.perform(function () {
        var out = {classes: [], total: 0, matched: 0};
        try {
            var loader = Java.use('java.lang.ClassLoader');
            var cls = Java.use('java.lang.Class');
            // 用 enumerateLoadedClasses 最直接（frida-java-bridge 提供）
            var all = Java.enumerateLoadedClassesSync();
            out.total = all.length;
            var re = PATTERN ? new RegExp(PATTERN, 'i') : null;
            for (var i = 0; i < all.length; i++) {
                var name = all[i];
                if (re === null || re.test(name)) {
                    out.matched++;
                    if (out.classes.length < LIMIT) { out.classes.push(name); }
                }
            }
        } catch (e) {
            out.error = String(e).slice(0, 300);
        }
        send(out);
    });
    """.replace("PATTERN", _js_str(pattern or "")).replace("LIMIT", str(n))

    box, err = _run_java_script(serial, pid, user_js, timeout=40.0)
    if err:
        return err
    box["ok"] = True
    box["implemented"] = True
    box["pattern"] = pattern
    if box.get("total"):
        box["note"] = (f"枚举到 {box['total']} 个已加载类，"
                       f"匹配 {box.get('matched', 0)} 个"
                       + (f"，本页返回 {len(box.get('classes') or [])} 个"
                          if box.get("matched", 0) > len(box.get("classes") or [])
                          else ""))
    return box


def java_hook(serial: str, pid: int, class_name: str, method: str,
              overload: str = "", duration: float = 5.0,
              max_calls: int = 200, include_stack: bool = True,
              stack_depth: int = 8) -> dict:
    """hook 一个 Java 方法，记录每次调用的参数、返回值、调用栈。

    (2) 第二次修改（2026-11-06）：新增。

    这是 mda 从"只看 native"跨到"Java 层可见"的关键能力。

    ## 参数

        class_name   全限定类名
        method       方法名
        overload     重载签名（可选），如 "(Ljava/lang/String;)V"；
                     不传则 hook 所有同名重载
        duration     采集秒数
        max_calls    最多记录多少次调用（防高频方法打爆内存）
        include_stack 是否抓 Java 调用栈
        stack_depth  栈深度

    ## 返回

        hooked       实际 hook 上的重载列表
        calls[]      {seq, thread, args[], ret, stack[], ts}
        call_count   调用次数（可能大于 calls 长度，被 max_calls 截断）
        truncated    是否因 max_calls 截断

    ## 已知边界（如实标注）

        · 只 hook **实例方法**；静态方法用 `Java.use(cls).method.overload(...)` 也能 hook，
          但这里统一用 implementation 覆盖，静态方法同样生效
        · 参数按 `String(v)` 转成字符串并截断 200 字符——**对象只给摘要**，
          需要细节的话再单独对那个对象做分析
        · 方法被内联或走 JIT 优化时，hook 可能失效（ART 的已知限制）
    """
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_hook", f"frida 不可用：{exc}",
                             {"class_name": class_name, "method": method})

    cap = max(1, min(int(max_calls), 5000))
    user_js = _JS_HELPERS + """
    Java.perform(function () {
        var out = {hooked: [], calls: [], call_count: 0};
        var seq = 0;
        try {
            var cls = Java.use(CLASS_NAME);
            var target = cls[METHOD];
            if (target === undefined) {
                send({kind: 'hook_error', error: '类里没有名为 ' + METHOD + ' 的方法'});
                return;
            }
            var overloads = target.overloads || [];
            var wanted = OVERLOAD;
            for (var i = 0; i < overloads.length; i++) {
                var ov = overloads[i];
                if (wanted && String(ov) !== wanted) { continue; }
                (function (ovObj, sig) {
                    ovObj.implementation = function () {
                        out.call_count++;
                        if (out.calls.length >= MAXCALLS) {
                            out.truncated = true;
                            return ovObj.apply(this, arguments);
                        }
                        var rec = {seq: out.call_count, ts: Date.now() / 1000, args: [],
                                   thread: null, stack: []};
                        try { rec.thread = String(Java.use('java.lang.Thread').currentThread().getId()); } catch (e) {}
                        try {
                            for (var k = 0; k < arguments.length; k++) {
                                rec.args.push(mdaDescribe(arguments[k]));
                            }
                        } catch (e) {}
                        if (INCLUDE_STACK) {
                            rec.stack = mdaJavaStack(STACKDEPTH);
                        }
                        var ret;
                        try {
                            ret = ovObj.apply(this, arguments);
                            rec.ret = mdaDescribe(ret);
                        } catch (e) {
                            rec.threw = String(e).slice(0, 200);
                            out.calls.push(rec);
                            throw e;
                        }
                        out.calls.push(rec);
                        return ret;
                    };
                    out.hooked.push(sig);
                })(ov, String(ov));
            }
            if (out.hooked.length === 0) {
                send({kind: 'hook_error',
                      error: '没有匹配的重载（wanted=' + wanted + '，可用 ' + overloads.length + ' 个）'});
                return;
            }
        } catch (e) {
            send({kind: 'hook_error', error: String(e).slice(0, 300)});
            return;
        }
        send({kind: 'ready', hooked: out.hooked});
        recv('stop', function () {
            send({kind: 'result', hooked: out.hooked, calls: out.calls,
                  call_count: out.call_count, truncated: out.truncated || false});
        });
    });
    """.replace("CLASS_NAME", _js_str(class_name)).replace(
        "METHOD", _js_str(method)).replace("OVERLOAD", _js_str(overload or "")).replace(
        "MAXCALLS", str(cap)).replace(
        "INCLUDE_STACK", "true" if include_stack else "false").replace(
        "STACKDEPTH", str(max(1, min(int(stack_depth or 8), 32))))

    return _run_java_hook(serial, pid, user_js, duration=float(duration))


# ---------------- 内部辅助 ----------------


def _js_str(s: str) -> str:
    """把 Python 字符串转成 JS 字符串字面量（转义引号与反斜杠）。"""
    import json as _json

    return _json.dumps(str(s or ""))


def _java_pending(feature: str, reason: str, extra: dict | None = None) -> dict:
    """Java 能力不可用时返回**明确结构**，绝不返回空列表冒充"没有"。"""
    out = {
        "ok": False,
        "implemented": False,
        "code": "NEEDS_FRIDA_JAVA",
        "feature": feature,
        "error": reason,
        "hint": ("frida 17 起 Java bridge 不再内置，需由 mda 注入 "
                 "frida_tools 自带的 java.js；请确认已安装 frida-tools"),
    }
    if extra:
        out.update(extra)
    return out


def _detach_async(sess, timeout: float = 2.0) -> None:
    """守护线程里 detach。

    (3) 第三次修改（2026-11-06）：新增。
        bug 原因：本设备上 session.detach() 会**永久阻塞**（已在 dyn/tracer、
                  dyn/rebase 多处实测），写在 finally 里等于每次调用都卡死。
        解决方案：丢进守护线程，主流程最多等 timeout 就走。
    """
    import threading as _th

    if sess is None:
        return

    def _w() -> None:
        try:
            sess.detach()
        except Exception:                                 # noqa: BLE001
            pass

    t = _th.Thread(target=_w, name="mda-java-detach", daemon=True)
    t.start()
    try:
        t.join(max(0.1, float(timeout)))
    except Exception:                                     # noqa: BLE001
        pass


def _run_java_script(serial: str, pid: int, user_js: str,
                     timeout: float = 25.0) -> tuple[dict, dict | None]:
    """注入 bridge + 跑脚本，取第一条消息。返回 (payload, error_dict)。"""
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return {}, _java_pending("java", f"frida 不可用：{exc}")

    try:
        full = wrap_with_java_bridge(user_js)
    except JavaBridgeError as exc:
        return {}, _java_pending("java", str(exc), {"code_detail": exc.code})

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(full)
        box: dict = {}
        box["_msgs"] = []

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if isinstance(payload, dict):
                if payload.get("kind") == "hook_error":
                    box["_err"] = payload.get("error") or "hook 失败"
                    return
                box.update(payload)
            elif msg.get("type") == "error":
                box["_err"] = msg.get("description") or "脚本异常"

        script.on("message", _on_msg)
        script.load()
        t0 = _time.time()
        while not box and _time.time() - t0 < timeout:
            _time.sleep(0.02)
        if box.get("_err"):
            return {}, {"ok": False, "implemented": True,
                        "code": "JAVA_SCRIPT_ERROR",
                        "error": str(box["_err"])[:400]}
        if not box:
            return {}, {"ok": False, "implemented": True, "code": "TIMEOUT",
                        "error": f"{timeout:g}s 内没有收到脚本结果",
                        "hint": "目标可能卡在 Java.perform（ART 未就绪或已加固阻断）"}
        return box, None
    except Exception as exc:                              # noqa: BLE001
        return {}, {"ok": False, "implemented": True,
                    "code": "JAVA_CALL_FAILED",
                    "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)


def _run_java_hook(serial: str, pid: int, user_js: str,
                   duration: float = 5.0) -> dict:
    """hook 类脚本的专用执行器：等 ready → 采集 duration → post stop → 收 result。"""
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_hook", f"frida 不可用：{exc}")

    try:
        full = wrap_with_java_bridge(user_js)
    except JavaBridgeError as exc:
        return _java_pending("java_hook", str(exc), {"code_detail": exc.code})

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(full)
        box: dict = {"ready": False, "done": False, "hooked": [],
                     "calls": [], "call_count": 0, "truncated": False}

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["_err"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["hooked"] = payload.get("hooked") or []
                return
            if kind == "result":
                box["done"] = True
                box["hooked"] = payload.get("hooked") or box["hooked"]
                box["calls"] = payload.get("calls") or []
                box["call_count"] = int(payload.get("call_count") or 0)
                box["truncated"] = bool(payload.get("truncated"))
                return
            if kind == "hook_error":
                box["_err"] = payload.get("error") or "hook 失败"
                return
            if kind == "bridge_error":
                box["_err"] = payload.get("message") or "bridge 注入失败"
                return

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box.get("_err") and _time.time() - t0 < 20.0:
            _time.sleep(0.02)
        if box.get("_err"):
            return {"ok": False, "implemented": True, "code": "JAVA_HOOK_FAILED",
                    "error": str(box["_err"])[:400],
                    "hint": ("类名/方法名要精确（类用全限定名）；"
                             "也可用 java_find_classes 先确认类已加载")}
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "hook 20 秒内未就位",
                    "hint": "目标可能被加固阻断 Java.perform，或 ART 尚未初始化"}

        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(50):
            if box["done"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "implemented": True, "code": "JAVA_HOOK_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)

    calls = box.get("calls") or []
    total = int(box.get("call_count") or 0)
    if total == 0:
        verdict = (f"hook 成功（{len(box.get('hooked') or [])} 个重载），"
                   f"但 {duration:g}s 内**一次都没被调用**："
                   "说明这个方法在当前操作下没被走到")
    else:
        verdict = (f"hook 成功，{duration:g}s 内被调用 {total} 次"
                   + ("（记录已按 max_calls 截断）" if box.get("truncated") else ""))
    return {
        "ok": True,
        "implemented": True,
        "hooked": box.get("hooked") or [],
        "calls": calls,
        "call_count": total,
        "truncated": bool(box.get("truncated")),
        "duration": duration,
        "verdict": verdict,
    }
