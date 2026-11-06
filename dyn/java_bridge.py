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


def bridge_status(lang: str = "java", serial: str = "", pid: int = 0) -> dict:
    """报告 bridge 可用性；给了 serial+pid 就额外报告**运行时可 hook 规模**。

    (8) 第八次修改（2026-11-06）：新增可选的运行时探测（对应 P2-2）。
        为什么：原来只报"bridge 文件在不在"。但真正决定能不能干活的是
        "这个进程里有多少类可以 hook、有哪些限制"——调用方拿到这些数
        才能判断后续查询的代价。

    不传 serial/pid 时**纯本地检查、不连设备**（保持原来的轻量语义）。

    返回（本地部分）：
        {ok, lang, path, size_bytes, loaded_from_cache, error, code}

    返回（给了 serial+pid 时额外）：
        runtime: {available, android_version, enumerable_classes,
                  hookable_methods, restrictions[], sample_ms}

    其中 hookable_methods 是**抽样估算**：取前 N 个非系统类统计其声明方法数
    再按比例外推。全量统计要几十秒，对"够不够用"的判断没必要那么精确。
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

    # 可选：连设备做运行时规模探测
    if serial and int(pid or 0) > 0:
        out["runtime"] = _probe_runtime_scale(serial, int(pid))
    return out


def _probe_runtime_scale(serial: str, pid: int) -> dict:
    """探测目标进程里 Java 类的可 hook 规模（抽样估算，不追求精确）。

    (8) 第八次修改（2026-11-06）：新增。

    为什么抽样：全量统计 3 万多个类的所有方法要几十秒，而调用方只是想知道
    "这个量级够不够干活"。取 200 个类统计平均方法数再外推，误差可接受，
    耗时降到亚秒级。返回里会写明 sample_size，不冒充精确值。
    """
    import time as _time

    js = """
    Java.perform(function () {
        var out = {available: false, sample_size: 0, methods_in_sample: 0};
        try {
            out.available = true;
            out.android_version = Java.androidVersion;
            var all = Java.enumerateLoadedClassesSync();
            out.enumerable_classes = all.length;
            var SAMPLE = 200, methods = 0, n = 0;
            for (var i = 0; i < all.length && n < SAMPLE; i++) {
                var nm = all[i];
                // 跳过系统类：它们方法多且 hook 风险高，用它们外推会高估
                if (nm.indexOf('java.') === 0 || nm.indexOf('android.') === 0 ||
                    nm.indexOf('kotlin.') === 0 || nm.indexOf('dalvik.') === 0) { continue; }
                try {
                    var jc = Java.use(nm).class;
                    methods += jc.getDeclaredMethods().length;
                    n++;
                } catch (e) {}
            }
            out.sample_size = n;
            out.methods_in_sample = methods;
            if (n > 0) {
                out.hookable_methods_estimate =
                    Math.round(methods / n * all.length);
            }
        } catch (e) { out.error = String(e).slice(0, 200); }
        send(out);
    });
    """
    t0 = _time.time()
    box, err = _run_java_script(serial, pid, js, timeout=45.0)
    if err:
        return {"available": False, "error": err.get("error") or "探测失败",
                "code": err.get("code") or "PROBE_FAILED"}
    box["restrictions"] = [
        "java.lang.* / dalvik.* / sun.* / libcore.* 已在 hook 前自动排除",
        "final 方法可 hook（ART 未内联时）",
        "被 JIT 内联的方法 hook 会漏",
        "native 方法可 hook（走 Java 层桥接）",
        "hookable_methods 是**抽样外推**，非精确值",
    ]
    box["sample_ms"] = int((_time.time() - t0) * 1000)
    return box


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
                      limit: int = 200, field: str = "",
                      return_type: str = "", method_pattern: str = "",
                      max_scan_classes: int = 0) -> dict:
    """在**已加载的类**里搜索——支持按类名、字段名、方法返回类型三种维度。

    (7) 第七次修改（2026-11-06）：新增 field / return_type / method_pattern
        三个搜索维度（对应 P1-3）。

    为什么需要：只知道类名正则时，找"谁持有 headers 字段"或"谁返回 Request
    对象"都得先猜类名。而这两类查询恰恰是定位采集点最直接的手段。

    ## 四种搜索方式（可组合）

        pattern        类名正则（大小写不敏感）—— 原来的能力
        field          类里有这个**字段名**（支持通配符）
        return_type    类里某个方法**返回这个类型**（支持通配符，全限定名）
        method_pattern 类里有匹配这个**方法名**的方法

    ## 性能提示（重要）

    按 field / return_type / method_pattern 搜索需要**逐类反射扫描**，
    已加载类有几万个时很慢。所以：

        · 只给 pattern → 走 enumerateLoadedClassesSync，秒回
        · 给了其他维度 → 需要扫描，用 max_scan_classes 限制扫描量
          （默认 3000；给 0 表示扫全部，会慢）

    返回里会报告实际扫描了多少类，方便判断结果是否可信。

    ## 返回

        classes[]      全限定类名
        total          枚举到的类总数
        scanned        实际做了反射扫描的类数
        matched        匹配数
        matched_by     本次用了哪些维度（便于确认查询意图）
        note
    """
    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_find_classes", f"frida 不可用：{exc}",
                             {"pattern": pattern})

    n = max(1, min(int(limit), 2000))
    deep = bool(field or return_type or method_pattern)
    scan_cap = int(max_scan_classes) if max_scan_classes else (3000 if deep else 0)

    # (10) 第十次修改（2026-11-06）：**必须是 raw string**。
    #     bug 原因：这里写的是普通三引号字符串，Python 会把 \\\\ 解析成 \\，
    #              于是 JS 里的字符类 /[.+^${}()|[\\]\\\\]/ 变成 /[.+^${}()|[\\]\]/,
    #              方括号提前闭合，frida 报 "unexpected line terminator in regexp"。
    #              同样的正则在 _JS_JAVA_HOOK_MULTI 里是 raw string（r"""），
    #              所以那边一直是好的——**同一个表达式两种字符串类型，只有一处坏**，
    #              这类不对称最容易漏掉。
    #     解决方案：改成 r"""，让反斜杠原样传给 JS。
    user_js = _JS_HELPERS + r"""
    Java.perform(function () {
        var out = {classes: [], total: 0, matched: 0, scanned: 0};
        var PATTERN = __PATTERN__;
        var FIELD = __FIELD__;
        var RETURN_TYPE = __RETURN_TYPE__;
        var METHOD_PATTERN = __METHOD_PATTERN__;
        var LIMIT = __LIMIT__;
        var SCAN_CAP = __SCAN_CAP__;

        // (11) 第十一次修改（2026-11-06）：修回正则语义 + 去掉全匹配锚定。
        //     bug 原因：上一版把 pattern 走"通配符转正则"，做了两件与用户期望
        //              冲突的事：
        //                ① 转义了正则元字符 —— 用户传 java\.lang\.String /
        //                   mtopsdk|anetwork 会被当**字面量**，永远匹配不到；
        //                ② 加了 ^...$ 全匹配 —— 用户传 Security 变成
        //                   必须整个类名等于 Security，而真实类名是
        //                   com.xxx.SecurityFoo，同样匹配不到。
        //              结果是**任何非空 pattern 都返回 0**，而空 pattern 正常，
        //              极易误判成"这个进程没有目标类"。
        //              之所以没被发现：我自己的测试全用 *NetworkConverter* 这种
        //              带 * 的写法，转成 ^.*X.*$ 恰好能匹配，掩盖了问题。
        //     解决方案：① **不再锚定**，改为子串搜索（还原最初实现的语义）；
        //               ② 智能判断——先当**正则**编译，成功就用正则（所以
        //                  Security / java\.lang\.String / a|b 都对）；
        //                  失败才转通配符（所以 *NetworkConverter* 也对）。
        //                  两种写法都能用，且不歧义。
        //               ③ 两者都失败时**明确报错**，绝不静默返回全部——
        //                  静默放行会让用户以为"匹配到了所有类"。
        // 判定规则（**不能用"能不能编译"来判断**—— convert* 是合法正则，
        // 会被理解成 ^convert*$ 也就是只匹配 conver/convert/convertt，
        // 用户的真实意图却是 "convert 开头的所有方法"）。
        //
        //   含 * 或 ?，且**不含**正则专属符号（\\ | [ ] ( ) { } ^ $）
        //       → 按通配符：* 变 .*  ? 变 .  其余转义
        //   否则 → 按正则原样编译
        //
        // 于是这几种写法都对：
        //   convert* / *NetworkConverter*  → 通配符
        //   java\.lang\.String / a|b      → 正则
        //   Security                       → 正则子串（匹配 com.x.SecurityFoo）
        function makeRe(p, label, anchor) {
            if (!p) { return null; }
            var a = anchor ? '^' : '', z = anchor ? '$' : '';
            var isWild = /[*?]/.test(p) && !/[\\|\[\](){}^$]/.test(p);
            if (isWild) {
                var esc = p.replace(/[.+${}()|[\]]/g, '\\$&');
                esc = esc.replace(/\*/g, '.*').replace(/\?/g, '.');
                try { return new RegExp(a + esc + z, 'i'); }
                catch (e) { throw new Error(label + ' 通配符转换失败：' + p); }
            }
            try { return new RegExp(a + p + z, 'i'); }
            catch (e) {
                // 到这里说明用户写的是"想当正则用但不合法"的东西，必须报错。
                // 静默放行（返回 null）会匹配所有类，比报错危险得多。
                throw new Error(label + ' 不是合法正则：' + p
                                + '（若想用通配符请写 convert* 这种形式）');
            }
        }
        var nameRe, fieldRe, retRe, methRe;
        try {
            nameRe = makeRe(PATTERN, 'pattern', false);
            fieldRe = makeRe(FIELD, 'field', false);
            retRe = makeRe(RETURN_TYPE, 'return_type', false);
            // 方法名锚定：搜 setHeaders 不该把 setHeadersAndMore 也算进来
            methRe = makeRe(METHOD_PATTERN, 'method_pattern', true);
        } catch (e) {
            // 参数本身有语法错 → 明确报错，不要抛到脚本层变成看不出原因的崩溃
            send({kind: 'hook_error', code: 'BAD_PATTERN', error: String(e)});
            return;
        }

        var all;
        try { all = Java.enumerateLoadedClassesSync(); }
        catch (e) { send({kind: 'hook_error', error: '无法枚举类：' + e}); return; }
        out.total = all.length;

        for (var i = 0; i < all.length; i++) {
            var nm = all[i];
            if (nameRe && !nameRe.test(nm)) { continue; }

            // 只按类名搜：不需要反射，直接算命中
            if (!fieldRe && !retRe && !methRe) {
                out.matched++;
                if (out.classes.length < LIMIT) { out.classes.push(nm); }
                continue;
            }

            // 需要反射扫描，受 SCAN_CAP 限制
            if (SCAN_CAP > 0 && out.scanned >= SCAN_CAP) { continue; }
            out.scanned++;

            var hit = false, reason = [];
            try {
                var jc = Java.use(nm).class;
                if (fieldRe) {
                    var fs = jc.getDeclaredFields();
                    for (var f = 0; f < fs.length && !hit; f++) {
                        if (fieldRe.test(String(fs[f].getName()))) {
                            hit = true; reason.push('field:' + String(fs[f].getName()));
                        }
                    }
                }
                if (!hit && (retRe || methRe)) {
                    var ms = jc.getDeclaredMethods();
                    for (var m = 0; m < ms.length && !hit; m++) {
                        if (methRe && !methRe.test(String(ms[m].getName()))) { continue; }
                        if (retRe) {
                            var rt = String(ms[m].getReturnType().getName());
                            if (retRe.test(rt)) {
                                hit = true;
                                reason.push('method:' + String(ms[m].getName()) + '->' + rt);
                            }
                        } else if (methRe) {
                            hit = true; reason.push('method:' + String(ms[m].getName()));
                        }
                    }
                }
            } catch (e) { /* 部分类反射会抛，跳过 */ }

            if (hit) {
                out.matched++;
                if (out.classes.length < LIMIT) {
                    out.classes.push(nm);
                    if (!out.reasons) { out.reasons = {}; }
                    out.reasons[nm] = reason.slice(0, 3);
                }
            }
        }
        send(out);
    });
    """.replace("__PATTERN__", _js_str(pattern or "")).replace(
        "__FIELD__", _js_str(field or "")).replace(
        "__RETURN_TYPE__", _js_str(return_type or "")).replace(
        "__METHOD_PATTERN__", _js_str(method_pattern or "")).replace(
        "__LIMIT__", str(n)).replace("__SCAN_CAP__", str(scan_cap))

    timeout = 90.0 if deep else 40.0
    box, err = _run_java_script(serial, pid, user_js, timeout=timeout)
    if err:
        return err
    box["ok"] = True
    box["implemented"] = True
    used = []
    if pattern:
        used.append("pattern")
    if field:
        used.append("field")
    if return_type:
        used.append("return_type")
    if method_pattern:
        used.append("method_pattern")
    box["matched_by"] = used
    if box.get("total"):
        note = (f"枚举到 {box['total']} 个已加载类，匹配 {box.get('matched', 0)} 个"
                + (f"，本页返回 {len(box.get('classes') or [])} 个"
                   if box.get("matched", 0) > len(box.get("classes") or []) else ""))
        if deep:
            note += (f"；反射扫描了 {box.get('scanned', 0)} 个类"
                     + ("（已达上限，结果可能不全，调大 max_scan_classes 或先用 pattern 缩小范围）"
                        if scan_cap and box.get("scanned", 0) >= scan_cap else ""))
        box["note"] = note
    return box


def java_hook(serial: str, pid: int, class_name: str = "", method: str = "",
              overload: str = "", duration: float = 5.0,
              max_calls: int = 200, include_stack: bool = True,
              stack_depth: int = 8,
              pattern: str = "", package: str = "", max_classes: int = 20,
              capture: dict | None = None,
              sibling_probe: bool = True) -> dict:
    """hook Java 方法，支持**通配符批量**、参数深挖、调用者回溯。

    (4) 第四次修改（2026-11-06）：大改。原来的实现只能 hook 单个类的单个方法，
        实际用起来最大的痛点不是"怎么 hook"，而是**不知道该 hook 哪个类**——
        hook 一个类要 16~20 秒，试三个类就一分钟，而答案往往就在第四个类里。
        这次把"找类"和"hook"合并成一步。

    ## 三种定位方式（可组合）

        class_name="com.x.Y"            精确类名
        pattern="*NetworkConverter*"    类名通配符（* 和 ?，大小写不敏感）
        package="mtopsdk"               包名前缀

    三者可同时给（取交集）。匹配到多个类时全部 hook，**分别统计命中数**，
    直接告诉你哪个类真的被调用了。

    ## 参数

        method        方法名，也支持通配符（如 "convert*"）。空 = 该类所有方法
        overload      重载签名（可选）
        duration      采集秒数
        max_calls     每个方法最多记录多少条（全局预算，防打爆内存）
        max_classes   最多 hook 多少个类（防一次挂几千个）
        capture       参数深挖配置：
                        {"args": true, "ret": true,
                         "arg_fields": ["url", "headers"],   # 从参数对象里取字段
                         "expand_map": true}                 # Map/List 自动展开
        sibling_probe 当方法 0 命中时，**自动探测同类其他方法**有没有被调用
                      （这是定位"我是不是 hook 错方法了"最有效的手段）

    ## 返回（P0-3 要的诊断信息）

        classes[]     每个被 hook 的类：{class, hooked_methods[], call_count,
                      calls[], subclass_of, instantiated}
        call_count    所有类合计调用数
        diagnosis     0 命中时给出：class_loaded / method_exists /
                      sibling_methods_called / suggestion
        verdict       一句话结论

    ## 已知边界（如实标注）

        · `java.lang.*` 等系统类部分方法 hook 后会崩，已在注入前排除
        · final 方法可以 hook（ART 未内联时）；被 JIT 内联的会漏
        · 通配符匹配用的是**已加载类**列表，未加载的类匹配不到
        · 参数只取 String 摘要 + 指定字段；对象深拷贝不支持（ART 不提供）
    """
    # 至少要有一种定位方式
    if not (str(class_name or "").strip() or str(pattern or "").strip()
            or str(package or "").strip()):
        return {
            "ok": False, "implemented": True, "code": "NEED_SELECTOR",
            "error": "至少要给 class_name / pattern / package 之一",
            "hint": ("不知道 hook 哪个类时，先用 pattern 通配："
                     "pattern='*NetworkConverter*' 会把所有匹配的类一起 hook，"
                     "再按各自的命中数判断哪个是真的"),
        }

    cap = max(1, min(int(max_calls), 5000))
    maxc = max(1, min(int(max_classes), 200))
    cfg = capture if isinstance(capture, dict) else {}
    want_args = bool(cfg.get("args", True))
    want_ret = bool(cfg.get("ret", True))
    arg_fields = cfg.get("arg_fields") or []
    if not isinstance(arg_fields, list):
        arg_fields = []
    expand_map = bool(cfg.get("expand_map", True))

    user_js = _JS_HELPERS + _JS_JAVA_HOOK_MULTI
    user_js = (user_js
               .replace("__CLASS_NAME__", _js_str(class_name or ""))
               .replace("__METHOD__", _js_str(method or ""))
               .replace("__OVERLOAD__", _js_str(overload or ""))
               .replace("__PATTERN__", _js_str(pattern or ""))
               .replace("__PACKAGE__", _js_str(package or ""))
               .replace("__MAX_CLASSES__", str(maxc))
               .replace("__MAX_CALLS__", str(cap))
               .replace("__INCLUDE_STACK__", "true" if include_stack else "false")
               .replace("__STACK_DEPTH__", str(max(1, min(int(stack_depth or 8), 32))))
               .replace("__WANT_ARGS__", "true" if want_args else "false")
               .replace("__WANT_RET__", "true" if want_ret else "false")
               .replace("__ARG_FIELDS__", _js_str_list(arg_fields))
               .replace("__EXPAND_MAP__", "true" if expand_map else "false")
               .replace("__SIBLING_PROBE__", "true" if sibling_probe else "false"))

    return _run_java_hook(serial, pid, user_js, duration=float(duration))


# 批量 hook 的 JS 模板。占位符统一用 __XXX__，避免与 JS 里的字面量冲突。
_JS_JAVA_HOOK_MULTI = r"""
Java.perform(function () {
    var CLASS_NAME = __CLASS_NAME__;
    var METHOD = __METHOD__;
    var OVERLOAD = __OVERLOAD__;
    var PATTERN = __PATTERN__;
    var PACKAGE = __PACKAGE__;
    var MAX_CLASSES = __MAX_CLASSES__;
    var MAX_CALLS = __MAX_CALLS__;
    var INCLUDE_STACK = __INCLUDE_STACK__;
    var STACK_DEPTH = __STACK_DEPTH__;
    var WANT_ARGS = __WANT_ARGS__;
    var WANT_RET = __WANT_RET__;
    var ARG_FIELDS = __ARG_FIELDS__;
    var EXPAND_MAP = __EXPAND_MAP__;
    var SIBLING_PROBE = __SIBLING_PROBE__;

    // 这些包里的方法 hook 后容易让目标崩，注入前就排除
    var SKIP_PREFIX = ['java.lang.', 'java.lang.reflect.', 'dalvik.', 'sun.', 'libcore.'];
    function shouldSkip(name) {
        for (var i = 0; i < SKIP_PREFIX.length; i++) {
            if (name.indexOf(SKIP_PREFIX[i]) === 0) { return true; }
        }
        return false;
    }

    // (11) 第十一次修改（2026-11-06）：与 java_find_classes 同一处回归的修复。
    //     bug 原因：同样的"转义 + 全匹配"写法，导致 pattern="Security" 这类
    //              不带 * 的写法永远匹配不到（被锚成 ^Security$）。
    //     解决方案：makeRe 智能判断（正则优先，通配符兜底），并用 anchor
    //              参数区分两种语义：
    //                · 类名 pattern  → **不锚定**，子串搜（Security 能匹配
    //                  com.xxx.SecurityFoo）
    //                · 方法名 method  → **锚定**，精确或通配（sendMessage 只
    //                  匹配 sendMessage，不会把 sendMessageDelayed 也挂上）
    // 判定规则同 java_find_classes：含 * 或 ? 且不含正则专属符号 → 通配符，
    // 否则按正则。不能用"能不能编译"判断，因为 convert* 是合法正则。
    function makeRe(p, label, anchor) {
        if (!p) { return null; }
        var a = anchor ? '^' : '', z = anchor ? '$' : '';
        var isWild = /[*?]/.test(p) && !/[\\|\[\](){}^$]/.test(p);
        if (isWild) {
            var esc = p.replace(/[.+${}()|[\]]/g, '\\$&');
            esc = esc.replace(/\*/g, '.*').replace(/\?/g, '.');
            try { return new RegExp(a + esc + z, 'i'); }
            catch (e) { throw new Error(label + ' 通配符转换失败：' + p); }
        }
        try { return new RegExp(a + p + z, 'i'); }
        catch (e) {
            throw new Error(label + ' 不是合法正则：' + p
                            + '（若想用通配符请写 convert* 这种形式）');
        }
    }

    // Map / List / 数组 展开成可读结构（P1-1）
    function mdaExpand(v) {
        if (v === null || v === undefined) { return null; }
        try {
            if (!EXPAND_MAP) { return mdaDescribe(v); }
            var cn = v.getClass().getName();
            if (cn.indexOf('java.util.') === 0 && v.entrySet !== undefined) {
                var out = {};
                var it = v.entrySet().iterator();
                var n = 0;
                while (it.hasNext() && n < 50) {
                    var e = it.next();
                    out[String(e.getKey())] = mdaDescribe(e.getValue());
                    n++;
                }
                return {__type: cn, entries: out};
            }
            if (cn.indexOf('java.util.') === 0 && v.toArray !== undefined) {
                var arr = v.toArray();
                var a = [];
                for (var i = 0; i < arr.length && i < 50; i++) {
                    a.push(mdaDescribe(arr[i]));
                }
                return {__type: cn, items: a};
            }
        } catch (e) {}
        return mdaDescribe(v);
    }

    // 从参数对象里按字段名取值（P1-1）
    function mdaFields(obj, fields) {
        if (!obj || !fields || fields.length === 0) { return null; }
        var out = {};
        for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            try {
                var v = obj[f];
                if (typeof v === 'function') { v = v.call(obj); }   // getter
                out[f] = mdaExpand(v);
            } catch (e) {
                try {
                    var v2 = obj[f + '()'];
                    out[f] = (typeof v2 === 'function') ? mdaExpand(v2.call(obj)) : null;
                } catch (e2) { out[f] = null; }
            }
        }
        return out;
    }

    // ① 选出候选类
    var candidates = [];
    if (CLASS_NAME) {
        candidates.push(CLASS_NAME);
    } else {
        var all;
        try { all = Java.enumerateLoadedClassesSync(); }
        catch (e) { send({kind: 'hook_error', error: '无法枚举类：' + e}); return; }
        var re;
        var methRe;
        try {
            re = makeRe(PATTERN, 'pattern', false);      // 类名：子串
            methRe = makeRe(METHOD, 'method', true);     // 方法名：精确/通配
        } catch (e) {
            send({kind: 'hook_error', code: 'BAD_PATTERN', error: String(e)});
            return;
        }
        for (var i = 0; i < all.length && candidates.length < MAX_CLASSES; i++) {
            var nm = all[i];
            if (shouldSkip(nm)) { continue; }
            if (PACKAGE && nm.indexOf(PACKAGE) !== 0) { continue; }
            if (re && !re.test(nm)) { continue; }
            candidates.push(nm);
        }
    }

    if (candidates.length === 0) {
        send({kind: 'hook_error', code: 'NO_CLASS_MATCHED',
              error: '没有类匹配 pattern=' + PATTERN + ' package=' + PACKAGE,
              hint: '用 java_find_classes 先确认类是否已加载'});
        return;
    }

    var result = {classes: [], total_hits: 0};
    var siblingHits = {};      // 用于 0 命中时的旁证

    // ② 逐个类 hook
    for (var ci = 0; ci < candidates.length; ci++) {
        var cname = candidates[ci];
        var entry = {class: cname, hooked_methods: [], call_count: 0, calls: []};
        var jc = null;
        try { jc = Java.use(cname); } catch (e) {
            entry.error = 'Java.use 失败: ' + String(e).slice(0, 120);
            result.classes.push(entry);
            continue;
        }
        // 记录继承关系：诊断时用来建议"试试父类"
        try {
            var sup = jc.class.getSuperclass();
            entry.subclass_of = sup === null ? null : String(sup.getName());
        } catch (e) {}

        var seen = {};
        var methods = [];
        try {
            var ms = jc.class.getDeclaredMethods();
            for (var k = 0; k < ms.length; k++) {
                var mn = String(ms[k].getName());
                if (mn === 'finalize' || mn === 'wait' || mn === 'notify' ||
                    mn === 'equals' || mn === 'hashCode' || mn === 'toString') { continue; }
                if (methRe && !methRe.test(mn)) { continue; }
                if (seen[mn]) { continue; }
                seen[mn] = true;
                methods.push(mn);
            }
        } catch (e) { entry.error = '列方法失败: ' + String(e).slice(0, 120); }

        for (var mi = 0; mi < methods.length; mi++) {
            var mname = methods[mi];
            try {
                var target = jc[mname];
                if (target === undefined || target.overloads === undefined) { continue; }
                var ovs = target.overloads;
                for (var oi = 0; oi < ovs.length; oi++) {
                    (function (ovObj, sig, cls, mnm) {
                        ovObj.implementation = function () {
                            result.total_hits++;
                            entry.call_count++;
                            if (entry.calls.length >= MAX_CALLS) { entry.truncated = true; }
                            else {
                                var rec = {method: mnm, overload: sig,
                                           ts: Date.now() / 1000, args: [],
                                           arg_fields: null};
                                if (WANT_ARGS) {
                                    for (var a = 0; a < arguments.length; a++) {
                                        rec.args.push(mdaDescribe(arguments[a]));
                                    }
                                    // 对第一个"像对象"的参数做字段深挖
                                    if (ARG_FIELDS.length > 0) {
                                        for (var a2 = 0; a2 < arguments.length; a2++) {
                                            var fv = mdaFields(arguments[a2], ARG_FIELDS);
                                            if (fv) { rec.arg_fields = fv; break; }
                                        }
                                    }
                                }
                                if (INCLUDE_STACK) { rec.stack = mdaJavaStack(STACK_DEPTH); }
                                var ret;
                                try {
                                    ret = ovObj.apply(this, arguments);
                                    if (WANT_RET) { rec.ret = mdaExpand(ret); }
                                } catch (e) {
                                    rec.threw = String(e).slice(0, 200);
                                    entry.calls.push(rec);
                                    throw e;
                                }
                                entry.calls.push(rec);
                                return ret;
                            }
                            return ovObj.apply(this, arguments);
                        };
                        // (13) 第十三次修改（2026-11-06）：修正签名拼接。
                        //     bug 原因：原来写成 mnm + sig，而 sig 本身已是
                        //              "function execute(java.lang.Runnable): void"
                        //              这种完整签名，拼出来变成
                        //              "executefunction execute(...)"，方法名重复且粘连。
                        //     解决方案：直接用 sig（它已包含方法名），仅在
                        //              没有签名文本时退回 mnm。
                        entry.hooked_methods.push(sig || mnm);
                    })(ovs[oi], String(ovs[oi]), jc, mname);
                }
            } catch (e) {
                // 单个方法 hook 失败不影响其他方法
                if (!entry.hook_errors) { entry.hook_errors = []; }
                if (entry.hook_errors.length < 10) {
                    entry.hook_errors.push(mname + ': ' + String(e).slice(0, 100));
                }
            }
        }
        // 记录该方法名在类里存不存在（P0-3 诊断用）
        entry.method_exists = entry.hooked_methods.length > 0;

        // ③ 兄弟方法探测：0 命中时看同类其他方法有没有被调
        if (SIBLING_PROBE && entry.hooked_methods.length === 0 && METHOD) {
            try {
                var allms = jc.class.getDeclaredMethods();
                var names = {};
                for (var q = 0; q < allms.length; q++) {
                    var n2 = String(allms[q].getName());
                    if (n2 === 'finalize' || n2 === '<init>' || n2 === '<clinit>') { continue; }
                    names[n2] = true;
                }
                var probed = 0;
                for (var nmKey in names) {
                    if (probed >= 8) { break; }
                    if (methRe && methRe.test(nmKey)) { continue; }   // 已 hook 过
                    try {
                        var tgt = jc[nmKey];
                        if (tgt === undefined || tgt.overloads === undefined) { continue; }
                        var ov2 = tgt.overloads[0];
                        (function (o2, key, cn2) {
                            o2.implementation = function () {
                                var k2 = cn2 + '.' + key;
                                siblingHits[k2] = (siblingHits[k2] || 0) + 1;
                                return o2.apply(this, arguments);
                            };
                        })(ov2, nmKey, cname);
                        probed++;
                    } catch (e2) {}
                }
            } catch (e3) {}
        }

        result.classes.push(entry);
    }

    send({kind: 'ready', class_count: result.classes.length,
          classes: result.classes.map(function (c) {
              return {class: c.class, hooked: c.hooked_methods.length,
                      subclass_of: c.subclass_of || null,
                      method_exists: !!c.method_exists,
                      error: c.error || null};
          })});

    recv('stop', function () {
        result.sibling_hits = siblingHits;
        send({kind: 'result', data: result});
    });
});
"""


def java_find_callers(serial: str, pid: int, class_name: str, method: str,
                      overload: str = "", duration: float = 8.0,
                      max_samples: int = 30, stack_depth: int = 12) -> dict:
    """找出**谁调用了**某个 Java 方法，返回调用栈样本。

    (6) 第六次修改（2026-11-06）：新增（对应 P0-2）。

    为什么需要它：`java_hook` 只能回答"这个方法有没有被调用"。当答案是
    "没被调用"时，下一步该问的是**"那到底谁在干活"**——可能是父类、
    兄弟方法、或者完全另一个类。追调用栈比逐个猜快得多。

    ## 与 java_hook 的分工

        java_hook         看"这个方法被调时参数/返回值是什么"
        java_find_callers 看"这个方法**被谁**调用"（只关心调用链，不抓参数）

    ## 返回

        callers[]     按次数降序：{frame, hits}
                      frame 是"类.方法(文件:行)"形式的上层帧
        samples[]     原始调用栈样本（最多 max_samples 条）
        call_count    总调用次数
        verdict

    ## 实测（写调用链分析的典型用法）

        java_find_callers("mtopsdk...ANetworkConverter", "convertRequest")
        → callers: [{"frame": "mtopsdk.mtop...HttpCallImpl.execute", "hits": 12}, ...]
        这样能把 mtopsdk → anetwork → tnet 的链路串起来

    ## 已知边界

        · 只抓**Java 层**栈；native 调用者看不到（要配合 trace_call_tree）
        · 栈帧按"类.方法(文件:行)"归并，行号相同才算同一处——同一方法的
          不同调用点会被分开统计，这是刻意的（能看出具体哪个分支）
    """
    if not str(class_name or "").strip() or not str(method or "").strip():
        return {"ok": False, "implemented": True, "code": "NEED_TARGET",
                "error": "必须给 class_name 和 method"}

    cap = max(1, min(int(max_samples), 200))
    user_js = _JS_HELPERS + """
    Java.perform(function () {
        var SIZE = 0, samples = [], callers = {}, total = 0;
        try {
            var cls = Java.use(CLASS);
            var target = cls[METHOD];
            if (target === undefined) {
                send({kind: 'hook_error', code: 'METHOD_NOT_FOUND',
                      error: '类里没有名为 ' + METHOD + ' 的方法'});
                return;
            }
            var ovs = target.overloads || [];
            var wanted = OVERLOAD;
            var hookedN = 0;
            for (var i = 0; i < ovs.length; i++) {
                if (wanted && String(ovs[i]) !== wanted) { continue; }
                (function (ov, sig) {
                    ov.implementation = function () {
                        total++;
                        try {
                            var frames = mdaJavaStack(DEPTH);
                            // (9) 第九次修改（2026-11-06）：跳过取栈自身的帧。
                            //     bug 原因：实测调用者被识别成
                            //               "java.lang.Thread.getStackTrace(Thread.java:1724)"——
                            //               因为 getStackTrace 是我们**自己调**的，
                            //               它就在栈顶，把真正的调用者挤到了后面。
                            //               这会让 callers 列表完全失真（全是同一个"调用者"）。
                            //     解决方案：从栈里跳过连续出现的
                            //               Thread.getStackTrace / mdaJavaStack 帧，
                            //               再跳过本方法自身的帧，第一个剩下的才是真调用者。
                            // 取栈链路会连续出现好几帧（Thread.getStackTrace ->
                            // VMStack.getThreadStackTrace -> ...），必须全部跳过。
                            // 用"前缀匹配 + 从栈顶连续跳过"两个条件，避免误杀
                            // 真正业务代码里偶尔出现的方法名。
                            var skipRe = /^(java\.lang\.Thread\.getStackTrace|dalvik\.system\.VMStack|dalvik\.system\.VMDebug|java\.lang\.Throwable\.)/;
                            var caller = '<无上层帧>';
                            var selfName = METHOD;
                            for (var fi = 0; fi < frames.length; fi++) {
                                var fr = frames[fi];
                                if (skipRe.test(fr)) { continue; }
                                // 本方法自身的帧（名字以 METHOD 开头的那条）
                                if (fr.indexOf(selfName + '(') >= 0 ||
                                    fr.indexOf('.' + selfName + '(') >= 0) { continue; }
                                caller = fr;
                                break;
                            }
                            callers[caller] = (callers[caller] || 0) + 1;
                            if (samples.length < SAMPLES) { samples.push(frames); }
                        } catch (e) {}
                        return ov.apply(this, arguments);
                    };
                    hookedN++;
                })(ovs[i], String(ovs[i]));
            }
            if (hookedN === 0) {
                send({kind: 'hook_error', code: 'OVERLOAD_NOT_FOUND',
                      error: '没有匹配的重载（wanted=' + wanted + '）'});
                return;
            }
            send({kind: 'ready', hooked: hookedN});
        } catch (e) {
            send({kind: 'hook_error', code: 'CLASS_NOT_LOADED',
                  error: String(e).slice(0, 200),
                  hint: '类可能还没加载；用 java_find_classes 确认'});
            return;
        }
        recv('stop', function () {
            var list = [];
            for (var k in callers) { list.push({frame: k, hits: callers[k]}); }
            list.sort(function (a, b) { return b.hits - a.hits; });
            send({kind: 'result', callers: list, samples: samples, total: total});
        });
    });
    """.replace("CLASS", _js_str(class_name)).replace(
        "METHOD", _js_str(method)).replace("OVERLOAD", _js_str(overload or "")).replace(
        "DEPTH", str(max(2, min(int(stack_depth or 12), 32)))).replace(
        "SAMPLES", str(cap))

    return _run_java_callers(serial, pid, user_js, duration=float(duration),
                             class_name=class_name, method=method)


# ---------------- 内部辅助 ----------------


def _js_str(s: str) -> str:
    """把 Python 字符串转成 JS 字符串字面量（转义引号与反斜杠）。"""
    import json as _json

    return _json.dumps(str(s or ""))


def _js_str_list(items) -> str:
    """把 Python 字符串列表转成 JS 数组字面量。

    (4) 第四次修改（2026-11-06）：新增。
        用于把 capture.arg_fields 安全地内插进 JS——直接拼 f-string 会
        在字段名含引号时破坏语法，走 json 序列化最稳。
    """
    import json as _json

    seq = [str(x) for x in (items or [])]
    return _json.dumps(seq)


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
        # (4) 第四次修改（2026-11-06）：异常时补进程活性探测。
        #     bug 原因：死进程只抛 ProcessNotFoundError，调用方看不出
        #               "是进程没了"还是"Java bridge 有问题"——与 probe_hits
        #               当初踩的坑完全一样。
        #     解决方案：调 adb 层的 probe_process_alive，把三条证据带回去。
        probe = None
        try:
            from dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception:                                 # noqa: BLE001
            probe = None
        msg = f"{type(exc).__name__}: {exc}"
        code = "JAVA_CALL_FAILED"
        if probe and probe.get("alive") is False:
            code = "TARGET_DIED"
            msg += f"；并且进程 {pid} 在内核里已不存在（已退出/闪退）"
        elif probe and probe.get("injectable") is False:
            msg += f"；进程 {pid} 仍存在但已不可注入"
        return {}, {"ok": False, "implemented": True, "code": code,
                    "error": msg, "process_probe": probe}
    finally:
        _detach_async(sess)


def _run_java_callers(serial: str, pid: int, user_js: str,
                      duration: float = 8.0, class_name: str = "",
                      method: str = "") -> dict:
    """java_find_callers 的执行器（结果结构与 hook 不同，单独解析）。"""
    import time as _time

    try:
        import frida
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_find_callers", f"frida 不可用：{exc}")

    try:
        full = wrap_with_java_bridge(user_js)
    except JavaBridgeError as exc:
        return _java_pending("java_find_callers", str(exc), {"code_detail": exc.code})

    sess = None
    try:
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(full)
        box: dict = {"ready": False, "done": False, "data": None}

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["_err"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                return
            if kind == "result":
                box["done"] = True
                box["data"] = payload
                return
            if kind in ("hook_error", "bridge_error"):
                box["_err"] = payload.get("error") or "hook 失败"
                box["_err_code"] = payload.get("code") or ""
                box["_err_hint"] = payload.get("hint") or ""
                return

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box.get("_err") and _time.time() - t0 < 25.0:
            _time.sleep(0.02)
        if box.get("_err"):
            out = {"ok": False, "implemented": True,
                   "code": box.get("_err_code") or "CALLERS_FAILED",
                   "error": str(box["_err"])[:400]}
            if box.get("_err_hint"):
                out["hint"] = box["_err_hint"]
            return out
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "hook 25 秒内未就位"}
        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(60):
            if box["done"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "implemented": True, "code": "CALLERS_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)

    d = box.get("data") or {}
    callers = d.get("callers") or []
    total = int(d.get("total") or 0)
    if total == 0:
        verdict = (f"{duration:g}s 内该方法**一次都没被调用**，"
                   "所以没有调用者。先确认这个方法在当前操作下会不会走到")
    else:
        top = callers[0] if callers else None
        verdict = (f"共被调用 {total} 次"
                   + (f"，最直接的调用者是 {top['frame']}（{top['hits']} 次）"
                      if top else ""))
    return {
        "ok": True,
        "implemented": True,
        "class_name": class_name,
        "method": method,
        "call_count": total,
        "callers": callers,
        "samples": d.get("samples") or [],
        "duration": duration,
        "verdict": verdict,
    }


def _run_java_hook(serial: str, pid: int, user_js: str,
                   duration: float = 5.0) -> dict:
    """hook 类脚本的执行器：等 ready → 采集 duration → post stop → 收 result。

    (5) 第五次修改（2026-11-06）：适配批量 hook 的新返回结构。
        bug 原因：原执行器按"单类单方法"解析结果（顶层 hooked/calls），
                  批量模式下结果是 {classes: [...], sibling_hits: {...}}，
                  旧解析会把所有数据丢掉，返回空。
        解决方案：按新结构解析，并在这里统一生成 diagnosis——
                  这是调用方最需要的部分（P0-3），放在上层比放 JS 里好维护。
    """
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
        box: dict = {"ready": False, "done": False, "info": None, "data": None}

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["_err"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
                box["info"] = payload
                return
            if kind == "result":
                box["done"] = True
                box["data"] = payload.get("data") or {}
                return
            if kind in ("hook_error", "bridge_error"):
                box["_err"] = payload.get("error") or payload.get("message") or "hook 失败"
                box["_err_code"] = payload.get("code") or ""
                box["_err_hint"] = payload.get("hint") or ""
                return

        script.on("message", _on_msg)
        script.load()

        t0 = _time.time()
        while not box["ready"] and not box.get("_err") and _time.time() - t0 < 25.0:
            _time.sleep(0.02)
        if box.get("_err"):
            out = {"ok": False, "implemented": True,
                   "code": box.get("_err_code") or "JAVA_HOOK_FAILED",
                   "error": str(box["_err"])[:400]}
            if box.get("_err_hint"):
                out["hint"] = box["_err_hint"]
            return out
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "hook 25 秒内未就位",
                    "hint": ("目标是加固 app 时可能阻断 Java.perform；"
                             "先用 java_bridge_status 确认 bridge 可用，"
                             "再用 java_find_classes 确认类已加载")}

        _time.sleep(max(0.1, float(duration)))
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(60):
            if box["done"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        probe = None
        try:
            from dyn.adb import Adb

            probe = Adb(serial).probe_process_alive(int(pid))
        except Exception:                                 # noqa: BLE001
            probe = None
        msg = f"{type(exc).__name__}: {exc}"
        code = "JAVA_HOOK_FAILED"
        if probe and probe.get("alive") is False:
            code = "TARGET_DIED"
            msg += f"；并且进程 {pid} 在内核里已不存在（已退出/闪退）"
        return {"ok": False, "implemented": True, "code": code,
                "error": msg, "process_probe": probe}
    finally:
        _detach_async(sess)

    data = box.get("data") or {}
    classes = data.get("classes") or []
    total = int(data.get("total_hits") or 0)

    # 汇总每个类的命中数，按命中降序——直接回答"哪个类真的被调用了"
    summary = sorted(
        ({"class": c.get("class"),
          "call_count": int(c.get("call_count") or 0),
          "hooked_methods": len(c.get("hooked_methods") or []),
          "method_exists": bool(c.get("method_exists")),
          "subclass_of": c.get("subclass_of")}
         for c in classes),
        key=lambda x: -x["call_count"])

    out = {
        "ok": True,
        "implemented": True,
        "class_count": len(classes),
        "classes": summary,
        "details": classes,
        "call_count": total,
        "duration": duration,
        "sibling_hits": data.get("sibling_hits") or {},
    }

    # (12) 第十二次修改（2026-11-06）：单类时补回顶层 hooked / calls。
    #      bug 原因：把 java_hook 改成批量之后，返回结构变成 classes[] 嵌套，
    #                顶层的 hooked 与 calls **被去掉了**。只 hook 一个类的
    #                场景下，调用方读 r["hooked"] 会拿到 None（不是报错，
    #                所以更隐蔽），旧脚本与旧文档的用法都会失效。
    #      解决方案：class_count == 1 时在顶层补一份 hooked / calls，
    #                与批量结构的 classes[0] 内容一致；多类时不补
    #                （那时顶层放哪一份都会误导）。
    if len(classes) == 1:
        only = classes[0]
        out["hooked"] = only.get("hooked_methods") or []
        out["calls"] = only.get("calls") or []
        out["truncated"] = bool(only.get("truncated"))

    # ---- P0-3：0 命中时给诊断，而不是只说"没被调用" ----
    if total == 0:
        diag: dict = {}
        loaded = [c for c in classes if not c.get("error")]
        diag["class_loaded"] = bool(loaded)
        diag["class_count"] = len(loaded)
        diag["method_exists"] = any(c.get("method_exists") for c in loaded)
        sib = data.get("sibling_hits") or {}
        if sib:
            diag["sibling_methods_called"] = [
                {"method": k, "hits": v}
                for k, v in sorted(sib.items(), key=lambda kv: -kv[1])[:8]]
        else:
            diag["sibling_methods_called"] = []
        # 从继承链给建议：本类没命中时，父类往往是真正干活的地方
        parents = [c.get("subclass_of") for c in loaded if c.get("subclass_of")]
        sug = []
        if diag["method_exists"]:
            sug.append("方法存在但零调用：该路径在当前操作下没被走到，"
                       "先触发对应功能（如发一次请求）再重试")
        else:
            sug.append("类里没有匹配的方法：检查方法名，或用通配符 method='*' 看全部")
        if parents:
            sug.append(f"可试父类：{parents[0]}")
        if diag["sibling_methods_called"]:
            top = diag["sibling_methods_called"][0]
            sug.append(f"同类里 {top['method']} 被调了 {top['hits']} 次——"
                       "真正干活的很可能是它")
        diag["suggestion"] = "；".join(sug)
        out["diagnosis"] = diag
        out["verdict"] = (f"{len(classes)} 个类已 hook，但 {duration:g}s 内 **0 次调用**"
                          + ("（方法存在）" if diag["method_exists"] else "（方法不存在）"))
    else:
        top = summary[0]
        out["verdict"] = (f"{len(classes)} 个类中 {sum(1 for s in summary if s['call_count'])} 个被调用，"
                          f"共 {total} 次；最热的是 {top['class']}（{top['call_count']} 次）")
    return out
