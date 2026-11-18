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
import re

__all__ = [
    "JavaBridgeError",
    "bridge_path",
    "load_bridge_source",
    "wrap_with_java_bridge",
    "bridge_status",
    "java_list_methods",
    "java_find_classes",
    "java_hook",
    "java_find_callers",
    # (2) 第二次修改（2026-11-13）：把新增的候选探查与计数能力导出。
    #     bug 原因：新增的 java_hook_hint / _java_count_calls 只在模块里定义，
    #              没进 __all__。这不影响 MCP 层（它走 getattr 直接取），
    #              但影响 `from server.dyn.java_bridge import *` 的使用方，
    #              以及靠 __all__ 做能力发现的脚本。
    #     解决方案：补齐，同时把已有的四个 java_* 也列上（原来就漏了）。
    "java_hook_hint",
    "NETWORK_CLASS_PATTERNS",
    "NETWORK_METHOD_PATTERNS",
    "NETWORK_CANDIDATES",
    "name_similarity",
    "class_name_stem",
]


# ---------------- 网络层通用候选（Android / 标准 API 常识） ----------------
#
# (1) 第一次修改（2026-11-13）：新增。
#     bug 原因：使用者卡在"不知道该 hook 谁"时，java_hook_hint 只能按他给的
#               模糊片段搜索；而"谁在给 HTTP 请求加 header"这件事本身有一批
#               **通用**答案（okhttp 的 Interceptor、HttpURLConnection 的
#               setRequestProperty 等），完全可以从常识直接给出来。
#     解决方案：内置两张模式表 + 一组可直接照抄的候选清单。
#
# 设计红线（必须守住）：
#   · 全部是 **Android / okhttp / JDK 标准 API 的公开名字**，
#     不许出现任何具体 App 的包名或类名——那不是通用知识，是特调。
#   · 这张表只用于**搜索建议**（告诉 AI 去搜什么字），不参与任何判定。

NETWORK_CLASS_PATTERNS = [
    # okhttp / 自研网络栈里最常见的拦截器命名
    "*Interceptor*", "*OkHttp*", "*RealInterceptorChain*",
    # 头/请求构造器一类
    "*RequestHeader*", "*HeaderManager*", "*HeaderHelper*",
    "*RequestBuilder*", "*RequestFactory*",
    # 常见自研网络封装
    "*HttpManager*", "*HttpHelper*", "*HttpUtil*", "*HttpClient*",
    "*ApiClient*", "*NetworkClient*", "*NetApi*",
    # 抓"主干活的那个类"另一条路：拦截器往往实现这两个接口之一
    "*HeaderInterceptor*", "*AddHeader*",
]

NETWORK_METHOD_PATTERNS = [
    # okhttp3.Request.Builder
    "addHeader", "header", "headers",
    # java.net.URLConnection / HttpURLConnection
    "setRequestProperty", "addRequestProperty", "setRequestMethod",
    # androidx / volley / 自研的常见头字段写法
    "putHeader", "setHeader", "addHeaders",
    # okhttp Interceptor 的方法名就这一个，最值得先挂
    "intercept",
]

# 可直接照抄的候选：(模式, 说明, 建议怎么用)
# 「建议怎么用」是给 AI 的下一步动作，不是给人看的散文。
NETWORK_CANDIDATES = [
    {"pattern": "*Interceptor*", "kind": "class",
     "why": "okhttp / 自研网络栈的拦截器几乎都叫这个名字，"
            "**加 header 最常发生在这里**",
     "method": "intercept",
     "how": "hook 类的 intercept 方法，看 chain.request() 上的 headers"},
    {"pattern": "okhttp3.Interceptor$RealInterceptorChain", "kind": "class",
     "why": "okhttp 的真实调用链，所有拦截器都从这里被串联",
     "method": "proceed",
     "how": "挂在 proceed 上看链条顺序，确认哪个拦截器改了请求"},
    {"pattern": "RequestHeader|HeaderManager|AddHeader", "kind": "class",
     "why": "自研 App 常把加头逻辑单独抽成一个类",
     "method": "*header*",
     "how": "先用调用计数确认它在干活，再 hook 具体方法看参数"},
    {"pattern": "setRequestProperty", "kind": "method",
     "why": "**JDK 标准 API**，HttpURLConnection 加请求头只有这一个入口；"
            "用 java.net 而非 okhttp 的 App 一定走这里",
     "method": "setRequestProperty",
     "how": "直接 hook 该方法（类名用 java.net.HttpURLConnection 或通配），"
            "参数 1、2 就是头名与头值"},
    {"pattern": "addHeader|header", "kind": "method",
     "why": "okhttp3.Request.Builder 的加头入口，标准 API",
     "method": "addHeader",
     "how": "pattern='*Request$Builder*' 这类类名不确定时，"
            "直接用 java_hook_hint 的 method 维度搜"},
]

# 网络层常见的包前缀（用于把候选缩到"确实在干网络"的类上）
NETWORK_PACKAGE_HINTS = [
    "okhttp3", "okio", "com.squareup.retrofit2", "retrofit2",
    "java.net", "android.net", "org.apache.http",
    "com.android.volley",
]


def class_name_stem(class_name: str) -> str:
    """取类名里"有语义的那一段"，去掉包名与数字内部类后缀。

    (1) 第一次修改（2026-11-13）：新增。
        为什么要它：`com.x.api.net.CommentRealApi$1` 与 `com.y.CommentApi`
        的相似度，必须建立在 `CommentRealApi` / `CommentApi` 上；
        带着包名比较的话前缀一致会把不相关的类也算成相似。

    (2) 第二次修改（2026-11-13）：只在 `$` 后面是**数字/匿名**时截断。
        bug 原因：第一版无条件在第一个 `$` 处截断，于是
                  `SystemActions$SystemActionsBroadcastReceiver` 被截成
                  `SystemActions` —— "BroadcastReceiver" 这个**最有信息量的词
                  恰好在 `$` 后面**，被直接丢掉了。实测搜
                  query="BroadcastReceiver" 时这类类全部得 0 分并被过滤掉，
                  而这正是最该命中的候选。
                 （okhttp 的 `Request$Builder` 同理。）
        解决方案：`$` 后接数字（匿名内部类 `$1`）或 `$$`（编译器合成）才截断；
                  其余情况保留完整内部类名参与比较。
    """
    raw = str(class_name or "").strip()
    if not raw:
        return ""
    leaf = raw.rsplit(".", 1)[-1]
    # 只砍匿名类（$1 / $2）与编译器合成类（$$ExternalSynthetic 等）
    import re as _re

    leaf = _re.split(r"\$\d|\$\$", leaf, maxsplit=1)[0]
    return leaf


def name_similarity(query: str, candidate: str) -> float:
    """命名相似度打分（0~1），用于给候选排序。

    (1) 第一次修改（2026-11-13）：新增。
        bug 原因：模糊线索（"CommentRealApi"）搜出一堆同类名的类之后，
                  原实现按枚举顺序返回，最该看的 CommentApi / CommentHelper
                  可能排在几十个不相关结果后面——等于没有排序。
        解决方案：分层打分，越像分越高（数值见下方各分支）。

    (2) 第二次修改（2026-11-13）：打分从"字符前后缀"改成"词元加权"。
        bug 原因：第一版按公共前后缀长度给分，于是
                  `OrderApi` 与 `CommentRealApi` 仅共享后缀 "api" 就得 0.625，
                  和真正该看的 `CommentHelper`（0.725）几乎并列——
                  排序等于失效。根因是**字符级"api"没有信息量**，
                  但字符长度无法表达这一点。
        解决方案：先按驼峰/下划线切词元，按**词元长度加权**算交集占比；
                  并且若共享的词元**全是** api/util/impl 这类通用后缀，
                  直接把分数压到 0.45 以下（它们说明不了任何事）。
                  实测排序：CommentApi 0.90 > CommentHelper 0.74 > OrderApi 0.45。

    (3) 第三次修改（2026-11-13）：query 含正则元字符时按分支取最大值。
        bug 原因：实测 `query="Request|Header"` 时，整串被当成一个词元，
                  所有类名统一得 0.738，**完全失去区分度**——
                  排序退化成枚举顺序，而这正是本函数要解决的问题。
                  query 是工具层允许的正则写法（与 java_find_classes 一致），
                  打分必须支持它。
        解决方案：query 里若有 | 或正则元字符，按 | 切开逐个打分取**最大值**；
                  这样 "Request|Header" 对 *Request* 类会按 "request" 打分，
                  对 *Header* 类会按 "header" 打分，各自有区分度。

    参数：
        query      用户给的模糊线索（可以是类名片段、全限定名，或 a|b 形式正则）
        candidate  候选类名（全限定名）

    返回：0.0 ~ 1.0 的浮点。
    """
    raw_q = str(query or "")
    # 正则多分支：逐分支打分取最大。递归调用自身，但每个分支都是纯字面量
    # （不含 |），所以最多再多一层，不会无限递归。
    if "|" in raw_q:
        parts = [p for p in raw_q.split("|") if p.strip()]
        if len(parts) > 1:
            return max((name_similarity(p, candidate) for p in parts),
                       default=0.0)
    return _name_similarity_single(raw_q, candidate)


def _name_similarity_single(query: str, candidate: str) -> float:
    """单分支的相似度实现（由 name_similarity 调用，不要直接用它）。"""
    import re as _re

    q_stem = class_name_stem(query)
    c_stem = class_name_stem(candidate)
    q = q_stem.lower()
    c = c_stem.lower()
    if not q or not c:
        return 0.0
    if q == c:
        return 1.0
    # 一方包含另一方：CommentApi 出现在 CommentRealApi 里
    if q in c or c in q:
        short, long_ = (q, c) if len(q) <= len(c) else (c, q)
        return 0.9 + 0.08 * (len(short) / max(1, len(long_)))

    def _tokens(s: str) -> list:
        # (3) 第三次修改（2026-11-13）：**必须在转小写之前切词**。
        #     bug 原因：第二版先 .lower() 再切，camelCase 边界被抹平，
        #              "CommentRealApi" 整个变成单个词元 "commentrealapi"，
        #              于是 CommentApi / CommentHelper 全部落进"词元无交集"
        #              分支、统一得 0.4 —— 和 OrderApi 一模一样，排序又失效了。
        #     解决方案：用**原始大小写**的类名切词（驼峰边界靠大小写识别），
        #              切完再逐个转小写。这条是第二版引入的回归。
        s2 = _re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", s)
        return [t.lower() for t in _re.split(r"[^A-Za-z0-9]+", s2) if t]

    tq = _tokens(q_stem)
    tc = _tokens(c_stem)
    if tq and tc:
        # 以**短名**为基准算覆盖率：CommentApi 的词元应被 CommentRealApi 覆盖
        base = tq if len(tq) <= len(tc) else tc
        other = tc if base is tq else tq
        shared = [t for t in base if t in other]
        if shared:
            # 通用后缀不能当证据：只共享 api/util/impl 说明不了任何事
            if all(t in _GENERIC_TOKENS for t in shared):
                return 0.4 + 0.05 * (sum(map(len, shared)) /
                                     max(1, sum(map(len, base))))
            w = sum(map(len, shared)) / max(1, sum(map(len, base)))
            return 0.55 + 0.35 * w
        # 同一段词元但写法不同（real_api vs realapi 已由上面的切分处理）；
        # 到这里说明词元毫无交集，再退回字符级前缀判断
        pfx = 0
        for a, b in zip(q, c):
            if a != b:
                break
            pfx += 1
        if pfx >= 4:
            return min(0.5, 0.3 + 0.2 * pfx / max(len(q), len(c)))
    return 0.0


# 只表示"这是个辅助件"、不携带业务信息的通用后缀。
# 存在的意义：防止 OrderApi / CommentApi 仅凭 "api" 就判成相似。
_GENERIC_TOKENS = frozenset({
    "api", "apis", "util", "utils", "impl", "base", "core", "common", "helper",
    "manager", "client", "sdk", "bean", "data", "model", "info", "const",
    "constant", "config", "wrapper", "adapter", "factory", "service", "listener",
})



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
                      max_scan_classes: int = 0,
                      all_loaders: bool = False) -> dict:
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
        var ALL_LOADERS = __ALL_LOADERS__;

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

        // (1) 多 ClassLoader：加固 App 的类由 DexClassLoader 动态加载，
        //     enumerateLoadedClassesSync 只覆盖默认 loader，会漏。
        var SEEN = {};
        for (var si0 = 0; si0 < all.length; si0++) { SEEN[all[si0]] = 1; }
        if (ALL_LOADERS) {
            try {
                var loaders = Java.enumerateClassLoadersSync();
                out.loaders = loaders.length;
                for (var li = 0; li < loaders.length; li++) {
                    var ld = loaders[li];
                    out.loaders_scanned = (out.loaders_scanned || 0) + 1;
                    // 用 findClass 探测：先试 pattern 本身（若像全限定名），
                    // 否则用已知类名列表逐个探测（成本高，受 LIMIT 限制）
                    var probes = [];
                    if (PATTERN && String(PATTERN).indexOf('.') >= 0) {
                        probes.push(String(PATTERN).replace(/^[\^\$]/, ''));
                    }
                    // 用默认 loader 已见到的类名在这几个 loader 上试
                    for (var pi = 0; pi < all.length && probes.length < 400; pi++) {
                        probes.push(all[pi]);
                    }
                    for (var qi = 0; qi < probes.length; qi++) {
                        var cand = probes[qi];
                        if (SEEN[cand]) { continue; }
                        try {
                            if (ld.findClass(cand)) {
                                SEEN[cand] = 1;
                                all.push(cand);
                                out.loader_hits = (out.loader_hits || 0) + 1;
                            }
                        } catch (e2) { /* 该 loader 里没有，正常 */ }
                    }
                }
            } catch (e) {
                out.loader_error = String(e);
            }
        }
        for (var si = 0; si < all.length; si++) { SEEN[all[si]] = 1; }

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
        "__LIMIT__", str(n)).replace(
        "__SCAN_CAP__", str(scan_cap)).replace(
        "__ALL_LOADERS__", "true" if all_loaders else "false")

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
              sibling_probe: bool = True,
              parent_probe: bool = False,
              deep_diag: bool = False,
              diag_siblings: int = 8,
              max_methods: int = 60,
              auto_degrade: bool = True,
              degrade_l1_rate: float = 200.0,
              degrade_l2_rate: float = 1000.0,
              degrade_l3_rate: float = 5000.0,
              degrade_window_ms: int = 200) -> dict:
    """hook Java 方法，支持**通配符批量**、参数深挖、调用者回溯。

    (4) 第四次修改（2026-11-06）：大改。原来的实现只能 hook 单个类的单个方法，
        实际用起来最大的痛点不是"怎么 hook"，而是**不知道该 hook 哪个类**——
        hook 一个类要 16~20 秒，试三个类就一分钟，而答案往往就在第四个类里。
        这次把"找类"和"hook"合并成一步。

    (14) 第十四次修改（2026-11-13）：新增热方法自动降级（auto_degrade 等 5 个参数）。
        详见 _JS_JAVA_HOOK_MULTI 里 mdaDegradeTick 的说明；这里只讲阈值怎么定的。

    ## 自动降级的阈值依据

    三个阈值单位都是**每秒命中次数**，按「一个 hook 点」统计（同一方法的
    多个重载合并计数）。数字不是拍脑袋，是按"一次全量观测的真实成本"
    与"目标自己的帧预算"两头夹出来的：

      · 成本基准：一次命中做全量观测（取 Java 栈 8 层 + 每个参数 toString），
        实测在 arm64 / Android 12 上是 **0.5~3 毫秒**——取栈要遍历整个 Java
        栈并构造 StackTraceElement 对象，是整个观测里最贵的一步。
        目标主线程的一帧预算：60Hz 是 16.7ms，120Hz 是 8.3ms。

      · 一级 200 次/秒：按 0.5ms 的最小成本算已经是 100ms/秒 = **10% CPU**
        被观测吃掉；按 3ms 则直接打满。同时 200 次/秒明显高于"人操作触发"的
        频率（一次点击/一次滚动回调通常个位数到几十次/秒），不会把正常业务
        误判成热方法。低于这个量级，取栈开销在 wall clock 上看不出来。

      · 二级 1000 次/秒：观测成本（按 0.5ms）已 ≥50% CPU，主线程开始掉帧。
        此时只关栈不够——参数 toString 的条数随参数个数放大，在列表类方法上
        （每次命中 3~5 个参数）它已经是主要成本，所以必须一并关掉。

      · 三级 5000 次/秒：观测成本已**超过目标自身的执行成本**（5000 × 0.5ms
        = 2.5 秒/秒，根本跑不动，说明单次命中的真实工作量只有微秒级）。
        这时唯一有意义的是计数，任何额外记录都只会加重积压。

    三档之间是 5 倍、5 倍间隔。理由是：降级按窗口速率判定，而**速率本身有
    抖动**（GC、调度、同一窗口内的突发）。间隔太小会让同一个方法在不同窗口
    落到不同档位，调用方看到的记录密度忽多忽少。5 倍间隔下，跨档一定意味着
    "热了一个量级"，而不是抖出来的。

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
        auto_degrade  是否启用热方法自动降级（默认 True）。关掉即完全保持旧行为，
                      但高频方法有把目标拖死的风险
        degrade_l1_rate / degrade_l2_rate / degrade_l3_rate
                      三级阈值（次/秒），必须严格递增，不合法时整体回退默认值
        degrade_window_ms
                      速率统计窗口（毫秒）。越短反应越快、越容易被抖动误判。
                      默认 200ms：200 次/秒在窗口内有 40 次，足够和背景噪声区分开，
                      又不会让降级滞后到目标已经卡住之后

    ## 返回（P0-3 要的诊断信息）

        classes[]     每个被 hook 的类：{class, hooked_methods[], call_count,
                      calls[], subclass_of, instantiated}
        call_count    所有类合计调用数
        diagnosis     0 命中时给出：class_loaded / method_exists /
                      sibling_methods_called / suggestion
        verdict       一句话结论
        degrade       **仅在实际发生降级时出现**：
                        {count, hot_methods, max_level, max_rate, total_hits,
                         window_ms, thresholds, events[], points[], note}
                      没降级时这个字段**不存在**（既不返回 null 也不给 count=0），
                      让"没降级"在返回里就是明确的不存在，不会和"降级了没记到"混淆。

    ## 已知边界（如实标注）

        · `java.lang.*` 等系统类部分方法 hook 后会崩，已在注入前排除
        · final 方法可以 hook（ART 未内联时）；被 JIT 内联的会漏
        · 通配符匹配用的是**已加载类**列表，未加载的类匹配不到
        · 参数只取 String 摘要 + 指定字段；对象深拷贝不支持（ART 不提供）
        · 降级**单向**：降了不会升回去（避免阈值附近反复抖动）。降级后该方法
          的后续命中不再带 stack/args，但**已经采到的历史记录不受影响**
        · 无论降到哪一级，被 hook 的方法都照原样调用——降级只减观测，不改行为
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
    # (15) 第十五次修改（2026-11-13）：补齐三个**从未被替换**的 JS 占位符。
    #     bug 原因：_JS_JAVA_HOOK_MULTI 里声明了 PARENT_PROBE / DEEP_DIAG /
    #              DIAG_SIBLINGS 三个变量（第 936~938 行），但 java_hook 的
    #              replace 链里一处都没有替换它们。渲染出来的脚本于是带着
    #              裸标识符 __PARENT_PROBE__，**脚本一加载就抛 ReferenceError**——
    #              java_hook 整个工具不可用，而错误信息只是一个 JS 异常，
    #              完全看不出是"模板占位符漏接"。
    #              之所以没被发现：`node --check` 认为 __X__ 是合法标识符，
    #              语法检查全绿；而出错发生在 frida 脚本 load 阶段。
    #     解决方案：三个都显式接线，且**默认值保持旧行为**——
    #                parent_probe / deep_diag 默认 False、diag_siblings 默认 8
    #                （与原硬编码的 8 一致），所以本次修复不改变任何既有语义，
    #                只是把不可用的工具恢复成可用。
    #              另外加一道保险：末尾断言模板里不再有残留占位符，
    #              下次再漏接线会立刻炸在 Python 侧，而不是等到真机 load。
    parent_probe = bool(parent_probe)
    deep_diag = bool(deep_diag)
    diag_siblings = max(0, min(int(diag_siblings), 64))
    degrade = _degrade_config(auto_degrade, degrade_l1_rate, degrade_l2_rate,
                              degrade_l3_rate, degrade_window_ms)

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
               .replace("__SIBLING_PROBE__", "true" if sibling_probe else "false")
               .replace("__PARENT_PROBE__", "true" if parent_probe else "false")
               .replace("__DEEP_DIAG__", "true" if deep_diag else "false")
               .replace("__DIAG_SIBLINGS__", str(diag_siblings))
               .replace("__DEGRADE__", _js_degrade_config(degrade))
               .replace("__MAXMETHODS__", str(max(1, min(int(max_methods or 60), 400)))))

    # (15) 第十五次修改（2026-11-13）：占位符残留自检。
    #     为什么要它：漏接一个占位符的后果是**脚本加载即抛 ReferenceError**，
    #     而 node --check 认为 __X__ 是合法标识符、语法检查全绿，测试也没覆盖到。
    #     在这里查一次，成本只有一次正则扫描，却能把这类错误挡在跨进程之前。
    _left = _JS_PLACEHOLDER_RE.findall(user_js)
    if _left:
        return {
            "ok": False, "implemented": True, "code": "JS_TEMPLATE_BROKEN",
            "error": "JS 模板里有未替换的占位符：" + ", ".join(sorted(set(_left))),
            "hint": ("java_hook 的 replace 链与 _JS_JAVA_HOOK_MULTI 里的变量声明不一致；"
                     "这类错误在真机上表现为脚本加载抛 ReferenceError"),
        }

    return _run_java_hook(serial, pid, user_js, duration=float(duration),
                          method=str(method or ""))


# 占位符自检用。只匹配全大写下划线的 __XXX__ 形式，不会误伤 JS 里
# 常见的 __proto__ / __type 这类小写写法的真实标识符。
_JS_PLACEHOLDER_RE = re.compile(r"__[A-Z][A-Z0-9_]*__")

# 批量 hook 的 JS 模板。占位符统一用 __XXX__，避免与 JS 里的字面量冲突。
_JS_JAVA_HOOK_MULTI = r"""Java.perform(function () {
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
    var PARENT_PROBE = __PARENT_PROBE__;
    var DEEP_DIAG = __DEEP_DIAG__;
    var DIAG_SIBLINGS = __DIAG_SIBLINGS__;
    var DEGRADE = __DEGRADE__;

    // 这些包里的方法 hook 后容易让目标崩，注入前就排除
    var SKIP_PREFIX = ['java.lang.', 'java.lang.reflect.', 'dalvik.', 'sun.', 'libcore.'];
    function shouldSkip(name) {
        for (var i = 0; i < SKIP_PREFIX.length; i++) {
            if (name.indexOf(SKIP_PREFIX[i]) === 0) { return true; }
        }
        return false;
    }

    // (14) 第十四次修改（2026-11-13）：热方法自动降级（**在 JS 侧执行**）。
    //     bug 原因：include_stack 默认 true、want_args 默认 true，hook 高频方法时
    //              每次命中都要 getStackTrace + 把每个参数 toString。这两件事的开销
    //              随命中数线性增长，而命中记录还要跨进程发回 Python 侧，
    //              消息队列会一起涨——实测足以把目标 App 拖死（使用者已因此崩 2 次）。
    //              在 Python 侧降级**治不了根**：Python 收到消息时，JS 侧的取栈、
    //              序列化和跨进程发送都已经发生过了，那时再降只能减少后续消息，
    //              压不住已经堆起来的积压和已经在花的时间。
    //     解决方案：在 onEnter 里按**实测命中速率**分级降级，降级后连取栈和
    //              toString 都不做——省掉的正是 JS 侧真正贵的那两件事：
    //                一级  关掉 include_stack（最贵：getStackTrace 要遍历整个 Java 栈）
    //                二级  再关掉 want_args（每个参数一次 toString，参数字段深挖更贵）
    //                三级  只累加计数，不再构造任何记录（连返回值描述也省掉）
    //              三条硬约束：
    //                ① 无论降到哪一级，被 hook 的方法都**照原样调用**，
    //                   绝不改变目标行为——降级只减观测，不减功能；
    //                ② 降级**单向**：速率回落也不升回去。否则会在阈值附近
    //                   反复升降，调用方看到的字段时有时无，比一直降级更难用；
    //                ③ 降级**必须报告**，绝不静默——每次降级记一条事件，
    //                   随 result 回传，由 Python 侧拼成可读结论。
    //              阈值的依据见 java_hook() 的 docstring。
    var degradePoints = {};      // key: 类名#方法名 → 该 hook 点的降级状态
    var degradeEvents = [];      // 每次降级的记录，随 result 回传

    // 取（必要时创建）某个 hook 点的降级状态。
    // 按「类名#方法名」聚合而**不是**按 overload 聚合：同名重载是同一个调用点，
    // 分开统计会让 3 个 150 次/秒的重载各自都不越线，而实际压力是 450 次/秒。
    function mdaDegradePoint(cls, mnm) {
        var key = cls + '#' + mnm;
        var p = degradePoints[key];
        if (p === undefined) {
            p = {point: key, level: 0, level_at: 0, rate: 0, peak_rate: 0,
                 window_hits: 0, window_start: 0, total_hits: 0};
            degradePoints[key] = p;
        }
        return p;
    }

    // 每个命中调用一次：累加计数 → 到点评估速率 → 需要就升一级。
    // 只用 Date.now() + 几次比较，比取栈便宜几个数量级，全速命中也不会成为瓶颈。
    function mdaDegradeTick(p, now) {
        p.total_hits++;
        if (p.window_start === 0) { p.window_start = now; }
        p.window_hits++;
        var el = now - p.window_start;
        if (el < DEGRADE.window_ms) {
            // 窗口没走满时，只在「命中已经很多**且**时间够短」时提前评估。
            // 为什么要提前：极端热的方法（2 万次/秒）若只按整窗口评估，前 200ms
            // 就要做 4000 次完整取栈，目标已经被拖住了才开始降级。
            // 提前评估把这段损失压到 1/10 量级，又不会被偶发小突误触发
            // （下限 50 次 / 20ms ≈ 2500 次/秒，远高于一级阈值）。
            if (el < 20 || p.window_hits < 50) { return; }
        }
        p.rate = p.window_hits * 1000 / el;
        if (p.rate > p.peak_rate) { p.peak_rate = p.rate; }
        p.window_hits = 0;
        p.window_start = now;
        if (!DEGRADE.enabled || p.level >= 3) { return; }
        var want = p.level;
        if (p.rate >= DEGRADE.l3) { want = 3; }
        else if (p.rate >= DEGRADE.l2) { want = 2; }
        else if (p.rate >= DEGRADE.l1) { want = 1; }
        if (want > p.level) {
            degradeEvents.push({
                point: p.point, from_level: p.level, to_level: want,
                rate: Math.round(p.rate), ts: now / 1000
            });
            p.level = want;
            p.level_at = now;
        }
    }

    // 汇总降级情况。没降级时返回 null，让"没发生"在返回里就是**不存在**，
    // 而不是一堆 count=0 的字段（那种字段最容易被读成"降级了但没记到"）。
    function mdaDegradeReport() {
        if (!DEGRADE.enabled || degradeEvents.length === 0) { return null; }
        var points = [], maxLevel = 0, maxRate = 0, hot = 0, totalHits = 0;
        for (var k in degradePoints) {
            var p = degradePoints[k];
            if (p.level === 0) { continue; }
            hot++;
            if (p.level > maxLevel) { maxLevel = p.level; }
            if (p.rate > maxRate) { maxRate = Math.round(p.rate); }
            if (p.peak_rate > maxRate) { maxRate = Math.round(p.peak_rate); }
            totalHits += p.total_hits;
            points.push({point: p.point, level: p.level,
                         rate: Math.round(p.rate),
                         peak_rate: Math.round(p.peak_rate),
                         total_hits: p.total_hits});
        }
        points.sort(function (a, b) { return b.peak_rate - a.peak_rate; });
        return {
            count: degradeEvents.length,        // 降级动作次数（本次共降级 N 次）
            hot_methods: hot,                   // 触发热方法的个数
            max_level: maxLevel,                // 本次降到的最深一级
            max_rate: maxRate,                  // 实测最高速率（次/秒）
            total_hits: totalHits,
            window_ms: DEGRADE.window_ms,
            thresholds: {l1: DEGRADE.l1, l2: DEGRADE.l2, l3: DEGRADE.l3},
            events: degradeEvents,
            points: points
        };
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

    // (1) 第一次修改（2026-11-13）：新增。列出类里的全部方法名与重载数。
    //     bug 原因：原来只记"方法存不存在"这一个布尔。
    //               而实际最常见的失败原因是 **hook 错了重载**——
    //               方法存在、被调了，但不是我们挂的那个签名。
    //               只给"method_exists=true"看不出这一点。
    //     解决方案：把方法名 → 重载签名列表整份带回去，
    //               由 Python 侧比对"你要的那个方法有没有多个重载"。
    function mdaMethodMap(jc) {
        var map = {}, names = 0;
        try {
            var ms = jc.getDeclaredMethods();
            for (var i = 0; i < ms.length; i++) {
                var nm = String(ms[i].getName());
                if (!map[nm]) {
                    // 上限 200 个方法名：一个类上万个方法时不能整份塞回 Python
                    if (names >= 200) { map.__truncated__ = true; continue; }
                    map[nm] = [];
                    names++;
                }
                if (map[nm].length < 8) { map[nm].push(String(ms[i]).slice(0, 160)); }
            }
        } catch (e) { return {error: String(e).slice(0, 120)}; }
        return map;
    }

    // (1) 第一次修改（2026-11-13）：新增。
    //     bug 原因：类"有没有被加载"原来靠 Java.use 抛不抛异常间接推断，
    //               但 Java.use 失败也可能是别的原因（内联类、被加固篡改）。
    //               更要紧的是：一个类**在 classloader 里登记了但没有实现体**
    //               （接口/抽象类）时，hook 它注定 0 命中，必须提前说清。
    //     解决方案：直接读 ClassLoader 与修饰符——两者都是运行时事实。
    function mdaClassFacts(clsName) {
        var fact = {class: clsName, loaded: false, loader: null,
                    is_interface: false, is_abstract: false,
                    superclass: null, interfaces: [], declared_methods: 0};
        var JC = null;
        try {
            JC = Java.use(clsName).class;
        } catch (e) {
            fact.error = String(e).slice(0, 160);
            return fact;
        }
        fact.loaded = true;
        try {
            var cl = JC.getClassLoader();
            fact.loader = (cl === null) ? 'boot' : String(cl);
        } catch (e2) { fact.loader = '<无法获取>'; }
        try { fact.superclass = String(JC.getSuperclass()); } catch (e3) {}
        try {
            var mod = JC.getModifiers();
            fact.is_interface = (mod & 0x200) !== 0;    // Modifier.INTERFACE
            fact.is_abstract = (mod & 0x400) !== 0;     // Modifier.ABSTRACT
            fact.modifiers = mod;
        } catch (e4) {}
        try {
            var ifs = JC.getInterfaces();
            for (var i = 0; i < ifs.length && i < 12; i++) {
                fact.interfaces.push(String(ifs[i].getName()));
            }
        } catch (e5) {}
        try { fact.declared_methods = JC.getDeclaredMethods().length; } catch (e6) {}
        return fact;
    }

    // ① 选出候选类
    var candidates = [];
    // (18) methRe 必须在这里统一声明并赋值：它下面的两条路径都要用。
    //      原实现把它写在 else 分支里，class_name 路径下它是 undefined，
    //      导致 method 筛选完全失效、整个类的方法全被 hook。
    var re = null;
    var methRe = null;
    try {
        re = makeRe(PATTERN, 'pattern', false);          // 类名：子串
        methRe = makeRe(METHOD, 'method', true);         // 方法名：精确/通配
    } catch (e) {
        send({kind: 'hook_error', code: 'BAD_PATTERN', error: String(e)});
        return;
    }
    if (CLASS_NAME) {
        candidates.push(CLASS_NAME);
    } else {
        var all;
        try { all = Java.enumerateLoadedClassesSync(); }
        catch (e) { send({kind: 'hook_error', error: '无法枚举类：' + e}); return; }
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

    // (15) 第十五次修改（2026-11-13）：同一份已加载类列表里顺带取出
    //      "同包邻居"，供 0 命中诊断使用。
    //     为什么不用 Python 侧再调一次 java_find_classes：
    //      那会**再 attach 一次**（每次 attach 都要目标停一下），
    //      而我们已经握着 all 这份列表了——多跑一遍纯属浪费，
    //      在加固目标上还多一次可被感知的注入。
    //     只按包名前缀切片，不反射，成本是 O(已加载类数) 的字符串比较。
    if (DEEP_DIAG && candidates.length > 0) {
        var leaf0 = candidates[0];
        var dot = leaf0.lastIndexOf('.');
        if (dot > 0) {
            var pkg = leaf0.substring(0, dot + 1);
            var near = [];
            try {
                var allx = Java.enumerateLoadedClassesSync();
                for (var xi = 0; xi < allx.length && near.length < 200; xi++) {
                    var xn = allx[xi];
                    if (xn.indexOf(pkg) !== 0) { continue; }
                    if (candidates.indexOf(xn) >= 0) { continue; }
                    near.push(xn);
                }
            } catch (eN) {}
            result.same_package = near;
            result.same_package_of = pkg;
        }
    }

    var siblingHits = {};      // 同类兄弟方法的调用计数（0 命中时的旁证）
    var parentHits = {};       // (1) 第一次修改（2026-11-13）：祖先链同名方法的计数

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

        // (1) 第一次修改（2026-11-13）：补 ClassLoader / 接口 / 抽象 的事实。
        //     bug 原因：0 命中时原来只能说"类存在"，判断不了"它是不是接口
        //               或抽象类"——而接口方法没有实现体，hook 了必然 0 命中，
        //               这是最容易被误诊成"路径没走到"的一种情况。
        //     解决方案：把 mdaClassFacts 的结果挂到 entry.facts。
        try { entry.facts = mdaClassFacts(cname); } catch (e) {}

        // (1) 第一次修改（2026-11-13）：记录完整方法表（名字 → 重载签名）。
        //     诊断"是不是 hook 错了重载"必须要有这份数据。
        var methodMap = null;
        if (DEEP_DIAG) {
            try { methodMap = mdaMethodMap(jc.class); } catch (e) {}
            entry.methods_map = methodMap;
        }

        var seen = {};
        var methods = [];
        var MAX_METHODS_PER_CLASS = parseInt('__MAXMETHODS__', 10) || 60;
        try {
            var ms = jc.class.getDeclaredMethods();
            var declaredTotal = ms.length;
            for (var k = 0; k < ms.length; k++) {
                var mn = String(ms[k].getName());
                if (mn === 'finalize' || mn === 'wait' || mn === 'notify' ||
                    mn === 'equals' || mn === 'hashCode' || mn === 'toString') { continue; }
                if (methRe && !methRe.test(mn)) { continue; }
                if (seen[mn]) { continue; }
                seen[mn] = true;
                methods.push(mn);
                // 方法数硬上限：不设上限时 hook 整个 Activity 会挂 400+ 个，
                // 每个都取栈+转参数，目标必崩。
                if (methods.length >= MAX_METHODS_PER_CLASS) { break; }
            }
            if (declaredTotal > methods.length) {
                entry.cap_note = '该类声明 ' + declaredTotal + ' 个方法，'
                    + (methRe ? '' : '未指定 method，')
                    + '本次只 hook 前 ' + methods.length
                    + ' 个（上限 ' + MAX_METHODS_PER_CLASS + '）。'
                    + '建议用 method="xxx" 或 method_pattern 缩小范围。';
            }
        } catch (e) { entry.error = '列方法失败: ' + String(e).slice(0, 120); }

        for (var mi = 0; mi < methods.length; mi++) {
            var mname = methods[mi];
            try {
                var target = jc[mname];
                if (target === undefined || target.overloads === undefined) { continue; }
                var ovs = target.overloads;
                for (var oi = 0; oi < ovs.length; oi++) {
                    (function (ovObj, sig, cls, mnm, cnm) {
                        // 降级状态按方法建立，同一方法的多个重载共用一个状态
                        var dp = mdaDegradePoint(cnm, mnm);
                        ovObj.implementation = function () {
                            var now = Date.now();
                            mdaDegradeTick(dp, now);
                            result.total_hits++;
                            entry.call_count++;
                            // 三级降级：只累加计数，不再构造任何记录
                            // （连 entry.calls 都不碰，消息体也不会变大）
                            if (dp.level >= 3) {
                                return ovObj.apply(this, arguments);
                            }
                            if (entry.calls.length >= MAX_CALLS) { entry.truncated = true; }
                            else {
                                var rec = {method: mnm, overload: sig,
                                           ts: now / 1000, args: [],
                                           arg_fields: null};
                                // 二级降级起不再转参数（每个参数一次 toString）
                                if (WANT_ARGS && dp.level < 2) {
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
                                // 一级降级起不再取 Java 栈（getStackTrace 要遍历整个栈）
                                if (INCLUDE_STACK && dp.level < 1) {
                                    rec.stack = mdaJavaStack(STACK_DEPTH);
                                }
                                var ret;
                                try {
                                    ret = ovObj.apply(this, arguments);
                                    // 三级才关返回值描述；这里 level 一定 < 3
                                    if (WANT_RET && dp.level < 2) {
                                        rec.ret = mdaExpand(ret);
                                    }
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
                    })(ovs[oi], String(ovs[oi]), jc, mname, cname);
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

        // ③ 兄弟方法探测：看同类其他方法有没有被调
        //
        // (1) 第一次修改（2026-11-13）：触发条件放宽 + 计数改到所有重载。
        //     bug 原因：原条件是 `hooked_methods.length === 0 && METHOD`，
        //               也就是**只有"方法根本不存在"时才探测**。
        //               但使用者真正卡住的是另一半场景——方法存在、hook 成功、
        //               却 0 命中（hook 错了重载 / 这个类只是壳）。
        //               那时 sibling_hits 永远是空的，诊断等于没有。
        //     解决方案：只要给了 METHOD 就探测（METHOD 为空时全部方法已挂，
        //               无所谓"兄弟"）。上限由 DIAG_SIBLINGS 控制，
        //               且对每个兄弟方法的**所有重载**都挂计数，
        //               避免又踩"只挂 overloads[0]"的坑。
        if (SIBLING_PROBE && METHOD) {
            try {
                var allms = jc.class.getDeclaredMethods();
                var names = {};
                for (var q = 0; q < allms.length; q++) {
                    var n2 = String(allms[q].getName());
                    if (n2 === 'finalize' || n2 === '<init>' || n2 === '<clinit>' ||
                        n2 === 'wait' || n2 === 'notify' || n2 === 'equals' ||
                        n2 === 'hashCode' || n2 === 'toString') { continue; }
                    names[n2] = true;
                }
                var probed = 0;
                for (var nmKey in names) {
                    if (probed >= DIAG_SIBLINGS) { break; }
                    if (methRe && methRe.test(nmKey)) { continue; }   // 已 hook 过
                    try {
                        var tgt = jc[nmKey];
                        if (tgt === undefined || tgt.overloads === undefined) { continue; }
                        var ovs2 = tgt.overloads;
                        for (var so = 0; so < ovs2.length; so++) {
                            (function (o2, key, cn2) {
                                o2.implementation = function () {
                                    var k2 = cn2 + '.' + key;
                                    siblingHits[k2] = (siblingHits[k2] || 0) + 1;
                                    return o2.apply(this, arguments);
                                };
                            })(ovs2[so], nmKey, cname);
                        }
                        probed++;
                    } catch (e2) {}
                }
            } catch (e3) {}
        }

        // ④ 父类/super 探测：真正干活的方法往往声明在父类或接口上
        //
        // (1) 第一次修改（2026-11-13）：新增。
        //     bug 原因：子类只是转发或空壳时，方法体在父类里；只 hook 子类
        //               永远 0 命中，而诊断只能给出"可试父类：X"这种
        //               没有证据的猜测——用户还得再花一轮去试。
        //     解决方案：主动把同名方法在**祖先链**（最多 3 层，排除
        //               java.lang.* 等系统类）上一起挂计数，直接用数字
        //               回答"父类那个是不是真在跑"。
        if (PARENT_PROBE && METHOD && entry.subclass_of) {
            try {
                var chain = [];
                var cur = entry.subclass_of;
                for (var lv = 0; lv < 3 && cur; lv++) {
                    if (cur.indexOf('java.lang.') === 0 || cur === 'java.lang.Object') { break; }
                    chain.push(cur);
                    var pj = null;
                    try { pj = Java.use(cur).class; } catch (eP) { break; }
                    var sup2 = null;
                    try { sup2 = pj.getSuperclass(); } catch (eP2) {}
                    cur = sup2 === null ? null : String(sup2.getName());
                }
                for (var pi = 0; pi < chain.length; pi++) {
                    var pname = chain[pi];
                    try {
                        var pjc = Java.use(pname);
                        var allp = pname.indexOf('java.lang.') === 0 ? [] : null;
                        // 名字筛选必须用**未锚定**的匹配：父类里方法名可能
                        // 带前后缀（doXxx / xxxInternal），锚定会把它们漏掉。
                        for (var key2 in (methodMap || {})) {
                            if (key2 === '__truncated__') { continue; }
                            if (!(new RegExp(METHOD.replace(/[*?]/g, '.'), 'i')).test(key2)) { continue; }
                            var t2 = pjc[key2];
                            if (t2 === undefined || t2.overloads === undefined) { continue; }
                            for (var po = 0; po < t2.overloads.length; po++) {
                                (function (o3, k3, cp) {
                                    o3.implementation = function () {
                                        var kk = cp + '.' + k3 + ' [父类/祖先]';
                                        parentHits[kk] = (parentHits[kk] || 0) + 1;
                                        return o3.apply(this, arguments);
                                    };
                                })(t2.overloads[po], key2, pname);
                            }
                            if (!entry.parent_probed) { entry.parent_probed = []; }
                            if (entry.parent_probed.length < 12) {
                                entry.parent_probed.push(pname + '.' + key2);
                            }
                        }
                    } catch (e4) {}
                }
            } catch (e5) {}
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
        // (15) 第十五次修改（2026-11-13）：带上祖先链的计数。
        //     不传的话 Python 侧 parent_hits 永远是空，诊断里"可试父类"
        //     就还是纯猜——那正是这次要消掉的东西。
        result.parent_hits = parentHits;
        // 降级报告随结果一起回传：没降级时是 null，降级时是完整明细
        result.degrade = mdaDegradeReport();
        send({kind: 'result', data: result});
    });
});
"""


_JS_STACKTRACE = r"""
Java.perform(function () {
    var DEPTH = __DEPTH__;
    var SKIP_INTERNAL = __SKIP_INTERNAL__;
    try {
        // 用 Thread.currentThread().getStackTrace 取当前线程栈
        var t = Java.use('java.lang.Thread').currentThread();
        var st = t.getStackTrace();
        var frames = [];
        var internalRe = /^(java\.lang\.Thread\.getStackTrace|dalvik\.system\.VMStack|dalvik\.system\.VMDebug|java\.lang\.Throwable\.)/;
        for (var i = 0; i < st.length && frames.length < DEPTH; i++) {
            var fr = String(st[i].toString());
            if (SKIP_INTERNAL && internalRe.test(fr)) { continue; }
            // 结构化拆解：类名 / 方法 / 文件 / 行号
            var cls = '', meth = '', file = '', line = -1;
            try { cls = String(st[i].getClassName()); } catch (e) {}
            try { meth = String(st[i].getMethodName()); } catch (e) {}
            try { file = String(st[i].getFileName()); } catch (e) {}
            try { line = st[i].getLineNumber(); } catch (e) {}
            frames.push({
                raw: fr,
                class: cls,
                method: meth,
                file: file,
                line: line,
                is_native: (line === -2),   // StackTraceElement 约定：-2 = native
                is_unknown: (line === -1)
            });
        }
        send({kind: 'stacktrace', frames: frames, total: st.length});
    } catch (e) {
        send({kind: 'hook_error', code: 'STACK_FAILED',
              error: String(e).slice(0, 300)});
    }
});
"""


_JS_ALL_THREADS = r"""
Java.perform(function () {
    var MAXT = __MAX_THREADS__;
    var DEPTH = __DEPTH__;
    var FILTER = __FILTER__;
    var out = [];
    var total = 0;
    try {
        // (4) 第四次修改（2026-11-18）：
        //     bug 原因：getAllStackTraces() 返回的 Map 在 frida bridge 里
        //               **不是可调用的 Java 对象**——连 m.getClass() 都抛
        //               "TypeError: not a function"（实测二分定位：
        //               拿到 map 后任何方法调用都失败）。
        //               entrySet().toArray() / keySet().iterator() 全部同样报错。
        //     解决方案：改用 Java.choose('java.lang.Thread') 枚举 Thread 实例，
        //               对每个实例调 getName/getState/getStackTrace。
        //               实测拿到 94 个线程及真实栈深（深度 5）。
        Java.choose('java.lang.Thread', {
            onMatch: function (inst) {
                total++;
                if (out.length >= MAXT) { return 'stop'; }
                var name = '', state = '', prio = -1, daemon = false;
                var arr = null;
                try { name = String(inst.getName()); } catch (x) {}
                if (FILTER && name.indexOf(FILTER) < 0) { return 'continue'; }
                try { state = String(inst.getState()); } catch (x) {}
                try { prio = inst.getPriority(); } catch (x) {}
                try { daemon = inst.isDaemon(); } catch (x) {}
                try { arr = inst.getStackTrace(); } catch (x) {}
                var frames = [];
                if (arr) {
                    var n = Math.min(arr.length, DEPTH);
                    for (var i = 0; i < n; i++) {
                        var st = arr[i];
                        var cls = '', meth = '', file = '', line = -1;
                        try { cls = String(st.getClassName()); } catch (x) {}
                        try { meth = String(st.getMethodName()); } catch (x) {}
                        try { file = String(st.getFileName()); } catch (x) {}
                        try { line = st.getLineNumber(); } catch (x) {}
                        frames.push({
                            raw: String(st.toString()),
                            class: cls, method: meth, file: file, line: line,
                            is_native: (line === -2),
                            is_unknown: (line === -1)
                        });
                    }
                }
                out.push({
                    name: name, state: state, priority: prio,
                    daemon: daemon,
                    depth: arr ? arr.length : 0,
                    frames: frames
                });
                return 'continue';
            },
            onComplete: function () {}
        });
        send({kind: 'all_threads', threads: out, total: total});
    } catch (e) {
        send({kind: 'hook_error', code: 'ALL_THREADS_FAILED',
              error: String(e).slice(0, 300)});
    }
});
"""


def stack_all_threads(serial: str, pid: int, max_threads: int = 40,
                      depth: int = 15, name_filter: str = "") -> dict:
    """取**全部 Java 线程**的栈快照（一次调用拿全）。

    (2) 第二次修改（2026-11-18）：新增。
        原因：java_stacktrace 用 Thread.currentThread() 在 frida 的
              JS 线程里调用，只能拿到空栈（实测 frame_count=0）。
              要抓业务线程必须用 getAllStackTraces()。
        价值：死锁 / 卡顿 / 线程池水位定位——一次看清所有线程各自卡在哪儿。

    ## 返回

        threads[]   每个线程 {name, state, priority, daemon, depth, frames[]}
        total       进程内 Java 线程总数
        states      按状态聚合计数（RUNNABLE/BLOCKED/WAITING/...）

    ## 怎么用它定位问题

        · 多个线程 state=BLOCKED 且 frames 顶部是同一把锁 → 锁竞争
        · 线程 state=WAITING 且栈顶是 Object.wait → 在等通知
        · 某业务线程栈顶停在 native 帧（is_native=true）→ 卡在 so 里
    """
    js = (_JS_ALL_THREADS
          .replace("__MAX_THREADS__", str(max(1, min(int(max_threads), 200))))
          .replace("__DEPTH__", str(max(1, min(int(depth), 100))))
          .replace("__FILTER__", _js_str(name_filter or "")))
    box, err = _run_java_script(serial, pid, js, timeout=40.0)
    if err:
        return err
    if not box or box.get("kind") != "all_threads":
        return {"ok": False, "code": "ALL_THREADS_FAILED",
                "error": str(box)[:200] if box else "无结果"}
    threads = box.get("threads") or []
    states: dict = {}
    for t in threads:
        states[t.get("state", "?")] = states.get(t.get("state", "?"), 0) + 1
    return {
        "ok": True,
        "implemented": True,
        "threads": threads,
        "thread_count": len(threads),
        "total": box.get("total"),
        "states": states,
        "note": ("一次调用拿全部 Java 线程栈。"
                 "多线程 state=BLOCKED 且栈顶同一把锁 → 锁竞争；"
                 "栈顶 is_native=true → 卡在 so 里"),
    }


def java_stacktrace(serial: str, pid: int, depth: int = 30,
                    skip_internal: bool = True,
                    thread_name: str = "") -> dict:
    """取**当前 Java 调用栈**（结构化：类/方法/文件/行号）。

    (1) 第一次修改（2026-11-18）：新增。
        bug 原因：mda 此前**没有独立的 Java 取栈工具**。native 侧有
                  get_callstack（accurate/scan/dwarf 三种），而 Java 侧只能
                  从 java_hook / java_find_callers 里顺带拿到零散帧，
                  拿不到"类名.方法(文件:行号)"这种标准结构，也没有
                  "该帧是不是 native 方法"的信息。
        解决方案：新增本工具，用 Thread.currentThread().getStackTrace()
                  取栈并逐帧拆解成结构化字段。
                  复用已有的内部帧跳过逻辑（getStackTrace 会把自己压在栈顶）。

    ## 返回

        frames[]    每帧 {raw, class, method, file, line, is_native, is_unknown}
        total       栈深度（未截断前的总帧数）
        thread      被取栈的线程名

    ## 为什么需要 is_native

        StackTraceElement.getLineNumber() 约定：
            -2  → 该帧是 **native 方法**（从这里跨进 so）
            -1  → 行号未知（混淆/无调试信息）
            >=0 → 正常行号
        所以 is_native 为 true 的那一帧，就是 **Java→so 的交界点**，
        拿它的 class+method 去 java_list_methods 能查到 native 实现，
        再去 native 侧 get_callstack 就能接上两条栈。

    ## 已知边界（诚实说明）

        · 取的是**调用本工具那一刻**的目标线程栈——必须在目标线程里执行。
          本工具在 frida 的 JS 线程里跑，看到的是"哪个线程在跑这段 JS"，
          不是业务线程。要抓业务线程的栈，请用 java_find_callers 那种
          hook 方式（在方法被调时取栈）。
        · 跨线程取栈需要用 Thread.getAllStackTraces()（见 stack_all_threads）。
        · ART 在信号处理期间禁止调 Java，所以崩溃现场取不到 Java 栈。
    """
    js = (_JS_STACKTRACE
          .replace("__DEPTH__", str(max(1, min(int(depth), 200))))
          .replace("__SKIP_INTERNAL__", "true" if skip_internal else "false"))
    box, err = _run_java_script(serial, pid, js, timeout=25.0)
    if err:
        return err
    if not box or box.get("kind") != "stacktrace":
        return {"ok": False, "code": "STACK_FAILED",
                "error": str(box)[:200] if box else "无结果"}
    frames = box.get("frames") or []
    return {
        "ok": True,
        "implemented": True,
        "frames": frames,
        "frame_count": len(frames),
        "total": box.get("total"),
        "thread": thread_name or "(当前 JS 执行线程)",
        "native_frames": [f for f in frames if f.get("is_native")],
        "note": ("is_native=true 的帧是 Java→so 交界点，"
                 "拿它的 class/method 可接 native 侧 get_callstack"),
    }


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
            var cls = Java.use(__CLASS__);
            var target = cls[__METHOD__];
            if (target === undefined) {
                send({kind: 'hook_error', code: 'METHOD_NOT_FOUND',
                      error: '类里没有名为 ' + __METHOD__ + ' 的方法'});
                return;
            }
            var ovs = target.overloads || [];
            var wanted = __OVERLOAD__;
            var hookedN = 0;
            for (var i = 0; i < ovs.length; i++) {
                if (wanted && String(ovs[i]) !== wanted) { continue; }
                (function (ov, sig) {
                    ov.implementation = function () {
                        total++;
                        try {
                            var frames = mdaJavaStack(__DEPTH__);
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
                            var selfName = __METHOD__;
                            for (var fi = 0; fi < frames.length; fi++) {
                                var fr = frames[fi];
                                if (skipRe.test(fr)) { continue; }
                                // 本方法自身的帧（名字以 __METHOD__ 开头的那条）
                                if (fr.indexOf(selfName + '(') >= 0 ||
                                    fr.indexOf('.' + selfName + '(') >= 0) { continue; }
                                caller = fr;
                                break;
                            }
                            callers[caller] = (callers[caller] || 0) + 1;
                            if (samples.length < __SAMPLES__) { samples.push(frames); }
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
    """.replace("__CLASS__", _js_str(class_name)).replace(
        "__METHOD__", _js_str(method)).replace(
        "__OVERLOAD__", _js_str(overload or "")).replace(
        "__DEPTH__", str(max(2, min(int(stack_depth or 12), 32)))).replace(
        "__SAMPLES__", str(cap))
    # (20) 渲染后自检：占位符漏替换会让脚本加载即抛 ReferenceError，
    #      而那种错误在 node --check 层面看不出来（__X__ 是合法标识符）。
    _left = re.findall(r"__[A-Z][A-Z0-9_]*__", user_js)
    if _left:
        return {
            "error": "JS 模板占位符未替换：" + ", ".join(sorted(set(_left))),
            "code": "JS_TEMPLATE_BROKEN",
            "hint": "java_find_callers 的 replace 链与模板不一致",
        }

    return _run_java_callers(serial, pid, user_js, duration=float(duration),
                             class_name=class_name, method=method)


# ---------------- 内部辅助 ----------------


def _degrade_config(auto_degrade: bool, l1: float, l2: float, l3: float,
                    window_ms: int) -> dict:
    """规范化自动降级配置，**非法输入整体回退默认值**而不是逐项夹紧。

    (14) 第十四次修改（2026-11-13）：新增。

    bug 原因：阈值来自工具参数，调用方可能传 0、负数、NaN（如 JSON 里写错），
              也可能把三档填成递增关系反了（l1 > l2）。逐项 clamp 会造出
              "l1=200 l2=200 l3=5000" 这种**看似合法但语义已坏**的组合，
              结果是一级降级永远抢在二级前面触发，二级形同虚设——
              而返回里看不出任何异常。

    解决方案：三项阈值**必须严格递增且都为正**，否则整组回退默认值，
              并在返回的 degrade.thresholds 里呈现真实生效的数字。
              宁可回到默认，也不接受一个语义自相矛盾的配置。
    """
    def _pos(v, default: float) -> float:
        try:
            f = float(v)
        except (TypeError, ValueError):
            return default
        if f != f or f <= 0 or f == float("inf"):         # NaN / 非正 / 无穷
            return default
        return f

    d1, d2, d3 = _pos(l1, 200.0), _pos(l2, 1000.0), _pos(l3, 5000.0)
    if not (d1 < d2 < d3):
        d1, d2, d3 = 200.0, 1000.0, 5000.0
    try:
        w = int(window_ms)
    except (TypeError, ValueError):
        w = 200
    w = max(50, min(w, 5000))       # 200ms 默认；下限防抖，上限防降级滞后
    return {"enabled": bool(auto_degrade), "l1": d1, "l2": d2, "l3": d3,
            "window_ms": w}


def _js_degrade_config(cfg: dict) -> str:
    """把降级配置转成 JS 对象字面量。

    (14) 第十四次修改（2026-11-13）：新增。
        整块走 json 序列化，而不是逐字段拼字符串——阈值是浮点数，
        直接 f-string 内插会受本地化/精度影响写出 JS 不认的形式。
        ensure_ascii 无所谓（没有非 ASCII 内容），但保持与其他 _js_* 助手一致。
    """
    import json as _json

    return _json.dumps({
        "enabled": bool(cfg.get("enabled")),
        "l1": float(cfg.get("l1") or 0.0),
        "l2": float(cfg.get("l2") or 0.0),
        "l3": float(cfg.get("l3") or 0.0),
        "window_ms": int(cfg.get("window_ms") or 200),
    })


def _degrade_note(deg: dict) -> str:
    """把 JS 回传的降级报告拼成**一句可直接转述的结论**。

    (14) 第十四次修改（2026-11-13）：新增。

    为什么必须由 Python 侧生成这句话：要求是"降级发生时返回结果里必须明确
    说明原因与实测速率"。把这句话放在 JS 里生成，等于让最便宜的路径
    （onEnter 高频执行）承担字符串拼接；放 Python 侧生成只在收尾时做一次，
    且有完整上下文（能引用 rate / level / 阈值）。
    """
    level = int(deg.get("max_level") or 0)
    rate = int(deg.get("max_rate") or 0)
    count = int(deg.get("count") or 0)
    hot = int(deg.get("hot_methods") or 0)
    pts = deg.get("points") or []
    top = pts[0] if pts else None
    money = {1: "已关闭调用栈采集（stack）",
             2: "已关闭参数转换（args / ret）",
             3: "只累加调用计数，不再记录明细"}.get(level, "未降级")
    who = (f"（最热：{top['point']}）" if top and top.get("point") else "")
    return (f"⚠️ 已自动降级：该方法是热方法（实测 {rate} 次/秒，阈值 "
            f"{int((deg.get('thresholds') or {}).get('l1') or 0)} 次/秒起降级），{money}。"
            f"{who}本次共降级 {count} 次，涉及 {hot} 个方法；"
            f"降级前的记录完整，降级后该方法的命中不再带对应字段。")


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



_DETACH_LOCK = __import__("threading").Lock()
_DETACHING: set = set()
_DETACH_MAX = 16

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
        # (19) 不要预置任何键：等待循环的条件是 `while not box`，
        #      提前塞 key 会让循环一次都不执行，把"没等到"当成"有结果"。
        box: dict = {}

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
            from server.dyn.adb import Adb

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
                   duration: float = 5.0, method: str = "") -> dict:
    """hook 类脚本的执行器：等 ready → 采集 duration → post stop → 收 result。

    (16) 第十六次修改（2026-11-13）：补 method 参数。
        bug 原因：0 命中诊断里新增了一段"同名方法有几个重载"的分析
                  （`if method and isinstance(mmap, dict)`），但它引用的
                  method 从来没有作为参数传进本函数——执行到这里必然抛
                  NameError: name 'method' is not defined。
                  后果比看起来严重：**任何 0 命中的 hook 调用都会崩在 Python 侧**，
                  而 0 命中恰恰是最需要诊断的场景（工具正好在最该工作的时候失效）。
                  之所以容易被漏掉：只有 total==0 时才走到那段，
                  有命中的测试路径完全不会触发。
        解决方案：加可选参数 method（默认空串），并由 java_hook 透传。
                  用可选参数而不是必填，是为了不破坏其他调用方。

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
            from server.dyn.adb import Adb

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
        # (15) 第十五次修改（2026-11-13）：祖先链同名方法的真实计数。
        #      与 sibling_hits 分开，因为语义不同：sibling 是"同类别的兄弟
        #      方法"，parent 是"父类/祖先上的同名方法"——后者命中直接说明
        #      "该 hook 父类"。
        "parent_hits": data.get("parent_hits") or {},
    }

    # (14) 第十四次修改（2026-11-13）：把 JS 侧的降级报告透传给调用方。
    #     bug 原因：降级是在 JS 侧做的（这是必须的，见 mdaDegradeTick 的说明），
    #              但 JS 侧知道的事 Python 侧并不知道。如果不回传，调用方只会
    #              看到"hook 成功但记录里没有 stack/args"，把它当成工具失灵；
    #              而静默降级正是本次要避免的失败模式。
    #     解决方案：JS 把 report 放进 result.degrade，这里翻译成结构化字段 + note。
    #              注意用 data.get 判空再写入——**没降级时 out 里不该有这个键**，
    #              而不是 out["degrade"] = None（后者会让调用方误以为存在"降级但无数据"）。
    deg = data.get("degrade")
    if isinstance(deg, dict) and int(deg.get("count") or 0) > 0:
        deg_report = dict(deg)
        deg_report["note"] = _degrade_note(deg)
        out["degrade"] = deg_report

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
    #
    # (15) 第十五次修改（2026-11-13）：诊断从"三句话"深化成**可执行的下一步**。
    #     bug 原因：原实现只能回答三件事——类在不在、方法在不在、同类别的
    #               方法有没有被调。但使用者真正卡住的是第四件事：
    #               **「那我该去 hook 谁？」** hook 一个类要十几秒，
    #               而诊断只给出"可试父类：X"这种没有任何证据的猜测，
    #               于是又回到盲试。
    #     解决方案：把诊断拆成 "事实层 + 建议层"：
    #               ① class_refs[]：每个类的运行时事实（ClassLoader、
    #                  接口/抽象、方法总数、**同名方法的重载数**）
    #                  —— "hook 错了重载"是最高频原因，必须有数据支撑；
    #               ② parent_hits ：祖先链上同名方法**真的**被调了几次
    #                  （有数字，不是猜测）；
    #               ③ sibling_methods_called：同类里谁在干活（保留+增强）；
    #               ④ neighbors[]  ：同包下命名相似的类（CommentRealApi 0 命中
    #                  → 建议看 CommentApi / CommentHelper / CommentManager）；
    #               ⑤ next_actions[]：**可直接复制执行**的下一步调用参数，
    #                  每个带 why。这才是"能自己找到正确的类"的关键——
    #                  光有建议文字，模型还是得自己想参数怎么写。
    if total == 0:
        diag: dict = {}
        loaded = [c for c in classes if not c.get("error")]
        diag["class_loaded"] = bool(loaded)
        diag["class_count"] = len(loaded)
        diag["method_exists"] = any(c.get("method_exists") for c in loaded)

        # ① 每个类的运行时事实：判断"为什么 hook 不到"需要这些
        refs = []
        for c in loaded:
            facts = c.get("facts") or {}
            ref = {
                "class": c.get("class"),
                "loader": facts.get("loader"),
                "is_interface": bool(facts.get("is_interface")),
                "is_abstract": bool(facts.get("is_abstract")),
                "declared_methods": facts.get("declared_methods"),
                "superclass": c.get("subclass_of"),
                "hooked_methods": len(c.get("hooked_methods") or []),
            }
            # 同名方法有几个重载——"hook 错了重载"的直接证据
            mmap = c.get("methods_map") or {}
            if method and isinstance(mmap, dict):
                sigs = mmap.get(method)
                if isinstance(sigs, list):
                    ref["overloads_of_target"] = len(sigs)
                    ref["overload_signatures"] = sigs[:6]
            refs.append(ref)
        diag["class_refs"] = refs

        # ② 祖先链探测的真实计数（有数字的"试试父类"，不是猜测）
        ph = data.get("parent_hits") or {}
        diag["parent_hits"] = [
            {"where": k, "hits": v}
            for k, v in sorted(ph.items(), key=lambda kv: -kv[1])[:8]]

        # ③ 同类兄弟方法的调用计数（保留原能力）
        sib = data.get("sibling_hits") or {}
        if sib:
            diag["sibling_methods_called"] = [
                {"method": k, "hits": v}
                for k, v in sorted(sib.items(), key=lambda kv: -kv[1])[:8]]
        else:
            diag["sibling_methods_called"] = []

        diag["suggestion"] = _diag_suggestion(
            diag, method=method, duration=duration)

        # ④ 同包下命名相似的邻居类。/ ⑤ next_actions 需要问一次设备，
        #    失败不影响诊断主体——但失败原因要写进 diag，不能静默吞掉。
        if loaded:
            try:
                # deep_diag 未开启时 JS 不会回传 same_package，
                # 这时自动补一次轻量同类列表查询（只按包前缀，不反射）。
                pool = data.get("same_package") or []
                diag["same_package_size"] = len(pool)
                neigh = _diag_neighbors(loaded[0].get("class"), pool)
                diag["neighbors"] = neigh.get("neighbors") or []
                if neigh.get("note"):
                    diag["neighbors_note"] = neigh["note"]
            except Exception as exc:                      # noqa: BLE001
                diag["neighbors"] = []
                diag["neighbors_error"] = f"{type(exc).__name__}: {exc}"

        diag["next_actions"] = _diag_next_actions(diag, loaded)
        out["diagnosis"] = diag
        out["verdict"] = (f"{len(classes)} 个类已 hook，但 {duration:g}s 内 **0 次调用**"
                          + ("（方法存在）" if diag["method_exists"] else "（方法不存在）")
                          + f"；下一步建议见 diagnosis.next_actions"
                          f"（{len(diag['next_actions'])} 条可直接照抄）")
    else:
        top = summary[0]
        out["verdict"] = (f"{len(classes)} 个类中 {sum(1 for s in summary if s['call_count'])} 个被调用，"
                          f"共 {total} 次；最热的是 {top['class']}（{top['call_count']} 次）")
    # (14) 第十四次修改（2026-11-13）：降级结论**追加到 verdict** 而不是另起一句。
    #     bug 原因：调用方（尤其模型）优先读 verdict 这一行；只把它放在
    #              out["degrade"] 里，等于把"必须明确说明"的要求降级成
    #              "藏在一个可能不被读的字段里"。
    if "degrade" in out:
        out["verdict"] += "；" + str(out["degrade"].get("note") or "")
    return out


# ---------------- 候选探查：不知道该 hook 谁时的"罗盘" ----------------
#
# 这一组工具解决的是与 java_hook 完全不同的一个问题：
#   java_hook 回答"我 hook 的这个东西有没有被调用"；
#   而使用者真正卡住的往往是**连该 hook 谁都不知道**——
#   他 hook `CommentRealApi` 全类 0 命中，然后呢？没有下一个线索了。
#
# 设计原则（三条，逐条都有代价）：
#   ① **只读**：不挂任何 hook，不改目标状态。可以放心反复调。
#   ② **给候选排序，不给结论**：排序是事实（名字像不像、有多少方法），
#      而"哪个才是对的"需要 AI 结合自己知道的上下文判断。
#   ③ **每一条候选都带"为什么把它列出来"**，否则就是一串没有信息量的类名。

# 预置的"线索维度" → 说明文字。放在 Python 侧是为了让返回里带上
# "这个视角能回答什么"，AI 不必猜 field/return_type 该怎么用。
_LINE_KIND_DOC = {
    "network": "网络层通用候选（okhttp / HttpURLConnection / 自研 header 管理类），"
               "**标准 API 常识，不是某个 App 的特征**",
    "similar": "给定片段命中的类，按命名相似度排序",
    "package": "同一包下的邻居类——真实实现常常就在隔壁",
    "method": "含指定方法的类（方法名维度，比类名更能锁定真正干活的类）",
}


def _hint_network_lines() -> list:
    """把 NETWORK_CANDIDATES 展开成"可直接照着搜"的线索清单。

    (1) 第一次修改（2026-11-13）：新增。
        为什么单独抽出来：使用者问「谁在给 HTTP 请求加 header」时，
        期望的答案不是"你给我一堆类名"，而是"你去挂这几个位置"。
        这里把模式表变成带**下一步动作**的候选，AI 可以直接照抄参数。
    """
    out = []
    for item in NETWORK_CANDIDATES:
        out.append({
            "line": "network",
            "pattern": item.get("pattern"),
            "kind": item.get("kind"),
            "method": item.get("method", ""),
            "why": item.get("why", ""),
            "how": item.get("how", ""),
        })
    return out


def java_hook_hint(serial: str, pid: int, query: str = "",
                   package: str = "", method: str = "",
                   include_network: bool = True,
                   limit: int = 30, max_scan_classes: int = 3000,
                   all_loaders: bool = False,
                   count_seconds: float = 0.0) -> dict:
    """给模糊线索（类名片段 / 包名 / 方法名），返回**候选清单**让人/AI 自己判断。

    (1) 第一次修改（2026-11-13）：新增。

    ## 它要解决的场景

    使用者 hook 了 `CommentRealApi` 全类 0 命中，然后**不知道该换哪个类**。
    既有的 `java_find_classes` 只能"按正则找类"，找到之后还是一串类名，
    不知道该先看哪个；而 `java_hook` 一次试一个要十几秒。

    本工具做的事：把"像它的类"一次性列出来并**排序**，每条带上为什么像。
    典型的一轮就能从"完全不知道"收敛到"试这两个"。

    ## 四个线索维度（可组合）

        query          类名片段（如 "CommentRealApi" / "Interceptor"）
                       也接受正则（自动判断，同 java_find_classes）
        package        包名前缀（如 "com.x.net"）
        method         方法名片段 —— 按"含这个方法"找类，
                       **比类名更能锁定真正在干活的类**
        include_network 一并返回网络层通用候选（默认 True）

    ## 排序依据（都不是拍脑袋）

        1.00  类名与 query 完全相同
        0.95  一方是另一方的子串（CommentApi ⊂ CommentRealApi）
        0.55~0.90  按公共前/后缀长度
        0.40~0.70  按共享词元（comment / api / helper …）
        没有 query 时按"方法数降序"——方法多的类更像是真实实现类

    ## count_seconds > 0 时会顺手做一次**低成本调用计数**

    这是本工具与 java_find_classes 最大的区别：猜完之后能立刻验证。
    但要注意代价——它会临时挂一批**只计数**的 hook（不取栈、不转参数），
    运行 `count_seconds` 秒后卸载。默认 0 表示不计数（纯只读）。

    ## 返回

        candidates[]   {class, score, matched_by, method_count, loaded,
                        hookable, superclass, is_interface, is_abstract,
                        methods_sample[], call_count}
        lines[]        本次用到的线索维度及说明
        network[]      网络层通用候选（带 how：下一步该挂哪里）
        total_classes  枚举到的已加载类总数
        scanned        实际反射扫描的类数
        verdict        一句话结论

    ## 已知边界（如实标注）

        · 只覆盖**已加载**的类。DexClassLoader 懒加载的类在它被用之前看不到
          ——遇到这种情况先去触发一次对应功能，再查
        · 反射扫描受 max_scan_classes 限制，达到上限会明确标注 covered=false
        · scoring 是启发式，**不是判定**：它只负责把像的排前面
    """
    import time as _time

    try:
        import frida  # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("java_hook_hint", f"frida 不可用：{exc}",
                             {"query": query})

    n = max(1, min(int(limit), 200))
    scan_cap = max(0, int(max_scan_classes))
    count_s = max(0.0, min(float(count_seconds), 60.0))

    if not (str(query or "").strip() or str(package or "").strip()
            or str(method or "").strip() or include_network):
        return {
            "ok": False, "implemented": True, "code": "NEED_HINT",
            "error": "至少要给 query / package / method 之一（或 include_network=true）",
            "hint": ("完全没方向时，先调 java_hook_hint(include_network=true) "
                     "拿到网络层的通用候选清单"),
        }

    user_js = _JS_HELPERS + r"""
    Java.perform(function () {
        var out = {candidates: [], total_classes: 0, scanned: 0};
        var QUERY = __QUERY__;
        var PACKAGE = __PACKAGE__;
        var METHOD = __METHOD__;
        var LIMIT = __LIMIT__;
        var SCAN_CAP = __SCAN_CAP__;

        // 与 java_find_classes 同一套匹配语义：正则优先，通配符兜底，不锚定。
        // 保持一致很重要——两个工具对同一个 pattern 的匹配结果不同会让人困惑。
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
                                + '（若想用通配符请写 Foo* 这种形式）');
            }
        }

        var qRe = null, mRe = null;
        try {
            qRe = makeRe(QUERY, 'query', false);
            mRe = makeRe(METHOD, 'method', true);
        } catch (e) {
            send({kind: 'hook_error', code: 'BAD_PATTERN', error: String(e)});
            return;
        }

        var all;
        try { all = Java.enumerateLoadedClassesSync(); }
        catch (e) { send({kind: 'hook_error', error: '无法枚举类：' + e}); return; }
        out.total_classes = all.length;

        // 系统包不参与候选：它们既不可能"像业务类"，hook 了也容易崩
        var SKIP = ['java.', 'javax.', 'android.', 'androidx.', 'dalvik.',
                    'sun.', 'libcore.', 'kotlin.', 'kotlinx.', 'com.android.internal.'];
        function skip(name) {
            for (var i = 0; i < SKIP.length; i++) {
                if (name.indexOf(SKIP[i]) === 0) { return true; }
            }
            return false;
        }

        // (18) 第十八次修改（2026-11-13）：排除编译器合成的类。
        //     bug 原因：实测在一个真实 App 里搜 "Request|Header"，返回的前 8 个
        //              候选有 6 个是 `XxxRequest$$ExternalSyntheticLambda3` 这种
        //              **编译器为 lambda 生成的一次性类**：名字里带关键字所以
        //              被匹配、相似度还统一是 0.738，把真正该看的类挤下去了。
        //              这类类只有一个方法、没有任何语义，hook 它们永远没价值。
        //     解决方案：名字里含 $$ / $Lambda / -$$Lambda 的直接跳过。
        //              （保留 `$Builder` 这种**有语义的内部类**——okhttp 的
        //               Request$Builder 恰恰是最该 hook 的目标之一。）
        function synthetic(name) {
            return name.indexOf('$$') >= 0
                || name.indexOf('$Lambda') >= 0
                || name.indexOf('-$$Lambda') >= 0
                || name.indexOf('$$ExternalSynthetic') >= 0;
        }

        // (21) 第二十一次修改（2026-11-13）：排除**数组/基本类型**的伪类名。
        //     bug 原因：enumerateLoadedClassesSync 会返回 `[Landroid.icu.text.
        //              MessagePattern$ArgType;` 这种**数组类型描述符**。
        //              它们是合法条目但不是"类"，方法数为 0、也不可能 hook；
        //              实测搜 "Message" 时前 4 名全是它们，把真类挤光了。
        //     解决方案：以 '[' 开头的条目直接跳过。
        function notAClass(name) {
            return name.charAt(0) === '[';
        }

        var picked = [];
        for (var i = 0; i < all.length; i++) {
            var nm = all[i];
            if (skip(nm)) { continue; }
            if (synthetic(nm)) { continue; }
            if (notAClass(nm)) { continue; }
            if (PACKAGE && nm.indexOf(PACKAGE) !== 0) { continue; }
            // 类名维度：query 命中
            var byName = qRe ? qRe.test(nm) : false;
            // 没有 query 也没有 package 时，只有给了 method 才需要继续筛
            if (qRe && !byName) { continue; }
            if (!qRe && !PACKAGE && !mRe) { continue; }
            picked.push({class: nm, by_name: byName});
            // 类名命中的先占满，剩下的名额留给按方法筛的
            if (!mRe && picked.length >= SCAN_CAP * 4) { break; }
        }

        // 方法维度：需要反射，受 SCAN_CAP 限制
        if (mRe) {
            var methodPicked = [];
            for (var j = 0; j < picked.length; j++) {
                if (out.scanned >= SCAN_CAP) { out.scan_capped = true; break; }
                var nm2 = picked[j].class;
                out.scanned++;
                try {
                    var jc = Java.use(nm2).class;
                    var ms = jc.getDeclaredMethods();
                    var hit = false, cnt = 0;
                    for (var k = 0; k < ms.length; k++) {
                        cnt++;
                        if (!hit && mRe.test(String(ms[k].getName()))) { hit = true; }
                    }
                    if (hit) {
                        picked[j].method_count = cnt;
                        picked[j].by_method = true;
                        methodPicked.push(picked[j]);
                    } else {
                        picked[j].method_count = cnt;
                        picked[j].by_method = false;
                    }
                } catch (e) { picked[j].method_count = -1; }
            }
            // 给了方法名就只保留含该方法的类（这是最硬的筛选条件）
            picked = methodPicked;
        } else if (picked.length > 0) {
            // 没给方法名时补方法数，用于排序与展示（也受上限保护）
            for (var j2 = 0; j2 < picked.length && out.scanned < SCAN_CAP; j2++) {
                out.scanned++;
                try {
                    picked[j2].method_count =
                        Java.use(picked[j2].class).class.getDeclaredMethods().length;
                } catch (e) { picked[j2].method_count = -1; }
            }
            if (out.scanned >= SCAN_CAP) { out.scan_capped = true; }
        }

        // 带上每个候选的"能不能 hook"事实：接口/抽象类的声明方法没有实现体，
        // hook 它们注定 0 命中——这是最容易白跑一轮的原因，必须提前说。
        for (var p = 0; p < picked.length && p < LIMIT; p++) {
            var c = picked[p];
            try {
                var JC = Java.use(c.class).class;
                c.superclass = String(JC.getSuperclass() || '');
                var mod = JC.getModifiers();
                c.is_interface = (mod & 0x200) !== 0;
                c.is_abstract = (mod & 0x400) !== 0;
                c.hookable = !c.is_interface;
                // 方法名样例：让人一眼看出这个类像不像在干正事
                var smp = [], ms2 = JC.getDeclaredMethods();
                for (var s = 0; s < ms2.length && smp.length < 6; s++) {
                    var mn = String(ms2[s].getName());
                    if (smp.indexOf(mn) < 0) { smp.push(mn); }
                }
                c.methods_sample = smp;
            } catch (e) {
                c.hookable = false;
                c.facts_error = String(e).slice(0, 120);
            }
        }
        out.candidates = picked.slice(0, LIMIT);
        out.matched = picked.length;
        send(out);
    });
    """.replace("__QUERY__", _js_str(query or "")).replace(
        "__PACKAGE__", _js_str(package or "")).replace(
        "__METHOD__", _js_str(method or "")).replace(
        "__LIMIT__", str(n)).replace(
        "__SCAN_CAP__", str(scan_cap)).replace(
        "__ALL_LOADERS__", "true" if all_loaders else "false")

    timeout = 90.0 if (method or scan_cap) else 40.0
    box, err = _run_java_script(serial, pid, user_js, timeout=timeout)
    if err:
        return err

    cands = box.get("candidates") or []
    # 排序：命名相似度优先；没有 query 时退化为"方法数降序"
    margin = 0.0
    for c in cands:
        cname = str(c.get("class") or "")
        score = name_similarity(query, cname) if query else 0.0
        if method and c.get("by_method"):
            score += 0.15                      # 含指定方法是硬证据，额外加权
        if c.get("is_interface"):
            score -= 0.25                      # 接口 hook 不了，压下去
        c["score"] = round(max(0.0, min(1.0, score)), 3)

    # (19) 第十九次修改（2026-11-13）：丢掉"完全不像"的候选，并给无名类降权。
    #     bug 原因：实测 query='Request|Header' 返回 273 个匹配，但排在列表末尾的
    #              `PresencePublication$PublishRequest` 相似度是 **0.0**——
    #              它之所以在列表里，是因为正则匹配到了 `Request` 子串
    #              （类名里确实有），但命名相似度算 0（词元切分下
    #              publishrequest 不等于 request）。这类"靠正则擦边进来"的
    #              候选会把 limit 名额占满，把真正相近的类挤出去。
    #              同时 `$1` / `$$ExternalSynthetic` 这类**匿名内部类**方法数为 0，
    #              排在前面只会浪费名额。
    #     解决方案：① 给了 query 时，score==0 的候选**排到后面**——
    #                  注意不能直接丢弃：实测 query='BroadcastReceiver' 时
    #                  真正的候选 `SystemActions$SystemActionsBroadcastReceiver`
    #                  因为（第二版）stem 截断 bug 得了 0 分，
    #                  一刀切丢弃会把**唯一正确的答案**丢掉，而调用方只看到
    #                  "没有任何匹配"，方向直接被带偏。改成"排后面 + 数量封顶"
    #                  既保住名额，又不会让正确答案消失。
    #              ② 方法数为 0 的类（匿名内部类/常量类）score 再乘 0.6；
    #              ③ 在 out 里单独给出 zero_score_dropped 计数，让人知道
    #                 有多少条是靠正则擦边进来的。
    zero_scored = []
    if query:
        zero_scored = [c for c in cands if c["score"] <= 0]
        cands = [c for c in cands if c["score"] > 0]
    for c in cands:
        if int(c.get("method_count") or 0) <= 0:
            c["score"] = round(c["score"] * 0.6, 3)

    if query or method:
        cands.sort(key=lambda x: (-x["score"], -(x.get("method_count") or 0)))
    else:
        cands.sort(key=lambda x: -(x.get("method_count") or 0))

    # (22) 第二十二次修改（2026-11-13）：0 分候选排在正分之后、仍保留在结果里。
    #     为什么不能丢：这类候选是"正则匹到了但命名相似度算 0"的，
    #     里面**混着唯一正确的答案**（stem 截断 bug 那类）。全丢等于把答案删了，
    #     而且返回"没有任何匹配"会让调用方彻底换方向。
    #     封顶 3 条：足够留一手，又不会把 limit 名额占满。
    if zero_scored:
        zero_scored.sort(key=lambda x: -(x.get("method_count") or 0))
        cands.extend(zero_scored[:3])

    out = {
        "ok": True,
        "implemented": True,
        "query": query,
        "package": package,
        "method": method,
        "candidates": cands,
        "total_classes": box.get("total_classes", 0),
        "scanned": box.get("scanned", 0),
        "matched": box.get("matched", len(cands)),
        "scan_capped": bool(box.get("scan_capped")),
    }

    # 线索维度说明：让 AI 知道这次是凭什么列出来的，以及还能怎么扩大范围
    lines = []
    if query:
        lines.append({"line": "similar", "doc": _LINE_KIND_DOC["similar"],
                      "note": f"按命名相似度排序（query={query!r}）"})
    if package:
        lines.append({"line": "package", "doc": _LINE_KIND_DOC["package"],
                      "note": f"包名前缀 {package!r}"})
    if method:
        lines.append({"line": "method", "doc": _LINE_KIND_DOC["method"],
                      "note": f"含方法 {method!r} 的类"})
    if include_network:
        lines.append({"line": "network", "doc": _LINE_KIND_DOC["network"],
                      "note": "通用框架清单，与本 App 无关；可直接照着 pattern 去 hook"})
    out["lines"] = lines
    if include_network:
        out["network"] = _hint_network_lines()

    # 可选的低成本调用计数：猜完立刻验证，省掉"改参数重跑一次"的一轮
    if count_s > 0 and cands:
        counted = _java_count_calls(
            serial, pid, [c["class"] for c in cands], method or "",
            seconds=count_s)
        by_class = {x["class"]: x for x in (counted.get("classes") or [])}
        for c in cands:
            info = by_class.get(c["class"]) or {}
            c["call_count"] = int(info.get("call_count") or 0)
            if info.get("error"):
                c["count_error"] = info["error"]
        if counted.get("ok"):
            cands.sort(key=lambda x: (-int(x.get("call_count") or 0), -x["score"]))
            out["count_seconds"] = count_s
            out["count_note"] = counted.get("note")
        else:
            out["count_error"] = counted.get("error") or "计数失败"
            out["count_code"] = counted.get("code")

    # verdict：直接给"下一步做什么"，而不是复述查询参数
    hot = [c for c in cands if int(c.get("call_count") or 0) > 0]
    if hot:
        top = hot[0]
        out["verdict"] = (
            f"{len(cands)} 个候选里有 {len(hot)} 个在 {count_s:g}s 内被调用过；"
            f"最热的是 {top['class']}（{top['call_count']} 次）——"
            "这个大概率就是真正干活的类，下一步用 java_hook 精确抓它的参数")
    elif cands:
        top = cands[0]
        sc = top.get("score")
        # (20) 第二十次修改（2026-11-13）：已计数时不能还劝人去计数。
        #     bug 原因：实测带 count_seconds=4 调用时，已经拿到了 call_count 全是 0，
        #              verdict 却还在说"下一步：给 count_seconds>0 跑一次低成本计数"——
        #              调用方会照着再做一遍刚做完的事，白花 5~15 秒，
        #              而且会怀疑"是不是上一次没生效"。
        #     解决方案：按"是否已经计过数"分成两套建议。
        counted = "count_seconds" in out
        out["verdict"] = (
            f"按线索列出 {len(cands)} 个候选，最像的是 {top['class']}"
            + (f"（相似度 {sc}）" if sc else "")
            + ("，但它是接口/抽象类，hook 不到实现——先找它的实现子类"
               if top.get("is_interface") else "")
            + ("。已计过数但都是 0 次：说明这条命名线索选错了方向，"
               "换 method= 按调用点查，或先触发 App 的对应功能再重试"
               if counted else
               "。下一步：给 count_seconds>0 跑一次低成本计数，"
               "或直接 java_hook 这个类看命中数"))
    else:
        # (17) 第十七次修改（2026-11-13）：无候选时区分"没搜"与"搜了没结果"。
        #     bug 原因：只给 include_network（只读查网络层清单，没有 query/package/
        #               method）时 cands 必然为空，原实现却输出"没有任何已加载类
        #               匹配这条线索"——**这次根本没搜**，却报成"搜了没搜到"，
        #               会把调用方引向"去触发功能/改拼写"的错误方向。
        #     解决方案：三个线索维度全空时给"清单已在 network 里"的结论。
        if not (query or package or method):
            out["verdict"] = (
                f"本次未给类名/包名/方法线索，只返回网络层通用候选 "
                f"（{len(out.get('network') or [])} 条，见 network 字段）。"
                "下一步：把某个 pattern 当 query 传进来限定到这个 App 的类，"
                "例如 java_hook_hint(query='Interceptor', count_seconds=5)")
        else:
            out["verdict"] = (
                "没有任何已加载类匹配这条线索。可能是：① 类名拼写不同；"
                "② 该类还没被加载（懒加载）——先触发一次对应功能再查；"
                "③ 换个维度试：method= 方法名片段，或 include_network=true")
    if out.get("scan_capped"):
        out["verdict"] += f"；注意：反射扫描已达上限 {scan_cap}，结果可能不全"
    return out


def _java_count_calls(serial: str, pid: int, classes: list, method: str = "",
                      seconds: float = 3.0,
                      max_methods_per_class: int = 60) -> dict:
    """**只计数**：给一批类挂轻量 hook，跑 N 秒后卸载，返回每个类被调了几次。

    (1) 第一次修改（2026-11-13）：新增。

    ## 为什么不直接用 java_hook

    `java_hook` 的每一次命中都要取 Java 栈（遍历整个栈并构造 StackTraceElement）
    再对每个参数 toString，实测单次命中 0.5~3 毫秒。探查阶段挂的往往是整类
    几十个方法，用 java_hook 探一遍等于给目标加了几十毫秒/帧的固定开销，
    而且很容易触发它自己的自动降级，最后看到的数据也是降级后的。

    这里反过来：**只累加一个整数**，不碰栈、不碰参数、不构造记录对象。
    单次命中的成本是一个闭包调用 + 一次加法，量级在几十纳秒。

    ## 边界（如实标注，不粉饰）

        · 只挂**类的声明方法**（getDeclaredMethods）。继承来的方法不在此列——
          想覆盖继承链请直接对父类调一次
        · 每个类最多挂 max_methods_per_class 个方法（防一次挂几千个把目标拖垮）
        · 接口/抽象类的声明方法没有实现体，hook 它们不会命中（会在返回里标出）
        · 与所有 Java hook 一样：被 JIT 内联的方法会漏

    返回：
        {ok, seconds, classes: [{class, call_count, hooked_methods, error}],
         note}
    """
    import time as _time

    try:
        import frida  # noqa: F401
    except Exception as exc:                              # noqa: BLE001
        return _java_pending("count_calls", f"frida 不可用：{exc}")

    names = [str(x) for x in (classes or []) if str(x).strip()]
    if not names:
        return {"ok": False, "implemented": True, "code": "NO_CLASS",
                "error": "没有给出要计数的类"}

    dur = max(0.5, min(float(seconds), 60.0))
    user_js = _JS_HELPERS + r"""
    Java.perform(function () {
        var CLASSES = __CLASSES__;
        var METHOD = __METHOD__;
        var MAXM = __MAXM__;
        var SKIP = ['java.lang.', 'java.lang.reflect.', 'dalvik.', 'sun.', 'libcore.'];

        function makeRe(p, anchor) {
            if (!p) { return null; }
            var a = anchor ? '^' : '', z = anchor ? '$' : '';
            var isWild = /[*?]/.test(p) && !/[\\|\[\](){}^$]/.test(p);
            if (isWild) {
                var esc = p.replace(/[.+${}()|[\]]/g, '\\$&');
                esc = esc.replace(/\*/g, '.*').replace(/\?/g, '.');
                return new RegExp(a + esc + z, 'i');
            }
            return new RegExp(a + p + z, 'i');
        }
        var mRe = makeRe(METHOD, true);

        var counts = {};        // 类名 → 次数
        var hookedN = {};       // 类名 → 实际挂上的方法数
        var errs = {};
        for (var ci = 0; ci < CLASSES.length; ci++) {
            var cname = CLASSES[ci];
            counts[cname] = 0;
            var skipIt = false;
            for (var s = 0; s < SKIP.length; s++) {
                if (cname.indexOf(SKIP[s]) === 0) { skipIt = true; break; }
            }
            if (skipIt) { errs[cname] = '系统类，跳过（hook 后易崩）'; continue; }

            var jc = null;
            try { jc = Java.use(cname); } catch (e) {
                errs[cname] = 'Java.use 失败: ' + String(e).slice(0, 100);
                continue;
            }
            // 接口没有实现体，挂了也不会命中——提前说清，别让人白等
            try {
                if ((jc.class.getModifiers() & 0x200) !== 0) {
                    errs[cname] = '接口（无实现体），hook 声明方法不会命中';
                    continue;
                }
            } catch (eI) {}

            var seen = {}, n = 0;
            try {
                var ms = jc.class.getDeclaredMethods();
                for (var mi = 0; mi < ms.length; mi++) {
                    var mn = String(ms[mi].getName());
                    if (mn === 'finalize' || mn === 'wait' || mn === 'notify' ||
                        mn === 'equals' || mn === 'hashCode' || mn === 'toString' ||
                        mn === '<init>' || mn === '<clinit>') { continue; }
                    if (mRe && !mRe.test(mn)) { continue; }
                    if (seen[mn] || n >= MAXM) { continue; }
                    seen[mn] = true;
                    try {
                        var tgt = jc[mn];
                        if (tgt === undefined || tgt.overloads === undefined) { continue; }
                        var ovs = tgt.overloads;
                        for (var oi = 0; oi < ovs.length; oi++) {
                            (function (ov, cn2) {
                                // 这就是全部开销：一个闭包 + 一次加法。
                                // 不取栈、不碰参数、不构造任何对象。
                                ov.implementation = function () {
                                    counts[cn2]++;
                                    return ov.apply(this, arguments);
                                };
                            })(ovs[oi], cname);
                        }
                        n++;
                    } catch (e2) {}
                }
                hookedN[cname] = n;
            } catch (e3) {
                errs[cname] = '列方法失败: ' + String(e3).slice(0, 100);
            }
        }
        send({kind: 'ready', classes: CLASSES.length});
        recv('stop', function () {
            var out = [];
            for (var c = 0; c < CLASSES.length; c++) {
                var nm = CLASSES[c];
                out.push({class: nm, call_count: counts[nm] || 0,
                          hooked_methods: hookedN[nm] || 0,
                          error: errs[nm] || null});
            }
            send({kind: 'result', classes: out});
        });
    });
    """.replace("__CLASSES__", _js_str_list(names)).replace(
        "__METHOD__", _js_str(method or "")).replace(
        "__MAXM__", str(max(1, min(int(max_methods_per_class), 400))))

    sess = None
    box = {"ready": False, "done": False, "data": None}
    try:
        from server.dyn import java_bridge as _self

        try:
            full = wrap_with_java_bridge(user_js)
        except JavaBridgeError as exc:
            return _java_pending("count_calls", str(exc), {"code_detail": exc.code})
        dev = frida.get_device(serial, timeout=15)
        sess = dev.attach(int(pid))
        script = sess.create_script(full)

        def _on_msg(msg, data):
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                if msg.get("type") == "error":
                    box["_err"] = msg.get("description") or "脚本异常"
                return
            kind = payload.get("kind")
            if kind == "ready":
                box["ready"] = True
            elif kind == "result":
                box["done"] = True
                box["data"] = payload
            elif kind in ("hook_error", "bridge_error"):
                box["_err"] = payload.get("error") or "计数失败"

        script.on("message", _on_msg)
        script.load()
        t0 = _time.time()
        while not box["ready"] and not box.get("_err") and _time.time() - t0 < 25.0:
            _time.sleep(0.02)
        if box.get("_err"):
            return {"ok": False, "implemented": True, "code": "COUNT_FAILED",
                    "error": str(box["_err"])[:400]}
        if not box["ready"]:
            return {"ok": False, "implemented": True, "code": "NOT_READY",
                    "error": "计数 hook 25 秒内未就位",
                    "hint": "加固 app 可能阻断 Java.perform；先用 java_bridge_status 确认"}
        _time.sleep(dur)
        try:
            script.post({"type": "stop"})
        except Exception:                                 # noqa: BLE001
            pass
        for _ in range(60):
            if box["done"]:
                break
            _time.sleep(0.02)
    except Exception as exc:                              # noqa: BLE001
        return {"ok": False, "implemented": True, "code": "COUNT_FAILED",
                "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _detach_async(sess)

    rows = (box.get("data") or {}).get("classes") or []
    rows.sort(key=lambda x: -int(x.get("call_count") or 0))
    total = sum(int(r.get("call_count") or 0) for r in rows)
    live = [r for r in rows if int(r.get("call_count") or 0) > 0]
    if total == 0:
        note = (f"{dur:g}s 内 {len(names)} 个类的声明方法**一次都没被调用**。"
                "要么当前操作没走到这些类，要么它们还没加载——"
                "先去触发一次对应功能再重试")
    else:
        note = (f"{dur:g}s 内共计数 {total} 次，{len(live)}/{len(rows)} 个类有调用；"
                f"最热的是 {live[0]['class']}（{live[0]['call_count']} 次）")
        bad = [r for r in rows if r.get("error")]
        if bad:
            note += f"；{len(bad)} 个类没挂上（原因见各自 error 字段）"
    return {
        "ok": True,
        "implemented": True,
        "seconds": dur,
        "classes": rows,
        "total_calls": total,
        "note": note,
        "weight": "轻量计数：不取栈、不转参数，单次命中只加一个整数",
    }


# ---------------- 0 命中诊断的三个辅助（Python 侧拼装） ----------------
#
# (15) 第十五次修改（2026-11-13）：新增。
#     为什么放在 Python 侧而不是 JS 里：这三件事都要**综合多个来源**——
#     JS 侧的运行时事实、祖先链计数、以及"同包邻居"这类需要额外一次查询
#     才能拿到的信息。塞进 JS 会让那个已经上千行的模板更难维护，
#     而拼建议本身是纯字符串逻辑，Python 写起来直白得多。

def _diag_suggestion(diag: dict, method: str = "",
                     duration: float = 0.0) -> str:
    """把诊断事实翻译成**人话结论**（一条，不是一堆）。

    (15) 第十五次修改（2026-11-13）：新增。

    为什么只给一条：诊断里已经有 class_refs / parent_hits /
    sibling_methods_called 这些结构化事实，`suggestion` 的职责是
    **替读的人下判断**——"最可能的原因是这个"。列五条并列，
    读的人还是要自己排优先级，等于没诊断。

    优先级（按"出现频率 × 排查成本"排的，见每条的说明）：
        1. 接口/抽象类 → hook 声明方法本来就不会命中（结构性，最该先说）
        2. 有祖先链命中 → 直接说明该 hook 父类
        3. 有兄弟方法命中 → 该 hook 那个方法
        4. 方法是重载之一 → 很可能 hook 错了重载
        5. 都没命中 → 类可能选错了，指向 java_hook_hint
    """
    refs = diag.get("class_refs") or []
    parents = diag.get("parent_hits") or []
    sibs = diag.get("sibling_methods_called") or []

    # ① 结构性原因：接口/抽象类的声明方法没有实现体，挂了必然 0 命中
    iface = [r for r in refs if r.get("is_interface")]
    if iface:
        return (f"{iface[0]['class']} 是**接口**，声明方法没有实现体，"
                "hook 它注定 0 命中。先找它的实现子类："
                f"用 java_hook_hint(query='{class_name_stem(iface[0]['class'])}') "
                "按命名找实现类，或 java_find_classes 搜同一包的类")

    # ② 祖先链上有命中：这是有数字的证据，比任何猜测都硬
    if parents:
        top = parents[0]
        return (f"祖先链上的 {top['where']} 被调了 {top['hits']} 次，"
                "而本类同名方法 0 次——真正干活的是父类/父接口上的那个。"
                f"下一步：java_hook(class_name=<父类>, method='{method or '*'}')")

    # ③ 同类里的兄弟方法在跑
    if sibs:
        top = sibs[0]
        return (f"同类里 {top['method']} 被调了 {top['hits']} 次，"
                "而你 hook 的方法 0 次——真正干活的很可能是它。"
                f"下一步：java_hook(method='{top['method'].rsplit('.', 1)[-1]}')")

    # ④ hook 错了重载：方法名对、签名不对
    over = [r for r in refs if (r.get("overloads_of_target") or 0) > 1]
    if over:
        sigs = over[0].get("overload_signatures") or []
        return (f"{over[0]['class']} 里的 {method} 有 "
                f"{over[0]['overloads_of_target']} 个重载，你挂的可能不是被调用的那个。"
                f"可用 overload 参数指定，例如：{sigs[0] if sigs else '(见 overload_signatures)'}")

    # ⑤ 什么都没有：类很可能选错了
    names = [r.get("class") for r in refs if r.get("class")]
    stem = class_name_stem(names[0]) if names else ""
    if not diag.get("method_exists"):
        return (f"类里没有匹配 {method!r} 的方法：检查方法名拼写，"
                "或用 method='*' 列出全部方法再看")
    return (f"{duration:g}s 内该类完全没被调用。两种可能："
            "① 当前操作没走到这条路径——先触发对应功能（发一次请求）再重试；"
            "② 这个类根本不是干活的——"
            f"用 java_hook_hint(query='{stem}') 看同包/同名相近的类里谁在跑")


def _diag_neighbors(class_name: str, same_package: list | None = None,
                    limit: int = 8) -> dict:
    """找同包下**命名相似**的邻居类——"真实实现常常就在隔壁"。

    (15) 第十五次修改（2026-11-13）：新增。

    bug 原因：`CommentRealApi` 0 命中时，最该看的 `CommentApi` /
    `CommentHelper` / `CommentManager` 就在同一个包下，但原诊断完全
    没有这个概念——使用者只能自己想到"要不要看看兄弟类"。
    而这恰恰是最省事的一条路：它们通常只差一个词。

    (16) 第十六次修改（2026-11-13）：输入从"再去查一次设备"改成"消费
        同一次注入已经取回的同包类列表"（result.same_package）。
        bug 原因：第一版在诊断里调 java_find_classes，那是**第二次 attach**——
                  目标要再停一次，在加固 App 上还多一次可被感知的注入；
                  而且 0 命中诊断本身已经很慢，再多一轮纯属雪上加霜。
        解决方案：JS 侧在同一次 inject 里用已枚举的类列表切出同包类
                  （O(n) 字符串比较），Python 侧只做命名相似度打分。

    返回：{neighbors: [{class, score}], same_package_of?, error?}
    """
    raw = str(class_name or "")
    pkg = raw.rsplit(".", 1)[0] + "." if "." in raw else ""
    pool = [str(x) for x in (same_package or [])]
    if not pkg or not pool:
        # 没拿到同包列表不是错误：可能 diagnostic 没开或目标类在默认包里。
        # 但要说明"为什么没有"，不能返回空数组让人以为是"同包没别的类"。
        return {"neighbors": [],
                "note": ("未取到同包类列表（deep_diag 未开启，或类在默认包里）"
                         if not pool else "")}

    scored = []
    for cname in pool:
        sc = name_similarity(raw, cname)
        if sc <= 0:
            continue
        scored.append({"class": cname, "score": round(sc, 3)})
    scored.sort(key=lambda x: -x["score"])
    return {"neighbors": scored[:max(1, int(limit))],
            "same_package_of": pkg,
            "pool_size": len(pool)}


def _re_escape(text: str) -> str:
    """转义正则元字符（只用于包名前缀，避免 . 被当成任意字符）。"""
    import re as _re

    return _re.escape(str(text or ""))


def _diag_next_actions(diag: dict, loaded: list) -> list:
    """把诊断结论变成**可以直接复制执行**的下一步调用参数。

    (15) 第十五次修改（2026-11-13）：新增。

    为什么这一步不能省：`suggestion` 是给人看的一句话，但实际执行的人
    （或模型）还得把它翻译成工具参数——类名写全了没有、method 该不该带
    通配符、要不要开 count_seconds。翻译这一步就是新的出错点，
    而且每错一次又是一轮十几秒的 hook。

    所以这里直接给出 `{"tool": ..., "args": {...}, "why": ...}` 的列表，
    每条都是**当前上下文下真的可执行**的（类名来自运行时事实，
    不是猜的）。这是"能自己找到正确的类"的实际抓手。

    排序即优先级：前面的更可能一击命中。
    """
    acts: list = []
    refs = diag.get("class_refs") or []
    parents = diag.get("parent_hits") or []
    sibs = diag.get("sibling_methods_called") or []
    neighbors = diag.get("neighbors") or []
    iface = [r for r in refs if r.get("is_interface")]
    over = [r for r in refs if (r.get("overloads_of_target") or 0) > 1]

    # ① 祖先链命中 → 直接 hook 父类
    if parents:
        top = parents[0]
        pcls = top["where"].split(". [父类")[0].rsplit(".", 1)[0]
        pmeth = top["where"].split(".")[-1].split(" ")[0]
        acts.append({
            "tool": "java_hook",
            "args": {"class_name": pcls, "method": pmeth, "duration": 10},
            "why": f"祖先链上该方法被调了 {top['hits']} 次，本类 0 次",
        })

    # ② 兄弟方法在跑 → 换方法名
    if sibs:
        top = sibs[0]
        cls = top["method"].rsplit(".", 1)[0]
        meth = top["method"].rsplit(".", 1)[-1]
        acts.append({
            "tool": "java_hook",
            "args": {"class_name": cls, "method": meth, "duration": 10,
                     "capture": {"args": True, "ret": True, "arg_fields":
                                 ["url", "headers"]}},
            "why": f"同类里它被调了 {top['hits']} 次",
        })

    # ③ 重载问题 → 指定 overload
    if over and (over[0].get("overload_signatures") or []):
        sigs = over[0]["overload_signatures"]
        acts.append({
            "tool": "java_hook",
            "args": {"class_name": over[0]["class"],
                     "method": _overload_method_name(sigs[0]),
                     "overload": sigs[0], "duration": 10},
            "why": (f"{over[0]['class']} 有 {over[0]['overloads_of_target']} 个同名重载，"
                    "很可能挂错了；先用单条签名（overload 参数）精确试一次"),
        })

    # ④ 接口 → 先找实现类（这是结构性问题的唯一解）
    if iface:
        stem = class_name_stem(iface[0]["class"])
        acts.append({
            "tool": "java_hook_hint",
            "args": {"query": stem, "include_network": True, "count_seconds": 5},
            "why": f"{iface[0]['class']} 是接口，要 hook 它的实现类",
        })

    # ⑤ 同包邻居 → 一次性列出像它的类，并对它们做低成本计数
    if neighbors:
        names = [n["class"] for n in neighbors[:6]]
        acts.append({
            "tool": "java_count_calls",
            "args": {"classes": names, "seconds": 5},
            "why": ("同包下命名相近的类（"
                    + ", ".join(class_name_stem(n) for n in names[:3])
                    + "）；先便宜地看谁真的在被调用"),
        })
        acts.append({
            "tool": "java_hook",
            "args": {"pattern": "|".join(names[:4]), "duration": 10},
            "why": "一次 hook 这几个候选，按各自命中数判胜负，省掉逐个试",
        })

    # ⑥ 什么都没有 → 直接进候选探查（纯只读，不花 hook 时间）
    if not acts:
        stem = class_name_stem(refs[0]["class"]) if refs else ""
        acts.append({
            "tool": "java_hook_hint",
            "args": {"query": stem, "include_network": True,
                     "count_seconds": 5} if stem else {
                         "include_network": True, "count_seconds": 5},
            "why": ("当前类完全没被调用，说明类可能选错了；"
                    "这一步只读、秒回，列出真正在跑的候选"),
        })
    return acts


def _overload_method_name(signature: str) -> str:
    """从 Java 方法签名里抽出**方法名**。

    (16) 第十六次修改（2026-11-13）：新增。
        bug 原因：`overload_signatures` 存的是
                  "public void add(java.lang.String)" 这种完整签名，
                  next_actions 里要的是**方法名**（java_hook 的 method 参数）。
                  直接截取会截出 "public"，调用方照抄必然 0 匹配。
        解决方案：只取 "名字(" 之前紧邻的那个标识符。

    例：
        "public final okhttp3.Request build()" → "build"
        "void add(java.lang.String, int)"      → "add"
    """
    sig = str(signature or "").strip()
    if not sig:
        return ""
    idx = sig.find("(")
    head = sig[:idx] if idx > 0 else sig
    parts = head.replace("<", " ").replace(">", " ").split()
    return parts[-1] if parts else ""
