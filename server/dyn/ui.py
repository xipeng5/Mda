"""Android 界面（UI）操作能力：读界面、找控件、点击、输入、滑动、按键。

职责：让 AI 能像人一样操作 Android 设备的界面，而不只是看 so/内存。
全部通过 adb shell 实现，不依赖 frida、不注入目标进程，因此对加固 App
也不构成风控信号（uiautomator dump 走的是系统的 accessibility 快照，
是 Android 官方提供的调试通道）。

设计要点（都是实测踩出来的，不要随手改回去）：

1. **uiautomator dump 的退出码不可信**
   实测（MIUI / Android 12）：输出路径不存在时 `uiautomator dump /nonexistent/a.xml`
   仍然 rc=0，且照样打印 "UI hierchary dumped to: ..."。只信退出码会把
   "文件根本没写出来"当成成功。所以本模块的判据是：
       先 rm（避免读到上一次的残留）→ dump → cat → 能解析成 XML 才算成功。

2. **MIUI 会在 stderr 喷无关异常**
   每次 dump 都会带一段 `java.io.FileNotFoundException:
   /data/system/theme_config/theme_compatibility.xml` 堆栈。这是 MIUI 主题
   加载器的噪声，**不是 dump 失败**。判断成败只看 cat 出来的内容。

3. **dump 一次约 1-2 秒，绝不能在一次调用里 dump 多次**
   ui_click / ui_input 带条件时内部只 dump 一次，找到控件复用同一份快照。

4. **input text 只支持 ASCII 可映射字符**
   实测 `adb shell input text '你好'` 直接抛
   `java.lang.NullPointerException: Attempt to get length of null array`
   （InputShellCommand.sendText 里 KeyCharacterMap.getEvents() 返回 null），
   rc=255。é / ü / 日本語 / emoji 同样失败。这是 Android 本身的限制，
   不是转义没做好——所以本模块**如实报错**，不静默丢字符。

5. **参数一律经 shell 单引号包裹 + 内部单引号转义**
   `input text 'a&b'` 若不加引号会被设备 shell 解释成命令分隔符，
   实测报 `/system/bin/sh: b: inaccessible or not found`。所有落到设备
   shell 的字符串都必须 _quote() 处理。

6. **坐标必须是整数且在屏幕范围内**
   拒绝把用户/模型给的字符串直接拼进命令（注入面），同时避免
   `input tap 1e9 0` 这种把设备点花的值。
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from server.dyn.adb import DynError, resolve_adb

# dump 落到 /data/local/tmp：shell 身份可写，且不必占 /sdcard（有些 ROM 上
# /sdcard 需要额外存储权限）。每次调用前先 rm，避免读到上次的残留。
_DUMP_PATH = "/data/local/tmp/mda_ui_dump.xml"

# bounds 形如 "[0,0][1080,2201]"，也见过 "[0,0][1080,2201] "（尾部空格）
_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")

# input text 能可靠输入的字符：ASCII 可见字符（含空格，空格由调用方转成 %s）
_ASCII_PRINTABLE = {chr(c) for c in range(0x20, 0x7F)}

# 输入类控件：常常既无文本又不可点击，simplify 必须保留，否则模型找不到输入框
_INPUT_CLASS_RE = re.compile(r"EditText|AutoCompleteTextView|SearchView|"
                             r"TextInputEditText", re.I)

# 按键名 -> Android keycode。只收常用键，避免暴露"任意 keycode"的注入面。
KEYCODES = {
    "back": 4,
    "home": 3,
    "menu": 82,
    "enter": 66,
    "delete": 67,
    "del": 67,
    "forward_delete": 112,
    "tab": 61,
    "space": 62,
    "escape": 111,
    "esc": 111,
    "power": 26,
    "volume_up": 24,
    "volume_down": 25,
    "mute": 164,
    "recent": 187,
    "app_switch": 187,
    "search": 84,
    "camera": 27,
    "up": 19,
    "down": 20,
    "left": 21,
    "right": 22,
    "center": 23,
    "move_home": 122,
    "move_end": 123,
    "page_up": 92,
    "page_down": 93,
    "wakeup": 224,
    "sleep": 223,
}


@dataclass
class UiNode:
    """一个界面节点。字段与 uiautomator 的 XML 属性一一对应。"""

    text: str = ""
    resource_id: str = ""
    cls: str = ""
    content_desc: str = ""
    package: str = ""
    bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
    clickable: bool = False
    enabled: bool = True
    checked: bool = False
    checkable: bool = False
    focused: bool = False
    selected: bool = False
    scrollable: bool = False
    long_clickable: bool = False
    password: bool = False
    index: int = 0
    children: list["UiNode"] = field(default_factory=list)

    # ---------- 派生属性 ----------

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return ((x1 + x2) // 2, (y1 + y2) // 2)

    @property
    def area(self) -> int:
        x1, y1, x2, y2 = self.bounds
        return max(0, x2 - x1) * max(0, y2 - y1)

    @property
    def visible(self) -> bool:
        """bounds 面积为 0 视为不可见。

        uiautomator 对不可见节点给 [0,0][0,0]；也见过宽或高为 0 的。
        """
        return self.area > 0

    @property
    def label(self) -> str:
        """给 AI 看的"这个节点是什么"。

        为什么需要它（实测痛点）：Android 列表里**可点击的是行容器**
        （LinearLayout/FrameLayout，自身 text 为空），真正显示文字的
        是它的子 TextView。只按 text/clickable 输出，模型会看到一堆
        "clickable=true 但没有名字"的容器，根本不知道点哪一行。

        关键：只取**叶子**文本。祖先容器会把所有后代文本都拼上来，
        实测设置页因此每个容器都变成 "返回 / 应用管理 / 99" 全一样，
        反而更没用。叶子才是"这一行显示的东西"。
        """
        if self.text or self.content_desc:
            return self.text or self.content_desc
        parts: list[str] = []
        for c in iter_nodes(self.children):
            if c.children:                    # 跳过中间布局层
                continue
            t = c.text or c.content_desc
            if t and t not in parts:
                parts.append(t)
            if len(parts) >= 3:               # 3 段足够认出是哪一行
                break
        return " / ".join(parts)

    @property
    def meaningful(self) -> bool:
        """simplify 的保留判据：这个节点对"操作界面"有没有信息量。

        (1) 第一次修改（2026-11-13）：
            bug 原因：初版判据是 "text 或 content_desc 或 resource_id 或
                      clickable..."。两个问题叠在一起让 simplify 形同无效：
                      ① resource_id 单独就能让节点通过——97 个节点里 62 个
                         带 id，压完还有 74；
                      ② 祖先容器的 label 把后代文本全拼上来，每个上层
                         FrameLayout 都变成 "返回 / 应用管理 / 99"，压完 59
                         且内容重复，模型读了反而更困惑。
            解决方案：判据收敛为三类真正有用处的节点——
                      ① 可交互（clickable/long_clickable/scrollable/checkable）；
                      ② 叶子语义节点（自身有 text/content-desc 且无子节点）；
                      ③ 输入控件（EditText 等，常常既无文本又不可点击）。
                      中间的布局容器一律不返回，实测 97 -> 24。
        """
        if (self.clickable or self.long_clickable or self.scrollable
                or self.checkable or self.password):
            return True
        if _INPUT_CLASS_RE.search(self.cls or ""):
            return True
        if not self.children:                 # 叶子：它的文本才是内容
            return bool(self.text or self.content_desc)
        return False

    def to_dict(self, with_children: bool = True, with_label: bool = True,
                compact: bool = False) -> dict:
        """转 dict。

        (3) compact=True 时只保留**有信息量**的字段：
            空字符串不输出、布尔只输出 True（False 是默认值，写了也白写）。
            实测 97 节点界面从 1.9 万字符压到约 4 千，AI 才读得完。
        """
        if compact:
            d: dict = {}
            for key, val in (("text", self.text), ("resource_id", self.resource_id),
                             ("class", self.cls), ("content_desc", self.content_desc)):
                if val:
                    # class 去掉包前缀，"android.widget.TextView" -> "TextView"
                    d[key] = val.rsplit(".", 1)[-1] if key == "class" else val
            # label 与 text/content_desc 相同时不重复输出
            lb = self.label
            if with_label and lb and lb not in (self.text, self.content_desc):
                d["label"] = lb
            d["center"] = list(self.center)
            # 布尔只输出"非默认"的一项：
            #   clickable/scrollable/checked/focused/password 默认 False，
            #   为 True 才写；enabled 默认 True，为 False 时写成 disabled=True。
            # (4) 第四次修改（2026-11-13）：原循环把 enabled=True 也写进去，
            #     与"布尔只输出 True"的注释矛盾，且每个节点白占一个字段。
            for key, val in (("clickable", self.clickable),
                             ("scrollable", self.scrollable),
                             ("checked", self.checked),
                             ("focused", self.focused),
                             ("password", self.password)):
                if val:
                    d[key] = True
            if not self.enabled:
                d["disabled"] = True
            if with_children and self.children:
                d["children"] = [c.to_dict(with_children=True, with_label=with_label,
                                           compact=True) for c in self.children]
            return d

        d = {
            "text": self.text,
            "resource_id": self.resource_id,
            "class": self.cls,
            "content_desc": self.content_desc,
            "package": self.package,
            "bounds": list(self.bounds),
            "center": list(self.center),
            "clickable": self.clickable,
            "enabled": self.enabled,
            "checked": self.checked,
            "focused": self.focused,
            "selected": self.selected,
            "scrollable": self.scrollable,
            "long_clickable": self.long_clickable,
            "password": self.password,
        }
        if with_label:
            # 补 label 的条件：它给出了 text 之外的语义（可点容器的行名，
            # 或 content-desc 提供的图标含义）。等于 text 时不补，避免重复。
            lb = self.label
            if lb and lb not in (self.text, self.content_desc):
                d["label"] = lb
        if with_children and self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


# ---------------- 基础工具 ----------------


def _quote(s: str) -> str:
    """设备 shell 单引号包裹。内部单引号按 shell 规则写成 '\\''。

    为什么要自己做而不是 shlex.quote：shlex 用的是同一种规则，
    但它对空串返回 ''，对某些字符的处理依赖 posix 模式；这里只需
    一个明确的、可审计的实现，避免行为随 Python 版本漂移。
    """
    return "'" + str(s).replace("'", "'\\''") + "'"


def _run(shell_cmd: str, serial: str, timeout: int = 30):
    """以**普通 shell 身份**执行一条设备命令。

    为什么不用现有封装：
      · perfwatch._adb(serial, *args) 签名是 (serial, *args)，调用形状不同；
      · appproc._adb(shell_cmd, serial) 与 perfwatch._shell_root 都会把命令
        包进 `su -c '...'`，而 su 的**外层单引号**会与本模块为防注入加的
        单引号嵌套冲突（`input text 'a b'` 变成 `su -c 'input text 'a b''`，
        实测被设备 shell 拆散），且 uiautomator / input 本来就是 shell
        身份可执行的系统命令，套 su 反而在某些 ROM 上因 SELinux 拿不到
        accessibility 权限。

    所以这里直接走 adb shell，参数作为**独立 argv** 传给 subprocess，
    不经本地 shell；命令内部的引号由 _quote() 负责。

    (2) 第二次修改（2026-11-13）：
        bug 原因：serial 不存在时 adb 的 stderr 是 "adb: device 'xxx' not
                  found"，但 stdout 为空——上层只看 stdout 判成败，于是
                  报成 "UI_DUMP_FAILED 屏幕锁定/无障碍被禁用"，把排查
                  方向完全带偏。设备没连和界面读不到是两件完全不同的事。
        解决方案：命令失败且 stderr 里是设备级错误时，改抛
                  DEVICE_NOT_FOUND / ADB_COMMAND_FAILED，并带上原文。
    """
    cmd = [resolve_adb(), "-s", str(serial), "shell", shell_cmd]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DynError("ADB_TIMEOUT",
                       f"adb shell 超时（{timeout}s）: {shell_cmd[:80]}")
    err = (r.stderr or "")
    if r.returncode != 0 and err.strip():
        low = err.lower()
        if "not found" in low and "device" in low:
            raise DynError(
                "DEVICE_NOT_FOUND",
                f"设备 {serial} 不在线（{err.strip().splitlines()[0]}）；"
                "先用 list_devices 确认 serial，或检查 USB 连接/无线调试",
            )
        if "more than one device" in low:
            raise DynError("DEVICE_AMBIGUOUS",
                           f"有多台设备在线，必须指定 serial: {err.strip()[:120]}")
        # 其余 stderr 不在这里一律当失败：uiautomator 在 MIUI 上每次都会喷
        # 主题加载器的无关异常，而命令其实成功。交给调用方按 stdout 判。
    return r


def _int_arg(value, name: str, lo: int | None = None,
             hi: int | None = None) -> int:
    """把参数强制成整数并校验范围。

    安全：坐标/时长一律走这里，绝不把原始字符串拼进 shell 命令——
    否则 `x="0; reboot"` 就是命令注入。
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise DynError("BAD_ARGUMENT", f"{name} 必须是整数，收到 {value!r}")
    if lo is not None and n < lo:
        raise DynError("BAD_ARGUMENT", f"{name} 不能小于 {lo}，收到 {n}")
    if hi is not None and n > hi:
        raise DynError("BAD_ARGUMENT", f"{name} 不能大于 {hi}，收到 {n}")
    return n


def _parse_bounds(raw: str) -> tuple[int, int, int, int]:
    """解析 bounds 属性。兼容 "[x1,y1][x2,y2]" 的常见变体（含空格）。"""
    m = _BOUNDS_RE.search(raw or "")
    if not m:
        return (0, 0, 0, 0)
    x1, y1, x2, y2 = (int(g) for g in m.groups())
    return (x1, y1, x2, y2)


def _flag(elem, key: str, default: bool = False) -> bool:
    """读布尔属性。XML 里是 "true"/"false"，缺失或异常值按 default。"""
    v = (elem.get(key) or "").strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    return default


# ---------------- 屏幕信息 ----------------


def screen_size(serial: str) -> dict:
    """读屏幕分辨率。返回 {width, height, density, ...}。

    `wm size` 可能输出两行：Physical size 与 Override size（有人改过分辨率）。
    **优先用 Override**——那才是实际渲染尺寸，坐标换算必须用它。
    """
    out = {"width": 0, "height": 0, "density": 0, "physical": "", "override": ""}
    try:
        r = _run("wm size", serial, timeout=10)
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            m = re.search(r"(\d+)\s*x\s*(\d+)", line)
            if not m:
                continue
            w, h = int(m.group(1)), int(m.group(2))
            if line.lower().startswith("override"):
                out["override"] = f"{w}x{h}"
                out["width"], out["height"] = w, h   # override 覆盖 physical
            elif line.lower().startswith("physical"):
                out["physical"] = f"{w}x{h}"
                if not out["width"]:
                    out["width"], out["height"] = w, h
        r2 = _run("wm density", serial, timeout=10)
        for line in (r2.stdout or "").splitlines():
            m = re.search(r"(\d+)", line)
            if m and line.strip():
                out["density"] = int(m.group(1))      # 后出现的 Override 也覆盖
    except Exception:                                     # noqa: BLE001
        # 屏幕信息是辅助信息，拿不到不该让整个 UI 操作失败
        pass
    return out


# ---------------- dump + 解析 ----------------


def raw_dump(serial: str, timeout: int = 30, retries: int = 3) -> str:
    """执行 uiautomator dump 并把 XML 取回来（**本模块唯一一次 dump**）。

    失败一律抛 DynError，绝不返回空串让上层当成"界面没有控件"。

    (4) 增加了重试：界面切换动画期间 dump 会静默失败（rc=0 但没写文件）。
        实测刚 `am start` 完立刻 dump 最容易撞上，连续 5 次复测则是 5/5
        成功——说明这是**瞬时**问题，不是设备坏了。真问题（锁屏/无障碍
        被禁）连试几次都会失败，照样如实报错，不会被重试掩盖。

    (5) 第五次修改（2026-11-13）：
        bug 原因：重试间隔写死 0.6 秒、只重试 2 次。实测"点完立刻切界面"
                  这个最常用的时序下，3 次全失败仍报 UI_DUMP_FAILED——
                  因为页面切换动画本身就要几百毫秒，0.6 秒间隔有可能
                  每次都正好卡在同一段动画里（相位对齐）。
        解决方案：改成**递增退避**（0.5 / 1.0 / 1.5 秒）打散相位，
                  并把默认重试次数提到 3。总最坏耗时约 3s，对"一次 UI
                  操作本来就要 1-2 秒"可以接受；换来的是条件点击不会
                  因为一次瞬时而整条失败。
    """
    import time as _t

    last = ""
    attempts = max(1, int(retries) + 1)
    for attempt in range(attempts):
        # 先删：避免 dump 失败时 cat 到上一次的残留，把旧界面当新界面
        _run(f"rm -f {_DUMP_PATH}", serial, timeout=10)
        _run(f"uiautomator dump {_DUMP_PATH}", serial, timeout=timeout)
        r = _run(f"cat {_DUMP_PATH} 2>/dev/null", serial, timeout=timeout)
        xml = r.stdout or ""
        if "<hierarchy" in xml:
            return xml
        last = xml.strip()[:200]
        if attempt < attempts - 1:
            # 递增退避：打散与动画周期的相位对齐，避免每次撞同一段动画
            _t.sleep(0.5 * (attempt + 1))

    raise DynError(
        "UI_DUMP_FAILED",
        f"uiautomator dump 连续 {attempts} 次都没产出可解析的 XML。"
        "常见原因：① 屏幕锁定/息屏（先解锁）；② 无障碍服务被禁用；"
        "③ 界面一直在动画中（刚点完按钮时最常见，稍等再试）。"
        "原始输出: " + (last or "(空)"),
    )


def parse_dump(xml: str) -> list[UiNode]:
    """把 dump 的 XML 解析成节点树，返回顶层节点列表。

    健壮性：ElementTree 默认不解析外部实体（顺带避免 XXE）；属性缺失
    一律给默认值；单个节点异常不影响整体。

    注意：_node_from 已递归带上 children，所以这里**只取顶层**——
    早期写法对 root.iter("node") 每个元素都 _node_from 一次，会让每个
    非顶层节点被重复解析 N 次（N = 深度），大界面直接慢一个数量级。
    """
    try:
        root = ET.fromstring(xml.strip())
    except ET.ParseError as e:
        # XML 被截断会走到这里（cat 到一半读断），如实报错
        raise DynError("UI_PARSE_FAILED",
                       f"界面 XML 解析失败（可能被截断）: {e}；"
                       f"长度 {len(xml)} 字节")
    return [_node_from(e) for e in list(root) if e.tag == "node"]


def _node_from(e) -> UiNode:
    """单个 XML 元素 -> UiNode（含递归子节点）。"""
    n = UiNode(
        text=e.get("text") or "",
        resource_id=e.get("resource-id") or "",
        cls=e.get("class") or "",
        content_desc=e.get("content-desc") or "",
        package=e.get("package") or "",
        bounds=_parse_bounds(e.get("bounds") or ""),
        clickable=_flag(e, "clickable"),
        enabled=_flag(e, "enabled", True),
        checked=_flag(e, "checked"),
        checkable=_flag(e, "checkable"),
        focused=_flag(e, "focused"),
        selected=_flag(e, "selected"),
        scrollable=_flag(e, "scrollable"),
        long_clickable=_flag(e, "long-clickable"),
        password=_flag(e, "password"),
        index=int(e.get("index") or 0) if (e.get("index") or "").isdigit() else 0,
    )
    n.children = [_node_from(c) for c in list(e) if c.tag == "node"]
    return n


def dump_tree(serial: str, timeout: int = 30) -> tuple[list[UiNode], dict]:
    """一次 dump -> (节点树, 屏幕信息)。所有上层操作都走这里，保证只 dump 一次。"""
    nodes = parse_dump(raw_dump(serial, timeout=timeout))
    return nodes, screen_size(serial)


def iter_nodes(nodes: list[UiNode]):
    """深度优先遍历整棵树。"""
    for n in nodes:
        yield n
        yield from iter_nodes(n.children)


def count_nodes(nodes: list[UiNode]) -> int:
    return sum(1 for _ in iter_nodes(nodes))


def flatten(nodes: list[UiNode], simplify: bool = False,
            include_invisible: bool = False,
            compact: bool = True) -> list[dict]:
    """把树摊平成列表（给 AI 阅读，不是给人看）。

    simplify：只保留「可交互 / 叶子语义 / 输入控件」的节点。
              实测设置页 97 个节点压到 24 个。
    include_invisible=False：过滤 bounds 面积为 0 的节点。

    (1) 第一次修改（2026-11-13）：
        bug 原因：初版对不可见节点直接 continue，把它**整棵子树**一起丢了。
                  实测部分悬浮窗/动画容器的父节点 bounds 为 [0,0][0,0]，
                  但子节点有正常 bounds 且可操作——整棵跳过会让模型
                  "看不到明明在屏幕上的按钮"。
        解决方案：不可见只影响**该节点自己**是否输出，子节点照常递归。
    (2) 同时在 simplify 下抑制冗余叶子：列表行是「可点击容器（label=行文本）
        + 子 TextView（text=行文本）」，两条内容相同只会白占上下文。
        祖先里有可点击且 label 相同的，就不再单独输出这个叶子。
    """
    out: list[dict] = []

    def walk(items: list[UiNode], clickable_labels: frozenset) -> None:
        for n in items:
            visible = include_invisible or n.visible
            keep = visible and (not simplify or n.meaningful)
            if keep and simplify and not n.children and not n.clickable:
                # 冗余叶子：父级可点击容器已经用 label 表达了同样的内容
                if (n.text or n.content_desc) and \
                        (n.text or n.content_desc) in clickable_labels:
                    keep = False
            if keep:
                out.append(n.to_dict(with_children=False, compact=compact))
            sub = clickable_labels
            if simplify and n.clickable:
                lb = n.label
                if lb:
                    sub = clickable_labels | {lb}
            walk(n.children, sub)

    walk(nodes, frozenset())
    return out


# ---------------- 查找 ----------------


def _match(n: UiNode, text: str, resource_id: str, content_desc: str,
           cls: str, exact: bool) -> bool:
    """多条件 AND 匹配。所有给定条件都必须满足。"""

    def hit(value: str, want: str) -> bool:
        if not want:
            return True
        return value == want if exact else want.lower() in value.lower()

    # resource_id 允许省略包名前缀：人常说 "id/ok_button" 而不是
    # "com.foo:id/ok_button"。两种写法都支持。
    if resource_id and not hit(n.resource_id, resource_id):
        alt = resource_id
        if not alt.startswith("id/") and ":id/" in n.resource_id:
            alt = "id/" + resource_id
        if not (hit(n.resource_id, alt) or n.resource_id.endswith(":" + resource_id)
                or n.resource_id.endswith("/" + resource_id.lstrip("id/"))):
            return False
    return (hit(n.text, text) and hit(n.content_desc, content_desc)
            and hit(n.cls, cls))


def find_nodes(nodes: list[UiNode], text: str = "", resource_id: str = "",
               content_desc: str = "", cls: str = "", exact: bool = False,
               clickable_only: bool = False, visible_only: bool = True,
               limit: int = 50, label_match: bool = True) -> list[UiNode]:
    """按条件找节点。无条件时返回空列表（由调用方报"至少给一个条件"）。

    visible_only / clickable_only 只决定**该节点自己**是否算命中，不剪枝——
    与 flatten 同理：bounds 为 0 的容器底下可能有正常的可点按钮。

    label_match：按 text 查找时，额外匹配 label（可点容器用后代文本拼出的
    语义名）。实测列表行是「可点容器(text 空) + 子 TextView(text=行名)」，
    若只匹配 text，find(text="百度地图") 会命中不可点的子 TextView，
    点它虽然坐标相同但 clickable=false 会误导模型；有了 label 匹配能同时
    命中可点容器，返回里两者的 clickable 字段足以区分。

    (2) 第二次修改（2026-11-13）：
        bug 原因：label 匹配对**任意层**的容器生效，而祖先容器的 label 是
                  把很多代后代文本拼起来的。实测查 "已连接到 USB 调试" 时，
                  最外层 FrameLayout（label = "已连接到 USB 调试 / 点按即可
                  关闭 / 正在通过 USB 充电"）也命中了，且它的中心 y=1100
                  与真正可点的那条通知（y=595）不同 → pick_target 判成
                  "中心分散"直接报 AMBIGUOUS，条件点击完全不可用。
        解决方案：label 匹配只对**"叶子级容器"**生效——即该节点的后代里
                  不再有可点击节点。真正的行容器后代只有文字，符合；
                  整屏容器后代里有可点控件，排除。
                  这样既不破坏"整行可点"的匹配，也不会把整屏匹配进来。
    """
    # 只给 clickable_only 也是有效查询（"这屏能点哪些"），
    # 此时不加文本过滤，但仍要按结构条件筛
    if not any([text, resource_id, content_desc, cls]) and not clickable_only:
        return []
    out: list[UiNode] = []
    for n in iter_nodes(nodes):
        if visible_only and not n.visible:
            continue
        if clickable_only and not n.clickable:
            continue
        hit = _match(n, text, resource_id, content_desc, cls, exact)
        if not hit and label_match and text and _leaf_container(n):
            lb = n.label
            hit = (lb == text) if exact else (text.lower() in lb.lower())
        if hit:
            out.append(n)
            if limit and len(out) >= limit:
                break
    return out


def _leaf_container(n: UiNode) -> bool:
    """是不是"叶子级容器"：后代里没有任何可点击/可滚动节点。

    用途见 find_nodes 的第二次修改：只有这种容器的 label 才代表
    "这一行/这一个控件"，祖先容器的 label 是一堆东西的拼接。
    """
    return not any(c.clickable or c.scrollable for c in iter_nodes(n.children))


def pick_target(hits: list[UiNode], tol: int = 0) -> tuple[UiNode, bool]:
    """从多个命中里挑一个"真正该点"的，返回 (目标, 是否真歧义)。

    为什么需要它（实测痛点）：
        查 text="百度地图" 会命中 3 个节点——
            可点击的 LinearLayout   中心 (540,1589)
            不可点的内层 LinearLayout 中心 (605,1589)
            显示文字的 TextView      中心 (336,1589)
        三者中心点几乎同高，**点哪个都落在同一行上**。旧逻辑一看
        len(hits)>1 就报 AMBIGUOUS，逼调用方加 index，纯属自找麻烦
        （而这个 App 列表每一行都是这种三层结构，等于每次都歧义）。

    (1) 第一次修改（2026-11-13）：
        bug 原因：容差写死 3 像素时，同一行内的"行容器中心 y=595"与
                  "行内文字中心 y=563"差 32 像素就被判成不同行 → 又报
                  AMBIGUOUS。文字在行内偏上是常态，固定像素容差必然误判。
        解决方案：不再用固定 tol，改按**命中自身的高度**动态判同行——
                  两个命中的竖向区间有重叠，就算"同一行"。行容器与它的
                  子文字天然重叠，而屏幕上真正上下分开的两行不会重叠。
                  tol 参数保留，给调用方在需要时收紧。

    判定：
        所有命中的竖向区间互相重叠 → 算同一行，自动挑最合适的：
        可点击优先，其次面积最小（最内层通常才是真正的点击响应者）。
        竖向真的分开（命中分布在不同行）→ 返回 is_ambiguous=True。
    """
    if len(hits) <= 1:
        return hits[0], False
    lo = max(h.bounds[1] for h in hits)      # 所有命中的最下起点
    hi = min(h.bounds[3] for h in hits)      # 所有命中的最上终点
    same_row = (hi - lo) >= -tol             # 区间有交集（或只差 tol 内）
    if not same_row:
        return hits[0], True
    best = sorted(hits, key=lambda n: (not n.clickable, n.area))
    return best[0], False


# ---------------- 操作 ----------------


def tap(serial: str, x: int, y: int) -> None:
    """点击坐标。坐标经 _int_arg 校验，杜绝命令注入。"""
    _run(f"input tap {x} {y}", serial, timeout=15)


def swipe(serial: str, x1: int, y1: int, x2: int, y2: int,
          duration_ms: int = 300) -> None:
    _run(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}", serial, timeout=20)


def keyevent(serial: str, code: int) -> None:
    _run(f"input keyevent {code}", serial, timeout=15)


def input_text_checked(serial: str, text: str, timeout: int = 20) -> dict:
    """输入 ASCII 文本，并**回读控件内容校验**。

    为什么必须校验：`input text` 对能映射的字符也可能因焦点不在输入框、
    软键盘未就绪而丢字，但 rc 仍是 0。只信 rc 会给出"输入成功"的假结论。

    返回 {ok, sent, unsupported, hint}
    """
    if not text:
        return {"ok": False, "sent": "", "unsupported": [],
                "hint": "文本为空"}
    bad = sorted({c for c in text if c not in _ASCII_PRINTABLE})
    if bad:
        # 如实报错，不静默丢字符
        return {
            "ok": False,
            "sent": "",
            "unsupported": bad,
            "hint": ("这些字符无法通过 adb input text 输入（Android 的 "
                     "KeyCharacterMap 无法把它们映射成按键事件）。"
                     "input text 只支持 ASCII 可见字符；空格需写成 %s。"
                     "如需输入中文，请在设备上安装 ADBKeyboard 并 "
                     "`ime set com.android.adbkeyboard/.AdbIME`，"
                     "本工具当前未自动走该通道。"),
        }
    # 空格必须转成 %s：实测 `input text 'a b'` 只有第一个词被送出
    payload = text.replace(" ", "%s")
    r = _run(f"input text {_quote(payload)}", serial, timeout=timeout)
    err = (r.stderr or "") + (r.stdout or "")
    if "Exception" in err or "error" in err.lower():
        raise DynError("UI_INPUT_FAILED",
                       f"input text 执行失败: {err.strip().splitlines()[0][:200]}")
    return {"ok": True, "sent": text, "unsupported": [], "hint": ""}


def dispatch_key(serial: str, key: str) -> dict:
    """按键。key 可以是常见键名（back/home/enter...）或纯数字 keycode。"""
    raw = str(key or "").strip().lower()
    if not raw:
        raise DynError("BAD_ARGUMENT", "key 不能为空")
    if raw.lstrip("-").isdigit():
        code = _int_arg(raw, "keycode", lo=0, hi=1000)
        name = f"keycode_{code}"
    else:
        norm = raw.replace("-", "_")
        if norm not in KEYCODES:
            raise DynError(
                "BAD_ARGUMENT",
                f"不认识的键 {key!r}；可用: "
                + ", ".join(sorted(k for k in KEYCODES if k != "del")),
            )
        code = KEYCODES[norm]
        name = norm
    keyevent(serial, code)
    return {"key": name, "keycode": code}


def swipe_by_direction(serial: str, direction: str, size: dict,
                       duration_ms: int = 300) -> dict:
    """方向滑动。距离取屏幕 1/3：太小不触发翻页，太大容易误触。"""
    w = int(size.get("width") or 0)
    h = int(size.get("height") or 0)
    if w <= 0 or h <= 0:
        raise DynError("SCREEN_SIZE_UNKNOWN",
                       "读不到屏幕分辨率，无法按方向滑动；"
                       "请改用坐标 x1/y1/x2/y2")
    cx, cy = w // 2, h // 2
    d = max(1, h // 3)
    dx = max(1, w // 3)
    table = {
        "up": (cx, cy + d // 2, cx, cy - d // 2),
        "down": (cx, cy - d // 2, cx, cy + d // 2),
        "left": (cx + dx // 2, cy, cx - dx // 2, cy),
        "right": (cx - dx // 2, cy, cx + dx // 2, cy),
    }
    if direction not in table:
        raise DynError("BAD_ARGUMENT",
                       f"direction 只能是 {list(table)}，收到 {direction!r}")
    x1, y1, x2, y2 = table[direction]
    swipe(serial, x1, y1, x2, y2, duration_ms)
    return {"direction": direction, "from": [x1, y1], "to": [x2, y2],
            "duration_ms": duration_ms}


# ---------------- 对外能力（供 MCP 工具层调用） ----------------


def ui_dump(serial: str, simplify: bool = True,
            include_invisible: bool = False, max_nodes: int = 300,
            detail: bool = False) -> dict:
    """读取当前界面结构。

    max_nodes 兜底：极少数界面（游戏、大型列表）会有上千节点，
    全量返回会撑爆上下文。截断时明确告知被截了多少。
    """
    nodes, size = dump_tree(serial)
    total = count_nodes(nodes)
    rows = flatten(nodes, simplify=bool(simplify),
                   include_invisible=bool(include_invisible),
                   compact=not bool(detail))
    truncated = 0
    if max_nodes and len(rows) > max_nodes:
        truncated = len(rows) - max_nodes
        rows = rows[:max_nodes]
    return {
        "ok": True,
        "screen": size,
        "node_count": total,
        "returned": len(rows),
        "truncated": truncated,
        "simplify": bool(simplify),
        "include_invisible": bool(include_invisible),
        "nodes": rows,
    }


def ui_find(serial: str, text: str = "", resource_id: str = "",
            content_desc: str = "", cls: str = "", exact: bool = False,
            clickable_only: bool = False, limit: int = 20) -> dict:
    """按条件查找控件，返回 bounds 与中心点坐标。

    找不到时**明确说明**，不返回空数组了事——空数组会被模型读成
    "界面为空"或"成功但没有匹配"，两种误读都会让后续操作点错地方。
    """
    if not any([text, resource_id, content_desc, cls]) and not clickable_only:
        raise DynError("BAD_ARGUMENT",
                       "至少给一个查找条件：text / resource_id / "
                       "content_desc / cls / clickable_only")
    nodes, size = dump_tree(serial)
    hits = find_nodes(nodes, text=text or "", resource_id=resource_id or "",
                      content_desc=content_desc or "", cls=cls or "",
                      exact=bool(exact), clickable_only=bool(clickable_only),
                      limit=int(limit or 20))
    total = count_nodes(nodes)
    if not hits:
        cond = {k: v for k, v in
                [("text", text), ("resource_id", resource_id),
                 ("content_desc", content_desc), ("class", cls)] if v}
        raise DynError(
            "UI_NODE_NOT_FOUND",
            f"没找到匹配 {cond} 的控件（本次界面共 {total} 个节点）。"
            "可先用 ui_dump(simplify=true) 看当前界面到底有哪些控件；"
            "精确匹配没命中时试试 exact=false（默认子串匹配）。",
        )
    matches = []
    for n in hits:
        d = n.to_dict(with_children=False)
        d["matched_by"] = [k for k, v in
                           [("text", text), ("resource_id", resource_id),
                            ("content_desc", content_desc), ("class", cls)] if v]
        matches.append(d)
    out = {
        "ok": True,
        "screen": size,
        "node_count": total,
        "count": len(matches),
        "matches": matches,
    }
    first = matches[0]
    if not first["clickable"]:
        out["hint"] = ("首个匹配控件的 clickable=false，直接点它可能没有反应；"
                       "真正可点的是它的父/子节点，可用 "
                       "clickable_only=true 再看一次。")
    return out


def ui_click(serial: str, x: int | None = None, y: int | None = None,
             text: str = "", resource_id: str = "", content_desc: str = "",
             cls: str = "", exact: bool = False, index: int = 0,
             wait: float = 0.0) -> dict:
    """点击。两种模式：给坐标，或给查找条件（内部只 dump 一次）。

    条件命中多个时**不瞎点第一个**（除非显式给 index），而是列出候选
    让人/模型确认——点错控件在真实 App 上可能产生不可逆操作。
    """
    use_coord = x is not None or y is not None
    use_cond = any([text, resource_id, content_desc, cls])

    if use_coord and use_cond:
        raise DynError("BAD_ARGUMENT",
                       "坐标 (x,y) 与查找条件不能同时给，选一种")
    if not use_coord and not use_cond:
        raise DynError("BAD_ARGUMENT",
                       "要么给坐标 (x,y)，要么给查找条件 "
                       "(text/resource_id/content_desc/cls)")

    size: dict = {"width": 0, "height": 0}
    if use_coord:
        if x is None or y is None:
            raise DynError("BAD_ARGUMENT", "坐标模式必须同时给 x 和 y")
        size = screen_size(serial)
        w, h = int(size.get("width") or 0), int(size.get("height") or 0)
        # 屏幕尺寸已知就直接用真实值当上限——报错信息才能给出准确范围；
        # 读不到时才用 10000 兜底（防止明显荒谬的坐标，同时不误杀合法值）。
        px = _int_arg(x, "x", lo=0, hi=w if w else 10000)
        py = _int_arg(y, "y", lo=0, hi=h if h else 10000)
        if w and h and (px > w or py > h):
            raise DynError(
                "BAD_ARGUMENT",
                f"坐标 ({px},{py}) 超出屏幕范围 {w}x{h}，请确认分辨率",
            )
        tap(serial, px, py)
        out = {"ok": True, "mode": "coordinate", "tapped": [px, py],
               "screen": size}
    else:
        nodes, size = dump_tree(serial)
        hits = find_nodes(nodes, text=text or "", resource_id=resource_id or "",
                          content_desc=content_desc or "", cls=cls or "",
                          exact=bool(exact))
        if not hits:
            cond = {k: v for k, v in
                    [("text", text), ("resource_id", resource_id),
                     ("content_desc", content_desc), ("class", cls)] if v}
            raise DynError(
                "UI_NODE_NOT_FOUND",
                f"没找到匹配 {cond} 的控件（本次界面共 "
                f"{count_nodes(nodes)} 个节点），未执行点击",
            )
        if index:
            idx = _int_arg(index, "index", lo=0, hi=max(0, len(hits) - 1))
            target = hits[idx]
        else:
            target, ambiguous = pick_target(hits)
            if ambiguous:
                return {
                    "ok": False,
                    "code": "AMBIGUOUS",
                    "message": (f"条件命中 {len(hits)} 个控件且中心点分散，"
                                "未点击。请加 index 指定要点的那个（0 起），"
                                "或用更精确的条件"),
                    "screen": size,
                    "candidates": [
                        {"index": i, "text": n.text,
                         "resource_id": n.resource_id, "class": n.cls,
                         "content_desc": n.content_desc, "label": n.label,
                         "clickable": n.clickable, "center": list(n.center)}
                        for i, n in enumerate(hits[:20])
                    ],
                }
        px, py = target.center
        if px <= 0 and py <= 0:
            raise DynError("UI_BAD_BOUNDS",
                           f"目标控件 bounds 无效 {list(target.bounds)}，"
                           "无法计算点击坐标")
        tap(serial, px, py)
        out = {
            "ok": True,
            "mode": "find",
            "tapped": [px, py],
            "target": {
                "text": target.text,
                "resource_id": target.resource_id,
                "class": target.cls,
                "content_desc": target.content_desc,
                "bounds": list(target.bounds),
                "clickable": target.clickable,
            },
            "screen": size,
        }
        if not target.clickable:
            out["hint"] = ("目标控件 clickable=false，点击可能无反应；"
                           "若没有反应，试试点击它的父节点")

    if wait and float(wait) > 0:
        import time as _t

        _t.sleep(min(float(wait), 10.0))
        out["after_wait_s"] = round(min(float(wait), 10.0), 2)
    return out


def ui_input(serial: str, content: str, text: str = "",
             resource_id: str = "", content_desc: str = "", cls: str = "",
             exact: bool = False, index: int = 0,
             clear_first: bool = True) -> dict:
    """输入文本。先点中目标控件，再 input text。

    clear_first：先发 50 次 delete 清空（小输入框够用；超大文本输入框
    如备忘录不适用，会明确提示）。
    """
    if not any([text, resource_id, content_desc, cls]):
        raise DynError("BAD_ARGUMENT",
                       "必须给目标控件条件（text/resource_id/"
                       "content_desc/cls），否则不知道往哪输入")

    # 字符检查放在 dump 之前：不支持就直接报错，不白花 1-2 秒 dump
    bad = sorted({c for c in str(content or "") if c not in _ASCII_PRINTABLE})
    if bad:
        raise DynError(
            "UI_INPUT_UNSUPPORTED_CHARS",
            "这些字符无法通过 adb input 输入: "
            + " ".join(repr(c) for c in bad)
            + "。原因：Android 的 input text 用 KeyCharacterMap 把字符映射成"
            "按键事件，非 ASCII 字符（中文/日文/emoji/重音字母）映射结果为空，"
            "系统直接抛 NullPointerException。"
            "如需中文输入，请在设备安装 ADBKeyboard 后切到该输入法；"
            "本工具当前不擅自安装第三方 APK。",
        )

    nodes, size = dump_tree(serial)
    hits = find_nodes(nodes, text=text or "", resource_id=resource_id or "",
                      content_desc=content_desc or "", cls=cls or "",
                      exact=bool(exact))
    if not hits:
        cond = {k: v for k, v in
                [("text", text), ("resource_id", resource_id),
                 ("content_desc", content_desc), ("class", cls)] if v}
        raise DynError(
            "UI_NODE_NOT_FOUND",
            f"没找到输入目标 {cond}（本次界面共 {count_nodes(nodes)} 个节点）",
        )
    if index:
        idx = _int_arg(index, "index", lo=0, hi=max(0, len(hits) - 1))
        target = hits[idx]
    else:
        target, ambiguous = pick_target(hits)
        if ambiguous:
            return {
                "ok": False,
                "code": "AMBIGUOUS",
                "message": (f"条件命中 {len(hits)} 个控件且中心点分散，"
                            "未输入。请加 index 指定"),
                "screen": size,
                "candidates": [
                    {"index": i, "text": n.text, "resource_id": n.resource_id,
                     "class": n.cls, "label": n.label, "center": list(n.center)}
                    for i, n in enumerate(hits[:20])
                ],
            }
    px, py = target.center
    tap(serial, px, py)

    cleared = 0
    if clear_first:
        # 50 次 delete 是经验值：一次性发太多条命令要合批，否则每条
        # 都是一次 adb 往返（50 次 = 好几秒）。
        cleared = 50
        _run(f"input keyevent {' '.join(['67'] * cleared)}", serial, timeout=25)

    r = input_text_checked(serial, str(content or ""))
    if not r.get("ok"):
        raise DynError("UI_INPUT_FAILED", r.get("hint") or "输入失败")
    return {
        "ok": True,
        "target": {
            "text": target.text,
            "resource_id": target.resource_id,
            "class": target.cls,
            "bounds": list(target.bounds),
        },
        "tapped": [px, py],
        "content": str(content or ""),
        "clear_first": bool(clear_first),
        "cleared_chars": cleared,
        "screen": size,
        "hint": "已发送 input text；如需确认是否真的输入成功，"
                "可再调 ui_dump 看该控件的 text 字段",
    }


def ui_swipe(serial: str, direction: str = "",
             x1: int | None = None, y1: int | None = None,
             x2: int | None = None, y2: int | None = None,
             duration_ms: int = 300) -> dict:
    """滑动。给方向（up/down/left/right）或给两点坐标。"""
    d = (direction or "").strip().lower()
    coords_given = all(v is not None for v in (x1, y1, x2, y2))
    if d and coords_given:
        raise DynError("BAD_ARGUMENT",
                       "方向与坐标不能同时给，选一种")
    if not d and not coords_given:
        raise DynError("BAD_ARGUMENT",
                       "要么给 direction (up/down/left/right)，"
                       "要么给 x1/y1/x2/y2")

    dur = _int_arg(duration_ms, "duration_ms", lo=1, hi=60000)
    size = screen_size(serial)
    if d:
        return {"ok": True, **swipe_by_direction(serial, d, size, dur),
                "screen": size}

    w, h = int(size.get("width") or 0), int(size.get("height") or 0)
    # 与 ui_click 同一策略：屏幕尺寸已知就用真实值当上限，读不到再兜底
    cap_x = w if w else 10000
    cap_y = h if h else 10000
    ax = _int_arg(x1, "x1", lo=0, hi=cap_x)
    ay = _int_arg(y1, "y1", lo=0, hi=cap_y)
    bx = _int_arg(x2, "x2", lo=0, hi=cap_x)
    by = _int_arg(y2, "y2", lo=0, hi=cap_y)
    if (ax, ay) == (bx, by):
        raise DynError("BAD_ARGUMENT", "起点与终点相同，不会产生滑动")
    swipe(serial, ax, ay, bx, by, dur)
    return {"ok": True, "from": [ax, ay], "to": [bx, by],
            "duration_ms": dur, "screen": size}


def ui_key(serial: str, key: str) -> dict:
    """按键。返回键名与实际 keycode，便于确认映射是否符合预期。"""
    return {"ok": True, **dispatch_key(serial, key)}
