# Android 设备 UI 操作能力（server/dyn/ui.py）

> 落地时间：2026-11-13
> 实测设备：M2002J9E（serial `3e2ff172`），MIUI V13.0.9.0.SJVCNXM，Android 12（SDK 31），arm64，已 root

## 为什么加这一组能力

mda 原有的能力都在 so 层面（反汇编、hook、内存读写）。但很多问题**必须先让设备
走到某个界面才能复现**——登录态、某个设置项、滑到第几屏。没有 UI 操作，这些前置
步骤只能靠人手点，AI 完全帮不上。

实现全部走 adb + uiautomator，**不注入目标进程**，因此对加固 App 不构成 hook 类
风控信号。

## 六个工具

| 工具 | 作用 | 关键参数 |
|---|---|---|
| `ui_dump` | 读当前界面结构（XML → 结构化 JSON） | `simplify=True`、`include_invisible=False`、`detail=False` |
| `ui_find` | 按条件找控件，返回 bounds + 中心点 | `text` / `resource_id` / `content_desc` / `cls`、`exact`、`clickable_only` |
| `ui_click` | 点击（坐标模式 或 条件模式） | `x,y` 或查找条件 + `index`、`wait` |
| `ui_input` | 输入文本（先点中目标，再 input text） | `content`、目标控件条件、`clear_first` |
| `ui_swipe` | 滑动 | `direction`（up/down/left/right）或 `x1,y1,x2,y2`、`duration_ms` |
| `ui_key` | 按键 | `key`（back/home/enter/del/up/down/recent…）或数字 keycode |

## 实测踩到的坑（这些会决定实现细节，改代码前务必先读）

### 坑 1：uiautomator dump 的退出码完全不可信

```
$ adb shell uiautomator dump /nonexistent/a.xml
UI hierchary dumped to: /nonexistent/a.xml     ← rc=0，但文件根本没写出来
$ adb shell ls /nonexistent/a.xml
ls: /nonexistent/a.xml: No such file or directory
```

**只信退出码会把"文件没写出来"当成成功**，然后 cat 到上一次的残留内容，
把旧界面当新界面。

判定必须是：**先 rm（清掉可能的残留）→ dump → cat → 能解析成 XML 才算成功**。

### 坑 2：MIUI 每次 dump 都在 stderr 喷无关异常

```
java.io.FileNotFoundException: /data/system/theme_config/theme_compatibility.xml
```

这是 MIUI 主题加载器的噪声，**不是 dump 失败**。成败只看 cat 出来的内容。

### 坑 3：`input text` 对非 ASCII 字符根本不可用

```
$ adb shell input text '你好'
java.lang.NullPointerException: Attempt to get length of null array
    at com.android.server.input.InputShellCommand.sendText(InputShellCommand.java:275)
rc=255
```

实测字符支持矩阵：

| 字符 | 结果 |
|---|---|
| `abc`、`a-b_c.d`、`a@b#1` | ✅ 正常 |
| `你好`、`日本語`、`🎉`、`é`、`ü` | ❌ rc=255，NPE |
| 空格（不加转义） | ⚠️ 只有第一个词被送出 |
| 空格写成 `%s` | ✅ 正常 |
| `&`/`\|`/`;` 不加引号 | ❌ 被设备 shell 当成命令分隔符（`/system/bin/sh: b: inaccessible or not found`） |

根因：`input text` 用 `KeyCharacterMap.getEvents()` 把字符映射成按键事件，
非 ASCII 字符映射结果为空数组 → 系统直接 NPE。**这是 Android 本身的限制，
不是转义没做好，换写法也绕不过去。**

**试过并失败的替代路径**（这台 MIUI 上）：

- ADBKeyboard：设备上没装（`pm list packages` 里没有），本工具不擅自安装第三方 APK
- `cmd clipboard set`：`No shell command implementation`（MIUI 把该子命令精简了）
- `service call clipboard 3 ...`（binder 直调）：Android 12 拒绝，
  返回 `Package does not belong to 502000`（需要是 focused app）
- `KEYCODE_PASTE`：keycode 存在（rc=0），但剪贴板里没有内容，无法作为输入通道

所以本模块对非 ASCII **如实报 `UI_INPUT_UNSUPPORTED_CHARS` 并列出具体是哪几个字符**，
不静默丢字符、不假装成功。

**要是真需要中文输入**：设备上装 ADBKeyboard 后
`ime set com.android.adbkeyboard/.AdbIME`，再发
`am broadcast -a ADB_INPUT_TEXT --es msg '<base64>'`。本模块预留了这条路，
但当前不自动走（涉及第三方 APK 安装，需用户同意）。

### 坑 4：simplify 的判据必须够狠，否则等于没压

初版判据是「有 text 或 content_desc 或 resource_id 或可点击」——`resource_id`
单独就能让节点通过。实测应用管理列表 **97 个节点里 62 个带 resource_id**，
压完还有 74 个，等于没压。

更糟的是：祖先容器的 label 是把**所有后代**文本拼起来的，于是每个上层容器都变成
`"返回 / 应用管理 / 99"`，压完 59 个且内容高度重复，模型读了反而更困惑。

最终判据（三类真正有用的节点）：

1. **可交互**：`clickable` / `long_clickable` / `scrollable` / `checkable` / `password`
2. **叶子语义节点**：自身有 text/content-desc 且**没有子节点**
3. **输入控件**：`EditText` 等——常常既无文本又不可点击，压掉就找不到输入框

中间的布局容器一律不返回。实测 **97 → 16**。

### 坑 5：可点击的是「行容器」，文字在子节点里

真实 App 列表每一行都是三层结构：

```
LinearLayout (clickable=true, text="")        ← 真正可点的
  └ LinearLayout (clickable=false, text="")
      └ TextView (text="百度地图")             ← 文字在这里
```

只按 text 输出，模型看到的是一堆"clickable=true 但没名字"的容器，
根本不知道点哪一行。

解决办法：`label` 属性——可点容器用**后代叶子文本**拼出语义名
（只取叶子，不取中间层，否则又会变成整屏拼接）。

### 坑 6：条件点击的"假歧义"

查 `text="百度地图"` 会命中 3 个节点，中心点：

```
可点击的 LinearLayout      (540, 1589)
不可点的内层 LinearLayout   (605, 1589)
显示文字的 TextView        (336, 1589)
```

**点哪个都落在同一行**。初版一看"命中多个"就报 AMBIGUOUS 逼调用方加 index，
而这个 App 列表每一行都是这种结构——等于每次都要加 index，纯属自找麻烦。

第二版按「中心 y 相差 ≤ 3 像素」判同行，结果又踩坑：行容器中心 `y=595`
与行内文字中心 `y=563` 差 32 像素，被判成不同行，**条件点击在通知栏上完全不可用**。

最终方案：**按竖向区间是否重叠判同行**。行容器 `[480,710]` 与文字
`[508,618]` 天然重叠；屏幕上真正上下分开的两行不会重叠。
同行的多个命中里，按「可点击优先 → 面积最小」挑一个。

### 坑 7：label 匹配曾把整屏容器匹配进来

祖先容器的 label 是多段后代文本的拼接。查「已连接到 USB 调试」时，
最外层 FrameLayout（label = `"已连接到 USB 调试 / 点按即可关闭 / 正在通过 USB 充电"`）
也命中了，且它的中心 y=1100 与真正可点的那条通知（y=595）不同 →
又被判成"中心分散"报 AMBIGUOUS。

解决：`_leaf_container()`——label 匹配只对「后代里不再有可点击节点」的容器生效。

### 坑 8：不可见节点不能连子树一起剪掉

初版对 `bounds` 面积为 0 的节点直接 `continue`，把它**整棵子树**一起丢了。
实测部分悬浮窗/动画容器的父节点 `bounds=[0,0][0,0]`，但子节点有正常 bounds
且可操作——整棵跳过会让模型"看不到明明在屏幕上的按钮"。

现在不可见只影响**该节点自己**是否输出，子节点照常递归。

### 坑 9：别误用现有 _adb 封装

- `perfwatch._adb(serial, *args)`：参数是 `(serial, *args)`，传 `(cmd, serial)`
  会得到 `adb: unknown command 3e2ff172`
- `appproc._adb(shell_cmd, serial)` 和 `perfwatch._shell_root()` 都会把命令包进
  `su -c '...'`，而 su 的外层单引号会与本模块为防注入加的单引号**嵌套冲突**
  （`input text 'a b'` 变成 `su -c 'input text 'a b''`，被设备 shell 拆散）
- uiautomator / input 本来就是 shell 身份可执行的系统命令，套 su 反而在某些
  ROM 上因 SELinux 拿不到 accessibility 权限

所以 ui.py 自己实现了 `_run()`，直接 `adb shell`，参数作为独立 argv 传给
subprocess，命令内部的引号由 `_quote()` 负责。

## 性能

| 操作 | 实测耗时 |
|---|---|
| `ui_dump`（含 dump + 解析 + 屏幕信息） | 2.7 ~ 3.1 s |
| `ui_find` | 2.7 s |
| `ui_click`（条件） | 2.7 s + tap |
| `ui_click`（坐标） | ~0.1 s（不 dump） |
| `ui_input`（含点击+清空+输入） | 4.0 s |

`uiautomator dump` 本身就占 1~2 秒。**所有带条件的操作内部只 dump 一次**，
`ui_click` 条件模式复用同一份快照算坐标，不会重复 dump。

## 输出体积（实测）

应用管理列表（97 节点）：

- `simplify=True`：16 节点，约 2.5 KB
- `simplify=False`：97 节点，约 15 KB

桌面（172 节点，时钟组件信息量大）：`simplify=True` 37 节点 / 7.9 KB。

## 安全

- 坐标/时长一律过 `_int_arg()` 强制转整数并校验范围
  （`x="0; reboot"` → `BAD_ARGUMENT`；`x=99999` → `x 不能大于 1080`）
- 落到设备 shell 的字符串一律 `_quote()` 单引号包裹 + 内部单引号转义
- `ui_key` 只接受白名单键名或数字 keycode，不接受任意字符串
- 不执行任何从参数拼出来的 shell 片段

## 错误码

| code | 含义 |
|---|---|
| `UI_DUMP_FAILED` | dump 连续几次都没产出可解析 XML（锁屏/无障碍被禁/一直在动画） |
| `UI_PARSE_FAILED` | XML 被截断或格式异常 |
| `UI_NODE_NOT_FOUND` | 找不到匹配控件，会带上条件与本次节点总数 |
| `UI_INPUT_UNSUPPORTED_CHARS` | 输入含非 ASCII 字符，会列出具体字符 |
| `UI_INPUT_FAILED` | input text 执行失败 |
| `UI_BAD_BOUNDS` | 目标控件 bounds 无效，算不出点击坐标 |
| `BAD_ARGUMENT` | 参数非法（非整数坐标、未知键名、既没条件也没坐标…） |
| `ADB_TIMEOUT` | adb shell 超时 |
| `AMBIGUOUS` | 命中多个且分布在不同行，附候选列表 |

## 回归测试

- `test_r83_android_ui_operations()`：形态检查（源码里有必要的机制、
  6 个工具都注册了、不硬编码第三方 App 包名）
- `test_r86_ui_parse_and_targeting()`：**行为**断言——构造节点验证 bounds
  解析、同行判定、可点击优先、simplify 压缩、参数注入拦截

R83 是形态检查，挡不住行为回退（把 pick_target 改回"命中多个就报歧义"，
R83 依然全绿）。**真正的守卫是 R86。**
