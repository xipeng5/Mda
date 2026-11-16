# mda 八项需求 — 可执行验收标准

> 编写日期：2026-11-13
> 设备：`3e2ff172`（M2002J9E，Android 12 / API 31，arm64，root），frida-server 17.23.3 与客户端版本一致
> 代码版本：working tree @ `472c1de` + 未提交的 server/ 目录迁移（46 删除 / 18 修改 / 19 新增）
> 既有回归：**639 通过 / 0 失败**（e2e 14 + dyn_runtime 26 + regressions 590 + shell_sample 9）

---

## 0. 先说结论：这份文档里哪部分是真的

我把工作分成两类，**不混在一起**：

| 类别 | 含义 | 本文档中的标记 |
|---|---|---|
| **已执行验证** | 我在本次会话里真的跑了命令/真机实验，贴出的数字是实测输出 | `[已执行]` |
| **建议的测试** | 我读代码判断「应当这样验收」，但没有跑过，或跑不了（能力不存在） | `[建议]` |

**总判定：NEEDS WORK（不是 DONE）。** 三条需求（`net_request_dump` / `dex_smali` / `read_std_container`）在代码库里**根本不存在**；
另有两条需求（PLT 精确性、MCP 包装层）存在**实测缺陷**。这不是「差不多能过」，是「验收会失败」。

### 现状判定表

| # | 需求 | 代码是否存在 | 实测判定 | 依据等级 |
|---|---|---|---|---|
| 1 | `net_request_dump`（抓真实出网 HTTP 请求） | ❌ 不存在 | 无法验收 | `[已执行]` 全库 grep + 103 工具名枚举 |
| 2 | `dex_smali`（jadx 失败时字节码降级） | ❌ 不存在 | 无法验收 | `[已执行]` 全库 grep |
| 3 | `read_std_container`（libc++ string/vector/map） | ❌ 不存在 | 无法验收，但 ground truth 已备好 | `[已执行]` grep + 真机布局探针 |
| 4 | hold 断点真暂停 | ✅ 存在 | **PASS** | `[已执行]` 真机 40 秒冻结实验 |
| 5 | hook 保护（防 ANR/崩溃） | ⚠️ 部分存在 | **PARTIAL** —— 有 RPC 超时/分批/崩溃归因，**无 hold 看门狗** | `[已执行]` 40 秒挂起无自动恢复 |
| 6 | 函数边界修复 | ✅ 存在 | **PASS（有保留）** —— 区间不重叠，但 91% 的 size 是推断值 | `[已执行]` 4 个样本量化 |
| 7 | PLT 地址精确性 | ⚠️ 有缺陷 | **FAIL** —— 50% 桩地址偏 8 字节 | `[已执行]` 三样本量化 + 修复方案验证 |
| 8 | 地址换算 | ✅ 存在 | **PASS（有条件）** —— 数学正确，但 MCP 包装层当前全断 | `[已执行]` 往返 + 降级路径 |

---

## 1. 一个必须先处理的阻断项（影响 45 个工具）

在验收任何一条需求之前，先说这个，因为它会让「看起来能用的工具」全部返回错误。

`[已执行]` 实测（6 个工具抽样，全部失败）：

```
read_typed(so_name="liblog.so", addr=0x5020, type_name="uint32")   → MODULE_UNAVAILABLE
read_string(so_name="liblog.so", addr=0x3187)                      → MODULE_UNAVAILABLE
read_pointer(so_name="liblog.so", addr=0x2cd0)                     → MODULE_UNAVAILABLE
resolve_br(so_name="liblog.so", addr=0x5020)                       → MODULE_UNAVAILABLE
suggest_breakpoints(so_name="liblog.so", function="create_android_logger") → MODULE_UNAVAILABLE
read_jump_table(so_name="liblog.so", table_static_addr=0x30fd8)    → MODULE_UNAVAILABLE

错误内容统一是：
{"error": "dyn.memread 尚不可用：ModuleNotFoundError: No module named 'dyn'",
 "code": "MODULE_UNAVAILABLE", "available": false,
 "hint": "该模块由并行开发提供，落地后本工具自动生效，无需改动 tools.py"}
```

注意那个 `hint` 是**误导性的** —— 它说「模块由并行开发提供」，暗示「等别人做完就好」。
实际模块**早就在** `server/dyn/memread.py` 里，只是字符串路径写错了。这个 hint 会把排查引向错误方向。

**根因**：`server/mcp_server/tools.py` 里有 48 处 `_load_dyn_module("dyn.memread", ...)` 这类**惰性字符串导入**，
写的是迁移前的顶层包名 `dyn.X`。而代码已经整体搬进 `server/dyn/`，真实模块名是 `server.dyn.X`。

```
[已执行] .venv/bin/python -c "import dyn.memread"        → ModuleNotFoundError
[已执行] .venv/bin/python -c "import server.dyn.memread" → OK
```

**量化**：

```
[已执行] 注册工具 103 个
         引用旧路径 dyn.X 的函数: 48 个（48 个调用点，一对一无重复）
         引用新路径 server.dyn.X 的函数: 31 个
         两者都引用（能靠新路径降级工作）: 3 个 —— hit_analysis / locate_runtime_addr / probe_vm_from_hits
         → 只引用旧路径、当前必然报 MODULE_UNAVAILABLE 的: 45 个
```

**这不是能力缺陷，是包装层缺陷**：绕过包装层直调 dyn 层，同一功能是好的。

```
[已执行] from server.dyn.memread import read_typed
         read_typed(SoFile('samples/liblog.so'), 0x2cd0, "uint32")
         → {'ok': True, 'value': 1632914214, 'section': '.rodata', ...}

[已执行] read_typed(SoFile('samples/device/libc.so'), 0x97a80, "uint32", source="runtime", rb=rb)
         → {'ok': True, 'value': 3573752639, 'raw_hex': '3f2303d5', 'source': 'runtime'}
         （与本地文件 0x97a80 处字节完全一致 → 换算与读取都对）
```

**为什么 639 项测试没抓到**：

`[已执行]` 两个原因，缺一不可：

1. **测试根本不走这条路径**。`grep -rn "load_dyn_module\|MODULE_UNAVAILABLE" tests/*.py` → **0 命中**。
   测试全部是 `from server.dyn.X import ...` 直调（`test_regressions.py:43/98/115/128` 都是这种写法），
   而生产代码走的是 `_load_dyn_module("dyn.X")` 字符串导入。**两条路径完全不同，测试覆盖不到生产路径。**
2. **R32/R50/R56 只看形状不看行为**。它们核对「工具是否注册」「参数签名是否对齐」，
   从不真的调用一次工具。所以「工具在表里、签名对得上、但一调就报错」这类问题完全不可见。

这正是 `test_regressions.py` 开头自己写的那个教训的翻版：
> StubDebugger 比真实实现**宽容**，导致关键对立状态从未被构造过。

现在多了一条同类型的：**测试直接 import 比生产用的字符串 import 更宽容**。

### 阻断项验收场景

**A0.1 工具导入路径必须与真实包名一致** `[建议]`

- 前置：仓库处于 server/ 迁移后的状态
- 步骤：遍历 `tools.py` 中所有 `_load_dyn_module(<name>, ...)` 的 `<name>`，对每个执行 `importlib.import_module(<name>)`
- 期望：**全部成功**；任何一个失败即验收不通过
- 期望的错误做法：把这条写成「检查字符串是否以 server. 开头」（那是测实现不是测行为）

**A0.2 每个注册工具至少真调用一次** `[建议]`

- 前置：设备就绪，进程可 attach
- 步骤：对 103 个工具各构造一组「最小合法参数」（静态类工具用 `samples/liblog.so`；动态类用 `com.android.contacts` pid）；
  逐个调用，收集返回
- 期望：**没有任何一个返回 `code == "MODULE_UNAVAILABLE"`**；
  允许的失败是业务性失败（如 `MODULE_NOT_LOADED` / `BAD_ALIGNMENT`），因为它们证明包装层已经走到 dyn 层
- 边界：动态类工具在无设备环境下应返回明确的 `NEEDS_FRIDA` 而不是 `MODULE_UNAVAILABLE` —— 两者含义完全不同，不能混

**A0.3 打包版必须能跑同一个工具** `[建议]`

- 前置：`dist/MDA.app` 或重新打包
- 步骤：在打包产物内执行 A0.2 的抽样（至少 `read_typed` / `resolve_br` / `locate_runtime_addr`）
- 期望：与源码环境行为一致
- `[已执行]` 现状提示：`dist/MDA/_internal/dyn/` 与 `/Applications/MDA.app/Contents/Resources/dyn/` 里**只有 `device/` 子目录，没有任何 .py**，
  而 `packaging/mda.spec` 声称 `_scan_pkg_modules(ROOT, "server/dyn")`。打包版是否真能工作目前**未验证**，不要假设它行

---

## 2. 需求 1：`net_request_dump`（抓真实出网 HTTP 请求）

### 现状

`[已执行]` 判定：**能力不存在**。

```
全库 grep "net_request_dump"                          → 0 命中（server/ docs/ web/ tests/ README.md）
103 个已注册工具枚举                                   → 无 net/http/request 类抓包工具
唯一相关的是 probe_network_processes                  → 只统计 /proc/<pid>/fd 里 socket 数量，不抓内容
```

已有的可复用底座（这是好消息，说明不需要从零搭）：

| 底座 | 状态 | 证据 |
|---|---|---|
| Java bridge 自动注入 | ✅ 可用 | `[已执行]` `bridge_status()` → `{ok: True, path: .../frida_tools/bridges/java.js}` |
| 运行时类枚举 | ✅ 可用 | `[已执行]` `java_find_classes(7674, pattern="OkHttp|URLConnection|HttpClient|Request")` → `total: 22481` 个类，返回真实类名如 `com.android.ims.rcs.uce.request.CapabilityRequest` |
| 设备出网 | ✅ 正常 | `[已执行]` `adb shell curl -m 4 https://example.com` → HTTP `200` |
| 多进程识别 | ✅ 可用 | `probe_network_processes` 已实现，用于找出哪个 pid 在跑网络 |

### 验收场景

**A1.1 抓到一个真实的请求行（URL + method）** `[建议]`

- 前置：
  1. 设备 root，frida-server 版本与客户端一致（`preflight` 的 `version_match` 必须为 true）
  2. 选定一个**会主动出网**的前台 app，且该 app 用的是 Java 层网络栈（OkHttp / HttpURLConnection / HttpClient 之一）
  3. 用 `probe_network_processes` 确认目标进程（注意：实测闲鱼这类 app 有 4 个进程都在跑网络，要逐个确认）
- 步骤：
  1. 启动 `net_request_dump`，指定 pid
  2. 在 app 里触发一次明确的操作（下拉刷新 / 打开某个列表页）
  3. 读取 dump 结果
- 期望：
  - 至少 1 条记录，`url` 是**完整 URL**（scheme + host + path + query），不是空串也不是占位符
  - `method` ∈ {GET, POST, PUT, DELETE, ...}，不是 `"UNKNOWN"`
  - **反向对照**：同时用 `adb shell` 侧抓一次（例如让设备走可控代理），两边的 URL 必须对得上。
    只有「工具说有请求」而没有外部佐证，不算验收通过
- 反例（必须判失败）：
  - 返回 `{"requests": []}` 但 app 界面明明加载出了新数据 → 说明 hook 打偏了（挂到 `onCreate` 而非真正发请求的方法）
  - URL 是 `"https://example.com"` 这种样板值 → 假数据，直接红线

**A1.2 请求体与响应码** `[建议]`

- 前置：找到一个 POST 接口
- 步骤：触发 POST，读 dump
- 期望：`body` 字段有内容且**看起来是真实业务数据**（JSON 键名与 app 功能吻合）；
  `status_code` 是真实 HTTP 码（200/401/500 等），不是恒为 0
- 边界：POST body 可能是 gzip / protobuf / 加密二进制 —— **此时不许假装解出来**。
  正确行为是给 `body_hex` + `body_encoding: "binary"` 并明确说明，而不是塞一段乱码当文本

**A1.3 不抓包时不得影响 app** `[建议]`

- 前置：选中一个**用户日常在用**的 app
- 步骤：挂上 dump → 正常使用 5 分钟 → 卸载 hook
- 期望：
  - app 无 ANR、无闪退（`adb logcat | grep -E "ANR in|FATAL EXCEPTION"`
    在实验前后各取一次，**新增行数必须为 0**）
  - 流量统计（`/proc/<pid>/net/dev` 或系统流量面板）与未 hook 时同量级，偏差 < 20%

### 边界与异常场景

| 场景 | 期望行为 | 为什么必须测 |
|---|---|---|
| app 用 native 网络栈（libcurl / 自研 so） | 明确返回「Java 层 hook 未捕获到请求」，并建议改走 `trace_app_startup` / native hook | 谎称「没请求」会让分析走错方向 |
| 目标进程无 Java 运行时（如 `logd`） | 返回明确错误码，**不是**空列表 | 空列表 = 假成功 |
| HTTPS + 证书固定（pinning） | 能抓到**发送前的明文参数**即可（hook 在拼装层而非 TLS 层）；不许声称能解密 TLS | 承诺做不到的事 |
| 请求量大（如 500 条/分钟） | 有上限与截断标记（`truncated: true`, `dropped: N`），不许静默丢 | 静默丢数据 = 假完整 |
| 多进程同时出网 | 按 pid 分开列，不许混成一锅 | 实测闲鱼 4 进程都有 socket |
| 进程在采集中途重启 | 明确报「目标已退出」，不是挂住不返回 | 见 R45 已有先例 |

### 回滚条件

1. 使用时导致目标 app **ANR 或闪退**（即使数据是对的）→ 立即回滚，先修稳定性
2. 抓不到任何真实请求但号称成功 → 回滚，这是红线（假数据）
3. 抓到的 URL/body 与外部对照**对不上** → 回滚，说明 hook 位置错
4. 采集期间目标进程功耗/流量异常升高 >50% → 回滚，检查 hook 是否放在了高频路径上

---

## 3. 需求 2：`dex_smali`（jadx 反编译失败时的字节码降级）

### 现状

`[已执行]` 判定：**能力不存在**。全库 grep `jadx|baksmali|smali|dexlib` 在 `server/` 下 **0 命中**
（只有 `.venv` 里 pygments 的 SmaliLexer，与本项目无关）。

但 **ground truth 通道已经打通**，这很关键 —— 意味着验收不需要「猜期望值」：

| 工具 | 本机状态 | 用途 |
|---|---|---|
| jadx | `[已执行]` `/opt/homebrew/bin/jadx`，版本 **1.5.5** | 制造「反编译失败」的样本 |
| apktool | `[已执行]` `/opt/homebrew/bin/apktool` | 产出 smali 作为对照真值 |
| java | `[已执行]` 17.0.12 | 两者都依赖 |
| 真机 APK | `[已执行]` `pm path com.android.contacts` → `/system/priv-app/MIUIIContacts/MIUIIContacts.apk`（31.5MB，2 个 dex） | 真实样本 |

### 实测出的「失败样本」清单（这是验收的靶子）

`[已执行]` 对 `MIUIIContacts.apk` 跑 jadx 普通模式：

```
jadx -d out --no-res --no-imports contacts.apk
→ ERROR - finished with errors, count: 1570
→ 生成的 6150 个 .java 里，793 个含 JADX ERROR 标记
```

具体失败形态（三种，验收要各覆盖一个）：

| 形态 | 真实样例 | 特征 |
|---|---|---|
| 方法体被整体跳过 | `miui/cloud/net/XHttpClient$HttpRequest.doHttpRequest` | 输出 `Method dump skipped, instruction units count: 463` + 抛 `UnsupportedOperationException("Method not decompiled")` |
| 代码反编译不正确 | 同文件 `doHttpRequest` 附近 | `Code decompiled incorrectly, please refer to instructions dump` |
| pass 级异常 | `androidx/recyclerview/widget/DiffUtil.java` | `JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor` |
| pass 级溢出 | 同上 | `JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor` |
| Kotlin 元数据 | `kotlinx/android/parcel/Parcelize.java` | `JADX ERROR: Error in decompile pass: KotlinMetadataDecompile` |

**降级后的期望内容也是实测的**（不是推测）：

```
[已执行] jadx -m fallback --show-bad-code -d out_fb --no-res contacts.apk
→ EXIT=0，同一方法 doHttpRequest() 输出了约 238 行原始指令，
   含 r0..r13 虚拟寄存器、goto L30、catch 注释、`r6 = 1024(0x400, float:1.435E-42)`

[已执行] apktool d -f -o smali_out contacts.apk
→ 14674 个 .smali 文件
→ smali_classes2/miui/cloud/net/XHttpClient$HttpRequest.smali 里
   .method public doHttpRequest()V / .locals 13 / 238 行指令
```

两条独立通道（jadx fallback 与 apktool）给出**同一数量级的指令数（238）**，可以互相校验。

### 验收场景

**A2.1 jadx 成功时不得降级** `[建议]`

- 前置：选一个 jadx 能正常反编译的类（如 `androidx/recyclerview/widget/DiffUtil` 的父类部分）
- 步骤：调 `dex_smali`（或等价入口）取该类的「源码视图」
- 期望：返回的是 **Java 源码**（有 `public class`、有 `if/for`），不是字节码；`mode == "java"`
- 反例：无论什么输入都返回字节码 → 说明降级逻辑恒真，属于功能没做

**A2.2 jadx 失败时必须降级到字节码，且内容可核对** `[建议]`

- 前置：用 `XHttpClient$HttpRequest.doHttpRequest` 这个**已证实 jadx 失败**的方法
- 步骤：
  1. 让工具对该方法取反编译结果
  2. 同时用 apktool 取 smali 作为对照
- 期望：
  - `mode == "smali"`（或 `"bytecode"`），并带 `reason` 说明 jadx 为什么失败（如 `"Method dump skipped"`）
  - 返回的指令行数在 **238 ± 10%** 区间内（与 apktool 真值对得上）
  - 至少能对上 3 个具体特征：`.locals 13` / `const/4` 系列 / `goto` 目标标签
- 反例：返回 `"decompile failed"` 就结束 → 这不是降级，是没做

**A2.3 降级结果必须标注「不可信程度」** `[建议]`

- 步骤：分别对「jadx 成功」「jadx 方法级失败」「jadx pass 级异常」三种情况取结果
- 期望：三者的 `confidence` / `degraded` 字段**互不相同**。pass 级异常可能影响整个类甚至相邻类，
  与「单方法跳过」不是同一风险等级，不许用同一个标记糊过去

### 边界与异常场景

| 场景 | 期望行为 |
|---|---|
| APK 有多个 dex（本样本 2 个） | 按 dex 分开定位，报告「方法在 classes2.dex」而不是只说「找不到」 |
| 方法名是混淆后的 `a()` | 用「类名 + 方法签名」定位，不用名字猜 |
| 输入是 .dex 单文件（不是 apk） | 同样支持；若只支持 apk 要明确报错 |
| 目标是加固壳的 dex（运行时解密） | 明确报「静态 dex 里没有这个方法，需运行时 dump」，不许返回空 |
| 方法体超大（>5000 指令） | 有截断标记，不许无声截断 |
| apktool 也不可用（环境缺 jar） | 报告环境缺失，不是报「反编译失败」 |

### 回滚条件

1. jadx 能成功时却走了降级路径 → 回滚（说明判定逻辑反了）
2. 降级输出的指令数与 apktool 真值偏差 >20% → 回滚（说明解析错了，数字看着像其实不是）
3. 把「找不到方法」和「方法存在但反编译失败」报成同一个错误 → 回滚
4. 降级输出里出现任何**推断/补全**的指令（如凭空补一个 `return`）→ 回滚，这是造假

---

## 4. 需求 3：`read_std_container`（正确解析 libc++ string/vector/map，注意 SSO 标志位）

### 现状

`[已执行]` 判定：**能力不存在**。

```
grep -rniE "vector|__tree|basic_string|SSO|string_view" server/ → 0 命中
read_typed 支持的类型: int8..int64, uint8..uint64, float, double, pointer（含别名 i32/u64/f32/ptr/void*）
                     —— 全是标量，无任何容器类型
```

### 但 ground truth 已经拿到（这是本条最有价值的部分）

`[已执行]` 用 NDK 27 编了一个 arm64 探针（源码存于 `tests/acceptance/probes/container_probe.cpp`），
推到设备上真跑，输出**真实内存布局**，不是从头文件推的：

```
sizeof(std::string)=24
sso.bytes (24 bytes): 0a68656c6c6f00000060a1b879000000a0fda2b879000000
                     ↑ 首字节 0x0a = 5<<1   ↑ 数据从 offset 1 开始（"hello"）
long.bytes (24 bytes): 510000000000000040000000000000000040a1b3790000b4
                      ↑ cap_=0x51        ↑ size_=0x40      ↑ data_ 指针
```

`[已执行]` 另跑一个 SSO 边界扫描（`probes/sso_boundary.c`），0..32 字符逐个看首字节：

```
n= 0 first_byte=0x00 data_inside_obj=1 size=0  cap=22
n=21 first_byte=0x2a data_inside_obj=1 size=21 cap=22
n=22 first_byte=0x2c data_inside_obj=1 size=22 cap=22   ← SSO 上限
n=23 first_byte=0x21 data_inside_obj=0 size=23 cap=31   ← 转堆，首字节变 0x21
n=32 first_byte=0x31 data_inside_obj=0 size=32 cap=47
```

**由此确定的硬事实**（实现必须照这个来，不许照别的版本抄）：

| 事实 | 实测值 | 含义 |
|---|---|---|
| `sizeof(std::string)` | **24** | 3 个 8 字节字 |
| SSO 容量 | **22** 字符 | `(sizeof(__long)-1)/1 = 23`，实际可用 22 |
| long/short 标志位 | **首字节最低位**（`__size_ & 0x01`） | n=22 时 0x2c（偶数=short），n=23 时 0x21（奇数=long） |
| short 模式下长度 | **首字节 >> 1** | 0x2c>>1 = 22 ✓ |
| short 模式下数据起点 | **offset 1**（不是 0） | 编译用的是 ABI v1（`_LIBCPP_ABI_VERSION == 1`），**不是** `_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT` |
| `__long` 成员顺序 | `cap_` / `size_` / `data_` | 从 long.bytes 前两字 0x51/0x40 与末尾指针确认 |
| long 模式下首字节是什么 | **`cap_` 的最低字节**（不是 size） | short 的 `__size_` 与 long 的 `__cap_` 是 union 叠加；`__is_long()` 就是读首字节的最低比特 |
| cap 的低位标记 | `cap_ & 0x01 == 1` 表示 long | 实测 n=23 → 首字节 0x21（即 `cap_` 低字节=0x21），`capacity()` = `(0x21 & ~1) - 1` = 0x20-1 = **31**，与实测 31 一致 |
| cap 的换算 | `capacity() = (cap_ & ~1) - 1` | n=32 → 首字节 0x31（cap_ 低字节=0x31）→ 0x30-1=**47**，与实测 47 一致 |
| `vector` | `begin_` / `end_` / `end_cap_` 三指针 | `vector.bytes` 三个指针，前两个相同区间 |
| `map`(`__tree`) | `__begin_node_` / `__pair1_(__end_node)` / `__pair3_(size=3)` | `map.bytes` 末字 = 0x03 = size |

### 这里有个必须写进文档的坑

**同一个 Android 设备上可能同时存在两套 libc++ ABI 命名空间**：

```
[已执行] 设备 /system/lib64/libutils.so 的符号: _ZNSt3__112basic_string... （ABI v1，__1）
[已执行] 本机 NDK 27 编译的 so 用:               __ndk1（ABI v1 但命名空间是 __ndk1）
```

`_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT` 只在 `_LIBCPP_ABI_UNSTABLE || ABI_VERSION >= 2` 时启用。
**如果实现里写死「数据从 offset 0 开始」或「flag 在最高位」，在 Android 上就会全错。**
这正是需求里「注意 SSO 标志位」要防的事。

### 验收场景

**A3.1 短串（SSO）解析** `[建议]`

- 前置：目标进程里有一个长度 ≤22 的 `std::string`，内容是已知的（建议用自建探针，别用 app 的随机对象当断言依据）
- 步骤：对该对象地址调 `read_std_container(type="string")`
- 期望：返回值**逐字节等于**探针打印的原文；`size` 等于真实长度；`is_long == false`
- 反例：n=5 的 "hello" 被解析成 `"\x0ahello"` → 说明实现把首字节当数据了（没跳 flag）
- 反例：n=5 解析出 size=10 → 说明忘了 `>>1`

**A3.2 长串（堆分配）解析** `[建议]`

- 前置：一个长度 ≥23 的 `std::string`（如 64 个 'A'）
- 步骤：同上
- 期望：`is_long == true`；`size == 64`；`capacity == 79`
- **cap 的算法必须写清楚**（源码 `string:948`：`capacity() = (is_long ? __get_long_cap() : __min_cap) - 1`，
  `__get_long_cap() = cap_ & ~__long_mask`，`__long_mask = 0x1`）：
  实测 `cap_ = 0x51` → `0x51 & ~1 = 0x50 = 80`（这是分配字节数） → `80 - 1 = 79`（`capacity()` 返回值）
  - 常见错误 1：直接返回 `cap_`（得到 81）
  - 常见错误 2：忘了 `-1`（得到 80）
  - short 分支同理：`__min_cap - 1 = 23 - 1 = 22`，与实测 `cap=22` 一致
- 边界：**必须测 `n=22` 和 `n=23` 两个临界点**。只测 n=10 和 n=100 会漏掉 off-by-one，
  而 SSO 边界正是这类实现最常错的地方

**A3.3 vector 解析** `[建议]`

- 前置：`std::vector<int>` 含 3 个已知元素
- 步骤：调 `read_std_container(type="vector")`，给出元素类型 `int32`
- 期望：`size == 3`，元素值逐个匹配；`capacity >= size`；
  `(end_ - begin_) == size * 4`（自洽校验，防止把三个指针的顺序弄反）
- 反例：把 `end_cap_` 当成 `end_` 算 size → 会得到 capacity 而不是 size，字段顺序错就必然暴露

**A3.4 map 解析** `[建议]`

- 前置：`std::map<int,int>` 含 `{1:10, 2:20, 3:30}`
- 步骤：调 `read_std_container(type="map")`
- 期望：`size == 3`（从 `__pair3_` 末字读）；遍历出 3 对键值，且**按 key 升序**（红黑树中序）
- 边界：空 map（size=0）时不许崩、不许读野指针

### 边界与异常场景

| 场景 | 期望行为 | 注意 |
|---|---|---|
| `n=22`（SSO 满） | 解析为 short，data 在对象内 offset 1 | 最容易 off-by-one 的点 |
| `n=23`（刚转堆） | 解析为 long，data 是堆指针 | 与上一条必须是**不同分支** |
| 空串 `""` | size=0，返回空字符串，不报错 | 首字节 0x00，`0x00 & 1 == 0` → short ✓ |
| 字符串内容非 UTF-8（二进制 key） | 返回 `raw_hex` + `lossy: true`，不抛异常 | 网络场景里到处都是二进制 |
| 非法指针（地址不可读） | 明确 `READ_FAILED`，不返回空串 | 空串会让下游以为「值确实是空」 |
| `size` 字段明显异常（如 >10MB） | 拒绝读取并报 `SIZE_SUSPICIOUS`，附实测可疑值 | 防止偏移填错时把进程内存读爆（`dump_vm_state` 已有同类保护，应一致） |
| ABI 是 v2（`_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT`） | 必须能识别并切换布局，或明确报「不支持的 ABI 变体」 | 不许用 v1 的规则硬解 v2 数据然后返回乱码 |
| 32 位进程 | 指针 4 字节，string 大小不同 | 当前设备是 64 位，但工具不该假设 |

### 回滚条件

1. **n=22 / n=23 两个临界点任一解析错误** → 立即回滚。这是本需求的核心，错这里等于没做
2. 任何情况下返回了「看起来对但实际是猜的」值（例如读失败后补空串）→ 回滚，红线
3. 遇到不认识的 ABI 变体时按 v1 硬解 → 回滚（宁可报错也不能给错数据）
4. 解析导致目标进程崩溃（读到非法地址未捕获）→ 回滚

---

## 5. 需求 4：hold 断点真暂停（**这条已经能验，且我验了**）

### 现状：PASS

`[已执行]` 我做了一个**自建靶子**（源码 `tests/acceptance/probes/hold_target.c`）：
`work()` 每 200ms 被调一次，每次往 stdout 打一行 `tick N`。
这样「线程有没有真的停住」可以用**外部可见的计数器**判定，而不是靠工具自述。

**实验一：hold 是否真暂停**

```
基线：  ticks = 229
设 hold 断点 @ hold_target_dyn+0x17e0 (work 入口), hold=true
→ {"set": true, "armed": true, "mechanism": "Interceptor", "runtime_addr": 0x6101ef77e0}
采样3次（间隔1秒）：229 / 229 / 229        ← 冻结
poll_events → {"type":"breakpoint_hit","held":true,"thread_id":12955,
               "context": {36 个寄存器, sp/pc/nzcv/x0..x28/fp/lr 齐全}}
resume → {"resumed": true, "woken": 1}
采样3次：230 / 230 / 230 → 之后恢复增长
```

**实验二：挂 40 秒会不会自己放开**

```
设 hold 断点后等 40 秒
→ 进程状态 S（不是 T，说明是 frida 挂住而非 SIGSTOP）
→ ticks 仍停在 91，3 次采样 91/91/91
→ 无任何自动放行事件
```

**实验三：detach_target 能否解冻**

```
detach_target(pid) → {"detached": true}
→ ticks 立刻恢复：157 → 163 → 168
```

**实验四：撤销断点后恢复**

```
remove_breakpoint → {"removed": true, "partial": false}
resume → woken: 1
→ ticks 持续增长：289 / 295 / 300 / 306
```

### 验收场景

**A4.1 hold 必须让线程真停住（用外部计数器判定）** `[已执行 ✅]`

- 前置：自建靶子进程运行中，`work()` 每 200ms 打一次计数
- 步骤：设 hold 断点 → 连续 3 次读计数（间隔 ≥1 秒）
- 期望：**3 次读数完全相同**；`poll_events` 的命中里 `held == true`
- 已实测：229/229/229，`held: true` ✅
- **判定要点**：不许只看 `held: true` 字段就认定成功 —— 那个字段是工具自己报的。
  必须有独立的外部信号（本例是 stdout 计数）

**A4.2 resume 必须真的放行** `[已执行 ✅]`

- 步骤：在 A4.1 的 paused 状态下调 `resume`
- 期望：`resumed == true`、`woken >= 1`，且**计数恢复增长**
- 已实测：`woken: 1`，计数 229→230 后继续 ✅

**A4.3 非 paused 状态下 resume 不许谎报成功** `[已执行 ✅]`

- 步骤：目标处于 attached（没挂住）时调 `resume`
- 期望：`{"resumed": false, "reason": "not_paused"}`
- 依据：`server/dyn/debugger.py` `resume()` 有该分支；`tests/test_regressions.py` R3 已锁定

**A4.4 detach 是最后的安全网** `[已执行 ✅]`

- 步骤：hold 挂住时直接 `detach_target`
- 期望：`detached: true`，且目标线程恢复运行
- 已实测：计数从冻结恢复增长 ✅
- **注意**：这是目前唯一能解冻的手段（见需求 5 的看门狗缺失）

### 边界与异常场景

| 场景 | 期望行为 | 实测状态 |
|---|---|---|
| 同一函数被 2 个线程同时命中 | 每个线程一个 token，`resume` 无参时全部放行（`woken == 2`） | `[建议]` 未测 |
| `resume` 传了不存在的 token | `{"resumed": false, "reason": "token_not_found"}` | `[建议]` 代码有该分支，未实测 |
| **前台 app 被 hold** | 5 秒内 ANR（Android input dispatch timeout） | `[建议]` **未测，且不该在没有用户同意时测** —— 会真把用户的手机搞出 ANR 弹窗 |
| hold 期间目标被杀 | 明确报「目标已退出」，不给假 hit | `[建议]` 未测 |
| 断点地址非 4 字节对齐 | `BAD_ALIGNMENT` + 提示最近合法地址 | `[已执行 ✅]` `0x17e1` → 报错并给出 `0x17e0`/`0x17e4` |
| 模块不存在 | `MODULE_NOT_LOADED` + 提示先调 modules() | `[已执行 ✅]` `libnosuch.so` → 明确报错 |
| 同地址重复下断 | 返回 `existing: true`，不重复挂钩 | `[建议]` 未测（代码有此逻辑） |

### 回滚条件

1. hold 命中后**既不冻住也不报错**（假成功）→ 回滚，这是 R1/R3 已经修过的老坑，复发即回滚
2. `resume` 报成功但计数不恢复 → 回滚
3. `held` 字段与实际冻结状态不一致 → 回滚（R1 就是这个问题）

---

## 6. 需求 5：hook 保护机制（防 ANR / 进程崩溃）

### 现状：PARTIAL —— 有一半，缺最关键的一半

`[已执行]` 已有的保护（读码 + 部分实测）：

| 保护机制 | 实现位置 | 效果 | 实测 |
|---|---|---|---|
| 单次 RPC 超时 5 秒 | `debugger.py: _RPC_TIMEOUT = 5.0` | 目标无响应时按失败返回，不卡调用方 | 读码确认 |
| 关闭时摘钩超时 2 秒 | `debugger.py: _CLOSE_RPC_TIMEOUT = 2.0` | `close()` 不会卡死 | 读码确认 |
| detach 丢守护线程 + 有限 join | `rebase.py` detach() | 规避 frida 17 已知的 `detach()` 永久阻塞 | 读码 + 实测 `detach_target` 正常返回 |
| resume 的 post 移到锁外 | `debugger.py` resume() | 跨进程 IPC 卡住时不会把整把锁带死 | 读码确认 |
| 假成功防护（hooks 表反查） | `service.py` set_breakpoint | `set: true` 不等于钩子真装上 | 读码确认 |
| 探针数量硬上限 4000 + 均匀采样 | `tracer.py` watch_module | 防止一次挂几百个探针把目标拖垮 | 读码；注释记载「实测 765 个直接崩进程」 |
| 分批 attach + 批间隔 | `tracer.py: batch_interval_ms=200` | 密集 patch 时给目标喘息 | 读码；注释记载「max_points=400 时崩过」 |
| 崩溃归因 | `tracer.py` | 区分「进程死了」与「代码没跑」，并给 `hint` 建议降 max_points | 读码；R45 已锁定 |
| vmbreak 达上限自动 detach | `vmbreak.py` `hitCount >= MAX_HITS` | 自动摘钩 | 读码确认 |
| 明确不用会崩目标的 API | `tracer.py` | `MemoryAccessMonitor.enable()` 注释写明「实测会让目标进程崩溃」 | 读码确认 |
| freeze 时限提示 | `adb.py` freeze_process | 返回 `hint`「建议 5 秒内解冻」 | `[已执行]` preflight/freeze 链路可用 |
| Stalker 危险警告 | `tracer.py` trace_code | 明确写「对 system_server 使用会导致系统重启」 | 读码确认 |

**缺失的关键一环：hold 断点没有看门狗 / 超时自动放行。**

`[已执行]` 证据：

```
grep -rniE "hold.?timeout|auto.?resume|watchdog|max_hold|release_after" server/
→ 只命中 adb.py:547 的一句注释（讲 freeze 的 ANR），没有任何 hold 超时实现

JS 侧 op.wait() 不带超时参数（debugger.py:189 就是裸的 op.wait()）

实测：hold 挂住 40 秒，ticks 停在 91 不动，无任何自动恢复
```

**后果**：如果 AI 忘记 `resume`，目标线程永久阻塞。
- 对后台进程：不致命（可能被系统回收）
- **对前台 app：5 秒后 ANR 弹窗**，用户会看到「应用无响应」

这是本条需求最该验收的点，而它现在是空的。

### 验收场景

**A5.1 hold 超过阈值必须自动放行（或至少显式告警）** `[建议，当前必然失败]`

- 前置：自建靶子（同 A4）
- 步骤：设 hold 断点 → 不做任何操作，等 30 秒
- 期望（二选一，实现方自己定但要写死）：
  - **方案 A（自动放行）**：到达阈值（建议 10~30 秒，前台可识别时更短）自动 resume，
    事件流里出现 `{"type":"auto_resumed","reason":"hold_timeout","held_ms":N}`
  - **方案 B（强告警）**：不放行，但 `poll_events` / `state()` 的返回里带
    `{"warning": "目标已挂起 N 秒", "risk": "前台 app 将在 5 秒内 ANR", "target_in_foreground": true}`
- **当前实测**：等 40 秒，什么都不会发生 → 本条 **FAIL**
- 边界：阈值不许是「无限」。`0` 或 `None` 表示不限 时要**显式写进参数说明**，不能是默认值

**A5.2 目标在前台时 hold 要额外降级** `[建议]`

- 步骤：对前台 app 设 hold 断点（**需要用户明确同意**，因为真会 ANR）
- 期望：工具在 `set_breakpoint` 的返回里就提示风险（现在有 `env.warning`，但讲的是「可能不命中」，
  不是「hold 会导致 ANR」——这是两个不同的风险，必须分开讲）
- 现状：`[已执行]` `set_breakpoint` 确实返回了 `env.warning`，内容为
  "你正在操作 xxx，但当前前台是 com.android.contacts...断点或 hook 装上了也可能永远不命中"
  —— **没有** ANR 风险提示

**A5.3 批量 hook 不许把目标拖垮** `[建议]`

- 前置：一个函数较多的 so（本机 `samples/device/libc_apex.so` 有 2754 个函数）
- 步骤：`watch_module` 用 `max_points=400`、`batch=20`、`batch_interval_ms=200`，跑 10 秒
- 期望：
  - 目标进程存活（前后 `probe_process` 都是 `alive: true, injectable: true`）
  - 返回里有 `recommendation`（含 `fail_rate`、`suggested_max_points`、`advice`）
  - 若目标真崩了，返回 `WATCH_FAILED` + 明确 hint「降低 max_points 或缩小 offset_range」，**不是**静默空结果
- 已读码确认这些机制都在（`tracer.py:2738` cap、`2842` 崩溃归因、`2947` recommendation）
- 未实测（会打断用户设备的进程，属高风险操作）

### 边界与异常场景

| 场景 | 期望行为 |
|---|---|
| 目标在 hold 期间被杀（OOM / 用户划掉） | 明确报「目标已退出」，`state()` 不能再报 `paused` |
| 同一 pid 反复 attach/detach 20 次 | 线程数不增长（R31 已锁定「曾实测 20 次泄漏 20 个线程」） |
| 摘钩失败（JS 侧无响应） | `remove_breakpoint` 返回 `partial: true` + 原因，不谎报 `removed: true` |
| 一次挂 >100 个断点 | 有上限或明确警告；不许默默挂到进程卡死 |
| freeze_process 超过 20 秒 | 已知会被 AMS 按 ANR 回收（`adb.py:547` 有注释）；工具应在 20 秒时告警或自动 unfreeze |
| 目标进程是 system_server | Stalker 路径必须拒绝或强警告（注释已写明曾导致系统重启） |

### 回滚条件

1. 任何 hook 操作导致目标 app **ANR 或闪退**，而工具没有事前告警 → 立即回滚
2. `set_breakpoint` 报 `armed: true` 但钩子实际没装上 → 回滚（假成功）
3. 目标崩溃后工具报空结果而非 `WATCH_FAILED` → 回滚
4. attach 泄漏线程（连续 20 次后线程数增长）→ 回滚

---

## 7. 需求 6：函数边界修复

### 现状：PASS（有保留）

`[已执行]` 对 4 个真实样本量化：

| 样本 | 函数数 | 区间重叠 | 零长函数 | `function_at(函数起点)` 抽样 300 次 |
|---|---|---|---|---|
| liblog.so | 111 | **0** | **0** | 300/300 返回自身 |
| libbase.so | 386 | **0** | **0** | 300/300 返回自身 |
| libcutils.so | 168 | **0** | **0** | 300/300 返回自身 |
| libc_apex.so | 2754 | **0** | **0** | 300/300 返回自身 |

**保留意见**：`libc_apex.so` 里 **2508/2754（91%）** 的函数 `size` 恰好等于「到下一个入口的间距」。
这说明这些 size 是**推断值**（`_refresh_functions` 用 gap 填满），不是 FDE 给出的真实边界。
后果：函数「看起来」有边界，但 `size` 不可信 —— 不能拿它做「函数是否被完整覆盖」的判断。

`[已执行]` 另一个已知取舍（代码注释已写明）：`aggressive=True` 会误报。

```
libbase.so：386 → 557（+171，全部 reason=prologue）
libcutils.so：168 → 173（+5）
```

注释自己写得很清楚：这 171 个是同一个 switch 的 case 块，不是真入口。**默认 `aggressive=False` 是对的**。

### 验收场景

**A6.1 区间必须互不重叠** `[已执行 ✅]`

- 步骤：加载样本，遍历 `sorted(so.functions)`，对每对相邻入口断言 `functions[a].end <= b`
- 期望：重叠数 **== 0**
- 已实测：4 个样本全部 0 ✅
- 依据：`elf_model.py:_refresh_functions` 的注释记载「抬到 0x10 会让区间互相重叠（实测 93 处重叠）」

**A6.2 function_at 对函数起点必须返回自身** `[已执行 ✅]`

- 步骤：随机抽 300 个函数起点，调 `function_at`
- 期望：300/300 返回 `f.addr == 该起点`，0 个返回外层函数，0 个返回 None
- 已实测：全部通过 ✅（这正是 BUG-17 / P1 的修法）

**A6.3 粗 FDE 必须按后出现的入口切开** `[建议]`

- 前置：找一个 FDE 边界明显粗于实际函数的样本（注释举例 `0x29b2d0..0x29c830`）
- 步骤：查该区间内每个 `bl` 目标，看是否被登记成独立函数
- 期望：区间内真实入口各自独立，`function_at` 对每个都返回正确的（内层）函数
- `[已执行]` 部分证据：`libc_apex.so` 有 41 个 `size >= 0x800` 的大函数，
  但**它们内部独立入口数都是 0** —— 说明在这个样本上没触发该场景，需要专门找样本

**A6.4 `add_function` 切开宿主后缓存必须失效** `[建议]`

- 步骤：对一个已有函数内部地址调 `add_function`，然后读宿主的 `instructions`
- 期望：宿主 `size` 被截断到新入口，且 `instructions == []`（缓存失效）
- 依据：`elf_model.py` 有 `host.instructions = []  # 边界变化 → 解码缓存失效`

### 边界与异常场景

| 场景 | 期望行为 | 实测 |
|---|---|---|
| 跳转表里相距 4 字节的紧邻入口 | 不许合并、不许给 size 设 0x10 下限 | 读码确认（注释明确写了这个坑） |
| 最后一个函数没有后继 | size 不许无限大；实测 `libc_apex` 最后函数 size=0x50c（0x10000 兜底未触发） | `[已执行]` |
| 节表被抹的壳样本 | 走段表模式，函数仍可发现（`liblog.so` 有节表，需专门用壳样本测） | `[建议]` 未测 |
| PLT 桩被登记成函数 | 必须剔除（`0x1a4140` 被调 1436 次霸榜的历史问题） | 读码确认逻辑在；**但见需求 7 的缺陷** |
| `aggressive=True` 的 case 块误报 | 必须可查（`by_reason` 里能看到 `prologue` 计数） | `[已执行]` 实测 +171 全部标注为 prologue ✅ |

### 回滚条件

1. 出现任何区间重叠 → 回滚（`function_at` 二分查找会返回错函数）
2. `function_at(函数起点)` 返回外层函数 → 回滚（BUG-17 复发）
3. 默认模式（`aggressive=False`）的误报率从 0 上升 → 回滚

---

## 8. 需求 7：PLT 地址精确性（**这条实测有缺陷**）

### 现状：FAIL

`[已执行]` 定位到具体代码行 `server/core/elf_model.py:435`：

```python
pending = (insn.operands[1].imm, insn.address & ~0xF, insn.operands[0].reg)
#                                  ^^^^^^^^^^^^^^^^^^^ 这里把 adrp 地址向下对齐到 16 字节
```

`insn.address & ~0xF` 做的是「向下取整到 16 字节」。当 adrp 本身就在 16 字节边界上时无害；
但 PLT 桩之间是 **16 字节步进**，而桩内的 `adrp` 位置在「桩头」或「桩头 + 8」两种排布之间摆动（取决于前面的 stub 用了几条 nop）。

**实测偏差（liblog.so，逐 4 字节反汇编 0xe010 起）**：

```
0xe010  adrp x16, #0xf000     ← plt_map: __cxa_finalize   （真桩头，对）
0xe014  ldr x17, [x16, #0x278]
0xe018  add x16, x16, #0x278
0xe01c  br x17
0xe020  nop                    ← plt_map: create_android_logger  （这是 nop，不是桩头！）
0xe024  nop
0xe028  adrp x16, #0xf000     ← 真正的桩头在这里，plt_map 里没有
0xe02c  ldr x17, [x16, #0x280]
0xe030  add x16, x16, #0x280
0xe034  br x17
0xe040  adrp x16, #0xf000     ← plt_map: calloc  （真桩头，对）
0xe050  nop                    ← plt_map: __memcpy_chk  （错）
0xe058  adrp x16, #0xf000     ← 真桩头
```

**量化（三个真机样本）**：

| 样本 | `plt_map` 条目 | 键是真桩头（首指令=`adrp x16`） | 键不是（+8 处才是） |
|---|---|---|---|
| liblog.so | 105 | **53** | **52** |
| libbase.so | 235 | **118** | **117** |
| libcutils.so | 174 | **87** | **87** |

**下游后果（这才是真问题）**：

```
[已执行] liblog.so .text 里 bl → .plt 区间的调用点共 450 个
         能解析出符号名的只有 193 个（42.9%）
         另 257 个调用的目标地址在 plt_map 里根本没有键

[已执行] 各样本解析率：
         liblog.so     450 个调用点 → 193 可解析（42.9%）
         libbase.so   1831 个调用点 → 694 可解析（37.9%）
         libcutils.so  844 个调用点 → 472 可解析（55.9%）
```

**这不是「少了一点信息」，而是「一半的导入调用在报告里显示为无名地址」** —— 分析时会误以为那些是内部函数。

**修复方案已验证**（`[已执行]` 我按 `insn.address` 为键重跑了一遍）：

| 样本 | bl→PLT 目标数 | 当前键命中 | 改为真桩头命中 | 修复后 plt_map 条目 |
|---|---|---|---|---|
| liblog.so | 103 | 51 | **103** | 105 |
| libbase.so | 219 | 107 | **219** | 235 |
| libcutils.so | 169 | 84 | **169** | 174 |

**100% 命中**，且条目总数不变（105/235/174，说明没有多解或少解，只是键值对错了位）。

**另一个相关问题**：`in_plt_stub()` 在**有节表**的样本上恒返回 False。

```
[已执行] liblog.so  .plt 区间内「adrp x16」位置 106 个（其中 0xdff8 属 PLT0 头部，符号桩 105 个）
         in_plt_stub 命中 0/106
         另两个样本同样为 0：libbase 0/236、libcutils 0/175
         原因：plt_stubs 只在 _sections_usable == False 时才填充
               （_scan_plt_stubs_by_segment 开头就 `if self._sections_usable: return`）
```

后果：`elf_model.py` 里那句「剔除落在任一桩 16 字节区间内的所有函数入口」在**有节表的样本上不生效**。
实测 4 个样本的「函数表中落在 .plt 内的入口数」都是 0，**且用半开区间 `[addr,end)` 判「与 .plt 真正重叠」也全是 0**
—— 说明在这个样本集上保护没被触发过，不是保护生效。换一个 FDE 边界更粗的样本（壳样本）就会暴露。

### 验收场景

**A7.1 每个 plt_map 的键必须指向真正的桩头** `[建议，当前必然失败]`

- 步骤：对三个样本，遍历 `plt_map` 每个键 `k`，反汇编 `so.read(k, 4)`
- 期望：首指令 **必须是 `adrp`，且第 1 个操作数是 `x16`**
- 当前实测：liblog 53/105 满足，52 个不满足 → **FAIL**
- 反例：用「键指向的 4 条指令里含 adrp」当判据 —— 那会放过所有错位的键，是**弱化判据**

**A7.2 bl→PLT 的调用点必须能解析出符号名** `[建议，当前必然失败]`

- 步骤：反汇编 `.text` 全部指令，收集所有 `bl #imm` 且 imm 落在 `.plt` 区间的目标；
  对每个目标查 `symbol_name()`
- 期望：**100% 能解析**（因为 `.rela.plt` 有全部重定位信息，这不是「靠猜」的场景）
- 当前实测：liblog 42.9% / libbase 37.9% / libcutils 55.9% → **FAIL**
- 允许的唯一例外：`.plt` 头部 PLT0（`0xdff0`，`bti c; stp ...`），它不属于任何符号，应在测试里显式排除

**A7.3 桩地址与 GOT 槽必须互相印证** `[建议]`

- 步骤：对每个桩，从桩内 `adrp` + `ldr` 解出 GOT 槽地址；用 `.rela.plt` 的 `r_offset` 反查符号名；两者必须一致
- 期望：100% 一致
- 说明：**这个测试若只对「已经是正确桩头」的条目做，会全部通过**（我实测那 53 个是对的）。
  所以必须**从 `plt_map` 的键出发**做，才能抓出偏移问题 —— 测试设计上要防这个自欺

**A7.4 `in_plt_stub` 在有节表样本上也要工作** `[建议，当前必然失败]`

- 步骤：加载 `liblog.so`（有节表），对 `.plt` 区间内每个真实桩头调 `in_plt_stub(addr)`
- 期望：**全部返回 True**
- 当前实测：0/106 → **FAIL**
- 关联断言：对一个 FDE 误登记在桩内部的地址（如 `stub+4`），`in_plt_stub` 也应返回 True（因为按区间判定）

### 边界与异常场景

| 场景 | 期望行为 |
|---|---|
| `.plt` 首部 PLT0 | 不属于任何符号（实测 `0xdff0` = `bti c; stp x16,x30,[sp,#-0x10]!`），不许塞一个猜的名字 |
| 桩用 `bti c` 开头（CFI） | 桩头判定要能容忍前导 `bti`。**注意**：三个样本里 `bti` 只出现在 PLT0 头部（各 1 处），符号桩一律直接 `adrp` 开头 —— 所以这条是**前瞻性要求，不是当前样本的需求**，别据它改判据 |
| 无节表壳样本 | 走段表扫描，只有地址没有名字 —— **不许编造符号名**（注释已写明这个原则） |
| 同一条 FDE 覆盖多个桩 | 不许把中间的 nop（`0xe020`/`0xe024` 这类）当成函数入口 |
| `.plt.sec`（新链接器会把桩分到独立节） | 要能处理；只认 `.plt` 会漏 |
| AArch64 与 AArch32 混用 | 桩模板完全不同；架构不匹配要明确报错 |

### 回滚条件

1. 修好 A7.1 后 `plt_map` 条目数**变化** → 回滚（说明改动影响了解析范围，不只是键）
2. 修好后出现 `symbol_name` 返回错符号（名字对不上 GOT）→ 回滚
3. 修复导致既有断言失效 → 这些断言里 `test_e2e.py:38` 写的是 `len(log.plt_map) == 105`。
   **条目数不应变**（liblog 105 / libbase 235 / libcutils 174 实测都是条目数=符号桩数），所以该断言应保持通过；
   若它变红，说明修复动到了解析范围而不只是键，按第 1 条回滚
4. 修复后 bl→PLT 解析率没到 100% → 说明还有别的偏移问题，不许当作「已修」

---

## 9. 需求 8：地址换算

### 现状：PASS（有条件）—— 数学对，但 MCP 包装层当前全断

`[已执行]` 往返一致性：

```
static=0x0        → runtime=0x72016a0000   → 回 static=0x0        往返一致=True  在模块内=True
static=0x5020     → runtime=0x72016a5020   → 回 static=0x5020     往返一致=True  在模块内=True
static=0xdfc0     → runtime=0x72016adfc0   → 回 static=0xdfc0     往返一致=True  在模块内=True
static=0x31dfff   → runtime=0x72019bdfff   → 回 static=0x31dfff   往返一致=True  在模块内=True
越界: static=0x400000 → contains()=False
```

`[已执行]` 真机端到端（这条最有说服力）：

```
本地 samples/device/libc.so 的 openat 静态偏移 = 0x97a80
该处 16 字节（本地文件）= 3f2303d5ffc304d1fd7b0ea9fc7b00f9
设备模块表：libc.so base=0x72016a0000
运行时读回（read_runtime_memory）= 3f2303d5ffc304d1fd7b0ea9fc7b00f9   ← 完全一致
换算：0x72016a0000 + 0x97a80 = 0x7201737a80
读回的值：uint32 = 3573752639 = 0x3f2303d5（与文件前 4 字节一致）
```

`[已执行]` `locate_static` 的三条降级路径都**如实说明**，没有编造：

```
无模块表:        static_addr=None, function=None, loaded_in_mda=False,
                 notes=["未提供运行时模块表（modules），无法确定模块基址；请从 dyn/service.py 或 dyn/rebase.py 取模块表后传入"]
地址不在任何模块: so=None, static_addr=None, notes=["运行时地址不落在任何已知模块区间内"]
落在 PLT 桩内:    static_addr='0xe040', function=None, in_plt_stub=True, plt_name='calloc'
```

**但**：MCP 层的 `locate_runtime_addr` 当前返回 `MODULE_UNAVAILABLE`（见第 1 节），所以从 AI 侧走不通。

`[已执行]` 另一个已实测的能力边界：

```
read_typed(SoFile('samples/device/libc_apex.so'), 0x97a80, "uint32", source="runtime", rb=rb)
→ MemReadError: MODULE_NOT_LOADED: libc_apex.so 未出现在目标进程的模块表里

而同内容、名字为 libc.so 的样本 → 成功
```

即：**本地文件名必须与设备模块名对得上**（或能靠指纹反查到），否则明确报错而不是读错内存。这是正确行为。

### 验收场景

**A8.1 换算往返必须互逆** `[已执行 ✅]`

- 步骤：对 `{0, 0x5020, 0xdfc0, 模块末尾-1}` 逐个 `to_static(to_runtime(x)) == x`
- 期望：全部相等
- 已实测 ✅

**A8.2 换算结果与真机内存必须一致** `[已执行 ✅]`

- 前置：本地有与设备完全相同的 so 文件；目标进程已 attach
- 步骤：
  1. 从符号表取某函数静态偏移 `S`
  2. 从模块表取基址 `B`
  3. 读 `B + S` 处 16 字节
  4. 与本地文件的 `S` 处 16 字节比较
- 期望：**逐字节相同**
- 已实测：`openat @ 0x97a80` → 两边都是 `3f2303d5ffc304d1fd7b0ea9fc7b00f9` ✅
- 加强版：换 3 个不同函数各测一次（防「恰好第一个对」）

**A8.3 越界与降级必须明确说明** `[已执行 ✅]`

- 步骤：分别测「无模块表」「地址不在任何模块」「落在 PLT 桩」
- 期望：三种情况给出**三种不同的、可区分的结果**，且都有 `notes` 说明原因；不许返回 `static_addr=0` 冒充成功
- 已实测 ✅（见上面三段输出）

**A8.4 MCP 层与 dyn 层结果必须一致** `[建议，当前必然失败]`

- 步骤：同一输入分别调 `locate_runtime_addr`（MCP）与 `locate_static`（dyn 直调）
- 期望：字段完全一致
- 当前实测：dyn 直调 `{so: 'liblog.so', static_addr: '0x5020', function: 'create_android_logger', in_gap: False, loaded_in_mda: True}`；
  MCP 层 `MODULE_UNAVAILABLE` → **不一致 → FAIL**（这是第 1 节阻断项的表现）

### 边界与异常场景

| 场景 | 期望行为 | 实测 |
|---|---|---|
| 地址字符串含 a-f 但无 0x 前缀（如 `"7fff1234"`） | 按十六进制解析 = 2147422772 | `[已执行]` `parse_addr` ✅ |
| 纯数字 `"5020"` | 按**十进制** = 5020（不是 0x5020） | `[已执行]` ✅ |
| `"0x5020"` | 十六进制 = 20512 | `[已执行]` ✅ |
| `None` / `""` | 返回 None（不是 0） | `[已执行]` ✅ |
| 负数 | 保留符号 `-1` | `[已执行]` ✅ |
| 本地名与设备名不同（带版本号/壳前缀） | 去版本号匹配 → 指纹反查 → 明确报错，三级降级 | 读码确认（R29/R33 已锁定） |
| 运行时地址带 ARM64 tag（`0xb4...`） | 自动脱 tag | 读码确认（perfwatch C 侧有 `0x00FFFFFFFFFFFFFF`） |
| 32 位进程 | 指针 4 字节 | `[建议]` 未测 |
| so 被改名后再换算 | 指纹匹配找到模块；找不到就报错不猜 | 读码确认 R33 |

### 回滚条件

1. `to_static(to_runtime(x))` 不互逆 → 回滚
2. 换算结果与真机内存字节不一致 → 回滚（这是整体正确性的地基）
3. 越界时返回 `static_addr=0` 而非 None/错误 → 回滚（假值）
4. 模块名不匹配时读了「相近的另一个模块」→ 回滚（读错内存比读不到严重得多）

---

## 10. 边界与异常场景总表（跨需求）

这一节把散落在各条的边界集中，便于一次性设计测试用例。

### 10.1 环境类（实测已知）

| 坑 | 实测证据 | 影响 |
|---|---|---|
| 静态链接的 arm64 程序在 Android 12 被拒 | `error: executable's TLS segment is underaligned: alignment is 8 (skew 0), needs to be at least 64 for ARM64 Bionic` | 靶子必须 `-fPIE -pie` 动态链接 |
| NDK 21.0.6113669 的 clang++ 在本机被 SIGKILL | `Killed: 9` | 改用 NDK 27.1.12297006 |
| `adb shell "nohup x &"` 会被杀 | 后台进程随 shell 退出 | 用 `( nohup x & )` 或 `nohup sh -c '...' &` |
| `adb shell` 里跑前台长命令会挂住调用 | 我的一次 `sleep 240 &` 直接把 bash 工具卡了 60 秒 | 目标进程一律后台化 |
| frida 17 的 `script.unload()` 永久阻塞 | `rebase.py` 注释记载「每次都是 25 秒」 | 代码已规避（不 unload）；测试环境里若自己写 frida 脚本要注意 |
| frida 17 的 `session.detach()` 在有脚本时永久阻塞 | `rebase.py` 注释记载 | 已改为守护线程 + 有限 join |
| 进程名带版本号（`libsgmainso-6.7.260202.so`） | R29/R33 已锁定 | 本地文件名与设备名不必字面相同 |

### 10.2 系统行为类

| 场景 | 已知事实 | 验收要求 |
|---|---|---|
| 前台 app 线程被阻塞 5 秒 | Android input dispatch timeout → ANR | hold 必须有看门狗（当前缺） |
| 后台进程 SIGSTOP 约 20 秒 | 被 AMS/Watchdog 按 ANR 回收（`adb.py:547` 注释） | `freeze_process` 要在 20 秒内 unfreeze，且有提示 |
| `MemoryAccessMonitor.enable()` | 实测让目标进程崩溃 | 明确禁用（代码已注明） |
| Stalker 跟随 system_server | 实测导致 zygote + 框架整体重启 | 必须拒绝或强警告（代码已注明） |
| 探针数 765 个 | 实测直接崩进程 | `max_points` 硬上限 4000 + 均匀采样（已在） |
| 密集 patch（max_points=400） | 实测崩过 | 分批 + 批间隔（已在） |

### 10.3 数据质量类

| 场景 | 期望 |
|---|---|
| 读失败 | `READ_FAILED` / `ADDR_UNMAPPED`，**绝不返回零填充或空串**（R2/R15/R18 已锁定） |
| 类型不支持 | `BAD_TYPE` + 列出可用类型（`[已执行]` `uint24` → 明确报错 ✅） |
| 参数越界 | `BAD_REQUEST`（`[已执行]` `count=-1`、`max_length=999999` ✅） |
| 断点不对齐 | `BAD_ALIGNMENT` + 最近合法地址（`[已执行]` ✅） |
| 模块不存在 | `MODULE_NOT_LOADED` + 提示先调 modules()（`[已执行]` ✅） |
| 找不到符号名 | 返回 `None`，不许编一个像样的名字（`[已执行]` `symbol_name(0xe028)` → `None` ✅） |
| 数量超限 | `truncated: true` + 实际丢弃数，不许静默截断 |

---

## 11. 回滚条件总表（按触发门槛排序）

「回滚」= 撤销本次改动 / 下架该工具，恢复上一可用状态。

### R1 级：立即回滚，无讨论（数据造假）

| 条件 | 对应需求 |
|---|---|
| 任何**假数据**：`example.com` 这种样板值、编造的符号名、补全的指令、读失败后返回 0/空串 | 全部 |
| 工具报成功但实际没做（hooks 没装上 / 断点没冻住 / 没抓到请求） | 5, 7 |
| 报 `held: true` 但线程在跑，或报 `resume` 成功但计数不恢复 | 4 |
| 换算结果与真机内存字节对不上 | 8 |

### R2 级：当次改动回滚（功能性错误）

| 条件 | 对应需求 |
|---|---|
| `plt_map` 键指向的不是真桩头（A7.1 不通过） | 7 |
| bl→PLT 解析率 < 100%（A7.2 不通过） | 7 |
| SSO 的 n=22 / n=23 临界点解析错 | 3 |
| jadx 成功时却走了降级路径 | 2 |
| 降级输出与 apktool 真值偏差 > 20% | 2 |
| `to_static(to_runtime(x)) != x` | 8 |
| 函数区间出现重叠，或 `function_at(函数起点)` 返回外层 | 6 |

### R3 级：先修稳定性再谈功能（安全）

| 条件 | 对应需求 |
|---|---|
| 任何 hook 导致目标 app **ANR 或闪退**，且工具无事前告警 | 1, 5 |
| attach 泄漏线程（连续 20 次后线程数增长） | 5 |
| 目标崩溃后工具报空结果而非 `WATCH_FAILED` | 5 |
| 采集导致目标流量/功耗异常升高 > 50% | 1 |
| `freeze_process` 后忘记/无法 unfreeze，进程被系统回收 | 5 |

### R4 级：允许上线但必须挂标注

| 条件 | 处理方式 |
|---|---|
| 函数 `size` 是 gap 推断值（`libc_apex` 91%） | 返回里标注 `size_source: "inferred"`，不许当真实边界用 |
| `aggressive=True` 的 prologue 误报（libbase +171） | 默认关闭；开启时 `by_reason` 必须能分辨 |
| 本地名与设备名不匹配但靠指纹找到了 | 标注 `module_match: "fingerprint"`，让人知道这是推断的 |
| 运行时读到了 `.bss`（文件里没有） | 标注 `source: "runtime"`，与静态读区分 |

---

## 12. 我没做 / 做不了的（诚实清单）

写清楚，避免下一轮有人以为这些都验过了。

| 项目 | 为什么没做 |
|---|---|
| **在前台 app 上测 hold 的 ANR** | 会真把用户手机的 app 搞出「无响应」弹窗。**需要用户明确同意**才能做，我不擅自做 |
| `net_request_dump` 的端到端 | 工具不存在，无可测对象。已备好前置条件核查（Java bridge ✅ / 出网 ✅ / 类枚举 ✅） |
| `dex_smali` 的端到端 | 工具不存在。已备好 ground truth 通道（jadx 1.5.5 + apktool + 真实失败样本 3 类） |
| `read_std_container` 的端到端 | 工具不存在。已备好真机布局真值（22 字符 SSO 边界、首字节 flag、成员顺序） |
| `watch_module` 用 max_points=400 实测崩溃 | 会打断用户设备上的进程，属高风险 |
| 打包版（`dist/MDA.app`）能否真正跑工具 | 需要重新打包并在打包环境里跑测试。`[已执行]` 只观察到 `dyn/` 目录里没有 .py 文件，这本身就是个疑点 |
| 32 位进程的地址换算 / 容器解析 | 手上没有 32 位样本 |
| 加固壳样本（节表被抹）的函数边界 | `liblog/libbase/libcutils` 都有正常节表；壳样本需要另找 |
| PLT 修复后的回归 | 我只验证了「方案有效」，**没有改代码**（未经用户同意不改） |
| 45 个工具路径修复 | 同上，只定位不改 |

---

## 13. 复现命令附录

### 13.1 既有回归基线

```bash
cd /Users/waterclean/Desktop/ProJect/mac/mda
.venv/bin/python tests/test_e2e.py          # 14 通过 / 0 失败
.venv/bin/python tests/test_dyn_runtime.py  # 26 通过 / 0 失败
.venv/bin/python tests/test_regressions.py  # 590 通过 / 0 失败
.venv/bin/python tests/test_shell_sample.py #  9 通过 / 0 失败
# 合计 639
```

### 13.2 阻断项复现（45 个工具不可用）

```bash
cd /Users/waterclean/Desktop/ProJect/mac/mda
MDA_GUI_MCP=http://127.0.0.1:9/mcp .venv/bin/python - <<'PY'
import sys; sys.path.insert(0,'.')
from server.mcp_server import tools as T
print(T.read_typed(so_name="liblog.so", addr=0x5020, type_name="uint32"))
PY
# 期望（现状）：{"error": "dyn.memread 尚不可用：ModuleNotFoundError: No module named 'dyn'", ...}
```

### 13.3 PLT 偏移复现

```bash
cd /Users/waterclean/Desktop/ProJect/mac/mda
.venv/bin/python - <<'PY'
import sys; sys.path.insert(0,'.')
from server.core.elf_model import SoFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
for p in ("samples/liblog.so","samples/libbase.so","samples/libcutils.so"):
    so = SoFile(p); plt = so._sec_by_name(".plt")
    lo, hi = plt["sh_addr"], plt["sh_addr"] + plt["sh_size"]
    text = so._sec_by_name(".text")
    tot = hit = 0
    for ins in md.disasm(text.data(), text["sh_addr"]):
        if ins.mnemonic == "bl" and ins.op_str.startswith("#"):
            t = int(ins.op_str[1:], 16)
            if lo <= t < hi:
                tot += 1; hit += 1 if so.symbol_name(t) else 0
    print(f"{p.split('/')[-1]:14s} bl→PLT={tot:4d} 可解析={hit:4d} ({hit/tot*100:.1f}%)")
PY
# 现状：liblog 42.9% / libbase 37.9% / libcutils 55.9%
```

### 13.4 hold 真暂停复现

```bash
NDK=~/Library/Android/sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/darwin-x86_64/bin
cd /Users/waterclean/Desktop/ProJect/mac/mda/tests/acceptance/probes
$NDK/aarch64-linux-android21-clang -O0 -fno-inline -fPIE -pie -o hold_target hold_target.c
adb -s 3e2ff172 push hold_target /data/local/tmp/hold_target_dyn
adb -s 3e2ff172 shell "chmod 755 /data/local/tmp/hold_target_dyn; rm -f /data/local/tmp/hold.log"
adb -s 3e2ff172 shell "(nohup /data/local/tmp/hold_target_dyn > /data/local/tmp/hold.log 2>&1 &); sleep 1; ps -A -o PID,NAME | grep hold_target"
# 记下 pid，然后：
#   set_breakpoint(pid=..., so_name="hold_target_dyn", static_addr=0x17e0, hold=True)
#   连续 3 次 `adb shell wc -l < /data/local/tmp/hold.log` → 必须完全相同
#   poll_events → held=true
#   resume → woken=1，计数恢复增长
```

### 13.5 容器布局真值复现

```bash
cd /Users/waterclean/Desktop/ProJect/mac/mda/tests/acceptance/probes
NDK=~/Library/Android/sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/darwin-x86_64/bin
$NDK/aarch64-linux-android21-clang++ -O1 -fPIE -pie -static-libstdc++ -o container_probe container_probe.cpp
$NDK/aarch64-linux-android21-clang++ -O1 -fPIE -pie -static-libstdc++ -o sso_boundary     sso_boundary.c
adb -s 3e2ff172 push container_probe sso_boundary /data/local/tmp/
adb -s 3e2ff172 shell "chmod 755 /data/local/tmp/container_probe /data/local/tmp/sso_boundary"
adb -s 3e2ff172 shell "/data/local/tmp/sso_boundary"   # 看 n=22 → 0x2c，n=23 → 0x21
adb -s 3e2ff172 shell "/data/local/tmp/container_probe"
```

### 13.6 jadx 失败样本复现

```bash
adb -s 3e2ff172 shell "su -c 'cat /system/priv-app/MIUIContacts/MIUIContacts.apk'" > /tmp/contacts.apk
jadx -d /tmp/out --no-res --no-imports /tmp/contacts.apk
#   → ERROR - finished with errors, count: 1570
grep -rn "Method dump skipped" /tmp/out/sources/miui/cloud/net/XHttpClient.java
#   → instruction units count: 463

# 对照真值：
jadx -m fallback --show-bad-code -d /tmp/out_fb --no-res /tmp/contacts.apk
apktool d -f -o /tmp/smali_out /tmp/contacts.apk
#   → smali_classes2/miui/cloud/net/XHttpClient$HttpRequest.smali 里 doHttpRequest 约 238 行指令
```

---

## 14. 最终判定

| # | 需求 | 判定 | 一句话 |
|---|---|---|---|
| — | MCP 包装层（阻断项） | **FAIL** | 45/103 个工具必报 `MODULE_UNAVAILABLE`，根因是一行字符串路径 |
| 1 | `net_request_dump` | **不存在** | 底座齐（Java bridge / 出网 / 类枚举都验过），功能零 |
| 2 | `dex_smali` | **不存在** | 但 jadx/apktool/失败样本/对照真值全部就位 |
| 3 | `read_std_container` | **不存在** | 真机布局真值已拿到（SSO 22 字符、首字节 flag），可直接照做 |
| 4 | hold 真暂停 | **PASS** | 外部计数器实测冻结 40 秒 + resume 恢复 |
| 5 | hook 保护 | **PARTIAL** | 超时/分批/崩溃归因都有；**hold 无看门狗**，前台必 ANR |
| 6 | 函数边界 | **PASS（有保留）** | 4 样本零重叠零零长；但 91% 的 size 是推断值 |
| 7 | PLT 精确性 | **FAIL** | 50% 桩地址偏 8 字节，bl 解析率 38~56% |
| 8 | 地址换算 | **PASS（有条件）** | 数学与真机字节都对；MCP 层走不通 |

**整体：NEEDS WORK。** 8 条里 3 条不存在、2 条有实测缺陷、1 条部分缺失。按我的经验，这批需求需要 **2~3 轮迭代**才能到可交付状态，第一轮不可能全过 —— 这很正常，不需要为了让报告好看而调高评分。

### 建议的迭代顺序

1. **先修阻断项**（45 个工具的导入路径）—— 否则后面所有真机验收都会撞同一堵墙
2. **再修 PLT 键值**（一行改动，已有 100% 命中验证方案）
3. **补 hold 看门狗**（最危险的一项：前台 app 会 ANR）
4. 然后才做三个新工具（`net_request_dump` / `dex_smali` / `read_std_container`），
   因为它们都要用到「能正常读内存 / 能正常 hook」这两个底座

---

**文档作者**：TestingRealityChecker（集成验收）
**证据位置**：本文所有 `[已执行]` 数字均可在第 13 节复现；探针源码在 `tests/acceptance/probes/`
**再评估条件**：上述 FAIL / 不存在项修完后，本文档的 A 系列场景全部重跑一遍
