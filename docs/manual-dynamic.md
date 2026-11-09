# 动态调试与 Java Hook 使用手册

> 面向「用 AI 驱动 MDA 做真机分析」的实操手册。
> 记录的是**参数语义、真实示例与踩过的坑**，不是 API 罗列（完整 schema 以 `tools/list` 为准）。

---

## 一、开工前的三件事

任何动态分析开始前，按顺序做完这三步，能省掉后面大量的"为什么没反应"。

### 1. 环境体检

```
preflight(serial="<设备序列号>")
```

一次调用拿到：adb 是否可用、在线设备、是否 root、frida-server 是否在跑、
**设备端与本机客户端版本是否一致**、27042 端口被谁占用。

期望看到 `version_match: true`。不一致时任何 attach 都会报
`ProtocolError: unable to communicate with remote frida-server`。

### 2. 确认进程活着且可注入

```
probe_process(serial="<设备序列号>", package="<目标App包名>")
```

**这一步不能省。** 三条证据交叉验证：

| 证据 | 作用 |
|---|---|
| `/proc/<pid>` 是否存在 | 进程在内核里还在不在 |
| `/proc/<pid>/stat` 状态字符 | `R/S/D/T/Z/X`，其中 `Z`=僵尸、`T`=被冻结 |
| frida 能否枚举到 | 能不能注入 |

**实测踩过的坑**：`adb ps` 能看到 pid，但 frida 枚举不到它——进程已失去可注入性。
这时后续所有断点都报"0 命中"，看起来像"代码没跑"，实际是**进程没了**。

### 3. 版本对齐（仅在 preflight 报不一致时）

```
frida_server_align(serial="<设备序列号>", dry_run=True)     # 先看计划
frida_server_align(serial="<设备序列号>", dry_run=False)    # 确认后执行
```

会备份原文件、按 GitHub 官方 sha256 校验新包、任一步失败自动回滚。

> 设备上可能同时有别的项目的 frida 实例（监听其他端口）。
> MDA 只操作 **27042**，不会碰其他的。

---

## 二、断点的正确用法

### 2.1 两种模式：记录 vs 挂起

```
set_breakpoint(serial, pid, so_name, static_addr, hold=False)   # 只记录，不阻塞
set_breakpoint(serial, pid, so_name, static_addr, hold=True)    # 命中即挂起目标线程
```

**选择原则**：

- 想统计"这段代码跑不跑、跑了多少次、寄存器值分布" → `hold=False`
- 想"停在那一刻看内存、看调用栈" → `hold=True`，**但记得 `resume`**

> `hold=True` 会真的挂住线程。忘了 `resume`，目标 App 会卡到 ANR。

### 2.2 地址必须 4 字节对齐

AArch64 是定长 4 字节指令，`static_addr` 必须是 4 的倍数。
传错会返回 `BAD_ALIGNMENT`，并告诉你最近的两个合法地址。**不会静默接受**。

### 2.3 下完断点先自检

```
verify_breakpoint(serial, pid, so_name, static_addr, bp_id)
```

`set: true` 只代表"frida 接受了挂钩请求"，**不代表真的 armed**。返回里：

| 字段 | 含义 |
|---|---|
| `hits_since_set > 0` | 断点正常工作 |
| `hits == 0` 且 `already_hooked` | 钩子装上了，但这段代码没执行 |
| `hits == 0` 且 `not already_hooked` | 钩子没装上，检查地址/模块 |
| `bytes_match == false` | 地址对应错了文件 |

### 2.4 0 命中时怎么排查

**不要立刻怀疑地址错了。** 按这个顺序排除：

```
probe_process          ① 进程还在吗？（最常见的原因）
probe_hits             ② 纯计数：地址被执行过几次（最直接）
watch_module           ③ 这个 so 里到底哪些函数被执行了
```

`probe_hits` 和 `verify_breakpoint` 的分工：

- `verify_breakpoint` 查"断点有没有 armed"（字节、hook 状态）
- `probe_hits` 查"这段代码到底跑不跑"（一个计数器，最直接）

`watch_module` 用来区分"地址算错了"与"这段代码没被执行"——
它会在 so 的所有函数入口撒点，告诉你实际被执行的是哪几个偏移。

> **实测对照**：某 VM 解释器入口断点 0 命中。`watch_module` 显示该区间
> 确实有 24 个函数在跑，但目标入口不在列表里——结论是"这条路径当前没走"，
> 不是地址错误。这个区分靠 0 命中本身永远分不出来。

---

## 三、命中数据的正确读法

### 3.1 三个取数据的工具，别混用

| 工具 | 用途 | 特点 |
|---|---|---|
| `poll_events` | 事件流，边跑边看 | 有游标，可增量拉取 |
| `hits` | 命中现场列表 | 含 36 个寄存器 + 调用栈，**数据量大** |
| `hit_analysis` | 最近一次命中 → 静态上下文 | 一站式：前后指令 + 伪代码 + 调用者 |

### 3.2 hits 的数据量问题（必读）

每条命中约 **12KB**（36 个寄存器 + 调用栈 + 256 字节栈快照）。
2000 条就是 24MB——远超单次返回上限，会被**截断成残缺 JSON**。

**必须用参数裁剪**，否则拿到的可能是坏数据：

```python
# 只关心某个断点，最近 5 条，不要寄存器
hits(bp_id="<bp_id>", limit=5, include_context=False)

# 增量拉取
hits(since_seq=1000, limit=50)
```

返回里的 `fields_omitted` 会告诉你省略了哪些字段，`size_hint` 估算体积。

### 3.3 按寄存器值筛选（从 2000 条里精准定位）

```python
hits(filter={"x2": 5})                      # x2 == 5
hits(filter={"x0": "0x20", "x2": 5})        # 多条件 AND
hits(filter={"x2": {"in": [1, 4, 5]}})      # 值在集合里
hits(filter={"x2": {"min": 1, "max": 10}})  # 闭区间
```

支持的比较：`eq` / `ne` / `in` / `not_in` / `min` / `max` / `gt` / `lt` / `ge` / `le`。

**寄存器取不到时视为不匹配**（而不是放行）——否则写错寄存器名会悄悄
把所有命中都放回来，看起来像"过滤没生效"。

### 3.4 聚合统计（比原始数据有用得多）

```python
hits(group_by="x2")        # → {"0x1": 523, "0x4": 437, "0x5": 210}
hits(group_by="lr")        # → 看哪个调用点最频繁
hits(group_by="thread_id") # → 看是哪个线程在干活
```

给了 `group_by` 就**不返回全量 hits**，只给聚合结果 + 3 条样本。
`group_top` 控制返回多少个桶（默认 50）。

### 3.5 推荐的完整流程

```
① set_breakpoint(hold=False)          只记录，让 App 正常跑
② 期间操作 App（发请求、切页面…）
③ hits(group_by="x2")                 先看值分布，找到你要的那个值
④ hits(filter={"x2": <目标值>})        再精准筛出那批
⑤ hit_analysis                        看命中的静态上下文
```

先聚合再筛选，比"取回 3 条自己看"有效一个数量级。

---

## 四、内存与内存地址

### 4.1 三种读内存的方式，别混

| 工具 | 地址类型 | 用途 |
|---|---|---|
| `read_process_memory` | **静态**地址 | 按 so 内偏移读（自动 ASLR 换算） |
| `read_runtime_memory` | **运行时**绝对地址 | 读断点现场的 `x0`/`lr`/`sp`，常指向堆 |
| `read_memory_batch` | 运行时地址，多段 | 一次读十几段，减少对目标的打断 |

**最容易踩的坑**：断点现场的 `x0` 是运行时绝对地址，通常指向堆上的对象，
**根本不在任何 so 里**。用 `read_process_memory` 会报 `ADDR_UNMAPPED`，
必须用 `read_runtime_memory`。

### 4.2 读字符串

```
read_runtime_string(runtime_addr="0xb400...")    # 断点现场 x0 指向的路径/内容
```

典型用法：在 `open` / `dlopen` 这类函数上命中后，直接把第一个参数读出来。

### 4.3 运行时地址折回静态模型

```
locate_runtime_addr(runtime_addr="0x7a0005201c")
```

把带 ASLR 的地址换算成 `so / 静态地址 / 所属函数 / 函数内偏移`，
之后就能用 `disassemble` / `xrefs_to` 这些静态工具。

结果里几个字段要看清（都是**如实标注**，不是错误）：

- `in_gap: true` — 在模块内但没函数覆盖（FDE 空洞 / PLT 桩），不编造函数名
- `in_plt_stub: true` — 落在 PLT 跳板，`plt_name` 给出符号
- `loaded_in_mda: false` — mda 没加载该 so，先 `load_so` 再查一次

### 4.4 从进程内存读指令（发现 hook）

```
decode_runtime_insn(so_name, static_addr, pid, serial, count=8)
```

与 `disassemble` 的关键区别：

```
disassemble          读**本地文件**——so 加载时的原始字节
decode_runtime_insn  读**进程内存**——此刻真正在跑的字节
```

以下场景两者不一样，只有后者能看到真相：断点处（被改了指令）、
运行时自解密的代码段、被 hook / inline patch 过的函数。
返回里的 `patched: true` 就是明确告诉你"这条指令与文件不一样"。

---

## 五、找入口（壳样本的难点）

### 5.1 JNI 注册表

```
find_jni_registrations(so_name)
```

`JNINativeMethod` 是 Java 与 native 的桥，找到它就**一次拿到所有 JNI 入口的
名字 ↔ 地址映射**，不用再猜哪个 `sub_xxxx` 是目标。

返回里的 `fn_source` 要看清：

- `rela` — 函数地址是从重定位补的（**文件里常是 0，靠 RELA 填**）
- `file` — 文件里就有值
- `none` — 没找到地址

> **找不到是正常的结论**。表在运行时才构造的话，静态必然找不到。
> 这时返回空 + 四条证据说明（比如"全文件 N 个字符串里含 `Ljava` 的为 0 个"），
> 不是"功能没实现"。

### 5.2 跳转表全库扫描

```
find_dispatch_tables(so_name, max_tables=200, min_entries=3)
```

不用给任何地址，全库找所有 `switch` 跳转表。识别四种形态：

| 模式 | 特征 |
|---|---|
| `signed_offset_4` | `adr/adrp` + `ldrsw` + `add` + `br`，表项是 4 字节有符号偏移 |
| `absolute_ptr_8` | `adrp` + `ldr` + `br`，表项是 8 字节绝对地址 |
| `byte_indexed` | 单字节索引 |
| `byte_offset_table` | `adr` + `ldrb` + `add lsl #2` + `br`，**1 字节表项 ×4** |

`confidence` 分三档：`high`（目标全在可执行段）/ `medium` / `low`（多越界，可能误报）。

> 2.8MB / 3000 函数的样本上约 20 秒，找到 84 张表。属正常耗时。

### 5.3 单条 br 与单张表

```
resolve_br(so_name, addr)                    # 解开某条 br 指向哪
read_jump_table(so_name, table_static_addr)  # 读一张表的内容
```

**`resolved=false` 是有价值的结论**，不是工具坏了。原因通常是：

- 目标来自运行时寄存器（参数/返回值传递）
- 指针表在运行时才被填充或解密

> 实测：同一个 so 里两张表性质完全不同。
> 一张文件里就是常量（`140000004c...`），另一张文件里是密文、
> 运行时才解密成真指针。**只读文件会解出垃圾指针。**
> 这时给 `read_jump_table` 传 `serial` + `pid`，它会从进程内存读。

---

## 六、Java 层

### 6.1 前提：Java bridge

frida 17 起 Java bridge **不再内置**在 server 里。脚本里直接 `Java.use(...)`
会报 `ReferenceError: 'Java' is not defined`——这是上游架构调整，**不是环境坏了**。

MDA 会自动注入 `frida_tools` 自带的 `bridges/java.js`，不需要额外安装。
开工前确认一次：

```
java_bridge_status()                                   # 纯本地，看 bridge 文件在不在
java_bridge_status(serial="...", pid=1234)             # 额外探测运行时规模
```

给了 `serial`+`pid` 时会额外返回：已加载类数、可 hook 方法数
（**抽样外推，会明确标注非精确值**）、限制清单。

### 6.2 不知道 hook 哪个类时——用通配符批量

这是最容易浪费时间的地方。**猜一个类 → 等 16 秒 → 0 命中 → 再猜**，
而答案往往在第四个类里。

```python
java_hook(pattern="*NetworkConverter*", method="convert*",
          max_classes=20, duration=15, sibling_probe=True)
```

一次 hook 所有匹配的类，**分别统计命中数**：

```
4 个类中 1 个被调用，共 56 次；最热的是 android.os.HandlerExecutor（56 次）
    56 次  android.os.HandlerExecutor      ← 一次定位
     0 次  android.os.Handler
     0 次  android.os.HandlerThread
```

三种定位方式可组合（取交集）：`class_name` 精确 / `pattern` 通配符 / `package` 前缀。

### 6.3 0 命中时看诊断

`java_hook` 在 0 命中时返回 `diagnosis`，而不是只说"没被调用"：

```json
{
  "class_loaded": true,
  "method_exists": true,
  "sibling_methods_called": [{"method": "X.convertNetworkStats", "hits": 12}],
  "suggestion": "方法存在但零调用：该路径在当前操作下没被走到；
                 同类里 X.convertNetworkStats 被调了 12 次——真正干活的很可能是它"
}
```

`sibling_probe=True`（默认开）会自动 hook 同类里另外最多 8 个方法，
看哪个在跑。**这是定位"我是不是 hook 错方法了"最有效的手段。**

### 6.4 谁调用了它

```python
java_find_callers(class_name="...", method="convertRequest", duration=8)
```

返回按次数降序的调用栈：

```
共被调用 2 次，最直接的调用者是
com.android.systemui.broadcast.ActionReceiver.dispatchReceiver(ActionReceiver.kt:128)
```

> 实现上会自动跳过取栈链路自身（`Thread.getStackTrace` / `VMStack` / `VMDebug`），
> 否则"调用者"永远是 `getStackTrace` 自己。

### 6.5 按四个维度找类

```python
java_find_classes(pattern="Security")                       # 类名
java_find_classes(pattern="*StatusBar*", field="m*")        # 有这些字段的类
java_find_classes(return_type="*Request")                   # 返回这个类型的类
java_find_classes(method_pattern="get*")                    # 有这些方法的类
```

**匹配语义**（踩过坑，特别注意）：

- 类名 / 字段名 → **子串搜索**，`Security` 能匹配 `com.x.SecurityGuard`
- 方法名 → **精确/通配**，`setHeaders` 不会连带 `setHeadersAndMore`
- 同时支持正则与通配符：`a|b`、`java\.lang\.String`、`convert*`、`*X*` 都行
- 非法正则（如 `[[[`）→ **明确报错**，绝不静默返回全部

> **性能**：只给 pattern 是秒回（不反射）；叠加 field/return_type/method_pattern
> 需要逐类反射，几万个类时很慢。用 `max_scan_classes` 限制，看返回的 `scanned`
> 判断结果是否可信。**建议先用 pattern 缩小范围再叠加其他维度。**

### 6.6 参数深挖

```python
java_hook(class_name="X", method="convert",
          capture={"args": True, "ret": True,
                   "arg_fields": ["url", "headers"], "expand_map": True})
```

- `arg_fields` 从参数对象里按字段名取值（getter 也会试）
- `expand_map` 让 `Map` / `List` 自动展开成键值对
- 实测样本：`{ what=3211264 target=...CommandQueue$H }` —— 能直接从参数看出目标类

### 6.7 Java 层的边界（如实标注）

- `java.lang.*` / `dalvik.*` / `sun.*` / `libcore.*` 已在注入前**自动排除**（hook 后易崩）
- `final` 方法可 hook；被 JIT 内联的会漏
- 通配符只在**已加载类**里匹配，未加载的类匹配不到
- 参数按 `String(v)` 转字符串并截断 200 字符——**对象只给摘要**
- `enumerateLoadedClassesSync` 列出**所有 classloader** 的类，
  而 `Java.use` 用当前 classloader——**"在枚举列表里"不等于"能 Java.use"**

---

## 七、执行轨迹

| 需求 | 工具 |
|---|---|
| App 启动时加载了什么、什么时候 | `trace_module_load` / `trace_app_startup` |
| 这个 so 里哪些函数被执行过 | `watch_module` |
| 指定几个入口，谁调用了它 | `trace_call_tree` |
| 谁被调用最多 | `trace_aggregate` |
| 先发生什么、后发生什么 | `trace_timeline` |
| 谁读/写了这块内存 | `trace_read` / `trace_write` |

`trace_app_startup` 必须是 **spawn** 模式才有意义——attach 到已运行进程时，
启动阶段的加载早就发生完了。它会先挂起 App、装好观察器、再放行，
所以能覆盖从第一条指令开始的全过程。

> `trace_code` 用 Stalker 跟随线程，**对 `system_server` 使用会导致系统重启**。
> 实测两次都崩。除明确知悉风险，不要调用。

---

## 八、常见故障对照表

| 现象 | 最可能的原因 | 怎么确认 |
|---|---|---|
| 所有断点 0 命中 | 进程已经死了 | `probe_process` |
| 某个断点 0 命中，其他正常 | 这段代码在该场景没执行 | `watch_module` 看实际跑的是哪些 |
| `ProtocolError: unable to communicate` | frida 两端版本不一致 | `preflight` 看 `version_match` |
| `Java is not defined` | bridge 没注入 | `java_bridge_status` |
| `ADDR_UNMAPPED` | 用静态地址工具读了运行时地址 | 改用 `read_runtime_memory` |
| `MODULE_UNAVAILABLE`（仅打包版） | 模块没打进包 | 见 README 打包章节 |
| 断点挂住后 App 卡死 | 忘了 `resume` | `resume(serial, pid)` |
| 命中数据是残缺 JSON | 没裁剪 hits 的数据量 | 加 `bp_id` / `limit` / 关掉 context |
| `NOT_ATTACHED` | 会话已断开 | 重新 `set_breakpoint` 或 attach |

---

## 九、两条铁律

### 1. 解除挂起与冻结

- `set_breakpoint(hold=True)` 命中后**必须** `resume`
- `freeze_process` 之后**必须** `unfreeze_process`

忘掉的后果是目标 App 一直卡着（界面无响应、ANR），而 MDA 这边不会报错。

### 2. 不编造

MDA 的所有动态工具遵循同一条原则：**采不到就说清原因，绝不返回假数据**。

- 0 命中 → 报 0 并给诊断，不编一个"看起来合理"的数字
- 表解不出来 → 报 `resolved: false` 并说明原因，不给假目标
- 找不到函数 → 报 `in_gap: true`，不猜一个函数名

看到 `code` / `error` / `hint` 字段时，那是**结论的一部分**，不是故障噪音。
