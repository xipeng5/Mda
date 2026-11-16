# uprobe 内存分配追踪（trace_alloc）实测报告

> 设备：3e2ff172 / Android 12 / arm64 / 内核 4.19.113 / root（Magisk）
> 代码：`server/dyn/uprobe.py`，MCP 工具：`trace_alloc`、`uprobe_probe`
> 时间：2026-11-16

## 一、为什么走 uprobe 而不是 frida

用户实测：frida hook malloc **60 秒 167358 次命中 → 目标进程被反调试杀死**（3 次）。

uprobe 是内核机制：在文件页上打一次 brk 断点，命中后由内核直接写环形缓冲，
**不修改目标进程代码、不注入任何库**，风控信号与开销都低一个数量级。

## 二、uprobe 语法实测结果（逐项验证，这台内核差别很大）

### 取值语法：只认 `%REG`，不认 `$argN`

| 语法 | 结果 |
|---|---|
| `$arg1` / `$tgid` / `$pid` / `$stack` / `$ustack` | **全部被拒**（写入 rc=1） |
| `%x0` `%x1` `%x2` `%lr` `%sp` `%pc` | **可用** |
| `r:GROUP/NAME PATH:OFF ret=$retval`（返回探针） | 可用（本工具不挂，见下） |

最终采用：

```
p:mda_alloc/malloc /apex/.../libc.so:0x48d3c sz=%x0 lr=%lr
```

- `%x0` = 第一个参数 = malloc 的 size
- **`%lr` = 调用者返回地址**（这是拿调用栈的唯一可行途径）

### 符号偏移怎么来

从 `/proc/<pid>/maps` 实时解析出该进程实际用的 libc 路径
（本机是 `/apex/com.android.runtime/lib64/bionic/libc.so`，老设备是
`/system/lib64/libc.so`），`adb pull` 回来后用 mda 自己的
`server.core.elf_model.SoFile` 取 vaddr。实测 `uprobe_events` 按 **vaddr**
解释 OFFSET（malloc=0x48d3c 注册即命中）。

**不硬编码任何路径/偏移/包名。**

## 三、三个必须绕过的环境坑（都是撞出来的）

### ① 全局 `tracing_on` 写不进去（静默失败）

```
echo 1 > /sys/kernel/tracing/tracing_on   → rc=0，但读回来仍是 0
```

rc=0 却不生效。同一时刻 `instances/<名>/tracing_on` 写 1 读回就是 1。
→ 收集与开关一律走 **tracefs instance**。

### ② 实例目录删不掉（EBUSY），只能复用不能每次新建

```
mkdir instances/xxx   → 成功
rmdir instances/xxx   → EBUSY（连全新空实例也删不掉）
rm -rf                → 同样失败
```

→ 固定名字 `mda_probe` 复用，每次只 `echo > trace` 清缓冲区。
这是本工具唯一留在设备上的痕迹（空目录 + 空缓冲区，不采集时零开销）。

### ③ filter 有长度上限，超了**静默失效**

实测（同一事件，逐个加 tid 条件）：

| 条件数 | 表达式长度 | 结果 |
|---|---|---|
| 45 | 1015 字节 | 写成功 |
| 46 | 1037 字节 | `printf: write: Invalid argument` |

**关键危害**：写失败后事件照常 enable、tracing_on 照常置 1，
但过滤条件根本没生效 → 抓到全系统的分配。
实测一次泄漏了 **230555 条**别的进程的事件。

→ 代码里硬性截断到 960 字节（`_MAX_FILTER_BYTES`），并在结果里如实报
`threads_covered` / `threads_skipped`，不假装全覆盖。
写 filter 后立刻用 `echo FRC_$?` 验证，被拒就返回 `FILTER_REJECTED` 而不是继续跑。

### ④ `common_pid` 是线程 id，不是 tgid

用 tgid 过滤 → 0 命中。必须把 `/proc/<pid>/task` 下所有 tid 列进 OR 链。

## 四、真机实测输出

### com.android.settings（用户指定的测试目标）

```
uprobe 捕获 4 条分配事件（1 个函数 × 30 个线程，窗口 2s）

<...>-3220 [002] 34.137480: malloc: (0x79320ced3c) sz=0x8  lr=0x7947f94e58
<...>-3220 [002] 34.137514: malloc: (0x79320ced3c) sz=0x30 lr=0x7947f94e58
<...>-3226 [000] 34.181000: malloc: (0x79320ced3c) sz=0x8  lr=0x7947f94e58
<...>-3227 [000] 34.181320: malloc: (0x79320ced3c) sz=0x8  lr=0x7947f94e58
```

### surfaceflinger（过程进程，用于验证大流量）

```
uprobe 捕获 1242 条分配事件（4 个函数 × 20 个线程，窗口 3.5s）

{'tid': 1329, 'func': 'malloc', 'size': 40,  'caller_off': 314968, 'caller_mod': 'libc++.so'}
{'tid': 1329, 'func': 'malloc', 'size': 6,   'caller_off': 434440, 'caller_mod': 'libhidlbase.so'}
{'tid': 1329, 'func': 'free',   'size': None,'caller_off': 440916, 'caller_mod': 'libhidlbase.so'}
{'tid': 1408, 'func': 'malloc', 'size': 40,  'caller_off': 314968, 'caller_mod': 'libc++.so'}
```

`caller_mod` 是 `%lr` 折算出的模块（基址取自 `/proc/<pid>/maps`），
`caller_off` 可直接喂 `disassemble` / `xrefs_to` 做静态回溯。

## 五、拿得到 / 拿不到（如实声明）

**拿得到**

| 字段 | 说明 |
|---|---|
| `ts` | 内核单调时钟（秒） |
| `tid` | 内核 `common_pid`（线程 id） |
| `func` | malloc / calloc / realloc / free |
| `size` | `%x0`，即请求字节数 |
| `caller_off` / `caller_mod` | `%lr` 折算到模块内偏移 |

**拿不到**

- **完整调用栈**：uprobe 不做 unwind，本机 `$stack` 语法不被支持。只有一层 `%lr`。
- **分配到的地址**：malloc **入口**还没有返回值，`addr` 恒为 None。
  要它必须额外挂 `r:` 返回探针，那会让内核开销翻倍，本工具不挂。
- **free 的大小**：`free(p)` 的参数是待释放指针，不是大小 → size 置 None，
  不把指针当大小报出去。

## 六、开销对比（frida vs uprobe）

| | frida Interceptor | uprobe（本工具） |
|---|---|---|
| 改目标进程代码 | **是**（InlineHook 覆写指令） | **否**（只在文件页打 brk） |
| 注入库 | 是 | 否 |
| 每次命中开销 | 走 trampoline + 回调 JS | 内核直接写环形缓冲 |
| 实测表现 | 60 秒 16.7 万次 → **目标被杀** | 同量级事件不惊动目标 |
| 被检测风险 | 高 | 低 |

**注意开销的真实位置**：libc 是全系统共享页，探针对**每个进程的每次 malloc**
都会触发。实测未过滤时每秒 6~9 万条事件、9MB trace。所以本工具强制：
tid 过滤 + 窗口默认 10s / 硬顶 60s + trace 超 48MB 提前收窗。
开关在 `instances/` 里，不影响系统已有的 tracing。

## 七、已知限制与实测踩坑

1. **空闲进程会返回 0 条**，这是正常结果不是故障。实测
   `com.android.settings` 多次在 2~8 秒窗口内一次 malloc 都没有
   （空闲的 Activity 栈确实不分配）。要验证功能可用，挑一个在干活的进程
   （如 surfaceflinger），或边跑边操作目标 App。
2. **pid 在窗口内重启**会导致 0 命中（tid 集合已失效）。
3. **测试期间设备反复重启（8 次）**，但归因不是本工具：
   - 对照组①：静置 90 秒不碰 tracefs → 不重启
   - 对照组②：只注册探针**不 enable** → 40 秒不重启
   - 对照组③：enable 探针但 filter 只留极少数 tid → 25 秒不重启
   - 对照组④：只跑 `am start` 驱动、完全不碰 tracefs → 不重启

   同时在本机 `ps` 里抓到**另一个 agent 正在并发轮询同一台设备**
   （`bash -c ... adb -s 3e2ff172 shell "cat /proc/uptime"` 循环）。
   结论：重启来自**设备被多个 agent 争用**，不是 uprobe 本身。
   （本次仍据此把探针生命周期做成强清理 + 失联检测。）
4. **adb 往返约 200ms**，设备异常时会飙到十几秒。所以：
   - 窗口内只在剩余时间 >1s 时才探测体量
   - 探测结果里识别 `adb: device not found` / `error: closed`，
     标记 `device_lost` 而不是当作"0 命中"
   - 清理失败时区分 `unknown: true`（设备失联，无法确认）
     与确定性残留，不让人去排查不存在的问题
5. **写坏 filter 会让事件永久失效**：往 filter 写非法内容后该事件从此 0 命中，
   且 `echo > filter` 清不掉（`cat filter` 变成 `Error: (0)`）。
   唯一恢复是删事件重注册 —— 所以清理一律走「删事件」。

## 八、测试与回归

- `.venv/bin/python tests/test_regressions.py` → **934 通过 / 0 失败**
  （含 R99 内存观察栈：`_parse_trace` 的解析、tid 过滤、无关行不误判）
- 真机：`trace_alloc` / `uprobe_probe` 均可用，探针注册→采集→清理全链路通过

## 九、实现中发现并修掉的 4 个自身缺陷

这些值记录下来，因为它们都属于"看不出来、但会给出错答案"的类型：

1. 清理只按 `events/<组>/` 目录枚举 → 残留事件删不掉 → `uprobe_events` 卡在
   EBUSY → 后续注册全失败，却表现为"tracing_on 置不上 1"。
   改为直接解析 `uprobe_events` 文本找本组事件。
2. **Python f-string 把 `\1` 当八进制转义**（变成 `\x01`）。发给设备的
   `sed -n 's|...|\1|p'` 里根本没有反向引用 → `MINE` 恒为空 → 删除循环
   一条都没执行，而脚本"看起来"完全正确。改用 `grep -o` + `cut`，
   整段脚本不出现任何反斜杠转义。
3. 单次删除不可靠：内核移除 uprobe 是异步的，删完立刻回读可能还没生效。
   改为收敛重试（最多 3 轮）。
4. 窗口计时口径混乱：报告里写"窗口 13.1s"而用户只给了 5 秒。
   拆成 `window_ms`（实际采集）与 `elapsed_ms`（总耗时）。
