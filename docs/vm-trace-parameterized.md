# VM 追踪能力参数化（去掉写死的结构偏移）

修改日期：2026-11-16
涉及文件：`server/dyn/vmbreak.py`、`server/dyn/memread.py`、`server/dyn/vmtrace.py`、
`server/mcp_server/tools.py`、`tests/manual_vm_trace_device.py`

---

## 1. 为什么改（用户实测痛点）

mda 原来的 VM 工具把「结构长什么样」写死在代码里：

```
ctx + 0x194  = 指令计数
ctx + 0x1a0  = 指令数组指针
ctx + 0x8    = VM pc
x27          = ctx
x25          = 寄存器堆
```

但用户分析的目标完全不同：

```
寄存器堆在 ctx + 0x6070      ← 不是在寄存器里
opcode  在 sp + 8            ← 不在结构体里
派发点   adr x22, #0x2F50D0; br x8
```

**关键区别**：这不是「偏移填错了」，而是**取值方式本身不同**。
偏移参数化只能改「加多少」，改不了「从哪里取」——所以原工具怎么调都不行。

---

## 2. 改了什么

### 2.1 引入「取值来源描述」（spec）

这是本次改动的核心抽象。把「从哪取一个值」变成数据，而不是代码：

| kind | 含义 | 例子 |
|---|---|---|
| `reg` | 从某个寄存器直接取 | `x20` |
| `sp` | 相对 native 栈指针 | `sp+8` |
| `ctx` | 相对 ctx 指针的偏移 | `ctx+0x6070` |
| `regoff` | 寄存器 + 偏移 | `x20+0x8` |
| `none` | 不取（返回 null，**不编造**） | `""` |
| `bad` | 解析失败（**明确报错**，不静默） | `"乱写"` |

用户用**一行字符串**表达（`parse_value_expr`）：

```
"x8"             -> {"kind":"reg","reg":"x8"}
"sp+8"           -> {"kind":"sp","offset":8}
"ctx+0x6070"     -> {"kind":"ctx","offset":24688}
"ctx+x20+0x10"   -> {"kind":"ctx","ctx":"x20","offset":16}
"x20+0x6070"     -> {"kind":"regoff","reg":"x20","offset":24688}
""               -> {"kind":"none"}
"乱写"            -> {"kind":"bad"}   ← 调用方据此报 BAD_EXPR
```

JS 侧统一由 `resolveValue()` 执行（`_JS_SPEC_HELPERS`，**三个模板共用一份**），
模板里从此**没有任何具体寄存器名或结构偏移常量**。

### 2.2 三个工具的能力对照

| 工具 | 原来 | 现在新增参数 |
|---|---|---|
| `vm_breakpoint` | 寄存器约定写死在函数体 | `reg_base_offset` / `ip_mode` / `opcode_expr` / `ctx_expr` |
| `vm_regs_snapshot` | 同上，且参数根本不对外开放 | 全部 8 个布局参数 |
| `vm_trace` | ctx/寄存器堆/pc 硬编码在 JS | **全部参数化 + ops[] 输出** |
| `dump_vm_state` | 计数宽度、合理区间、位域规则写死 | `count_size` / `count_min` / `count_max` / `opcode_shift,bits` / `func_shift,bits` |
| `probe_vm_from_hits` | 判定条件写死（2..100000、readU64） | 同上，并原样下传给 `dump_vm_state` |

### 2.3 新增 `vm_trace`

按用户要求的签名实现，**所有偏移都能配置**：

```python
vm_trace(
    serial, pid, so_name,
    dispatch_offset="",       # 派发点；或给 pattern_hex 自动扫
    ctx_reg="x0",             # ctx 在哪个寄存器
    ctx_expr="",              # 更精确："x20" / "sp+0x10" / "x20+0x8"
    opcode_expr="",           # "sp+8" / "x8" / "ctx+0x100"
    reg_base_offset=0,        # 寄存器堆相对 ctx 的偏移（如 0x6070）
    reg_base_reg="",          # 或在某个寄存器里
    ip_mode="ctx",            # VM pc：ctx / reg / none
    ip_reg="", ip_offset=8,
    count_offset=0x194, array_offset=0x1A0,   # 兼容旧接口，原样回显
    max_ops=1000, duration=10.0,
    code_base="", prog_base_p1_offset=0x240, prog_base_p2_offset=0x1A0,
    idx_from=0, idx_to=0,
    record_regs=False, reg_count=8,
    with_bytes=False,
    max_rows=0,               # 旧参数名，向后兼容
) -> {
    "ok": True,
    "ops": [{"seq","ts","tid","opcode","opcode_source","pc","ip_source",
             "idx","idx_source","ctx","regs"?,"pc_bytes"?}],
    "count": int, "truncated": bool, "stop_reason": str,
    "ctx_fail": int, "ip_fail": int,
    "layout_used": {...},
}
```

**实现要点（对应任务要求）**：

1. `Interceptor.attach` 挂在 `dispatch_offset`（**被分析代码的地址**，不是 VM 内部）
2. 命中时按 `ctx_reg`/`ctx_expr` 从上下文取 ctx
3. 按 `opcode_expr` 取 opcode（支持 `"sp+8"` 与寄存器名）
4. **限流**：`ops.length >= max_ops` 立即 `shutdown()` → `listener.detach()`，
   **不 hold、不阻塞目标线程**
5. **控制开销**：默认 `record_regs=False`（不读 32 个寄存器），
   `max_ops` 默认 1000，每条只留必需字段

### 2.4 关键诊断改进：区分「没执行」与「结构不符」

这是参数化带来的**最大实用价值**。

原来 0 条结果只有一种模糊提示。现在 JS 侧统计 `ctx_fail` / `ip_fail`：

```
派发点被命中 1940 次，但每次都取不到关键字段
（ctx 失败 0 / VM pc 失败 1940）。
**这是结构配置不符，不是 VM 没运行**
```

真机实测就是这样抓到问题的：把 `malloc` 当派发点、用 `ip_mode=ctx` 时，
`x0` 是「要分配的字节数」而不是结构体指针，读 `[x0+8]` 必然失败。
改 `ip_mode=reg` 立刻采到数据——**参数一改，行为就变**，证明参数真生效。

---

## 3. 向后兼容怎么保证的

三条措施，逐条可验证：

1. **默认值 = 原硬编码值**
   `VM_DEFAULTS` 里 `reg_base_reg="x25"`、`ctx_reg="x27"`、`ip_offset=8`、
   `prog_base_p1_offset=0x240`、`prog_base_p2_offset=0x1A0`；
   `dump_vm_state` 的 `count_size=8` / `opcode_shift=1,bits=4` / `func_shift=5,bits=4`。
   **不传任何新参数时，生成的 JS 与改动前逐字节等价。**

2. **旧参数名保留**
   `vm_trace` 同时接受 `max_rows`（>0 时覆盖 `max_ops`）；
   返回同时给 `ops` 和 `rows`（指向同一份数据）。
   `count_offset` / `array_offset` 仍在签名里并原样回显。

3. **回归锁定**
   `tests/test_regressions.py` 的 R59/R60 断言的是旧行为特征
   （`P1_OFF`/`P2_OFF` 两跳、`rows.push`、`VM_TRACE_MAX`、`max_rows` 参数）。
   这些断言**一条没改**，全部继续通过——说明改动没有破坏既有契约。

---

## 4. 真机验证结果

脚本：`tests/manual_vm_trace_device.py`
环境：3e2ff172 / Android 12 / arm64 / root
目标：`com.android.systemui`（选它是因为它有持续的 UI 刷新，
分配活动稳定；Settings 停在后台时 malloc 3 秒 0 命中，无法验机制）

```
探测 pid=3140: {'malloc': 1524, 'calloc': 83, 'realloc': 56, 'free': 1505}
选用 pid=3140  派发点偏移=0x48d3c（3s 内命中 1524 次）

[通过] V1  hook 挂上（派发点确实被执行）
[通过] V1  取不到值时不静默：verdict 指明结构配置不符
[通过] V1  不取 opcode 时 opcode 为 null（不编造）
[通过] V1  opcode_source 标明没取
[通过] V1b 改 ip_mode=reg 后真的采到数据
[通过] V1b pc 来自寄存器（ip_source 标注）
[通过] V1b opcode 按 sp+8 取到值
[通过] V2  max_ops 到顶就不再采（count=3，stop_reason=max_ops）
[通过] V2  stop_reason=max_ops 且 truncated=True
[通过] V3  opcode_expr='sp+8'     生效    sources={'sp+8'}
[通过] V3  opcode_expr='x1'       生效    sources={'reg:x1'}
[通过] V3  opcode_expr='ctx+0x10' 生效    sources={'ctx+0x10'}
[通过] V4  ctx_reg 生效 / reg_base_offset 生效 / opcode_expr 生效
[通过] V5  非法 opcode_expr 报 BAD_EXPR（带正确写法提示）
[通过] V6  ip_mode=reg 缺 ip_reg 时明确报错
[通过] V7  没给派发点来源时明确报错
[通过] V8  全程调用都按时返回（没有 hold 卡住）
[通过] V8  采集结束后目标进程仍存活（未 hold）

结果: 24 通过 / 0 失败
```

测试脚本本身改过 10 次（注释里都留了 bug 原因 + 解决方案），
主要是处理**目标的非确定性**：进程被系统重启、UI 停顿时分配活动归零、
系统进程不在 `enumerate_applications()` 里。这些都不是工具的问题，
但如果不处理，会把「环境波动」误报成「工具坏了」。

---

## 5. 真实调用示例

### 5.1 用户的 metasec_ml.so 形态（结构已知）

```python
vm_trace(
    serial="3e2ff172", pid=<pid>, so_name="libmetasec_ml.so",
    dispatch_offset="0x261820",   # adr x22, #0x2F50D0 之后的派发点
    ctx_reg="x20",                # ctx 在 x20
    opcode_expr="sp+8",           # opcode 在栈上
    reg_base_offset=0x6070,       # 寄存器堆在 ctx+0x6070
    max_ops=200, duration=5,
)
```

### 5.2 机制验证（无 VM 样本时）

```python
vm_trace(
    serial="3e2ff172", pid=3140, so_name="libc.so",
    dispatch_offset="0x48d3c",    # malloc 入口
    ip_mode="reg", ip_reg="x0",   # 不从 ctx 解引用（这里 x0 是 size）
    opcode_expr="sp+8",
    max_ops=3, duration=3,
)
# -> ops: [{"seq":1,"ts":0,"tid":...,"opcode":<u64>,"opcode_source":"sp+8",
#           "pc":"0x...","ip_source":"reg:x0",...}, ...]
```

### 5.3 验证结构配置对不对（改参数后先跑这个）

```python
vm_regs_snapshot(
    serial, pid, "libmetasec_ml.so",
    dispatch_offset="0x261820", ctx_reg="x20",
    opcode_expr="sp+8", reg_base_offset=0x6070,
)
# -> 返回 vm_pc / ip_source / ctx / ctx_source / reg_base / reg_base_source
#    / regs / opcode。哪一项是 null，看对应 *_source 就知道问题在哪。
```

---

## 6. 已知边界（如实标注）

1. **VM 语义未验证**。本机没有 VM 样本，`metasec_ml.so` 的
   opcode → 语义映射、handler 表都无从验证。已验的是**机制**：
   hook 能挂、参数真生效、不卡目标、错误能被明确诊断。
   要验语义需要真实样本。

2. **只挂一个派发点**。只能看到经过该点的指令。VM 有几百个派发点时，
   挂哪个就只能看哪段路径。

3. **`prog_base` 两跳路径是某一类壳的实测值**（0x240 / 0x1A0）。
   `vm_trace` 里传 `prog_base_p1_offset=-1` 可彻底关掉；
   `vm_breakpoint` 里靠 `data_base_enabled`。

4. **`dump_vm_state_auto` 未参数化宽度**：它的定位是"盲扫找候选"，
   实测在本轮真机上本来就不可用（4MB 扫不完 60 秒），
   保留它是因为在更小的目标上仍有意义。若要彻底参数化，需要先解决性能问题。

5. **`vm_trace` 不能边跑边看**。实测逐条 send 会把目标拖死，
   所以必须在 JS 侧累积、采完一次性返回。

---

## 7. 怎么验证这次改动

```bash
# 回归（必须全过）
.venv/bin/python tests/test_regressions.py

# 真机机制验证（需要设备 + frida-server 在跑）
.venv/bin/python tests/manual_vm_trace_device.py

# 可选：换目标
.venv/bin/python tests/manual_vm_trace_device.py com.android.settings
```

真机验证需要 `frida-server` 在跑。本轮实测它会被系统反复杀掉，
重启方式：`mda MCP 的 start_frida`，或
`adb shell "su -c 'setsid /data/local/tmp/frida-server -D'"`。
