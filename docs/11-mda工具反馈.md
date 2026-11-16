# 使用反馈处理记录（第 32 轮）

来源：一位 AI 代理用 mda 分析加固 App（sscronet.so，4.9MB，12160 函数）
连续 32 轮后的反馈。本文逐条记录核实结果与处理。

---

## 一、最影响效率的 3 个问题

### 问题 1 ✅ 成立 —— hold 断点后读内存失效

**反馈**：

```
set_breakpoint(hold=True) → 命中，线程挂起
read_runtime_memory(runtime_addr=0x6d82600810)
→ {"error": "InvalidOperationError: session is gone"}
```

**核实**：成立。原文文档写着「挂起状态下可以放心调用」，这个承诺过头了。

根因在 `server/dyn/rebase.py`：

```python
script = self.session.create_script(...)   # 用的是同一个 frida session
```

`create_script` 依赖的 session 在 hold 挂住线程后可能失效，
所以「走独立脚本」这句话只对了一半——脚本独立，session 不独立。

**处理**（`server/dyn/rebase.py` 新增 `read_memory_proc`）：
走 `adb shell + dd` 读 `/proc/<pid>/mem`，**完全不经过 frida**。
`read_runtime` 改为先走这条链路，失败再回退 frida，返回里标 `via` 字段。

实测：

| 大小 | 耗时 |
|---|---|
| 16 字节 | 0.13s |
| 4096 字节 | 0.17s |

实现要点：按 4096 页对齐分块，每页一次 `dd`（约 30ms），
再裁掉页内偏移。**不能用 `bs=1`** —— 那样要 dd 循环 4096 次，实测 4KB 要 12 秒。

---

### 问题 2 ✅ 成立 —— hit_analysis 取到旧命中

**反馈**：

```
1. 在 0x2da314 下断点 → 命中 → hit_analysis 正常
2. remove_breakpoint(0x2da314)
3. 在 0x2d8a48 下断点 → 触发
4. hit_analysis() → 仍然返回 0x2da314 的旧命中，hits_total 一直是 1
```

**核实**：成立。`hit_analysis` 取 `hits[-1]`，而 `remove_breakpoint`
只摘钩子，**不清命中队列**，旧记录一直留着。

**处理**：
1. `hit_analysis` 新增 `bp_id` 参数，按断点过滤
   （`bp_id` 形如 `serial:pid:so:2d8a48`，末段是十六进制静态地址）
2. 新增 `clear_hits(serial, pid)` 工具，手动清空命中队列
   （同时清 `_pending_tokens` 与 `_events`，避免 poll_events 又翻出来）

---

### 问题 3 ❌ 不成立 —— string_refs 的 function 字段是对的

**反馈**：

```
string_refs("sscronet.so", 0x89324)
→ {"string": "x-gorgon", "refs": [{"site": 3135252, "function": "sub_2fd470"}]}
3135252 = 0x2fd714
用户说：实际入口是 0x2fd6e4（paciasp 位置），mda 报错了
```

**核实**：**mda 没错**。实测 `0x2fd6e4` 处的指令：

```
0x2fd6e0  adrp x1, #0x81000
0x2fd6e4  add  x1, x1, #0x930      ← 用户说的"paciasp 位置"
0x2fd6e8  bl   #0xf7980
```

这是 `adrp` 的配对 `add`，**不是函数入口**。真正的函数入口以
`paciasp` / `stp x29, x30, [sp, #-N]!` / `bti c` 开头。

`0x2fd714` 归到 `sub_2fd470 + 0x2a4` 是正确的：`0x2fd470` 的 size 是 `0xcd4`。

**但反馈里有个真实痛点**：只给函数名、不给偏移，用户无法判断
命中点是函数头还是内部——他据此分析错了 3 轮。

**处理**：`string_refs` 每条引用补上：
- `site_hex` —— 十六进制地址（原来只有十进制）
- `function_entry` —— 函数入口地址
- `offset` —— 函数内偏移
- `is_entry` —— **明确告诉调用方这是不是函数入口**
- 落不到任何函数时给 `note` 说明原因

---

## 二、新功能

### 功能 1 ⭐⭐⭐⭐⭐ search_insn —— 已实现

**反馈原话**：

> 这 32 轮里最有效的突破，是我自己写 capstone 脚本扫出来的：
> 找所有 `str x?, [x?, #0x1100]`，一步定位到 `TTConfigManager`（`sub_32C7E0`），
> 这是前面 20 多轮都没找到的。

**为什么必须内置**：在这之前 mda 只有 `search_bytes`（按字节匹配），
它表达不了「所有 `str` 到 `[x?, #0x1100]` 的指令」这类语义查询。

**实现**：`server/core/insn_search.py` + `server/mcp_server/tools.py` 的 `search_insn` 工具。

```
search_insn(so_name="sscronet.so", mnemonic="str", operand_pattern="[x*, #0x1100]")
```

实测（复现用户的发现）：

```
3.6s | scanned=997597 matched=1
0x32dbe0  str x0, [x28, #0x1100] | sub_32c7e0 +0x1400
```

**和用户手写脚本的区别**：
- 助记符支持通配（`str*` 覆盖 str/strb/strh/strsw）
- 操作数为**子串匹配**（`[x*, #0x1100]` 能命中 `x19, [sp, #0x1100]`）
- 自动带上所在函数与函数内偏移
- 支持 `func_filter` 只搜指定函数（提速）

**踩过的坑**（已写进代码注释）：
初版把操作数模式当「完整操作数字符串」精确匹配，
而 `str x19, [sp, #0x30]` 的 op_str 是 `"x19, [sp, #0x30]"`，
用 `^\[x...\]$` 永远匹配不上，搜索结果恒为空。改为默认子串匹配。

---

### 功能 2 xrefs_struct_field —— 等价于 search_insn 的语义封装

未单独实现。`search_insn` 已经覆盖这个场景：

```
search_insn(so_name, mnemonic="str", operand_pattern="[x*, #0x1100]")   # 写
search_insn(so_name, mnemonic="ldr", operand_pattern="[x*, #0x1100]")   # 读
```

先做前者，等有真实的「按结构体名聚合」需求再封装。

---

### 功能 3 ✅ probe_hits 带寄存器捕获 —— 已实现

**反馈**：

> 现在 probe_hits 只返回命中次数。它已经用 Interceptor 挂上了，
> 顺手抓寄存器几乎零成本。这个不需要 hold，风险低，适合高频函数。

**实现**：

```
probe_hits(..., capture_regs=["x0", "x1", "lr"], max_samples=20)
→ samples: [{x0: "0x...", x1: "0x...", lr: "0x...", tid: 123, n: 4}]
```

同一组寄存器值反复命中只留一条并累加 `n`（去重），高频函数下不会爆。
**默认空数组、不采样**，行为与旧版完全一致。

---

### 功能 4 ✅ 启发式栈回溯 —— 已实现

**反馈**：

> backtrace 在 PAC/无 fp 的 so 上只有 2 帧。
> 希望扫描栈内存，找"落在代码段且前面有 bl 指令"的值作为候选帧。
> 这比 DWARF CFI 实现简单，准确率也够用（对逆向来说，"候选"比"空"有用）。

**实现**：`get_callstack(..., method="scan", scan_bytes=1024)`

判据（保守，宁可少给也不错给）：
1. 值落在某个已加载模块的 `[base, base+size)` 内
2. 该地址 `-4` 处的指令是 `bl`（编码高 6 位 `0b100101`）或 `blr`

返回里标 `heuristic: true` + `note`，**不冒充精确调用栈**。
`method="accurate"` 保持原行为（默认）。

---

### 功能 5 ✅ disassemble 对齐提示 —— 已实现

**反馈**：

> disassemble(addr=0x36c9b8, size=100) → 第一条 "cbz x21, #0x36ce6c"
> 但 capstone 在 0x36c9b8 解码得到 "bl #0x2c5fd4"，两者不一致。

**核实**：**无法复现，mda 是对的**。实测：

```
mda disassemble(0x36c9b8)        → adrp x3, #0xc6000
独立 capstone 从 0x36c9b8 解码   → adrp x3, #0xc6000     ← 完全一致
独立 capstone 从 0x36c9b0 解码   → bl #0x1e4aa8 (0x36c9b0), ..., adrp x3 (0x36c9b8)
```

用户报的 `cbz x21` 和 `bl #0x2c5fd4` 都对不上，可能是样本版本不同或记错。

**但反馈暴露了文档缺失**：工具没给"起点有没有被挪动"的信息，用户无法自证。

**处理**：返回改为对象（数组放在 `insns` 字段），带上：

```json
{
  "requested_addr": "0x36c9b8",
  "first_insn_addr": "0x36c9b8",
  "aligned": true,
  "count": 10,
  "insns": [...]
}
```

未对齐时给 `align_note` 说明实际从哪开始解。

---

## 三、几个小的

| 反馈 | 处理 |
|---|---|
| `trace_call_tree` 看不到尾跳转 | **未改**。这是 ARM64 尾调用的固有现象，不是 bug。已在文档说明：调用者落在自己内部说明是尾调用，真实调用方要往上找一层 |
| `MODULE_NOT_LOADED` 误报 | **已在前几轮修复**：`find_module` 加了 lib 前缀双向匹配 + `set_breakpoint` 拒绝假成功 |
| `watch_module` 上限 4000 不够 | **未改**。12160 函数的样本要挂满会拖死目标。建议用 `offset_range` 分段扫 |
| `perf_watch` 0 命中 | **部分改善**：返回里已带 tid 与 hint。完整方案见下 |

---

## 四、最有价值的一条建议

**反馈原话**：

> mda 最有价值的差异点是「静态模型 + 动态现场」的结合——
> `locate_runtime_addr`、`hit_analysis`、`function_at` 这套东西，frida 原生没有。
> 但现在的瓶颈是：静态侧的「查询能力」太弱。
> 缺的是「指令级模式匹配」。补齐这一块，mda 就能从「辅助工具」变成「逆向主力」。

这个判断我们认同，`search_insn` 就是按这个方向做的。

---

## 五、未处理项与原因

| 项 | 原因 |
|---|---|
| `xrefs_struct_field` | `search_insn` 已覆盖；等有真实聚合需求再封装，避免做无用抽象 |
| `watch_module` 上限提升 | 挂满 12160 个探针会拖死目标，不提供这个能力是刻意的 |
| `trace_call_tree` 尾跳转 | ARM64 固有现象，工具无法"修"，只能文档说明 |
| `perf_watch` 默认 tid 选择 | 硬件观察点只有 4 槽位且按线程生效，自动选错是常态。返回里已给 tid 列表与 hint，需要用户按提示换线程重试 |

---

## 六、回归

新增 `R97` 锁住本轮全部修改：

- `read_memory_proc` 存在且被 `read_runtime` 优先使用（双链路）
- `hit_analysis` 有 `bp_id` 参数、`clear_hits` 工具已注册
- `search_insn` 的操作数是子串匹配（不是精确匹配）
- `probe_hits` 默认不采样寄存器
- `get_callstack` 有 `method="scan"` 且 JS 语法合法
- `disassemble` 返回带 `aligned` / `first_insn_addr`
- `string_refs` 返回带 `offset` / `is_entry`
