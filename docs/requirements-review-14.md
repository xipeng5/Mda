# mda 14 项工具能力需求评审

> 评审日期：2026-11-13
> 代码基线：`server/`（core 静态 / dyn 动态 / mcp_server 工具层，103 工具）
> 方法：**不信转述，全部回代码 + 跑样本实测**。样本为真机 ARM64 so：
> liblog / libbase / libcutils（健康）、libanti_complete_patched（1984 函数）、
> libsgmainso-5.5.110 dump（2656 函数，无节表）、libsgmainso-6.7.260202（3012→4367 函数，无节表）。
> 基线回归：`test_e2e 14/0`、`test_shell_sample 9/0`、`test_dyn_runtime 26/0`、`test_regressions 590/0`。

---

## 一、判定总表（14 项）

图例：**已有** = 等价能力已存在；**需增强** = 有骨架但达不到需求；**真缺失** = 完全没有；**不该做** = 建议拒绝并说明理由。

| # | 需求 | 判定 | 一句话结论 |
|---|---|---|---|
| 1 | net_request_dump 抓最终出网请求 | **不该做**（改做两个替代） | 抓包/解密超出静态动态分析器定位，且现有工具已能覆盖它的真实目标（看 header 内容） |
| 2 | java_hook 0 命中自动探测兄弟方法 | **已有** | `sibling_probe` 默认开启，且已有 `diagnosis.suggestion` |
| 3 | coverage_report 枚举所有路径＋标注查没查过 | **需增强**（收窄为"已执行覆盖率"） | 不可能枚举"所有路径"；但"哪些函数真的执行过/哪些没查"已有 `watch_module` + `probe_hits` |
| 4 | dex_smali（jadx 失败时降级） | **真缺失**，但**不该**做 smali 全反编译 | 搜遍 server/ 无任何 dex 处理；合理形态是"dex 字符串/方法表提取"而非 smali 反编译 |
| 5 | xref_scan 替换坏掉的 string_refs | **需增强（真 bug 已复现）** | `string_refs` 对"引用指向字符串中部/短串"确实返回 `no string at or before address`，实测 libbase 237 个引用目标里 128 个查不到 |
| 6 | function_repair 修函数边界 | **转述不成立，但有真 bug** | 六个样本 `size==0` 全为 0；真 bug 是 IDC 建的函数不进 `_starts`，`function_at` 查不到 |
| 7 | plt_resolve 精确 PLT 地址 | **真 bug（已复现）** | `elf_model.py:435` 的 `& ~0xF` 让**一半** PLT 键错位 8 字节 |
| 8 | read_std_container 解析 libc++ string/vector/map | **真缺失** | `memread.py` 只有 11 个标量类型，无任何容器/布局建模 |
| 9 | breakpoint hold 真正可用 | **部分已有，一处真 bug** | hold 机制是真的（JS 侧 `recv().wait()`）；但"同址重复下断 + hold=True"会吞掉 hold |
| 10 | hook_safe 带保护的 hook | **需增强** | 已有 `probe_hits`/`verify_breakpoint`/`detach_target`，缺"批量 hook 前的预检闸门"与"命中风暴自停" |
| 11 | 支持 hook 函数中部 | **已有（能力），缺一层引导** | `probe_hits` 对挂不上的点明确报 `INTERCEPT_FAILED`；`suggest_breakpoints` 给四个候选位。缺"挂不上时自动改推荐" |
| 12 | session_persist 别动不动重置 | **需增强（真痛点，根因明确）** | 21 处工具用严格 `_session.get()`（大小写/路径/版本号全不匹配就抛），只有 4 处走别名解析 |
| 13 | addr_calc 地址换算 | **已有（工具），转述数字有误** | `_addr_facts` 已返回 hex/dec/函数/偏移/段/最近函数；转述的 `0x2fd794` 本身就等于 3135380，无换算错误 |
| 14 | verify_analysis_target 确认设备 so 与本地同一文件 | **真缺失** | `runtime_modules` 只给 name/base/size/path，**无任何 hash**；`metadata` 也没有 |

---

## 二、五个点名转述的核实（a–e）

### (a) `string_refs` 是否返回空？根因在 `_collect_function` / `_linear_scan`？

**判定：半真。** 健康路径正常；**引用指向字符串中部或短串时确实返回空**（这是需求 #5 的真身）。
根因**不在** `_collect_function`，而在 `_linear_scan` 的死代码 + `string_starting_at_or_before` 只向前找**已提取**的字符串。

#### 1. 健康路径是对的（不是"恒空"）

```
liblog.so    字符串 88，有引用 84
libbase.so   字符串 145，有引用 101
libcutils.so 字符串 245，有引用 130
```
MCP 实调：`string_refs("liblog.so", 0x2DD3)` → `{"string":"events","refs":[{"site":23944,"function":"android_name_to_log_id"}]}`

#### 2. 真缺口：`data_refs` 里查不到字符串的比例很高

`libbase.so`：`data_refs` 引用目标 237 个，**`string_refs` 查不到的 128 个（54%）**。
MCP 实调（`.venv/bin/python` 直连工具层，未转发）：

```
string_refs("libbase.so", 0xb793) → {"error": "no string at or before address"}
string_refs("libbase.so", 0xbb9a) → {"error": "no string at or before address"}
string_refs("libbase.so", 0xbc55) → {"error": "no string at or before address"}
```

原始字节证明这些地址**确实指向真实字符串**：

```
0xb793 → b'::~bigint()\x00REL\x00]\x00is not a regular file or symbo…'   ← 指向 ']'（1 字符）
0xbb9a → b'sign_pow10(int)\x00ms\x00ANDROID_LOG_TAGS\x00[%s]:%d\x00…'  ← 指向 'ms'（2 字符）
0xbc55 → b'perator<<=(int)\x00, \x00, received \x00system/libbase/lo…'  ← 指向 ', '（2 字符）
0xb3a5 → b'\x00/proc/self/exe\x00.\x00/\x00({ __typeof__(lseek(fd(),0…' ← 指向 '.'（1 字符）
```

128 个缺失按性质分类：

| 类别 | 个数 | 原因 |
|---|---|---|
| **≤3 字符** | **32** | `strings.py:16` `_MIN_LEN = 4`，短串根本没进索引 |
| 不可打印（UTF-8 多字节/二进制） | 50 | `strings.py:28` 只认 `0x20..0x7E` |
| 零字节（.got 槽等非字符串） | 46 | 正常，不是字符串 |
| ≥4 字符可打印 | **0** | ← 说明 ASCII 主体没问题 |

**结论：需求 #5 的抱怨是真的，但根因是"短串/多字节被过滤"，不是引用图坏了。**
它自己写 `adrp+add` 脚本"找到"了引用——因为它直接算地址不查字符串表。

#### 3. 附带：`_linear_scan` 是死代码（会在无节表样本上放大问题）

`server/core/xref.py:162`：
```python
text = so.section_at_name(".text") if hasattr(so, "section_at_name") else None
```
`SoFile` **没有** `section_at_name`（全库 `def section_at_name` 零命中，真实存在的是私有
`elf_model.py:297 _sec_by_name`）。于是 `hasattr` → False → `text = None` →
回落 `.text` 节（`xref.py:163-164`）→ 无节表样本 `sections == []` →
`xref.py:165-166` 直接 `return`。

实测 `xref._linear_scan_added`：

| 样本 | sections | `_linear_scan_added` | 手跑同算法可补新目标 |
|---|---|---|---|
| liblog.so | 24 | 105 | 0 |
| libbase.so | 24 | 176 | 0 |
| **libsgmainso 6.7** | **0** | **0** | **509（32 个落在字符串上）** |
| **libsgmainso 5.5.110** | **0** | **0** | **548（16 个落在字符串上）** |

最需要它的加固样本上，它一次没跑过。

### (b) `function_at` 是否返回 `size=0`？

**判定：不成立。但存在同族的真 bug。**

#### 1. `size=0` 已被兜住

`elf_model.py:520-538`：
```python
gap = (starts[i + 1] - addr) if i + 1 < len(starts) else 0x10000
if fn.size <= 0 or fn.size > gap:
    fn.size = min(gap, 0x10000)
```
实测六个样本（含 4367 函数的 6.7）：

| 样本 | 函数数 | `size<=0` | size 最小 | size 最大 |
|---|---|---|---|---|
| liblog.so | 111 | **0** | 8 | 0xd84 |
| libbase.so | 386 | **0** | 8 | 0xe74 |
| libcutils.so | 168 | **0** | 8 | 0x9b8 |
| libanti_complete_patched.so | 1984 | **0** | — | 0xc948 |
| libsgmainso 5.5.110 | 2656 | **0** | — | 0x81bc |
| libsgmainso 6.7 | 4367 | **0** | — | 0x1578c |

6.7 的 `function_at` 在函数区间 `[0x51ffc, 0x1aa278)` 内 352415 个地址中只有 5257 个（1%）返回 None。
不是"大量返回 size=0"。

#### 2. 真 bug：IDC 建的函数对 `function_at` 不可见

`server/scripting/idc.py:71-72`：
```python
def _refresh_ranges(self) -> None:
    self.so._func_ranges = sorted((f.addr, f.end) for f in self.so.functions.values())
```
只重建 `_func_ranges`，**没调 `so._refresh_functions()`**；而 `function_at`
（`elf_model.py:769-776`）用的是 `self._starts` 二分。

复现（liblog 的 `.text` 空洞 `0xdf5c`）：
```
before: function_at(0xdf5c) = None
run_idc('MakeFunction(0xdf5c); MakeName(0xdf5c,"hook_target");')
after : function_at(0xdf5c) = None      ← 仍是 None
        0xdf5c in so.functions        = True   ← 明明在表里
        disasm_function(0xdf5c)       = 0 条
        xrefs_from(0xdf5c)            = []
手动 _refresh_functions() 后 → Function(addr=0xdf5c, name='hook_target') ✅
```

### (c) PLT 地址是否差 8 字节？

**判定：属实，命中率 100%，影响面比转述更大。**

#### 根因

`server/core/elf_model.py:435`：
```python
pending = (insn.operands[1].imm, insn.address & ~0xF, insn.operands[0].reg)
#                              ^^^^^^^^^^^^^^^^^^ adrp 指令地址被向下取整到 16 字节
```
AArch64 PLT stub = `bti c`(4B) + `stp`(4B) + `adrp`(4B)，`adrp` 落在 **stub+8**（`0x...8` 结尾）。
`& ~0xF` 抹成 `0x...0`，键就少 8。`elf_model.py:440` 用这个错地址写 `plt_map`。

#### 实测

| 样本 | 真桩数 | 键正确 | 键错位 8 字节 | 错位可用 `&~0xF` 解释 |
|---|---|---|---|---|
| liblog.so | 105 | 53 | **52** | 52/52 |
| libbase.so | 235 | 118 | **117** | 117/117 |
| libcutils.so | 174 | 87 | **87** | 87/87 |

```
真桩 0xe028 → create_android_logger ；plt_map[0xe028]=None，plt_map[0xe020]=create_android_logger
bl  目标 0xe028 → plt_name(0xe028)=None → resolve_call 返回 None → call_chain continue → 边消失
```

#### 后果链（全部实测）

1. **call_chain 丢边**：
   ```
   libbase 的 _ZN7android4base10boot_clock3nowEv 调用 clock_gettime
   → call_chain 里既没有 "clock_gettime" 也没有 "plt_" 占位   ← 边消失
   对照：调用 abort 的函数，链里正常出现 "abort"
   ```
2. **callers_of 漏一半**：`session.py:374` 用 `plt_map` 键查 `_calls_to`，键错就查不到。
   ```
   callers_of("...ReadFdToString...") → 0 条（实际 2 个调用点）
   callers_of("abort")                → 165 条 ✅
   libbase：112 个导入符号的调用者完全查不到
   ```
3. 落在 `.plt` 的调用点解不出符号：liblog 57%(257/450)、libbase 62%(1137/1831)、libcutils 44%(372/844)。

#### 修法与风险

`insn.address & ~0xF` → `insn.address`。PLT0 头部会多一个候选，但 `got2name.get(...)`
已经天然过滤。**回归红线：`test_e2e` 的「PLT 解码 105 个」必须仍是 105**；
若变 106，说明过滤没兜住。

### (d) `set_breakpoint(hold=true)` 是否返回 `hold:false`？

**判定：只在"同址重复下断"这一条路径成立。hold 机制本身是真的，"hold 是假的"的旧结论已过时。**

#### 1. hold 实现完整

`debugger.py:179-190`（注入到目标的 JS）：
```javascript
if (hook.policy === 'hold') {
    holdSeq += 1;
    var token = 'mda_resume:' + hook.runtime + ':' + ctx.threadId + ':' + holdSeq;
    payload.token = token;
    var op = recv(token, function () {});
    send(payload);
    try { op.wait(); } catch (e) {}     // ← 线程真的阻塞
}
```
`debugger.py:941` `hit.held = bool(token)`；`service.py:1042-1058` `_resolve_held` 三级优先。

#### 2. 真 bug：早退分支吞掉 hold 变更

`server/dyn/service.py:227-229`：
```python
with self._lock:
    if bp_id in tgt.breakpoints:
        return {**tgt.breakpoints[bp_id], "existing": True}   # ← 直接返回旧记录
```
这个早退在 `service.py:242` 的 `dbg.set_breakpoint(..., policy="hold" if hold else "resume")`
**之前**。

离线复现（`tests/fake_frida.py` + StubDebugger）：
```
首次 set_breakpoint(0x1234, hold=False) → 返回 hold=False，dbg 收到 'resume'
同址 set_breakpoint(0x1234, hold=True)  → 返回 hold=False（existing=True）
                                          dbg 全程只收到一次 'resume'，从未收到 'hold'
换址 set_breakpoint(0x2344, hold=True)  → 返回 hold=True，dbg 收到 'hold' ✅
```
后果：AI 以为"改成 hold 了，下一步会停"，实际一直 resume，`poll_events` 永远等不到 `paused`。

### (e) 是否已有等价的 std 容器解析能力？

**判定：完全没有。真缺失，且是本次评审技术难度最高的一项。**

1. `memread.py` 全文 grep `std::|STL|sso|容器|小字符串|basic_string|vector<` → **零命中**
2. `memread.py:59-71` `_TYPES` 只有 11 个标量 + `pointer`；`memread.py:82` `SUPPORTED_TYPES` 就是它们
3. `read_pointer`（`memread.py:623`）能按 `depth` 跟链、能报 `null/cycle/unmapped/underflow/overflow`，
   但只懂"每层读一个指针宽度"，不懂任何布局：
   - `std::string`（libc++ 24B）：`__short`/`__long` 靠**最后 1 字节最高位**区分
   - `std::vector`（libc++ 24B）：`begin`/`end`/`cap` 三指针，长度要相减除 `sizeof(T)`
   - `std::shared_ptr`：对象指针 + 控制块指针
4. 全库 grep `vtable|rtti|typeinfo|structs` → 零命中

---

## 三、其余 9 项逐条判定

### #1 net_request_dump —— 不该做（改做两个替代）

**为什么不该做**
- 抓最终出网请求 = 抓包 + TLS 解密，超出"so 静态+动态分析器"的定位；且
  `记忆 0abb636b` 记了阿里系 App 的风控事故（批量 hook 直接触发拦截页），
  抓包解密是更强的信号。
- 它自己试过 tcpdump → 加密，这条路的失败原因是**密码学**，不是 mda 缺工具。

**它真正想回答的是"最终 header 里有什么"**，这有两个通用替代（都能做成参数化工具）：

| 替代 | 形态 | 为什么通用 |
|---|---|---|
| `java_hook` 抓 `Map`/`JSONObject` 入参 | 已有：`capture={"args":true,"expand_map":true}`（`java_bridge.py`） | 任何 App 的 header 都是 Map/JSONObject，不依赖包名 |
| 在 `SSL_write`/`write` 上 hook 前 N 字节 | 新增，参数是 lib 符号名（`libssl.so`/`libc.so`），不是 App 符号 | 用导出符号而非 App 内部符号，换目标仍可用 |

**建议**：不新增 `net_request_dump`；改为在 `java_hook` 的 docstring 里写清
"要在 header 上用 `capture.expand_map`"，并新增 `hook_export(symbol="SSL_write", capture={"arg2_bytes":256})`
这类**按导出符号**的通用 hook。

### #2 java_hook 0 命中自动探测兄弟方法 —— 已有

`sibling_probe: bool = True`（`tools.py:4762`、`java_bridge.py:618`），
0 命中时填 `diagnosis.sibling_methods_called` + `suggestion`（`java_bridge.py:1497-1513`）。
docstring 也写明了"同类里 X 被调了 12 次——真正干活的很可能是它"。
**判定：已有等价能力，不需新增。**（可增强：把 sibling 探测扩到**父类/接口**，目前是同类的其它方法）

### #3 coverage_report —— 需增强，但必须收窄语义

"枚举所有可能路径"在静态层面是不可判定问题（间接跳转、VM、JIT）。做成工具只会产出
"看起来完整其实全是猜测"的假覆盖率，违反项目"不造假数据"铁律。

**可做的通用版本**：`coverage_report(serial, pid, so_name)`，只回答**可验证的三件事**：

| 维度 | 数据来源（已在代码里） |
|---|---|
| 哪些函数**真的被执行过** | `watch_module` 已实现（`tracer.py`，在函数入口撒点 + 均匀采样） |
| 哪些地址**下断能挂上** | `probe_hits` 已实现（`INTERCEPT_FAILED` 明确区分"挂不上"与"没执行"） |
| 哪些函数**我查过** | 新增：`DynSession` 里记一张"已查地址"表，工具读它 |

**判定：需增强**——把散在 `watch_module` / `probe_hits` 的能力聚合成一个"我查了哪些、哪些没查"的
报告；**不做**"所有可能路径"。

### #4 dex_smali —— 真缺失，但请**不要**做 smali 反编译

**现状**：搜遍 `server/` 无任何 dex/smali/jadx/dalvik 解析（`grep -riE "dex|smali|jadx"`
只命中 `DexClassLoader` 这类字符串字面量）。

**为什么不做 smali**：smali 反编译是 jadx/baksmali 的领域，自己写一个既做不好也维护不起。
它真正卡住的是"**这个 1762 指令单元的类里，哪个方法碰了 header**"——这只需要
**方法表 + 字符串常量 + 方法间调用**，不需要可读的 smali。

**通用形态**（一份自研 dex 解析，约 400 行，零第三方依赖）：

```
dex_info(apk_or_dex)          → 类数/方法数/字符串数
dex_find_class(pattern)       → 类名正则（含 * ? 通配）
dex_list_methods(class_name)  → 方法签名 + 代码偏移 + 指令数（不做反编译）
dex_strings(class_name)       → 该类引用的字符串常量（这才是定位 header 的入口）
dex_callers(method_sig)       → 方法级 invoke 反查
```
`dex_list_methods` 的"1762 指令单元"照样能报出来（`code_units` 字段），足够判断"这函数多大"。

**判定：真缺失，优先级中等**——但实现形态是"dex 索引器"而非"smali 反编译器"。
**风险**：dex 格式解析是新模块（新依赖面 0，但工作量大）。**如果原清单只要"能定位到方法"，
上面 5 个接口够用；如果要"可读代码"，直接建议调 jadx 二进制，mda 不重造。**

### #5 xref_scan —— 需增强（真 bug 见 (a)）

**判定：需增强。** 具体三件事：
1. 短串（`_MIN_LEN` 从 4 降到 1，或分档：`list_strings` 用 4、`string_refs` 用 1）
2. UTF-8 多字节（`strings.py:28` 的 `0x20..0x7E` 判定改成"合法 UTF-8 序列即接受"）
3. `_linear_scan` 死代码修复（`xref.py:162`）

不需要新增 `xref_scan` 工具——`string_refs` 修好后它自然可用。
**建议在 `string_refs` 返回里加一个 `"reason"` 字段**：当查不到时明确说
"该地址指向 <4 字符短串 / 非法 UTF-8，当前字符串索引不收录"，而不是笼统的
`no string at or before address`。这一条能直接省掉它好几轮 debug。

### #6 function_repair —— 转述不成立，但有真 bug

详见 (b)。**判定：不做 `function_repair` 新工具**（`size=0` 不成立），
但**必须修** IDC 建函数不进 `_starts` 的 bug。另有一个已知边界应在文档里写清：
6.7 样本 exec 段开头 `0x0..0x51ffc`（19%）完全没有函数覆盖，那是 `.init`/`.plt0`/
未发现的叶子函数区，不是 bug。

### #7 plt_resolve —— 真 bug（见 (c)）

一行修复。**判定：修 bug，不新增工具**。

### #8 read_std_container —— 真缺失（见 (e)）

**建议形态（参数化 ABI，符合项目"禁止特调"铁律）**：

```
read_container(kind="std_string|std_vector|std_map|std_shared_ptr",
               addr=0x..., abi="libc++",      # 可传 libstdc++
               elem_type="uint8|pointer|...", # vector/map 元素宽度
               layout=None)                   # 可选覆盖 data_off/size_off/cap_off
→ {value, size, capacity, sso, ambiguous, layout_source}
```
- `abi` 枚举：`libc++`（NDK 默认）/ `libstdc++`（GCC）
- 布局参数可传，默认值在返回里标 `layout_source: "default(libc++ NDK r26)"`
- **SSO 判定失败必须返回 `ambiguous: true` + 两种解释，不许猜**（这正是使用者错了 5 轮的地方）
- 必须能 `source="runtime"`（走 `memread.py` 已有的 `_read_exact_runtime`）

**判定：真缺失，优先级 P2**（它自选的前三里就有这条，说明消耗轮次最多）。

### #9 breakpoint hold —— 部分已有，一处真 bug（见 (d)）

**判定：修 bug，不新增工具。** 另建议 `set_breakpoint` 的返回里显式加
`"hold_effective": bool`，与请求的 `hold` 分开——只要两者不一致就是这种 bug 还在。

### #10 hook_safe —— 需增强

**现状**：已有 `probe_hits`（纯计数，不挂起）、`verify_breakpoint`（是否 armed）、
`detach_target`（清理所有 hook）。**缺三样**：

| 缺口 | 为什么重要 | 通用实现 |
|---|---|---|
| 批量 hook 前的预检闸门 | `记忆 0abb636b`：一次挂 317 个方法触发阿里风控 | `java_hook` 在 `max_classes>N`（默认 20）时**拒绝执行**并返回"请缩小范围或显式传 `allow_bulk=true`" |
| 命中风暴自停 | hook 高频方法会让 App 卡死/ANR | 在 JS 侧计数，超过 `max_calls` 后**自动 detach 并在返回里标 `auto_detached: true`**（不是静默继续） |
| hook 失败回滚 | 它把 App 弄崩 2 次 ANR | 捕获 `unable to intercept` 后立刻 `detachAll`，返回已回滚的清单 |

**判定：需增强，P1。** 这三条都是"防事故"，比新增能力更重要。

### #11 hook 函数中部 —— 已有能力，缺一层引导

**现状**：`probe_hits` 明确报 `INTERCEPT_FAILED`，docstring 写了
"实测同一区间 78 个入口里 19 个挂不上，它们多是函数内部块而非真入口"（`tools.py:3833`）。
`suggest_breakpoints` 已给四类候选（entry/after_call/before_ret/data_ref）。

**缺的引导**：`set_breakpoint` 失败时，**自动**跑一次 `suggest_breakpoints` 并返回
"这个地址挂不上，同函数里可挂的点有：…"。这是纯返回值增强，不改机制。

**判定：已有能力，建议增强返回值（P2）。**

### #12 session_persist —— 需增强（真痛点，根因明确）

**根因**：`session.get()` 是**严格键匹配**（`session.py:127` 抛 `KeyError: 未加载的 so: X`），
而工具层**只有 4 处**用别名解析 `_pick_so_by_name`（`tools.py:2047/4555/4609/5104`），
**21 处**直接 `_session.get()`（`tools.py:373/473/524/542/568/592/607/628/667/688/706/759/832/870/920/2374…`）。

于是：设备上是 `libsgmainso-6.7.260202.so`，本地 `load_so` 成 `libsgmainso.so`，
`string_refs("libsgmainso.so")` 有时能过（走别名）、`metadata()` 有时报 KeyError（走严格）——
**同一会话里行为不一致**，这正是它"至少 8 次 KeyError"的来源。

**修法（一处改，全域生效）**：把工具层的 `_session.get(so_name)` 统一换成
`_pick_so_by_name(_session, so_name)` 的包装（或在 `Session.get` 里内置别名回退 + 记录
`matched_by` 字段）。**判定：需增强，P0**（一行改动覆盖 21 处，直接消除它的高频挫败点）。

### #13 addr_calc —— 已有，转述数字有误

**现状**：`_addr_facts`（`tools.py:356`）对每个地址返回
`hex / dec / section / function{name,hex,dec} / offset_in_fn / is_function_entry / nearby_function`，
并且 `set_breakpoint`、`read_process_memory` 的返回里**都带 `addr_facts`**。

**转述核对**：它说"把 `0x2fd794` 算成 3135892，实际 3135380"。
实测 `0x2fd794 == 3135380`，而 `3135892 == 0x2fd994` —— **差的是它自己把 `7` 打成 `9`**，
不是工具算错。**判定：已有能力，转述不成立。**

可增强（低成本）：`_addr_facts` 加 `bit_width` 与 `"is_16_byte_aligned"`，并把
"你传的地址不是函数入口，最近入口在 X" 提到返回的**第一个字段**（现在在 `nearby_function` 里）。

### #14 verify_analysis_target —— 真缺失

**现状**：`runtime_modules` 只返回 `{name, base, size, path}`（`service.py:197-201`），
**没有任何 hash/大小校验**；`metadata` 返回 name/path/arch/functions/… 也没有 hash。
所以它"到第 47 轮才自己 md5 比对"是真的没工具可用。

**通用实现**（`verify_analysis_target(serial, pid, so_name_or_local_path)`）：

```
设备侧：adb shell "md5sum /data/app/.../libxxx.so"   （root 已有）
本地侧：hashlib.md5(open(local).read())
→ {same_file: bool, device_md5, local_md5, device_path, local_path,
   device_size, local_size, runtime_base, verdict}
```
- 不用 frida，纯 adb + hashlib，零风险
- 若设备路径不可读，退化为"按 size + 前 4KB 的 md5"（够判同一个文件）
- **返回里必须说明"这不等于 APK 里的同一份"**——设备上的 so 可能是解压/优化过的

**判定：真缺失，P1**（成本极低、收益极高：错了 47 轮才发现分析对象不对，是最大的浪费）。

---

## 四、优先级（按"能省多少轮 debug"排，不按实现难易）

### P0 —— 一行到几行，直接消除"假成功"和高频挫败

| 序 | 项 | 改动点 | 能省多少轮 |
|---|---|---|---|
| 1 | **#7 PLT `& ~0xF`** | `elf_model.py:435` 删 `& ~0xF` | 跨 so 反查恢复约 50%；不修则 112 个导入符号的调用者永远查不到 |
| 2 | **#12 会话别名统一** | 21 处 `_session.get()` 换别名解析（或 `Session.get` 内置回退） | 直接消掉它 8 次 KeyError，这是它最频繁的挫败点 |
| 3 | **#9 同址早退吞 hold** | `service.py:227-229` 早退前透传 policy + 返回 `hold_effective` | 消掉"以为在暂停其实在跑" |
| 4 | **#6 IDC 函数不可见** | `idc.py:72` 改调 `so._refresh_functions()` | 消掉"刚建的函数查不到" |
| 5 | **#5 短串/UTF-8** | `strings.py:16` `_MIN_LEN` 分档 + `:28` 接受 UTF-8 | 消掉需求 #5 的全部抱怨（54% 引用查不到） |

### P1 —— 真缺失/真风险，成本可控

| 序 | 项 | 改动点 | 收益 |
|---|---|---|---|
| 6 | **#14 verify_analysis_target** | 新增，adb md5 vs 本地 md5 | 避免"分析对象根本不对"的 47 轮浪费 |
| 7 | **#10 hook_safe 三件套** | 批量闸门 + 命中风暴自停 + 失败回滚 | 防 ANR/风控事故（已有两次真实教训） |
| 8 | **#5 附带 `_linear_scan` 死代码** | `xref.py:162` 换 `_sec_by_name` + `exec_regions()` | 无节表样本引用目标 +509/+548 |
| 9 | **#5 string_refs 的 `reason` 字段** | `tools.py:830` 返回具体原因 | 直接省掉"为什么空"的猜测轮次 |

### P2 —— 需要设计，成本高

| 序 | 项 | 说明 |
|---|---|---|
| 10 | **#8 read_std_container** | 参数化 ABI（libc++/libstdc++）+ 可覆盖布局 + 必须能报 `ambiguous` |
| 11 | **#3 coverage_report（收窄版）** | 聚合 `watch_module`/`probe_hits` + 新增"已查地址"表；**明确不做"所有路径"** |
| 12 | **#4 dex 索引器** | 类/方法/字符串/调用反查，**不做 smali 反编译** |

### P3 —— 不该做

| 序 | 项 | 理由 |
|---|---|---|
| 13 | **#1 net_request_dump** | 超出定位 + 风控面；改用 `java_hook` 的 `expand_map` + 按**导出符号** hook |
| 14 | **#6 转述的 `size=0` 修复** | 不成立，六个样本全 0，不用改 |
| — | **#2 / #11 / #13** | 已有能力，最多增强返回值 |

---

## 五、可合并项（一次改完、一次回归）

| 合并组 | 成员 | 共同点 | 回归红线 |
|---|---|---|---|
| **A. PLT 模型** | #7 + (#9 的 `plt_stubs`) | 都在改 `plt_map` 键的地址语义 | `test_e2e`「PLT 解码 105 个」仍 = 105；`callers_of` 计数上升 |
| **B. 符号/函数身份** | #6 + (#5 的键归一化) | 都改"函数身份"的一致性 | IDC 建函数后 `function_at` 立即可见 |
| **C. 会话/地址可用性** | #12 + #13 + #14 | 都是"我到底在操作哪个文件/哪个地址" | KeyError 归零；`addr_facts` 每个地址类工具都带 |
| **D. 采集面重做** | #5（短串+UTF-8） + #5（`_linear_scan` 死代码） | 都在改"字符串与数据引用的采集范围" | `list_strings` 条数变化要重设基线；短串样本能提取 |
| **E. 安全护栏** | #10 + #11 的引导 | 都是"hook 出事前后怎么兜" | 批量 hook 默认被拒；挂不上时给出替代点 |

不建议合并：#8（std 容器）独立做（新工具面 + 新 ABI 维度）；#3/#4 各自独立（不同模块）。
**#1 不做。**

---

## 六、通用性自检（铁律：禁止为特定 App hardcode）

按 `记忆 e47b9c87`（能力必须通用，禁止为特定 App/样本特调）逐项过：

| 项 | 修法是否通用 |
|---|---|
| #7 PLT 差 8 | ✅ 纯位运算修正，无样本名/偏移 |
| #12 别名解析 | ✅ 已有 `_pick_so_by_name` 的四级规范化，只是没铺开 |
| #9 hold 早退 | ✅ 逻辑修正 |
| #6 `_refresh_functions` | ✅ 机制修正 |
| #5 短串/UTF-8 | ⚠️ 分档阈值要按**通用类型**（标识符/多字节/UTF-16），不能按某 App 的字串特征调 |
| #14 hash 比对 | ✅ adb + hashlib，无任何 App 知识 |
| #10 护栏 | ✅ 阈值是**数量**（默认 20），不是类名 |
| #8 std 容器 | ⚠️ **最大风险**：必须 ABI 参数化 + 默认值标来源 + SSO 失败报 `ambiguous` |
| #3 coverage | ✅ 只报可验证事实，不猜路径 |
| #4 dex 索引器 | ✅ dex 是标准格式，与 App 无关 |
| #1 | 不做 |

**顺带发现的既有硬编码**（不在 14 项内，但违反同一条铁律）：

| 位置 | 硬编码 | 现状 | 建议 |
|---|---|---|---|
| `tools.py:5072` / `vmbreak.py:94` | `pattern_hex` 默认 `"750700f9"`（`str x21,[x27,#8]`） | 参数可覆盖 ✅，但默认只在一个壳上验过 | 返回里标注"默认特征仅在一个壳验证；其他壳需先用 `watch_module` 重标定" |
| `tools.py:3954` | `count_offset=0x194` / `array_offset=0x1a0` | 参数可覆盖 ✅，docstring 已写"经验值" | 已合格 |

---

## 七、附加发现（不在 14 项内，同属"看着成功其实没生效"）

### 附1 `build_xrefs(aggressive=True)` 在已建图时被 `cached` 分支吞掉

`tools.py:868-876`：`if prog.get("built"): return {...,"cached":True}`，不看 `aggressive`。

```
第一次 build_xrefs()              → functions = 386
再调 build_xrefs(aggressive=True) → {"cached": true, "functions": 386}
                                    函数数无变化，激进发现从未执行
```
而 docstring（`tools.py:855-859`）明确承诺能"捞到跳转表分发的 handler"。

### 附2 `build()` 先于 `discover()` 时新增函数永不入图（潜在）

`xref.py:118-119` 用 `_built` 守卫；`discover_functions`（`session.py:227-236`）在 build 之后
补的函数不会被回填。正常工具路径顺序是对的，但 `run_script`/插件里任何"先读
`x.called_by`（触发 build）再 `ensure_xrefs`"都会踩中：

```
先读 x.called_by（build，3012 函数）→ 再 ensure_xrefs（discover 补到 4367）
→ 已收集 3012 / 应收集 4367，缺口 1355
→ 逐个 ensure_function 补回后，数据引用站点 16276 → 22219（漏 5943 条）
```

---

## 八、验收清单

| 项 | 验收标准 |
|---|---|
| #7 | `test_e2e`「PLT 解码 105 个」仍 = 105；`callers_of("clock_gettime")` > 0；`call_chain` 里出现 `clock_gettime` |
| #12 | 用设备全名 `libxxx-1.2.3.so` 调任意静态工具都不再 `KeyError`；返回带 `matched_by` |
| #9 | 同址 `hold=False` → `hold=True` 后返回 `hold_effective: true`，且 debugger 记录了 `hold` 策略 |
| #6 | `run_idc("MakeFunction(x);MakeName(x,...)")` 后立刻 `function_at(x) != None` |
| #5 | 短串样本（`libbase` 的 `0xb793`）`string_refs` 能返回引用；无节表样本 `_linear_scan_added > 0` |
| #14 | `verify_analysis_target` 对同一文件报 `same_file: true`，对改动过的副本报 `false` |
| #10 | 批量 hook 超过阈值默认被拒；命中超过 `max_calls` 自动 detach 并标 `auto_detached` |
| #8 | `read_container("std_string")` 对短串/长串都正确；无法判定时返回 `ambiguous: true` |
| 整体 | `test_e2e 14` / `test_shell_sample 9` / `test_dyn_runtime 26` / `test_regressions 590` 全部不退化 |

---

## 九、一句话结论

- **(a) 半真**：不是"恒空"，是"引用指向短串/中部时查不到"——`libbase` 54% 的引用目标查不到，根因是 `_MIN_LEN=4` + 纯 ASCII 判定；`_linear_scan` 因 `section_at_name` 不存在而是死代码。
- **(b) 不真**：六个样本 `size<=0` 全为 0；真 bug 是 IDC 建的函数不进 `_starts`。
- **(c) 真**：`elf_model.py:435` 的 `& ~0xF` 让一半 PLT 键错位 8 字节，`callers_of`/`call_chain` 丢一半跨 so 反查。
- **(d) 半真**：hold 机制是真的；同址重复下断的早退分支会吞掉 hold 变更。
- **(e) 真缺失**：`memread.py` 只有 11 个标量，无任何容器/vtable/RTTI。
- **14 项里 3 项已有（#2/#11/#13）、1 项不该做（#1）、5 项是真 bug 或真缺失（#5/#7/#9/#8/#14）、其余需增强。**
- **最省轮次的三件事**：PLT 一行修复（#7）、会话别名统一（#12）、verify_analysis_target（#14）。
