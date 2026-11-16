# DWARF CFI 栈回溯（method="dwarf"）

> 实现于 2026-11-16。模块：`server/core/dwarf.py`；入口：`get_callstack(method="dwarf")`。

## 1. 解决什么问题

frida 的 `Thread.backtrace(ctx, Backtracer.ACCURATE)` 在**开了 PAC 且省略帧指针**
的 so 上实测只返回 2 帧，且是同一个地址重复——fp 链（x29 链）在 prologue
之后就被复用成普通寄存器了，扫不出来。

`.eh_frame` 是编译器生成的**权威**展开信息。它不依赖帧指针，而是描述
"某函数在某 PC 处：CFA（Canonical Frame Address）怎么算、返回地址存在哪"。
libunwind / libgcc 就这么展开的。本模块复刻这条路：

```
断点现场的 pc/sp + .eh_frame 规则
   → 算 CFA
   → 从 [CFA+off] 读出返回地址（= 上一帧的 pc）
   → 恢复寄存器，循环
```

**关键点：这条路径完全不经过 frida 的 unwind 实现。**

## 2. 支持的 CFA 指令

实测 4 个真样本（libbase / liblog / libcutils / sscronet）里出现的指令全覆盖：

| 指令 | 作用 |
|---|---|
| `DW_CFA_advance_loc` / `_loc1` / `_loc2` / `_loc4` / `set_loc` | 推进当前 PC（`code_alignment_factor` 缩放） |
| `DW_CFA_def_cfa` | 设 CFA = reg + off |
| `DW_CFA_def_cfa_register` | 换 CFA 基址寄存器，保留 offset |
| `DW_CFA_def_cfa_offset` | 只改 CFA offset |
| `DW_CFA_def_cfa_sf` / `_def_cfa_offset_sf` | 同上的有符号缩放版 |
| `DW_CFA_offset` / `_offset_extended` / `_offset_extended_sf` | 值在 `[CFA + n*data_align]` |
| `DW_CFA_val_offset` / `_val_offset_sf` | 值就是 `CFA + n`（不解引用） |
| `DW_CFA_register` | 值在另一个寄存器里 |
| `DW_CFA_same_value` / `_undefined` | 值未变 / 值不可得 |
| `DW_CFA_restore` / `_restore_extended` | 恢复成 CIE 初始规则 |
| `DW_CFA_remember_state` / `_restore_state` | 规则状态栈 |
| `DW_CFA_AARCH64_negate_ra_state` (0x2d) | PAC 标志：只记录不改 CFA |
| `DW_CFA_nop` / `GNU_args_size` | 无副作用 |

### 不支持（会出现在 `unsupported_ops` 里）

| 指令 | 为什么放弃 |
|---|---|
| `DW_CFA_def_cfa_expression` | CFA 变成 DWARF 表达式，本模块不解表达式 → 整条 FDE 放弃 |
| `DW_CFA_expression` / `_val_expression` | 单一寄存器值由表达式算出 → 该寄存器值视为未知 |
| 未知 opcode | **编码长度不可知，无法安全跳过**。继续读必然错位并解出垃圾规则——这正是"给假结果"的来源，必须放弃整条 FDE |

这是刻意保守：宁可返回"这帧展开不了"，也不返回一条看起来合理但实际错误的栈。

## 3. 正确性验证

### 3.1 与 objdump 逐行交叉验证（第三方真值）

用 `/usr/bin/objdump --dwarf=frames` 的结果当真值，对本实现的每一个
"PC → CFA 规则 + 各寄存器保存槽位"逐行对比：

| 样本 | objdump 真值行数 | 完全一致 | 不一致 |
|---|---|---|---|
| liblog.so | 276 | 276 | **0** |
| libbase.so | 1055 | 1055 | **0** |
| libcutils.so | 456 | 456 | **0** |
| 合计 | **1787** | **1787** | **0** |

复现脚本：`/tmp/cfi_crosscheck.py`（逻辑已固化进 `tests/test_regressions.py` 的 R100）。

典型对照（libbase，最关键的三种状态）：

```
objdump 真值:
  0x12080: CFA=reg31                        ← 函数入口，无帧
  0x12084: CFA=reg31: reg34=1               ← PAC 标志置位
  0x12094: CFA=reg29+32: reg19=[CFA-16],
           reg29=[CFA-32], reg30=[CFA-24]   ← 已建 fp 帧

本实现:
  0x12080 → ('sp', 0, None)
  0x12094 → ('x29', 32, 'CFA-24')，槽位 {19:-16, 29:-32, 30:-24}   ✓
```

### 3.2 真实展开成功率

按 CFI 规则构造自洽的栈镜像，用 4 层调用链测试逐帧展开：

| 样本 | 构造层数 | 成功展开 | 地址逐层匹配 | 备注 |
|---|---|---|---|---|
| libbase.so | 4 | **4** | 精确一致 | 栈顶正确停止 |
| liblog.so | 4 | **4** | 精确一致 | 栈顶正确停止 |
| libcutils.so | 4 | **4** | 精确一致 | 栈顶正确停止 |
| sscronet.so | — | **1** | — | CFI 被剥离，如实报"不可信" |

"地址逐层匹配"指展开出的每帧 static_addr 与构造调用链的 pc 完全相等
（不是"差不多"）。

端到端（走 `tools.py` 的完整工具路径）实测输出：

```
frame_count=3, symbolized=3, unresolved=0
  0 _ZN7android4base10boot_clock3nowEv
  1 _ZN7android4baselsERNSt3__113basic_ostream...ERKNS0_5TimerE
  2 _ZNSt3__124__put_character_sequenceIcNS_11char_traits...EE...
```

3 帧全部符号化出真实 C++ 函数名。

## 4. CFI 覆盖度：`cfi_coverage`

**这是本功能最重要的诚实机制。** 不是所有 so 都有可用的 `.eh_frame`——
加固/裁剪会把它们剥掉。三条判据，任一不满足即 `enough=false`：

| 判据 | 阈值 | 理由 |
|---|---|---|
| `.eh_frame` 字节数 | ≥ 1024 | 正常 so 是几十~几百 KB |
| FDE 条数 | ≥ 10 | 每条 FDE 覆盖一个函数 |
| **FDE 覆盖代码比例** | **≥ 5%** | 最强信号：条数够但覆盖千分之几，说明只留下零星几条 |

第三条是实测逼出来的：sscronet.so 有 13 条 FDE（过了"≥10 条"），但只覆盖
`.text` 的 0.04%——只看条数会误判成"够用"。

实测覆盖度：

| 样本 | `.eh_frame` | FDE | 覆盖比例 | enough |
|---|---|---|---|---|
| libbase.so | 15084 B | 386 | 100.00% | ✅ |
| liblog.so | 4020 B | 111 | 99.98% | ✅ |
| libcutils.so | 6084 B | 168 | 99.98% | ✅ |
| **sscronet.so** | **392 B** | **13** | **0.04%** | ❌ |

sscronet 的实际返回：

```json
"cfi_coverage": {
  "eh_frame_bytes": 392, "total_fdes": 13, "cies": 1,
  "text_bytes": 3975988, "covered_bytes": 1484,
  "coverage_ratio": 0.000373, "enough": false, "covered_pc": true,
  "warning": "CFI 信息不足，回溯结果**不可信**：.eh_frame 仅 392 字节（< 1024）；
              FDE 只覆盖可执行段的 0.04%（< 5%）。这个 so 的 .eh_frame
              很可能被剥离/裁剪过。建议改用 method='scan'..."
}
```

注意 `covered_pc: true` 而 `enough: false` 这个组合——**起点那个函数确实有
CFI，但整个样本的 CFI 不足以支撑一条完整调用栈**。两个字段必须分开看，
这正是本任务要求"不能假装成功"的落点。

## 5. 使用方式

```
① set_breakpoint(serial, pid, so_name, static_addr, hold=True)   # 制造一次命中
② get_callstack(serial, pid, method="dwarf")
```

也可以不下断点直接用 `method="scan"`（启发式扫栈）或 `method="accurate"`（frida）。

返回字段：

| 字段 | 含义 |
|---|---|
| `frames[]` | 每帧 `{depth, pc, runtime_addr, static_addr, so, function, offset, cfa, cfa_rule, ra_rule, in_gap}` |
| `cfi_coverage` | 覆盖度；**必须读** `enough` 与 `warning` |
| `unsupported_ops` | 遇到的不支持 CFI 指令（十六进制） |
| `stop_reason` | 为什么停下（栈顶 / 无 FDE / 循环 / 栈地址读不到 / 缺 sp） |
| `decisive_frames` | 真正算出 CFA 的帧数 |
| `mem_reads` | 实际读目标内存的次数（叶帧读不到栈就不读，所以常比帧数少） |
| `regs_source` | 寄存器来自哪条命中（`hit:same_thread` / `hit:latest`） |

## 6. 已知限制（如实列出）

1. **CFI 被剥离的 so 救不了**。sscronet.so 这种只能展开 1 帧。
2. **需要目标进程可读栈内存**。栈页不可读时展开会在该帧停止并说明，
   不会把读不到当成 0 继续往下走。
3. **不做 DWARF 表达式**。`DW_CFA_*_expression` 一律视为不支持。
4. **PAC 只剥签名不认证**。`_strip_pac` 按"高位非零则取低 48 位"处理，
   不做真正的指针认证（那需要密钥）。
5. **跨 so 展开依赖模块表**。调用链进入没载入 mda 的 so 时，那一帧会标
   `note` 说明"该 PC 不在已登记模块范围内"，不会静默返回短栈。
6. **帧数上限默认 64**（可调 1..512），超限时 `stop_reason` 会明说
   "可能有更多帧"。
7. **`ra - 4` 的约定**：第 2 帧起的 pc 是返回地址（指向 bl 的下一条），
   查 FDE 与算规则都回退 4 字节落回调用点。ARM64 定长指令，这个偏移可靠；
   若将来支持 Thumb/变长指令集需要改。

## 7. 本轮修掉的三个真 bug（回归测试 R100 守着）

这三个都是并行写出的初版实现里的缺陷，共同特点是**测试"形状"能过、
值全错**：

| bug | 现象 | 根因 | 修法 |
|---|---|---|---|
| ① PAC 指令中断扫描 | 0x12094 返回 `sp+0`（真值 `x29+32`） | `DW_CFA_AARCH64_negate_ra_state`(0x2d) 被当未知 opcode，`break` 掉整个指令流，后面所有 `def_cfa`/`offset` 全丢 | 显式识别 0x2d，只记 `ra_signed` 标志 |
| ② RA 规则从不记录 | `ra_off` 恒为 `None`，永远展不开第 2 帧 | FDE 指令执行后没有把 `ra_reg` 的规则取出来 | `_rules_at` 产出完整 `_State`，`_resolve_return_pc` 按规则类型分别求值 |
| ③ `enough` 恒 True | sscronet（392 字节）被报"CFI 充足" | 只看 `len(fdes)>=10`，不看字节数与覆盖比例 | 三条判据（字节/条数/覆盖率），并给出可解释的 warning |

另有一个同类隐患：`restore` 的复原基准与工作状态曾是**同一个 dict**，
FDE 指令原地修改后 `restore` 会从改过的字典取值。已改为先拷贝。

反向对照已做：把上述 bug 逐个注回去，R100 的对应断言全部失败
（bug① 复现出精确的旧值 `('sp', 0, None)`），确认测试不是摆设。
