# 需求清单核实（20 条）：问题 + 能力，全部回代码/跑样本

> 日期：2026-11-18
> 基线：`server/`（core 静态 / plugins / mcp_server），git HEAD `45020d0`
> 方法：不信转述，逐条回源码 + 用真机 so 跑最小复现。
> 样本：`so_test/libanti_complete_patched.so`（1984 函数，PT_LOAD flags=0x5/0x6）、
> `samples/liblog.so`（有 `.relr.dyn`）、`samples/libbase.so`、`samples/libcutils.so`。
> 环境：`.venv/bin/python`，unicorn 2.1.4。
> **本文档只做核实与理解，不改任何代码**（按规矩：先问再做）。

---

## 0. 一条先纠正：P0-1 的根因不是"只读段"

这条最重要，因为它决定修复方向。转述说：

> `buffer=[{addr:"0x60000",hex:"aabbccdd"}]` 写到 `0x60000`（只读 PT_LOAD），
> Unicorn 写只读页失败，mda 静默不报 → dump 仍是 `4e0f409e`。

实测三件事：

**① Unicorn 在 mda 里对所有段都是 RWX，不存在"只读页写不进去"。**
`emulate_func.py:130` 映射时调用 `uc.mem_map(cur, map_size)`，没传 `perms`；
unicorn 2.1.4 的签名是 `mem_map(address, size, perms=7)`，7=RWX。
直接实验：

```
uc.mem_map(0x60000, 0x1000)      # 默认 perms=7
uc.mem_write(0x60000, "aabbccdd")
读回 = aabbccdd                   ← 写成功
```

**② 用正确形状 `{addr, hex}`（dict）写 `0x60000`，端到端也成功。**
跑 `emulate_func`（函数 `0x6a1f0`）＋`buffer={"addr":"0x60000","hex":"aabbccdd"}`：
`dump` 读回 `aabbccdda0000000...` → 前 8 个 hex 就是 `aabbccdd`。

**③ 转述里的值 `4e0f409e` 与"写没写进去"无关，是另一个 so 的文件原内容。**
本机样本 `0x60000` 原字节是 `00560900a0000000`；转述用的加固 so 不是本机样本，
`4e0f409e` 就是它那个地址的文件原值——符合"一个字节都没写进去"。

**真正根因：`buffer` 参数形状是 list，代码只接受 dict，整段被静默跳过。**
`emulate_func.py:156-167`：

```python
buf = args.get("buffer")
if isinstance(buf, dict) and buf.get("addr") and buf.get("hex"):   # ← list 直接 False
    ...
    uc.mem_write(baddr, bdata)
```

传 `[{"addr":...,"hex":...}]` 时 `isinstance(buf, dict)` 为 False，
**不写、不报错、返回里也没有任何 `buffer_applied` 字段**。
端到端复现：list 形状 dump = `00560900a0000000...`，返回顶层字段
`['entry','mapped_segments','memory','note','ok','registers','so','stopped']`——调用方无从知道被丢弃。

而且 `usage` 字符串 `emulate_func.py:68` 明确写的是
`"buffer: {addr, hex}"`（单对象，不是数组），是调用方传错了形状；
但工具没有校验、没有提示，所以"静默失败"这个批评**成立**，"只读段"这个归因**不成立**。

**修复方向**：兼容 list/dict + 写入后回读校验 + 返回 `buffer_applied` /
`buffer_skipped_reason`。不是去改映射权限（本来就是 RWX）。

---

## 1. 逐条核实表

图例：✅ 成立 ｜ ⚠️ 部分成立/根因不同 ｜ ❌ 不成立 ｜ 🆕 能力确实缺失

### 第一部分：问题（BUG）

| # | 反馈 | 核实 | 证据 / 真实根因 |
|---|---|---|---|
| P0-1 | buffer 只读段静默失败 | ⚠️ 现象成立、根因错 | 见第 0 节：真实根因是 list 形状被静默跳过；段本来就 RWX |
| P0-2 | `decompile_c` 丢分支条件 | ✅ 成立，且更严重 | `decompile_c.py:141-146` 的 `_to_expr` **不识别** `cbz/cbnz/tbz/tbnz/b.ne/cmp`，这些指令全部返回 None 被丢弃；输出只剩 `if (cond) goto` 无条件的骨架。实测函数 `0xe8a88`：`tbz w9,#0,#0xe8aac` 在伪代码里只剩 `if (cond)` |
| P1-1 | `func_profile` 与 `list_functions` 差 1 万倍 | ✅ 成立 | `func_profile.py:24` 只遍历 `so.exports`。加固 so 抹导出表 → exports 极少。模拟把 exports 砍到只剩 JNI_OnLoad，`func_profile` 返回 1 条，而 `so.functions` 有 1984 个。健康 liblog 63 exports/111 functions 时正常 |
| P1-2 | `rela_dump` 不解析 RELR | ✅ 成立 | `rela.py:674-682,778-782` 明确标 `relr=True` + warning 不解析。实测 liblog 的 `.relr.dyn`（40 字节）手工解码出 11 条相对重定位，覆盖 `0xf000-0x10648`（正是 `.data.rel.ro` 区），现有 entries 105 条完全没算它们 |
| P2-1 | writes 模式返 4096 字节、4000+ 个 0 | ✅ 设计如此 | `emulate_func.py:207-217,380-382`：`UC_HOOK_MEM_WRITE` 只记页号，导出整页 0x1000 字节。有 `dump_max` 限制单段，但确实没有 trim 尾部 0 的选项 |
| P2-2 | `plugin_run` 参数名报错误导 | ✅ 成立 | `plugin_run` 把 `args` 原样传给插件；`func_profile.py:18` 取 `so_name`，取不到就是 `session.get(None)` → KeyError `"未加载的 so: None..."`。实测确认。根因是参数名不统一（全项目多数插件用 `so`，只有 `func_profile`/`sensitive_scan` 用 `so_name`） |
| P3 | `call_graph` 的 `vtable_in` 字段名易误读 | ✅ 命名问题 | `call_graph.py:133` 写 `node["vtable_in"]`，但 `indirect_only` 里同类字段已经叫 `vtable_slots`（`:163`）。note 已诚实解释语义，只是字段名不统一 |
| P3 | `xref_enhanced`/`data_flow` 返回 0 不区分原因 | ⚠️ 部分成立 |
| | —— `data_flow` | ❌ 已带说明 | `data_flow.py:125-127` 的 note 明说"函数范围内后向切片…跨函数需人工跟进"；返回有 `node_count`，0 就是没找到。但**没有**"扫了多少指令/几个基本块"的计数 |
| | —— `xref_enhanced` | ✅ 成立 | `xref_enhanced.py:66-70` 只在"完全没有可执行区域"时返回 `NOTHING_SCANNED`；正常 0 结果只有 `count:0`，不带扫描指令数。实测扫了 libanti 28 万条指令后 `xrefs_to(0x117cd0)=0`，但返回里看不到"扫了多少" |

### 第二部分：能力（需求）

| # | 需求 | 核实 | 现状 / 差距 |
|---|---|---|---|
| P0 | `emulate_func` libc stub 自动注入 | 🆕 真缺失，价值认同 | 现状 `emulate_func.py:239-248`：bl 到未映射地址就停，报 `external_call_or_unmapped` 并建议"用 buffer 预置外部函数桩"——但**没有真正的 stub 机制**。类中无 stub 相关参数/代码。你要的 malloc/fopen/memcpy/... 全套 stub + vfs + heap 完全是新能力 |
| P1-1 | vtable 遍历点解析（谁在读表） | 🆕 真缺失 | `xref_enhanced.py:_vtable_refs` 和 `call_graph.py:_vtable_edges` 只从**重定位表**给"槽→目标"反向边，不给"哪条 `adrp+add` 加载了这张表"。实测扫描发现 libanti 里确实有 `0xd1890 add x10,x10,#0xcd0 -> 0x117cd0` 这类引用（共 29 条落在该页），但 `xrefs_to(0x117cd0)=0`——因为 xref 索引没收录这条数据引用方向。**能力有数据基础但没做成工具** |
| P1-2 | 模板化穷举引擎 `fuzz_combine` | 🆕 真缺失 | 全项目无组合模板穷举工具；最接近的是 `string_crack`（只做 XOR/LCG 字符串解密）和 `solve_constraint`（z3 解等式）。你要的是"字符串模板 × 算法 × 密钥源 × 分隔符"的笛卡尔积搜索，确实没有 |
| P2-1 | 定向符号执行（单函数） | ⚠️ 有骨架但不够 | `angr_bridge.mode="symbolic"` 在 `worker.py:94-105`：`blank_state(addr=entry+base)` → `simgr.explore(find=find+base)` → **只返回 `reached: bool`**。无符号变量注入、无具体参数、无约束求解、无"解出 x19"。`cfg`/`decompile` 模式全函数跑确实容易超时（300s 超时保护在 `angr_bridge.py:127`） |
| P2-2 | 跨函数数据流 `data_flow_interproc` | 🆕 真缺失 | `data_flow.py` 全在函数内（`:69` `so.function_at(a)` 后只在该函数指令里走）；note 明说"跨函数需人工跟进 call_chain"。无沿调用链往上追的实现 |
| P3-1 | 解密后字符串反查引用 | 🆕 真缺失 | `string_refs` 走静态 xref，指向密文地址；`string_crack` 解密后只返回结果，没有"把解密串反查到引用函数"的桥。`const_fingerprint` 是算法常量表，无关 |
| P3-2 | so 指纹库（跨样本经验） | ⚠️ 有雏形但不是同一个 | `const_fingerprint` 是**公开算法常量**表（非样本特征），输入 so 输出常量命中；你要的是**样本级**指纹库（某 so 的算法地址/签名头结构/vtable成员/反hook点），是"分析结果持久化+复用"，目前没有 |

### "做得好的"逐条确认

| 项 | 代码证据 |
|---|---|
| `load_so` 函数表警告 | `tools.py:_so_table_warning` + `load_so` 两条路径都调用；函数数<100 明确警告 |
| `call_graph` vtable 语义说明 | `call_graph.py:181-185` note 明确"vtable 边是入边…不代表运行时谁真的调了它" |
| `emulate_func` stopped.reason | `emulate_func.py:221-250` 区分 returned / external_call_or_unmapped / invalid_instruction / instruction_limit_or_unknown |
| `rela_dump` addend_is_target | `rela.py` 明确"只有 RELATIVE 的 addend 才是目标地址" |
| `xref_enhanced`/`string_crack` 返回 0 不假装成功 | `xref_enhanced.py:66-70` NOTHING_SCANNED；`string_crack` 0 结果有明确 note |

---

## 2. 我的理解（一句话版）

**问题那 8 条**：核心不是"工具笨"，而是**静默**——参数传错形状不提示、条件指令不识别直接丢、只扫导出表不说、RELR 不解析只藏在 warning 里、0 结果不告诉我扫了多少。对 agent 最致命的就是"信任了不完整的输出继续推理"。

**能力那 8 条**：核心也不是"更聪明的分析"，而是**三道墙**：
1. **跑不起来**（libc stub）——所以只能验纯算法，验不了依赖 libc 的完整签名函数；
2. **静态看不到动态**（vtable 遍历点、跨函数数据流、解密串反查）——信息在 so 里但工具没暴露；
3. **重复造轮子**（穷举引擎、样本指纹库、定向符号执行）——每次手写脚本/重走 260 轮。

**优先级我同意你的排序**：`libc stub` 一条是决定性的——它把"猜答案"变成"看答案"。其余都是放大器。

---

## 3. 关键待确认（按规矩：先问再做）

1. **P0-1 修复方向**：你说的是"只读段"，但实测是"list 形状 + 不校验"。确认按哪个修？
   - A：兼容 list/dict + 写入回读校验 + 返回 `buffer_applied`（我建议）
   - B：你补充那个加固 so 的实际路径，我复现"只读段"现象再定
2. **libc stub 范围**：先做最小集 `malloc/free/memcpy/memset/strlen` + 空实现 noop，还是一次做全（含 fopen/vfs/snprintf/pthread）？vfs 的"预置文件 hex"要不要支持多文件？
3. **是否现在动手**：以上全部是核实理解，没有改代码。确认后再排期实现。
