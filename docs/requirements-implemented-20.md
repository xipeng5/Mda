# 需求清单落地记录（20 条）：BUG 修复 + 通用能力

> 日期：2026-11-18
> 基线：git HEAD `45020d0`，按 `docs/requirements-review-20-verify.md` 的核实结论实施。
> 原则：**全部通用能力，零样本特调**——代码里没有任何具体 so 名/地址/函数/样本特征。
> 验证：`.venv/bin/python tests/test_plugin_fixes.py` → **51/0**；
> `test_rela.py` **104/0** / `test_e2e.py` 14/0 / `test_regressions.py` **1058/0** /
> `test_discover_tiers.py` 53/0 / `test_pseudocode_addr.py` 31/0 —— 全部全绿。

---

## 0. 一条纠正：P0-1 的根因不是"只读段"

核实阶段实测推翻了转述：mda 映射 so 段时 `uc.mem_map(cur, map_size)` 不传 perms，
unicorn 默认 `perms=7`(RWX)，**所有段都可写**。真正根因是 `buffer` 传了
list 形状 `[{addr,hex}]`，而旧代码 `isinstance(buf, dict)` 直接 False →
整段静默跳过。dict 形状写 `0x60000` 读回 `aabbccdd` 成功。

---

## 1. 修复的 BUG（8 项）

| # | 文件 | 修复 | 验证 |
|---|---|---|---|
| P0-1 | `server/plugins/emulate_func.py` | buffer 兼容 dict/list；逐条写入后 **回读校验**；返回 `buffer_applied`/`buffer_skipped` 让静默失败可见 | 测试[6]：list 形状 applied+verified；坏 buffer 有 skipped 原因 |
| P0-2 | `server/plugins/decompile_c.py` | 新增 `if_lines` 带源地址与真实条件；覆盖 cbz/cbnz/tbz/tbnz + 18 个 ARM 条件码；修 ldr/str 目的寄存器 bug；补 ldp/stp；未知指令保留 `// 0xADDR` 注释不丢弃 | 用户样本函数 `0xe8a88`：`tbz w9 @0xe8aa0` 真条件、`x10=mem[x8]`、`bti c` 注释保留、`condition_not_recovered=0` |
| P1-1 | `server/plugins/func_profile.py` | 遍历 `so.functions` 而非被抹的 exports；导出>符号>发现排序 + source 字段；函数表<100 警告；`so`/`so_name` 兼容 + 清晰 BAD_ARGS | libanti：function_count=1984，首条 source=export size=4960；缺参 BAD_ARGS |
| P1-2 | `server/core/rela.py` | 实现 RELR 位图+增量地址解析；并入 rela_dump/summary；新增 `kind='relr'` | libbase：235→250（+15 条 RELR），覆盖 .data.rel.ro |
| P2-1 | `emulate_func.py` | `writes` 模式新增 `trim_writes`，裁尾部连续 0 | — |
| P2-2 | `func_profile.py` / `sensitive_scan.py` | 统一 `so`/`so_name` 兼容；缺失返回清晰错误，不再走 `session.get(None)` 误导 | 两插件缺参都报 BAD_ARGS |
| P3 | `call_graph.py` | `vtable_in` → `vtable_slots`（保留旧名别名渐进废弃）；note 说明语义 | 集成测试 tree 正常 |
| P3 | `xref_enhanced.py` / `data_flow.py` | 返回 `scanned_insns`/`scanned_ranges`/`scanned_functions`，0 结果可区分原因 | vtable_traversal 同样带 scanned_insns=281852 |

---

## 2. 新增/增强的通用能力（8 项）

| # | 文件 | 能力 | 关键设计 |
|---|---|---|---|
| P0 | **新增** `server/core/unicorn_stubs.py` (500行) + 集成 `emulate_func.py` | **libc stub 注入** | PLT 入口 hook → Python 语义实现 → 设 x0 → PC 拉回 LR 跳过 GOT 链。实验验证：无 stub 崩 `0x0`，有 stub 正常 `returned` 且报告 memcpy 调用。覆盖堆(malloc/calloc/realloc)、内存(memcpy/memset/memcmp)、字符串(strlen/strcmp/strcpy)、vfs(fopen/fread/fwrite)、格式化(snprintf)、noop(pthread)、异常报告(__stack_chk_fail)。`stubs:'auto'\|dict\|null` + `vfs` + `heap_base/size` 参数 |
| P1-1 | **新增** `server/plugins/vtable_traversal.py` | vtable 遍历点解析 | 全 so 扫 `ref_addr` 落表地址区间的 adrp+add；8 指令窗口启发式找 `ldr+blr` 虚调用；带 scanned_insns。实测扫 281852 指令命中 6 条，首条正是 `0xd1890 add x10,x10,#0xcd0 → 0x117cd0` |
| P1-2 | **新增** `server/plugins/fuzz_combine.py` (526行) | 模板化穷举 | 管道语法 `{url}\|sha1hex(url)`、`{kh_le}` 嵌套，8 transformer；7 算法（md5/sha1/sha256/hmac_sha1/rc4/xxtea/aes256/none，RC4/XXTEA 纯 Python，AES 惰性探测 cryptography）；`target_len` 只比前 N 字节；`max_combos`/`timeout_ms` 到限即停标 truncated，绝不静默。验证：abc 的 md5 命中 |
| P2-1 | `angr_bridge.py` + `angr_worker/worker.py` | 定向符号执行 | 新增 symbolic/concrete/constraint/max_depth/avoid/find 透传；worker 用 blank_state + 符号寄存器 + 限深 explore + solver 求解，返回 `solved:{x19:hex}`；失败如实报 reason，不编造 |
| P2-2 | `data_flow.py` | 跨函数数据流 | `interproc`/`up_depth` 参数；追到函数参数后沿 xrefs_to 上溯调用者，看 bl 前最后写入；返回 interproc_chain + 扫描计数；note 诚实标注启发式 |
| P3-1 | **新增** `server/plugins/string_ref_resolve.py` | 解密串反查引用 | 三模式：cipher_addr→xrefs_to 折回函数；cipher_hex→搜文件字节+段映射；仅 plaintext→NEED_CIPHER_LOC 不猜 |
| P3-2 | **新增** `server/plugins/so_fingerprint.py` | 样本指纹库 | `~/.mda/fingerprints.json` 用户自建库，**零内置特征**；save/list/query/match 四动作，覆盖需 force，match 给 high/medium/low 置信度 |

---

## 3. libc stub 的价值（用户核心诉求）

用户反馈"260 轮里真正缺的是能让函数跑起来的沙箱"——所有算法都验对了
（8 原语/3 解密/分派/41of41 签名头），唯一没拿到的 20 字节 tail 恰恰因为
它需要跑依赖 libc 的完整签名函数。

本次实现的 stub 引擎把"猜答案"（试 21000 种组合）变成"看答案"（直接跑出 20 字节）。
**AB 测试证据**：同一个调用 memcpy 的真实函数，无 stub → `external_call_or_unmapped @0x0`；
有 stub → `returned` 且 `stub_calls` 记录 memcpy 被拦截。机制通用，不含任何样本特征。

---

## 4. 边界 / 说明

- angr 环境：本机 `/tmp/angr_venv` 缺 claripy，符号执行会返回 `CLARIPY_NOT_INSTALLED`（报错清晰、不崩溃）；装好 angr 环境即可用。
- AES 依赖 `cryptography`（本机 50.0.2 可用），无库时进 `unsupported_algos` 不假装支持。
- RELR 解码公式字面产出里有个重复的 `0xf000`（公式原样结果，未擅自去重）；word 宽度按 ELF class + `DT_*RELRENT` 判定，节表/动态段双路径统一。
- `string_crack.py`/`version.py` 的改动是介入前工作区既有状态，非本次任务，未触碰。

阿倍倍 4号-正在为您服务

阿倍倍 4号-正在为您服务
