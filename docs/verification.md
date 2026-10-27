# 核心链路验证记录（基于真实样本 liblog.so）

样本来源：Android 13 真机 `b0b5800722` 的 `/system/lib64/liblog.so`
文件信息：ELF 64-bit LSB shared object, ARM aarch64, stripped, 66576 字节

---

## 已验证可行的链路

### 1. ELF 解析（pyelftools 0.33）
- `e_type=ET_DYN`、`e_machine=EM_AARCH64`、`e_entry=0`
- 关键 section：`.text`(0x5000, 0x8ff0)、`.plt`(0xdff0, 0x9f8)、`.rodata`(0x2cd0, 0x7c8)、`.dynsym`(0x338, 0xeb8)、`.rela.plt`(0x22f8, 0x9d8)、`.got.plt`(0xf260, 0x360)

### 2. PLT → GOT → 符号名（105/105 全部解析成功）
```
.rela.plt 的 r_offset(GOT 槽) -> r_info_sym -> .dynsym 符号名
例：GOT 0xf280 -> create_android_logger
PLT stub 反推：adrp x16,page ; ldr x17,[x16,#off]  =>  GOT 槽地址 -> 符号名
例：0xe020 -> create_android_logger
```

### 3. adrp + add 字符串引用还原（android_name_to_log_id @ 0x5d30）
```
0x5d5c -> 0x3187 "main"
0x5d74 -> 0x3259 "radio"
0x5d88 -> 0x2dd3 "events"
0x5d9c -> 0x318c "system"
0x5db0 -> 0x3052 "crash"
0x5dc4 -> 0x2de6 "stats"
0x5dd8 -> 0x2f9f "security"
0x5dec -> 0x325f "kernel"
```
与 Android log 的 buffer 名完全吻合，证明地址计算正确。

---

## 踩坑记录（开发时必须注意）

### 坑 1：capstone 输入必须是「文件真实字节」，不是 objdump 显示的字
- objdump 显示的 `b0ffffe4` 是指令**字**（大端显示风格）
- 文件里真实字节是 `e4 ff ff b0`（小端存储，ARM64 定长 4 字节指令）
- **结论**：直接把 section 的 `data()` 切片喂给 capstone 是对的；
  如果从 objdump 输出抄字节再转 hex，必须按小端重组，否则全盘反汇编错乱。

### 坑 2：vma -> section 数据索引，不能用 sh_offset
错误写法：
```python
fo = sh_offset + (addr - sh_addr)   # 这是"文件偏移"
return section_data[fo:fo+n]        # 但 section_data 的索引是"section 内偏移"
```
当 `sh_offset != sh_addr` 时（例如本例 `.data`: sh_addr=0x105c0, sh_offset=0xf5c0）索引越界，读出空 bytes，且不报错。

正确写法：
```python
for s in sections:
    if s.sh_addr <= addr < s.sh_addr + s.sh_size:
        return s.data()[addr - s.sh_addr : addr - s.sh_addr + n]
```

附加过滤条件：必须排除 `sh_addr == 0` 的 section（`.shstrtab`、`.gnu_debugdata`），
否则 `(0, 0x124)` 这种假区间会干扰匹配。

### 坑 3：BTI / PAC 指令
- 函数入口常见 `bti c`(d503245f) 与 `paciasp`(d503233f)，属 ARM64 安全扩展指令
- capstone 5.0.7 能正常识别，反汇编时不应跳过

---

### 4. 函数发现：.eh_frame FDE（stripped so 的可靠方案）
```
FDE 数量: 111
.text: 0x5000 .. 0xdff0 (size 0x8ff0)
FDE 覆盖率: 0x8fe8 / 0x8ff0 = 100.0%
间隙: 仅 2 个 4 字节对齐填充 (0xdf5c-0xdf60, 0xdf8c-0xdf90)
dynsym 导出函数 63 个，100% 命中 FDE 起点
例: 0x5020 create_android_logger / 0x5d30 android_name_to_log_id
```
**结论**：`.eh_frame` FDE 是 stripped ARM64 so 最可靠的函数发现源，无需启发式扫描。

pyelftools 正确用法（参数顺序易错）：
```python
from elftools.dwarf.callframe import CallFrameInfo
from elftools.dwarf.structs import DWARFStructs
import io
structs = DWARFStructs(little_endian=True, dwarf_format=32, address_size=8)
cfi = CallFrameInfo(io.BytesIO(eh.data()), len(eh.data()),
                    eh['sh_addr'], structs, for_eh_frame=True)
for e in cfi.get_entries():
    if e.__class__.__name__ == 'FDE':
        pc = e.header['initial_location']; size = e.header['address_range']
```
注意：`DWARFStructs(little_endian, dwarf_format, address_size)` 三个都是位置参数，
`address_size` 传 True 会触发断言（8 或 4）。

---

## 已修复的 bug 记录（多轮防复现）

### bug 1：string_refs 返回空引用列表
- (1) 第一次修改 bug 原因：`string_refs` 里用 `if not x._built` 判断是否需要归并字符串引用，
  但 `session.xref()` 内部已经调用了 `x.build()` 把 `_built` 置 True，
  导致判断恒为 False，`annotate_refs` 永远不执行，`referenced_by` 恒为空。
  解决：`StringAnalyzer` 增加 `_annotated` 独立标志，归并与提取分开标记；
  并在 `Session.ensure_xrefs()` 里封装「建图 + 归并」原子顺序，调用方不再关心先后。
- 教训：两个有依赖的惰性初始化步骤不能共用同一个 built 标志。

### bug 2：伪代码符号名输出 "!name"
- bug 原因：`PseudocodeGenerator._name_of` 拼 `f"{r[0]}!{r[1]}"`，
  但 `CallLink.callee_so` 对未解析导入是空串，输出成 `"!calloc"`。
  解决：`r[0]` 为空时只返回 `r[1]`。
- 另：首次编辑时 `return ins.text` 后的换行被吞，导致与下一个方法定义挤在同一行，
  SyntaxError。教训：edit 工具替换时要带上完整边界（含换行）。

### bug 3：frida 17 API 断代（Module.getExportByName 不存在）
- bug 原因：frida 17 移除了 `Module.getExportByName` / `Memory.readByteArray` 全局函数，
  旧脚本报 `TypeError: not a function`，表现为"断点不命中"（实际是脚本没加载成功）。
  解决：新 API 为 `Module.getGlobalExportByName`；读内存用 `ptr(x).readByteArray(n)`。
- 排查手法：二分注释 JS 语句定位到具体行；`Object.getOwnPropertyNames(Module)` 枚举实际可用 API。

### bug 4：frida 客户端与服务端版本不匹配
- 现象：`frida.ProtocolError: unable to communicate with remote frida-server`。
- 原因：本机 pip frida 17.23.3，设备端旧 server 16.0.19，大版本必须一致。
- 解决：下载 17.2.14 server 推送到设备 `/data/local/tmp/frida-server-17` 并以 root 启动。
  版本常量在 `dyn/adb.py` 顶部（FRIDA_SERVER_VERSION）。

### bug 5：frida 读内存返回 None
- bug 原因：`send(buf)` 二进制经 data 通道返回时 data 参数为 None（版本行为差异）。
- 解决：JS 端把 Uint8Array 转 hex 字符串走 JSON 通道，Python 端 `bytes.fromhex` 还原。

---

### bug 6：GUI QDockWidget 构造参数传错
- bug 原因：`QDockWidget("动态分析", session)` 把 Session 当 parent 传入，
  实际签名是 `QDockWidget(title, parent_widget)`，抛 TypeError。
  解决：只传标题，session 作为实例属性保存。
- 另：`_build_dynamic_panel` 必须在 `_build_menu` 之前调用，
  因为菜单的"刷新设备"动作绑定了面板的方法，顺序颠倒抛 AttributeError。

### bug 7：GUI 连续加载多个 so 时 QThread 被销毁
- 现象：连续三次 load_so 后程序崩溃退出，输出 `QThread: Destroyed while thread is still running`。
- 原因：Worker 线程在 run() 完成前被 Python GC 回收（引用只存在局部变量），
  且三个 Worker 同时启动时分析同一 Session 存在竞争。
- 解决：`self._worker = w` 保持引用防 GC；测试侧错峰触发（间隔 3 秒）。
  后续如需并行加载，须给 Session.add 加锁。

---

## 环境事实

- macOS，无 readelf（用 objdump 代替）
- 本机装有 IDA Professional 9.0.app（可作对照验证）
- Python 3.11.15，venv 位于 `.venv/`
- capstone 5.0.7（cs_version 5.0.1280）、pyelftools 0.33 已安装且验证可用

---

## 段表兜底架构（dump so 支持，2026-10-13）

用户系统性测试发现 7 个 bug，全部源于同一架构缺陷：过度依赖 section 表。

### 样本
`so_test/dump/libsgmainso-5.5.110.so.758a6e6000.bin`（设备 dump，2.2MB）：
- `e_shoff=0x217b00` 指向非法区域（壳抹掉节表），pyelftools 抛 `ELFParseError: expected 4, found 0`
- PT_LOAD 完好：RX(0x0, 2.1MB) + RW(0x2172d0, 0x104c8)
- PT_DYNAMIC 的文件区全零（dump 时未写回）→ dynsym 也不可用
- PT_GNU_EH_FRAME 完好（0x1e914c, 0x530c）→ 2656 个函数边界可恢复

### 修复内容（core/elf_model.py）
1. `_parse_loads()`：手工按 e_phoff 读 PT_LOAD，不碰 pyelftools 的 section API
   （其 iter_segments() 内部也会触发同一 ELFParseError）
2. `_parse_sections()`：try/except 包裹，失败返回 False；假名检测
   （sh_name 指向 ELF 头会读出 ELF 魔数 → 替换为 (bad_name@offset)）
3. `_sec_by_name()`：get_section_by_name 的安全包装，坏节表时全部调用点短路
4. `_parse_dynamic_fallback()`：从 PT_DYNAMIC 手工解析 dynsym/dynstr
   （DT_HASH nchain 得符号数）；本样本 dynamic 区全零无符号，
   但对节表坏而 dynamic 完好的 dump（更常见）有效
5. `_functions_from_eh_frame_hdr()`：从 PT_GNU_EH_FRAME 的 binary search
   table（sdata4 pcrel 编码）恢复全部函数起点，相邻差分为大小
6. `read()` 三级读取：section 缓存 → PT_LOAD 段表 → 静默空（.bss 场景）

### 修复效果
- 加载：不再抛异常 ✓
- 函数：0 → 2656（eh_frame_hdr 恢复）✓
- read(0xB9DA4)：空 → 94 f9 ff 97 e0 0f 00 f9 ✓
- 分析质量：引用图 10495 调用边 + 5065 数据引用，抽样解码 100% ✓
- 字符串：0 → 7138 条（PT_LOAD 兜底扫描）✓
- MCP 端到端：load_so/metadata/disassemble 全部可用 ✓
- 回归：liblog.so 111 函数/105 PLT/25 sections 不变 ✓

### 附带修复
- core/strings.py：无节表时从 PT_LOAD 非可写段兜底扫描（>8MB 跳过）

### 未修（记录）
- Bug 4：segments 端点返回的是 sections；后续可加 program_headers 工具
- Bug 7：0 函数仍报 loaded；GUI 日志已显示 FDE 数，MCP 返回含 functions 计数

### 参考实现
rea 的 bridge/pwntools/layout_impl.py（314 行）对坏节表的校验思路：
显式 unknown 而非猜测、名字偏移越界即 LayoutFailure。

---

## 用户测试报告 14 bug 修复记录（2026-10-13 第二轮）

### P0（全部修复）
- **BUG-1 calls_to/called_by 语义颠倒**：重写 core/xref.py。新语义：
  calls_to[target]=[调用点地址]，called_by[fn]=[该函数发出的调用目标]。
  用户报告的"called_by[malloc] 与 malloc 自己的 bl 目标一致"正是旧代码
  把 caller 视角数据存进 callee 名字典的证据。随机抽样 17 条边方向全对。
  注：malloc calls_to=0 经核实是真实结果（libc 内部不直接调 malloc）。
- **BUG-1b call 指令 ref_addr=None**：core/disasm.py 对 is_call 同步
  ref_addr=call_target。下游只读 ref_addr 不再丢 call 边。
- **BUG-2/撤销说明**：用户已自行撤销"xrefs_from 返回他函数指令"（地址换算失误）。
  但顺手修复了真实隐患：fn.instructions 跨函数残留 → Xref 改用
  _insn_cache[fn_addr] 缓存，不再依赖指令回写。
- **BUG-3 string_refs 爆炸**：旧代码遍历全局 data_refs 的所有 key 按
  "像 rodata"过滤 → 每个函数拿到全库引用。新代码只取本函数发出的
  数据引用（_fn_data_refs）。libcutils 9 个爆炸函数 → 0。

### P1（全部修复）
- **BUG-4/10 节表无效静默垃圾**：_parse_sections 增加 all_null 检测
  （24 项全 SHT_NULL）、假名计数（ELF 魔数/控制字符）、sh_offset 越界
  检测；无效时 sections=[] + section_warning 诊断信息 + 段表兜底。
  实测 sgmiddletier dump：sections=0、warning 明确、节名垃圾消失。
- **BUG-5 read 静默空**：负地址/负长度抛 ValueError；完全 miss 记录
  _read_miss；新增 maps() 诊断接口列出全部已注册虚拟区域。
- **BUG-6 segments 端点**：改为 {program_headers, sections,
  sections_usable, warning}。program_headers 手工解析原始 ELF 头，
  RX 段（此前完全丢失）现在正确出现。

### P2（全部修复）
- **BUG-7 异常吞掉**：@logged 装饰器（现已覆盖全部 32 工具）捕获异常后
  返回 CallToolResult(is_error=True, content=含 error/tool/traceback_tail
  的 JSON)。修了 mcp 2.x 字段名坑：is_error（isError 是 1.x 的）。
- **BUG-8 metadata.sections**：与真实节表对齐（无效时 0 + warning），
  不再把 PT_DYNAMIC 当节。

### P3（全部修复）
- **BUG-9 search 负 limit**：limit<=0 返回 []（与 limit=0 一致），文档约定
  不限制传大数。
- **BUG-11 MCP 与脚本端同一套实现**：xrefs_to 已走 ensure_xrefs + 跨 so
  归并（此前修过）；calls_to 语义修复后两端自然一致。
- **BUG-12 rename 导出一致性**：exports 字典键同步 + _export_index 重建，
  改回名后 resolve_import 仍可用（实测 ✓）。
- **BUG-13 decompile 未建函数**：返回 "_MDA_ERROR_\nno_function\naddr"
  结构化错误，与空串可区分。
- **BUG-14 同名改名提示**：Session.add 设 renamed_from，load_so 返回
  {"renamed_from": "liblog.so"}。

### 验收结论
- libc_dev.so 回归：2795 函数 / 1440 导出与报告一致 ✓
- sgmiddletier dump：855 函数（eh_frame_hdr 恢复）、warning 明确、
  RX 段可读（"errno\0sem_init" 字符串可见）✓
- 全部 14 项闭环。

---

## BUG-15 + IDC 兼容性修复（2026-10-13 第三轮）

### BUG-15 else if 不支持（用户实测抓到）
最小复现：`if (1) ok = 1; else if (0) ok = 2;` → 产出非法 Python
三处修复（scripting/idc.py）：
1. if 分支单行体按顶层分号切分，`else...` 段回送循环续处理
2. em 分支（同单行内 else if）保留 "(cond) body" 完整结构交给
   _split_cond_body（此前剥 "(" 导致条件切分错位）
3. 独立行 else if（用户 mk() 的实际形态）也改用 _split_cond_body
   （旧 rest.find(")") 嵌套调用时错位）

### 连带修复
- BUG-16（新发现）：_parse_dynamic_fallback 在 _parse_symbols 之前运行
  但引用了 symbols/imports/exports → AttributeError。已自行初始化。
- get_flags 语义修正：旧实现用 function_at（有 FDE 才算代码），
  新地址恒 False → 用户 APSE_scp_handlers 11/33。现用 capstone 试解码。

### 验收
- 最小复现：if 1: / ok = 1 / elif 0: / ok = 2 语法合法 ✓
- 用户原版 APSE_scp_handlers.idc（33 个 SCP handler）：
  - 24 个完整创建（函数+命名）——落在可解码代码区
  - 9 个仅命名——落在加密数据区（字节随机，IDA 同样无法建函数；
    MakeName 无条件执行与 IDA 语义一致）
  - scp_op_SIGN @ 0xB9DA4 等关键函数全部命名成功
- e2e 回归 14/14 ✓

---

## 四个 P0 阻断 bug 修复（2026-10-13 第四轮，加固样本）

用户实测「三个连环失效」：RX 段读不到 → IDC 建函数名字错位 → MCP disassemble 取址错。
根因收敛为 4 个 P0，全部修复。

### BUG-1 sh_addr=0 的节被丢弃 → PIE 首段整段不可读（最根本）
- 根因：`if s["sh_addr"] == 0: continue` 把 vaddr=0 的节全丢掉。
  而 PIE/共享库首个 PT_LOAD 常规就是 vaddr=0（样本 4.2MB .text 全在此）。
- 修复：改用 SHF_ALLOC 位判定——`sh_addr==0 且非 SHF_ALLOC 且非 NOBITS`
  才跳过（.shstrtab 等无虚拟地址语义的节）。cache 同址时保留数据量更大者。
- 效果：原始样本（未改 sh_addr）直接可读 .text，6047 函数。

### BUG-4 反汇编遇数据块整体终止（最致命）
- 根因：capstone `disasm()` 遇无法解码的字节会**直接终止迭代**。
  加固样本大量内联跳转表，一次数据块即放弃后续全部代码
  （实测 2380 字节函数只出 71 条，丢 84%）。
- 修复：改为逐条 `disasm(count=1)` 手动推进；失败则按 ARM64 定长
  跳 4 字节并记一条 `.data` 伪指令，跨越数据块继续。
- 效果：71 → 595 条指令，覆盖率 100%；健康文件不受影响。

### BUG-2 MakeFunction 吞并中间函数 + 名字错位
- 根因：`_ensure_func` 用 `function_at(ea)`，ea 落在某函数**内部**时
  返回外层函数 → `MakeName` 把名字写到外层函数上（32 个 JNI 只活 5 个
  且名字错位）；`MakeFunction(ea, BADADDR)` 还会吞并后续函数。
- 修复：① `_ensure_func` 仅按**起点精确匹配**，否则新建独立函数；
  ② `BADADDR` 按 IDA 语义走**边界推断**（`_infer_end`）：扫描到 ret
  或下一个函数起点即停，不吞并。
- 效果：用户原版 APSE_jni_impl.idc **32/32 名字正确**（此前 5 个且错位）。

### BUG-3 MCP disassemble 取址偏差
- 复核结论：**BUG-1 的连带症状**，非独立缺陷。`.text` 被丢弃导致
  read 走不同退化路径才出现 0x400 偏差。BUG-1 修复后
  `disassemble(0xB9DA4)` 与 `disasm_range(0xB9DA4)` 完全一致，无需单独修。

### 回归
- e2e 14/14 ✓
- liblog 111 函数 / 105 PLT / 25 节 / 573 调用边 全部不变 ✓
- libAPSE_mda：6047 函数、.text 可读、0xB9DA4 函数 595 条指令 ✓

---

## 超时治理：惰性构建 + 缓存复用（2026-10-13 第五轮）

### 用户复盘（成立）
1. run_script 里跑全库反汇编循环（17×64KB 覆盖 4.2MB RX 段），且重复 3-4 轮
2. BFS 每节点调 `disasm_function` —— 该接口**不复用缓存**，每次完整重解码
3. 单个长脚本占住进程 → 后续所有 MCP 请求排队撞客户端超时

### 工具侧真实缺陷（已修）
**缺陷 1：`disasm_function` 无缓存复用**
- 现象：BFS 访问几百个函数 = O(N × 指令数) 次完整解码
- 根因：`Xref._insn_cache` 只在 build 路径填充；脚本直调
  `disasm_function` 不经过它，每次都重新解码
- 修复：`disasm_function` 命中 `fn.instructions` 直接返回；
  新增 `invalidate_cache(addr)` 供 IDC 改边界后失效

**缺陷 2：`disasm_range` 无缓存**
- 现象：用户分 17 块扫全库、重复 4 轮 = 同样的昂贵操作付 4 遍
- 修复：`(addr,size)` 键缓存，FIFO 上限 64 条防内存膨胀

**缺陷 3：`xref()` 无条件全量构建（最致命）**
- 现象：查**一个**函数也要先付 20-30 秒全量（6047 函数 / 86 万条指令）
- 修复：`xref()` 改为不自动构建，新增三层 API：
  - `ensure_function(so, addr)` —— 惰性单函数收集（O(该函数)）
  - `ensure_xrefs(so)` —— 显式全量（昂贵，符合语义）
  - `xref_progress(so)` —— 构建进度查询
- 连带修复：`callers_of` / `call_chain` 改为自行 ensure 所需模块/函数
  （e2e 曾捕获该回归：跨 so 反查因 calls_to 未构建而恒返回 []）

**缺陷 4：混合解码（性能与正确性兼顾）**
- BUG-4 的逐条 `disasm(count=1)` 打开了跨数据块能力，但每条一次跨语言
  调用（profile：20 万次调用占大半耗时）
- 改为**批量迭代解连续段 + 遇数据块重新定位**：实测 7.9× 加速，
  且 BUG-4 正确性保持（0xB9DA4 仍 595 条 / 100% 覆盖 / 22 个 .data）

**缺陷 5：`call_chain` 无节点预算**
- 新增 `max_nodes=2000` 与 `CallChain.truncated` 标记，防深树输出爆炸

### 效果对比（libAPSE_loadable.so，6047 函数 / 86 万条指令）
| 操作 | 修复前 | 修复后 |
|---|---|---|
| 查单个函数的引用 | 28s（全量） | **0.005s** |
| BFS 200 个函数 | 28s + 遍历 | **0.46s** |
| call_chain depth=3 | 超时 | **0.124s** |
| 用户超时脚本（SIGN 直接调用） | 超时 | **0.03s** |
| 用户超时 BFS depth≤4 | 超时 | **0.62s** |
| 重复全库扫描 4 轮 | 4× 全价 | 仅首轮付费 |

### 文档
`run_script` 工具描述补充性能约定：查单函数用 `ensure_function`，
全库引用才用 `ensure_xrefs`（且只调一次），遍历调用树优先用 `call_chain`。

### 回归
- e2e 14/14 ✓
- liblog：111 函数 / 105 PLT / 25 节 / 573 调用边 / 0x5d30 覆盖 0x118 全部不变 ✓

---

## P0/P1/P2 函数发现补全（2026-10-13 第六轮，用户建议）

### 用户建议（全部验证成立）
| 级别 | 建议 | 验证结果 |
|---|---|---|
| P0 | FDE 漏掉标准函数入口，需递归发现 | libAPSE_loadable 实测漏 **1207** 个带序言的 bl 目标入口 |
| P1 | 大函数吞掉内部入口（sub_29B2D0 吞 0x29BD54） | 复现：0x29BD54 序言 `sub sp,sp,#0x80; stp x28,x29`，被 0x29b2d0..0x29c830 整体吞掉 |
| P2 | build_xrefs 前须先补函数发现 | FDE 表**本身只有 6047 条**，0x29BD54 确不在表内 |

### 实现
新增 `core/discover.py`（FunctionDiscoverer），迭代到不动点：
1. **bl 目标 + 标准序言**（默认，安全）：ARM64 序言识别含 paciasp / bti /
   stp x29,x30,[sp,#-N]! / sub sp,sp,#N / stp 族 pre-index
2. **终止指令 + 序言**（`aggressive=True` 才开）：捕获跳转表分发的 handler

配套改动：
- `SoFile._refresh_functions()`：重建区间索引并保证**互不重叠**，
  按后出现的入口切开宿主（P1 的修法）
- `SoFile.add_function()`：IDC 与发现共用，避免两处各写切分逻辑
- `function_at()`：改为 **二分 O(log N)**（区间不重叠后成立）
- `Session.ensure_xrefs(discover=True)`：build 前先发现（P2）
- `mcp build_xrefs(aggressive=False)`：开关暴露给 AI

### 三个连带 bug（都已修）
1. **野调用目标**：BUG-4 让解码跨越数据块，数据字被误认成 bl，
   产生 692 个负地址/越界目标（`-0x7e59e98`）。修：引用收集时校验
   `in_load()`，越界一律丢弃；同时把 call 目标从 data_refs 剔除
   （此前 ref_addr==call_target 导致同一目标进两个表，data_refs 灌水）
2. **called_by 键不一致**：`_collect_function` 直接用传入地址作键，
   于是 `ensure_function(0xB9DA4)` 记在 0xB9DA4、`build()` 记在起点
   0xB9528 → 同一查询时而 8 条时而 0 条。修：统一归一化到函数真实起点
3. **区间重叠 93 处**：`_refresh_functions` 里 `max(0x10, ...)` 下限在
   相邻起点间距 <0x10 时反而造成越界（实测跳转表存在相距 4 字节的入口）。
   修：去掉下限，size 直接取 gap

### 误报治理（重要）
`aggressive=True` 的「终止+序言」启发式会**把 switch case 块切成函数**：
实测 libbase 386 → 557（+171），全部不是 bl 目标，而是同一 switch 的连续
case 块（每块 `bti jc; mov w0,#imm`）。故：
- 默认只认 bl 目标 → liblog/libbase/libcutils 新增 **0**（FDE 完整、零误报）
- aggressive 仅按需开启，并在工具描述里写明风险

### 效果
| 样本 | 发现前 | 默认发现后 | 依据 |
|---|---|---|---|
| liblog.so | 111 | 111 (+0) | — |
| libbase.so | 386 | 386 (+0) | — |
| libcutils.so | 168 | 168 (+0) | — |
| libAPSE_loadable.so | 6047 | **7861 (+1814)** | 全部 bl_target |
| libAPSE_loadable（aggressive） | 6047 | 9062 (+3015) | bl 1814 + prologue 1201 |

### 对既有结论的修正
- 上轮"SIGN handler 0xB9DA4 有 7 个调用、可追到 S-box"**不成立**：
  那是**宿主 0xB9528 整个函数体**（0x94c 字节）的调用。按真实边界，
  0xB9DA4 是**叶子函数**（52 条指令、0 个 bl、3 处 GOT 引用），
  通过 `ldr x26,[x26,#0xf90]` 取函数指针间接调用——这正是
  Ant Secure Compiler 隐藏 S-box 引用（全库 4502 条 adrp 无一条指向
  S-box 页）的机制。
- 边界修正后 0xB9DA4 需 `aggressive=True` 才会成为独立函数。

### 回归
e2e 14/14 ✓

---

## 用户第 7 轮报告复核（2026-10-13）

| # | 用户报告 | 判定 | 证据 |
|---|---|---|---|
| 1 | `ins` 变量名导致 SyntaxError | **不成立** | `ins` 与 `lst` 结果完全一致（7 个调用/595 条指令）。runner.py 只做 compile+exec，无标识符预处理。真实原因是提交代码括号未配对（如 `session.modules['x'` 少 `]`），改名时顺带修好被误归因 |
| 2 | `function_at(0x17FDC8)` 返回错误 addr | **不成立** | 0x17FDC8 是真实入口（18 处 bl 调用、12 个不同函数、序言 `sub sp,sp,#0xf0`）。用户认为的"真实入口 0x17D358"实为 0x17d340 内部 +0x18 的次级入口，且 **0 个 bl 调用**；两者相距 0x2A70，分属不同 FDE 区间 |
| 3 | FDE 漏识别函数入口 | **成立，已修** | 见下 |
| 4 | `calls_to` 恒空 | **成立，已修（我的回归）** | 见下 |

### Bug 4 真因：惰性构建的副作用（我引入的回归）
- 现象：`x = session.xref(n)` 后直接读 `x.calls_to` 得到**空字典**
- 根因：上一轮为治理超时把 `xref()` 改成不自动构建，但脚本的惯用写法
  正是「先 xref 再读索引」。**我此前的验证先调了 ensure_xrefs，所以看不出来——验证方法有缺陷**
- 修复：`calls_to` / `called_by` / `data_refs` 改为**属性，访问即构建**
  （结果有缓存，只付一次）。同时新增三个**不触发构建**的快速访问器
  供 GUI/调用链使用：`callees_of_fn()` / `callers_of_fn()` / `data_refs_of_fn()`
- 连带：GUI 全部改用快速访问器（UI 线程绝不能触发 15s 全量构建）；
  `call_chain` 改用 `callees_of_fn` 保持 0.12s 惰性
- 验证：`x = session.xref(k); x.calls_to` → 2817 个非空键、
  `calls_to[0x3495F4] = 486`；二次访问 0.000s

### Bug 3 真因：叶子函数被判据挡掉
- 现象：0x3495F4 被 486 处调用（来自 100 个不同函数）却不在函数表
- 根因：`_entry_ok` **要求标准序言**，而**叶子函数没有栈帧、也就没有序言**
  — 0x3495F4 首指令是 `ldrb w8,[x0]`（随后 tbnz/ret）。FDE 之外的
  979 个 bl 目标里 976 个是真入口，全被这一条判据挡掉
- 修复：新增 `_bl_entry_ok()`——bl 目标**不要求序言**，只要求
  可加载 + 4 字节对齐 + 可解码 + 非 PLT 桩
- 连带：`is_plt_stub()` 识别 ARM64 标准 4 条桩指令
  `adrp x16,pg; ldr x17,[x16,#imm]; add x16,x16,#imm; br x17`
  （我最初按 3 条判定，因中间还有 add 而全部漏掉）
- 效果：libAPSE_loadable 7861 → **8577**（+716 个叶子函数）；
  误建 PLT 桩 **0**；liblog/libbase/libcutils 仍 **+0 零误报**

### 已知限制（非 bug）
发现函数的 size 用「到下一个已知起点的距离」估算，可能越界。
实测"函数体内无 ret"的比例：发现函数 47%、**FDE 原生函数 64%**——
该二进制大量使用控制流平坦化与尾调用，碎片化是固有特征。
0x17FDC8 的 3 条 `b` 全部汇向公共出口块 0x17fec8，属同类碎片。

### 回归
e2e 14/14 ✓；liblog 111 / libbase 386 / libcutils 168 均 +0 ✓

---

## PLT 桩剔除：无节表加固样本的扇入污染修复（2026-10-27 第八轮）

样本：`libsgmainso-6.7.260202.so`（2985052 字节，ARM64，用户提供）
文件特征比前几轮的 dump 更刁钻：

```
$ file libsgmainso-6.7.260202.so
ELF 64-bit LSB shared object, ARM aarch64, dynamically linked,
can't read elf note at -1
```

- **节表头完好但内容被写坏**：pyelftools 迭代 section 直接抛
  `Expected section size to be a multiple of entry size in section ''`
- **PT_DYNAMIC 也被抹**：`relocations=0`、`symbols=0`
  → 导入/导出符号名在文件里已无任何残留，**不可能恢复**（非代码缺陷）
- MDA 表现：`sections=0 exports=0 imports=0`，靠 PT_LOAD 兜底 +
  PT_GNU_EH_FRAME 二分表恢复函数，FDE 初扫 **3016** 个函数

### 缺陷 1：PLT 桩被当成普通函数，霸占扇入榜首

- 现象：扇入 TOP5 全是 `size=0`、零出边的函数，
  其中 `0x1a4140` 被调用 **1436 次**排第一
- 反汇编一看全是标准桩：
  `adrp x16,#0x1aa000 | ldr x17,[x16,#0xee8] | add x16,x16,#0xee8 | br x17`
- 根因：`_parse_plt()` 开头 `plt = self._sec_by_name(".plt")`，
  无节表时返回 None 直接 return → `plt_map` 恒空；
  而 FDE 会把这些桩原样登记进函数表（`discovered_by="fde"`）
- 修复：新增 `_scan_plt_stubs_by_segment()`——无节表时按 ARM64
  标准 4 条桩指令模板扫可执行 PT_LOAD，命中地址进 `plt_stubs`；
  `_parse_functions()` 末尾按 `[stub, stub+16)` **区间**剔除函数入口
- 为什么必须按区间而非精确匹配：FDE 边界不准时会在桩**内部**登记假入口，
  实测 `0x1a4124` 是桩 `0x1a4120` 的第 2 条指令却被登记成函数
- 效果：3016 → **3007**（剔掉 9 个假入口）；扫出 **165** 个桩

### 缺陷 2：桩剔除后仍污染扇入统计

- 现象：桩已从函数表删除，`calls_to` 里 `0x1a4140` 仍以 1436 次排第一
- 根因：`xref._collect_function()` 把所有 bl 目标无差别写入 `_calls_to`
- 修复：落到桩的调用改记 `_plt_calls`（外部导入调用），不进 `_calls_to`；
  新增 `Xref.plt_calls` 只读属性暴露该表
- 效果（同一份样本，修复前后对比）：

| | 扇入榜首 | 值 |
|---|---|---|
| 修复前 | `0x1a4140`（PLT 桩） | 1436 |
| 修复后 | `0x14054c`（真函数，带完整序言） | 1064 |

外部调用 TOP5 正确归入 `plt_calls`：`0x1a4140`(1436) `0x1a41a0`(759)
`0x1a4160`(376) `0x1a4170`(206) `0x1a42f0`(205)

### 缺陷 3：`list_functions` 返回值误导

- 现象：无节表样本只显示 FDE 初扫数（3016），用户会误判"函数就这么多"
- 实际：建引用图时递归补 bl 目标，3016 → **4363**（+1356，+45%）
- 修复：初扫状态下返回 `hint` 字段明确提示；补全后不再出现

### 缺陷 4：`metadata` 三项全 0 掩盖真实外部依赖

- 修复：`plt_stubs` 数量 + 说明文案（符号名无法恢复，但外部调用确实存在）

### 同轮样本对比（5.5.110 dump）

`libsgmainso-5.5.110.so.758a6e6000.bin`（节表偏移非法，`too large
section header offset`）：扫出 **308** 个桩，但该样本 FDE 本就没把桩
登记成函数（桩附近 0 个函数入口），故剔除数 = 0 —— 属正确行为，非漏修。
其扇入榜首修复前后由 `0x27c00`(1656) 变为 `0x113548`(638)。

### 回归

- e2e **14/14 通过**
- 健康样本零误伤：liblog 111/plt_map 105、libbase 386/235、
  libcutils 168/174、libanti_complete_patched 1984/367
  （`plt_stubs` 均为 0，走原 `.plt` 节解析通路，行为不变）
- 桩复活检查：补全后函数表中落在桩区间内的入口 = **0**

### 第九轮：代码评审后的 5 项修正（2026-10-27）

第八轮改动经 code-review 审出 2 个阻断 + 3 个重要问题，逐条修复：

**① 桩扫描性能：构造耗时 4.79s → 0.35s**

初版对可执行段**每个 4 字节偏移**都解 16 字节交给 capstone
（1.7MB 段 → 43 万次解码，占 3.44s）。改为 ADRP 位模式预筛：

```python
w = struct.unpack_from("<I", raw, off + i * 4)[0]
if (w & 0x9F000000) != 0x90000000 or (w & 0x1F) != 16:   # ADRP 且 Rd==x16
    continue
```

实测 3.44s → 0.065s（53 倍），命中 165 个桩，与旧实现差异 **0**。
附带收益：预筛只落在合法 ADRP 编码上，减少非指令边界误判。

> 曾尝试"线性扫全段"（capstone 顺序解码），命中 0 —— 数据区会让
> 解码脱同步，此路不通，勿再尝试。

**② `list_functions` hint 在健康样本误报**

初版判据 `len(functions) == by_fde`（全来自 FDE），而这是健康样本常态：
liblog 111 个全 fde、libbase 386 个全 fde，补全增量实际为 **+0**，
却收到"函数数通常明显增加"的提示。改为 `by_fde and not so.sections`
（段表模式才提示）。实测：liblog/libbase 不再出现 hint，6.7 样本仍提示。

**③ `in_plt_stub` 线性扫描 → 二分**

该函数在引用图构建时每条 call 指令都要问一次（15814 调用点 × 165 桩），
把构建拖慢约 9%。改为 `_stub_sorted` + `bisect`，O(log n)。
保留长度不一致时自动重建的防御（外部若直接改 `plt_stubs`）。

**④ 桩地址被邻近函数"吞掉"，`function_at` 归属错误**

实测桩 `0x1a4104` 落在函数 `0x1a4084` 的区间 `[0x1a4084,0x1a4124)` 内
（`_refresh_functions` 按间隙拉长 size 所致）→ `function_at(桩)` 返回真函数。
修复：`function_at` 遇桩区间一律返回 `None`。

**⑤ `call_chain` 静默丢弃外部调用边**

段表模式桩无名字（`plt_map` 空），`resolve_call` 返回 None，
`call_chain` 遇 None 直接 `continue` → 实测 `children=[]`，边凭空消失。
修复：`resolve_call` 识别桩并返回 `callee=f"plt_{addr:x}", callee_addr=0,
via_plt=True`（地址派生名，不臆造真实符号名）。

**⑥ 模板判据去重**

`discover.is_plt_stub()` 与段表扫描各写一份 4 条指令模板，有判据漂移风险。
抽出 `elf_model.is_arm64_plt_stub(insns)` 作为唯一实现，两处共用。

### 修正后完整验证

| 项目 | 结果 |
|---|---|
| SoFile 构造（6.7 样本） | 0.350s（原 4.79s） |
| SoFile 构造（5.5 dump） | 0.367s |
| 引用图构建 | 8.04s / 8.42s（与基线 7.1~8.2s 同级） |
| 调用边完整性 | `calls_to` 8323 + `plt_calls` 5168 = **13491**（与修复前完全一致，无丢边） |
| 扇入 TOP3 | `0x14054c`(1064) `0x14f598`(709) `0x152598`(456)，无桩 |
| `function_at(桩)` | None ✓ |
| `call_chain` 外部边 | 可见 `plt_1a4140` / `plt_1a41b0` ✓ |
| 健康样本零误伤 | liblog 111/桩0、libbase 386/桩0、libcutils 168/桩0、libanti 1984/桩0 |
| e2e | **14/14 通过** |
