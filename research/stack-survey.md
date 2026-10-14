# 轻量 so 逆向工具 — 技术栈调研

> **调研方式**：playwright / curl 直查官方仓库与 PyPI 页面（本机 web_search 无 API key）。
> 所有版本号均来自页面实际显示或本机实测，未确认的明确标注。
>
> **本机已验证范围**（Python 3.11.15，样本 `liblog.so`，stripped）：
> - ELF 解析（section / symbol / relocation / FDE）
> - `.eh_frame` FDE 函数发现：**111 个函数，覆盖 .text 100%**
> - PLT/GOT 符号解析：**105/105 成功**
> - `adrp + add` 字符串引用还原：8 个参数全部还原
> - xref 建图：**927 条调用/分支边，381 个被引用目标**
>
> 因此「反汇编引擎 / ELF 解析 / 函数发现 / arm64 寻址」四节给出**已验证结论**；
> 「反编译引擎 / GUI 栈 / 同类项目 / rea 架构」给出**调研结论**。

---

## 1. 反汇编引擎选型（arm64）

| 引擎 | 许可 | ARM64 | 最新版本 | 评估 |
|---|---|---|---|---|
| **capstone** | BSD | ✅ 原生完整支持 | repo 稳定线 **5.0.9**（2026-05-28）；PyPI wheel **5.0.2**；**6.0.0-Alpha11**（2026-09-21）仍是 alpha | **推荐**。纯 C 内核 + ctypes Python 绑定，体积小，无重型依赖，macOS arm64 有官方 wheel |
| zydis | MIT | ❌ **仅 x86/x86-64** | v4.1.1（2025-02-16） | README 自述 "Fast and lightweight **x86/x86-64** disassembler"，无 ARM 支持。不选 |
| distorm3 | GPL-3.0 | ❌ **仅 x86/AMD64** | 3.5.2 | PyPI 描述 "decode x86/AMD64 binary streams"；上游 2023-10 后停更。双重排除 |
| LLVM MC | Apache-2.0 | ✅ 最强（clang 同源） | 未确认 | 无稳定 Python 绑定，需链接 libLLVM，违背"轻量" |

- 来源：[capstone-engine/capstone releases](https://github.com/capstone-engine/capstone/releases)、[PyPI capstone](https://pypi.org/project/capstone/)、[zydis](https://github.com/zyantific/zydis)、[PyPI distorm3](https://pypi.org/project/distorm3/)

**capstone Python 绑定在 arm64 上的成熟度**：
- 生态验证：angr 把 capstone 作为**硬性运行时依赖**（v10.0.3 锁 `capstone==5.0.9`），说明 5.0.x 是经大规模生产验证的稳定线
- macOS arm64 有官方预编译 wheel（`macosx_11_0_arm64`），用户零编译成本
- AArch64 模块持续维护：6.0 Alpha 系列几乎每版都带 AArch64 修复，且 `aarch64_op_mem.disp` 已从 `int32_t` 提升为 `int64_t`（支持 64bit displacement）
- **本机实测**：5.0.7 + Python 3.11.15 在 liblog.so 上完成全 .text 反汇编、`adrp/add` 操作数解析、927 条 xref，无崩溃

**结论**：capstone 是 arm64 唯一合理的主力引擎。**钉 5.0.x，不要上 6.0 Alpha**（Alpha 有 enum 改名等 API break）。

**已知局限**：capstone 只做线性反汇编 + 指令细节，**不提供 CFG、函数边界、类型推断、反编译**——这些必须自研。

---

## 2. ELF 解析：pyelftools / LIEF / 自研

| 方案 | 许可 | 评估 |
|---|---|---|
| **pyelftools** | **public domain**（无传染性，商业最友好） | **推荐**。纯 Python，零第三方依赖，section/symbol/relocation/DWARF/Android 压缩重定位全支持 |
| LIEF | Apache-2.0 | 功能更强（可**改写** ELF、跨 ELF/PE/Mach-O、自带 disassemble/assemble），但需编译 C++ 扩展，体积大；且 repo 1.0.0 与 PyPI 0.15.1 版本严重脱节 |
| 自研解析 | — | **不推荐**。坑极多（见下），重复造轮子且易错 |

- 来源：[pyelftools](https://github.com/eliben/pyelftools)、[PyPI pyelftools](https://pypi.org/project/pyelftools/)、[LIEF](https://github.com/lief-project/LIEF)、[PyPI lief](https://pypi.org/project/lief/)
- pyelftools 最新 tag **v0.33**（PyPI 显示 0.31，repo 更新更快，建议按 repo tag 装）
- pyelftools 已支持 **Android 压缩重定位**（`DT_ANDROID_RELA` 等，0.28 起）与 **RELR**（`SHT_RELR` / `DT_RELR`，0.29 起，含 `RelrRelocationTable` 位图解压）

### 自研 ELF 解析的坑

**本项目已实测踩到**：
1. `vma -> section 数据` 必须用 `sh_addr` 计算 section 内偏移，**不能**用 `sh_offset`。
   当 `sh_addr != sh_offset` 时（本例 `.data`: addr=0x105c0, off=0xf5c0）会索引越界且不报错。
2. 必须排除 `sh_addr == 0` 的 section（`.shstrtab`、`.gnu_debugdata`），否则产生 `(0, size)` 假区间干扰地址匹配。
3. objdump 打印的指令字（如 `b0ffffe4`）是「字」的大端风格显示，文件真实字节是小端存储（`e4 ff ff b0`）。
   从 objdump 抄字节必须按小端重组，否则反汇编全盘错乱。

**尚未实测但已从源码/文档确认会踩的坑**：
4. **`.gnu.hash` vs `.hash` 双表**：`.dynsym` 符号数不能靠 `.hash` 的 `nchain` 推；`.gnu.hash` 是 bloom+bucket+chain，最后一个 bucket 之后的符号数要从 `DT_SYMTAB` 与 `.gnu.hash` 区间差反推。
5. **`DT_RELR` / `SHT_RELR` 压缩重定位**：不是简单数组，是「基址 + 位图」编码。entry 偶数 = 新基址，奇数 = 位图（bit i 表示 `base + i*4/8` 处有一个隐式 addend 的相对重定位）。**位图的隐式 addend 是未知的**——这是最容易算错的地方。
6. **`rela.plt` ↔ GOT 的对应关系**：`.rela.plt` 每个 `r_offset` 指向 `.got.plt`（arm64 实为 `.got`）槽位，槽位内容 = 解析后的函数地址；PLT stub 通过 `adrp/ldr` 从该槽位跳转。**arm64 没有 i386 那样的 PLT0 push/jmp 结构**，PLT 条目固定 16 字节（`adrp x16; ldr x17,[x16,#off]; add x16; br x17`），不能照抄 x86 的「PLT 条目大小」经验。
7. **stripped so 的函数发现**：stripped 通常只删 `.symtab`，**`.dynsym` 仍在**（导出函数可见）；但**静态函数在 `.dynsym` 里完全没有**，必须靠 `.eh_frame` / DWARF / traversal 补。
8. **`.eh_frame` FDE 覆盖不完整**：FDE 只覆盖「需要 unwind 信息的函数」（有栈帧/会调函数的）。leaf 函数、纯计算函数可能没有 FDE。所以「111 个 FDE 覆盖 100% .text」在 liblog.so 上成立，**不能推广为普遍规律**。
9. **`SHN_XINDEX` 扩展索引**：`e_shstrndx == 0xffff` 时真实索引在 section 0 的 `sh_link`；符号 `st_shndx >= 0xff00` 同理走扩展表。
10. **section 可能整体缺失**：极端 stripped 的 so 会砍掉 section header，只留 program header，此时**只能从 PT_LOAD 推布局**。

---

## 3. stripped so 函数发现（已实测通过）

### 方案：`.eh_frame` FDE 遍历（主方案）

实测数据（liblog.so，stripped）：
```
FDE 数量: 111
.text: 0x5000 .. 0xdff0 (size 0x8ff0)
FDE 覆盖率: 0x8fe8 / 0x8ff0 = 100.0%
间隙: 仅 2 个 4 字节对齐填充
dynsym 导出函数 63 个，100% 命中 FDE 起点
```

**为什么这是 arm64 Android so 的最佳选择**：
1. **NDK 默认产出 `.eh_frame`**（clang 默认 `-funwind-tables`），而 `.debug_info` 在 release 构建中通常被 strip 掉。
2. **arm64 指令定长 4 字节**，误对齐风险远低于 x86 变长编码，使 traversal / prologue 匹配的可靠性都显著更高。
3. FDE 精确给出每个函数的 `[pc, pc+size)`，且 CFI 可推出栈帧大小——**无需启发式**。
4. 比递归反汇编（间接跳转 `br xN` 会断、switch 跳表难恢复）和 prologue 匹配（leaf 函数无帧、`-fomit-frame-pointer` 下 x29/x30 也不保存）都可靠。

正确用法（pyelftools 参数顺序易错）：
```python
from elftools.dwarf.callframe import CallFrameInfo
from elftools.dwarf.structs import DWARFStructs
import io
structs = DWARFStructs(True, 32, 8)   # little_endian, dwarf_format, address_size
cfi = CallFrameInfo(io.BytesIO(eh.data()), len(eh.data()),
                    eh['sh_addr'], structs, for_eh_frame=True)
for e in cfi.get_entries():
    if e.__class__.__name__ == 'FDE':
        pc = e.header['initial_location']; size = e.header['address_range']
```

**备选 / 补充方案**（当 `.eh_frame` 缺失或覆盖不足时）：
- `bl` 目标地址反推（本项目实测 `bl` 的 `operands[0].imm` 即目标地址）
- prologue 特征匹配（`stp x29,x30,[sp,#-N]!` / `mov x29, sp`；arm64 还有 `paciasp`）。本项目实测该模式在 liblog.so 中普遍存在
- `DT_INIT_ARRAY` / `DT_INIT_ARRAYSZ` 给出的构造函数是**免费的高置信函数地址**，且常指向 FDE 遗漏区域
- DWARF（若存在则最准，含函数名）

**推荐管线**：`.dynsym` FUNC → FDE 扫描 → init_array → bl/b 递归 traversal → 重叠消解 → DWARF 补充命名。

---

## 4. 反编译 / 伪代码（IDA F5 等价物）

| 方案 | 体积/依赖 | 许可 | 最新版 | 评估 |
|---|---|---|---|---|
| **angr** | 传递依赖极多（pyvex, cle, claripy, z3-solver, sympy, unicorn...） | BSD-2 | **10.0.3**（repo tag v10.0.3） | arm64 反编译可用，但**启动慢、内存占用高**，与"轻量"冲突 |
| Ghidra headless | 发布包约 500MB+，**需 JDK** | Apache-2.0 | **12.1.4**（2026-09-21） | 反编译质量最高，但体积与"不繁琐"目标冲突 |
| RetDec | 基于 LLVM，需编译 LLVM | MIT | 未确认 | 依赖庞大，且 README 自述已进入 "limited maintenance mode"。不选 |

- 来源：[PyPI angr](https://pypi.org/project/angr/)、[angr v10.0.3 pyproject](https://github.com/angr/angr/blob/v10.0.3/pyproject.toml)、[Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)、[avast/retdec](https://github.com/avast/retdec)

**angr 版本说明（重要）**：PyPI 首页显示的 `9.2.115`（2024-08-13）已严重滞后；实际最新为 **10.0.3**（提供 `macosx_11_0_arm64` wheel），`requires-python = ">=3.12"`，且锁 `capstone==5.0.9`。**注意：angr 10.x 要求 Python ≥3.12，与主项目的 3.11 冲突**——若将来接入，必须在独立 venv + 独立 Python 版本中运行。

**结论**：**第一阶段不做真反编译**。先做「结构化伪代码」——把 arm64 指令按控制流归类，
输出带缩进和 if/while 框架的类 C 文本（业界称 "pseudo-code" 而非 full decompiler）。
这是性价比最高的路径。若后续需要真反编译，再以「可选后端」形式接入 angr / Ghidra，
**不作为核心依赖，且必须在独立进程中运行**（angr 的 capstone 版本锁会与主项目冲突）。

---

## 5. arm64 寻址与 xref（已实测通过）

### `adrp + add` 字符串引用还原

实测还原 `android_name_to_log_id` 全部 8 个参数：
```
0x5d5c -> 0x3187 "main"      0x5d74 -> 0x3259 "radio"
0x5d88 -> 0x2dd3 "events"    0x5d9c -> 0x318c "system"
0x5db0 -> 0x3052 "crash"     0x5dc0 -> 0x2de6 "stats"
0x5dd8 -> 0x2f9f "security"  0x5dec -> 0x325f "kernel"
```

**地址计算规则**：
- `adrp xN, imm` → `xN = (PC & ~0xFFF) + (imm21 << 12)`，imm21 是**有符号 21 位**，页粒度 4KB
- `add xN, xN, #imm12` → `xN = 页基址 + imm12`（无符号 12 位，0–4095）
- capstone `detail=True` 下 `Arm64OpMem` 暴露 `base` / `index` / `disp`，**无需自己解位域**

### PLT/GOT 符号解析（实测 105/105 成功）

```
.rela.plt 的 r_offset(GOT 槽) -> r_info_sym -> .dynsym 符号名
PLT stub 反推: adrp x16,page ; ldr x17,[x16,#off] => GOT 槽 -> 符号名
```

### xref（实测 927 条调用/分支边，381 个被引用目标）

- `bl`/`b` 的 `operands[0].imm` 即目标地址
- 目标落在 PLT stub 起点 → 显示为外部符号名
- 目标落在 FDE 起点 → 显示为内部函数

**待处理**：arm64 还有 `adrp + ldr` 模式（取 GOT 中的数据地址），需单独处理。`ldr` 的 `operands[1].mem.base`/`mem.disp` 可解析。另外 `br xN`（间接跳转/跳表）与 `blr xM`（虚调用）目标未知，应标为「间接」。

**现成库**：**没有**「arm64 adrp/add → xref」的专用独立库。事实标准都内嵌在 radare2 / angr / Ghidra 中。capstone 已把最难的位域解码做完，自研约 100–200 行（本机已验证）。

---

## 6. macOS GUI 技术栈

| 方案 | 优势 | 劣势 |
|---|---|---|
| **PySide6** | Qt 官方绑定，原生 macOS 体验，**与 Python 分析后端同语言零 IPC 开销**，Qt 的 hex view / 语法高亮 / 大列表虚拟滚动成熟 | 打包后体积较大（含 Qt 运行时，可用 macdeployqt 裁剪） |
| Electron + TS | 前端生态丰富，UI 迭代快 | 需 Python 后端 + 进程间通信，架构复杂，内存占用高；DOM 万行指令会卡 |
| Tauri | 体积最小（用系统 WebView） | 同 Electron 的双进程问题，且 Rust 学习成本；逆向工具无主流案例 |

- PySide6 最新 **6.7.2**（[PyPI PySide6](https://pypi.org/project/PySide6/)）
- **同类架构参考**：[iaito](https://github.com/radareorg/iaito) 是 radare2 的官方 Qt GUI，纯 C++/Qt5-6，基于 r2 的 r2pipe 管道通信。radare2 最新 release **6.2.4**。

**推荐 PySide6**。核心论据：分析后端是 Python（capstone/pyelftools 都是 Python 生态），
GUI 用 PySide6 可直接调用后端函数，无需 IPC。iaito 证明了「薄 core + 细粒度 widget」能做成生产级逆向 GUI。

**iaito 架构观察（本机 clone 实测，可借鉴）**：
- 分层：`src/core/` 只做「转发给 radare2」（`Iaito.cpp` 5362 行几乎全是 `r_core_cmd_str` 封装）；`src/widgets/` 约 120 个面板纯渲染（43008 行）
- **决定性观察**：`Iaito.cpp` 与 `DisassemblyWidget.cpp`（2165 行）中 `grep -i aarch64` **零命中**——即 **GUI 层完全不知道目标是什么架构**，所有架构知识都在下层引擎
- License：**GPL-3.0**（有传染性，**只能读思路不能贴代码**）

**反汇编视图实现建议**：`QAbstractItemModel` + `QTableView` + 自定义 delegate painter，以获得稳定的大文件虚拟滚动性能。

---

## 7. 同类开源项目对比

| 项目 | 定位 | 规模 | 可借鉴点 |
|---|---|---|---|
| **radare2** | UNIX-like 逆向框架，CLI 优先 | 25.0k stars，最新 6.2.4 | 架构分层（IO/core/analysis/asm/cons），但 C 实现、学习曲线陡 |
| **iaito** | r2 的 Qt GUI | src 89609 行 / 431 文件（本机实测），1722 stars，GPL-3.0 | **GUI 与引擎分离的架构；GUI 层零架构知识；widget 一文件一职责可插拔** |
| **Cutter** | r2 的 Qt GUI（iaito 分支） | — | 现代 UI 设计参考 |
| **Ghidra** | NSA 全功能逆向平台 | 500MB+，最新 12.1.4，Apache-2.0 | 反编译算法、数据类型推断（太重，不照搬） |
| **GDA** | Android 逆向（Dalvik 为主），C++ 原生、低内存低磁盘 | 4852 stars，Apache-2.0 | **产品定位与功能路线图最接近**：xref（字符串/类/方法/字段）、搜索、重命名、注释、结果存 db、路径求解、污点分析、Frida hook、内存 dump。但**仓库不含 C++ 源码**（本机 clone 实测 359 文件全为文档/截图/脚本），且主攻 dex 而非 native .so，Windows only |
| **voltron** | 调试器 GUI（LLDB/GDB/VDB 后端） | 6340 stars，MIT | Python GUI + 外部后端分离架构可行，但性能有天花板；2025-01 后近乎停更 |
| **rea** | MCP 服务器，驱动 Hopper/Ghidra/IDA | 见第 8 节 | 分层架构设计 |

**三个项目提供的互补视角**：
- **iaito** 证明「薄 core + 细粒度 widget」能做成生产级逆向 GUI → **GUI 架构照抄这个分层**
- **GDA** 证明「低内存/低磁盘/免 JVM/专注 Android」是被市场验证的产品定位 → **产品定位与功能路线图照抄**
- **voltron** 证明 Python GUI + 外部后端可行但性能有天花板 → **反证渲染层要够快，选 Qt 而非纯 Python 绘制**

---

## 8. rea 架构的可借鉴与不可借鉴之处

仓库：<https://github.com/morluto/rea>（MIT，TypeScript/Node.js）

**rea 是什么**：一个 MCP 服务器 + CLI，让 AI agent 调用 Hopper/Ghidra/IDA 分析二进制/JS/.NET/网站等。

**它的分层**（来自 [docs/architecture.mermaid](https://github.com/morluto/rea/blob/main/docs/architecture.mermaid)）：
```
Entry Points (cli/main + dispatcher)
  → Production Composition (typed provider/session factories)
  → Adapters (Hopper bridge py / Ghidra bridge java / IDA 外挂 / 安装适配器)
  → Application Layer (SessionProviderRouter + BinarySession, AnalysisProviderRegistry, EvidenceLedger)
  → Provider Layers (15+ 个: pwntools/wasm/evm/hopper/ghidra/ida/browser/js/dotnet/firmware/android...)
  → Provider Process Foundation (owned process groups, deadlines, bounded reads)
  → Contracts Layer (caller-visible schemas + errorSchemas)
  → Domain Layer (Pure side-effect-free modules)
```

**规模（本机实测）**：`rea-agents` v6.4.0；37 个运行时 npm 依赖 + 19 个 devDependency；Node `^22.19.0 || ^24.11.0 || >=26.0.0`；CHANGELOG.md 单文件 305KB。**公开 tarball 不含 `src/`**，可测量的只有 `bridge/`：Python 3254 行 + Java 5172 行 + Swift 572 行 = **8998 行**，其中 `bridge/pwntools/` 仅 598 行。TypeScript 主体规模**未确认**。

### 可借鉴（这些层是它自己写的逻辑）

- **Domain Layer**：纯无副作用模块。本项目对应「分析核心」——ELF 解析、反汇编、xref 计算，全部纯函数化，可独立测试。**这是最有价值的一条**：domain 层可 100% 单测，不需要 Qt、不需要 GUI 事件循环。本机能快速用真实样本验证 FDE/adrp/xref，正是因为这些逻辑都在纯函数层。
- **Contracts Layer**：调用方可见的 schema。本项目对应「数据结构定义」——Function/Section/Symbol/Xref 的类型。**但不要做成生成式 schema 目录**，内部用 dataclass 即可。
- **Process Layer 纪律**：它用自有进程管理外部引擎（owned process groups / private roots / deadlines / bounded file reads / cleanup）。本项目若将来接 Ghidra 后端，**必须**有类似机制：启动超时、子进程组隔离（Ghidra 崩了不能带走 GUI）、有界读取（畸形 .so 不能让分析进程吃满内存）、私有临时目录 + 退出清理。
- **"one immutable deep binding per target" + "deterministic selection, no fallback"**：一个目标绑定一个后端，**后端失败就失败，绝不静默换后端**。否则「引擎 A 的函数列表 + 引擎 B 的伪代码」会拼出不存在的结果。这个纪律极重要。
- **Evidence / Unknown 显式归属**：REA 对 RELR 输出 `"addends": None` 和 `"offset_meaning": "unknown"`，并附说明 *"per-offset packed-word locations and implicit addends remain unknown"*；对 GOT/PLT 输出 `"convenience_maps_completeness": "unknown"`。**宁可输出「未知」，也不输出一个看起来合理的猜测。** 对逆向工具这是正确的工程纪律——一个错误的 xref 比一个缺失的 xref 危害大得多。
- **BYO + 上游原样 + 精确 pin**：REA 要求 "Provide an absolute Python executable whose environment already contains unchanged pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2"，且 "REA never installs Python, packages or GDB"。
- **snapshot 缓存思想**：`BinarySessionRecords + AnalysisSnapshotCache`。大 so 分析慢，缓存分析结果是必要的。
- **测试 seam**：REA 用 `fixtures/` 里的 fake launcher / fake bridge / fake CDP 做测试——这正是「内置后端可单测、Ghidra 后端用 fake 测」的模式。

### 不可借鉴（这些是"包装别人的引擎"）

- **Hopper / Ghidra / IDA Adapters**（含 `bridge/ghidra/` 8 个 Java 文件 5172 行）：这正是本项目要**替换掉**的核心。rea 的深度分析完全依赖这三个商业/重型工具，与「自研核心、不依赖这些」的定位正面冲突。
- **MCP 协议层**（`@modelcontextprotocol/server`、tool catalog 生成、mcp-registry 校验）：本项目是桌面 GUI，不是给 agent 用的服务。
- **多目标支持**（wasm / evm / browser / js / inspector / firmware / dotnet / android-dex）：rea 支持十几类目标，本项目只做 ELF so，**这是最大的精简点**。
- **安装适配器**（macOS verified vendor DMG → ~/Applications，Linux apt/dnf/pacman）：v1 不需要，v2 做 Ghidra 后端时再加。
- **Windows 层**（`src/windows/` + Node-API NTFS/Job Object）：macOS 优先，砍掉。
- **Evaluation**（agent release 评估 / transcript scoring）：与桌面 GUI 无关。

### 核心启发：Provider 抽象——应该预留「可插拔后端」

rea 用 `AnalysisProviderRegistry` 把「分析」操作路由到不同引擎（Hopper/Ghidra/IDA 选一个）。**本项目应预留同样的可插拔后端设计**，但形式要轻得多：

```python
class AnalysisBackend(Protocol):
    def functions(self) -> list[Function]: ...
    def disassemble(self, addr: int, n: int) -> list[Insn]: ...
    def decompile(self, func: Function) -> str | None: ...   # None = 不支持
    def xrefs_to(self, addr: int) -> list[Xref]: ...

class CapstoneBackend:   # 内置，永远可用
class GhidraBackend:     # 可选，检测到 analyzeHeadless 才启用
```

- 默认后端：内置 capstone 引擎（自研控制流 + 伪代码）
- 可选后端：Ghidra headless（用户本地有安装时才启用，做真反编译）
- 好处：核心功能零外部依赖，高级功能可选增强
- **必须抄的三条纪律**：no fallback / deep immutable binding / 后端能力显式声明（`decompile()` 返回 `None` 表示「我不支持」，UI 显示「该后端不支持反编译」而非报错）
- **不要抄的**：不要把后端抽象做成「用户可配置文件里写任意 provider 路径」。后端集合是封闭的（内置 capstone + 可选 Ghidra），硬编码两个实现比开放式注册表简单一个数量级。

### rea 的 MCP/CLI 双入口对桌面 GUI 的启发

rea 的入口是 `scripts/rea.mjs` dispatcher 路由到 `mcp` 或 one-shot CLI。启发：

- **不要只做 GUI。** 用同一套 domain + engine，额外暴露一个 **CLI**（`mytool analyze libfoo.so --json`）和一个 **headless 模式**。
- 收益：① 能在终端快速验证 domain 层（不必启动 GUI）；② 将来若要接 AI agent，MCP server 是薄薄一层（rea 证明了这条路）；③ 批量处理脚本化。
- 代价极低：`argparse` + JSON 序列化，约 200–400 行。
- **但不要抄 MCP server 本体**——那是 rea 的主入口，对你只是可选项。

### 轻量版最小可行核心模块清单（对应 rea 分层，砍掉 Adapter/MCP/多目标）

| # | 模块 | 对应 rea 的层 | 砍/留 |
|---|---|---|---|
| 1 | `core/elf_model.py` — ELF 结构封装（section/symbol/relocation/FDE） | 无（rea 用 pwntools） | **必做** |
| 2 | `core/disasm.py` — capstone 封装 + arm64 指令语义辅助 | 无 | **必做** |
| 3 | `core/functions.py` — 函数发现（FDE 优先 + 兜底） | 无 | **必做** |
| 4 | `core/xref.py` — 交叉引用（bl / adrp+add / adrp+ldr） | 无 | **必做** |
| 5 | `core/strings.py` — 字符串提取与引用还原 | 无 | **必做** |
| 6 | `core/pseudocode.py` — 结构化伪代码生成 | 无 | **必做** |
| 7 | `core/backends.py` — `AnalysisBackend` protocol + CapstoneBackend | Provider Layers + Composition | **必做**（预留接口，只实现一个） |
| 8 | `core/session.py` — 一目标一后端绑定，no fallback | Application Layer 的 `SessionProviderRouter + BinarySession` | **必做**（抄纪律，砍复杂度） |
| 9 | `core/runner.py` — 有界子进程运行器 | Provider Process Foundation 的 `src/process/` | **建议做** |
| 10 | `cli.py` — `analyze --json` headless 入口 | Entry Points 的 CLI | **建议做** |
| 11 | `models.py` — 数据结构定义 | Contracts Layer | **必做** |
| 12 | `ui/` — PySide6 面板 | Adapters 的 `src/server/`（换成 Qt widgets） | **必做** |
| 13 | ~~MCP server~~ | Entry Points 的 `src/main.ts` | 砍（将来可加，约 200 行） |
| 14 | ~~Hopper/Ghidra/IDA bridge~~ | Adapters 的 3 个 bridge | 砍（Ghidra 后端留到 v2） |
| 15 | ~~安装适配器~~ | Adapters 的 `Setup*` | 砍 |
| 16 | ~~contracts/errorSchemas 生成目录~~ | Contracts Layer | 砍（用 dataclass + 显式 Unknown 字段） |
| 17 | ~~evaluation~~ | Evaluation | 砍 |
| 18 | ~~wasm/evm/browser/js/firmware/dotnet/android-dex provider~~ | Provider Layers 的 8 个 | 砍 |
| 19 | ~~Windows 层~~ | `src/windows/` + Node-API | 砍 |

---

## 推荐技术栈组合

```
语言:        Python 3.11+ （避免过早上 3.13；注意 angr 10.x 要求 >=3.12，故 angr 必须独立 venv）
反汇编:      capstone 5.0.x （PyPI wheel 5.0.2 / repo 5.0.9；本机实测 5.0.7。BSD。钉 5.x，勿上 6.0 Alpha）
ELF 解析:    pyelftools v0.33 （repo tag；PyPI 0.31。public domain） —— 不自研
函数发现:    .eh_frame FDE (pyelftools) 为主 + .dynsym + DT_INIT_ARRAY + bl 目标反推 + prologue 特征匹配兜底
xref:        capstone detail 模式自研（bl / adrp+add / adrp+ldr），约 100-200 行
GUI:         PySide6 6.7.2 （Qt 官方绑定，原生 macOS，与 Python 后端同进程零 IPC）
打包:        PyInstaller + macdeployqt 裁剪 Qt 运行时（后续）
反编译:      第一阶段自研"结构化伪代码"；后续可选 angr 10.0.3 / Ghidra 12.1.4 作为可插拔后端，
            必须在独立 venv + 子进程中运行，绝不进核心依赖
```

### 目录结构

```
mda/
  core/           # Domain Layer：纯分析逻辑，无 GUI 依赖，可 100% 单测
    elf_model.py    ELF 结构封装（section/symbol/relocation/FDE）
    disasm.py       capstone 封装 + arm64 指令语义辅助
    functions.py    函数发现（FDE 优先 + 兜底）
    xref.py         交叉引用（bl/adrp+add/adrp+ldr）
    strings.py      字符串提取与引用还原
    pseudocode.py   结构化伪代码生成
    backends.py     AnalysisBackend protocol + CapstoneBackend（预留 GhidraBackend）
    session.py      一目标一后端绑定，no fallback
    runner.py       有界子进程（为 Ghidra 后端预留）
  models.py      # Contracts Layer：数据结构定义（dataclass + 显式 Unknown 字段）
  cli.py         # headless: analyze --json
  ui/            # GUI Layer：PySide6，不 import capstone/pyelftools
  app.py         # 入口
```

### 关键决策

**不依赖 IDA / Ghidra / Hopper / angr。** 全部核心能力用 capstone + pyelftools 自研实现。

### 负清单（不要做的事）

1. **不要自己写 ELF 解析器**——pyelftools 是 public domain 且零依赖，自研 ROI 为负（第 2 节列了 10 个坑）。
2. **不要追 capstone 6.0 Alpha**——API 在 break，钉 5.0.x。
3. **不要把 angr 装进主 venv**——依赖极多 + capstone 版本锁 + Python ≥3.12 要求，必须子进程 + 独立 venv 隔离。
4. **不要在第一版做真反编译**——先做「反汇编 + 符号/字符串/xref 还原 + 结构化伪代码」，覆盖 80% 需求。
5. **不要在 GUI 层写任何 arm64 特判**——iaito 用 5362 行 core 做到 `aarch64` 零命中，这是架构干净的证明。
6. **不要抄 rea 的 contracts / evaluation / MCP / 15 个 provider**——那些是为「一个 MCP 面挂 N 个商业引擎」服务的，与你的定位正交。
7. **不要贴 iaito 的代码**——GPL-3.0，只能读架构思路。
8. **不要输出"看起来合理的猜测"**——学 rea 的 Evidence/Unknown 纪律：宁可标 unknown，不要给错 xref。

---

## 附：证据边界

**已实际抓取/实测的来源**（均为当日）：
- GitHub API / raw / codeload / releases.atom：capstone、zydis、pyelftools、LIEF、angr、retdec、ghidra、iaito、GDA、voltron、rea
- PyPI（经清华/阿里镜像，直连 pypi.org 被 DNS 拦截）：capstone、lief、pyelftools、angr、distorm3、PySide6
- 本机 clone 实测：iaito（89609 行 / 431 文件）、GDA（359 文件 / 68MB / **0 个 .cpp**）、REA（bridge 8998 行，src 未包含）
- 本机 Python 实测：capstone 5.0.7 + pyelftools 0.33 在 liblog.so 上的完整管线（FDE 111 函数 / 100% .text、PLT/GOT 105/105、adrp+add 8 参数、xref 927 边）

**未确认 / 未覆盖的项**（明确列出，不做推测）：
- LLVM MC 最新版本号
- capstone 6.0 正式版发布计划
- angr 之外是否有成熟的轻量 arm64 反编译库（仅发现 `dmaivel/libdecomp`、`ata-nvm/chibidec` 两个低 star 线索，未验证）
- Tauri / Electron 在逆向工具中的主流案例
- rea 的 TypeScript 主体代码规模（tarball 不含 `src/`）
- rea 的 star 数 / commit 数（委托方提供为 162k star、2600 commits，本次未独立复核）
- GDA 的 C++ 源码规模（仓库不含源码）
- retdec 最新版本号
