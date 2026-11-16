# MDA Web 界面：从原型到生产

> 原型：`docs/design/ui-proposal.html`（静态，用来定方向）
> 生产：`web/src/`（React + TS，接真实后端）
>
> 这份文档记录**哪些已经落地、哪些还没有、以及为什么**。

---

## 一、已经落地的视图（9 个）

主体区 7 个标签 + 左栏 2 个入口：

```
主体  [实时] [模块·代码] [引用] [图谱] [工具] [进程] [时间线]
左栏  字符串   段 / 节
```

### 1. 实时 —— 每次 MCP 工具调用都上流

**数据来源**：服务端 `@logged` 装饰器每次工具调用都会广播
`{type:"ai", tool, args, summary, ms, ts}`，不需要 AI 配合写任何东西。

**布局**（与原型一致的三栏）：
- 左：**目标** —— 自动跟随前台 App 的进程（`/api/foreground`），显示 inet 连接数
- 中：**事件流** —— 工具名 + 关键参数 + 返回摘要 + 耗时
- 右：**详情** —— 点任意一行看完整 `args` JSON

**底部泳道**：6 条（STATIC / VM / BP / PROC / BEHAVIOR / MEM），
每格 = 1 次**真实调用**（按时间桶落位，不是装饰曲线），右侧是整场累计计数。

**分类**：按工具名前缀通用归类，102 个工具全覆盖：

| 类别 | 前缀规则 |
|---|---|
| VM | `vm_` / `dump_vm` / `probe_vm` |
| 观察点 | `perf_watch` |
| Java | `java_` |
| 轨迹 | `trace_` / `watch_module` / `module_load` |
| 内存 | `mem_` |
| 行为 | `behavior_` |
| 进程 | `process` / `list_threads` / `probe_network` |
| 断点 | `breakpoint` / `hits` / `wait_hits` / `resume` / `freeze` … |
| 运行时 | `read_` / `locate_` / `get_callstack` / `list_modules` |
| 静态 | 其余 |

**边界**：界面**不承载 AI 的结论**。结论、建议、判断留在对话里。

### 2. 模块（代码）—— 热力条 + 可展开的反汇编

- **热力条**：220 格，位置 = 真实地址（`0x5000 → 0xdff0`），
  颜色 = 真实引用密度（对数尺度）。颜色用 `--hot1..4`，双主题自动跟随。
- **函数列表**：前 60 个，带导出标记与地址。
- **内联展开**：点函数头看它的**真实反汇编**（按需拉取后缓存），
  `bl` 蓝色、`ret` 橙色，一眼看出控制流。

> 原来这里是个 3D 球体，已移除。球体的位置是哈希、没有语义，
> 只有引用数被编码，等于把右侧函数列表又画了一遍；131K 函数的模块会变成噪声。

### 3. 引用 —— 谁调用了它 / 它调用了谁

**端点**：`GET /api/xref_tree?so=&addr=&depth=`

左右两栏，点击任意一条跳到该函数（自动切回模块视图）。

**为什么后端做名字映射**：前端只认地址只能显示 `0x5248`；
拉全部函数在浏览器里做映射，131K 函数的模块会卡死。

### 4. 图谱 —— 调用关系的固定布局

左=调用者、中=当前函数、右=被调用。

**为什么不用力导向**：力导向每次坐标都不同，同一个函数重开界面位置会跳。
固定三层，位置本身携带语义。跟随容器尺寸自适应。

### 5. 工具 —— 102 个工具的可查清单

**端点**：`GET /api/tools`，直接读 `server.list_tools()` 注册表。

**为什么不前端存一份**：工具会增加（这一轮就多了 10 个端点关联的工具），
任何手写副本都会过期。

### 6. 进程 —— 一个 App 到底有几个进程、哪个在跑网络

**端点**：`GET /api/app_processes?package=|pid=`

解决的实际问题：**抓包抓不到，很多时候网络不在你以为的那个进程里**。

**判定口径**：`inet_conns` = 该进程 fd 里的 socket inode ∩ `/proc/net/tcp|udp`
的 inode。只统计 socket 总数会把只用 unix socket 的进程误报成联网
（实测渲染进程 inet=0 但 socket=13）。界面标出口径，宽口径时明确写"宽"。

**无感知**：纯读 `/proc`，不注入、不 attach。

### 7. 时间线 —— 按真实耗时画甘特条

位置 = 调用时刻，长度 = 这次真实花了多久；最慢的标在顶部。

**诚实边界**：长度用 √ 压缩（否则几毫秒的条会被几秒的压成看不见），
只表示相对量级。没测到 `ms` 的显示 `—`，不编造。

### 8. 字符串（左栏入口）

**端点**：`GET /api/strings?so=&kw=`。真实字符串表 + 引用数。
实测 liblog.so 有 88 条。

### 9. 段 / 节（左栏入口）

**端点**：`GET /api/sections?so=`。真实段表 + 权限位。
实测 liblog.so 有 25 个段。

**权限位怎么来的**：`Section` 对象**没有** `flags` 字段
（实测只有 `name/addr/offset/size/sec_type/is_exec/is_write`），
所以按 `is_write`/`is_exec` 拼 `rwx` 串。

---

## 二、待命状态（标签栏常驻）

AI 装上监控后，标签栏右侧常驻 `待命中 N`，悬停展开。

**和事件流的区别**：事件流是**一次性**的（调完就过去），
待命是**持久状态**——断点装上后一直在，直到被撤掉。

**后端怎么做**（`server/api.py`）：声明式规则表，不写 if/else：

```python
_ARM_SPECS = {
    "set_breakpoint":         ("断点 {so_name}@{static_addr}", ("so_name", "static_addr")),
    "behavior_monitor_start": ("行为监控 pid={pid}",            ("pid",)),
    "perf_watch_daemon":      ("观察点 pid={pid}@{addr}",       ("pid", "addr")),
    ...
}
_CLEAR_MAP = {   # 清理类工具撤掉哪些装上项
    "unfreeze_process": ("freeze_process",),
    "detach_target":    ("set_breakpoint", "java_hook", "vm_breakpoint", "trace_code"),
    ...
}
```

新增工具只需在表里加一行。地址类参数统一按 `0x` 显示。

**两个设计决定**：
1. **失败的调用不记待命**。`_activity` 里失败时 summary 以 `✗` 开头，据其跳过。
   宁可少显示，也不能显示一个根本不存在的断点。
2. **「清空」只清界面**，不撤设备上的断点。界面不越权替 AI 做清理。

---

## 三、修掉的 bug

### (1) 工具耗时出现负数
`time.time()`（墙钟）→ NTP 校时会让差值倒退。换 `time.monotonic()`。

### (2) 浮层压住标签栏
`.stage` 是 `position:relative`，`.legend` 是 `absolute` → 盖到新加的 `.viewtabs`。
加 `.stage-canvas` 中间层。

### (3) xref_tree 500 Internal Server Error
把 `callees_of_fn` 当 hex 字符串写 `int(c, 16)`，实测它返回 **int**（`57408`）。
加 `_as_int()` 兼容三种形态。

### (4) CSS 变量名与项目不符 → 图谱节点黑块
按原型写了 `--livebg` / `--ok` / `--err` / `--line2` / `--sans`，项目里都没有。
`var()` 找不到变量时**整条声明失效** → SVG `fill` 退化成默认黑色。

### (5) 空参数显示成 `→ -`

### (6) 失败的调用被记成待命

### (7) `freeze_process` 有时限（实测教训）
把后台进程 SIGSTOP **20 秒**后进程消失（`/proc/<pid>` 不存在）。
原因：SIGSTOP 期间进程完全无法响应，Android AMS / Watchdog 按 ANR 回收。
**结论**：冻结适合"拍瞬间快照"，不能当暂停按钮；5 秒内必须解冻。

### (8) `index.html` 硬编码 `data-theme="dark"`
浅色主题永不生效。这是"改了 CSS/JS 都没用"的真正原因。

### (9) `HEALTH = URL + "api/health"`
给 `URL` 加了 `?v=...` 后，拼出 `...?v=..api/health` 返回的是 index.html，
`_wait_ready` 永远超时，窗口在 API 未就绪时打开、连失效会话。

### (10) WebSocket `useEffect` 依赖 `modules`
每次模块变化重建连接，消息丢失。

### (11) `hello` 消息未处理
首连时不同步已有模块。

### (12) `load_so` 不幂等
同一路径重复加载产生 `liblog_2.so` 副本。

### (13) **WebSocket 回调读闭包旧值**（最隐蔽的一个）
`setModules` 一直在正常工作，但回调里的 `modules` 是挂载时的旧值（空数组）。
我用"状态上报"去验证，而那个上报自己也在闭包里 → 报的是过期值，
让我误判为"模块加不进去"，追了 90 分钟一个不存在的问题。

**修复**：`modulesRef` 镜像最新 state，回调读 ref。

### (14) `Section` 没有 `flags` 字段
权限列恒为空。改按 `is_write`/`is_exec` 拼 `rwx`。

### (15) `LeftNav` effect 依赖漂移
父组件每次渲染传新函数引用 → effect 无限重跑 → 计数被覆盖成空。
回调放进 ref，effect 只依赖 `so`。

---

## 四、还没做的

| 原型里的 | 状态 | 说明 |
|---|---|---|
| 力导向图谱 | ⚠ 有意不同 | 用固定三层布局（位置稳定，见上） |
| AI 任务进度条 | ❌ 不做 | 服务端没有"开始"事件，编一个就是假数据 |
| 引用连线动画 | ⚠ 等价实现 | 用事件行左侧色条表示目标类型 |

---

## 五、数据真实性声明

**所有结构性数据都是真的**：
- 工具清单：102 个，直接读 `server.list_tools()`
- 函数 / 引用数：ELF 解析 `liblog.so`，111 个函数、406 条引用边
- 字符串：88 条（真实值，如 `lBinary log entry conversion failed`）
- 段表：25 个段（`.note.android.ident` 等）
- 进程 / socket / inet：真机 `3e2ff172` 现场读取
- 时间线耗时：`time.monotonic()` 真实测量

**演示性内容**：无。

---

## 六、验证

```bash
# 端点
curl 'http://127.0.0.1:8766/api/tools'                    # 102
curl 'http://127.0.0.1:8766/api/nav_stats?so=liblog.so'   # 111/88/25/406
curl 'http://127.0.0.1:8766/api/heatmap?so=liblog.so'     # max_refs 22
curl 'http://127.0.0.1:8766/api/sections?so=liblog.so'    # 25
curl 'http://127.0.0.1:8766/api/strings?so=liblog.so'     # 88
curl 'http://127.0.0.1:8766/api/foreground'               # 前台包名

# 回归
python tests/test_e2e.py            # 14
python tests/test_shell_sample.py   # 9
python tests/test_dyn_runtime.py    # 26
python tests/test_regressions.py    # 570
```

合计 **619** 项，全过。

### 专门锁住这轮踩过的坑

| 测试 | 防什么 |
|---|---|
| R68 | `int` / `"0x.."` / `"123"` 三种引用形态都能解析 |
| R69 | `styles.css` 里每个 `var(--x)` 都真的有定义 |
| R70 | 端点实现了就必须注册进 Route 表 |
| R71 | 段权限位由 `is_exec`/`is_write` 生成 |
| R72 | 交付前不留调试钩子（`__mda*` / `client_state`） |

---

## 七、与原型逐项对齐（2026-11-12 复核）

这是**逐屏点开原型页面后**的对照结果，不是凭印象。原型实际有 6 个视图、
5 组 20 项左栏导航、19 个 keyframes。

### 视图（原型 6 个）

| 原型 | 生产 | 说明 |
|---|---|---|
| 实时 ● | 实时 ● | 有活动点 |
| 代码 | 代码 111 | 原叫「模块」，已改名 |
| 引用 248 | 引用 406 | 计数真实 |
| 图谱 | 图谱 | — |
| 时间线 199 | 时间线 N | 计数=真实事件数 |
| 工具 102 | 工具 102 | 计数=注册表大小 |

「进程」不再是独立标签——原型把它放在左栏「目标进程」，生产同样从左栏进入。

### 左栏导航（原型 5 组 20 项，已全部补齐）

```
静态  代码 · 引用 · 字符串 · 段/节 · 图谱
动态  目标进程 · 断点 · 命中 · 内存
VM    派发点 · 寄存器 · 轨迹
行为  算法 · 文件 · Activity · assets
工具  全部工具 · 热力条 · 内存 diff · 模块管理
```

计数分三种来源，都是真的：

1. **静态组** —— `nav_stats` 解析当前 so 得到（函数/引用/字符串/段）
2. **动态 · VM 组** —— 服务端 `_tool_facts` 累积的「AI 本次会话调用过什么」，
   取 summary 里第一个整数（通用规则，不为每个工具写解析分支）
3. **行为组** —— 待命表里 `behavior_monitor_start` 的**真实参数**推导出
   哪些 hook 开着（crypto→MessageDigest/Cipher/Mac，file→FileIn/FileOut…）

取不到的显示 `—`，不填演示数字。

### 实时页左栏（原型三段，已补齐）

目标（进程）→ 模块 N 个（本会话已加载，带函数数）→ Hook N 已挂（开关状态）

> 原型那里「模块 1495 个」是**设备侧进程加载的全部 so**（读 `/proc/<pid>/maps`）。
> 生产显示的是**本会话真正加载过的模块**，因为 mda 的模块概念是"人工/AI
> 显式加载进分析会话的 so"，和进程 maps 不是一回事。混在一起会让人以为
> 已经分析过 1495 个模块。这条差异是刻意的。

### 实时顶栏（原型 6 个信息位）

`监控中 · 目标包名 pid · 条/分 · 次工具调用 · [前台不一致警告] · 暂停/自动滚动/清空/导出`

- 条/分：按真实 `ts` 算最近 60 秒
- 前台警告：当 AI 操作的目标包 != 当前前台包时出现
- 导出：把事件流原样存 JSON（取证）

### 事件流

- 六个筛选项（全部/静态/运行时/VM/行为/进程），覆盖 classify 的 10 个类别
- 表头可点折叠
- 行内容三段着色：工具名加粗 / 参数值底色 / 返回结果蓝色

### 代码页

指令拆四段：地址 · 机器码 · **助记符（加粗）** · **操作数（次级色）**，
`bl` 蓝、`ret` 橙。热力条在上方（220 格真实引用密度）。

### 动画

原型 19 个 keyframes，生产 25 个（含原型全部动作 + 交互态）。
补齐的：`pulse` `srin` `rowin` `enter` `fadebg` `bpulse` `armedsweep` `hkping`
`fxline` `fxdur` `fxdotpulse` `tagdrift`。全部挂在真实状态变化上，
并且都在 `prefers-reduced-motion` 下关闭。

### 这一轮修的两个真 bug

**(16) 顶栏「引用」计数永远为空**
`doSync` 里那句 `navStats("")` 没带 so，服务端只回 `serverModules`，
`refs` 是 undefined。左栏有 406、顶栏没有——同一个数据两处不一致。
改为按当前模块单独查一次。

**(17) 加载遮罩会卡住盖住整屏**
AI 连调 `load_so` 时每条事件都起一个异步任务去设 `loading`，
而清 `loading` 写在正常路径上。中间任何一环抛异常，遮罩就一直挂着，
整个界面看着像"发白打不开"（实测截图整屏发白就是它）。
改为 `try/finally` 无条件收遮罩，并用 `backendMods` 去重避免重复拉函数表。

**(18) 左栏「工具」组被挤出可视区**
5 组 20 项总高 618px，`.nav` 只给 `max-height:62%`（实测 500px），
最后 4 项看不到。改成导航占满剩余空间、日志面板固定高度。

---

## 八、目标选中态 / 因果特效 / 工具定位（2026-11-12 补充）

对着原型逐行核对后补的三件事，以及一个我自己造的 bug。

### 1. 目标行选中态

原型：`.proc.sel{background:var(--livebg); box-shadow:inset 1px 0 0 var(--live)}`

我原来只写了 `border-left:2px solid var(--live)`——**只有一条竖线，没有背景**。
改成原型同款：`background:var(--live-soft)` + `inset 1px 0 0`。
用 inset box-shadow 而不是 border 的原因：border 会占布局宽度，切换选中态时
行内文字会横向位移 1px；inset 不占位。

实测：`background: rgb(239,246,255)`、`box-shadow: rgb(37,99,235) 1px 0 0 0 inset`。

### 2. 因果连线 + 目标光点（原型 drawLink / markTarget）

每次工具调用，原型会：
- 从目标元素右缘画一条贝塞尔曲线到刚插入的那一行（`.fx-layer path.go`，900ms 消失）
- 在目标右上角闪一个 6px 光点（`.fxdot`，900ms）
- 把 `title` 写成「刚执行：<工具名>」

这个之前完全没做，现在补上了。

**但要说实话**：两栏是紧挨着的（左栏右缘 201px、事件行左缘 206px），
**原型里这条线本身也只有 5px 长**，视觉上几乎看不出来。它真实存在、逻辑正确，
但不是"一眼能看到"的特效。真正看得见的是**目标行 ping（蓝色光晕扩散）**
和右上角的**光点**。

### 3. 「工具在使用时自动定位」

原型 `pulseToolRow()` 里除了给那一行加 `busy` 脉冲，还有：

```js
if (rr.top < lr.top || rr.bottom > lr.bottom)
  hit.scrollIntoView({ block: "center", behavior: "smooth" });
```

即：**被调用的那个工具，如果不在工具列表的可视区，就自动滚到中间。**

我原来只做了脉冲没做滚动——工具在列表下方时等于没反馈。

实现踩了两个坑：
- `scrollIntoView` 会滚**所有可滚祖先**，实测把列表滚过头（目标行跑到视口上方 -54px）
- 用「当前中心差 + scrollTop」算落点也不对：平滑滚动期间 `scrollTop` 与
  视觉位置不同步

最终方案：列表设 `position:relative`，用 `row.offsetTop` 算落点后**立即赋值**。
实测：`preflight` 行被调用后 `scrollTop` 1808 → 467，该行 `visible: true`。

### 4. 我自己造的 bug：199 个 ERR_INSUFFICIENT_RESOURCES

上一轮为了让左栏计数跟 AI 活动刷新，我把 `aiEvents.length` 直接写进多个
`useEffect` 依赖。结果是**每来一条工具调用就发一次 `nav_stats` + `foreground`**。
一次会话几百条调用 = 几百个并发请求，浏览器直接报
`ERR_INSUFFICIENT_RESOURCES`（实测 199 条错误），页面卡死。

修法：
- App 里加一个**节流 tick**（最多 900ms 前进一次），所有刷新点共用它
- `hooks` 由父组件统一取一次传给 `RealtimeMonitor`，不再各发一次
- `foreground` 只在挂载时取一次（前台应用变化是低频的）

修完再跑 3 轮驱动脚本（24 次调用），console **0 错误**。

### 5. R69 抓到的问题

注释里写了原型变量名 `var(--livebg)`，而本项目没有这个变量。
R69（扫全文检查每个 `var(--x)` 都有定义）当场报失败——注释也在扫描范围内。
把注释改成说明性文字，不留用不了的变量名。

### 6. 目标行的「armed」状态（2026-11-12 再补）

用户看截图时指出：目标行应该有**蓝色竖条纹动效**。核对原型发现那一层是：

```css
.armed::after{
  content:"";position:absolute;left:0;right:0;top:0;height:100%;
  background:repeating-linear-gradient(90deg,
    transparent 0 6px, rgba(37,99,235,.13) 6px 7px);
  animation:armedsweep 2.2s linear infinite;
}
@keyframes armedsweep{from{background-position:0 0}to{background-position:14px 0}}
```

含义：**条纹在动 = 这个目标上装着断点/钩子/观察点，AI 还没撤**；静止即已撤离。
我之前只有纯色背景，等于把「AI 正在盯着」这个状态整个丢了。

同批补的还有：
- `◉ N` 待命计数（原型 `.armtag`，挂在行下方，不压进程名）
- 主进程圆点的 `bpulse` 外圈呼吸（原型 `.dotg.live`）
- 进程名 `font-weight:600`（原型 `.pn`）
- `N inet  M sock` 两列（接口本来就有 `sockets`，我解析时丢了）

### 7. 「模块 N 个」的数字来源，最终定了

之前我问过这个数该显示什么。核对后确认：**接口 `app_processes` 一直返回
`loaded_so_count`**（实测 com.miui.home = 1268），原型那个「1495 个」就是这个
——即**目标进程加载的 so 总数**，不是本会话加入分析的模块数。

现在标题显示真实总数，旁边小字标「会话 N」表示其中已经放进分析会话的有几个，
列表里是可点开的本会话模块。两个数字都真实，含义不混淆。

---

## 九、右侧改成「函数检视器」（2026-11-12）

用户指出：右侧还是旧的机制。核对原型，右侧是 `aside.insp` —— **一个函数的
全部已知事实**，不是一张 1900 行的函数列表。

### 原型结构（五个区块）

```
函数名
[导出] 0x5020 · 80 B

概况    引用数 / 调用者 N 个 / 被调用 N 个 / 所在段 / 连接
调用者  N        列表：函数名 + 地址，超过 4 条折成「还有 N 个…」
被调用  N        列表：函数名 + 地址（落在 PLT 的标 plt）
引用字符串 N     "system/libbase/cmsg.cpp" 这类真实字符串
动态    断点 / 命中
```

### 我原来是列表，为什么不对

原来右侧是虚拟滚动的函数列表——**列表用来"找"，检视器用来"看清一个"**。
原型要的是后者：选中一个函数，把它的入边、出边、引用的字符串、断点状态摊开。

### 新接口 `/api/fn_detail?so=&addr=`

一次返回：函数元信息 + callers + callees（含 plt 标记）+ 引用字符串 +
所在段 + 断点/命中。

三个实现要点：
- 调用者/被调用要在后端做地址→名字映射（前端拉全量函数在 131K 函数时会卡死）
- 引用字符串走 `StringAnalyzer.string_starting_at_or_before`——引用可能指向
  字符串中间，向前找起点才正确；且它是二分，不会线性扫 11 万条
- 所在段按 `addr` 落进哪个 `section` 判定

### 这一轮修的三个 bug

**(22) 引用字符串永远是空**
`so.read_cstring()` 这个方法根本不存在，每次抛异常被 `except` 吞掉。
而 `string_refs_of(0x12740)` 实测返回 11 个地址——数据是有的，只是读不出文本。
改成走 `StringAnalyzer`，现在能显示 `"system/libbase/cmsg.cpp"` 这类真实内容。

**(23) 未命名函数显示成空行**
`fn.name` 可能是空字符串（剥离符号的 so 很常见），直接渲染就得到"只有地址没有名字"
的一行。兜底成 `sub_<addr>`。

**(24) 顶栏跳转不切视图**
输入 `0x12740` 回车，只更新了"选中函数"，人还停在实时页——
看起来像什么都没发生。改成跳转后一并切到代码视图。

### 数据真实性

原型里那些数字（引用数 12、调用者 12、`"log_id out of range"`）是**设计稿的演示数据**。
`samples/liblog.so` 里根本没有那个字符串（`list_strings` 实测返回空）。

所以检视器显示的是样本的真实情况：`create_android_logger` 调用者 0（liblog 里
没有内部函数调用这个导出 API），`libbase.so` 的 `ReceiveFileDescriptorVector`
有 23 个出边、9 条真实字符串引用。

数字比设计稿小，但每一个都能在 so 里对上。

### 热力条提到全局（2026-11-12）

用户指出：「引用密度应该直接展示，而不是只在代码 tab 里」。

核对原型：`#heat` 在 `.heatwrap` 里，而 `.heatwrap` 是 `main.work` 的
**第一个子元素**——在视图标签之下、所有视图之上，跟切哪个标签无关。

我原来把它写在 `mainView === "module"` 分支里，切到实时/引用/图谱就没了。

热力条的信息性质是**背景**：它回答"这个模块整体哪里热"，不是某个视图的细节。
放在视图外面才对。

现在实测：实时 / 引用 / 图谱 / 工具 / 时间线 五页都可见，220 个色块 + 图例 +
「386 个函数 · 0x12000 → 0x3a3ec」。没有加载模块时不渲染（避免空条）。

### 调用工具时的定位 + 蓝色闪烁（2026-11-12 修复）

用户问："调用工具的时候会定位以及蓝色的闪烁吗？"

**答案：现在会了。之前全是坏的。**

#### 三个 bug 叠在一起

**(27) `findName` / `toIdx` 读的是挂载时的 modules 闭包**

这两个函数定义在 WS 的 `useEffect` 里，而那个 effect 只在挂载时跑一次
（依赖列表刻意保持最小，避免连接重建）。闭包里的 `modules` 永远是空数组。

后果：AI 每次调用带 `addr`，`toIdx` 永远返回 `null` → **代码页既不定位也不闪**，
"关注"列表里的函数名也只能显示裸地址。

修法与之前 `modulesRef` 那次同源：改读 `modulesRef.current`。

**(28) 代码页只渲染前 60 个函数**

`mod.funcs.slice(0, 60)`。AI 操作第 300 个函数时，列表里根本没有它 ——
即使 `toIdx` 返回了正确的 `i=300`，DOM 上也没有那一行。

修法：列表改为**以当前选中为中心的 60 行窗口**，任何函数都能被定位。

**(29) 闪烁动画本身不存在**

`.fnrow` 只有 `.sel` 背景色，没有动画。原来的 `flash` state 是传给
`SphereCanvas` 的——而球体在改版时已经移除、不再渲染，所以那个反馈整条断掉。

修法：加 `@keyframes fnflash`（蓝色背景 + 左侧竖条，1.3s 渐隐），
由 `flash.seq` 驱动：找到 `[data-i]` 对应行 → 加类 → 不在可视区就滚进可视区。

#### 实测证据

触发 `xrefs_to(so_name=libbase.so, addr=0x2ebd0)`（该函数在第 300 位）：

```
hit:        { mi: 0, i: 300 }        ← 定位命中
flashAddr:  0x2ebd0                  ← 闪的是这一行
flashFrames: 26                      ← 持续约 1.3s，说明动画真在跑
selSeen:    [0x12020, 0x2ebd0]       ← 选中跟着变
windows:    [0x12000~0x160dc, 0x2b030~0x33b70]   ← 列表窗口滚到以它为中心
```

#### 一个刻意的取舍

AI 操作时**不会自动切视图**。如果你正在看实时页，代码页的定位/闪烁不会把你
拽走——只有你自己在代码页时才看得到。打断用户当前视图比"让效果被看到"更糟。

## 十、空状态下的可用性（2026-11-12）

用户反馈：没加载 so 时，顶栏「建立引用图」「跳转框」看着能用，点了没反应，
会以为程序坏了。

### 原则

**不能用的东西必须看得出来不能用。** 静默失败比直接置灰更容易被误解成 bug。

### 逐个梳理

| 控件 | 空状态 | 依据 |
|---|---|---|
| 打开 so | 可用 | 唯一能脱离空状态的动作 |
| 建立引用图 | **禁用** | 没有 so 就没有可建图的对象 |
| 跳转框 | **禁用** | 没有函数表，跳去哪里都没有意义；placeholder 改成说明文字 |
| 代码 / 引用 / 图谱 | **禁用** | 依赖当前选中函数 |
| 实时 / 时间线 / 工具 | 可用 | 与是否加载模块无关 |
| 主题切换 | 可用 | 全局功能 |
| 复制 MCP 配置 | 可用 | 全局功能，没加载 so 也能先配好给 AI |

### 视觉

补了 `.btn:disabled` / `.jump:disabled` 的样式（原来完全没有）：
降透明度 + `cursor:not-allowed` + 取消 hover 反馈。

每个禁用控件都带 `title` 说明**为什么**不能用（"先打开一个 so" / "先选一个函数"），
而不是让人猜。

### 顺带记一条更新流程的坑

替换 `.app` 后如果**同时**存在「旧 stdio 转发进程」和「新主进程」，
AI 客户端会连到已经不存在的旧会话（表现为"MCP 断了"）。

正确顺序：
1. 杀掉所有 `MDA.app/Contents/MacOS/MDA`（含 `--mcp-stdio`）
2. 替换 `.app`
3. 启动**一个**主进程
4. 让 AI 客户端重连（旧 session id 已失效，服务端会返回 400）

不要替换完又手动开第二个实例——第二个会抢 8765/8766 并清掉前一个的会话。

---

## 十一、MCP 进程生命周期（方案 A + C，2026-11-12）

用户问："为什么 mcp 是监控进程的？每次变的话 mcp 就会一直变，那不就乱套了？"

**观察是对的。** `MDA --mcp-stdio` 不是监控进程，它是 stdio 形态的**转接器**：

| 进程 | 身份 | 端口 |
|---|---|---|
| `MDA`（无参） | GUI 主进程，持有 Session 与 8765/8766 | 监听 |
| `MDA --mcp-stdio` | AI 客户端拉起的 stdio 代理，把调用转发给 GUI | 不监听 |

AI 客户端配的是 stdio 形态，所以每次连接都会拉起一个代理。**问题在于它会堆积**。

### 原来会乱在哪

```
GUI 重启 → 旧代理的 stdin 还开着，它不认为自己该死
         → 继续读 stdin，转发目标已消失 → forward() 返回 None
         → 退化成本地独立分析 → AI 在分析，界面一动不动
```

实测同时出现过 **1 主 + 2 个 stdio**，老的连的是已消失的会话。

`link.py` 里的 `_Stale` 重握手只解决"GUI 还在、session 失效"；
解决不了"GUI 换了、代理变孤儿"。

### A：stdio 单例守护（`mcp_server/proxy.py`）

用文件锁保证同一时刻只有一个代理：

```python
_LOCK_PATH = os.path.join(os.environ.get("TMPDIR", "/tmp"), "mda-mcp-stdio.lock")

def _acquire_singleton():
    fh = open(_LOCK_PATH, "a+")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    ...
```

- 拿到锁 → 正常服务
- 拿不到 → 说明已有代理，**主动退出**（客户端会复用那条连接）

用 `flock` 而不是 PID 文件：进程崩了内核自动释放，不会留下死锁。

实测：父进程拿锁 OK，子进程 BLOCKED（跨进程也生效）。

### C：GUI 启动时清理孤儿（`server/api.py`）

`lifespan` 里第一件事就是把所有 `--mcp-stdio` 进程收掉：

```python
def _reap_orphan_stdio() -> int:
    out = subprocess.run(["pgrep", "-f", "MDA --mcp-stdio"], ...)
    for pid in pids:
        if pid != os.getpid():
            os.kill(pid, 9)
```

- **只匹配带 `--mcp-stdio` 的**，绝不误伤主进程
- 尽力而为，失败不影响启动
- 客户端下次连接会重新拉起一个（那时由单例锁裁决）

### 为什么 A 和 C 都要

- **只有 A**：老代理占着锁不肯退，新代理起不来（因为老的那个不认为自己该死）
- **只有 C**：清理只发生在 GUI 启动那一刻，运行期间仍可能堆积

两个一起：GUI 启动 → C 清场 → 客户端重连 → A 保证只留一个。

### 正确的更新流程（补记）

```bash
# 1. 全部退出（含 stdio 代理）
pkill -9 -f "/Applications/MDA.app/Contents/MacOS/MDA"

# 2. 替换
rm -rf /Applications/MDA.app
cp -R dist/MDA.app /Applications/MDA.app
xattr -dr com.apple.quarantine /Applications/MDA.app

# 3. 启动【一个】主进程
/Applications/MDA.app/Contents/MacOS/MDA &

# 4. AI 客户端重连一次（旧 session id 已失效）
```

**不要替换完再手动开第二个实例**——第二个会抢 8765/8766 并清掉前一个的会话。
