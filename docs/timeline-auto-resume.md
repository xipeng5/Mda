# 统一时间线 / 自动放行 / load_so 函数表警告

三个能力的实现说明 + **真机实测的精度数据**。数据来自
`tests/manual_timeline_clock.py`、`tests/manual_timeline_precision.py`、
`tests/manual_timeline_device.py`（serial=3e2ff172，Android，frida 17.23.3）。

---

## 1. timeline —— 统一事件时间线

### 用法

```
timeline(serial, pid, duration=10.0, limit=500)
```

返回每条事件 `{t_rel_ms, kind, so, addr, tid, detail, seq, ts}`。

### 数据来源

| 来源 | 取自 | 说明 |
|---|---|---|
| 断点命中 | `get_dyn().hits()` → 内部 `debugger._hits` | 带完整现场（36 寄存器 + 栈） |
| 事件流 | `get_dyn().poll_events()` 同一份内部队列 | 带 seq、含 `auto_resumed` 等状态事件 |

**合并而不是重新采**：hold 命中一旦放行，现场就没了；重采会丢掉已经发生的事。

### 精度 —— 真机实测（不是估计）

| 量 | 实测值 | 方法 |
|---|---|---|
| 设备 `CLOCK_MONOTONIC` 分辨率 | **≈ 6 µs** | 连续读 20 万次取最小步进 |
| `Date.now()` 分辨率 | 1 ms（墙钟，粒度粗） | 同上 |
| frida RPC 往返（中位数） | **2.8 ms** | 200 次 `rpc.exports.ping` 往返 |
| frida RPC 往返（p90 / max） | 4.6 ms / 13.9 ms | 同上 |
| **单向延迟估计** | **≈ 1.4 ms** | RTT/2（两侧时钟域不同，单向无法直接量） |
| 相邻命中的实测间隔（真机） | 0.05–0.13 ms | systemui 上 libc 断点 6 秒采到多条 |

**结论**：同源事件（都来自 frida 消息）的相对间隔**可信到毫秒级，±2 ms 量级**——
比需求的"几十毫秒"好一个数量级。命中载荷比空 RPC 大（寄存器 + 24 帧 + 256B 栈），
所以按 2 ms 而不是 1.4 ms 报，是保守的。

### 为什么内存写入**不**混进这条时间线

perfwatch helper 的 `ts_ms` 是设备单调时钟、**相对 daemon 启动**。
要落回墙钟必须用"读状态文件的墙钟 − age_ms"反推，而状态文件
（`mda_perfwatch.c` 的 `write_state`）约 1 秒才刷新一次。
→ 该来源的绝对时刻误差可达**秒级**。混进来会让"毫秒级对齐"变成假精度，
所以明确排除，并在 `precision.cross_source_note` 里写清楚。

### 墙钟回退的处理

排序键是 `(ts, seq)`：seq 是服务级自增序号，严格反映**入队顺序**。
墙钟被 NTP 校时跳变时，seq 仍给出真实先后；
跳了多大由 `precision.wall_clock_backwards_ms` 如实报出。
真机验证时确实抓到过一次 **11.1 ms** 的墙钟回退——这条不是理论风险。

### 踩过的坑（已修）

`_sync_hits` 会把每条命中**同时**放进 `debugger._hits` 和 `service._events`
（type=`breakpoint_hit`）。两处都收 → 每条命中在时间线上出现两次，
实测 2 条命中给出 `count=4`，间隔算成 0。
→ 现在以事件流里的 `breakpoint_hit` 为准，`hits` 只补事件流没覆盖的（旧路径）。

---

## 2. set_breakpoint(auto_resume_after_ms) —— 防 ANR

### 用法

```
set_breakpoint(..., hold=True, auto_resume_after_ms=2000)
```

### 关键行为

- 定时器绑在**命中**上，不是绑在 `set_breakpoint` 那一刻。
  （`service._schedule_auto_resume`，每个 token 一个 `threading.Timer`）
- 到期自动 `resume()`，事件流记 `auto_resumed`。**绝不静默自动放行。**
- 手动 `resume()` 会取消对应定时器 → 不会重复 post。
- `detach()` 清空全部定时器 → 不会对已关闭会话 post。
- `hold=False` 配 `auto_resume_after_ms` → 抛 `BAD_REQUEST`，不静默忽略。
- 负数 → `BAD_REQUEST`。

### 边界情况（逐条实测）

| 场景 | 行为 | 事件 |
|---|---|---|
| 正常命中 → 到点 | 自动放行 | `auto_resume_armed` → `resumed` → `auto_resumed` |
| 到期前手动 resume | 定时器取消，不二次放行 | `auto_resume_cancelled`（返回里也带计数） |
| 到期但已不是 paused | 不报假成功 | `auto_resume_skipped` |
| 放行本身失败 | 记失败，**不重试** | `auto_resume_failed` |
| detach | 清空全部 | `auto_resume_cancelled` |
| 同一 token 重复扫描 `_sync_hits` | 只登记一次 | — |
| 一次下断、多线程同时命中 | 每 token 独立定时器，各管各的 | 每个都有一对 armed/resumed |

**为什么必须 token 粒度**：hold 命中可能同时挂住多个线程（不同 token），
每个命中的 deadline 不同。按 target 粒度管就会"一个到点把别的也放了"。

---

## 3. load_so 函数表不完整警告

### 阈值为什么是 100

正常 NDK 库 FDE/dynsym 初扫就有上百（liblog **111**、libcutils **168**、
device libc **2754**）；加固样本初扫可以只有个位数（实测某样本 **1** 个，
补全后 5476）。100 是这两类的分界。有测试锁住 99 报、100 不报。

### 两条路径都给警告

`reused=True` 的幂等分支过去会 `return` 掉、跳过警告——而"再 load 一次看看"
正是使用者最可能的动作。现在两条分支共用 `_so_table_warning()`。

### 文案

- `warning`: 函数表只有 N 个，可能不完整。基于它得出的『没有某个符号/函数』这类**否定结论不可信**——先补全再下结论。
- `next_step`: 调 build_xrefs 或 load_so(auto_discover=True)

### auto_discover 的结果如实带出

`auto_discover=True` 的成功/失败都进返回（`{ok, added, total, rounds}` 或
`{ok:false, error}`）。过去是 `try/except: pass`——补全失败时返回和成功一模一样，
调用方会以为"补全过了，函数就这么多"。
