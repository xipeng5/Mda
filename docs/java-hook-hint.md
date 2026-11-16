# 「不知道该 hook 谁」的解决流程

> 2026-11-13。对应实现：`server/dyn/java_bridge.py` + `server/mcp_server/tools.py`。
> 回归测试：`tests/test_regressions.py` 的 R87 / R88 / R89。

## 一、问题是什么

`java_hook` 本来就能回答「我 hook 的这个方法被调用了吗」。真正的堵点是**它回答不了"那我该 hook 谁"**：

```
用户 hook 了 com.x.CommentRealApi.add → 0 命中
然后呢？没有下一个线索了。
```

原来的诊断只能给三句话：类在不在、方法在不在、同类别的其他方法有没有被调。
而使用者真正需要的是第四件——**下一步去试谁**。

代价是可量化的：hook 一个类要 16~20 秒（等 ready + 采集 duration + detach）。
盲试四个类就是一分多钟，而且每次都要重新想参数。

## 二、三层能力，从上往下成本递增

| 层 | 工具 | 成本 | 是否 hook |
|---|---|---|---|
| ① 候选清单 | `java_hook_hint` | 2~5 秒，纯只读 | 不 hook |
| ② 调用计数 | `java_count_calls` | 5~8 秒 | 挂**仅计数**的空壳 |
| ③ 精确抓取 | `java_hook` | 16~20 秒 | 全套观测 |

关键设计：**先用便宜的把范围收敛，再上贵的**。
第 ① 层扫 2 万个已加载类只要 2 秒；第 ③ 层 hook 一个类要 20 秒。
顺序反过来就是本末倒置。

## 三、标准流程

### 第 1 步：没有方向时，先问网络层

```python
java_hook_hint(serial, pid, include_network=True)     # 只读，秒回
```

返回的 `network[]` 是 **Android / okhttp / JDK 标准 API 的常识清单**，不是某个 App 的特征：

| pattern | 为什么值得先看 |
|---|---|
| `*Interceptor*` | okhttp / 自研网络栈的拦截器几乎都叫这个，**加 header 最常发生在这里** |
| `okhttp3.Interceptor$RealInterceptorChain` | 所有拦截器都从这里被串联，挂 `proceed` 能看链条顺序 |
| `RequestHeader\|HeaderManager\|AddHeader` | 自研 App 常把加头逻辑单独抽一个类 |
| `setRequestProperty` | **JDK 标准 API**，用 `java.net` 而非 okhttp 的 App 一定走这里 |
| `addHeader\|header` | `okhttp3.Request.Builder` 的加头入口 |

每条都带 `how` 字段说明"下一步该挂哪里、看什么"。

### 第 2 步：有线索时，按命名找候选

```python
java_hook_hint(serial, pid, query="CommentRealApi", limit=10)
```

排序依据（`name_similarity`，纯 Python 实现）：

| 分数 | 条件 | 例子（query = `CommentRealApi`） |
|---|---|---|
| 1.00 | 完全相同 | `CommentRealApi` |
| ~0.95 | 一方是另一方的子串 | `CommentApi` → 0.90 |
| 0.55~0.90 | 共享**有信息量**的词元（按长度加权） | `CommentHelper` → 0.74 |
| ~0.42 | 只共享 `api`/`util`/`impl` 这类通用后缀 | `OrderApi` → 0.42 |
| 0 | 毫无交集 | `android.util.Log` → 0 |

`OrderApi` 得 0.42 是刻意的：只共享 `api` 说明不了任何事，不能当证据。

### 第 3 步：对候选做低成本计数

```python
java_count_calls(serial, pid,
                 classes=["com.x.CommentApi", "com.x.CommentHelper"],
                 seconds=5)
→ [{"class": "com.x.CommentHelper", "call_count": 42, "hooked_methods": 8},
   {"class": "com.x.CommentApi",    "call_count": 0,  "hooked_methods": 6}]
```

或者一步到位（hint 内置了计数）：

```python
java_hook_hint(serial, pid, query="Comment", count_seconds=5)
```

**为什么单独做一个计数工具**：`java_hook` 的每次命中都要取 Java 栈
（遍历整个栈 + 构造 `StackTraceElement`）再对每个参数 `toString`，
实测 **0.5~3 毫秒/次**。探查阶段挂整类几十个方法时这会明显拖慢目标，
还容易触发 `java_hook` 自己的自动降级——最后看到的是降级后的数据。

`java_count_calls` 反过来：**单次命中只做一个整数加法**，不取栈、不碰参数、
不构造对象。挂 37 个方法跑 4 秒，目标无感。

### 第 4 步：确认了，再上 java_hook 抓参数

```python
java_hook(serial, pid, class_name="com.x.CommentHelper", method="add",
          capture={"args": True, "ret": True, "arg_fields": ["url", "headers"]})
```

## 四、0 命中时诊断给什么（`diagnosis` 字段）

`total == 0` 时 `java_hook` 返回 `diagnosis`，分两层：**事实层**与**建议层**。

### 事实层（都是运行时真值，不是猜的）

| 字段 | 内容 | 能回答什么 |
|---|---|---|
| `class_refs[].loader` | `ClassLoader.toString()` | 类是不是被正确的 ClassLoader 加载（能看出 apk 路径） |
| `class_refs[].is_interface` | `Modifier.INTERFACE` | **接口的声明方法没有实现体，hook 了必然 0 命中** |
| `class_refs[].is_abstract` | `Modifier.ABSTRACT` | 同上，抽象方法也没实现体 |
| `class_refs[].overloads_of_target` | 同名方法的签名列表 | **是不是 hook 错了重载**（最高频原因） |
| `parent_hits[]` | 祖先链同名方法的真实调用次数 | 该 hook 父类的**证据**（有数字） |
| `sibling_methods_called[]` | 同类其他方法的调用次数 | 真正干活的是哪个方法 |
| `neighbors[]` | 同包下命名相似的类（按相似度排序） | 真实实现常常就在隔壁 |

`parent_hits` 是关键改进之一：原来是「可试父类：X」（纯猜），
现在会**主动在祖先链上挂计数**，直接给「父类那个方法被调了 12 次」。

### 建议层（`next_actions`，可直接照抄执行）

```json
[{"tool": "java_count_calls",
  "args": {"classes": ["com.x.net.CommentApi", "com.x.net.CommentHelper"], "seconds": 5},
  "why": "同包下命名相近的类（CommentApi, CommentHelper）；先便宜地看谁真的在被调用"},
 {"tool": "java_hook",
  "args": {"pattern": "com.x.net.CommentApi|com.x.net.CommentHelper", "duration": 10},
  "why": "一次 hook 这几个候选，按各自命中数判胜负，省掉逐个试"}]
```

**为什么非要有 `next_actions`**：`suggestion` 是给人看的一句话，
但执行的人（或模型）还得把它翻译成工具参数——类名写全了没有、
method 该不该带通配符、要不要开 count_seconds。翻译就是新的出错点，
错一次又是十几秒。

`suggestion` 的优先级顺序（按出现频率 × 排查成本排）：

1. **接口/抽象类** → 结构性原因，hook 了注定 0 命中
2. **祖先链有命中** → 有数字的证据，压过一切猜测
3. **兄弟方法在跑** → 换方法名
4. **有多个重载** → hook 错了重载
5. **都没有** → 类很可能选错了，指向 `java_hook_hint`

## 五、真实设备实测

设备 `3e2ff172`（M2002J9E / Android 12 / arm64 / frida 17.23.3）。

### 候选探查速度

| 操作 | 类数量 | 耗时 |
|---|---|---|
| `java_hook_hint(include_network=True)` | 22,216 | **4.7 秒** |
| `java_hook_hint(query="Interceptor")` | 11 命中 | **2.3 秒** |
| `java_hook_hint(query="Message")` | 87 命中 | **1.6 秒** |

### 计数能真正区分活跃与空闲

同一个 4 秒窗口，同一个进程（systemui）：

```
    98 次  hooked=37  android.os.Handler
    33 次  hooked=14  android.os.SystemClock
     0 次  hooked= 8  gov.nist.javax.sip.stack.IOHandler
```

活跃类有数、空闲类为 0——计数不是恒为 0，能真正区分。

### 0 命中诊断的实际输出

hook `com.android.systemui.demomode.DemoModeController`
的 `onDemoModeAvailabilityChanged`（方法存在但当前不会跑）：

```
耗时 5.0s  call_count=0
verdict: 1 个类已 hook，但 3s 内 **0 次调用**（方法存在）；
         下一步建议见 diagnosis.next_actions（2 条可直接照抄）

diagnosis 字段: class_count, class_loaded, class_refs, method_exists,
                neighbors, next_actions, parent_hits, same_package_size,
                sibling_methods_called, suggestion

class_refs[0].loader:
  dalvik.system.PathClassLoader[DexPathList[[zip file
    "/system_ext/priv-app/MiuiSystemUI/MiuiSystemUI.apk"], ...]]
```

注意 `loader` 里的 apk 路径——这直接回答了「这个类是从哪个 apk 加载的」，
对多 dex / 插件化的 App 尤其有用。

## 六、踩过的坑（都写进代码注释了）

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | `OrderApi` 相似度 0.625，与正确答案并列 | 按**字符**前后缀算分，`api` 三个字符也算贡献 | 改按**词元**加权；纯通用后缀压到 0.45 以下 |
| 2 | 所有类统一得 0.738 | camelCase 切词前先转了**小写**，驼峰边界被抹平 | 用原始大小写切词，切完再转小写 |
| 3 | 前 8 名有 6 个是 `$$ExternalSyntheticLambda3` | 编译器为 lambda 生成的一次性类，名字含关键字 | 名字含 `$$` / `$Lambda` 直接跳过（保留 `$Builder` 这类有语义的） |
| 4 | 前 4 名全是 `[Landroid.icu...;` | `enumerateLoadedClassesSync` 会返回**数组类型描述符** | 以 `[` 开头的跳过 |
| 5 | `SystemActions$SystemActionsBroadcastReceiver` 得 0 分 | `class_name_stem` 无条件在第一个 `$` 处截断，把最有信息量的词丢了 | 只有 `$` 后接数字或 `$$` 时才截断 |
| 6 | 已计数却还劝人"去跑计数" | verdict 分支没看 `count_seconds` 是否已给 | 按"是否已计过数"分两套建议 |
| 7 | 只给 `include_network` 却说"没有类匹配这条线索" | 没区分"没搜"与"搜了没结果" | 三个线索全空时给专门结论 |
| 8 | 0 分候选被整批丢弃，正确答案一起没了 | 一刀切过滤 | 改成排到后面 + 封顶 3 条，不丢 |

第 8 条是最值得记的：过滤看起来是"清理噪声"，但这个 App 里
**唯一正确的答案恰好得了 0 分**（因为第 5 条那个 bug 还没修）。
一刀切丢弃会让调用方看到"没有任何匹配"，方向彻底走偏。

## 七、能省多少轮试错

以「找到谁在给 HTTP 请求加 header」为例：

| 做法 | 轮次 | 耗时 |
|---|---|---|
| 盲试（改一个类名跑一次 `java_hook`） | 3~6 轮 | 60~120 秒 |
| hint → 计数 → 锁定 | 1~2 轮 | **7~10 秒** |

省的不是单次速度，而是**轮次**。原来每失败一次要重新构思"下一个猜谁"，
现在第一步就把候选按相似度排好、第二步用真实调用计数判胜负。

阿倍倍 2号-正在为您服务
