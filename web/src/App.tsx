import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { hex, type ModuleData, type Func } from "./lib/data";
import { api, hasNativeDialog, pickSoFile } from "./lib/api";
import type { ApiInsn, ApiNavStats } from "./lib/api";
import { SphereCanvas } from "./components/SphereCanvas";
import { LeftPanel } from "./components/LeftPanel";
import { LeftNav } from "./components/LeftNav";
import { HeatBar } from "./components/HeatBar";
import { FlatTable } from "./components/FlatTable";
import { Inspector } from "./components/Inspector";
import { DynStateView } from "./components/DynStateView";
import type { DynKind } from "./components/DynStateView";
import { NeedSoView } from "./components/DynStateView";
import { RealtimeMonitor, type AiEvent } from "./components/RealtimeMonitor";
import { ConsoleOverlay } from "./components/ConsoleOverlay";
import { ToolsView } from "./components/ToolsView";
import { ProcessesView } from "./components/ProcessesView";
import { XrefView } from "./components/XrefView";
import { GraphView } from "./components/GraphView";
import { TimelineView } from "./components/TimelineView";
import { ArmedBar } from "./components/ArmedBar";
import { CodeOverlay } from "./components/CodeOverlay";
import type { Relations, Theme } from "./lib/sphere";

type LogItem = { time: string; text: string; kind?: string };
type WatchItem = { so: string; name: string; addr: number };

const now = () => new Date().toLocaleTimeString("zh-CN", { hour12: false });

export default function App() {
  const [modules, setModules] = useState<ModuleData[]>([]);
  const [active, setActive] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [watch, setWatch] = useState<WatchItem[]>([]);
  // 实时监控台：每次 MCP 工具调用都进这条流（服务端 @logged 广播）
  const [aiEvents, setAiEvents] = useState<AiEvent[]>([]);
  // 节流 tick：AI 事件再多，依赖它的刷新最多 900ms 一次。
  // 直接用 aiEvents.length 做依赖会变成"每条事件一次请求"，几百条就把
  // 浏览器的并发配额打爆（实测 ERR_INSUFFICIENT_RESOURCES）。
  const [aiTick, setAiTick] = useState(0);
  const tickTimer = useRef<number | null>(null);
  // 顶部标签上的计数要真实：引用数来自 nav_stats，工具数来自注册表
  const [navSt, setNavSt] = useState<ApiNavStats | null>(null);
  const [toolN, setToolN] = useState<number | null>(null);
  const [aiPaused, setAiPaused] = useState(false);
  // (131) WS 的 onmessage 闭包里读不到最新的 aiPaused（effect 依赖不含它），
  //       用 ref 镜像，保证暂停立刻生效。
  const aiPausedRef = useRef(false);
  // 每个工具被调用过几次（事件流与工具页共用）
  const [toolCounts, setToolCounts] = useState<Record<string, number>>({});
  // 视图集合：monitor / module / tools / processes / xref / graph / timeline
  //         / strings / sections / dyn:*（断点/命中/内存/派发点/寄存器/轨迹/行为）
  // 用 string 而不是字面量联合：左栏入口会持续增加，字面量类型每加一个都要改这里，
  // 改了还会忘记同步渲染分支（R83 那种"渲染条件是 mod，没 so 就白屏"的坑）。
  const [mainView, setMainView] = useState<string>("monitor");
  // (1) 第一次修改：主题默认跟随系统外观（macOS 深色/浅色），不再硬编码 dark。
  //     手动点过切换按钮后锁定用户选择，系统再变也不覆盖。
  // 默认浅色，与设计稿一致（原型 --bg:#fbfbfc）；用户可手动切深色
  const [theme, setTheme] = useState<Theme>("light");
  const themeLocked = useRef(false);
  const [code, setCode] = useState<{ open: boolean; rows: ApiInsn[]; live: boolean }>({ open: false, rows: [], live: false });
  // 代码页内联展开：addr → 反汇编行（按需拉取后缓存）
  const [expanded, setExpanded] = useState<Record<number, ApiInsn[]>>({});
  // 代码页列表：以当前选中函数为中心的 60 行窗口。
  // 只渲染前 60 个的话，AI 操作靠后的函数时列表里没有它，定位就落空了。
  const codeListRef = useRef<HTMLDivElement | null>(null);
  const [relations, setRelations] = useState<Relations | null>(null);
  const [bps] = useState<Record<string, Set<number>>>({});
  const [progress, setProgress] = useState<{ percent: number } | null>(null);
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  // 版本号来自 /api/health（唯一来源是 version.py），不在前端硬编码
  const [ver, setVer] = useState("");
  const [rotateIdx, setRotateIdx] = useState<number | null>(null);
  const [jumpText, setJumpText] = useState("");
  const [busySo, setBusySo] = useState<string | null>(null);
  const [flash, setFlash] = useState<{ i: number; seq: number } | null>(null);
  const [pulseKey, setPulseKey] = useState(0);
  const [loading, setLoading] = useState<{ name: string } | null>(null);
  const [loadError, setLoadError] = useState("");
  const [dragging, setDragging] = useState(false);
  const flashSeq = useRef(0);
  const backendMods = useRef<Set<string>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  // 最新 state 的镜像：ws 回调里的闭包拿不到最新值，必须走 ref
  const modulesRef = useRef<ModuleData[]>([]);
  const modRef = useRef<ModuleData | undefined>(undefined);
  // 服务端有、界面还没有的 so（来自 nav_stats 这条可靠路径）
  const [pendingSo, setPendingSo] = useState("");
  const booted = useRef(false);

  const mod = modules[active];
  const selected = sel[active] ?? -1;
  const f = mod && selected >= 0 ? mod.funcs[selected] : null;

  const log = useCallback((text: string, kind?: string) => {
    setLogs((prev) => [...prev.slice(-300), { time: now(), text, kind }]);
  }, []);

  /** 展开/收起某个函数的反汇编（内联在代码页里，和原型一致） */
  const toggleFn = useCallback(
    async (soName: string, addr: number) => {
      setExpanded((prev) => {
        if (prev[addr]) {
          const next = { ...prev };
          delete next[addr];
          return next;
        }
        return prev;
      });
      if (expanded[addr]) return;               // 刚才是展开态，这次是收起
      const d = await api.disasm(soName, addr);
      if (d?.items?.length) {
        setExpanded((prev) => ({ ...prev, [addr]: d.items }));
      }
    },
    [expanded]
  );

  /** 跳到指定 so 的指定函数（引用页/图谱点击进出）
   *  先切回模块视图，否则用户点了没反应会以为坏了 */
  const jumpToAddr = useCallback(
    (soName: string, a: number) => {
      const mi = modules.findIndex((m) => m.so === soName);
      if (mi < 0) {
        log(`跳转失败：没有模块 ${soName}`);
        return;
      }
      const i = modules[mi].funcs.findIndex((x) => x.a === a);
      if (i < 0) {
        log(`跳转失败：${soName} 里没有 0x${a.toString(16)}`);
        return;
      }
      setActive(mi);
      setSel((prev) => prev.map((v, k) => (k === mi ? i : v)));
      setMainView("module");
    },
    [modules, log]
  );

  /* 代码页可见的那 60 个函数：以当前选中为中心 */
  const codeWindow = (() => {
    if (!mod) return [];
    const n = mod.funcs.length;
    const cur = Math.min(Math.max(sel[active] ?? 0, 0), Math.max(0, n - 1));
    const win = Math.min(60, n);
    const start = Math.max(0, Math.min(cur - Math.floor(win / 2), n - win));
    return mod.funcs.slice(start, start + win);
  })();

  /* AI 打到某个函数时：那一行蓝色闪一下，并滚到可见处。
     原来是 flash → SphereCanvas（已不再渲染），等于这个反馈丢了。 */
  useEffect(() => {
    if (!flash) return;
    const box = codeListRef.current;
    if (!box) return;
    const row = box.querySelector<HTMLElement>(`.fnrow[data-i="${flash.i}"]`);
    if (!row) return;
    row.classList.remove("flash");
    void row.offsetWidth;              // 强制回流，让动画能重播
    row.classList.add("flash");
    const br = box.getBoundingClientRect();
    const rr = row.getBoundingClientRect();
    if (rr.top < br.top || rr.bottom > br.bottom) {
      box.scrollTop += (rr.top + rr.bottom) / 2 - (br.top + br.bottom) / 2;
    }
    const t = window.setTimeout(() => row.classList.remove("flash"), 1300);
    return () => window.clearTimeout(t);
  }, [flash?.seq]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // 把最新的 modules / 当前模块镜像到 ref，供 WebSocket 回调读取
  useEffect(() => {
    modulesRef.current = modules;
    modRef.current = mod;
  }, [modules, mod]);

  // 跟随系统外观变化 —— **仅在用户手动切过主题之后**才生效。
  // 启动时不跟随：设计稿是浅色基准，且 WKWebView 启动会派发一次媒体查询事件，
  // 若不设门槛，窗口会在这时被改回深色（浏览器里没有这个行为，实测踩到）。
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const onChange = (e: MediaQueryListEvent) => {
      if (themeLocked.current) setTheme(e.matches ? "light" : "dark");
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  useEffect(() => {
    setPulseKey((k) => k + 1);
  }, [active]);

  /** 后端已解析完成 → 拉函数表、建模块、选中第一个导出函数 */
  const appendModule = useCallback(async (so: string, path: string) => {
    const mark = (m: string) => {
    };
    mark(`enter:${so}`);
    const fn = await api.functions(so, "", 200000);
    mark(`funcs:${so}:${fn?.items?.length ?? "null"}`);
    if (!fn) throw new Error("后端没有返回函数表");
    const funcs: Func[] = fn.items.map((it) => ({
      n: it.name, a: it.addr, s: it.size, e: it.is_export ? 1 : 0, r: it.refs ?? 0,
    }));
    if (!funcs.length) throw new Error("这个 so 里没有解析出任何函数");
    const data: ModuleData = { so, path, size: 0, sections: [], funcs, disasm: {}, callers: {}, callees: {} };
    backendMods.current.add(so);
    let newIndex = 0;
    setModules((prev) => {
      const exists = prev.findIndex((m) => m.so === so);
      if (exists >= 0) { newIndex = exists; return prev; }
      newIndex = prev.length;
      return [...prev, data];
    });
    setSel((prev) => {
      const next = prev.slice();
      next[newIndex] = funcs.findIndex((x) => x.e) >= 0 ? funcs.findIndex((x) => x.e) : 0;
      return next;
    });
    setActive(newIndex);
    log(`已打开 ${so} · ${funcs.length} 函数（后端实时解析）`, "ai");
  }, [log]);

  /** 释放一个模块：只清 mda 内的解析结果，不影响设备端进程。 */
  const unloadModule = useCallback(async (so: string) => {
    try {
      const r = await fetch(`${location.origin}/api/unload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ so }),
      });
      const j = await r.json();
      if (!r.ok || j.ok === false) {
        log(`释放失败：${j.error || r.statusText}`, "ai");
        return;
      }
      // 从本地状态里移除，保持前后端一致
      backendMods.current.delete(so);
      // (3) 第三次修改（2026-11-11）：
      //     bug 原因：原来无条件 setActive(0)，卸载非当前模块时界面会莫名跳回第一个。
      //     解决方案：按剩余模块重新定位——如果卸载的不是当前模块，保持当前；
      //               否则退到第一个（没有模块时归零）。同时用"按 so 名过滤"而不是
      //               "用旧下标过滤"，避免稀疏数组错位。
      setModules((prev) => {
        const kept = prev.filter((m) => m.so !== so);
        const curSo = prev[active]?.so;
        const newIdx = curSo === so ? 0 : kept.findIndex((m) => m.so === curSo);
        setActive(newIdx < 0 ? 0 : newIdx);
        return kept;
      });
      setSel((prev) => {
        const kept = prev.filter((_, i) => modules[i]?.so !== so);
        return kept;
      });
      log(`已释放 ${so}（约 ${j.freed_estimate_mb ?? "?"} MB），设备端进程不受影响`, "ai");
    } catch (e) {
      log(`释放出错：${String(e)}`, "ai");
    }
  }, [log, modules]);

  /** 按路径加载（原生对话框选择的结果） */
  const buildModule = useCallback(async (path: string): Promise<void> => {
    const name = path.split("/").pop() || path;
    setLoading({ name });
    setLoadError("");
    try {
      const r = await api.load(path);
      if (!r?.module) throw new Error("解析失败：不是可识别的 ELF，或文件不可读");
      await appendModule(r.module.so, path);
    } catch (e) {
      setLoadError(String(e));
      log(`打开失败：${e}`);
    } finally {
      setLoading(null);
    }
  }, [appendModule, log]);

  /** 拖入文件：字节上传 → 后端落盘解析 */
  const uploadFile = useCallback(async (file: File): Promise<void> => {
    setLoading({ name: file.name });
    setLoadError("");
    try {
      const buf = await file.arrayBuffer();
      const r = await api.upload(file.name, buf);
      await appendModule(r.module.so, r.path);
    } catch (e) {
      setLoadError(String(e));
      log(`拖入失败：${e}`);
    } finally {
      setLoading(null);
    }
  }, [appendModule, log]);

  /** 系统文件对话框 → 后端加载 */
  const openSo = useCallback(async () => {
    if (!hasNativeDialog()) {
      setLoadError("当前是浏览器窗口，没有系统文件对话框；请用桌面窗口（python app.py）打开 so。");
      return;
    }
    const path = await pickSoFile();
    if (!path) return;                       // 用户取消
    await buildModule(path);
  }, [buildModule]);

  // 启动：后端若已有会话就重建模块；没有就停在空状态（不再有任何内置示例数据）
  /** 启动时从服务端拉模块列表并补齐。
   *  用 nav_stats 而不是 /api/modules：后者在 WKWebView 里会被缓存成旧空数组。 */
  const bootstrapModules = useCallback(async () => {
    // 优先用服务端**内联**进 HTML 的初始模块（最可靠：
    // WKWebView 里 /api/modules 的响应恒为空，实测没找到根治办法）
    const boot = (window as unknown as {
      __MDA_BOOT__?: { modules?: { so: string; path: string }[] };
    }).__MDA_BOOT__;
    for (const m of boot?.modules ?? []) {
      if (backendMods.current.has(m.so)) continue;
      try {
        await appendModule(m.so, m.path);
      } catch {
        /* 坏文件交给日志 */
      }
    }
    if (boot?.modules?.length) return;

    // 定时问一次"服务端有哪些模块"：nav_stats 不带 so 时返回 serverModules。
    // 这是在 /api/modules 不可用时唯一能拿到列表的通道。
    try {
      const r = await api.navStats("");
      const live = new Set((r?.serverModules ?? []).map((m) => m.so));
      void live;
      for (const m of r?.serverModules ?? []) {
        if (backendMods.current.has(m.so)) continue;
        try {
          await appendModule(m.so, m.path);
        } catch {
          /* 坏文件交给日志 */
        }
      }
    } catch {
      /* 启动探测失败不影响其它功能 */
    }
  }, [appendModule]);

  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    (async () => {
      const h = await api.health();
      const ok = !!h?.ok;
      setApiOk(ok);
      if (h?.version) setVer(h.version);
      if (!ok) {
        setLogs([{ time: now(), text: "后端未连接：请用 python app.py 启动（不要直接开 HTML）" }]);
        return;
      }
      setLogs([{ time: now(), text: `MDA Web 启动 · 后端已连接（${location.host}）` }]);
      await bootstrapModules();
      for (const so of h.modules ?? []) {
        setLoading({ name: so });
        try {
          await appendModule(so, so);
        } catch (e) {
          log(`${so} 恢复失败：${e}`);
        }
      }
      setLoading(null);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 真实 AI 事件（MCP 调用 → 日志/观察/脉冲）
  /** 把界面模块列表和服务端对齐（新增 + 删除）。
   *  抽成独立函数是因为 hello / modules_changed 两条路径都要用；
   *  用 useCallback 保持稳定引用，避免 ws 因它重建。 */
  const syncSeq = useRef(0);

  const doSync = useCallback(async (mySeq: number) => {
    // 直接问 nav_stats（不带 so）：后端会返回 serverModules。
    // 不再先用 /api/modules 判断"要不要查"——那一步在 WKWebView 里恒空，
    // 会让整条链在第一环就断掉（实测：anySo="" 导致 navStats 根本不调用）。
    const nav = await api.navStats("");
    const serverMods = nav?.serverModules ?? [];
    setNavSt(nav ?? null);
    const mods = { modules: serverMods };
    const alive = new Set((mods?.modules ?? []).map((m) => m.so));

    // ① 先把服务端有、本地没有的模块数据全部取好（异步阶段）
    // 注意：mods 来自 nav_stats（更可靠），不是 /api/modules
    const needLoad = (mods?.modules ?? []).filter((m) => !backendMods.current.has(m.so));
    const loaded: ModuleData[] = [];
    for (const m of needLoad) {
      try {
        const fn = await api.functions(m.so, "", 200000);
        if (!fn?.items?.length) continue;
        const fns: Func[] = fn.items.map((it) => ({
          n: it.name, a: it.addr, s: it.size, e: it.is_export ? 1 : 0, r: it.refs ?? 0,
        }));
        loaded.push({
          so: m.so, path: m.path, size: 0, sections: [], funcs: fns,
          disasm: {}, callers: {}, callees: {},
        });
        backendMods.current.add(m.so);
      } catch {
      }
    }

    // ② 只有最新一次同步能落地（旧请求的结果丢弃，防覆盖）
    if (mySeq !== syncSeq.current) return;
    // 注意：**不在这里删模块**。alive 来自 /api/modules，而它在 WKWebView
    // 里恒返回空——拿它做过滤会把刚加进去的模块又删掉（实测就是这个原因
    // 导致 backendMods 有值而 modules 恒空）。
    // 删除统一由 unload / clear_modules 的 modules_changed 处理。
    if (loaded.length) {
      setModules((prev) => {
        const merged = [...prev];
        for (const d of loaded) {
          if (!merged.some((x) => x.so === d.so)) merged.push(d);
        }
        return merged;
      });
      for (const d of loaded) log(`已打开 ${d.so} · ${d.funcs.length} 函数`, "ai");
    }
    if (loaded.length) {
      setActive(0);
      setSel((prev) => {
        const next = prev.slice();
        next[0] = 0;
        return next;
      });
    }
  }, [appendModule, log]);

  /** 串行包装：并发调用会互相覆盖 setModules，必须互斥 */
  /** nav_stats 带回来的服务端模块列表 → 补齐本地。
   *  这是 /api/modules 被 WKWebView 缓存时的可靠替代路径。 */
  const handleServerModules = useCallback(
    (mods: { so: string; path: string }[]) => {
      for (const m of mods) {
        if (backendMods.current.has(m.so)) continue;
        setPendingSo(m.so);
        void (async () => {
          try {
            await appendModule(m.so, m.path);
          } catch {
            /* 坏文件交给日志 */
          }
        })();
      }
    },
    [appendModule]
  );

  const syncModules = useCallback(async () => {
    // 不用锁：用请求号保证只有最新一次的结果落地。
    // 锁在这里反复卡死（ref + useCallback 重建的组合不可靠），
    // 而"旧结果不落地"这个需求用序号就能满足，且不可能卡死。
    syncSeq.current += 1;
    const mySeq = syncSeq.current;
    try {
      await doSync(mySeq);
    } catch (e) {
      log(`同步模块失败：${String(e).slice(0, 80)}`, "ai");
    }
  }, [doSync, log]);

  /** WebSocket 心跳：每 3 秒要一次模块快照。
   *  独立于连接生命周期——连接重建不该让同步停摆（实测 sent 会卡住）。 */
  useEffect(() => {
    const ask = () => {
      const ws = wsRef.current;
      try {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "sync" }));
        }
      } catch {
        /* 断线下一轮再试 */
      }
    };
    ask();
    const id = setInterval(ask, 3000);
    return () => {
      clearInterval(id);
    };
  }, []);

  // 顶栏计数：按当前模块查，事件到来时刷新（左栏与顶栏必须同源）
  useEffect(() => {
    void (async () => {
      const r = await api.navStats(mod?.so ?? "");
      if (r) setNavSt(r);
    })();
  }, [mod?.so, aiTick]);

  // 工具注册表大小（顶栏「工具 N」用）。只取一次，注册表不会在运行中变。
  useEffect(() => {
    void (async () => {
      const r = await api.tools();
      if (r?.tools) setToolN(r.tools.length);
    })();
  }, []);

  /** 轮询服务端模块列表（3 秒）。
   *  为什么必须轮询：模块通常是页面加载**之后**才加进来的，
   *  启动时那一次探测拿不到；而 /api/modules 在 WKWebView 里不可靠。
   *  nav_stats（不带 so）会返回 serverModules，这是验证可用的通道。 */
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      if (stop) return;
      try {
        const r = await api.navStats("");
        for (const m of r?.serverModules ?? []) {
          if (backendMods.current.has(m.so)) continue;
          try {
            await appendModule(m.so, m.path);
          } catch (e) {
          }
        }
      } catch (e) {
      }
    };
    void tick();
    const id = setInterval(tick, 3000);
    return () => {
      stop = true;
      clearInterval(id);
    };
  }, [appendModule]);



  // 事件流连接状态（与 HTTP「后端已连接」是两回事）
  const [wsAlive, setWsAlive] = useState(false);
  const retryDelay = useRef(1000);
  const closed = useRef(false);

  useEffect(() => {
    closed.current = false;
    // (133) 每条连接自己的销毁标记：共享 ref 会被下一次 effect 重置，
    //       导致旧连接的 onclose 误判为"没销毁"并额外建连（StrictMode 下必现）。
    let disposed = false;
    let ws: WebSocket | null = null;

    // 注意：必须读 modulesRef，不能读 modules —— 这个 effect 只在挂载时跑一次，
    // 闭包里的 modules 永远是空数组（AI 定位因此一直失效，实测 hit 恒为 null）。
    const findName = (so: string, addr: number): string => {
      const m = modulesRef.current.find((x) => x.so === so);
      return m?.funcs.find((x) => x.a === addr)?.n ?? hex(addr);
    };
    const toIdx = (so: string, addr: number): { mi: number; i: number } | null => {
      const cur = modulesRef.current;
      const mi = cur.findIndex((m) => m.so === so);
      if (mi < 0) return null;
      const i = cur[mi].funcs.findIndex((x) => x.a === addr);
      return i < 0 ? null : { mi, i };
    };

    /** 给一条连接挂上全部 handler（新建/重连共用同一套） */
    const wire = (sock: WebSocket) => {
    sock.onopen = () => {
      wsRef.current = sock;
      setWsAlive(true);
      retryDelay.current = 1000;
    };
    sock.onclose = () => {
      setWsAlive(false);
      wsRef.current = null;
      // (133) 只看**本连接**是否被销毁，不看共享 ref
      if (disposed) return;
      const delay = retryDelay.current;
      retryDelay.current = Math.min(delay * 2, 10_000);
      window.setTimeout(() => { if (!disposed) connect(); }, delay);
    };
    sock.onerror = () => { setWsAlive(false); };

    sock.onmessage = (ev) => {
      // (1) 第一次修改（2026-11-19）：补 t / ok / result 三件套。
      //    bug 原因：这条 WS 消息类型里没有工具返回值字段，而服务端
      //              api.py 的 _on_ai 已经会推 result/result_truncated/result_bytes。
      //              不补类型就只能 as any 绕过，那等于放弃编译期检查。
      //    解决方案：把控制台需要的字段显式声明在这里，与 server/api.py 的
      //              _broadcast_sync 载荷一一对应。
      let msg: { type?: string; tool?: string; args?: Record<string, unknown>;
                 summary?: string; ms?: number; ts?: string; t?: number;
                 ok?: boolean; result?: string; result_truncated?: boolean;
                 result_bytes?: number;
                 event?: Record<string, unknown> };
      try { msg = JSON.parse(ev.data); } catch { return; }
      // hello：刚连上时服务端把已有模块报一次，必须对齐（之前完全没处理）
      if (msg.type === "hello") {
        void syncModules();
        return;
      }
      // WebSocket 推来的模块快照：这是 WKWebView 里唯一可靠的通道
      // （/api GET 会被复用成旧响应，实测请求到达后端但 body 是旧的）
      if (msg.type === "modules_snapshot") {
        type FnRow = {
          name: string; addr: number; size: number; is_export: boolean; refs: number;
        };
        const details = (msg as {
          details?: { so: string; path: string; functions?: FnRow[] }[];
        }).details ?? [];
        for (const m of details) {
          if (backendMods.current.has(m.so)) continue;
          const rows = m.functions ?? [];
          if (!rows.length) continue;
          // 直接用快照里的函数表建模块 —— 不走 /api/functions。
          // 那条 HTTP GET 在 WKWebView 里会被复用成旧/空响应（实测）。
          const funcs: Func[] = rows.map((it) => ({
            n: it.name, a: it.addr, s: it.size,
            e: it.is_export ? 1 : 0, r: it.refs ?? 0,
          }));
          const data: ModuleData = {
            so: m.so, path: m.path, size: 0, sections: [],
            funcs, disasm: {}, callers: {}, callees: {},
          };
          backendMods.current.add(m.so);
          setModules((prev) =>
            prev.some((x) => x.so === m.so) ? prev : [...prev, data]
          );
          setActive(0);
          setSel((prev) => {
            const next = prev.slice();
            next[0] = funcs.findIndex((x) => x.e) >= 0 ? funcs.findIndex((x) => x.e) : 0;
            return next;
          });
          log(`已打开 ${m.so} · ${funcs.length} 函数（WebSocket 快照）`, "ai");
        }
        return;
      }
      // (3) 第三次修改（2026-11-11）：
      //     bug 原因：服务端在卸载/清空后会广播 modules_changed，
      //               但前端只处理 ai / ui 两类消息——于是 AI 通过 MCP 调
      //               unload_so / clear_modules 之后，界面仍显示旧模块，
      //               点一下就是 404，与「AI 与界面同会话」的目标相悖。
      //     解决方案：收到 modules_changed 就按服务端给的模块列表对齐本地状态。
      if (msg.type === "modules_changed") {
        void syncModules();
        return;
      }
      if (msg.type === "ai" && msg.tool === "load_so") {
        // (2) 第一次修改：AI 通过 MCP 加载 so 后，界面自动出现该模块。
        //     原因：之前只有 AI 自己看得见，人要在窗口里手动再开一次。
        void (async () => {
          try {
          // 直接问 nav_stats（不带 so）：后端会返回 serverModules。
    // 不再先用 /api/modules 判断"要不要查"——那一步在 WKWebView 里恒空，
    // 会让整条链在第一环就断掉（实测：anySo="" 导致 navStats 根本不调用）。
    const nav = await api.navStats("");
    const serverMods = nav?.serverModules ?? [];
    setNavSt(nav ?? null);
    const mods = { modules: serverMods };
          for (const m of mods?.modules ?? []) {
            // backendMods 是 ref，比 state 可靠（state 在闭包里会过期）
            if (backendMods.current.has(m.so)) continue;
            setLoading({ name: m.so });
            try { await appendModule(m.so, m.path); } catch { /* 坏文件交给日志 */ }
          }
          } finally {
            // 无论成功失败都必须收遮罩，否则整屏被盖住
            setLoading(null);
          }
        })();
      }
      if (msg.type === "armed_changed") {
        // 待命状态是持久状态，单独走一条通道给 ArmedBar
        const list = (msg as { items?: unknown }).items;
        window.dispatchEvent(
          new CustomEvent("mda:armed", { detail: Array.isArray(list) ? list : [] })
        );
      }
      if (msg.type === "ai") {
        // 节流：900ms 内只让 tick 前进一次
        if (tickTimer.current == null) {
          tickTimer.current = window.setTimeout(() => {
            tickTimer.current = null;
            setAiTick((v) => v + 1);
          }, 900);
        }
        // 每次工具调用都进实时流。暂停时不再追加（但也不丢已有数据）。
        setToolCounts((prev) => {
          const k = msg.tool ?? "";
          if (!k) return prev;
          return { ...prev, [k]: (prev[k] ?? 0) + 1 };
        });
        setAiEvents((prev) => {
          if (aiPausedRef.current) return prev;
          const next = [
            { tool: msg.tool ?? "", args: msg.args as Record<string, unknown> | undefined,
              summary: msg.summary, ms: msg.ms, ts: msg.ts,
              // (1) 第一次修改（2026-11-19）：透传后端给的输入/输出完整信息，
              // 控制台据此渲染两段。缺这些字段时控制台只能看到参数摘要，
              // 输出侧永远空白——那正是改之前的状态。
              t: typeof msg.t === "number" ? msg.t : undefined,
              ok: msg.ok !== false,
              result: typeof msg.result === "string" ? msg.result : "",
              result_truncated: !!msg.result_truncated,
              result_bytes: typeof msg.result_bytes === "number" ? msg.result_bytes : 0 },
            ...prev,
          ];
          return next.slice(0, 500);   // 上限，避免长时间运行吃内存
        });
        const a = (msg.args ?? {}) as { so_name?: string; name?: string; addr?: number };
        const so = a.so_name ?? a.name ?? "";
        const addr = typeof a.addr === "number" ? a.addr : undefined;
        log(`[AI] ${msg.tool}(${so}${addr !== undefined ? ", " + hex(addr) : ""}) ${msg.summary ?? ""}`, "ai");
        if (so && addr !== undefined) {
          setWatch((w) => [{ so, name: findName(so, addr), addr }, ...w].slice(0, 60));
          const hit = toIdx(so, addr);
          if (hit) {
            setActive(hit.mi);
            setSel((prev) => prev.map((v, k) => (k === hit.mi ? hit.i : v)));
            flashSeq.current += 1;
            setFlash({ i: hit.i, seq: flashSeq.current });
          }
        }
        setBusySo(so || null);
        setTimeout(() => setBusySo((v) => (v === so ? null : v)), 1600);
      } else if (msg.type === "ui" && msg.event?.type === "goto") {
        const e = msg.event as { so_name: string; addr: number };
        const hit = toIdx(e.so_name, e.addr);
        if (hit) {
          setActive(hit.mi);
          setSel((prev) => prev.map((v, k) => (k === hit.mi ? hit.i : v)));
          setRotateIdx(hit.i);
        }
      }
    };
    };  // ← wire() 结束

    /** 建一条新连接；断线后由 onclose 再次调用（指数退避） */
    const connect = () => {
      try {
        const proto = location.protocol === "https:" ? "wss" : "ws";
        ws = new WebSocket(`${proto}://${location.host}/api/events`);
      } catch {
        return;
      }
      wire(ws);
    };
    connect();

    return () => {
      // (133) 标记本连接已销毁（只影响它自己）
      disposed = true;
      closed.current = true;
      wsRef.current = null;
      ws?.close();
    };
    // 只依赖 appendModule：modules 变化不应重建连接（否则消息会丢）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appendModule, syncModules]);

  // 选中变化：取真实 xrefs + 反汇编
  useEffect(() => {
    if (!mod || selected < 0) return;
    let cancelled = false;
    const so = mod.so;
    const addr = mod.funcs[selected].a;
    (async () => {
      const have = backendMods.current.has(so);
      const x = have ? await api.xrefs(so, addr) : null;
      if (cancelled) return;
      const toNum = (h: string) => parseInt(h, 16);
      if (x) setRelations({ ins: x.callers.map(toNum), outs: x.callees.map(toNum) });
      else setRelations(null);
      if (code.open) {
        const d = have ? await api.disasm(so, addr) : null;
        if (cancelled) return;
        if (d) setCode((c) => ({ ...c, rows: d.items, live: true }));
        else setCode((c) => ({ ...c, rows: [], live: false }));
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, selected]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setCode((c) => ({ ...c, open: false })); return; }
      if (e.key === "Enter" && !(e.target instanceof HTMLInputElement)) void openCode();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, selected]);

  const selectFn = (mi: number, i: number) => {
    setSel((prev) => prev.map((v, k) => (k === mi ? i : v)));
    if (mi !== active) setActive(mi);
    setRotateIdx(i);
  };

  const openCode = async () => {
    if (!mod || !f) return;
    setCode({ open: true, rows: [], live: false });
    const d = await api.disasm(mod.so, f.a);
    if (d) {
      setCode({ open: true, rows: d.items, live: true });
      log(`反汇编 ${f.n} · ${d.items.length} 条（后端实时解码）`, "ai");
    } else {
      setCode({ open: true, rows: [], live: false });
      log(`反汇编失败：后端没有返回 ${f.n} 的指令`, "ai");
    }
  };

  const buildXrefs = async () => {
    if (!mod) return;
    log("开始构建引用图（后端真实构建）");
    setProgress({ percent: 5 });
    const t0 = setInterval(() => setProgress((p) => (p ? { percent: Math.min(92, p.percent + 7) } : p)), 260);
    const r = await api.buildXrefs(mod.so);
    clearInterval(t0);
    setProgress({ percent: 100 });
    setTimeout(() => setProgress(null), 700);
    log(r ? "引用图构建完成" : "引用图构建失败", "ai");
  };

  /** 复制 MCP 配置：HTTP 与 stdio 两种都写进同一个 mcpServers，粘过去删掉不用的那条即可 */
  const copyMcpConfig = useCallback(async () => {
    try {
      const cfg = await (await fetch(`${location.origin}/api/mcp-config`)).json();
      const text = JSON.stringify(
        {
          mcpServers: {
            mda: { url: cfg.http_url },
            "mda-stdio": { command: cfg.stdio.command, args: cfg.stdio.args },
          },
        },
        null,
        2
      );
      // 优先级：pywebview 原生剪贴板 > 浏览器 clipboard > execCommand
      // (1) 第一次修改：WKWebView 里前两种都可能失败（用户实测"复制失败"），
      //     所以先走原生 NSPasteboard，后面的只作兜底。
      let ok = false;
      const bridge = (window as unknown as {
        pywebview?: { api?: { copy_text?: (t: string) => Promise<boolean> | boolean } };
      }).pywebview;
      if (bridge?.api?.copy_text) {
        try { ok = !!(await bridge.api.copy_text(text)); } catch { ok = false; }
      }
      if (!ok) {
        try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = false; }
      }
      if (!ok) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand("copy");
        ta.remove();
      }
      log(ok ? "已复制 MCP 配置（含 HTTP 与 stdio 两种写法）" : "复制失败：请检查剪贴板权限", "ai");
    } catch (e) {
      log(`读取 MCP 配置失败：${e}`);
    }
  }, [log]);

  const empty = modules.length === 0;

  return (
    <div
      className="app"
      onDragOver={(e) => { e.preventDefault(); if (!dragging) setDragging(true); }}
      onDragLeave={(e) => {
        // 只有真正离开窗口才收起提示（子元素间移动会连续触发 dragleave）
        if (e.clientX <= 0 || e.clientY <= 0 ||
            e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
          setDragging(false);
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files?.[0];
        if (file) void uploadFile(file);
      }}
    >
      <header className="topbar">
        <div className="brand">
          <span className="mark" />MDA
          <small>{ver ? `${ver} · web` : "web"}</small>
        </div>
        <div className="divider" />
        <div className="so-tabs">
          {modules.map((m, i) => (
            <span
              key={m.so}
              className={"so-tab" + (i === active ? " on" : "") + (busySo === m.so ? " busy" : "")}
            >
              <button className="so-tab-main" onClick={() => setActive(i)}>
                {m.so}<span className="n">{m.funcs.length}</span>
              </button>
              <button
                className="so-tab-x"
                title={`释放 ${m.so}（只清界面与解析结果，不影响设备）`}
                onClick={(e) => {
                  e.stopPropagation();
                  void unloadModule(m.so);
                }}
              >
                ✕
              </button>
            </span>
          ))}
          <button className="so-add" onClick={openSo} title="打开 so">+</button>
        </div>
        <div className="divider" />
        <button className="btn primary" onClick={openSo}>打开 so</button>
        <div className="grow" />
        <input
          className="jump"
          disabled={empty}
          title={empty ? "先打开一个 so 才能跳转" : ""}
          placeholder={empty ? "打开 so 后可跳转地址 / 函数名" : "跳转到地址或函数名…"}
          value={jumpText}
          onChange={(e) => setJumpText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== "Enter" || !mod) return;
            const v = jumpText.trim().toLowerCase();
            if (!v) return;
            const i = mod.funcs.findIndex((fn) => fn.n.toLowerCase().includes(v) || hex(fn.a) === v);
            if (i < 0) { log(`未找到「${jumpText}」`); return; }
            selectFn(active, i);
            setMainView("module");   // 跳转 = 过去看它，不能只改选中
            log(`跳转到 ${mod.funcs[i].n} @ ${hex(mod.funcs[i].a)}`);
          }}
        />
        <button
          className="btn"
          onClick={buildXrefs}
          disabled={empty}
          title={empty ? "先打开一个 so 才能建引用图" : "真实构建引用图（全库扫描入边）"}
        >
          建立引用图
        </button>
        <button className="btn" onClick={() => { themeLocked.current = true; setTheme(theme === "dark" ? "light" : "dark"); }}>
          {theme === "dark" ? "◑ 深色" : "◒ 浅色"}
        </button>
        <div className="divider" />
        <button className="btn" onClick={copyMcpConfig} title="复制 MCP 配置，粘到 AI 客户端的 mcpServers 里">
          复制 MCP 配置
        </button>
        <span className="chip" title={wsAlive ? "事件流正常，界面在实时更新" : "事件流已断开，界面可能停在旧数据；正在自动重连"}>
          <i className={"dot " + (wsAlive ? "ok" : "")} />
          事件流 {wsAlive ? "实时" : "重连中"}
        </span>
        <span className="chip" title="HTTP 接口可用性（与事件流独立）">
          <i className={"dot " + (apiOk ? "ok" : "")} />
          {apiOk ? "接口正常" : "接口断开"}
        </span>
        <span className="chip" id="modcount">模块 {modules.length} / 函数 {mod?.funcs.length ?? 0}</span>
      </header>

      <main className="workspace">
        <div className="side">
          <LeftNav
            so={mod?.so ?? ""}
            activeView={mainView}
            onPick={(v) => setMainView(v as typeof mainView)}
            onServerModules={handleServerModules}
            fnCount={mod?.funcs.length}
            tick={aiTick}
          />
          <LeftPanel
            logs={logs}
            watch={watch}
            onPickWatch={(w) => log(`观察：${w.name} @ ${hex(w.addr)}`)}
          />
        </div>
        <section className={"stage" + (code.open ? " compact" : "")}>
          {/* 主视图切换：实时监控台（AI 在做什么） / 模块视图（so 结构） */}
          <div className="viewtabs">
            {/* 标签顺序与原型一致：实时 / 代码 / 引用 / 图谱 / 时间线 / 工具。
                计数都来自真实数据：引用=xref 边数，函数=真实函数数，
                工具=注册表大小，时间线=事件条数。
                「进程」不再是独立标签——原型把它放在左栏「目标进程」，
                这里同样通过左栏进入（视图仍然存在）。 */}
            <button
              className={"vtab" + (mainView === "monitor" ? " on" : "")}
              onClick={() => setMainView("monitor")}
            >
              <i className={"vdot" + (aiPaused ? "" : " live")} />
              实时
            </button>
            <button
              className={"vtab" + (mainView === "module" ? " on" : "")}
              onClick={() => setMainView("module")}
              disabled={empty}
              title={empty ? "先打开一个 so" : modules[active]?.so ?? ""}
            >
              代码{!empty && mod ? ` ${mod.funcs.length}` : ""}
            </button>
            <button
              className={"vtab" + (mainView === "xref" ? " on" : "")}
              onClick={() => setMainView("xref")}
              disabled={!f}
              title={f ? "谁调用了它 / 它调用了谁" : "先选一个函数"}
            >
              引用{navSt?.refs != null ? ` ${navSt.refs}` : ""}
            </button>
            <button
              className={"vtab" + (mainView === "graph" ? " on" : "")}
              onClick={() => setMainView("graph")}
              disabled={!f}
              title={f ? "调用关系图" : "先选一个函数"}
            >
              图谱
            </button>
            <button
              className={"vtab" + (mainView === "timeline" ? " on" : "")}
              onClick={() => setMainView("timeline")}
            >
              时间线{aiEvents.length ? ` ${aiEvents.length}` : ""}
            </button>
            <button
              className={"vtab" + (mainView === "tools" ? " on" : "")}
              onClick={() => setMainView("tools")}
            >
              工具{toolN != null ? ` ${toolN}` : ""}
            </button>
            {/* (1) 第一次修改（2026-11-19）：控制台作为「工具」右侧的新 tab。
                用户明确要求"右边直接新建一个 tab 就行了，不用弹窗"——
                做成视图而非浮层，可以和反汇编/监控台并排切着用。
                显示真实事件条数（与本视图里能翻到的记录同源）。 */}
            <button
              className={"vtab" + (mainView === "console" ? " on" : "")}
              onClick={() => setMainView("console")}
              title="控制台：看 AI 每次调用的完整输入/输出，也可以手动执行 frida 脚本"
            >
              控制台{aiEvents.length ? ` ${aiEvents.length}` : ""}
            </button>
            <span className="grow" />
            <ArmedBar />
          </div>

          {/* 引用密度：全局背景信息，不属于任何一个视图（原型同位置） */}
          {!empty && mod && (
            <HeatBar so={mod.so} onPickAddr={(a) => jumpToAddr(mod.so, a)} />
          )}

          {/* 「实时」页永远渲染监控台：动态操作不依赖 so 文件。
              没模块时监控台自己引导，而不是整页换成空状态——
              否则 AI 在 hook/操作设备时，用户看到的是死页面。 */}
          {mainView === "monitor" && (
            <RealtimeMonitor
              mods={modules.map((m) => ({ so: m.so, n: m.funcs.length }))}
              hooksProp={navSt?.hooks ?? null}
              events={aiEvents}
              paused={aiPaused}
              onTogglePause={() =>
                setAiPaused((v) => {
                  aiPausedRef.current = !v;   // (131) 同步给 WS 闭包
                  return !v;
                })
              }
              onClear={() => setAiEvents([])}
            />
          )}

          {mainView === "xref" && f && mod && (
            <XrefView
              so={mod.so}
              addr={f.a}
              fnName={f.n}
              onJump={(a) => jumpToAddr(mod.so, a)}
            />
          )}

          {mainView === "graph" && f && mod && (
            <GraphView
              so={mod.so}
              addr={f.a}
              fnName={f.n}
              onJump={(a) => jumpToAddr(mod.so, a)}
            />
          )}

          {mainView === "strings" && !mod && !loading && (
            <NeedSoView what="字符串表" why="字符串来自 ELF 的 .rodata 段，必须先载入一个 so" />
          )}

          {mainView === "strings" && mod && (
            <FlatTable so={mod.so} kind="strings" />
          )}

          {mainView === "sections" && !mod && !loading && (
            <NeedSoView what="段 / 节表" why="段表是 ELF 文件结构的一部分，必须先载入一个 so" />
          )}

          {mainView === "sections" && mod && (
            <FlatTable so={mod.so} kind="sections" />
          )}

          {mainView === "timeline" && (
            <TimelineView events={aiEvents} />
          )}

          {mainView === "tools" && (
            <ToolsView counts={toolCounts} />
          )}

          {/* (1) 第一次修改（2026-11-19）：控制台视图（与工具同级，不是弹窗）。
              为什么无条件渲染而不加 empty 判断：控制台看的是 AI 调了哪些工具、
              手动跑 frida 的结果，这些都与是否加载了 so 无关——
              加上 empty 守卫会退化成"没 so 就白屏"（R83 那种坑）。 */}
          <ConsoleOverlay open={mainView === "console"} />

          {mainView === "processes" && (
            <ProcessesView />
          )}

          {mainView.startsWith("dyn:") && (
            <DynStateView kind={mainView.slice(4) as DynKind} />
          )}

          {mainView === "module" && !empty && mod && (
            <>
            <div className="stage-canvas">
              {/* 反汇编列表：热力条下面的主体（原型代码页） */}
              <div className="code-listing" ref={codeListRef}>
                {codeWindow.map((fn) => (
                  <div key={fn.a}>
                    <div
                      className={"fnrow" + (f && f.a === fn.a ? " sel" : "")}
                      data-i={mod.funcs.findIndex((x) => x.a === fn.a)}
                      onClick={() => {
                        // (132) 必须先选中：右边检视器/引用/图谱都跟着 f 走，
                        //       只 toggle 不 select 会让 f 永远停在第一个函数。
                        const idx = mod.funcs.findIndex((x) => x.a === fn.a);
                        if (idx >= 0) {
                          setActive(modules.findIndex((m) => m.so === mod.so));
                          selectFn(modules.findIndex((m) => m.so === mod.so), idx);
                        }
                        toggleFn(mod.so, fn.a);
                      }}
                    >
                      <span className="fn-t">
                        {expanded[fn.a] ? "▾" : "▸"}
                      </span>
                      <span className="fn-n">{fn.n}</span>
                      {fn.e && <span className="fn-tag">导出</span>}
                      <span className="fn-a">0x{fn.a.toString(16)}</span>
                    </div>
                    {expanded[fn.a] && (
                      <div className="ins-list">
                        {(expanded[fn.a] ?? []).map((ins) => (
                          <div className="ins-row" key={ins.addr}>
                            <span className="ins-a">
                              0x{ins.addr.toString(16)}
                            </span>
                            <span className="ins-b">{ins.bytes}</span>
                            {/* 指令拆成 助记符 + 操作数 分别着色，
                                跳转/返回再单独标色（原型是这么分的） */}
                            <span
                              className={
                                "ins-x" +
                                (ins.is_call ? " call" : "") +
                                (ins.is_ret ? " ret" : "")
                              }
                            >
                              <b className="ins-mn">
                                {ins.text.includes(" ")
                                  ? ins.text.slice(0, ins.text.indexOf(" "))
                                  : ins.text}
                              </b>
                              {ins.text.includes(" ") && (
                                <span className="ins-op">
                                  {ins.text.slice(ins.text.indexOf(" ") + 1)}
                                </span>
                              )}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                <div className="fn-more">
                  … 其余 {Math.max(0, mod.funcs.length - 60)} 个函数
                </div>
              </div>
            </div>
            </>
          )}

          {mainView === "module" && empty && !loading && (
            <div className="empty-stage">
              <div className="empty-mark"><span className="mark" /></div>
              <div className="empty-title">打开一个 so 开始分析</div>
              <div className="empty-sub">多 so 同会话 · 跨 so 调用链 · ELF 32/64 · 节表损坏也能读</div>
              <button className="btn primary" onClick={openSo}>打开 so 文件</button>
              <div className="empty-hint">
                {hasNativeDialog() ? "会弹出 macOS 文件选择框" : "浏览器模式没有文件对话框，请用 python app.py 打开桌面窗口"}
              </div>
              {loadError && <div className="empty-err">{loadError}</div>}
            </div>
          )}

          {loading && (
            <div className="loading-layer">
              <div className="spinner" />
              <div className="loading-text">正在解析 {loading.name}…</div>
              <div className="loading-sub">读取段表 → 发现函数 → 建索引</div>
            </div>
          )}


          <CodeOverlay
            open={code.open}
            fnName={f?.n ?? "—"}
            fnAddr={f?.a ?? 0}
            size={f?.s ?? 0}
            refs={f?.r ?? 0}
            isExport={!!f?.e}
            rows={code.rows}
            onClose={() => setCode((c) => ({ ...c, open: false }))}
          />
        </section>
        {/* 右栏：实时页自带「事件详情」，不需要再挂一个函数列表（原型也是这样） */}
        {/* 右侧：函数检视器（原型 aside.insp）。实时页自带事件详情，不显示。 */}
        {mainView !== "monitor" && (
          <Inspector
            mods={modules}
            current={mod && f ? { so: mod.so, addr: f.a, name: f.n } : null}
            onPickFn={(soName, addr2) => jumpToAddr(soName, addr2)}
          />
        )}
      </main>

      {dragging && (
        <div className="drop-overlay">
          <div className="drop-box">
            <span className="drop-icon" />
            <span>松开即加载 .so</span>
            <span className="drop-sub">也可以拖多个文件，逐个加入会话</span>
          </div>
        </div>
      )}

      <footer className="statusbar">
        <span>so <span className="k">{mod?.so ?? "未加载"}</span></span>
        <span>addr <span className="k">{f ? hex(f.a) : "—"}</span></span>
        <span>指令 <span className="k">{f ? f.s + "B" : "—"}</span></span>
        <span>模块 <span className="k">{modules.length}</span></span>
        <span className="r"><span>{code.live ? "后端实时" : "静态数据"}</span><span>React + TS</span></span>
      </footer>
    </div>
  );
}

function API_LABEL(): string {
  return location.host || "127.0.0.1:8766";
}
