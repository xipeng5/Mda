import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { hex, type ModuleData, type Func } from "./lib/data";
import {
  API_BASE,
  CLIENT_HEADERS,
  api,
  apiWsUrl,
  copyText,
  hasNativeDialog,
  pickSoFile,
  type ApiDynState,
  type ApiNavStats,
  type ApiSection,
  type ApiString,
  type ApiTool,
} from "./lib/api";
import { classifyTool, LAYER_NAMES, TOOL_COLOR, TOOL_LABEL, toolToLayer } from "./lib/toolMeta";
import { LeftNav } from "./components/LeftNav";
import { LeftPanel } from "./components/LeftPanel";
import { HeatBar } from "./components/HeatBar";
import { FlatTable } from "./components/FlatTable";
import { Inspector } from "./components/Inspector";
import { DynStateView, NeedSoView, type DynKind } from "./components/DynStateView";
import { RealtimeMonitor, type AiEvent } from "./components/RealtimeMonitor";
import { ToolsView } from "./components/ToolsView";
import { ProcessesView } from "./components/ProcessesView";
import { XrefView } from "./components/XrefView";
import { GraphView } from "./components/GraphView";
import { TimelineView } from "./components/TimelineView";
import { CodeStage } from "./components/CodeStage";
import { BottomDrawer } from "./components/BottomDrawer";
import { CommandPalette, type PaletteAction } from "./components/CommandPalette";
import { SettingsView } from "./components/SettingsView";
import type { OpsSignal } from "./components/DeviceOpsDeck";
import type { Theme } from "./lib/sphere";

type LogItem = { time: string; text: string; kind?: string };
type WatchItem = { so: string; name: string; addr: number };
type HistEntry = { so: string; addr: number };

const now = () => new Date().toLocaleTimeString("zh-CN", { hour12: false });

export default function App() {
  const [modules, setModules] = useState<ModuleData[]>([]);
  const [active, setActive] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const [selInsnAddr, setSelInsnAddr] = useState<number | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [watch, setWatch] = useState<WatchItem[]>([]);
  const [aiEvents, setAiEvents] = useState<AiEvent[]>([]);
  const [aiTick, setAiTick] = useState(0);
  const tickTimer = useRef<number | null>(null);
  const [navSt, setNavSt] = useState<ApiNavStats | null>(null);
  const [dynState, setDynState] = useState<ApiDynState | null>(null);
  const [toolsList, setToolsList] = useState<ApiTool[]>([]);
  const [aiPaused, setAiPaused] = useState(false);
  const aiPausedRef = useRef(false);
  const [followAi, setFollowAi] = useState(true);
  const followAiRef = useRef(true);
  followAiRef.current = followAi;

  const [toolCounts, setToolCounts] = useState<Record<string, number>>({});
  // 主视图：monitor(工具流) | tools(137工具库) | split(并排伪代码 F5) | disasm(反汇编 1) | cfg(Space) | graph(4)
  //         以及完整保留原有次级视图：xref | timeline | processes | strings | sections | dyn:*
  const [mainView, setMainView] = useState<string>("monitor");
  const mainViewRef = useRef<string>("monitor");
  mainViewRef.current = mainView;
  const [preselectTool, setPreselectTool] = useState<string | null>(null);

  // 主题（支持 localStorage 记住用户手动偏好，默认浅色与原版一致）
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem("mda_theme");
      if (saved === "dark" || saved === "light") return saved;
    } catch { /* ignore */ }
    return "light";
  });
  const themeLocked = useRef(false);

  // 可拖拽三栏与底部抽屉布局
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState<"plugins" | "terminal">("plugins");
  const [leftW, setLeftW] = useState(248);
  const [rightW, setRightW] = useState(288);
  const [drawerH, setDrawerH] = useState(206);
  const [leftTab, setLeftTab] = useState<"funcs" | "strings" | "sections" | "nav">("funcs");
  const [leftFilter, setLeftFilter] = useState("");
  const [leftStrings, setLeftStrings] = useState<ApiString[]>([]);
  const [leftSections, setLeftSections] = useState<ApiSection[]>([]);

  // 导航历史栈（Alt+← / Alt+→）
  const [history, setHistory] = useState<HistEntry[]>([]);
  const [histIdx, setHistIdx] = useState(-1);

  // 原地注释 / 重命名 / 本地断点标记
  const [commentsBySo, setCommentsBySo] = useState<Record<string, Record<string, string>>>({});
  const [bpMarks, setBpMarks] = useState<Set<string>>(new Set());
  const [inlineDialog, setInlineDialog] = useState<{ kind: "rename" | "comment"; value: string } | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toast, setToast] = useState("");
  const toastTimer = useRef<number | null>(null);

  // 全局 AI 操控动效状态（顶栏流光条 + 热力条雷达扫光 + 右下角悬浮 HUD + 设备动效信号）
  const [opsSignal, setOpsSignal] = useState<OpsSignal | null>(null);
  const opsSeqRef = useRef(0);
  const [beamCol, setBeamCol] = useState<string | null>(null);
  const [heatSweepKey, setHeatSweepKey] = useState(0);
  const [stageAura, setStageAura] = useState<"" | "aura-freeze" | "aura-hit" | "aura-hook">("");
  const [hud, setHud] = useState<{ tool: string; cat: string; col: string; sub: string; layer: string } | null>(null);
  const [aiHit, setAiHit] = useState<{ seq: number; addr: number | null }>({ seq: 0, addr: null });
  const beamTimerRef = useRef<number | null>(null);
  const hudTimerRef = useRef<number | null>(null);

  const [liveScripts, setLiveScripts] = useState(0);
  const [armedBpCount, setArmedBpCount] = useState(0);
  const aiEventSeq = useRef(0);
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [ver, setVer] = useState("");
  const [busySo, setBusySo] = useState<string | null>(null);
  const [loading, setLoading] = useState<{ name: string } | null>(null);
  const [loadError, setLoadError] = useState("");
  const [dragging, setDragging] = useState(false);
  const backendMods = useRef<Set<string>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const modulesRef = useRef<ModuleData[]>([]);
  const modRef = useRef<ModuleData | undefined>(undefined);
  const activeRef = useRef(0);
  const selRef = useRef<number[]>([]);
  const booted = useRef(false);
  const [wsAlive, setWsAlive] = useState(false);
  const retryDelay = useRef(1000);
  const syncSeq = useRef(0);

  const mod = modules[active];
  const selected = sel[active] ?? -1;
  const f = mod && selected >= 0 ? mod.funcs[selected] : null;
  modulesRef.current = modules;
  modRef.current = mod;
  activeRef.current = active;
  selRef.current = sel;

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current != null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(""), 2200);
  }, []);

  const log = useCallback((text: string, kind?: string) => {
    setLogs((prev) => [...prev.slice(-300), { time: now(), text, kind }]);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("mda_theme", theme); } catch { /* ignore */ }
  }, [theme]);

  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const onChange = (e: MediaQueryListEvent) => {
      if (themeLocked.current) setTheme(e.matches ? "light" : "dark");
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  /** 触发全局 AI 操控动效（仅由真实后端 WebSocket AI 工具事件驱动） */
  const fireGlobalFx = useCallback((tool: string, summary: string, ms?: number) => {
    const cat = classifyTool(tool);
    const col = /freeze/.test(tool) ? "#38bdf8" : (TOOL_COLOR[cat] || "#4c8dff");
    const layerIdx = toolToLayer(tool, cat);
    const seq = ++opsSeqRef.current;

    setOpsSignal({ seq, tool, ms, summary });
    setBeamCol(col);
    setHeatSweepKey((k) => k + 1);
    if (beamTimerRef.current != null) window.clearTimeout(beamTimerRef.current);
    beamTimerRef.current = window.setTimeout(() => setBeamCol(null), 1550);

    if (/freeze/.test(tool)) setStageAura("aura-freeze");
    else if (cat === "bp") setStageAura("aura-hit");
    else if (cat === "behavior") setStageAura("aura-hook");
    else setStageAura("");
    window.setTimeout(() => setStageAura(""), 900);

    if (mainViewRef.current !== "monitor") {
      setHud({ tool, cat, col, sub: summary, layer: LAYER_NAMES[layerIdx].replace(/ 层$/, "") });
      if (hudTimerRef.current != null) window.clearTimeout(hudTimerRef.current);
      hudTimerRef.current = window.setTimeout(() => setHud(null), 2600);
    } else {
      setHud(null);
    }
  }, []);

  /** 跳转到指定 so + 地址，支持历史栈入栈与自动切代码视图 */
  const jumpToAddr = useCallback(
    (soName: string, a: number, opts?: { pushHist?: boolean; targetView?: string }) => {
      const curMods = modulesRef.current;
      const mi = curMods.findIndex((m) => m.so === soName);
      if (mi < 0) {
        showToast(`未加载模块 ${soName}`);
        return;
      }
      const funcs = curMods[mi].funcs;
      if (!funcs.length) return;
      let i = funcs.findIndex((x) => x.a === a);
      if (i < 0) i = funcs.findIndex((x) => a >= x.a && a < x.a + Math.max(4, x.s));
      if (i < 0) {
        // 落到最近函数（热力条点击保证不报失败）
        let best = 0;
        let bestDist = Infinity;
        for (let k = 0; k < funcs.length; k++) {
          const d = Math.abs(funcs[k].a - a);
          if (d < bestDist) { bestDist = d; best = k; }
        }
        i = best;
      }
      const targetFn = funcs[i];
      activeRef.current = mi;
      setActive(mi);
      setSel((prev) => {
        const next = prev.slice();
        next[mi] = i;
        selRef.current = next;
        return next;
      });
      setSelInsnAddr(a >= targetFn.a && a < targetFn.a + Math.max(4, targetFn.s) ? a : targetFn.a);

      if (opts?.pushHist !== false) {
        setHistory((prev) => {
          const sliced = prev.slice(0, histIdx + 1);
          const last = sliced[sliced.length - 1];
          if (last && last.so === soName && last.addr === targetFn.a) return sliced;
          const next = [...sliced, { so: soName, addr: targetFn.a }].slice(-80);
          setHistIdx(next.length - 1);
          return next;
        });
      }

      if (opts?.targetView) {
        setMainView(opts.targetView);
      } else if (mainViewRef.current === "monitor" || mainViewRef.current === "tools") {
        setMainView("split");
      }
    },
    [histIdx, showToast]
  );

  const goBack = useCallback(() => {
    if (histIdx <= 0) return;
    const nextIdx = histIdx - 1;
    const h = history[nextIdx];
    setHistIdx(nextIdx);
    if (h) jumpToAddr(h.so, h.addr, { pushHist: false });
  }, [histIdx, history, jumpToAddr]);

  const goFwd = useCallback(() => {
    if (histIdx >= history.length - 1) return;
    const nextIdx = histIdx + 1;
    const h = history[nextIdx];
    setHistIdx(nextIdx);
    if (h) jumpToAddr(h.so, h.addr, { pushHist: false });
  }, [histIdx, history, jumpToAddr]);

  /** 同步对齐服务端模块集合（支持新增与移除已卸载模块） */
  const reconcileModules = useCallback(
    (aliveSet: Set<string> | null, added: ModuleData[], focusNew = false) => {
      const curMods = modulesRef.current;
      const curSel = selRef.current;
      const curSo = curMods[activeRef.current]?.so;

      let changed = false;
      const nextMods: ModuleData[] = [];
      const nextSel: number[] = [];

      curMods.forEach((m, i) => {
        if (aliveSet && !aliveSet.has(m.so)) {
          changed = true;
          backendMods.current.delete(m.so);
        } else {
          nextMods.push(m);
          nextSel.push(curSel[i] ?? 0);
        }
      });

      let firstNewIdx = -1;
      for (const d of added) {
        if (nextMods.some((x) => x.so === d.so)) continue;
        if (firstNewIdx < 0) firstNewIdx = nextMods.length;
        const firstExp = d.funcs.findIndex((x) => x.e);
        nextMods.push(d);
        nextSel.push(firstExp >= 0 ? firstExp : 0);
        backendMods.current.add(d.so);
        changed = true;
      }

      if (!changed) return;

      let nextActive = 0;
      if (focusNew && firstNewIdx >= 0) nextActive = firstNewIdx;
      else if (curSo) {
        const keptIdx = nextMods.findIndex((m) => m.so === curSo);
        nextActive = keptIdx >= 0 ? keptIdx : 0;
      }

      modulesRef.current = nextMods;
      selRef.current = nextSel;
      activeRef.current = nextActive;
      setModules(nextMods);
      setSel(nextSel);
      setActive(nextActive);
    },
    []
  );

  const appendModule = useCallback(
    async (so: string, path: string) => {
      const fn = await api.functions(so, "", 200000);
      if (!fn) throw new Error("后端没有返回函数表");
      const funcs: Func[] = fn.items.map((it) => ({
        n: it.name,
        a: it.addr,
        s: it.size,
        e: it.is_export ? 1 : 0,
        r: it.refs ?? 0,
      }));
      if (!funcs.length) throw new Error("这个 so 里没有解析出任何函数");
      const data: ModuleData = { so, path, size: 0, sections: [], funcs, disasm: {}, callers: {}, callees: {} };
      backendMods.current.add(so);
      const cur = modulesRef.current;
      const exists = cur.findIndex((m) => m.so === so);
      if (exists >= 0) {
        activeRef.current = exists;
        setActive(exists);
        return;
      }
      reconcileModules(null, [data], true);
      log(`已打开 ${so} · ${funcs.length} 函数（后端实时解析）`, "ai");
    },
    [log, reconcileModules]
  );

  const unloadModule = useCallback(
    async (so: string) => {
      try {
        const r = await fetch(`${API_BASE}/api/unload`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...CLIENT_HEADERS },
          body: JSON.stringify({ so }),
        });
        const j = await r.json();
        if (!r.ok || j.ok === false) {
          showToast(`释放失败：${j.error || r.statusText}`);
          return;
        }
        backendMods.current.delete(so);
        const aliveSet = new Set(modulesRef.current.map((m) => m.so).filter((n) => n !== so));
        reconcileModules(aliveSet, [], false);
        showToast(`已释放 ${so}（约 ${j.freed_estimate_mb ?? "?"} MB）`);
      } catch (e) {
        showToast(`释放出错：${String(e)}`);
      }
    },
    [reconcileModules, showToast]
  );

  const buildModule = useCallback(
    async (path: string) => {
      const name = path.split("/").pop() || path;
      setLoading({ name });
      setLoadError("");
      try {
        const r = await api.load(path);
        if (!r?.module) throw new Error("解析失败：不是可识别的 ELF，或文件不可读");
        await appendModule(r.module.so, path);
        setMainView("split");
      } catch (e) {
        setLoadError(String(e));
        log(`打开失败：${e}`);
      } finally {
        setLoading(null);
      }
    },
    [appendModule, log]
  );

  const uploadFile = useCallback(
    async (file: File) => {
      setLoading({ name: file.name });
      setLoadError("");
      try {
        const buf = await file.arrayBuffer();
        const r = await api.upload(file.name, buf);
        await appendModule(r.module.so, r.path);
        setMainView("split");
      } catch (e) {
        setLoadError(String(e));
        log(`拖入失败：${e}`);
      } finally {
        setLoading(null);
      }
    },
    [appendModule, log]
  );

  const openSo = useCallback(async () => {
    if (!hasNativeDialog()) {
      showToast("浏览器模式可直接拖入 .so 文件，或用 python app.py 桌面窗口打开文件选择框");
      return;
    }
    const path = await pickSoFile();
    if (!path) return;
    await buildModule(path);
  }, [buildModule, showToast]);

  const bootstrapModules = useCallback(async () => {
    const boot = (window as unknown as {
      __MDA_BOOT__?: { modules?: { so: string; path: string }[] };
    }).__MDA_BOOT__;
    for (const m of boot?.modules ?? []) {
      if (backendMods.current.has(m.so)) continue;
      try { await appendModule(m.so, m.path); } catch { /* ignore */ }
    }
    if (boot?.modules?.length) return;
    try {
      const r = await api.navStats("");
      for (const m of r?.serverModules ?? []) {
        if (backendMods.current.has(m.so)) continue;
        try { await appendModule(m.so, m.path); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  }, [appendModule]);

  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    void (async () => {
      const h = await api.health();
      const ok = !!h?.ok;
      setApiOk(ok);
      if (h?.version) setVer(h.version);
      if (!ok) {
        setLogs([{ time: now(), text: "后端未连接：请用 python app.py 或 python -m server.api 启动" }]);
        return;
      }
      setLogs([{ time: now(), text: `MDA Studio v2 已连接后端（${location.host}）` }]);
      await bootstrapModules();
      for (const so of h.modules ?? []) {
        if (backendMods.current.has(so)) continue;
        setLoading({ name: so });
        try { await appendModule(so, so); } catch (e) { log(`${so} 恢复失败：${e}`); }
      }
      setLoading(null);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const doSync = useCallback(
    async (mySeq: number) => {
      const nav = await api.navStats("");
      if (!nav) return;
      const serverMods = nav.serverModules ?? [];
      setNavSt(nav);
      const alive = new Set(serverMods.map((m) => m.so));
      const needLoad = serverMods.filter((m) => !backendMods.current.has(m.so));
      const loaded: ModuleData[] = [];
      for (const m of needLoad) {
        try {
          const fn = await api.functions(m.so, "", 200000);
          if (!fn?.items?.length) continue;
          const fns: Func[] = fn.items.map((it) => ({
            n: it.name, a: it.addr, s: it.size, e: it.is_export ? 1 : 0, r: it.refs ?? 0,
          }));
          loaded.push({ so: m.so, path: m.path, size: 0, sections: [], funcs: fns, disasm: {}, callers: {}, callees: {} });
        } catch { /* ignore */ }
      }
      if (mySeq !== syncSeq.current) return;
      const wasEmpty = modulesRef.current.length === 0;
      reconcileModules(Array.isArray(nav.serverModules) ? alive : null, loaded, wasEmpty);
    },
    [reconcileModules]
  );

  const syncModules = useCallback(async () => {
    syncSeq.current += 1;
    const mySeq = syncSeq.current;
    try { await doSync(mySeq); } catch { /* ignore */ }
  }, [doSync]);

  const handleServerModules = useCallback(
    (mods: { so: string; path: string }[]) => {
      for (const m of mods) {
        if (backendMods.current.has(m.so)) continue;
        void appendModule(m.so, m.path).catch(() => {});
      }
    },
    [appendModule]
  );

  // 拉取 137 个真实工具清单
  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await api.tools();
      if (alive && r?.tools) setToolsList(r.tools);
    })();
    return () => { alive = false; };
  }, []);

  // 拉取导航统计 + 动态状态 + 待命断点计数
  useEffect(() => {
    let alive = true;
    void (async () => {
      const [ns, ds, arm] = await Promise.all([
        api.navStats(mod?.so ?? ""),
        api.dynState(),
        api.armed(),
      ]);
      if (!alive) return;
      if (ns) setNavSt(ns);
      if (ds) setDynState(ds);
      if (arm) setArmedBpCount(arm.count ?? 0);
    })();
    return () => { alive = false; };
  }, [mod?.so, aiTick]);

  // 切换模块时加载真实注释表 + 左栏字符串/段节
  useEffect(() => {
    if (!mod) return;
    let alive = true;
    void (async () => {
      const r = await api.comments(mod.so);
      if (alive && r?.items) {
        setCommentsBySo((prev) => ({ ...prev, [mod.so]: r.items }));
      }
    })();
    return () => { alive = false; };
  }, [mod?.so]);

  useEffect(() => {
    if (!mod || (leftTab !== "strings" && leftTab !== "sections")) return;
    let alive = true;
    void (async () => {
      if (leftTab === "strings") {
        const r = await api.strings(mod.so, leftFilter);
        if (alive && r?.items) setLeftStrings(r.items);
      } else {
        const r = await api.sections(mod.so);
        if (alive && r?.items) setLeftSections(r.items);
      }
    })();
    return () => { alive = false; };
  }, [mod?.so, leftTab, leftFilter]);

  // WebSocket 实时事件流 + 3s 模块对齐心跳
  useEffect(() => {
    const id = window.setInterval(() => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify({ type: "sync" })); } catch { /* ignore */ }
      }
    }, 3000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      if (stop) return;
      const r = await api.navStats("");
      if (stop || !r) return;
      const list = r.serverModules ?? [];
      if (Array.isArray(r.serverModules)) {
        reconcileModules(new Set(list.map((m) => m.so)), [], false);
      }
      for (const m of list) {
        if (stop || backendMods.current.has(m.so)) continue;
        try { await appendModule(m.so, m.path); } catch { /* ignore */ }
      }
    };
    const id = window.setInterval(() => void tick(), 3500);
    return () => { stop = true; window.clearInterval(id); };
  }, [appendModule, reconcileModules]);

  useEffect(() => {
    let disposed = false;
    let ws: WebSocket | null = null;
    let retryTimer: number | null = null;

    const connect = () => {
      try { ws = new WebSocket(apiWsUrl("/api/events")); } catch { return; }
      ws.onopen = () => {
        wsRef.current = ws;
        setWsAlive(true);
        retryDelay.current = 1000;
      };
      ws.onclose = () => {
        setWsAlive(false);
        wsRef.current = null;
        if (disposed) return;
        const delay = retryDelay.current;
        retryDelay.current = Math.min(delay * 2, 10_000);
        retryTimer = window.setTimeout(() => { if (!disposed) connect(); }, delay);
      };
      ws.onerror = () => setWsAlive(false);
      ws.onmessage = (ev) => {
        let msg: {
          type?: string;
          tool?: string;
          args?: Record<string, unknown>;
          summary?: string;
          ms?: number;
          ts?: string;
          t?: number;
          ok?: boolean;
          result?: string;
          result_truncated?: boolean;
          result_bytes?: number;
          items?: unknown;
          details?: { so: string; path: string; functions?: { name: string; addr: number; size: number; is_export: boolean; refs: number }[] }[];
          event?: Record<string, unknown>;
        };
        try { msg = JSON.parse(ev.data); } catch { return; }

        if (msg.type === "hello" || msg.type === "modules_changed") {
          void syncModules();
          return;
        }
        if (msg.type === "modules_snapshot") {
          const details = msg.details ?? [];
          const serverSet = new Set(details.map((m) => m.so));
          const added: ModuleData[] = [];
          for (const m of details) {
            if (backendMods.current.has(m.so) || !m.functions?.length) continue;
            added.push({
              so: m.so,
              path: m.path,
              size: 0,
              sections: [],
              funcs: m.functions.map((it) => ({
                n: it.name, a: it.addr, s: it.size, e: it.is_export ? 1 : 0, r: it.refs ?? 0,
              })),
              disasm: {}, callers: {}, callees: {},
            });
          }
          reconcileModules(serverSet, added, modulesRef.current.length === 0);
          return;
        }
        if (msg.type === "armed_changed") {
          const list = Array.isArray(msg.items) ? msg.items : [];
          setArmedBpCount(list.length);
          window.dispatchEvent(new CustomEvent("mda:armed", { detail: list }));
          return;
        }
        if (msg.type === "ai") {
          if (msg.tool === "load_so") void syncModules();
          if (tickTimer.current == null) {
            tickTimer.current = window.setTimeout(() => {
              tickTimer.current = null;
              setAiTick((v) => v + 1);
            }, 900);
          }
          const toolName = msg.tool ?? "";
          if (toolName) {
            setToolCounts((prev) => ({ ...prev, [toolName]: (prev[toolName] ?? 0) + 1 }));
          }
          const newEv: AiEvent = {
            id: ++aiEventSeq.current,
            tool: toolName,
            args: msg.args,
            summary: msg.summary,
            ms: msg.ms,
            ts: msg.ts || now(),
            t: typeof msg.t === "number" ? msg.t : undefined,
            ok: msg.ok !== false,
            result: typeof msg.result === "string" ? msg.result : "",
            result_truncated: !!msg.result_truncated,
            result_bytes: typeof msg.result_bytes === "number" ? msg.result_bytes : 0,
          };
          setAiEvents((prev) => (aiPausedRef.current ? prev : [newEv, ...prev].slice(0, 500)));

          // 驱动真实 AI 操控设备动画特效
          fireGlobalFx(toolName, msg.summary || toolName, msg.ms);

          const a = (msg.args ?? {}) as { so_name?: string; name?: string; addr?: number };
          const so = a.so_name ?? a.name ?? "";
          const addr = typeof a.addr === "number" ? a.addr : undefined;
          log(`[AI] ${toolName}(${so}${addr !== undefined ? ", " + hex(addr) : ""}) ${msg.summary ?? ""}`, "ai");
          if (so && addr !== undefined) {
            const curMod = modulesRef.current.find((x) => x.so === so);
            const fnNm = curMod?.funcs.find((x) => x.a === addr)?.n ?? hex(addr);
            setWatch((w) => [{ so, name: fnNm, addr }, ...w].slice(0, 60));
            if (followAiRef.current && mainViewRef.current !== "monitor" && mainViewRef.current !== "tools") {
              jumpToAddr(so, addr, { pushHist: false });
            }
            setAiHit((prev) => ({ seq: prev.seq + 1, addr }));
          }
          if (so) {
            setBusySo(so);
            window.setTimeout(() => setBusySo((v) => (v === so ? null : v)), 1500);
          }
        } else if (msg.type === "ui" && msg.event?.type === "goto") {
          const e = msg.event as { so_name: string; addr: number };
          jumpToAddr(e.so_name, e.addr);
        }
      };
    };

    connect();
    return () => {
      disposed = true;
      if (retryTimer != null) window.clearTimeout(retryTimer);
      if (tickTimer.current != null) window.clearTimeout(tickTimer.current);
      wsRef.current = null;
      ws?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appendModule, syncModules, reconcileModules, fireGlobalFx]);

  const buildXrefs = useCallback(async () => {
    if (!mod) return;
    showToast(`正在为 ${mod.so} 构建真实交叉引用图…`);
    const r = await api.buildXrefs(mod.so);
    if (r?.ok) {
      setAiTick((v) => v + 1);
      showToast(`${mod.so} 交叉引用图构建完成`);
    } else {
      showToast("引用图构建失败");
    }
  }, [mod, showToast]);

  const copyMcpConfig = useCallback(async () => {
    try {
      const cfg = await (await fetch(`${API_BASE}/api/mcp-config`)).json();
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
      const ok = await copyText(text);
      showToast(ok ? "已复制 MCP 配置（HTTP + stdio）" : "复制失败：请检查剪贴板权限");
    } catch (e) {
      showToast(`读取 MCP 配置失败：${e}`);
    }
  }, [showToast]);

  /** 提交原地重命名或注释到真实后端 */
  const submitInlineDialog = useCallback(async () => {
    if (!inlineDialog || !mod || !f) {
      setInlineDialog(null);
      return;
    }
    const val = inlineDialog.value.trim();
    if (inlineDialog.kind === "rename") {
      if (!val) { setInlineDialog(null); return; }
      const r = await api.renameFn(mod.so, f.a, val);
      if (r?.ok) {
        setModules((prev) =>
          prev.map((m) =>
            m.so !== mod.so
              ? m
              : { ...m, funcs: m.funcs.map((fn) => (fn.a === f.a ? { ...fn, n: val } : fn)) }
          )
        );
        showToast(`已重命名为 ${val}`);
      } else {
        showToast("重命名失败");
      }
    } else {
      const targetAddr = selInsnAddr ?? f.a;
      const r = await api.setComment(mod.so, targetAddr, val);
      if (r?.ok) {
        setCommentsBySo((prev) => {
          const cur = { ...(prev[mod.so] ?? {}) };
          if (val) cur[hex(targetAddr)] = val;
          else delete cur[hex(targetAddr)];
          return { ...prev, [mod.so]: cur };
        });
        showToast(val ? `已写入注释 @ ${hex(targetAddr)}` : `已清除注释 @ ${hex(targetAddr)}`);
      } else {
        showToast("写入注释失败");
      }
    }
    setInlineDialog(null);
  }, [inlineDialog, mod, f, selInsnAddr, showToast]);

  const toggleBpMark = useCallback(
    (soName: string, addr: number) => {
      const k = `${soName}:${hex(addr)}`;
      setBpMarks((prev) => {
        const next = new Set(prev);
        if (next.has(k)) {
          next.delete(k);
          showToast(`已移除本地断点标记 ${hex(addr)}`);
        } else {
          next.add(k);
          showToast(`已标记断点位 ${soName} @ ${hex(addr)}（真机断点可让 AI 调 set_breakpoint）`);
        }
        return next;
      });
    },
    [showToast]
  );

  // 拖拽调整左栏 / 右栏 / 底部抽屉尺寸
  const startResize = (kind: "left" | "right" | "drawer", e: React.MouseEvent) => {
    e.preventDefault();
    const startPos = kind === "drawer" ? e.clientY : e.clientX;
    const startSize = kind === "left" ? leftW : kind === "right" ? rightW : drawerH;
    const onMove = (ev: MouseEvent) => {
      const delta = (kind === "drawer" ? ev.clientY : ev.clientX) - startPos;
      if (kind === "left") setLeftW(Math.max(180, Math.min(420, startSize + delta)));
      else if (kind === "right") setRightW(Math.max(220, Math.min(440, startSize - delta)));
      else setDrawerH(Math.max(120, Math.min(420, startSize - delta)));
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // 全局快捷键（严格隔离 INPUT/TEXTAREA/SELECT/contentEditable 与弹窗）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      if (meta && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
        return;
      }
      if (meta && e.key.toLowerCase() === "b") {
        e.preventDefault();
        setLeftOpen((v) => !v);
        return;
      }
      if (meta && e.key.toLowerCase() === "j") {
        e.preventDefault();
        setDrawerOpen((v) => !v);
        return;
      }
      if (meta && e.key.toLowerCase() === "i") {
        e.preventDefault();
        setRightOpen((v) => !v);
        return;
      }
      if (meta && e.key === ",") {
        e.preventDefault();
        setMainView((v) => (v === "settings" ? "monitor" : "settings"));
        return;
      }
      if (e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        goBack();
        return;
      }
      if (e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        goFwd();
        return;
      }

      const tgt = e.target as HTMLElement | null;
      if (
        tgt instanceof HTMLInputElement ||
        tgt instanceof HTMLTextAreaElement ||
        tgt instanceof HTMLSelectElement ||
        tgt?.isContentEditable ||
        paletteOpen ||
        inlineDialog != null
      ) {
        return;
      }

      if (e.key === "F5" && modRef.current) {
        e.preventDefault();
        setMainView((v) => (v === "split" ? "disasm" : "split"));
      } else if (e.key === " " && modRef.current) {
        e.preventDefault();
        setMainView((v) => (v === "cfg" ? "split" : "cfg"));
      } else if (e.key === "1" && modRef.current) {
        setMainView("disasm");
      } else if (e.key === "4" && modRef.current) {
        setMainView("graph");
      } else if (e.key === "5") {
        setMainView("monitor");
      } else if (e.key === "6") {
        setMainView("tools");
      } else if (e.key.toLowerCase() === "n" && modRef.current && f) {
        e.preventDefault();
        setInlineDialog({ kind: "rename", value: f.n });
      } else if (e.key === ";" && modRef.current && f) {
        e.preventDefault();
        const a = selInsnAddr ?? f.a;
        setInlineDialog({ kind: "comment", value: commentsBySo[modRef.current.so]?.[hex(a)] ?? "" });
      } else if (e.key.toLowerCase() === "b" && modRef.current && f) {
        e.preventDefault();
        toggleBpMark(modRef.current.so, selInsnAddr ?? f.a);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goBack, goFwd, paletteOpen, inlineDialog, f, selInsnAddr, commentsBySo, toggleBpMark]);

  // 左侧函数列表（支持关键词过滤 + 导出优先 + 限制 400 条保证万级函数流畅）
  const filteredFuncs = useMemo(() => {
    if (!mod) return [];
    const kw = leftFilter.trim().toLowerCase();
    const src = kw
      ? mod.funcs.filter((fn) => fn.n.toLowerCase().includes(kw) || hex(fn.a).includes(kw))
      : mod.funcs;
    return src.slice(0, 400);
  }, [mod, leftFilter]);

  const paletteActions = useMemo<PaletteAction[]>(
    () => [
      { kind: "视图", title: "实时工具流 & 设备运行态监控", meta: "5", run: () => setMainView("monitor") },
      { kind: "视图", title: `全部 ${toolsList.length || 140} 个真实 MCP 工具目录`, meta: "6", run: () => setMainView("tools") },
      { kind: "设置", title: "设置 & 设备工具箱（手机代理 / 冻结 App / 清数据重启）", meta: "⌘,", run: () => setMainView("settings") },
      { kind: "视图", title: "并排对照：反汇编 + 伪代码 (F5)", meta: "F5", run: () => mod && setMainView("split") },
      { kind: "视图", title: "CFG 基本块控制流图 (Space)", meta: "Space", run: () => mod && setMainView("cfg") },
      { kind: "视图", title: "跨 SO 调用图谱", meta: "4", run: () => mod && setMainView("graph") },
      { kind: "抽屉", title: "打开底部 Frida 终端", meta: "⌘J", run: () => { setDrawerTab("terminal"); setDrawerOpen(true); } },
      { kind: "抽屉", title: "打开底部插件快捷分析", meta: "⌘J", run: () => { setDrawerTab("plugins"); setDrawerOpen(true); } },
      { kind: "操作", title: "建立当前 SO 交叉引用图", meta: "Xref", run: () => void buildXrefs() },
      { kind: "操作", title: "切换深色 / 浅色主题", meta: "Theme", run: () => { themeLocked.current = true; setTheme((t) => (t === "dark" ? "light" : "dark")); } },
    ],
    [toolsList.length, mod, buildXrefs]
  );

  const empty = modules.length === 0;
  const totalFnsAll = modules.reduce((acc, m) => acc + m.funcs.length, 0);
  const showRightInspector = rightOpen && mainView !== "monitor" && mainView !== "tools" && mainView !== "settings";

  return (
    <div
      className="v2-shell"
      onDragOver={(e) => { e.preventDefault(); if (!dragging) setDragging(true); }}
      onDragLeave={(e) => {
        if (e.clientX <= 0 || e.clientY <= 0 || e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
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
      {/* 顶栏 */}
      <header className="v2-topbar">
        <div className="v2-brand">
          <div className="v2-brand-mark">M</div>
          <span>MDA</span>
          <span className="v2-brand-ver">{ver || "Studio"}</span>
        </div>
        <div className="v2-sep" />

        <div className="v2-mod-pills">
          {modules.map((m, i) => (
            <div
              key={m.so}
              className={"v2-mod-pill" + (i === active ? " active" : "") + (busySo === m.so ? " busy" : "")}
              onClick={() => {
                setActive(i);
                if (mainView === "monitor" || mainView === "tools") setMainView("split");
              }}
            >
              <span
                className="v2-mod-dot"
                style={{ background: i % 2 === 0 ? "var(--accent)" : "var(--violet)" }}
              />
              <span>{m.so}</span>
              <span className="cnt">{m.funcs.length}</span>
              <button
                className="v2-mod-x"
                title={`释放 ${m.so}`}
                onClick={(e) => { e.stopPropagation(); void unloadModule(m.so); }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
        <button className="v2-top-btn" onClick={openSo} title="打开或拖入 .so 文件">
          + 打开 so
        </button>

        <div className="v2-sep" />

        <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
          <button className="v2-icon-btn" onClick={goBack} disabled={histIdx <= 0} title="后退 (Alt+←)">
            <svg className="ic" viewBox="0 0 16 16"><path d="M10 3.5L5.5 8 10 12.5" /></svg>
          </button>
          <button className="v2-icon-btn" onClick={goFwd} disabled={histIdx >= history.length - 1} title="前进 (Alt+→)">
            <svg className="ic" viewBox="0 0 16 16"><path d="M6 3.5L10.5 8 6 12.5" /></svg>
          </button>
        </div>

        <button className="v2-cmd-trigger" onClick={() => setPaletteOpen(true)} title="全局搜索与命令面板 (⌘K)">
          <svg className="ic ic-sm" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5L14 14" /></svg>
          <span className="v2-cmd-crumb">
            {mod && f ? (
              <>{mod.so} <span>/</span> {f.n} <span>@ {hex(f.a)}</span></>
            ) : (
              <span>搜索函数、{toolsList.length || 140} 个工具或设置…</span>
            )}
          </span>
          <span className="v2-kbd">⌘K</span>
        </button>

        <button
          className={"v2-ai-pill" + (followAi ? " following" : "") + (beamCol ? " busy" : "")}
          onClick={() => {
            if (mainView !== "monitor") setMainView("monitor");
            else {
              setFollowAi((v) => !v);
              showToast(!followAi ? "已开启 AI 视角跟随" : "已暂停 AI 视角跟随");
            }
          }}
          title="点击进入工具流，或在工具流内开关 AI 视角跟随"
        >
          <span className={"v2-pulse-dot" + (wsAlive ? "" : " off")} />
          <span>{wsAlive ? (followAi ? "AI 实时 · 跟随开" : "AI 实时 · 跟随关") : "事件流重连中"}</span>
        </button>

        <button
          className="v2-top-btn"
          onClick={buildXrefs}
          disabled={empty}
          title="为当前 SO 构建全量交叉引用图"
        >
          建引用图
        </button>

        <button className="v2-top-btn" onClick={copyMcpConfig} title="复制 MCP 配置（HTTP + stdio）">
          MCP 配置
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 2 }}>
          <button
            className={"v2-icon-btn" + (leftOpen ? " on" : "")}
            onClick={() => setLeftOpen((v) => !v)}
            title="折叠/展开左栏 (⌘B)"
          >
            <svg className="ic" viewBox="0 0 16 16"><rect x="2" y="2.5" width="12" height="11" rx="2" /><path d="M6 2.5v11" /></svg>
          </button>
          <button
            className={"v2-icon-btn" + (drawerOpen ? " on" : "")}
            onClick={() => setDrawerOpen((v) => !v)}
            title="折叠/展开底部插件与 Frida 终端抽屉 (⌘J)"
          >
            <svg className="ic" viewBox="0 0 16 16"><rect x="2" y="2.5" width="12" height="11" rx="2" /><path d="M2 10h12" /></svg>
          </button>
          <button
            className={"v2-icon-btn" + (rightOpen ? " on" : "")}
            onClick={() => setRightOpen((v) => !v)}
            title="折叠/展开右侧检视器 (⌘I)"
          >
            <svg className="ic" viewBox="0 0 16 16"><rect x="2" y="2.5" width="12" height="11" rx="2" /><path d="M10 2.5v11" /></svg>
          </button>
        </div>

        <button
          className={"v2-top-btn" + (mainView === "settings" ? " pri" : "")}
          onClick={() => setMainView((v) => (v === "settings" ? "monitor" : "settings"))}
          title="设置 & 设备工具箱：手机代理、冻结 App、清数据重启 (⌘,)"
        >
          设置
        </button>

        <button
          className="v2-top-btn"
          onClick={() => {
            themeLocked.current = true;
            setTheme((t) => (t === "dark" ? "light" : "dark"));
          }}
        >
          {theme === "dark" ? "深色" : "浅色"}
        </button>
      </header>

      {/* AI 操控能量流光条 */}
      <div
        className={"v2-ai-beam" + (beamCol ? " on" : "")}
        style={beamCol ? { ["--beam-col" as string]: beamCol } : undefined}
      />

      {/* 全局引用密度热力条 */}
      {!empty && mod && (
        <div className="v2-heat-wrap">
          <HeatBar
            so={mod.so}
            xrefBuilt={navSt?.xref_built}
            onPickAddr={(a) => jumpToAddr(mod.so, a, { targetView: "split" })}
          />
          <div key={heatSweepKey} className={"v2-heat-sweep" + (heatSweepKey > 0 ? " go" : "")} />
        </div>
      )}

      {/* 主三栏可拖拽工作区 */}
      <div className="v2-main">
        {/* 左栏 */}
        <aside
          className={"v2-sidebar" + (leftOpen ? "" : " collapsed")}
          style={{ width: leftOpen ? leftW : 0 }}
        >
          <div className="v2-seg-wrap">
            <div className="v2-seg">
              <button className={leftTab === "funcs" ? "on" : ""} onClick={() => setLeftTab("funcs")}>函数</button>
              <button className={leftTab === "strings" ? "on" : ""} onClick={() => setLeftTab("strings")}>字符串</button>
              <button className={leftTab === "sections" ? "on" : ""} onClick={() => setLeftTab("sections")}>段节</button>
              <button className={leftTab === "nav" ? "on" : ""} onClick={() => setLeftTab("nav")}>导航</button>
            </div>
            {leftTab !== "nav" && (
              <div className="v2-filter-box">
                <svg className="ic ic-sm" style={{ color: "var(--fg-3)" }} viewBox="0 0 16 16">
                  <circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5L14 14" />
                </svg>
                <input
                  value={leftFilter}
                  onChange={(e) => setLeftFilter(e.target.value)}
                  placeholder="过滤函数、地址或字符串…"
                  autoComplete="off"
                />
              </div>
            )}
          </div>

          <div className="v2-list-body">
            {leftTab === "funcs" && (
              mod ? (
                <>
                  {filteredFuncs.map((fn) => {
                    const isSel = f?.a === fn.a;
                    return (
                      <div
                        key={fn.a}
                        className={"v2-fn-item" + (isSel ? " sel" : "") + (fn.e ? " exp" : "")}
                        onClick={() => jumpToAddr(mod.so, fn.a)}
                      >
                        <span className="nm" title={fn.n}>{fn.n}</span>
                        <span className="ad">{hex(fn.a)}</span>
                        <span className="rf">{fn.r || ""}</span>
                      </div>
                    );
                  })}
                  {!filteredFuncs.length && (
                    <div style={{ padding: 18, textAlign: "center", color: "var(--fg-3)" }}>无匹配函数</div>
                  )}
                </>
              ) : (
                <div style={{ padding: 18, textAlign: "center", color: "var(--fg-3)", fontSize: 12 }}>
                  拖入或点击「+ 打开 so」加载模块；动态分析可直接切到「工具流」或「导航」
                </div>
              )
            )}

            {leftTab === "strings" && (
              mod ? (
                leftStrings.map((s) => (
                  <div
                    key={s.addr}
                    className="v2-str-item"
                    onClick={() => {
                      if (s.ref_fn != null) {
                        jumpToAddr(mod.so, s.ref_fn, { targetView: "split" });
                        showToast(`已跳至引用该字符串的函数 ${hex(s.ref_fn)}`);
                      } else {
                        showToast(`字符串地址 ${hex(s.addr)}（尚未发现代码引用）`);
                      }
                    }}
                  >
                    <div className="v2-str-val">"{s.value}"</div>
                    <div className="v2-str-meta">
                      <span>{hex(s.addr)}{s.section ? ` · ${s.section}` : ""}</span>
                      <span>{s.refs} 引用</span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: 18, textAlign: "center", color: "var(--fg-3)" }}>请先打开一个 so</div>
              )
            )}

            {leftTab === "sections" && (
              mod ? (
                leftSections.map((s) => {
                  const cls = s.flags.includes("x") ? " exec" : s.flags.includes("w") ? " rw" : "";
                  return (
                    <div className="v2-sec-item" key={`${s.name}-${s.addr}`}>
                      <span className={"v2-sec-perm" + cls}>{s.flags}</span>
                      <span style={{ flex: 1, color: "var(--fg)", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {s.name}
                      </span>
                      <span style={{ color: "var(--fg-3)" }}>{s.addr}</span>
                    </div>
                  );
                })
              ) : (
                <div style={{ padding: 18, textAlign: "center", color: "var(--fg-3)" }}>请先打开一个 so</div>
              )
            )}

            {leftTab === "nav" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <LeftNav
                  so={mod?.so ?? ""}
                  activeView={mainView === "split" || mainView === "disasm" ? "module" : mainView}
                  onPick={(v) => setMainView(v === "module" ? "split" : v)}
                  onServerModules={handleServerModules}
                  fnCount={mod?.funcs.length}
                  tick={aiTick}
                />
                <LeftPanel
                  logs={logs}
                  watch={watch}
                  onPickWatch={(w) => jumpToAddr(w.so, w.addr, { targetView: "split" })}
                />
              </div>
            )}
          </div>
        </aside>

        {leftOpen && (
          <div className="v2-resizer-v" onMouseDown={(e) => startResize("left", e)} title="拖拽调整左侧宽度" />
        )}

        {/* 中央工作台 + 底部抽屉 */}
        <div className="v2-center">
          <div className="v2-stage-bar">
            <div className="v2-mode-tabs">
              <button
                className={"v2-mode-tab" + (mainView === "monitor" ? " on" : "")}
                onClick={() => setMainView("monitor")}
              >
                工具流 <span className="hint-k">{aiEvents.length || 5}</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "tools" ? " on" : "")}
                onClick={() => setMainView("tools")}
              >
                工具库 <span className="hint-k">{toolsList.length || 140}</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "split" ? " on" : "")}
                onClick={() => setMainView("split")}
                disabled={empty}
              >
                并排伪代码 <span className="hint-k">F5</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "disasm" ? " on" : "")}
                onClick={() => setMainView("disasm")}
                disabled={empty}
              >
                反汇编 <span className="hint-k">1</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "cfg" ? " on" : "")}
                onClick={() => setMainView("cfg")}
                disabled={!f}
              >
                CFG 控制流 <span className="hint-k">Space</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "graph" ? " on" : "")}
                onClick={() => setMainView("graph")}
                disabled={!f}
              >
                跨 SO 图谱 <span className="hint-k">4</span>
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "xref" ? " on" : "")}
                onClick={() => setMainView("xref")}
                disabled={!f}
              >
                引用{navSt?.refs != null ? ` ${navSt.refs}` : ""}
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "timeline" ? " on" : "")}
                onClick={() => setMainView("timeline")}
              >
                时间线
              </button>
              <button
                className={"v2-mode-tab" + (mainView === "settings" ? " on" : "")}
                onClick={() => setMainView("settings")}
                title="设置 & 设备常用工具箱 (⌘,)"
              >
                设置 <span className="hint-k">⌘,</span>
              </button>
            </div>

            <div className="v2-fn-actions">
              <button
                className="v2-act-btn"
                disabled={!f}
                onClick={() => f && setInlineDialog({ kind: "rename", value: f.n })}
                title="原地重命名当前函数 (N)"
              >
                重命名 <span className="v2-kbd">N</span>
              </button>
              <button
                className="v2-act-btn"
                disabled={!f}
                onClick={() => {
                  if (!mod || !f) return;
                  const a = selInsnAddr ?? f.a;
                  setInlineDialog({ kind: "comment", value: commentsBySo[mod.so]?.[hex(a)] ?? "" });
                }}
                title="给选中地址写注释 (;)"
              >
                注释 <span className="v2-kbd">;</span>
              </button>
              <button
                className="v2-act-btn"
                disabled={!f}
                onClick={() => mod && f && toggleBpMark(mod.so, selInsnAddr ?? f.a)}
                title="本地标记/取消断点 (B)"
              >
                断点 <span className="v2-kbd">B</span>
              </button>
            </div>
          </div>

          <div className={"v2-stage-body" + (stageAura ? ` ${stageAura}` : "")}>
            {mainView === "monitor" && (
              <RealtimeMonitor
                events={aiEvents}
                wsAlive={wsAlive}
                paused={aiPaused}
                onTogglePause={() =>
                  setAiPaused((v) => {
                    aiPausedRef.current = !v;
                    return !v;
                  })
                }
                onClear={() => setAiEvents([])}
                mods={modules.map((m) => ({ so: m.so, n: m.funcs.length }))}
                hooksProp={navSt?.hooks ?? null}
                dynState={dynState}
                currentAddr={f?.a ?? null}
                opsSignal={opsSignal}
                onOpenTools={(tn) => {
                  if (tn) setPreselectTool(tn);
                  setMainView("tools");
                }}
                onJumpToCode={(soName, addr) => {
                  if (addr != null) jumpToAddr(soName, addr, { targetView: "split" });
                  else {
                    const mi = modules.findIndex((m) => m.so === soName);
                    if (mi >= 0) { setActive(mi); setMainView("split"); }
                  }
                }}
                armedBpCount={armedBpCount}
                toolsCount={toolsList.length || 140}
              />
            )}

            {mainView === "tools" && (
              <ToolsView
                counts={toolCounts}
                initialSelected={preselectTool}
              />
            )}

            {mainView === "settings" && (
              <SettingsView
                theme={theme}
                onToggleTheme={() => {
                  themeLocked.current = true;
                  setTheme((t) => (t === "dark" ? "light" : "dark"));
                }}
                onOpenToolDoc={(tn) => {
                  setPreselectTool(tn);
                  setMainView("tools");
                }}
                onToast={showToast}
              />
            )}

            {(mainView === "split" || mainView === "disasm" || mainView === "cfg") && mod && f && (
              <CodeStage
                so={mod.so}
                fnAddr={f.a}
                fnName={f.n}
                fnSize={f.s}
                isExport={!!f.e}
                mode={mainView}
                selInsnAddr={selInsnAddr}
                onSelectInsn={setSelInsnAddr}
                onJump={(soName, addr) => jumpToAddr(soName, addr)}
                onSwitchMode={(m) => setMainView(m)}
                comments={commentsBySo[mod.so] ?? {}}
                bpMarks={bpMarks}
                onToggleBpMark={toggleBpMark}
                aiHitSeq={aiHit.seq}
                aiHitAddr={aiHit.addr}
              />
            )}

            {(mainView === "split" || mainView === "disasm" || mainView === "cfg") && empty && !loading && (
              <div className="empty-stage">
                <div className="empty-mark"><span className="mark" /></div>
                <div className="empty-title">拖入或打开一个 .so 开始分析</div>
                <div className="empty-sub">多 so 同会话 · F5 伪代码联动 · Space 控制流图 · 跨 so 调用链</div>
                <button className="v2-top-btn pri" style={{ height: 32, padding: "0 14px" }} onClick={openSo}>
                  打开 so 文件
                </button>
                {loadError && <div className="empty-err">{loadError}</div>}
              </div>
            )}

            {mainView === "graph" && mod && f && (
              <GraphView
                so={mod.so}
                addr={f.a}
                fnName={f.n}
                onJump={(soName, addr) => jumpToAddr(soName, addr, { targetView: "graph" })}
                onOpenCode={(soName, addr) => jumpToAddr(soName, addr, { targetView: "split" })}
                onBuildXrefs={buildXrefs}
              />
            )}

            {mainView === "xref" && mod && f && (
              <XrefView
                so={mod.so}
                addr={f.a}
                fnName={f.n}
                onJump={(a) => jumpToAddr(mod.so, a, { targetView: "split" })}
              />
            )}

            {mainView === "timeline" && <TimelineView events={aiEvents} />}
            {mainView === "processes" && <ProcessesView />}
            {mainView.startsWith("dyn:") && <DynStateView kind={mainView.slice(4) as DynKind} />}
            {mainView === "strings" && (mod ? <FlatTable so={mod.so} kind="strings" /> : <NeedSoView what="字符串表" why="请先载入一个 so" />)}
            {mainView === "sections" && (mod ? <FlatTable so={mod.so} kind="sections" /> : <NeedSoView what="段 / 节表" why="请先载入一个 so" />)}

            {loading && (
              <div className="loading-layer">
                <div className="spinner" />
                <div className="loading-text">正在解析 {loading.name}…</div>
                <div className="loading-sub">读取段表 → 发现函数 → 建索引</div>
              </div>
            )}
          </div>

          {drawerOpen && (
            <div className="v2-resizer-h" onMouseDown={(e) => startResize("drawer", e)} title="拖拽调整底部抽屉高度" />
          )}

          {/* 底部可拖拽抽屉：插件快捷分析 + 真实 Frida 终端 */}
          <BottomDrawer
            open={drawerOpen}
            height={drawerH}
            tab={drawerTab}
            onChangeTab={setDrawerTab}
            onClose={() => setDrawerOpen(false)}
            so={mod?.so ?? ""}
            fnAddr={f?.a ?? null}
            fnName={f?.n ?? ""}
            onJumpFn={(soName, addr) => jumpToAddr(soName, addr, { targetView: "split" })}
            liveScripts={liveScripts}
            onScriptsChange={setLiveScripts}
          />
        </div>

        {showRightInspector && (
          <>
            <div className="v2-resizer-v" onMouseDown={(e) => startResize("right", e)} title="拖拽调整右侧检视器宽度" />
            <aside className="v2-inspector" style={{ width: rightW }}>
              <Inspector
                mods={modules}
                current={mod && f ? { so: mod.so, addr: f.a, name: f.n } : null}
                onPickFn={(soName, addr) => jumpToAddr(soName, addr)}
              />
            </aside>
          </>
        )}
      </div>

      {/* 状态栏 */}
      <footer className="v2-statusbar">
        <span style={{ color: apiOk ? "var(--green)" : "var(--rose)", display: "inline-flex", alignItems: "center", gap: 5 }}>
          <span className={"v2-pulse-dot" + (apiOk ? "" : " off")} style={{ width: 6, height: 6 }} />
          {apiOk ? "后端已连接" : "后端未连接"} · WS {wsAlive ? "实时" : "重连中"}
        </span>
        <span className="mono">
          {mod && f ? `${mod.so} · ${hex(selInsnAddr ?? f.a)} (${f.s} B)` : "未选中函数"}
        </span>
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          ⌘K 搜索 · F5 并排伪代码 · Space CFG · 5 工具流 · 6 工具库 · ⌘J 终端/插件抽屉
        </span>
        <div className="r">
          <span className="mono">{modules.length} 模块 · {totalFnsAll} 函数</span>
          <span>MDA Studio v2</span>
        </div>
      </footer>

      {/* 跨视图悬浮 AI 操控迷你雷达 HUD */}
      <div
        className={"v2-device-hud" + (hud ? " show" : "")}
        style={hud ? { ["--hud-col" as string]: hud.col } : undefined}
        onClick={() => { setHud(null); setMainView("monitor"); }}
      >
        <div className="v2-hud-top">
          <span className="v2-pulse-dot" style={{ width: 6, height: 6, background: hud?.col || "var(--accent)" }} />
          <span className="v2-hud-title">{hud?.tool || "AI 操控设备"}</span>
          {hud && <span className={"v2-badge " + hud.cat} style={{ marginLeft: "auto" }}>{TOOL_LABEL[hud.cat] || hud.cat}</span>}
        </div>
        <div className="v2-hud-sub">{hud?.sub || ""}</div>
        <div className="v2-hud-track">
          <span>AI</span>
          <span className="v2-hud-wire" />
          <span>{hud?.layer || "Android"}</span>
        </div>
      </div>

      {/* ⌘K 全局命令面板 */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        modules={modules}
        tools={toolsList}
        actions={paletteActions}
        onJumpFn={(soName, addr) => jumpToAddr(soName, addr, { targetView: "split" })}
        onPickTool={(tName) => { setPreselectTool(tName); setMainView("tools"); }}
      />

      {/* 原地重命名 / 注释弹窗 */}
      {inlineDialog && (
        <div
          className="v2-modal-backdrop"
          onClick={(e) => { if (e.target === e.currentTarget) setInlineDialog(null); }}
        >
          <div className="v2-modal-box">
            <h3>
              {inlineDialog.kind === "rename"
                ? `重命名函数 · ${f ? hex(f.a) : ""}`
                : `写入/编辑指令注释 · ${hex(selInsnAddr ?? f?.a ?? 0)}`}
            </h3>
            <input
              autoFocus
              value={inlineDialog.value}
              onChange={(e) => setInlineDialog({ ...inlineDialog, value: e.target.value })}
              onKeyDown={(e) => {
                e.stopPropagation();
                if (e.key === "Enter") { e.preventDefault(); void submitInlineDialog(); }
                if (e.key === "Escape") { e.preventDefault(); setInlineDialog(null); }
              }}
            />
            <div className="v2-modal-foot">
              <button className="v2-top-btn" onClick={() => setInlineDialog(null)}>取消</button>
              <button className="v2-top-btn pri" onClick={() => void submitInlineDialog()}>确定</button>
            </div>
          </div>
        </div>
      )}

      {dragging && (
        <div className="drop-overlay">
          <div className="drop-box">
            <span className="drop-icon" />
            <span>松开即加载 .so</span>
            <span className="drop-sub">自动上传到后端实时解析</span>
          </div>
        </div>
      )}

      {toast && <div className="v2-toast">{toast}</div>}
    </div>
  );
}
