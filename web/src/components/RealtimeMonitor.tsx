import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiHooks } from "../lib/api";

/**
 * 实时监控台 —— AI 的每次 MCP 工具调用都在这里上流。
 *
 * 设计依据（重要）：
 *   界面**不承载 AI 的结论**，只承载机器产生的证据。
 *   服务端 @logged 装饰器每次工具调用都会广播
 *   {type:"ai", tool, args, summary, ms, ts}，不需要 AI 配合写任何东西。
 *   结论、建议、判断 → 留在对话里。
 *
 * 特效都是因果的，不是装饰：
 *   · 类型徽章 —— 按工具名前缀通用归类（137 个工具全覆盖）
 *   · 工具行脉冲 —— 这个工具正在被使用
 *   · 待命徽章 —— 装断点/hook 后一直挂着（AI 正在盯着）
 *   · 冻结脉冲 —— 断点命中时目标短暂失活
 */

export type AiEvent = {
  tool: string;
  args?: Record<string, unknown>;
  summary?: string;
  ms?: number;
  ts?: string;
};

type Props = {
  events: AiEvent[];
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  /** 当前会话已加载的模块（真实）。左栏「模块」段用。
   *  原型那里是 1495 个设备侧 so，我们显示的是本会话真正加载过的。 */
  mods?: { so: string; n: number }[];
  /** 行为监控当前挂了哪些 hook（父组件统一取，避免每处各发一次请求） */
  hooksProp?: ApiHooks | null;
};

/* 按工具名前缀归类——通用规则，不针对任何具体工具写死 */
function classify(tool: string): string {
  const t = tool || "";
  if (/^vm_|^dump_vm|^probe_vm/.test(t)) return "vm";
  if (/^perf_watch/.test(t)) return "watch";
  if (/^java_/.test(t)) return "java";
  if (/^trace_|^watch_module|^module_load/.test(t)) return "trace";
  if (/^mem_/.test(t)) return "mem";
  if (/^behavior_/.test(t)) return "behavior";
  if (/process|^list_threads|^probe_network/.test(t)) return "proc";
  if (/breakpoint|^hits$|^wait_hits|^poll_events|^probe_hits|^resume$|^freeze|^unfreeze|^attach|^detach/.test(t))
    return "bp";
  if (/^read_|^locate_|^get_callstack|^runtime_modules|^list_modules/.test(t)) return "runtime";
  return "static";
}

const LABEL: Record<string, string> = {
  static: "静态", vm: "VM", bp: "断点", proc: "进程", behavior: "行为",
  mem: "内存", watch: "观察点", trace: "轨迹", java: "Java", runtime: "运行时",
};

/* 只展示有信息量的参数，避免刷屏 */
const SHOW_ARG = [
  "so_name", "pid", "addr", "name", "package", "pattern", "key",
  "dispatch_offset", "duration", "class_name", "method", "symbol",
  "target_idx", "size", "slot",
];

/**
 * 这次调用作用在什么类型的对象上。
 *
 * 通用规则：按参数名推断，不针对任何具体工具写死。
 * 返回的 kind 决定事件行左侧那条"来向线"的颜色——
 * 蓝色=模块、橙色=进程、紫色=地址、青色=包名。
 * 这不是装饰：颜色的含义是"这次操作打在了哪类对象上"。
 */
function targetKind(args?: Record<string, unknown>): "so" | "pid" | "addr" | "pkg" | null {
  if (!args) return null;
  if (args.so_name || args.name) return "so";
  if (args.pid !== undefined) return "pid";
  if (args.addr !== undefined || args.static_addr !== undefined) return "addr";
  if (args.package) return "pkg";
  return null;
}

/** "HH:MM:SS" → 今天该时刻的毫秒数；解析不了返回 null（不编造时间） */
const clockMs = (ts?: string): number | null => {
  if (!ts) return null;
  const m = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(ts);
  if (!m) return null;
  const d = new Date();
  d.setHours(Number(m[1]), Number(m[2]), Number(m[3]), 0);
  return d.getTime();
};

const clock = (ts?: string) => {
  if (!ts) return new Date().toLocaleTimeString("zh-CN", { hour12: false });
  // 后端给的是 ISO 或已格式化字符串，能解析就用，不能就原样
  const d = new Date(ts);
  return isNaN(d.getTime())
    ? ts
    : d.toLocaleTimeString("zh-CN", { hour12: false }) +
      "." + String(d.getMilliseconds()).padStart(3, "0");
};

/** 一次工具调用渲染成一行 */
/* 事件流筛选项 —— 和原型的六个标签一致。
   把 classify() 的 10 个类别都归进来，不留"选不到"的事件。 */
const CATS: { k: string; label: string; types: string[] | null }[] = [
  { k: "all", label: "全部", types: null },
  { k: "static", label: "静态", types: ["static"] },
  { k: "runtime", label: "运行时", types: ["runtime", "java"] },
  { k: "vm", label: "VM", types: ["vm"] },
  { k: "behavior", label: "行为", types: ["behavior", "memo", "watch", "bp"] },
  { k: "proc", label: "进程", types: ["proc", "trace"] },
];

/** 转义：拼 HTML 前必须做，参数里可能有 < > & */
function esc(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderCall(ev: AiEvent): { type: string; html: string; meta: string; kind: string | null } {
  const type = classify(ev.tool);
  const a = ev.args ?? {};
  const shown = SHOW_ARG
    .filter((k) => a[k] !== undefined && a[k] !== null)
    .slice(0, 3)
    .map((k) => {
      let v = a[k];
      // 地址类参数统一 0x 显示，和反汇编/引用页保持一致
      if (k.includes("addr")) {
        const n = typeof v === "number" ? v : parseInt(String(v), 0);
        if (Number.isFinite(n)) v = "0x" + n.toString(16);
      }
      // 参数值高亮：一眼分清哪个是键、哪个是值
      return `${esc(k)}=<em>${esc(String(v).slice(0, 26))}</em>`;
    })
    .join(" ");
  const summary = ev.summary ? ` → <b>${esc(ev.summary)}</b>` : "";
  return {
    type,
    // 工具名加粗，和参数、结果拉开层次
    html: `<span class="tn">${esc(ev.tool)}</span>${shown ? "(" + shown + ")" : ""}${summary}`,
    meta: ev.ms != null ? `${ev.ms}ms` : "",
    kind: targetKind(ev.args),
  };
}

/** 左栏目标：**前台那个 App** 的真实进程（自动跟随，不写死包名） */
function Procs({ onMain }: { onMain?: (n: number | null) => void }) {
  const [procs, setProcs] = useState<{
    pid: number; name: string; suffix: string; role: string;
    inet: number | null; isMain: boolean;
    sock?: number | null; soCount?: number | null;
  }[]>([]);
  const [note, setNote] = useState("正在读前台 App…");
  const [pkg, setPkg] = useState("");
  // 「AI 正在盯着」的待命条数：复用服务端已广播的 mda:armed（ArmedBar 同源）
  const [armed, setArmed] = useState(0);
  useEffect(() => {
    const on = (e: Event) => {
      const items = (e as CustomEvent).detail;
      setArmed(Array.isArray(items) ? items.length : 0);
    };
    window.addEventListener("mda:armed", on as EventListener);
    // 首屏主动拉一次：事件只在变化时广播，刚打开页面时还没有事件
    void (async () => {
      const r = await api.armed();
      if (r?.count != null) setArmed(r.count);
    })();
    return () => window.removeEventListener("mda:armed", on as EventListener);
  }, []);

  useEffect(() => {
    void (async () => {
      // ① 先问设备：前台是哪个 App
      const fg = await api.foreground();
      if (!fg || !fg.package) {
        setNote(fg?.error ? String(fg.error).slice(0, 46) : "读不到前台 App（设备未连接？）");
        return;
      }
      setPkg(fg.package);

      // ② 再查它的全部进程
      const r = await api.appProcesses({ package: fg.package });
      if (!r || r.ok === false) {
        setNote(r?.error ? String(r.error).slice(0, 46) : "这个 App 没有可取到的进程");
        return;
      }
      setProcs(
        (r.processes ?? []).map((p) => ({
          pid: p.pid, name: p.name, suffix: p.suffix, role: p.role,
          inet: p.inet_conns, isMain: p.is_main,
          sock: p.sockets, soCount: p.loaded_so_count,
        }))
      );
      const main = (r.processes ?? []).find((x) => x.is_main);
      onMain?.(main?.loaded_so_count ?? null);
      setNote("");
    })();
  }, [onMain]);

  if (!procs.length) {
    return <div className="mon-note">{note}</div>;
  }
  return (
    <>
      {procs.map((p) => (
        <div
          className={
            "proc2" + (p.isMain ? " main" : "") +
            (p.isMain && armed > 0 ? " armed" : "")
          }
          key={p.pid}
          data-target="proc"
          title={
            (p.isMain && armed > 0
              ? `AI 正在盯着这个目标（${armed} 项待命）`
              : p.name) + ` · ${p.role}`
          }
        >
          <span className="pn2" title={p.name}>
            {p.isMain ? p.name : "…" + p.suffix}
          </span>
          {/* 原型是「N inet  M sock」两列，都是真实读数 */}
          <span className="pm2">
            <span><b className={p.inet ? "hot" : ""}>{p.inet ?? "—"}</b> inet</span>
            <span><b>{p.sock ?? "—"}</b> sock</span>
          </span>
          {p.isMain && armed > 0 && <span className="armtag">◉ {armed}</span>}
        </div>
      ))}
    </>
  );
}

/* ══ 因果特效（原型 drawLink / markTarget）══
   目标元素由这条事件的真实参数决定：
     带 so_name 的操作打在「模块」段，其余打在主进程行。
   没加载模块、也没有进程时返回 null，不画假连线。 */

function pickTarget(ev: AiEvent): HTMLElement | null {
  const soName = (ev.args ?? {})["so_name"];
  if (typeof soName === "string" && soName) {
    const mods = document.querySelectorAll<HTMLElement>(".mon-mods .mod2");
    for (const m of mods) {
      if (m.textContent?.includes(soName)) return m;
    }
  }
  return document.querySelector<HTMLElement>(".mon-left .proc2.main")
      ?? document.querySelector<HTMLElement>(".mon-left .proc2");
}

function relRect(el: Element) {
  const host = document.querySelector(".monitor")!;
  const h = host.getBoundingClientRect();
  const r = el.getBoundingClientRect();
  return { x: r.left - h.left, y: r.top - h.top, w: r.width, h: r.height };
}

/** 从目标右缘画一条贝塞尔曲线到新记录左缘（900ms 后消失） */
function drawLink(target: Element, row: Element) {
  const layer = document.querySelector(".fx-layer");
  if (!layer) return;
  const t = relRect(target);
  const r = relRect(row);
  const x1 = t.x + t.w;
  const y1 = t.y + t.h / 2;
  const x2 = r.x;
  const y2 = r.y + r.h / 2;
  if (x2 <= x1) return;                       // 行在目标左边，不画
  const mid = (x1 + x2) / 2;
  const d = `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", d);
  path.setAttribute("class", "go");
  layer.appendChild(path);
  window.setTimeout(() => path.remove(), 950);
}

/** 目标右上角闪一个光点 + 把这次调用的工具名挂到 title 上 */
function markTarget(target: HTMLElement, tool: string) {
  target.title = "刚执行：" + tool;
  const dot = document.createElement("span");
  dot.className = "fxdot";
  target.appendChild(dot);
  window.setTimeout(() => dot.remove(), 900);
}

/** 底部活动密度：把最近 40 次调用按**时间桶**落到 6 条泳道上。
 *
 * 每一格 = 一个真实调用（按时间顺序），高度 = 该桶里这类调用的次数。
 * 没有数据的桶就是 0。右侧数字是整场的真实累计计数。
 * 不编造起伏——这是测量数据。
 */
const LANE_KINDS = ["static", "vm", "bp", "proc", "behavior", "mem"] as const;
const LANE_CAP = 40;

function Lanes({ events }: { events: AiEvent[] }) {
  // 事件流是最新在前，泳道按时间从左到右，所以取末尾 40 个再反转
  const recent = events.slice(0, LANE_CAP).reverse();

  const buckets: Record<string, number[]> = {};
  for (const k of LANE_KINDS) buckets[k] = new Array(LANE_CAP).fill(0);

  recent.forEach((e, i) => {
    const k = classify(e.tool);
    if (buckets[k]) buckets[k][i] = (buckets[k][i] || 0) + 1;
  });

  const totals = LANE_KINDS.map((k) =>
    events.filter((e) => classify(e.tool) === k).length
  );
  const max = Math.max(1, ...totals);

  return (
    <div className="lanes2">
      <div className="lanes-h">
        <span>活动密度</span>
        <span className="span">最近 {recent.length} 次 · 每格 = 1 次真实调用</span>
      </div>
      {LANE_KINDS.map((k, idx) => (
        <div className={"lane2 " + k} key={k}>
          <span className="nm">{k.toUpperCase()}</span>
          <span className="tr">
            {buckets[k].map((v, j) => {
              // 每格固定高度 11px 里的比例：有调用就亮，没有就是空
              const h = v ? Math.max(3, Math.round((v / max) * 11) + 3) : 0;
              return <i key={j} style={{ height: Math.min(11, h) }} />;
            })}
          </span>
          <span className={"cnt" + (totals[idx] ? " has" : "")}>{totals[idx]}</span>
        </div>
      ))}
    </div>
  );
}

export function RealtimeMonitor({ events, paused, onTogglePause, onClear, mods, hooksProp }: Props) {
  const [sel, setSel] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  /* 新事件进来时，若开着自动滚动就滚到顶部（最新的在最上面） */
  useEffect(() => {
    if (autoScroll && listRef.current) listRef.current.scrollTop = 0;
  }, [events.length, autoScroll]);

  const detail = sel != null ? events[sel] : null;
  const toolCalls = events.length;

  /* 分类筛选 + 折叠（原型事件流表头那两个能力） */
  const [cat, setCat] = useState<string>("all");
  const [collapsed, setCollapsed] = useState(false);

  /* 前台包名：和目标不一致时给一条警告（原型同款）。
     第一次进来查一次即可——前台应用变化是低频的，不需要跟着每条事件重查。 */
  const [fgPkg, setFgPkg] = useState("");
  useEffect(() => {
    void (async () => {
      const r = await api.foreground();
      if (r?.package) setFgPkg(r.package);
    })();
  }, []);

  /* 监控目标 = AI 最近一次操作过的包/进程（从真实 args 里取） */
  const lastPkg = (() => {
    for (const e of events) {
      const v = (e.args ?? {})["package"];
      if (typeof v === "string" && v) return v;
    }
    return "";
  })();
  const lastPid = (() => {
    for (const e of events) {
      const v = (e.args ?? {})["pid"];
      if (typeof v === "number") return v;
      if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
    }
    return null;
  })();

  /* 每分钟调用数：按真实 ts 统计最近 60 秒 */
  const perMin = (() => {
    const cut = Date.now() - 60_000;
    let c = 0;
    for (const e of events) {
      const t = clockMs(e.ts);
      if (t != null && t >= cut) c += 1;
    }
    return c;
  })();

  /* 导出：把当前事件流原样存成 JSON（取证用） */
  const exportEvents = () => {
    const blob = new Blob([JSON.stringify(events, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `mda-events-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // Hook 墙：数据来自服务端待命表里 behavior_monitor 的真实参数。
  // 由父组件把 hooks 传进来（父组件已经在节流刷新，不必在这里再发一遍请求）。
  const hooks = hooksProp ?? null;
  // 目标进程加载的 so 总数（真实读数，来自 app_processes 的 loaded_so_count）
  const [soCount, setSoCount] = useState<number | null>(null);
  const onMain = useCallback((n: number | null) => setSoCount(n), []);

  // 特效触发：每来一条新事件，按它的类型给目标/模块加一次短暂的 class。
  // 这不是装饰——它回答「AI 刚才对谁做了什么」，所以必须对应真实事件。
  const lastRef = useRef<string>("");
  useEffect(() => {
    const ev = events[0];
    if (!ev) return;
    const sig = `${ev.ts}|${ev.tool}|${events.length}`;
    if (sig === lastRef.current) return;      // 同一条不重复触发
    lastRef.current = sig;

    const flash = (el: Element | null, cls: string, ms: number) => {
      if (!el) return;
      el.classList.remove(cls);
      void (el as HTMLElement).offsetWidth;   // 强制回流，让动画能重播
      el.classList.add(cls);
      window.setTimeout(() => el.classList.remove(cls), ms);
    };

    /* 因果连线 + 目标光点：把「这次调用」和「它打到的目标」连起来。
       原型就是这个机制（drawLink + markTarget），之前完全没做。 */
    const rowEl = listRef.current?.querySelector(".sr");
    const tgt = pickTarget(ev);
    if (tgt && rowEl) drawLink(tgt, rowEl);
    if (tgt && ev.tool) markTarget(tgt, ev.tool);

    const t = ev.tool || "";
    if (/behavior_monitor/.test(t)) {
      document.querySelectorAll(".hook, .hk").forEach((hk, i) => {
        window.setTimeout(() => flash(hk, "poweron", 600), i * 90);
      });
    }
    if (/^vm_|vm_trace/.test(t)) {
      flash(document.querySelector(".modlist .mr, .so-tab"), "strobe", 1600);
    }
    if (/breakpoint|^hits$/.test(t)) {
      flash(document.querySelector(".mon-body"), "freeze-pulse", 400);
    }
    if (ev.tool) {
      flash(document.querySelector(".mon-left .proc2, .mon-left .proc"), "ping", 900);
    }
  }, [events]);

  return (
    <div className="monitor">
      {/* 特效层：因果连线画在这里，不参与布局、不吃点击 */}
      <svg className="fx-layer" aria-hidden="true" />
      {/* 顶部状态条 */}
      <div className="mon-bar">
        <span className={"dot " + (paused ? "" : "live")} />
        <span className="mon-title">{paused ? "已暂停" : "监控中"}</span>
        {lastPkg && (
          <span className="mon-tgt">
            {lastPkg}{lastPid != null ? ` pid ${lastPid}` : ""}
          </span>
        )}
        {lastPkg && <span className="mon-sep">·</span>}
        <span className="mon-epm"><b>{perMin}</b> 条/分</span>
        <span className="mon-sep">·</span>
        <span className="mon-count"><b>{events.length}</b> 次工具调用</span>
        <span className="grow" />
        {fgPkg && lastPkg && fgPkg !== lastPkg && (
          <span className="mon-warn" title="AI 正在操作的目标不是前台应用">
            前台是 {fgPkg}，目标在后台
          </span>
        )}
        <button className="mon-btn" onClick={onTogglePause}>
          {paused ? "继续" : "暂停"}
        </button>
        <button
          className={"mon-btn" + (autoScroll ? " on" : "")}
          onClick={() => setAutoScroll((v) => !v)}
        >
          自动滚动
        </button>
        <button className="mon-btn" onClick={onClear} disabled={!toolCalls}>
          清空
        </button>
        <button className="mon-btn" onClick={exportEvents} disabled={!toolCalls}>
          导出
        </button>
      </div>

      <div className="mon-body">
        {/* 左：目标 / 模块 / Hook —— 原型就是这三段 */}
        <div className="mon-left">
          <div className="mon-hd">目标</div>
          <Procs onMain={onMain} />

          <div className="mon-hd" title="数字是目标进程加载的 so 总数；下面是本会话已加入分析的模块">
            模块 <b className="mon-hdn">{soCount ?? "—"}</b> 个
            {soCount != null && (mods?.length ?? 0) > 0 && (
              <span className="mon-sub">会话 {mods?.length ?? 0}</span>
            )}
          </div>
          <div className="mon-mods">
            {(mods ?? []).map((m) => (
              <div className="mod2" key={m.so}>
                <span className="mn2" title={m.so}>{m.so}</span>
                <b>{m.n}</b>
              </div>
            ))}
            {!mods?.length && (
              <div className="mon-empty">
                还没有加载模块
                <span className="mon-empty-sub">
                  动态能力（hook / 断点 / 设备 UI）不需要 so，可以直接用
                </span>
              </div>
            )}
          </div>

          <div className="mon-hd">
            Hook <b className="mon-hdn">{hooks?.on.length ?? 0}</b> 已挂
            {hooks?.armed && hooks.pid != null && (
              <span className="mon-pid">pid {hooks.pid}</span>
            )}
          </div>
          <div className="hookwall">
            {(hooks?.on ?? []).map((h) => (
              <span className="hk on" key={h}>{h}</span>
            ))}
            {(hooks?.off ?? []).map((h) => (
              <span className="hk off" key={h}>
                {h}{h === "exec" ? " 关" : ""}
              </span>
            ))}
            {!hooks?.armed && (
              <div className="mon-empty">还没挂行为监控</div>
            )}
          </div>
        </div>

        {/* 事件流：主体 */}
        <div className="mon-stream">
          {/* 表头：分类筛选 + 折叠（原型同款） */}
          <div
            className="ev-hd"
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? "展开事件流" : "折叠事件流"}
          >
            <span className="ttl">{collapsed ? "▸" : "▾"} 事件流</span>
            <span className="evhd-tabs" onClick={(e) => e.stopPropagation()}>
              {CATS.map((c) => {
                const n =
                  c.types == null
                    ? events.length
                    : events.filter((e) => c.types!.includes(classify(e.tool))).length;
                return (
                  <button
                    key={c.k}
                    className={"evtab" + (cat === c.k ? " on" : "")}
                    onClick={() => setCat(c.k)}
                  >
                    {c.label}
                    {n > 0 && <b>{n}</b>}
                  </button>
                );
              })}
            </span>
            <span className="grow" />
          </div>

          {!collapsed && (
          <div className="ev-list" ref={listRef}>
          {events.length === 0 && (
            <div className="mon-empty">
              还没有工具调用。让 AI 做点什么（比如「打开一个 so」），
              这里会实时出现每一次调用。
            </div>
          )}
          {events
            .map((ev, i) => ({ ev, i }))
            .filter(({ ev }) => {
              if (cat === "all") return true;
              const spec = CATS.find((c) => c.k === cat);
              return spec?.types?.includes(classify(ev.tool)) ?? true;
            })
            .map(({ ev, i }) => {
            const r = renderCall(ev);
            return (
              <div
                key={i}
                className={
                  "sr " + r.type + (sel === i ? " sel" : "") +
                  (r.kind ? " from-" + r.kind : "") +
                  (i === 0 ? " fresh" : "")
                }
                onClick={() => setSel(i)}
                title={`${ev.tool}  ${r.meta}`}
              >
                <span className="sr-t">{clock(ev.ts)}</span>
                <span className={"sr-tp " + r.type}>{LABEL[r.type] ?? r.type}</span>
                <span
                  className="sr-tx"
                  // 内容是 html 片段（工具名/参数/结果分色），已在 renderCall 里 escape
                  dangerouslySetInnerHTML={{ __html: r.html }}
                />
                <span className="sr-m">{r.meta}</span>
              </div>
            );
          })}
          </div>
          )}

          {events.length > 0 && cat !== "all" &&
            events.every((e) => !(CATS.find((c) => c.k === cat)?.types ?? []).includes(classify(e.tool))) && (
              <div className="mon-empty">这个分类下还没有事件</div>
            )}
        </div>

        {/* 详情：这一次调用的完整参数与返回（原型：事件详情） */}
        <div className="mon-detail">
          <div className="mon-hd">事件详情</div>
          {!detail ? (
            <div className="mon-empty">点左边任意一条，看完整参数</div>
          ) : (
            <>
              <div className="det-hd">{detail.tool}</div>
              <div className="det-sub">
                类别 {LABEL[classify(detail.tool)]} · 耗时{" "}
                {detail.ms != null ? `${detail.ms}ms` : "—"}
              </div>
              <div className="det-sec">参数 args</div>
              <pre className="det-json">
                {detail.args && Object.keys(detail.args).length
                  ? JSON.stringify(detail.args, null, 1)
                  : "（无参数）"}
              </pre>
              {detail.summary && (
                <>
                  <div className="det-sec">返回摘要</div>
                  <pre className="det-json">{detail.summary}</pre>
                </>
              )}
              <div className="det-sec">在界面上能做的</div>
              <div className="det-acts">
                <button
                  className="det-act"
                  onClick={() => {
                    const txt = JSON.stringify(detail.args ?? {}, null, 1);
                    void navigator.clipboard?.writeText(txt);
                  }}
                >
                  复制为提问
                </button>
                <button
                  className="det-act"
                  disabled={!detail.summary}
                  onClick={() => {
                    void navigator.clipboard?.writeText(detail.summary ?? "");
                  }}
                >
                  复制原始返回
                </button>
              </div>
              <div className="det-note">
                界面不发起分析。分析在对话侧进行，这里只让你看见并取证。
              </div>
            </>
          )}
        </div>
      </div>

      <Lanes events={events} />
    </div>
  );
}
