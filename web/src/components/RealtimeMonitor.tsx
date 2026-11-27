import { useCallback, useEffect, useRef, useState } from "react";
import { api, copyText, type ApiDynState, type ApiHooks } from "../lib/api";
import { hex } from "../lib/data";
import {
  classifyTool,
  HOOK_NAMES,
  TOOL_COLOR,
  TOOL_LABEL,
} from "../lib/toolMeta";
import { ArmedBar } from "./ArmedBar";
import { DeviceOpsDeck, type OpsSignal } from "./DeviceOpsDeck";

export type AiEvent = {
  /** 单调递增唯一 ID，避免新事件头插导致选中项错位及满 500 条后滚动失效 */
  id?: number;
  tool: string;
  args?: Record<string, unknown>;
  summary?: string;
  ms?: number;
  ts?: string;
  t?: number;
  ok?: boolean;
  result?: string;
  result_truncated?: boolean;
  result_bytes?: number;
};

type Props = {
  events: AiEvent[];
  wsAlive: boolean;
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  mods: { so: string; n: number }[];
  hooksProp?: ApiHooks | null;
  dynState: ApiDynState | null;
  currentAddr: number | null;
  opsSignal: OpsSignal | null;
  onOpenTools: (toolName?: string) => void;
  onJumpToCode: (so: string, addr?: number) => void;
  armedBpCount: number;
  toolsCount?: number;
};

const LIVE_CATS: { k: string; label: string; types: string[] | null }[] = [
  { k: "all", label: "全部", types: null },
  { k: "static", label: "静态", types: ["static", "plugin"] },
  { k: "proc", label: "进程", types: ["proc", "trace"] },
  { k: "bp", label: "断点", types: ["bp", "watch"] },
  { k: "behavior", label: "行为", types: ["behavior"] },
  { k: "mem", label: "内存/运行时", types: ["mem", "runtime"] },
  { k: "vm", label: "VM/UI", types: ["vm", "java", "ui"] },
];

const LANE_SPECS = [
  { k: "static", label: "STATIC", col: "#4c8dff", match: (c: string) => c === "static" || c === "plugin" },
  { k: "proc", label: "PROC", col: "#34d399", match: (c: string) => c === "proc" || c === "trace" },
  { k: "bp", label: "BP", col: "#fb7185", match: (c: string) => c === "bp" || c === "watch" },
  { k: "behavior", label: "HOOK", col: "#a78bfa", match: (c: string) => c === "behavior" || c === "ui" || c === "java" },
  { k: "mem", label: "MEM", col: "#fbbf24", match: (c: string) => c === "mem" || c === "runtime" },
  { k: "vm", label: "VM", col: "#22d3ee", match: (c: string) => c === "vm" },
];

/**
 * 实时工具流与 AI 操控设备监控台（Studio v2 精细版）：
 * - 顶部：方向 2 精细仪器感 AI↔设备运行态动效舞台（可折叠）
 * - 左栏：真实前台进程（/api/foreground + /api/app_processes）+ 已加载 SO 模块 + 行为 Hook 墙
 * - 中栏：纤细 28px 单行高密度日志流 + 紧凑 2×3 活动密度泳道 + 因果 SVG 光弧连线
 * - 右栏：选中事件的完整入参、真实返回值（支持复制）、跳到源码与 137 工具库定位
 * - 底部：ArmedBar 持久待命监控条
 */
export function RealtimeMonitor({
  events,
  wsAlive,
  paused,
  onTogglePause,
  onClear,
  mods,
  hooksProp,
  dynState,
  currentAddr,
  opsSignal,
  onOpenTools,
  onJumpToCode,
  armedBpCount,
  toolsCount = 140,
}: Props) {
  const [deckOpen, setDeckOpen] = useState(true);
  const [cat, setCat] = useState("all");
  const [selId, setSelId] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  const [fgInfo, setFgInfo] = useState<{ package?: string; serial?: string; error?: string } | null>(null);
  const [procs, setProcs] = useState<{ pid: number; name: string; suffix: string; isMain: boolean; inet: number | null; sock: number | null }[]>([]);
  const [procNote, setProcNote] = useState("正在探测前台设备…");
  const [hookPowerSeq, setHookPowerSeq] = useState(0);

  const gridRef = useRef<HTMLDivElement | null>(null);
  const fxLayerRef = useRef<SVGSVGElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const lastArcSigRef = useRef<string>("");

  // 真实拉取前台 App 与进程（只读真机，失败如实展示，不造假）
  useEffect(() => {
    let alive = true;
    void (async () => {
      const fg = await api.foreground();
      if (!alive) return;
      if (!fg || !fg.package) {
        setFgInfo({ serial: fg?.serial, error: fg?.error });
        setProcNote(fg?.error ? String(fg.error).slice(0, 44) : "未检测到前台 App（设备未连或离线）");
        return;
      }
      setFgInfo({ package: fg.package, serial: fg.serial });
      const r = await api.appProcesses({ package: fg.package, serial: fg.serial });
      if (!alive) return;
      if (!r || r.ok === false || !r.processes?.length) {
        setProcNote(r?.error ? String(r.error).slice(0, 44) : "无可见进程");
        return;
      }
      setProcs(
        r.processes.map((p) => ({
          pid: p.pid,
          name: p.name,
          suffix: p.suffix,
          isMain: p.is_main,
          inet: p.inet_conns,
          sock: p.sockets,
        }))
      );
      setProcNote("");
    })();
    return () => { alive = false; };
  }, []);

  const specCat = LIVE_CATS.find((c) => c.k === cat) || LIVE_CATS[0];
  const filtered = specCat.types
    ? events.filter((e) => specCat.types!.includes(classifyTool(e.tool)))
    : events;
  const sel =
    (selId != null ? events.find((e) => e.id === selId) : null) ??
    filtered[0] ??
    events[0] ??
    null;

  // 新事件到达时：绘制因果贝塞尔光弧（左栏目标/模块卡 → 事件流首行）+ 行为监控触发 Hook 墙级联点亮
  useEffect(() => {
    const ev = events[0];
    if (!ev) return;
    const sig = ev.id != null ? `id:${ev.id}` : `${ev.ts}|${ev.tool}|${events.length}`;
    if (sig === lastArcSigRef.current) return;
    lastArcSigRef.current = sig;

    if (/behavior_monitor/.test(ev.tool || "")) {
      setHookPowerSeq((v) => v + 1);
    }

    const grid = gridRef.current;
    const layer = fxLayerRef.current;
    if (!grid || !layer) return;

    const rafId = window.requestAnimationFrame(() => {
      const soArg = (ev.args?.so_name ?? ev.args?.name) as string | undefined;
      const soEl = soArg
        ? grid.querySelector<HTMLElement>(`.v2-tgt-card[data-tso="${CSS.escape(soArg)}"]`)
        : null;
      const tgt = soEl ?? grid.querySelector<HTMLElement>(".v2-tgt-card");
      const row = listRef.current?.querySelector<HTMLElement>(".v2-ev-row");
      if (!tgt || !row) return;

      const gr = grid.getBoundingClientRect();
      const tr = tgt.getBoundingClientRect();
      const rr = row.getBoundingClientRect();
      const x1 = tr.right - gr.left;
      const y1 = tr.top + tr.height / 2 - gr.top;
      const x2 = rr.left - gr.left;
      const y2 = rr.top + rr.height / 2 - gr.top;
      if (x2 <= x1) return;

      const mx = (x1 + x2) / 2;
      const col = TOOL_COLOR[classifyTool(ev.tool)] || "#4c8dff";
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`);
      path.setAttribute("class", "v2-fx-arc");
      path.setAttribute("stroke", col);
      layer.appendChild(path);
      window.setTimeout(() => path.remove(), 900);

      tgt.classList.remove("hit-ping");
      void tgt.offsetWidth;
      tgt.classList.add("hit-ping");
    });

    return () => window.cancelAnimationFrame(rafId);
  }, [events]);

  const exportEvents = useCallback(() => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `mda-events-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }, [events]);

  const onHooks = new Set<string>(hooksProp?.armed ? (hooksProp.on ?? []) : []);

  // 活动密度最近 32 格
  const cap = 32;
  const recent = events.slice(0, cap).reverse();

  // 解析选中事件可跳转的目标 SO + 地址
  const selSo = (sel?.args?.so_name ?? sel?.args?.name) as string | undefined;
  const selAddrRaw = sel?.args?.addr ?? sel?.args?.static_addr;
  const selAddr =
    typeof selAddrRaw === "number"
      ? selAddrRaw
      : typeof selAddrRaw === "string" && /^0x[0-9a-fA-F]+$|^\d+$/.test(selAddrRaw)
        ? parseInt(selAddrRaw, 0)
        : undefined;

  return (
    <div className="v2-live-view">
      {/* 顶部真实运行态控制条 */}
      <div className="v2-live-bar">
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, color: "var(--fg-2)", whiteSpace: "nowrap" }}>
          <span className={"v2-pulse-dot" + (wsAlive ? "" : " off")} />
          <strong style={{ color: "var(--fg)", fontWeight: 600 }}>AI MCP 实时监控</strong>
          <span style={{ color: "var(--fg-3)", fontSize: 11 }}>
            {wsAlive ? "· 监听真实工具调用，触发即驱动设备运行态动效" : "· 正在重连事件流…"}
          </span>
        </span>

        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4, flex: "0 0 auto" }}>
          <button className="v2-fx-btn" onClick={() => setDeckOpen((v) => !v)}>
            {deckOpen ? "收起动效台" : "展开动效台"}
          </button>
          <button className={"v2-fx-btn" + (paused ? " on" : "")} onClick={onTogglePause}>
            {paused ? "继续" : "暂停"}
          </button>
          <button className="v2-fx-btn" onClick={onClear} disabled={!events.length}>
            清空
          </button>
          <button className="v2-fx-btn" onClick={exportEvents} disabled={!events.length}>
            导出
          </button>
          <button className="v2-fx-btn" onClick={() => onOpenTools()}>
            {toolsCount} 工具 →
          </button>
        </div>
      </div>

      {/* 方向 2 精细仪器感 AI↔设备运行态动效舞台 */}
      {deckOpen && (
        <DeviceOpsDeck
          signal={opsSignal}
          mods={mods}
          hooks={hooksProp ?? null}
          dynState={dynState}
          fgInfo={fgInfo}
          currentAddr={currentAddr}
          armedBpCount={armedBpCount}
        />
      )}

      {/* 三栏实时监控主区 */}
      <div className="v2-mon-grid" ref={gridRef}>
        <svg className="v2-fx-layer" ref={fxLayerRef} aria-hidden="true" />

        {/* 左栏：真实前台进程 / 会话模块 / 行为 Hook 墙 */}
        <div className="v2-mon-left">
          <div>
            <div className="v2-mon-hd">
              <span>目标设备与进程</span>
              <span className="mono">{fgInfo?.serial ? "ADB" : "Root"}</span>
            </div>
            {procs.length > 0 ? (
              procs.slice(0, 4).map((p) => (
                <div className="v2-tgt-card" key={p.pid} title={p.name}>
                  <div className="v2-tgt-nm">{p.isMain ? p.name : `…${p.suffix}`}</div>
                  <div className="v2-tgt-sub">
                    <span>pid {p.pid}</span>
                    <span>{p.inet ?? "—"} inet · {p.sock ?? "—"} sock</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="v2-tgt-card">
                <div className="v2-tgt-nm">Android ARM64 设备通道</div>
                <div className="v2-tgt-sub">
                  <span title={procNote}>{procNote || "等待连接"}</span>
                </div>
              </div>
            )}
          </div>

          <div>
            <div className="v2-mon-hd">
              <span>会话已加载 SO</span>
              <span className="mono">{mods.length}</span>
            </div>
            {mods.length > 0 ? (
              mods.map((m, idx) => (
                <div
                  key={m.so}
                  className="v2-tgt-card"
                  data-tso={m.so}
                  onClick={() => onJumpToCode(m.so)}
                >
                  <div className="v2-tgt-nm" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span
                      className="v2-mod-dot"
                      style={{ background: idx % 2 === 0 ? "var(--accent)" : "var(--violet)" }}
                    />
                    {m.so}
                  </div>
                  <div className="v2-tgt-sub">
                    <span>{m.n} 函数</span>
                    <span>点击看代码</span>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ fontSize: 11, color: "var(--fg-3)", padding: "2px 2px" }}>
                尚未加载 .so（动态 Hook/设备操控可直接运行）
              </div>
            )}
          </div>

          <div>
            <div className="v2-mon-hd">
              <span>行为 Hook 墙</span>
              <span className="mono">{onHooks.size}/{HOOK_NAMES.length}</span>
            </div>
            <div className="v2-hook-wall">
              {HOOK_NAMES.map((h, i) => (
                <span
                  key={`${h}-${hookPowerSeq}`}
                  className={
                    "v2-hk-chip" +
                    (onHooks.has(h) ? " on" : "") +
                    (hookPowerSeq > 0 && onHooks.has(h) ? " poweron" : "")
                  }
                  style={hookPowerSeq > 0 ? { animationDelay: `${i * 65}ms` } : undefined}
                >
                  {h}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* 中栏：分类筛选 + 纤细 28px 单行事件流 + 紧凑 2×3 活动密度泳道 */}
        <div className="v2-mon-center">
          <div className="v2-cat-bar">
            {LIVE_CATS.map((c) => {
              const cnt = c.types
                ? events.filter((e) => c.types!.includes(classifyTool(e.tool))).length
                : events.length;
              return (
                <button
                  key={c.k}
                  className={"v2-cat-pill" + (cat === c.k ? " on" : "")}
                  onClick={() => setCat(c.k)}
                >
                  <span>{c.label}</span>
                  {cnt > 0 && <b>{cnt}</b>}
                </button>
              );
            })}
            <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 10, color: "var(--fg-3)" }}>
              {filtered.length} 条
            </span>
          </div>

          <div className="v2-ev-list" ref={listRef}>
            {filtered.map((e, idx) => {
              const tCat = classifyTool(e.tool);
              const col = TOOL_COLOR[tCat] || "#4c8dff";
              const isSel = sel && e.id === sel.id;
              const subText = e.summary || "";
              return (
                <div
                  key={e.id ?? idx}
                  className={
                    "v2-ev-row" +
                    (isSel ? " sel" : "") +
                    (idx === 0 ? " fresh" : "")
                  }
                  style={{ ["--ev-col" as string]: col }}
                  onClick={() => setSelId(e.id ?? null)}
                >
                  <span className="v2-ev-dot" />
                  <span className="v2-ev-ts">{e.ts || "—"}</span>
                  <span className={"v2-badge " + tCat}>{TOOL_LABEL[tCat] || tCat}</span>
                  <span className="v2-ev-tool">{e.tool}</span>
                  <span className="v2-ev-sub" title={subText}>{subText}</span>
                  <span className="v2-ev-ms">{e.ms != null ? `${e.ms}ms` : ""}</span>
                </div>
              );
            })}
            {!filtered.length && (
              <div style={{ padding: 26, textAlign: "center", color: "var(--fg-3)", fontSize: 12 }}>
                {events.length
                  ? "当前分类下暂无调用记录"
                  : "等待 AI 调用 MCP 工具（连接客户端发指令即实时上流并驱动设备运行态动效）"}
              </div>
            )}
          </div>

          <div className="v2-lanes-box">
            <div className="v2-lanes-hd">
              <span>活动密度（6 通道）</span>
              <span className="mono">最近 {recent.length} 次</span>
            </div>
            <div className="v2-lanes-grid">
              {LANE_SPECS.map((ln) => {
                let total = 0;
                events.forEach((e) => { if (ln.match(classifyTool(e.tool))) total++; });
                return (
                  <div className="v2-lane-row" key={ln.k}>
                    <span className="v2-lane-nm">{ln.label}</span>
                    <span className="v2-lane-tr">
                      {Array.from({ length: cap }, (_, i) => {
                        const ev = recent[i];
                        const hit = !!ev && ln.match(classifyTool(ev.tool));
                        return (
                          <i
                            key={i}
                            className={hit ? "lit" : ""}
                            style={{ ["--lane-col" as string]: ln.col, height: hit ? 9 : 2 }}
                          />
                        );
                      })}
                    </span>
                    <span className={"v2-lane-cnt" + (total ? " has" : "")}>{total}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* 右栏：事件入参与真实返回详情 */}
        <div className="v2-live-detail">
          {sel ? (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                <strong className="mono" style={{ fontSize: 13 }}>{sel.tool}</strong>
                <span className={"v2-badge " + classifyTool(sel.tool)}>
                  {TOOL_LABEL[classifyTool(sel.tool)] || classifyTool(sel.tool)}
                </span>
                {sel.ms != null && (
                  <span className="mono" style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--fg-3)" }}>
                    {sel.ms} ms
                  </span>
                )}
              </div>

              <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 10 }}>
                {selSo && mods.some((m) => m.so === selSo) && (
                  <button
                    className="v2-act-btn"
                    onClick={() => onJumpToCode(selSo, selAddr)}
                  >
                    跳到{selAddr != null ? ` ${hex(selAddr)}` : "代码"}
                  </button>
                )}
                <button className="v2-act-btn" onClick={() => onOpenTools(sel.tool)}>
                  在 {toolsCount} 工具库查看
                </button>
                <button
                  className="v2-act-btn"
                  onClick={() => {
                    void copyText(sel.result || sel.summary || "").then((ok) => {
                      if (!ok) return;
                      setCopied(true);
                      window.setTimeout(() => setCopied(false), 1200);
                    });
                  }}
                >
                  {copied ? "已复制" : "复制返回"}
                </button>
              </div>

              <div style={{ fontSize: 11, color: "var(--fg-3)" }}>入参</div>
              <pre>{JSON.stringify(sel.args ?? {}, null, 2)}</pre>

              <div style={{ fontSize: 11, color: "var(--fg-3)", display: "flex", justifyContent: "space-between" }}>
                <span>真实返回</span>
                {sel.result_truncated && (
                  <span style={{ color: "var(--amber)" }}>
                    已截断（原 {sel.result_bytes ?? "?"} B）
                  </span>
                )}
              </div>
              <pre>{sel.result || sel.summary || "（无文本输出）"}</pre>
            </>
          ) : (
            <div style={{ color: "var(--fg-3)", fontSize: 12 }}>
              点击左侧任意一条工具调用查看完整入参与返回内容。
            </div>
          )}
        </div>
      </div>

      {/* 底部持久待命监控条（与真实后端 /api/armed 实时同步） */}
      <ArmedBar />
    </div>
  );
}
