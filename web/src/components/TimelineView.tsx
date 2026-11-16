import { useMemo } from "react";
import type { AiEvent } from "./RealtimeMonitor";

/**
 * 时间线：把工具调用按真实耗时画成甘特条。
 *
 * 位置 = 调用发生的时刻，长度 = 这次调用真实花了多久。
 * 好处是一眼看出「哪次调用卡住了」——事件流里只有数字，
 * 这里能直接看到它有多长。
 *
 * 只有真实测到 ms 的才画长度；ms 缺失的用最小刻度并标注，
 * 不编造耗时。
 */

type Props = { events: AiEvent[] };

const CHART_H = 300;
const MIN_PX = 3;

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

export function TimelineView({ events }: Props) {
  const rows = useMemo(() => {
    // 事件流是「最新在前」，时间线要「最早在上」
    const chrono = [...events].reverse().slice(-60);
    const withMs = chrono.filter((e) => typeof e.ms === "number" && e.ms > 0);
    const maxMs = Math.max(1, ...withMs.map((e) => e.ms as number));

    return chrono.map((e, i) => {
      const ms = typeof e.ms === "number" ? e.ms : null;
      // 用平方根做视觉压缩：几毫秒和几秒都能看清，又不至于全被长条压平
      const ratio = ms && ms > 0 ? Math.sqrt(ms) / Math.sqrt(maxMs) : 0;
      const w = Math.max(MIN_PX, Math.round(ratio * 260));
      return { e, i, ms, w, type: classify(e.tool) };
    });
  }, [events]);

  const slowest = useMemo(() => {
    let best: { tool: string; ms: number } | null = null;
    for (const e of events) {
      if (typeof e.ms === "number" && (!best || e.ms > best.ms)) {
        best = { tool: e.tool, ms: e.ms };
      }
    }
    return best;
  }, [events]);

  if (!rows.length) {
    return (
      <div className="tv-empty" style={{ padding: "18px 14px", lineHeight: 1.8 }}>
        还没有工具调用。让 AI 做点什么，这里会按真实耗时画出时间线。
        <br />
        位置 = 调用时刻，长度 = 这次花了多久。
      </div>
    );
  }

  return (
    <div className="tl-view">
      <div className="tl-bar">
        <span>最近 {rows.length} 次调用</span>
        {slowest && (
          <>
            <span className="pv-sep">·</span>
            <span>
              最慢 <b className="tl-slow">{slowest.tool}</b> {slowest.ms.toFixed(1)}ms
            </span>
          </>
        )}
        <span className="pv-sep">·</span>
        <span className="tl-note">长度按真实耗时（√ 压缩，避免长条压平短条）</span>
      </div>

      <div className="tl-rows">
        {rows.map((r) => (
          <div className="tl-row" key={r.i}>
            <span className="tl-time">{r.e.ts?.slice(0, 8) ?? ""}</span>
            <span className="tl-tool" title={r.e.tool}>
              {r.e.tool}
            </span>
            <span className="tl-barwrap">
              <span
                className={"tl-b " + r.type}
                style={{ width: r.w }}
                title={r.ms != null ? `${r.ms.toFixed(1)}ms` : "耗时未测到"}
              />
            </span>
            <span className={"tl-ms" + (r.ms != null && r.ms > 1000 ? " slow" : "")}>
              {r.ms != null ? `${r.ms.toFixed(1)}ms` : "—"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
