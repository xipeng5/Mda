import { useEffect, useRef, useState } from "react";

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
 *   · 类型徽章 —— 按工具名前缀通用归类（102 个工具全覆盖）
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
function renderCall(ev: AiEvent): { type: string; html: string; meta: string } {
  const type = classify(ev.tool);
  const a = ev.args ?? {};
  const shown = SHOW_ARG
    .filter((k) => a[k] !== undefined && a[k] !== null)
    .slice(0, 3)
    .map((k) => `${k}=${String(a[k]).slice(0, 26)}`)
    .join(" ");
  const summary = ev.summary ? ` → ${ev.summary}` : "";
  return {
    type,
    html: `${ev.tool}${shown ? "(" + shown + ")" : ""}${summary}`,
    meta: ev.ms != null ? `${ev.ms}ms` : "",
  };
}

export function RealtimeMonitor({ events, paused, onTogglePause, onClear }: Props) {
  const [sel, setSel] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  /* 新事件进来时，若开着自动滚动就滚到顶部（最新的在最上面） */
  useEffect(() => {
    if (autoScroll && listRef.current) listRef.current.scrollTop = 0;
  }, [events.length, autoScroll]);

  const detail = sel != null ? events[sel] : null;
  const toolCalls = events.length;

  return (
    <div className="monitor">
      {/* 顶部状态条 */}
      <div className="mon-bar">
        <span className={"dot " + (paused ? "" : "live")} />
        <span className="mon-title">{paused ? "已暂停" : "监控中"}</span>
        <span className="mon-count"><b>{events.length}</b> 次工具调用</span>
        <span className="grow" />
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
      </div>

      <div className="mon-body">
        {/* 事件流：主体 */}
        <div className="mon-stream" ref={listRef}>
          {events.length === 0 && (
            <div className="mon-empty">
              还没有工具调用。让 AI 做点什么（比如「打开一个 so」），
              这里会实时出现每一次调用。
            </div>
          )}
          {events.map((ev, i) => {
            const r = renderCall(ev);
            return (
              <div
                key={i}
                className={"sr " + r.type + (sel === i ? " sel" : "")}
                onClick={() => setSel(i)}
                title={`${ev.tool}  ${r.meta}`}
              >
                <span className="sr-t">{clock(ev.ts)}</span>
                <span className={"sr-tp " + r.type}>{LABEL[r.type] ?? r.type}</span>
                <span className="sr-tx">{r.html}</span>
                <span className="sr-m">{r.meta}</span>
              </div>
            );
          })}
        </div>

        {/* 详情：这一次调用的完整参数与返回 */}
        <div className="mon-detail">
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
              <div className="det-sec">为什么这里是只读的</div>
              <div className="det-note">
                工具由 AI 在对话侧调用。界面只负责让你看清「调了什么、传了什么、
                返回什么、花多久」。想追问，在对话里说就行。
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
