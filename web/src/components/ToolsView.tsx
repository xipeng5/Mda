import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiTool } from "../lib/api";

/**
 * 工具页：全部 MCP 工具的可查清单。
 *
 * 数据直接读服务端注册表（/api/tools）——不复用前端副本，
 * 因为工具是会增加的（这一轮就多了 5 个），任何写死的清单都会过期。
 *
 * 这里只读：工具由 AI 在对话侧调用，界面负责让人看清
 * 「有哪些工具、各自干什么、这一会话调过几次」。
 */

/** 按工具名前缀归类——通用规则，102 个工具全覆盖，不写死具体工具 */
export function classify(tool: string): string {
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

type Props = { counts: Record<string, number> };

export function ToolsView({ counts }: Props) {
  const [tools, setTools] = useState<ApiTool[]>([]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const prevCounts = useRef<Record<string, number>>({});
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    void (async () => {
      const r = await api.tools();
      if (!r) {
        setErr("读不到工具清单：后端未连接");
        return;
      }
      setTools(r.tools ?? []);
    })();
  }, []);

  // 计数变了说明刚被调用过 → 那一行脉冲，并自动定位到可视区
  useEffect(() => {
    for (const [tool, n] of Object.entries(counts)) {
      if ((prevCounts.current[tool] ?? 0) !== n) {
        prevCounts.current = { ...counts };
        setBusy(tool);
        const t = window.setTimeout(() => setBusy(null), 1200);
        return () => window.clearTimeout(t);
      }
    }
    prevCounts.current = { ...counts };
  }, [counts]);

  // 自动定位：被调用的那行若不在可视区，平滑滚到中间
  useEffect(() => {
    if (!busy) return;
    const list = listRef.current;
    if (!list) return;
    const row = [...list.querySelectorAll<HTMLElement>(".tvrow")]
      .find((el) => el.dataset.tool === busy);
    if (!row) return;                       // 被搜索过滤掉了就不滚
    // 用 offsetTop 直接算落点并**立即赋值**：
    //   · getBoundingClientRect 在平滑滚动进行中读到的位置不可靠，
    //     用"中心差 + scrollTop"算落点会算错（实测滚完行仍在视口外）
    //   · smooth 动画期间还会被下一次 busy 打断
    // 即时赋值一次到位，行为确定。
    const top = row.offsetTop - (list.clientHeight - row.offsetHeight) / 2;
    const clamped = Math.max(0, Math.min(top, list.scrollHeight - list.clientHeight));
    if (Math.abs(list.scrollTop - clamped) > 2) list.scrollTop = clamped;
  }, [busy]);

  const rows = useMemo(() => {
    const kw = q.trim().toLowerCase();
    if (!kw) return tools;
    return tools.filter(
      (t) =>
        t.name.toLowerCase().includes(kw) ||
        (t.desc ?? "").toLowerCase().includes(kw) ||
        t.params.some((p) => p.toLowerCase().includes(kw))
    );
  }, [tools, q]);

  const detail = sel ? tools.find((t) => t.name === sel) : null;

  return (
    <div className="tools-view">
      <div className="tv-bar">
        <input
          className="tv-search"
          placeholder="搜工具名 / 参数 / 描述…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <span className="tv-count">
          {rows.length} 个{q ? ` / ${tools.length}` : ""}
        </span>
        {err && <span className="tv-err">{err}</span>}
      </div>

      <div className="tv-body">
        <div className="tv-list" ref={listRef}>
          {rows.map((t) => {
            const type = classify(t.name);
            const n = counts[t.name] ?? 0;
            return (
              <div
                key={t.name}
                data-tool={t.name}
                className={
                  "tvrow" + (sel === t.name ? " sel" : "") +
                  (busy === t.name ? " busy" : "")
                }
                onClick={() => setSel(t.name)}
              >
                <span className="tv-n">{t.name}</span>
                <span className={"tv-tp " + type}>{LABEL[type] ?? type}</span>
                <span className="tv-d">{t.desc}</span>
                <span className={"tv-c" + (n ? " has" : "")}>{n ? `${n} 次` : "—"}</span>
              </div>
            );
          })}
          {!rows.length && (
            <div className="tv-empty">
              {tools.length ? "没有匹配的工具" : "正在读取工具清单…"}
            </div>
          )}
        </div>

        <div className="tv-detail">
          {!detail ? (
            <div className="tv-empty">点左边任意一个工具</div>
          ) : (
            <>
              <div className="tvd-hd">{detail.name}</div>
              <div className="tvd-sec">类别</div>
              <div className="tvd-p">
                <span className={"tv-tp " + classify(detail.name)}>
                  {LABEL[classify(detail.name)]}
                </span>
                <span style={{ marginLeft: 8, color: "var(--fg3)", fontSize: 11 }}>
                  本会话调用 {counts[detail.name] ?? 0} 次
                </span>
              </div>

              <div className="tvd-sec">说明</div>
              <div className="tvd-desc">{detail.desc || "（无描述）"}</div>

              <div className="tvd-sec">参数（{detail.params.length}）</div>
              <div className="tvd-params">
                {detail.params.length ? (
                  detail.params.map((p) => (
                    <span
                      key={p}
                      className={"tvd-par" + (detail.required.includes(p) ? " req" : "")}
                      title={detail.required.includes(p) ? "必填" : "可选"}
                    >
                      {p}
                    </span>
                  ))
                ) : (
                  <span style={{ fontSize: 11, color: "var(--fg3)" }}>无参数</span>
                )}
              </div>

              <div className="tvd-sec">为什么这里是只读的</div>
              <div className="tvd-desc">
                工具由 AI 在对话侧调用。界面只负责让你看清「有哪些工具、
                各自干什么、这一会话调过几次」。想用某个工具，在对话里说就行。
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
