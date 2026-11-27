import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiTool } from "../lib/api";
import { classifyTool, isReadbackTool, LAYER_NAMES, TOOL_LABEL, toolToLayer } from "../lib/toolMeta";

export { classifyTool as classify } from "../lib/toolMeta";

const TOOLS_CATS = [
  { k: "all", label: "全部" },
  { k: "static", label: "静态" },
  { k: "bp", label: "断点" },
  { k: "proc", label: "进程" },
  { k: "vm", label: "VM" },
  { k: "mem", label: "内存" },
  { k: "behavior", label: "行为" },
  { k: "runtime", label: "运行时" },
  { k: "trace", label: "轨迹" },
  { k: "java", label: "Java" },
  { k: "watch", label: "观察点" },
  { k: "ui", label: "UI" },
];

type Props = {
  counts: Record<string, number>;
  /** 外部预选工具（如从工具流详情点击「在 137 工具库查看」或 ⌘K 搜索进入） */
  initialSelected?: string | null;
};

/**
 * 全部 137 个真实 MCP 工具目录：
 * 直接同步自后端注册表 /api/tools，支持关键词搜索、12 分类过滤、实时调用计数脉冲与自动定位。
 */
export function ToolsView({ counts, initialSelected }: Props) {
  const [tools, setTools] = useState<ApiTool[]>([]);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("all");
  const [sel, setSel] = useState<string | null>(initialSelected ?? null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const prevCounts = useRef<Record<string, number>>({});
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (initialSelected) setSel(initialSelected);
  }, [initialSelected]);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await api.tools();
      if (!alive) return;
      if (!r) {
        setErr("读不到工具清单：后端未连接");
        return;
      }
      const list = r.tools ?? [];
      setTools(list);
      setSel((cur) => cur || list[0]?.name || null);
    })();
    return () => { alive = false; };
  }, []);

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

  useEffect(() => {
    if (!busy) return;
    const list = listRef.current;
    if (!list) return;
    const row = [...list.querySelectorAll<HTMLElement>(".v2-tv-row")].find(
      (el) => el.dataset.tool === busy
    );
    if (!row) return;
    const top = row.offsetTop - (list.clientHeight - row.offsetHeight) / 2;
    list.scrollTop = Math.max(0, Math.min(top, list.scrollHeight - list.clientHeight));
  }, [busy]);

  const rows = useMemo(() => {
    const kw = q.trim().toLowerCase();
    return tools.filter((t) => {
      const c = classifyTool(t.name);
      if (cat !== "all" && c !== cat) return false;
      if (!kw) return true;
      return (
        t.name.toLowerCase().includes(kw) ||
        (t.desc ?? "").toLowerCase().includes(kw) ||
        t.params.some((p) => p.toLowerCase().includes(kw))
      );
    });
  }, [tools, q, cat]);

  const detail = sel ? tools.find((t) => t.name === sel) ?? rows[0] ?? null : rows[0] ?? null;
  const dCat = detail ? classifyTool(detail.name) : "static";

  return (
    <div className="v2-tools-view">
      <div className="v2-tv-bar">
        <input
          className="v2-tv-search"
          placeholder="搜工具名 / 参数 / 描述…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <span className="mono" style={{ fontSize: 11, color: "var(--fg-2)", whiteSpace: "nowrap" }}>
          {rows.length} 个{q || cat !== "all" ? ` / ${tools.length}` : ""}
        </span>
        <div className="v2-sep" />
        {TOOLS_CATS.map((c) => {
          const n =
            c.k === "all"
              ? tools.length
              : tools.filter((t) => classifyTool(t.name) === c.k).length;
          return (
            <button
              key={c.k}
              className={"v2-cat-pill" + (cat === c.k ? " on" : "")}
              onClick={() => setCat(c.k)}
            >
              <span>{c.label}</span>
              <b>{n}</b>
            </button>
          );
        })}
        {err && <span style={{ color: "var(--rose)", fontSize: 11 }}>{err}</span>}
      </div>

      <div className="v2-tv-body">
        <div className="v2-tv-list" ref={listRef}>
          {rows.map((t) => {
            const c = classifyTool(t.name);
            const n = counts[t.name] ?? 0;
            return (
              <div
                key={t.name}
                data-tool={t.name}
                className={
                  "v2-tv-row" +
                  (detail?.name === t.name ? " sel" : "") +
                  (busy === t.name ? " busy" : "")
                }
                onClick={() => setSel(t.name)}
              >
                <span className="v2-tv-name" title={t.name}>{t.name}</span>
                <span className={"v2-badge " + c} style={{ textAlign: "center" }}>
                  {TOOL_LABEL[c] ?? c}
                </span>
                <span className="v2-tv-desc" title={t.desc}>{t.desc}</span>
                <span className={"v2-tv-cnt" + (n ? " has" : "")}>
                  {n ? `${n} 次` : "—"}
                </span>
              </div>
            );
          })}
          {!rows.length && (
            <div style={{ padding: 28, textAlign: "center", color: "var(--fg-3)" }}>
              {tools.length ? "没有匹配的工具" : "正在读取后端工具注册表…"}
            </div>
          )}
        </div>

        <div className="v2-tv-detail">
          {!detail ? (
            <div style={{ color: "var(--fg-3)" }}>点左边任意一个工具查看参数与说明</div>
          ) : (
            <>
              <div className="v2-tvd-hd">{detail.name}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
                <span className={"v2-badge " + dCat}>{TOOL_LABEL[dCat] ?? dCat}</span>
                <span style={{ fontSize: 11.5, color: "var(--fg-3)" }}>
                  本会话调用 <b className="mono" style={{ color: "var(--fg)" }}>{counts[detail.name] ?? 0}</b> 次
                </span>
              </div>

              <div className="v2-tvd-sec">功能说明</div>
              <div className="v2-tvd-desc">{detail.desc || "（无描述）"}</div>

              <div className="v2-tvd-sec">参数列表（{detail.params.length}）</div>
              <div className="v2-tvd-params">
                {detail.params.length ? (
                  detail.params.map((p) => {
                    const req = detail.required.includes(p);
                    return (
                      <span
                        key={p}
                        className={"v2-tvd-par" + (req ? " req" : "")}
                        title={req ? "必填参数" : "可选参数"}
                      >
                        {p}{req ? " *" : ""}
                      </span>
                    );
                  })
                ) : (
                  <span style={{ fontSize: 11.5, color: "var(--fg-3)" }}>无参数</span>
                )}
              </div>

              <div className="v2-tvd-sec">目标子系统通道</div>
              <div className="v2-tvd-desc">
                {LAYER_NAMES[toolToLayer(detail.name, dCat)]}（
                {isReadbackTool(detail.name) ? "双向数据回传通道" : "单向下发控制通道"}）
              </div>

              <div className="v2-tvd-sec">说明</div>
              <div className="v2-tvd-desc">
                全部 {tools.length} 个工具直接读自 MDA 后端注册表（/api/tools）。工具由 AI 在对话侧调用，界面负责实时展示调用流、计数脉冲与设备运行态动效。
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
