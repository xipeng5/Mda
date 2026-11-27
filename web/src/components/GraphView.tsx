import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiXrefItem } from "../lib/api";

type Props = {
  so: string;
  addr: number;
  fnName: string;
  onJump: (so: string, addr: number) => void;
  onOpenCode?: (so: string, addr: number) => void;
  onBuildXrefs?: () => void;
};

/**
 * 可缩放、可拖拽跨 SO 调用图谱（左=调用者，中=当前函数，右=被调用）。
 * 支持同模块蓝色实线 + 跨 SO 紫色虚线（如 libbase.so → liblog.so），单击重新聚焦、双击进入 F5 并排源码。
 */
export function GraphView({ so, addr, fnName, onJump, onOpenCode, onBuildXrefs }: Props) {
  const [callers, setCallers] = useState<ApiXrefItem[]>([]);
  const [callees, setCallees] = useState<ApiXrefItem[]>([]);
  const [err, setErr] = useState("");
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const vpRef = useRef<SVGGElement | null>(null);
  const [vp, setVp] = useState({ x: 0, y: 0, scale: 1 });

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await api.xrefTree(so, addr, 1);
      if (!alive) return;
      if (!r || (r as unknown as { error?: string }).error) {
        setErr("引用图未就绪：先建立引用图");
        setCallers([]);
        setCallees([]);
        return;
      }
      setErr("");
      setCallers(r.callers ?? []);
      setCallees(r.callees ?? []);
    })();
    return () => { alive = false; };
  }, [so, addr]);

  const layout = useMemo(() => {
    const NW = 228;
    const NH = 46;
    const ROW = 58;
    const shownL = callers.slice(0, 12);
    const shownR = callees.slice(0, 12);

    const place = (arr: ApiXrefItem[], x: number) => {
      const startY = Math.max(36, 220 - (arr.length * ROW) / 2);
      return arr.map((it, i) => ({
        it,
        x,
        y: startY + i * ROW,
        so: it.so || so,
        cross: !!(it.so && it.so !== so),
      }));
    };

    const left = place(shownL, 32);
    const mid = { x: 336, y: 197, name: fnName, so, addr: "0x" + addr.toString(16) };
    const right = place(shownR, 640);
    return { NW, NH, left, mid, right, hiddenL: callers.length - shownL.length, hiddenR: callees.length - shownR.length };
  }, [callers, callees, fnName, so, addr]);

  const fit = () => {
    const wrap = wrapRef.current;
    const g = vpRef.current;
    if (!wrap || !g) return;
    try {
      const bb = g.getBBox();
      const cw = wrap.clientWidth || 780;
      const ch = wrap.clientHeight || 440;
      if (bb.width > 0 && bb.height > 0) {
        const pad = 40;
        const scale = Math.max(0.45, Math.min(1.08, Math.min((cw - pad * 2) / bb.width, (ch - pad * 2) / bb.height)));
        const x = Math.round((cw - bb.width * scale) / 2 - bb.x * scale);
        const y = Math.round((ch - bb.height * scale) / 2 - bb.y * scale);
        setVp({ x, y, scale });
      }
    } catch {
      /* 忽略不可见 SVG getBBox 异常 */
    }
  };

  useEffect(() => {
    const id = window.requestAnimationFrame(fit);
    return () => window.cancelAnimationFrame(id);
  }, [layout]);

  const startDrag = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".xnode,.v2-canvas-tools")) return;
    const sx = e.clientX;
    const sy = e.clientY;
    const ox = vp.x;
    const oy = vp.y;
    const onMove = (ev: MouseEvent) => {
      setVp((cur) => ({ ...cur, x: ox + (ev.clientX - sx), y: oy + (ev.clientY - sy) }));
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  if (err) {
    return (
      <div style={{ flex: 1, display: "grid", placeItems: "center", color: "var(--fg-3)" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ marginBottom: 10 }}>{err}</div>
          {onBuildXrefs && (
            <button className="v2-top-btn pri" onClick={onBuildXrefs}>
              立即建立引用图
            </button>
          )}
        </div>
      </div>
    );
  }

  const { NW, NH, left, mid, right } = layout;

  return (
    <div
      className="v2-canvas-view"
      ref={wrapRef}
      onMouseDown={startDrag}
      onWheel={(e) => {
        e.preventDefault();
        const f = e.deltaY < 0 ? 1.12 : 0.89;
        setVp((c) => ({ ...c, scale: Math.max(0.35, Math.min(2.2, c.scale * f)) }));
      }}
    >
      <div className="v2-canvas-tools">
        <button className="v2-icon-btn" title="放大" onClick={() => setVp((c) => ({ ...c, scale: Math.min(2.2, c.scale * 1.18) }))}>
          <svg className="ic" viewBox="0 0 16 16"><path d="M8 3.5v9M3.5 8h9" /></svg>
        </button>
        <button className="v2-icon-btn" title="缩小" onClick={() => setVp((c) => ({ ...c, scale: Math.max(0.35, c.scale * 0.84) }))}>
          <svg className="ic" viewBox="0 0 16 16"><path d="M3.5 8h9" /></svg>
        </button>
        <button className="v2-icon-btn" title="重置居中" onClick={fit}>
          <svg className="ic" viewBox="0 0 16 16"><path d="M3 8a5 5 0 1 0 1.5-3.5L3 6m0-3v3h3" /></svg>
        </button>
      </div>

      <div className="v2-canvas-legend">
        <span><i className="v2-leg-dot" style={{ background: "var(--accent)" }} />同模块调用</span>
        <span><i className="v2-leg-dot" style={{ background: "var(--violet)" }} />跨 SO 调用边</span>
        <span style={{ color: "var(--fg-3)" }}>
          调用者 {callers.length} · 被调用 {callees.length}
          {layout.hiddenL + layout.hiddenR > 0 ? `（另有 ${layout.hiddenL + layout.hiddenR} 个在引用页查看）` : ""} · 单击聚焦，双击进代码
        </span>
      </div>

      <svg width="100%" height="100%" style={{ display: "block" }}>
        <defs>
          <marker id="v2GArrBlue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0 1L8 5L0 9z" fill="var(--accent)" />
          </marker>
          <marker id="v2GArrViolet" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0 1L8 5L0 9z" fill="var(--violet)" />
          </marker>
        </defs>
        <g ref={vpRef} transform={`translate(${vp.x},${vp.y}) scale(${vp.scale})`}>
          {left.map((p, i) => {
            const x1 = p.x + NW;
            const y1 = p.y + NH / 2;
            const x2 = mid.x;
            const y2 = mid.y + NH / 2;
            const mx = (x1 + x2) / 2;
            return (
              <path
                key={"le" + i}
                d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={p.cross ? "var(--violet)" : "var(--accent)"}
                strokeWidth={p.cross ? 1.9 : 1.4}
                strokeDasharray={p.cross ? "6 3" : undefined}
                strokeOpacity="0.85"
                markerEnd={p.cross ? "url(#v2GArrViolet)" : "url(#v2GArrBlue)"}
              />
            );
          })}
          {right.map((p, i) => {
            const x1 = mid.x + NW;
            const y1 = mid.y + NH / 2;
            const x2 = p.x;
            const y2 = p.y + NH / 2;
            const mx = (x1 + x2) / 2;
            return (
              <path
                key={"re" + i}
                d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={p.cross ? "var(--violet)" : "var(--accent)"}
                strokeWidth={p.cross ? 1.9 : 1.4}
                strokeDasharray={p.cross ? "6 3" : undefined}
                strokeOpacity="0.85"
                markerEnd={p.cross ? "url(#v2GArrViolet)" : "url(#v2GArrBlue)"}
              />
            );
          })}

          {left.map((p, i) => (
            <g
              key={"ln" + i}
              className={"xnode" + (p.cross ? " cross" : "")}
              onClick={() => onJump(p.so, parseInt(p.it.addr, 16))}
              onDoubleClick={() => (onOpenCode || onJump)(p.so, parseInt(p.it.addr, 16))}
            >
              <title>{`${p.so}!${p.it.name} @ ${p.it.addr}`}</title>
              <rect x={p.x} y={p.y} width={NW} height={NH} />
              <circle cx={p.x + 13} cy={p.y + 17} r="3.5" fill={p.cross ? "var(--violet)" : "var(--accent)"} />
              <text x={p.x + 23} y={p.y + 20} fill="var(--fg)" fontFamily="var(--mono)" fontSize="11" fontWeight="600">
                {p.it.name.length > 24 ? p.it.name.slice(0, 23) + "…" : p.it.name}
              </text>
              <text x={p.x + 23} y={p.y + 36} fill="var(--fg-3)" fontFamily="var(--mono)" fontSize="10">
                {p.so} · {p.it.addr}
              </text>
            </g>
          ))}

          <g
            className="xnode center"
            onDoubleClick={() => onOpenCode?.(mid.so, addr)}
          >
            <title>{`${mid.so}!${mid.name} @ ${mid.addr}`}</title>
            <rect x={mid.x} y={mid.y} width={NW} height={NH} />
            <circle cx={mid.x + 13} cy={mid.y + 17} r="3.5" fill="var(--accent)" />
            <text x={mid.x + 23} y={mid.y + 20} fill="var(--fg)" fontFamily="var(--mono)" fontSize="11.5" fontWeight="700">
              {mid.name.length > 24 ? mid.name.slice(0, 23) + "…" : mid.name}
            </text>
            <text x={mid.x + 23} y={mid.y + 36} fill="var(--fg-3)" fontFamily="var(--mono)" fontSize="10">
              {mid.so} · {mid.addr}
            </text>
          </g>

          {right.map((p, i) => (
            <g
              key={"rn" + i}
              className={"xnode" + (p.cross ? " cross" : "")}
              onClick={() => onJump(p.so, parseInt(p.it.addr, 16))}
              onDoubleClick={() => (onOpenCode || onJump)(p.so, parseInt(p.it.addr, 16))}
            >
              <title>{`${p.so}!${p.it.name} @ ${p.it.addr}`}</title>
              <rect x={p.x} y={p.y} width={NW} height={NH} />
              <circle cx={p.x + 13} cy={p.y + 17} r="3.5" fill={p.cross ? "var(--violet)" : "var(--accent)"} />
              <text x={p.x + 23} y={p.y + 20} fill="var(--fg)" fontFamily="var(--mono)" fontSize="11" fontWeight="600">
                {p.it.name.length > 24 ? p.it.name.slice(0, 23) + "…" : p.it.name}
              </text>
              <text x={p.x + 23} y={p.y + 36} fill="var(--fg-3)" fontFamily="var(--mono)" fontSize="10">
                {p.so} · {p.it.addr}
              </text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  );
}
