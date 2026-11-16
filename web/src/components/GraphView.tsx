import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiXrefItem } from "../lib/api";

/**
 * 图谱：当前函数在调用图里的位置（左=调用者，右=被调用）。
 *
 * 为什么不用力导向布局：力导向每次跑的坐标都不一样，同一个函数重开
 * 界面位置会跳，人记不住。这里用固定三层布局——调用者 / 当前 / 被调用，
 * 位置本身携带语义。
 */

type Props = {
  so: string;
  addr: number;
  fnName: string;
  onJump: (addr: number) => void;
};

const W = 900;
const H = 460;
const ROW = 34;

export function GraphView({ so, addr, fnName, onJump }: Props) {
  const [callers, setCallers] = useState<ApiXrefItem[]>([]);
  const [callees, setCallees] = useState<ApiXrefItem[]>([]);
  const [err, setErr] = useState("");
  const boxRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ w: W, h: H });

  useEffect(() => {
    void (async () => {
      const r = await api.xrefTree(so, addr, 1);
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
  }, [so, addr]);

  /* 跟随容器尺寸，避免固定 900×460 在大屏上缩成一小块 */
  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      setSize({ w: el.clientWidth || W, h: el.clientHeight || H });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const layout = useMemo(() => {
    const { w, h } = size;
    const cx = w / 2;
    const cy = h / 2;
    const colW = Math.min(190, w * 0.22);
    const leftX = cx - Math.min(w * 0.34, 300);
    const rightX = cx + Math.min(w * 0.34, 300);

    const place = (items: ApiXrefItem[], x: number) => {
      const n = items.length;
      // 超过能放下的行数就只画前 N 个（其余靠计数说明，不硬挤）
      const cap = Math.max(3, Math.floor((h - 80) / ROW));
      const shown = items.slice(0, cap);
      const step = ROW;
      const start = cy - ((shown.length - 1) * step) / 2;
      return {
        shown,
        hidden: n - shown.length,
        pts: shown.map((it, i) => ({ it, x, y: start + i * step })),
      };
    };

    return {
      cx, cy, colW,
      left: place(callers, leftX),
      right: place(callees, rightX),
    };
  }, [callers, callees, size]);

  const { cx, cy, colW, left, right } = layout;

  if (err) {
    return <div className="gv-empty">{err}</div>;
  }

  return (
    <div className="gv-wrap" ref={boxRef}>
      <svg className="gv-svg" width={size.w} height={size.h}>
        {/* 连线：先画，压在节点下面 */}
        {left.pts.map((p, i) => (
          <path
            key={"lc" + i}
            className="gv-edge"
            d={`M${p.x + colW},${p.y} C${(p.x + colW + cx) / 2},${p.y} ${(cx - 70 + cx) / 2},${cy} ${cx - 70},${cy}`}
          />
        ))}
        {right.pts.map((p, i) => (
          <path
            key={"rc" + i}
            className="gv-edge"
            d={`M${cx + 70},${cy} C${(cx + 70 + p.x) / 2},${cy} ${(p.x + cx + 70) / 2},${p.y} ${p.x},${p.y}`}
          />
        ))}

        {/* 左：调用者 */}
        {left.pts.map((p, i) => (
          <g key={"ln" + i} className="gv-node" onClick={() => onJump(parseInt(p.it.addr, 16))}>
            <rect x={p.x} y={p.y - 11} width={colW} height={22} rx={3} />
            <text className="gv-label" x={p.x + 8} y={p.y + 4}>
              {p.it.name.length > 18 ? p.it.name.slice(0, 17) + "…" : p.it.name}
            </text>
            <text className="gv-addr" x={p.x + colW - 6} y={p.y + 4} textAnchor="end">
              {p.it.addr}
            </text>
          </g>
        ))}

        {/* 中：当前函数 */}
        <g className="gv-root">
          <rect x={cx - 70} y={cy - 13} width={140} height={26} rx={4} />
          <text className="gv-rootlabel" x={cx} y={cy + 4} textAnchor="middle">
            {fnName.length > 16 ? fnName.slice(0, 15) + "…" : fnName}
          </text>
        </g>

        {/* 右：被调用 */}
        {right.pts.map((p, i) => (
          <g key={"rn" + i} className="gv-node" onClick={() => onJump(parseInt(p.it.addr, 16))}>
            <rect x={p.x} y={p.y - 11} width={colW} height={22} rx={3} />
            <text className="gv-label" x={p.x + 8} y={p.y + 4}>
              {p.it.name.length > 18 ? p.it.name.slice(0, 17) + "…" : p.it.name}
            </text>
            <text className="gv-addr" x={p.x + colW - 6} y={p.y + 4} textAnchor="end">
              {p.it.addr}
            </text>
          </g>
        ))}
      </svg>

      <div className="gv-legend">
        <span>调用者 {callers.length}</span>
        <span>·</span>
        <span>被调用 {callees.length}</span>
        {(left.hidden > 0 || right.hidden > 0) && (
          <span className="gv-more">
            （另有 {left.hidden + right.hidden} 个未画出，点引用页看全部）
          </span>
        )}
      </div>
    </div>
  );
}
