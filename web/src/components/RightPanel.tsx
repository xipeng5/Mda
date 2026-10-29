import { useEffect, useRef, useState } from "react";
import type { ModuleData } from "../lib/data";
import { hex } from "../lib/data";

const ROW_H = 22;
const OVERSCAN = 8;

type Props = {
  modules: ModuleData[];
  active: number;
  selected: number[];
  onActivate: (mi: number) => void;
  onSelect: (mi: number, i: number) => void;
  onOpen: (mi: number, i: number) => void;
};

/** 单个 so 的函数面板：1900+ 行必须做虚拟滚动，否则滚动必掉帧。 */
function ModulePanel({
  mod, mi, isActive, sel, onActivate, onSelect, onOpen,
}: {
  mod: ModuleData; mi: number; isActive: boolean; sel: number;
  onActivate: (mi: number) => void; onSelect: (mi: number, i: number) => void;
  onOpen: (mi: number, i: number) => void;
}) {
  const [kw, setKw] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(200);
  const boxRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight));
    ro.observe(el);
    setViewportH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  const lower = kw.trim().toLowerCase();
  const items: number[] = [];
  for (let i = 0; i < mod.funcs.length; i++) {
    const f = mod.funcs[i];
    if (lower && !(f.n.toLowerCase().includes(lower) || hex(f.a).includes(lower))) continue;
    items.push(i);
  }

  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const end = Math.min(items.length, Math.ceil((scrollTop + viewportH) / ROW_H) + OVERSCAN);

  return (
    <div className={"mod" + (isActive ? " act" : "")}>
      <div className="mod-head" onClick={() => onActivate(mi)}>
        <span className="mod-name">{mod.so}</span>
        <span className="mod-n">{mod.funcs.length}</span>
      </div>
      <input className="search" placeholder="过滤…（名称或地址）" value={kw} onChange={(e) => setKw(e.target.value)} />
      <div
        className="rows"
        ref={boxRef}
        onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
      >
        <div style={{ height: items.length * ROW_H, position: "relative" }}>
          {items.slice(start, end).map((i, k) => {
            const f = mod.funcs[i];
            const isSel = i === sel;
            const cls = "row" + (f.e ? " exp" : "") + (isSel ? (isActive ? " sel" : " dimsel") : "");
            return (
              <div
                key={i}
                className={cls}
                style={{ top: (start + k) * ROW_H }}
                title={f.n}
                onClick={() => onSelect(mi, i)}
                onDoubleClick={() => onOpen(mi, i)}
              >
                <span className={"marker" + (f.e ? " s" : "")} />
                <span className="name">{f.n}</span>
                <span className="addr">{hex(f.a)}</span>
                <span className="ref">{f.r || ""}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function RightPanel({ modules, active, selected, onActivate, onSelect, onOpen }: Props) {
  return (
    <aside className="right">
      {modules.map((m, mi) => (
        <ModulePanel
          key={m.so}
          mod={m}
          mi={mi}
          isActive={mi === active}
          sel={selected[mi] ?? -1}
          onActivate={onActivate}
          onSelect={onSelect}
          onOpen={onOpen}
        />
      ))}
    </aside>
  );
}
