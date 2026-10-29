import { useEffect, useRef, useState } from "react";
import type { ApiInsn } from "../lib/api";
import { hex } from "../lib/data";

type Props = {
  open: boolean;
  fnName: string;
  fnAddr: number;
  size: number;
  refs: number;
  isExport: boolean;
  rows: ApiInsn[];
  onClose: () => void;
};

const ROW_H = 20;          // 单行高度（与 CSS .irow 对齐）
const OVERSCAN = 12;       // 上下多渲染几行，滚动时不露白

/** 代码浮出层：球缩到右上角后，反汇编铺满舞台。
 *  12k+ 条指令必须虚拟滚动，否则一次插入上万 DOM 节点会卡死。 */
export function CodeOverlay({ open, fnName, fnAddr, size, refs, isExport, rows, onClose }: Props) {
  const boxRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH] = useState(600);

  useEffect(() => {
    const el = boxRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    setViewH(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  useEffect(() => { setScrollTop(0); }, [rows]);
  useEffect(() => { if (boxRef.current) boxRef.current.scrollTop = 0; }, [rows]);

  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const end = Math.min(rows.length, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);

  return (
    <div className={"code" + (open ? " on" : "")}>
      <div className="code-head">
        <span className="fn" title={fnName}>{fnName}</span>
        <span className="meta">
          {hex(fnAddr)} · {size}B · 引用 {refs} · {isExport ? "导出" : "内部"}
        </span>
        <span className="grow" />
        <span className="meta" style={{ cursor: "pointer" }} onClick={onClose}>Esc 返回</span>
      </div>
      <div className="code-body" ref={boxRef} onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}>
        {rows.length === 0 ? (
          <div className="empty">没有反汇编结果（函数不存在或后端未连）。</div>
        ) : (
          <div style={{ height: rows.length * ROW_H, position: "relative" }}>
            {rows.slice(start, end).map((r, k) => (
              <div
                key={r.addr}
                className={"irow" + (r.is_call ? " call" : "") + (r.is_ret ? " ret" : "")}
                style={{ position: "absolute", left: 0, right: 0, top: (start + k) * ROW_H, height: ROW_H }}
              >
                <span className="a">{hex(r.addr)}</span>
                <span className="b">{r.bytes}</span>
                <span className="t">{r.text}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
