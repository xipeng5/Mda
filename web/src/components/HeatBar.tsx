import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiHeatmap } from "../lib/api";

/**
 * 热力条 —— 替换原来的球体。
 *
 * 为什么换：球体的位置是个哈希，没有任何语义；只有引用数被编码了，
 * 等于把右侧函数列表又画了一遍。而 131K 函数的模块会变成一团噪声。
 *
 * 热力条是**一维**的：位置 = 真实地址，颜色 = 真实引用密度。
 * 每一格都能对上一个地址区间，鼠标移上去能看到落在哪个区间。
 */

type Props = {
  so: string;
  onPickAddr?: (addr: number) => void;
};

export function HeatBar({ so, onPickAddr }: Props) {
  const [data, setData] = useState<ApiHeatmap | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!so) return;
    void (async () => {
      const r = await api.heatmap(so);
      if (r) setData(r);
    })();
  }, [so]);

  const maxRefs = data?.max_refs ?? 0;

  /** 引用数 → 颜色档（对数尺度，避免个别热点把整条压平） */
  const colorOf = (v: number) => {
    if (!maxRefs || v <= 0) return "var(--panel2)";
    const t = Math.log2(1 + v) / Math.log2(1 + maxRefs);
    // 用 design token：深色主题下自动跟随，不用各写一套
    if (t > 0.78) return "var(--hot4)";
    if (t > 0.52) return "var(--hot3)";
    if (t > 0.26) return "var(--hot2)";
    return "var(--hot1)";
  };

  const buckets = data?.buckets ?? [];

  /** 鼠标位置 → 地址区间（真实换算，不是估算） */
  const addrAt = useMemo(() => {
    if (!data || !buckets.length) return null;
    const lo = parseInt(data.lo, 16);
    const hi = parseInt(data.hi, 16);
    const span = Math.max(1, hi - lo);
    return (i: number) => {
      const a = lo + Math.floor((span * i) / buckets.length);
      const b = lo + Math.floor((span * (i + 1)) / buckets.length);
      return [a, b] as const;
    };
  }, [data, buckets.length]);

  if (!so) {
    return <div className="heat-empty">打开一个 so，这里会显示引用密度热力条</div>;
  }
  if (!data) {
    return <div className="heat-empty">正在计算引用密度…</div>;
  }

  return (
    <div className="heatwrap">
      <div className="heat" ref={boxRef}>
        {buckets.map((v, i) => (
          <span
            key={i}
            className="hseg"
            style={{ background: colorOf(v), opacity: hover === i ? 1 : 0.92 }}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
            onClick={() => {
              if (!addrAt) return;
              const [a] = addrAt(i);
              onPickAddr?.(a);
            }}
            title={
              addrAt
                ? `0x${addrAt(i)[0].toString(16)} – 0x${addrAt(i)[1].toString(16)} · 引用 ${v}`
                : `引用 ${v}`
            }
          />
        ))}
      </div>
      <div className="heat-legend">
        <span><i style={{ background: "var(--hot4)" }} />最热</span>
        <span><i style={{ background: "var(--hot3)" }} />热</span>
        <span><i style={{ background: "var(--hot2)" }} />温</span>
        <span><i style={{ background: "var(--hot1)" }} />冷</span>
        <span className="r">
          {data.functions} 个函数 · {data.lo} → {data.hi}
          {hover != null && addrAt ? ` · 指向 0x${addrAt(hover)[0].toString(16)}` : ""}
        </span>
      </div>
    </div>
  );
}
