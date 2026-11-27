import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ApiCfgBlock, type ApiInsn } from "../lib/api";
import { hex } from "../lib/data";

type Props = {
  so: string;
  fnAddr: number;
  fnName: string;
  fnSize: number;
  isExport: boolean;
  mode: "disasm" | "split" | "cfg";
  selInsnAddr: number | null;
  onSelectInsn: (addr: number) => void;
  onJump: (so: string, addr: number) => void;
  onSwitchMode: (mode: "disasm" | "split" | "cfg") => void;
  comments: Record<string, string>;
  bpMarks: Set<string>;
  onToggleBpMark: (so: string, addr: number) => void;
  aiHitSeq: number;
  aiHitAddr: number | null;
};

/** 助记符语义着色分类 */
function classifyMnem(mnem: string): string {
  const m = mnem.toLowerCase();
  if (m === "bl" || m === "blr") return "k-call";
  if (m === "ret" || m === "retaa" || m === "retab") return "k-ret";
  if (m === "b" || m === "br" || m.startsWith("b.") || m.startsWith("cb") || m.startsWith("tb")) {
    return "k-branch";
  }
  if (m.startsWith("ld") || m.startsWith("st") || m === "adrp" || m === "adr") return "k-mem";
  return "";
}

/** 格式化 4 字节 hex 为带空格阅读形态 */
function formatBytes(raw: string): string {
  if (!raw || raw.includes(" ")) return raw;
  return raw.replace(/(.{2})(?=.)/g, "$1 ");
}

/** 单遍渲染操作数高亮（避免二次正则污染属性） */
function renderOperands(
  ops: string,
  jumpAddr: number | undefined,
  jumpSo: string | undefined,
  curSo: string,
  onJump: (so: string, addr: number) => void
) {
  const re = /(#-?0x[0-9a-fA-F]+|#-?\d+|\b(?:[xwsdqv]\d+|sp|fp|lr|xzr|wzr)\b)/g;
  const parts: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(ops)) !== null) {
    if (m.index > last) parts.push(ops.slice(last, m.index));
    const tok = m[0];
    if (tok[0] === "#") {
      if (jumpAddr !== undefined && tok.includes("0x")) {
        parts.push(
          <span
            key={k++}
            className="tok-target"
            onClick={(e) => {
              e.stopPropagation();
              onJump(jumpSo || curSo, jumpAddr);
            }}
          >
            {tok}
          </span>
        );
      } else {
        parts.push(<span key={k++} className="tok-imm">{tok}</span>);
      }
    } else {
      parts.push(<span key={k++} className="tok-reg">{tok}</span>);
    }
    last = re.lastIndex;
  }
  if (last < ops.length) parts.push(ops.slice(last));
  return parts;
}

/** 单遍伪 C 语法高亮（关键字 / 类型 / 字符串 / 函数调用 / 标签 / 常量 / 注释） */
function renderPseudoTokens(code: string) {
  const re =
    /(\/\*[\s\S]*?\*\/|\/\/.*$|"(?:\\.|[^"\\])*"|\b(?:void|if|else|return|goto|while|for|switch|case|break|continue|int64_t|uint64_t|int32_t|uint32_t|int16_t|uint16_t|int8_t|uint8_t|uint128_t|int|char|bool)\b|\bL_[0-9a-fA-F]+\b|\b[A-Za-z_][\w!]*\s*(?=\()|\b0x[0-9a-fA-F]+\b|\b-?\d+\b)/g;
  const parts: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(code)) !== null) {
    if (m.index > last) parts.push(code.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("//") || tok.startsWith("/*")) {
      parts.push(<span key={k++} className="pc-cmt">{tok}</span>);
    } else if (tok.startsWith('"')) {
      parts.push(<span key={k++} className="pc-str">{tok}</span>);
    } else if (tok.startsWith("L_")) {
      parts.push(<span key={k++} className="pc-lbl">{tok}</span>);
    } else if (/^(?:0x|-?\d)/.test(tok)) {
      parts.push(<span key={k++} className="pc-num">{tok}</span>);
    } else if (code[re.lastIndex] === "(" && !/^(?:if|else|while|for|switch|return)$/.test(tok.trim())) {
      parts.push(<span key={k++} className="pc-fn">{tok}</span>);
    } else {
      parts.push(<span key={k++} className="pc-kw">{tok}</span>);
    }
    last = re.lastIndex;
  }
  if (last < code.length) parts.push(code.slice(last));
  return parts;
}

/**
 * 核心代码工作台：
 * - disasm（1）：全宽 ARM64 语义高亮反汇编（含机器码字节、可点击跨 SO 跳转、行内字符串/符号/用户注释、行内断点圆点）
 * - split（F5）：反汇编 + 真实源地址映射伪代码并排对照，悬停/点击双向高亮同步
 * - cfg（Space）：可缩放平移的真实基本块控制流流程图，点击基本块直达汇编行
 */
export function CodeStage({
  so,
  fnAddr,
  fnName,
  fnSize,
  isExport,
  mode,
  selInsnAddr,
  onSelectInsn,
  onJump,
  onSwitchMode,
  comments,
  bpMarks,
  onToggleBpMark,
  aiHitSeq,
  aiHitAddr,
}: Props) {
  const [insns, setInsns] = useState<ApiInsn[]>([]);
  const [pseudo, setPseudo] = useState<string>("");
  const [pseudoLines, setPseudoLines] = useState<{ addr: number | null; text: string }[] | null>(null);
  const [pseudoStyle, setPseudoStyle] = useState<"c" | "raw">("c");
  const [blocks, setBlocks] = useState<ApiCfgBlock[]>([]);
  const [loadingDisasm, setLoadingDisasm] = useState(false);
  const [loadingPseudo, setLoadingPseudo] = useState(false);
  const [loadingCfg, setLoadingCfg] = useState(false);
  const [syncAddr, setSyncAddr] = useState<number | null>(null);
  const [flashHit, setFlashHit] = useState(false);

  // 并排模式下左/右栏可拖拽占比（24% ~ 76%，持久化到 localStorage）
  const [splitPct, setSplitPct] = useState<number>(() => {
    try {
      const saved = Number(localStorage.getItem("mda_split_pct"));
      if (saved >= 24 && saved <= 76) return saved;
    } catch { /* ignore */ }
    return 46;
  });
  const [resizingSplit, setResizingSplit] = useState(false);
  const splitWrapRef = useRef<HTMLDivElement | null>(null);

  const disasmScrollRef = useRef<HTMLDivElement | null>(null);
  const cfgWrapRef = useRef<HTMLDivElement | null>(null);
  const cfgVpRef = useRef<SVGGElement | null>(null);
  const [vp, setVp] = useState({ x: 36, y: 24, scale: 0.9 });

  // 拉取真实反汇编
  useEffect(() => {
    let alive = true;
    setLoadingDisasm(true);
    void (async () => {
      const r = await api.disasm(so, fnAddr);
      if (!alive) return;
      setInsns(r?.items ?? []);
      setLoadingDisasm(false);
    })();
    return () => { alive = false; };
  }, [so, fnAddr]);

  // 并排模式下按需拉取真实伪 C / 指令对照代码
  useEffect(() => {
    if (mode !== "split") return;
    let alive = true;
    setLoadingPseudo(true);
    void (async () => {
      const r = await api.decompile(so, fnAddr, pseudoStyle);
      if (!alive) return;
      setPseudo(r?.code ?? "");
      setPseudoLines(Array.isArray(r?.lines) ? r!.lines! : null);
      setLoadingPseudo(false);
    })();
    return () => { alive = false; };
  }, [so, fnAddr, mode, pseudoStyle]);

  // 拖拽调整左反汇编 / 右伪 C 宽度占比
  const startSplitResize = (e: React.MouseEvent) => {
    e.preventDefault();
    const wrap = splitWrapRef.current;
    if (!wrap) return;
    const rect = wrap.getBoundingClientRect();
    if (rect.width <= 0) return;
    setResizingSplit(true);
    let latest = splitPct;
    const onMove = (ev: MouseEvent) => {
      const raw = ((ev.clientX - rect.left) / rect.width) * 100;
      latest = Math.max(24, Math.min(76, Math.round(raw * 10) / 10));
      setSplitPct(latest);
    };
    const onUp = () => {
      setResizingSplit(false);
      try { localStorage.setItem("mda_split_pct", String(latest)); } catch { /* ignore */ }
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // CFG 模式下按需拉取真实基本块
  useEffect(() => {
    if (mode !== "cfg") return;
    let alive = true;
    setLoadingCfg(true);
    void (async () => {
      const r = await api.cfg(so, fnAddr);
      if (!alive) return;
      setBlocks(r?.blocks ?? []);
      setLoadingCfg(false);
    })();
    return () => { alive = false; };
  }, [so, fnAddr, mode]);

  // AI 命中当前函数时触发代码行激光扫光
  useEffect(() => {
    if (!aiHitSeq) return;
    setFlashHit(true);
    const id = window.setTimeout(() => setFlashHit(false), 1200);
    return () => window.clearTimeout(id);
  }, [aiHitSeq]);

  const parsedPseudo = useMemo(() => {
    if (pseudoLines && pseudoLines.length > 0) {
      return pseudoLines.map((ln, idx) => ({
        idx,
        srcAddr: ln.addr,
        body: ln.text,
      }));
    }
    if (!pseudo) return [];
    return pseudo.split("\n").map((ln, idx) => {
      const m = ln.match(/\/\/\s*(0x[0-9a-fA-F]+)\s+(.*)$/);
      const srcAddr = m ? parseInt(m[1], 16) : null;
      const body = m ? "    " + m[2] : ln;
      return { idx, srcAddr, body };
    });
  }, [pseudo, pseudoLines]);

  // 确定性 BFS 分层 CFG 布局
  const cfgLayout = useMemo(() => {
    if (!blocks.length) return null;
    const norm = blocks.map((b) => ({
      start: parseInt(b.start, 16),
      insns: b.insns.map((x) => ({ addr: parseInt(x.addr, 16), text: x.text })),
      succ: b.successors
        .filter((s) => s.to && s.to.startsWith("0x"))
        .map((s) => ({ target: parseInt(s.to, 16), kind: s.kind })),
    }));
    const byAddr = new Map(norm.map((b) => [b.start, b]));
    const depth = new Map<number, number>([[norm[0].start, 0]]);
    const q = [norm[0].start];
    while (q.length) {
      const u = q.shift()!;
      const d = depth.get(u)!;
      const blk = byAddr.get(u);
      if (!blk) continue;
      for (const s of blk.succ) {
        if (byAddr.has(s.target) && !depth.has(s.target)) {
          depth.set(s.target, d + 1);
          q.push(s.target);
        }
      }
    }
    norm.forEach((b) => { if (!depth.has(b.start)) depth.set(b.start, 0); });

    const layers = new Map<number, typeof norm>();
    norm.forEach((b) => {
      const d = depth.get(b.start)!;
      if (!layers.has(d)) layers.set(d, []);
      layers.get(d)!.push(b);
    });

    const BW = 274;
    const GAP_X = 34;
    const GAP_Y = 44;
    const pos = new Map<number, { x: number; y: number; w: number; h: number; blk: (typeof norm)[number] }>();
    let curY = 24;
    [...layers.keys()].sort((a, b) => a - b).forEach((d) => {
      const row = layers.get(d)!;
      const totalW = row.length * BW + (row.length - 1) * GAP_X;
      let sx = Math.max(24, (920 - totalW) / 2);
      let maxH = 0;
      row.forEach((b) => {
        const shownCount = Math.min(b.insns.length, 7);
        const h = 28 + shownCount * 16 + (b.insns.length > 7 ? 16 : 6);
        pos.set(b.start, { x: sx, y: curY, w: BW, h, blk: b });
        sx += BW + GAP_X;
        maxH = Math.max(maxH, h);
      });
      curY += maxH + GAP_Y;
    });
    return { entry: norm[0].start, pos };
  }, [blocks]);

  // CFG 渲染后自动适配居中视口
  const fitCfg = () => {
    const wrap = cfgWrapRef.current;
    const g = cfgVpRef.current;
    if (!wrap || !g) return;
    try {
      const bb = g.getBBox();
      const cw = wrap.clientWidth || 760;
      const ch = wrap.clientHeight || 460;
      if (bb.width > 0 && bb.height > 0) {
        const pad = 36;
        const scale = Math.max(
          0.42,
          Math.min(1.05, Math.min((cw - pad * 2) / bb.width, (ch - pad * 2) / bb.height))
        );
        const x = Math.round((cw - bb.width * scale) / 2 - bb.x * scale);
        const y = Math.round(Math.max(22, (ch - bb.height * scale) / 2) - bb.y * scale);
        setVp({ x, y, scale });
      }
    } catch {
      /* 忽略不可见 SVG getBBox 异常 */
    }
  };

  useEffect(() => {
    if (mode !== "cfg" || !cfgLayout) return;
    const id = window.requestAnimationFrame(fitCfg);
    return () => window.cancelAnimationFrame(id);
  }, [mode, cfgLayout]);

  // CFG 拖拽平移（用 window 一次性监听器，绝不泄漏）
  const startCfgDrag = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".cfg-block,.v2-canvas-tools")) return;
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

  if (mode === "cfg") {
    return (
      <div
        className="v2-canvas-view"
        ref={cfgWrapRef}
        onMouseDown={startCfgDrag}
        onWheel={(e) => {
          e.preventDefault();
          const f = e.deltaY < 0 ? 1.12 : 0.89;
          setVp((cur) => ({ ...cur, scale: Math.max(0.32, Math.min(2.2, cur.scale * f)) }));
        }}
      >
        <div className="v2-canvas-tools">
          <button
            className="v2-icon-btn"
            title="放大"
            onClick={() => setVp((c) => ({ ...c, scale: Math.min(2.2, c.scale * 1.18) }))}
          >
            <svg className="ic" viewBox="0 0 16 16"><path d="M8 3.5v9M3.5 8h9" /></svg>
          </button>
          <button
            className="v2-icon-btn"
            title="缩小"
            onClick={() => setVp((c) => ({ ...c, scale: Math.max(0.32, c.scale * 0.84) }))}
          >
            <svg className="ic" viewBox="0 0 16 16"><path d="M3.5 8h9" /></svg>
          </button>
          <button className="v2-icon-btn" title="重置居中" onClick={fitCfg}>
            <svg className="ic" viewBox="0 0 16 16"><path d="M3 8a5 5 0 1 0 1.5-3.5L3 6m0-3v3h3" /></svg>
          </button>
        </div>

        <div className="v2-canvas-legend">
          <span><i className="v2-leg-dot" style={{ background: "var(--green)" }} />条件跳转 (True)</span>
          <span><i className="v2-leg-dot" style={{ background: "var(--rose)" }} />顺序落入 (False)</span>
          <span><i className="v2-leg-dot" style={{ background: "var(--accent)" }} />无条件跳转</span>
          <span style={{ color: "var(--fg-3)" }}>
            {loadingCfg
              ? "正在切分基本块…"
              : `${blocks.length} 个基本块 · 滚轮缩放 · 拖拽画布 · 点击基本块跳到反汇编`}
          </span>
        </div>

        <svg width="100%" height="100%" style={{ display: "block" }}>
          <defs>
            <marker id="v2ArrGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0 1L8 5L0 9z" fill="var(--green)" />
            </marker>
            <marker id="v2ArrRose" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0 1L8 5L0 9z" fill="var(--rose)" />
            </marker>
            <marker id="v2ArrBlue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0 1L8 5L0 9z" fill="var(--accent)" />
            </marker>
          </defs>
          <g ref={cfgVpRef} transform={`translate(${vp.x},${vp.y}) scale(${vp.scale})`}>
            {cfgLayout &&
              [...cfgLayout.pos.values()].flatMap((p) =>
                p.blk.succ.map((s, si) => {
                  const dst = cfgLayout.pos.get(s.target);
                  if (!dst) return null;
                  const x1 = p.x + p.w / 2;
                  const y1 = p.y + p.h;
                  const x2 = dst.x + dst.w / 2;
                  const y2 = dst.y;
                  const isBack = y2 <= y1;
                  const isTrue = s.kind === "branch" || s.kind === "true";
                  const isFalse = s.kind === "fallthrough" || s.kind === "false";
                  const col = isTrue ? "var(--green)" : isFalse ? "var(--rose)" : "var(--accent)";
                  const marker = isTrue ? "url(#v2ArrGreen)" : isFalse ? "url(#v2ArrRose)" : "url(#v2ArrBlue)";
                  const d = isBack
                    ? `M ${x1} ${y1} C ${x1} ${y1 + 24}, ${Math.max(p.x + p.w, dst.x + dst.w) + 28} ${y1 + 24}, ${Math.max(p.x + p.w, dst.x + dst.w) + 28} ${(y1 + y2) / 2} S ${x2} ${y2 - 24}, ${x2} ${y2}`
                    : `M ${x1} ${y1} C ${x1} ${(y1 + y2) / 2}, ${x2} ${(y1 + y2) / 2}, ${x2} ${y2}`;
                  return (
                    <path
                      key={`${p.blk.start}-${s.target}-${si}`}
                      d={d}
                      fill="none"
                      stroke={col}
                      strokeWidth="1.5"
                      strokeOpacity="0.82"
                      markerEnd={marker}
                    />
                  );
                })
              )}
            {cfgLayout &&
              [...cfgLayout.pos.entries()].map(([addr, p]) => {
                const isEntry = addr === cfgLayout.entry;
                const shown = p.blk.insns.slice(0, 7);
                return (
                  <g
                    key={addr}
                    className={"cfg-block" + (isEntry ? " entry" : "")}
                    onClick={() => {
                      onSelectInsn(addr);
                      setSyncAddr(addr);
                      onSwitchMode("split");
                    }}
                  >
                    <rect className="box" x={p.x} y={p.y} width={p.w} height={p.h} />
                    <path d={`M ${p.x + 1} ${p.y + 23} H ${p.x + p.w - 1}`} stroke="var(--line)" strokeWidth="1" />
                    <text className="cfg-hd-txt" x={p.x + 10} y={p.y + 15}>
                      {isEntry ? "ENTRY · " : "BB · "}
                      {hex(addr)} ({p.blk.insns.length} 条)
                    </text>
                    {shown.map((ins, i) => (
                      <g key={ins.addr}>
                        <text className="cfg-ins-addr" x={p.x + 10} y={p.y + 40 + i * 16}>
                          {hex(ins.addr)}
                        </text>
                        <text className="cfg-ins-txt" x={p.x + 68} y={p.y + 40 + i * 16}>
                          {ins.text.slice(0, 29)}
                        </text>
                      </g>
                    ))}
                    {p.blk.insns.length > 7 && (
                      <text className="cfg-ins-addr" x={p.x + 10} y={p.y + 40 + 7 * 16}>
                        … 还有 {p.blk.insns.length - 7} 条指令
                      </text>
                    )}
                  </g>
                );
              })}
          </g>
        </svg>
      </div>
    );
  }

  return (
    <div
      ref={splitWrapRef}
      className={"v2-split" + (mode === "split" ? " is-split" : "") + (resizingSplit ? " is-resizing" : "")}
    >
      {/* 左：ARM64 反汇编 */}
      <div
        className="v2-pane"
        style={mode === "split" ? { flex: `0 0 ${splitPct}%` } : undefined}
      >
        <div className="v2-pane-hd">
          <strong>ARM64 反汇编</strong>
          <span className="tag">{insns.length} 条</span>
          <span className="tag">{fnSize} B</span>
          <span className="hint">点击蓝色目标跳转 · 圆点标记断点</span>
        </div>
        <div className="v2-scroll" ref={disasmScrollRef}>
          <div className="v2-fn-banner">
            <div className="sig">{fnName}()</div>
            <div className="sub">
              {so} · {hex(fnAddr)}..{hex(fnAddr + fnSize)} · {isExport ? "导出函数" : "内部函数"}
            </div>
          </div>
          {loadingDisasm && !insns.length ? (
            <div style={{ padding: 18, color: "var(--fg-3)" }}>正在实时解码指令…</div>
          ) : (
            insns.map((ins) => {
              const sp = ins.text.indexOf(" ");
              const mnem = sp >= 0 ? ins.text.slice(0, sp) : ins.text;
              const ops = sp >= 0 ? ins.text.slice(sp + 1).trim() : "";
              const mk = classifyMnem(mnem);
              const uCmt = comments[hex(ins.addr)];
              const hasBp = bpMarks.has(`${so}:${hex(ins.addr)}`);
              const isSel = selInsnAddr === ins.addr;
              const isSync = syncAddr === ins.addr;
              const isAiHit = flashHit && (aiHitAddr === ins.addr || (aiHitAddr === fnAddr && ins.addr === fnAddr));
              return (
                <div
                  key={ins.addr}
                  data-iaddr={ins.addr}
                  className={
                    "v2-insn-row" +
                    (isSel ? " sel" : "") +
                    (isSync ? " sync-hi" : "") +
                    (hasBp ? " has-bp" : "") +
                    (isAiHit ? " ai-hit" : "")
                  }
                  onMouseEnter={() => setSyncAddr(ins.addr)}
                  onClick={() => {
                    onSelectInsn(ins.addr);
                    setSyncAddr(ins.addr);
                  }}
                >
                  <span
                    className="v2-insn-bp"
                    title="点击切换本地断点标记 (B)"
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleBpMark(so, ins.addr);
                    }}
                  >
                    ●
                  </span>
                  <span className="v2-insn-addr">{hex(ins.addr)}</span>
                  <span className="v2-insn-bytes">{formatBytes(ins.bytes)}</span>
                  <span className={"v2-insn-mnem " + mk}>{mnem}</span>
                  <span className="v2-insn-ops">
                    {renderOperands(ops, ins.jump_addr, ins.jump_so, so, onJump)}
                  </span>
                  {uCmt ? (
                    <span className="v2-insn-cmt is-user" title={uCmt}>; {uCmt}</span>
                  ) : ins.str_ref ? (
                    <span className="v2-insn-cmt is-str" title={ins.str_ref}>; "{ins.str_ref}"</span>
                  ) : ins.sym_ref ? (
                    <span className="v2-insn-cmt" title={ins.sym_ref}>; → {ins.sym_ref}</span>
                  ) : (
                    <span />
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 中间可拖拽分栏分隔条（双击恢复 50/50） */}
      {mode === "split" && (
        <div
          className={"v2-split-resizer" + (resizingSplit ? " active" : "")}
          title="左右拖动调整反汇编与伪 C 占比（双击恢复 50/50）"
          onMouseDown={startSplitResize}
          onDoubleClick={() => {
            setSplitPct(50);
            try { localStorage.setItem("mda_split_pct", "50"); } catch { /* ignore */ }
          }}
        />
      )}

      {/* 右：F5 伪 C 代码对照（源地址双向同步） */}
      {mode === "split" && (
        <div className="v2-pane" style={{ flex: "1 1 0%" }}>
          <div className="v2-pane-hd">
            <strong>{pseudoStyle === "c" ? "伪 C 代码 (F5)" : "指令对照 (F5)"}</strong>
            <div className="v2-mini-seg">
              <button
                className={pseudoStyle === "c" ? "on" : ""}
                onClick={() => setPseudoStyle("c")}
              >
                伪 C
              </button>
              <button
                className={pseudoStyle === "raw" ? "on" : ""}
                onClick={() => setPseudoStyle("raw")}
              >
                指令对照
              </button>
            </div>
            <span className="hint">悬停/点击联动高亮左侧汇编 · 中缝可拖拽</span>
          </div>
          <div className="v2-scroll">
            {loadingPseudo && !parsedPseudo.length ? (
              <div style={{ padding: 18, color: "var(--fg-3)" }}>正在生成源地址映射伪代码…</div>
            ) : (
              parsedPseudo.map((ln) => {
                const isSync = ln.srcAddr !== null && syncAddr === ln.srcAddr;
                const isAiHit = flashHit && ln.srcAddr !== null && aiHitAddr === ln.srcAddr;
                return (
                  <div
                    key={ln.idx}
                    className={"v2-pc-line" + (isSync ? " sync-hi" : "") + (isAiHit ? " ai-hit" : "")}
                    onMouseEnter={() => {
                      if (ln.srcAddr !== null) setSyncAddr(ln.srcAddr);
                    }}
                    onClick={() => {
                      if (ln.srcAddr === null) return;
                      onSelectInsn(ln.srcAddr);
                      setSyncAddr(ln.srcAddr);
                      const row = disasmScrollRef.current?.querySelector<HTMLElement>(
                        `[data-iaddr="${ln.srcAddr}"]`
                      );
                      row?.scrollIntoView({ block: "center", behavior: "smooth" });
                    }}
                  >
                    <span className="v2-pc-src">{ln.srcAddr !== null ? hex(ln.srcAddr) : ""}</span>
                    <span className="v2-pc-code">{renderPseudoTokens(ln.body)}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
