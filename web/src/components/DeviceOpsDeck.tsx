import { useEffect, useRef, useState } from "react";
import type { ApiDynState, ApiHooks } from "../lib/api";
import { hex } from "../lib/data";
import {
  classifyTool,
  HOOK_NAMES,
  HOOK_SHORT,
  isReadbackTool,
  LAYER_NAMES,
  TOOL_COLOR,
  TOOL_LABEL,
  toolToLayer,
} from "../lib/toolMeta";

export type OpsSignal = {
  seq: number;
  tool: string;
  ms?: number;
  summary?: string;
};

type Props = {
  /** 最新触发的真实 AI MCP 工具调用信号（来自后端 WebSocket） */
  signal: OpsSignal | null;
  mods: { so: string; n: number }[];
  hooks: ApiHooks | null;
  dynState: ApiDynState | null;
  fgInfo: { package?: string; serial?: string } | null;
  currentAddr: number | null;
  armedBpCount: number;
};

const CONDUIT_PATHS = [
  "M 5 61 C 76 61, 118 19, 215 19",
  "M 5 61 C 80 61, 122 47, 215 47",
  "M 5 61 C 80 61, 122 75, 215 75",
  "M 5 61 C 76 61, 118 103, 215 103",
];
const CONDUIT_END_Y = [19, 47, 75, 103];

/**
 * AI ↔ 真实设备运行态监控动效舞台（方向 2 精细仪器版）。
 *
 * 左侧：极简 4 角星芒 AI 芯片徽标（触发时斜向扫光）。
 * 中间：1px 精细 4 通道信号总线 + 60fps 2.5px 微光粒子 + 落地涟漪 + 读取类双向回传光点。
 * 右侧：真实设备运行态控制台（ADB/Frida/Root/PID/Hook LED/SO 内存激光/ARM64 PC 与断点）。
 * 未连接真机时真实字段一律显示 "—"，绝不伪造 PID、序列号或寄存器数值。
 */
export function DeviceOpsDeck({
  signal,
  mods,
  hooks,
  dynState,
  fgInfo,
  currentAddr,
  armedBpCount,
}: Props) {
  const [firing, setFiring] = useState(false);
  const [frozen, setFrozen] = useState(false);
  const [shake, setShake] = useState(false);
  const [ledBlink, setLedBlink] = useState(false);
  const [pingLayer, setPingLayer] = useState<number | null>(null);
  const [vmStrobe, setVmStrobe] = useState(false);
  const [laserKey, setLaserKey] = useState(0);
  const [igniteSeq, setIgniteSeq] = useState(0);

  const fxGroupRef = useRef<SVGGElement | null>(null);
  const pathRefs = useRef<(SVGPathElement | null)[]>([]);
  const beamRefs = useRef<(SVGPathElement | null)[]>([]);
  const lastSeqRef = useRef<number>(0);

  const tool = signal?.tool || "就绪";
  const cat = signal ? classifyTool(tool) : "static";
  const col = /freeze/.test(tool) ? "#38bdf8" : (TOOL_COLOR[cat] || "#4c8dff");
  const layerIdx = signal ? toolToLayer(tool, cat) : 2;

  // 真实连接状态：来自 /api/dyn_state 与 /api/foreground
  const activeTarget = dynState?.targets?.find((t) => t.state !== "detached");
  const serial = activeTarget?.serial || fgInfo?.serial || "";
  const realPid = activeTarget?.pid ?? null;
  const realBpTotal = Math.max(
    armedBpCount,
    (dynState?.breakpoints ?? []).filter((b) => b.armed).length
  );
  const onHooks = new Set<string>(hooks?.armed ? (hooks.on ?? []) : []);
  const totalFns = mods.reduce((acc, m) => acc + m.n, 0);

  // 每当 signal.seq 前进，驱动 SVG 光粒子束、落地涟漪与对应子系统卡片动效
  useEffect(() => {
    if (!signal || signal.seq === lastSeqRef.current) return;
    lastSeqRef.current = signal.seq;

    const timers: number[] = [];
    const aliveRef = { current: true };
    const tName = signal.tool;
    const tCat = classifyTool(tName);
    const tCol = /freeze/.test(tName) ? "#38bdf8" : (TOOL_COLOR[tCat] || "#4c8dff");
    const tLayer = toolToLayer(tName, tCat);
    const isFreeze = /freeze_process/.test(tName);
    const isHook = /behavior_monitor/.test(tName);

    setFiring(true);
    setLedBlink(true);
    setPingLayer(tLayer);
    if (tCat === "vm") setVmStrobe(true);
    if (tLayer === 2) setLaserKey((k) => k + 1);
    if (isHook) setIgniteSeq((k) => k + 1);
    if (isFreeze) {
      setFrozen(true);
      timers.push(window.setTimeout(() => setFrozen(false), 1450));
    }
    if (tCat === "bp" || isFreeze) {
      setShake(true);
      timers.push(window.setTimeout(() => setShake(false), 360));
    }

    timers.push(window.setTimeout(() => setFiring(false), 1150));
    timers.push(window.setTimeout(() => setLedBlink(false), 950));
    timers.push(window.setTimeout(() => { setPingLayer(null); setVmStrobe(false); }, 1100));

    // SVG 纤细光束 + 60fps 2.5px 微光粒子 + 落地细涟漪 + 读取类双向回传
    const fxGroup = fxGroupRef.current;
    const pathEl = pathRefs.current[tLayer];
    const beamEl = beamRefs.current[tLayer];
    if (beamEl) {
      beamEl.setAttribute("stroke", tCol);
      beamEl.classList.add("lit");
      timers.push(window.setTimeout(() => beamEl.classList.remove("lit"), 960));
    }

    if (fxGroup && pathEl) {
      const totalLen = pathEl.getTotalLength();

      const spawnRipple = (pt: DOMPoint, rCol: string) => {
        [0, 130].forEach((delay) => {
          timers.push(
            window.setTimeout(() => {
              if (!aliveRef.current || !fxGroup.isConnected) return;
              const ring = document.createElementNS("http://www.w3.org/2000/svg", "circle");
              ring.setAttribute("cx", pt.x.toFixed(1));
              ring.setAttribute("cy", pt.y.toFixed(1));
              ring.setAttribute("r", "2.5");
              ring.setAttribute("fill", "none");
              ring.setAttribute("stroke", rCol);
              ring.setAttribute("stroke-width", "1.2");
              fxGroup.appendChild(ring);
              const t0 = performance.now();
              const step = (now: number) => {
                const p = Math.min(1, (now - t0) / 540);
                ring.setAttribute("r", (2.5 + p * 14).toFixed(1));
                ring.setAttribute("opacity", (0.9 * (1 - p)).toFixed(2));
                if (p < 1 && aliveRef.current && fxGroup.isConnected) requestAnimationFrame(step);
                else ring.remove();
              };
              requestAnimationFrame(step);
            }, delay)
          );
        });
      };

      const spawnPacket = (reverse: boolean, delayMs: number, radius: number, durMs: number, pCol: string) => {
        timers.push(
          window.setTimeout(() => {
            if (!aliveRef.current || !fxGroup.isConnected) return;
            const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
            const halo = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            halo.setAttribute("r", (radius * 2.2).toFixed(1));
            halo.setAttribute("fill", pCol);
            halo.setAttribute("opacity", "0.24");
            const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            dot.setAttribute("r", String(radius));
            dot.setAttribute("fill", pCol);
            g.appendChild(halo);
            g.appendChild(dot);
            fxGroup.appendChild(g);

            const t0 = performance.now();
            const tick = (now: number) => {
              const p = Math.min(1, (now - t0) / durMs);
              const eased = 1 - Math.pow(1 - p, 2.2);
              const dist = reverse ? totalLen * (1 - eased) : totalLen * eased;
              const pt = pathEl.getPointAtLength(dist);
              g.setAttribute("transform", `translate(${pt.x.toFixed(1)},${pt.y.toFixed(1)})`);
              if (p < 1 && aliveRef.current && fxGroup.isConnected) {
                requestAnimationFrame(tick);
              } else {
                g.remove();
                if (!reverse && delayMs === 0) {
                  spawnRipple(pathEl.getPointAtLength(totalLen), pCol);
                }
              }
            };
            requestAnimationFrame(tick);
          }, delayMs)
        );
      };

      spawnPacket(false, 0, 2.5, 440, tCol);
      spawnPacket(false, 70, 1.9, 440, tCol);
      spawnPacket(false, 140, 1.4, 440, tCol);

      if (isReadbackTool(tName)) {
        const retCol = /mem_|read_|dump_/.test(tName) ? "#f59e0b" : "#0ea5e9";
        spawnPacket(true, 460, 2.2, 420, retCol);
        spawnPacket(true, 535, 1.5, 420, retCol);
      }
    }

    return () => {
      aliveRef.current = false;
      timers.forEach((id) => window.clearTimeout(id));
    };
  }, [signal]);

  return (
    <div className="v2-ops-deck">
      {/* 左侧：AI Agent 芯片徽标卡 */}
      <div
        className={"v2-ai-card" + (firing ? " firing" : "")}
        style={{ ["--ops-col" as string]: col }}
      >
        <div className="v2-ai-emblem">
          <svg viewBox="0 0 20 20" fill="none">
            <path
              d="M10 2.2L12.1 7.9L17.8 10L12.1 12.1L10 17.8L7.9 12.1L2.2 10L7.9 7.9L10 2.2Z"
              fill={`color-mix(in srgb, ${col} 22%, transparent)`}
              stroke={col}
              strokeWidth="1.35"
              strokeLinejoin="round"
            />
            <circle cx="10" cy="10" r="1.6" fill={col} />
          </svg>
        </div>
        <div className="v2-core-meta">
          <div className="v2-core-label">
            <span>AI AGENT</span>
            <span className={"v2-badge " + cat}>{TOOL_LABEL[cat] || cat}</span>
          </div>
          <div className="v2-core-tool" title={tool}>{tool}</div>
          <div className="v2-core-sub">
            {signal?.ms ? `${signal.ms} ms · ` : ""}
            {LAYER_NAMES[layerIdx]}
          </div>
        </div>
      </div>

      {/* 中间：1px 精密 4 通道信号总线 */}
      <div className="v2-conduit-wrap">
        <svg className="v2-conduit" viewBox="0 0 220 122">
          <defs>
            <filter id="v2OpsGlow">
              <feGaussianBlur stdDeviation="1.6" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {CONDUIT_PATHS.map((d, i) => (
            <path
              key={"rail" + i}
              ref={(el) => { pathRefs.current[i] = el; }}
              className="v2-rail"
              d={d}
            />
          ))}
          <path className="v2-ambient" d={CONDUIT_PATHS[layerIdx]} stroke={col} />
          {CONDUIT_PATHS.map((d, i) => (
            <path
              key={"beam" + i}
              ref={(el) => { beamRefs.current[i] = el; }}
              className="v2-beam"
              d={d}
              filter="url(#v2OpsGlow)"
            />
          ))}
          <circle cx="5" cy="61" r="2.4" fill={col} />
          {CONDUIT_END_Y.map((cy, i) => (
            <circle
              key={"ep" + i}
              cx="215"
              cy={cy}
              r={i === layerIdx ? 2.5 : 1.7}
              fill={i === layerIdx ? col : "var(--line-strong)"}
            />
          ))}
          <g ref={fxGroupRef} />
        </svg>
        <span className="v2-bus-tag">
          <span
            className="v2-pulse-dot"
            style={{ width: 4, height: 4, background: col }}
          />
          ADB · Frida 总线
        </span>
      </div>

      {/* 右侧：真实设备运行态监控控制台 */}
      <div
        className={
          "v2-dev-console" +
          (firing ? " active-pulse" : "") +
          (frozen ? " frozen" : "") +
          (shake ? " hit-shake" : "")
        }
        style={{ ["--dev-col" as string]: col }}
      >
        <div className="v2-dc-top">
          <span className="v2-dc-name">
            <span className={"v2-dc-led" + (ledBlink ? " blink" : "")} />
            {serial ? `Android · ${serial.slice(0, 14)}` : "Android ARM64 · Root"}
          </span>
          <span className={"v2-dc-pill" + (serial ? " ok" : "")}>
            <i />ADB
          </span>
          <span className={"v2-dc-pill" + (activeTarget ? " ok" : "")}>
            <i />Frida
          </span>
          <span className={"v2-dc-pill" + (realBpTotal > 0 ? " warn" : "")}>
            <i />BP {realBpTotal}
          </span>
          <span
            className={
              "v2-dc-state " +
              (frozen ? "frozen" : cat === "bp" ? "hit" : "live")
            }
            title={tool}
          >
            {frozen ? "❄ FROZEN" : tool === "就绪" ? "在线待命" : `⚡ ${tool}`}
          </span>
        </div>

        <div className="v2-dc-grid">
          {/* 卡 1：进程 & 系统链路 */}
          <div
            className={"v2-sub-card" + (pingLayer === 1 ? " ping" : "")}
            style={{ ["--sub-col" as string]: col }}
          >
            <div className="v2-sc-hd">
              <span className="v2-sc-title">
                <span className="v2-sc-dot" style={{ background: "var(--green)" }} />
                进程 &amp; 系统链路
              </span>
              <span className="v2-sc-tag">
                {frozen ? "SIGSTOP" : activeTarget ? activeTarget.state : "待附加"}
              </span>
            </div>
            <div className="v2-sc-kv">
              <span>前台 / PID</span>
              <b title={fgInfo?.package || ""} style={{ maxWidth: 165 }}>
                {realPid != null
                  ? `pid ${realPid}`
                  : fgInfo?.package || "—"}
              </b>
            </div>
            <div className="v2-sc-kv">
              <span>架构 / 权限</span>
              <b>ARM64 · Root</b>
            </div>
          </div>

          {/* 卡 0：行为 Hook & UI */}
          <div
            className={"v2-sub-card" + (pingLayer === 0 ? " ping" : "")}
            style={{ ["--sub-col" as string]: col }}
          >
            <div className="v2-sc-hd">
              <span className="v2-sc-title">
                <span className="v2-sc-dot" style={{ background: "var(--violet)" }} />
                行为 Hook &amp; UI
              </span>
              <span className="v2-sc-tag">
                {onHooks.size}/{HOOK_NAMES.length} 已挂
              </span>
            </div>
            <div className="v2-mini-leds">
              {HOOK_NAMES.map((h, i) => (
                <span
                  key={`${h}-${igniteSeq}`}
                  className={
                    "v2-m-led" +
                    (onHooks.has(h) ? " on" : "") +
                    (igniteSeq > 0 && onHooks.has(h) ? " ign" : "")
                  }
                  style={igniteSeq > 0 ? { animationDelay: `${i * 55}ms` } : undefined}
                  title={h}
                >
                  {HOOK_SHORT[i]}
                </span>
              ))}
            </div>
          </div>

          {/* 卡 2：Native SO & 内存段 */}
          <div
            className={
              "v2-sub-card" +
              (pingLayer === 2 ? " ping" : "") +
              (vmStrobe ? " strobe" : "")
            }
            style={{ ["--sub-col" as string]: col }}
          >
            <div className="v2-sc-hd">
              <span className="v2-sc-title">
                <span className="v2-sc-dot" style={{ background: "var(--accent)" }} />
                Native SO &amp; 内存段
              </span>
              <span className="v2-sc-tag">
                {mods.length} SO · {totalFns} fn
              </span>
            </div>
            <div className="v2-mem-strip">
              {mods.length > 0 ? (
                mods.slice(0, 3).map((m, idx) => (
                  <span
                    key={m.so}
                    className="v2-mem-seg"
                    style={{
                      background:
                        idx % 2 === 0
                          ? "color-mix(in srgb, var(--accent) 78%, transparent)"
                          : "color-mix(in srgb, var(--violet) 78%, transparent)",
                    }}
                    title={`${m.so} (${m.n} 函数)`}
                  >
                    {m.so.replace(/\.so$/, "")}
                  </span>
                ))
              ) : (
                <span
                  className="v2-mem-seg"
                  style={{ background: "var(--surface-3)", color: "var(--fg-3)" }}
                >
                  未加载模块
                </span>
              )}
              <div
                key={laserKey}
                className={"v2-mem-laser" + (laserKey > 0 ? " go" : "")}
              />
            </div>
          </div>

          {/* 卡 3：断点 & ARM64 寄存器 */}
          <div
            className={"v2-sub-card" + (pingLayer === 3 ? " ping" : "")}
            style={{ ["--sub-col" as string]: col }}
          >
            <div className="v2-sc-hd">
              <span className="v2-sc-title">
                <span className="v2-sc-dot" style={{ background: "var(--rose)" }} />
                断点 &amp; ARM64 寄存器
              </span>
              <span className="v2-sc-tag">{realBpTotal} 待命</span>
            </div>
            <div className="v2-reg-row">
              <div className={"v2-reg-cell" + (currentAddr != null ? " pc-hot" : "")}>
                <span>PC</span>
                <b>{currentAddr != null ? hex(currentAddr) : "—"}</b>
              </div>
              <div className="v2-reg-cell"><span>X0</span><b>—</b></div>
              <div className="v2-reg-cell"><span>SP</span><b>—</b></div>
              <div className="v2-reg-cell"><span>LR</span><b>—</b></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
