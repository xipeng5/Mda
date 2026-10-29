import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { hex, type ModuleData, type Func } from "./lib/data";
import { api, hasNativeDialog, pickSoFile } from "./lib/api";
import type { ApiInsn } from "./lib/api";
import { SphereCanvas } from "./components/SphereCanvas";
import { LeftPanel } from "./components/LeftPanel";
import { RightPanel } from "./components/RightPanel";
import { Hud, type HudData } from "./components/Hud";
import { CodeOverlay } from "./components/CodeOverlay";
import type { Relations, Theme } from "./lib/sphere";

type LogItem = { time: string; text: string; kind?: string };
type WatchItem = { so: string; name: string; addr: number };

const now = () => new Date().toLocaleTimeString("zh-CN", { hour12: false });

export default function App() {
  const [modules, setModules] = useState<ModuleData[]>([]);
  const [active, setActive] = useState(0);
  const [sel, setSel] = useState<number[]>([]);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [watch, setWatch] = useState<WatchItem[]>([]);
  // (1) 第一次修改：主题默认跟随系统外观（macOS 深色/浅色），不再硬编码 dark。
  //     手动点过切换按钮后锁定用户选择，系统再变也不覆盖。
  const [theme, setTheme] = useState<Theme>(() =>
    window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark"
  );
  const themeLocked = useRef(false);
  const [hud, setHud] = useState<HudData | null>(null);
  const [code, setCode] = useState<{ open: boolean; rows: ApiInsn[]; live: boolean }>({ open: false, rows: [], live: false });
  const [relations, setRelations] = useState<Relations | null>(null);
  const [bps] = useState<Record<string, Set<number>>>({});
  const [progress, setProgress] = useState<{ percent: number } | null>(null);
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [rotateIdx, setRotateIdx] = useState<number | null>(null);
  const [jumpText, setJumpText] = useState("");
  const [busySo, setBusySo] = useState<string | null>(null);
  const [flash, setFlash] = useState<{ i: number; seq: number } | null>(null);
  const [pulseKey, setPulseKey] = useState(0);
  const [loading, setLoading] = useState<{ name: string } | null>(null);
  const [loadError, setLoadError] = useState("");
  const [dragging, setDragging] = useState(false);
  const flashSeq = useRef(0);
  const backendMods = useRef<Set<string>>(new Set());
  const booted = useRef(false);

  const mod = modules[active];
  const selected = sel[active] ?? -1;
  const f = mod && selected >= 0 ? mod.funcs[selected] : null;

  const log = useCallback((text: string, kind?: string) => {
    setLogs((prev) => [...prev.slice(-300), { time: now(), text, kind }]);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  // 跟随系统外观变化（用户未手动切换时）
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const onChange = (e: MediaQueryListEvent) => {
      if (!themeLocked.current) setTheme(e.matches ? "light" : "dark");
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  useEffect(() => {
    setPulseKey((k) => k + 1);
  }, [active]);

  /** 后端已解析完成 → 拉函数表、建模块、选中第一个导出函数 */
  const appendModule = useCallback(async (so: string, path: string) => {
    const fn = await api.functions(so, "", 200000);
    if (!fn) throw new Error("后端没有返回函数表");
    const funcs: Func[] = fn.items.map((it) => ({
      n: it.name, a: it.addr, s: it.size, e: it.is_export ? 1 : 0, r: it.refs ?? 0,
    }));
    if (!funcs.length) throw new Error("这个 so 里没有解析出任何函数");
    const data: ModuleData = { so, path, size: 0, sections: [], funcs, disasm: {}, callers: {}, callees: {} };
    backendMods.current.add(so);
    let newIndex = 0;
    setModules((prev) => {
      const exists = prev.findIndex((m) => m.so === so);
      if (exists >= 0) { newIndex = exists; return prev; }
      newIndex = prev.length;
      return [...prev, data];
    });
    setSel((prev) => {
      const next = prev.slice();
      next[newIndex] = funcs.findIndex((x) => x.e) >= 0 ? funcs.findIndex((x) => x.e) : 0;
      return next;
    });
    setActive(newIndex);
    log(`已打开 ${so} · ${funcs.length} 函数（后端实时解析）`, "ai");
  }, [log]);

  /** 按路径加载（原生对话框选择的结果） */
  const buildModule = useCallback(async (path: string): Promise<void> => {
    const name = path.split("/").pop() || path;
    setLoading({ name });
    setLoadError("");
    try {
      const r = await api.load(path);
      if (!r?.module) throw new Error("解析失败：不是可识别的 ELF，或文件不可读");
      await appendModule(r.module.so, path);
    } catch (e) {
      setLoadError(String(e));
      log(`打开失败：${e}`);
    } finally {
      setLoading(null);
    }
  }, [appendModule, log]);

  /** 拖入文件：字节上传 → 后端落盘解析 */
  const uploadFile = useCallback(async (file: File): Promise<void> => {
    setLoading({ name: file.name });
    setLoadError("");
    try {
      const buf = await file.arrayBuffer();
      const r = await api.upload(file.name, buf);
      await appendModule(r.module.so, r.path);
    } catch (e) {
      setLoadError(String(e));
      log(`拖入失败：${e}`);
    } finally {
      setLoading(null);
    }
  }, [appendModule, log]);

  /** 系统文件对话框 → 后端加载 */
  const openSo = useCallback(async () => {
    if (!hasNativeDialog()) {
      setLoadError("当前是浏览器窗口，没有系统文件对话框；请用桌面窗口（python app.py）打开 so。");
      return;
    }
    const path = await pickSoFile();
    if (!path) return;                       // 用户取消
    await buildModule(path);
  }, [buildModule]);

  // 启动：后端若已有会话就重建模块；没有就停在空状态（不再有任何内置示例数据）
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    (async () => {
      const h = await api.health();
      const ok = !!h?.ok;
      setApiOk(ok);
      if (!ok) {
        setLogs([{ time: now(), text: "后端未连接：请用 python app.py 启动（不要直接开 HTML）" }]);
        return;
      }
      setLogs([{ time: now(), text: `MDA Web 启动 · 后端已连接（${location.host}）` }]);
      for (const so of h.modules ?? []) {
        setLoading({ name: so });
        try {
          await appendModule(so, so);
        } catch (e) {
          log(`${so} 恢复失败：${e}`);
        }
      }
      setLoading(null);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 真实 AI 事件（MCP 调用 → 日志/观察/脉冲）
  useEffect(() => {
    let ws: WebSocket | null = null;
    try {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/events`);
    } catch { return; }
    const findName = (so: string, addr: number): string => {
      const m = modules.find((x) => x.so === so);
      return m?.funcs.find((x) => x.a === addr)?.n ?? hex(addr);
    };
    const toIdx = (so: string, addr: number): { mi: number; i: number } | null => {
      const mi = modules.findIndex((m) => m.so === so);
      if (mi < 0) return null;
      const i = modules[mi].funcs.findIndex((x) => x.a === addr);
      return i < 0 ? null : { mi, i };
    };
    ws.onmessage = (ev) => {
      let msg: { type?: string; tool?: string; args?: Record<string, unknown>; summary?: string; event?: Record<string, unknown> };
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === "ai" && msg.tool === "load_so") {
        // (2) 第一次修改：AI 通过 MCP 加载 so 后，界面自动出现该模块。
        //     原因：之前只有 AI 自己看得见，人要在窗口里手动再开一次。
        void (async () => {
          const mods = await api.modules();
          for (const m of mods?.modules ?? []) {
            if (modules.some((x) => x.so === m.so)) continue;
            setLoading({ name: m.so });
            try { await appendModule(m.so, m.path); } catch { /* 坏文件交给日志 */ }
          }
          setLoading(null);
        })();
      }
      if (msg.type === "ai") {
        const a = (msg.args ?? {}) as { so_name?: string; name?: string; addr?: number };
        const so = a.so_name ?? a.name ?? "";
        const addr = typeof a.addr === "number" ? a.addr : undefined;
        log(`[AI] ${msg.tool}(${so}${addr !== undefined ? ", " + hex(addr) : ""}) ${msg.summary ?? ""}`, "ai");
        if (so && addr !== undefined) {
          setWatch((w) => [{ so, name: findName(so, addr), addr }, ...w].slice(0, 60));
          const hit = toIdx(so, addr);
          if (hit) {
            setActive(hit.mi);
            setSel((prev) => prev.map((v, k) => (k === hit.mi ? hit.i : v)));
            flashSeq.current += 1;
            setFlash({ i: hit.i, seq: flashSeq.current });
          }
          setHud({ kind: "ai", so, fn: findName(so, addr), addr: hex(addr), detail: msg.tool ?? "" });
        }
        setBusySo(so || null);
        setTimeout(() => setBusySo((v) => (v === so ? null : v)), 1600);
      } else if (msg.type === "ui" && msg.event?.type === "goto") {
        const e = msg.event as { so_name: string; addr: number };
        const hit = toIdx(e.so_name, e.addr);
        if (hit) {
          setActive(hit.mi);
          setSel((prev) => prev.map((v, k) => (k === hit.mi ? hit.i : v)));
          setRotateIdx(hit.i);
        }
      }
    };
    return () => ws?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modules, appendModule]);

  // 选中变化：取真实 xrefs + 反汇编
  useEffect(() => {
    if (!mod || selected < 0) return;
    let cancelled = false;
    const so = mod.so;
    const addr = mod.funcs[selected].a;
    (async () => {
      const have = backendMods.current.has(so);
      const x = have ? await api.xrefs(so, addr) : null;
      if (cancelled) return;
      const toNum = (h: string) => parseInt(h, 16);
      if (x) setRelations({ ins: x.callers.map(toNum), outs: x.callees.map(toNum) });
      else setRelations(null);
      if (code.open) {
        const d = have ? await api.disasm(so, addr) : null;
        if (cancelled) return;
        if (d) setCode((c) => ({ ...c, rows: d.items, live: true }));
        else setCode((c) => ({ ...c, rows: [], live: false }));
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, selected]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { setCode((c) => ({ ...c, open: false })); setHud(null); return; }
      if (e.key === "Enter" && !(e.target instanceof HTMLInputElement)) void openCode();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, selected]);

  const selectFn = (mi: number, i: number) => {
    setSel((prev) => prev.map((v, k) => (k === mi ? i : v)));
    if (mi !== active) setActive(mi);
    setRotateIdx(i);
  };

  const openCode = async () => {
    if (!mod || !f) return;
    setCode({ open: true, rows: [], live: false });
    const d = await api.disasm(mod.so, f.a);
    if (d) {
      setCode({ open: true, rows: d.items, live: true });
      log(`反汇编 ${f.n} · ${d.items.length} 条（后端实时解码）`, "ai");
    } else {
      setCode({ open: true, rows: [], live: false });
      log(`反汇编失败：后端没有返回 ${f.n} 的指令`, "ai");
    }
  };

  const buildXrefs = async () => {
    if (!mod) return;
    log("开始构建引用图（后端真实构建）");
    setProgress({ percent: 5 });
    const t0 = setInterval(() => setProgress((p) => (p ? { percent: Math.min(92, p.percent + 7) } : p)), 260);
    const r = await api.buildXrefs(mod.so);
    clearInterval(t0);
    setProgress({ percent: 100 });
    setTimeout(() => setProgress(null), 700);
    log(r ? "引用图构建完成" : "引用图构建失败", "ai");
  };

  /** 复制 MCP 配置：HTTP 与 stdio 两种都写进同一个 mcpServers，粘过去删掉不用的那条即可 */
  const copyMcpConfig = useCallback(async () => {
    try {
      const cfg = await (await fetch(`${location.origin}/api/mcp-config`)).json();
      const text = JSON.stringify(
        {
          mcpServers: {
            mda: { url: cfg.http_url },
            "mda-stdio": { command: cfg.stdio.command, args: cfg.stdio.args },
          },
        },
        null,
        2
      );
      // 优先级：pywebview 原生剪贴板 > 浏览器 clipboard > execCommand
      // (1) 第一次修改：WKWebView 里前两种都可能失败（用户实测"复制失败"），
      //     所以先走原生 NSPasteboard，后面的只作兜底。
      let ok = false;
      const bridge = (window as unknown as {
        pywebview?: { api?: { copy_text?: (t: string) => Promise<boolean> | boolean } };
      }).pywebview;
      if (bridge?.api?.copy_text) {
        try { ok = !!(await bridge.api.copy_text(text)); } catch { ok = false; }
      }
      if (!ok) {
        try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = false; }
      }
      if (!ok) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand("copy");
        ta.remove();
      }
      log(ok ? "已复制 MCP 配置（含 HTTP 与 stdio 两种写法）" : "复制失败：请检查剪贴板权限", "ai");
    } catch (e) {
      log(`读取 MCP 配置失败：${e}`);
    }
  }, [log]);

  const empty = modules.length === 0;

  return (
    <div
      className="app"
      onDragOver={(e) => { e.preventDefault(); if (!dragging) setDragging(true); }}
      onDragLeave={(e) => {
        // 只有真正离开窗口才收起提示（子元素间移动会连续触发 dragleave）
        if (e.clientX <= 0 || e.clientY <= 0 ||
            e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
          setDragging(false);
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files?.[0];
        if (file) void uploadFile(file);
      }}
    >
      <header className="topbar">
        <div className="brand"><span className="mark" />MDA<small>0.2.1 · web</small></div>
        <div className="divider" />
        <div className="so-tabs">
          {modules.map((m, i) => (
            <button
              key={m.so}
              className={"so-tab" + (i === active ? " on" : "") + (busySo === m.so ? " busy" : "")}
              onClick={() => setActive(i)}
            >
              {m.so}<span className="n">{m.funcs.length}</span>
            </button>
          ))}
        </div>
        <div className="divider" />
        <button className="btn primary" onClick={openSo}>打开 so</button>
        <div className="grow" />
        <input
          className="jump"
          placeholder="跳转到地址或函数名…"
          value={jumpText}
          onChange={(e) => setJumpText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== "Enter" || !mod) return;
            const v = jumpText.trim().toLowerCase();
            if (!v) return;
            const i = mod.funcs.findIndex((fn) => fn.n.toLowerCase().includes(v) || hex(fn.a) === v);
            if (i < 0) { log(`未找到「${jumpText}」`); return; }
            selectFn(active, i);
            log(`跳转到 ${mod.funcs[i].n} @ ${hex(mod.funcs[i].a)}`);
          }}
        />
        <button className="btn" onClick={buildXrefs} disabled={empty}>建立引用图</button>
        <button className="btn" onClick={() => { themeLocked.current = true; setTheme(theme === "dark" ? "light" : "dark"); }}>
          {theme === "dark" ? "◑ 深色" : "◒ 浅色"}
        </button>
        <div className="divider" />
        <button className="btn" onClick={copyMcpConfig} title="复制 MCP 配置，粘到 AI 客户端的 mcpServers 里">
          复制 MCP 配置
        </button>
        <span className="chip"><i className={"dot " + (apiOk ? "ok" : "")} />后端 {apiOk ? "已连接" : "未连接"}</span>
      </header>

      <main className="workspace">
        <LeftPanel logs={logs} watch={watch} onPickWatch={(w) => log(`观察：${w.name} @ ${hex(w.addr)}`)} />
        <section className={"stage" + (code.open ? " compact" : "")}>
          {!empty && (
            <SphereCanvas
              modules={modules}
              active={active}
              selected={sel}
              theme={theme}
              relations={relations}
              breakpoints={bps}
              progress={progress}
              rotateTo={rotateIdx}
              compact={code.open}
              flash={flash}
              pulseKey={pulseKey}
            />
          )}

          {empty && !loading && (
            <div className="empty-stage">
              <div className="empty-mark"><span className="mark" /></div>
              <div className="empty-title">打开一个 so 开始分析</div>
              <div className="empty-sub">多 so 同会话 · 跨 so 调用链 · ELF 32/64 · 节表损坏也能读</div>
              <button className="btn primary" onClick={openSo}>打开 so 文件</button>
              <div className="empty-hint">
                {hasNativeDialog() ? "会弹出 macOS 文件选择框" : "浏览器模式没有文件对话框，请用 python app.py 打开桌面窗口"}
              </div>
              {loadError && <div className="empty-err">{loadError}</div>}
            </div>
          )}

          {loading && (
            <div className="loading-layer">
              <div className="spinner" />
              <div className="loading-text">正在解析 {loading.name}…</div>
              <div className="loading-sub">读取段表 → 发现函数 → 建索引</div>
            </div>
          )}

          {!empty && (
            <>
              <div className="legend">
                <div><i className="hi" />热点（被引用 ≥5）</div>
                <div><i className="mid" />有引用</div>
                <div><i />无引用</div>
              </div>
              <div className="lat">
                纬度 = 地址<br />{hex(mod.funcs[0].a)} → {hex(mod.funcs[mod.funcs.length - 1].a)}
              </div>
              <div className="active-label">
                {mod.so}<span>{mod.funcs.length} 函数 · 导出 {mod.funcs.filter((x) => x.e).length}</span>
              </div>
              <div className="hint">
                {code.open ? "Esc 返回球体" : "拖动旋转 · 点右侧函数定位 · 双击 / 回车展开代码"}
              </div>
            </>
          )}

          <Hud hud={hud} onClose={() => setHud(null)} />
          <CodeOverlay
            open={code.open}
            fnName={f?.n ?? "—"}
            fnAddr={f?.a ?? 0}
            size={f?.s ?? 0}
            refs={f?.r ?? 0}
            isExport={!!f?.e}
            rows={code.rows}
            onClose={() => setCode((c) => ({ ...c, open: false }))}
          />
        </section>
        <RightPanel modules={modules} active={active} selected={sel} onActivate={setActive} onSelect={selectFn} onOpen={(mi, i) => { selectFn(mi, i); void openCode(); }} />
      </main>

      {dragging && (
        <div className="drop-overlay">
          <div className="drop-box">
            <span className="drop-icon" />
            <span>松开即加载 .so</span>
            <span className="drop-sub">也可以拖多个文件，逐个加入会话</span>
          </div>
        </div>
      )}

      <footer className="statusbar">
        <span>so <span className="k">{mod?.so ?? "未加载"}</span></span>
        <span>addr <span className="k">{f ? hex(f.a) : "—"}</span></span>
        <span>指令 <span className="k">{f ? f.s + "B" : "—"}</span></span>
        <span>模块 <span className="k">{modules.length}</span></span>
        <span className="r"><span>{code.live ? "后端实时" : "静态数据"}</span><span>React + TS</span></span>
      </footer>
    </div>
  );
}

function API_LABEL(): string {
  return location.host || "127.0.0.1:8766";
}
