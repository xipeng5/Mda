import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ApiConsoleEvent } from "../lib/api";

/**
 * frida 输出终端 —— 屏幕上就是脚本 console.log / send 打印出来的行。
 *
 * 用户明确（2026-11-19，纠正三次后确定）：
 *   "这里就是 ai 调用 frida 执行脚本的输出啊，你没运行过 frida 脚本吗？"
 *   "脚本打印什么就显示什么"
 *
 * 所以这块区域**不是**工具调用 JSON 查看器：没有"输入/输出"区块、
 * 没有参数格式化、没有折叠按钮、不显示 preflight 那种 MCP 工具记录。
 * 它就是 frida 命令行：脚本打印一行，这里多一行。
 *
 * 后端做了两件关键事（见 server/dyn/console.py 的实测注释）：
 *   1. 自动注入 console.log → send 重定向（实测 frida 的 console.log 根本
 *      不走 message 回调，不重定向 Python 收不到）
 *   2. 把每条输出变成纯文本行，不再 JSON 包装
 *
 * 数据来源只有一处：/api/console/events 里的 kind=line 事件。
 * AI 调工具产生的记录（ws 的 msg.type=ai）**不进这里**——那不是脚本输出。
 */

type Props = {
  open: boolean;
};

type Line = {
  id: number;
  text: string;
  kind: "out" | "err" | "sys";
  ts?: string;
};

export function ConsoleOverlay({ open }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<"once" | "keep">("once");
  const [serial, setSerial] = useState("");
  const [pid, setPid] = useState("");
  const [busy, setBusy] = useState(false);
  const [scripts, setScripts] = useState<{ script_id: number; pid: number; age_s: number }[]>([]);

  const cursor = useRef(0);
  const keepIds = useRef<Set<number>>(new Set());
  const seq = useRef(0);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const stick = useRef(true);

  const push = useCallback((text: string, kind: Line["kind"] = "out", ts?: string) => {
    setLines((prev) => [...prev, { id: ++seq.current, text, kind, ts }].slice(-500));
  }, []);

  // 打开时自动填目标（已附加会话优先，其次前台主进程）
  useEffect(() => {
    if (!open) return;
    let alive = true;
    void (async () => {
      const d = await api.dynState();
      if (!alive) return;
      const tgt = d?.targets?.find((t) => t.state !== "detached" && t.pid);
      if (tgt?.serial && tgt?.pid) {
        setSerial((v) => v || tgt.serial);
        setPid((v) => v || String(tgt.pid));
        return;
      }
      const fg = await api.foreground();
      if (!alive || !fg?.serial) return;
      setSerial((v) => v || fg.serial);
      try {
        const pr = await api.appProcesses({ package: fg.package, serial: fg.serial });
        if (!alive) return;
        const main = pr?.main_pid ?? pr?.processes?.[0]?.pid;
        if (main) setPid((v) => v || String(main));
      } catch { /* 留空让用户手填，绝不编造 */ }
    })();
    return () => { alive = false; };
  }, [open]);

  // 轮询脚本输出事件，两类：
  //   ① AI 调工具时内部脚本的输出：带 source 字段、无 script_id → 直接显示
  //      （全局 frida hook 旁路来的，这是本终端最主要的输出来源）
  //   ② 手动常驻脚本的持续输出：有 script_id 且在 keepIds 里 → 显示
  //      once 的输出已由 run() 返回值直接 push，不在这里处理，避免重复。
  useEffect(() => {
    if (!open) return;
    let alive = true;
    const tick = async () => {
      const r = await api.consoleEvents(cursor.current);
      if (!alive || !r?.ok) return;
      const items = r.items ?? [];
      if (!items.length) return;
      cursor.current = items.reduce((m, e) => Math.max(m, e.t || 0), cursor.current);
      for (const e of items as ApiConsoleEvent[]) {
        const isToolOutput = !!e.source;             // AI 工具旁路输出
        const isKeep = e.script_id != null && keepIds.current.has(e.script_id);
        if (!isToolOutput && !isKeep) continue;
        if (e.kind === "line") push(e.text ?? "", "out", e.ts);
        else if (e.kind === "error") push(e.error ?? "未知错误", "err", e.ts);
        else if (e.kind === "stop") push(`[脚本 #${e.script_id} 已停止]`, "sys", e.ts);
      }
    };
    void tick();
    const h = window.setInterval(tick, 800);
    return () => { alive = false; window.clearInterval(h); };
  }, [open, push]);

  const refreshScripts = useCallback(async () => {
    const r = await api.fridaJsList();
    if (r?.ok) setScripts(r.items ?? []);
  }, []);

  useEffect(() => {
    if (!open) return;
    void refreshScripts();
    const h = window.setInterval(refreshScripts, 3000);
    return () => window.clearInterval(h);
  }, [open, refreshScripts]);

  const run = useCallback(async () => {
    const js = input.trim();
    if (!js) return;
    const pidNum = Number(pid);
    // 终端里输入命令本身就该回显出来（以 > 开头，终端习惯）
    push(`> ${js.split("\n")[0]}${js.includes("\n") ? " …" : ""}`, "sys");
    if (!serial.trim() || !pidNum) {
      push("错误：需要先填 serial 与 pid（不做隐式兜底）", "err");
      return;
    }
    setBusy(true);
    try {
      const r = await api.runFridaJs({ serial: serial.trim(), pid: pidNum, js, mode });
      if (mode === "once") {
        // once：把脚本打印的每一行原样铺出来
        if (r?.ok && r.lines?.length) {
          for (const line of r.lines) push(line, "out");
        } else if (!r?.ok) {
          push(r?.error ?? "执行失败", "err");
        } else {
          push("（脚本没有打印任何内容）", "sys");
        }
        cursor.current = Math.max(cursor.current, Date.now() / 1000);
        setInput("");
      } else {
        if (r?.script_id != null) keepIds.current.add(r.script_id);
        if (!r?.ok) push(r?.error ?? "挂载失败", "err");
        else push(`[常驻脚本 #${r.script_id} 已启动，输出会实时打印在下面]`, "sys");
      }
      void refreshScripts();
    } finally {
      setBusy(false);
    }
  }, [input, serial, pid, mode, push, refreshScripts]);

  const stopAll = useCallback(async (scriptId?: number) => {
    await api.stopFridaJs(scriptId ? { script_id: scriptId } : { serial: serial.trim(), pid: Number(pid) || undefined });
    if (scriptId != null) keepIds.current.delete(scriptId);
    else keepIds.current.clear();
    void refreshScripts();
  }, [serial, pid, refreshScripts]);

  // 贴底
  useEffect(() => {
    const el = bodyRef.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [lines.length]);

  const onScroll = () => {
    const el = bodyRef.current;
    if (!el) return;
    stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  if (!open) return null;

  return (
    <div className="console-view">
      <div className="console-box">
        <div className="console-head">
          <span className="title">frida 终端</span>
          <span className="sub">脚本 console.log / send 的输出</span>
          <span className="grow" />
          {scripts.length > 0 && (
            <span className="con-live">
              <i className="dot live" />观测中 {scripts.length}
              <button className="con-mini" onClick={() => void stopAll()}>全停</button>
            </span>
          )}
          <button className="btn" onClick={() => setLines([])}>清屏</button>
        </div>

        <div className="term-body" ref={bodyRef} onScroll={onScroll}>
          {lines.length === 0 && (
            <div className="term-hint">
              frida 终端 —— 在下面写脚本按 Enter，脚本打印什么就显示什么。
              {'\n'}例如：console.log("hello", Process.enumerateModules().length)
            </div>
          )}
          {lines.map((l) => (
            <div key={l.id} className={"term-line " + l.kind}>
              {l.kind === "out" && <span className="term-prefix">{"  "}</span>}
              <span className="term-text">{l.text}</span>
            </div>
          ))}
        </div>

        <div className="console-input">
          <div className="con-tools">
            <input className="con-field" placeholder="serial" value={serial}
              onChange={(e) => setSerial(e.target.value)} title="设备序列号（必填）" />
            <input className="con-field narrow" placeholder="pid" value={pid}
              onChange={(e) => setPid(e.target.value)} title="目标进程 pid（必填）" />
            <button className={"ctab" + (mode === "once" ? " on" : "")}
              onClick={() => setMode("once")} title="执行一次，打印完自动卸载">一次性</button>
            <button className={"ctab" + (mode === "keep" ? " on" : "")}
              onClick={() => setMode("keep")} title="保持脚本存活，输出实时打印，直到停止">常驻</button>
            <span className="grow" />
            {scripts.map((s) => (
              <span className="con-live" key={s.script_id}>
                #{s.script_id} pid {s.pid} {s.age_s}s
                <button className="con-mini" onClick={() => void stopAll(s.script_id)}>停</button>
              </span>
            ))}
          </div>
          <textarea
            className="con-ta"
            placeholder={'send(Process.enumerateModules().length)  —— Enter 执行'}
            title={'frida 脚本，输出什么就显示什么：\n\nsend(Process.enumerateModules().length);\nsend(Process.findModuleByName("libc.so").base);\nconsole.log("模块数", Process.enumerateModules().length);\n\n常驻观察：\nvar n=0;\nsetInterval(function(){ send({tick: ++n}); }, 500);'}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
                e.preventDefault();
                if (!busy) void run();
              }
            }}
            spellCheck={false}
          />
          <div className="con-actions">
            <span className="hint">Enter 执行 · Shift+Enter 换行</span>
            <span className="grow" />
            <button className="btn primary" disabled={busy || !input.trim()} onClick={() => void run()}>
              {busy ? "执行中…" : "执行"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
