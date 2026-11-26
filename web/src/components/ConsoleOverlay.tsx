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
  /** 活跃常驻脚本数量变化回调，供顶部 Tab 显示真实角标 */
  onScriptsChange?: (count: number) => void;
};

type Line = {
  id: number;
  text: string;
  kind: "out" | "err" | "sys";
  ts?: string;
};

// (1) 第一次修改（2026-11-26）
// bug 原因：① 刷新页面后 refreshScripts 未将已存活脚本的 script_id 同步进 keepIds，常驻脚本永久静默；
//           ② keep 模式请求期间 800ms 轮询提前推进 cursor 导致首条输出丢失；
//           ③ once 模式强推 cursor=Math.max(cursor, Date.now()/1000) 吞掉并发常驻脚本输出；
//           ④ 头部「全停」发 {serial, pid} 无法全停，且不检查 r.ok 就清空 keepIds；
//           ⑤ once 出错时既丢弃已打印的 r.lines 又清空用户输入；
//           ⑥ 贴底依赖 lines.length 在满 500 行后失效；
//           ⑦ textarea 的 onKeyDown 未 stopPropagation 触发全局 Enter 快捷键；
//           ⑧ 残留废弃 isToolOutput/e.source 分支，且未校验 !fg.package 就请求 appProcesses。
// 解决方案：同步存活脚本到 keepIds；keep 模式记录 runStart 并在拿到 script_id 后补拉并去重；
//           once 改为维护 onceIds 过滤而绝不强推游标；全停发送 {} 且仅 r.ok 才清理 keepIds；
//           once 出错先输出已有 lines 且保留 input；贴底改用单调递增 lineSeq；
//           onKeyDown 调 e.stopPropagation()；清理废弃分支并加 !fg?.package 守卫。
export function ConsoleOverlay({ open, onScriptsChange }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const [lineSeq, setLineSeq] = useState(0);
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<"once" | "keep">("once");
  const [serial, setSerial] = useState("");
  const [pid, setPid] = useState("");
  const [busy, setBusy] = useState(false);
  const [scripts, setScripts] = useState<{ script_id: number; pid: number; age_s: number }[]>([]);

  const cursor = useRef(0);
  const keepIds = useRef<Set<number>>(new Set());
  const onceIds = useRef<Set<number>>(new Set());
  const seenEvents = useRef<Set<string>>(new Set());
  const seq = useRef(0);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const stick = useRef(true);
  const onScriptsRef = useRef(onScriptsChange);
  onScriptsRef.current = onScriptsChange;

  const push = useCallback((text: string, kind: Line["kind"] = "out", ts?: string) => {
    const id = ++seq.current;
    setLines((prev) => [...prev, { id, text, kind, ts }].slice(-500));
    setLineSeq(id);
  }, []);

  /** 将后端事件流渲染为终端行，按事件指纹去重防止补拉与轮询重复输出。 */
  const renderEvents = useCallback(
    (items: ApiConsoleEvent[], onlyScriptId?: number) => {
      for (const e of items) {
        const sid = e.script_id;
        if (sid == null) continue;
        if (onceIds.current.has(sid)) continue;
        if (onlyScriptId != null) {
          if (sid !== onlyScriptId) continue;
        } else if (!keepIds.current.has(sid)) {
          continue;
        }
        const evKey = `${e.t}|${sid}|${e.kind}|${e.text ?? e.error ?? e.reason ?? ""}`;
        if (seenEvents.current.has(evKey)) continue;
        seenEvents.current.add(evKey);
        if (seenEvents.current.size > 1000) {
          const first = seenEvents.current.values().next().value;
          if (first !== undefined) seenEvents.current.delete(first);
        }
        if (e.kind === "line") push(e.text ?? "", "out", e.ts);
        else if (e.kind === "error") push(e.error ?? "未知错误", "err", e.ts);
        else if (e.kind === "stop") push(`[脚本 #${sid} 已停止]`, "sys", e.ts);
      }
    },
    [push]
  );

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
      setSerial((v) => v || fg.serial!);
      if (!fg.package) return;
      try {
        const pr = await api.appProcesses({ package: fg.package, serial: fg.serial });
        if (!alive) return;
        const main = pr?.main_pid ?? pr?.processes?.[0]?.pid;
        if (main) setPid((v) => v || String(main));
      } catch { /* 留空让用户手填，绝不编造 */ }
    })();
    return () => { alive = false; };
  }, [open]);

  const refreshScripts = useCallback(async () => {
    const r = await api.fridaJsList();
    if (!r?.ok) return;
    const list = r.items ?? [];
    for (const s of list) {
      if (s.script_id != null) keepIds.current.add(s.script_id);
    }
    setScripts(list);
    onScriptsRef.current?.(list.length);
  }, []);

  // 启动时探测一次常驻脚本数，让 Tab 角标在未打开终端时也准确
  useEffect(() => {
    void refreshScripts();
  }, [refreshScripts]);

  // 轮询常驻脚本的持续输出：仅渲染属于 keepIds 且不在 onceIds 中的事件；
  // 先同步 refreshScripts 再拉首次事件，保证刷新页面后已存活常驻脚本立即恢复显示。
  useEffect(() => {
    if (!open) return;
    let alive = true;
    const tick = async () => {
      const r = await api.consoleEvents(cursor.current);
      if (!alive || !r?.ok) return;
      const items = r.items ?? [];
      if (!items.length) return;
      cursor.current = items.reduce((m, e) => Math.max(m, e.t || 0), cursor.current);
      renderEvents(items);
    };
    let timerId: number | null = null;
    void (async () => {
      await refreshScripts();
      if (!alive) return;
      await tick();
      if (!alive) return;
      timerId = window.setInterval(tick, 800);
    })();
    return () => {
      alive = false;
      if (timerId != null) window.clearInterval(timerId);
    };
  }, [open, refreshScripts, renderEvents]);

  useEffect(() => {
    if (!open) return;
    const h = window.setInterval(() => {
      void refreshScripts();
    }, 3000);
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
    const runStart = Date.now() / 1000;
    try {
      const r = await api.runFridaJs({ serial: serial.trim(), pid: pidNum, js, mode });
      if (mode === "once") {
        if (r?.script_id != null) onceIds.current.add(r.script_id);
        // once：即使脚本中途报错，也先把已打印出的行展示出来再报错误，且出错不清空 input
        if (r?.lines?.length) {
          for (const line of r.lines) push(line, "out");
        }
        if (!r?.ok) {
          push(r?.error ?? "执行失败", "err");
        } else {
          if (!r.lines?.length) push("（脚本没有打印任何内容）", "sys");
          setInput("");
        }
      } else {
        if (r?.script_id != null) keepIds.current.add(r.script_id);
        if (!r?.ok) {
          push(r?.error ?? "挂载失败", "err");
        } else {
          push(`[常驻脚本 #${r.script_id} 已启动，输出会实时打印在下面]`, "sys");
          setInput("");
          // 补拉自 runStart - 1 起该脚本已产生的事件，防止 800ms 轮询提前推进游标丢首条输出
          if (r.script_id != null) {
            const back = await api.consoleEvents(Math.max(0, runStart - 1));
            if (back?.ok && back.items?.length) {
              cursor.current = back.items.reduce((m, e) => Math.max(m, e.t || 0), cursor.current);
              renderEvents(back.items, r.script_id);
            }
          }
        }
      }
      void refreshScripts();
    } finally {
      setBusy(false);
    }
  }, [input, serial, pid, mode, push, refreshScripts, renderEvents]);

  const stopAll = useCallback(async (scriptId?: number) => {
    const r = await api.stopFridaJs(scriptId != null ? { script_id: scriptId } : {});
    if (r?.ok) {
      if (scriptId != null) keepIds.current.delete(scriptId);
      else keepIds.current.clear();
    } else if (r?.error) {
      push(`停止失败：${r.error}`, "err");
    }
    void refreshScripts();
  }, [push, refreshScripts]);

  // 贴底：依赖单调递增的 lineSeq，满 500 行截断后仍持续自动滚动到底部
  useEffect(() => {
    const el = bodyRef.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [lineSeq]);

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
              e.stopPropagation();
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
