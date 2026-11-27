import { useEffect, useMemo, useRef, useState } from "react";
import type { ApiTool } from "../lib/api";
import { hex, type ModuleData } from "../lib/data";
import { classifyTool, TOOL_LABEL } from "../lib/toolMeta";

export type PaletteAction = {
  kind: string;
  title: string;
  meta: string;
  run: () => void;
};

type Props = {
  open: boolean;
  onClose: () => void;
  modules: ModuleData[];
  tools: ApiTool[];
  actions: PaletteAction[];
  onJumpFn: (so: string, addr: number) => void;
  onPickTool: (toolName: string) => void;
};

/**
 * ⌘K / Ctrl+K 全局命令面板：跨模块搜任意函数、137 个真实 MCP 工具、视图与快捷操作。
 */
export function CommandPalette({
  open,
  onClose,
  modules,
  tools,
  actions,
  onJumpFn,
  onPickTool,
}: Props) {
  const [query, setQuery] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setIdx(0);
    const id = window.setTimeout(() => inputRef.current?.focus(), 10);
    return () => window.clearTimeout(id);
  }, [open]);

  const items = useMemo<PaletteAction[]>(() => {
    const kw = query.trim().toLowerCase();
    const out: PaletteAction[] = [];

    for (const a of actions) {
      if (!kw || a.title.toLowerCase().includes(kw) || a.meta.toLowerCase().includes(kw)) {
        out.push(a);
      }
    }

    for (const t of tools) {
      const text = `${t.name} ${t.desc}`.toLowerCase();
      if (!kw || text.includes(kw)) {
        out.push({
          kind: "工具",
          title: `${t.name} — ${t.desc}`,
          meta: TOOL_LABEL[classifyTool(t.name)] || "工具",
          run: () => onPickTool(t.name),
        });
      }
      if (out.length >= 36 && kw) break;
    }

    for (const mod of modules) {
      for (const fn of mod.funcs) {
        if (
          !kw ||
          fn.n.toLowerCase().includes(kw) ||
          hex(fn.a).includes(kw) ||
          mod.so.toLowerCase().includes(kw)
        ) {
          out.push({
            kind: "函数",
            title: fn.n,
            meta: `${mod.so} · ${hex(fn.a)}`,
            run: () => onJumpFn(mod.so, fn.a),
          });
        }
        if (out.length >= 42) break;
      }
      if (out.length >= 42) break;
    }

    return out.slice(0, 32);
  }, [query, actions, tools, modules, onJumpFn, onPickTool]);

  useEffect(() => {
    if (idx >= items.length) setIdx(0);
  }, [items.length, idx]);

  if (!open) return null;

  const exec = (i: number) => {
    const it = items[i];
    onClose();
    if (it) it.run();
  };

  return (
    <div
      className="v2-palette-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="v2-palette" role="dialog" aria-label="全局命令面板">
        <div className="v2-palette-in">
          <svg className="ic" style={{ color: "var(--fg-3)" }} viewBox="0 0 16 16">
            <circle cx="7" cy="7" r="4.5" />
            <path d="M10.5 10.5L14 14" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setIdx(0); }}
            onKeyDown={(e) => {
              e.stopPropagation();
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setIdx((v) => Math.min(items.length - 1, v + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setIdx((v) => Math.max(0, v - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                exec(idx);
              } else if (e.key === "Escape") {
                e.preventDefault();
                onClose();
              }
            }}
            placeholder="搜索任意函数、137 个 MCP 工具、地址或视图（工具流 / 伪代码 / CFG / 终端）…"
            autoComplete="off"
          />
          <span className="v2-kbd">Esc</span>
        </div>
        <div className="v2-palette-list">
          {items.map((it, i) => (
            <div
              key={`${it.kind}-${it.title}-${i}`}
              className={"v2-pal-row" + (i === idx ? " active" : "")}
              onMouseEnter={() => setIdx(i)}
              onClick={() => exec(i)}
            >
              <span className="v2-pal-kind">{it.kind}</span>
              <span className="v2-pal-title">{it.title}</span>
              <span className="v2-pal-meta">{it.meta}</span>
            </div>
          ))}
          {!items.length && (
            <div style={{ padding: 20, textAlign: "center", color: "var(--fg-3)" }}>
              没有匹配项
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
