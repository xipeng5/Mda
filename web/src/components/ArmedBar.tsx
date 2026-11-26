import { useEffect, useState } from "react";
import { api, type ApiArmed } from "../lib/api";

/**
 * 待命条：AI 现在在哪些目标上装着监控。
 *
 * 和事件流的区别：事件流是**一次性**的（调完就过去），
 * 待命是**持久状态**——断点装上后一直在那儿，直到被撤掉。
 * 这是「AI 正在盯着什么」唯一能持续看见的地方。
 */
export function ArmedBar() {
  const [items, setItems] = useState<ApiArmed[]>([]);
  const [open, setOpen] = useState(false);

  // (1) 第一次修改（2026-11-26）
  // bug 原因：首屏异步拉取 armed 缺少取消标志。
  // 解决方案：增加 alive 标志防止组件卸载后 setState。
  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await api.armed();
      if (alive && r) setItems(r.items ?? []);
    })();
    return () => {
      alive = false;
    };
  }, []);

  /* WebSocket 推来的变化由 App 处理；这里只负责首屏 */
  useEffect(() => {
    const onUpdate = (e: Event) => {
      const detail = (e as CustomEvent<ApiArmed[]>).detail;
      setItems(detail ?? []);
    };
    window.addEventListener("mda:armed", onUpdate);
    return () => window.removeEventListener("mda:armed", onUpdate);
  }, []);

  if (!items.length) {
    return (
      <div className="arm-bar">
        <span className="arm-idle">没有正在待命的监控</span>
      </div>
    );
  }

  return (
    <div className={"arm-bar" + (open ? " open" : "")}>
      <button className="arm-toggle" onClick={() => setOpen((v) => !v)}>
        <span className="arm-dot" />
        待命中 <b>{items.length}</b>
        <span className="arm-chev">{open ? "▾" : "▸"}</span>
      </button>

      {!open && (
        <span className="arm-preview">
          {items.slice(0, 3).map((it) => (
            <span key={it.key} className="arm-chip" title={`${it.tool} · ${it.ts}`}>
              {it.label}
            </span>
          ))}
          {items.length > 3 && <span className="arm-more">+{items.length - 3}</span>}
        </span>
      )}

      {open && (
        <div className="arm-list">
          {items.map((it) => (
            <div key={it.key} className="arm-row">
              <span className="arm-t">{it.ts}</span>
              <span className="arm-tool">{it.tool}</span>
              <span className="arm-l">{it.label}</span>
            </div>
          ))}
          <div className="arm-note">
            这是 AI 当前装着的监控。点「清空」只清这个列表，
            设备上的断点/监控还在——要真撤掉，让 AI 调对应的 stop/remove。
          </div>
        </div>
      )}
    </div>
  );
}
