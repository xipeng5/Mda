import { useState } from "react";

type WatchItem = { so: string; name: string; addr: number };

type Props = {
  logs: { time: string; text: string; kind?: string }[];
  watch: WatchItem[];
  onPickWatch: (w: WatchItem) => void;
};

const hex = (a: number) => "0x" + a.toString(16);

export function LeftPanel({ logs, watch, onPickWatch }: Props) {
  const [tab, setTab] = useState<"log" | "watch">("log");
  return (
    <aside className="left">
      <div className="left-head">
        <button className={"tab" + (tab === "log" ? " on" : "")} onClick={() => setTab("log")}>日志</button>
        <button className={"tab" + (tab === "watch" ? " on" : "")} onClick={() => setTab("watch")}>观察</button>
      </div>
      {tab === "log" ? (
        <div className="left-body">
          {logs.map((l, i) => (
            <div key={i} className={"log-line" + (l.kind ? " " + l.kind : "")} title={`[${l.time}] ${l.text}`}>
              <span className="t">[{l.time}]</span> {l.text}
            </div>
          ))}
        </div>
      ) : (
        <div className="left-body">
          {watch.length === 0 && <div className="log-line" style={{ border: 0 }}>还没有 AI 操作。</div>}
          {watch.map((w, i) => (
            <div key={i} className="log-line" style={{ cursor: "pointer" }} onClick={() => onPickWatch(w)}>
              <span className="k">{w.name}</span> <span className="t">{hex(w.addr)}</span>
            </div>
          ))}
        </div>
      )}
    </aside>
  );
}
