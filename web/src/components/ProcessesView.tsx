import { useState } from "react";
import { api, type ApiProc, type ApiProcResult } from "../lib/api";

/**
 * 进程页：一个 App 到底有几个进程，哪个在真正跑网络。
 *
 * 解决的实际问题：抓包抓不到，很多时候不是工具不行，
 * 而是**网络根本不在你以为的那个进程里**。
 * 实测闲鱼有 4 个进程，网络分散在主进程 / :channel / :windowChannel。
 *
 * 判定口径（通用，不依赖任何库名）：
 *   inet_conns = 该进程 fd 里的 socket inode ∩ /proc/net/tcp|udp 的 inode
 *   这才是「在跑网络」；只统计 socket 总数会把只用 unix socket 的进程误报。
 */

function msOf(role: string) {
  return role || "—";
}

export function ProcessesView() {
  const [input, setInput] = useState("");
  const [res, setRes] = useState<ApiProcResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function probe() {
    const raw = input.trim();
    if (!raw) return;
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      const opt = /^\d+$/.test(raw) ? { pid: Number(raw) } : { package: raw };
      const r = await api.appProcesses(opt);
      if (!r) {
        setErr("请求失败：后端未连接");
      } else if (r.ok === false || r.error) {
        setErr(r.error ?? "查询失败");
      } else {
        setRes(r);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const procs: ApiProc[] = res?.processes ?? [];
  const netSet = new Set(res?.network_pids ?? []);

  return (
    <div className="proc-view">
      <div className="pv-bar">
        <input
          className="tv-search"
          placeholder="包名或 PID，例如 com.taobao.idlefish / 31182"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !busy && void probe()}
        />
        <button className="mon-btn on" onClick={() => void probe()} disabled={busy || !input.trim()}>
          {busy ? "查询中…" : "查询"}
        </button>
        {res?.package && <span className="pv-pkg">{res.package}</span>}
        {err && <span className="tv-err">{err}</span>}
      </div>

      {!res && !busy && !err && (
        <div className="tv-empty" style={{ padding: "18px 14px", lineHeight: 1.8 }}>
          输入包名或 PID，查这个 App 有哪些进程、哪个在跑网络。
          <br />
          纯读 /proc，不注入、不 attach，目标完全无感知。
        </div>
      )}

      {res && (
        <>
          <div className="pv-summary">
            <span><b>{res.count ?? procs.length}</b> 个进程</span>
            <span className="pv-sep">·</span>
            <span><b>{netSet.size}</b> 个在跑网络</span>
            {res.network_basis && (
              <span className="pv-basis" title={
                res.network_basis === "inet_conns"
                  ? "用 socket inode 与 /proc/net/* 求交集，进程级准确"
                  : "没取到 inet 连接数，退回「所有 socket」的宽口径，可能含只用 unix socket 的进程"
              }>
                {res.network_basis === "inet_conns" ? "口径：真实 inet 连接" : "口径：socket 总数（宽）"}
              </span>
            )}
          </div>

          <div className="pv-table">
            <div className="pv-hd">
              <span className="c-pid">PID</span>
              <span className="c-name">进程</span>
              <span className="c-role">用途</span>
              <span className="c-num">inet</span>
              <span className="c-num">socket</span>
              <span className="c-num">so</span>
            </div>
            {procs.map((p) => (
              <div className={"pv-row" + (netSet.has(p.pid) ? " net" : "")} key={p.pid}>
                <span className="c-pid">{p.pid}</span>
                <span className="c-name" title={p.name}>
                  {p.is_main ? p.name : "…" + p.suffix}
                </span>
                <span className="c-role">{msOf(p.role)}</span>
                <span className={"c-num" + ((p.inet_conns ?? 0) > 0 ? " hot" : "")}>
                  {p.inet_conns ?? "—"}
                </span>
                <span className="c-num dim">{p.sockets ?? "—"}</span>
                <span className="c-num dim">{p.loaded_so_count ?? "—"}</span>
              </div>
            ))}
          </div>

          {res.verdict && <div className="pv-verdict">{res.verdict}</div>}
          {res.hint && <div className="pv-hint">{res.hint}</div>}
        </>
      )}
    </div>
  );
}
