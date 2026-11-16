import { useEffect, useState } from "react";
import { api, type ApiDynState } from "../lib/api";

/**
 * 动态状态视图：断点 / 命中 / 内存 / 派发点 / 行为监控。
 *
 * 为什么合并成一个组件而不是五个：这五类数据来自同一个接口
 * （/api/dyn_state），拆成五个组件只会重复写加载逻辑和空状态。
 * 用 kind 区分展示哪一段。
 *
 * 设计原则：**没有数据就说没有，不画假的行**。
 * 左栏的入口以前点了没反应（原文写着"原型同样不可点"），
 * 但 AI 确实在操作这些东西——界面看不到等于用户瞎了。
 */

export type DynKind = "bp" | "hits" | "mem" | "dispatch" | "regs" | "trace" | "behavior";

const TITLES: Record<DynKind, { title: string; sub: string }> = {
  bp: { title: "断点", sub: "当前进程里装着的断点（AI 通过 set_breakpoint 下的）" },
  hits: { title: "命中", sub: "断点命中的现场记录（时间倒序，最多 100 条）" },
  mem: { title: "内存", sub: "内存快照文件（mem_snapshot 留下的）" },
  dispatch: { title: "派发点", sub: "VM 派发点扫描结果" },
  regs: { title: "寄存器", sub: "VM 寄存器快照" },
  trace: { title: "轨迹", sub: "指令级 trace 采集记录" },
  behavior: { title: "行为监控", sub: "钩住的 API 类别（算法 / 文件 / Activity / assets）" },
};

export function DynStateView({ kind }: { kind: DynKind }) {
  const [d, setD] = useState<ApiDynState | null>(null);
  const [err, setErr] = useState("");
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const got = await api.dynState();
        if (!alive) return;
        setD(got);
        setErr("");
      } catch (e) {
        if (alive) setErr(String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [tick]);

  // 动态数据会变（断点被删、命中增加），5 秒自动刷一次。
  // 不用 WebSocket：这些数据变化频率低，轮询更简单且不会影响事件流的带宽。
  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 5000);
    return () => window.clearInterval(id);
  }, []);

  const meta = TITLES[kind];
  const rows = pick(d, kind);

  return (
    <div className="dynview">
      <div className="dyn-hd">
        <b>{meta.title}</b>
        <span className="dyn-sub">{meta.sub}</span>
        {rows.length > 0 && <span className="dyn-n">{rows.length}</span>}
        <button className="dyn-refresh" onClick={() => setTick((t) => t + 1)}>
          刷新
        </button>
      </div>

      {err && <div className="dyn-err">读取失败：{err}</div>}

      {!err && rows.length === 0 && (
        <div className="dyn-empty">
          <div className="dyn-empty-t">还没有数据</div>
          <div className="dyn-empty-s">{emptyHint(kind)}</div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="dyn-list">
          {rows.map((r, i) => (
            <div className="dyn-row" key={i}>
              {Object.entries(r).map(([k, v]) => (
                <span className="dyn-cell" key={k}>
                  <i>{k}</i>
                  <b>{fmt(v)}</b>
                </span>
              ))}
            </div>
          ))}
        </div>
      )}

      {d?.errors?.length ? (
        <div className="dyn-warn">
          {d.errors.map((e, i) => (
            <div key={i}>{e}</div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/** 从接口返回里挑出当前 kind 需要的行。 */
function pick(d: ApiDynState | null, kind: DynKind): Record<string, unknown>[] {
  if (!d) return [];
  if (kind === "bp") {
    return (d.breakpoints ?? []).map((b) => ({
      so: b.so,
      addr: b.addr_hex,
      hold: b.hold ? "是" : "否",
      pid: b.pid,
      armed: b.armed ? "已装" : "未装",
    }));
  }
  if (kind === "hits") {
    return (d.hits ?? []).map((h) => ({
      so: h.so,
      addr: h.static_hex,
      tid: h.tid,
      seq: h.seq,
      held: h.held ? "挂起" : "",
    }));
  }
  if (kind === "mem") {
    return (d.memory ?? []).map((m) => ({
      快照: m.name,
      大小: fmtSize(m.size),
      时间: new Date(m.mtime * 1000).toLocaleTimeString(),
    }));
  }
  if (kind === "behavior") {
    const on = d.behavior?.categories ?? [];
    if (!d.behavior?.armed) return [];
    return on.map((c) => ({ 已挂: c }));
  }
  return (d.vm?.[kind] ?? []) as Record<string, unknown>[];
}

function emptyHint(kind: DynKind): string {
  const map: Record<DynKind, string> = {
    bp: "让 AI 调 set_breakpoint(serial, pid, so_name, static_addr) 就能在这里看到",
    hits: "断点命中后会自动出现在这里；也可以用 poll_events / wait_hits 主动取",
    mem: "让 AI 调 mem_snapshot(key=...) 拍一份快照",
    dispatch: "让 AI 调 find_dispatch_tables(so_name) 扫描跳转表",
    regs: "让 AI 调 vm_regs_snapshot(serial, pid, so_name) 抓一次 VM 现场",
    trace: "让 AI 调 trace_code(serial, pid) 采集调用关系",
    behavior: "让 AI 调 behavior_monitor_start(serial, pid) 后，钩住的类别会显示在这里",
  };
  return map[kind];
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "是" : "否";
  return String(v);
}

function fmtSize(n: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * 「这个视图需要 so，但还没有」的解释页。
 *
 * 为什么单独一个组件：原来这些页面在没加载 so 时**什么都不渲染**，
 * 用户点了左栏看到一片空白，分不清是"没有数据"还是"程序坏了"。
 * 统一给一句原因 + 打开入口，比留白有用得多。
 */
export function NeedSoView({ what, why }: { what: string; why: string }) {
  return (
    <div className="dynview">
      <div className="dyn-empty">
        <div className="dyn-empty-t">还需要载入一个 so 才能看{what}</div>
        <div className="dyn-empty-s">{why}</div>
        <div className="dyn-empty-s" style={{ marginTop: 8, color: "var(--fg3)" }}>
          也可以让 AI 直接调 load_so(path=...) 载入
        </div>
      </div>
    </div>
  );
}
