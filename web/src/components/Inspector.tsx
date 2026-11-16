import { useEffect, useState } from "react";
import { api, type ApiFnDetail } from "../lib/api";
import type { ModuleData } from "../lib/data";
import { hex } from "../lib/data";

/**
 * 右侧函数检视器 —— 与原型 aside.insp 同构。
 *
 * 原型把「一个函数的所有已知事实」摊在右边：
 *   概况（引用数/调用者/被调用/所在段/连接）
 *   调用者列表  被调用列表  引用字符串  动态（断点/命中）
 *
 * 之前这里是一个 1900 行的函数列表（虚拟滚动），人能翻但不能看。
 * 列表的意义是"找"，检视器的意义是"看清一个"——原型要的是后者。
 *
 * 数据全部来自 /api/fn_detail，前端不做任何推断。
 */

type Props = {
  mods: ModuleData[];
  /** 当前选中的函数；为空时显示"没选中" */
  current: { so: string; addr: number; name: string } | null;
  /** 在这几个列表里点某一行 → 跳到那个函数 */
  onPickFn: (so: string, addr: number) => void;
};

const MAX_ROWS = 4;   // 原型只列 4 行，其余折叠成"还有 N 个…"

export function Inspector({ current, onPickFn }: Props) {
  const [d, setD] = useState<ApiFnDetail | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!current) {
      setD(null);
      return;
    }
    let alive = true;
    setLoading(true);
    void (async () => {
      const r = await api.fnDetail(current.so, current.addr);
      if (!alive) return;
      setD(r ?? null);
      setLoading(false);
    })();
    return () => {
      alive = false;
    };
  }, [current?.so, current?.addr]);

  if (!current) {
    return (
      <aside className="insp">
        <div className="insp-empty">在左边选一个函数，这里显示它的全部已知事实</div>
      </aside>
    );
  }

  const seg = d?.section || "—";
  return (
    <aside className="insp">
      {/* 头部：名字 + 导出 + 地址 · 大小 */}
      <div className="insp-hd">
        <div className="insp-nm" title={current.name}>{current.name}</div>
        <div className="insp-meta">
          {d?.is_export && <span className="insp-badge">导出</span>}
          <span className="insp-addr">{hex(current.addr)}</span>
          <span className="insp-sep">·</span>
          <span>{d?.size ?? 0} B</span>
          {loading && <span className="insp-loading">…</span>}
        </div>
      </div>

      {/* 概况 */}
      <div className="insp-sec">
        <div className="insp-sec-hd">概况</div>
        <div className="insp-sec-bd">
          <div className="kv"><span className="k">引用数</span><span className="v">{d ? d.refs_in + d.refs_out : "—"}</span></div>
          <div className="kv"><span className="k">调用者</span><span className="v">{d ? `${d.refs_in} 个` : "—"}</span></div>
          <div className="kv"><span className="k">被调用</span><span className="v">{d ? `${d.refs_out} 个` : "—"}</span></div>
          <div className="kv"><span className="k">所在段</span><span className="v">{seg}</span></div>
          <div className="kv">
            <span className="k">连接</span>
            <span className={"v" + (d?.attached ? "" : " dim")}>
              {d?.attached ? "已附加" : "未附加"}
            </span>
          </div>
        </div>
      </div>

      {/* 调用者 */}
      <div className="insp-sec">
        <div className="insp-sec-hd">调用者<b>{d?.refs_in ?? 0}</b></div>
        <div className="insp-sec-bd">
          {(d?.callers ?? []).slice(0, MAX_ROWS).map((c) => (
            <div
              className="insp-xref"
              key={c.addr}
              onClick={() => onPickFn(current.so, parseInt(c.addr, 16))}
              title={`跳到 ${c.name}`}
            >
              <span className="fn">{c.name}</span>
              <span className="a">{c.addr}</span>
            </div>
          ))}
          {(d?.refs_in ?? 0) > MAX_ROWS && (
            <div className="insp-xref more">还有 {d!.refs_in - MAX_ROWS} 个…</div>
          )}
          {d && d.refs_in === 0 && <div className="insp-none">没有函数调用它</div>}
        </div>
      </div>

      {/* 被调用 */}
      <div className="insp-sec">
        <div className="insp-sec-hd">被调用<b>{d?.refs_out ?? 0}</b></div>
        <div className="insp-sec-bd">
          {(d?.callees ?? []).slice(0, MAX_ROWS).map((c) => (
            <div
              className="insp-xref"
              key={c.addr}
              onClick={() => !c.plt && onPickFn(current.so, parseInt(c.addr, 16))}
              title={c.plt ? "外部导入（跨 so / libc），不在本模块内" : `跳到 ${c.name}`}
            >
              <span className="fn">{c.name}</span>
              <span className={"a" + (c.plt ? " dim" : "")}>{c.plt ? "plt" : c.addr}</span>
            </div>
          ))}
          {(d?.refs_out ?? 0) > MAX_ROWS && (
            <div className="insp-xref more">还有 {d!.refs_out - MAX_ROWS} 个…</div>
          )}
          {d && d.refs_out === 0 && <div className="insp-none">它没有调用别的函数</div>}
        </div>
      </div>

      {/* 引用字符串 */}
      <div className="insp-sec">
        <div className="insp-sec-hd">引用字符串<b>{d?.strings.length ?? 0}</b></div>
        <div className="insp-sec-bd">
          {(d?.strings ?? []).slice(0, 6).map((s) => (
            <div className="insp-str" key={s.addr} title={s.value}>
              <q>{s.value}</q>
            </div>
          ))}
          {d && d.strings.length === 0 && (
            <div className="insp-none">没有引用到字符串</div>
          )}
        </div>
      </div>

      {/* 动态 */}
      <div className="insp-sec">
        <div className="insp-sec-hd">动态</div>
        <div className="insp-sec-bd">
          <div className="kv">
            <span className="k">断点</span>
            <span className={"v" + (d?.breakpoint ? "" : " dim")}>
              {d?.breakpoint ? "已设置" : "未设置"}
            </span>
          </div>
          <div className="kv">
            <span className="k">命中</span>
            <span className={"v" + (d?.hits ? "" : " dim")}>{d?.hits ?? 0} 次</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
