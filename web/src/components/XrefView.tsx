import { useEffect, useState } from "react";
import { api, type ApiXrefItem, type ApiXrefNode } from "../lib/api";

/**
 * 引用页：当前函数被谁调用、又调用了谁。
 *
 * 这是逆向里最常用的动作——拿到一个函数，先看它处在调用图的哪个位置。
 * 名字由后端映射（前端拿地址没法显示成可读的名字）。
 */

type Props = {
  so: string;
  addr: number;
  fnName: string;
  onJump: (addr: number) => void;
};

function Column({
  title,
  items,
  empty,
  onJump,
}: {
  title: string;
  items: ApiXrefItem[];
  empty: string;
  onJump: (a: number) => void;
}) {
  return (
    <div className="xf-col">
      <div className="xf-hd">
        {title} <b>{items.length}</b>
      </div>
      <div className="xf-list">
        {!items.length && <div className="xf-empty">{empty}</div>}
        {items.map((it) => (
          <div
            key={it.addr}
            className="xf-row"
            onClick={() => onJump(parseInt(it.addr, 16))}
            title={`跳转到 ${it.name} @ ${it.addr}`}
          >
            <span className="xf-n">{it.name}</span>
            {it.is_export && <span className="xf-tag">导出</span>}
            <span className="xf-a">{it.addr}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function XrefView({ so, addr, fnName, onJump }: Props) {
  const [data, setData] = useState<ApiXrefNode | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    void (async () => {
      setBusy(true);
      setErr("");
      const r = await api.xrefTree(so, addr, 1);
      if (!alive) return;
      if (!r) setErr("引用图还没建好。先点顶部「建立引用图」，或等它后台完成。");
      else if ((r as unknown as { error?: string }).error) setErr(String((r as unknown as { error?: string }).error));
      else setData(r);
      setBusy(false);
    })();
    return () => {
      alive = false;
    };
  }, [so, addr]);

  return (
    <div className="xf-view">
      <div className="xf-bar">
        <span className="xf-cur">{fnName}</span>
        <span className="xf-cura">0x{addr.toString(16)}</span>
        {busy && <span className="xf-busy">读取中…</span>}
        {err && <span className="tv-err">{err}</span>}
      </div>
      <div className="xf-body">
        <Column
          title="调用者"
          items={data?.callers ?? []}
          empty={busy ? "" : "没有找到调用者（可能是导出函数，只被外部调）"}
          onJump={onJump}
        />
        <Column
          title="被调用"
          items={data?.callees ?? []}
          empty={busy ? "" : "没有找到被调用（叶子函数）"}
          onJump={onJump}
        />
      </div>
    </div>
  );
}
