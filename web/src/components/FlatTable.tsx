import { useEffect, useMemo, useState } from "react";
import { api, type ApiSection, type ApiString } from "../lib/api";

/**
 * 段/节 与 字符串 两个视图。
 *
 * 为什么放在一个文件：两者都是「平表 + 搜索」，结构完全一样，
 * 只有列定义不同。分成两个文件会是复制粘贴。
 *
 * 这两个表都是判断 so 有没有被加固的第一手依据：
 *   · 段表缺 .text / 权限异常（W+X）→ 可疑
 *   · 字符串里没有业务文案（IL2CPP 常见）→ 说明数据在别处
 */

type Props = { so: string; kind: "sections" | "strings" };

export function FlatTable({ so, kind }: Props) {
  const [sections, setSections] = useState<ApiSection[]>([]);
  const [strings, setStrings] = useState<ApiString[]>([]);
  const [kw, setKw] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!so) return;
    void (async () => {
      if (kind === "sections") {
        const r = await api.sections(so);
        if (r) setSections(r.items ?? []);
        else setErr("读不到段表");
      } else {
        const r = await api.strings(so, "");
        if (r) setStrings((r.items ?? []).slice(0, 2000));
        else setErr("读不到字符串表");
      }
    })();
  }, [so, kind]);

  const rows = useMemo(() => {
    const q = kw.trim().toLowerCase();
    if (kind === "sections") {
      if (!q) return sections;
      return sections.filter((s) => s.name.toLowerCase().includes(q));
    }
    if (!q) return strings;
    return strings.filter((s) => s.value.toLowerCase().includes(q));
  }, [kind, sections, strings, kw]);

  if (!so) {
    return <div className="tv-empty">先打开一个 so</div>;
  }

  return (
    <div className="ft-view">
      <div className="ft-bar">
        <input
          className="tv-search"
          placeholder={kind === "sections" ? "搜段名…" : "搜字符串内容…"}
          value={kw}
          onChange={(e) => setKw(e.target.value)}
        />
        <span className="tv-count">
          {rows.length} 条{kw ? ` / ${kind === "sections" ? sections.length : strings.length}` : ""}
        </span>
        {err && <span className="tv-err">{err}</span>}
      </div>

      <div className="ft-list">
        {kind === "sections" ? (
          <>
            <div className="ft-hd ft-sec">
              <span>段名</span>
              <span>地址</span>
              <span>偏移</span>
              <span>大小</span>
              <span>权限</span>
            </div>
            {rows.map((r) => (
              <div className="ft-row ft-sec" key={r.name}>
                <span className="ft-n">{r.name}</span>
                <span className="ft-m">{r.addr}</span>
                <span className="ft-m">{r.offset}</span>
                <span className="ft-m">
                  {r.size >= 1024 ? `${(r.size / 1024).toFixed(1)}K` : r.size}
                </span>
                <span className={r.flags.includes("W") && r.flags.includes("X") ? "ft-warn" : "ft-m"}>
                  {r.flags || "—"}
                </span>
              </div>
            ))}
          </>
        ) : (
          rows.map((r, i) => (
            <div className="ft-row ft-str" key={`${r.addr}-${i}`}>
              <span className="ft-m">0x{r.addr.toString(16)}</span>
              <span className="ft-s">{r.value}</span>
              <span className="ft-r">{r.refs}</span>
            </div>
          ))
        )}
        {!rows.length && (
          <div className="tv-empty">
            {kind === "sections" ? "没有段表（可能被剥掉了）" : "没有匹配的字符串"}
          </div>
        )}
      </div>
    </div>
  );
}
