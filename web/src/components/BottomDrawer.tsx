import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { hex } from "../lib/data";
import { ConsoleOverlay } from "./ConsoleOverlay";

type PluginKey = "struct_infer" | "sensitive_scan" | "func_profile";

type StructField = {
  offset: string;
  width: number;
  ctype: string;
  accesses?: unknown[];
};

type SensItem = { kind: string; addr: string; value: string };
type ProfileItem = { name: string; addr: string; insns: number; calls: number; strings: number };

type Props = {
  open: boolean;
  height: number;
  tab: "plugins" | "terminal";
  onChangeTab: (tab: "plugins" | "terminal") => void;
  onClose: () => void;
  so: string;
  fnAddr: number | null;
  fnName: string;
  onJumpFn: (so: string, addr: number) => void;
  liveScripts: number;
  onScriptsChange: (count: number) => void;
};

/**
 * 底部可拖拽常驻抽屉（⌘J）：
 * - Tab 1「插件快捷分析」：直接调真实后端 /api/plugin_run（struct_infer / sensitive_scan / func_profile）
 * - Tab 2「Frida 终端」：内嵌真实 ConsoleOverlay，完整保留真机一次性/常驻脚本执行与输出流
 */
export function BottomDrawer({
  open,
  height,
  tab,
  onChangeTab,
  onClose,
  so,
  fnAddr,
  fnName,
  onJumpFn,
  liveScripts,
  onScriptsChange,
}: Props) {
  const [pluginKey, setPluginKey] = useState<PluginKey>("struct_infer");
  const [loading, setLoading] = useState(false);
  const [structBase, setStructBase] = useState("x0");
  const [structFields, setStructFields] = useState<StructField[]>([]);
  const [sensitive, setSensitive] = useState<SensItem[]>([]);
  const [profiles, setProfiles] = useState<ProfileItem[]>([]);

  // 仅在抽屉展开且位于插件页时，按需向真实后端拉取插件分析结果
  useEffect(() => {
    if (!open || tab !== "plugins" || !so) return;
    let alive = true;
    setLoading(true);
    void (async () => {
      if (pluginKey === "struct_infer") {
        if (fnAddr == null) {
          setStructFields([]);
          setLoading(false);
          return;
        }
        const r = await api.pluginRun<{ ok?: boolean; base_reg?: string; fields?: StructField[] }>(
          "struct_infer",
          { so, addr: hex(fnAddr) }
        );
        if (!alive) return;
        setStructBase(r?.base_reg || "x0");
        setStructFields(r?.ok && Array.isArray(r.fields) ? r.fields : []);
      } else if (pluginKey === "sensitive_scan") {
        const r = await api.pluginRun<Record<string, { items?: { addr: string; value: string }[] }>>(
          "sensitive_scan",
          { so }
        );
        if (!alive) return;
        const flat: SensItem[] = [];
        if (r) {
          for (const [k, v] of Object.entries(r)) {
            if (v && Array.isArray(v.items)) {
              for (const it of v.items) {
                flat.push({ kind: k, addr: String(it.addr), value: String(it.value) });
              }
            }
          }
        }
        setSensitive(flat);
      } else {
        const r = await api.pluginRun<{
          profiles?: { name: string; addr: string; insns?: number; calls?: unknown[] | number; strings?: number }[];
        }>("func_profile", { so });
        if (!alive) return;
        const rows = (r?.profiles ?? []).slice(0, 25).map((p) => ({
          name: p.name,
          addr: String(p.addr),
          insns: Number(p.insns ?? 0),
          calls: Array.isArray(p.calls) ? p.calls.length : Number(p.calls ?? 0),
          strings: Number(p.strings ?? 0),
        }));
        setProfiles(rows);
      }
      if (alive) setLoading(false);
    })();
    return () => { alive = false; };
  }, [open, tab, pluginKey, so, fnAddr]);

  return (
    <section
      className={"v2-drawer" + (open ? "" : " collapsed")}
      style={{ height: open ? height : 0 }}
    >
      <div className="v2-drawer-hd">
        <button
          className={"v2-dtab" + (tab === "plugins" ? " on" : "")}
          onClick={() => onChangeTab("plugins")}
        >
          <svg className="ic ic-sm" viewBox="0 0 16 16">
            <path d="M6 2v4M10 2v4M4 6h8v2.5a4 4 0 0 1-8 0V6zM8 12.5V14" />
          </svg>
          插件快捷分析
        </button>
        <button
          className={"v2-dtab" + (tab === "terminal" ? " on" : "")}
          onClick={() => onChangeTab("terminal")}
        >
          <svg className="ic ic-sm" viewBox="0 0 16 16">
            <path d="M2.5 4.5L6 8l-3.5 3.5M7.5 11.5h6" />
          </svg>
          Frida 终端{liveScripts > 0 ? ` (${liveScripts})` : ""}
        </button>
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--fg-3)" }}>
          {tab === "plugins"
            ? so
              ? `当前焦点：${so}${fnAddr != null ? `!${fnName} (${hex(fnAddr)})` : ""}`
              : "先打开一个 so 后可使用插件分析"
            : "Enter 执行 · Shift+Enter 换行（直连后端 frida_js）"}
        </span>
        <button className="v2-icon-btn" onClick={onClose} title="收起抽屉 (⌘J)">
          <svg className="ic ic-sm" viewBox="0 0 16 16">
            <path d="M4 6l4 4 4-4" />
          </svg>
        </button>
      </div>

      <div className="v2-drawer-body">
        <div
          className="v2-plug-wrap"
          style={{ display: tab === "plugins" ? "flex" : "none" }}
        >
          <div className="v2-plug-nav">
            {(
              [
                ["struct_infer", "结构体推断", structFields.length],
                ["sensitive_scan", "敏感信息扫描", sensitive.length],
                ["func_profile", "热函数画像", profiles.length],
              ] as [PluginKey, string, number][]
            ).map(([k, label, cnt]) => (
              <button
                key={k}
                className={"v2-plug-btn" + (pluginKey === k ? " on" : "")}
                onClick={() => setPluginKey(k)}
              >
                <span>{label}</span>
                <span className="mono" style={{ fontSize: 10, color: "var(--fg-3)" }}>
                  {cnt || "—"}
                </span>
              </button>
            ))}
          </div>
          <div className="v2-plug-out">
            {!so ? (
              <div style={{ color: "var(--fg-3)" }}>请先打开或拖入一个 .so 文件。</div>
            ) : loading ? (
              <div style={{ color: "var(--fg-3)" }}>正在运行 {pluginKey} 插件…</div>
            ) : pluginKey === "struct_infer" ? (
              structFields.length > 0 ? (
                <table className="v2-plug-tbl">
                  <thead>
                    <tr><th>基址寄存器</th><th>偏移</th><th>推断类型</th><th>宽度</th><th>访问次数</th></tr>
                  </thead>
                  <tbody>
                    {structFields.map((f, i) => (
                      <tr key={i}>
                        <td>{structBase}</td>
                        <td style={{ color: "var(--c-imm)" }}>{f.offset}</td>
                        <td style={{ color: "var(--c-type)" }}>{f.ctype}</td>
                        <td>{f.width} B</td>
                        <td>{Array.isArray(f.accesses) ? f.accesses.length : 1}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ color: "var(--fg-3)" }}>
                  当前函数未检测到连续 [reg+offset] 结构体访问（切换含结构体指针操作的函数即可实时推断）。
                </div>
              )
            ) : pluginKey === "sensitive_scan" ? (
              sensitive.length > 0 ? (
                <table className="v2-plug-tbl">
                  <thead>
                    <tr><th>类别</th><th>地址</th><th>真实命中的字符串</th></tr>
                  </thead>
                  <tbody>
                    {sensitive.map((s, i) => (
                      <tr key={i}>
                        <td>{s.kind}</td>
                        <td style={{ color: "var(--fg-3)" }}>{s.addr}</td>
                        <td style={{ color: "var(--c-str)" }}>{s.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ color: "var(--fg-3)" }}>未命中敏感路径/URL/密钥特征字符串。</div>
              )
            ) : profiles.length > 0 ? (
              <table className="v2-plug-tbl">
                <thead>
                  <tr><th>函数</th><th>地址</th><th>指令数</th><th>调用数</th><th>引用字符串</th></tr>
                </thead>
                <tbody>
                  {profiles.map((p, i) => (
                    <tr
                      key={i}
                      style={{ cursor: "pointer" }}
                      onClick={() => onJumpFn(so, parseInt(p.addr, 16))}
                    >
                      <td style={{ color: "var(--c-call)" }}>{p.name}</td>
                      <td>{p.addr}</td>
                      <td>{p.insns}</td>
                      <td>{p.calls}</td>
                      <td>{p.strings}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div style={{ color: "var(--fg-3)" }}>暂无函数画像数据。</div>
            )}
          </div>
        </div>
        <div
          style={{
            display: tab === "terminal" ? "flex" : "none",
            flex: 1,
            minHeight: 0,
            flexDirection: "column",
          }}
        >
          <ConsoleOverlay open={open && tab === "terminal"} onScriptsChange={onScriptsChange} />
        </div>
      </div>
    </section>
  );
}
