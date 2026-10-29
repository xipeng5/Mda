export type HudData = { kind: string; so: string; fn: string; addr: string; detail: string };

const KIND: Record<string, string> = {
  ai: "AI 操作", disasm: "反汇编",
};

/** 半透明操作卡：压在球上，讲清"刚刚对谁做了什么"。 */
export function Hud({ hud, onClose }: { hud: HudData | null; onClose: () => void }) {
  return (
    <div className={"hud" + (hud ? " on" : "")}>
      <div className="hud-head">
        <i className="dot live" />
        <span>{hud ? KIND[hud.kind] ?? hud.kind : "操作"}</span>
        <span className="grow" />
        <span style={{ color: "var(--fg3)", cursor: "pointer" }} onClick={onClose}>ESC 关闭</span>
      </div>
      <div className="hud-scan" />
      <div className="hud-body">
        <div className="hud-row"><span>so</span><span className="v">{hud?.so ?? "—"}</span></div>
        <div className="hud-row"><span>函数</span><span className="v">{hud?.fn ?? "—"}</span></div>
        <div className="hud-row"><span>地址</span><span className="v">{hud?.addr ?? "—"}</span></div>
        <div className="hud-row"><span>参数</span><span className="v">{hud?.detail ?? "—"}</span></div>
      </div>
      <div className="hud-foot">来自内置 MCP 的真实调用</div>
    </div>
  );
}
