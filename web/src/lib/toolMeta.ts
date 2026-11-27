/**
 * MCP 工具分类、颜色语义、设备层级映射共享模块。
 * 供 RealtimeMonitor、DeviceOpsDeck、ToolsView、CommandPalette 共同复用，避免重复维护规则。
 */

export const TOOL_LABEL: Record<string, string> = {
  static: "静态",
  plugin: "插件",
  vm: "VM",
  bp: "断点",
  proc: "进程",
  behavior: "行为",
  mem: "内存",
  watch: "观察点",
  trace: "轨迹",
  java: "Java",
  runtime: "运行时",
  ui: "UI",
};

export const TOOL_COLOR: Record<string, string> = {
  static: "#4c8dff",
  plugin: "#a78bfa",
  vm: "#22d3ee",
  bp: "#fb7185",
  proc: "#34d399",
  behavior: "#a78bfa",
  mem: "#fbbf24",
  watch: "#fb7185",
  trace: "#34d399",
  java: "#38bdf8",
  runtime: "#fbbf24",
  ui: "#38bdf8",
};

export const LAYER_NAMES = [
  "UI / Java / Hook 层",
  "进程 & 线程层",
  "Native SO / 内存层",
  "Kernel / 断点层",
] as const;

export const HOOK_NAMES = [
  "MessageDigest",
  "Cipher",
  "Mac",
  "FileIn",
  "FileOut",
  "Activity",
  "Assets",
  "Socket",
] as const;

export const HOOK_SHORT = ["MD", "CP", "MC", "FI", "FO", "AC", "AS", "SK"] as const;

/** 按工具名前缀通用归类，覆盖全部 MCP 工具。 */
export function classifyTool(tool: string): string {
  const t = tool || "";
  if (/^ui_/.test(t)) return "ui";
  if (/^vm_|^dump_vm|^probe_vm|^find_vm_|^find_dispatch/.test(t)) return "vm";
  if (/^perf_watch|^uprobe_/.test(t)) return "watch";
  if (/^java_/.test(t)) return "java";
  if (/^trace_|^watch_module|^module_load/.test(t)) return "trace";
  if (/^mem_/.test(t)) return "mem";
  if (/^behavior_/.test(t)) return "behavior";
  if (/^device_|process|^list_threads|^probe_network|^list_devices|^start_frida|^frida_/.test(t)) return "proc";
  if (/breakpoint|^hits$|^wait_hits|^poll_events|^probe_hits|^resume$|^freeze|^unfreeze|^attach|^detach/.test(t)) {
    return "bp";
  }
  if (/^read_|^locate_|^get_callstack|^runtime_modules|^list_modules|^dump_so/.test(t)) return "runtime";
  if (/^plugin_/.test(t)) return "plugin";
  return "static";
}

/** 将工具映射到右侧设备运行态控制台的 4 个子系统槽位（0: Hook/UI · 1: 进程 · 2: SO/内存 · 3: 断点/寄存器）。 */
export function toolToLayer(tool: string, cat?: string): number {
  const c = cat || classifyTool(tool);
  if (/^device_|freeze|process|list_devices|threads|network|start_frida|attach|detach/.test(tool)) return 1;
  if (c === "ui" || c === "java" || c === "behavior") return 0;
  if (c === "bp" || c === "watch") return 3;
  if (c === "proc" || c === "trace") return 1;
  return 2;
}

/** 判断工具是否属于读取/扫描/回传类（用于触发双向回传光点动画）。 */
export function isReadbackTool(tool: string): boolean {
  return /read_|mem_|dump_|list_|decompile|disassemble|callers_of|call_chain|hits|scan|profile|infer|plugin_run/.test(
    tool || ""
  );
}
