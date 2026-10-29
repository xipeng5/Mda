/** 数据契约：由 tests/ui_review/dump_sphere_data.py 从真实 so 导出（public/data.js）。 */
export type Func = { n: string; a: number; s: number; e: number; r: number };
export type Insn = { a: number; b: string; t: string; c: number; r: number };
export type Section = { n: string; a: number; s: number };
export type ModuleData = {
  so: string;
  path: string;
  size: number;
  sections: Section[];
  funcs: Func[];
  disasm: Record<string, Insn[]>;
  callers: Record<string, number[]>;
  callees: Record<string, number[]>;
};
export type Payload = { modules: ModuleData[] };

declare global {
  interface Window {
    MDA_DATA?: Payload;
  }
}

/** 示例数据（仅"载入示例"按钮使用，启动时不再自动加载）。 */
export function loadModules(): ModuleData[] {
  const p = window.MDA_DATA;
  if (!p || !Array.isArray(p.modules)) return [];
  return p.modules;
}

export const hex = (a: number): string => "0x" + a.toString(16);
