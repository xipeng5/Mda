/** 后端接口封装：连不上就返回 null，前端自动退回 data.js（离线可用）。 */
// (1) 第一次修改
// bug 原因：API_BASE 写死 http://127.0.0.1:8766，但页面其实就是由同一个 API 进程托管
//   （web_app.py 打开的就是 http://127.0.0.1:8766/）。一旦用 MDA_API_PORT 换端口，
//   或改用 localhost 打开，REST 就会打到别的端口/协议上：浏览器按 CORS 拦截，而
//   WebSocket 用的是 location.host —— 同一页面出现「REST 连 A、事件连 B」的双会话。
//   实测报错：Access to fetch at 'http://127.0.0.1:8766/api/health' from origin
//   'http://127.0.0.1:18876' has been blocked by CORS policy。
// 解决方案：同源优先。页面由后端托管时 location.origin 就是唯一正确地址；只有 vite
//   开发服务器（5173，本身不带后端）才回退 8766。若将来由独立静态服务器托管前端，
//   用 MDA 后端反向代理同源即可，避免再引出一套地址配置。
const DEV_SERVER_PORT = "5173";
const FALLBACK_API_BASE = "http://127.0.0.1:8766";
const pageOrigin =
  typeof location !== "undefined" && location.protocol.startsWith("http")
    ? location.origin
    : "";
export const API_BASE =
  pageOrigin && location.port !== DEV_SERVER_PORT ? pageOrigin : FALLBACK_API_BASE;

export type ApiModule = { so: string; path: string; functions: number; exports: number; sections: number };
export type ApiFn = {
  name: string; addr: number; size: number; is_export: boolean;
  discovered_by: string; refs?: number;
};
export type ApiInsn = { addr: number; bytes: string; text: string; is_call: boolean; is_ret: boolean };

async function j<T>(url: string, init?: RequestInit): Promise<T | null> {
  try {
    const r = await fetch(url, init);
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

/** pywebview 注入的桥（只有桌面窗口里才有） */
type PywebviewBridge = { api?: { pick_so?: () => Promise<string> | string } };

export function hasNativeDialog(): boolean {
  return !!(window as unknown as { pywebview?: PywebviewBridge }).pywebview?.api?.pick_so;
}

/** 打开系统文件选择框，返回路径；浏览器里返回空串（没有该能力） */
export async function pickSoFile(): Promise<string> {
  const bridge = (window as unknown as { pywebview?: PywebviewBridge }).pywebview;
  const fn = bridge?.api?.pick_so;
  if (!fn) return "";
  const path = await fn();
  return typeof path === "string" ? path : "";
}

export const api = {
  health: () => j<{ ok: boolean; modules: string[] }>(`${API_BASE}/api/health`),
  modules: () => j<{ modules: ApiModule[] }>(`${API_BASE}/api/modules`),
  load: (path: string) =>
    j<{ module: ApiModule }>(`${API_BASE}/api/load`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ path }),
    }),
  /** 拖入的文件：字节直接上传，后端落盘后按路径解析 */
  upload: (name: string, buf: ArrayBuffer) =>
    fetch(`${API_BASE}/api/load_upload?name=${encodeURIComponent(name)}`, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: buf,
    }).then(async (r) => {
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(typeof body?.error === "string" ? body.error : `HTTP ${r.status}`);
      return body as { module: ApiModule; path: string };
    }),
  functions: (so: string, kw = "", limit = 5000) =>
    j<{ total: number; items: ApiFn[] }>(
      `${API_BASE}/api/functions?so=${encodeURIComponent(so)}&kw=${encodeURIComponent(kw)}&limit=${limit}`
    ),
  disasm: (so: string, addr: number) =>
    j<{ addr: number; items: ApiInsn[] }>(
      `${API_BASE}/api/disasm?so=${encodeURIComponent(so)}&addr=${addr}`
    ),
  xrefs: (so: string, addr: number) =>
    j<{ addr: number; callers: string[]; callees: string[] }>(
      `${API_BASE}/api/xrefs?so=${encodeURIComponent(so)}&addr=${addr}`
    ),
  buildXrefs: (so: string) =>
    j<{ ok: boolean }>(`${API_BASE}/api/xrefs/build`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ so }),
    }),
};
