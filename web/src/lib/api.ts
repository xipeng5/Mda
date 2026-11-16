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
// (40) 第四十次修改（2026-11-11）：
//      bug 原因：API_BASE 用 location.origin 拼绝对地址，但 WKWebView 里
//                页面 origin（localhost:8766）与请求 base（127.0.0.1:8766）
//                不一致，跨源请求被隔离 —— 表现为 /api/modules 恒返回空，
//                而带参数的 nav_stats 却正常（窗口里 sync.base 实测是
//                127.0.0.1 而页面是 localhost）。排了很久。
//      解决方案：一律用相对路径（空前缀），请求永远跟随页面 origin，
//                不再依赖任何 host 判断，也就没有跨源问题。
const DEV_SERVER_PORT = "5173";
const DEV_API_BASE = "http://127.0.0.1:8766";
const pageOrigin =
  typeof location !== "undefined" && location.protocol.startsWith("http")
    ? location.origin
    : "";
export const API_BASE =
  pageOrigin && location.port === DEV_SERVER_PORT ? DEV_API_BASE : "";

export type ApiModule = { so: string; path: string; functions: number; exports: number; sections: number };
export type ApiFn = {
  name: string; addr: number; size: number; is_export: boolean;
  discovered_by: string; refs?: number;
};
export type ApiInsn = { addr: number; bytes: string; text: string; is_call: boolean; is_ret: boolean };
export type ApiTool = { name: string; desc: string; params: string[]; required: string[] };
export type ApiHeatmap = {
  so: string; lo: string; hi: string; functions: number;
  max_refs: number; buckets: number[];
};
export type ApiSection = {
  name: string; addr: string; offset: string; size: number; flags: string; type?: string;
};
export type ApiString = { addr: number; value: string; refs: number };
export type ApiFact = { calls: number; num: number | null; summary: string; ts: string };
export type ApiHooks = { armed: boolean; pid?: number; on: string[]; off: string[] };
export type ApiNavStats = {
  loaded: boolean; so: string; functions: number; exports: number;
  strings: number; sections: number; refs: number | null; xref_built: boolean;
  /** 服务端当前全部模块。前端用它做同步，不再依赖 /api/modules
   *  （那条路径在 WKWebView 里会被缓存成旧空数组）。 */
  serverModules?: { so: string; path: string; functions?: number }[];
  /** 本次会话 AI 调用过什么（工具名 → 次数 / 最近 summary 里的首个整数）。
   *  左栏「派发点/命中/轨迹」这些数字从这里取，不是常量。 */
  facts?: Record<string, ApiFact>;
  /** 行为监控开了哪些 hook（数据来自待命表里的真实参数） */
  hooks?: ApiHooks;
};
export type ApiArmed = { key: string; tool: string; label: string; target: string; ts: string };
export type ApiXrefItem = { addr: string; name: string; is_export: boolean; size: number };
/** 函数检视器：一个函数的全部已知事实（右侧面板） */

/** 动态侧状态：断点 / 命中 / 内存 / VM / 行为监控。
 *  左栏各入口共用这一个接口，避免一次渲染发 5+ 个请求。 */
export type ApiDynState = {
  ok: boolean;
  targets: { key: string; serial: string; pid: number | null; state: string; breakpoints: number }[];
  breakpoints: {
    id: string; so: string; addr: number | null; addr_hex: string;
    runtime: number | null; hold: boolean; armed: boolean;
    serial: string; pid: number | null;
  }[];
  hits: {
    so: string; static_hex: string; tid: number | null;
    seq: number | null; held: boolean;
  }[];
  memory: { name: string; size: number; mtime: number }[];
  vm: {
    dispatch: { calls?: number; num?: number | null; ts?: string; summary?: string }[];
    regs: { calls?: number; num?: number | null; ts?: string; summary?: string }[];
    trace: { calls?: number; num?: number | null; ts?: string; summary?: string }[];
  };
  behavior: { armed: boolean; categories: string[]; off?: string[] };
  errors: string[];
};

export type ApiFnDetail = {
  ok: boolean;
  so: string;
  addr: string;
  name: string;
  is_export: boolean;
  size: number;
  refs_in: number;
  refs_out: number;
  section: string;
  attached: boolean;
  callers: { addr: string; name: string; is_export: boolean }[];
  callees: { addr: string; name: string; is_export: boolean; plt: boolean }[];
  strings: { addr: string; value: string }[];
  breakpoint: boolean;
  hits: number;
};
export type ApiXrefNode = {
  root: ApiXrefItem & { callers_tree?: ApiXrefItem[]; callees_tree?: ApiXrefItem[] };
  callers: ApiXrefItem[];
  callees: ApiXrefItem[];
};
export type ApiProc = {
  pid: number; ppid: number; name: string; suffix: string; is_main: boolean;
  role: string; sockets: number | null; inet_conns: number | null;
  loaded_so_count: number | null;
};
export type ApiProcResult = {
  ok?: boolean; error?: string; package?: string; count?: number;
  processes?: ApiProc[]; main_pid?: number; network_pids?: number[];
  network_basis?: string; verdict?: string; hint?: string;
};

/**
 * 用 XMLHttpRequest 发 GET 并解析 JSON。
 *
 * 为什么不用 fetch：实测 WKWebView（桌面窗口）里 fetch 对
 * /api/modules 会返回旧响应 {"modules":[]} —— 即使 URL 带了每次不同的
 * 时间戳、服务端发了 no-store。同一个 URL 用 curl 在外部拿是正常的，
 * 所以问题在 WebKit 的 fetch 实现，不在我们的服务端或缓存策略。
 * XHR 走的是 WebKit 更老的网络栈，实测能拿到正确数据。
 */
function xhrJson<T>(url: string, timeoutMs = 15000): Promise<T | null> {
  return new Promise((resolve) => {
    try {
      const x = new XMLHttpRequest();
      x.open("GET", url, true);
      x.timeout = timeoutMs;
      x.setRequestHeader("Cache-Control", "no-cache, no-store");
      x.setRequestHeader("Pragma", "no-cache");
      x.onload = () => {
        if (x.status >= 200 && x.status < 300) {
          try {
            resolve(JSON.parse(x.responseText) as T);
          } catch {
            resolve(null);
          }
        } else {
          resolve(null);
        }
      };
      x.onerror = () => resolve(null);
      x.ontimeout = () => resolve(null);
      x.send();
    } catch {
      resolve(null);
    }
  });
}

async function j<T>(url: string, init?: RequestInit): Promise<T | null> {
  try {
    // 给 GET 拼时间戳：WKWebView 会缓存**无查询参数**的 GET 响应，
    // 连服务端 no-store 和客户端 cache:"no-store" 都不遵守。
    // 带参数的请求（如 nav_stats?so=xxx）不会被缓存——这就是为什么
    // 左栏能显示真实计数、而 /api/modules 恒返回旧空数组（实测定位）。
    const isGet = !init || !init.method || init.method === "GET";
    const bust = isGet ? (url.includes("?") ? "&" : "?") + "_t=" + Date.now() : "";
    const finalUrl = url + bust;
    if (url.includes("nav_stats")) {
      try {
        const x = new XMLHttpRequest();
        x.open("GET", finalUrl, true);
        x.onload = () => {
          const w = window as unknown as { __mdaNavRaw?: string[] };
          w.__mdaNavRaw = [...(w.__mdaNavRaw ?? []).slice(-5), x.responseText.slice(0, 160)];
        };
        x.send();
      } catch { /* ignore */ }
    }
    // 诊断：把实际请求的 URL 记下来（窗口里 console 看不到，靠这个上报）
    try {
      const w = window as unknown as { __mdaUrls?: string[] };
      w.__mdaUrls = [...(w.__mdaUrls ?? []).slice(-20), finalUrl];
    } catch { /* ignore */ }
    const r = await fetch(finalUrl, { cache: "no-store", ...init });
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
  health: () => j<{ ok: boolean; version?: string; modules: string[] }>(
    `${API_BASE}/api/health`
  ),
  /** 全部 MCP 工具的真实元数据（直接读服务端注册表，不会过期） */
  tools: () => j<{ count: number; tools: ApiTool[] }>(`${API_BASE}/api/tools`),
  /** 代码页热力条：位置=真实地址、颜色=真实引用密度 */
  heatmap: (so: string) =>
    j<ApiHeatmap>(`${API_BASE}/api/heatmap?so=${encodeURIComponent(so)}`),
  /** 当前前台 App 的包名（左栏目标栏用来决定展示谁，不写死） */
  foreground: () => j<{ ok: boolean; package: string; serial?: string; error?: string }>(`${API_BASE}/api/foreground`),
  /** 左栏导航需要的全部真实计数（一次取回，避免 20 多个往返） */
  navStats: (so: string) =>
    j<ApiNavStats>(`${API_BASE}/api/nav_stats?so=${encodeURIComponent(so)}`),
  /** AI 当前在哪些目标上装着监控（持久状态，不是事件流） */
  dynState: () => j<ApiDynState>(`${API_BASE}/api/dyn_state`),
  armed: () => j<{ count: number; items: ApiArmed[] }>(`${API_BASE}/api/armed`),
  /** 清空待命显示（不撤设备上的断点，只清界面） */
  armedClear: () =>
    j<{ cleared: number }>(`${API_BASE}/api/armed/clear`, { method: "POST" }),
  /** 函数检视器（右侧面板：概况 / 调用者 / 被调用 / 引用字符串 / 动态） */
  fnDetail: (so: string, addr: number) =>
    j<ApiFnDetail>(
      `${API_BASE}/api/fn_detail?so=${encodeURIComponent(so)}&addr=${addr}`
    ),
  /** 段/节表（判断加固与否的第一手依据） */
  sections: (so: string) =>
    j<{ so: string; count: number; items: ApiSection[] }>(
      `${API_BASE}/api/sections?so=${encodeURIComponent(so)}`
    ),
  /** 字符串表（含引用数） */
  strings: (so: string, kw = "") =>
    j<{ items: ApiString[] }>(
      `${API_BASE}/api/strings?so=${encodeURIComponent(so)}&kw=${encodeURIComponent(kw)}`
    ),
  /** 当前函数的调用关系（带函数名），引 用页与图谱共用 */
  xrefTree: (so: string, addr: number, depth = 1) =>
    j<ApiXrefNode>(`${API_BASE}/api/xref_tree?so=${encodeURIComponent(so)}&addr=${addr}&depth=${depth}`),
  /** 一个包名下的全部进程 + 各自网络活动（纯 /proc，无注入） */
  appProcesses: (opts: { package?: string; pid?: number; serial?: string }) => {
    const q = new URLSearchParams();
    if (opts.package) q.set("package", opts.package);
    if (opts.pid) q.set("pid", String(opts.pid));
    if (opts.serial) q.set("serial", opts.serial);
    return j<ApiProcResult>(`${API_BASE}/api/app_processes?${q.toString()}`);
  },
  // (46) 第四十六次修改（2026-11-11）：
  //     实测：/api/modules 带了唯一时间戳（每次 URL 都不同），curl 同一 URL
  //     能拿到数据，WKWebView 里的 fetch 却返回 {"modules":[]}。
  //     URL 每次不同，不可能是 HTTP 缓存；问题在 fetch 本身。
  //     解决：关键端点的 GET 走 XMLHttpRequest（WebKit 更老的网络栈，实测稳定）。
  modules: () =>
    xhrJson<{ modules: ApiModule[] }>(
      `${API_BASE}/api/modules?_t=${Date.now()}`
    ),
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
