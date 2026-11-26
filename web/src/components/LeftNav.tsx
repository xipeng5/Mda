import { useEffect, useRef, useState } from "react";
import { api, type ApiNavStats } from "../lib/api";

/**
 * 左栏分组导航 —— 与原型一致的五组结构。
 *
 * 每个条目后面的数字都是**真实计数**：
 *   · 静态组来自 /api/nav_stats（当前 so 的真实结构）
 *   · 动态 / VM / 行为组来自 facts（AI 本次会话真实调用过什么）
 *   · Hook 墙来自待命表里 behavior_monitor 的真实参数
 * 取不到数据的条目显示 "—"，不撒谎、也不写死演示数字。
 *
 * 原型里大部分条目本身不切页（只是计数展示），这里保持一致：
 * 有对应视图的才可点。
 */

type Props = {
  so: string;
  activeView: string;
  onPick: (view: string) => void;
  /** 模块的真实函数数（来自 WS 快照，比 HTTP 可靠） */
  fnCount?: number;
  /** 把服务端模块列表带回去：这条请求（nav_stats）在 WKWebView 里是通的，
   *  而 /api/modules 会被缓存成旧空数组。用它做同步更可靠。 */
  onServerModules?: (mods: { so: string; path: string }[]) => void;
  /** 每次 AI 事件后自增，用来触发计数刷新。
   *  不用定时器：WKWebView 里 setInterval 可能不触发（实测）。 */
  tick?: number;
};

type Item = {
  key: string;
  label: string;
  count: number | string;
  /** 有视图才可点；原型里很多条目只是计数展示 */
  view?: string;
};

/** 导航条目 → 供给它数字的工具。
 *  加新工具只改这张表，不在别处写分支。 */
const FACT_SRC: Record<string, string[]> = {
  bp: ["set_breakpoint"],
  hits: ["hits", "wait_hits"],
  mem: ["mem_diff", "mem_snapshot"],
  dispatch: ["find_vm_dispatch_points", "find_dispatch_tables"],
  regs: ["vm_regs_snapshot"],
  trace: ["trace_code", "trace_module_load", "trace_app_startup", "trace_call_tree"],
  procs: ["list_app_processes", "probe_network_processes"],
};

/** 行为组：hook 名 → 它属于哪个条目 */
const HOOK_BUCKET: Record<string, string> = {
  MessageDigest: "algo",
  Cipher: "algo",
  Mac: "algo",
  FileIn: "file",
  FileOut: "file",
  Activity: "activity",
  Assets: "assets",
};

export function LeftNav({ so, activeView, onPick, onServerModules, fnCount, tick }: Props) {
  const [st, setSt] = useState<ApiNavStats | null>(null);
  const [fold, setFold] = useState<Record<string, boolean>>({});
  const [toolCount, setToolCount] = useState<number | null>(null);
  // 回调放 ref：父组件每次渲染都会传新引用，若放进依赖会让 effect 无限重跑，
  // 结果 st 被反复覆盖成旧 so 的空数据（实测左栏计数变 "—" 就是这个）。
  const cbRef = useRef(onServerModules);
  cbRef.current = onServerModules;

  // (1) 第一次修改（2026-11-26）
  // bug 原因：两个异步 useEffect 均缺少取消标志，切换 so 或卸载后过期响应会覆写左栏计数。
  // 解决方案：为 navStats 与 tools 的 useEffect 均补齐 alive 取消标志。
  useEffect(() => {
    // 即使 so 为空也查一次：此时服务端会返回"有哪些模块"，
    // 前端据此决定要加载谁（否则启动时永远不知道该查哪个 so）。
    let alive = true;
    void (async () => {
      const r = await api.navStats(so);
      if (!alive) return;
      if (r) {
        setSt(r);
        if (r.serverModules?.length) cbRef.current?.(r.serverModules);
      }
    })();
    return () => {
      alive = false;
    };
  }, [so, tick]);

  // 工具总数只取一次（137 是真实注册表大小，但不要写死）
  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await api.tools();
      if (!alive) return;
      if (r?.tools) setToolCount(r.tools.length);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const n = (v: number | undefined | null) => (v == null ? "—" : v);

  /** 从 facts 里取某个条目该显示的数字 */
  const fact = (key: string): number | string => {
    const src = FACT_SRC[key];
    if (!src || !st?.facts) return "—";
    for (const tool of src) {
      const f = st.facts[tool];
      if (f?.num != null) return f.num;
    }
    return "—";
  };

  /** 行为组：这个桶里有几个 hook 是开着的 */
  const hookCount = (bucket: string): number | string => {
    const h = st?.hooks;
    if (!h?.armed) return "—";
    return h.on.filter((x) => HOOK_BUCKET[x] === bucket).length;
  };

  const staticItems: Item[] = [
    { key: "code", label: "代码", count: n(fnCount ?? st?.functions), view: "module" },
    { key: "refs", label: "引用", count: st?.refs == null ? "建图" : st.refs, view: "xref" },
    { key: "strings", label: "字符串", count: n(st?.strings), view: "strings" },
    { key: "sections", label: "段 / 节", count: n(st?.sections), view: "sections" },
    { key: "graph", label: "图谱", count: "", view: "graph" },
  ];

  const dynItems: Item[] = [
    { key: "procs", label: "目标进程", count: fact("procs"), view: "processes" },
    { key: "bp", label: "断点", count: fact("bp"), view: "dyn:bp" },
    { key: "hits", label: "命中", count: fact("hits"), view: "dyn:hits" },
    { key: "mem", label: "内存", count: fact("mem"), view: "dyn:mem" },
  ];

  const vmItems: Item[] = [
    { key: "dispatch", label: "派发点", count: fact("dispatch"), view: "dyn:dispatch" },
    { key: "regs", label: "寄存器", count: fact("regs"), view: "dyn:regs" },
    { key: "trace", label: "轨迹", count: fact("trace"), view: "dyn:trace" },
  ];

  const behaviorItems: Item[] = [
    { key: "algo", label: "算法", count: hookCount("algo"), view: "dyn:behavior" },
    { key: "file", label: "文件", count: hookCount("file"), view: "dyn:behavior" },
    { key: "activity", label: "Activity", count: hookCount("activity"), view: "dyn:behavior" },
    { key: "assets", label: "assets", count: hookCount("assets"), view: "dyn:behavior" },
  ];

  const toolItems: Item[] = [
    { key: "tools", label: "全部工具", count: n(toolCount), view: "tools" },
    { key: "heat", label: "热力条", count: "", view: "tools" },
    { key: "memdiff", label: "内存 diff", count: "", view: "tools" },
    { key: "modmgr", label: "模块管理", count: "", view: "tools" },
  ];

  const Group = ({ title, items }: { title: string; items: Item[] }) => {
    const folded = !!fold[title];
    return (
      <div className={"navgrp" + (folded ? " fold" : "")}>
        <div className="navhdr" onClick={() => setFold((f) => ({ ...f, [title]: !f[title] }))}>
          <span className="car">{folded ? "▸" : "▾"}</span>
          {title}
        </div>
        {!folded && (
          <div className="navlist">
            {items.map((it) => (
              <button
                key={it.key}
                className={"navitem" + (it.view && activeView === it.view ? " on" : "")}
                onClick={() => it.view && onPick(it.view)}
                disabled={!it.view}
                title={it.view ? "" : "这个条目只做计数展示（原型同样不可点）"}
              >
                <span className="nm">{it.label}</span>
                {it.count !== "" && <b>{it.count}</b>}
              </button>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <nav className="nav">
      <Group title="静态" items={staticItems} />
      <Group title="动态" items={dynItems} />
      <Group title="VM" items={vmItems} />
      <Group title="行为" items={behaviorItems} />
      <Group title="工具" items={toolItems} />
    </nav>
  );
}
