import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  type ApiFavoriteApp,
  type ApiProxyStatus,
  type ApiSettings,
  type ApiToolboxDevice,
} from "../lib/api";

type Props = {
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onOpenToolDoc: (toolName: string) => void;
  onToast: (msg: string) => void;
};

type ActionLog = {
  time: string;
  ok: boolean;
  title: string;
  message: string;
  detail?: unknown;
};

const nowStr = () => new Date().toLocaleTimeString("zh-CN", { hour12: false });
const PKG_RE = /^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$/;

/**
 * MDA 设置 & 设备常用工具箱（全宽全高自适应 + 一键存常用，免手输包名/应用名）：
 * - 上半区：手机全局代理 & mitmproxy 系统证书（MCP: device_proxy）
 * - 主伸展区：常用 App 快捷管理（一键将当前前台或手机已安装 App 存为常用，自动读取并持久保存真实应用名 + 包名，
 *   同一行直接提供冻结 / 解冻 / 强停 / 清理数据重启，对应 MCP: device_app_suspend & device_app_reset）
 */
export function SettingsView({ theme, onToggleTheme, onOpenToolDoc, onToast }: Props) {
  const [cfg, setCfg] = useState<ApiSettings>({
    serial: "",
    proxy_host: "",
    proxy_port: 8080,
    cert_path: "~/.mitmproxy/mitmproxy-ca-cert.pem",
    favorite_apps: [],
    suspend_packages: [],
    reset_package: "",
    reset_wait_sec: 2.0,
    reset_relaunch: true,
  });
  const [cfgPath, setCfgPath] = useState("");
  const [hostIp, setHostIp] = useState("");
  const [adbPath, setAdbPath] = useState("");
  const [devices, setDevices] = useState<ApiToolboxDevice[]>([]);
  const [installedApps, setInstalledApps] = useState<ApiFavoriteApp[]>([]);
  const [pkgPickerOpen, setPkgPickerOpen] = useState(false);
  const [pkgPickerQ, setPkgPickerQ] = useState("");
  const [resolvingLabels, setResolvingLabels] = useState(false);
  const [manualAddOpen, setManualAddOpen] = useState(false);

  const [proxySt, setProxySt] = useState<ApiProxyStatus | null>(null);
  const [suspendMap, setSuspendMap] = useState<Record<string, boolean>>({});
  const [newAppName, setNewAppName] = useState("");
  const [newAppPkg, setNewAppPkg] = useState("");
  const [editingPkg, setEditingPkg] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [confirmClearApp, setConfirmClearApp] = useState<ApiFavoriteApp | null>(null);

  const [busy, setBusy] = useState<string>("");
  const [lastLog, setLastLog] = useState<ActionLog | null>(null);
  const [showRawDetail, setShowRawDetail] = useState(false);
  const pickerTokenRef = useRef(0);

  const onlineDevices = useMemo(
    () => devices.filter((d) => d.state === "device"),
    [devices]
  );

  const activeSerial = useMemo(() => {
    if (cfg.serial && onlineDevices.some((d) => d.serial === cfg.serial)) return cfg.serial;
    if (onlineDevices.length === 1) return onlineDevices[0].serial;
    return cfg.serial;
  }, [cfg.serial, onlineDevices]);

  const activeDevice = useMemo(
    () => onlineDevices.find((d) => d.serial === activeSerial) ?? null,
    [onlineDevices, activeSerial]
  );

  const recordLog = useCallback((ok: boolean, title: string, message: string, detail?: unknown) => {
    setLastLog({ time: nowStr(), ok, title, message, detail });
  }, []);

  const persistPatch = useCallback(
    async (patch: Partial<ApiSettings>, silent = false) => {
      const r = await api.saveSettings(patch);
      if (r?.ok && r.settings) {
        setCfg(r.settings);
        if (r.path) setCfgPath(r.path);
        if (!silent) onToast("设置已保存");
        return r.settings;
      }
      if (!silent) onToast("保存失败，请检查 IP / 端口 / 包名格式");
      return null;
    },
    [onToast]
  );

  const refreshDevices = useCallback(
    async (withPkgs = false, serialOverride?: string) => {
      const r = await api.toolboxDevices({
        serial: serialOverride ?? activeSerial,
        packages: withPkgs,
      });
      if (!r) return null;
      if (r.adb_path) setAdbPath(r.adb_path);
      if (r.host_ip) setHostIp(r.host_ip);
      setDevices(r.devices ?? []);
      if (withPkgs) {
        const list =
          r.installed_apps ??
          (r.packages ?? []).map((p) => ({ package: p, name: "" }));
        setInstalledApps(list);
      }
      return r;
    },
    [activeSerial]
  );

  const refreshProxyStatus = useCallback(
    async (ser?: string, port?: number, cert?: string) => {
      const r = await api.toolboxProxyStatus({
        serial: ser ?? activeSerial,
        port: port ?? cfg.proxy_port,
        cert_path: cert ?? cfg.cert_path,
      });
      if (r) setProxySt(r);
      return r;
    },
    [activeSerial, cfg.proxy_port, cfg.cert_path]
  );

  const refreshSuspendStatus = useCallback(
    async (pkgs?: string[], ser?: string) => {
      const list = pkgs ?? cfg.favorite_apps.map((a) => a.package);
      if (!list.length) {
        setSuspendMap({});
        return null;
      }
      const r = await api.toolboxAppSuspend({
        action: "status",
        serial: ser ?? activeSerial,
        packages: list,
      });
      if (r?.items) {
        const next: Record<string, boolean> = {};
        for (const it of r.items) next[it.package] = it.suspended;
        setSuspendMap(next);
      }
      return r;
    },
    [activeSerial, cfg.favorite_apps]
  );

  // 自动静默补全常用列表中缺少应用名的旧条目（直接从真机 APK 读真实名称并落盘）
  const autoBackfillFavoriteNames = useCallback(
    async (ser: string, favs: ApiFavoriteApp[]) => {
      const missing = favs.filter((a) => !a.name).map((a) => a.package);
      if (!ser || !missing.length) return;
      const lr = await api.toolboxAppLabels(ser, missing);
      const map = lr?.labels ?? {};
      const hasAny = missing.some((p) => !!map[p]);
      if (!hasAny) return;
      const merged = favs.map((a) => ({
        ...a,
        name: a.name || map[a.package] || "",
      }));
      await persistPatch({ favorite_apps: merged }, true);
    },
    [persistPatch]
  );

  // 首屏加载配置 + 真机 + 代理状态 + 冻结状态 + 自动补全缺失应用名
  useEffect(() => {
    let alive = true;
    void (async () => {
      setBusy("init");
      const [sRes, dRes] = await Promise.all([api.settings(), api.toolboxDevices()]);
      if (!alive) return;
      const loaded = sRes?.settings ?? cfg;
      if (sRes?.ok) {
        setCfg(loaded);
        setCfgPath(sRes.path || "");
        if (sRes.host_ip) setHostIp(sRes.host_ip);
      }
      if (dRes) {
        if (dRes.adb_path) setAdbPath(dRes.adb_path);
        if (dRes.host_ip) setHostIp(dRes.host_ip);
        setDevices(dRes.devices ?? []);
      }
      const online = (dRes?.devices ?? []).filter((d) => d.state === "device");
      const ser =
        loaded.serial && online.some((d) => d.serial === loaded.serial)
          ? loaded.serial
          : online.length === 1
            ? online[0].serial
            : "";
      const savedFavs = loaded.favorite_apps ?? [];
      const savedPkgs = savedFavs.map((a) => a.package);
      if (ser) {
        const [pRes, fRes] = await Promise.all([
          api.toolboxProxyStatus({ serial: ser, port: loaded.proxy_port, cert_path: loaded.cert_path }),
          savedPkgs.length
            ? api.toolboxAppSuspend({ action: "status", serial: ser, packages: savedPkgs })
            : Promise.resolve(null),
          autoBackfillFavoriteNames(ser, savedFavs),
        ]);
        if (!alive) return;
        if (pRes) setProxySt(pRes);
        if (fRes?.items) {
          const m: Record<string, boolean> = {};
          for (const it of fRes.items) m[it.package] = it.suspended;
          setSuspendMap(m);
        }
      }
      setBusy("");
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 代理动作
  const runProxyAction = async (
    action: "on" | "off" | "status" | "cert_install" | "cert_remove",
    label: string
  ) => {
    setBusy(`proxy:${action}`);
    try {
      await persistPatch(
        { serial: activeSerial, proxy_host: cfg.proxy_host, proxy_port: cfg.proxy_port, cert_path: cfg.cert_path },
        true
      );
      const r = await api.toolboxProxy({
        action,
        serial: activeSerial,
        host: cfg.proxy_host,
        port: cfg.proxy_port,
        cert_path: cfg.cert_path,
      });
      if (!r) {
        recordLog(false, label, "请求失败，请确认后端运行正常");
        return;
      }
      if (r.ok) setProxySt(r);
      const msg = r.message || r.error || (r.ok ? `${label}完成` : `${label}失败`);
      recordLog(!!r.ok, label, msg, r);
      onToast(msg);
    } finally {
      setBusy("");
    }
  };

  // 一键存入常用（未提供名称时自动从真机 APK 解析真实显示名称）
  const addFavoriteApp = async (rawPkg: string, rawName = "") => {
    const pkg = rawPkg.trim();
    if (!pkg) {
      onToast("请输入 App 包名");
      return;
    }
    if (!PKG_RE.test(pkg)) {
      onToast("包名格式不正确，例如 com.example.app");
      return;
    }

    let name = rawName.trim();
    if (!name && activeSerial) {
      setBusy(`label:${pkg}`);
      try {
        const lr = await api.toolboxAppLabel(activeSerial, pkg);
        if (lr?.ok && lr.label) name = lr.label;
      } finally {
        setBusy("");
      }
    }

    const exists = cfg.favorite_apps.find((a) => a.package === pkg);
    const next: ApiFavoriteApp[] = exists
      ? cfg.favorite_apps.map((a) => (a.package === pkg ? { name: name || a.name, package: pkg } : a))
      : [{ name, package: pkg }, ...cfg.favorite_apps];

    const saved = await persistPatch({ favorite_apps: next }, true);
    if (saved) {
      setNewAppPkg("");
      setNewAppName("");
      setManualAddOpen(false);
      onToast(exists ? `已更新常用：${name || pkg}` : `已存为常用：${name ? `${name} (${pkg})` : pkg}`);
      if (activeSerial) void refreshSuspendStatus(next.map((a) => a.package));
    }
  };

  // 一键把当前前台 App 存为常用（不用手动输任何字）
  const saveForegroundAsFavorite = async () => {
    if (!activeDevice?.foreground) {
      onToast("当前未检测到前台 App，请先在手机打开目标应用再点刷新设备");
      return;
    }
    await addFavoriteApp(activeDevice.foreground, activeDevice.foreground_label || "");
  };

  const saveRenameApp = async (pkg: string) => {
    const trimmed = editingName.trim();
    const next = cfg.favorite_apps.map((a) => (a.package === pkg ? { ...a, name: trimmed } : a));
    await persistPatch({ favorite_apps: next }, true);
    setEditingPkg(null);
    onToast("应用名称已保存");
  };

  const removeFavoriteApp = async (pkg: string) => {
    const next = cfg.favorite_apps.filter((a) => a.package !== pkg);
    if (confirmClearApp?.package === pkg) setConfirmClearApp(null);
    await persistPatch({ favorite_apps: next }, true);
    setSuspendMap((prev) => {
      const cp = { ...prev };
      delete cp[pkg];
      return cp;
    });
  };

  const runSuspendAction = async (
    action: "freeze" | "unfreeze" | "status",
    pkgs: string[],
    label: string
  ) => {
    if (!pkgs.length) {
      onToast("请先存至少一个常用 App");
      return;
    }
    setBusy(`suspend:${action}:${pkgs.join(",")}`);
    try {
      const r = await api.toolboxAppSuspend({
        action,
        serial: activeSerial,
        packages: pkgs,
      });
      if (!r) {
        recordLog(false, label, "请求失败");
        return;
      }
      if (r.items) {
        setSuspendMap((prev) => {
          const next = { ...prev };
          for (const it of r.items!) next[it.package] = it.suspended;
          return next;
        });
      }
      const msg = r.message || r.error || (r.ok ? `${label}完成` : `${label}失败`);
      recordLog(!!r.ok, label, msg, r);
      onToast(msg);
    } finally {
      setBusy("");
    }
  };

  const runAppReset = async (appItem: ApiFavoriteApp, clearData: boolean) => {
    const display = appItem.name ? `${appItem.name} (${appItem.package})` : appItem.package;
    const label = clearData
      ? cfg.reset_relaunch
        ? `清数据并重启 ${display}`
        : `强停并清数据 ${display}`
      : `强制停止 ${display}`;
    setConfirmClearApp(null);
    setBusy(`reset:${appItem.package}:${clearData ? "clear" : "stop"}`);
    try {
      await persistPatch(
        {
          serial: activeSerial,
          reset_package: appItem.package,
          reset_wait_sec: cfg.reset_wait_sec,
          reset_relaunch: cfg.reset_relaunch,
        },
        true
      );
      const r = await api.toolboxAppReset({
        serial: activeSerial,
        package: appItem.package,
        clear_data: clearData,
        relaunch: clearData ? cfg.reset_relaunch : false,
        wait_sec: cfg.reset_wait_sec,
      });
      if (!r) {
        recordLog(false, label, "请求失败");
        return;
      }
      const msg = r.message || r.error || (r.ok ? `${label}完成` : `${label}失败`);
      recordLog(!!r.ok, label, msg, r);
      onToast(msg);
    } finally {
      setBusy("");
    }
  };

  // 打开「从手机应用添加」：立即展示包列表，并分批后台并发读取全部真实应用名（自动落盘缓存，二次打开秒出）
  const togglePackagePicker = async () => {
    if (pkgPickerOpen) {
      pickerTokenRef.current += 1;
      setPkgPickerOpen(false);
      setResolvingLabels(false);
      return;
    }
    setPkgPickerOpen(true);
    setPkgPickerQ("");
    const myToken = ++pickerTokenRef.current;

    let list = installedApps;
    if (!list.length) {
      setBusy("pkgs");
      try {
        const dr = await refreshDevices(true);
        list =
          dr?.installed_apps ??
          (dr?.packages ?? []).map((p) => ({ package: p, name: "" }));
      } finally {
        setBusy("");
      }
    }

    // 分批并发补全尚未缓存的真实应用名
    const missing = list.filter((a) => !a.name).map((a) => a.package);
    if (!missing.length || !activeSerial) return;
    setResolvingLabels(true);
    try {
      for (let i = 0; i < missing.length; i += 24) {
        if (pickerTokenRef.current !== myToken) break;
        const batch = missing.slice(i, i + 24);
        const lr = await api.toolboxAppLabels(activeSerial, batch);
        if (pickerTokenRef.current !== myToken) break;
        const map = lr?.labels ?? {};
        setInstalledApps((prev) =>
          prev.map((a) => (map[a.package] ? { ...a, name: map[a.package] } : a))
        );
      }
    } finally {
      if (pickerTokenRef.current === myToken) setResolvingLabels(false);
    }
  };

  const favPkgSet = useMemo(() => new Set(cfg.favorite_apps.map((a) => a.package)), [cfg.favorite_apps]);
  const favPkgs = useMemo(() => cfg.favorite_apps.map((a) => a.package), [cfg.favorite_apps]);
  const fgSaved = !!(activeDevice?.foreground && favPkgSet.has(activeDevice.foreground));

  const filteredInstalled = useMemo(() => {
    const kw = pkgPickerQ.trim().toLowerCase();
    const list = kw
      ? installedApps.filter(
          (a) =>
            a.package.toLowerCase().includes(kw) ||
            (a.name || "").toLowerCase().includes(kw)
        )
      : installedApps;
    return list;
  }, [installedApps, pkgPickerQ]);

  const cert = proxySt?.cert;

  return (
    <div className="v2-settings-page">
      {/* 顶部设备目标栏 */}
      <div className="v2-set-topbar">
        <div className="v2-set-title-wrap">
          <h2>设置 &amp; 设备工具箱</h2>
          <span className="v2-set-sub">
            与 AI MCP 工具共用同一套真实设备引擎，支持手动点击与 AI 对话双入口
          </span>
        </div>

        <div className="v2-set-devbar">
          <label className="v2-set-lbl">目标设备</label>
          <select
            className="v2-set-select"
            value={activeSerial}
            onChange={(e) => {
              const ser = e.target.value;
              setCfg((prev) => ({ ...prev, serial: ser }));
              setInstalledApps([]);
              void persistPatch({ serial: ser }, true);
              if (ser) {
                void refreshProxyStatus(ser);
                void refreshSuspendStatus(favPkgs, ser);
              }
            }}
          >
            {!onlineDevices.length && <option value="">未检测到在线 ADB 设备</option>}
            {onlineDevices.length > 1 && <option value="">请选择设备（{onlineDevices.length} 台在线）</option>}
            {onlineDevices.map((d) => (
              <option key={d.serial} value={d.serial}>
                {d.serial}
                {d.model ? ` · ${d.model}` : ""}
                {d.root ? " (Root)" : " (非Root)"}
              </option>
            ))}
          </select>

          <button
            className="v2-act-btn"
            disabled={!!busy}
            onClick={async () => {
              setBusy("refresh");
              try {
                const dr = await refreshDevices(false);
                const on = (dr?.devices ?? []).filter((d) => d.state === "device");
                const ser =
                  activeSerial && on.some((d) => d.serial === activeSerial)
                    ? activeSerial
                    : on.length === 1
                      ? on[0].serial
                      : "";
                if (ser) {
                  await Promise.all([
                    refreshProxyStatus(ser),
                    refreshSuspendStatus(favPkgs, ser),
                  ]);
                }
                onToast(`已刷新（在线 ${on.length} 台设备）`);
              } finally {
                setBusy("");
              }
            }}
          >
            {busy === "refresh" ? "探测中…" : "刷新设备"}
          </button>

          {activeDevice?.foreground && (
            <span
              className="v2-set-fg-pill"
              title={`${activeDevice.foreground_label ? activeDevice.foreground_label + " · " : ""}${activeDevice.foreground}`}
            >
              <i />
              前台：{activeDevice.foreground_label
                ? `${activeDevice.foreground_label} (${activeDevice.foreground})`
                : activeDevice.foreground}
            </span>
          )}
        </div>
      </div>

      {/* 全宽全高自适应主内容区 */}
      <div className="v2-set-body">
        {/* 卡片 1：手机代理 & mitmproxy 系统证书 */}
        <section className="v2-set-card">
          <div className="v2-set-card-hd">
            <div>
              <div className="v2-set-card-title">
                <span className="v2-sc-dot" style={{ background: "var(--accent)" }} />
                手机全局代理 &amp; 系统证书
              </div>
              <div className="v2-set-card-desc">
                同时读写 4 项系统全局代理键（适配小米等 ROM），支持一键安装/卸载 mitmproxy 系统证书（Magisk 持久化 + 即时生效）。
              </div>
            </div>
            <button
              className="v2-set-mcp-chip"
              onClick={() => onOpenToolDoc("device_proxy")}
              title="在工具库查看 MCP 工具 device_proxy 的参数定义"
            >
              MCP: device_proxy
            </button>
          </div>

          <div className="v2-set-stats">
            <div className="v2-set-stat">
              <span>当前代理</span>
              <b className={proxySt?.enabled ? "is-on" : ""}>
                {proxySt?.ok
                  ? proxySt.enabled
                    ? proxySt.active_proxy || "已开启"
                    : "已关闭（直连）"
                  : "—"}
              </b>
            </div>
            <div className="v2-set-stat">
              <span>手机 wlan0 IP</span>
              <b>{proxySt?.phone_ip || "—"}</b>
            </div>
            <div className="v2-set-stat">
              <span>本机局域网 IP</span>
              <b>{proxySt?.host_ip || hostIp || "—"}</b>
            </div>
            <div className="v2-set-stat">
              <span>本机 {cfg.proxy_port} 端口</span>
              <b className={proxySt?.port_listening ? "is-on" : ""}>
                {proxySt?.ok
                  ? proxySt.port_listening
                    ? `监听中 (${proxySt.port_listener})`
                    : "未监听"
                  : "—"}
              </b>
            </div>
            <div className="v2-set-stat">
              <span>系统证书 / Magisk</span>
              <b
                className={cert?.installed ? "is-on" : ""}
                title={cert ? `${cert.hash}.0 · ${cert.src}` : ""}
              >
                {cert
                  ? !cert.exists
                    ? "本机无根证书"
                    : `${cert.installed ? `已生效 (${cert.hash}.0)` : "未安装"} · ${cert.magisk_module ? "Magisk已挂" : "无模块"}`
                  : "—"}
              </b>
            </div>
          </div>

          <div className="v2-set-form-row">
            <div className="v2-set-field" style={{ flex: "1.1 1 190px" }}>
              <label>本机代理 IP（留空自动检测）</label>
              <div className="v2-set-in-grp">
                <input
                  value={cfg.proxy_host}
                  onChange={(e) => setCfg((prev) => ({ ...prev, proxy_host: e.target.value }))}
                  placeholder={hostIp ? `自动：${hostIp}` : "例如 192.168.1.221"}
                />
                <button
                  className="v2-act-btn"
                  type="button"
                  onClick={() => {
                    if (hostIp) setCfg((prev) => ({ ...prev, proxy_host: hostIp }));
                    else void refreshDevices(false);
                  }}
                >
                  自动填入
                </button>
              </div>
            </div>

            <div className="v2-set-field" style={{ flex: "0 0 110px" }}>
              <label>代理端口</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={cfg.proxy_port}
                onChange={(e) =>
                  setCfg((prev) => ({
                    ...prev,
                    proxy_port: Math.max(1, Math.min(65535, Number(e.target.value) || 8080)),
                  }))
                }
              />
            </div>

            <div className="v2-set-field" style={{ flex: "2 1 280px" }}>
              <label>mitmproxy 根证书路径</label>
              <input
                value={cfg.cert_path}
                onChange={(e) => setCfg((prev) => ({ ...prev, cert_path: e.target.value }))}
                placeholder="~/.mitmproxy/mitmproxy-ca-cert.pem"
              />
            </div>

            <div className="v2-set-field" style={{ flex: "0 0 auto" }}>
              <label>&nbsp;</label>
              <button
                className="v2-act-btn"
                disabled={!!busy}
                onClick={() =>
                  void persistPatch({
                    proxy_host: cfg.proxy_host,
                    proxy_port: cfg.proxy_port,
                    cert_path: cfg.cert_path,
                  })
                }
              >
                保存参数
              </button>
            </div>
          </div>

          <div className="v2-set-actions">
            <button
              className="v2-top-btn pri"
              disabled={!!busy || !activeSerial}
              onClick={() => void runProxyAction("on", "开启手机代理")}
            >
              {busy === "proxy:on" ? "设置中…" : "开启手机代理"}
            </button>
            <button
              className="v2-top-btn"
              disabled={!!busy || !activeSerial}
              onClick={() => void runProxyAction("off", "关闭代理恢复直连")}
            >
              {busy === "proxy:off" ? "关闭中…" : "关闭代理（恢复直连）"}
            </button>
            <div className="v2-sep" />
            <button
              className="v2-top-btn"
              disabled={!!busy || !activeSerial}
              onClick={() => void runProxyAction("cert_install", "安装 mitmproxy 系统证书")}
            >
              {busy === "proxy:cert_install" ? "安装中…" : "安装系统证书"}
            </button>
            <button
              className="v2-top-btn danger"
              disabled={!!busy || !activeSerial}
              onClick={() => void runProxyAction("cert_remove", "移除 mitmproxy 系统证书")}
            >
              {busy === "proxy:cert_remove" ? "移除中…" : "移除系统证书"}
            </button>
            <button
              className="v2-act-btn"
              style={{ marginLeft: "auto" }}
              disabled={!!busy || !activeSerial}
              onClick={() => void runProxyAction("status", "刷新代理与证书状态")}
            >
              刷新状态
            </button>
          </div>
        </section>

        {/* 卡片 2（主伸展区）：统一常用 App 快捷管理（免输入，一键存常用） */}
        <section className="v2-set-card v2-set-apps-card">
          <div className="v2-set-card-hd">
            <div>
              <div className="v2-set-card-title">
                <span className="v2-sc-dot" style={{ background: "var(--amber)" }} />
                常用 App 快捷管理（冻结 / 解冻 / 强停 / 清理数据重启）
                <span className="v2-brand-ver">{cfg.favorite_apps.length} 个已存</span>
              </div>
              <div className="v2-set-card-desc">
                无需手输包名：点按钮一键把当前前台或手机已安装 App 存为常用（自动读真实应用名并持久化），下次直接点冻结、解冻、强停或清数据重开。
              </div>
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", flex: "0 0 auto" }}>
              <button
                className="v2-set-mcp-chip"
                onClick={() => onOpenToolDoc("device_app_suspend")}
                title="在工具库查看 MCP 工具 device_app_suspend"
              >
                MCP: device_app_suspend
              </button>
              <button
                className="v2-set-mcp-chip"
                onClick={() => onOpenToolDoc("device_app_reset")}
                title="在工具库查看 MCP 工具 device_app_reset"
              >
                MCP: device_app_reset
              </button>
            </div>
          </div>

          {/* 一键存常用 + 批量控制 + 清数据重启选项（无需手输） */}
          <div className="v2-set-subtoolbar">
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              <button
                className="v2-top-btn pri"
                disabled={!!busy || !activeDevice?.foreground}
                title={
                  activeDevice?.foreground
                    ? `一键保存当前前台 App：${activeDevice.foreground_label || activeDevice.foreground} (${activeDevice.foreground})`
                    : "连接手机并打开目标 App 后可一键存入"
                }
                onClick={() => void saveForegroundAsFavorite()}
              >
                {fgSaved
                  ? `✓ 前台已存（${activeDevice?.foreground_label || activeDevice?.foreground}）`
                  : activeDevice?.foreground
                    ? `+ 存当前前台为常用（${activeDevice.foreground_label || activeDevice.foreground}）`
                    : "+ 存当前前台为常用"}
              </button>

              <button
                className={"v2-top-btn" + (pkgPickerOpen ? " on" : "")}
                disabled={!!busy || !activeSerial}
                onClick={() => void togglePackagePicker()}
              >
                {pkgPickerOpen ? "收起手机应用列表" : "+ 从手机应用选"}
              </button>

              <button
                className={"v2-act-btn" + (manualAddOpen ? " on" : "")}
                onClick={() => setManualAddOpen((v) => !v)}
                title="仅在需要手贴未安装包名时展开"
              >
                {manualAddOpen ? "收起手动输入" : "手动输入"}
              </button>

              <div className="v2-sep" style={{ height: 16 }} />

              <button
                className="v2-act-btn"
                disabled={!!busy || !activeSerial || !favPkgs.length}
                onClick={() => void runSuspendAction("freeze", favPkgs, "全部冻结")}
              >
                全部冻结（{favPkgs.length}）
              </button>
              <button
                className="v2-act-btn"
                disabled={!!busy || !activeSerial || !favPkgs.length}
                onClick={() => void runSuspendAction("unfreeze", favPkgs, "全部解冻")}
              >
                全部解冻
              </button>
              <button
                className="v2-act-btn"
                disabled={!!busy || !activeSerial || !favPkgs.length}
                onClick={() => void runSuspendAction("status", favPkgs, "刷新冻结状态")}
              >
                刷新状态
              </button>
            </div>

            <div className="v2-set-reset-opts">
              <label className="v2-set-check">
                <input
                  type="checkbox"
                  checked={cfg.reset_relaunch}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setCfg((prev) => ({ ...prev, reset_relaunch: checked }));
                    void persistPatch({ reset_relaunch: checked }, true);
                  }}
                />
                <span>清数据后自动重开</span>
              </label>
              <span className="v2-set-wait-wrap">
                等待
                <input
                  type="number"
                  min={0}
                  max={15}
                  step={0.5}
                  value={cfg.reset_wait_sec}
                  onChange={(e) => {
                    const v = Math.max(0, Math.min(15, Number(e.target.value) || 0));
                    setCfg((prev) => ({ ...prev, reset_wait_sec: v }));
                  }}
                  onBlur={() => void persistPatch({ reset_wait_sec: cfg.reset_wait_sec }, true)}
                />
                秒
              </span>
            </div>
          </div>

          {/* 按需展开的手动输入条（默认折叠不打扰） */}
          {manualAddOpen && (
            <div className="v2-set-manual-bar">
              <input
                style={{ flex: "0.8 1 160px" }}
                value={newAppName}
                onChange={(e) => setNewAppName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && newAppPkg.trim()) void addFavoriteApp(newAppPkg, newAppName);
                }}
                placeholder="App 名称（留空自动读取）"
              />
              <input
                style={{ flex: "1.4 1 240px" }}
                value={newAppPkg}
                onChange={(e) => setNewAppPkg(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && newAppPkg.trim()) void addFavoriteApp(newAppPkg, newAppName);
                }}
                placeholder="输入包名，例如 com.example.app"
              />
              <button
                className="v2-top-btn pri"
                disabled={!!busy || !newAppPkg.trim()}
                onClick={() => void addFavoriteApp(newAppPkg, newAppName)}
              >
                {busy.startsWith("label:") ? "读取名称…" : "存为常用"}
              </button>
            </div>
          )}

          {/* 手机已安装第三方应用选择器（带真实应用名 + 包名 + 一键「存为常用」按钮） */}
          {pkgPickerOpen && (
            <div className="v2-pkg-picker">
              <div className="v2-pkg-picker-hd">
                <input
                  value={pkgPickerQ}
                  onChange={(e) => setPkgPickerQ(e.target.value)}
                  placeholder={`按应用名称或包名搜索手机已安装 App（共 ${installedApps.length} 个）…`}
                />
                <span className="v2-pkg-picker-note">
                  {busy === "pkgs"
                    ? "正在读取已安装列表…"
                    : resolvingLabels
                      ? "正在自动补全应用名称（首次解析后本地缓存）…"
                      : `已匹配 ${filteredInstalled.length} 个`}
                </span>
              </div>
              <div className="v2-pkg-picker-table">
                {filteredInstalled.map((item) => {
                  const saved = favPkgSet.has(item.package);
                  return (
                    <div key={item.package} className="v2-pkg-pick-row">
                      <span className="v2-pkg-pick-nm" title={item.name || item.package}>
                        {item.name || <em className="v2-set-unnamed">读取中…</em>}
                      </span>
                      <span className="mono v2-pkg-pick-id" title={item.package}>
                        {item.package}
                      </span>
                      <button
                        className={"v2-act-btn" + (saved ? "" : " pri")}
                        disabled={saved || !!busy}
                        onClick={() => void addFavoriteApp(item.package, item.name)}
                      >
                        {saved ? "已存" : "存为常用"}
                      </button>
                    </div>
                  );
                })}
                {!filteredInstalled.length && (
                  <div style={{ fontSize: 11.5, color: "var(--fg-3)", padding: 14, textAlign: "center" }}>
                    {busy === "pkgs" ? "正在读取手机已安装应用…" : "没有匹配的已安装应用"}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* 清理数据二次确认条 */}
          {confirmClearApp && (
            <div className="v2-set-confirm">
              <span>
                确认在设备 <b className="mono">{activeSerial}</b> 上强制停止并<strong>清空</strong>{" "}
                <b>{confirmClearApp.name || confirmClearApp.package}</b>{" "}
                <span className="mono" style={{ opacity: 0.85 }}>({confirmClearApp.package})</span> 的全部本地数据
                {cfg.reset_relaunch ? `（等待 ${cfg.reset_wait_sec}s 后自动重开）` : ""}？
              </span>
              <div style={{ display: "flex", gap: 6, flex: "0 0 auto" }}>
                <button
                  className="v2-top-btn danger-fill"
                  disabled={!!busy}
                  onClick={() => void runAppReset(confirmClearApp, true)}
                >
                  确认清空并执行
                </button>
                <button className="v2-act-btn" onClick={() => setConfirmClearApp(null)}>
                  取消
                </button>
              </div>
            </div>
          )}

          {/* 自适应撑满剩余高度的常用 App 表格 */}
          <div className="v2-set-app-table">
            <div className="v2-set-app-head">
              <span>App 名称</span>
              <span>包名</span>
              <span>状态</span>
              <span style={{ textAlign: "right" }}>快捷操作</span>
            </div>

            <div className="v2-set-app-list">
              {cfg.favorite_apps.length > 0 ? (
                cfg.favorite_apps.map((appItem) => {
                  const pkg = appItem.package;
                  const hasState = Object.prototype.hasOwnProperty.call(suspendMap, pkg);
                  const isSusp = suspendMap[pkg] === true;
                  const isFg = activeDevice?.foreground === pkg;
                  const isEditing = editingPkg === pkg;

                  return (
                    <div className={"v2-set-app-row" + (isFg ? " is-fg" : "")} key={pkg}>
                      <div className="v2-set-app-name-col">
                        {isEditing ? (
                          <div className="v2-set-inline-edit">
                            <input
                              autoFocus
                              value={editingName}
                              onChange={(e) => setEditingName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") void saveRenameApp(pkg);
                                if (e.key === "Escape") setEditingPkg(null);
                              }}
                              placeholder="输入易记的应用名称…"
                            />
                            <button className="v2-act-btn pri" onClick={() => void saveRenameApp(pkg)}>
                              保存
                            </button>
                            <button className="v2-act-btn" onClick={() => setEditingPkg(null)}>
                              取消
                            </button>
                          </div>
                        ) : (
                          <>
                            <span
                              className="v2-set-app-title"
                              title={appItem.name || pkg}
                              onDoubleClick={() => {
                                setEditingPkg(pkg);
                                setEditingName(appItem.name);
                              }}
                            >
                              {appItem.name || pkg.split(".").slice(-1)[0]}
                            </span>
                            {isFg && <span className="v2-set-fg-tag">前台</span>}
                          </>
                        )}
                      </div>

                      <span className="mono v2-set-pkg-nm" title={pkg}>{pkg}</span>

                      <div>
                        <span
                          className={
                            "v2-set-state-pill " +
                            (!hasState ? "unk" : isSusp ? "frozen" : "ok")
                          }
                        >
                          {!hasState ? "待查询" : isSusp ? "已冻结" : "正常"}
                        </span>
                      </div>

                      <div className="v2-set-pkg-ops">
                        <button
                          className="v2-act-btn"
                          disabled={!!busy || !activeSerial}
                          title="pm suspend 冻结（防浏览器跳 App，不删数据）"
                          onClick={() =>
                            void runSuspendAction("freeze", [pkg], `冻结 ${appItem.name || pkg}`)
                          }
                        >
                          冻结
                        </button>
                        <button
                          className="v2-act-btn"
                          disabled={!!busy || !activeSerial}
                          title="pm unsuspend 解冻恢复"
                          onClick={() =>
                            void runSuspendAction("unfreeze", [pkg], `解冻 ${appItem.name || pkg}`)
                          }
                        >
                          解冻
                        </button>
                        <div className="v2-sep" style={{ height: 14 }} />
                        <button
                          className="v2-act-btn"
                          disabled={!!busy || !activeSerial}
                          title="仅执行 am force-stop（保留数据）"
                          onClick={() => void runAppReset(appItem, false)}
                        >
                          强停
                        </button>
                        <button
                          className="v2-act-btn danger"
                          disabled={!!busy || !activeSerial}
                          title="强制停止 + 清理应用数据（+ 可选延时重开）"
                          onClick={() => setConfirmClearApp(appItem)}
                        >
                          {cfg.reset_relaunch ? "清数据重启" : "清数据"}
                        </button>
                        <div className="v2-sep" style={{ height: 14 }} />
                        <button
                          className="v2-act-btn"
                          title="修改应用名称/备注"
                          onClick={() => {
                            setEditingPkg(pkg);
                            setEditingName(appItem.name);
                          }}
                        >
                          改名
                        </button>
                        <button
                          className="v2-mod-x"
                          title="从常用列表移除（不影响手机上的 App）"
                          onClick={() => void removeFavoriteApp(pkg)}
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="v2-set-empty">
                  还没有常用 App。点上方 <strong>「+ 存当前前台为常用」</strong> 或 <strong>「+ 从手机应用选」</strong> 一键保存，自动记住应用名称与包名。
                </div>
              )}
            </div>
          </div>
        </section>

        {/* 底部常规环境信息条 */}
        <section className="v2-set-card v2-set-meta-card">
          <div className="v2-set-meta-row">
            <span>外观主题</span>
            <button className="v2-act-btn" onClick={onToggleTheme}>
              当前：{theme === "dark" ? "深色" : "浅色"}（点击切换）
            </button>
            <span>ADB 路径</span>
            <code className="mono">{adbPath || "未探测"}</code>
            <span>配置文件</span>
            <code className="mono">{cfgPath || "—"}</code>
          </div>
        </section>
      </div>

      {/* 底部真实执行结果输出条 */}
      {lastLog && (
        <div className={"v2-set-output" + (lastLog.ok ? " ok" : " err")}>
          <div className="v2-set-out-hd">
            <span className="mono">{lastLog.time}</span>
            <span className={"v2-set-state-pill " + (lastLog.ok ? "ok" : "err")}>
              {lastLog.ok ? "成功" : "失败"}
            </span>
            <strong>{lastLog.title}</strong>
            <span className="v2-set-out-msg">{lastLog.message}</span>
            {lastLog.detail !== undefined && (
              <button
                className="v2-act-btn"
                style={{ marginLeft: "auto" }}
                onClick={() => setShowRawDetail((v) => !v)}
              >
                {showRawDetail ? "收起详情" : "查看 JSON"}
              </button>
            )}
          </div>
          {showRawDetail && lastLog.detail !== undefined && (
            <pre className="v2-set-out-pre">{JSON.stringify(lastLog.detail, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  );
}
