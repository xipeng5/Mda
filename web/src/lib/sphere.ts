import type { ModuleData } from "./data";

/** 球面场景：多 so 同屏（当前放大、其余缩小停在两侧），并叠加关系线、断点、构建进度。
 *
 *  纯 canvas 2D 投影，没有 3D 引擎：
 *  - 点 = 函数；纬度 = 地址序；颜色分级 = 被引用次数
 *  - 关系线只画选中函数的入边/出边（各限 10 条，避免扇出 400 条变毛球）
 */
const GA = Math.PI * (3 - Math.sqrt(5));

export type Theme = "dark" | "light";
export type Relations = { ins: number[]; outs: number[] };

export type Palette = {
  dot: readonly number[];
  shell: string;
  meridian: string;
  live: readonly number[];
  fg3: string;
  fg4: string;
};

const PAL: Record<Theme, Palette> = {
  dark: {
    dot: [255, 255, 255],
    shell: "rgba(77,141,255,0.26)",
    meridian: "rgba(77,141,255,0.16)",
    live: [77, 141, 255],
    fg3: "rgba(168,176,174,0.95)",
    fg4: "rgba(123,132,130,0.85)",
  },
  light: {
    dot: [15, 20, 22],
    shell: "rgba(31,95,208,0.30)",
    meridian: "rgba(31,95,208,0.18)",
    live: [31, 95, 208],
    fg3: "rgba(74,83,80,0.95)",
    fg4: "rgba(105,114,112,0.85)",
  },
};

type ModState = {
  data: ModuleData;
  n: number;
  PX: Float32Array;
  PY: Float32Array;
  PZ: Float32Array;
  tier: Uint8Array;
  order: Int32Array;
  sx: Float32Array;
  sy: Float32Array;
  sz: Float32Array;
  idx: Map<number, number>;
  maxRef: number;
  view: { cx: number; cy: number; r: number };
};

export class SphereScene {
  private ctx: CanvasRenderingContext2D;
  private raf = 0;
  private W = 0;
  private H = 0;
  private dpr = 1;

  private mods: ModState[] = [];
  private active = 0;
  private selected: number[] = [];
  private relations: Relations | null = null;
  private breakpoints: Record<string, Set<number>> = {};
  private progress: { percent: number } | null = null;
  private compact = false;
  private mx = -1;
  private my = -1;
  private flash: { i: number; t0: number } | null = null;
  private switchT0 = 0;
  private breath = 1;                 /* 切换 so 时外壳的一次性呼吸系数（不写回 view.r） */              /* 代码打开时：球缩到右上角，其余球不画 */

  private yaw = 0.4;
  private pitch = 0.18;
  private tYaw: number | null = null;
  private tPitch: number | null = null;
  private animT0 = 0;
  private fromYaw = 0;
  private fromPitch = 0;

  theme: Theme = "dark";

  constructor(private canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("canvas 2d 不可用");
    this.ctx = ctx;
  }

  /** 幂等：同一个 so 复用已有球面数据，避免切换时重新布点 */
  setModules(mods: ModuleData[]) {
    const keep = this.mods;
    this.mods = mods.map((m, i) => {
      const old = keep[i];
      if (old && old.data.so === m.so && old.n === m.funcs.length) return old;
      return this.build(m);
    });
  }

  private build(m: ModuleData): ModState {
    const n = m.funcs.length;
    const st: ModState = {
      data: m,
      n,
      PX: new Float32Array(n),
      PY: new Float32Array(n),
      PZ: new Float32Array(n),
      tier: new Uint8Array(n),
      order: new Int32Array(n).map((_, i) => i),
      sx: new Float32Array(n),
      sy: new Float32Array(n),
      sz: new Float32Array(n),
      idx: new Map<number, number>(),
      maxRef: 1,
      view: { cx: 0, cy: 0, r: 0 },
    };
    for (let i = 0; i < n; i++) {
      const y = n === 1 ? 0 : 1 - (i / (n - 1)) * 2;
      const r = Math.sqrt(Math.max(0, 1 - y * y));
      const th = i * GA;
      st.PX[i] = Math.cos(th) * r;
      st.PY[i] = y;
      st.PZ[i] = Math.sin(th) * r;
      const rc = m.funcs[i].r;
      st.tier[i] = rc <= 0 ? 0 : rc < 5 ? 1 : 2;
      st.idx.set(m.funcs[i].a, i);
    }
    st.maxRef = m.funcs.reduce((a, f) => Math.max(a, f.r), 0) || 1;
    return st;
  }

  setActive(i: number) {
    this.active = i;
    this.relations = null;
  }
  setSelected(list: number[]) {
    this.selected = list;
  }
  setRelations(r: Relations | null) {
    this.relations = r;
  }
  setBreakpoints(map: Record<string, Set<number>>) {
    this.breakpoints = map;
  }
  setProgress(p: { percent: number } | null) {
    this.progress = p;
  }
  setCompact(b: boolean) {
    this.compact = b;
  }
  /** AI 一次性脉冲：目标点扩散环 + 外壳脉冲，1.5 秒，不循环 */
  setFlash(i: number) {
    this.flash = { i, t0: performance.now() };
  }

  /** 切 so 的交接：点云 260ms 淡入 + 外壳一次 1.5% 呼吸 */
  pulse() {
    this.switchT0 = performance.now();
  }

  /** 鼠标位置（用于悬停命中：2000 个点里找最近的一个） */
  setMouse(x: number, y: number) {
    this.mx = x;
    this.my = y;
  }
  private get modCompact() {
    return this.compact;
  }
  toggleBreakpoint(addr: number) {
    const so = this.mods[this.active]?.data.so;
    if (!so) return;
    if (!this.breakpoints[so]) this.breakpoints[so] = new Set();
    const set = this.breakpoints[so];
    if (set.has(addr)) set.delete(addr);
    else set.add(addr);
    this.breakpoints = { ...this.breakpoints };
  }

  rotateTo(i: number) {
    const st = this.mods[this.active];
    if (!st || i < 0 || i >= st.n) return;
    const x = st.PX[i], y = st.PY[i], z = st.PZ[i];
    const pitch = Math.atan2(y, z);
    const z1 = Math.hypot(y, z);
    const yaw = Math.atan2(-x, z1);
    this.fromYaw = this.yaw;
    this.fromPitch = this.pitch;
    let dy = yaw - this.yaw;
    while (dy > Math.PI) dy -= Math.PI * 2;
    while (dy < -Math.PI) dy += Math.PI * 2;
    this.tYaw = this.yaw + dy;
    this.tPitch = pitch;
    this.animT0 = performance.now();
  }

  dragBy(dx: number, dy: number) {
    this.tYaw = null;
    this.tPitch = null;
    this.yaw += dx * 0.0075;
    this.pitch = Math.max(-1.25, Math.min(1.25, this.pitch + dy * 0.0075));
  }

  start() {
    const loop = (now: number) => {
      this.raf = requestAnimationFrame(loop);
      this.draw(now);
    };
    this.raf = requestAnimationFrame(loop);
  }
  stop() {
    cancelAnimationFrame(this.raf);
  }

  resize() {
    this.dpr = Math.min(2, window.devicePixelRatio || 1);
    this.W = this.canvas.clientWidth;
    this.H = this.canvas.clientHeight;
    this.canvas.width = Math.max(1, this.W * this.dpr);
    this.canvas.height = Math.max(1, this.H * this.dpr);
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
  }

  /** 布局：当前 so 居中放大，其余缩小停在左右两侧 */
  private layout() {
    const { W, H } = this;
    if (!W || !H) return;
    if (this.compact) {
      /* 缩到右上角：只动当前球，其余球直接收成 0 半径（不参与绘制） */
      this.mods.forEach((st, i) => {
        if (i === this.active) {
          const r = Math.max(56, Math.min(W, H) * 0.09);
          const tcx = W - r - 26, tcy = r + 30;
          if (!st.view.r) st.view = { cx: tcx, cy: tcy, r };
          else {
            st.view.cx += (tcx - st.view.cx) * 0.18;
            st.view.cy += (tcy - st.view.cy) * 0.18;
            st.view.r += (r - st.view.r) * 0.18;
          }
        } else {
          st.view.r += (0 - st.view.r) * 0.2;
        }
      });
      return;
    }
    const R = Math.min(W, H) * 0.33;
    const rs = Math.max(26, Math.min(W, H) * 0.072);
    const others = this.mods.map((_, i) => i).filter((i) => i !== this.active);
    const n = others.length;
    this.mods.forEach((st, i) => {
      let tcx: number, tcy: number, tr: number;
      if (i === this.active) {
        tcx = W / 2;
        tcy = H / 2 - 6;
        tr = R;
      } else {
        const k = others.indexOf(i);
        const side = k % 2 === 0 ? 1 : -1;
        const slot = Math.floor(k / 2);
        const gap = R + rs + 40;
        tcx = Math.max(rs + 18, Math.min(W - rs - 18, W / 2 + side * gap));
        tcy = Math.max(rs + 46, Math.min(H - rs - 34,
          H / 2 + (slot - (Math.ceil(n / 2) - 1) / 2) * (rs * 2 + 46)));
        tr = rs;
      }
      if (!st.view.r) {
        st.view = { cx: tcx, cy: tcy, r: tr };
      } else {
        st.view.cx += (tcx - st.view.cx) * 0.16;
        st.view.cy += (tcy - st.view.cy) * 0.16;
        st.view.r += (tr - st.view.r) * 0.16;
      }
    });
  }

  private project(st: ModState, cx: number, cy: number, R: number) {
    const cyw = Math.cos(this.yaw), syw = Math.sin(this.yaw);
    const cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    for (let i = 0; i < st.n; i++) {
      const x = st.PX[i], y = st.PY[i], z = st.PZ[i];
      const y1 = y * cp - z * sp, z1 = y * sp + z * cp;
      const x2 = x * cyw + z1 * syw, z2 = -x * syw + z1 * cyw;
      const persp = 1 / (1 - z2 * 0.2);
      st.sx[i] = cx + x2 * R * persp;
      st.sy[i] = cy + y1 * R * persp;
      st.sz[i] = z2;
    }
  }

  private paintSphere(st: ModState, pal: Palette, isActive: boolean) {
    const ctx = this.ctx;
    const cx = st.view.cx, cy = st.view.cy;
    const R = isActive ? st.view.r * this.breath : st.view.r;
    const cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    this.project(st, cx, cy, R);

    ctx.lineWidth = 1;
    ctx.strokeStyle = pal.shell;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.stroke();
    ctx.strokeStyle = pal.meridian;
    ctx.beginPath();
    ctx.ellipse(cx, cy, R, R * Math.abs(sp) + 1, 0, 0, Math.PI * 2);
    ctx.stroke();

    st.order.sort((a, b) => st.sz[a] - st.sz[b]);
    const buckets = new Map<number, number[]>();
    for (let k = 0; k < st.n; k++) {
      const i = st.order[k];
      const depth = (st.sz[i] + 1) / 2;
      const key = Math.round(depth * 5) * 6 + st.tier[i] * 2 + (st.data.funcs[i].e ? 1 : 0);
      let b = buckets.get(key);
      if (!b) { b = []; buckets.set(key, b); }
      b.push(i);
    }

    const dot = pal.dot, live = pal.live;
    const COLS = [
      [dot[0], dot[1], dot[2]],
      [Math.round((dot[0] + live[0]) / 2), Math.round((dot[1] + live[1]) / 2), Math.round((dot[2] + live[2]) / 2)],
      [live[0], live[1], live[2]],
    ];
    const sk = isActive ? 1 : 0.52;
    for (const [key, list] of buckets) {
      const aLv = Math.floor(key / 6);
      const tier = Math.floor((key % 6) / 2);
      const isExp = key % 2;
      const c = COLS[tier];
      // (1) 第一次修改：浅色主题下 0.1 的透明度在白底上几乎不可见，
      //     按主题给不同的透明度下限，保证两张主题都能看清点云。
      const floor = this.theme === "light" ? 0.30 : 0.10;
      const span = this.theme === "light" ? 0.62 : 0.82;
      const alpha = (floor + (aLv / 5) * span) * (isActive ? 1 : 0.75);
      ctx.fillStyle = `rgba(${c[0]},${c[1]},${c[2]},${alpha.toFixed(3)})`;
      for (const i of list) {
        const depth = (st.sz[i] + 1) / 2;
        const hot = Math.min(1, Math.log2(1 + st.data.funcs[i].r) / Math.log2(1 + st.maxRef));
        const s = ((isExp ? 1.9 : 1.5) + depth * 1.7 + hot * 1.5) * sk;
        ctx.fillRect(st.sx[i] - s / 2, st.sy[i] - s / 2, s, s);
      }
    }

    if (!isActive) {
      ctx.fillStyle = pal.fg3;
      ctx.font = "11px ui-monospace, Menlo, monospace";
      ctx.textAlign = "center";
      const nm = st.data.so.length > 20 ? st.data.so.slice(0, 19) + "…" : st.data.so;
      ctx.fillText(nm, cx, cy + R + 15);
      ctx.fillStyle = pal.fg4;
      ctx.fillText(st.n + " 函数", cx, cy + R + 29);
      ctx.textAlign = "left";
    }
  }

  private drawRelations(st: ModState, pal: Palette) {
    const rel = this.relations;
    const sel = this.selected[this.active] ?? -1;
    if (!rel || sel < 0) return;
    const ctx = this.ctx;
    const tx = st.sx[sel], ty = st.sy[sel];
    const cx = st.view.cx, cy = st.view.cy;
    const arc = (ax: number, ay: number, dash: boolean) => {
      const mx = (ax + tx) / 2, my = (ay + ty) / 2;
      const nx = mx - cx, ny = my - cy;
      const len = Math.hypot(nx, ny) || 1;
      const push = Math.max(24, len * 0.3);
      ctx.beginPath();
      ctx.setLineDash(dash ? [3, 3] : []);
      ctx.moveTo(ax, ay);
      ctx.quadraticCurveTo(mx + (nx / len) * push, my + (ny / len) * push, tx, ty);
      ctx.stroke();
      ctx.setLineDash([]);
    };
    ctx.lineWidth = 1.3;
    ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.85)`;
    for (const a of rel.ins.slice(0, 10)) {
      const i = st.idx.get(a);
      if (i === undefined) continue;
      arc(st.sx[i], st.sy[i], false);
      ctx.fillStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.9)`;
      ctx.beginPath();
      ctx.arc(st.sx[i], st.sy[i], 2.6, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.strokeStyle = `rgba(${pal.dot[0]},${pal.dot[1]},${pal.dot[2]},0.42)`;
    for (const a of rel.outs.slice(0, 10)) {
      const i = st.idx.get(a);
      if (i === undefined) continue;
      arc(st.sx[i], st.sy[i], true);
    }
  }

  private drawBreakpoints(st: ModState, pal: Palette) {
    const set = this.breakpoints[st.data.so];
    if (!set || !set.size) return;
    const ctx = this.ctx;
    ctx.lineWidth = 1.2;
    for (const addr of set) {
      const i = st.idx.get(addr);
      if (i === undefined) continue;
      const x = st.sx[i], y = st.sy[i], r = 6;
      ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.95)`;
      ctx.beginPath();
      ctx.moveTo(x, y - r); ctx.lineTo(x + r, y); ctx.lineTo(x, y + r); ctx.lineTo(x - r, y);
      ctx.closePath();
      ctx.stroke();
      ctx.fillStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.25)`;
      ctx.fill();
    }
  }

  private drawProgress(st: ModState, pal: Palette) {
    if (!this.progress) return;
    const ctx = this.ctx;
    const t = Math.max(0, Math.min(1, this.progress.percent / 100));
    ctx.lineWidth = 3;
    ctx.strokeStyle = "rgba(255,255,255,0.07)";
    ctx.beginPath();
    ctx.arc(st.view.cx, st.view.cy, st.view.r + 10, 0, Math.PI * 2);
    ctx.stroke();
    ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.95)`;
    ctx.beginPath();
    ctx.arc(st.view.cx, st.view.cy, st.view.r + 10, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * t);
    ctx.stroke();
  }

  private draw(now: number) {
    if (!this.W || !this.H) this.resize();
    if (!this.mods.length) return;
    if (this.tYaw !== null && this.tPitch !== null) {
      const t = Math.min(1, (now - this.animT0) / 460);
      const k = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
      this.yaw = this.fromYaw + (this.tYaw - this.fromYaw) * k;
      this.pitch = this.fromPitch + (this.tPitch - this.fromPitch) * k;
      if (t >= 1) {
        this.tYaw = null;
        this.tPitch = null;
      }
    }

    this.layout();
    const ctx = this.ctx;
    const pal = PAL[this.theme];
    const swT = this.switchT0 ? Math.min(1, (now - this.switchT0) / 260) : 1;
    this.breath = 1 - 0.015 * Math.sin(Math.PI * swT);
    ctx.globalAlpha = swT;
    ctx.clearRect(0, 0, this.W, this.H);

    const order = this.mods.map((_, i) => i).filter((i) => i !== this.active).concat([this.active]);
    for (const i of order) {
      if (this.modCompact && this.mods[i].view.r < 8) continue;
      this.paintSphere(this.mods[i], pal, i === this.active);
    }

    const act = this.mods[this.active];
    if (!this.modCompact) {
      this.drawRelations(act, pal);
      this.drawProgress(act, pal);
    }
    this.drawBreakpoints(act, pal);

    /* 悬停：最近的函数点画环 + 名字，让"每个点是一个函数"能被指认 */
    if (!this.modCompact && this.mx >= 0) {
      let best = -1, bestD = 144;                 /* 12px 半径 */
      for (let i = 0; i < act.n; i++) {
        const dx = act.sx[i] - this.mx, dy = act.sy[i] - this.my;
        const d = dx * dx + dy * dy;
        if (d < bestD) { bestD = d; best = i; }
      }
      if (best >= 0) {
        const hx = act.sx[best], hy = act.sy[best];
        const nm = act.data.funcs[best].n;
        const label = nm.length > 34 ? nm.slice(0, 33) + "…" : nm;
        ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.95)`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(hx, hy, 7, 0, Math.PI * 2);
        ctx.stroke();
        ctx.font = "10.5px ui-monospace, Menlo, monospace";
        const tw = ctx.measureText(label).width + 10;
        const tx = Math.min(this.W - tw - 6, hx + 12);
        const ty = Math.max(14, hy - 16);
        ctx.fillStyle = pal.fg3;
        ctx.fillRect(tx, ty, tw, 15);
        ctx.fillStyle = this.theme === "light" ? "#ffffff" : "#0b0c0d";
        ctx.fillText(label, tx + 5, ty + 11);
      }
    }

    ctx.globalAlpha = 1;

    if (this.flash) {
      const t = (now - this.flash.t0) / 1000;
      if (t > 1.5) this.flash = null;
      else {
        const k = t / 1.5;
        const i = this.flash.i;
        const cx = act.view.cx, cy = act.view.cy;
        const a3 = `${pal.live[0]},${pal.live[1]},${pal.live[2]}`;
        ctx.lineWidth = 1.5;
        ctx.strokeStyle = `rgba(${a3},${(0.55 * (1 - k)).toFixed(3)})`;
        ctx.beginPath();
        ctx.arc(cx, cy, act.view.r + 6 * Math.sin(k * Math.PI), 0, Math.PI * 2);
        ctx.stroke();
        if (i >= 0 && i < act.n) {
          ctx.strokeStyle = `rgba(${a3},${(0.9 * (1 - k)).toFixed(3)})`;
          ctx.beginPath();
          ctx.arc(act.sx[i], act.sy[i], 6 + k * 46, 0, Math.PI * 2);
          ctx.stroke();
          ctx.fillStyle = `rgba(${a3},${(1 - k).toFixed(3)})`;
          ctx.fillRect(act.sx[i] - 2, act.sy[i] - 2, 4, 4);
        }
      }
    }

    /* 代码模式下小球外面套一个方形边框：是"缩略视图"，不是悬空的圆 */
    if (this.compact) {
      const v = act.view;
      const side = v.r * 2 + 30;
      const x = v.cx - side / 2, y = v.cy - side / 2;
      ctx.lineWidth = 1;
      ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.30)`;
      ctx.strokeRect(x, y, side, side);
      ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.85)`;
      const tick = 8;
      const corners: [number, number, number, number][] = [
        [x, y, 1, 1], [x + side, y, -1, 1], [x, y + side, 1, -1], [x + side, y + side, -1, -1],
      ];
      for (const [cx0, cy0, dx, dy] of corners) {
        ctx.beginPath();
        ctx.moveTo(cx0, cy0 + dy * tick);
        ctx.lineTo(cx0, cy0);
        ctx.lineTo(cx0 + dx * tick, cy0);
        ctx.stroke();
      }
      ctx.fillStyle = pal.fg4;
      ctx.font = "10px ui-monospace, Menlo, monospace";
      ctx.textAlign = "center";
      const nm = act.data.so.length > 18 ? act.data.so.slice(0, 17) + "…" : act.data.so;
      ctx.fillText(nm, v.cx, y + side + 12);
      ctx.textAlign = "left";
    }

    const sel = this.selected[this.active] ?? -1;
    if (sel >= 0) {
      const x = act.sx[sel], y = act.sy[sel];
      ctx.strokeStyle = `rgba(${pal.live[0]},${pal.live[1]},${pal.live[2]},0.95)`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(x, y, 11, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(x - 16, y); ctx.lineTo(x - 6, y);
      ctx.moveTo(x + 6, y); ctx.lineTo(x + 16, y);
      ctx.stroke();
    }
  }
}
