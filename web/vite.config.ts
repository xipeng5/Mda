import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// (1) 第一次修改（2026-11-26）
// bug 原因：开发模式（5173）未配置 /api 代理，直接访问同源 /api/* 或 WS /api/events 时失败。
// 解决方案：增加 /api 代理（含 ws: true）转发到本地后端 127.0.0.1:8766。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8766",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
