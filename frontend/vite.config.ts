/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: { port: 5173, proxy: { "/api": { target: "http://127.0.0.1:8787", changeOrigin: false } } },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test-setup.ts"], include: ["src/**/*.test.{ts,tsx}"], css: false },
});
