import { defineConfig, devices } from "@playwright/test";
import os from "node:os";
import path from "node:path";

const bin = process.env.SENTINEL_BIN ?? "rls-sentinel";
const port = Number(process.env.E2E_PORT ?? 8799);
const dataDir = path.join(os.tmpdir(), `rls-sentinel-e2e-${process.pid}`);

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: `http://localhost:${port}`, trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } }, testIgnore: /mobile\.spec\.ts/ },
    { name: "mobile", use: { ...devices["Pixel 7"] }, testMatch: /mobile\.spec\.ts/ },
  ],
  webServer: {
    command: `${bin} serve --port ${port}`,
    url: `http://localhost:${port}/api/v1/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: { SENTINEL_DATA_DIR: dataDir, SENTINEL_FIXTURE_BACKEND: process.env.SENTINEL_FIXTURE_BACKEND ?? "auto", PYTHONUTF8: "1" },
  },
});
