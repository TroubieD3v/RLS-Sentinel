import { createRequire } from "node:module";
import { expect, test, type Page } from "@playwright/test";

const require = createRequire(import.meta.url);
const axePath = require.resolve("axe-core/axe.min.js");

// The app ships a strict CSP (no inline scripts); the audit injects axe-core, so CSP is bypassed for this audit only.
test.use({ bypassCSP: true });

async function audit(page: Page, label: string) {
  await page.addScriptTag({ path: axePath });
  const results = await page.evaluate(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = await (window as any).axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] } });
    return r.violations.map((v: { id: string; impact: string; nodes: { target: string[]; html: string }[] }) => ({ id: v.id, impact: v.impact, targets: v.nodes.slice(0, 3).map((n) => n.target.join(" ")) }));
  });
  const serious = results.filter((v: { impact: string }) => v.impact === "serious" || v.impact === "critical");
  expect(serious, `${label}: ${JSON.stringify(serious, null, 1)}`).toEqual([]);
}

for (const theme of ["dark", "light"] as const) {
  test.describe(`accessibility (${theme})`, () => {
    test.beforeEach(async ({ page }) => {
      await page.addInitScript((t) => localStorage.setItem("sentinel.theme", t), theme);
    });
    for (const path of ["/", "/connections", "/matrix", "/findings", "/schema", "/policies", "/graph", "/studio", "/what-if", "/reports", "/history", "/settings"]) {
      test(`${path} has no serious/critical WCAG A/AA violations`, async ({ page }) => {
        await page.goto(path);
        await page.waitForLoadState("networkidle");
        await audit(page, `${theme} ${path}`);
      });
    }
  });
}

test("reduced motion setting disables animation", async ({ page }) => {
  await page.goto("/settings");
  await page.getByTestId("reduced-motion").check();
  await expect(page.locator("html")).toHaveAttribute("data-reduced-motion", "1");
});

test("theme follows OS preference and can be overridden", async ({ browser }) => {
  const ctx = await browser.newContext({ colorScheme: "light", baseURL: "http://localhost:8799" });
  const p = await ctx.newPage();
  await p.goto("/settings");
  await expect(p.locator("html")).toHaveAttribute("data-theme", "light");
  await p.getByRole("combobox", { name: "Theme" }).selectOption("dark");
  await expect(p.locator("html")).toHaveAttribute("data-theme", "dark");
  await ctx.close();
});
