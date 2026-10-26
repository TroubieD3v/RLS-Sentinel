import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";

// Records the frames of docs/assets/demo.gif from a real run of the bundled fixture. Skipped unless DEMO=1.
// Then: python scripts/make_gif.py
const frames = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../docs/assets/frames");
test.skip(!process.env.DEMO, "set DEMO=1 to record the README demo");
test.use({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1, colorScheme: "dark" });

let n = 0;
async function frame(page: Page, holdTenths: number) {
  await page.waitForTimeout(250);
  n += 1;
  await page.screenshot({ path: path.join(frames, `${String(n).padStart(3, "0")}-${holdTenths}.png`) });
}

test("README demo", async ({ page }) => {
  test.setTimeout(300_000);
  fs.rmSync(frames, { recursive: true, force: true });
  fs.mkdirSync(frames, { recursive: true });

  await page.goto("/");
  await expect(page.getByTestId("welcome")).toBeVisible();
  await frame(page, 22);

  await page.goto("/studio");
  await page.getByTestId("fixture-select").selectOption("multi-tenant-saas");
  await page.getByTestId("variant-select").selectOption("vulnerable");
  await frame(page, 14);
  await page.getByTestId("run-tests").click();
  await frame(page, 6);
  await expect(page.getByTestId("run-done")).toBeVisible({ timeout: 90_000 });
  await frame(page, 16);

  await page.goto("/");
  await expect(page.getByTestId("stat-confirmed")).toContainText("8");
  await page.waitForTimeout(1800);
  await frame(page, 26);

  await page.goto("/matrix");
  const cell = page.locator('[data-case="bob-cannot-read-alpha-comment"]');
  await cell.scrollIntoViewIfNeeded();
  await frame(page, 12);
  await cell.click();
  await expect(page.getByTestId("case-detail")).toContainText("ROW_RETURNED");
  await page.getByTestId("case-detail").evaluate((el) => el.scrollIntoView({ block: "center" }));
  await frame(page, 30);

  await page.goto("/findings");
  await page.getByTestId("finding-row").first().click();
  await expect(page.getByTestId("finding-detail")).toContainText("Steps to reproduce");
  await frame(page, 26);

  await page.goto("/graph?table=public.comments");
  await expect(page.getByTestId("graph-canvas")).toBeVisible();
  await page.waitForTimeout(900);
  await frame(page, 22);

  await page.goto("/what-if");
  await page.getByTestId("draft-sql").fill("DROP POLICY comments_select_all ON comments;\nDROP POLICY comments_delete_any ON comments;");
  await frame(page, 16);
  await page.getByTestId("run-whatif").click();
  await expect(page.getByTestId("whatif-results")).toBeVisible({ timeout: 90_000 });
  await page.getByTestId("whatif-results").evaluate((el) => el.scrollIntoView({ block: "start" }));
  await frame(page, 32);

  await page.goto("/studio");
  await page.getByTestId("fixture-select").selectOption("multi-tenant-saas");
  await page.getByTestId("variant-select").selectOption("secure");
  await page.getByTestId("run-tests").click();
  await expect(page.getByTestId("run-done")).toBeVisible({ timeout: 90_000 });
  await page.goto("/");
  await expect(page.getByTestId("stat-confirmed")).toContainText("0");
  await page.waitForTimeout(1800);
  await frame(page, 30);
});
