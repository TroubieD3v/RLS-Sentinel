import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

// Regenerates docs/assets/*.png from a real run of the bundled fixture. Skipped unless SCREENSHOTS=1.
const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../docs/assets");
test.skip(!process.env.SCREENSHOTS, "set SCREENSHOTS=1 to regenerate documentation screenshots");
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });

test("documentation screenshots from real data", async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto("/");
  await page.screenshot({ path: path.join(out, "welcome-dark.png") });

  await page.goto("/studio");
  await page.getByTestId("fixture-select").selectOption("multi-tenant-saas");
  await page.getByTestId("variant-select").selectOption("vulnerable");
  await page.getByTestId("run-tests").click();
  await expect(page.getByTestId("run-done")).toBeVisible({ timeout: 90_000 });

  await page.goto("/");
  await expect(page.getByTestId("stat-confirmed")).toBeVisible();
  await page.waitForTimeout(2000); // let chart entry animations finish
  await page.screenshot({ path: path.join(out, "overview-dark.png") });

  await page.goto("/matrix");
  const cell = page.locator('[data-case="bob-cannot-read-alpha-comment"]');
  await cell.scrollIntoViewIfNeeded();
  await cell.click();
  await expect(page.getByTestId("case-detail")).toContainText("ROW_RETURNED");
  await page.screenshot({ path: path.join(out, "matrix-evidence-dark.png") });

  await page.goto("/findings");
  await page.getByTestId("finding-row").first().click();
  await expect(page.getByTestId("finding-detail")).toContainText("Steps to reproduce");
  await page.screenshot({ path: path.join(out, "finding-dark.png") });

  await page.goto("/graph?table=public.invoices");
  await expect(page.getByTestId("graph-canvas")).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(out, "graph-dark.png") });

  await page.goto("/what-if");
  await page.getByTestId("draft-sql").fill("DROP POLICY comments_select_all ON comments;\nDROP POLICY comments_delete_any ON comments;");
  await page.getByTestId("run-whatif").click();
  await expect(page.getByTestId("whatif-results")).toBeVisible({ timeout: 90_000 });
  await page.screenshot({ path: path.join(out, "whatif-dark.png"), fullPage: false });
  await page.getByTestId("whatif-results").evaluate((el) => el.scrollIntoView({ block: "start" }));
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(out, "whatif-results-dark.png") });

  await page.goto("/schema?table=public.invoices");
  await expect(page.getByTestId("table-detail")).toContainText("Row-level security");
  await page.screenshot({ path: path.join(out, "schema-dark.png") });

  await page.emulateMedia({ colorScheme: "light" });
  await page.evaluate(() => localStorage.setItem("sentinel.theme", "light"));
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(out, "overview-light.png") });
  await page.goto("/matrix");
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(out, "matrix-light.png") });
});
