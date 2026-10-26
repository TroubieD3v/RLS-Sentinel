import { expect, test, type Page } from "@playwright/test";

const overflow = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

test("mobile: navigation drawer opens, routes work, page does not overflow horizontally", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("welcome").or(page.getByRole("heading", { name: "Command center" }))).toBeVisible();
  expect(await overflow(page)).toBeLessThanOrEqual(2);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("link", { name: "Findings" }).click();
  await expect(page).toHaveURL(/\/findings/);
  await expect(page.getByRole("heading", { name: "Findings", level: 1 })).toBeVisible();
});

test("mobile: data-dense pages keep wide tables inside their own scroll container", async ({ page }) => {
  for (const path of ["/reports", "/matrix", "/policies", "/schema", "/history", "/findings"]) {
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    expect(await overflow(page), `horizontal overflow on ${path}`).toBeLessThanOrEqual(2);
  }
});

test("mobile: welcome state uses the compact ASCII variant when no run exists", async ({ page }) => {
  await page.goto("/");
  const welcome = page.getByTestId("welcome");
  test.skip(!(await welcome.isVisible().catch(() => false)), "runs already exist on this server");
  await expect(page.locator("pre[aria-hidden='true']").filter({ hasText: "ACCESS TELEMETRY" }).last()).toBeVisible();
});
