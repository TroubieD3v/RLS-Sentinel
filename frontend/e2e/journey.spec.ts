import { expect, test, type Page } from "@playwright/test";

async function runFixture(page: Page, variant: "vulnerable" | "secure") {
  await page.goto("/studio");
  await page.getByTestId("fixture-select").selectOption("multi-tenant-saas");
  await page.getByTestId("variant-select").selectOption(variant);
  await page.getByTestId("run-tests").click();
  await expect(page.getByTestId("live-count")).toContainText("42 / 42 cases executed", { timeout: 90_000 });
  await expect(page.getByTestId("run-done")).toBeVisible({ timeout: 30_000 });
}

test.describe.serial("demo journey: fixture → run → evidence → what-if → report", () => {
  test("welcome state explains the product, with no fake data", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByTestId("welcome")).toContainText("Database access. Verified.");
    // the decorative ASCII art is hidden from assistive tech and followed by a real text description
    await expect(page.locator("pre[aria-hidden='true']").filter({ hasText: "ACCESS TELEMETRY" }).first()).toHaveAttribute("aria-hidden", "true");
    await expect(page.locator("figcaption")).toContainText("decorative example text, not scan output");
    await expect(page.getByTestId("lab-status").or(page.getByTestId("topbar-status"))).toBeVisible();
    await expect(page.getByTestId("stat-confirmed")).toHaveCount(0); // no counts before anything ran
  });

  test("vulnerable run streams real progress and updates real counts", async ({ page }) => {
    await runFixture(page, "vulnerable");
    await page.goto("/");
    await expect(page.getByTestId("stat-tests")).toContainText("42");
    await expect(page.getByTestId("stat-confirmed")).toContainText("8");
    await expect(page.getByTestId("stat-policies")).toContainText("16");
    await expect(page.getByTestId("coverage-panel")).toContainText("FAIL");
    await expect(page.getByTestId("coverage-panel")).toContainText("Verified coverage");
  });

  test("matrix cell opens evidence with the deciding gate and applicable policies", async ({ page }) => {
    await page.goto("/matrix");
    const cell = page.locator('[data-case="bob-cannot-read-alpha-comment"]');
    await cell.scrollIntoViewIfNeeded();
    await cell.click();
    const d = page.getByTestId("case-detail");
    await expect(d).toContainText(/fail/i);
    await expect(d).toContainText("ROW_RETURNED");
    await expect(d).toContainText("comments_select_all");
    await expect(d).toContainText("contents not retained");
  });

  test("keyboard: arrow keys move the matrix focus; Ctrl+K opens the command palette", async ({ page }) => {
    await page.goto("/matrix");
    const first = page.locator(".matrix-cell").first();
    await first.focus();
    await page.keyboard.press("ArrowRight");
    await expect(page.locator(".matrix-cell:focus")).toHaveCount(1);
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("combobox", { name: "Search" })).toBeFocused();
    await page.keyboard.type("invoices");
    await expect(page.getByRole("option").first()).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("combobox", { name: "Search" })).toBeHidden();
  });

  test("finding shows evidence line, reproduction and review workflow", async ({ page }) => {
    await page.goto("/findings");
    await page.getByTestId("finding-row").first().click();
    await expect(page.getByTestId("evidence-line")).toContainText("Test result");
    await expect(page.getByTestId("finding-detail")).toContainText("Steps to reproduce");
    await expect(page.getByTestId("finding-detail")).toContainText("Limitations");
    await page.getByTestId("review-state").selectOption("triaged");
    await page.getByTestId("review-save").click();
    await expect(page.getByText("Marked as Triaged")).toBeVisible();
    await page.reload();
    await page.getByTestId("finding-row").first().click();
    await expect(page.getByTestId("review-state")).toHaveValue("triaged");
  });

  test("schema, policy and graph explorers render real catalog data", async ({ page }) => {
    await page.goto("/schema?table=public.invoices");
    await expect(page.getByTestId("table-detail")).toContainText("Row-level security");
    await expect(page.getByTestId("table-detail")).toContainText("invoices_insert");
    await page.goto("/policies?table=public.comments");
    await expect(page.getByTestId("policy-comments_select_all")).toContainText("Permissive");
    await page.goto("/graph?table=public.invoices");
    await expect(page.getByTestId("graph-canvas")).toBeVisible();
    await page.getByRole("button", { name: "Show table equivalent" }).click();
    await expect(page.getByTestId("graph-table")).toContainText("POLICY_APPLIES_TO");
  });

  test("what-if: unsafe draft rejected; a real fix is verified in the sandbox without regressions", async ({ page }) => {
    await page.goto("/what-if");
    await expect(page.getByTestId("sandbox-banner")).toContainText("SIMULATED IN DISPOSABLE DATABASE — NO LIVE CHANGES");
    await page.getByTestId("draft-sql").fill("DROP TABLE comments");
    await page.getByRole("button", { name: "Check allow-list" }).click();
    await expect(page.getByRole("alert")).toContainText("only allowed for POLICY");
    await page.getByTestId("draft-sql").fill("DROP POLICY comments_select_all ON comments;\nDROP POLICY comments_delete_any ON comments;");
    await page.getByTestId("run-whatif").click();
    await expect(page.getByTestId("whatif-results")).toBeVisible({ timeout: 90_000 });
    await expect(page.getByTestId("wi-resolved")).toContainText("2");
    await expect(page.getByTestId("wi-regressions")).toContainText("0");
    await expect(page.getByTestId("whatif-verdict-text")).toContainText("no authorized behaviour regressed");
    await expect(page.getByTestId("export-patch")).toBeEnabled();
  });

  test("what-if flags a regression and blocks patch export", async ({ page }) => {
    await page.goto("/what-if");
    await page.getByTestId("draft-sql").fill("DROP POLICY invoices_select ON invoices;");
    await page.getByTestId("run-whatif").click();
    await expect(page.getByTestId("whatif-results")).toBeVisible({ timeout: 90_000 });
    await expect(page.getByTestId("wi-regressions")).not.toContainText(/^0$/);
    await expect(page.getByTestId("export-patch")).toBeDisabled();
  });

  test("report export downloads real files", async ({ page }) => {
    await page.goto("/reports");
    for (const fmt of ["html", "sarif"]) {
      const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId(`dl-${fmt}`).first().click()]);
      expect(dl.suggestedFilename()).toMatch(new RegExp(`\\.${fmt}$`));
    }
  });

  test("secure variant is the negative control: zero confirmed violations", async ({ page }) => {
    await runFixture(page, "secure");
    await page.goto("/");
    await expect(page.getByTestId("stat-confirmed")).toContainText("0");
    await page.goto("/history");
    await page.getByLabel("From (older)").selectOption({ index: 1 });
    await page.getByLabel("To (newer)").selectOption({ index: 2 });
    await page.getByTestId("compare-btn").click();
    await expect(page.getByTestId("diff-result")).toBeVisible();
  });
});

test.describe("error and edge states", () => {
  test("invalid spec shows actionable validation errors", async ({ page }) => {
    await page.goto("/studio");
    await expect(page.getByTestId("spec-editor")).not.toHaveValue("");
    await page.getByTestId("spec-editor").fill("version: 1\nproject: x\nactors: []\n");
    await page.getByTestId("validate-spec").click();
    await expect(page.getByTestId("validation-result")).toContainText("Invalid");
  });

  test("raw SQL in a spec is refused", async ({ page }) => {
    await page.goto("/studio");
    await expect(page.getByTestId("spec-editor")).not.toHaveValue("");
    await page.getByTestId("spec-editor").fill("version: 1\nproject: x\nactors: [{id: a, pg_role: r}]\nexpectations: [{id: e, actor: a, operation: SELECT, resource: r, expected: ALLOW, sql: 'DROP TABLE t'}]\n");
    await page.getByTestId("validate-spec").click();
    await expect(page.getByTestId("validation-result")).toContainText("Raw SQL");
  });

  test("connection to a non-allowlisted host is refused without echoing the secret", async ({ page }) => {
    await page.goto("/connections");
    await page.getByLabel("Alias").fill("prod-like");
    await page.getByTestId("dsn-input").fill("postgresql://u:SuperSecret123@10.255.255.1:5432/db");
    await page.getByTestId("test-conn").click();
    await expect(page.getByText("not in SENTINEL_ALLOWED_TARGETS")).toBeVisible();
    await expect(page.locator("body")).not.toContainText("SuperSecret123");
  });

  test("API outage shows an error state, not a blank page", async ({ page }) => {
    await page.route("**/api/v1/test-runs?**", (r) => r.abort());
    await page.goto("/matrix");
    await expect(page.getByRole("alert")).toContainText(/Cannot reach|Request failed/);
  });

  test("unknown route has a not-found state", async ({ page }) => {
    await page.goto("/definitely-not-a-page");
    await expect(page.getByText("Page not found")).toBeVisible();
  });
});
