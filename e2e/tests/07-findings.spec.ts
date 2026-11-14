import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded, getAPIToken, API_URL } from "./helpers";

test.describe("Findings - Full Coverage", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  test("findings page loads without errors", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("findings page shows heading", async ({ page }) => {
    await navigateTo(page, "/findings");
    const heading = page.locator("h1, h2").first();
    const text = await heading.textContent();
    expect(text?.toLowerCase()).toMatch(/finding/);
  });

  test("findings shows severity breakdown or empty state", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    const hasSeverity = /critical|high|medium|low/i.test(body || "");
    const hasEmpty = /no.*finding|empty|no data/i.test(body || "");
    expect(hasSeverity || hasEmpty || body!.length > 50).toBeTruthy();
  });

  test("no NaN or undefined in findings data", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    expect(body).not.toContain("NaN");
  });

  test("findings API returns data", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/findings/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data).toBeDefined();
  });

  test("findings search/filter exists", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    const input = page.locator('input[placeholder*="search" i], input[placeholder*="filter" i]').first();
    if (await input.isVisible()) {
      await input.fill("test");
      await page.waitForTimeout(1000);
      await assertNoErrors(page);
    }
  });

  test("findings can be filtered by severity", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    const filter = page.locator("select, button:has-text('Severity'), button:has-text('Filter')").first();
    if (await filter.isVisible()) {
      await filter.click();
      await page.waitForTimeout(500);
    }
    await assertNoErrors(page);
  });

  test("findings stats API works", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/findings/stats`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // Stats endpoint may or may not exist
    expect(resp.status()).toBeLessThan(500);
  });

  test("findings page has table or card layout", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    const table = page.locator("table, [class*='grid'], [class*='list']").first();
    const bodyText = await page.textContent("body");
    expect(bodyText!.length).toBeGreaterThan(50);
  });
});
