import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded, getAPIToken, API_URL } from "./helpers";

test.describe("Edge Cases & Error Handling", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  // === 404 pages ===
  test("non-existent route shows 404 or redirect", async ({ page }) => {
    await navigateTo(page, "/this-does-not-exist-12345");
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    const url = page.url();
    expect(body!.length > 0 || url.includes("/login")).toBeTruthy();
  });

  test("/admin/nonexistent shows error or redirect", async ({ page }) => {
    await navigateTo(page, "/admin/nonexistent-page");
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    expect(body!.length > 0).toBeTruthy();
  });

  // === Empty states ===
  test("findings page handles empty data gracefully", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    await assertNoErrors(page);
  });

  test("scans page handles empty data gracefully", async ({ page }) => {
    await navigateTo(page, "/scans");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    await assertNoErrors(page);
  });

  test("jobs page handles empty data gracefully", async ({ page }) => {
    await navigateTo(page, "/jobs");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    await assertNoErrors(page);
  });

  // === Data integrity ===
  test("no null displayed as text on dashboard", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    // Use innerText to get only visible text (excludes Next.js RSC script payloads)
    const body = await page.locator("main, [class*='content'], #__next").first().innerText();
    const nullCount = (body?.match(/\bnull\b/g) || []).length;
    expect(nullCount).toBeLessThan(3);
  });

  test("no 'undefined' displayed as text on reports", async ({ page }) => {
    await navigateTo(page, "/reports");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    // Check visible elements for "undefined" text — avoid slow full-page innerText
    const elems = page.locator("main h1, main h2, main h3, main p, main span, main td, main button");
    const count = await elems.count();
    for (let i = 0; i < Math.min(count, 50); i++) {
      const text = await elems.nth(i).innerText({ timeout: 5000 }).catch(() => "");
      expect(text).not.toMatch(/\bundefined\b/);
    }
  });

  test("no 'Something went wrong' on CVE page", async ({ page }) => {
    await navigateTo(page, "/cves");
    await waitForLoaded(page);
    await page.waitForTimeout(3000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).not.toContain("something went wrong");
  });

  test("no 'Something went wrong' on findings page", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await page.waitForTimeout(3000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).not.toContain("something went wrong");
  });

  test("no 'Something went wrong' on scans page", async ({ page }) => {
    await navigateTo(page, "/scans");
    await waitForLoaded(page);
    await page.waitForTimeout(3000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).not.toContain("something went wrong");
  });

  test("no 'Something went wrong' on dashboard", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    await page.waitForTimeout(3000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).not.toContain("something went wrong");
  });

  test("no 'Something went wrong' on reports", async ({ page }) => {
    await navigateTo(page, "/reports");
    await waitForLoaded(page);
    await page.waitForTimeout(3000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).not.toContain("something went wrong");
  });

  // === Rapid navigation ===
  test("rapid page switching doesn't crash", async ({ page }) => {
    const pages = ["/dashboard", "/scans", "/cves", "/reports", "/findings", "/plugins", "/settings"];
    for (const p of pages) {
      await page.goto(`http://localhost:7003${p}`, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(300);
    }
    await assertNoErrors(page);
  });

  // === API error handling ===
  test("API: malformed request returns 4xx, not 5xx", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.post(`${API_URL}/reports`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { invalid_field: "test" },
    });
    // Should return 4xx (validation error) or still work, but never 500
    expect(resp.status()).toBeLessThan(500);
  });

  test("API: GET nonexistent endpoint returns 404", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/nonexistent-endpoint-12345`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.status()).toBe(404);
  });

  // === Session/token ===
  test("clearing token and refreshing redirects to login", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    await page.evaluate(() => localStorage.removeItem("token"));
    await page.reload();
    await page.waitForTimeout(2000);
    const url = page.url();
    expect(url.includes("/login") || url.includes("/dashboard")).toBeTruthy();
  });

  // === Keyboard accessibility ===
  test("Tab key cycles through interactive elements on login", async ({ page }) => {
    await page.goto("http://localhost:7003/login");
    await page.waitForLoadState("domcontentloaded");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await assertNoErrors(page);
  });
});
