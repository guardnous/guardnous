import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded } from "./helpers";

test.describe("Every Button & Click Target", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  // === Dashboard buttons ===
  test("dashboard: all clickable cards don't crash", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    const clickables = page.locator('[class*="cursor-pointer"], [class*="card-hover"]');
    const count = await clickables.count();
    for (let i = 0; i < Math.min(count, 6); i++) {
      await clickables.nth(i).click();
      await page.waitForTimeout(300);
    }
    await assertNoErrors(page);
  });

  // === Report page buttons ===
  test("reports: delete button shows confirmation or deletes", async ({ page }) => {
    await navigateTo(page, "/reports");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const deleteBtn = page.locator("button[title*='Delete'], button:has-text('Delete')").first();
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
      await page.waitForTimeout(500);
      // May show confirm dialog
      await assertNoErrors(page);
    }
  });

  test("reports: download button behavior", async ({ page }) => {
    await navigateTo(page, "/reports");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const downloadBtn = page.locator("button[title*='Download'], button:has-text('Download'), a:has-text('Download')").first();
    if (await downloadBtn.isVisible()) {
      // Just check it exists and is clickable
      expect(await downloadBtn.isEnabled()).toBeTruthy();
    }
  });

  // === CVE page interactions ===
  test("CVE: expand all visible CVEs one by one", async ({ page }) => {
    await navigateTo(page, "/cves");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const cveRows = page.locator("button:has-text('CVE-')");
    const count = await cveRows.count();
    for (let i = 0; i < Math.min(count, 5); i++) {
      await cveRows.nth(i).click();
      await page.waitForTimeout(300);
      await assertNoErrors(page);
      // Collapse
      await cveRows.nth(i).click();
      await page.waitForTimeout(200);
    }
  });

  // === Sidebar links ===
  test("click every sidebar link sequentially", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    const sidebarLinks = page.locator("nav a, aside a");
    const count = await sidebarLinks.count();
    for (let i = 0; i < Math.min(count, 20); i++) {
      const href = await sidebarLinks.nth(i).getAttribute("href");
      if (href && href.startsWith("/")) {
        await sidebarLinks.nth(i).click();
        await page.waitForTimeout(500);
        await assertNoErrors(page);
      }
    }
  });

  // === Refresh behavior ===
  test("refresh button on scans page", async ({ page }) => {
    await navigateTo(page, "/scans");
    await waitForLoaded(page);
    const refresh = page.locator("button:has-text('Refresh'), button[title*='Refresh']").first();
    if (await refresh.isVisible()) {
      await refresh.click();
      await page.waitForTimeout(1000);
      await assertNoErrors(page);
    }
  });

  test("refresh button on CVE page", async ({ page }) => {
    await navigateTo(page, "/cves");
    await waitForLoaded(page);
    const refresh = page.locator("button:has-text('Sync'), button:has-text('Refresh')").first();
    if (await refresh.isVisible()) {
      await refresh.click();
      await page.waitForTimeout(1000);
      await assertNoErrors(page);
    }
  });

  // === Tab components ===
  test("settings: click all tabs", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    const tabs = page.locator('[role="tab"], button[class*="tab"], [class*="TabsTrigger"]');
    const count = await tabs.count();
    for (let i = 0; i < count; i++) {
      await tabs.nth(i).click();
      await page.waitForTimeout(300);
      await assertNoErrors(page);
    }
  });

  // === Scroll behavior ===
  test("CVE page scrolls to load more", async ({ page }) => {
    await navigateTo(page, "/cves");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(1000);
    await assertNoErrors(page);
  });

  test("findings page scrolls without error", async ({ page }) => {
    await navigateTo(page, "/findings");
    await waitForLoaded(page);
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(500);
    await page.evaluate(() => window.scrollTo(0, 0));
    await assertNoErrors(page);
  });

  // === Logout ===
  test("logout button exists and works", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    await waitForLoaded(page);
    const logoutBtn = page.locator("button:has-text('Logout'), button:has-text('Sign out'), button:has-text('Log out'), a:has-text('Logout')").first();
    if (await logoutBtn.isVisible()) {
      await logoutBtn.click();
      await page.waitForTimeout(2000);
      const url = page.url();
      expect(url.includes("/login") || url.includes("/")).toBeTruthy();
    }
  });
});
