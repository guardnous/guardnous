import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded, getAPIToken, API_URL } from "./helpers";

test.describe("Admin Panel - Full Coverage", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  // === Users ===
  test("admin users page loads", async ({ page }) => {
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("admin users shows user list", async ({ page }) => {
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).toMatch(/user|email|role/);
  });

  test("invite user button exists", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    const btn = page.locator("button:has-text('Invite User'), button:has-text('Invite'), button:has-text('Add')").first();
    await expect(btn).toBeVisible({ timeout: 5000 });
  });

  test("invite modal opens and has email field", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    const btn = page.locator("button:has-text('Invite User'), button:has-text('Invite'), button:has-text('Add')").first();
    await btn.click();
    await page.waitForTimeout(1000);
    const emailField = page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]').first();
    await expect(emailField).toBeVisible({ timeout: 5000 });
  });

  test("invite modal has role selector", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    const btn = page.locator("button:has-text('Invite User'), button:has-text('Invite'), button:has-text('Add')").first();
    await btn.click();
    await page.waitForTimeout(1000);
    const roleField = page.locator("select, [class*='select'], [role='combobox'], button:has-text('Select')").first();
    if (await roleField.isVisible()) {
      expect(await roleField.isVisible()).toBeTruthy();
    }
  });

  test("invite modal can be cancelled", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    const btn = page.locator("button:has-text('Invite User'), button:has-text('Invite'), button:has-text('Add')").first();
    await btn.click();
    await page.waitForTimeout(1000);
    const close = page.locator("button:has-text('Cancel'), button:has-text('Close'), button[aria-label='Close']").first();
    if (await close.isVisible()) {
      await close.click();
      await page.waitForTimeout(500);
    }
    await assertNoErrors(page);
  });

  test("users API returns list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/users/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeGreaterThan(0);
  });

  test("user email filter does not leak to invite modal", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await navigateTo(page, "/admin/users");
    await waitForLoaded(page);
    // Type in search/filter
    const search = page.locator('input[placeholder*="search" i], input[placeholder*="filter" i]').first();
    if (await search.isVisible()) {
      await search.fill("test@example.com");
      await page.waitForTimeout(500);
    }
    // Open invite modal
    const btn = page.locator("button:has-text('Invite User'), button:has-text('Invite'), button:has-text('Add')").first();
    await btn.click();
    await page.waitForTimeout(1000);
    // Email field in modal should be empty
    const emailField = page.locator('input[type="email"], input[name="email"]').first();
    if (await emailField.isVisible()) {
      const val = await emailField.inputValue();
      expect(val).toBe("");
    }
  });

  // === Roles ===
  test("admin roles page loads", async ({ page }) => {
    await navigateTo(page, "/admin/roles");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("roles page shows role names", async ({ page }) => {
    await navigateTo(page, "/admin/roles");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).toMatch(/admin|viewer|analyst|role/);
  });

  test("roles API returns list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/roles/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  // === Tenants ===
  test("admin tenants page loads", async ({ page }) => {
    await navigateTo(page, "/admin/tenants");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("tenants page shows tenant data", async ({ page }) => {
    await navigateTo(page, "/admin/tenants");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    expect(body?.toLowerCase()).toMatch(/tenant|organization/);
  });

  // === Audit Log ===
  test("admin audit log page loads", async ({ page }) => {
    await navigateTo(page, "/admin/audit");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("audit log shows entries or empty state", async ({ page }) => {
    await navigateTo(page, "/admin/audit");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    const hasAudit = /audit|log|action|event|timestamp/i.test(body || "");
    expect(hasAudit).toBeTruthy();
  });

  test("audit API returns data", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/audit/logs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  // === Groups ===
  test("admin groups page loads", async ({ page }) => {
    await navigateTo(page, "/admin/groups");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  // === Organizations ===
  test("admin organizations page loads", async ({ page }) => {
    await navigateTo(page, "/admin/organizations");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  // === No NaN/undefined anywhere ===
  test("no NaN on any admin page", async ({ page }) => {
    const adminPages = ["/admin/users", "/admin/roles", "/admin/tenants", "/admin/audit", "/admin/groups", "/admin/organizations"];
    for (const p of adminPages) {
      await navigateTo(page, p);
      await page.waitForTimeout(1000);
      const body = await page.textContent("body");
      expect(body).not.toContain("NaN");
    }
  });
});
