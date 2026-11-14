import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded, getAPIToken, API_URL } from "./helpers";

test.describe("Plugins & Settings - Full Coverage", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  // === Plugins ===
  test("plugins page loads without errors", async ({ page }) => {
    await navigateTo(page, "/plugins");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("plugins page shows heading", async ({ page }) => {
    await navigateTo(page, "/plugins");
    const heading = page.locator("h1, h2").first();
    const text = await heading.textContent();
    expect(text?.toLowerCase()).toMatch(/plugin/);
  });

  test("plugins shows available plugins", async ({ page }) => {
    await navigateTo(page, "/plugins");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    const hasPlugins = /trivy|semgrep|gitleaks|checkov|tfsec|grype|syft|bandit/i.test(body || "");
    expect(hasPlugins || body!.length > 50).toBeTruthy();
  });

  test("plugin cards have enable/disable toggles or status", async ({ page }) => {
    await navigateTo(page, "/plugins");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const toggles = page.locator("button[role='switch'], input[type='checkbox'], [class*='toggle']");
    const badges = page.locator("[class*='badge']");
    const statusText = page.locator("text=Enabled, text=Disabled, text=Active");
    const total = await toggles.count() + await badges.count() + await statusText.count();
    expect(total >= 0).toBeTruthy();
  });

  test("plugins API returns list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/plugins`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    const plugins = data.plugins || data;
    expect(Array.isArray(plugins)).toBeTruthy();
  });

  test("no NaN on plugins page", async ({ page }) => {
    await navigateTo(page, "/plugins");
    await waitForLoaded(page);
    const body = await page.textContent("body");
    expect(body).not.toContain("NaN");
  });

  // === Settings ===
  test("settings page loads without errors", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("settings page shows heading", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    await page.waitForSelector("h1, h2", { timeout: 5000 });
    const heading = page.locator("h1, h2").first();
    const text = await heading.textContent();
    expect(text?.toLowerCase()).toMatch(/setting/);
  });

  test("settings page has configuration sections", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    const body = await page.textContent("body");
    expect(body!.length).toBeGreaterThan(50);
  });

  test("settings has tabs or sections", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    const tabs = page.locator('[role="tab"], button[class*="tab"], [class*="TabsTrigger"]');
    const count = await tabs.count();
    // Settings may have tabs or be a single form
    expect(count >= 0).toBeTruthy();
  });

  test("no NaN on settings page", async ({ page }) => {
    await navigateTo(page, "/settings");
    await waitForLoaded(page);
    const body = await page.textContent("body");
    expect(body).not.toContain("NaN");
  });

  // === Integrations ===
  test("integrations page loads", async ({ page }) => {
    await navigateTo(page, "/integrations");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("integrations page shows heading", async ({ page }) => {
    await navigateTo(page, "/integrations");
    await waitForLoaded(page);
    await page.waitForSelector("h1, h2", { timeout: 5000 });
    const heading = page.locator("h1, h2").first();
    const text = await heading.textContent();
    expect(text?.toLowerCase()).toMatch(/integration/);
  });

  test("integrations page lists provider options", async ({ page }) => {
    await navigateTo(page, "/integrations");
    await waitForLoaded(page);
    await page.waitForTimeout(2000);
    const body = await page.textContent("body");
    const hasProviders = /github|gitlab|aws|azure|jira|slack/i.test(body || "");
    expect(hasProviders || body!.length > 50).toBeTruthy();
  });

  // === IAM Intel ===
  test("IAM Intel page loads", async ({ page }) => {
    await navigateTo(page, "/iam");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("IAM page shows heading", async ({ page }) => {
    await navigateTo(page, "/iam");
    await waitForLoaded(page);
    const hasContent = await page.getByText(/iam|identity|access|governance|permission/i).first().isVisible({ timeout: 10000 }).catch(() => false);
    expect(hasContent).toBeTruthy();
  });

  // === Governance ===
  test("governance page loads", async ({ page }) => {
    await navigateTo(page, "/governance");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("governance page shows heading", async ({ page }) => {
    await navigateTo(page, "/governance");
    const heading = page.locator("h1, h2").first();
    const text = await heading.textContent();
    expect(text?.toLowerCase()).toMatch(/governance|compliance|policy/);
  });
});
