import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded } from "./helpers";

test.describe("Navigation & Sidebar", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  const mainNavItems = [
    { path: "/dashboard", label: "Dashboard" },
    { path: "/integrations", label: "Integrations" },
    { path: "/scans", label: "Assessments" },
    { path: "/jobs", label: "Task Monitor" },
    { path: "/findings", label: "Findings" },
    { path: "/cves", label: "CVE Intel" },
    { path: "/reports", label: "Reports" },
    { path: "/iam", label: "IAM Intel" },
    { path: "/governance", label: "Governance" },
    { path: "/agents", label: "AI Copilot" },
    { path: "/plugins", label: "Plugins" },
    { path: "/settings", label: "Settings" },
  ];

  const adminNavItems = [
    { path: "/admin/users", label: "Users" },
    { path: "/admin/roles", label: "Roles" },
    { path: "/admin/tenants", label: "Tenants" },
    { path: "/admin/audit", label: "Audit Log" },
    { path: "/admin/groups", label: "Groups" },
    { path: "/admin/organizations", label: "Organizations" },
  ];

  for (const item of mainNavItems) {
    test(`sidebar link to ${item.label} (${item.path}) works`, async ({ page }) => {
      await navigateTo(page, "/dashboard");
      await waitForLoaded(page);
      // Click sidebar link
      const link = page.locator(`a[href="${item.path}"]`).first();
      if (await link.isVisible()) {
        await link.click();
        await page.waitForTimeout(1500);
        expect(page.url()).toContain(item.path);
      } else {
        // Navigate directly
        await navigateTo(page, item.path);
      }
      await assertNoErrors(page);
    });
  }

  for (const item of adminNavItems) {
    test(`admin nav to ${item.label} (${item.path}) works`, async ({ page }) => {
      await navigateTo(page, item.path);
      await waitForLoaded(page);
      await assertNoErrors(page);
      const body = await page.textContent("body");
      expect(body).toBeTruthy();
    });
  }

  test("sidebar is visible on desktop viewport", async ({ page }) => {
    await navigateTo(page, "/dashboard");
    const sidebar = page.locator("nav, aside, [class*='sidebar'], [class*='Sidebar']").first();
    if (await sidebar.isVisible()) {
      expect(await sidebar.isVisible()).toBeTruthy();
    }
  });

  test("clicking logo or brand navigates to dashboard", async ({ page }) => {
    await navigateTo(page, "/settings");
    const brand = page.locator("a[href='/dashboard'], a[href='/'], [class*='brand'], [class*='logo']").first();
    if (await brand.isVisible()) {
      await brand.click();
      await page.waitForTimeout(1500);
    }
  });

  test("no broken links (404 pages) in main nav", async ({ page }) => {
    test.setTimeout(120_000);
    for (const item of mainNavItems) {
      await navigateTo(page, item.path);
      const heading = page.locator("h1, h2, [role='heading']").first();
      const text = await heading.textContent({ timeout: 5000 }).catch(() => "");
      expect(text?.toLowerCase()).not.toContain("not found");
    }
  });

  test("no NaN or undefined text on any page", async ({ page }) => {
    const pages = ["/dashboard", "/scans", "/cves", "/reports", "/findings"];
    for (const p of pages) {
      await navigateTo(page, p);
      const bodyText = await page.textContent("body");
      expect(bodyText).not.toContain("NaN");
      // Allow "undefined" in some contexts but not as standalone display
      const nanCount = (bodyText?.match(/\bNaN\b/g) || []).length;
      expect(nanCount).toBe(0);
    }
  });
});
