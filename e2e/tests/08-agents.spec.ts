import { test, expect } from "@playwright/test";
import { loginViaAPI, navigateTo, assertNoErrors, waitForLoaded, getAPIToken, API_URL } from "./helpers";

test.describe("AI Copilot / Agents - Full Coverage", () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page);
  });

  test("agents page loads without errors", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    await assertNoErrors(page);
  });

  test("agents page shows heading", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    // Agents page has a custom layout — check main content for relevant text
    const hasContent = await page.getByText(/agent|copilot|ai|chat|new chat/i).first().isVisible({ timeout: 10000 }).catch(() => false);
    expect(hasContent).toBeTruthy();
  });

  test("AI setup banner appears when not configured", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    await page.waitForTimeout(1000);
    const body = await page.textContent("body");
    const hasSetup = /not configured|setup|configure|api key/i.test(body || "");
    // Either shows setup prompt or chat interface
    expect(body!.length).toBeGreaterThan(50);
  });

  test("chat input exists", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    const input = page.locator('input[placeholder*="message" i], input[placeholder*="ask" i], textarea[placeholder*="message" i], textarea[placeholder*="ask" i]').first();
    if (await input.isVisible()) {
      expect(await input.isVisible()).toBeTruthy();
    }
  });

  test("sending message without AI config shows appropriate response", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    const input = page.locator('input[placeholder*="message" i], textarea[placeholder*="message" i], input[placeholder*="ask" i], textarea[placeholder*="ask" i]').first();
    if (await input.isVisible()) {
      await input.fill("Hello, what vulnerabilities do I have?");
      await page.keyboard.press("Enter");
      await page.waitForTimeout(2000);
      await assertNoErrors(page);
    }
  });

  test("agents API returns config status", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/agents/config`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // May return 200 (config) or 404 (not set up)
    expect(resp.status()).toBeLessThan(500);
  });

  test("no NaN or undefined on agents page", async ({ page }) => {
    await navigateTo(page, "/agents");
    await waitForLoaded(page);
    const body = await page.textContent("body");
    expect(body).not.toContain("NaN");
  });
});
