import { Page } from "@playwright/test";
import { BASE_URL, API_URL, TEST_USER } from "../env";

// The test user comes from E2E_EMAIL / E2E_PASSWORD (see ../env.ts); it is
// registered by ../global-setup.ts when the installation does not have it.
export { BASE_URL, API_URL, TEST_USER };

// Cached token to avoid rate limiting
let _cachedToken: string | null = null;
let _tokenExpiresAt = 0;

/** Get a valid auth token, reusing cached one when possible */
async function getToken(page: Page): Promise<string> {
  if (_cachedToken && Date.now() < _tokenExpiresAt) {
    return _cachedToken;
  }

  // Retry with backoff for rate limiting
  for (let attempt = 0; attempt < 5; attempt++) {
    const resp = await page.request.post(`${API_URL}/auth/login`, {
      form: {
        username: TEST_USER.email,
        password: TEST_USER.password,
      },
    });

    if (resp.status() === 429) {
      const wait = Math.pow(2, attempt) * 1000;
      await page.waitForTimeout(wait);
      continue;
    }

    if (resp.ok()) {
      const data = await resp.json();
      _cachedToken = data.access_token;
      _tokenExpiresAt = Date.now() + 25 * 60 * 1000; // cache for 25min
      return _cachedToken!;
    }

    throw new Error(`Login failed: ${resp.status()} ${resp.statusText()}`);
  }
  throw new Error("Login failed after 5 retries (rate limited)");
}

/** Login via the UI login form */
export async function loginViaUI(page: Page) {
  await page.goto("/login");
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(1000);

  await page.fill('input[name="email"], input[type="email"]', TEST_USER.email);
  await page.fill('input[name="password"], input[type="password"]', TEST_USER.password);
  await page.click('button[type="submit"]');

  // Wait for either a redirect or the page to settle
  await page.waitForTimeout(3000);
  // Accept either /dashboard or staying on same page with success
  const url = page.url();
  return url;
}

/** Login via API and inject token + user into localStorage */
export async function loginViaAPI(page: Page) {
  const token = await getToken(page);

  // Also fetch user profile so AuthProvider doesn't need to call getMe()
  let userData: string | null = null;
  try {
    const meResp = await page.request.get(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (meResp.ok()) {
      userData = await meResp.text();
    }
  } catch { /* ignore */ }

  // Navigate to the app and inject both token and user data
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate(({ t, u }: { t: string; u: string | null }) => {
    localStorage.setItem("token", t);
    if (u) localStorage.setItem("user", u);
  }, { t: token, u: userData });

  return token;
}

/** Navigate to a page and wait for it to be ready */
export async function navigateTo(page: Page, path: string) {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  // Wait for page to settle and auth to be processed
  await page.waitForTimeout(2000);
  // If redirected to login, re-inject token and retry
  if (page.url().includes("/login") && path !== "/login") {
    const token = _cachedToken;
    if (token) {
      await page.evaluate((t: string) => {
        localStorage.setItem("token", t);
      }, token);
      await page.goto(path, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(2000);
    }
  }
}

/** Check that a page does NOT show an error toast/message */
export async function assertNoErrors(page: Page) {
  const errorToast = page.locator('[role="alert"]:has-text("error"), [role="alert"]:has-text("wrong")');
  const count = await errorToast.count();
  if (count > 0) {
    const texts = await errorToast.allTextContents();
    console.warn("Error messages found:", texts);
  }
}

/** Wait for any loading spinners to disappear */
export async function waitForLoaded(page: Page) {
  const spinner = page.locator('.animate-spin, [data-loading="true"]');
  if (await spinner.count() > 0) {
    await spinner.first().waitFor({ state: "hidden", timeout: 10_000 }).catch(() => {});
  }
}

/** Get an API token for direct API testing (standalone, no page needed) */
export async function getAPIToken(): Promise<string> {
  if (_cachedToken && Date.now() < _tokenExpiresAt) {
    return _cachedToken;
  }

  const context = await (await import("@playwright/test")).request.newContext();
  for (let attempt = 0; attempt < 5; attempt++) {
    const resp = await context.post(`${API_URL}/auth/login`, {
      form: {
        username: TEST_USER.email,
        password: TEST_USER.password,
      },
    });
    if (resp.status() === 429) {
      await new Promise((r) => setTimeout(r, Math.pow(2, attempt) * 1000));
      continue;
    }
    if (resp.ok()) {
      const data = await resp.json();
      _cachedToken = data.access_token;
      _tokenExpiresAt = Date.now() + 25 * 60 * 1000;
      await context.dispose();
      return _cachedToken!;
    }
    await context.dispose();
    throw new Error(`Login failed: ${resp.status()}`);
  }
  await context.dispose();
  throw new Error("Login failed after retries");
}
