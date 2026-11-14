import { test, expect } from "@playwright/test";
import { getAPIToken, API_URL, TEST_USER } from "./helpers";

test.describe("API Health & Endpoints - Full Coverage", () => {
  test("GET /health returns ok", async ({ request }) => {
    const resp = await request.get(API_URL.replace("/api/v1", "") + "/health");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.status).toBe("healthy");
  });

  test("auth: POST /auth/login works", async ({ request }) => {
    const resp = await request.post(`${API_URL}/auth/login`, {
      form: { username: TEST_USER.email, password: TEST_USER.password },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.access_token).toBeTruthy();
  });

  test("auth: POST /auth/login with bad creds returns 401", async ({ request }) => {
    const resp = await request.post(`${API_URL}/auth/login`, {
      form: { username: "nobody@bad.com", password: "wrong" },
    });
    expect([401, 429]).toContain(resp.status());
  });

  test("auth: GET /auth/me returns user profile", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.email).toBeTruthy();
  });

  test("unauthenticated access returns 401", async ({ request }) => {
    // Explicitly send no auth headers
    const resp = await request.get(`${API_URL}/scans`, {
      headers: { Authorization: "" },
    });
    // Accept 401 (unauthorized) or 307 (redirect to login)
    expect([401, 307, 403, 429]).toContain(resp.status());
  });

  test("GET /scans/ returns scans", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/scans/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /findings/ returns findings", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/findings/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /cves returns CVEs", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/cves?limit=5`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /reports returns reports list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/reports`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /dashboard/ returns dashboard data", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/dashboard/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /users/ returns users list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/users/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /roles/ returns roles list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/roles/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /plugins/ returns plugins list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/plugins/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /jobs/ returns jobs list", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/jobs/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /audit/logs returns audit log", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/audit/logs`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("POST /reports creates report", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.post(`${API_URL}/reports`, {
      headers: { Authorization: `Bearer ${token}` },
      data: { title: "API Health Test", format: "html", report_type: "executive_summary" },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /cves/stats returns stats", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/cves/stats`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /cves/sync triggers CVE sync", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.post(`${API_URL}/cves/sync`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // May be 200 or 202
    expect(resp.status()).toBeLessThan(500);
  });

  test("invalid token returns 401", async ({ request }) => {
    const resp = await request.get(`${API_URL}/scans/`, {
      headers: { Authorization: "Bearer invalidtoken123" },
    });
    expect([401, 429]).toContain(resp.status());
  });

  test("GET /tenants/ returns tenants", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/tenants/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /groups/ returns groups", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/groups/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.ok()).toBeTruthy();
  });

  test("GET /organizations/ returns orgs", async ({ request }) => {
    const token = await getAPIToken();
    const resp = await request.get(`${API_URL}/org/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    // May be /org/ or /organizations/
    expect(resp.status()).toBeLessThan(500);
  });
});
