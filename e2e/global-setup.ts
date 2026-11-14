import { request, APIRequestContext, APIResponse } from "@playwright/test";
import { API_ROOT, API_URL, TEST_USER } from "./env";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function login(api: APIRequestContext, email: string, password: string): Promise<APIResponse> {
  let resp = await api.post(`${API_URL}/auth/login`, { form: { username: email, password } });
  for (let attempt = 0; resp.status() === 429 && attempt < 4; attempt++) {
    await sleep(Math.pow(2, attempt) * 1000);
    resp = await api.post(`${API_URL}/auth/login`, { form: { username: email, password } });
  }
  return resp;
}

async function describe(resp: APIResponse): Promise<string> {
  let body = "";
  try {
    body = (await resp.text()).slice(0, 300);
  } catch {
    /* no body */
  }
  return `HTTP ${resp.status()} ${body}`.trim();
}

/**
 * Runs once before the suite: makes sure the test user from E2E_EMAIL /
 * E2E_PASSWORD can log in, registering it (with its own organization) when
 * the installation does not have it yet.
 */
export default async function globalSetup(): Promise<void> {
  // Reading these throws a clear error when a variable is missing.
  const email = TEST_USER.email;
  const password = TEST_USER.password;

  const api = await request.newContext();
  try {
    let health: APIResponse;
    try {
      health = await api.get(`${API_ROOT}/api/health`);
    } catch (err) {
      throw new Error(`The API at ${API_ROOT} is not reachable (${String(err)}). Start GuardNous first.`);
    }
    if (!health.ok()) {
      throw new Error(`The API at ${API_ROOT} is not healthy: ${await describe(health)}`);
    }

    const first = await login(api, email, password);
    if (first.ok()) return;

    const registration = await api.post(`${API_URL}/auth/register`, {
      data: {
        email,
        password,
        full_name: TEST_USER.name,
        organization_name: TEST_USER.organization,
      },
    });
    if (!registration.ok()) {
      throw new Error(
        `Could not log in as ${email} (${await describe(first)}) and could not register it ` +
          `(${await describe(registration)}).\n` +
          `If the user exists, E2E_PASSWORD is wrong. If the e-mail domain already belongs to an ` +
          `organization, use an address on a domain that is not registered yet.`,
      );
    }

    const second = await login(api, email, password);
    if (!second.ok()) {
      throw new Error(`Registered ${email} but login still fails: ${await describe(second)}`);
    }
  } finally {
    await api.dispose();
  }
}
