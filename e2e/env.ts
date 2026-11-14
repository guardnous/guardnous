/**
 * Settings for the end-to-end suite. Credentials come from the environment
 * only; nothing is hard-coded.
 *
 *   E2E_EMAIL      required  e-mail of the test user (registered on first run)
 *   E2E_PASSWORD   required  its password (8+ chars, upper, lower, digit, symbol)
 *   E2E_BASE_URL   optional  frontend address (default http://localhost:7003)
 *   E2E_API_URL    optional  API address      (default http://localhost:7002)
 *   E2E_ORG_NAME   optional  organization created when the user is registered
 */

function required(name: string): string {
  const value = (process.env[name] || "").trim();
  if (!value) {
    throw new Error(
      `${name} is not set. The end-to-end suite needs a test user:\n` +
        `  export E2E_EMAIL=e2e@your-test-domain.example\n` +
        `  export E2E_PASSWORD='<8+ characters with upper, lower, digit and symbol>'\n` +
        `The user is registered automatically on the first run if it does not exist.`,
    );
  }
  return value;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export const BASE_URL = trimSlash(process.env.E2E_BASE_URL || "http://localhost:7003");
export const API_ROOT = trimSlash(process.env.E2E_API_URL || "http://localhost:7002");
export const API_URL = `${API_ROOT}/api/v1`;

export const TEST_USER = {
  get email(): string {
    return required("E2E_EMAIL");
  },
  get password(): string {
    return required("E2E_PASSWORD");
  },
  name: process.env.E2E_NAME || "E2E Tester",
  organization: process.env.E2E_ORG_NAME || "E2E Test Organization",
};
