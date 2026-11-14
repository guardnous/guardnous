import { defineConfig } from "@playwright/test";

// Requires E2E_EMAIL and E2E_PASSWORD; see env.ts. global-setup.ts registers
// the user on the first run against a fresh installation.
export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  workers: 1,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: (process.env.E2E_BASE_URL || "http://localhost:7003").replace(/\/+$/, ""),
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium", headless: true },
    },
  ],
});
