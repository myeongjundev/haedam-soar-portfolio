import { defineConfig } from "@playwright/test";
const mysql = process.env.HAEDAM_E2E_MYSQL === "1";
export default defineConfig({
  testDir: "./tests",
  testIgnore: mysql ? [] : ["**/mysql-persistence.spec.js"],
  fullyParallel: false,
  workers: 1,
  timeout: 45000,
  use: {
    baseURL: "http://127.0.0.1:5005",
    browserName: "chromium",
    channel: process.env.PW_CHANNEL || "msedge",
    screenshot: "only-on-failure",
    trace: mysql ? "off" : "retain-on-failure",
  },
  webServer: mysql
    ? undefined
    : {
        command: "node scripts/e2e-server.mjs",
        url: "http://127.0.0.1:5005/api/v1/health",
        timeout: 60000,
        reuseExistingServer: false,
      },
  reporter: [["list"]],
});
