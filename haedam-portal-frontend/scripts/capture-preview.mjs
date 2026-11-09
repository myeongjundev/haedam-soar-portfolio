import { chromium } from "@playwright/test";
import fs from "node:fs/promises";

const browser = await chromium.launch({
  channel: process.env.PW_CHANNEL || "msedge",
});
try {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
  });
  const response = await page.goto("http://127.0.0.1:5000/");
  if (response.status() !== 200)
    throw new Error("Local preview is unavailable");
  await page.getByRole("heading", { level: 1 }).waitFor();
  await fs.mkdir(".local", { recursive: true });
  await page.screenshot({ path: ".local/haedam-home-preview.png" });
  console.log("Saved .local/haedam-home-preview.png");
} finally {
  await browser.close();
}
