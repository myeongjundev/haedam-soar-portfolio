import { test, expect } from "@playwright/test";

const password = "E2E-only-password-123";
const unlockLabel = "오탐 해제(비밀번호 유지)";
const confirmLabel = "오탐 확인 후 해제";
let serial = 0;

async function setup(page, locked = true) {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill("admin_e2e");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "계정 관리", exact: true }),
  ).toBeVisible();
  const csrf = (await (await page.request.get("/api/v1/auth/me")).json()).data
    .csrf_token;
  const response = await page.request.post("/api/v1/admin/users", {
    headers: { "X-CSRF-Token": csrf },
    data: {
      username: `unlock_${Date.now()}_${serial++}`,
      display_name: "오탐검증계정",
      role: "citizen",
      password,
    },
  });
  expect(response.status()).toBe(201);
  const user = (await response.json()).data;
  if (locked) await lock(page, user, csrf);
  await page.goto(`/admin?q=${user.username}`);
  const row = page.locator(".admin-table tbody tr");
  await expect(row).toHaveCount(1);
  return { user, row, csrf };
}

async function lock(page, user, csrf) {
  const response = await page.request.patch(`/api/v1/admin/users/${user.id}`, {
    headers: { "X-CSRF-Token": csrf },
    data: { locked: true },
  });
  expect(response.status()).toBe(200);
}

test("false-positive unlock keeps the password, revokes old sessions and refreshes server state", async ({
  page,
  browser,
}) => {
  const { user, row, csrf } = await setup(page, false);
  await expect(
    row.getByRole("button", { name: unlockLabel, exact: true }),
  ).toHaveCount(0);
  const citizen = await browser.newContext({
    baseURL: test.info().project.use.baseURL,
  });
  try {
    const token = (await (await citizen.request.get("/api/v1/auth/me")).json())
      .data.csrf_token;
    const login = await citizen.request.post("/api/v1/auth/login", {
      headers: { "X-CSRF-Token": token },
      data: { username: user.username, password },
    });
    expect(login.status()).toBe(200);
    await lock(page, user, csrf);
    expect((await citizen.request.get("/api/v1/petitions")).status()).toBe(401);
    await page.reload();
    await row.getByRole("button", { name: unlockLabel, exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText(user.username);
    await expect(dialog.locator('input[type="password"]')).toHaveCount(0);
    await expect(dialog.getByRole("definition")).toHaveText([
      "잠김",
      "잠금 해제 · 비밀번호 유지",
    ]);
    await page.screenshot({
      path: ".local/s4-unlock-1028/desktop-confirm.png",
    });
    const sent = page.waitForRequest((request) =>
      request.url().endsWith(`/users/${user.id}/unlock`),
    );
    await dialog
      .getByRole("button", { name: confirmLabel, exact: true })
      .click();
    const request = await sent;
    expect(request.method()).toBe("POST");
    expect(request.postDataJSON()).toEqual({ reason_code: "false_positive" });
    expect(request.headers()["x-csrf-token"]).toBeTruthy();
    await expect(dialog).not.toBeVisible();
    await expect(row).toContainText("이용 중");
    await expect(
      row.getByRole("button", { name: unlockLabel, exact: true }),
    ).toHaveCount(0);
    await expect(page.getByRole("status")).toContainText(
      "기존 비밀번호로 새로 로그인",
    );
    await expect(page.locator(".admin-summary-scope")).toContainText(
      "잠김 0개",
    );
    // Unlock never restores the session that existed before the lock.
    expect((await citizen.request.get("/api/v1/petitions")).status()).toBe(401);
    const loginPage = await citizen.newPage();
    await loginPage.goto("/login");
    await loginPage.getByLabel("아이디", { exact: true }).fill(user.username);
    await loginPage.getByLabel("비밀번호", { exact: true }).fill(password);
    await loginPage
      .getByRole("button", { name: "로그인", exact: true })
      .click();
    await expect(
      loginPage.getByRole("button", { name: "로그아웃", exact: true }),
    ).toBeVisible();
    expect(
      (await (await citizen.request.get("/api/v1/auth/me")).json()).data.user
        .id,
    ).toBe(user.id);
  } finally {
    await citizen.close();
  }
});

test("cancel and keyboard dismissal send no unlock request; narrow dialog stays in view", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const { row } = await setup(page);
  let calls = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/unlock")) calls++;
  });
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("button", { name: "닫기", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    dialog.getByRole("button", { name: "취소", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    dialog.getByRole("button", { name: confirmLabel, exact: true }),
  ).toBeFocused();
  const bounds = await dialog.boundingBox();
  expect(bounds.x).toBeGreaterThanOrEqual(0);
  expect(bounds.x + bounds.width).toBeLessThanOrEqual(390);
  expect(bounds.y).toBeGreaterThanOrEqual(0);
  expect(bounds.y + bounds.height).toBeLessThanOrEqual(844);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: ".local/s4-unlock-1028/mobile-confirm.png",
    fullPage: false,
  });
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  await dialog.getByRole("button", { name: "취소", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  expect(calls).toBe(0);
  await expect(row).toContainText("잠김");
});

test("unlock refreshes locked-only counts and clamps the last filtered page", async ({
  page,
}) => {
  const { user, csrf } = await setup(page);
  const created = await page.request.post("/api/v1/admin/users", {
    headers: { "X-CSRF-Token": csrf },
    data: {
      username: `${user.username}_b`,
      display_name: "두번째오탐검증계정",
      role: "citizen",
      password,
    },
  });
  expect(created.status()).toBe(201);
  await lock(page, (await created.json()).data, csrf);
  await page.goto(`/admin?q=${user.username}&locked=true&page_size=1&page=2`);
  const row = page.locator(".admin-table tbody tr");
  await expect(row).toHaveCount(1);
  await expect(page.locator(".admin-summary-scope")).toContainText("잠김 2개");
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: confirmLabel, exact: true })
    .click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(row).toHaveCount(1);
  await expect(page.locator(".admin-summary-scope")).toContainText("잠김 1개");
  await expect
    .poll(() => new URL(page.url()).searchParams.has("page"))
    .toBe(false);
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: confirmLabel, exact: true })
    .click();
  await expect(row).toHaveCount(0);
  await expect(page.getByText(/조건에 맞는 계정이 없습니다/)).toBeVisible();
  await expect(page.locator(".admin-summary-scope")).toContainText("잠김 0개");
  expect(new URL(page.url()).searchParams.get("locked")).toBe("true");
});

test("rejection, network failure and malformed success never show an unlocked account", async ({
  page,
}) => {
  const { user, row } = await setup(page);
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  const dialog = page.getByRole("dialog");
  for (const mode of [403, 409, 503, "network", "still-locked", "wrong-user"]) {
    let calls = 0;
    await page.route(
      `**/api/v1/admin/users/${user.id}/unlock`,
      async (route) => {
        calls++;
        if (mode === "network") return route.abort();
        if (typeof mode === "number")
          return route.fulfill({
            status: mode,
            json: {
              success: false,
              error: {
                code: "TEST_REJECTION",
                message: "해제 요청이 거부되었습니다.",
              },
            },
          });
        return route.fulfill({
          json: {
            success: true,
            data: {
              ...user,
              id: mode === "wrong-user" ? user.id + 1 : user.id,
              locked: mode === "still-locked",
            },
          },
        });
      },
    );
    await dialog
      .getByRole("button", { name: confirmLabel, exact: true })
      .click();
    await expect(dialog.getByRole("alert")).toBeVisible();
    await expect(dialog).toBeVisible();
    await expect(row).toContainText("잠김");
    await expect(page.getByRole("status")).toHaveCount(0);
    expect(calls).toBe(1);
    await page.unroute(`**/api/v1/admin/users/${user.id}/unlock`);
  }
  await dialog.getByRole("button", { name: "취소", exact: true }).click();
  await page.getByRole("button", { name: "새로고침", exact: true }).click();
  await expect(row).toContainText("잠김");
});

test("pending unlock disables confirmation and prevents duplicate form submission", async ({
  page,
}) => {
  const { user, row } = await setup(page);
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let calls = 0;
  await page.route(`**/api/v1/admin/users/${user.id}/unlock`, async (route) => {
    calls++;
    await gate;
    await route.continue();
  });
  await row.getByRole("button", { name: unlockLabel, exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: confirmLabel, exact: true }).click();
  try {
    await expect(
      dialog.getByRole("button", { name: "저장 중…", exact: true }),
    ).toBeDisabled();
    await expect(
      dialog.getByRole("button", { name: "취소", exact: true }),
    ).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await dialog.locator("form").evaluate((form) => form.requestSubmit());
    expect(calls).toBe(1);
  } finally {
    release();
  }
  await expect(dialog).not.toBeVisible();
  await expect(row).toContainText("이용 중");
  expect(calls).toBe(1);
});
