import { test, expect } from "@playwright/test";

test("category selected before login is retained on the application form", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByRole("button", { name: "분야로 바로 신청", exact: true })
    .click();
  await page
    .locator(".category-grid a")
    .filter({ hasText: "환경·청소" })
    .click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("아이디", { exact: true }).fill("citizen_e2e");
  await page
    .getByLabel("비밀번호", { exact: true })
    .fill("E2E-only-password-123");
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(page.getByLabel("민원 분야")).toHaveValue("환경·청소");
  expect(new URL(page.url()).searchParams.get("category")).toBe("환경·청소");
});

test("home shortcuts lead staff and administrators to their own workspace", async ({
  page,
}) => {
  for (const account of [
    { username: "staff_e2e", path: "/work", heading: "민원 업무" },
    { username: "admin_e2e", path: "/admin", heading: "계정 관리" },
  ]) {
    await page.goto("/login");
    await page.getByLabel("아이디", { exact: true }).fill(account.username);
    await page
      .getByLabel("비밀번호", { exact: true })
      .fill("E2E-only-password-123");
    await page.getByRole("button", { name: "로그인", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "로그아웃", exact: true }),
    ).toBeVisible();
    await page.goto("/");
    await expect(page.locator(".quick-links > a").first()).toHaveAttribute(
      "href",
      account.path,
    );
    await expect(page.locator(".category-grid")).toHaveCount(0);
    await expect(page.locator(".service-finder")).toHaveCount(0);
    await expect(page.locator(".guide-intro a")).toHaveAttribute(
      "href",
      account.path,
    );
    await page.locator(".quick-links > a").first().click();
    await expect(
      page.getByRole("heading", { name: account.heading, exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "로그아웃", exact: true }).click();
  }
});

test("narrow home keeps service explanations and categories usable", async ({
  page,
}) => {
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    const shortcut = page.locator(".quick-links > a").first();
    await expect(shortcut.locator("small")).toBeVisible();
    await expect(shortcut).toHaveAttribute("href", "/petitions/new");
    expect(
      await shortcut.evaluate((el) => el.getBoundingClientRect().height),
    ).toBeGreaterThanOrEqual(44);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page
      .getByRole("button", { name: "분야로 바로 신청", exact: true })
      .click();
    const category = page.locator(".category-grid a").first();
    await expect(category).toContainText("도로·교통");
    await category.click();
    await expect(page).toHaveURL(/\/login$/);
  }
});

test("admin search and server role filters combine and errors hide stale counts", async ({
  page,
}) => {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill("admin_e2e");
  await page
    .getByLabel("비밀번호", { exact: true })
    .fill("E2E-only-password-123");
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "로그아웃", exact: true }),
  ).toBeVisible();
  await page.goto("/admin");
  const summary = page.getByRole("group", { name: "전체 계정 권한 필터" });
  await expect(summary).toBeVisible();
  await expect(page.getByText(/검색어 기준 전체 \d+개/)).toBeVisible();
  await summary.getByRole("button", { name: /^담당자/ }).click();
  await expect(
    summary.getByRole("button", { name: /^담당자/ }),
  ).toHaveAttribute("aria-pressed", "true");
  const roles = await page
    .locator(".admin-table tbody .role-tag")
    .allTextContents();
  expect(roles.length).toBeGreaterThan(0);
  expect(roles.every((role) => role === "담당자")).toBe(true);
  await page.getByLabel("계정 검색", { exact: true }).fill("admin_e2e");
  await page.getByRole("button", { name: "검색", exact: true }).click();
  await expect(page.getByText(/조건에 맞는 계정이 없습니다/)).toBeVisible();
  await expect(
    summary.getByRole("button", { name: /^담당자/ }),
  ).toHaveAttribute("aria-pressed", "true");
  await summary.getByRole("button", { name: /^전체/ }).click();
  await expect(page.locator(".admin-table tbody tr")).toHaveCount(1);
  await expect(page.locator(".admin-table tbody")).toContainText("admin_e2e");
  await summary.getByRole("button", { name: /^담당자/ }).click();
  await expect(page.getByText(/조건에 맞는 계정이 없습니다/)).toBeVisible();
  await page.getByRole("button", { name: "초기화", exact: true }).click();
  await expect(page.getByLabel("계정 검색", { exact: true })).toHaveValue("");
  await expect(page.locator(".admin-table tbody tr")).not.toHaveCount(0);
  await page.route("**/api/v1/admin/users?*", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        ok: false,
        error: { code: "SERVER_ERROR", message: "테스트 서버 일시 오류" },
      }),
    }),
  );
  await page.getByRole("button", { name: "새로고침", exact: true }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(summary).toHaveCount(0);
  await page.unroute("**/api/v1/admin/users?*");
  await page.getByRole("button", { name: "다시 시도", exact: true }).click();
  await expect(summary).toBeVisible();
});
