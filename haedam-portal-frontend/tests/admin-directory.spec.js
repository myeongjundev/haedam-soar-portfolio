import { test, expect } from "@playwright/test";

const password = "E2E-only-password-123";
const summary = (page) =>
  page.getByRole("group", { name: "전체 계정 권한 필터" });
const rows = (page) => page.locator(".admin-table tbody tr");
async function login(page) {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill("admin_e2e");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "계정 관리", exact: true }),
  ).toBeVisible();
}
async function seed(page, amount, allStaff = false) {
  const prefix = `directory_${Date.now()}_`;
  const csrf = (await (await page.request.get("/api/v1/auth/me")).json()).data
    .csrf_token;
  const users = [];
  for (let i = 0; i < amount; i += 1) {
    const response = await page.request.post("/api/v1/admin/users", {
      headers: { "X-CSRF-Token": csrf },
      data: {
        username: prefix + String(i).padStart(2, "0"),
        display_name: `가상계정${i}`,
        password,
        role: allStaff ? "staff" : ["citizen", "staff", "admin"][i % 3],
      },
    });
    expect(response.status()).toBe(201);
    const user = (await response.json()).data;
    if (!allStaff && i % 4 === 0) {
      const lock = await page.request.patch(`/api/v1/admin/users/${user.id}`, {
        headers: { "X-CSRF-Token": csrf },
        data: { locked: true },
      });
      expect(lock.status()).toBe(200);
      user.locked = true;
    }
    users.push(user);
  }
  return { prefix, users };
}
async function expectTotal(page, total, shown) {
  await expect(page.locator(".admin-list .list-meta")).toContainText(
    `조건에 맞는 계정 ${total}개`,
  );
  await expect(rows(page)).toHaveCount(shown);
}

test("server directory spans pages, combines filters, and restores URL without changing search-wide counts", async ({
  page,
}) => {
  await login(page);
  const { prefix, users } = await seed(page, 36);
  await page.goto(`/admin?q=${prefix}`);
  await expectTotal(page, 36, 10);
  await expect(
    summary(page).getByRole("button", { name: /^전체/ }).locator("strong"),
  ).toHaveText("36");
  await summary(page)
    .getByRole("button", { name: /^담당자/ })
    .click();
  await expectTotal(page, 12, 10);
  await expect(
    summary(page)
      .getByRole("button", { name: /^담당자/ })
      .locator("strong"),
  ).toHaveText("12");
  await page
    .getByRole("navigation", { name: "페이지 선택" })
    .getByRole("button", { name: "다음" })
    .click();
  await expectTotal(page, 12, 2);
  let params = new URL(page.url()).searchParams;
  expect(params.get("page")).toBe("2");
  expect(params.get("role")).toBe("staff");
  await page.reload();
  await expectTotal(page, 12, 2);
  const filteredUrl = page.url();
  await page.goto("/account");
  await page.goBack();
  await expect(page).toHaveURL(filteredUrl);
  await expectTotal(page, 12, 2);
  await page.getByLabel("이용 상태", { exact: true }).selectOption("true");
  await expectTotal(page, 3, 3);
  expect(new URL(page.url()).searchParams.has("page")).toBe(false);
  const visible = await rows(page)
    .locator("td:first-child small")
    .allTextContents();
  expect(visible).toEqual(
    users.filter((u) => u.role === "staff" && u.locked).map((u) => u.username),
  );
  await expect(page.locator(".admin-summary-scope")).toContainText(
    "이용 중 27개 · 잠김 9개",
  );
  await expect(
    summary(page).getByRole("button", { name: /^전체/ }).locator("strong"),
  ).toHaveText("36");
  await page.getByLabel("이용 상태", { exact: true }).selectOption("false");
  await expectTotal(page, 9, 9);
  await page.getByLabel("표시 개수", { exact: true }).selectOption("20");
  await expectTotal(page, 9, 9);
  await page.getByLabel("계정 검색", { exact: true }).fill(users[1].username);
  await page.getByRole("button", { name: "검색", exact: true }).click();
  await expectTotal(page, 1, 1);
  params = new URL(page.url()).searchParams;
  expect(params.get("role")).toBe("staff");
  expect(params.get("locked")).toBe("false");
  await expect(
    summary(page).getByRole("button", { name: /^전체/ }).locator("strong"),
  ).toHaveText("1");
  await page.getByRole("button", { name: "초기화", exact: true }).click();
  await expect(page.getByLabel("계정 검색", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("이용 상태", { exact: true })).toHaveValue("");
  await expect(
    summary(page).getByRole("button", { name: /^전체/ }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("role, lock and reset refresh totals and clamp a filtered page after its last item disappears", async ({
  page,
}) => {
  await login(page);
  const { prefix } = await seed(page, 3, true);
  await page.goto(
    `/admin?q=${prefix}&role=staff&locked=false&page_size=1&page=3`,
  );
  await expectTotal(page, 3, 1);
  await rows(page)
    .getByRole("button", { name: "권한 변경", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByLabel("변경할 권한")
    .selectOption("citizen");
  await page.getByRole("button", { name: "확인 및 저장", exact: true }).click();
  await expectTotal(page, 2, 1);
  await expect(
    page.getByRole("navigation", { name: "페이지 선택" }),
  ).toContainText("2 / 2");
  expect(new URL(page.url()).searchParams.get("page")).toBe("2");
  await expect(
    summary(page).getByRole("button", { name: /^시민/ }).locator("strong"),
  ).toHaveText("1");
  await rows(page).getByRole("button", { name: "잠금", exact: true }).click();
  await page.getByRole("button", { name: "확인 및 저장", exact: true }).click();
  await expectTotal(page, 1, 1);
  expect(new URL(page.url()).searchParams.has("page")).toBe(false);
  await page.getByLabel("이용 상태", { exact: true }).selectOption("true");
  await expectTotal(page, 1, 1);
  await expect(page.locator(".admin-summary-scope")).toContainText("잠김 1개");
  await rows(page)
    .getByRole("button", { name: "비밀번호 재설정", exact: true })
    .click();
  await page.getByRole("dialog").getByLabel("새 임시 비밀번호").fill(password);
  await page.getByRole("button", { name: "확인 및 저장", exact: true }).click();
  await expectTotal(page, 0, 0);
  await expect(page.getByText(/조건에 맞는 계정이 없습니다/)).toBeVisible();
  await expect(
    summary(page)
      .getByRole("button", { name: /^담당자/ })
      .locator("strong"),
  ).toHaveText("2");
  await expect(page.locator(".admin-summary-scope")).toContainText("잠김 0개");
  await page.goto(`/admin?q=${prefix}&role=staff&page=999`);
  await expectTotal(page, 2, 2);
  expect(new URL(page.url()).searchParams.has("page")).toBe(false);
});

test("unsupported, malformed and failed server responses are errors rather than zero accounts", async ({
  page,
}) => {
  await login(page);
  await page.goto("/admin?role=staff&locked=false");
  await expect(summary(page)).toBeVisible();
  for (const mode of ["old", "wrong-count", "failed"]) {
    await page.route("**/api/v1/admin/users?*", async (route) => {
      if (mode === "failed") {
        await route.abort();
        return;
      }
      const response = await route.fetch();
      const body = await response.json();
      if (mode === "old") delete body.data.summary;
      else body.data.summary.roles.staff += 1;
      await route.fulfill({ response, json: body });
    });
    await page.getByRole("button", { name: "새로고침", exact: true }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(summary(page)).toHaveCount(0);
    await expect(rows(page)).toHaveCount(0);
    await expect(page.locator(".admin-list .list-meta")).toHaveCount(0);
    if (mode !== "failed")
      await expect(page.getByRole("alert")).toContainText("서버 버전");
    await page.unroute("**/api/v1/admin/users?*");
    await page.getByRole("button", { name: "다시 시도", exact: true }).click();
    await expect(summary(page)).toBeVisible();
    const params = new URL(page.url()).searchParams;
    expect(params.get("role")).toBe("staff");
    expect(params.get("locked")).toBe("false");
  }
});
