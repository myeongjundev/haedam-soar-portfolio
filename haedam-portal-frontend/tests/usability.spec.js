import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const password = "E2E-only-password-123";
async function login(page, username) {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "로그아웃", exact: true }),
  ).toBeVisible();
}
async function citizen(page, username) {
  await page.goto("/register");
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("표시 이름").fill("가상시민");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByLabel("비밀번호 확인", { exact: true }).fill(password);
  await page.getByRole("button", { name: "가입하기", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "회원가입이 완료되었습니다" }),
  ).toBeVisible();
  await login(page, username);
}
async function fillPetition(page, title) {
  await page
    .getByRole("combobox", { name: "민원 분야", exact: true })
    .selectOption("안전·시설");
  await page.getByRole("textbox", { name: "제목", exact: true }).fill(title);
  await page
    .getByRole("textbox", { name: "민원 내용", exact: true })
    .fill(
      "가상의 보행로 시설 점검을 요청합니다. 실제 장소나 개인정보가 없는 사용성 회귀 테스트용 민원입니다.",
    );
  await page.getByRole("checkbox").check();
}
function mainNav(page, name) {
  return page
    .getByRole("navigation", { name: "주 메뉴" })
    .getByRole("link", { name, exact: true });
}

test("citizen draft survives canceled navigation, Back, refresh and logout; explicit discard works", async ({
  page,
}) => {
  await citizen(page, "ux_guard");
  await mainNav(page, "민원 신청").click();
  const title = "이탈 경고로 보호할 가상 민원 제목";
  await fillPetition(page, title);
  await mainNav(page, "민원 안내").click();
  const dialog = page.getByRole("dialog", {
    name: "작성 중인 내용이 있습니다",
  });
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "계속 작성", exact: true }),
  ).toBeFocused();
  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
  await page.screenshot({
    path: "test-results/ux-leave-warning.png",
    fullPage: true,
  });
  await dialog.getByRole("button", { name: "계속 작성", exact: true }).click();
  await expect(mainNav(page, "민원 안내")).toBeFocused();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue(title);
  await page.goBack();
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(page).toHaveURL(/\/petitions\/new$/);
  await page.getByRole("textbox", { name: "제목", exact: true }).click();
  const nativePrompt = page.waitForEvent("dialog");
  // A canceled reload never reaches Playwright's navigation load event.
  const reload = page.evaluate(() => window.location.reload());
  const prompt = await nativePrompt;
  expect(prompt.type()).toBe("beforeunload");
  await prompt.dismiss();
  await reload;
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue(title);
  await page.getByRole("button", { name: "로그아웃", exact: true }).click();
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "계속 작성", exact: true }).click();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue(title);
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: title, exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("heading", { name: title, exact: true }),
  ).toBeVisible();
  await mainNav(page, "민원 신청").click();
  await page
    .getByRole("textbox", { name: "제목", exact: true })
    .fill("폐기할 가상 초안");
  await page.getByRole("link", { name: "취소", exact: true }).click();
  await dialog
    .getByRole("button", { name: "작성 취소하고 이동", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "나의 민원", exact: true }),
  ).toBeVisible();
  await mainNav(page, "민원 신청").click();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue("");
  await page
    .getByRole("textbox", { name: "제목", exact: true })
    .fill("로그아웃 시 폐기할 가상 초안");
  await page.getByRole("button", { name: "로그아웃", exact: true }).click();
  await dialog
    .getByRole("button", { name: "작성 취소하고 이동", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "로그인", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ local: [], session: [] });
});

test("client and server field errors are localized, linked, focused and keep input", async ({
  page,
}) => {
  await citizen(page, "ux_validation");
  await mainNav(page, "민원 신청").click();
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await expect(
    page.getByRole("combobox", { name: "민원 분야", exact: true }),
  ).toBeFocused();
  await expect(page.locator("#category-error")).toHaveText(
    "민원 분야를 선택해 주세요.",
  );
  await fillPetition(page, "짧음");
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toBeFocused();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveAttribute("aria-invalid", "true");
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveAttribute("aria-describedby", "title-hint title-error");
  await expect(page.locator("#title-error")).toHaveText(
    "제목은 5~120자로 입력해 주세요.",
  );
  await expect(
    page.getByRole("textbox", { name: "민원 내용", exact: true }),
  ).toHaveValue(/가상의 보행로/);
  await page
    .getByRole("textbox", { name: "제목", exact: true })
    .fill("서버 검증 오류를 확인할 충분한 길이의 제목");
  await page.route("**/api/v1/petitions", (route) =>
    route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({
        success: false,
        error: {
          code: "VALIDATION_ERROR",
          message: "민원 내용을 확인해 주세요.",
          fields: {
            content: "민원 내용에 필요한 상황을 더 자세히 적어 주세요.",
          },
        },
      }),
    }),
  );
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await expect(
    page.getByRole("textbox", { name: "민원 내용", exact: true }),
  ).toBeFocused();
  await expect(page.locator("#content-error")).toContainText(
    "민원 내용에 필요한 상황",
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: "test-results/ux-inline-errors-mobile.png",
    fullPage: true,
  });
  const axe = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(axe.violations).toEqual([]);
});

test("list URL restores search, category, status and page after detail, Back and reload", async ({
  page,
}) => {
  await citizen(page, "ux_list");
  const { data } = await (await page.request.get("/api/v1/auth/me")).json();
  for (const suffix of ["하나", "둘", "셋"]) {
    const response = await page.request.post("/api/v1/petitions", {
      headers: { "X-CSRF-Token": data.csrf_token },
      data: {
        title: `목록 유지 확인용 민원 ${suffix}`,
        content:
          "상세 화면 왕복 시 검색과 페이지를 유지하는지 확인하는 합성 민원입니다.",
        category: "환경·청소",
      },
    });
    expect(response.status()).toBe(201);
  }
  const query = new URLSearchParams({
    q: "목록 유지",
    category: "환경·청소",
    status: "received",
    page: "2",
    page_size: "1",
  });
  const url = `/petitions?${query}`;
  await page.goto(url);
  const row = page.getByRole("link", {
    name: "목록 유지 확인용 민원 둘",
    exact: true,
  });
  await expect(row).toBeVisible();
  await row.click();
  await page
    .getByRole("link", { name: "← 나의 민원 목록", exact: true })
    .click();
  await expect(page).toHaveURL(`http://127.0.0.1:5005${url}`);
  await expect(page.getByLabel("민원 제목 검색")).toHaveValue("목록 유지");
  await expect(page.getByLabel("분야", { exact: true })).toHaveValue(
    "환경·청소",
  );
  await expect(
    page.getByRole("button", { name: "접수 완료", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByRole("navigation", { name: "페이지 선택" }),
  ).toContainText("2 / 3");
  await row.click();
  await page.goBack();
  await expect(row).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("민원 제목 검색")).toHaveValue("목록 유지");
  await expect(row).toBeVisible();
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    expect(
      await row.evaluate((el) => parseFloat(getComputedStyle(el).fontSize)),
    ).toBeGreaterThanOrEqual(14);
    expect(
      await page
        .locator(".petition-table .badge")
        .evaluate((el) => parseFloat(getComputedStyle(el).fontSize)),
    ).toBeGreaterThanOrEqual(12);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect(
      await page
        .locator(".table-scroll")
        .evaluate((el) => el.scrollWidth <= el.clientWidth),
    ).toBe(true);
  }
  await page.screenshot({
    path: "test-results/ux-list-mobile-320.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "초기화", exact: true }).click();
  await expect(page.getByLabel("민원 제목 검색")).toHaveValue("");
  expect(new URL(page.url()).searchParams.has("page")).toBe(false);
  await mainNav(page, "민원 신청").click();
  await expect(page.locator("#title-hint")).toBeVisible();
  await expect(page.locator("#content-hint")).toBeVisible();
  expect(
    await page
      .getByRole("textbox", { name: "제목", exact: true })
      .evaluate((el) => parseFloat(getComputedStyle(el).fontSize)),
  ).toBeGreaterThanOrEqual(16);
});

test("staff reply remains after canceled navigation and is cleared only after confirmed discard or save", async ({
  page,
  browser,
}) => {
  await citizen(page, "ux_reply");
  await mainNav(page, "민원 신청").click();
  const title = "담당자 답변 유실 방지 검증용 가상 민원";
  await fillPetition(page, title);
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: title, exact: true }),
  ).toBeVisible();
  const url = page.url();
  const context = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  const staff = await context.newPage();
  await login(staff, "staff_e2e");
  await staff.goto(url);
  await staff
    .getByRole("button", { name: "내가 담당하기", exact: true })
    .click();
  await staff.getByRole("button", { name: "처리 시작", exact: true }).click();
  await staff
    .getByLabel("처리 결과 답변", { exact: true })
    .fill("유지되어야 하는 가상의 답변 초안입니다.");
  await mainNav(staff, "민원 업무").click();
  await staff
    .getByRole("dialog")
    .getByRole("button", { name: "계속 작성", exact: true })
    .click();
  await expect(staff.getByLabel("처리 결과 답변", { exact: true })).toHaveValue(
    "유지되어야 하는 가상의 답변 초안입니다.",
  );
  await mainNav(staff, "민원 업무").click();
  await staff
    .getByRole("dialog")
    .getByRole("button", { name: "작성 취소하고 이동", exact: true })
    .click();
  await staff.getByRole("link", { name: title, exact: true }).click();
  await expect(staff.getByLabel("처리 결과 답변", { exact: true })).toHaveValue(
    "",
  );
  await staff
    .getByRole("button", { name: "답변 내용 확인", exact: true })
    .click();
  await expect(
    staff.getByLabel("처리 결과 답변", { exact: true }),
  ).toBeFocused();
  await expect(staff.locator("#reply-error")).toContainText("10~3,000자");
  const reply =
    "확인하신 가상 민원에 대한 점검과 처리를 완료했습니다. 의견을 주셔서 감사합니다.";
  await staff.getByLabel("처리 결과 답변", { exact: true }).fill(reply);
  await staff
    .getByRole("button", { name: "답변 내용 확인", exact: true })
    .click();
  await staff
    .getByRole("checkbox", {
      name: "신청 내용과 실제 조치 결과를 확인했습니다",
    })
    .check();
  await staff
    .getByRole("button", { name: "답변 등록 및 처리 완료", exact: true })
    .click();
  await expect(staff.getByText(reply, { exact: true })).toBeVisible();
  await staff.reload();
  await page.reload();
  await expect(page.getByText(reply, { exact: true })).toBeVisible();
  await expect(page.locator(".detail-top .badge")).toHaveText("처리 완료");
  await context.close();
});

test("navigation while saving cannot abandon a pending write and success opens its result", async ({
  page,
}) => {
  await citizen(page, "ux_busy");
  await mainNav(page, "민원 신청").click();
  const title = "저장 중 이동과 접수 성공 경로를 확인하는 가상 민원";
  await fillPetition(page, title);
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/petitions", async (route) => {
    await gate;
    await route.continue();
  });
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "접수 중…", exact: true }),
  ).toBeDisabled();
  await mainNav(page, "민원 안내").click();
  await expect(
    page.getByRole("dialog", { name: "저장 중입니다" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "작성 취소하고 이동", exact: true }),
  ).toBeDisabled();
  release();
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: title, exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("dialog")).not.toBeVisible();
});
