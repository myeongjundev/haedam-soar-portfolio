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

test("citizen application → reload → staff assignment and completion → citizen response", async ({
  page,
  browser,
}) => {
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await login(page, "citizen_e2e");
  await page
    .getByRole("link", { name: "민원 신청", exact: true })
    .first()
    .click();
  await page.getByLabel("민원 분야").selectOption("안전·시설");
  const title = "가상 해담동 보행로 조명 점검 요청";
  await page.getByLabel("제목").fill(title);
  await page
    .getByLabel("민원 내용")
    .fill(
      "가상의 해담동 보행로 조명이 켜지지 않습니다. 시민들의 안전을 위해 점검을 부탁드립니다.",
    );
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "입력 내용 확인" }).click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await expect(
    page.locator('.journey-steps [aria-current="step"]'),
  ).toContainText("접수 완료");
  await expect(page.locator(".journey-action")).toHaveCount(0);
  const detail = page.url();
  await page.reload();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  const staffContext = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  const staff = await staffContext.newPage();
  await login(staff, "staff_e2e");
  await staff.getByRole("link", { name: title }).click();
  await staff.getByRole("button", { name: "내가 담당하기" }).click();
  await expect(
    staff.locator('.journey-steps [aria-current="step"]'),
  ).toContainText("담당자 배정");
  await staff.getByRole("button", { name: "처리 시작", exact: true }).click();
  await expect(
    staff.locator('.journey-steps [aria-current="step"]'),
  ).toContainText("처리 중");
  await expect(
    staff.getByRole("link", { name: "답변 작성으로 이동" }),
  ).toBeVisible();
  const reply =
    "보행로 조명 점검과 수리를 완료했습니다. 의견을 주셔서 감사합니다.";
  await staff.getByLabel("처리 결과 답변").fill(reply);
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
  await page.goto(detail);
  await expect(page.getByText(reply, { exact: true })).toBeVisible();
  await expect(
    page.locator('.journey-steps [aria-current="step"]'),
  ).toContainText("답변 완료");
  await page.getByRole("link", { name: "답변 확인하기", exact: true }).click();
  await expect(page.locator("#official-response")).toBeInViewport();
  await expect(page.locator(".detail-top .badge")).toHaveText("처리 완료");
  await page.screenshot({
    path: "test-results/citizen-detail-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
  await staffContext.close();
});

test("registration, login failure, private query, XSS-safe rendering and logout", async ({
  page,
}) => {
  await page.goto("/register");
  await page.getByLabel("아이디", { exact: true }).fill("new_citizen_e2e");
  await page.getByLabel("표시 이름").fill("새시민");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByLabel("비밀번호 확인", { exact: true }).fill(password);
  await page.getByRole("button", { name: "가입하기", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "회원가입이 완료되었습니다" }),
  ).toBeVisible();
  await page.getByRole("link", { name: "로그인하기", exact: true }).click();
  await page.getByLabel("아이디", { exact: true }).fill("new_citizen_e2e");
  await page.getByLabel("비밀번호", { exact: true }).fill("wrong-password");
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("아이디·비밀번호");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(page.getByText("아직 신청한 민원이 없어요")).toBeVisible();
  const denied = await page.request.get("/api/v1/petitions/1");
  expect(denied.status()).toBe(404);
  await page.goto("/petitions/new");
  await page.getByLabel("민원 분야").selectOption("기타");
  const title = "<img src=x onerror=alert(1)>";
  await page.getByLabel("제목").fill(title);
  await page
    .getByLabel("민원 내용")
    .fill(
      "스크립트 문자열도 일반 텍스트로 표시되는지 확인하는 가상 민원입니다.",
    );
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "입력 내용 확인" }).click();
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  expect(await page.locator(".detail-panel h1 img").count()).toBe(0);
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  await page.getByRole("button", { name: "로그아웃", exact: true }).click();
  await expect(
    page.getByRole("link", { name: "로그인", exact: true }),
  ).toBeVisible();
});

test("admin creates staff, changes role, locks account and resets password", async ({
  page,
}) => {
  await login(page, "admin_e2e");
  await page.getByRole("button", { name: "계정 만들기" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("아이디", { exact: true }).fill("new_staff_e2e");
  await dialog.getByLabel("표시 이름").fill("새담당");
  await dialog.getByLabel("임시 비밀번호", { exact: true }).fill(password);
  await dialog.getByRole("button", { name: "확인 및 저장" }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByLabel("계정 검색", { exact: true }).fill("new_staff_e2e");
  await page.getByRole("button", { name: "검색", exact: true }).click();
  const row = page.getByRole("row").filter({ hasText: "new_staff_e2e" });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "권한 변경" }).click();
  await page
    .getByRole("dialog")
    .getByLabel("변경할 권한")
    .selectOption("citizen");
  await expect(page.getByRole("dialog").getByRole("definition")).toHaveText([
    "담당자",
    "시민",
  ]);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "확인 및 저장" })
    .click();
  await expect(row).toContainText("시민");
  await row.getByRole("button", { name: "잠금", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("definition")).toHaveText([
    "이용 중",
    "잠김",
  ]);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "확인 및 저장" })
    .click();
  await expect(row).toContainText("잠김");
  await row.getByRole("button", { name: "비밀번호 재설정" }).click();
  await page
    .getByRole("dialog")
    .getByLabel("새 임시 비밀번호")
    .fill("Reset-e2e-password-123");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "확인 및 저장" })
    .click();
  await expect(row).toContainText("이용 중");
});

test("mobile home and forms fit viewport, keyboard skip and real 404", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const response = await page.goto("/");
  expect(response.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "시민의 목소리를",
  );
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "본문 바로가기" })).toBeFocused();
  await page.keyboard.press("Enter");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/home-mobile.png",
    fullPage: true,
  });
  await login(page, "citizen_e2e");
  await page.goto("/petitions");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/petitions-mobile.png",
    fullPage: true,
  });
  const missing = await page.request.get("/this-is-not-a-page");
  expect(missing.status()).toBe(404);
});

test("home and authentication meet automated accessibility checks", async ({
  page,
}) => {
  for (const route of ["/", "/login"]) {
    await page.goto(route);
    await expect(page.getByRole("main")).toBeVisible();
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze();
    expect(
      result.violations.map((v) => ({
        id: v.id,
        nodes: v.nodes.map((n) => ({
          target: n.target,
          summary: n.failureSummary,
        })),
      })),
    ).toEqual([]);
  }
});

test("desktop home, filtering, session password change and network error", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.screenshot({
    path: "test-results/home-desktop.png",
    fullPage: true,
  });
  await login(page, "citizen_e2e");
  await page.getByLabel("민원 제목 검색").fill("결과없는제목");
  await page.getByRole("button", { name: "검색", exact: true }).click();
  await expect(page.getByText("조건에 맞는 민원이 없습니다")).toBeVisible();
  await page.goto("/account");
  await page.getByLabel("현재 비밀번호", { exact: true }).fill(password);
  await page
    .getByLabel("새 비밀번호", { exact: true })
    .fill("Changed-e2e-password-123");
  await page
    .getByLabel("새 비밀번호 확인", { exact: true })
    .fill("Changed-e2e-password-123");
  await page
    .getByRole("button", { name: "비밀번호 변경", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText(
    "비밀번호를 변경했습니다.",
  );
  await page.route("**/api/v1/petitions?**", (route) => route.abort());
  await page.goto("/petitions");
  await expect(page.getByRole("alert")).toContainText(
    "서버에 연결할 수 없습니다",
  );
  await expect(page.getByRole("button", { name: "다시 시도" })).toBeVisible();
});
