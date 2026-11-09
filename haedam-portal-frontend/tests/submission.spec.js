import { test, expect } from "@playwright/test";

const password = "E2E-only-password-123";
async function prepare(page, username) {
  await page.goto("/register");
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("표시 이름").fill("접수검증시민");
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByLabel("비밀번호 확인", { exact: true }).fill(password);
  await page.getByRole("button", { name: "가입하기", exact: true }).click();
  await page.getByRole("link", { name: "로그인하기", exact: true }).click();
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "로그아웃", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("navigation", { name: "주 메뉴" })
    .getByRole("link", { name: "민원 신청", exact: true })
    .click();
  await page.getByLabel("민원 분야").selectOption("안전·시설");
  await page
    .getByRole("textbox", { name: "제목", exact: true })
    .fill(`${username} 가상 보행로 조명 점검`);
  await page
    .getByRole("textbox", { name: "민원 내용", exact: true })
    .fill(
      "가상의 보행로 조명이 꺼져 있습니다.\n조명을 점검하고 처리 결과를 알려 주세요.",
    );
  await page.getByRole("checkbox").check();
}
async function review(page) {
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "접수할 내용을 확인해 주세요",
      exact: true,
    }),
  ).toBeFocused();
}

test("review sends nothing, preserves edits and Back protection, and final double click creates one receipt", async ({
  page,
}) => {
  await prepare(page, "receipt_review");
  let posts = 0,
    release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await page.route("**/api/v1/petitions", async (route) => {
    posts++;
    await gate;
    await route.continue();
  });
  await review(page);
  expect(posts).toBe(0);
  await page.goBack();
  await expect(
    page.getByRole("dialog", { name: "작성 중인 내용이 있습니다" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "계속 작성", exact: true }).click();
  await expect(page.locator(".submission-review")).toBeVisible();
  await page.getByRole("button", { name: "내용 수정", exact: true }).click();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toBeFocused();
  await expect(page.getByRole("checkbox")).toBeChecked();
  const title = "내용을 고친 가상 조명 점검 요청";
  await page.getByRole("textbox", { name: "제목", exact: true }).fill(title);
  await review(page);
  await expect(page.locator(".submission-summary")).toContainText(title);
  expect(posts).toBe(0);
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .dblclick();
  await expect(
    page.getByRole("button", { name: "접수 중…", exact: true }),
  ).toBeDisabled();
  expect(posts).toBe(1);
  release();
  await expect(
    page.getByRole("heading", { name: "민원 접수 확인서", exact: true }),
  ).toBeVisible();
  const receiptUrl = page.url(),
    id = new URL(receiptUrl).pathname.split("/").at(-1);
  const stored = (
    await (await page.request.get(`/api/v1/petitions/${id}`)).json()
  ).data;
  await expect(page.locator(".receipt-reference")).toContainText(
    stored.reference,
  );
  expect(stored.title).toBe(title);
  await page.reload();
  await expect(page.locator(".receipt-information")).toContainText(title);
  expect(posts).toBe(1);
  await page.getByRole("link", { name: "진행 상황 확인", exact: true }).click();
  await page
    .getByRole("link", { name: "접수 확인서 보기", exact: true })
    .click();
  await expect(page).toHaveURL(receiptUrl);
});

test("a committed POST with a lost response keeps input and blocks blind retry", async ({
  page,
  context,
}) => {
  await prepare(page, "receipt_unknown");
  await review(page);
  let posts = 0;
  await page.route("**/api/v1/petitions", async (route) => {
    posts++;
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    await route.abort("failed");
  });
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "접수 결과를 확인하지 못했습니다",
  );
  await expect(page.locator(".submission-summary")).toContainText(
    "receipt_unknown 가상 보행로 조명 점검",
  );
  await expect(
    page.getByRole("button", { name: "최종 접수하기", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "내용 수정", exact: true }),
  ).toBeDisabled();
  await page
    .locator(".submission-review form")
    .evaluate((form) => form.requestSubmit());
  expect(posts).toBe(1);
  const stored = (await (await page.request.get("/api/v1/petitions")).json())
    .data;
  expect(stored.items).toHaveLength(1);
  const opened = context.waitForEvent("page");
  await page
    .getByRole("link", { name: "나의 민원 확인 (새 창)", exact: true })
    .click();
  const popup = await opened;
  await expect(
    popup.getByRole("link", {
      name: "receipt_unknown 가상 보행로 조명 점검",
      exact: true,
    }),
  ).toBeVisible();
  await popup.close();
});

test("receipt is private, prints only its record, and retry performs GET only", async ({
  page,
}) => {
  await prepare(page, "receipt_print");
  await review(page);
  await page
    .getByRole("button", { name: "최종 접수하기", exact: true })
    .click();
  await expect(page.locator(".receipt-sheet")).toBeVisible();
  const url = page.url();
  await page.evaluate(() => {
    window.__receiptPrintCalls = 0;
    window.print = () => {
      window.__receiptPrintCalls++;
    };
  });
  await page
    .getByRole("button", { name: "접수 확인서 인쇄", exact: true })
    .click();
  expect(await page.evaluate(() => window.__receiptPrintCalls)).toBe(1);
  await page.emulateMedia({ media: "print" });
  await expect(page.locator("header.header")).toBeHidden();
  await expect(page.locator(".receipt-actions")).toBeHidden();
  await expect(page.locator(".receipt-sheet")).toBeVisible();
  await expect(page.locator(".receipt-sheet")).toContainText(
    "실제 행정기관의 증명서가 아닙니다",
  );
  await page.emulateMedia({ media: "screen" });
  const id = new URL(url).pathname.split("/").at(-1);
  let gets = 0;
  await page.route(`**/api/v1/petitions/${id}`, (route) => {
    gets++;
    return route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        success: false,
        error: { code: "SERVER_ERROR", message: "조회 일시 실패" },
      }),
    });
  });
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("조회 일시 실패");
  await expect(page.locator(".receipt-sheet")).toHaveCount(0);
  await page.unroute(`**/api/v1/petitions/${id}`);
  await page.getByRole("button", { name: "다시 시도", exact: true }).click();
  await expect(page.locator(".receipt-sheet")).toBeVisible();
  expect(gets).toBe(1);
  await page.getByRole("button", { name: "로그아웃", exact: true }).click();
  await prepare(page, "receipt_foreign");
  await page.getByRole("link", { name: "취소", exact: true }).click();
  await page
    .getByRole("button", { name: "작성 취소하고 이동", exact: true })
    .click();
  const denied = page.waitForResponse((response) =>
    response.url().endsWith(`/api/v1/petitions/${id}`),
  );
  await page.goto(url);
  expect((await denied).status()).toBe(404);
  await expect(page.locator(".receipt-sheet")).toHaveCount(0);
});
