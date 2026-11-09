import { test, expect } from "@playwright/test";

const password = "E2E-only-password-123";
const answer =
  "1. 확인한 내용\n가상의 보행로 조명 고장을 확인했습니다.\n\n2. 조치 및 결과\n교육용 점검과 교체를 완료하고 동작을 확인했습니다.\n\n3. 추가 안내\n추가 안내는 없습니다.";
const nav = (page) => page.getByRole("navigation", { name: "주 메뉴" });
const draft = (page) => page.getByLabel("처리 결과 답변", { exact: true });
async function login(page, username) {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(page.getByRole("button", { name: "로그아웃" })).toBeVisible();
}
async function write(page, method, path, data) {
  const me = (await (await page.request.get("/api/v1/auth/me")).json()).data;
  return page.request.fetch(`/api/v1${path}`, {
    method,
    headers: { "X-CSRF-Token": me.csrf_token },
    data,
  });
}
async function setup(page, browser, suffix) {
  const username = `workspace_${Date.now()}`;
  await page.goto("/login");
  const registration = await write(page, "POST", "/auth/register", {
    username,
    display_name: "가상작업시민",
    password,
  });
  expect(registration.status()).toBe(201);
  await login(page, username);
  const response = await write(page, "POST", "/petitions", {
    title: `직원 작업 화면 검증용 가상 민원 ${suffix}`,
    content:
      "가상의 해담동 보행로 조명이 꺼져 있습니다. 실제 위치나 개인정보를 포함하지 않는 격리된 회귀 검증 민원입니다.",
    category: "안전·시설",
  });
  expect(response.status()).toBe(201);
  const petition = (await response.json()).data;
  const context = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  const staff = await context.newPage();
  await login(staff, "staff_e2e");
  return { petition, staff, context };
}
async function start(staff, petition) {
  await staff.goto(`/petitions/${petition.id}`);
  await staff.getByRole("button", { name: "내가 담당하기" }).click();
  await staff.getByRole("button", { name: "처리 시작", exact: true }).click();
  await expect(draft(staff)).toBeVisible();
}
async function review(staff) {
  await staff
    .getByRole("button", { name: "답변 내용 확인", exact: true })
    .click();
  await expect(
    staff.getByRole("heading", { name: "시민에게 전달할 답변 확인" }),
  ).toBeFocused();
  await staff
    .getByRole("checkbox", {
      name: "신청 내용과 실제 조치 결과를 확인했습니다",
    })
    .check();
}

test("staff shortcut preserves filters; outline, review and deliberate single save protect the draft", async ({
  page,
  browser,
}) => {
  const { staff, context, petition } = await setup(page, browser, "작업동선");
  try {
    await staff.goto(
      "/work?status=received&category=안전·시설&q=작업동선&page_size=1",
    );
    const shortcut = staff.getByRole("link", {
      name: `${petition.reference} 배정하기`,
    });
    await shortcut.click();
    await expect(staff).toHaveURL(new RegExp(`${petition.id}#staff-action$`));
    await expect(staff.locator("#staff-action")).toBeFocused();
    await expect(staff.locator(".back-link")).toHaveAttribute(
      "href",
      /status=received.*q=.*page_size=1/,
    );
    await staff.getByRole("button", { name: "내가 담당하기" }).click();
    await staff.getByRole("button", { name: "처리 시작", exact: true }).click();
    let patches = 0;
    let release;
    const gate = new Promise((resolve) => (release = resolve));
    await staff.route(
      `**/api/v1/petitions/${petition.id}/status`,
      async (route) => {
        patches += 1;
        await gate;
        await route.continue();
      },
    );
    await staff.getByText("답변 작성 요령", { exact: true }).click();
    const outline = staff.getByRole("button", {
      name: "빈 답변에 구성 틀 넣기",
    });
    await outline.click();
    await expect(draft(staff)).toHaveValue(/\[실제 조치와 결과 입력\]/);
    await expect(outline).toBeDisabled();
    await staff.getByRole("button", { name: "답변 내용 확인" }).click();
    await expect(staff.locator("#reply-error")).toContainText("실제 내용");
    await expect(draft(staff)).toBeFocused();
    expect(patches).toBe(0);
    await draft(staff).fill(answer);
    await review(staff);
    expect(patches).toBe(0);
    await staff.getByRole("button", { name: "답변 수정", exact: true }).click();
    await expect(draft(staff)).toHaveValue(answer);
    await expect(draft(staff)).toBeFocused();
    await nav(staff)
      .getByRole("link", { name: "민원 업무", exact: true })
      .click();
    await staff
      .getByRole("dialog")
      .getByRole("button", { name: "계속 작성" })
      .click();
    await expect(draft(staff)).toHaveValue(answer);
    await review(staff);
    const final = staff.getByRole("button", { name: "답변 등록 및 처리 완료" });
    await final.evaluate((button) => {
      button.click();
      button.click();
    });
    await expect(
      staff.getByRole("button", { name: "저장 중…" }),
    ).toBeDisabled();
    await nav(staff)
      .getByRole("link", { name: "민원 업무", exact: true })
      .click();
    await expect(
      staff.getByRole("dialog", { name: "저장 중입니다" }),
    ).toBeVisible();
    await expect(
      staff.getByRole("button", { name: "작성 취소하고 이동" }),
    ).toBeDisabled();
    release();
    await expect(staff.locator("#official-response")).toContainText(answer);
    expect(patches).toBe(1);
    await expect(staff.getByRole("dialog")).toHaveCount(0);
    await page.goto(`/petitions/${petition.id}`);
    await expect(page.locator("#official-response")).toContainText(answer);
    await expect(page.locator("#staff-action")).toHaveCount(0);
    await staff.locator(".back-link").click();
    await expect(staff).toHaveURL(/\/work\?status=received/);
    await expect(staff.getByText("조건에 맞는 민원이 없습니다")).toBeVisible();
  } finally {
    await context.close();
  }
});

test("real stale-version 409 preserves local draft and requires a fresh read without retrying", async ({
  page,
  browser,
}) => {
  const { staff, context, petition } = await setup(page, browser, "실제충돌");
  try {
    await start(staff, petition);
    await draft(staff).fill(answer);
    const current = (
      await (await staff.request.get(`/api/v1/petitions/${petition.id}`)).json()
    ).data;
    const serverAnswer =
      "다른 탭에서 확인 후 먼저 등록한 가상의 처리 결과입니다.";
    const first = await write(
      staff,
      "PATCH",
      `/petitions/${petition.id}/status`,
      {
        status: "completed",
        reply: serverAnswer,
        version: current.version,
      },
    );
    expect(first.status()).toBe(200);
    let attempts = 0;
    staff.on("request", (request) => {
      if (request.method() === "PATCH") attempts += 1;
    });
    await review(staff);
    await staff.getByRole("button", { name: "답변 등록 및 처리 완료" }).click();
    await expect(staff.getByRole("alert")).toContainText("변경됐습니다");
    await expect(draft(staff)).toHaveValue(answer);
    await expect(
      staff.getByRole("button", { name: "답변 내용 확인" }),
    ).toBeDisabled();
    await staff
      .getByRole("button", { name: "초안 유지하고 최신 상태 확인" })
      .click();
    await expect(staff.locator("#official-response")).toContainText(
      serverAnswer,
    );
    await staff.getByText("이 화면에 남아 있는 초안", { exact: true }).click();
    await expect(staff.locator(".retained-reply .reply-preview")).toHaveText(
      answer,
    );
    expect(attempts).toBe(1);
    await expect(
      staff.getByRole("button", { name: "답변 등록 및 처리 완료" }),
    ).toHaveCount(0);
    await nav(staff)
      .getByRole("link", { name: "민원 업무", exact: true })
      .click();
    await expect(staff.getByRole("dialog")).toBeVisible();
    await staff.getByRole("button", { name: "계속 작성", exact: true }).click();
    await expect(staff.locator(".retained-reply .reply-preview")).toHaveText(
      answer,
    );
  } finally {
    await context.close();
  }
});

test("another staff member's real assignment rejects a stale workspace and hides it on refresh", async ({
  page,
  browser,
}) => {
  const { staff, context, petition } = await setup(page, browser, "다른담당자");
  const otherContext = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  try {
    const other = await otherContext.newPage();
    await login(other, "admin_e2e");
    const create = await write(other, "POST", "/admin/users", {
      username: "staff_workspace_other",
      display_name: "가상다른담당",
      password,
      role: "staff",
    });
    expect(create.status()).toBe(201);
    await other.getByRole("button", { name: "로그아웃" }).click();
    await login(other, "staff_workspace_other");
    await staff.goto(`/petitions/${petition.id}`);
    await expect(
      staff.getByRole("button", { name: "내가 담당하기" }),
    ).toBeVisible();
    const assign = await write(
      other,
      "PATCH",
      `/petitions/${petition.id}/assignment`,
      {},
    );
    expect(assign.status()).toBe(200);
    await staff.getByRole("button", { name: "내가 담당하기" }).click();
    await expect(staff.getByRole("alert")).toContainText("찾을 수 없습니다");
    await expect(
      staff.getByRole("button", { name: "내가 담당하기" }),
    ).toBeDisabled();
    await staff
      .getByRole("button", { name: "초안 유지하고 최신 상태 확인" })
      .click();
    await expect(
      staff.getByRole("heading", { name: petition.title }),
    ).toHaveCount(0);
    expect(
      (await staff.request.get(`/api/v1/petitions/${petition.id}`)).status(),
    ).toBe(404);
    const denied = await write(
      staff,
      "PATCH",
      `/petitions/${petition.id}/status`,
      {
        status: "in_progress",
        version: 1,
      },
    );
    expect(denied.status()).toBe(404);
  } finally {
    await context.close();
    await otherContext.close();
  }
});

test("saved response lost in transit is reconciled by GET; no automatic second completion", async ({
  page,
  browser,
}) => {
  const { staff, context, petition } = await setup(page, browser, "응답유실");
  try {
    await start(staff, petition);
    await draft(staff).fill(answer);
    let writes = 0;
    await staff.route(
      `**/api/v1/petitions/${petition.id}/status`,
      async (route) => {
        writes += 1;
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        await route.abort("failed");
      },
    );
    await review(staff);
    await staff.getByRole("button", { name: "답변 등록 및 처리 완료" }).click();
    await expect(staff.getByRole("alert")).toBeVisible();
    await expect(draft(staff)).toHaveValue(answer);
    await expect(
      staff.getByRole("button", { name: "답변 내용 확인" }),
    ).toBeDisabled();
    await staff
      .getByRole("button", { name: "초안 유지하고 최신 상태 확인" })
      .click();
    await expect(staff.locator("#official-response")).toContainText(answer);
    expect(writes).toBe(1);
    await expect(
      staff.getByRole("button", { name: "답변 등록 및 처리 완료" }),
    ).toHaveCount(0);
    await page.goto(`/petitions/${petition.id}`);
    await expect(page.locator("#official-response")).toContainText(answer);
  } finally {
    await context.close();
  }
});
