import { test, expect } from "@playwright/test";
import { readFile, writeFile, rename } from "node:fs/promises";
import path from "node:path";

const password = "E2E-only-password-123";
const title = "[MySQL 통합] 가상 산책로 조명 점검 요청 🌱";
const content =
  "실제 장소와 개인정보가 없는 MySQL 통합 검증용 민원입니다. 가상 산책로 조명 점검을 요청합니다. 🌱";
const reply =
  "가상 산책로의 조명을 점검하고 처리를 완료했습니다. 시민 의견에 감사드립니다. 🌱";

async function login(page, username) {
  await page.goto("/login");
  await page.getByLabel("아이디", { exact: true }).fill(username);
  await page.getByLabel("비밀번호", { exact: true }).fill(password);
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "로그아웃", exact: true }),
  ).toBeVisible();
}

async function register(page, username) {
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

async function restartBackend(id) {
  const directory = process.env.HAEDAM_E2E_CONTROL_DIR;
  if (!directory || process.env.HAEDAM_E2E_MYSQL !== "1")
    throw new Error("Use the owned backend tools/check_mysql_e2e.py runner");
  const temporary = path.join(directory, "restart-request.tmp");
  await writeFile(temporary, JSON.stringify({ id, action: "restart" }), "utf8");
  await rename(temporary, path.join(directory, "restart-request.json"));
  let acknowledgement;
  await expect
    .poll(
      async () => {
        try {
          acknowledgement = JSON.parse(
            await readFile(
              path.join(directory, "restart-response.json"),
              "utf8",
            ),
          );
          return acknowledgement.id;
        } catch (error) {
          if (error.code === "ENOENT") return null;
          throw error;
        }
      },
      { timeout: 60000 },
    )
    .toBe(id);
  expect(acknowledgement.dialect).toBe("mysql");
  expect(acknowledgement.current_pid).not.toBe(acknowledgement.previous_pid);
}

async function detail(page, url) {
  const response = await page.request.get(
    `/api/v1/petitions/${url.split("/").at(-1)}`,
  );
  expect(response.status()).toBe(200);
  return (await response.json()).data;
}

test("MySQL citizen → process restart → staff reply → process restart → same sessions and private result", async ({
  page,
  browser,
}) => {
  test.setTimeout(120000);
  await register(page, "mysql_persist");
  const ownerId = (await (await page.request.get("/api/v1/auth/me")).json())
    .data.user.id;
  await page
    .getByRole("navigation", { name: "주 메뉴" })
    .getByRole("link", { name: "민원 신청", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "민원 분야", exact: true })
    .selectOption("안전·시설");
  await page.getByRole("textbox", { name: "제목", exact: true }).fill(title);
  await page
    .getByRole("textbox", { name: "민원 내용", exact: true })
    .fill(content);
  await page.getByRole("checkbox").check();
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
  const received = await detail(page, url);
  expect(received.status).toBe("received");
  expect(received.content).toBe(content);
  expect(received.applicant.id).toBe(ownerId);
  await restartBackend(1);
  await page.reload();
  await expect(
    page.getByRole("heading", { name: title, exact: true }),
  ).toBeVisible();
  expect(await detail(page, url)).toEqual(received);
  expect(
    (await (await page.request.get("/api/v1/auth/me")).json()).data.user.id,
  ).toBe(ownerId);

  const staffContext = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  const otherContext = await browser.newContext({
    baseURL: "http://127.0.0.1:5005",
  });
  try {
    const staff = await staffContext.newPage();
    await login(staff, "staff_e2e");
    await staff.getByRole("link", { name: title, exact: true }).click();
    await staff
      .getByRole("button", { name: "내가 담당하기", exact: true })
      .click();
    await staff.getByRole("button", { name: "처리 시작", exact: true }).click();
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
    await page.reload();
    await expect(page.getByText(reply, { exact: true })).toBeVisible();
    const completed = await detail(page, url);
    expect(completed.status).toBe("completed");
    expect(completed.reply).toBe(reply);
    expect(completed.history.map((item) => item.to_status)).toEqual([
      "received",
      "received",
      "in_progress",
      "completed",
    ]);
    expect(completed.version).toBeGreaterThan(received.version);
    await restartBackend(2);
    await page.reload();
    await staff.reload();
    await expect(page.getByText(reply, { exact: true })).toBeVisible();
    await expect(staff.getByText(reply, { exact: true })).toBeVisible();
    await expect(page.locator(".detail-top .badge")).toHaveText("처리 완료");
    expect(await detail(page, url)).toEqual(completed);
    expect(await detail(staff, url)).toEqual(completed);
    expect(
      (await (await page.request.get("/api/v1/auth/me")).json()).data.user.id,
    ).toBe(ownerId);
    const noCsrf = await page.request.post("/api/v1/petitions", {
      data: { title, content, category: "안전·시설" },
    });
    expect(noCsrf.status()).toBe(403);
    expect((await noCsrf.json()).error.code).toBe("CSRF_FAILED");
    await page.screenshot({
      path: "test-results/mysql-citizen-after-restart.png",
      fullPage: true,
    });

    const other = await otherContext.newPage();
    await register(other, "mysql_other");
    const denied = await other.request.get(`/api/v1/petitions/${completed.id}`);
    expect(denied.status()).toBe(404);
    const deniedText = await denied.text();
    for (const value of [title, content, reply])
      expect(deniedText).not.toContain(value);
    const ownList = (
      await (await other.request.get("/api/v1/petitions")).json()
    ).data.items;
    expect(ownList.some((item) => item.id === completed.id)).toBe(false);
    await other.goto(url);
    await expect(other.getByRole("alert")).toBeVisible();
    await expect(
      other.getByRole("heading", { name: title, exact: true }),
    ).not.toBeVisible();
    expect(
      await page.evaluate(() => ({
        local: Object.keys(localStorage),
        session: Object.keys(sessionStorage),
      })),
    ).toEqual({ local: [], session: [] });
  } finally {
    await staffContext.close();
    await otherContext.close();
  }
});
