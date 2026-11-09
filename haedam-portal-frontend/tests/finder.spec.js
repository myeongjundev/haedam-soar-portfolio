import { test, expect } from "@playwright/test";

async function login(page) {
  await page.getByLabel("아이디", { exact: true }).fill("citizen_e2e");
  await page
    .getByLabel("비밀번호", { exact: true })
    .fill("E2E-only-password-123");
  await page.getByRole("button", { name: "로그인", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "로그아웃", exact: true }),
  ).toBeVisible();
}

test("guest situation and guidance survive login without creating or filling a petition", async ({
  page,
}) => {
  let writes = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/api/v1/petitions"
    )
      writes++;
  });
  await page.goto("/");
  const button = page.getByRole("button", {
    name: "가로등이 꺼졌어요",
    exact: true,
  });
  await button.focus();
  await button.press("Enter");
  await expect(button).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.getByRole("region", { name: "선택한 상황의 작성 안내" }),
  ).toContainText("조명 시설 위치");
  await page
    .getByRole("link", { name: "이 상황으로 민원 작성", exact: true })
    .click();
  await expect(page).toHaveURL(/\/login$/);
  await login(page);
  expect(new URL(page.url()).searchParams.get("guide")).toBe("lighting");
  await expect(page.getByLabel("민원 분야")).toHaveValue("안전·시설");
  await expect(page.locator(".selected-service-guide")).toContainText(
    "가로등이 꺼졌어요",
  );
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue("");
  await expect(
    page.getByRole("textbox", { name: "민원 내용", exact: true }),
  ).toHaveValue("");
  await expect(page.getByRole("checkbox")).not.toBeChecked();
  await page.getByLabel("민원 분야").selectOption("도로·교통");
  const title = "직접 작성한 가상의 보행로 요청";
  await page.getByRole("textbox", { name: "제목", exact: true }).fill(title);
  await page
    .getByRole("textbox", { name: "민원 내용", exact: true })
    .fill(
      "가상의 보행로 시설을 점검해 주세요. 작성 내용을 보존하는지 확인합니다.",
    );
  await page.getByRole("checkbox").check();
  await page
    .getByRole("link", { name: "홈에서 다른 상황 찾기", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "작성 중인 내용이 있습니다" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "계속 작성", exact: true }).click();
  await expect(
    page.getByRole("textbox", { name: "제목", exact: true }),
  ).toHaveValue(title);
  await expect(page.getByLabel("민원 분야")).toHaveValue("도로·교통");
  await expect(page.getByRole("checkbox")).toBeChecked();
  await page
    .getByRole("button", { name: "입력 내용 확인", exact: true })
    .click();
  await expect(page.locator(".submission-summary")).toContainText("도로·교통");
  expect(writes).toBe(0);
});

test("all six situations link to editable categories and unknown IDs fall back safely", async ({
  page,
}) => {
  await page.goto("/login");
  await login(page);
  for (const [label, category, id] of [
    ["가로등이 꺼졌어요", "안전·시설", "lighting"],
    ["쓰레기가 쌓여 있어요", "환경·청소", "waste"],
    ["보행로가 파손됐어요", "도로·교통", "sidewalk"],
    ["공원 이용이 불편해요", "공원·녹지", "park"],
    ["생활·복지 이용이 어려워요", "생활·복지", "welfare"],
    ["어떤 분야인지 모르겠어요", "기타", "other"],
  ]) {
    await page.goto("/");
    await page.getByRole("button", { name: label, exact: true }).click();
    const link = page.getByRole("link", {
      name: "이 상황으로 민원 작성",
      exact: true,
    });
    await expect(link).toHaveAttribute("href", new RegExp(`guide=${id}$`));
    await link.click();
    await expect(page.getByLabel("민원 분야")).toHaveValue(category);
    await expect(page.locator(".selected-service-guide")).toContainText(label);
    await expect(
      page.getByRole("textbox", { name: "제목", exact: true }),
    ).toHaveValue("");
  }
  await page.goto(
    "/petitions/new?guide=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&category=unknown",
  );
  await expect(page.locator(".selected-service-guide")).toHaveCount(0);
  await expect(page.getByLabel("민원 분야")).toHaveValue("");
  await expect(
    page.getByRole("heading", { name: "작성 전 확인해 주세요", exact: true }),
  ).toBeVisible();
  await page.goto("/petitions/new?guide=waste");
  await expect(page.getByLabel("민원 분야")).toHaveValue("환경·청소");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator(".mobile-service-guide")).toContainText(
    "쓰레기가 쌓여 있어요",
  );
  await page.locator(".mobile-service-guide summary").click();
  await expect(page.locator(".mobile-service-guide ol")).toBeVisible();
  await expect(page.locator(".mobile-service-guide li")).toHaveCount(3);
});
