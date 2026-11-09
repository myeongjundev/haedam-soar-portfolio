let csrfToken = "";
export class ApiError extends Error {
  constructor(message, status, code, fields = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.fields =
      fields && typeof fields === "object" && !Array.isArray(fields)
        ? Object.fromEntries(
            Object.entries(fields).filter(
              ([, value]) => typeof value === "string",
            ),
          )
        : {};
  }
}
export function setCsrf(value) {
  csrfToken = value || "";
}
export async function api(path, { method = "GET", data, signal } = {}) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timeout = setTimeout(abort, 15000);
  try {
    const response = await fetch(`/api/v1${path}`, {
      method,
      credentials: "same-origin",
      signal: controller.signal,
      headers:
        method === "GET"
          ? { Accept: "application/json" }
          : { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: method === "GET" ? undefined : JSON.stringify(data ?? {}),
    });
    const result = await response.json().catch(() => null);
    if (!response.ok || !result?.success) {
      if (response.status === 401 && result?.error?.code === "AUTH_REQUIRED")
        window.dispatchEvent(new Event("auth-expired"));
      throw new ApiError(
        result?.error?.message || "서버 응답을 확인할 수 없습니다.",
        response.status,
        result?.error?.code,
        result?.error?.fields,
      );
    }
    if (result.data?.csrf_token) setCsrf(result.data.csrf_token);
    return result.data;
  } catch (error) {
    if (error.name === "AbortError")
      throw new ApiError(
        "요청 시간이 초과됐습니다. 연결을 확인하고 다시 시도해 주세요.",
        0,
        "TIMEOUT",
      );
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      "서버에 연결할 수 없습니다. 연결을 확인하고 다시 시도해 주세요.",
      0,
      "NETWORK_ERROR",
    );
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abort);
  }
}
