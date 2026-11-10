import { ApiError } from "./client";

const roles = ["citizen", "staff", "admin"];
const count = (value) => Number.isSafeInteger(value) && value >= 0;

export function readAdminListing(data, filters) {
  const summary = data?.summary;
  const valid =
    summary?.scope === "search" &&
    count(summary.total) &&
    count(summary.locked) &&
    count(summary.unlocked) &&
    roles.every((role) => count(summary.roles?.[role])) &&
    roles.reduce((sum, role) => sum + summary.roles[role], 0) ===
      summary.total &&
    summary.locked + summary.unlocked === summary.total &&
    count(data.total) &&
    data.total <= summary.total &&
    data.page === filters.page &&
    data.page_size === filters.pageSize &&
    data.pages === Math.max(1, Math.ceil(data.total / data.page_size)) &&
    Array.isArray(data.items) &&
    data.items.length <= data.page_size &&
    new Set(data.items.map((item) => item?.id)).size === data.items.length &&
    data.items.every(
      (item) =>
        Number.isSafeInteger(item?.id) &&
        item.id > 0 &&
        typeof item.username === "string" &&
        typeof item.display_name === "string" &&
        typeof item.department === "string" &&
        typeof item.created_at === "string" &&
        Number.isFinite(Date.parse(item.created_at)) &&
        roles.includes(item.role) &&
        typeof item.locked === "boolean" &&
        (!filters.roleFilter || item.role === filters.roleFilter) &&
        (!filters.lockedFilter ||
          item.locked === (filters.lockedFilter === "true")),
    );
  if (!valid)
    throw new ApiError(
      "계정 목록과 전체 집계 응답을 확인할 수 없습니다. 서버 버전을 확인한 뒤 다시 시도해 주세요.",
      0,
      "CONTRACT_ERROR",
    );
  return data;
}
