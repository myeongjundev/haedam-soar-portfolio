import { api, ApiError } from "./client";

export async function unlockFalsePositiveUser(userId) {
  const user = await api(`/admin/users/${userId}/unlock`, {
    method: "POST",
    data: { reason_code: "false_positive" },
  });
  if (user?.id !== userId || user.locked !== false) {
    throw new ApiError(
      "해제 응답을 확인할 수 없습니다. 계정 목록을 새로고침해 상태를 확인해 주세요.",
      502,
      "CONTRACT_ERROR",
    );
  }
  return user;
}
