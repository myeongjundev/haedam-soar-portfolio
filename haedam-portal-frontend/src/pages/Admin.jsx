import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { readAdminListing } from "../api/adminListing";
import { unlockFalsePositiveUser } from "../api/adminAccounts";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../components/auth";
import {
  ErrorBox,
  Icon,
  Loading,
  PageTitle,
  Pagination,
  ROLE,
} from "../components/ui";

function AccountDialog({ mode, onClose, onSaved }) {
  const dialog = useRef(null);
  const [error, setError] = useState(null),
    [busy, setBusy] = useState(false);
  const [nextRole, setNextRole] = useState(mode.user?.role || "staff");
  useEffect(() => {
    dialog.current.showModal();
  }, []);
  const submit = async (e) => {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      const data = Object.fromEntries(new FormData(e.currentTarget));
      if (mode.type === "create")
        await api("/admin/users", { method: "POST", data });
      else if (mode.type === "reset")
        await api(`/admin/users/${mode.user.id}/reset-password`, {
          method: "POST",
          data,
        });
      else if (mode.type === "unlock")
        await unlockFalsePositiveUser(mode.user.id);
      else
        await api(`/admin/users/${mode.user.id}`, {
          method: "PATCH",
          data: mode.type === "lock" ? { locked: true } : { role: data.role },
        });
      onSaved(
        mode.type === "unlock"
          ? "오탐 확인으로 잠금을 해제했습니다. 기존 비밀번호로 새로 로그인할 수 있습니다."
          : undefined,
      );
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <dialog
      ref={dialog}
      className="modal"
      onCancel={(e) => {
        if (busy) e.preventDefault();
        else onClose();
      }}
      aria-labelledby="dialog-title"
      aria-describedby={
        mode.type === "unlock" ? "unlock-description" : undefined
      }
    >
      <div className="modal-heading">
        <h2 id="dialog-title">
          {mode.type === "create"
            ? "계정 만들기"
            : mode.type === "reset"
              ? "비밀번호 재설정"
              : mode.type === "lock"
                ? "계정 잠금"
                : mode.type === "unlock"
                  ? "오탐 해제(비밀번호 유지)"
                  : "권한 변경"}
        </h2>
        <button
          type="button"
          className="icon-button"
          aria-label="닫기"
          disabled={busy}
          onClick={onClose}
        >
          ×
        </button>
      </div>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        {mode.type === "create" ? (
          <>
            <label>
              아이디
              <input
                name="username"
                required
                pattern="[a-z0-9_]{3,40}"
                minLength={3}
                maxLength={40}
                autoComplete="off"
              />
            </label>
            <label>
              표시 이름
              <input
                name="display_name"
                required
                minLength={2}
                maxLength={30}
              />
            </label>
            <label>
              임시 비밀번호
              <input
                name="password"
                type="password"
                required
                minLength={10}
                maxLength={128}
                autoComplete="new-password"
              />
            </label>
            <label>
              권한
              <select name="role" defaultValue="staff">
                {Object.entries(ROLE).map(([key, value]) => (
                  <option value={key} key={key}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label>
              부서
              <input
                name="department"
                maxLength={40}
                defaultValue="민원행정과"
              />
            </label>
          </>
        ) : (
          <>
            <div className="dialog-account-target">
              <span className="account-monogram" aria-hidden="true">
                {mode.user.display_name.slice(0, 1)}
              </span>
              <div>
                <small>변경 대상 계정</small>
                <strong>{mode.user.display_name}</strong>
                <span>{mode.user.username}</span>
              </div>
              <span className={`role-tag role-${mode.user.role}`}>
                {ROLE[mode.user.role]}
              </span>
            </div>
            <dl
              className="account-change-preview"
              aria-label="저장 시 변경 내용"
            >
              <div>
                <dt>현재</dt>
                <dd>
                  {mode.type === "role"
                    ? ROLE[mode.user.role]
                    : mode.user.locked
                      ? "잠김"
                      : "이용 중"}
                </dd>
              </div>
              <div>
                <dt>저장 후</dt>
                <dd>
                  {mode.type === "role"
                    ? ROLE[nextRole]
                    : mode.type === "lock"
                      ? "잠김"
                      : mode.type === "unlock"
                        ? "잠금 해제 · 비밀번호 유지"
                        : "비밀번호 재설정 · 잠금 해제"}
                </dd>
              </div>
            </dl>
            {mode.type === "reset" ? (
              <>
                <p className="form-hint">
                  새 비밀번호로 재설정한 뒤 잠금을 해제합니다. 기존 세션은
                  복원되지 않습니다.
                </p>
                <label>
                  새 임시 비밀번호
                  <input
                    name="new_password"
                    type="password"
                    required
                    minLength={10}
                    maxLength={128}
                    autoComplete="new-password"
                  />
                </label>
              </>
            ) : mode.type === "unlock" ? (
              <p id="unlock-description">
                오탐으로 확인한 계정의 잠금만 해제합니다. 비밀번호는 유지되며,
                기존 세션은 복원되지 않습니다. 사용자는 새로 로그인해야 합니다.
              </p>
            ) : mode.type === "lock" ? (
              <p>
                계정이 잠기며 현재 로그인한 모든 기기의 세션이 종료됩니다.
                오탐으로 확인되면 비밀번호를 유지하고 해제할 수 있습니다. 침해가
                의심되면 비밀번호를 재설정하세요.
              </p>
            ) : (
              <>
                <label>
                  변경할 권한
                  <select
                    name="role"
                    value={nextRole}
                    onChange={(event) => setNextRole(event.target.value)}
                  >
                    {Object.entries(ROLE).map(([key, value]) => (
                      <option value={key} key={key}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <p className="form-hint">
                  권한을 변경하면 기존 로그인 세션이 종료됩니다.
                </p>
              </>
            )}
          </>
        )}
        <div className="form-actions">
          <button
            className="button secondary"
            type="button"
            disabled={busy}
            onClick={onClose}
          >
            취소
          </button>
          <button
            className={`button ${mode.type === "lock" ? "danger" : "primary"}`}
            disabled={busy}
          >
            {busy
              ? "저장 중…"
              : mode.type === "unlock"
                ? "오탐 확인 후 해제"
                : "확인 및 저장"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

export default function Admin() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const pageValue = Number(params.get("page") || 1);
  const page =
    Number.isSafeInteger(pageValue) && pageValue > 0 && pageValue <= 100000
      ? pageValue
      : 1;
  const sizeValue = Number(params.get("page_size") || 10);
  const pageSize =
    Number.isInteger(sizeValue) && sizeValue >= 1 && sizeValue <= 50
      ? sizeValue
      : 10;
  const q = (params.get("q") || "").trim().slice(0, 40);
  const roleFilter = Object.hasOwn(ROLE, params.get("role"))
    ? params.get("role")
    : "";
  const lockedFilter = ["true", "false"].includes(params.get("locked"))
    ? params.get("locked")
    : "";
  const [data, setData] = useState(null),
    [error, setError] = useState(null),
    [loading, setLoading] = useState(true),
    [reload, setReload] = useState(0),
    [dialog, setDialog] = useState(null),
    [notice, setNotice] = useState(""),
    [searchInput, setSearchInput] = useState(q),
    [dashboard, setDashboard] = useState(null),
    [dashboardError, setDashboardError] = useState(null);
  const changeFilters = (changes) => {
    const values = {
      page,
      page_size: pageSize,
      q,
      role: roleFilter,
      locked: lockedFilter,
      ...changes,
    };
    const next = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
      if (
        value &&
        !(key === "page" && value === 1) &&
        !(key === "page_size" && value === 10)
      )
        next.set(key, String(value));
    }
    setParams(next, { preventScrollReset: true });
  };
  useEffect(() => {
    setSearchInput(q);
  }, [q]);
  useEffect(() => {
    let active = true,
      redirected = false;
    setLoading(true);
    setError(null);
    const filters = { page, pageSize, roleFilter, lockedFilter };
    api(
      `/admin/users?${new URLSearchParams({ page, page_size: pageSize, q, role: roleFilter, locked: lockedFilter })}`,
    )
      .then((result) => {
        if (!active) return;
        const listing = readAdminListing(result, filters);
        if (page > listing.pages) {
          redirected = true;
          changeFilters({ page: listing.pages });
          return;
        }
        setData(listing);
      })
      .catch((e) => {
        if (active) setError(e);
      })
      .finally(() => {
        if (active && !redirected) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [page, pageSize, q, roleFilter, lockedFilter, reload]);
  const loadDashboard = () => {
    setDashboardError(null);
    api("/config")
      .then((r) => setDashboard(r.dashboard_url))
      .catch(setDashboardError);
  };
  useEffect(loadDashboard, []);
  const accounts = data?.items || [];
  return (
    <>
      <div className="admin-workspace-heading">
        <PageTitle
          eyebrow="ADMINISTRATION"
          title="계정 관리"
          description="시민·담당자 계정의 권한과 이용 상태를 관리하세요."
        >
          <button
            className="button primary"
            onClick={() => setDialog({ type: "create" })}
          >
            <Icon name="plus" size={18} />
            계정 만들기
          </button>
        </PageTitle>
      </div>
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <div className="admin-workspace-grid">
        <section
          className="panel admin-guide"
          aria-labelledby="admin-guide-title"
        >
          <span className="eyebrow">ACCOUNT OPERATIONS</span>
          <h2 id="admin-guide-title">계정 관리 안내</h2>
          <p>계정을 찾은 뒤 목록의 관리 메뉴에서 작업하세요.</p>
          <ol className="admin-operation-steps">
            <li>
              <strong>계정 찾기</strong>
              <span>아이디·이름으로 검색하고 대상 계정을 확인합니다.</span>
            </li>
            <li>
              <strong>작업 선택</strong>
              <span>
                권한 변경·잠금·오탐 해제·비밀번호 재설정 중 필요한 작업을
                선택합니다.
              </span>
            </li>
            <li>
              <strong>변경 내용 확인</strong>
              <span>
                저장 전 변경 내용을 확인하세요. 기존 로그인 세션은 종료됩니다.
              </span>
            </li>
          </ol>
        </section>
        <section className="admin-banner" aria-label="보안 관제 서비스">
          <Icon name="shield" size={29} />
          <div>
            <strong>보안 관제 대시보드</strong>
            <p>보안 이벤트와 대응 기록은 별도 관제 서비스에서 확인합니다.</p>
          </div>
          {dashboardError ? (
            <ErrorBox error={dashboardError} retry={loadDashboard} />
          ) : dashboard ? (
            <a
              className="button secondary"
              href={dashboard}
              target="_blank"
              rel="noopener noreferrer"
            >
              대시보드 열기 <Icon name="arrow" size={16} />
            </a>
          ) : (
            <span className="muted">관제 주소 연결 대기</span>
          )}
        </section>
      </div>
      {!loading && !error && data && (
        <section
          className="admin-summary"
          aria-labelledby="admin-summary-title"
        >
          <div className="admin-section-heading">
            <div>
              <span className="eyebrow">ACCOUNT SUMMARY</span>
              <h2 id="admin-summary-title">
                {q ? "검색어에 맞는 전체 계정" : "전체 계정 현황"}
              </h2>
            </div>
            <p>
              검색어 기준 전체 {data.summary.total}개 · 권한·이용 상태 필터 적용
              전
            </p>
          </div>
          <div
            className="stat-grid"
            role="group"
            aria-label="전체 계정 권한 필터"
          >
            {[["", "전체"], ...Object.entries(ROLE)].map(([role, label]) => (
              <button
                type="button"
                key={role}
                className={`stat-card ${roleFilter === role ? "selected" : ""}`}
                aria-pressed={roleFilter === role}
                onClick={() => changeFilters({ role, page: 1 })}
              >
                <span>{label}</span>
                <strong>
                  {role ? data.summary.roles[role] : data.summary.total}
                </strong>
                <small>목록 보기</small>
              </button>
            ))}
          </div>
          <p className="admin-summary-scope">
            이용 중 {data.summary.unlocked}개 · 잠김 {data.summary.locked}개. 각
            수치는 페이지와 권한·이용 상태 선택에 관계없이 검색어 기준입니다.
          </p>
        </section>
      )}
      <section
        className="panel list-panel admin-list"
        aria-labelledby="admin-list-title"
      >
        <div className="admin-section-heading">
          <div>
            <span className="eyebrow">ACCOUNT DIRECTORY</span>
            <h2 id="admin-list-title">계정 목록</h2>
          </div>
          <button
            className="text-button"
            type="button"
            disabled={loading}
            onClick={() => setReload((value) => value + 1)}
          >
            새로고침
          </button>
        </div>
        <form
          className="filter-row"
          onSubmit={(e) => {
            e.preventDefault();
            changeFilters({ q: searchInput.trim(), page: 1 });
          }}
        >
          <div className="search-input">
            <Icon name="search" size={18} />
            <label className="sr-only" htmlFor="user-search">
              계정 검색
            </label>
            <input
              id="user-search"
              name="q"
              type="search"
              maxLength={40}
              placeholder="아이디 또는 이름 검색"
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
            />
          </div>
          <div className="admin-directory-select">
            <label htmlFor="account-status">이용 상태</label>
            <select
              id="account-status"
              value={lockedFilter}
              onChange={(event) =>
                changeFilters({ locked: event.target.value, page: 1 })
              }
            >
              <option value="">전체 상태</option>
              <option value="false">이용 중</option>
              <option value="true">잠김</option>
            </select>
          </div>
          <div className="admin-directory-select admin-page-size">
            <label htmlFor="account-page-size">표시 개수</label>
            <select
              id="account-page-size"
              value={pageSize}
              onChange={(event) =>
                changeFilters({
                  page_size: Number(event.target.value),
                  page: 1,
                })
              }
            >
              {![10, 20, 50].includes(pageSize) && (
                <option value={pageSize}>{pageSize}개</option>
              )}
              {[10, 20, 50].map((size) => (
                <option key={size} value={size}>
                  {size}개
                </option>
              ))}
            </select>
          </div>
          <button className="button secondary">검색</button>
          <button
            className="button secondary"
            type="button"
            onClick={() => {
              setSearchInput("");
              changeFilters({ q: "", role: "", locked: "", page: 1 });
            }}
          >
            초기화
          </button>
        </form>
        <ErrorBox error={error} retry={() => setReload((v) => v + 1)} />
        {loading ? (
          <Loading />
        ) : (
          !error && (
            <>
              <div className="list-meta">
                <span>
                  조건에 맞는 계정 <strong>{data.total}</strong>개 · 현재 페이지
                  표시 <strong>{accounts.length}</strong>개
                </span>
                <span>
                  권한: {ROLE[roleFilter] || "전체"} · 상태:{" "}
                  {lockedFilter === "true"
                    ? "잠김"
                    : lockedFilter === "false"
                      ? "이용 중"
                      : "전체"}
                </span>
              </div>
              <p className="table-scroll-hint" id="account-scroll-hint">
                <Icon name="arrow" size={16} /> 좌우로 밀어 계정 관리 메뉴를
                확인하세요.
              </p>
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="계정 목록"
                aria-describedby="account-scroll-hint"
              >
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th>사용자</th>
                      <th>권한</th>
                      <th>부서</th>
                      <th>상태</th>
                      <th>관리</th>
                    </tr>
                  </thead>
                  <tbody>
                    {accounts.map((u) => (
                      <tr key={u.id}>
                        <td>
                          <strong>{u.display_name}</strong>
                          <small className="block muted">{u.username}</small>
                        </td>
                        <td>
                          <span className={`role-tag role-${u.role}`}>
                            {ROLE[u.role]}
                          </span>
                        </td>
                        <td>{u.department || "—"}</td>
                        <td>
                          <span
                            className={`badge ${u.locked ? "locked" : "completed"}`}
                          >
                            {u.locked ? "잠김" : "이용 중"}
                          </span>
                        </td>
                        <td>
                          {u.id === user.id ? (
                            <span className="muted">내 계정</span>
                          ) : (
                            <div className="row-actions">
                              <button
                                onClick={() =>
                                  setDialog({ type: "role", user: u })
                                }
                              >
                                권한 변경
                              </button>
                              {!u.locked && (
                                <button
                                  className="account-lock-action"
                                  onClick={() =>
                                    setDialog({ type: "lock", user: u })
                                  }
                                >
                                  잠금
                                </button>
                              )}
                              {u.locked && (
                                <button
                                  onClick={() => {
                                    setNotice("");
                                    setDialog({ type: "unlock", user: u });
                                  }}
                                >
                                  오탐 해제(비밀번호 유지)
                                </button>
                              )}
                              <button
                                onClick={() =>
                                  setDialog({ type: "reset", user: u })
                                }
                              >
                                비밀번호 재설정
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {accounts.length === 0 && (
                  <p className="empty">
                    조건에 맞는 계정이 없습니다. 검색어나 권한·이용 상태를
                    변경해 보세요.
                  </p>
                )}
              </div>
              <Pagination
                data={data}
                onPage={(value) => changeFilters({ page: value })}
              />
            </>
          )
        )}
      </section>
      {dialog && (
        <AccountDialog
          mode={dialog}
          onClose={() => setDialog(null)}
          onSaved={(message) => {
            setDialog(null);
            setReload((v) => v + 1);
            setNotice(message || "계정 변경 사항을 저장했습니다.");
          }}
        />
      )}
    </>
  );
}
