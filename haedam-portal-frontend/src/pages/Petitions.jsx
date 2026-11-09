import { useEffect, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import {
  Badge,
  CATEGORIES,
  Empty,
  ErrorBox,
  Icon,
  Loading,
  PageTitle,
  Pagination,
  STATUS,
  formatDate,
} from "../components/ui";

export default function Petitions({ staff = false }) {
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const status = Object.hasOwn(STATUS, params.get("status"))
    ? params.get("status")
    : "";
  const category = CATEGORIES.includes(params.get("category"))
    ? params.get("category")
    : "";
  const q = (params.get("q") || "").slice(0, 100);
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
  const [data, setData] = useState(null),
    [error, setError] = useState(null),
    [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState(q),
    [reload, setReload] = useState(0);
  useEffect(() => {
    setSearchInput(q);
  }, [q]);
  const changeFilters = (changes) => {
    const values = {
      page,
      status,
      category,
      q,
      page_size: pageSize,
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
    let active = true;
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({
      page,
      page_size: pageSize,
      status,
      category,
      q,
    });
    api(`/petitions?${params}`)
      .then((result) => {
        if (active) setData(result);
      })
      .catch((e) => {
        if (active) setError(e);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [status, category, q, page, pageSize, reload]);
  const changeStatus = (value) => {
    changeFilters({ status: value, page: 1 });
  };
  return (
    <>
      <PageTitle
        eyebrow={staff ? "STAFF WORKSPACE" : "MY PETITIONS"}
        title={staff ? "민원 업무" : "나의 민원"}
        description={
          staff
            ? "미배정 민원과 내가 담당하는 민원의 처리 현황을 확인하세요."
            : "시민의 목소리가 어떻게 반영되고 있는지 확인해 보세요."
        }
      >
        {!staff && (
          <Link className="button primary" to="/petitions/new">
            <Icon name="plus" size={18} />
            민원 신청
          </Link>
        )}
      </PageTitle>
      <section
        className={`role-workflow-guide ${staff ? "staff-guide" : "citizen-guide"}`}
        aria-labelledby="workflow-guide-title"
      >
        <span className="workflow-guide-icon">
          <Icon name={staff ? "file" : "heart"} size={26} />
        </span>
        <div>
          <p className="eyebrow">
            {staff ? "YOUR NEXT ACTION" : "MY SERVICE GUIDE"}
          </p>
          <h2 id="workflow-guide-title">
            {staff
              ? "배정부터 답변까지, 순서대로 처리하세요"
              : "접수한 민원의 진행 상황을 한곳에서"}
          </h2>
          <p>
            {staff
              ? "미배정 민원을 선택해 본인에게 배정하고, 처리 시작 후 결과를 답변으로 남기세요."
              : "민원을 선택하면 담당자 배정, 처리 단계와 답변을 확인할 수 있습니다."}
          </p>
        </div>
        <button
          type="button"
          className="button secondary"
          disabled={loading || Boolean(error)}
          onClick={() => changeStatus(staff ? "in_progress" : "completed")}
        >
          {staff ? "진행 중 업무 보기" : "완료된 민원 보기"}
          <Icon name="arrow" size={17} />
        </button>
      </section>
      <p className="summary-scope">
        {staff
          ? "미배정 민원과 내가 담당하는 민원 전체 기준"
          : "본인이 신청한 민원 전체 기준"}{" "}
        · 검색·분야 필터와 별도 집계
      </p>
      <div className="stat-grid">
        {[
          ["", "전체 민원", "file"],
          ["received", "접수 완료", "file"],
          ["in_progress", "처리 중", "clock"],
          ["completed", "처리 완료", "check"],
        ].map(([key, label, icon]) => (
          <button
            key={key}
            className={`stat-card ${status === key ? "selected" : ""}`}
            aria-pressed={status === key}
            onClick={() => changeStatus(key)}
          >
            <span className={`stat-icon ${key}`}>
              <Icon name={icon} />
            </span>
            <span>
              {label}
              <strong>
                {data && !loading && !error
                  ? key
                    ? data.counts[key] || 0
                    : Object.values(data.counts).reduce((a, b) => a + b, 0)
                  : "—"}
                <small>건</small>
              </strong>
            </span>
          </button>
        ))}
      </div>
      <section className="panel list-panel">
        <div className="list-tabs" role="group" aria-label="처리 상태">
          {[["", "전체"], ...Object.entries(STATUS)].map(([key, label]) => (
            <button
              key={key}
              className={status === key ? "active" : ""}
              aria-pressed={status === key}
              onClick={() => changeStatus(key)}
            >
              {label}
            </button>
          ))}
        </div>
        <form
          className="filter-row"
          onSubmit={(event) => {
            event.preventDefault();
            changeFilters({ page: 1, q: searchInput.trim() });
          }}
        >
          <label className="sr-only" htmlFor="category-filter">
            분야
          </label>
          <select
            id="category-filter"
            value={category}
            onChange={(event) => {
              changeFilters({ category: event.target.value, page: 1 });
            }}
          >
            <option value="">전체 분야</option>
            {CATEGORIES.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
          <div className="search-input">
            <Icon name="search" size={18} />
            <label className="sr-only" htmlFor="petition-search">
              민원 제목 검색
            </label>
            <input
              id="petition-search"
              name="q"
              type="search"
              placeholder="민원 제목을 검색하세요"
              maxLength={100}
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
            />
          </div>
          <button className="button secondary">검색</button>
          {(q || category || status) && (
            <button
              type="button"
              className="button secondary"
              onClick={() =>
                changeFilters({ q: "", status: "", category: "", page: 1 })
              }
            >
              초기화
            </button>
          )}
        </form>
        <ErrorBox error={error} retry={() => setReload((v) => v + 1)} />
        {loading ? (
          <Loading />
        ) : (
          !error && (
            <>
              <div className="list-meta">
                총 <strong>{data?.total || 0}</strong>건{" "}
                <span>최근 접수 순</span>
              </div>
              {data?.items.length ? (
                <div className="table-scroll">
                  <table className="petition-table">
                    <thead>
                      <tr>
                        <th>접수 번호</th>
                        <th className="title-column">민원 제목</th>
                        <th>접수일</th>
                        <th>{staff ? "담당자" : "분야"}</th>
                        <th>처리 상태</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((item) => (
                        <tr key={item.id}>
                          <td className="reference">{item.reference}</td>
                          <td>
                            <Link
                              to={`/petitions/${item.id}`}
                              state={{
                                returnTo: location.pathname + location.search,
                              }}
                            >
                              {item.title}
                              <Icon name="arrow" size={15} />
                            </Link>
                            <span className="mobile-meta">
                              {formatDate(item.created_at)} · {item.category}
                            </span>
                            {staff && (
                              <Link
                                className="staff-next-action"
                                to={`/petitions/${item.id}#${item.status === "completed" ? "petition-history" : "staff-action"}`}
                                state={{
                                  returnTo: location.pathname + location.search,
                                }}
                                aria-label={`${item.reference} ${item.status === "completed" ? "처리 기록 확인" : !item.assignee ? "배정하기" : item.status === "received" ? "처리 시작하기" : "답변 작성하기"}`}
                              >
                                {item.status === "completed"
                                  ? "처리 기록 확인"
                                  : !item.assignee
                                    ? "배정하기"
                                    : item.status === "received"
                                      ? "처리 시작하기"
                                      : "답변 작성하기"}
                                <Icon name="arrow" size={15} />
                              </Link>
                            )}
                          </td>
                          <td>{formatDate(item.created_at)}</td>
                          <td>
                            {staff
                              ? item.assignee?.display_name || "배정 대기"
                              : item.category}
                          </td>
                          <td>
                            <Badge status={item.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty
                  action={!staff}
                  title={
                    q || category || status
                      ? "조건에 맞는 민원이 없습니다"
                      : staff
                        ? "대기 중인 민원이 없습니다"
                        : undefined
                  }
                  description={
                    q || category || status
                      ? "검색어나 선택한 분야·처리 상태를 변경해 보세요."
                      : staff
                        ? "새 민원이 접수되면 이곳에서 확인할 수 있습니다."
                        : undefined
                  }
                />
              )}
              <Pagination
                data={data}
                onPage={(value) => changeFilters({ page: value })}
              />
            </>
          )
        )}
      </section>
      <div className="information-line">
        <Icon name="lock" size={17} />
        {staff
          ? "배정 대기 민원을 본인에게 배정한 후 처리해 주세요."
          : "민원은 본인과 권한 있는 담당자만 조회할 수 있습니다."}
      </div>
    </>
  );
}
