import { useEffect, useRef, useState } from "react";
import {
  Link,
  useLocation,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../components/auth";
import {
  Badge,
  ErrorBox,
  Icon,
  Loading,
  STATUS,
  formatDate,
} from "../components/ui";
import { useFormFeedback } from "../components/formFeedback";
import StaffActions from "../components/StaffActions";
import { useUnsavedChanges } from "../components/UnsavedChanges";
import PetitionJourney from "../components/PetitionJourney";
import PetitionReceipt from "../components/PetitionReceipt";

export default function PetitionDetail() {
  const [params] = useSearchParams();
  const { id } = useParams(),
    { user } = useAuth(),
    location = useLocation();
  const [data, setData] = useState(null),
    [error, setError] = useState(null),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState(
      location.state?.created ? "민원이 정상적으로 접수되었습니다." : null,
    );
  const [reply, setReply] = useState("");
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const writePending = useRef(false);
  const readGeneration = useRef(0);
  const feedback = useFormFeedback();
  const markSaved = useUnsavedChanges(
    user.role === "staff" && Boolean(reply),
    busy,
  );
  const listPath = user.role === "staff" ? "/work" : "/petitions";
  let returnTo = listPath;
  try {
    const candidate = new URL(
      location.state?.returnTo || listPath,
      window.location.origin,
    );
    if (
      candidate.origin === window.location.origin &&
      candidate.pathname === listPath
    )
      returnTo = candidate.pathname + candidate.search;
  } catch {
    /* Invalid history state falls back to the role's own list. */
  }
  const load = async () => {
    const generation = ++readGeneration.current;
    setError(null);
    setRefreshing(true);
    try {
      const result = await api(`/petitions/${id}`);
      if (generation !== readGeneration.current) return;
      setData(result);
      setNeedsRefresh(false);
      feedback.reset();
    } catch (e) {
      if (generation !== readGeneration.current) return;
      setError(e);
      if (e.status === 403 || e.status === 404) setData(null);
      setNeedsRefresh(true);
    } finally {
      if (generation === readGeneration.current) setRefreshing(false);
    }
  };
  useEffect(() => {
    setData(null);
    setReply("");
    setNeedsRefresh(false);
    setNotice(
      location.state?.created ? "민원이 정상적으로 접수되었습니다." : null,
    );
    feedback.reset();
    load();
    return () => {
      readGeneration.current += 1;
    };
  }, [id]);
  useEffect(() => {
    if (!data || data.id !== Number(id)) return;
    if (!["#staff-action", "#petition-history"].includes(location.hash)) return;
    const target = document.getElementById(location.hash.slice(1));
    target?.scrollIntoView({ block: "start" });
    target?.focus({ preventScroll: true });
  }, [data?.id, id, location.hash]);
  const mutate = async (action, payload) => {
    if (writePending.current || needsRefresh || refreshing) return;
    writePending.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await api(`/petitions/${id}/${action}`, {
        method: "PATCH",
        data: payload,
      });
      setData(result);
      setNotice(
        action === "assignment"
          ? "민원이 나에게 배정되었습니다."
          : result.status === "completed"
            ? "답변을 등록하고 민원 처리를 완료했습니다."
            : "민원 처리를 시작했습니다.",
      );
      if (result.status === "completed") {
        setReply("");
        markSaved();
        feedback.reset();
      }
    } catch (e) {
      setNotice(null);
      if (e.status !== 400 && e.status !== 413) setNeedsRefresh(true);
      if (payload.reply !== undefined) feedback.report(e);
      else setError(e);
    } finally {
      writePending.current = false;
      setBusy(false);
    }
  };
  if (user.role === "citizen" && params.get("view") === "receipt") {
    return (
      <>
        <ErrorBox error={error} retry={load} />
        {data?.id === Number(id) ? (
          <PetitionReceipt petition={data} />
        ) : (
          !error && <Loading />
        )}
      </>
    );
  }
  return (
    <>
      <Link className="back-link" to={returnTo}>
        ← {user.role === "staff" ? "민원 업무" : "나의 민원"} 목록
      </Link>
      {user.role === "citizen" && data?.id === Number(id) && (
        <Link
          className="receipt-detail-link"
          to={`/petitions/${id}?view=receipt`}
        >
          접수 확인서 보기
          <Icon name="file" size={16} />
        </Link>
      )}
      {notice && (
        <div className="notice" role="status">
          <Icon name="check" size={19} />
          {notice}
        </div>
      )}
      <ErrorBox error={error} retry={load} />
      {!data ? (
        error && reply ? (
          <section className="panel staff-task-panel retained-reply">
            <h2>이 화면에 남아 있는 초안</h2>
            <p>
              민원은 다시 조회할 수 없습니다. 아래 내용은 서버 답변이 아닌 이
              화면의 초안입니다.
            </p>
            <p className="reply-preview">{reply}</p>
          </section>
        ) : (
          !error && <Loading />
        )
      ) : (
        <div
          className={`detail-layout ${user.role === "staff" ? "staff-workspace" : ""}`}
        >
          <article className="panel detail-panel">
            <div className="detail-top">
              <span className="reference">{data.reference}</span>
              <Badge status={data.status} />
            </div>
            <h1>{data.title}</h1>
            <PetitionJourney petition={data} staff={user.role === "staff"} />
            <dl className="detail-meta">
              <div>
                <dt>민원 분야</dt>
                <dd>{data.category}</dd>
              </div>
              <div>
                <dt>접수일</dt>
                <dd>{formatDate(data.created_at, true)}</dd>
              </div>
              <div>
                <dt>신청인</dt>
                <dd>{data.applicant.display_name}</dd>
              </div>
              <div>
                <dt>담당자</dt>
                <dd>{data.assignee?.display_name || "배정 대기"}</dd>
              </div>
            </dl>
            <section className="petition-content">
              <h2>신청 내용</h2>
              <p>{data.content}</p>
            </section>
            {data.reply && (
              <section
                className="reply-box"
                id="official-response"
                tabIndex={-1}
              >
                <span className="eyebrow">OFFICIAL RESPONSE</span>
                <h2>
                  <Icon name="check" />
                  담당자 답변
                </h2>
                <p>{data.reply}</p>
                <small>최종 처리일 {formatDate(data.updated_at, true)}</small>
              </section>
            )}
          </article>
          <div className="detail-side">
            {user.role === "staff" && (
              <StaffActions
                petition={data}
                user={user}
                reply={reply}
                onReply={setReply}
                busy={busy}
                needsRefresh={needsRefresh}
                refreshing={refreshing}
                onRefresh={load}
                onMutate={mutate}
                feedback={feedback}
              />
            )}
            <aside
              className="panel timeline-panel"
              id="petition-history"
              tabIndex={-1}
            >
              <h2>민원 처리 과정</h2>
              <p className="muted">접수부터 답변까지 확인하세요.</p>
              <ol className="timeline">
                {data.history.map((h, i) => (
                  <li key={i}>
                    <span
                      className={`timeline-dot ${i === data.history.length - 1 ? "current" : ""}`}
                    >
                      <Icon name="check" size={12} />
                    </span>
                    <strong>
                      {h.from_status === h.to_status
                        ? "담당자 배정"
                        : STATUS[h.to_status]}
                    </strong>
                    <time>{formatDate(h.created_at, true)}</time>
                    <small>{h.actor}</small>
                  </li>
                ))}
              </ol>
              <div className="information-line">
                <Icon name="shield" size={17} />
                {user.role === "staff"
                  ? "서버에 기록된 처리 이력"
                  : "안전하게 보관되는 나의 민원"}
              </div>
            </aside>
          </div>
        </div>
      )}
    </>
  );
}
