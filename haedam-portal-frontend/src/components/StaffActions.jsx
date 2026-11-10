import { useEffect, useRef, useState } from "react";
import { Icon } from "./ui";
import {
  FieldError,
  FormSummary,
  fieldAttributes,
  validateReply,
} from "./formFeedback";
import { REPLY_OUTLINE, hasReplyPrompts } from "../content/replyGuide";

export default function StaffActions({
  petition,
  user,
  reply,
  onReply,
  busy,
  needsRefresh,
  refreshing,
  onRefresh,
  onMutate,
  feedback,
}) {
  const [review, setReview] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const reviewTitle = useRef(null);
  const editor = useRef(null);
  const own = petition.assignee?.id === user.id;
  const canReply = own && petition.status === "in_progress";
  const disabled = busy || refreshing || needsRefresh;
  useEffect(() => {
    setReview(false);
    setConfirmed(false);
  }, [petition.id, petition.version, needsRefresh]);
  useEffect(() => {
    if (review) reviewTitle.current?.focus();
  }, [review]);
  const edit = () => {
    setReview(false);
    setConfirmed(false);
    requestAnimationFrame(() => editor.current?.focus());
  };
  const inspect = (event) => {
    event.preventDefault();
    if (disabled) return;
    const fields = validateReply(reply);
    if (hasReplyPrompts(reply))
      fields.reply = "구성 틀의 대괄호 안내를 실제 내용으로 바꿔 주세요.";
    if (Object.keys(fields).length) {
      feedback.report(fields, true);
      return;
    }
    feedback.reset();
    setConfirmed(false);
    setReview(true);
  };
  return (
    <section
      className="panel staff-action staff-task-panel"
      id="staff-action"
      tabIndex={-1}
      aria-labelledby="staff-task-title"
    >
      <span className="eyebrow">PROCESS & RESPOND</span>
      <h2 id="staff-task-title">민원 처리</h2>
      <p className="staff-task-reference">
        <Icon name="file" size={17} />
        {petition.reference} · {petition.assignee?.display_name || "배정 대기"}
      </p>
      {needsRefresh && (
        <div className="staff-refresh-warning" role="status">
          <strong>최신 처리 상태를 먼저 확인해 주세요</strong>
          <p>
            변경 충돌이나 요청 오류가 발생했습니다. 초안은 이 화면에 남아
            있습니다. 다시 전송하기 전에 서버 상태를 확인하세요.
          </p>
          <button
            type="button"
            className="button secondary"
            onClick={onRefresh}
            disabled={busy || refreshing}
          >
            {refreshing ? "확인 중…" : "초안 유지하고 최신 상태 확인"}
          </button>
        </div>
      )}
      {petition.status === "completed" ? (
        <p className="staff-complete-note">
          <Icon name="check" size={20} />
          서버에 등록된 답변과 처리 이력을 확인하세요. 완료된 답변은 수정할 수
          없습니다.
        </p>
      ) : !petition.assignee ? (
        <>
          <p>신청 내용을 확인한 뒤 본인에게 배정해 주세요.</p>
          <button
            className="button primary"
            disabled={disabled}
            onClick={() => onMutate("assignment", {})}
          >
            내가 담당하기
          </button>
        </>
      ) : !own ? (
        <p>
          현재 계정이 담당하는 민원이 아닙니다. 목록에서 담당 범위를 확인하세요.
        </p>
      ) : petition.status === "received" ? (
        <>
          <p>접수 내용을 확인한 후 처리 중 상태로 변경하세요.</p>
          <button
            className="button primary"
            disabled={disabled}
            onClick={() =>
              onMutate("status", {
                status: "in_progress",
                version: petition.version,
              })
            }
          >
            처리 시작
          </button>
        </>
      ) : canReply ? (
        <>
          <ol className="reply-steps" aria-label="답변 등록 순서">
            <li aria-current={!review ? "step" : undefined}>1 작성</li>
            <li aria-current={review ? "step" : undefined}>2 확인 후 등록</li>
          </ol>
          {review && !needsRefresh ? (
            <section
              className="reply-review"
              aria-labelledby="reply-review-title"
            >
              <h3 ref={reviewTitle} id="reply-review-title" tabIndex={-1}>
                시민에게 전달할 답변 확인
              </h3>
              <p className="reply-unsent">아직 등록되지 않은 답변입니다.</p>
              <p className="reply-preview">{reply}</p>
              <FormSummary feedback={feedback} />
              <label className="reply-confirmation">
                <input
                  type="checkbox"
                  checked={confirmed}
                  disabled={disabled}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>신청 내용과 실제 조치 결과를 확인했습니다</span>
              </label>
              <p className="field-hint">
                등록하면 처리 완료로 변경되며 시민이 답변을 볼 수 있습니다. 등록
                후에는 수정할 수 없습니다.
              </p>
              <div className="reply-actions">
                <button
                  className="button secondary"
                  type="button"
                  onClick={edit}
                  disabled={busy || refreshing}
                >
                  답변 수정
                </button>
                <button
                  className="button primary"
                  type="button"
                  disabled={disabled || !confirmed}
                  onClick={() => {
                    if (disabled || !confirmed) return;
                    onMutate("status", {
                      status: "completed",
                      reply,
                      version: petition.version,
                    });
                  }}
                >
                  {busy ? "저장 중…" : "답변 등록 및 처리 완료"}
                </button>
              </div>
            </section>
          ) : (
            <form ref={feedback.formRef} noValidate onSubmit={inspect}>
              <FormSummary feedback={feedback} />
              <details className="reply-writing-guide">
                <summary>답변 작성 요령</summary>
                <ul>
                  <li>신청 내용 중 확인한 사실을 정리해 주세요.</li>
                  <li>실제로 한 조치와 결과를 구체적으로 적어 주세요.</li>
                  <li>
                    추가 안내가 필요하면 적고, 없으면 해당 없음을 밝혀 주세요.
                  </li>
                </ul>
                <button
                  type="button"
                  className="button secondary"
                  disabled={disabled || Boolean(reply.trim())}
                  onClick={() => {
                    if (disabled || reply.trim()) return;
                    onReply(REPLY_OUTLINE);
                    feedback.clearField("reply");
                    editor.current?.focus();
                  }}
                >
                  빈 답변에 구성 틀 넣기
                </button>
                <p>
                  이미 쓴 내용은 덮어쓰지 않습니다. 구성 틀은 실제 처리 결과가
                  아닙니다.
                </p>
              </details>
              <label htmlFor="petition-reply">처리 결과 답변</label>
              <textarea
                ref={editor}
                id="petition-reply"
                name="reply"
                value={reply}
                onChange={(event) => {
                  onReply(event.target.value);
                  feedback.clearField("reply");
                }}
                disabled={busy || refreshing}
                {...fieldAttributes("reply", feedback)}
                rows={10}
                required
                minLength={10}
                maxLength={3000}
                placeholder="시민에게 전달할 실제 처리 결과를 작성해 주세요"
              />
              <p id="reply-hint" className="field-hint">
                10~3,000자 · {reply.trim().length.toLocaleString()}자 작성. 확인
                단계에서는 서버에 등록되지 않습니다. 초안 자동 저장은 제공하지
                않습니다.
              </p>
              <FieldError name="reply" feedback={feedback} />
              <button className="button primary" disabled={disabled}>
                답변 내용 확인
                <Icon name="arrow" size={17} />
              </button>
            </form>
          )}
        </>
      ) : null}
      {reply && !canReply && (
        <details className="retained-reply">
          <summary>이 화면에 남아 있는 초안</summary>
          <p>
            현재 서버 답변과 구분해 확인하세요. 이 초안이 저장됐다는 뜻은
            아닙니다.
          </p>
          <p className="reply-preview">{reply}</p>
        </details>
      )}
    </section>
  );
}
