import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { CATEGORIES, Icon, PageTitle } from "../components/ui";
import {
  FieldError,
  FormSummary,
  fieldAttributes,
  useFormFeedback,
  validatePetition,
} from "../components/formFeedback";
import { useUnsavedChanges } from "../components/UnsavedChanges";
import { findServiceGuide } from "../content/serviceGuides";

export default function NewPetition() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const guide = findServiceGuide(params.get("guide"));
  const initialCategory = CATEGORIES.includes(params.get("category"))
    ? params.get("category")
    : guide?.category || "";
  const [values, setValues] = useState({
    category: initialCategory,
    title: "",
    content: "",
  });
  const [agreed, setAgreed] = useState(false),
    [busy, setBusy] = useState(false),
    [submitted, setSubmitted] = useState(false),
    [review, setReview] = useState(false),
    [uncertain, setUncertain] = useState(false);
  const reviewHeading = useRef(null),
    openedReview = useRef(false),
    inFlight = useRef(false),
    unknownResult = useRef(false);
  const feedback = useFormFeedback();
  useEffect(() => {
    if (review) reviewHeading.current?.focus();
    else if (openedReview.current && !Object.keys(feedback.fields).length)
      feedback.formRef.current?.elements.namedItem("title")?.focus();
  }, [review]);
  const dirty =
    !submitted &&
    Boolean(
      values.title ||
      values.content ||
      values.category !== initialCategory ||
      agreed,
    );
  const markSaved = useUnsavedChanges(dirty, busy);
  const change = (event) => {
    const { name, value } = event.target;
    setValues((current) => ({ ...current, [name]: value }));
    feedback.clearField(name);
  };
  const check = (event) => {
    event.preventDefault();
    const fields = validatePetition(values, agreed);
    if (Object.keys(fields).length) {
      feedback.report(fields, true);
      return;
    }
    feedback.reset();
    openedReview.current = true;
    setReview(true);
  };
  const submit = async (event) => {
    event.preventDefault();
    if (!review || inFlight.current || unknownResult.current) return;
    inFlight.current = true;
    setBusy(true);
    feedback.reset();
    try {
      const data = await api("/petitions", { method: "POST", data: values });
      if (!Number.isSafeInteger(data?.id) || data.id <= 0)
        throw new Error("접수 응답을 확인할 수 없습니다.");
      setSubmitted(true);
      markSaved();
      navigate(`/petitions/${data.id}?view=receipt`, { replace: true });
    } catch (error) {
      if (error.status >= 400 && error.status < 500) {
        if (Object.keys(error.fields || {}).length) setReview(false);
        feedback.report(error);
      } else {
        // A lost response may follow a committed write. Do not offer blind retry.
        unknownResult.current = true;
        setUncertain(true);
      }
    } finally {
      setBusy(false);
      inFlight.current = false;
    }
  };
  return (
    <>
      <PageTitle
        eyebrow="NEW PETITION"
        title="민원 신청"
        description={
          uncertain
            ? "접수 여부 확인이 필요합니다. 아래 내용을 보관한 채 나의 민원을 확인해 주세요."
            : review
              ? "내용을 확인한 뒤 최종 접수해 주세요. 아직 접수되지 않았습니다."
              : "생활 속 불편한 점과 해담을 위한 의견을 들려주세요."
        }
      />
      <ol className="submission-steps" aria-label="민원 신청 단계">
        <li
          className={!review ? "current" : "done"}
          aria-current={!review ? "step" : undefined}
        >
          <span>01</span>내용 작성
        </li>
        <li
          className={review ? "current" : ""}
          aria-current={review ? "step" : undefined}
        >
          <span>02</span>입력 내용 확인
        </li>
        <li>
          <span>03</span>접수 확인
        </li>
      </ol>
      {review ? (
        <section
          className="panel submission-review"
          aria-labelledby="review-title"
        >
          <p className="eyebrow">CHECK BEFORE SUBMISSION</p>
          <h2 id="review-title" ref={reviewHeading} tabIndex={-1}>
            {uncertain
              ? "입력 내용을 보관하고 있습니다"
              : "접수할 내용을 확인해 주세요"}
          </h2>
          <p className="review-description">
            수정할 내용이 있으면 ‘내용 수정’으로 돌아갈 수 있습니다. 최종 접수
            후에는 내용을 직접 변경할 수 없습니다.
          </p>
          <form onSubmit={submit} noValidate>
            <FormSummary feedback={feedback} />
            {uncertain && (
              <div
                className="submission-uncertain"
                role="alert"
                tabIndex={-1}
                ref={(node) => node?.focus()}
              >
                <strong>접수 결과를 확인하지 못했습니다.</strong>
                <p>
                  서버에 이미 접수됐을 수 있어 재전송을 중지했습니다. 입력
                  내용은 아래에 남아 있습니다. 새 창에서 나의 민원을 확인해
                  주세요.
                </p>
                <Link
                  className="button secondary"
                  to="/petitions"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  나의 민원 확인 (새 창)
                  <Icon name="arrow" size={17} />
                </Link>
              </div>
            )}
            <dl className="submission-summary">
              <div>
                <dt>민원 분야</dt>
                <dd>{values.category}</dd>
              </div>
              <div>
                <dt>제목</dt>
                <dd>{values.title}</dd>
              </div>
              <div>
                <dt>민원 내용</dt>
                <dd className="review-content">{values.content}</dd>
              </div>
            </dl>
            <p className="review-consent">
              <Icon name="check" size={18} />
              교육용 서비스와 개인정보 미포함 여부를 확인했습니다.
            </p>
            <div className="form-actions">
              <button
                className="button secondary"
                type="button"
                disabled={busy || uncertain}
                onClick={() => {
                  feedback.reset();
                  setReview(false);
                }}
              >
                내용 수정
              </button>
              <button className="button primary" disabled={busy || uncertain}>
                {busy ? "접수 중…" : "최종 접수하기"}
                <Icon name="arrow" size={18} />
              </button>
            </div>
          </form>
        </section>
      ) : (
        <div className="form-layout">
          <section className="panel form-panel">
            <div className="panel-heading">
              <h2>민원 내용 작성</h2>
              <span>
                <span className="required" aria-hidden="true">
                  *
                </span>{" "}
                필수 입력
              </span>
            </div>
            {guide && (
              <div className="mobile-service-guide">
                <strong>선택한 상황 · {guide.label}</strong>
                <span>추천 분야 · {guide.category}</span>
                <details>
                  <summary>작성 요령 보기</summary>
                  <ol>
                    {guide.tips.map((tip) => (
                      <li key={tip}>{tip}</li>
                    ))}
                  </ol>
                  <p>
                    분야는 직접 바꿀 수 있습니다. 실제 개인정보 대신 가상의
                    장소와 상황을 사용해 주세요.
                  </p>
                </details>
              </div>
            )}
            <form ref={feedback.formRef} onSubmit={check} noValidate>
              <FormSummary feedback={feedback} />
              <label htmlFor="petition-category">
                민원 분야{" "}
                <span className="required" aria-hidden="true">
                  *
                </span>
              </label>
              <select
                id="petition-category"
                name="category"
                value={values.category}
                onChange={change}
                required
                disabled={busy}
                {...fieldAttributes("category", feedback)}
              >
                <option value="" disabled>
                  민원 분야를 선택해 주세요
                </option>
                {CATEGORIES.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
              <p id="category-hint" className="field-hint">
                가장 가까운 분야를 선택해 주세요. 해당 분야가 없으면 기타를
                선택하세요.
              </p>
              <FieldError name="category" feedback={feedback} />
              <label htmlFor="petition-title">
                제목{" "}
                <span className="required" aria-hidden="true">
                  *
                </span>
              </label>
              <input
                id="petition-title"
                name="title"
                value={values.title}
                onChange={change}
                placeholder="민원 내용을 한눈에 알 수 있는 제목을 입력해 주세요"
                required
                minLength={5}
                maxLength={120}
                disabled={busy}
                {...fieldAttributes("title", feedback)}
              />
              <p id="title-hint" className="field-hint">
                제목은 5~120자로 입력해 주세요.
              </p>
              <FieldError name="title" feedback={feedback} />
              <label htmlFor="petition-content">
                민원 내용{" "}
                <span className="required" aria-hidden="true">
                  *
                </span>
              </label>
              <textarea
                id="petition-content"
                name="content"
                value={values.content}
                onChange={change}
                rows={10}
                required
                minLength={10}
                maxLength={5000}
                disabled={busy}
                placeholder="어떤 불편이 있으신가요? 장소, 상황, 요청 사항을 구체적으로 작성해 주세요."
                {...fieldAttributes("content", feedback)}
              />
              <div className="field-bottom">
                <span id="content-hint">
                  10~5,000자 · 실제 개인정보를 입력하지 마세요.
                </span>
                <span aria-live="off">
                  {values.content.length.toLocaleString()} / 5,000
                </span>
              </div>
              <FieldError name="content" feedback={feedback} />
              <label className="checkbox-label" htmlFor="petition-consent">
                <input
                  id="petition-consent"
                  name="consent"
                  type="checkbox"
                  checked={agreed}
                  onChange={(e) => {
                    setAgreed(e.target.checked);
                    feedback.clearField("consent");
                  }}
                  required
                  disabled={busy}
                  aria-invalid={Boolean(feedback.fields.consent)}
                  aria-describedby={
                    feedback.fields.consent ? "consent-error" : undefined
                  }
                />
                교육용 서비스임을 확인했으며 실제 개인정보를 포함하지
                않았습니다.
              </label>
              <FieldError name="consent" feedback={feedback} />
              <div className="form-actions">
                <Link className="button secondary" to="/petitions">
                  취소
                </Link>
                <button className="button primary" disabled={busy}>
                  입력 내용 확인
                  <Icon name="arrow" size={18} />
                </button>
              </div>
            </form>
          </section>
          <aside
            className={`form-aside ${guide ? "selected-service-guide" : ""}`}
          >
            {guide ? (
              <>
                <p className="eyebrow">선택한 상황</p>
                <h3>{guide.label}</h3>
                <span className="finder-category">
                  추천 분야 · {guide.category}
                </span>
                <p className="selected-guide-summary">{guide.summary}</p>
                <ol className="selected-guide-tips">
                  {guide.tips.map((tip) => (
                    <li key={tip}>{tip}</li>
                  ))}
                </ol>
                <p className="selected-guide-note">
                  분야는 직접 바꿀 수 있습니다. 가상의 장소와 상황을 사용하고
                  실제 주소·연락처 등 개인정보는 입력하지 마세요.
                </p>
                <Link className="text-link" to="/">
                  홈에서 다른 상황 찾기
                  <Icon name="arrow" size={15} />
                </Link>
              </>
            ) : (
              <>
                <span className="aside-icon">
                  <Icon name="file" size={30} />
                </span>
                <h3>작성 전 확인해 주세요</h3>
                <ul>
                  <li>제목은 5~120자, 내용은 10~5,000자로 작성해 주세요.</li>
                  <li>민원은 본인과 담당자만 확인할 수 있습니다.</li>
                  <li>교육용으로 가상의 장소·상황을 사용해 주세요.</li>
                  <li>첨부파일은 현재 지원하지 않습니다.</li>
                </ul>
              </>
            )}
            <div className="aside-bottom">
              <Icon name="clock" />
              <strong>접수 후에는?</strong>
              <p>나의 민원에서 처리 상태와 담당자 답변을 확인할 수 있습니다.</p>
            </div>
          </aside>
        </div>
      )}
    </>
  );
}
