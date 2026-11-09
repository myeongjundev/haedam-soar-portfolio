import { useEffect, useRef, useState } from "react";
import { CATEGORIES } from "./ui";

export function validatePetition(values, agreed) {
  const fields = {};
  if (!CATEGORIES.includes(values.category))
    fields.category = "민원 분야를 선택해 주세요.";
  if (values.title.trim().length < 5 || values.title.trim().length > 120)
    fields.title = "제목은 5~120자로 입력해 주세요.";
  if (values.content.trim().length < 10 || values.content.trim().length > 5000)
    fields.content = "민원 내용은 10~5,000자로 입력해 주세요.";
  if (!agreed)
    fields.consent = "교육용 서비스와 개인정보 미포함 여부를 확인해 주세요.";
  return fields;
}
export function validateReply(reply) {
  return reply.trim().length < 10 || reply.trim().length > 3000
    ? { reply: "처리 결과 답변은 10~3,000자로 입력해 주세요." }
    : {};
}
export function useFormFeedback() {
  const formRef = useRef(null),
    summaryRef = useRef(null);
  const [fields, setFields] = useState({}),
    [error, setError] = useState(null),
    [focusRequest, setFocusRequest] = useState(0);
  useEffect(() => {
    if (!focusRequest) return;
    const first = Object.keys(fields)
      .map((name) => formRef.current?.elements.namedItem(name))
      .find(Boolean);
    const target = first || summaryRef.current;
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: "center", behavior: "instant" });
  }, [focusRequest]);
  const report = (errorOrFields, isFields = false) => {
    setFields(isFields ? errorOrFields : errorOrFields.fields || {});
    setError(isFields ? null : errorOrFields);
    setFocusRequest((value) => value + 1);
  };
  const clearField = (name) => {
    setFields((current) => {
      const next = { ...current };
      delete next[name];
      return next;
    });
    setError(null);
  };
  const reset = () => {
    setFields({});
    setError(null);
  };
  return { formRef, summaryRef, fields, error, report, clearField, reset };
}
export function FormSummary({ feedback }) {
  const count = Object.keys(feedback.fields).length;
  return count || feedback.error ? (
    <div
      ref={feedback.summaryRef}
      className="error-box form-error-summary"
      role="alert"
      tabIndex={-1}
    >
      {count
        ? `입력한 내용 중 ${count}곳을 확인해 주세요. 해당 입력란 아래에 안내가 있습니다.`
        : feedback.error.message}
    </div>
  ) : null;
}
export function FieldError({ name, feedback }) {
  return feedback.fields[name] ? (
    <p id={`${name}-error`} className="field-error">
      {feedback.fields[name]}
    </p>
  ) : null;
}
export function fieldAttributes(name, feedback) {
  return {
    "aria-invalid": Boolean(feedback.fields[name]),
    "aria-describedby": `${name}-hint${feedback.fields[name] ? ` ${name}-error` : ""}`,
  };
}
