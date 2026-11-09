import { useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../components/auth";
import { ErrorBox, Icon, PageTitle, ROLE } from "../components/ui";

export default function Account() {
  const { user, setUser } = useAuth();
  const [error, setError] = useState(null),
    [busy, setBusy] = useState(false),
    [success, setSuccess] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    setError(null);
    setBusy(true);
    setSuccess(false);
    try {
      if (data.new_password !== data.confirm_password)
        throw new Error("새 비밀번호 확인이 일치하지 않습니다.");
      const result = await api("/auth/password", { method: "POST", data });
      setUser(result.user);
      setSuccess(true);
      form.reset();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageTitle
        eyebrow="MY ACCOUNT"
        title="내 계정"
        description="계정 정보를 확인하고 비밀번호를 안전하게 관리하세요."
      />
      <div className="form-layout">
        <section className="panel form-panel">
          <h2>비밀번호 변경</h2>
          <p className="muted">
            변경하면 다른 기기의 로그인 세션이 모두 종료됩니다.
          </p>
          <form onSubmit={submit}>
            <ErrorBox error={error} />
            {success && (
              <div className="notice" role="status">
                비밀번호를 변경했습니다.
              </div>
            )}
            <label>
              현재 비밀번호
              <input
                name="current_password"
                type="password"
                autoComplete="current-password"
                required
                maxLength={128}
              />
            </label>
            <label>
              새 비밀번호
              <input
                name="new_password"
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                required
              />
            </label>
            <label>
              새 비밀번호 확인
              <input
                name="confirm_password"
                type="password"
                autoComplete="new-password"
                minLength={10}
                maxLength={128}
                required
              />
            </label>
            <button className="button primary" disabled={busy}>
              {busy ? "변경 중…" : "비밀번호 변경"}
            </button>
          </form>
        </section>
        <aside className="form-aside">
          <Icon name="user" size={32} />
          <h2>{user.display_name}</h2>
          <p>{user.username}</p>
          <span className="role-tag">{ROLE[user.role]}</span>
          {user.department && <p>{user.department}</p>}
          <p className="form-hint">
            비밀번호는 10자 이상으로 설정해 주세요. 다른 사이트의 비밀번호를
            재사용하지 마세요.
          </p>
        </aside>
      </div>
    </>
  );
}
