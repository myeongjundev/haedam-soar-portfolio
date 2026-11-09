import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../components/auth";
import { ErrorBox, Icon } from "../components/ui";
import CityScene from "../components/CityScene";

export default function AuthPage({ register = false }) {
  const { user, login, refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);
  useEffect(() => {
    setError(null);
    setCreated(false);
    refresh();
  }, [register]);
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const form = Object.fromEntries(new FormData(event.currentTarget));
    try {
      if (register) {
        if (form.password !== form.confirm_password)
          throw new Error("비밀번호 확인이 일치하지 않습니다.");
        await api("/auth/register", { method: "POST", data: form });
        setCreated(true);
      } else {
        const u = await login(form);
        const from = location.state?.from;
        navigate(
          from && from.startsWith("/") && !from.startsWith("//")
            ? from
            : u.role === "staff"
              ? "/work"
              : u.role === "admin"
                ? "/admin"
                : "/petitions",
          { replace: true },
        );
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  if (user)
    return (
      <section className="panel auth-card">
        <h1>이미 로그인되어 있습니다</h1>
        <Link to="/" className="button primary">
          홈으로 이동
        </Link>
      </section>
    );
  return (
    <div className="auth-layout">
      <aside>
        <p className="eyebrow">WELCOME TO HAEDAM</p>
        <h1>
          당신의 이야기에
          <br />귀 기울이는 해담.
        </h1>
        <p>
          시민의 목소리로 만드는 더 나은 일상.
          <br />
          해담시청 민원포털에서 시작하세요.
        </p>
        <ul className="auth-benefits">
          <li>
            <Icon name="file" size={19} />
            <span>생활 속 불편을 간편하게 접수</span>
          </li>
          <li>
            <Icon name="clock" size={19} />
            <span>접수부터 완료까지 처리 상태 확인</span>
          </li>
          <li>
            <Icon name="lock" size={19} />
            <span>본인과 권한 있는 담당자만 조회</span>
          </li>
        </ul>
        <div className="auth-city" aria-hidden="true">
          <CityScene />
        </div>
      </aside>
      <section className="panel auth-card">
        <p className="eyebrow">{register ? "CREATE ACCOUNT" : "SIGN IN"}</p>
        <h2>{register ? "시민 회원가입" : "로그인"}</h2>
        <p className="muted">
          {register
            ? "아이디를 만들고 민원 서비스를 이용하세요."
            : "해담시청 민원포털에 오신 것을 환영합니다."}
        </p>
        {created ? (
          <div className="success-box" role="status">
            <Icon name="check" />
            <h3>회원가입이 완료되었습니다</h3>
            <p>가입한 아이디로 로그인해 주세요.</p>
            <Link className="button primary" to="/login">
              로그인하기
            </Link>
          </div>
        ) : (
          <form onSubmit={submit} key={register ? "register" : "login"}>
            <ErrorBox error={error} />
            <label>
              아이디
              <input
                name="username"
                autoComplete="username"
                placeholder="영문 소문자, 숫자, 밑줄"
                required
                minLength={register ? 3 : 1}
                maxLength={40}
                pattern={register ? "[a-z0-9_]{3,40}" : undefined}
              />
            </label>
            {register && (
              <label>
                표시 이름
                <input
                  name="display_name"
                  autoComplete="nickname"
                  required
                  minLength={2}
                  maxLength={30}
                  placeholder="가상 이름을 입력하세요"
                />
              </label>
            )}
            <label>
              비밀번호
              <input
                name="password"
                type="password"
                autoComplete={register ? "new-password" : "current-password"}
                required
                minLength={register ? 10 : 1}
                maxLength={128}
                placeholder={
                  register ? "10자 이상 입력하세요" : "비밀번호를 입력하세요"
                }
              />
            </label>
            {register && (
              <>
                <label>
                  비밀번호 확인
                  <input
                    name="confirm_password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={10}
                    maxLength={128}
                  />
                </label>
                <p className="form-hint">
                  교육용 서비스입니다. 실제 개인정보나 다른 서비스에서 사용하는
                  비밀번호를 입력하지 마세요.
                </p>
              </>
            )}
            <button className="button primary full" disabled={busy}>
              {busy ? "처리 중…" : register ? "가입하기" : "로그인"}
              <Icon name="arrow" size={18} />
            </button>
            <p className="auth-switch">
              {register ? "이미 계정이 있으신가요?" : "처음 방문하셨나요?"}{" "}
              <Link to={register ? "/login" : "/register"}>
                {register ? "로그인" : "회원가입"}
              </Link>
            </p>
          </form>
        )}
      </section>
    </div>
  );
}
