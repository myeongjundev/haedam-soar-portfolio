import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { ErrorBox, Icon, ROLE } from "./ui";
import { useLeaveConfirmation } from "./UnsavedChanges";

export default function Layout() {
  const { user, logout } = useAuth();
  const requestLeave = useLeaveConfirmation();
  const [error, setError] = useState(null);
  const location = useLocation();
  const first = useRef(true);
  useEffect(() => {
    setError(null);
    if (first.current) first.current = false;
    else
      document.querySelector("#main-content")?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [location.pathname]);
  const signOut = () =>
    requestLeave(async () => {
      try {
        await logout();
      } catch (e) {
        setError(e);
      }
    });
  return (
    <>
      <a className="skip-link" href="#main-content">
        본문 바로가기
      </a>
      <div className="official-strip">
        <div className="container">
          <span>
            <span className="tiny-mark">H</span> 해담시청 민원포털
          </span>
          <span>본 서비스는 가상 도시의 교육용 프로젝트입니다.</span>
        </div>
      </div>
      <header className="header">
        <div className="container header-main">
          <Link to="/" className="brand" aria-label="해담시청 민원포털 홈">
            <img src="/favicon.svg" alt="" />
            <span>
              해담시청<small>시민의 목소리를 담다</small>
            </span>
          </Link>
          <div className="header-right">
            {user ? (
              <>
                <span className="user-name">
                  {user.display_name} 님{" "}
                  <span className="role-tag">{ROLE[user.role]}</span>
                </span>
                <Link to="/account" className="account-link">
                  내 계정
                </Link>
                <button className="text-button" onClick={signOut}>
                  로그아웃
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="account-link">
                  로그인
                </Link>
                <Link to="/register" className="register-link">
                  회원가입 <Icon name="arrow" size={15} />
                </Link>
              </>
            )}
          </div>
        </div>
        <nav className="container nav" aria-label="주 메뉴">
          <NavLink to="/" end>
            민원 안내
          </NavLink>
          {(!user || user.role === "citizen") && (
            <>
              <NavLink to="/petitions/new">민원 신청</NavLink>
              <NavLink to="/petitions" end>
                나의 민원
              </NavLink>
            </>
          )}
          {user?.role === "staff" && <NavLink to="/work">민원 업무</NavLink>}
          {user?.role === "admin" && <NavLink to="/admin">계정 관리</NavLink>}
          <a href="/#guide">이용 안내</a>
          <span className="nav-caption">
            <span className="live-dot" /> 시민과 함께 만드는 해담
          </span>
        </nav>
      </header>
      <main id="main-content" tabIndex="-1" className="container main">
        <ErrorBox error={error} />
        <Outlet />
      </main>
      <footer className="footer">
        <div className="container footer-main">
          <div>
            <strong>해담시청</strong>
            <p>시민의 작은 목소리가, 더 나은 해담의 시작입니다.</p>
            <small>가상 공공기관 · NoBugs ALEPH 교육용 프로젝트</small>
          </div>
          <div>
            <strong>민원 이용 안내</strong>
            <p>신청 내역과 처리 결과는 나의 민원에서 확인하세요.</p>
            <small>실제 개인정보를 입력하지 마세요.</small>
          </div>
        </div>
        <div className="container footer-bottom">
          © 2026 HAEDAM CITY. <span>시민의 목소리를 담다, 해담시청.</span>
        </div>
      </footer>
    </>
  );
}
