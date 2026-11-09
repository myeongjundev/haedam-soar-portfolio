import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../components/auth";
import CityScene from "../components/CityScene";
import ServiceFinder from "../components/ServiceFinder";
import {
  Badge,
  CATEGORIES,
  Empty,
  ErrorBox,
  Icon,
  Loading,
  formatDate,
} from "../components/ui";

export default function Home() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const load = () => {
    setError(null);
    api("/petitions?page_size=3").then(setData).catch(setError);
  };
  useEffect(() => {
    if (user && user.role !== "admin") load();
  }, [user?.id]);
  const action =
    user?.role === "staff"
      ? "/work"
      : user?.role === "admin"
        ? "/admin"
        : "/petitions/new";
  const citizen = !user || user.role === "citizen";
  const shortcuts = [
    {
      to: action,
      icon:
        user?.role === "admin"
          ? "user"
          : user?.role === "staff"
            ? "file"
            : "plus",
      title:
        user?.role === "admin"
          ? "계정 관리"
          : user?.role === "staff"
            ? "민원 업무"
            : "민원 신청",
      description:
        user?.role === "admin"
          ? "이용 계정과 권한을 확인하세요"
          : user?.role === "staff"
            ? "접수된 민원을 확인하고 처리하세요"
            : "생활 속 불편과 제안을 전해 주세요",
    },
    {
      to: citizen ? "/petitions" : "/account",
      icon: citizen ? "search" : "user",
      title: citizen ? "나의 민원" : "내 계정",
      description: citizen
        ? "신청 내역과 답변을 확인하세요"
        : "내 정보와 비밀번호를 관리하세요",
    },
  ];
  const categoryDescriptions = [
    "보행로 · 교통 불편",
    "생활 쓰레기 · 환경",
    "공원 이용 · 녹지",
    "시설물 · 생활 안전",
    "생활 지원 · 복지",
    "그 밖의 불편과 제안",
  ];
  return (
    <>
      <section className="hero">
        <div className="hero-content">
          <p className="eyebrow">
            <span className="small-line" /> HAEDAM, TOGETHER
          </p>
          <h1>
            {user?.role === "staff" ? (
              <>
                시민의 요청에 답하는,
                <br />
                <em>민원 업무</em>의 시작.
              </>
            ) : user?.role === "admin" ? (
              <>
                안전한 업무의 시작,
                <br />
                <em>계정과 권한</em>을 한곳에.
              </>
            ) : (
              <>
                시민의 목소리를 담아,
                <br />더 나은 <em>해담</em>으로.
              </>
            )}
          </h1>
          <p className="hero-description">
            {user?.role === "staff" ? (
              <>
                미배정 민원부터 내가 맡은 요청까지.
                <br />
                배정과 처리, 답변을 차례로 이어가세요.
              </>
            ) : user?.role === "admin" ? (
              <>
                계정의 권한과 이용 상태를 확인하고,
                <br />
                변경 내용을 검토한 뒤 관리하세요.
              </>
            ) : (
              <>
                일상 속 작은 불편부터 도시를 바꾸는 제안까지.
                <br />
                해담시청이 듣고, 함께 해결하겠습니다.
              </>
            )}
          </p>
          <div className="hero-actions">
            <Link to={action} className="button primary">
              {user?.role === "staff"
                ? "민원 업무 시작하기"
                : user?.role === "admin"
                  ? "계정 관리하기"
                  : "민원 신청하기"}
              <Icon name="arrow" size={19} />
            </Link>
            <Link
              to={citizen ? "/petitions" : "/account"}
              className="button hero-secondary"
            >
              {citizen ? "나의 민원 조회" : "내 계정 확인"}
              <Icon name={citizen ? "search" : "user"} size={18} />
            </Link>
          </div>
          <span className="hero-note">
            <Icon name="shield" size={15} /> 나의 민원은 안전하게, 처리 과정은
            투명하게
          </span>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="visual-label">
            <span className="visual-mark">H</span> HAEDAM CITY
          </div>
          <p className="visual-title">
            당신의 일상에,
            <br />한 걸음 더 가까이.
          </p>
          <CityScene />
          <span className="visual-caption">시민과 함께 만들어가는 내일</span>
        </div>
      </section>
      <div className="quick-links" aria-label="주요 서비스 바로가기">
        {shortcuts.map((item) => (
          <Link to={item.to} key={item.to}>
            <span className="quick-icon">
              <Icon name={item.icon} size={24} />
            </span>
            <span>
              <strong>{item.title}</strong>
              <small>{item.description}</small>
            </span>
            <Icon name="arrow" size={19} />
          </Link>
        ))}
        <a href="#guide">
          <span className="quick-icon">
            <Icon name="help" size={24} />
          </span>
          <span>
            <strong>이용 안내</strong>
            <small>처음이라면 여기서 시작하세요</small>
          </span>
          <Icon name="arrow" size={19} />
        </a>
      </div>
      {citizen && (
        <ServiceFinder>
          <div className="category-grid">
            {CATEGORIES.map((label, i) => (
              <Link
                key={label}
                to={`/petitions/new?category=${encodeURIComponent(label)}`}
              >
                <span className={`category-icon category-${i}`}>
                  <Icon
                    name={["road", "leaf", "pin", "shield", "heart", "grid"][i]}
                    size={27}
                  />
                </span>
                <strong>{label}</strong>
                <p>{categoryDescriptions[i]}</p>
                <span>
                  민원 신청 <Icon name="arrow" size={13} />
                </span>
              </Link>
            ))}
          </div>
        </ServiceFinder>
      )}
      {user && user.role !== "admin" && (
        <section className="home-section">
          <div className="section-heading">
            <div>
              <p className="eyebrow">MY PETITIONS</p>
              <h2>
                {user.role === "staff"
                  ? "확인할 민원이 있어요"
                  : `${user.display_name} 님의 최근 민원`}
              </h2>
            </div>
            <Link
              className="text-link"
              to={user.role === "staff" ? "/work" : "/petitions"}
            >
              전체 보기 <Icon name="arrow" size={15} />
            </Link>
          </div>
          <div className="panel recent-panel">
            <ErrorBox error={error} retry={load} />
            {!data && !error ? (
              <Loading />
            ) : data?.items.length ? (
              data.items.map((item) => (
                <Link
                  className="recent-row"
                  key={item.id}
                  to={`/petitions/${item.id}`}
                >
                  <span className="recent-category">{item.category}</span>
                  <strong>{item.title}</strong>
                  <time>{formatDate(item.created_at)}</time>
                  <Badge status={item.status} />
                  <Icon name="arrow" size={16} />
                </Link>
              ))
            ) : (
              !error && (
                <Empty
                  action={user.role === "citizen"}
                  title={
                    user.role === "staff"
                      ? "대기 중인 민원이 없습니다"
                      : undefined
                  }
                />
              )
            )}
          </div>
        </section>
      )}
      <section className="guide-section home-section" id="guide">
        <div className="guide-intro">
          <p className="eyebrow">HOW IT WORKS</p>
          <h2>
            신청은 간편하게,
            <br />
            결과는 확실하게.
          </h2>
          <p>
            민원 신청부터 답변 확인까지
            <br />세 단계로 이용해 보세요.
          </p>
          <Link to={action} className="text-link">
            지금 시작하기 <Icon name="arrow" size={16} />
          </Link>
        </div>
        <ol className="steps">
          <li>
            <span>01</span>
            <Icon name="file" size={27} />
            <h3>민원 작성</h3>
            <p>
              분야를 선택하고
              <br />
              불편 사항을 알려 주세요.
            </p>
          </li>
          <li>
            <span>02</span>
            <Icon name="clock" size={27} />
            <h3>담당자 확인</h3>
            <p>
              담당자가 내용을 확인하고
              <br />
              처리를 진행합니다.
            </p>
          </li>
          <li>
            <span>03</span>
            <Icon name="check" size={27} />
            <h3>처리 결과 확인</h3>
            <p>
              나의 민원에서 답변과
              <br />
              처리 결과를 확인하세요.
            </p>
          </li>
        </ol>
      </section>
      <section className="faq-section home-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">HELP & INFORMATION</p>
            <h2>이용 전에 확인해 주세요</h2>
          </div>
        </div>
        <div className="faq-grid">
          <details>
            <summary>다른 시민도 제 민원을 볼 수 있나요?</summary>
            <p>
              민원은 본인과 업무 권한이 있는 담당자만 조회할 수 있습니다. 일반
              게시판처럼 공개되지 않습니다.
            </p>
          </details>
          <details>
            <summary>민원 처리 결과는 어디서 확인하나요?</summary>
            <p>
              로그인 후 ‘나의 민원’에서 신청 내역을 선택하면 현재 상태와
              담당자의 답변, 처리 이력을 확인할 수 있습니다.
            </p>
          </details>
          <details>
            <summary>어떤 정보를 입력하면 되나요?</summary>
            <p>
              현재는 교육용 서비스입니다. 가상의 장소와 상황을 이용하고, 실제
              주민등록번호·연락처·주소 등 개인정보를 입력하지 마세요.
            </p>
          </details>
          <details>
            <summary>접수 후 내용을 수정할 수 있나요?</summary>
            <p>
              처리 이력 보존을 위해 접수한 민원은 직접 수정·삭제할 수 없습니다.
              내용 보완이 필요하면 새 민원에 기존 접수 번호를 적어 주세요.
            </p>
          </details>
        </div>
      </section>
    </>
  );
}
