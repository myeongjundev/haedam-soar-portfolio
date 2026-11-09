import { Link } from "react-router-dom";

export const STATUS = {
  received: "접수 완료",
  in_progress: "처리 중",
  completed: "처리 완료",
};
export const ROLE = { citizen: "시민", staff: "담당자", admin: "관리자" };
export const CATEGORIES = [
  "도로·교통",
  "환경·청소",
  "공원·녹지",
  "안전·시설",
  "생활·복지",
  "기타",
];
export function Icon({ name = "arrow", size = 22, ...props }) {
  const paths = {
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    plus: <path d="M12 5v14M5 12h14" />,
    file: (
      <>
        <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
        <path d="M14 3v6h6M8 13h8M8 17h5" />
      </>
    ),
    search: (
      <>
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="m16 16 5 5" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    shield: (
      <>
        <path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    user: (
      <>
        <circle cx="12" cy="8" r="4" />
        <path d="M4 21v-2a8 8 0 0 1 16 0v2" />
      </>
    ),
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    home: (
      <>
        <path d="m3 10 9-7 9 7v11H3zM9 21v-8h6v8" />
      </>
    ),
    pin: (
      <>
        <path d="M20 10c0 6-8 11-8 11S4 16 4 10a8 8 0 1 1 16 0Z" />
        <circle cx="12" cy="10" r="2.5" />
      </>
    ),
    leaf: (
      <>
        <path d="M20 3S4 2 4 13a7 7 0 0 0 12 5c5-5 4-15 4-15ZM4 21 16 9" />
      </>
    ),
    road: (
      <>
        <path d="m7 3-4 18M17 3l4 18M12 3v3m0 4v4m0 4v3" />
      </>
    ),
    heart: (
      <path d="M20 5c-3-3-7-1-8 2-1-3-5-5-8-2s-1 7 1 9l7 7 7-7c2-2 4-6 1-9Z" />
    ),
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" />
      </>
    ),
    help: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M9.5 8a2.5 2.5 0 1 1 3 3.5L12 13M12 16v.5" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {paths[name] || paths.file}
    </svg>
  );
}
export function Badge({ status }) {
  return <span className={`badge ${status}`}>{STATUS[status] || status}</span>;
}
export function ErrorBox({ error, retry }) {
  return error ? (
    <div className="error-box" role="alert">
      <span>{error.message || error}</span>
      {retry && (
        <button className="text-button" onClick={retry}>
          다시 시도
        </button>
      )}
    </div>
  ) : null;
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      불러오는 중입니다
    </div>
  );
}
export function Empty({
  title = "아직 신청한 민원이 없어요",
  description = "생활 속 불편한 점이나 더 나은 해담을 위한 의견을 알려 주세요.",
  action = true,
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name="file" size={32} />
      </span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action && (
        <Link className="button primary" to="/petitions/new">
          첫 민원 신청하기 <Icon name="plus" size={17} />
        </Link>
      )}
    </div>
  );
}
export function PageTitle({ eyebrow, title, description, children }) {
  return (
    <div className="page-title">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}
export function Pagination({ data, onPage }) {
  return data && data.pages > 1 ? (
    <nav className="pagination" aria-label="페이지 선택">
      <button disabled={data.page <= 1} onClick={() => onPage(data.page - 1)}>
        이전
      </button>
      <span>
        {data.page} / {data.pages}
      </span>
      <button
        disabled={data.page >= data.pages}
        onClick={() => onPage(data.page + 1)}
      >
        다음
      </button>
    </nav>
  ) : null;
}
export function formatDate(value, full = false) {
  return new Intl.DateTimeFormat("ko-KR", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    ...(full ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(new Date(value));
}
