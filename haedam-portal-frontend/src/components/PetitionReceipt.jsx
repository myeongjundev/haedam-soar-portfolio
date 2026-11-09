import { Link } from "react-router-dom";
import { useEffect, useRef } from "react";
import { Icon } from "./ui";

export default function PetitionReceipt({ petition }) {
  const heading = useRef(null);
  useEffect(() => {
    heading.current?.focus();
    window.scrollTo(0, 0);
  }, [petition.id]);
  const receivedAt = new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(new Date(petition.created_at));
  return (
    <div className="receipt-layout">
      <div className="receipt-screen-heading no-print">
        <span className="receipt-success">
          <Icon name="check" size={26} />
        </span>
        <div>
          <p className="eyebrow">PETITION RECEIPT</p>
          <h1 ref={heading} tabIndex={-1}>
            접수 내역을 확인해 주세요
          </h1>
          <p>
            저장된 민원 정보를 불러왔습니다. 진행 상황과 답변은 민원 상세에서
            확인할 수 있습니다.
          </p>
        </div>
      </div>
      <article className="receipt-sheet" aria-labelledby="receipt-title">
        <div className="receipt-brand">
          <img src="/favicon.svg" alt="" />
          <div>
            <strong>해담시청</strong>
            <span>시민의 목소리를 담다</span>
          </div>
          <span className="receipt-education">교육용 확인서</span>
        </div>
        <h2 id="receipt-title">민원 접수 확인서</h2>
        <p className="receipt-reference">
          접수 번호<strong>{petition.reference}</strong>
        </p>
        <dl className="receipt-information">
          <div>
            <dt>접수 시각</dt>
            <dd>{receivedAt} (KST)</dd>
          </div>
          <div>
            <dt>신청인</dt>
            <dd>{petition.applicant.display_name}</dd>
          </div>
          <div>
            <dt>민원 분야</dt>
            <dd>{petition.category}</dd>
          </div>
          <div>
            <dt>제목</dt>
            <dd>{petition.title}</dd>
          </div>
        </dl>
        <section className="receipt-content">
          <h3>신청 내용</h3>
          <p>{petition.content}</p>
        </section>
        <div className="receipt-note">
          <strong>접수 후에는</strong>
          <p>
            나의 민원에서 담당자 배정, 처리 상태와 답변을 확인하세요. 이
            확인서는 민원 접수 기록이며 처리 완료를 뜻하지 않습니다.
          </p>
        </div>
        <footer className="receipt-document-footer">
          가상 도시 해담시청 · NoBugs ALEPH 교육용 프로젝트
          <br />본 확인서는 교육용이며 실제 행정기관의 증명서가 아닙니다.
        </footer>
      </article>
      <div className="receipt-actions no-print">
        <Link className="button primary" to={`/petitions/${petition.id}`}>
          진행 상황 확인
          <Icon name="arrow" size={17} />
        </Link>
        <button
          className="button secondary"
          type="button"
          onClick={() => window.print()}
        >
          접수 확인서 인쇄
        </button>
        <Link className="text-link" to="/petitions/new">
          다른 민원 신청
        </Link>
      </div>
      <p className="receipt-print-hint no-print">
        인쇄 창에서 PDF 저장을 선택할 수 있습니다. 확인서가 필요한 경우 본인
        기기에 보관해 주세요.
      </p>
    </div>
  );
}
