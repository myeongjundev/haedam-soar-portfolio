import { Icon } from "./ui";

const steps = ["접수 완료", "담당자 배정", "처리 중", "답변 완료"];

export default function PetitionJourney({ petition, staff }) {
  const current =
    petition.status === "completed"
      ? 3
      : petition.status === "in_progress"
        ? 2
        : petition.assignee
          ? 1
          : 0;
  const guidance = staff
    ? [
        [
          "담당할 민원인지 확인해 주세요",
          "신청 내용을 읽고 본인에게 배정한 뒤 처리를 시작하세요.",
          "배정 메뉴로 이동",
          "staff-action",
        ],
        [
          "배정된 민원의 처리를 시작하세요",
          "접수 내용을 확인한 뒤 ‘처리 시작’을 누르면 처리 중으로 변경됩니다.",
          "처리 메뉴로 이동",
          "staff-action",
        ],
        [
          "처리 결과를 답변으로 남겨 주세요",
          "답변을 등록하면 처리 완료되며 시민이 결과를 확인할 수 있습니다.",
          "답변 작성으로 이동",
          "staff-action",
        ],
        [
          "답변 등록과 처리가 완료되었습니다",
          "등록한 답변과 실제 처리 이력을 확인할 수 있습니다.",
          "처리 이력 보기",
          "petition-history",
        ],
      ]
    : [
        [
          "민원이 접수되었습니다",
          "담당자 배정을 기다리고 있습니다. 배정과 처리 상황은 이 화면에서 확인할 수 있습니다.",
        ],
        [
          "담당자가 배정되었습니다",
          "담당자 배정이 완료되었습니다. 처리가 시작되면 상태가 변경됩니다.",
        ],
        [
          "담당자가 민원을 처리하고 있습니다",
          "처리 결과가 등록되면 이 화면에서 답변을 확인할 수 있습니다.",
        ],
        [
          "민원 처리가 완료되었습니다",
          "아래 담당자 답변에서 처리 결과를 확인해 주세요.",
          "답변 확인하기",
          "official-response",
        ],
      ];
  const [title, description, action, target] = guidance[current];
  return (
    <section className="petition-journey" aria-label="민원 진행 단계">
      <ol className="journey-steps">
        {steps.map((label, index) => (
          <li
            key={label}
            className={
              index < current
                ? "done"
                : index === current
                  ? "current"
                  : "upcoming"
            }
            aria-current={index === current ? "step" : undefined}
          >
            <span className="journey-marker" aria-hidden="true">
              {index < current ? (
                <Icon name="check" size={15} />
              ) : (
                String(index + 1).padStart(2, "0")
              )}
            </span>
            <span>
              {label}
              <small>
                {index < current
                  ? "완료"
                  : index === current
                    ? "현재 단계"
                    : "예정"}
              </small>
            </span>
          </li>
        ))}
      </ol>
      <div className="journey-guidance">
        <Icon name={current === 3 ? "check" : "clock"} size={23} />
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        {action && (
          <a className="journey-action" href={`#${target}`}>
            {action}
            <Icon name="arrow" size={17} />
          </a>
        )}
      </div>
    </section>
  );
}
