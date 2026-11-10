import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./ui";
import {
  SERVICE_GUIDES,
  findServiceGuide,
  guideApplicationPath,
} from "../content/serviceGuides";

export default function ServiceFinder({ children }) {
  const [mode, setMode] = useState("situation"),
    [selected, setSelected] = useState("");
  const guide = findServiceGuide(selected);
  return (
    <section
      className="home-section service-finder"
      aria-labelledby="finder-title"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">FIND YOUR SERVICE</p>
          <h2 id="finder-title">어떤 불편이 있으신가요?</h2>
        </div>
        <span className="muted">
          상황에 맞는 분야와 작성 요령을 찾아보세요.
        </span>
      </div>
      <div className="finder-modes" role="group" aria-label="민원 찾기 방식">
        <button
          type="button"
          aria-pressed={mode === "situation"}
          onClick={() => setMode("situation")}
        >
          <Icon name="help" size={17} />
          상황으로 찾기
        </button>
        <button
          type="button"
          aria-pressed={mode === "category"}
          onClick={() => setMode("category")}
        >
          <Icon name="grid" size={17} />
          분야로 바로 신청
        </button>
      </div>
      {mode === "category" ? (
        children
      ) : (
        <div className="finder-workspace">
          <div
            className="finder-situations"
            role="group"
            aria-label="생활 문제 선택"
          >
            {SERVICE_GUIDES.map((item) => (
              <button
                type="button"
                key={item.id}
                aria-label={item.label}
                aria-pressed={selected === item.id}
                onClick={() => setSelected(item.id)}
              >
                <span className="finder-situation-icon">
                  <Icon name={item.icon} size={23} />
                </span>
                <strong>{item.label}</strong>
                <Icon name="arrow" size={16} />
              </button>
            ))}
          </div>
          <div
            className={`finder-advice ${guide ? "has-selection" : ""}`}
            role="region"
            aria-label="선택한 상황의 작성 안내"
            aria-live="polite"
            aria-atomic="true"
          >
            {guide ? (
              <>
                <span className="finder-category">
                  추천 분야 · {guide.category}
                </span>
                <h3>{guide.label}</h3>
                <p>{guide.summary}</p>
                <ol>
                  {guide.tips.map((tip) => (
                    <li key={tip}>{tip}</li>
                  ))}
                </ol>
                <p className="finder-choice-note">
                  분야는 신청 화면에서 바꿀 수 있습니다. 실제 개인정보 대신
                  가상의 장소와 상황을 사용해 주세요.
                </p>
                <Link
                  className="button primary"
                  to={guideApplicationPath(guide)}
                >
                  이 상황으로 민원 작성
                  <Icon name="arrow" size={17} />
                </Link>
              </>
            ) : (
              <div className="finder-placeholder">
                <span>
                  <Icon name="file" size={30} />
                </span>
                <h3>생활 문제를 골라 주세요</h3>
                <p>
                  추천 분야와 작성 요령을 확인한 뒤<br />
                  민원 신청으로 이어갈 수 있습니다.
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
