// Curated educational guidance, not a lookup of other citizens' petitions.
export const SERVICE_GUIDES = [
  {
    id: "lighting",
    label: "가로등이 꺼졌어요",
    category: "안전·시설",
    icon: "shield",
    summary: "어두운 보행로와 조명 시설의 불편을 알려 주세요.",
    tips: [
      "가상의 장소와 조명 시설 위치를 적어 주세요.",
      "불이 꺼진 시간대와 반복되는 상황을 설명해 주세요.",
      "점검·수리 등 필요한 조치를 구체적으로 적어 주세요.",
    ],
  },
  {
    id: "waste",
    label: "쓰레기가 쌓여 있어요",
    category: "환경·청소",
    icon: "leaf",
    summary: "생활 쓰레기와 주변 환경의 불편을 알려 주세요.",
    tips: [
      "가상의 장소와 쓰레기가 쌓인 범위를 적어 주세요.",
      "언제부터 어떤 불편이 있었는지 설명해 주세요.",
      "수거·청소 등 원하는 조치를 적어 주세요.",
    ],
  },
  {
    id: "sidewalk",
    label: "보행로가 파손됐어요",
    category: "도로·교통",
    icon: "road",
    summary: "보행로나 도로 이용 중 불편한 부분을 알려 주세요.",
    tips: [
      "가상의 보행로·도로 위치를 적어 주세요.",
      "파손된 부분과 통행에 생긴 불편을 설명해 주세요.",
      "보수·통행 안내 등 필요한 조치를 적어 주세요.",
    ],
  },
  {
    id: "park",
    label: "공원 이용이 불편해요",
    category: "공원·녹지",
    icon: "pin",
    summary: "공원 시설과 녹지 이용의 불편을 알려 주세요.",
    tips: [
      "가상의 공원 이름과 시설 위치를 적어 주세요.",
      "시설·수목 등의 상태와 이용 중 불편을 설명해 주세요.",
      "시설 점검·환경 정비 등 원하는 개선을 적어 주세요.",
    ],
  },
  {
    id: "welfare",
    label: "생활·복지 이용이 어려워요",
    category: "생활·복지",
    icon: "heart",
    summary: "생활 지원과 복지 이용 과정의 불편을 알려 주세요.",
    tips: [
      "가상의 서비스나 이용 절차를 적어 주세요.",
      "이용 과정에서 어려웠던 점을 설명해 주세요.",
      "안내·절차 개선 등 바라는 내용을 적어 주세요.",
    ],
  },
  {
    id: "other",
    label: "어떤 분야인지 모르겠어요",
    category: "기타",
    icon: "help",
    summary: "분야를 고르기 어렵다면 상황부터 설명해 주세요.",
    tips: [
      "가상의 장소나 상황을 간단히 적어 주세요.",
      "어떤 불편이 있었는지 순서대로 설명해 주세요.",
      "해담시청에 요청할 내용이나 제안을 적어 주세요.",
    ],
  },
];

export function findServiceGuide(id) {
  return SERVICE_GUIDES.find((guide) => guide.id === id);
}

export function guideApplicationPath(guide) {
  return `/petitions/new?${new URLSearchParams({ category: guide.category, guide: guide.id })}`;
}
