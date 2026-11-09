# 원본 출처와 개인 기여

| 원본 | 기준 커밋 | 용도 |
| --- | --- | --- |
| [NoBugs-Aleph/aleph-soar-capstone](https://github.com/NoBugs-Aleph/aleph-soar-capstone) | [3ac60e8](https://github.com/NoBugs-Aleph/aleph-soar-capstone/commit/3ac60e8a1ff11128d0ea352fd9929b99187396c7) | 티켓 저장소, 탐지·대응 설정, 실측 도구 |
| [NoBugs-Aleph/haedam-portal-backend](https://github.com/NoBugs-Aleph/haedam-portal-backend) | [98e549c](https://github.com/NoBugs-Aleph/haedam-portal-backend/commit/98e549c71a766f104b3e6ddccdb4cc94ccf0e8fe) | Flask·DB·마이그레이션·로그·대응 API |
| [NoBugs-Aleph/haedam-portal-frontend](https://github.com/NoBugs-Aleph/haedam-portal-frontend) | [994fc45](https://github.com/NoBugs-Aleph/haedam-portal-frontend/commit/994fc45da2439cc3f819624eef251ce5fed347a1) | React 시민·담당자·관리자 화면 |

김명준은 팀에서 React·Flask 포털 구현과 B 시나리오 S8·S10의 시험 입력, 차단 효과 확인, 원복 검증을 담당했습니다. 기능별 출처는 README 팀원 표와 반입 PR에 기록합니다. 팀의 수치는 팀 시험 날짜와 환경을 붙이고, 개인 수치는 이 저장소에서 다시 확인한 결과만 적습니다.

원본은 비공개 저장소입니다. 배포 범위를 정할 때 팀의 공개 범위와 평가자 접근을 확인합니다. [팀 공개 정책](https://github.com/NoBugs-Aleph/aleph-soar-public/blob/main/docs/publication-policy.md)

## 반입 경로

| 경로 | 파일과 작성·기여 출처 |
| --- | --- |
| `haedam-portal-backend/`, `haedam-portal-frontend/` | 김명준 주도 포털 구현과 두 팀 레포의 병합 변경. 각각 상단 기준 커밋의 앱·계약·테스트 |
| `services/ticket-store/` | 김상혁의 티켓 저장소와 보안 대시보드 |
| `infra/graylog/`, `infra/n8n/` | 김대훈의 관제 배치, 파이프라인과 n8n 워크플로. 팀 Compose는 `compose.team.yaml`로 보존 |
| `lab/s1s4/`, `tools/s1_input_probe.py` | 반소람의 S1·S4 탐지·실측, 김명준의 시험 입력·복구 검증 지원 |
| `lab/s7/` | 김상혁의 변조·복구 도구와 Wazuh 활성 대응, 김대훈의 경보 중계 연결 |
| `lab/s8s10/`, `tools/s8s10_input.py` | 김명준의 S8·S10 입력·검증과 김대훈의 Graylog 탐지·알림 |
| `lab/s12/`, `tools/s12_*.py` | 김대훈의 S12 관제·실측과 김명준의 비교 입력·검사 지원 |
| `contracts/` | 팀 공통 이벤트·포털·티켓 계약과 합성 예시 |

팀 VPN 주소는 문서용 IP로, 워크플로의 서비스 URL은 개인 Compose용 DNS 이름으로 치환했습니다. n8n 자격증명 참조 ID와 이름은 개인 랩에서 다시 연결할 자리표시자로 바꿨습니다. 워크플로는 비활성 상태로 보존했습니다. 기존 Graylog 콘텐츠 팩, Wazuh 배포 규칙, pfSense 설정 백업과 팀 최종 PPT는 별도 확보 대상으로 기록합니다.

## 개인 기여와 검증 근거

| 범위 | 확인된 내용 | 근거 |
| --- | --- | --- |
| 김명준 팀 담당 · 포털 | React·Flask 민원포털 구현, 서버 세션·권한, 앱 이벤트·IP 대응 경로 | 위 프론트·백엔드 기준 커밋과 [백엔드 테스트](../haedam-portal-backend/tests) |
| 김명준 팀 담당 · S8/S10 | 공격 입력 도구, 차단 효과와 원복 검증. S10 팀 시험에서 PF 차단 중 새 연결 timeout → PF만 해제한 뒤 포털 403 → 포털 해제 후 정상 접근·활성 조치 0 확인 | [S8/S10 입력 반입 PR](https://github.com/NoBugs-Aleph/aleph-soar-capstone/pull/131), [팀 발표 대본](https://github.com/NoBugs-Aleph/aleph-soar-capstone/blob/7155489/team_docs/%EB%B0%9C%ED%91%9C-%EB%8C%80%EB%B3%B8.md) |
| 팀 공통 구현 | Wazuh·S7, 티켓 저장소, Graylog·n8n 연동, S1/S4/S12의 담당과 반입 경로 | [반입 경로](#반입-경로), [팀 시나리오와 담당](https://github.com/NoBugs-Aleph/aleph-soar-public/blob/main/docs/scenarios.md) |
| 개인 전환 · P01 | 팀 코드 출처 고정, 웹·DB의 Compose 기동과 마이그레이션, 합성 가입·로그인과 재시작 후 세션 유지 | [11/9 작업일지](../work-log/members/myeongjundev/2026-11-09.md), [개인 P01 PR](https://github.com/myeongjundev/haedam-soar-portfolio/pull/1) |
