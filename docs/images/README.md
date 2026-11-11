# README 이미지 출처

김명준의 [개인 포트폴리오 PPT r7](../../output/portfolio/김명준-해담시청-SOAR-개인포트폴리오-20261111-r7.pptx)에서 검증한 1280×720 렌더링을 그대로 재사용했습니다. PPT 파일과 실제 캡처 원본은 변경하지 않았습니다. 아래 표의 장 번호는 r7 기준입니다.

| 이미지 | PPT 장 | 종류와 적용 범위 |
| --- | --- | --- |
| [S7 서비스 아키텍처](readme-s7-architecture.png) | 6 | 구성도. 파일 감시·경보 전달·자동 대응·효과 확인 경로 |
| [S7 Docker 망](readme-s7-network.png) | 7 | 11/10 개인 랩 관측 CIDR. 새 설치의 고정 주소가 아님 |
| [호스트 접근 포트](readme-host-ports.png) | 10 | S7·S8·H1 설정 표. 전체 사례의 포트 목록이 아님 |
| [내부 통신 포트](readme-internal-ports.png) | 11 | 로그 수집·대응·저장소 통신 설정 표 |
| [해담 보안 대시보드](readme-security-dashboard.png) | 23 | S12 실제 티켓 화면의 요약 슬라이드. UI MTTD/MTTR 미측정과 외부 검증 수치를 구분 |
| [Wazuh 대시보드](readme-wazuh-dashboard.png) | 24 | 기존 관제 환경의 11/11 실제 Overview 요약. 개인 S7 동일 회차 UI가 아님 |

README의 n8n·Graylog 이미지는 PPT 21·22장에도 쓰인 원본 [n8n 캡처](../evidence/s12-20261111/n8n-respond.jpg)·[Graylog 캡처](../evidence/s12-20261111/graylog-events.jpg)를 직접 참조합니다. [티켓 원본](../evidence/s12-20261111/ticket-restored.jpg)과 [Wazuh 원본](../evidence/wazuh-overview-20261111.jpg)도 보존합니다.

기존 `readme-system.png`, `readme-flow.png`, `readme-pfsense-network.png`는 앞서 README에 반영한 시스템·흐름·S10 망 요약 이미지입니다. 구성 근거와 팀원 제안 출처는 [PPT 작성 기록](../portfolio/README.md), [코드·자료 출처](../sources.md)에 있습니다. 그림 자체만으로 시나리오 통과를 판정하지 않으며, [S12 결과](../s12-results.md)·[S7 결과](../panel-results-20261110.md)의 실행 증적을 함께 봅니다.
