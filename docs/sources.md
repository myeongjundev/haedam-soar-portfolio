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
| `lab/pfsense/`, `tools/build_pfsense_bundle.py`, `contracts/pfsense-*`, `tests/test_pfsense_*` | 김명준(B)의 S10 pfSense 제한 대응 도구와 설치 번들. 팀 저장소 `94451bf`(`codex/pf-reconcile-1103`, 팀 main 미병합 후보)를 수정 없이 반입했습니다. 장비 실측은 아직 없습니다 |
| `infra/pfsense/`, `compose.pf.yaml`, `tools/pf_*.py`, `tests/test_pf_config.py` | Claude의 개인 QEMU pfSense 랩 준비(WIP). [인수인계](s10-handoff-20261109.md) |

팀 VPN 주소는 문서용 IP로, 워크플로의 서비스 URL은 개인 Compose용 DNS 이름으로 치환했습니다. n8n 자격증명 참조 ID와 이름은 개인 랩에서 다시 연결할 자리표시자로 바꿨습니다. 워크플로는 비활성 상태로 보존했습니다. 기존 Graylog 콘텐츠 팩, Wazuh 배포 규칙, pfSense 설정 백업과 팀 최종 PPT는 별도 확보 대상으로 기록합니다.

개인 랩에서 만든 관제 Compose와 스모크 콘텐츠 팩은 팀 버전을 기준으로 새 볼륨·내부 DNS에서 검증했습니다. 콘텐츠 팩은 팀 n8n 수신 확인 워크플로를 사용합니다. [개인 관제 Docker 설치](docker-soc.md)

개인 S8에서는 팀 워크플로 7개의 필요한 연결을 `tools/build_s8_workflows.py`로 교정해 `infra/n8n/portfolio-s8/`에 생성합니다. 김명준·Codex의 추가 범위는 전용 Docker 네트워크, 배포·자격증명 연결, 대상·원복 티켓 회차 제한, 실패 HTTP 상태, 실행 payload 저장 제한과 실제 클라이언트 검증 도구입니다. 팀 JSON과 포털·티켓 코어 구현의 출처는 유지합니다. Discord 외부 발송은 개인 배포에서 사용하지 않습니다. [S8 설치·변경 범위](s8-lab.md)

## 개인 기여와 검증 근거

11/11 개인 S12의 `infra/s12-*.json`, `infra/n8n/s12-src/`, `infra/n8n/portfolio-s12/`, `infra/graylog/portfolio-s12.json`, `services/s12-target/`, 새 `tools/s12_{settings,lab,client,runtime,configure,measure}.py`, `tools/build_s12_workflows.py`와 S12 테스트는 김명준·Codex의 후속 구현입니다. 김대훈의 팀 S12 요청 수/기준선 정책, 검토된 개인 S1 티켓·포털 하위 흐름, 김상혁의 티켓 저장소를 사용합니다. 기존 `lab/s12/`의 팀 자료는 그대로 보존했습니다. 실제 기준선, 정상 서비스 무대응, 통제된 자원 경합에서 차단·정상 대조·동일 티켓 원복을 확인했습니다. 운영 DDoS 성능 시험은 아닙니다. [개인 결과](s12-results.md).

PPT r6의 추가 S4/S12 실측 장과 n8n·Graylog·해담 보안 대시보드 이미지는 김명준·Codex의 개인 결과입니다. 기존 팀원 아이디어와 원본 출처 표시는 유지하고, 실제 캡처와 노드 요약 도식을 구분했습니다. [편집·검증 내역](portfolio/README.md).

11/10 후속 개인 S1 실측은 [결과·실패 수정·환경 재개 기록](s1-results.md)에 있습니다. 김명준·Codex가 관리 bridge 설정과 n8n 하위 흐름의 반환 경로를 수정하고, 실제 9회 실패 → 탐지 → 차단·티켓 → 정상 로그인 → 원복을 확인했습니다. 아래 S1 문단의 오프라인/미실측 설명은 각 반입 단계 당시의 범위이며, 팀 S1 정책·원본 작성자의 기여는 유지합니다.

PR #20 이후 `tools/s1_rehearsal.py`, `tools/s1_probe.py`, `tools/s1_evidence.py`와 연결 테스트·실측 절차는 김명준·Codex의 개인 후속 준비입니다. 팀 S1 규칙, 기존 입력기·포털·티켓 계약을 그대로 사용하며 정상 합성 계정 로그인, 개인 import 파일 생성, 회차별 증적 대조를 추가했습니다. 실제 엔진 실행 결과로 표시하지 않습니다. [S1 실측 준비](s1-live-preparation.md).

PR #17/#18 검토 인계 후 S1·S4 티켓 응답 소비 수정과 `tests/generated_workflow_rpc.cjs`, 포털 `tests/test_workflow_store_contract.py`는 김명준·Codex의 후속 작업입니다. 저장소 API를 변경하지 않고 실제 반환 필드에 맞춰 소비자·테스트 모델을 교정했습니다. Claude의 독립 승인이나 실제 n8n 실측으로 표시하지 않습니다. [실패 재현과 검토 기록](s1-s4-review-20261110.md).

개인 S4의 `infra/s4-*.json`, `infra/n8n/s4-src/`, `infra/n8n/portfolio-s4/`, `infra/graylog/portfolio-s4.json`, `tools/*s4*`, 포털 `integration/s4_accounts.py`·소유권 모델/마이그레이션은 김명준·Codex의 후속 구현입니다. 반소람의 팀 S4 집계 기준과 김대훈의 티켓 하위 워크플로 10번, 김상혁의 티켓 저장소 계약을 사용합니다. PR #18 `40e180b`의 오프라인 S1 구조를 별도 파일로 확장하여 계정 ID·티켓 소유권·키 분리·세션 회수·오탐 해제를 추가했습니다. 팀 원본과 S1 구현은 수정하지 않았으며 개인 실제 배포·실측은 아직 아닙니다. [변경 범위와 검증 경계](s4-auto-workflows.md).

개인 S1 자동 대응의 `infra/n8n/s1-src/`, `infra/n8n/portfolio-s1/`, `infra/graylog/portfolio-s1.json`, `infra/s1-integration-settings.json`, `tools/build_s1_workflows.py`는 김명준·Codex의 후속 구현입니다. 반소람의 팀 S1 집계 기준과 김대훈의 n8n 티켓/포털 하위 워크플로를 유지·분리하고, 개인 대상 제한·계정+IP 묶음·티켓 선기록·소유권/현재 상태 대조·운영자 원복을 추가했습니다. 원본 10/12는 수정하지 않고 생성기로 파생합니다. 오프라인 검증이며 개인 실측 완료가 아닙니다. [구성과 검증 경계](s1-auto-workflows.md).

개인 S1의 `infra/s1-settings.json`, `tools/s1_settings.py`, `tools/s1_lab.py`, `tools/s1_client.py`, `tests/test_s1_personal.py`는 김명준·Codex의 후속 구현입니다. 반소람의 팀 S1 탐지 기준과 김명준의 기존 Kali 입력 도구를 참고해, 개인 Docker 클라이언트의 실제 소켓 출발지·요청 상한·중지·비밀정보 없는 입력 증적을 구현했습니다. 팀 S1 JSON과 기존 도구는 보존했습니다. Graylog/n8n 실제 연결이나 개인 차단·원복 완료를 의미하지 않습니다. [구현 범위](s1-personal-prep.md).

개인 S7 자동 연결의 `compose.s7-auto.yaml`, `services/s7-response/`, `infra/wazuh/agent/s7_guard.py`, `tools/*s7_auto*`, `infra/n8n/portfolio-s7/`, `infra/graylog/s7-fim.json`은 김명준·Codex의 후속 구현입니다. 김상혁의 파일 복구 함수를 그대로 호출하며 팀 티켓 저장소에는 완료 조치 이름과 활성 조치/대시보드 판정 일치 수정만 추가했습니다. [설치와 범위](s7-auto-lab.md), [개인 연결 계약](s7-auto-contract.md). 반소람 님의 제어판 소개 HTML은 후속 UI 흐름 참고이며 실제 제어판 소스나 팀원 실측으로 반입하지 않았습니다.

개인 S7의 `compose.s7.yaml`, `infra/wazuh/`, `tools/s7_lab.py`, `tools/s7_verify.py`는 김명준·Codex의 컨테이너 배치와 재실측 추가입니다. 김상혁의 `lab/s7/restore/` 두 실행 파일은 수정하지 않고 컨테이너 경로 환경변수로 사용합니다. Wazuh 설정은 [wazuh/wazuh-docker v4.9.0](https://github.com/wazuh/wazuh-docker/tree/cb63566719ce2e78b9d3c111a0a61d743fc699fc/single-node)의 indexer/dashboard/certs 설정을 반입·조정했습니다. 라이선스와 저작권 고지는 `infra/wazuh/LICENSE.upstream`에 보존했습니다. 개인 결과는 [S7 실측](s7-results.md)이며 팀의 n8n 자동 대응 실측을 대신하지 않습니다.

H1 아이디어(민원 도배 탐지와 계정의 작성만 제한)는 반소람(whiteclover0542)이 2026-11-09 공유한 `MVP-설계.md` 7절·구현계획·진행 현황에서 채택했습니다. 해당 문서의 개인 경로·계정·환경 설정·성과는 김명준의 것으로 옮기지 않았습니다. `infra/n8n/portfolio-h1/`, `infra/graylog/h1-petition-flood.json`, `tools/*h1*`, 포털 제한 API·마이그레이션과 H1 계약/검증기는 김명준·Codex의 개인 후속 구현입니다. 김상혁의 티켓 저장소에는 H1 검증·목록·카드를 추가했으며 원본 출처를 유지합니다. [H1 작업과 인수 조건](h1-task.md).

| 범위 | 확인된 내용 | 근거 |
| --- | --- | --- |
| 김명준 팀 담당 · 포털 | React·Flask 민원포털 구현, 서버 세션·권한, 앱 이벤트·IP 대응 경로 | 위 프론트·백엔드 기준 커밋과 [백엔드 테스트](../haedam-portal-backend/tests) |
| 김명준 팀 담당 · S8/S10 | 공격 입력 도구, 차단 효과와 원복 검증. S10 팀 시험에서 PF 차단 중 새 연결 timeout → PF만 해제한 뒤 포털 403 → 포털 해제 후 정상 접근·활성 조치 0 확인 | [S8/S10 입력 반입 PR](https://github.com/NoBugs-Aleph/aleph-soar-capstone/pull/131), [팀 발표 대본](https://github.com/NoBugs-Aleph/aleph-soar-capstone/blob/7155489/team_docs/%EB%B0%9C%ED%91%9C-%EB%8C%80%EB%B3%B8.md) |
| 팀 공통 구현 | Wazuh·S7, 티켓 저장소, Graylog·n8n 연동, S1/S4/S12의 담당과 반입 경로 | [반입 경로](#반입-경로), [팀 시나리오와 담당](https://github.com/NoBugs-Aleph/aleph-soar-public/blob/main/docs/scenarios.md) |
| 개인 전환 · P01 | 팀 코드 출처 고정, 웹·DB의 Compose 기동과 마이그레이션, 합성 가입·로그인과 재시작 후 세션 유지 | [11/9 작업일지](../work-log/members/myeongjundev/2026-11-09.md), [개인 P01 PR](https://github.com/myeongjundev/haedam-soar-portfolio/pull/1) |

S4 후속 `tools/s4_client.py`, 입력 계획·번들 패킷과 `docs/s4-live-preparation.md`는 김명준·Codex의 개인 작업입니다. 반소람의 팀 집계 조건을 유지하며 기존 개인 S1 전송/중지/증적 함수를 재사용합니다. S1에서 실측한 관리망 수정도 S4 설정에 반영했습니다. 원본 팀 규칙·워크플로는 바꾸지 않았고, 실제 Flask·임시 SQLite 대조는 개인 S4 실측으로 표시하지 않습니다.

S4 `tools/s4_probe.py`, `s4_collect.py`, `s4_rehearsal.py`, `s4_evidence.py`와 세션·증적 통합 테스트는 김명준·Codex의 개인 후속 구현입니다. 기존 개인 S1 전송/증적 저장 함수, 김명준의 포털 API, 김상혁의 티켓 저장소 및 반소람·김대훈의 S4 탐지/대응 출처를 유지합니다. 생성 워크플로를 실제 Flask·임시 SQLite에 연결한 오프라인 검증이며 실제 n8n/Graylog 실행으로 표시하지 않습니다. [구현·실측 경계](s4-session-evidence.md).

11/10 S4 후속 실제 결과: 김명준·Codex가 n8n HTTP Request의 정적 Send Body 제약을 실제 실패에서 확인해 조회/변경 노드를 분리하고 새 개인 프로젝트에서 재실측했습니다. 팀 S4 집계 정책·기여는 유지하며 개인 계정 잠금·세션 회수·정상 대조·원복 근거는 [S4 결과](s4-results.md)에 있습니다. 위 S4 준비 단계의 미실측 문장은 당시 범위입니다.
