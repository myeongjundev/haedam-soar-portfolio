# P03 · 개인 Wazuh/S7 Docker

- 기준: PR #4 `39e937d`에서 `codex/wazuh-s7-docker`. Claude PR #5는 별도 검토이며 병합하지 않습니다.
- 담당: 김명준·Codex. 팀 S7 복구 코드(김상혁)를 보존하고 컨테이너 배치·시험 도구를 추가합니다.
- 범위: Wazuh manager/indexer/dashboard, 실제 포털 정적 파일을 공유하는 agent, 새 MySQL·포털. 개인 프로젝트의 볼륨·네트워크만 사용합니다.
- 완료 조건: 새 볼륨 기동, agent 연결, 실제 HTTP 파일 변조→FIM 경보→indexer 검색, 인증 API의 AR 요청→해시·HTTP 복원 확인, 추가 파일 격리·정상 파일 대조, 재시작 후 기준 보존.
- 경계: 이번 단계의 복구 호출은 시험 도구가 Wazuh API로 요청합니다. Graylog→n8n 자동 판단·티켓 생성은 다음 연결 단계이며 S7 전체 완료로 표시하지 않습니다. pfSense와 기존 팀 서비스는 수정하지 않습니다.
- 설정: Wazuh 4.9.0 팀 호환 버전 고정, 무작위 로컬 비밀번호, loopback 공개 포트, 격리 네트워크. 관리자 API는 로컬 랩 초기 검증용이며 n8n 연결 전에 agent별 최소 권한 계정으로 분리합니다.
- 파일: `compose.s7.yaml`, `infra/wazuh/`, `tools/s7_lab.py`, `tools/s7_verify.py`, 관련 문서·검증·개인 작업일지. 공통 이벤트/API 계약 변경 없음.
- 자원: 현재 Docker 6GiB에서는 기존 관제 스택을 일시 중지한 뒤 실행하고, 실측 종료 후 개인 스택을 중지하고 기존 실행 목록을 복원합니다. 볼륨 삭제와 전역 설정 변경 없음.
