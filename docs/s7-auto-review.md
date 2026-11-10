# Claude IDE · 개인 S7 자동 연결 검토

대상 브랜치 `codex/s7-auto-pipeline`, 기반 PR #8 `ccf37d1`(PR #6 의존). 실행 검증 소스 `db4c64f`, 이후 커밋은 증적·문서 정리입니다. 기존 Claude H1 변경은 보존하고 별도 검토 worktree를 사용합니다. 최종 병합은 김명준이 합니다.

먼저 [설치](s7-auto-lab.md), [실측](s7-auto-results.md), [계약](s7-auto-contract.md)을 읽습니다. 목표는 파일 입력에서 실제 Wazuh·Graylog·n8n·티켓·AR·HTTP 효과·원복까지의 연결입니다. 개인 FIM 정책이며 팀의 접근 로그 상관 정책은 별도입니다.

1. PR HEAD와 증적 `source_sha256` 대조, `python -m pytest -q tests`, S7 생성물 `--check`. 설정을 바꾸면 생성기·agent·연결 서비스·검증기가 같은 값을 쓰는지 확인합니다. 경로·URL·계정은 JSON/환경값, 비밀값은 Git 제외 파일입니다.
2. Docker 메모리가 약 6GiB이므로 다른 실측과 순서를 맞춥니다. 현재 실행 목록을 기록하고 사용자와 합의된 정지 범위만 사용합니다. `S7_PROJECT=haedam-s7-claude`로 새 볼륨 init/up/ready/configure/verify/failures. 공유 포트 때문에 다른 개인 S7과 동시 실행하지 않습니다. 종료 후 원래 실행 목록을 복원합니다.
3. 실제 경보의 ID·파일 해시가 Graylog 판단 및 티켓 event_ids와 일치하는지, API 200과 파일/HTTP 효과를 구분하는지 확인합니다. 정상 검증기에서 조치를 직접 호출하는 부분은 잘못된 해시 거부 시험뿐이며 정상 대응은 Graylog가 시작해야 합니다.
4. 잘못된 agent/path/hash, baseline RO, 중복 이벤트·원복 재경보, 다른 티켓 완료, 과거 성공 후 새 변조를 확인합니다. scoped Wazuh 권한이 자기 agent로 제한되고 wrapper 외 실행 파일이 제거됐는지 확인합니다.
5. 부분 실패를 우선 검토합니다: 티켓 저장소 정지 전 무조치/후 재시도, 조치 이후 티켓 기록 실패, agent/API 장애, 영수증 저장 전 강제 종료. 실제 재현하지 않은 항목은 미검증으로 남깁니다. 현재 코드가 영수증 전 중단을 완전 자동 복구한다고 주장하지 않습니다.
6. 완료 후 티켓 restored, 정상 홈 해시/200, 시험 파일404·격리물0, 중복 조치0을 확인합니다. 새 설치에서 API DB 초기화·인증서 경로·LF shebang도 봅니다.
7. 새로 확인한 Claude PR #9(`1fba5ad`)는 같은 PR #8 기반의 형제 변경이며 여기에는 포함하지 않았습니다. `s7_auto_lab.ready()`는 `s7_lab.ready()`를 호출하지 않으므로 PR #9 병합만으로 자동 환경의 backend 볼륨 불일치 검사가 적용되지는 않습니다. 새 프로젝트 실행 지침을 유지하고 통합 시 두 경로를 함께 검증합니다.

발견 사항은 `[Claude]` PR 코멘트로 검토 커밋·재현 명령·실제 결과·파일/줄·영향을 남깁니다. 수정은 자신의 브랜치에서 최소 범위로 하고 Codex 파일과 동시 편집하지 않습니다. 같은 계정의 리뷰 코멘트를 GitHub 승인으로 표시하지 않습니다.
