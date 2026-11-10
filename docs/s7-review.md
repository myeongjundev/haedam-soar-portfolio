# S7 개인 Wazuh 독립 검토 카드 · Claude IDE

- 작성: 김명준·Codex. 브랜치 `codex/wazuh-s7-docker`, 기반 H1 PR #4 `39e937d`. PR #5 reconcile 변경은 포함하지 않습니다.
- 먼저 [설치](s7-lab.md)·[실측](s7-results.md)·PR 최신 HEAD를 확인합니다. Claude 작업 폴더의 PR #5 변경은 보존하고 별도 검토 worktree에서 시작합니다.
- 범위: Wazuh 3개 서비스, portal/DB, 웹 볼륨을 감시하는 agent, API 복구/격리. Graylog/n8n/티켓 자동 연결은 미구현입니다. 이 경계를 결함 은폐나 전체 완료로 해석하지 않습니다.

## 문제 해결 중심 확인

1. `python -m pytest -q tests`와 증적의 `source_sha256`을 대조합니다. Windows CRLF와 Git LF 차이를 구분합니다.
2. 6GiB에서는 기존 실행 목록을 기록하고 잠시 중지한 뒤, `S7_PROJECT=haedam-s7-claude`로 **새 볼륨**에서 초기화·기동·ready·verify를 수행합니다. 기존/다른 개인 컨테이너를 일괄 삭제하지 않습니다. 종료 후 개인 스택 중지·기존 목록 복원이 필요합니다.
3. 무해한 실제 HTML 변조가 HTTP에 보이고 rule 550의 before/after hash와 맞는지 확인합니다. API 200만으로 복원 성공을 판정하지 않습니다. 추가 파일 rule 554, 격리 후 404·정상 자산의 해시도 확인합니다.
4. 변조 상태 baseline 거부, agent 재시작으로 기준이 바뀌지 않음, 웹 루트 밖 경로·symlink의 처리, API 미인증, 포털 읽기 전용 볼륨을 확인합니다.
5. 부분 실패: agent 정지/연결 끊김, manager/API 장애, baseline 파일 손상, indexer 지연 때 성공 표시를 하지 않는지 확인합니다. 격리 후 재호출 및 복구로 생기는 FIM 이벤트도 다음 자동화 설계의 근거로 기록합니다.
6. 중지→재기동, `init` 반복, 새로운 프로젝트의 첫 dashboard 기동을 확인합니다. 4.9 이미지가 `1513629884013` 식별자를 요구하고 `hosts`를 덧붙이는 동작을 확인했습니다.

변경이 필요하면 최소 재현·실패 지점·수정 후 실제 결과를 `[Claude]` PR 코멘트로 남기고 자기 브랜치에서 수정합니다. 같은 파일 동시 수정은 피합니다. 사용자만 최종 병합합니다. Codex의 실행 결과를 독립 검토 결과로 대신하지 않습니다.
