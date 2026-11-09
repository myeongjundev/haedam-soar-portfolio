# Claude 첫 작업 · Graylog에서 n8n까지 새 환경으로 연결

공통 규칙은 [AGENTS.md](../AGENTS.md)를 읽습니다. 브랜치는 `claude/graylog-n8n-fresh-start`를 사용합니다. `gh pr list --state open`으로 포털 반입 PR의 변경 범위와 HEAD를 먼저 확인합니다. 작업에 필요한 팀 Compose 참고본은 `infra/graylog/compose.team.yaml`과 `infra/n8n/compose.team.yaml`입니다. 개인용 구성에서는 새 프로젝트 이름과 빈 볼륨을 사용합니다.

## 재현할 문제

팀 n8n Compose가 기존 외부 볼륨을 요구하고, 팀 Graylog 설정은 PC별 주소와 수동 설정에 의존합니다. 빈 볼륨과 개인 랩 이름으로 시작했을 때 첫 실패 지점을 재현하고, 입력에서 실제 n8n 실행까지 연결합니다.

- 입력은 개인 랩의 합성 GELF 1건을 사용합니다. 검색 → 스트림·이벤트 → n8n 실행 ID를 대조합니다.
- 먼저 볼륨, 서비스 DNS, webhook 경로, 규칙 가져오기 중 실패 지점을 확인합니다. 확인된 원인을 해결하는 범위에서 Compose와 가져오기 문서를 수정합니다.
- P01은 포털 파일과 루트 Compose를 담당합니다. 초기 P02는 `infra/`의 개인 Graylog·n8n 구성과 관련 설치 문서를 담당합니다. 같은 파일 수정은 순서를 조율합니다.
- 기존 팀 볼륨과 실제 방화벽 설정을 유지하고 새 랩에서 확인합니다. 비밀값을 출력·커밋하지 않습니다.
- 재현 명령, 실제 에러, 가설을 반증한 확인, 변경 후 새 볼륨에서 확인한 결과, 남은 연결을 초안 PR에 적습니다. Codex의 포털 PR에는 `[Claude]`와 검토 커밋을 붙여 독립 재현 결과를 코멘트로 남깁니다.

착수하려면 이 폴더의 터미널에서 `claude auth login`을 완료한 뒤 `claude`를 실행하고 이 작업 카드를 전달합니다.
