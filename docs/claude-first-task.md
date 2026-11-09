# Claude 첫 작업 · 개인 Docker 관제 재현과 실패 원인 확인

[공통 규칙](../AGENTS.md)을 확인합니다. 시작 전에 `gh pr list --state open`으로 P01 포털 PR과 P02 Docker PR의 현재 HEAD를 확인합니다. 브랜치는 `claude/graylog-n8n-fresh-start`를 사용합니다.

1. P01은 [README](../README.md#포털과-db-실행)의 새 볼륨 기동을 독립 확인하고 해당 PR에 `[Claude]` 코멘트를 남깁니다.
2. P02는 [개인 관제 Docker 설치](docker-soc.md)를 따라 별도 프로젝트·빈 볼륨에서 재현합니다. 포트가 사용 중이면 프로젝트와 루프백 포트를 분리합니다.
3. 컨테이너가 정상인데 n8n 실행이 없다면 GELF 입력 → 스트림 → 이벤트 정의 → Graylog URL Allowlist → n8n 게시 상태 순으로 확인합니다. P02에서 관찰한 첫 실패는 웹훅 URL 미등록이었습니다.
4. 검토 HEAD, 첫 실패 명령, 관찰한 결과와 반증, 재검증 결과를 P02 PR에 코멘트로 남깁니다. 추가 수정이 필요하면 별도 Claude 초안 PR을 열고 의존 PR을 연결합니다.

착수하려면 이 작업 폴더에서 `claude auth login`을 완료한 뒤 `claude`를 실행하고 이 카드를 전달합니다.
