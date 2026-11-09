# Claude 첫 작업 · 개인 Docker 관제 재현과 실패 원인 확인

S8 수정 PR을 검토할 때는 최신 [S8 독립 검토 카드](s8-review.md)를 우선 사용합니다. 아래 P01/P02 카드는 초기 연결 검증 이력입니다.

[공통 규칙](../AGENTS.md)을 확인합니다. 시작 전에 `gh pr list --state open`으로 P01 포털 PR과 P02 Docker PR의 현재 HEAD를 확인합니다. 브랜치는 `claude/graylog-n8n-fresh-start`를 사용합니다.

1. P01은 [README](../README.md#포털과-db-실행)의 새 볼륨 기동을 독립 확인하고 해당 PR에 `[Claude]` 코멘트를 남깁니다.
2. P02는 [개인 관제 Docker 설치](docker-soc.md)를 따라 별도 프로젝트·빈 볼륨에서 재현합니다. 포트가 사용 중이면 프로젝트와 루프백 포트를 분리합니다.
3. 컨테이너가 정상인데 n8n 실행이 없다면 GELF 입력 → 스트림 → 이벤트 정의 → Graylog URL Allowlist → n8n 게시 상태 순으로 확인합니다. P02에서 관찰한 첫 실패는 웹훅 URL 미등록이었습니다.
4. 검토 HEAD, 첫 실패 명령, 관찰한 결과와 반증, 재검증 결과를 P02 PR에 코멘트로 남깁니다. 추가 수정이 필요하면 별도 Claude 초안 PR을 열고 의존 PR을 연결합니다.

2026-11-09 사용자 확인: Claude IDE가 이미 준비되어 있습니다. 추가 설치나 CLI 로그인을 선행 조건으로 요구하지 않습니다. IDE에서 개인 작업 폴더 `C:/SKT aleph/haedam-soar-portfolio-claude`를 열고 이 카드를 사용합니다. 팀 원본 `aleph-soar-capstone`에 남아 있는 미커밋 작업은 그대로 보존합니다.

Claude IDE 사용 준비와 `claude.ai/artifact/...` 공유 페이지의 웹 접근 권한은 별개입니다. 이후 사용자가 공유한 반소람 님의 `PROGRESS.md`, `MVP-설계.md`, `MVP-구현계획.md`를 읽고 H1을 첫 추가 케이스로 구현했습니다. 웹 artifact 내용을 읽었다고 주장하지 않습니다. 새 PR 검토에는 [H1 검토 카드](h1-review.md)를 사용합니다.
