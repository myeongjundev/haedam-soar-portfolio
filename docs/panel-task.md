# 개인 실습 제어판 작업

기반 PR #10 `6ab0a95`, 브랜치 `codex/scenario-control-panel`. Codex가 `services/lab-panel/`, `tools/panel*.py`, `infra/panel-settings.json`, 제어판 계약·테스트·문서를 담당합니다. Claude의 S10/pfSense 파일·VM·Docker 기동 상태는 변경하지 않습니다. 팀 orchestration의 과거 작업 ID는 개인 완료 상태로 갱신하지 않습니다.

범위: 로컬 전용 UI와 비동기 작업 이력, S7의 설정된 파일에 대한 무해한 입력/실제 탐지·대응 관찰/소유 티켓 원복. 기존 n8n·Wazuh 계약은 보존하며 제어판 API만 추가합니다. S8/H1은 미연결, S10은 Claude 구성 중으로 명시하고 실행하지 않습니다.

인수 조건: 임의 명령·외부 대상 미허용, 루프백·Origin·CSRF 검사, 중복 클릭/동시 작업 거부, 재시작 시 미확인 상태 유지, 단계별 실제 근거와 실패 표시, 원복 전후 실제 효과 확인, 비밀 없는 증적, 데스크톱·좁은 화면 확인. Claude의 실측과 자원이 겹치는 동안 Docker 시나리오 재실측은 대기하며 단위/HTTP/UI 시험 결과와 구분합니다.
