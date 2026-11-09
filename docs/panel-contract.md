# 개인 제어판 API · v1

`127.0.0.1` 전용 HTTP API입니다. 기존 포털·티켓·n8n 계약은 변경하지 않습니다. 브라우저에는 비밀값·실행 명령·Docker socket을 제공하지 않습니다. 요청 예시는 [합성 예시](../contracts/panel-job-examples.json), 구조는 [스키마](../contracts/panel-job.schema.json)입니다.

| 경로 | 입력/출력 | 동작 |
| --- | --- | --- |
| GET `/` | HTML + HttpOnly/SameSite=Strict 세션 쿠키 | 화면 열기, 조치 없음 |
| GET `/api/state` | project, targets, health, runs, jobs, errors, observed_at, csrf | 마지막 관측 상태. Docker 조회는 별도 refresh 작업 |
| POST `/api/jobs` | action, request_id, 조건부 target/run_id → 202 job_id/run_id/duplicate | 비동기 작업 접수이며 성공 판정 아님 |
| GET `/api/runs/{id}/evidence` | kind, run, jobs, exported_at | 해당 회차의 JSON 다운로드 |

API 읽기에는 세션 쿠키, 쓰기에는 정확한 Host·Origin·세션·`X-Panel-CSRF`·JSON이 필요합니다. cross-site Fetch Metadata 요청은 거부합니다. CORS를 열지 않습니다. 포트/바인드/프로젝트/관측 제한은 `infra/panel-settings.json`, S7 대상/주소/경로는 기존 공통 S7 설정에서 읽습니다. `target`은 서버의 허용 목록으로 다시 검사합니다.

작업 종류: `refresh`는 지정된 Docker 프로젝트·worktree·공개 포트·실행 설정과 서비스 응답을 조회합니다. `attack`은 정상 기준·미완료 티켓 검사 후 회차와 입력 해시를 먼저 저장하고, 부모의 저장 확인을 받은 다음 탐지 예약과 무해한 파일 입력을 실행합니다. `observe`는 같은 입력 해시의 실제 경보→Graylog 판단→티켓→기존 조치의 현재 효과를 관측합니다. 정상 조치를 새로 호출하지 않습니다. `restore`는 관측한 회차의 사건·소유 티켓만 사용하여 n8n 완료를 요청하고 실제 원복을 확인합니다.

동시에 한 작업만 실행합니다. `request_id` 재전송은 기존 job을 반환하며 같은 ID의 다른 본문은 409입니다. 미완료 회차가 있으면 새 공격을 409로 거부합니다. HTTP 오류: 400 형식/대상 오류, 403 접근 거부, 404 미등록 회차/경로, 409 동시 작업·범위/상태 충돌, 413 크기 초과, 415 JSON 아님, 503 제어판 내부 의존 문제. 실제 worker 실패는 접수된 job의 `failed`와 허용된 오류 코드로 표시합니다. 원문 예외·키·서비스 로그는 반환하지 않습니다.

회차 상태는 `preparing → armed → input_sent → observing → verified → restored`입니다. 저장 전 실패는 `not_started`, 입력 준비 저장 후 실패/중단은 `needs_check`입니다. `restored`는 해당 회차의 마지막 관측 결과이며 지속적인 정상 보장이 아닙니다. 재조회에서 새로운 변조가 확인되면 `needs_check`가 됩니다. `steps`의 시각은 제어판이 관측한 시각이며 SIEM 원본 타임스탬프/MTTD로 사용하지 않습니다.

재시작 시 진행 중 job은 `interrupted`로 남고 자동 재실행하지 않습니다. 입력 준비 저장 전에는 worker가 부모의 ack 없이 파일을 변경할 수 없습니다. 저장 후에는 실제 변경 여부가 불확실할 수 있으므로 `observe`로 확인합니다. 기본 180초 관측/240초 worker 한도를 넘었다고 해서 파일이 자동 원복된 것으로 표시하지 않습니다. 확인할 경보가 없거나 의존 서비스가 끊겼다면 기존 S7 도구와 원천 로그로 확인하고 기록을 보존합니다.

현재는 S7만 연결됩니다. S8/H1은 버튼 미연결, S10은 별도 담당 작업으로 잠겨 있습니다. Docker 시작·중지·볼륨 삭제·VM 제어 API는 없습니다.
