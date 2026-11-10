# S1 Graylog·n8n 대응과 원복

2026-11-10 · 김명준/Codex. 선행은 PR #17 `c64787a`의 개인 설정·입력 도구입니다. 이번 범위는 **연결 설정 생성, n8n 워크플로 구현과 오프라인 검증**입니다. Docker·VM·실제 Graylog/n8n·기존 dotenv는 변경하지 않습니다.

## 구현과 출처

- 반소람의 팀 S1 정의를 기준으로 동일 `username+src_ip`, 30분 내 401 실패 9회, 실행 60초, 알림 유예 30분을 유지합니다. 개인 설정의 공격 IP·합성 계정 접두어로 범위를 제한합니다. 429는 집계에서 제외합니다.
- 김대훈의 팀 티켓/포털 하위 워크플로(10/12)를 S1 전용 ID·credential로 분리했습니다. 기존 S8의 응답망 주소 일치·확인 실패 보류와 S7의 명시적 분기 구조를 참고했습니다. 기존 팀·S8·S7·H1 워크플로는 변경하지 않습니다.
- `infra/n8n/s1-src/flow.js`는 개인 대응·원복 가드 원본입니다. `tools/build_s1_workflows.py`가 4개 n8n JSON과 Graylog 설정 명세를 생성합니다. 자격증명 **참조**만 공개 파일에 포함합니다.
- 공통 포털·티켓 API는 변경하지 않습니다. 개인 Webhook 계약은 [스키마](../contracts/s1-webhook.schema.json), [탐지 예시](../contracts/ticket-examples/s1-respond.json), [원복 예시](../contracts/ticket-examples/s1-release.json)입니다. 예시는 합성이며 실행 결과가 아닙니다.

## 설정과 생성

배치 주소는 [S1 설정](../infra/s1-settings.json), 연결 정책·URL·Webhook 경로·운영자 표시·credential 참조는 [통합 설정](../infra/s1-integration-settings.json)에서 읽습니다. URL은 해당 Compose의 소유 서비스만 허용합니다. 컨테이너 내부 포트는 기존 앱이 실제 바인딩하는 계약 값이며 외부 포트와 구분합니다.

```powershell
py -3.12 tools/build_s1_workflows.py
py -3.12 tools/build_s1_workflows.py --check
py -3.12 tools/s1_lab.py init --output .local/s1-auto
```

명령은 파일만 생성·검사합니다. `init`의 새 번들에는 통합 설정, Graylog 미연결 명세, 4개 워크플로도 포함됩니다. 기존 번들을 덮어쓰지 않습니다. 기본 `detection_enabled:false`, 워크플로 `active:false`, Graylog 예약 비활성 계획을 유지합니다. 입력기의 `execution_enabled`와 관제의 `detection_enabled`는 별개입니다.

| 생성 파일 | 역할 |
| --- | --- |
| `infra/n8n/portfolio-s1/s1-respond.json` | 탐지 Webhook, 티켓 선기록, 현재 티켓/다른 자원 소유권 대조, 차단과 기록 |
| `s1-release.json` | 운영자 Webhook, 정확한 현재 티켓의 차단 해제, 해제 기록과 최종 상태 재조회 |
| `s1-ticket.json` | 인증된 티켓 조회·기록, 같은 idempotency key로 최대 1회 재시도 |
| `s1-portal.json` | 제한한 IP의 목록·차단·해제, 같은 키로 최대 1회 재시도와 실제 목록 재조회 |
| `infra/graylog/portfolio-s1.json` | GELF TCP 입력·스트림·원본 규칙·인증 알림·URL 허용 목록의 미연결 명세 |

포털 `integration/events.py`는 GELF에 rule/status/username/src_ip를 직접 보냅니다. S1을 위해 별도 파싱 파이프라인을 만들거나 기존 Graylog 처리 순서를 변경하지 않습니다. 실제 기동 후 해당 필드의 수신을 확인해야 합니다. GELF 재전송에 따른 중복 이벤트와 유실도 원천 event_id로 대조하며 단순 count를 고유 로그인 횟수로 단정하지 않습니다.

## 인증과 요청 계약

| 역할 | 헤더 | 로컬 비밀값 변수 |
| --- | --- | --- |
| Graylog 탐지 전달 | `X-S1-Detection-Key` | `S1_DETECTION_KEY` |
| 운영자 원복 | `X-S1-Operator-Key` | `S1_OPERATOR_KEY` |
| 포털 대응 API | `X-Response-Key` | `PORTAL_RESPONSE_KEY` |
| 티켓 저장소 API | `X-Response-Key` | `TICKET_STORE_KEY` |

탐지는 `case_id, asset_id, src_ip, username, event_id, detected_at`, 원복은 `case_id, asset_id, src_ip, username, ticket_id`만 받습니다. 다른 키는 거부합니다. 요청의 `dry_run`, `store_real`, `cfg`, `approver`, `group_key`로 정책·운영자·티켓 범위를 바꿀 수 없습니다. 시각은 최대 1,860초 이전과 30초 미래까지이며 설정에서 더 좁힐 수 있습니다. Graylog의 `timestamp_processing`은 탐지 생성 시각이며 임계 충족 시각을 대신하지 않습니다.

티켓 묶음은 `S1|username|src_ip`입니다. 팀의 username 단독 묶음과 달라 개인 전용 새 티켓 볼륨에서만 사용합니다. 같은 IP를 다른 계정/다른 자리의 티켓이 소유하면 추가 차단과 해제를 보류합니다. 동일 IP의 여러 티켓을 함께 소유·해제하는 기능은 구현하지 않습니다.

## 대응·원복 판정

대응은 현재 티켓, 자원 소유권, 포털 차단 목록을 읽은 뒤 detected를 먼저 기록합니다. 기록 뒤에도 현재 티켓·소유권·목록을 재확인합니다. 티켓 기록 실패나 소유권 변화 때는 차단을 호출하지 않습니다. 차단 후 API 목록에 대상이 실제로 존재해야 `responded`를 반환합니다. 이미 소유한 차단은 현재 목록까지 맞을 때만 중복 처리하고 새 이벤트 ID도 기존 티켓에 기록합니다. 원복된 사건의 옛 이벤트 재전송은 새 차단을 만들지 않습니다.

원복은 운영자가 지정한 정확한 현재 티켓만 사용합니다. 다른 티켓/봇의 같은 자원 소유권이 있으면 해제하지 않습니다. 해제 응답과 대상이 없는 목록을 확인한 뒤 released를 기록하고, 티켓 restored·활성 조치 없음·포털 목록에서 대상 없음까지 다시 확인합니다. 탐지 비활성 상태에서도 소유 사건의 원복은 가능합니다.

- `responded`: 포털 설정 반영과 티켓 기록을 확인했다는 뜻입니다. 공격 클라이언트 403·정상 사용자 200의 효과를 의미하지 않습니다. `effect_verified:null`을 유지합니다.
- `released`: 티켓/포털 API의 원복 상태 확인입니다. 실제 클라이언트 재로그인·200 복구는 별도 실측해야 합니다.
- 400: 요청 형식·대상·시각 오류. 409: 비활성, 오래된 티켓, 소유권/상태 불일치. 503: 조회·저장·반영 확인 실패.
- 차단은 됐지만 applied 기록에 실패하면 `held_applied_record_reconcile`입니다. 다음 요청은 소유권 없는 차단을 임의로 인수하지 않습니다. 현재 조치와 티켓을 대조하는 수동 복구가 필요합니다.
- 해제 후 released 기록에 실패하면 티켓 소유권을 유지합니다. 같은 티켓으로 다시 요청해 동일 해제 키의 재조회·기록을 완료할 수 있습니다. 실패를 전체 원복 성공으로 표시하지 않습니다.

개인 n8n은 S1 번들의 production concurrency=1을 전제로 합니다. 조회와 포털 조치는 서로 다른 서비스여서 원자적 트랜잭션이 아니며 외부 운영자의 동시 변경을 완전히 잠그지 않습니다. 이 개인 랩의 키를 다른 실행기와 공유하거나 수동 동시 실행하지 않습니다. 운영자 원복 전에 Graylog 정의 예약을 정지하고 진행 중 실행을 확인해야 합니다. 이 워크플로 자체가 Graylog 예약을 정지하는 것은 아닙니다.

## Graylog와 credential의 오프라인 바인딩

`materialize(settings, integration, bindings, secrets)`는 실제 입력/인덱스/스트림/알림 ID 4개와 명시적으로 전달한 별도 키 4개를 검증해 연결된 요청 본문을 반환하는 **순수 함수**입니다. 기존 환경·키를 자동으로 읽거나 API를 호출하지 않습니다. 스트림은 포털 source와 전용 GELF input ID(type 8)를 함께 요구하고, 정의에 실제 스트림/알림 ID를 연결합니다. 키는 n8n credential과 Graylog 알림의 api_secret에만 넣습니다. 공개 생성 파일에는 실제 ID·키가 없습니다.

미연결 공개 파일의 `api_secret:null`, 스트림/알림 빈 목록을 그대로 설치 완료로 취급하지 않습니다. 실제 배포 도구는 다음 순서를 수행해야 합니다: 소유 프로젝트 확인, 입력·인덱스·스트림 확인/생성, credential/워크플로 가져오기와 게시, URL 허용·인증 알림 연결, 정의 생성 후 예약 정지, 미인가 요청 거부 확인. 비밀값이 든 materialize 반환값은 로그·Git에 저장하지 않고 임시 가져오기 파일을 사용했다면 정리해야 합니다.

## 검증과 다음 작업

`tests/s1_graph_runner.cjs`는 생성된 Code·IF·하위 워크플로 연결을 실행하고 HTTP 노드만 메모리 모델로 대체합니다. n8n 엔진·credential 인증 미들웨어·Graylog 검색기를 실행한 것이 아닙니다. 추가로 생성된 티켓 HTTP 요청 순서를 실제 Flask 저장소와 새 임시 SQLite에 적용해 계약·원복 상태를 확인합니다. 서버나 소켓을 열지 않습니다.

검사에는 정상 대응/원복, 새 사건 분리, 같은 사건·활성 중 새 알림 중복, 옛 이벤트 재전송, 다른 계정/티켓 소유권, 저장소 장애, 잘못된 200 응답, 반영 조회 실패, 기록 실패, 응답 유실 시 동일 키 재시도, 비활성 상태 원복과 스키마 거부가 포함됩니다. 기존 S1 입력기의 실제 요청은 실행하지 않았습니다.

다음은 독립 코드 검토 후 개인 환경의 실제 배포·인가/미인가 Webhook·Graylog 8/9회 경계·동일 회차 티켓·공격/정상 HTTP·원복 실측입니다. Compose 충돌 검사, 새 PC 설치, n8n 엔진 호환성, 실제 비밀값 비저장·임시 credential 정리도 그때 확인합니다.

## 인수인계

- 작업 ID: 개인 S1 자동 연결 2차. 브랜치 `codex/s1-auto-workflows`, 선행 PR #17 `c64787a`. 담당은 김명준/Codex이며 Claude S10 worktree와 겹치는 파일은 수정하지 않았습니다.
- 확인: 전체 호스트 95 passed·29 subtests passed. S1 새 그래프/바인딩 검사 16개와 새 계약 검사 1개를 포함합니다. 팀 S1/S4 합성 규칙 검사 15개, 4개 워크플로·1개 Graylog 생성물 일치 확인. 실제 HTTP·Docker·VM·서비스 가져오기/예약 조작은 0건입니다.
- 최초 임시 SQLite 재생 검사에서 Windows 파일 잠금 때문에 테스트 정리가 실패했습니다. 연결을 명시적으로 닫도록 수정한 뒤 전체 검사를 통과했습니다. 실제 서비스 장애로 기록하지 않습니다.
- 다음 검토 시작점: `infra/n8n/s1-src/flow.js`, `tools/build_s1_workflows.py`, `tests/test_s1_workflows.py`, 개인 Webhook 스키마. n8n 엔진·Graylog에 배포하기 전에 소유권/오래된 이벤트/부분 실패 분기와 실제 바인딩 순서를 독립 검토합니다.
