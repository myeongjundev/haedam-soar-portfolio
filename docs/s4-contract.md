# S4 개인 연결 계약 v1

구현 범위·팀 출처·시험 절차는 [S4 워크플로](s4-auto-workflows.md)를 따릅니다. 공통 티켓 스키마의 필드를 바꾸지 않고 S4 전용 경로만 추가합니다. 기존 계정/IP API 입력·응답 형식은 유지합니다. 새 DB 마이그레이션은 필수이며 관리자/일반 대응의 계정 변경 시 S4 소유권을 취소하는 동작이 추가됩니다.

## 포털

`S4_ENABLED=1`, 서로 다른 32자 이상 `RESPONSE_API_KEY`/`S4_RELEASE_KEY`, 정확한 `S4_ACCOUNT_ALLOWLIST`, 대응 CIDR가 모두 필요합니다. 기본은 비활성·빈 목록입니다. 목록에 넣어도 `zz_` 합성 이름, citizen/staff만 허용하며 admin은 거절합니다.

| 요청 | 인증 | 입력/결과 |
| --- | --- | --- |
| GET `/api/v1/response/s4/accounts/{username}` | X-Response-Key: RESPONSE_API_KEY | `{success:true,data:{user_id,username,locked,active_sessions,owner_ticket_id}}` |
| POST 같은 경로 `/lock` | RESPONSE_API_KEY + Idempotency-Key | `{user_id,ticket_id}`. 기존 잠금·소유권은 409. 잠금/회수/소유권/영수증을 함께 커밋 |
| POST 같은 경로 `/unlock` | **S4_RELEASE_KEY** + Idempotency-Key | `{user_id,ticket_id,reason_code:"false_positive"}`. 현재 포털 소유 티켓이 일치해야 해제 |

변경 응답에는 상태 필드와 `changed:boolean`, `revoked_sessions:integer`가 포함됩니다. 비밀번호·세션 값은 반환하지 않습니다. 동일 Idempotency-Key/본문은 원래 영수증을 반환하며 다른 본문은 409입니다. **영수증은 과거 결과이므로 GET 현재 상태를 반드시 재확인합니다.** 다른 계정 ID, 역할, 허용 목록, 키 또는 CIDR는 적용 전에 검사합니다. 해제 후 세션을 생성하거나 과거 세션을 복원하지 않습니다.

[요청 스키마](../contracts/s4-account-request.schema.json) · [성공 응답 스키마](../contracts/s4-account-response.schema.json) · [잠금 예시](../contracts/ticket-examples/s4-lock-account.json) · [해제 예시](../contracts/ticket-examples/s4-unlock-account.json) · [상태 예시](../contracts/ticket-examples/s4-account-state.json). 오류는 기존 `{success:false,error:{code,message}}` 형식을 따릅니다.

## 웹훅과 티켓

탐지: `{case_id:"S4",asset_id,src_ip,username,event_id,detected_at}`. 기본 허용 나이는 660초, 미래 시계 오차 30초입니다. 원복: `{case_id:"S4",asset_id,src_ip,username,ticket_id}`. 계정·IP·asset은 설정과 정확히 일치해야 합니다. `cfg`, `dry_run`, 키, 사용자 지정 URL, approver 등 추가 필드는 거절합니다. 탐지가 꺼져 있어도 원복은 가능합니다.

[웹훅 스키마](../contracts/s4-webhook.schema.json) · [탐지 예시](../contracts/ticket-examples/s4-respond.json) · [원복 예시](../contracts/ticket-examples/s4-release.json). 예시는 합성 데이터이며 실행 증거가 아닙니다. 웹훅 경로·헤더·credential ID는 설정에서 생성합니다. 탐지와 운영자 키는 별도이며 HTTP 노드의 포털 해제 키와도 다릅니다.

티켓은 seat A, case S4, group `S4|username`, bot `111`, via `portal`, target `username:user_id`, action `lock` 또는 `unlock`을 사용합니다. 공통 `unlock→lock` 활성 조치 대응을 그대로 사용합니다. 포털 소유권과 티켓 활성 조치를 모두 확인하며 별개 저장소 사이의 분산 트랜잭션은 제공하지 않습니다. 중간 장애는 [복구 절차](s4-auto-workflows.md#장애와-복구)에 따라 조정합니다.
