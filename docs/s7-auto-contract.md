# 개인 S7 자동 대응 연결 계약

팀 티켓의 공통 필드는 유지합니다. 새 n8n 입력은 [스키마](../contracts/s7-auto-webhook.schema.json)와 `contracts/ticket-examples/s7-auto-*.json`에 있습니다. 예시는 합성이며 실측 증거가 아닙니다.

| 호출 | 인증 | 입력/의미 |
| --- | --- | --- |
| POST `/webhook/haedam-s7-respond` | `X-S7-Detection-Key` | case_id S7, asset_id haedam-portal, 실제 경보 event_key, Graylog event_id와 detected_at |
| POST `/webhook/haedam-s7-complete` | 별도 `X-S7-Operator-Key` | case_id, asset_id, event_key, 해당 ticket_id |
| 내부 POST `s7-response:8097/claim` | `X-S7-Key`의 bridge credential | event_key, graylog_event_id, detected_at, n8n execution_id. 실제 경보만 허용하고 최초 판단을 영속 고정 |
| 내부 POST `/respond` | bridge credential | event_key, ticket_id. 고정 agent/path/hash/기준 검사→영수증→실제 효과 |
| 내부 POST `/complete` | 별도 complete credential | event_key, ticket_id, execution_id. 소유 티켓·복구 상태·격리물 해시 확인 후 완료 |

명시하지 않은 입력 필드는 거부합니다. 인증 실패 403, 형식 오류 400, 미등록 실제 경보 404, 상태/소유권/해시 불일치 409, 의존 서비스 오류 503입니다. n8n은 내부 오류를 `held_*` verdict로 표시하며 성공 HTTP로 위장하지 않습니다. 성공은 `{ok:true,status:200,verdict:verified|restored|already_restored,ticket_id,event_key}`입니다. 내부 연결 서비스는 `{ok:true,data:{...}}`로 최초 판단, 조치 영수증, requested/finished/effect_verified_at, HTTP/해시 효과를 반환합니다.

티켓 seat C / case S7 / asset haedam-portal, group_key는 `S7:haedam-portal:<event_key>`입니다. 개별 Wazuh 사건에 한 회차를 연결하며 두 event_ids에 Graylog ID와 원본 Wazuh ID를 남깁니다. group_key의 팀 기본 설명 `{asset}:{file}`와 다른 **개인 자동화 회차 규칙**이며 팀 설정은 바꾸지 않습니다. 적용→효과→완료 기록의 idempotency key는 event_key에 단계별 접두사를 붙입니다.

| 적용 action | 완료 action (`result: released`) | 실제 의미 |
| --- | --- | --- |
| `restore` | `complete_restore` | 정상 기준 파일 복구 확인·처리 종료 |
| `quarantine` | `complete_quarantine` | 해당 실행 격리 파일 정리·처리 종료 |

bot 117 / via wazuh-ar / target는 고정 file_key입니다. 티켓 저장소 `db.action_key`와 대시보드 SQL의 활성 조치 판정에 같은 매핑을 적용합니다. 기존 `restore` + `result: released`의 quarantine 해제 의미는 그대로 보존합니다. applied restore를 SQL에서 quarantine으로 잘못 분류하던 부분도 result 조건으로 구분합니다. API와 대시보드 두 판정이 동일해지는 것을 테스트합니다.

재시도 시 n8n 실행 ID와 시각을 새로 만들어 같은 키의 본문을 바꾸지 않습니다. 연결 서비스가 저장한 최초 조치/완료 응답으로 티켓 기록을 재시도합니다. 티켓 기록 장애 뒤 물리 조치가 끝났더라도 기록까지 성공하기 전에는 전체 완료로 판정하지 않습니다.
