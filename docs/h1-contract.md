# H1 작성 제한 계약

기존 S8 IP 차단 API와 워크플로는 그대로 유지합니다. H1은 시민 계정에 대한 별도 조치입니다. 계약 변경은 개인 저장소의 포털·이벤트 스키마 사본·티켓 검증기·대시보드에 함께 반영합니다.

## 포털

- `POST /api/v1/response/petitions/restrict`와 `/release`: `X-Response-Key`, 허용 대응 CIDR, 8~100자 `Idempotency-Key` 필요.
- JSON: `{"username":"h1_abuse","ticket_id":"T-20261109-0001"}`. 다른 필드 거부. [요청 스키마](../contracts/h1-petition-response.schema.json).
- 성공: `success:true`, `data`에는 username, ticket_id, restricted, changed, changed_at(UTC)이 있습니다. changed_at은 조치/해제 DB 시각이며 동일 요청 재시도 시 처음 결과를 반환합니다. [응답 스키마](../contracts/h1-petition-result.schema.json).
- `GET /api/v1/response/petitions/restrictions/<username>`: 같은 인증으로 현재 username, restricted, 활성 ticket_id(없으면 null)를 반환합니다. 조치 응답 재전송은 과거 영수증일 수 있으므로 현재 상태를 이 경로에서 재확인합니다.
- 오류: 인증/비시민 제한 403, 없는 계정 404, 잘못된 입력 400, 다른 소유자·해제된 티켓 재사용·같은 키의 다른 입력 409. DB 장애는 기존 503 처리.
- 제한된 시민의 `POST /api/v1/petitions`: 429 `PETITION_WRITE_RESTRICTED`. 로그인·조회·다른 시민은 유지합니다.
- 사용자 행의 MySQL 잠금으로 작성과 제한 변경을 직렬화합니다. 이미 커밋된 민원은 보존합니다. 다른 티켓이 소유한 제한은 덮어쓰거나 해제하지 않습니다.
- 해제 기록을 삭제하지 않으므로 같은 티켓 ID의 새 키로 다시 제한할 수 없습니다. 새 사건은 새 티켓 ID를 사용합니다. 관리자/직원에게 제한을 적용할 수 없지만, 제한 뒤 역할이 바뀌었을 때 기존 소유자의 해제는 허용합니다.

## 이벤트와 티켓

`petition.write_restricted`, `petition.write_released`, `petition.write_denied`를 공통 이벤트 enum에 추가합니다. 대상 username, 결과·HTTP 상태, 제한/해제의 details.ticket_id만 기록합니다. 민원 내용·비밀번호·키는 넣지 않습니다. 기존 `petition.created` 성공 이벤트의 username과 event_id를 탐지에 사용합니다.

티켓 case_id `H1`을 허용합니다. seat는 개인 작업자 김명준의 기존 B, group_key는 `H1:haedam-portal:<username>`입니다. 기존 IP 기반 S8과 충돌하지 않습니다. 자원은 `asset_id=haedam-portal, via=portal, action=restrict_write, target=<username>, bot=112`입니다. 해제 기록도 같은 action 이름에 `result=released`를 사용해 정확한 자원 소유권을 제거합니다.

H1 n8n 탐지 입력은 case_id H1, asset_id haedam-portal, username h1_abuse, 실제 Graylog event_id와 detected_at을 받습니다. 전용 탐지 키로 인증하고 티켓 detected 기록에 성공한 다음 조치합니다. 기록/조회가 실패하면 503, 오래된 티켓/이벤트와 티켓 저장소의 409(같은 키의 다른 본문 등)는 409로 보류합니다. 조치 전에 포털 현재 제한을 읽습니다. 티켓에 이미 조치 기록이 있으면 포털 제한이 그 티켓 소유일 때만 200 `duplicate_no_action`이고, 아니면 409 `held_portal_mismatch`입니다. n8n 생산 실행 동시성은 1입니다.

승인 해제 입력은 같은 case_id·asset_id·username과 정확한 ticket_id입니다. 별도 운영자 키가 필요하며 현재 티켓·케이스·자산·계정·활성 소유권을 확인합니다. 포털의 티켓 소유권 검사는 마지막 방어선입니다. 응답에는 비밀값을 포함하지 않습니다.

외부 HTTP 효과는 검증기가 별도로 관찰합니다. n8n의 현재 상태 조회 성공은 `applied_verified=true`로 기록하지만, 그것만으로 HTTP 효과를 확인했다고 표시하지 않습니다. 현재 H1 티켓의 effect_verified/verified_at은 null이며 실제 효과는 실행 증적에 있습니다. 대시보드 MTTD도 condition_met_at이 없으면 미측정입니다. 실측기는 다섯 번째 고유 성공 이벤트 시각으로 지연을 별도 계산합니다.
