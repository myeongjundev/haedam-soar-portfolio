# 개인 S8 연결 계약

이 문서는 `compose.s8.yaml`과 `infra/n8n/portfolio-s8/`의 개인 랩 계약입니다. 팀 원본 JSON은 출처용으로 보존하며 일괄 게시하지 않습니다. Flask 대응 API와 티켓 저장 API의 본문·스키마는 변경하지 않습니다.

## 주소와 인증

| 호출 | 주소 | 인증 |
| --- | --- | --- |
| Graylog → n8n | `http://n8n:5678/webhook/haedam-s8-s10` | `X-S8-Detection-Key`, n8n `s8DetectionAuth` |
| 검증 도구 → 효과 기록 | `http://127.0.0.1:15700/webhook/haedam-effect-report` | `X-S8-Operator-Key`, `s8OperatorAuth` |
| 담당자/검증 도구 → 원복 | `http://127.0.0.1:15700/webhook/haedam-release` | 같은 운영자 키 |
| n8n → 티켓 | `http://ticket-store:8088/api/v1/tickets` | `X-Response-Key`, `s8TicketAuth` |
| n8n → 포털 대응 | `http://portal-response:5000/api/v1/response/ips` | 별도 `X-Response-Key`, `s8PortalAuth`; 출발지 `172.30.89.2/32` |

키 값은 로컬 `.env.soc`·`.env.s8`과 서비스 저장소에만 둡니다. n8n 가져오기용 비밀 JSON은 컨테이너 안에 0600 권한으로 잠시 만들고 삭제합니다. Git 파일에는 자격증명 ID만 있습니다. Graylog API 관리자와 Docker 접근 권한 보유자는 신뢰된 로컬 운영자입니다.

## 탐지와 대응

S8은 같은 `src_ip`의 15분 이내 `web-scan/status:404`와 `login-bruteforce/status:401` 두 종류를 결합합니다. 순서를 요구하지 않습니다. 실행 주기는 개인 시연용 15초이며 팀 기본 60초와 구분합니다. 소스가 포털인 실제 스트림 ID를 생성해 연결하고, 랩 클라이언트 대역을 조회합니다. 조치 허용 대상은 `172.30.88.21` 하나입니다.

알림 본문은 `event_id`, `asset_id:haedam-portal`, `case_id:S8`, `src_ip`, `detected_at`, `dry_run:false`, `store_real:true`입니다. 스크립트가 가진 탐지 키로만 이 경로를 호출할 수 있습니다. S10·다른 자산은 400, 다른 IP는 조치 없이 `protected_source`로 종료합니다. n8n의 부분 실행으로 실제 조치를 우회하지 않습니다.

## 원복과 효과 보고 변경

원복은 [요청 스키마](../contracts/s8-release.schema.json)와 [합성 예시](../contracts/ticket-examples/s8-release.json)를 따릅니다. 팀 후보에 비해 **`ticket_id`가 필수**입니다. 현재 티켓과 다르면 보류하고, 다른 티켓이 같은 자원의 활성 조치를 소유하면 해제하지 않습니다. 본문 `approver`는 신원으로 사용하지 않고 운영자 자격증명의 고정 식별자 `portfolio-operator`를 기록합니다.

효과 보고도 같은 `ticket_id`를 요구합니다. 원래 필드 `seat/case_id/group_key/asset_id/bot/via/action/target/effect_verified`와 함께 보내며, 현재 티켓 ID와 상태를 조회한 뒤 기록합니다. 허용 조치는 `B/S8/haedam-portal/112/portal/block/172.30.88.21`입니다. 원복 전 독립 HTTP 관찰로 공격 403과 정상 200을 확인한 후 효과를 보고합니다.

생산 웹훅의 실행 동시성은 1입니다. 차단·원복·효과 보고를 이 n8n 인스턴스로 직렬 처리합니다. 수동 편집기 실행·CLI 실행·외부 API 직접 변경까지 보호하는 분산 잠금은 아닙니다. 실제 랩 시험 중에는 이 경로를 병행 사용하지 않습니다. [n8n 동시성 적용 범위](https://docs.n8n.io/hosting/scaling/concurrency-control/)

## 성공·실패와 재시도

- HTTP 200은 정상 처리 또는 명시적인 중복 무조치입니다. 본문의 `ok`, `verdict`, 실제 티켓·포털 상태를 함께 확인합니다.
- 잘못된 입력은 400, 없는/틀린 웹훅 키는 403입니다. 티켓 조회·기록 실패나 상태 확인 실패는 503, 다른 자원의 소유권 보류는 409입니다. 예외로 중단된 n8n 실행은 500입니다.
- 티켓 저장소·포털 HTTP 실패에 대한 기존 하위 워크플로의 같은 키 1회 재시도를 유지합니다. 실패한 조치의 결과를 성공으로 기록하지 않습니다.
- Graylog 6.1.16 HTTP 알림은 non-2xx를 실패로 기록하지만 자동 재전송을 보장하지 않습니다. 장애 복구 후 **같은 Graylog 이벤트 ID**로 재시도합니다. 조치 반영 뒤 티켓 기록이 실패했다면 포털 상태와 동일 Idempotency-Key를 먼저 대조하며 새 사건 ID를 만들어 재차단하지 않습니다. [해당 버전 알림 구현](https://github.com/Graylog2/graylog2-server/blob/6.1.16/graylog2-server/src/main/java/org/graylog/events/notifications/types/HTTPEventNotificationV2.java)
- 원복 전에 탐지를 일시 정지합니다. 과거 15분 로그가 남은 채 규칙을 다시 켜면 새로운 집계 이벤트가 생길 수 있으므로, 재시험은 창이 지난 뒤 또는 새 개인 랩 볼륨에서 합니다.

## 증거와 알림

n8n 성공·실패·수동 실행의 원문 payload 저장을 끕니다. **2.39.5에서는 저장 끄기만으로 충분하지 않았습니다.** 기본 pruning은 실행을 soft-delete한 뒤 payload의 물리 삭제를 미뤘습니다. 해당 버전의 `deleteInFlightExecution` 구현을 확인해 개인 S8에는 `EXECUTIONS_DATA_PRUNE=false`를 함께 적용합니다. 이 조합의 생산 웹훅 실행은 종료 시 hard-delete 경로를 사용하며, 실측 종료 후 SQLite에 네 종류의 키가 남지 않는지 검사합니다. 모든 워크플로의 저장 끄기와 함께 유지해야 하며, 다른 워크플로를 추가하거나 버전을 바꾸면 재검증합니다.

장기 증거는 Graylog 이벤트 ID, 티켓의 n8n 실행 ID, 독립 HTTP 결과와 시각을 가린 JSON으로 보존합니다. 실행 중 처리에 필요한 일시적 DB 자료·SQLite 여유 페이지까지 암호화/삭제한다는 의미는 아닙니다. 기존 시험 데이터의 지연 삭제 자료는 증적을 가린 뒤 개인 시험용 볼륨을 새로 만들어 제거했습니다. [해당 버전 실행 저장 구현](https://github.com/n8n-io/n8n/blob/n8n%402.39.5/packages/cli/src/executions/execution-persistence.ts)

별도의 Discord 주소는 설정하지 않았으며 외부 메시지를 발송하지 않습니다. 티켓 대시보드에서 상태를 확인하고 반환값은 `discord_sent:false`입니다. 개인 S8 결과를 S10/pfSense나 나머지 시나리오의 검증 결과로 확장하지 않습니다.
