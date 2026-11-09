# n8n 워크플로 내보내기

**현재 파일은 10/26 학원 D 후보(#56→#57→#61→#63)에 집 C/D 교정을 더한 미배포 후보다.** 모든 내보내기는 active:false, 동작은 dry_run:true다. 실제 n8n 가져오기·엔진 실행과 장비 효과/원복은 이번 집 작업에서 검증하지 않았다.

## 생성 원본과 검사

```powershell
python tools/build_n8n_workflows.py
python tools/build_n8n_workflows.py --check
python tools/build_ticket_guard.py --check
python -m pytest tests/test_n8n_workflow_integration.py tests/test_ticket_store_core.py -q
```

원본: tools/gen_n8n_workflows.py → gen_n8n_cases.py → gen_n8n_stage2.py → tools/n8n_hardening.py 최종 교정. **기본 생성기만 단독 실행하지 않고 build 명령을 사용한다.** --check는 임시 생성과 바이트 비교만 수행한다. haedam-16은 별도 build_ticket_guard.py 원본을 유지한다.

## 구성

| 파일/ID | 역할 | 현재 범위 |
| --- | --- | --- |
| haedam-00 | 수신 확인 | 10/22 D 로컬363·364 시험 기록, 인증/중복 방지 없음 |
| haedam-01 | C 저장소 연결 확인 | 실제 check HTTP 경로 후보. C #59는 10/26 인증 조회/쓰기 성공을 보고하지만 이번 교정 버전의 실제 엔진 시험은 별도 |
| haedam-10 | C check/record/active | store_real=true면 C 8088, false면 자리표시. store_real이 없는 기존 호출만 dry_run=false를 실제 저장으로 해석. 조치 모드와 분리하며 dry_run/skipped 결과는 detected 티켓만 기록. 키는 별도 자격 증명, via·target 단독 조회 보존·형식/실패 보류. 5xx/응답 없음에 같은 키·본문1회 재시도, 노드 기본 재시도 끔 |
| haedam-11 | Discord 알림 | D 10/23 dry_run에서 실행412 도착 보고. 이번 집에서 메시지 발송 없음 |
| haedam-12·13 | 포털 IP 조치·계정 잠금 | HTTP 후보. 실제 호출/배포/효과는 학원 확인. IP 조치 후 목록 반영은 effect와 구분 |
| haedam-14·15 | PF 경계·Wazuh 복구 | main #72의 실제 호출 노드 후보를 포함. 기본 dry_run·비활성·자격 증명 미포함, 실장비 미실행. B #64 전용 SSH/C117 권한·운영 연결은 별도 |
| haedam-16 | 집 오프라인 판단 가드 | 별도 합성 후보. 실제 호출 허용=false. [입력·제약](../guards/README.md) |
| haedam-20 | S12 | 기준선 기본null. 회복은 health200/본문 정상 필요. VPN 관측으로 실제 외부 경로 effect를 완료 처리하지 않음 |
| haedam-30·31 | S1·S4 | via 포함 중복, 조회/기록 실패·terminal 상태 후 대상 호출 중단. S4 username 잠금은 backend #3 등 배포 필요 |
| haedam-32 | S8·S10 | portal/pfsense를 via로 구분. PF 적용은 block, 해제는 unblock |
| haedam-33 | S7 | group_key=asset_id:file_key, action.target=file_key. 실제117 호출 미연결 |
| haedam-40 | 효과 보고 | 시험 스크립트/사람의 독립 근거가 필요. Webhook 인증/권한의 운영 인수 미완료 |
| haedam-50 | 사람 요청 원복 후보 | 자산/경로/동작/대상별 활성 소유권 대조. 같은 자리 다른 티켓·닫힌 미해제 조치도 보류. live_release_enabled=false 추가 유지 |

## 호출·증거 의미

- 포털 키와 C X-Response-Key는 서로 다른 n8n 자격 증명이다. JSON·프롬프트·일지에 값을 넣지 않는다. C 운영 서비스의 이전 버전은 /active가 없을 수 있으므로 교정 코드 채택/재빌드/별도 DB 시험이 선행돼야 한다.
- check는 사건 묶음, active는 실제 자원이다. 정상 응답의 완전한 빈 목록만0건이다. 실패/누락/정의 없음/서비스 미가동은0건이 아니다.
- 10/27 통합 후보는 활성 조치가 없는 restored의 새 이벤트 detected에서 이전 회차를 닫고 새 open 티켓을 먼저 확보한다. 과거 이벤트/이전 ticket_id 캐시는 대상 호출 전에 중단한다. 주 대응은 ACK 뒤 현재 seat/group을 재조회하여 같은 ticket_id·비종료 상태를 대조한 결과만 대상 입력으로 넘긴다. 수동 close 뒤 부재·다른 회차·조회 실패도 중단하며 예약/잠금은 아니다. 대상 성공 뒤 기록 실패는 대상 재실행 대신 기존 요청/상태 대조부터 한다.
- detected_at은 입력 Graylog 생성 시각을 보존하고 없으면null, received_at은 n8n 입력 시각이다. MTTD는 condition_met_at→Graylog detected_at으로 계산한다.
- 원복 전 자원 조회는 읽기 스냅샷이며 동시 적용/해제 보호가 아니다. 모든 호출자 직렬화·소유자 인증·실제 원복 독립 확인을 인수하기 전 실해제를 활성화하지 않는다. approver 문자열은 인증이 아니다.
- 기존 pfsense fw_block은 C에서 block 자원으로 읽기 호환한다. 원본 이력을 지우지 않는다. 새 소비자와 서비스는 같은 매핑/버전으로 채택한다.
- 원문 수신/정규화, dry_run/실제 HTTP/목록 반영/실제 효과, 티켓 생성/정상 사용자 영향/원복을 각각 기록한다. 현재 후보는 원복 후 외부 정상 동작을 자동 검증하지 않는다.

[상세 변경·미검증·학원 인수](../../../docs/home-integration-1027.md) · [S1 단독 시험 카드](../../../docs/school-s1-card-1026.md)

## 10/27 main 최신화

- main3f52b03의 포털 본문 필드 방식·티켓 입력 전달·보호 대상203.0.113.12·자격 증명 연결 설명·PF/Wazuh 호출 노드 후보를 반영했다. 자격 증명 값·학교 설정·실제 호출을 적용하지 않는다.
- 생성 순서는 gen_n8n_workflows → gen_n8n_cases → gen_n8n_actions → gen_n8n_stage2 → 기존 harden이다. `python tools/build_n8n_workflows.py`가 이 순서를 묶고 `--check`로 JSON 재현성을 검사한다. 생성은 n8n 실행이 아니다.
- haedam-02의 포털 호출 시험 입구는 입력의 dry_run과 관계없이 true로 고정한다. haedam-14/15의 실제 호출 분기는 명시적인 dry_run=false와 현장 자격 증명/권한/경로 검증이 필요하다. 이 집 통합에서는 활성화·호출하지 않았다.
- 기존 시간·via 자원 대조·오류/미확정 중단·live_release_enabled=false 조건은 유지한다. 이전 문서의 ‘14/15 자리표시’ 설명은 이 후보에 대해서는 위의 호출 노드 준비 상태로 읽는다. 학원 배포/효과/원복 완료를 뜻하지 않는다.


## Webhook 인증 정적 점검

`python tools/check_n8n_webhooks.py --expected-webhooks 10`으로 수신 인증 선언을 읽기 전용 검사한다. 현재 후보는 내보내기17개 중 Webhook10개 모두 내장 인증 미설정으로 **종료1**이다. inactive는 수신 인증 설정을 대신하지 않는다. 학원 게시본의 실제 보호 상태는 미확인이다. 종료0도 자격 증명 참조/선언에 한정하며 실제 인증 통과를 뜻하지 않는다. [검사 결과·D의 격리 거부/허용 인수 절차](../../../docs/n8n-webhook-audit-1027.md)를 따른다. 이 점검에서는 JSON·생성 원본·실제 키/설정을 변경하지 않았다.


S1의 고정 소스 묶음/의존성은 `python tools/check_s1_candidate.py`로 한 번에 확인할 수 있다. 종료0은 로컬 소스 일치이며 실제 준비 완료가 아니다. 현재 S1 수신 인증 발견1건과 실행 환경 pending은 별도로 남는다. [기존 S1 카드](../../../docs/school-s1-card-1026.md)의 명령 해석·현장 인수를 따른다.
