# 제한된 PF 차단·해제 도구

11/03 로컬 보강 후보. **새 후보의 장비 배포·실제 재인수는 미실행**이다.
기존 설치본 ACCEPT01은 차단 효과 확인 후 841/843 실패·B 수동 정리로 복구했다.
과거 실패를 이번 후보의 성공 증거로 바꾸지 않는다.

## 호출과 범위

`haedam-pf-response ACTION TARGET REQUEST_ID OWNER_ID`

- ACTION은 status/block/unblock. 기존 r5와 같은 시험 IP .22/.41만 허용.
- CE2.7.2-RELEASE, WAN em0/203.0.113.1. 다른 환경·CIDR·보호 IP 거부.
- SSH_ORIGINAL_COMMAND는 파싱만 하며 임의 셸을 실행하지 않는다.
- 단일 owner journal로 직렬화. 다른 owner/target·ID충돌·미관리 차단은 거부.
- 성공 stdout JSON/exit0, 실패 JSON/exit1. effect_verified는 계속 null.
- C/D 매핑은 112/pfsense/block 또는 unblock. C 저장 여부는 D의 별도 모드.

## 반영 대기

변경 명령은 1회만 실행하고 상태 조회만 반복한다. 각 반영 대기 구간은8초,
간격은 최대0.25초이며 pfctl 조회에도 남은 시간을 전달한다. 전체 SSH 제한은 아니다.
EasyRule 최대30초, 대상 state 제거·조회, 정리PHP 최대20초의 실행 시간이 별도라
D는 SSH timeout을 함께 대조해야 한다. 실패·조회불능·시간초과·다른 항목 변경은
failed/changed:null과 pending/실패 receipt를 보존한다. failure_detail은 고정코드다.
같은 실패 ID를 자동 재실행하지 않는다. 보상 해제도 새 ID이며 과거 실패는 보존한다.

## 규칙 소유권과 해제

변경 전 config/runtime 규칙 유무를 claim에 기록한다. 빈 기준 상태에서 생성한
단일 tracker만 owner 소유 근거로 저장한다. target alias/table 제거 반영 후
동일 tracker·WAN·EasyRule 설명·빈 alias/table을 다시 확인하고 해당 규칙만
native config backup/write_config와 filter reload로 제거한다. 기존 빈 테이블은
보존한다. 전체 state flush는 없고 block에서 대상 state만 제거한다.

기존 공유 규칙은 삭제하지 않는다. 기존 규칙을 보존하며 target만 해제한 결과는
released일 수 있고 상태필드로 드러난다. 규칙0 조건의 단독 인수는 빈 기준 상태에서
시작한다. 변경된 tracker·다른 항목 추가·소유 근거 없는 구 claim은 pending을 유지한다.
config 변경 직전 해시 대조로 충돌을 거부한다. journal lock은 도구 호출끼리만
직렬화하므로 공동 시험 중 GUI 등 다른 방화벽 편집을 하지 않는다.

## 출력 필드

| 필드 | 의미 |
| --- | --- |
| configured | 정확한 target IP의 config alias 등록 여부. 규칙 존재와 다름 |
| table_present | 정확한 target IP의 runtime table 등록 여부 |
| config_rule_present | 테이블을 참조하는 config 규칙 존재 |
| runtime_rule_present | 테이블을 참조하는 runtime 규칙 존재 |
| rule_present | WAN IPv4 quick block과 pass보다 앞선 순서까지 확인 |
| journal_state | status의 실제 claim owner/target·pending action/request ID |

[스키마](../../contracts/pfsense-response.schema.json)는 기존1.0 키 의미를 유지하며
필드를 추가한다. 엄격한 소비자는 새 스키마와 함께 갱신한다. 합성 예시는 실측이 아니다.

## 검증과 반영

`python -m pytest tests/test_pfsense_response.py tests/test_pfsense_readback.py tests/test_pfsense_bundle.py tests/test_contracts.py -q`

지연·timeout·공유규칙·다른 owner/target·tracker 변경·부분 해제·실패 보존을
격리 검증한다. 실제 반영은 [설치 안내](INSTALL.md), D PR128 게시본/timeout 대조와
별도 GO가 필요하다. 빈 기준 → 자동block/pending0 → 대상 연결실패/정상200 →
자동unblock/claim0/pending0/이번규칙0 → 양쪽200을 재인수한 후 S10 실제 회차로 간다.
