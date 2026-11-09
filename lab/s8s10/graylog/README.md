# 10/31 집 통합 후보

현재 반입 순서는 [S8/S10 완주 안내](../../../docs/S8S10-COMPLETION.md)를 따른다. 404/401만 포함하도록 보완했고429는 제외한다. 알림은 detected_at도 전달한다. 첫 인수 프로파일은 .21/.22와 실제 입력 tracker로 분리한다. 실제 Graylog 반입/발동은 미검증이다. 아래 10/28 본문은 설계 이력이며 새 후보의 운영 완료를 뜻하지 않는다.

# S8·S10 Graylog 이벤트 정의 (B 제안 → D 반입)

- 상태: **제안 · 미반입 · Graylog 미시험** (2026-10-28). 오프라인 점검 `check.py`만 통과.
- 기준: 기획서 합의본 ④ 이벤트 조건(S8 `card(rule)>1`, S10 세 rule만 검색해 `card(rule)>2`, 15분, `src_ip`)·⑤ 5.2 입력표·5.9 순서 조건. 필드 값은 B의 보강 전 증적에서 실제로 확인한 것을 쓴다: 포털 `rule=web-scan`·`login-bruteforce`, pfSense 정규화 `src_ip`·`rule=pfsense-block`([S8-before-01](../../../docs/capstone/evidence/S08/before/S8-before-01/README.md)·[S10-before-01](../../../docs/capstone/evidence/S10/before/S10-before-01/README.md)).

| 파일 | 케이스 | 쿼리 | 스트림 | 묶기 | 조건 | 창 / 실행 |
| --- | --- | --- | --- | --- | --- | --- |
| `s8-scan-then-login.json` | S8 | 포털(`source:haedam-portal`)의 `web-scan`·`login-bruteforce` | `haedam-portal` | src_ip | `card(rule) > 1` | 15분 / 1분 |
| `s10-three-layer.json` | S10 | 위 둘 + `pfsense-block`(`pf_noise`·`pf_scope` 없는 것만) | `haedam-portal`, `pfsense` | src_ip | `card(rule) > 2` | 15분 / 1분 |
| `s8-s10-n8n-notification.json` | 알림 | 두 정의 공용. `haedam-32`(`/webhook/haedam-s8-s10`)로 `event_id`·`asset_id`·`src_ip`·`case_id` | — | — | — | — |

- **로그인 성공은 넣지 않는다.** 넣으면 pfSense 신호 없이도 rule 종류가 3개가 된다(합의본 S10 근거). 점검의 "PF 없음, 3종" 입력이 미발동이다.
- **S10의 pfSense 신호에서 브로드캐스트·멀티캐스트(`pf_noise`)와 팀 VPN(`pf_scope`)은 뺀다.** 둘 다 `pfsense-parse` 파이프라인(#75)이 붙이는 태그다. 팀원 VPN 주소의 기본 차단과 포털 실수가 겹쳐 S10이 뜨지 않게 한다.
- **쿼리 형식:** `rule:(A OR B)` 같은 필드 괄호형은 쓰지 않았다(강사님 참고 노션 [178]: 이벤트 정의에서 0건 발동). 대신 A의 S4(#65)와 같은 절 단위 괄호 `(… AND …) OR (… AND …)`다. 이 형식도 Graylog 이벤트 정의에서는 아직 시험하지 않았다.
- **반복 발동·grace:** 조건이 유지되는 동안 1분마다 다시 발동한다. `grace_period_ms`를 창(15분)과 같게 두어 알림은 출발지당 한 번만 나간다. 그래서 **같은 출발지로 15분 안에 다시 시험하면 알림이 나가지 않는다.** 회차마다 출발지를 바꾼다.
- **첫 발동 지연:** 조건 성립 뒤 다음 실행까지 최대 60초 + 수집 지연.
- **알려진 오탐(S8):** 신호 종류만 보므로 정상 사용자의 없는 주소 1회 + 비밀번호 오타 1회도 발동한다. n8n 보호 목록(팀 VPN·`.10`·`.12`·`.100~.109`)은 차단·티켓 전에 멈추지만, 목록 밖 정상 사용자는 차단될 수 있다. 5.10 사전 시험에서 오탐으로 기록하고, 기준선을 잰 뒤 `web-scan` 횟수 조건을 더할지 팀이 정한다.
- **S8·S10 동시 발동:** S10 조건이 채워지면 S8 조건도 이미 채워져 있다. 10/26 S10-before-01처럼 세 신호가 1초 안에 들어오면 두 정의가 같은 실행 주기에 발동한다. 그러면 `haedam-32`가 같은 출발지로 거의 동시에 두 번 불린다. 첫 시험에서 티켓 1건·포털 차단 중복 없음을 C·D가 확인한다.

## 반입 (D)

1. `REPLACE_haedam-portal_stream_id`·`REPLACE_pfsense_stream_id`를 실제 스트림 ID로 바꾼다.
2. 넣기 전에 Search에서 두 쿼리를 10/26 보강 전 원문에 돌려 필드 값을 확인한다. 새 입력은 필요 없다.
   - S8 쿼리, `src_ip:203.0.113.21`, 10/26 15:15~15:16 KST → `rule` 종류 2개.
   - S10 쿼리, `src_ip:203.0.113.22`, 10/26 15:20~15:21 KST → `rule` 종류 3개(pfSense 1건 포함).
   - Search 결과가 맞아도 이벤트 정의의 발동을 보장하지는 않는다(강사님 자료의 괄호형 문제는 이벤트 정의에서 나타났다).
3. `POST /api/events/definitions?schedule=true`(헤더 `X-Requested-By`)로 넣는다. 거부되면 Graylog 6.1 화면에서 같은 값으로 만들고 내보낸 JSON으로 이 파일을 고친다.
4. 알림: URL 허용 목록에 `http://host.docker.internal:5678/webhook/haedam-s8-s10`(Exact match)을 넣는다. `s8-s10-n8n-notification.json`으로 알림을 만들고 **두 정의 모두**의 `notifications`에 붙인다. 화면의 "Execute Test Notification"으로 `haedam-32` 실행 1건이 `invalid_input`이 아닌지 본다(기본 `dry_run`). 반입하면 이 파일은 `infra/graylog/notifications/`로 옮긴다.
5. 첫 실제 시험에서 이벤트가 뜨는지 확인한다. 0건이면 쿼리 형식부터 의심한다. 정의를 끄고 다시 켤 때마다 발동 이력으로 실제로 도는지 확인한다(강사님 자료: 다시 켠 정의가 켜짐으로 보여도 발동 0).

## 전제

- pfSense 로그는 **UDP**로 들어와야 `pfsense` 스트림과 파이프라인을 거친다. TCP 입력은 스트림 규칙 밖이다(#75 주석).
- S1 정의와의 섞임: S8·S10 입력에서 같은 계정의 로그인 실패가 30분 안에 9회 이상이면 S1도 발동한다. 입력은 8회 이하로 두거나, A README대로 S8·S10 시험 동안 S1을 끈다.

## 점검

```
python lab/s8s10/graylog/check.py
```

A의 `lab/s1s4/graylog/check.py`에서 1분 실행 재현·조건식·첫 발동 지연 함수를 불러 쓴다. 경계 입력 21개(S8 10·S10 11)와 S10-before-01 실제 입력 재생을 판정한다. 쿼리를 바꾸면 `check.py`의 matcher도 같이 고친다. A의 `check.py`를 바꾸면 두 점검을 함께 돌린다. Graylog 실측이 아니다.
