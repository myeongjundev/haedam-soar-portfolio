# S1·S4 Graylog 이벤트 정의 (A 제안 → D 반입)

- 상태: **제안 · 미반입 · Graylog 미시험** (2026-10-26). 오프라인 점검 `check.py`만 통과.
- 기준: [룰 정의](../../../docs/capstone/A-S1-S4-정상패턴.md) §1, 기획서 합의본 ④·5.9. 보강 전 S1·S4는 10/22 완료라 반입해도 된다. 단 B의 S8·S10 보강 전 측정 동안은 꺼 둔다(S8 공격의 로그인 반복이 S1을 발동시킴).

| 파일 | 케이스 | 쿼리(스트림 `haedam-portal`) | 묶기 | 조건 | 창 / 실행 |
| --- | --- | --- | --- | --- | --- |
| `s1-login-bruteforce.json` | S1 | `source:haedam-portal`, `rule:"login-bruteforce"`, `status:401` | username, src_ip | `count() > 8` | 30분 / 1분 |
| `s4-fail-then-success.json` | S4 | 위 실패 + `rule:"login-success"` `status:200` | username, src_ip | `card(rule) > 1 && count() > 5` | 10분 / 1분 |

- `status:401`·`200`만 받아 429(포털 레이트리밋)를 뺀다. `source:haedam-portal`(포털 GELF `host`)로 D 로컬 시험 로그(`zz-d-local`)를 뺀다(PROGRESS 3-5).
- 이벤트 필드 `username`·`src_ip`·`case_id`는 n8n Webhook 입력(112 차단 대상·111 잠금 대상)으로 쓴다.
- **반복 발동:** 1분마다 30분(10분) 창을 다시 보므로 조건이 유지되는 동안 같은 키로 여러 번 발동한다(S1 공격 입력에서 6회). `grace_period_ms`를 창과 같게 두어 알림(n8n 호출)은 키당 한 번만 나가게 했다. 티켓 중복은 n8n·티켓 저장소가 한 번 더 막는다.
- **첫 발동 지연:** 조건 성립 뒤 다음 실행까지 최대 60초(+ 수집 지연). MTTD 해상도로 결과표에 적는다.

## 반입 (D)

1. `REPLACE_haedam-portal_stream_id`를 `haedam-portal` 스트림 ID로 바꾼다.
2. `POST /api/events/definitions?schedule=true`(헤더 `X-Requested-By`)로 넣는다. 거부되면 Graylog 6.1 화면에서 같은 값으로 만들고 내보낸 JSON으로 이 파일을 고친다.
3. `notifications`는 비어 있다. n8n 웹훅 알림(`haedam-30`·`31`)은 D가 붙인다.
4. 넣은 뒤 1회: 실제 로그로 `status`가 숫자로 검색되는지, `username`·`src_ip` 이벤트 필드가 채워지는지 확인.

## 점검

```
python lab/s1s4/graylog/check.py
```

JSON의 창·실행 주기·묶기·조건식을 읽어 1분 실행을 재현하고 경계 입력 15개(S1 7·S4 8)를 판정한다. 쿼리를 바꾸면 `check.py`의 `QUERIES`도 같이 고친다. Graylog 실측이 아니다.
