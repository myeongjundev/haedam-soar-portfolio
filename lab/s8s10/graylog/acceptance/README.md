# S8·S10 격리 인수 프로파일 (11/02 B-observe)

- 상위 `lab/s8s10/graylog/` 정의에 출발지를 S8 `203.0.113.21`, S10 `203.0.113.22`로 고정하고 S10에 ICMP 목적지(`203.0.113.1`)·`pf_tracker` 조건을 더한 것입니다.
- `REPLACE_*`는 입력 직전에 채웁니다. 포털 스트림 ID는 `6ad95444188b5d4016e9d412`, pfSense 스트림 ID와 `pf_tracker`는 B가 확인한 값을 씁니다.
- 반입은 DISABLED로 하고, B의 입력 시작 직전에 켭니다. 알림(`s8-s10-n8n-notification.json`)은 n8n `haedam-32`(현재 `dry_run:true`, `store_real:false`)를 호출합니다.
- 실제 Graylog 반입·발동은 미검증입니다.
