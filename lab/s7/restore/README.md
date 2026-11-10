# S7 117 파일 복구·격리 (포털 VM, agent 010)

`s7_restore.py`는 포털 VM에서 root로 실행합니다. 바뀌거나 지워진 파일은 기준본으로 되돌린 뒤 해시를 확인하고, 기준본에 없는 새 파일은 웹 루트 밖 격리 폴더로 옮깁니다. 동작마다 JSON 한 줄을 로그에 남기며, 파일 내용은 기록하지 않습니다(경로·해시·크기만).

> 상태(10/22): C의 WSL 임시 폴더에서만 시험했습니다. **VM 시험, n8n·Wazuh API 연결, manager `ossec.conf` 등록은 하지 않았습니다.**

## 위치

| 구분 | 경로 | 권한 | 이유 |
| --- | --- | --- | --- |
| 웹 루트(감시) | `/home/haedam/haedam-portal-frontend/dist` | 배포 계정 | FIM realtime 감시 대상 |
| 기준본 | `/opt/haedam-s7/baseline/` | root, 파일 0444 | 감시 폴더 밖, 웹 계정이 쓸 수 없음 |
| 해시 목록 | `/opt/haedam-s7/baseline.sha256` | root, 0444 | `sha256sum` 형식(상대 경로) → D 상관 규칙의 "복구본 해시" 목록 |
| 격리 | `/var/lib/haedam-s7/quarantine/<UTC시각>_<run_id>/` | root, 0700 / 파일 0400 | 웹 루트 밖, 실행 불가 |
| 로그 | `/var/log/haedam-s7/s7-restore.log` | root | 검문소 C `s7-restore.log` |

경로는 환경변수 `S7_WEB_ROOT`, `S7_STATE_DIR`, `S7_QUARANTINE_DIR`, `S7_LOG`로 바꿀 수 있습니다(연습 폴더 시험용).

## 명령

```bash
sudo python3 s7_restore.py baseline              # 현재 dist → 기준본 + 해시 목록 (승인된 배포 직후 1회)
sudo python3 s7_restore.py baseline --replace    # 정상 재배포 뒤 기준본 교체
sudo python3 s7_restore.py restore index.html --run-id s7-05
sudo python3 s7_restore.py restore /home/haedam/haedam-portal-frontend/dist/zz_x.html --run-id s7-02
sudo python3 s7_restore.py verify                # 웹 루트 = 해시 목록인지 (원복 확인)
sudo python3 s7_restore.py purge 20261022T032537Z_s7-02   # 격리한 시험 파일 삭제
```

- 마지막 줄 출력: `ok` / `error` / `mismatch`, 종료 코드 0 = 성공
- 인자 없이 실행하면 Wazuh 4.x active response 입력(stdin JSON)으로 동작합니다. `parameters.alert.syscheck.path`를 대상으로 쓰고, `extra_args[0]`이 있으면 run_id로 씁니다.
- 거부하는 경우: 웹 루트 밖 경로(`path_outside_web_root`), 디렉터리, 기준본 파일 해시가 해시 목록과 다른 경우(`baseline_missing_or_tampered`, 기준본 변조 방지)

## VM에서 할 순서 (A + C)

**① 보강 전 측정(테스트셋 #1)은 117 설치 전에 한 번만 합니다.** 보강 전 조건은 "S7 규칙·117 없음"입니다.

1. 시계: VM에서 `timedatectl`(`System clock synchronized: yes`인지)과 `date -u +%FT%T.%3N`을 실행해 C PC 시각과 비교합니다. 10/21에는 VM 기록이 경보보다 3~5초 늦었습니다.
2. 보강 전 #1: 새 시험 파일(예: `dist/zz_s7_run01.html`, 내용은 무해한 한 줄)을 만들고 시각을 기록합니다. 10분 안에 브라우저나 `curl -i`로 같은 경로에 접근해 200 응답과 시각을 기록합니다.
3. C가 manager `alerts.json`에서 010의 554 경보를 추출해 증적으로 저장합니다. 기대 결과는 "공격 성공, 로그만, 이벤트·티켓 없음"입니다.
4. 시험 파일을 지우고(553 확인), 남아 있는 `dist/zz_fimtest.txt`도 정리합니다.

**② 117 설치와 기준본**

5. `s7_restore.py`를 VM으로 복사합니다(예: C에서 `scp`). 권장 위치는 `/opt/haedam-s7/bin/`, root 소유, 0755입니다.
6. `dist`가 승인된 배포 상태인지 확인합니다(`zz_*` 시험 파일 없음). 확인한 뒤 `baseline`을 실행합니다. 출력의 `files=`와 `manifest_sha256=`를 기록합니다.
7. `verify`를 실행해 `ok`가 나오는지 확인합니다.

**③ 수동 복구·격리 시험(VM)**

8. 새 파일: `dist/zz_s7_manual01.html` 생성 → `restore … --run-id manual-01` → `ok` 확인 → `curl` 결과 404, 격리 폴더에 파일 있음
9. 변조: `index.html` 끝에 한 줄 추가 → `restore index.html --run-id manual-02` → `sha256_after = sha256_expected` 확인 → 정상 화면 확인
10. 원복: `purge <격리 항목>` → `verify`가 `ok`
11. C가 각 단계의 FIM 경보(554·553·550)와 로그 줄을 대조합니다. **복구 550의 `sha256_after`가 해시 목록 값과 같은지** 확인합니다. 이 값이 D 상관 규칙의 제외 조건 근거가 됩니다.

## Wazuh active response 연결 (`s7-restore-ar`)

> **상태(10/29):** VM 설치 완료(11:13 KST, 출처 A 10/28 일지 `work-log/members/whiteclover0542/2026-10-28.md`)와 Wazuh API 호출 시험 완료(`n8n-s7` 계정, 새 파일 격리·변조 복구 각 2회, 교체 전·후 기준본에서). 명령 이름은 `!s7-restore-ar`로 A와 맞춰 사용했습니다. 증적: `docs/capstone/evidence/S07/2026-10-28-ar-api-call-test.md`, `2026-10-28-ar-api-call-newbaseline.md`. 10/29에는 같은 호출로 새 파일 격리 1회·`index.html` 변조 복구 1회를 다시 했고 FIM 경보와 Graylog 수신을 대조했습니다(수동 호출, `2026-10-29-manual-ar-fim-compare.md`). **미시험:** n8n 워크플로 경유 호출, manager `<active-response>` 자동 실행 경로.

Wazuh는 agent의 `/var/ossec/active-response/bin/` 안 실행 파일만 부를 수 있습니다. 그래서 그 폴더에 연결 파일 `s7-restore-ar`을 두고, 이 파일이 `/opt/haedam-s7/bin/s7_restore.py`를 CLI 모드로 부릅니다. 설치된 `s7_restore.py`와 기준본은 바꾸지 않습니다.

| 구분 | 내용 |
| --- | --- |
| VM 설치 | `/var/ossec/active-response/bin/s7-restore-ar`, `root:wazuh`, `0750` |
| 호출(n8n → Wazuh API) | `PUT /active-response?agents_list=010`, 본문 `{"command": "!s7-restore-ar", "arguments": ["<경로>", "<run_id>"]}` |
| 경로 | 웹 루트 기준 상대 경로 또는 절대 경로. `arguments`가 없으면 `alert.syscheck.path` → `alert.data.syscheck.path` 순서로 찾음 |
| run_id | 영문·숫자·`.`·`_`·`-`, 1~64자. 격리 폴더 이름에 들어가므로 `/`는 거부 |
| manager 설정 | **바꾸지 않음.** `!`로 시작하는 명령은 manager 명령 목록(`ar.conf`)을 거치지 않고 agent 스크립트 이름으로 바로 전달됨(manager 4.9.0 API 코드 `validate_command`에서 확인). `<active-response>` 블록을 넣지 않으므로 FIM 경보마다 자동으로 실행되지 않음 |
| API 권한 | `n8n-s7`(역할 `n8n-s7-ar`)에 `active-response:command`, 대상 `agent:id:010`만 허용. 정책 조회와 실제 호출로 확인(10/28) |

- `alert`는 API 본문에 넣은 그대로 agent에 전달됩니다(`{"data": …}`). 그래서 경로는 `arguments`로 넘깁니다.
- 결과는 `s7_restore.py`의 로그 `s7-restore.log`에 남습니다. API 응답은 "agent에 전달됨"까지만 알려 주므로, 성공 여부는 로그·`verify`·FIM 경보로 확인합니다.
- 10/27 C의 WSL 임시 폴더 시험 결과는 모두 기대대로였습니다(새 파일 격리, 변조 복구, `alert.data` 경로, 잘못된 run_id·경로 없음·웹 루트 밖·JSON 오류 거부, `delete` 무시). VM 설치와 API 호출은 10/28에 시험했습니다(위 상태 줄의 증적).
- `!` 명령은 10/28 VM 시험에서 agent에서 실제로 실행됐고, manager `ossec.conf` 변경은 필요하지 않았습니다. 만약 실행이 안 되는 환경이면 manager `ossec.conf`에 `<command>`(이름 `s7-restore-ar`, 실행 파일 `s7-restore-ar`)와 자동 실행되지 않는 `<active-response>` 블록을 추가하는 방법이 있고, 이 경우 manager 재시작이 필요합니다.

### 자동 실행(`<active-response>`) 설계 — 미적용 (10/30)

FIM 경보(554·550, agent 010)가 뜨면 n8n·API 호출 없이 manager가 바로 agent로 AR을 보내는 조각을 `ossec-active-response-fragment.xml`에 준비했습니다. **아직 어떤 manager에도 넣지 않았고, 적용 여부는 팀과 시간을 맞춘 뒤 정합니다.** 이유:

- manager `ossec.conf`를 바꾸고 재시작해야 합니다. 지금 manager는 B·D의 Graylog 파이프라인이 실시간으로 쓰는 공용 인프라라, 재시작 시점을 혼자 정하면 안 됩니다.
- **배포 순서 문제가 있습니다.** `s7_restore.py`는 해시가 기준본과 다르면 무조건 "변조"로 보고 복구합니다. 정상 재배포도 550 경보를 내므로, 자동 실행이 걸려 있으면 **배포 직후 `baseline --replace`를 하기 전에 FIM 경보가 뜨면 방금 배포한 새 파일이 바로 이전 기준본으로 되돌려집니다.** 지금처럼 수동(API) 호출이면 사람이 배포인지 변조인지 보고 호출하므로 이 문제가 없습니다. 자동 실행을 넣으려면 B의 배포 절차가 "`dist` 교체 → 즉시 `baseline --replace`"를 FIM 감시보다 먼저 끝내거나, 배포 중에는 `<active-response>`를 끄는 절차가 같이 있어야 합니다.
- D 쪽도 영향이 있습니다. 지금 상관 규칙은 554·553·550이 시간차를 두고 들어온다고 보고 짰습니다(수동 호출 기준 수백 ms~수 초). 자동 실행이면 간격이 더 좁아지고 변조 550과 복구 550이 한 묶음으로 더 빨리 들어와서, 규칙의 중복 억제·`signal_kind` 판정이 영향받는지 D가 다시 봐야 합니다.

적용하기로 정하면: ① B가 배포 절차에 `baseline --replace` 순서를 넣거나 배포 중 `<active-response>`를 끄는 방법을 정하고, ② D가 위 간격 변화를 반영한 규칙을 확인하고, ③ 재시작 시간을 팀과 맞춘 뒤 ④ C가 조각을 `ossec.conf`에 넣고 재시작합니다.

## 확인할 점

- 복구는 같은 폴더에 임시 파일 `.s7restore.*`를 만든 뒤 이름을 바꿔 덮어씁니다. 이 임시 파일 때문에 FIM 경보가 추가로 생기는지 VM에서 확인하고, 생긴다면 상관 규칙 제외 조건에 넣습니다. 10/28 `index.html` 복구 3회(수동 ar-02m, API 호출 ar-02·ar-04)에서는 `.s7restore.*` 경보가 따로 없었고 `index.html`의 550만 발생했습니다. 격리 3회(ar-01m, ar-01, ar-03)까지 합친 6회 모두 대상 파일의 553·550 외 추가 경보는 없었습니다.
- 복구한 파일은 웹 루트 디렉터리 소유자·0644로 둡니다. VM의 실제 배포 소유자와 같은지 확인합니다.
- 포털이 컨테이너라면 bind mount 경로와 VM 경로가 같은 파일인지 확인합니다(VM에서 바꾼 파일이 바로 응답에 반영되는지).
