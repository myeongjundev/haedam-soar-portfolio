# S4 계정·세션 준비와 잠금·티켓·원복 증적

> 11/10 후속: HTTP 본문 누락 수정 후 새 개인 랩에서 실제 완주했습니다. [실측 결과·실패 수정](s4-results.md). 아래 검증 수치와 미실측 설명은 도구 준비 단계의 기록입니다.

2026-11-10 김명준·Codex, 개인 작업 `S4-SESSION-EVIDENCE`. PR #26 `2168478`에서 분리한 `codex/s4-session-evidence`입니다. **오프라인 구현·검증 완료이며 개인 Docker/Graylog/n8n 실측 완료는 아닙니다.** 기존 Docker·VM·MySQL을 변경하지 않았습니다.

## 작업 범위와 연결

[S4 입력 준비](s4-live-preparation.md)의 후속으로, S4 도구·설정·Compose 생성기·검사·문서를 변경합니다. 포털 API와 [S4 대응 계약](s4-contract.md), 팀 탐지 정책 및 생성된 n8n 흐름은 유지합니다. S1 검토 브랜치와 S1 소스도 수정하지 않습니다. 과거 팀 `workplan.json`/`team.py ready`는 역사적 P01 후보이며 이번 개인 완료 판정을 대신하지 않습니다.

| 도구 | 동작 | 하지 않는 일 |
| --- | --- | --- |
| `tools/s4_rehearsal.py` | 새 번들·별도 합성 비밀번호·소스 해시·증적 색인, 실제 ID/키를 넣은 import 생성 | Docker 실행, import/워크플로 게시 |
| `tools/s4_probe.py` | 정상 출발지에서 계정 준비, 대상 세션 2개·정상 세션 1개 보관, 잠금·원복 효과 확인 | 계정 잠금/해제 API 호출 |
| `tools/s4_collect.py` | 계정 상태 GET, 지정 티켓 상세 GET, 계정 상태 재조회, 허용 필드만 저장 | POST, 티켓 생성/수정, 자동 원복 |
| `tools/s4_evidence.py` | 입력·세션 검사·계정·티켓·이벤트·원복 응답 대조, 승인 원복 요청 본문 생성 | 실제 엔진 실행/증적 출처 인증, 원복 전송 |

계정명·주소·포트·경로·간격은 `infra/s4-settings.json`, 서비스 URL/자격증명 참조는 `infra/s4-integration-settings.json`을 소비합니다. 이번 설정에 `paths.register/private_mount/integration_mount`와 `observation.ticket_read_url`이 추가됐으므로 **기존 번들을 부분 수정하지 말고 새 번들을 생성**합니다.

## 세션과 비밀값 보관

기본값은 실행 비활성·계획 출력입니다. 실제 probe는 개인 Linux `normal` 컨테이너와 프로젝트 식별이 일치해야 합니다. 대상과 정상 계정의 서로 다른 비밀번호를 `{"target":"…","normal":"…"}` 형식의 JSON 한 줄로 stdin에 전달합니다. 명령행 인자나 환경변수에 넣지 않습니다.

baseline은 정상 출발지에서 시민 계정 2개를 가입합니다. 이미 있는 계정의 409 응답만으로 준비를 통과시키지 않고, 지정 비밀번호로 로그인해 계정 ID·시민 역할·잠기지 않은 상태를 확인합니다. 대상 세션 2개와 정상 세션 1개의 쿠키는 모두 달라야 합니다. 정상 출발지를 사용하므로 대상의 공격 IP 검색 키에 준비용 200을 추가하지 않습니다.

- `passwords.json`: 호스트의 번들 루트에만 저장하며 컨테이너에 마운트하지 않습니다.
- `private/<run-id>-sessions.json`: 원본 쿠키, 계정 ID, 설정/소스 해시, 회차 식별자, 비밀번호 연속성 확인용 salt·PBKDF2 digest를 저장합니다. 비밀번호 원문은 저장하지 않습니다. **normal 컨테이너만 접근**합니다.
- `runs/`: 쿠키·비밀번호·CSRF·응답 원문·예외 메시지를 제외한 공개 검토용 JSON입니다. 원본 쿠키나 비밀번호 digest도 내보내지 않습니다.

private 파일은 배타 생성하며 POSIX 0600, 폴더는 0700을 요청합니다. Windows 바인드 폴더의 접근은 호스트 ACL도 따르므로 `.local` 전체를 공유하지 않습니다. `.local`은 Git에서 제외합니다. 종료 후 원본 쿠키/비밀번호는 재검증 필요 기간 동안만 로컬에서 보관합니다.

잠금·원복 검사는 저장했던 **원본 쿠키**를 매번 다시 사용합니다. 잠금 후 서버가 새 익명 쿠키를 반환해도 원본 파일을 바꾸지 않습니다. 정상 세션이 만료되거나 잘못된 계정으로 바뀌면 실패로 남기며 자동 재로그인으로 옛 세션 검사를 대신하지 않습니다. 별도의 새 로그인 검사에는 baseline과 같은 비밀번호만 허용합니다.

## 관찰 컨테이너와 실행 상한

새 overlay의 선택형 `observer`는 `s4-evidence` Compose profile에 속하며 `network_mode: service:n8n`으로 **새 개인 n8n의 망 공간만 공유**합니다. 기존 서비스나 다른 프로젝트의 n8n을 지정하지 않습니다. 포털 조회는 설정된 n8n 응답 IP에 바인딩합니다. 포털 `RESPONSE_ALLOWED_CIDRS`는 기존 n8n `/32` 그대로이며 별도 IP를 허용하지 않습니다.

observer에는 도구·설정·증적 폴더만 마운트하며 private 폴더·비밀번호·lab.env는 마운트하지 않습니다. 조회할 때 포털 대응 키만 stdin으로 받습니다. 이 키 자체는 기존 대응 권한도 가지지만 수집기 구현은 두 종류의 고정 GET만 제공합니다. 키를 티켓 대시보드 요청에 전달하지 않습니다. 임의 URL·경로·리다이렉트·재시도는 허용하지 않고 응답은 최대 1MiB로 제한합니다.

| 단계 | probe 최대 HTTP | snapshot 최대 GET | 확인 사항 |
| --- | --- | --- | --- |
| baseline | 14 | 1 | 대상 2세션·정상 1세션, 계정 unlocked·owner 없음·활성 대상 세션 2개 이상 |
| locked | 9 | 3 | 옛 대상 세션 2개 무효, 같은 비밀번호 새 로그인 401, 정상 옛/새 세션 정상, 실제 소유 티켓·계정 locked·세션 0 |
| restored | 10 | 3 | 옛 대상 세션은 계속 무효, 같은 비밀번호 새 로그인 200, 정상 옛/새 세션 정상, unlocked·owner 없음·티켓 restored·활성 조치 0 |

snapshot은 계정 → 티켓 → 계정을 읽어 사이에 상태가 바뀌면 실패합니다. baseline 계정 조회만으로 기존 티켓이 0건이라고 주장하지 않습니다. 전체 증적 검사는 입력 이후 생성된 동일 티켓의 이벤트·계정 ID·잠금 이력과 후속 해제 이력을 대조합니다.

probe는 입력 도구와 같은 `input.lock`으로 동시 실행을 막습니다. STOP 파일을 요청 전 확인합니다. probe/snapshot 파일의 `--attempt`는 기본 1, 허용 범위 1~9이며 이전 파일을 덮어쓰지 않습니다. 재시도는 수동으로 새 attempt를 지정해야 합니다. 실패한 준비가 만든 계정/세션은 자동 삭제하지 않습니다. 실패 증적을 확인하고 새 회차 또는 랩 정리 절차로 이어갑니다.

## 지금 가능한 오프라인 준비

```powershell
python tools/s4_rehearsal.py prepare --run-id s4prep20261110b --output .local/s4-session-prep-20261110
python tools/s4_probe.py --settings infra/s4-settings.json --run-id s4prep20261110b --phase baseline
python tools/s4_collect.py --settings infra/s4-settings.json --integration infra/s4-integration-settings.json --run-id s4prep20261110b --phase baseline
python tools/build_s4_workflows.py --check
python -m pytest tests -q
```

`prepare`는 새 출력 경로만 허용하고 실행 플래그는 기본 false입니다. 이후 실측 실행 순서가 정해지면 `--arm-input`으로 **다른 새 번들**을 생성합니다. 코드/설정이 바뀐 뒤 기존 번들을 재사용하면 해시 검사에서 거절합니다. 검증 명령에 사용한 임시 DB와 새 번들 생성은 기존 Docker/VM을 사용하지 않습니다.

실제 Graylog 입력·index set·stream·notification ID를 확보한 뒤 로컬 bindings JSON을 `imports --bundle <번들> --bindings <JSON> --enable-detection`에 전달합니다. 이는 키가 포함된 import 파일을 `.local`에 만들 뿐 실제 가져오기·게시·스케줄 활성화를 하지 않습니다. 다섯 키 분리·실제 ID 형식·기존 파일 덮어쓰기 거부를 적용합니다.

## 이후 개인 실측 순서

1. PR 검토와 메모리·포트·망 충돌 점검 후 개인 새 랩의 기동 순서를 정합니다. 이번 작업에서는 기존 환경을 중지하거나 observer를 기동하지 않았습니다. 관찰 profile 사용 시 10개 서비스이며 기본 랩은 기존 9개입니다.
2. 개인 서비스와 `s4-evidence` profile을 기동하고 마이그레이션·import·게시를 확인합니다. 탐지 스케줄은 준비 중 비활성으로 유지합니다. 생성된 `input-packet.json`의 명령 배열을 사용하며, `plan_argv`는 계획만 출력합니다. `input_argv`에는 실행 플래그가 있어 사전 조건을 마친 뒤 사용합니다.
3. `probe_baseline`에 호스트 `passwords.json` 내용을 stdin으로 전달하고, `snapshot_baseline`에 로컬 `PORTAL_RESPONSE_KEY` 한 줄을 stdin으로 전달합니다. 비밀값을 화면에 출력하지 않습니다. probe 통과 뒤 snapshot을 실행합니다.
4. 같은 username+공격 IP의 600초 검색창이 깨끗한지 확인하고 탐지를 활성화합니다. 경계 입력은 [이전 준비 절차](s4-live-preparation.md)를 따르며 각 유형을 섞지 않습니다. 이번 완주 검사기는 `trigger6` 5실패+1성공 회차를 검증합니다.
5. 실제 Graylog 원천 401/200과 이벤트를 확인합니다. **Graylog 이벤트 자동 내보내기는 이번 도구에 없습니다.** 실제 event ID, definition ID, `fields.username/src_ip`, `timestamp_processing`을 가진 export를 별도 로컬 JSON에 보관합니다. 알림 요청을 직접 보낸 결과를 Graylog 자동 탐지 증거로 대신하지 않습니다.
6. 자동 대응 후 `probe_locked`, `snapshot_locked`를 차례로 실행합니다. snapshot 명령의 `<actual_ticket_id>`는 실제 티켓 ID로 교체해야 하며 미교체 시 거절됩니다. 수집기는 티켓을 새로 만들거나 목록의 첫 티켓을 임의 선택하지 않습니다.
7. 탐지 스케줄·알림과 대기 실행을 확인해 원복 중 재대응을 방지합니다. `python tools/s4_evidence.py release-body --bundle <번들>`로 **검증된 잠금 snapshot에 대응하는 본문만** 생성합니다. 승인된 운영자 원복 워크플로에 별도 키로 전달하는 동작은 기존 절차로 수행합니다. 본문 생성은 승인·전송·현재 상태 재확인을 대신하지 않습니다. 워크플로는 실행 시 현재 소유권을 다시 검증합니다.
8. 실제 원복 응답을 로컬 JSON에 보관하고 `probe_restored`, `snapshot_restored`를 차례로 실행합니다. 같은 비밀번호의 새 로그인과 옛 세션 무효, 정상 계정 영향 없음, 티켓/계정 소유권 해소를 확인합니다.
9. `evidence-index.json`에 실제 Graylog export·definition ID·원복 응답 경로와 사용한 attempt 경로를 연결합니다. `python tools/s4_evidence.py check --bundle <번들>`로 회차/계정/출발지/코드 해시/입력 간격/세션 식별/이벤트/티켓 이력/시각을 대조합니다. 경로 탈출이나 private 폴더를 증적으로 연결하면 거절합니다.

검사 결과의 `artifact_consistency=passed`는 제공한 파일들이 일치한다는 뜻입니다. **`provenance_attested=false`를 유지**하므로 실제 엔진 실행과 원천 증거의 출처는 별도 검토해야 합니다. n8n 실행 화면·DB 직접 감사·실제 Docker 망 검증을 이 결과로 대신하지 않습니다.

## 이번 검증 결과와 인계

- 전체 호스트 **150 passed·63 subtests passed**. 새 검사는 실행 기본 거부·역할, private 마운트 분리, GET/응답 상한·오류/리다이렉트 중단, STOP·덮어쓰기 거부, 새 번들·키 분리·소스/설정 변경 거부, 증적 경로 경계를 포함합니다.
- 실제 Flask·임시 SQLite 관련 **27 passed**, 기존 마이그레이션 `get_engine` 폐기 예정 경고 4건. 세션 준비 → 실제 로그인 입력 → 생성된 워크플로 그래프의 계정 잠금·티켓 → 승인 해제 → 세션 효과·계정·티켓 수집 → 최종 일치 검사를 수행했습니다. 그래프 HTTP를 테스트 클라이언트에 연결했으며 n8n 엔진·Graylog·실제 소켓은 사용하지 않았습니다.
- 정상 세션 손상, 옛 세션 무효 누락, 바뀐 비밀번호, 회차/계정 ID·티켓 소유권/이벤트 불일치, 해제 이력 누락, 429 입력 혼입, 소스 해시 변경, 잘못된 원복 응답을 거절했습니다. baseline 원본 쿠키 파일이 잠금/원복 검사 후에도 동일한지 확인했습니다.
- 최초 통합 검사에서 가상 입력 시계와 그래프의 실제 원복 시각이 달라 시간 검사가 실패했습니다. 검증 허용치를 늘리지 않고 테스트 시계를 그래프 경계에서 맞춘 뒤 통과했습니다. 실제 실측에서는 호스트·컨테이너 시계와 Graylog 수집 시각을 대조해야 합니다.
- S4 n8n 4개·Graylog 1개 생성물 일치. 새 로컬 번들의 `docker compose --profile s4-evidence config --format json`에서 10개 서비스, private=normal 전용, observer=n8n 망 공유, 응답 허용 `/32` 유지, localhost 포트 5개를 확인했습니다. **Compose 설정 해석만 실행**했습니다.

다음 담당은 이 PR의 세션 원본 보존·민감값 제외·응답 계약·증적 거절 조건을 검토하고, 실제 실행 순서가 정해지면 새 번들에서 준비 → 경계/탐지 입력 → 잠금/원복 관찰을 진행합니다. 실제 이벤트 export, 원복 전송, 실측 화면과 시간 기록은 남아 있습니다. PPT에는 아직 개인 S4 실측 통과를 추가하지 않습니다.
