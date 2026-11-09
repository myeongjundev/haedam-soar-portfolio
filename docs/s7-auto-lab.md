# 개인 S7 · Wazuh → Graylog → n8n → 복구·티켓

실제 배포 파일의 변조/추가를 Wazuh가 감지하고, 신뢰한 에이전트 경보를 Graylog에 전달합니다. Graylog의 이벤트가 인증된 n8n 워크플로를 호출하면 티켓을 먼저 기록한 뒤 Wazuh Active Response로 복구·격리합니다. 전체 기준 파일 해시와 실제 HTTP 응답을 대조한 뒤 티켓을 `verified`로 갱신합니다.

김상혁의 팀 파일 복구 함수를 재사용하며, 개인 자동화의 전용 Compose·중계/검증 서비스·가드·워크플로·실측 도구는 김명준·Codex의 추가 작업입니다. **개인 FIM 즉시 대응 정책**입니다. 팀 S7의 FIM과 HTTP 접근 성공을 결합하는 상관 규칙을 그대로 검증한 것은 아닙니다. 백엔드 소스와 앱 로그 감시는 PR #8을 유지하지만 자동 수정 대상은 아닙니다.

## 설치

Windows Docker Desktop Linux 컨테이너, Python 3.12(`py -3.12`), Compose 2.24.4 이상(`!override` 지원)을 사용합니다. 12개 서비스가 실행되며 현재 약 6GiB WSL과 swap 4GiB에서는 기존 관제 환경을 잠시 중지하고 번갈아 실행합니다. 도구가 다른 프로젝트를 임의로 중지하지 않습니다. DB·관제·Wazuh 데이터는 프로젝트별 볼륨에 보존합니다.

```powershell
py -3.12 tools/s7_auto_lab.py init
py -3.12 tools/s7_auto_lab.py up
py -3.12 tools/s7_auto_lab.py ready
py -3.12 tools/s7_auto_lab.py configure
py -3.12 tools/s7_auto_verify.py
py -3.12 tools/s7_auto_failures.py
py -3.12 tools/s7_auto_lab.py stop
```

각 명령의 성공을 확인하고 다음으로 진행합니다. `init`은 수동 S7의 `.env.s7`·인증서도 먼저 준비하며 개인 자동화의 비밀값은 `.env.s7-auto`에 생성합니다. `.env.s7-auto.example`은 변수 목록입니다. 자격증명을 출력하거나 커밋하지 않습니다. 개인 수동 S7과 CA·bootstrap 자격증명을 공유하지만 컨테이너·볼륨은 별도입니다.

`configure`는 이미지와 실제 웹 볼륨 해시가 일치할 때만 복구 기준을 만들고, 전용 Wazuh 계정·규칙·워크플로를 설치합니다. 활성 티켓이 있으면 재설정을 거부합니다. 최초 기준 생성은 별도 setup 컨테이너만 수행하며 실행 중 에이전트와 연결 서비스에는 읽기 전용으로 제공합니다. 기존 기준은 덮어쓰지 않습니다.

기본 프로젝트는 `haedam-s7-auto`입니다. 새 볼륨 재현은 기존 개인 프로젝트를 중지한 뒤 `$env:S7_PROJECT='haedam-s7-autocheck'`를 설정하고 위 순서를 사용합니다. 공개 포트와 로컬 설정을 공유하므로 두 개인 프로젝트를 동시에 실행하지 않습니다. `down -v`는 실행 절차에 포함하지 않습니다.

| 화면/서비스 | 주소 |
| --- | --- |
| 해담 포털 | http://127.0.0.1:15030 |
| Graylog | http://127.0.0.1:19130 |
| n8n | http://127.0.0.1:15730 |
| 티켓·보안 대시보드 | http://127.0.0.1:18130 |
| Wazuh 대시보드 | https://127.0.0.1:15630 |
| Wazuh API / indexer | https://127.0.0.1:15530 / https://127.0.0.1:19230 |

Graylog `admin`은 `.env.s7-auto`의 `GRAYLOG_ADMIN_PASSWORD`, Wazuh `admin`은 `WAZUH_INDEXER_PASSWORD`를 사용합니다. n8n 소유자 설정은 최초 UI에서 진행할 수 있으며 워크플로 설치 자체는 컨테이너 CLI를 사용합니다. 브라우저 로그인·전역 신뢰 저장소를 도구가 변경하지 않습니다.

## 환경값과 변경 절차

비밀값은 `.env.s7-auto`, 비밀이 아닌 연결·감시 설정은 `infra/s7-auto-settings.json`에서 관리합니다. 공통 JSON의 `asset_id`, 에이전트 이름·대응 계정, `targets`, `paths`, `urls`를 중계 서비스·에이전트·워크플로 생성기·검증기가 함께 사용합니다. 위 주소와 아래 시험 파일은 기본 구성의 예시입니다. 호스트 공개 포트는 `.env.s7-auto`의 값을 우선하며 JSON의 `host_ports`는 최초 기본값입니다.

설정 변경 후 `init → up → ready → configure`로 재생성·재배포합니다. `init`이 로컬 JSON·Wazuh agent 설정·Compose 변수를 만들고, `configure`가 현재 설정으로 n8n 워크플로를 설치합니다. 저장소의 기본 워크플로 JSON은 `py -3.12 tools/build_s7_workflows.py`로 갱신합니다. 다른 설정 파일은 `S7_CONFIG_FILE` 환경변수로 선택할 수 있습니다. 비밀번호·토큰을 JSON에 넣지 않습니다.

서비스 내부 주소를 변경할 때는 상대 서비스의 Compose 리스너·네트워크 DNS·TLS 인증서도 일치시켜야 합니다. 외부 서비스 설정을 이 도구가 자동으로 변경하지 않습니다. 기존 Graylog 입력·스트림이나 기준 볼륨을 다른 대상으로 바꾸는 경우 새 개인 프로젝트로 검증합니다. 웹 홈 파일은 포털이 실제 `/`에서 제공하는 파일이어야 합니다. 운영자가 설정한 대상 외 경로, 경로 탈출, 임의 명령은 웹훅 입력으로 받지 않습니다. API 경로·S7 규칙 ID·티켓 상태는 환경값이 아닌 계약 상수입니다.

## 자동 조치와 원복 완료

| 입력 | 자동 대응 | 효과 확인 | 운영자 완료 |
| --- | --- | --- | --- |
| `index.html` 변조/삭제 | 승인된 기준 바이트 복구 | 전체 기준 해시 일치, `/` 200·본문 해시 | 복구 상태 재확인 후 처리 종료, `complete_restore` 기록 |
| `assets/s7-probe.txt` 추가 | 웹 루트 밖 격리 | 추가 파일 부재·404, 정상 기준 파일 유지 | 해당 티켓의 격리 파일 해시 확인 후 삭제, `complete_quarantine` 기록 |

원복 완료는 정상 파일을 다시 변조하거나 시험 파일을 웹에 재배포하는 동작이 아닙니다. 자동 대응 티켓은 `verified`까지, 별도 운영자 키로 완료한 뒤 `restored`입니다. 완료도 반드시 n8n 기록까지 확인합니다. 기존 팀의 격리 해제 별칭 `restore → quarantine`은 유지하고 개인의 두 완료 조치 이름을 추가했습니다. [계약](s7-auto-contract.md).

`s7_auto_verify.py`는 무해한 HTML 주석/시험 파일을 실제 개인 볼륨에 생성합니다. 정상 자동 대응을 직접 호출하지 않으며 실제 Graylog 판단을 기다립니다. 후반 중복 시험만 관측한 이벤트를 재전송합니다. `s7_auto_failures.py`는 해당 개인 티켓 서비스를 잠시 중지해 조치 보류를 확인하고 같은 실제 이벤트 재전송으로 회복합니다. 실패 시 두 고정 시험 경로를 기준으로 정리하되, 이 수동 정리를 자동 성공으로 기록하지 않고 티켓·경보·격리 기록을 보존합니다.

검증기는 종료 시 Graylog 탐지를 일시 정지합니다. 실습을 계속할 때는 `py -3.12 tools/s7_auto_lab.py enable`, 중지할 때는 `pause`를 실행합니다. 원복 완료 요청은 `s7_auto_verify.completion(event_key, ticket_id)`를 통해 별도 운영자 자격증명으로 n8n에 보낼 수 있습니다. 사용자 입력의 임의 파일 경로나 shell 명령은 받지 않습니다.

## 가드와 한계

- 경보 중계는 manager alerts 볼륨을 읽기 전용으로 읽고 SQLite에 이벤트·offset·전달 상태·최초 실행 정보를 보관합니다. Graylog HTTP GELF 입력은 내부 12202이며 호스트에 공개하지 않습니다. caller의 event_key가 실제 경보 저장소에 없으면 거부합니다.
- 에이전트 001의 read/Active Response만 허용한 `s7-responder`를 사용합니다. [Wazuh RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/how-it-works.html)의 `white` 모드를 확인합니다. 명령 인자는 연결 서비스와 고정 AR wrapper에서 제한합니다. API RBAC 자체는 명령별 인자 권한을 제공하지 않으며 scoped 자격증명 탈취에 대한 완전한 명령 격리까지 주장하지 않습니다.
- API 클라이언트는 manager CA와 `wazuh.manager` hostname을 검증합니다. 에이전트 등록도 manager CA를 확인합니다. 호스트 검증 도구만 기존 loopback/Docker SAN 차이에 따른 hostname 예외를 사용합니다. 4.9 CA 확장 호환을 위해 strict 플래그만 조정하며 인증서 검증을 끄지 않습니다.
- 실제 경보의 해시와 현재 파일이 다르거나 기준이 바뀌면 조치하지 않습니다. wrapper는 같은 job의 영수증을 재사용하며 다른 티켓의 완료를 거부합니다. 기존 성공 기록 재조회도 현재 파일·HTTP를 다시 확인합니다. 기준으로 복원된 FIM과 격리 후 삭제 경보는 새 대응 후보에서 제외합니다.
- API 전달 성공만으로 성공 판정하지 않습니다. agent 영수증, 전체 기준 파일 해시, 실제 HTTP 응답이 모두 필요합니다. n8n 실행 payload는 저장하지 않으며 키는 credential 저장소에만 둡니다.
- root 권한으로 에이전트 내부를 장악한 공격자, 파일 변경과 해시 확인 사이 경쟁, 파일 조치 직후 영수증 저장 전 강제 종료, 자정 로그 회전 순간의 미처리 로그, 장시간 부하/여러 파일 동시 사고는 완전 검증 범위가 아닙니다. 이런 경우 자동 성공으로 처리하지 않고 보류한 뒤 원천 경보·실제 파일·티켓을 대조합니다. 운영 배포용 EDR 완성을 뜻하지 않습니다.

공유받은 반소람 님의 `제어판-소개-공유.html`은 소개문과 캡처 4장이며 실제 `lab/panel.py`는 포함하지 않았습니다. 케이스별 공격/효과/해제, 근거 화면 링크와 단계별 진행 표시를 후속 UI의 참고로 채택했습니다. 해당 스크린샷·14개 컨테이너 구성·성과를 개인 실측으로 반입하지 않습니다. 이번 변경은 자동화와 실행 도구이며 버튼 제어판은 아직 구현하지 않았습니다.
