# 개인 Wazuh / S7 파일 무결성 랩

이 단계는 **실제 포털 파일 → Wazuh FIM → indexer 검색 → 인증된 Wazuh API 복구/격리 → HTTP·해시 대조**를 검증합니다. 복구를 요청하는 주체는 `s7_verify.py`입니다. Graylog·n8n 판단·티켓 생성은 아직 연결하지 않았으며 S7 전체 자동 대응 완료가 아닙니다. [작업 범위](s7-task.md), [결과](s7-results.md), [Claude 검토 카드](s7-review.md).

## 설치와 실행

Windows Docker Desktop Linux 컨테이너, Docker Compose v2, Python 3.12 이상을 사용합니다. 앱 의존성은 Docker가 설치하며 아래 도구는 Python 표준 라이브러리만 필요합니다. Wazuh 세 이미지와 agent 패키지는 팀 호환 버전 4.9.0으로 고정했습니다. 최신 운영 배포 구성을 뜻하지 않습니다.

현재 PC는 Docker 메모리 약 6GiB·swap 4GiB이며 기존 관제 스택과 **번갈아** 실행합니다. 초기 이미지 다운로드·agent 패키지 빌드에는 인터넷이 필요합니다. `vm.max_map_count >= 262144`를 확인합니다. 도구는 전역 설정과 다른 컨테이너를 변경하지 않습니다. 메모리 8GiB 미만에서 다른 컨테이너가 실행 중이면 `up`을 거부합니다. 8GiB 이상도 전체 스택 동시 실행을 보장하지 않습니다.

```powershell
py -3.12 tools/s7_lab.py init
py -3.12 tools/s7_lab.py up
py -3.12 tools/s7_lab.py ready
py -3.12 tools/s7_lab.py baseline
py -3.12 tools/s7_verify.py
py -3.12 tools/s7_lab.py status
```

각 명령이 성공한 뒤 다음으로 진행합니다. `up`은 시작 요청이고, **`ready` 성공**이 에이전트 active·인덱서 응답·대시보드 로그인 페이지의 접속 확인입니다. `baseline`은 빌드 이미지와 실제 웹 볼륨의 모든 파일 해시가 같아야 기준을 만들며, 기존 기준은 덮어쓰지 않습니다. 재시작에도 기준은 유지됩니다.

| 구성 | 접속 | 인증/설정 |
| --- | --- | --- |
| React·Flask 포털 | http://127.0.0.1:15020 | 합성 데이터 전용; MySQL은 내부 `db:3306` |
| Wazuh dashboard | https://127.0.0.1:15620 | `admin` / `.env.s7`의 `WAZUH_INDEXER_PASSWORD` |
| Wazuh API | https://127.0.0.1:15520 | `portfolio-api` / `WAZUH_API_PASSWORD`; 도구가 토큰 발급 |
| Wazuh indexer | https://127.0.0.1:19220 | `admin` / `WAZUH_INDEXER_PASSWORD` |
| 에이전트 등록·전송 | 내부 `wazuh.manager:1515`, `:1514` | 무작위 등록 암호, 호스트 포트 미공개 |

`init`은 `.env.s7`, `.local/s7/`에 무작위 비밀번호, bcrypt, 인증서를 생성합니다. 파일은 Git에서 제외되며 값을 콘솔·PR·캡처에 붙이지 않습니다. 재실행은 기존 비밀번호와 인증서를 유지합니다. 비밀번호 변경만으로 이미 초기화된 DB/indexer 계정이 회전하지 않으므로 실행 중 임의 편집하지 않습니다. `.env.s7.example`은 변수 목록입니다.

인증서는 개인 랩 CA이며 브라우저에 경고가 표시될 수 있습니다. 운영체제 신뢰 저장소는 자동 수정하지 않습니다. 도구의 loopback TLS 클라이언트는 해당 로컬 CA의 체인/서명을 검증합니다. Docker DNS SAN과 loopback 주소 차이로 hostname 검증을 끄며, 4.9 CA의 KeyUsage 누락 때문에 Python 3.13의 추가 strict 플래그만 해제합니다. `CERT_NONE`을 사용하지 않습니다. 운영 연동 시 정상 SAN·CA 확장을 가진 인증서로 교체해야 합니다.

기본 프로젝트는 `haedam-s7-live`입니다. 새 볼륨 검증은 기존 개인 프로젝트를 중지한 뒤 별도 이름으로 진행합니다. 기존 볼륨은 삭제하지 않습니다.

```powershell
py -3.12 tools/s7_lab.py stop
$env:S7_PROJECT = 'haedam-s7-check'
py -3.12 tools/s7_lab.py init
py -3.12 tools/s7_lab.py up
py -3.12 tools/s7_lab.py ready
py -3.12 tools/s7_verify.py
py -3.12 tools/s7_lab.py stop
Remove-Item Env:S7_PROJECT
```

이름은 `haedam-s7-` 접두사로 제한합니다. 프로젝트별 볼륨·망은 분리되지만 로컬 자격증명과 공개 포트는 공유하므로 동시에 실행하지 않습니다. 기존 학원 컨테이너를 잠시 중지했다면 기록해 둔 **원래 실행 목록만** 다시 시작하고 각 서비스의 응답을 확인합니다. `docker compose down -v`는 설치/시험 절차에 포함하지 않습니다.

## 감시 대상과 복구

`compose.yaml`에 `compose.s7.yaml`을 겹쳐 씁니다. 이미지에서 초기화된 `s7-web` 볼륨을 포털은 `/app/frontend`에 읽기 전용, agent는 `/var/www/haedam`에 마운트합니다. 호스트 디렉터리·PID·Docker socket을 agent에 제공하지 않습니다. DB와 agent는 내부망에만 있으며 UI/API를 제공하는 서비스는 loopback 포트 공개를 위한 별도 access 망에도 연결됩니다. 완전한 외부 통신 차단 환경은 아닙니다.

- `infra/wazuh/agent/ossec.conf`: 웹 루트만 실시간 감시. 파일 내용 diff 전송은 끄고 경로·해시만 사용합니다.
- Wazuh 기본 ruleset 550(변경), 554(추가), 553(삭제)을 사용합니다. 규칙은 4.9.0 이미지에 포함되어 있으며 이번 단계에 사용자 정의 탐지 규칙은 없습니다.
- manager는 JSON alerts→Filebeat→TLS indexer `wazuh-alerts-*`로 전달합니다. Wazuh dashboard의 FIM에서 `agent.name: haedam-s7-agent`와 `syscheck.path`로 확인합니다.
- `lab/s7/restore/s7_restore.py`, `s7-restore-ar`는 팀 원본을 보존했습니다. 컨테이너 환경변수로 경로만 지정합니다. 기준 파일은 원본으로 복구하고 신규 파일은 웹 루트 밖 격리 폴더로 이동합니다.
- API의 `!s7-restore-ar` 호출 성공은 **명령 전달**입니다. 실제 성공은 해당 실행 ID의 복구 기록, 복구 후 파일 해시, HTTP 본문/상태로 별도 확인합니다.

`s7_verify.py`는 index.html에 무해한 HTML 주석을 붙이고, `assets/s7-probe.txt`에 무해한 시험 문자열을 생성합니다. 경보 2건을 검색한 뒤 API로 복구·격리합니다. 기준 재생성 거부, API 미인증 401, 웹 루트 밖 경로 거부, 정상 파일 유지, 재시작 후 기준 유지와 격리물 정리도 확인합니다. 결과 JSON은 `.local/s7/S7-*.json`입니다. 실패 시 두 시험 경로에만 로컬 복구를 시도하며, 이 정리는 실측된 API 복구와 구분됩니다. 실패 증적/격리물이 남으면 검토 전 삭제하지 않습니다.

포털 코드를 재배포할 때는 named volume의 정적 파일이 이미지 변경만으로 자동 갱신되지 않습니다. 새 프로젝트·새 웹 볼륨으로 승인된 이미지를 확인하고 새 기준을 만드세요. 현재 도구는 운영 중 자동 배포·기준 교체를 구현하지 않습니다.

## 다음 연결 단계

Wazuh 경보를 Graylog에 전달하고, S7 규칙과 n8n 워크플로가 경보의 agent/path/hash를 검증한 뒤 제한된 Wazuh API 계정으로 요청하도록 연결합니다. 동일 이벤트 중복, 복원 자체의 FIM 재경보, 기록 장애, 티켓 상태와 격리물 정리를 검증해야 합니다. 현재 관리자 API 자격증명을 n8n에 그대로 넣지 않습니다. 이번 랩에서는 티켓·알림을 생성하거나 S7의 공격 접근 로그 상관분석을 수행하지 않습니다.

공식 기준: [Wazuh Docker v4.9.0](https://github.com/wazuh/wazuh-docker/tree/v4.9.0/single-node), [Linux agent 설치](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html), [FIM 설정](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html). 현재 공식 문서의 최신 버전과 이번 고정 버전은 구분합니다. 반입한 설정의 라이선스는 `infra/wazuh/LICENSE.upstream`에 보존했습니다.
