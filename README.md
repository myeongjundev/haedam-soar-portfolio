# 해담시청 SOAR · 김명준 개인 포트폴리오

팀 원본 [NoBugs-Aleph/aleph-soar-capstone](https://github.com/NoBugs-Aleph/aleph-soar-capstone) · [팀 공개 소개](https://github.com/NoBugs-Aleph/aleph-soar-public)

| 팀원 | 담당 |
| --- | --- |
| 김명준 (@myeongjundev) | 조장·B. React·Flask 민원포털, S8·S10 시험 입력과 검증, pfSense 경계 대응·원복 검증 |
| 반소람 (@whiteclover0542) | A. S1·S4 계정 공격과 대응 검증 |
| 김상혁 (@shk12170-dev) | C. S7 파일 무결성, Wazuh, 티켓 저장소 |
| 김대훈 (@chacha1650a) | D. S12 가용성, Graylog·n8n 관제 연동 |

가상 해담시청 민원포털의 공격 신호를 수집해 탐지·대응·티켓으로 연결하고, 차단 효과와 서비스 원복까지 확인하는 교육용 랩입니다. 개인 전환 작업에서는 한 대의 PC에서 초기 설치부터 증적 수집까지 재현합니다.

개인 설치·실측 상태는 [과제 검증표](docs/portfolio-plan.md)에 기록합니다. 원본 세 저장소의 기준 커밋과 팀원별 출처는 [출처와 기여](docs/sources.md)에서 확인할 수 있습니다.

## 포털과 DB 실행

GitHub에서 처음 받는 경우 아래 명령을 실행합니다. 초안 PR 검증 중에는 새 폴더에서 해당 PR 브랜치를 checkout합니다.

```powershell
git clone https://github.com/myeongjundev/haedam-soar-portfolio.git
Set-Location haedam-soar-portfolio
```

Docker Desktop 또는 Linux Docker Engine과 Docker Compose v2를 준비합니다. 첫 빌드는 이미지와 잠금 의존성을 내려받습니다. 아래 명령은 PowerShell 7에서 저장소 루트 기준입니다.

```powershell
if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  $rootSecret = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
  $appSecret = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
  @("MYSQL_ROOT_PASSWORD=$rootSecret", "MYSQL_PASSWORD=$appSecret", "PORTAL_PORT=15000") |
    Set-Content -Encoding utf8NoBOM .env
}
docker compose config --quiet
docker compose up -d --build --wait
docker compose ps
curl.exe --fail http://127.0.0.1:15000/api/v1/health
```

Linux에서는 최초 실행 전에 아래 명령으로 같은 형식의 `.env`를 만든 다음 Compose 명령을 실행합니다.

```sh
if [ ! -f .env ]; then
  (umask 077; printf 'MYSQL_ROOT_PASSWORD=%s\nMYSQL_PASSWORD=%s\nPORTAL_PORT=15000\n' \
    "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" > .env)
fi
```

- 포털은 `http://127.0.0.1:15000`에서 열립니다. MySQL만 시작하려면 `docker compose up -d --wait db`를 사용합니다. MySQL 포트는 Compose 내부에서 접근합니다.
- 새 DB에서는 포털 기동 시 Alembic 마이그레이션을 적용합니다. 시민은 화면에서 가입할 수 있습니다. 관리자는 `docker compose exec portal flask --app haedam_portal:create_app create-admin`으로 합성 계정을 만듭니다.
- `docker compose stop`으로 멈추고 `docker compose up -d --wait`로 다시 실행하면 DB와 포털 이벤트 볼륨을 재사용합니다.
- 이미 초기화된 볼륨은 최초 MySQL 비밀번호를 사용합니다. 환경값을 직접 넣을 때는 DB URL에 쓸 수 있는 16진수 값을 사용합니다.

포털 화면·API·DB·규칙을 수정할 위치와 확인 방법은 [변경 후 재검증](docs/portfolio-plan.md#변경-후-재검증)에 있습니다.

## 관제 설정 반입 상태

[개인 관제 Docker 설치](docs/docker-soc.md)를 따르면 포털과 MySQL에 Graylog·MongoDB·OpenSearch·n8n·티켓 저장소를 추가할 수 있습니다. `compose.team.yaml`과 [팀 규칙·워크플로](docs/sources.md#반입-경로)는 출처와 시나리오 설정을 확인할 때 사용합니다.

## S8 실제 차단·티켓·원복

[S8 개인 랩 설치와 실측](docs/s8-lab.md)은 별도 프로젝트 `haedam-s8-live`에 필요한 워크플로와 자격증명, 실제 Graylog 스트림·알림을 연결합니다. 공격·정상 클라이언트를 별도 컨테이너로 두고 실제 포털 404·로그인 실패 401 → 탐지 → IP 차단 403 → 티켓 검증 → 원복 200을 시험합니다.

```powershell
py -3.12 tools/s8_lab.py init
py -3.12 tools/s8_lab.py up
py -3.12 tools/s8_lab.py configure
py -3.12 tools/s8_verify.py
```

P01/P02와 S8은 포털 기본 포트가 같으므로 번갈아 실행합니다. 메모리가 작은 PC에서는 기존 관제 스택도 중지한 뒤 실행합니다. 도구는 다른 프로젝트를 자동 중지하지 않습니다. 실제 차단 대상은 개인 랩 IP 하나이며, [원복 인증과 티켓 계약](docs/s8-contract.md)을 따릅니다.

## H1 민원 도배 · 작성 제한과 원복

[H1 개인 랩](docs/h1-lab.md)은 반소람 님의 시청 업무 보안 제안을 개인 환경에 구현한 추가 케이스입니다. 실제 민원 등록 → 계정별 Graylog 탐지 → n8n 작성 제한·티켓 → 운영자 해제를 연결합니다. 제한 중에도 로그인·기존 민원 조회와 다른 시민의 작성은 유지합니다. 임계값은 합성 랩 기준이며 운영 기준으로 확정한 값이 아닙니다.

```powershell
py -3.12 tools/h1_lab.py init
py -3.12 tools/h1_lab.py up
py -3.12 tools/h1_lab.py configure
py -3.12 tools/h1_verify.py
```

S8과 별도 프로젝트·포트·볼륨을 사용하며, 메모리가 작은 PC에서는 번갈아 실행합니다. [H1 실측 결과](docs/h1-results.md) · [H1 계약](docs/h1-contract.md) · [검토 카드](docs/h1-review.md).

## Wazuh / S7 파일 변조 탐지와 복구

[S7 개인 Docker 설치](docs/s7-lab.md)는 Wazuh manager·indexer·dashboard와 실제 포털 웹 파일을 감시하는 agent를 새 포털·MySQL과 함께 구성합니다. 변조 경보 검색과 Wazuh API 복구·격리, HTTP·해시 원복을 검증합니다. 수동 단계의 재현 안내이며 전체 자동 연결은 아래 별도 절차를 사용합니다.

```powershell
py -3.12 tools/s7_lab.py init
py -3.12 tools/s7_lab.py up
py -3.12 tools/s7_lab.py ready
py -3.12 tools/s7_lab.py baseline
py -3.12 tools/s7_verify.py
```

각 명령의 성공을 확인하고 다음으로 진행합니다. 낮은 메모리에서는 기존 관제 환경과 번갈아 실행합니다. [S7 결과와 남은 범위](docs/s7-results.md) · [Claude 검토 카드](docs/s7-review.md).

[프론트·백엔드 파일과 앱 로그 감시](docs/portal-wazuh-paths.md)를 연결했습니다. `ready` 이후 `py -3.12 tools/s7_paths_verify.py`로 백엔드 FIM과 실제 포털 접속 로그의 Wazuh 수집을 재현합니다.

## S7 Wazuh → Graylog → n8n 자동 복구·티켓

[S7 자동 연결 설치](docs/s7-auto-lab.md)는 별도 개인 프로젝트에서 실제 FIM 경보를 Graylog·n8n으로 전달하고 티켓 선기록 → 자동 복구/격리 → 파일·HTTP 효과 확인 → 운영자 원복 완료까지 연결합니다. [새 볼륨 실측](docs/s7-auto-results.md)에서 정상·중복·기록 장애·재시도·원복을 확인했습니다. 팀의 접근 성공 상관 정책과 구분한 개인 FIM 정책입니다.

```powershell
py -3.12 tools/s7_auto_lab.py init
py -3.12 tools/s7_auto_lab.py up
py -3.12 tools/s7_auto_lab.py ready
py -3.12 tools/s7_auto_lab.py configure
py -3.12 tools/s7_auto_verify.py
py -3.12 tools/s7_auto_failures.py
py -3.12 tools/s7_auto_lab.py stop
```

각 명령이 성공한 뒤 다음 명령을 실행합니다. Compose 2.24.4 이상이 필요합니다. 비밀값은 `.env.s7-auto`, 연결·감시 환경값은 [공통 설정](infra/s7-auto-settings.json)에서 관리합니다. 기존 개인 S7 및 다른 관제 실측과 순서를 맞춥니다. [계약](docs/s7-auto-contract.md) · [Claude 검토 카드](docs/s7-auto-review.md).

## 버튼으로 실행하는 개인 제어판

```powershell
py -3.12 tools/panel.py
```

기본 `http://127.0.0.1:15800`에서 **환경 확인 → S7 시험 입력 → 탐지·대응 확인 → 원복 완료**를 실행합니다. 허용된 개인 랩만 대상으로 하며 Docker/VM을 켜거나 끄지 않습니다. S7 랩은 별도로 준비해야 합니다. [설치·설정·검증 범위](docs/panel-lab.md) · [API 계약](docs/panel-contract.md). S8/H1은 버튼 미연결, S10은 Claude 구성 중으로 표시합니다. 11/10 새 개인 랩에서 두 대상의 실제 버튼 입력→Wazuh→Graylog→n8n→복구/격리→티켓 원복을 확인했습니다. [실측 결과와 캡처](docs/panel-results-20261110.md).

## 작업 시작

[공통 작업 규칙](AGENTS.md)과 [과제 검증표](docs/portfolio-plan.md)를 읽고 작업별 PR을 엽니다. 준비된 Claude IDE에서 별도의 개인 작업 폴더를 열고 [첫 문제 해결 카드](docs/claude-first-task.md)를 사용합니다.

마감은 **2026-11-11 수요일 오후 5시 30분 KST**입니다. 개인 GitHub 주소, 김명준 명의 PPT, 설치·실측 완료 한 줄은 검증이 끝난 뒤 제출합니다.
