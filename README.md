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

## 개인 포트폴리오 발표자료

[개인 포트폴리오 PPTX](output/portfolio/김명준-해담시청-SOAR-개인포트폴리오-20261110-r4.pptx)는 27장으로 구성했습니다. 플로우차트, 상세 아키텍처, Docker·pfSense 망 구조, 포트 구성, 개인 실측·기여와 개선 내용을 포함합니다. n8n 노드 연결도, Graylog·Wazuh 경보 증적, 제어판 화면과 팀원의 시청 특화 사례도 추가했습니다. [편집 원본·출처·후속 작업](docs/portfolio/README.md)에서 현재 범위를 확인할 수 있습니다. S10은 11/10 실측 결과(17장)를 반영했고, n8n·Graylog·Wazuh의 실제 UI 캡처는 후속 작업입니다.

S1·S4·S12는 [개인 재실측 준비](docs/s1-s4-s12-rehearsal-plan.md)에 연결 설정의 차이, 경계값·정상 대조·원복 절차를 정리했습니다. 오프라인 점검만 완료했으며 개인 배포·실측은 아직 진행하지 않았습니다.

S1은 [개인 설정·입력 도구](docs/s1-personal-prep.md)를 추가했습니다. 중앙 설정, 기존 dotenv와 분리된 번들 생성, 8회/9회 제한 입력과 증적·중지 기능을 오프라인 검증했습니다. 기본은 계획만 출력하며 Graylog·n8n 배포와 실제 재실측은 후속입니다.

[S1 자동 대응·원복 워크플로](docs/s1-auto-workflows.md)는 Graylog 인증 알림, n8n 티켓 선기록·IP 차단·소유 티켓 원복까지 구현하고 오프라인 검증했습니다. 기본 탐지는 비활성이며 실제 서비스에 가져오거나 실행하지 않았습니다.

[S4 개인 계정 잠금·원복](docs/s4-auto-workflows.md)은 전용 설정, Graylog 인증 알림, 티켓 선기록, 계정 잠금·세션 회수, 별도 키의 오탐 해제를 구현했습니다. 포털 소유 티켓과 현재 계정 ID를 대조하며 기존 세션은 복원하지 않습니다. 오프라인 검증 단계로 실제 배포·탐지·로그인 효과 재실측은 후속입니다.

[PR #17·#18 인계 검토와 S4 수정](docs/s1-s4-review-20261110.md)에서 실제 티켓 응답의 필드 차이로 중복·원복이 중단되는 문제를 재현·수정했습니다. 설치 후보에는 이 후속 수정도 포함해야 합니다. 실제 Flask 응답을 워크플로 그래프에 직접 연결한 오프라인 검사이며 실제 엔진 실측은 아닙니다.

[S1 실제 실측 준비 절차](docs/s1-live-preparation.md)는 새 번들·import 파일, 정상 계정 로그인과 공격 200→403→200 검사, 같은 이벤트/티켓의 원복 증적 대조를 제공합니다. 기본은 계획·파일 생성이며 기존 Docker/VM을 변경하지 않았습니다. 실제 실측은 아직입니다.

[제출 준비와 남은 확인](docs/submission-readiness-20261110.md)에서 결과물과 실행 순서를 확인할 수 있습니다. [이력서·자기소개서 프로젝트 문안](docs/application-materials.md)은 개인 실측과 팀 기여 근거를 연결한 기본 문안이며 지원 직무에 맞춰 수정합니다.

## 포털과 DB 실행

현재 제출 후보는 **PR #24의 `claude/submission-s10` 브랜치**(열린 PR #1~#23 포함)이며 `main`에는 아직 병합하지 않았습니다. `main`에 병합한 뒤에는 `--branch main`을 사용합니다. 처음 받는 경우 아래처럼 브랜치를 지정합니다. 비공개 저장소 접근 권한이 있는 GitHub 계정으로 Git 인증을 준비합니다. 다른 작업 폴더가 있으면 새 빈 폴더에서 실행합니다.

```powershell
git clone --single-branch --branch claude/submission-s10 https://github.com/myeongjundev/haedam-soar-portfolio.git
Set-Location haedam-soar-portfolio
git branch --show-current
git rev-parse --short HEAD
```

Windows 개인 랩은 PowerShell 7, Git, Docker Desktop의 Linux 컨테이너 엔진, Docker Compose **2.24.4 이상**, Python **3.12와 `py` 실행기**를 사용합니다. 첫 빌드에는 이미지·잠금 의존성을 받을 인터넷 연결이 필요합니다. 호스트 Node.js와 MySQL은 Docker 설치에 필요하지 않습니다. 아래 명령은 저장소 루트 기준입니다.

```powershell
$PSVersionTable.PSVersion
git --version
py -3.12 --version
docker version
docker compose version
docker info --format '{{.OSType}} / memory bytes={{.MemTotal}}'
docker ps --format '{{.Names}}'
```

`docker version`에서 Server에 연결되지 않으면 설치를 계속하지 않습니다. 도구의 `init`도 S7에서는 인증서·비밀번호 해시 생성용 컨테이너를 실행합니다. 다른 실측 중에는 S7 초기화를 포함해 순서를 조율합니다. 이 PC의 약 6GiB Docker 환경에서는 랩을 하나씩 실행하며 `stop`은 원복을 대신하지 않습니다. [설치 순서·환경 파일·정지 및 재개](docs/installation-guide.md)를 먼저 확인합니다.

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
py -3.12 tools/s8_lab.py stop
```

P01/P02와 S8은 포털 기본 포트가 같으므로 번갈아 실행합니다. 메모리가 작은 PC에서는 기존 관제 스택도 중지한 뒤 실행합니다. 도구는 다른 프로젝트를 자동 중지하지 않습니다. 실제 차단 대상은 개인 랩 IP 하나이며, [원복 인증과 티켓 계약](docs/s8-contract.md)을 따릅니다.

## H1 민원 도배 · 작성 제한과 원복

[H1 개인 랩](docs/h1-lab.md)은 반소람 님의 시청 업무 보안 제안을 개인 환경에 구현한 추가 케이스입니다. 실제 민원 등록 → 계정별 Graylog 탐지 → n8n 작성 제한·티켓 → 운영자 해제를 연결합니다. 제한 중에도 로그인·기존 민원 조회와 다른 시민의 작성은 유지합니다. 임계값은 합성 랩 기준이며 운영 기준으로 확정한 값이 아닙니다.

```powershell
py -3.12 tools/h1_lab.py init
py -3.12 tools/h1_lab.py up
py -3.12 tools/h1_lab.py configure
py -3.12 tools/h1_verify.py
py -3.12 tools/h1_lab.py stop
```

S8과 별도 프로젝트·포트·볼륨을 사용하며, 메모리가 작은 PC에서는 번갈아 실행합니다. [H1 실측 결과](docs/h1-results.md) · [H1 계약](docs/h1-contract.md) · [검토 카드](docs/h1-review.md).

## Wazuh / S7 파일 변조 탐지와 복구

[S7 개인 Docker 설치](docs/s7-lab.md)는 Wazuh manager·indexer·dashboard와 실제 포털 웹 파일을 감시하는 agent를 새 포털·MySQL과 함께 구성합니다. 변조 경보 검색과 Wazuh API 복구·격리, HTTP·해시 원복을 검증합니다. 수동 단계의 재현 안내이며 전체 자동 연결은 아래 별도 절차를 사용합니다.

자동 복구·티켓·제어판을 검사하려면 이 수동 랩을 먼저 실행할 필요 없이 아래 **S7 자동 연결**로 바로 진행합니다. 두 S7 프로젝트를 동시에 기동하지 않습니다.

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
# 제어판과 같은 프로젝트·감시 설정을 선택합니다.
$panelConfigPath = if ($env:PANEL_CONFIG_FILE) { $env:PANEL_CONFIG_FILE } else { 'infra/panel-settings.json' }
$panelSettings = Get-Content -LiteralPath $panelConfigPath -Raw | ConvertFrom-Json
$env:S7_PROJECT = $panelSettings.s7_project
$env:S7_CONFIG_FILE = $panelSettings.s7_settings
py -3.12 tools/s7_auto_lab.py init
py -3.12 tools/s7_auto_lab.py up
py -3.12 tools/s7_auto_lab.py ready
py -3.12 tools/s7_auto_lab.py configure
py -3.12 tools/s7_auto_verify.py
py -3.12 tools/s7_auto_failures.py
py -3.12 tools/s7_auto_lab.py stop
```

각 명령이 성공한 뒤 다음 명령을 실행합니다. Compose 2.24.4 이상이 필요합니다. 비밀값은 `.env.s7-auto`, 연결·감시 환경값은 [공통 설정](infra/s7-auto-settings.json)에서 관리합니다. 기존 개인 S7 및 다른 관제 실측과 순서를 맞춥니다. [계약](docs/s7-auto-contract.md) · [Claude 검토 카드](docs/s7-auto-review.md).

마지막 `stop` 이후에는 제어판이 연결 대기를 표시합니다. 버튼 검사를 계속하려면 같은 설정을 선택한 터미널에서 `py -3.12 tools/s7_auto_lab.py up`과 `ready`를 다시 실행하고 제어판을 켭니다. 새 PowerShell 창에서는 위 설정 선택 네 줄도 다시 실행합니다. 기존 정상 랩 재개에 `configure`를 반복할 필요는 없습니다.

## 버튼으로 실행하는 개인 제어판

```powershell
py -3.12 tools/panel.py
```

기본 `http://127.0.0.1:15800`에서 **환경 확인 → S7 시험 입력 → 탐지·대응 확인 → 원복 완료**를 실행합니다. 허용된 개인 랩만 대상으로 하며 Docker/VM을 켜거나 끄지 않습니다. S7 랩은 별도로 준비해야 합니다. [설치·설정·검증 범위](docs/panel-lab.md) · [API 계약](docs/panel-contract.md). S8/H1은 버튼 미연결, S10은 CLI 실측은 통과했지만(PR #13 반입) 버튼은 연결하지 않아 실행 잠금으로 표시합니다. 11/10 새 개인 랩에서 두 대상의 실제 버튼 입력→Wazuh→Graylog→n8n→복구/격리→티켓 원복을 확인했습니다. [실측 결과와 캡처](docs/panel-results-20261110.md).

## P04·S10 pfSense 경계 차단·포털 차단·원복

[P04·S10 개인 랩](docs/s10-lab.md)은 pfSense CE 2.7.2를 Docker 컨테이너 안의 QEMU VM(KVM 없음, 소프트웨어 에뮬레이션)으로 띄웁니다. 공격·정상 클라이언트의 실제 요청이 pfSense를 거쳐 포털에 닿습니다. S10은 이 경로에서 세 신호를 모읍니다.

- pfSense ICMP 차단 로그
- 포털 404
- 포털 401

이후 흐름은 Graylog 상관 탐지 → n8n 티켓 선기록 → 포털 IP 차단과 pfSense 차단 → 운영자 원복입니다.

```powershell
$iso = Read-Host 'pfSense CE 2.7.2 ISO 파일 경로'
py -3.12 tools/pf_lab.py init --iso $iso
py -3.12 tools/pf_lab.py up pfsense        # 최초 1회 설치는 docs/s10-lab.md 순서
py -3.12 tools/pf_verify.py                # P04: 경계 차단·정상 유지·원복
py -3.12 tools/s10_lab.py init
py -3.12 tools/s10_lab.py up
py -3.12 tools/s10_lab.py pfsense
py -3.12 tools/s10_lab.py configure
py -3.12 tools/s10_verify.py               # S10 실제 경로
py -3.12 tools/s10_failures.py             # 티켓 저장소·relay 장애
```

pfSense ISO는 Git에 넣지 않습니다. 실행 중에는 기존 관제 스택을 멈춥니다. 시험 대상은 팀 도구가 허용하는 개인 랩 출발지 하나입니다. [실측 결과](docs/s10-results-20261110.md) · [인수인계](docs/s10-handoff-20261110.md).

## 작업 시작

[공통 작업 규칙](AGENTS.md)과 [과제 검증표](docs/portfolio-plan.md)를 읽고 작업별 PR을 엽니다. 준비된 Claude IDE에서 별도의 개인 작업 폴더를 열고 [첫 문제 해결 카드](docs/claude-first-task.md)를 사용합니다.

마감은 **2026-11-11 수요일 오후 5시 30분 KST**입니다. 개인 GitHub 주소, 김명준 명의 PPT, 설치·실측 완료 한 줄은 검증이 끝난 뒤 제출합니다.
