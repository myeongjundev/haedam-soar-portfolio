# 개인 랩 설치 순서와 재개 안내

이 문서는 [README](../README.md)의 Windows 설치 명령을 어떤 순서로 선택할지 설명합니다. 제출 후보는 PR #24의 `claude/submission-s10` 브랜치입니다. pfSense/S10은 개인 랩에서 실측했지만, 다섯 구성을 새 clone에서 실제로 기동하는 통합 설치 확인은 아직 미완료입니다. [정적 설치 점검 결과](installation-audit-20261110.md)는 실제 기동 검사와 구분합니다.

## 실행할 랩 선택

각 행은 독립된 개인 랩입니다. 표 위에서 아래로 모든 컨테이너를 누적해서 켜는 방식이 아닙니다. 검사할 케이스 하나를 선택하고, 완료 티켓·정상 응답·원복을 확인한 뒤 해당 랩만 정지합니다.

| 목적 | 설치와 설정 반입 | 실측 | 종료 |
| --- | --- | --- | --- |
| 포털·MySQL 기본 | [README](../README.md#포털과-db-실행): `.env` 준비 → Compose up | 헬스·가입·로그인 | `docker compose stop` |
| Graylog·n8n 연결만 확인 | [관제 스모크](docker-soc.md): `.env.soc` → Compose up → 콘텐츠 팩·수신 워크플로 | 합성 입력과 정상 대조 전달 | 같은 터미널의 `docker compose @soc stop` |
| S8 차단·티켓·해제 | [S8](s8-lab.md): `s8_lab.py init/up/configure` | `s8_verify.py` | `s8_lab.py stop` |
| H1 작성 제한·해제 | [H1](h1-lab.md): `h1_lab.py init/up/configure` | `h1_verify.py` | `h1_lab.py stop` |
| Wazuh 수동 복구 학습 | [수동 S7](s7-lab.md): `s7_lab.py init/up/ready/baseline` | `s7_verify.py` | `s7_lab.py stop` |
| S7 전체 자동 복구·티켓 | [자동 S7](s7-auto-lab.md): 프로젝트 선택 → `s7_auto_lab.py init/up/ready/configure` | `s7_auto_verify.py`, `s7_auto_failures.py` | `s7_auto_lab.py stop` |
| S7 버튼 검사 | [제어판](panel-lab.md): 같은 프로젝트의 자동 S7 준비 → `panel.py` | 입력 → 관찰 → 원복 | 제어판 Ctrl+C, 해당 자동 S7 stop |

표의 Python 명령은 `py -3.12 tools/` 뒤에 붙입니다. 각 명령이 성공한 뒤에만 다음으로 넘어갑니다. `up` 성공은 시험 성공이 아니며 `stop`도 티켓이나 방화벽 조치를 해제하지 않습니다.

## 환경 파일과 데이터 보관

| 랩 | 로컬 환경 파일 | 첫 설정 명령 |
| --- | --- | --- |
| 포털·DB | `.env` | README의 난수 생성 블록 |
| 관제 스모크 | `.env`, `.env.soc` | 관제 설치 문서의 난수 생성 블록 |
| S8 | `.env`, `.env.soc`, `.env.s8` | `py -3.12 tools/s8_lab.py init` |
| H1 | `.env.h1` | `py -3.12 tools/h1_lab.py init` |
| 수동 S7 | `.env.s7`, `.local/s7/` 인증서·설정 | `py -3.12 tools/s7_lab.py init` |
| 자동 S7 | `.env.s7-auto`, 수동 S7 인증서, `.local/s7-auto/` | `py -3.12 tools/s7_auto_lab.py init` |

새 PC에서는 `.env.example`의 빈 값을 자격증명으로 사용하지 않습니다. 초기화 도구 또는 문서의 난수 생성 절차로 만듭니다. 기존 볼륨을 재사용할 때는 대응하는 환경 파일·n8n 암호화 키·인증서를 함께 보관합니다. Git에 올리거나 캡처에 표시하지 않습니다.

Docker 볼륨은 프로젝트 이름에 연결됩니다. 프로젝트 이름이나 작업 폴더를 바꿨다면 기존 환경을 그대로 재개한 것으로 간주하지 않습니다. 제어판은 컨테이너의 worktree와 프로젝트도 확인합니다. `down -v`, 다른 프로젝트 전체 정지, 전역 WSL 설정 변경은 설치 명령에 포함하지 않습니다.

## 자동 S7과 제어판을 같은 환경으로 연결

자동 S7 도구 자체의 기본 프로젝트와 제어판 설정의 기본 프로젝트는 다릅니다. [README](../README.md)의 자동 S7 명령처럼 제어판 설정을 읽어 `S7_PROJECT`와 `S7_CONFIG_FILE`을 선택한 뒤 초기화합니다. 다른 설정 파일을 쓰면 `PANEL_CONFIG_FILE`을 먼저 지정합니다. 기본 JSON을 직접 고칠 필요는 없습니다.

새 터미널에서는 환경변수가 유지되지 않습니다. 먼저 같은 설정 선택 블록을 실행한 뒤 `up → ready`로 재개합니다. `configure`는 최초 반입 또는 명시적인 설정 변경 때 실행하며 활성 사건이 있으면 먼저 관찰·원복합니다. 이미지/볼륨 불일치가 나오면 재설정으로 덮지 말고 새 프로젝트의 배포로 확인합니다.

제어판 포트·bind·대상은 `infra/panel-settings.json`과 그 `s7_settings`가 가리키는 파일에서 읽습니다. 기본 접속 주소는 각 설치 문서에 있고, 실제 포트를 바꾸었다면 해당 환경 파일 값을 사용합니다.

## 로그인과 초기 설정

- 포털: 합성 시민을 화면에서 가입시킵니다. 관리자 생성은 해당 프로젝트의 portal 컨테이너에서 README 명령을 실행합니다.
- Graylog: 계정 `admin`, 선택한 랩 환경 파일의 `GRAYLOG_ADMIN_PASSWORD`입니다. 다른 랩의 비밀번호와 혼동하지 않습니다.
- Wazuh 대시보드: 계정 `admin`, 해당 S7 환경 파일의 `WAZUH_INDEXER_PASSWORD`입니다.
- n8n: 최초 접속에서 소유자를 설정합니다. 개인 케이스의 `configure`가 워크플로와 서비스 자격증명을 반입·게시합니다. 소유자 화면 로그인과 워크플로 반입은 별도입니다.
- 티켓 대시보드: 해당 랩의 읽기 전용 호스트 포트를 사용합니다. 내부 쓰기 API의 키를 브라우저나 문서에 붙이지 않습니다.

## 실행 실패 시 확인 순서

1. `py -3.12 --version`, `docker version`, `docker compose version`을 확인합니다. S7 자동 초기화는 내부에서도 Windows `py -3.12` 실행기를 사용하므로 Python 실행 파일만 별도로 있다고 같은 설치 경로가 되는 것은 아닙니다.
2. 포트 사용 중이면 해당 랩과 다른 실행 환경을 확인합니다. P01/P02와 S8은 기본 포털 포트가 같고, S7 프로젝트끼리도 포트를 공유합니다.
3. S7/H1/S8이 메모리 가드로 거부하면 다른 작업이 끝난 뒤 소유 랩의 실행 순서를 맞춥니다. 가드를 제거하거나 다른 사람의 컨테이너를 일괄 정지하지 않습니다.
4. OpenSearch의 `vm.max_map_count` 오류, 이미지 다운로드 실패, 인증서 초기화 실패는 서비스 로그와 개별 설치 문서에서 확인합니다. 호스트 설정을 자동 수정하지 않습니다.
5. 환경 파일을 바꾼 뒤 기존 DB 인증이나 n8n credential 복호화가 실패하면 기존 데이터와 키의 일치부터 확인합니다. 볼륨 삭제로 증적을 없애지 않습니다.
6. 제어판의 `scope_mismatch`는 프로젝트·worktree·포트·설정, `active_ticket`은 진행 중 사건, `dirty_target`은 현재 대상 파일, `stale_runtime`은 이미지/볼륨 불일치를 확인합니다.

## 개발 검사 환경

Docker 실행만 할 때는 호스트 앱 패키지를 설치할 필요가 없습니다. 호스트에서 테스트하려면 별도 새 작업 폴더의 저장소 루트에서 아래처럼 잠금 의존성으로 가상환경을 준비합니다. 기본 SQLite 마이그레이션도 생성되므로 실행 환경 파일이나 DB 연결 변수를 가져오지 않은 개발용 셸에서 실행합니다.

```powershell
py -3.12 haedam-portal-backend/tools/bootstrap.py
$testPython = Join-Path (Get-Location) 'haedam-portal-backend/.venv/Scripts/python.exe'
& $testPython -m pytest -q tests
& $testPython tools/build_s7_workflows.py --check
& $testPython tools/build_s8_workflows.py --check
& $testPython tools/build_h1_workflows.py --check
& $testPython tools/build_s10_workflows.py --check
& $testPython tools/build_s1_workflows.py --check
& $testPython tools/build_s4_workflows.py --check
Push-Location haedam-portal-backend
& $testPython -m pytest -q
Pop-Location
```

MySQL 통합 시험 `haedam-portal-backend/tools/check_mysql.py`는 컨테이너를 만들므로 다른 실측 중에는 실행하지 않습니다. 위 호스트 테스트와 Compose 해석 성공은 서비스 설치·탐지·대응·원복 실측을 대신하지 않습니다.
