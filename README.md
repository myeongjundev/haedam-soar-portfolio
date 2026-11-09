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

- 포털은 `http://127.0.0.1:15000`에서 열립니다. MySQL은 Compose 내부에서만 접근합니다.
- 새 DB에서는 포털 기동 시 Alembic 마이그레이션을 적용합니다. 시민은 화면에서 가입할 수 있습니다. 관리자는 `docker compose exec portal flask --app haedam_portal:create_app create-admin`으로 합성 계정을 만듭니다.
- `docker compose stop`으로 멈추고 `docker compose up -d --wait`로 다시 실행하면 DB와 포털 이벤트 볼륨을 재사용합니다.
- 이미 초기화된 볼륨은 최초 MySQL 비밀번호를 사용합니다. 환경값을 직접 넣을 때는 DB URL에 쓸 수 있는 16진수 값을 사용합니다.

## 관제 설정 반입 상태

팀 Graylog와 n8n Compose, 규칙, 워크플로는 [반입 목록](docs/sources.md#반입-경로)에서 확인할 수 있습니다. `compose.team.yaml`은 Claude가 개인 환경으로 이식할 참고본입니다. 이번 기동 확인은 포털과 MySQL에 해당합니다.

## 작업 시작

[공통 작업 규칙](AGENTS.md)과 [과제 검증표](docs/portfolio-plan.md)를 읽고 작업별 PR을 엽니다. Claude Code는 저장소 루트에서 `claude`로 실행하고 [첫 문제 해결 카드](docs/claude-first-task.md)를 전달합니다.

마감은 **2026-11-12 오전 10시 KST**입니다. 개인 GitHub 주소, 김명준 명의 PPT, 설치·실측 완료 한 줄은 검증이 끝난 뒤 제출합니다.
