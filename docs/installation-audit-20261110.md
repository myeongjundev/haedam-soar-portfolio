# README 설치 절차와 제출 자료 점검

2026-11-10, Codex · 김명준. Claude의 pfSense/S10 실측과 겹치지 않도록 **컨테이너 생성·기동·정지·재시작, VM 조작을 실행하지 않은 점검**입니다. 새 Git 클론에서 환경 파일 초기화·설정 해석·호스트 의존성 설치·테스트를 실행했습니다. 다섯 구성 전체의 새 설치 완료를 의미하지 않습니다.

## 소스와 환경

- 원격 `codex/personal-portfolio-deck`를 새 빈 폴더에 clone했습니다. 검사한 앱 소스는 `4273290`이며 이번 수정은 설치 문서뿐입니다. 이전 작업 폴더의 비밀값·상태 파일·가상환경을 복사하지 않았습니다.
- Windows, PowerShell 7.6.9, Python 3.12.10, Docker Compose 5.6.0. 백엔드 bootstrap으로 새 Python 가상환경을 만들고 저장소의 잠금 의존성·앱을 설치했습니다. 패키지 다운로드에는 로컬 pip 캐시가 사용됐습니다.
- SQLite 초기 마이그레이션 3개가 적용됐습니다. MySQL 또는 Wazuh·Graylog·n8n 서버에 연결한 설치 시험은 아닙니다.

## 발견과 수정

| 발견 | 설치 중 영향 | 수정 |
| --- | --- | --- |
| clone 명령이 기본 main만 선택 | 미병합 제출 후보의 PPT·제어판·문서가 빠질 수 있음 | PR #16 브랜치를 지정하고 현재 브랜치·커밋 확인 명령 추가 |
| 자동 S7과 제어판의 기본 프로젝트가 다름 | 각 문서의 기본 명령만 실행하면 제어판이 다른 프로젝트를 조회 | 같은 제어판 JSON에서 프로젝트와 감시 설정을 읽는 준비 블록 추가 |
| S7 정지 후 panel만 실행하는 순서가 모호 | 서비스가 꺼진 채 연결 대기로 남음 | 같은 설정으로 up/ready 재개 후 panel 실행, 새 터미널의 환경변수 재선택 명시 |
| 호스트 테스트의 가상환경 생성·선택 불명확 | 전역 Python 또는 다른 환경에서 패키지 누락 | 백엔드 bootstrap과 가상환경 절대 경로 실행 안내 |
| S8 복구 예시에 꺾쇠 자리표시자 사용 | PowerShell에 그대로 붙이면 문법 오류 | 실제 이벤트·티켓 ID를 Read-Host로 입력하게 변경 |
| pfSense/S10 미통합 범위가 README에서 불명확 | 현재 설치 명령으로 다섯 구성 완료라고 오해 | 별도 PR #13 진행 중과 전체 설치 미완료 명시 |

## 실행한 확인

| 확인 | 결과 | 의미와 한계 |
| --- | --- | --- |
| `s8_lab.py init`, `h1_lab.py init` | 성공 | 새 clone에 난수 환경 파일 생성. 서비스 연결 없음 |
| 포털·관제·S8·H1 Compose config | 성공, 서비스 2/7/11/9개 | 환경 파일 변수와 Compose 병합 해석. 실제 up 미실행 |
| 수동 S7·자동 S7 Compose config | 성공, 서비스 6/12개 | 예시·공통 JSON에서 만든 임시 난수 설정으로 해석만 확인. 실제 init·TLS 생성·마운트 파일 준비 아님 |
| 위 6개 구성의 published ports | 모두 loopback | Compose 선언 확인. 실제 리스너·접속 확인 아님 |
| 제어판 JSON 기반 프로젝트·targets 대조 | 일치 | 두 모듈의 설정을 읽어 대조. 컨테이너 label 대조 아님 |
| 백엔드 bootstrap | 성공 | 잠금 의존성·editable 앱 설치와 새 SQLite 마이그레이션 |
| 저장소 `pytest -q tests` | **62 passed** | Python 3.12.10 새 가상환경 |
| 백엔드 `pytest -q` | **65 passed, 6 skipped** | SQLite 테스트. 건너뛴 시험은 통과로 세지 않음 |
| S7/S8/H1 워크플로 `--check` | 2/7/2개 일치 | 배포 생성물 대조. n8n import·실행 아님 |
| 설치 문서 PowerShell 코드 | 26개 블록 문법 오류 없음 | 전체 명령 실행은 아님 |
| 추적 JSON | 111개 파싱 성공 | 값의 서비스 적용·스키마 검증 전체를 뜻하지 않음 |
| PPT·지원 문안 | PPTX 22장과 이력서·자소서 파일 존재 | 새 캡처·S10 수치 추가 없음 |
| 로컬 환경 파일·가상환경 | Git ignore 확인, clone 추적 파일 clean | 실제 비밀값은 결과 문서에 반입하지 않음 |
| 변경 문서 링크·비밀정보 | 로컬 링크 70개 유효, gitleaks 탐지 0 | 변경 문서 8개 범위 |

실행한 Compose 명령은 `config --quiet` 또는 `config --format json`뿐입니다. JSON의 자격증명은 메모리에서만 해석하고 출력·증적에 기록하지 않았습니다. S7 임시 설정은 Git 제외 `.local`에 보관합니다.

## 다음 실제 설치 검사

1. Claude 실측 종료 뒤 사용 가능한 자원과 시작 목록을 확인합니다.
2. [설치 안내](installation-guide.md)의 같은 프로젝트 선택으로 S7 `init/up/ready/configure`를 실행하고, 버튼 입력·관찰·원복을 다시 검증합니다.
3. pfSense/S10 완료 커밋을 독립 검토한 뒤 설치 절차를 합칩니다. 그 전에는 전체 다섯 구성 설치 완료 문구를 사용하지 않습니다.
4. 검사할 티켓과 실행 버전을 고정해 README 순서의 실제 기동·효과·원복을 확인하고 대시보드 캡처와 PPT를 갱신합니다.

## 11/10 오후 재점검 · PR #24 `1738175` (Claude)

제출 라인 PR #24(열린 PR #1~#23 포함)를 GitHub에서 새 빈 폴더로 `--single-branch --branch claude/submission-s10` clone해 같은 방식으로 다시 점검했습니다. 이번에도 **컨테이너 생성·기동·정지, 이미지 빌드, VM 조작은 실행하지 않았습니다.** 기존 Docker·VM·서비스는 변경하지 않았습니다. 다섯 구성의 실제 새 설치 완료를 뜻하지 않습니다.

| 확인 | 결과 | 의미와 한계 |
| --- | --- | --- |
| clone 직후 | 브랜치·커밋 일치, 작업 트리 clean | 이전 작업 폴더의 비밀값·가상환경·상태 파일을 복사하지 않음 |
| 줄끝(`core.autocrlf=true`) | `eol=lf` 지정 파일 중 CRLF 0개. 컨테이너가 쓰는 `start.sh`·`entrypoint.sh`·Dockerfile 7개 LF | Windows clone에서 스크립트가 깨지지 않는지 확인. 실행은 아님 |
| 백엔드 bootstrap | 성공(약 40초), SQLite 마이그레이션 4개 적용 | 잠금 의존성·editable 앱 설치. 로컬 pip 캐시 사용 |
| 저장소 `pytest -q tests` | **207 passed, 57 subtests passed** | Python 3.12.10 새 가상환경 |
| 백엔드 `pytest -q` | **87 passed, 6 skipped** | 건너뛴 6개(외부 MySQL 전용)는 통과로 세지 않음 |
| 생성기 `--check` | S7·S8·H1·S10·S1·S4 모두 일치(2/7/2/7/4+1/4+1) | 배포 생성물 대조. n8n·Graylog 가져오기 아님 |
| 파일만 만드는 `init` | S8·H1·S1·S4 성공. P04는 ISO 자리에 **빈 임시 파일**을 주고 성공, S10 성공 | 난수 환경 파일·번들 생성. S7 `init`은 컨테이너를 실행하므로 제외 |
| Compose `config` 해석 | 포털 2·포털+관제 7·S8 11·H1 9·P04 7·S10 12·S1 9·S4 9개 서비스 모두 성공 | 게시 포트는 모두 `127.0.0.1`. S1/S4는 #23 수정대로 기본망만 internal 아님(3/4). 실제 up·리스너 확인 아님 |
| init 후 Git 상태 | clean | `.env*`·`.local`·`.venv`가 Git 제외인지 확인 |
| README·docs 로컬 링크 | 251개 중 깨진 링크 0 | 외부 URL 접속은 확인하지 않음 |
| 추적 JSON | 152개 파싱 성공 | 스키마 전체 검증은 아님 |
| 문서 PowerShell 블록 | 45개 중 3개 문법 오류 → 2개 수정 | Windows PowerShell 5.1 파서로 검사(이 PC에 PowerShell 7 없음). 실행은 아님 |
| 비밀정보 패턴 | 추적 텍스트 파일에서 11건, 모두 시험용 합성 값(`Synthetic-test-password` 등) | gitleaks가 없어 정규식 검사로 대신함 |

발견과 수정(이 커밋):

| 발견 | 영향 | 수정 |
| --- | --- | --- |
| README·설치 안내가 제출 후보를 PR #16 `codex/personal-portfolio-deck`로 안내 | 새 clone이 S10·S1/S4·H1 수정이 빠진 브랜치를 받음 | PR #24 `claude/submission-s10`로 변경, 병합 뒤 `main` 사용 안내 |
| P04 `init --iso <ISO 경로>` 꺾쇠 자리표시자(README, `docs/s10-lab.md`) | PowerShell에 그대로 붙이면 문법 오류 | `Read-Host`로 경로를 받는 형태로 변경. 대체된 `s10-handoff-20261109.md`는 기록이라 그대로 둠 |
| 설치 안내의 생성기 검사가 S7·S8·H1만 나열 | S10·S1·S4 생성물 불일치를 놓칠 수 있음 | 세 줄 추가 |
| 제출 준비 문서의 PR #16 기준 표기 | 현재 제출 라인과 다름 | PR #24 기준으로 변경 |

남은 실제 설치 검사: 기존 학원 스택을 멈출 범위를 정한 뒤, 같은 clone에서 포털 → 관제 → 사례별 랩을 하나씩 `up`하고 효과·원복을 확인합니다. pfSense는 실제 ISO와 최초 설치 순서([s10-lab.md](s10-lab.md))가 필요합니다.
