# 개인 보안 실습 제어판

명령을 매번 입력하는 대신 **시험 입력 → 탐지·대응 확인 → 원복 완료**를 버튼으로 진행합니다. 회차별 경보 ID·티켓·파일/HTTP 효과·작업 이력을 저장하고 JSON으로 내보냅니다. 반소람 님의 제어판 소개에서 단계별 실행 흐름을 참고했으며 원본 HTML/화면/코드는 반입하지 않았습니다. 김명준·Codex의 별도 구현입니다.

## 시작

Python 3.12 표준 라이브러리만으로 제어판을 실행합니다. Docker 조작 권한을 웹 컨테이너에 마운트하지 않고 개인 PC의 제한된 실행기가 기존 S7 도구를 사용합니다.

처음에는 같은 worktree에서 아래처럼 제어판 설정을 읽고 자동 S7을 준비합니다. 다른 담당이 실측 중이면 이 초기화도 기다립니다. `PANEL_CONFIG_FILE`을 사용할 경우 먼저 지정하고, 새 PowerShell 창마다 설정 선택 네 줄을 다시 실행합니다.

```powershell
$panelConfigPath = if ($env:PANEL_CONFIG_FILE) { $env:PANEL_CONFIG_FILE } else { 'infra/panel-settings.json' }
$panelSettings = Get-Content -LiteralPath $panelConfigPath -Raw | ConvertFrom-Json
$env:S7_PROJECT = $panelSettings.s7_project
$env:S7_CONFIG_FILE = $panelSettings.s7_settings
py -3.12 tools/s7_auto_lab.py init
py -3.12 tools/s7_auto_lab.py up
py -3.12 tools/s7_auto_lab.py ready
py -3.12 tools/s7_auto_lab.py configure
```

각 단계가 성공해야 다음으로 넘어갑니다. 이미 초기화한 정상 랩을 재개할 때는 같은 설정을 선택한 뒤 `up → ready`만 실행합니다. 자동 S7 도구의 기본 프로젝트는 `haedam-s7-auto`, 제어판 기본 설정은 `haedam-s7-autocheck`이므로 설정 선택을 생략하지 않습니다.

```powershell
py -3.12 tools/panel.py
```

기본 접속: `http://127.0.0.1:15800`. 종료는 실행 터미널에서 Ctrl+C입니다. 브라우저를 닫아도 서버가 살아 있으면 접수한 작업은 계속됩니다. 서버 종료·시간 초과를 공격 취소나 원복으로 해석하지 않습니다.

`infra/panel-settings.json`의 `s7_project`가 실제 실행할 개인 S7 프로젝트와 일치해야 합니다. 기본값은 기존 검증 랩 `haedam-s7-autocheck`입니다. 다른 설정은 Git 제외 파일을 만들어 선택할 수 있습니다.

```powershell
Copy-Item infra/panel-settings.json .local/panel-settings.json
# 복사한 JSON의 프로젝트·제어판 포트를 변경한 뒤:
$env:PANEL_CONFIG_FILE = '.local/panel-settings.json'
py -3.12 tools/panel.py
```

S7의 경로/대상/계정/서비스 주소는 `s7_settings`가 가리키는 기존 `infra/s7-auto-settings.json`을 사용합니다. S7 환경 비밀값은 `.env.s7-auto`에서만 읽고 브라우저에 전달하지 않습니다. 제어판 설정이나 프로젝트/경로를 변경한 뒤 서버를 다시 시작합니다. 기존 회차와 scope가 다르면 조치하지 않습니다.

제어판을 켠다고 S7 컨테이너가 시작되지는 않습니다. [S7 자동 연결 설치](s7-auto-lab.md)의 init/up/ready/configure를 먼저 완료해야 합니다. 같은 worktree에서 만들어진 지정 프로젝트만 사용하며 포트·에이전트·마운트 설정도 대조합니다. 다른 담당이 Docker 실측 중이면 순서를 맞추고 진행합니다. 이 제어판은 S10/pfSense·다른 스택의 시작/중지 기능을 갖지 않습니다.

## 버튼 사용

1. **환경 확인:** 지정 프로젝트의 실제 서비스와 설정을 조회합니다. 꺼졌거나 다르면 시험 입력이 비활성화됩니다. 연결 정보는 60초가 지나면 UI에서 재조회를 요구하며 실제 입력 전에도 서버가 다시 확인합니다.
2. **시험 입력:** 설정의 허용 목록에서 파일 변조 또는 추가 파일을 선택합니다. 확인 창에서 프로젝트·대상을 보고 실행합니다. 정상 기준과 미완료 티켓을 먼저 확인한 뒤 무해한 입력을 한 번 기록합니다. 탐지 예약은 활성화됩니다.
3. **탐지·대응 확인:** 입력 해시와 일치하는 실제 Wazuh 경보, Graylog 판단, n8n 티켓 및 이미 수행된 대응의 현재 파일/HTTP 효과를 관찰합니다. 정상 조치는 Graylog→n8n이 시작합니다.
4. **원복 완료:** 같은 회차의 소유 티켓에만 완료를 요청하고, 정상 파일·티켓 restored·해당 격리물 제거를 확인합니다. Graylog 탐지는 일시 정지됩니다. 다음 시험 입력이 다시 활성화합니다.

중복 클릭과 동시 작업은 브라우저와 서버 양쪽에서 막습니다. 같은 개인 프로젝트의 제어판을 두 개 띄우면 파일 잠금으로 거부합니다. 회차는 `.local/panel/panel.sqlite3`에 남습니다. 비밀번호/토큰/원문 로그는 저장하지 않습니다. 화면의 완료 단계는 마지막 관측이며 영구적인 현재 상태가 아닙니다. 이력에서 선택한 회차를 재조회할 수 있습니다.

중단 뒤 `needs_check`가 남으면 공격을 반복하지 말고 탐지·대응 확인을 실행합니다. 입력 전 실패(`not_started`)는 새 회차를 시작할 수 있습니다. 준비 저장 뒤 실제 입력 전에 실패했거나 경보/티켓이 사라졌다면 자동으로 성공·원복 처리하지 않습니다. 원천 로그와 [S7 도구](s7-auto-lab.md)로 실제 상태를 확인하고 기록을 보존해야 합니다.

## 이번 검증과 남은 범위

제어판 큐/인증/CSRF/동시성/재시작과 adapter의 입력 해시·저장 ack·다른 worktree 거부는 격리 테스트로 확인합니다. 브라우저 자동화는 **합성 worker**로 취소→입력→확인→원복→새로고침 이력→증적 다운로드를 시험하며 실제 보안 탐지 실측으로 표시하지 않습니다. 실제 서비스가 꺼진 상태에서 실행 버튼 거부와 데스크톱/390px 화면도 확인합니다.

11/9에는 Docker 버튼 실측을 실행하지 않았습니다. **11/10 PR #12 통합 후 새 개인 랩에서 두 대상 모두 실제 버튼으로 Wazuh→Graylog→n8n→복구/격리·티켓·원복을 완료했습니다.** [실측·현재 한계](panel-results-20261110.md). 새 입력 전에 백엔드·웹 볼륨과 빌드 이미지도 대조합니다. S8/H1 버튼 연결과 S10 연결은 후속이며 UI에 미연결 상태를 표시합니다.

검토 시 실제 개인 S7을 준비하고 두 입력을 각각 버튼으로 실행해 같은 사건/티켓/원복 결과를 대조하세요. 실패·중단에서 새 입력이 차단되는지, 다른 회차 원복이 거부되는지, 최신 관측 실패가 과거 성공을 숨기지 않는지도 확인합니다. [API 계약](panel-contract.md).

11/9 확인: 전체 호스트 테스트 54개(제어판17개), 합성 worker 브라우저9항목, 실제 오프라인 화면/390px 가로 넘침 없음. [검증 구분 JSON](evidence/panel-checks-20261109.json), [데스크톱](evidence/panel-desktop-20261109.png), [모바일](evidence/panel-mobile-20261109.png). 캡처는 연결 대기 상태이며 실제 공격 성공 화면이 아닙니다.
