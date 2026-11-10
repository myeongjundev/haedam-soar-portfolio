# S1 개인 실측 준비 — PR #20 이후

**11/10 후속:** [실제 실측과 환경 재개](s1-results.md)를 완료했습니다. 아래 미실행·읽기 전용 설명은 최초 준비/사전 점검 당시의 기록입니다. 관리 포트와 하위 워크플로 반환 수정까지 포함된 코드에서 새 번들을 생성하세요. 실제 실행 시점의 자원·중지 허용 범위는 매번 확인합니다.

2026-11-10, 김명준·Codex. 기준 PR #20 `1ecf3b4`. 최초 준비는 파일 생성과 오프라인 검증이며, PR #21 후속 검토에서 Docker·Windows 자원을 읽기 전용으로 조회했습니다. 기존 Docker·VM·서비스를 변경하거나 실제 경보·차단을 실행하지 않았습니다. 아래 기동 이후 절차는 **실측 시간에만 새 개인 랩에서** 실행합니다.

## PR #21 검토 후 설치 판정

후속 [메모리 확보·단계별 설치·기존 환경 재개 순서](s1-memory-sequence.md)에 재확인 수치와 선택 가능한 실행 경로를 정리했습니다. 기존 자원의 중지/재개는 아직 수행하지 않았습니다.

실기동 보완: 최초 사전 검사는 Compose 선언만 확인했습니다. 이후 새 S1 기동에서 모든 망이 internal이면 localhost 포트가 실제 게시되지 않는 문제를 확인했습니다. `network_internal` 설정으로 관리 기본망만 일반 bridge로 두고 나머지 세 망은 internal로 유지합니다. 설치 후에는 `docker compose ps`의 실제 `127.0.0.1:호스트포트->컨테이너포트`와 호스트 HTTP 응답까지 확인해야 하며, 내부 health만으로 접속 가능 판정을 내리지 않습니다. 변경 전 번들은 코드/설정 해시가 달라 재사용하지 않습니다.

11/10 읽기 전용 사전 점검 시 Windows 가용 RAM은 2.21GiB(총 15.85GiB), Docker 한도는 5.79GiB였습니다. 실행 중인 기존 Wazuh·Graylog·MySQL 7개 컨테이너의 사용량 합계는 약 4.32GiB입니다. 한도와 사용량의 차이는 실제 가용 RAM이 아니며, 호스트와 Docker 사용량을 합산하지 않습니다. S1은 9개 서비스이며 Graylog/OpenSearch의 Java 힙만 합계 1GiB이고 나머지 서비스·네이티브 메모리·빌드 여유가 추가로 필요합니다. **현재 동시 설치는 보류**하며 실제 S1 최대 사용량은 미측정입니다.

- 중앙 설정의 후보 포트 `15060/19160/15760/22360/18160`은 리스너와 Windows IPv4 TCP/UDP 예약 범위에 겹치지 않았습니다.
- 후보 망 `172.30.100.0/24`, `172.30.101.0/24`, `172.30.102.0/29`, `172.30.103.0/29`는 확인한 Docker 네트워크 39개와 Windows IPv4 경로에 겹치지 않았습니다. VM 내부 경로는 검사하지 않았습니다.
- `haedam-s1-lab`의 기존 컨테이너·네트워크·볼륨 이름 충돌은 없었습니다. Compose `config --format json` 해석으로 9개 서비스, localhost 바인딩 5개, 내부 네트워크 4개와 응답 허용 출발지를 확인했습니다. 기동·빌드 검증은 아닙니다.
- 조회 시점의 결과이므로 실제 설치 직전에 다시 검사합니다. 기존 랩을 중지하거나 Docker/WSL 메모리 설정을 바꾸지 않았습니다.

다음 실행 순서는 **검토된 코드의 새 번들 → 사용할 PC/실행 시간 결정 → 메모리·이름·포트·망 재확인 → 새 개인 랩 설치 → 아래 실측 절차**입니다. 기존 환경을 유지해야 하면 충분한 여유가 있는 별도 PC/VM 호스트로 개인 랩을 옮깁니다. 같은 PC에서 기존 작업과 순차 실행하려면 사용자가 중지 가능한 서비스와 시점을 지정한 후에만 해당 범위의 중지·재개를 진행합니다. 검증 없이 Docker 메모리 한도를 높이거나 기존 볼륨을 삭제하지 않습니다.

검증기 수정으로 이전 `.local/s1-live-ready`의 코드 해시는 더 이상 일치하지 않습니다. 이력은 보존하고 새 번들을 생성합니다. 준비 번들은 실행 비활성 상태이며 실제 실측 때 검토된 코드에서 별도 실행용 번들을 만듭니다.

## 준비한 도구

| 도구 | 기본 동작과 범위 |
| --- | --- |
| [s1_rehearsal.py](../tools/s1_rehearsal.py) | 새 번들·정상 계정용 난수 비밀번호·실행 인수·증적 목록 생성. 실제 ID로 import JSON 생성. Docker/HTTP 호출 없음 |
| [s1_probe.py](../tools/s1_probe.py) | 기본 계획 출력. 명시적 실행 시 개인 Linux 클라이언트에서 baseline/blocked/restored 검사. 정상은 합성 계정 로그인, 공격자는 health 200→403→200 확인 |
| [s1_client.py](../tools/s1_client.py) | 기존 8/9회 제한 입력기. 401만 인정하고 403·429·예상 외 응답에서 중단 |
| [s1_evidence.py](../tools/s1_evidence.py) | 로컬 증적의 실행/계정/IP/설정·코드 해시/이벤트/티켓/원복 일치 검사와 정확한 원복 요청 본문 생성. 외부 요청 없음 |

정상 계정은 `설정 username_prefix + n_ + run_id`이며 비밀번호는 `normal-password.txt`에만 둡니다. 클라이언트에는 이 파일이나 lab.env를 마운트하지 않습니다. 비밀번호는 실행 시 stdin으로 전달하고 argv·환경변수·증적에 넣지 않습니다. baseline에서 같은 계정이 이미 있으면 409만으로 성공하지 않고 비밀번호 로그인까지 성공해야 합니다. 시민 역할·잠금 없음·세션의 동일 사용자도 검사합니다. 기존 계정 비밀번호를 변경하지 않습니다.

배치 주소·포트·경로는 [중앙 설정](../infra/s1-settings.json), 연결/credential은 [통합 설정](../infra/s1-integration-settings.json)에서 읽습니다. register 경로가 추가되어 이전 번들을 그대로 쓰지 않습니다. 새 번들에서 준비해야 합니다. 원본 코드 해시가 바뀌면 import/증적 검사를 거절하므로 검토된 코드를 고정한 뒤 번들을 생성합니다.

## 지금 실행 가능한 오프라인 준비

```powershell
py -3.12 tools/s1_rehearsal.py prepare --run-id s1prep --output .local/s1-live-prep
py -3.12 tools/s1_probe.py --settings .local/s1-live-prep/settings.json --run-id s1prep --role normal --phase baseline
py -3.12 tools/build_s1_workflows.py --check
```

첫 명령은 기본 execution_enabled=false입니다. 출력 폴더가 있으면 덮어쓰지 않습니다. `rehearsal.json`의 command_argv는 실행할 인수 배열일 뿐 도구가 실행하지 않습니다. `evidence-index.json`의 미확인 파일/definition_id는 null입니다. 이 상태에서 증적 검사는 실패해야 정상입니다. API 키·비밀번호·import 파일은 `.local` 아래 Git 제외이며 Windows 폴더 ACL도 본인만 읽도록 유지합니다.

## 실측 당일: 소유 환경 확인과 설치

이 절 이후 명령은 이번 작업에서 실행하지 않았습니다. 기존 환경을 정지하거나 재시작하는 명령은 없습니다. 메모리가 부족하거나 망/포트가 겹치면 여기서 중단합니다.

1. #20 후속 수정까지 검토된 이 브랜치에서 새 실측 번들을 만듭니다. 예: `py -3.12 tools/s1_rehearsal.py prepare --run-id r20261111 --output .local/s1-r20261111 --arm-input`. 이는 파일 준비만 수행하고 실행 허용 플래그만 설정합니다. 기본 정책 9회/30분, 간격 100초를 줄이지 않습니다.
2. Docker의 프로젝트·볼륨·네트워크를 **읽기만** 확인해 설정 project 이름이 기존 자원에 사용되지 않았는지, 설정 4개 망/5개 호스트 포트가 겹치지 않는지 확인합니다. 이미 존재하는 같은 이름의 랩은 이 새 설치 절차로 덮어쓰지 않습니다. 명명된 다른 프로젝트를 사용하려면 중앙 설정을 바꿔 새 번들을 생성합니다.
3. 별도 PowerShell에서 번들의 Compose 인수를 사용합니다. 아래 함수는 현재 셸의 환경을 바꾸지 않고 자식 프로세스에서 dotenv 충돌 키만 제외합니다. 원문 stderr에는 민감정보가 들어갈 수 있어 사용자 출력에 전부 붙이지 않습니다.

```powershell
$bundle = (Resolve-Path '.local/s1-r20261111').Path
$settings = Get-Content (Join-Path $bundle 'settings.json') -Raw | ConvertFrom-Json
$packet = Get-Content (Join-Path $bundle 'rehearsal.json') -Raw | ConvertFrom-Json
$manifest = Get-Content (Join-Path $bundle 'bundle.json') -Raw | ConvertFrom-Json
function Invoke-OwnedS1([string[]]$Command, [string]$InputText = '') {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Command[0]
    foreach ($arg in $Command[1..($Command.Count-1)]) { $psi.ArgumentList.Add($arg) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($key in $manifest.clear_process_env_before_future_compose) { $psi.Environment.Remove($key) | Out-Null }
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    $proc.StandardInput.Write($InputText); $proc.StandardInput.Close()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) { throw 'S1 command failed; inspect locally with secrets redacted.' }
    return $stdout.GetAwaiter().GetResult()
}
# 소유권/충돌 확인 후, 새 개인 프로젝트에서만 실행
Invoke-OwnedS1 ($manifest.compose_argv + @('up','-d','--build','--wait')) | Out-Null
```

PowerShell 7에서 실행합니다. Compose가 새 프로젝트와 새 볼륨을 사용하고 포털 DB 마이그레이션을 끝냈는지 확인합니다. API/credential/워크플로 준비가 끝나기 전 입력 명령을 실행하지 않습니다. 기존 랩에 이 작업 폴더를 bind mount하거나 기존 .env를 복사하지 않습니다.

## Graylog·n8n 가져오기 순서

1. 새 Graylog에 해당 번들의 관리자 키로 로그인합니다. `graylog-integration.template.json`의 input 객체로 GELF TCP 입력을 만듭니다. 기본 인덱스 세트 ID와 새 input ID를 확인합니다.
2. 같은 파일의 stream 객체에 실제 index_set_id를 넣고, source 규칙 외에 `type:8, field:gl2_source_input, value:<실제 input ID>` 규칙을 추가합니다. 이 스트림을 실행하고 포털 GELF의 source/rule/status/username/src_ip 필드가 원문대로 도착하는지 확인합니다.
3. n8n에는 아직 알림을 보내지 않는 상태에서 Graylog HTTP 알림을 만들고 ID를 확보합니다. 웹훅 경로·헤더 이름은 통합 설정에서, 비밀값은 **이 번들의** lab.env에서 가져옵니다. 이 단계에는 이벤트 정의를 예약하지 않습니다.
4. 아래 네 ID를 `bindings.json`에 넣습니다. `input_id`, `index_set_id`, `stream_id`, `notification_id`만 허용하며 각각 실제 24자리 hex ID여야 합니다. 예시 숫자를 실제 ID로 오인해 넣지 않습니다.
5. `py -3.12 tools/s1_rehearsal.py imports --bundle .local/s1-r20261111 --bindings .local/s1-r20261111/bindings.json --enable-detection`을 실행합니다. 키 4개 분리와 코드/설정 해시를 검사하고 새 `import/`에 credentials.json/workflows.json/graylog.json을 만듭니다. **파일 생성만 하며 import/예약은 실행하지 않습니다.**
6. 새 n8n의 소유자 계정 설정을 완료하고 credentials/workflows를 가져온 뒤 하위 워크플로 포함 4개 ID를 게시합니다. UI에서 해당 개인 프로젝트·credential 참조가 연결됐는지도 확인합니다. 예시는 아래와 같습니다. 임시 파일은 finally에서 제거하고 stdout에 credential 내용을 출력하지 않습니다.

```powershell
foreach ($kind in @('credentials','workflows')) {
    $remoteFile = "/tmp/s1-$kind.json"
    $content = Get-Content (Join-Path $bundle "import/$kind.json") -Raw
    try {
        Invoke-OwnedS1 ($manifest.compose_argv + @('exec','-T','n8n','node','-e',
          "require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})",$remoteFile)) $content | Out-Null
        $subcommand = if ($kind -eq 'credentials') { 'import:credentials' } else { 'import:workflow' }
        Invoke-OwnedS1 ($manifest.compose_argv + @('exec','-T','n8n','n8n',$subcommand,"--input=$remoteFile")) | Out-Null
    } finally {
        Invoke-OwnedS1 ($manifest.compose_argv + @('exec','-T','n8n','node','-e',
          "require('fs').rmSync(process.argv[1],{force:true})",$remoteFile)) | Out-Null
    }
}
$imports = Get-Content (Join-Path $bundle 'import/manifest.json') -Raw | ConvertFrom-Json
foreach ($id in $imports.workflow_ids.PSObject.Properties.Value) {
    Invoke-OwnedS1 ($manifest.compose_argv + @('exec','-T','n8n','n8n','publish:workflow',"--id=$id")) | Out-Null
}
# 이 새 프로젝트의 n8n만 게시 설정을 읽도록 재시작
Invoke-OwnedS1 ($manifest.compose_argv + @('restart','n8n')) | Out-Null
Invoke-OwnedS1 ($manifest.compose_argv + @('up','-d','--wait','n8n')) | Out-Null
```

7. Graylog `import/graylog.json`의 notification 객체로 **해당 notification ID만** 갱신합니다. literal URL 허용 목록 항목을 추가하고 definition 객체로 새 이벤트 정의를 만듭니다. `/events/definitions/{id}/unschedule`(PUT)로 예약 정지를 확인합니다. 실제 definition ID는 evidence-index.json에 기록합니다. 다른 정의·기존 allowlist 항목을 덮어쓰지 않습니다.
8. 개인 n8n에서 키 없는/잘못된 키의 웹훅 요청이 거절되는지, 잘못된 case/대상/계정이 HTTP 400이며 대응·티켓 변경이 없는지 확인합니다. 예시 이벤트나 직접 웹훅 재생을 실제 탐지 증거로 쓰지 않습니다. 실제 엔진 호환성·게시가 확인되지 않으면 입력을 시작하지 않습니다.

## 실측 입력과 같은 회차의 효과 확인

1. baseline을 먼저 저장합니다. 정상 비밀번호는 stdin으로 전달합니다.

```powershell
Invoke-OwnedS1 $packet.command_argv.attacker_baseline | Out-Null
$normalPassword = Get-Content (Join-Path $bundle 'normal-password.txt') -Raw
Invoke-OwnedS1 $packet.command_argv.normal_baseline $normalPassword | Out-Null
```

2. 8회 경계 검사는 다른 탐지 키(username `b_`)로 수행합니다. 해당 키의 지난 30분 로그·남은 조치가 없는지 확인하고 이벤트 정의를 예약(PUT `/events/definitions/{id}/schedule`)한 후 `Invoke-OwnedS1 $packet.command_argv.boundary8`을 실행합니다. 마지막 401이 Graylog에 들어온 뒤 최소 1,860초 관찰하여 S1 이벤트/차단이 없는지 확인합니다. 입력 완료만으로 미탐지를 판정하지 않습니다.
3. 9회 입력 `Invoke-OwnedS1 $packet.command_argv.trigger9`를 실행합니다. 기본 입력 시간은 최소 800초입니다. 터미널을 강제 종료하지 말고 `runs/STOP` 파일로 중지합니다. 403/429/예상 외 응답이 나오면 자동 재시도하지 않습니다.
4. 같은 username `t_`·공격 출발지의 Graylog 원천 401 9건을 확인합니다. 실제 event ID와 definition ID를 확인하고 `/events/search` 응답의 **해당 event 객체 하나**를 `graylog-event.json`으로 보관합니다. 웹훅을 직접 호출해 대신 만든 이벤트는 제외합니다.
5. 티켓 대시보드의 GET `/api/v1/tickets/{실제 ticket_id}` 응답을 `ticket-blocked.json`으로 저장합니다. group_key/asset/event_ids/portal block을 대조합니다. 목록 summary 대신 ticket 상세 객체가 필요합니다. 목록에는 username이 없으므로 group_key로 후보를 찾은 뒤 상세의 username/src_ip를 확인합니다. 주기 평가로 이벤트가 여러 건 생길 수 있으므로 해당 티켓이 처음 수신한 event ID를 선택합니다. 전체 검색 결과가 반드시 1건이라고 가정하지 않습니다.
6. `Invoke-OwnedS1 $packet.command_argv.attacker_blocked`, `Invoke-OwnedS1 $packet.command_argv.normal_blocked $normalPassword`를 실행합니다. 공격 health는 403 IP_BLOCKED, 정상 health/새 로그인/세션은 성공해야 합니다.

## 원복과 최종 증적

Graylog 이벤트 정의를 먼저 unschedule하고 n8n의 실행 중·대기 작업이 없는지 확인합니다. 이 검사는 도구가 대신 수행하지 않습니다. 지난 30분 입력이 검색창에서 사라지기 전에 재예약하면 새 이벤트로 다시 차단될 수 있습니다.

evidence-index.json의 ticket_blocked를 `ticket-blocked.json`으로 설정하고 다음 명령으로 원복 본문을 만듭니다. 현재 실제 티켓의 활성 portal block 한 개만 허용합니다. 스냅숏이 오래됐더라도 실제 웹훅은 최신 티켓/소유권을 다시 검사합니다.

```powershell
$releaseBody = py -3.12 tools/s1_evidence.py release-body --bundle $bundle | Out-String
if ($LASTEXITCODE -ne 0) { throw 'Release body validation failed' }
$localValues = @{}
Get-Content (Join-Path $bundle 'lab.env') | ForEach-Object {
    $parts = $_.Split('=',2); $localValues[$parts[0]] = $parts[1]
}
$integration = Get-Content (Join-Path $bundle 'integration-settings.json') -Raw | ConvertFrom-Json
$uri = 'http://127.0.0.1:' + $settings.host_ports.N8N_PORT + '/webhook/' + $integration.release_path
$headers = @{}
$headers[$integration.credentials.operator.header] = $localValues[$integration.credentials.operator.env]
$released = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json' -Body $releaseBody
$released | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $bundle 'release-response.json') -Encoding utf8
Invoke-OwnedS1 $packet.command_argv.attacker_restored | Out-Null
Invoke-OwnedS1 $packet.command_argv.normal_restored $normalPassword | Out-Null
```

해제 후 같은 ticket 상세 응답을 `ticket-restored.json`으로 다시 저장합니다. restored·활성 조치 0과 실제 공격 출발지 200, 정상 로그인 성공을 모두 확인합니다. 실패하면 snapshot/부분 성공을 완료로 표시하지 않고 [실패 복구 절차](s1-auto-workflows.md#대응원복-판정)를 따릅니다.

evidence-index.json에 graylog_event/ticket_blocked/ticket_restored/release_response의 상대 파일 경로와 실제 definition_id를 채운 뒤 다음 명령을 실행합니다.

```powershell
py -3.12 tools/s1_evidence.py check --bundle .local/s1-r20261111
```

검사기는 같은 run ID, 설정·도구 해시, 9회 401와 간격/시간창, 6개 probe, 정상 로그인, 같은 Graylog event/ticket, 적용·해제 이력, 최종 활성 조치 0과 시간 순서를 검사합니다. 누락/혼합/샘플/코드 불일치이면 종료 코드 2입니다. 통과도 **제공된 증적 사이의 일치**이며 provenance_attested=false입니다. 실제 환경에서 생성됐는지와 스크린샷/Graylog 원천 건수/8회 무탐지 관찰은 사람이 별도 확인해야 합니다. 인증 키·세션·비밀번호가 보이는 화면은 보관하지 않습니다.

PR #21 검토 수정: 원복 후 상세 티켓은 원복 전 작업 이력을 변경 없이 앞부분에 보존하고, 그 뒤에 같은 봇·경로·대상의 검증된 해제 기록을 추가해야 합니다. 중복 해제 기록만 있거나 적용 이력이 사라진 경우에는 통과하지 않습니다. 티켓 저장소의 초 단위 `restored_at`은 `[표시 시각, 다음 초)` 구간으로 비교합니다. 같은 초 안의 세부 순서는 증명할 수 없으며, 다음 초 이후 끝난 차단 probe는 거절합니다. 소수 초가 있는 시각은 정확한 시각 비교를 유지합니다. 이 정밀도 처리는 요청 timeout이나 임의의 긴 허용 오차로 확장하지 않습니다.

검증표에는 `입력 시작/종료`, `Graylog 조건 충족/탐지`, `포털 적용`, `정상 대조`, `원복 완료` 시각을 구분합니다. 클라이언트 종료→탐지 시간 차이를 탐지 지연으로 단정하지 않습니다. 실제 동작이 확인된 후에만 포트폴리오 PPT에 실측을 반영합니다.

기본 정책을 유지하면 8회 입력 700초 + 경계 관찰 1,860초 + 9회 입력 800초로 **최소 56분**이 필요하며, 설치·알림 지연·원복 확인 시간은 별도입니다. 마감 때문에 간격/검색창을 축소한 결과를 팀 S1 기준의 실측으로 제출하지 않습니다.
