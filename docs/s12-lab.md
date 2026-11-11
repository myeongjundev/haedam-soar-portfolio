# S12 개인 설치와 제한 실측

팀 김대훈의 요청 집계/health 정책과 개인 S1의 티켓·IP 소유권 처리를 연결한 별도 랩입니다. [작업 범위](s12-task.md)를 먼저 확인합니다. **통제된 자원 경합 시험**이며 운영 환경 DDoS 방어 성능 검사가 아닙니다. 사용자 입력·민원 데이터는 사용하지 않습니다.

## 새 환경 준비

Docker Desktop Linux 엔진, Python 3.12, 약 6GiB Docker 메모리가 필요합니다. 다른 랩과 동시에 실행하지 않습니다. 기존 환경의 중지는 별도 실행 순서에 따라 수행하며 아래 도구가 다른 프로젝트를 정지하지 않습니다.

1. `infra/s12-settings.json`을 Git 제외 `.local/s12-settings.json`으로 복사합니다. `project`는 새 `haedam-s12-...` 이름으로 정하고 네트워크·포트 충돌을 읽기 전용으로 확인합니다. `execution_enabled`를 `true`로 설정합니다. baseline 값은 `null`로 둡니다.
2. 기본 입력은 1→2→5회/초, 단계별 30초입니다. 자원 경합 시험에서 30초 탐지 주기와 health 관찰 시간을 확보하려면 `load.rates_per_second`를 `[2,5,5]`로 설정할 수 있습니다. 최대 요청 240, 동시성 2, 90초 상한은 유지합니다. 사용한 설정을 증적에 보존합니다.
3. 새 번들을 생성합니다. 기존 디렉터리를 덮어쓰지 않습니다.

```powershell
New-Item -ItemType Directory -Force .local | Out-Null
Copy-Item infra/s12-settings.json .local/s12-settings.json
# 위 설명대로 .local/s12-settings.json을 편집한 다음 실행
py -3.12 tools/s12_lab.py --settings .local/s12-settings.json --output .local/s12-demo
$bundle = Resolve-Path .local/s12-demo
$manifest = Get-Content "$bundle/bundle.json" -Raw | ConvertFrom-Json
foreach ($key in $manifest.clear_process_env_before_future_compose) {
    Remove-Item "Env:$key" -ErrorAction SilentlyContinue
}
$composeArgs = @($manifest.compose_argv | Select-Object -Skip 1)
docker @composeArgs config --quiet
docker @composeArgs up -d --build --wait --wait-timeout 240
```

`docker network ls`, `docker network inspect`, `Get-NetTCPConnection -State Listen`으로 기존 망/포트를 확인합니다. `config` 전체 출력에는 키가 포함될 수 있으므로 공유할 때는 `--quiet`만 사용합니다. `lab.env`, n8n 소유자 정보, import 파일은 Git 제외입니다. 초기화 비밀번호는 무작위로 생성하며 코드에 넣지 않습니다.

## 연결·기준선·시험

```powershell
py -3.12 tools/s12_configure.py baseline --bundle .local/s12-demo
py -3.12 tools/s12_measure.py baseline --bundle .local/s12-demo --run-id base01
py -3.12 tools/s12_configure.py measured --bundle .local/s12-demo
py -3.12 tools/s12_measure.py boundary --bundle .local/s12-demo --run-id boundary01
py -3.12 tools/s12_measure.py healthy --bundle .local/s12-demo --run-id healthy01
```

첫 configure는 Graylog GELF TCP 입력·전용 스트림·인증 알림·URL allowlist와 n8n 자격증명 4개/워크플로 5개를 만듭니다. 건강 상태 측정 전에는 탐지 정의를 만들지 않습니다. baseline은 공격/정상 클라이언트 각각 31회와 n8n 실제 경로 30회, Graylog 고유 수신 건수를 대조합니다. 실패·누락이 있으면 임계값을 확정하지 않습니다.

계산식은 60초 최대 정상 요청 수×3 올림, n8n 경로 max(p95×3, p95+300ms)입니다. 측정값을 번들의 settings와 해시에 반영합니다. measured configure는 기준값이 있는 워크플로를 다시 게시하고 탐지 정의를 생성하되 예약을 정지합니다. configure는 초기 생성 단계별 1회 실행용이며 부분 실패 후 기존 리소스를 무작정 재생성하지 않습니다.

boundary는 **3건 입력과 90초 무탐지** 검사입니다. 정확한 N/N+1 경계를 검증했다고 표시하지 않습니다. healthy는 실측값을 넘는 요청에도 health가 정상이면 티켓/차단이 없어야 합니다. 같은 이벤트의 후속 직접 재전달 진단은 최초 Graylog 자동 전달과 별도 파일에 남습니다.

healthy 완료 뒤 최소 90초가 지나고 해당 공격 IP의 마지막 60초 요청이 0건인지 확인한 다음 실행합니다. 도구는 이 조건을 충족하지 못하면 거부합니다.

```powershell
py -3.12 tools/s12_measure.py controlled --bundle .local/s12-demo --run-id controlled01
# 결과 파일의 실제 ticket_id를 확인하고 사용합니다. 아래 값은 예시가 아닙니다.
$result = Get-Content .local/s12-demo/controlled01-result.json -Raw | ConvertFrom-Json
$ticketId = $result.tickets[0].ticket_id
py -3.12 tools/s12_measure.py recover --bundle .local/s12-demo --run-id restored01 --ticket-id $ticketId
docker @composeArgs stop --timeout 30
```

controlled는 포털의 실제 health/config 처리가 공유하는 슬롯을 랩 요청으로 점유합니다. 슬롯 1개·점유 500ms·최대 150초이며 실제 health 본문을 바꾸지 않습니다. 대응 API는 이 경합에서 제외하고 실제 IP 차단 가드가 먼저 실행되므로 차단된 입력은 슬롯을 차지하지 않습니다. 낮은 요청 수에서도 재현되는 인위적 랩 조건임을 결과에 표시해야 합니다.

성공 기준은 Graylog 원천/이벤트 → 동일 event_id의 티켓/차단 조치, 공격 403, 정상 200/본문, 경합 만료 전 지연 회복, 운영자 원복 후 양쪽 200/티켓 restored입니다. API 200 또는 그래프 테스트만으로 전체 통과 처리하지 않습니다. `effect_verified`가 null이면 별도 클라이언트 증거를 제시합니다.

## 중지·실패 복구

`runs/STOP` 파일은 입력 중지 신호입니다. 정상 대조 오류가 발생하면 자동 생성됩니다. CLI 오류 시 같은 번들의 경합을 끄고 탐지 예약 정지를 시도합니다. 실제 차단이 이미 적용됐다면 소유 티켓 상태를 확인하고 **recover로 해제한 뒤** 랩을 정지합니다. STOP을 무작정 지우거나 같은 run ID로 증적을 덮어쓰지 않습니다. 부분 실패의 티켓 상태와 원복 응답은 직접 확인해야 합니다.

원복 이후 포털 DB 활성 IP 차단 0, 티켓 활성 조치 0, n8n 실행 payload 0을 함께 확인합니다. 기존 환경을 일시 정지했다면 원래 컨테이너 ID로 재개하고 대시보드 응답·MySQL/VM 유지 여부를 검사합니다. `down -v`는 사용하지 않습니다.

## 주소와 파일

기본 localhost 접속: 포털 `15080`, Graylog `19180`, n8n `15780`, 티켓 `18180`, GELF TCP `22380`. 실제 값은 번들 `settings.json`이 기준입니다. 기본 망은 관리 `172.30.120.0/24`, 클라이언트 `172.30.121.0/24`, 대응 `172.30.122.0/29`, Graylog 저장망 `172.30.123.0/29`입니다. 포털 대응 API는 n8n 대응 IP `/32`만 허용합니다.

원본 설정은 `infra/s12-*.json`, 비활성 생성물은 `infra/n8n/portfolio-s12/`와 `infra/graylog/portfolio-s12.json`입니다. 미측정 템플릿을 그대로 활성화하지 않습니다. `py -3.12 tools/build_s12_workflows.py --check`로 생성물 일치를 확인합니다. 실제 측정 원본은 번들의 `runs/`, `baseline.json`, `<run-id>-result.json`, 원복 응답에 남습니다. 게시 전 비밀값과 세션 정보가 없는 허용 필드만 선별합니다.
