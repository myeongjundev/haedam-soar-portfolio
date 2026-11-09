# 개인 관제 Docker Compose 설치

먼저 [README](../README.md#포털과-db-실행)의 `.env` 준비까지 진행합니다. `compose.yaml`은 포털·MySQL만 실행할 때 쓰고, 아래 명령은 Graylog·n8n·티켓 저장소를 추가합니다. Docker Desktop의 Linux 엔진을 사용합니다.

## 관제용 비밀값 생성

PowerShell 7에서 저장소 루트 기준으로 한 번 실행합니다. `.env.soc.example`은 변수 목록입니다.

```powershell
if (-not (Test-Path .env.soc)) {
  function New-LabSecret {
    [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).ToLowerInvariant()
  }
  $admin = New-LabSecret
  $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($admin))).ToLowerInvariant()
  @(
    "GRAYLOG_ADMIN_PASSWORD=$admin"
    "GRAYLOG_PASSWORD_SECRET=$(New-LabSecret)"
    "GRAYLOG_ROOT_PASSWORD_SHA2=$hash"
    "N8N_ENCRYPTION_KEY=$(New-LabSecret)"
    "TICKET_STORE_KEY=$(New-LabSecret)"
  ) | Set-Content -Encoding utf8NoBOM .env.soc
}
```

Linux에서는 OpenSSL과 `sha256sum`으로 같은 파일을 생성할 수 있습니다.

```sh
if [ ! -f .env.soc ]; then
  (
    umask 077
    admin=$(openssl rand -hex 24)
    hash=$(printf %s "$admin" | sha256sum | cut -d ' ' -f 1)
    printf 'GRAYLOG_ADMIN_PASSWORD=%s\nGRAYLOG_PASSWORD_SECRET=%s\nGRAYLOG_ROOT_PASSWORD_SHA2=%s\nN8N_ENCRYPTION_KEY=%s\nTICKET_STORE_KEY=%s\n' \
      "$admin" "$(openssl rand -hex 24)" "$hash" "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" > .env.soc
  )
fi
```

Graylog 로그인은 `admin`과 `.env.soc`의 `GRAYLOG_ADMIN_PASSWORD`를 사용합니다. 기존 볼륨을 다시 사용할 때는 기존 `.env`와 `.env.soc`를 보관합니다. n8n의 암호화 키를 바꾸면 기존 자격증명을 읽을 수 없습니다.

## 실행

```powershell
$soc = @('--env-file','.env','--env-file','.env.soc','-f','compose.yaml','-f','compose.soc.yaml')
docker compose @soc config --quiet
docker compose @soc up -d --build --wait --wait-timeout 180
docker compose @soc ps
```

Linux에서는 `docker compose` 뒤에 `--env-file .env --env-file .env.soc -f compose.yaml -f compose.soc.yaml`를 붙여 같은 하위 명령을 실행합니다.

| 구성 | 이 PC에서 접속 | Compose 내부 |
| --- | --- | --- |
| 해담시청 포털 | `http://127.0.0.1:15000` | `portal:5000` |
| MySQL | 내부 네트워크 | `db:3306` |
| Graylog | `http://127.0.0.1:19000` | `graylog:9000` |
| GELF TCP 입력 | `127.0.0.1:22201` | `graylog:12201` |
| MongoDB·OpenSearch | Graylog 전용 네트워크 | `graylog-mongo:27017` · `graylog-search:9200` |
| n8n | `http://127.0.0.1:15678` | `n8n:5678` |
| 티켓 대시보드 | `http://127.0.0.1:18089` | `ticket-store:8089` |
| 티켓 쓰기·조회 API | 내부 네트워크 | `ticket-store:8088` |

포털의 DB는 MySQL 컨테이너에서, Graylog의 상태와 검색 인덱스는 MongoDB·OpenSearch 컨테이너에서 유지합니다. n8n과 티켓 저장소는 각 서비스의 SQLite 파일을 별도 Docker 볼륨에 저장합니다. Web UI와 GELF 포트는 루프백에 바인딩합니다.

중지할 때는 `docker compose @soc stop`을 사용합니다. 다시 기동할 때 같은 프로젝트 이름과 환경 파일을 사용하면 볼륨을 재사용합니다.

OpenSearch가 `vm.max_map_count`를 이유로 시작하지 못하면 Docker가 사용하는 Linux 환경에서 현재 값을 확인합니다. Linux 기준으로 최소 `262144`가 필요합니다. [Graylog Docker 설치 문서](https://go2docs.graylog.org/current/downloading_and_installing_graylog/docker_installation_os.htm)

## 포털 로그와 Graylog → n8n 연결 검사

1. n8n 화면에서 첫 로컬 사용자 설정을 완료합니다. 팀의 수신 확인 워크플로를 가져와 게시합니다. 이 워크플로는 받은 이벤트와 실행 ID를 반환합니다.

   ```powershell
   docker compose @soc cp infra/n8n/workflows/haedam-00-recv-check.json n8n:/tmp/haedam-00-recv-check.json
   docker compose @soc exec -T n8n n8n import:workflow --input=/tmp/haedam-00-recv-check.json
   docker compose @soc exec -T n8n n8n publish:workflow --id=haedamRecvCheck01
   docker compose @soc restart n8n
   docker compose @soc up -d --wait n8n
   ```

2. Graylog의 **System → Configurations → URL Allowlist**에서 `http://n8n:5678/webhook/haedam-recv-check`를 **Exact match**로 추가합니다. 허용 목록을 켜 둡니다. 이 주소는 Compose 내부 서비스 DNS를 사용합니다.
3. **System → Content Packs**에서 [Haedam SOC smoke](../infra/graylog/content-packs/haedam-soc-smoke.json)를 업로드하고 설치합니다. GELF TCP 입력, 합성 로그 전용 스트림, 탐지 규칙, HTTP 알림이 포함됩니다. 입력이 Running이고 스트림과 이벤트 정의가 활성인지 확인합니다.
4. 브라우저나 `curl.exe`로 포털의 없는 경로 `http://127.0.0.1:15000/p02-not-found`에 요청합니다. 404 응답 뒤 Graylog Search에서 최근 5분에 `source:"haedam-portal" AND rule:"web-scan"`가 보이는지 확인합니다.
5. PowerShell에서 표식 입력과 정상 대조 입력을 보냅니다. `GELF_PORT`를 변경한 경우 명령의 `22201`도 바꿉니다.

   ```powershell
   $probe = 'p02' + [Guid]::NewGuid().ToString('N').Substring(0,12)
   foreach ($marker in @('haedamnormalcontrol','haedamsocsmoke')) {
     $id = if ($marker -eq 'haedamsocsmoke') { $probe } else { "${probe}control" }
     $gelf = @{
       version = '1.1'
       host = 'haedam-docker-qa'
       short_message = 'P02 connectivity smoke'
       _lab_marker = $marker
       _probe_id = $id
     } | ConvertTo-Json -Compress
     $client = [Net.Sockets.TcpClient]::new('127.0.0.1', 22201)
     try {
       $bytes = [Text.Encoding]::UTF8.GetBytes($gelf + [char]0)
       $client.GetStream().Write($bytes, 0, $bytes.Length)
     } finally {
       $client.Dispose()
     }
   }
   $probe
   ```

6. Graylog Search에서 두 `probe_id`를 조회합니다. 표식 입력만 **Haedam SOC smoke** 스트림에 들어갑니다. **Alerts & Events**에서 표식 입력의 이벤트 ID를 확인하고 n8n **Executions**에서 같은 `body.event_id`를 받은 실행이 성공인지 확인합니다. 실측을 마치면 필요에 따라 스모크 이벤트 정의를 일시 중지합니다.

이 테스트는 실제 포털 로그 수집과 합성 이벤트의 n8n 전달을 검증합니다. S8/S10의 실제 차단·티켓 생성·원복은 케이스별 설정을 연결한 뒤 별도로 측정합니다.

## Wazuh와 pfSense

Wazuh는 Manager·Indexer·Dashboard를 공식 단일 노드 Compose로 실행하는 P03으로 관리합니다. 포털 파일 감시와 Graylog 경보 전달을 확인할 때 통합 상태를 갱신합니다. 공식 단일 노드 안내의 Docker 호스트 메모리 기준은 8 GB입니다. [Wazuh Docker 설치 문서](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)

pfSense는 FreeBSD 기반의 가상 머신 구성으로 분리합니다. 과제 검사에서 VM 방식이 인정되는지 확인한 뒤 경계 로그와 실제 차단·원복을 연결합니다. [Netgate 가상화 문서](https://docs.netgate.com/pfsense/en/latest/virtualization/)
