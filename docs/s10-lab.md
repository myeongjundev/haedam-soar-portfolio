# P04·S10 개인 랩 · pfSense 경계 차단과 포털 차단

제안·구현 범위: 팀 S8·S10 설계와 B(김명준)의 pfSense 제한 도구(팀 저장소 `94451bf`)를 개인 환경에서 재현합니다. 개인 랩 구성·연결·검증 도구는 김명준·Claude가 작업했습니다. [결과](s10-results-20261110.md), [인수인계](s10-handoff-20261110.md).

## 구성

pfSense CE 2.7.2는 **Docker 컨테이너 안의 QEMU VM**으로 실행합니다. 이 PC의 Docker/WSL에는 `/dev/kvm`이 없어 QEMU가 소프트웨어 에뮬레이션(TCG)으로 동작합니다. 2026-11-10 측정값은 다음과 같습니다(관측값이며 보장값이 아닙니다).

- ISO 설치: 파일 추출 약 2분.
- 디스크 부팅: 약 2.5~3분.

팀 VMware `Haedam-pfSense`와 VMnet, Windows 네트워크 설정은 사용하지 않습니다.

```text
attacker 203.0.113.22 ─┐ pf-wan 203.0.113.0/24            pf-lan 172.30.94.0/24 ┌─ portal 172.30.94.10:5000
normal   203.0.113.12 ─┘   em0 203.0.113.1 [pfSense VM] em1 172.30.94.1  ───────┼─ controller/relay 172.30.94.100
                            (QEMU in container "pfsense", tap ↔ bridge)          ├─ graylog 172.30.94.20 (syslog UDP 5514)
                                                                                 └─ n8n 172.30.94.30
portal GELF ─(default net)→ Graylog        n8n ─(s10-response 172.30.95.0/29)→ portal-response (IP 차단 API)
```

- **실제 경로:** 클라이언트는 포털 대역으로 가는 경로를 pfSense WAN으로만 갖고 있습니다. 포털은 돌아가는 경로를 pfSense LAN으로 잡습니다.
  - 공격 컨테이너는 `pf-wan`에만 연결돼 있습니다. 포털이 있는 망에는 인터페이스가 없습니다.
  - pfSense가 차단하면 공격 쪽 요청이 실제로 끊기는 것으로 이 경로를 확인했습니다.
- **망 설정:** `pf-wan`·`pf-lan`은 `internal`이 아닙니다. NAT masquerade는 끕니다.
  - Docker의 `DOCKER-INTERNAL` 규칙은 bridge 프레임 중 목적지가 다른 대역인 것을 버립니다. 그래서 `internal`이면 라우팅된 트래픽이 모두 사라졌습니다.
  - QEMU 컨테이너 bridge의 Docker 쪽 포트는 MAC을 학습하지 않습니다. Docker bridge가 프레임을 되돌려 보내 게스트 MAC을 잘못 학습했기 때문입니다.
- **제어:** 컨트롤러가 SSH로 팀 도구를 실행합니다.
  - 호스트 키는 고정(`StrictHostKeyChecking=yes`)입니다.
  - 키는 `command=`·`from="172.30.94.100"`로 제한합니다.
  - n8n의 SSH 노드는 호스트 키를 고정할 수 없습니다. 그래서 S10에서는 같은 컨테이너의 `pf_relay.py`가 n8n 주소·키·허용 동작(`status/block/unblock`)·허용 대상만 받아 같은 SSH를 실행합니다.

## 설정과 비밀값

| 위치 | Git | 내용 |
| --- | --- | --- |
| `infra/pfsense/lab-settings.json` | 포함 | 망·주소·인터페이스·포털·컨트롤러·클라이언트·VM 메모리·도구 경로, `s10`(Graylog·n8n·relay 주소/포트, 응답망, ICMP tracker, 탐지 창). 다른 파일은 `PF_LAB_SETTINGS`로 지정 |
| `.env.pf` | 제외 | `MYSQL_*`, `PORTAL_PORT`, `PFSENSE_ISO`, S10의 `GRAYLOG_*`, `N8N_ENCRYPTION_KEY`, `TICKET_STORE_KEY`, `PORTAL_RESPONSE_KEY`, `S10_DETECTION_KEY`, `S10_OPERATOR_KEY`, `PF_RELAY_KEY`, 포트. `pf_lab.py init`·`s10_lab.py init`이 생성(값 출력 안 함). 변수 목록은 `.env.pf.example` |
| `.local/pf/ssh/` | 제외 | 컨트롤러 키와 pfSense 호스트 키 `known_hosts` |
| `.local/pf/*.json`, `*.png` | 제외 | 실측 증적·화면. 공개용은 검토 후 `docs/evidence/`에 선별 |
| 팀 도구 상수 | 포함 | 대상 `.22`/`.41`, WAN `em0`/`203.0.113.1`, 2.7.2, 고정 SHA. 배포 설정과 별개인 계약 상수이며 바꾸지 않습니다 |

## P04 실행 순서

```powershell
$iso = Read-Host 'pfSense CE 2.7.2 ISO 파일 경로'
py -3.12 tools/pf_lab.py init --iso $iso
ssh-keygen -q -t ed25519 -N "" -C haedam-pf-controller -f .local/pf/ssh/controller
py -3.12 tools/build_pfsense_bundle.py --out .local/pf/bundle
docker ps --format "{{.Names}}"            # 시작 목록 기록. 메모리가 부족하면 합의된 범위만 정지
py -3.12 tools/pf_lab.py up pfsense
py -3.12 tools/pf_lab.py screen            # .local/pf/screen.png를 보며 keys로 설치(Accept → Install → Auto UFS → vtbd0 → Entire Disk → MBR → Finish → Commit)
```

설치가 끝나면 설치기에서 **Shell**을 고릅니다.

1. 설치된 루트를 붙이고 기본 설정을 전송 디스크로 꺼냅니다: `mount /dev/vtbd0s1a /mnt`, `mount_msdosfs /dev/vtbd1 /tmp/x`, `cp /mnt/conf.default/config.xml /tmp/x/default.xml`.
2. 호스트에서 `pf_lab.py xfer-get default.xml .local/pf/default-config.xml`을 실행합니다.
3. `pf_config.py`로 랩 설정을 만들고 `xfer-put`으로 넣습니다.
4. VM 안에서 `/mnt/cf/conf/config.xml`로 복사하고, 시리얼 콘솔용 `/mnt/boot/loader.conf.local`을 씁니다.
5. `pf_lab.py installed` 후 `poweroff` → `pf_lab.py up`으로 디스크 부팅합니다.

부팅 뒤에는 다음 순서로 진행합니다.

1. 시리얼 콘솔에서 메뉴 8(셸)을 엽니다: `pf_lab.py serial 8`. 이 셸은 tcsh이고 줄 길이 제한이 있어 `pf_lab.shell()`이 명령을 base64로 나눠 보내고 `/bin/sh`로 실행합니다.
2. 번들을 전송 디스크로 넣고 `install_bundle.py --verify`, `--install`을 실행합니다. `new_tool_file_installed`와 고정 SHA를 확인합니다.
3. `/etc/ssh/ssh_host_ed25519_key.pub`로 `.local/pf/ssh/known_hosts`를 만듭니다.
4. `py -3.12 tools/pf_lab.py up` 후 `py -3.12 tools/pf_verify.py`를 실행합니다.

## S10 실행 순서

```powershell
py -3.12 tools/s10_lab.py init        # S10 비밀값·포트를 .env.pf에 추가
py -3.12 tools/s10_lab.py up          # Graylog·OpenSearch·MongoDB·n8n·티켓 + relay. pfSense VM은 디스크 유지
py -3.12 tools/s10_lab.py pfsense     # pfSense syslog → Graylog, WAN ICMP 로그 차단 규칙(tracker는 설정값)
py -3.12 tools/s10_lab.py configure   # n8n 자격증명·워크플로, Graylog 입력·스트림·pfsense-parse·S10 정의(정지 상태)
py -3.12 tools/s10_verify.py          # 실제 ICMP+404+401 → Graylog → n8n → 포털·pfSense 차단 → 중복 → 원복
py -3.12 tools/s10_failures.py        # 티켓 저장소 장애·relay 장애(직접 웹훅 시험 입력)
```

- `configure`는 이 랩 Graylog의 메시지 처리 순서를 바꿉니다. Pipeline Processor를 스트림 라우팅 뒤로 옮깁니다. 6.1 기본 순서에서는 스트림에 연결한 파이프라인이 실행되지 않았기 때문입니다.
- S10 정의는 팀 `lab/s8s10/graylog/acceptance/s10-three-layer.json`을 씁니다. 같은 `src_ip`에서 pfSense ICMP 차단 로그(tracker), 포털 404 `web-scan`, 401 `login-bruteforce`가 15분 안에 모두 나오면(`card(rule)>2`) 발동합니다. 출발지·WAN 주소·tracker는 설정값으로 바꿉니다.
- 같은 출발지는 grace 15분 동안 다시 알리지 않습니다. 같은 대상으로 다시 시험할 때는 15분을 기다립니다.
- n8n 배포는 팀 `haedam-32/50/12/14/10`의 S10 경로를 그대로 씁니다. `build_s10_workflows.py`가 S8 배포 패치를 사례·대상만 바꿔 재사용합니다.
  - 동작: 티켓 선기록 → 포털 차단 → pfSense 차단 → 각 결과 기록. 모든 조치를 확인해야 성공입니다. 원복은 소유 티켓으로만 두 조치를 해제합니다.
  - pfSense 해제 성공은 도구의 `applied_verified`가 아니라 재조회 결과(config·table·rule 모두 없음)로 판정합니다.
- 메모리: 11/10 측정에서 S10 전체 컨테이너 합계는 약 3.9GB였습니다(Docker 6GB). pfSense VM 컨테이너가 1.42GB, Graylog 0.85GB, OpenSearch 0.75GB, n8n 0.46GB였습니다. 이 측정은 기존 학원 컨테이너를 모두 멈춘 상태에서 했고, 다른 관제 스택과 동시에 실행하지 않습니다.
