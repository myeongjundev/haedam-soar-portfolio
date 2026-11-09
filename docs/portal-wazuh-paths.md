# 반입한 프론트·백엔드와 Wazuh 감시 경로

2026-11-09 두 원본 저장소를 fetch하여 확인했습니다. 프론트 원본 main `994fc45`, 백엔드 원본 main `98e549c`는 개인 저장소의 기존 반입 기준과 같습니다. 새로 덮어쓸 upstream main 변경은 없습니다. 개인 H1 변경과 미커밋 S7 연결 작업은 보존합니다.

| 용도 | 개인 저장소 | 포털 컨테이너 | Wazuh agent |
| --- | --- | --- | --- |
| 프론트 원본 | `haedam-portal-frontend/src/` | 빌드 시 React/Vite 입력 | 원본 개발 폴더가 아닌 배포 결과 감시 |
| 실제 프론트 배포 파일 | Dockerfile의 프론트 빌드 | `/app/frontend` (RO) | `/var/www/haedam` FIM |
| 실제 백엔드 소스 | `haedam-portal-backend/src/` | `/app/src` (RO) | `/var/lib/haedam/backend` (RO) FIM |
| 실제 앱 JSON 이벤트 | backend `integration/events.py` | `/app/instance/events.jsonl` | `/var/log/haedam-portal/events.jsonl` (RO), JSON logcollector |

`compose.s7.yaml`의 `s7-web`, `s7-backend`, `portal-instance` 볼륨으로 같은 실제 파일을 공유합니다. 호스트의 프로젝트 폴더나 `.env`, Git 이력, DB 파일을 Wazuh에 마운트하지 않습니다. named volume은 첫 초기화 후 이미지 재빌드만으로 갱신되지 않으므로 코드 배포 변경은 새 개인 프로젝트에서 승인된 이미지를 확인한 뒤 진행합니다.

Wazuh 기본 FIM 550/553/554로 변경·삭제·추가를 확인합니다. 앱 로그는 `infra/wazuh/portal-rules.xml`의 100710 부모 규칙 아래, 실제 성공 파일 접근 100711과 인증 실패 100712만 경보로 만듭니다. 일상 health/web.request 전부를 경보로 승격하지 않습니다. 파일 내용 diff는 수집하지 않습니다.

백엔드 파일은 **감시 전용**입니다. 실행 중 Python 소스를 임의로 복구·재시작하지 않습니다. S7 자동 복구의 고정 대상은 프론트 `index.html`과 무해한 시험 파일 `assets/s7-probe.txt`이며, source 경로를 입력받아 임의로 조치하지 않습니다.

실행: [S7 Docker 설치](s7-lab.md). 이 문서의 경로 추가는 개인 S7 프로젝트에 적용되며, 현재 Chrome에서 보고 있는 기존 학원 Wazuh와 H1 포털에는 적용하지 않습니다.

## 재현과 확인 위치

설치 안내의 `init → up → ready`가 성공한 뒤 같은 PowerShell에서 실행합니다. 다른 프로젝트 이름을 선택했다면 모든 명령에 동일한 `S7_PROJECT` 환경변수를 유지합니다.

```powershell
py -3.12 tools/s7_paths_verify.py
py -3.12 tools/s7_verify.py
```

첫 명령은 해당 개인 프로젝트 소유의 backend 볼륨에만 무해한 주석을 추가해 FIM을 확인하고, `finally`에서 이미지의 원본 바이트로 복원합니다. 이어서 실제 HTTP 접속이 만든 `web.file_access`의 event_id를 Wazuh 색인과 대조합니다. 두 번째 명령은 프론트 파일 변경·추가와 API 복구·격리 및 정리를 확인합니다. 출력 JSON은 `.local/s7/`에 저장됩니다.

개인 Wazuh 대시보드 `https://127.0.0.1:15620`의 Security events에서 `agent.name: haedam-s7-agent`와 다음 항목으로 검색합니다.

| 확인 대상 | 검색 항목 |
| --- | --- |
| 프론트 변경 | `rule.id: 550` 및 `syscheck.path: /var/www/haedam/index.html` |
| 백엔드 변경 | `rule.id: 550` 및 `syscheck.path: /var/lib/haedam/backend/haedam_portal/__init__.py` |
| 실제 파일 접근 로그 | `rule.id: 100711` 및 `data.event_id` |

## 개인 실측 · 2026-11-09

새 볼륨 프로젝트 `haedam-s7-paths`에서 KST 14:26~14:27에 확인했습니다. [파일·로그 증적](evidence/portal-wazuh-paths-20261109.json)은 미커밋 작업 트리의 실행 결과이며 해당 설정 파일 해시를 포함합니다.

- 백엔드 무해한 주석 추가 → 실제 규칙 550 경보 `1794201978.4801` 검색. 포털과 agent 양쪽에서 소스 쓰기 거부를 확인했고 원본 SHA-256으로 복원했습니다.
- 실제 GET `/` → HTTP 200 → 앱 event_id `2d33a4e4-c5c3-4b30-9067-6955d768517b` → 규칙 100711 경보 `1794201989.7339`를 대조했습니다.
- 프론트 회귀 실행 `S7-20261109T052709Z` 통과. index.html 변조 550·추가 파일 554, API 복구/격리, 정상 자산 3개 유지, 기준 파일 4개 일치, 재시작 후 기준 유지, 격리 잔여 0을 확인했습니다. [회귀 결과 요약](evidence/portal-wazuh-frontend-20261109.json).
- 첫 로그 수집 시험은 실패했습니다. JSON의 `event_type`이 Wazuh 4.9 기본 규칙 86600에 먼저 매칭되어 독립된 JSON 부모 규칙으로는 기대 경보가 나오지 않았습니다. 86600의 하위에서 정확한 `source=haedam-portal`을 판별하도록 연결한 뒤 실제 접속 로그로 재검증했습니다. 고정 버전의 기본 규칙에 의존하므로 Wazuh 업그레이드 시 같은 실제 로그로 재검증합니다.

인증 실패 규칙 100712는 설정에 포함했으나 이번 실측은 파일 접근 100711 범위입니다. 감시 대상은 컨테이너가 실제 사용하는 배포 파일이며 Windows 개발 원본 폴더 전체가 아닙니다. Graylog·n8n 자동 판단과 티켓 생성은 아직 후속 연결 단계입니다.
