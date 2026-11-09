# S7 개인 Docker · FIM과 API 복구 실측

2026-11-09 김명준·Codex가 개인 새 볼륨에서 수행했습니다. **Wazuh 탐지·색인·API 복구 단계 통과**이며 Graylog/n8n 자동 대응·티켓 생성은 미연결입니다. 팀 결과나 Claude 독립 재검증 결과로 표시하지 않습니다.

- 기준 코드: `2820c854a5c814b2b8a2647cb9526f9dba1725e2`, 실행 시작 시 작업 트리 clean. 이후 결과 문서만 추가했습니다.
- 실행 ID: `S7-20261109T033732Z`, 개인 프로젝트 `haedam-s7-verify`, agent `001` / `haedam-s7-agent`.
- Wazuh manager/indexer/dashboard·agent 4.9.0, 새 MySQL·실제 React/Flask 포털. Windows Docker Desktop 29.8.2, WSL Docker 메모리 약 6GiB. 기존 8개 관제 컨테이너를 잠시 중지하고 실행했습니다.
- [가린 JSON 증적](evidence/s7-live-20261109.json), [기동 상태](evidence/s7-runtime-20261109.json). 비밀번호·토큰·파일 본문은 포함하지 않습니다. 파일 SHA-256으로 실측 소스와 대조할 수 있으며 Git LF/Windows CRLF 차이는 구분합니다.

## 실제 결과

| 입력 / 실제 효과 | 경보 | 입력 직전→색인 검색 확인 | API 요청 직전→효과 확인 | 복구 결과 |
| --- | --- | --- | --- | --- |
| index.html에 무해한 HTML 주석 추가, HTTP 응답에 표식 노출 | 550 / modified, before·after SHA-256 대조 | 7.028초 | 0.597초 | 원래 SHA-256과 HTTP 200 본문 일치 |
| assets/s7-probe.txt 생성, HTTP 200 | 554 / added | 6.268초 | 0.581초 | 웹 루트 밖 격리, HTTP 404, 시험 격리물 정리 |

색인 확인은 3초 주기의 클라이언트 폴링과 검증 작업을 포함합니다. 경보 자체 시각은 각각 입력 직전 기록에서 0.165초·0.161초 후였지만, 이 값은 같은 PC 한 회차의 관측입니다. 일반 처리량·평균 MTTD·n8n 대응 시간으로 해석하지 않습니다. API 200은 전달 확인일 뿐이며, 실행 ID가 같은 복구 로그·해시·HTTP 결과를 추가 확인했습니다.

추가 확인:

- 인증 없는 Wazuh API 요청 401.
- 포털 컨테이너에서 웹 파일 쓰기 거부(읽기 전용 볼륨).
- 변조 상태를 새 기준으로 채택하는 `baseline` 요청 거부.
- 웹 루트 밖 `/tmp/s7-sentinel`의 복구 요청은 agent에서 `path_outside_web_root`로 거부. API의 명령 전달 응답과 실제 조치 실패를 구분했습니다.
- 정상 파일 3개 유지, 웹 파일 총 4개 모두 원본 이미지 해시 일치.
- agent 재시작 뒤 기준 manifest 동일, HTTP 본문 동일, 격리 폴더 잔여 0.
- 전체 개인 스택 stop→up→ready→baseline 재검증 통과(12:39 KST). 같은 기준 파일 4개, changed/missing/extra 모두 0.
- 종료 시 개인 S7 컨테이너를 중지하고 기존 학원 8개를 복원했습니다(12:42 KST). Graylog·n8n·Wazuh 대시보드 HTTP 200, MySQL TCP 연결을 확인했습니다. 기존 보안 시나리오 전체를 다시 실행한 것은 아닙니다.
- dashboard 인증 `/api/status` HTTP 200·overall green, indexer green. 화면 렌더링 캡처를 뜻하지 않습니다.
- 호스트 안전 경계·기존 계약/워크플로 테스트 14 passed. Claude PR #5는 별도 worktree에서 11 passed와 정적 검토를 완료했으며 그 PR의 장애 실측은 Claude 보고와 구분했습니다.

## 발견한 문제와 수정

1. 인증서 폴더 전체를 마운트하면 생성 도구가 설정한 디렉터리 권한 때문에 non-root indexer가 읽지 못했습니다. 서비스별 필요한 인증서 파일만 마운트했습니다.
2. Docker 내부 전용망만 연결한 서비스의 published port가 이 엔진에서 열리지 않았습니다. DB·agent 내부망과 UI/API의 loopback 접속용 access 망을 분리했습니다.
3. indexer 512MB 힙의 direct memory 상한 때문에 security plugin 초기화가 실패했습니다. 공식 단일 노드 구성의 1GB 힙과 컨테이너 2GB 제한을 적용했습니다.
4. Windows subprocess stdin의 CRLF가 bcrypt 입력에 섞였습니다. 컨테이너에서 줄 끝 CR을 제거한 뒤 해시를 생성했습니다. 실패한 초기 랩은 보존하고, 수정 이후 새 볼륨의 계정 초기화를 검증했습니다.
5. Wazuh 4.9 CA의 KeyUsage 누락과 Python 3.13 strict 검증 차이를 확인했습니다. 로컬 CA 체인 검증은 유지하고 이 loopback 클라이언트의 추가 strict 플래그만 해제했습니다. 운영 인증서 대체가 필요한 호환 설정입니다.
6. dashboard 이미지가 특정 기본 host ID가 없을 때 `hosts`를 중복 추가했습니다. 공식 ID `1513629884013`으로 생성해 새 대시보드 첫 기동을 확인했습니다.
7. 최초 agent 설정 동기화의 짧은 재시작을 즉시 실패로 처리하던 실행기를 연결 대기로 변경했습니다. Windows 새 clone에서도 AR shebang이 유효하도록 해당 파일의 LF를 고정했습니다.

앞선 두 개발 회차도 복구에 성공했지만 설정/검증기가 달랐으므로 성능 평균으로 묶지 않았습니다. 최종 수치는 위 고정 커밋과 실행 ID만 사용합니다. `lab/s7/restore/` 원본 코드는 바꾸지 않았습니다.

## 남은 검증

Graylog 경보 전달, n8n의 제한된 agent/path 대상 검증·최소 권한 API 계정, 중복/복구 재경보 방지, 티켓 기록과 부분 실패 원복, 실제 공격 접근 로그와의 상관분석이 남았습니다. 삭제·symlink·기준 손상·manager/agent 장애와 다른 OS의 새 설치는 독립 리뷰에서 추가 확인합니다. 다섯 구성 전체 동시 실행·pfSense/S10·개인 PPT 완성을 이번 결과로 대신하지 않습니다.
