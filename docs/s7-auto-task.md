# S7 자동 연결 작업 · Wazuh 사전 검토 포함

기준 PR #8 `ccf37d1`(PR #6 의존), 별도 `codex/s7-auto-pipeline`. 김명준·Codex 담당. 사용자 요청에 따라 먼저 Wazuh 설정을 검토하고 자동화에 필요한 가드를 구현합니다. 원본 팀 저장소·Claude worktree는 수정하지 않습니다.

## 검토 결과와 조치

| 항목 | 기존 상태 | 이번 조치 / 검증 |
| --- | --- | --- |
| 감시 경로 | PR #8의 프론트·백엔드 FIM 및 앱 JSONL | 유지. 자동 조치는 고정 프론트 2개 경로만 허용 |
| Wazuh API | 개인 수동 시험은 관리자 사용 | 자동화에는 해당 agent의 read/AR만 허용한 별도 계정. 보안 계정 조회·다른 agent 조치 거부 확인 |
| 기준 파일 | agent의 RW named volume, 파일 chmod 444만 적용 | 자동화 agent에는 RO mount. 별도 초기화 컨테이너만 승인 이미지와 대조 후 기준 생성 |
| 복구 명령 | 웹 루트 경계는 검사하지만 현재 파일 해시와 경보의 일치 검사 없음 | 자동화 전용 AR wrapper에서 대상·기준 해시·현재 SHA-256·중복 job 검증. 기존 팀 함수 재사용 |
| 등록 TLS | 등록 암호는 있으나 manager 인증서 검증 없음 | 인증 CA로 manager 신원 검증 추가. API도 고정 인증서 사용 |
| 재경보/중복 | 수동 API 복구만 있어 재경보 억제 없음 | 기준 해시로 돌아온 경보·격리 후 삭제는 대응 후보 제외. 원본 Wazuh 이벤트의 지속 저장 키로 멱등 처리 |
| 전달/복구 기록 | 일회성 시험 도구 | manager alerts를 RO 수집, 지속 큐→Graylog HTTP GELF, n8n 티켓 선기록→제한된 API→실제 효과 확인→verified |
| 자원 | 6GiB Docker에서 Wazuh 약 2.5GiB | 기존 학원 스택 중지 후 전용 프로젝트. 자원 제한·상태 확인. 전역 메모리 변경 안 함 |

자동화 서비스는 Wazuh 관리 자격증명과 n8n 티켓 키를 동시에 갖지 않습니다. n8n은 실제 기록/순서를 담당하고, 좁은 Wazuh 연결 서비스는 경보 증거·agent 명령·파일/HTTP 효과만 확인합니다. 상태가 어긋나면 409/503으로 보류합니다.

## 인수 조건

- 실제 파일 변조/추가→실제 Wazuh 경보→Graylog event→n8n 실행→티켓→AR 복구/격리→HTTP·해시 검증을 같은 키로 연결.
- API 응답 성공을 효과 검증으로 대신하지 않음. 자동 티켓은 verified까지, 운영자 확인 후 시험 격리물 정리·작업 소유권 종료를 restored로 기록(복구된 정상 파일을 다시 변조하지 않음).
- 정상 자산 유지, 인증·대상/해시 불일치 거부, 중복·복구 재경보 무조치, 티켓 기록 장애 전 무조치/후 재시도, 최종 정리와 기존 환경 복원.
- 설치·계약/예시·가린 증적·PR 검토 카드 작성. 개인 FIM 즉시 대응 정책이며 팀의 접근 로그 200 상관분석과 구분.

공식 근거: [Wazuh API RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html), [manager 신원 검증 설정](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html). 4.9.0 실제 이미지의 API spec/구현도 대조합니다. RBAC는 agent 범위를 제한하며 명령/파일 인자는 별도 wrapper와 연결 서비스에서 제한합니다.
