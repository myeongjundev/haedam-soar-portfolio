# S7 제어판 실제 버튼 실측 · 2026-11-10

**통과:** 브라우저 버튼 → 실제 파일 입력 → Wazuh → Graylog → n8n → 자동 복구/격리 → 티켓 생성 → 운영자 원복 완료. 11/9 합성 브라우저 시험 및 기존 CLI 실측과 별도로 수행했습니다.

실행 소스 `af19e506204423aa7bd4234b495615e5f71840c7`, 두 회차 모두 clean. PR #11에 Claude PR #12를 로컬 통합한 `codex/submission-integration`입니다. 새 볼륨 프로젝트 `haedam-s7-panel-live`에서 README의 `init/up/ready/configure`를 완료했습니다. 원격 PR 병합은 하지 않았습니다.

## 결과

11/10 09:21 KST, Chrome 자동화가 실제 제어판의 버튼을 클릭했습니다. 합성 worker 또는 직접 대응 호출로 대신하지 않았습니다. 원복 요청만 제어판에서 운영자 n8n 경로를 사용했습니다.

| 항목 | 파일 변조 | 추가 파일 |
| --- | --- | --- |
| 대상 | `index.html` | `assets/s7-probe.txt` |
| 회차 | `f1150dea-8170-4ec9-a086-bff89e319da0` | `05acdc82-be28-4919-9f49-de2b5973e051` |
| Wazuh rule / alert | 550 / `1794270073.1200` | 554 / `1794270094.8076` |
| Graylog 이벤트 | `01M71D9B28BB77DTGY1ER0X6Z6` | `01M71D9YNVCZFR4GQAZY093ND3` |
| n8n 대응 / 완료 execution | 1 / 2 | 3 / 4 |
| 입력 준비 기록→자동 대응 효과 확인 | **8.211초** | **6.699초** |
| 입력 준비 기록→제어판 관측 기록 | 10.537초 | 7.370초 |
| 현재 효과 | 원래 해시 복구, 대상 HTTP 200 | 웹 루트 밖 격리, 대상 HTTP 404 |
| 정상 홈페이지 | HTTP 200 | HTTP 200 |
| 티켓 | `T-20261110-0001` restored | `T-20261110-0002` restored |

시간은 `input_at`(파일 변경 직전 기록)에서 gateway `effect_verified_at` 또는 제어판 `steps.response.at`까지입니다. 단일 회차 수치이며 성능 평균·보장 시간이 아닙니다. UI의 단계 시각은 관측 시각이고 원천 경보 시각과 다릅니다.

## 독립 대조와 종료 상태

- 제어판 내보내기의 입력 해시·경보 ID를 실제 Wazuh indexer 조회와 대조했습니다.
- gateway SQLite를 읽기 전용으로 조회해 event/response/completion 영수증과 n8n 실행 ID를 확인하고, 티켓 API의 실제 상태를 대조했습니다. 제어판 표시만으로 판정하지 않았습니다.
- 기준 파일 4개 전체 해시 일치, baseline manifest 유지, 격리물 0개. 티켓은 정확히 2개이고 모두 restored입니다.
- n8n execution payload 저장 행 0개. 컨테이너 12개 running·OOMKilled false, 에이전트 active·indexer green을 확인했습니다.
- UI 새로고침 후 두 회차 유지, JSON 다운로드, 390px 가로 넘침 없음, 브라우저 JavaScript 오류 없음.
- 개인 랩과 제어판 서버는 검증 후 정지했고 볼륨·증적은 보존했습니다. 09:24 KST 기존 실행 목록 7개와 복원 목록이 일치하며 Graylog/Wazuh HTTP 200·MySQL TCP 연결을 확인했습니다. n8n과 H1은 오늘 시작 목록에 없었습니다.

## 증적

- [파일 변조 회차 내보내기](evidence/panel-index-live-20261110.json), [추가 파일 회차 내보내기](evidence/panel-probe-live-20261110.json)
- [원천 경보·영수증·파일·컨테이너 독립 대조](evidence/panel-live-audit-20261110.json), [실제 브라우저 검증](evidence/panel-live-browser-20261110.json), [기존 환경 복원](evidence/panel-environment-restored-20261110.json)
- [파일 복구 확인 화면](evidence/panel-index-verified-20261110.png), [격리 후 원복 완료 화면](evidence/panel-probe-restored-20261110.png), [모바일 화면](evidence/panel-live-mobile-20261110.png)

## 수정과 검증 범위

Claude의 PR #9/#12에서 만든 볼륨/이미지 불일치 검사를 제어판 새 입력과 자동 랩 재설정에도 적용했습니다. 배포 주소·경로는 기존 설정에서 읽습니다. 사건의 파일 변조 자체로 관찰·원복이 차단되지 않도록 새 입력 검사와 구분했습니다.

호스트 테스트 **60 passed**, S8/H1/S7 워크플로 생성물 일치. 추가 테스트는 오래된 코드의 새 입력 차단, 기존 사건 관찰 유지, 재설정 전 거부를 확인합니다. 실제 버튼 실측은 정상 2회차이며, 제어판에서 manager/agent 중단·응답 직후 강제 종료·동시 변조는 이번에 재현하지 않았습니다. 이전 CLI 장애 시험이나 Claude 기록을 새 제어판 장애 실측으로 표시하지 않습니다.

팀 S7의 FIM+HTTP 접근 성공 상관 정책을 그대로 재현한 결과가 아니라 **개인 FIM 즉시 대응 정책**입니다. S8/H1의 버튼 연결과 pfSense/S10 실제 동작은 여전히 별도 작업입니다. 팀 복구 함수의 출처와 개인 추가 구현은 [S7 문서](s7-auto-lab.md), [출처](sources.md)에 구분합니다.

## 다음 담당 첫 행동

[검토 카드](panel-review.md)에서 통합 소스와 증적을 확인합니다. 재실측할 경우 새 `S7_PROJECT`와 같은 프로젝트를 가리키는 Git 제외 `PANEL_CONFIG_FILE`을 사용하고, 다른 Docker 실측과 순서를 맞춥니다. 제출 마감은 **11/11 17:30 KST**입니다. 남은 우선 항목은 Claude PR #13의 pfSense/S10 실측과 개인 PPT·설치 재현 자료입니다.
