# H1 민원 도배 · 개인 구현 작업

- 제안 출처: 반소람(whiteclover0542), 2026-11-09 공유 `MVP-설계.md` 7절. 개인 구현·검증: 김명준 / Codex. 원본 문서는 수정하지 않습니다.
- 기준: 검증된 S8 `a367e0d`. 브랜치 `codex/city-security-cases`. Claude는 별도 작업 폴더에서 PR 실패 재현과 원인 검토를 맡습니다. 독립 검토 완료를 가정하지 않습니다.
- 범위: 시민 계정의 민원 작성만 제한. 로그인·기존 민원 조회·같은 IP의 다른 시민 작성은 유지합니다. IP 차단이나 계정 잠금은 H1에 사용하지 않습니다.
- 변경: 포털 제한 테이블/마이그레이션/대응 API, 이벤트·티켓 계약과 소비자, H1 전용 Graylog 정의·n8n 워크플로·격리 Compose·검증기.
- 조치 소유자: 실제 티켓 ID. 동일 요청 재시도는 멱등, 다른 티켓의 해제는 거부, 해제된 소유자의 재제한은 거부합니다. 민원 작성과 제한은 같은 사용자 행을 잠가 직렬화합니다.
- 탐지: 같은 username의 성공한 petition.created 고유 event_id 수. 10분 창, 랩 임계값 5건. 합성 정상 기준선 2건/계정 및 임계 직전 4건을 검증합니다. 실제 시민 이용 통계나 운영 권장 임계값으로 주장하지 않습니다.
- 검증: 임계 전후, 다른 계정 혼재, 실제 HTTP→GELF→Graylog→n8n→티켓→작성 429, 로그인/조회 200·정상 작성 201, 승인 해제 후 작성 201. 인증 실패, 중복, 오래된 원복, 저장소 장애도 확인합니다.
- 기존 S8 파일·볼륨과 학원 환경을 보존합니다. H1은 별도 프로젝트/볼륨/포트/망을 씁니다. 종료 시 기존 실행 컨테이너를 복구합니다.

## 인프라 확인 · 2026-11-09

Docker Desktop 엔진 29.8.2, WSL 메모리 설정 6GB, docker-desktop의 `/dev/kvm` 없음. 기존 VMware Haedam-pfSense가 실행 중이며 변경하지 않았습니다. 팀원 문서의 KVM 가능·12GB 설정을 이 PC의 결과로 옮기지 않습니다. 개인 pfSense 신규 설치·경로 실측과 Wazuh/S7 연결은 별도 미완료 작업입니다.

pfSense의 VMware 테스트 VM 경로는 [Netgate 가상화 안내](https://docs.netgate.com/pfsense/en/latest/virtualization/index.html)를 참고합니다. 공식 설치 미디어의 계정·해시 확인 절차는 [설치 이미지 안내](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html)에 있습니다. Docker 안 KVM이 없다는 결과가 VMware 실행 불가를 뜻하지 않습니다.
