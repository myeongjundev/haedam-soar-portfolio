# 사용하는 계약의 출처

원본: NoBugs-Aleph/aleph-soar-capstone, capstone `d134c71a6a9ae941c149c969ca42884348197eba`. 사용하는 계약 사본 8개를 이 단일 커밋에 맞췄으며 파일별 SHA-256은 [SOURCE.json](../docs/SOURCE.json)에 기록했다.

- [포털 API v1.0](../docs/haedam/PORTAL-API.md) ← 원본 docs/haedam/PORTAL-API.md
- [포털 이벤트 v1.0](portal-event.schema.json) ← 원본 contracts/portal-event.schema.json
- [오류 응답 v1.0](portal-error.schema.json) ← 원본 contracts/portal-error.schema.json
- [필드 오류 예시](portal-examples/validation-error.json) ← 원본 contracts/portal-examples/validation-error.json
- [합성 예시](portal-examples/flow.json) ← 원본 contracts/portal-examples/flow.json
- 공통 규칙 v3의 원본 커밋·SHA-256·초기 스켈레톤 이력: [SOURCE.json](../docs/SOURCE.json). SHA는 UTF-8 LF로 비교한다.

로그인·가입·로그아웃·현재 사용자·비밀번호 변경, 민원 목록/작성/조회/배정/처리, 관리자 계정, 설정·헬스, 제한된 계정 대응 API를 구현/소비한다. 기존 관제 event/incident v1.0과 자동 호환되지 않으며 D가 별도 매핑한다. 복사본을 별도 계약 원본으로 발전시키지 않는다. 스키마 검증과 실제 외부 탐지·차단·원복의 성공은 구분한다.

- [관리자 전체 계정 조회](../docs/haedam/ADMIN-USERS-API.md), [응답 스키마](portal-admin-users.schema.json), [합성 예시](portal-examples/admin-users-filtered.json). WQ04 부가 필터/검색 전체 집계. 기존 포털 이벤트/앱 차단 계약 사본도 같은 원본으로 동기화했다.
