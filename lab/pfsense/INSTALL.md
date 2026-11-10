# PF readback 보강 후보 패키지

로컬 검증·검토용. 실제 설치본은 자동 교체하지 않는다.
현재 장비 SHA256: 86c2a30fc630f4333d471ca62ae4b659a6a4acf8d7d71546d9b1f9a04759420d.
새 후보 해시는 빌더/설치기 고정값과 생성된 bundle.json에서 확인한다.

## 로컬 준비

```powershell
python tools/build_pfsense_bundle.py --out .local/pf-readback-candidate
python .local/pf-readback-candidate/install_bundle.py --verify
```

상위 폴더는 미리 만들고 새 출력 폴더만 사용한다. 네트워크 호출 없이 도구·스키마·
설치기·안내4파일의 해시와 문법을 확인한다. SHA고정은 후보 식별이며 리뷰/인수 통과가 아니다.

## 교체 전 대조

1. D 호출 중지·claim/pending/활성조치0와 포털 정상 상태 확인.
2. D PR128 cwd수정·forced command·호스트지문·전용키 유지, 추가필드/SSH timeout 대조.
3. 기존 도구/journal은 PF 내부 제한권한으로 백업. 실패 receipts 유지.
4. Python3.11 문법·해시 대조 후 별도 검토된 교체 절차로 한 파일만 반영.
   root:wheel0750, SSH/키/방화벽/서비스 설정 유지.
5. 설치본 해시·D status 확인 후 새 owner/요청 ID로 별도 PF 인수 GO.

기본 설치기/--verify는 파일 검사만 한다. --install은 최초 생성/같은 해시만 허용하고
**기존 다른 버전은 거부**한다. 강제 설치하거나 journal 삭제로 재시도를 허용하지 않는다.
파일 교체·삭제는 방화벽 복구가 아니다. 배포 실패 시 현재 상태와 원본/후보 해시를 대조한다.

## 재인수

새 owner로 status → block → 실제 차단/정상 영향 → 같은 owner·새ID unblock →
양쪽복귀·claim/pending/이번규칙0을 확인한다. C저장 여부는 D GO에서 결정한다.
status도 journal lock을 잠깐 만들 수 있다. failed/changed:null이면 추가 mutation없이
실제 상태를 대조한다. 구 journal에 규칙 소유 근거가 없으면 자동 정리를 거부한다.
수동 복구와 자동 인수 성공을 구분한다. 과거 실패 회차는 그대로 보존한다.
