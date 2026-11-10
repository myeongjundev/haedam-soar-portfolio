import {readFileSync} from 'node:fs';
import {addNetworkSlides} from './network-slides.mjs';
import {addReviewSlides} from './add-review-slides.mjs';
// Run buildPortfolio(presentation, {root}) inside an Artifact Session callback.
// Source facts are pinned to 2026-11-10. S10 figures come from Claude's live run S10-20261110T021934Z (PR #13, docs/s10-results-20261110.md).
export function buildPortfolio(p, {root, inventory}) {
  const C={bg:'#F5F7F3',ink:'#14312E',teal:'#167366',muted:'#536B65',pale:'#E5EEE7',white:'#FFFFFF',amber:'#916019'};
  const F='Malgun Gothic'; p.theme.defaultFont=F;
  const repo='https://github.com/myeongjundev/haedam-soar-portfolio';
  const source=(file)=>`${repo}/blob/06fb3a43d2d9a90e961949c3ffcb7b931dd2af83/${file}`;
  const s10source=(file)=>`${repo}/blob/38593a73345e4a4b336ab14e47c13a55f545f272/${file}`; // PR #13 head
  let n=0;
  function txt(s,text,x,y,w,h,size=28,color=C.ink,bold=false,name,hyperlink){
    const t=s.shapes.add({geometry:'textbox',hyperlink,name:name||`text-${s.shapes.items.length}`,position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
    t.text=text;t.text.style={fontFamily:F,fontSize:size,color,bold};t.text.insets=0;return t;
  }
  function slide(title,subtitle,notes=''){
    const s=p.slides.add();s.setViewportSize(1280,720);s.background.fill=C.bg;n++;
    txt(s,title,64,48,1152,70,44,C.ink,true,'title');
    if(subtitle)txt(s,subtitle,66,130,1148,56,24,C.muted);
    txt(s,`김명준  /  해담시청 SOAR`,66,671,960,24,16,C.muted);
    txt(s,String(n).padStart(2,'0'),1150,671,64,24,16,C.muted);
    s.speakerNotes.text=notes;return s;
  }
  function table(s,values,y=220,widths=[250,430,472],rowH=74){
    const t=s.tables.add({rows:values.length,columns:values[0].length,left:64,top:y,width:1152,height:values.length*rowH,columnWidths:widths,values});
    t.cells.block({row:0,column:0,rowCount:values.length,columnCount:values[0].length}).assign({fill:C.white,textStyle:{fontFamily:F,typeface:F,fontSize:25,color:C.ink},margins:{left:16,right:16,top:14,bottom:12}});
    t.cells.block({row:0,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.ink,textStyle:{fontFamily:F,typeface:F,fontSize:25,bold:true,color:C.white}});
    for(let r=1;r<values.length;r++)if(r%2===0)t.cells.block({row:r,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.pale});
    return t;
  }
  function metric(s,value,label,x,y,w=510){txt(s,value,x,y,w,96,66,C.teal,true);txt(s,label,x,y+102,w,70,26,C.ink);}
  function node(s,label,x,y,w,h=90,color=C.pale){
    const v=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill:color,line:{fill:C.teal,width:1.5}});
    v.text=label;v.text.style={fontFamily:F,fontSize:25,color:C.ink,bold:true,alignment:'center',verticalAlignment:'middle'};v.text.insets=12;return v;
  }
  function connect(s,a,b,from='right',to='left',dashed=false){s.shapes.connect(a,b,{kind:'elbow',fromSide:from,toSide:to,line:{fill:C.teal,width:2,style:dashed?'dashed':'solid'},tail:{type:'arrow',width:'med',length:'med'}});}
  function image(s,file,x,y,w,h){s.images.add({blob:new Uint8Array(readFileSync(`${root}/docs/evidence/${file}`)),contentType:'image/png',alt:'개인 랩에서 촬영한 실제 실행 증적',position:{left:x,top:y,width:w,height:h},fit:'contain'});}

  let s=slide('해담시청 보안 자동화','',`김명준 개인 포트폴리오. 팀 NoBugs의 공공기관 민원포털 프로젝트를 개인 Docker 랩으로 전환했습니다. 확인 기준은 2026-11-10입니다.\n출처: ${source('docs/sources.md')}\n개인 저장소: ${repo}`);
  s.background.fill=C.ink;
  s.shapes.getItem('title').text.style={fontFamily:F,fontSize:58,bold:true,color:C.white};
  s.shapes.getItem('title').position={left:72,top:170,width:1136,height:100};
  txt(s,'개인 환경에서 확인한 탐지와 자동 대응',74,292,1110,70,34,'#D9E8DA');
  txt(s,'김명준',74,446,1050,60,36,C.white,true);
  txt(s,'React · Flask 포털 구현과 보안 시나리오 검증',74,514,1090,52,26,'#D9E8DA');
  // Cover has one clear title composition, without a separate page footer.
  s.shapes.items.filter(x=>x.position.top===671).forEach(x=>x.text.style={fontFamily:F,fontSize:16,color:'#D9E8DA'});

  s=slide('본인 역할과 팀 기여','팀 공통 구현을 출처와 함께 반입하고 개인 재현 범위를 추가했습니다.',`팀원: 김명준, 반소람, 김상혁, 김대훈. 표의 팀 담당과 개인 후속 구현을 구분해 설명합니다. AI를 활용해 구현하고 검증했으며 팀원의 코드를 개인 단독 구현으로 주장하지 않습니다.\n출처: ${source('README.md')}\n${source('docs/sources.md')}`);
  table(s,[['범위','담당','구현·검증 내용'],['팀에서 본인 담당','김명준','React·Flask 포털, S8/S10 입력·검증'],['팀 공통 기반','반소람 / 김상혁 / 김대훈','S1·S4 / Wazuh·티켓 / Graylog·n8n'],['개인 전환','김명준 + AI 도구','Docker 재현, S7 자동 연결, H1, 제어판']],218,[220,335,597],90);

  s=slide('공공기관 민원포털의 보안 과제','가상 해담시청의 시민 서비스와 내부 업무를 보호하는 교육용 랩',`공공기관 도메인과 해담시청은 팀 합의입니다. 실제 기관이나 운영 시스템이 아닙니다. CIA 항목은 프로젝트의 보안 목표이며 전체 운영 보안을 입증한 것은 아닙니다.\n출처: ${source('README.md')}\n${source('docs/portfolio-plan.md')}`);
  txt(s,'기밀성',66,228,300,56,36,C.teal,true);txt(s,'세션과 역할에 따른\n민원 접근 통제',66,308,325,124,28);
  txt(s,'무결성',456,228,300,56,36,C.teal,true);txt(s,'배포 파일 변조 감지와\n기준 파일 복구',456,308,325,124,28);
  txt(s,'가용성',846,228,300,56,36,C.teal,true);txt(s,'공격 주체를 제한하고\n정상 시민의 이용 유지',846,308,350,124,28);
  txt(s,'팀 사례  S1 · S4 · S7 · S8 · S10 · S12\n개인 추가 사례  H1 민원 작성 도배',66,520,1148,94,27,C.muted);

  s=slide('개인 랩 시스템 구성','사례별 개인 프로젝트에서 실측한 연결입니다. pfSense/S10은 별도 랩이라 점선으로 구분합니다.',`개념 구성도입니다. S7은 12개 컨테이너로 실행했고, S8/H1은 별도 개인 프로젝트에서 검증했습니다. 모든 시나리오를 동시에 실행한 단일 스택을 뜻하지 않습니다. 약 6GiB Docker 메모리에서 기존 스택과 순차 실행했습니다. pfSense/S10은 별도 haedam-pf-lab에서 11/10 실측했습니다(S10-20261110T021934Z).\n출처: ${source('docs/s7-auto-lab.md')}\n${source('docs/s8-lab.md')}\n${source('docs/h1-results.md')}`);
  const portal=node(s,'React / Flask\n포털·앱 로그',64,230,240,100),db=node(s,'MySQL',64,395,240,70);
  const wazuh=node(s,'Wazuh\n파일 변경 감지',375,230,230,100),gray=node(s,'Graylog\n수집·탐지',685,230,230,100),n8n=node(s,'n8n\n대응·원복',995,230,220,100);
  const target=node(s,'포털 차단 / 작성 제한\n파일 복구 / 격리',375,430,390,100),ticket=node(s,'티켓 저장소\n사건·조치 이력',865,430,350,100);
  connect(s,portal,db,'bottom','top');connect(s,portal,wazuh);connect(s,wazuh,gray);connect(s,gray,n8n);connect(s,n8n,ticket,'bottom','top');connect(s,n8n,target,'bottom','top');
  txt(s,'S8·H1 앱 로그도 Graylog로 수집',64,184,1150,38,22,C.muted);
  const pf=node(s,'pfSense VM / S10  11/10 실측 통과',64,574,550,56,'#F3EADC');connect(s,target,pf,'bottom','right',true);
  txt(s,'프로젝트별 볼륨 보존 · 메모리 제약에 따라 순차 실행',665,580,550,65,22,C.muted);

  s=slide('개인 실측 범위','팀 실행 기록과 개인 환경에서 다시 확인한 결과를 분리했습니다.',`S7은 팀의 FIM+HTTP 접근 성공 상관 정책과 구분되는 개인 FIM 즉시 대응입니다. S1/S4/S12는 이 포트폴리오의 개인 실측이 아직 없습니다. S10은 11/10 Claude 실측 S10-20261110T021934Z입니다.\n출처: ${source('docs/portfolio-plan.md')}\n${source('docs/panel-results-20261110.md')}`);
  table(s,[['사례','개인 실측 판정','확인한 효과'],['S8 웹 탐색·인증 실패','11/9 통과','공격 IP 403, 정상 200, 해제 200'],['S7 파일 무결성','11/10 버튼 실측 통과','기준 해시 복구, 추가 파일 격리·정리'],['H1 민원 도배','11/9 통과','작성만 429, 정상 시민 작성 201'],['S10 경계·포털 차단','11/10 통과','공격 차단·정상 200, 원복 후 양쪽 200'],['S1 반복 로그인 실패','11/10 통과','공격 IP 403, 정상 로그인 유지, 해제 200'],['S4·S12','개인 미실측','팀 결과를 개인 통과로 대체하지 않음']],205,[300,330,522],60);

  s=slide('S8  공격 출발지 IP 차단','실제 HTTP 요청의 웹 탐색과 로그인 실패를 같은 출발지로 결합했습니다.',`실행 S8-20261109T013617Z. 조건 충족부터 Graylog 판정 3.828초, 판정부터 차단 API 응답 0.693초. 4.521초는 최초 HTTP403 관측 시각이 아닙니다. 별도 클라이언트 요청으로 실제 효과를 확인했습니다. 한 회차의 관측이며 평균/보장 시간이 아닙니다. 개인 S8은 포털 애플리케이션 차단입니다. pfSense 패킷 드롭은 포함하지 않습니다.\n출처: ${source('docs/s8-results.md')}\n${source('docs/evidence/s8-live-20261109.json')}`);
  metric(s,'4.521초','조건 충족부터 차단 API 응답까지',66,205,1100);
  table(s,[['검증 시점','시험 클라이언트','정상 클라이언트'],['차단 후','403 IP_BLOCKED','200 정상 접근'],['승인 원복 후','200 정상 접근','200 정상 접근']],402,[340,406,406],69);
  txt(s,'티켓 1건 restored · 활성 차단과 소유권 0',66,625,1120,36,24,C.muted);

  s=slide('S7  자동 파일 복구와 격리','개인 FIM 즉시 대응 정책으로 Wazuh·Graylog·n8n 연결을 확인했습니다.',`11/10 09:21 KST, 실행 소스 af19e50 clean, 새 프로젝트 haedam-s7-panel-live. input_at은 파일 변경 직전 기록이고 효과 시각은 gateway effect_verified_at입니다. 제어판 관측까지는 10.537초/7.370초입니다. 두 수치는 단일 회차이며 성능 평균이 아닙니다. 티켓 T-20261110-0001/0002 모두 restored.\n출처: ${source('docs/panel-results-20261110.md')}\n${source('docs/evidence/panel-live-audit-20261110.json')}`);
  txt(s,'입력 직전 기록부터 실제 효과 확인까지의 개인 1회 실측',66,636,1148,28,21,C.muted);
  metric(s,'8.211초','index.html 변조 후 복구',66,208);metric(s,'6.699초','추가 시험 파일 격리',680,208);
  table(s,[['대조 항목','복구','격리 후 원복 완료'],['파일 / HTTP','기준 해시 일치 / 200','시험 URL 404 / 정상 홈 200'],['잔여 상태','기준 파일 4개 일치','격리물 0개, 티켓 restored']],410,[260,410,482],70);

  s=slide('H1  민원 작성 권한만 일시 제한','반소람의 민원 도배 대응 제안을 개인 환경에서 구현·검증했습니다.',`아이디어 출처: 반소람의 11/9 공유 MVP 문서. 개인 구현: 김명준·Codex. 합성 랩 임계값은 계정별 성공 작성 5건/10분입니다. 최종 실행 H1-20261109T021122Z. 조건부터 탐지14.087초, 제한 API 응답까지14.532초이며 최초429 관측 시각이 아닙니다. 운영 정상 사용량/오탐률은 검증하지 않았습니다.\n출처: ${source('docs/h1-results.md')}\n${source('docs/sources.md')}`);
  txt(s,'14.532초',66,205,1100,88,64,C.teal,true);txt(s,'조건 충족부터 작성 제한 API 응답까지',66,300,1120,45,27);
  table(s,[['관찰 대상','제한 중','원복 후'],['시험 계정의 작성','429 제한','201 작성 성공'],['같은 계정의 조회','200 유지','200 유지'],['다른 정상 시민의 작성','201 유지','201 유지']],380,[460,346,346],64);

  s=slide('S10  경계 차단과 포털 차단, 원복','pfSense 경계 로그·웹 탐색·로그인 실패를 결합해 두 단계로 차단했습니다.',`실행 S10-20261110T021934Z(코드 70c0ea6 clean). 입력 02:19:37.686Z, Graylog 이벤트는 15.0초 뒤, 포털 차단 applied 다음 pfSense 차단 applied는 입력에서 26.2초. 원복 요청 02:20:32.916Z부터 티켓 restored 02:20:47.462Z까지 14.5초. 한 회차 관측이며 평균/보장 시간이 아닙니다. 차단 중 공격 요청은 5초 시간 초과, 정상 200, 원복 뒤 양쪽 200·잔여 조치 0. 중복 재전송 2회 duplicate_no_action, 오래된 티켓 원복 503, 재원복 nothing_to_release. 첫 회차 S10-20261110T020326Z에서는 원복이 pfSense만 해제하고 500으로 멈춘 결함을 재현했고, 해제를 재조회로 판정하도록 고친 뒤(d37287c) 같은 티켓 재시도로 restored를 확인했습니다. 장애 시험 S10FAULT-20261110T020814Z는 Graylog를 거치지 않은 인증 웹훅 직접 입력입니다. 티켓 effect_verified·condition_met_at·verified_at은 비어 있고 화면 MTTD/MTTR은 미측정입니다. 실제 효과는 검증기의 클라이언트 요청으로 확인했습니다. pfSense CE 2.7.2는 Docker 안 QEMU VM(KVM 없음)이며 VM 방식은 11/9 사용자 결정, 강사님 확인 기록은 없습니다. 외부 Discord 알림은 보내지 않았습니다.\n출처: ${s10source('docs/s10-results-20261110.md')}\n${s10source('docs/evidence/s10-live-20261110.json')}\nPR13: ${repo}/pull/13`);
  // Same frame as the S7 slide; r4 was made by duplicating that slide.
  txt(s,'원복 요청→티켓 restored 14.5초 · 잔여 조치 0 · 저장소·relay 장애 시험 별도 통과',66,636,1148,28,21,C.muted);
  metric(s,'15.0초','입력부터 Graylog 상관 탐지까지',66,208);metric(s,'26.2초','입력부터 포털·pfSense 차단 완료까지',680,208);
  table(s,[['대조 항목','시험 클라이언트','정상 클라이언트'],['차단 중','시간 초과(경계 차단)','200 정상 접근'],['원복 후','200 정상 접근','200 정상 접근']],410,[260,410,482],70);

  s=slide('S1  반복 로그인 실패 탐지와 IP 차단','같은 계정·출발지의 실제 로그인 실패 9회를 탐지해 공격 출발지만 차단했습니다.',`Codex 실측 s1fix20261110(코드 e06ed60, PR #25). 9번째 실제 401 로그 15:28:02.012 KST → Graylog 처리 39.216초 → 포털 차단 API 완료 40.299초. 1분 주기 Graylog 평가를 포함한 한 회차 값이며 평균·보장 시간이 아닙니다. 공격 출발지 health 200→403 IP_BLOCKED→200, 정상 출발지 health 200·새 로그인 200 유지. 이벤트 01M7229ZMCN5QNEBME9QJNJ1AA, 티켓 T-20261110-0001 restored·활성 조치 0, 원복 후 DB 활성 IP 차단 0. 8회 경계(31분 무경보)는 반환 노드 수정 전 같은 정책의 별도 회차 s1live20261110입니다. 최종 9회는 기존 개인 S1 스택에 수정본 워크플로를 다시 게시한 재실측이며 새 볼륨 전체 재설치가 아닙니다. 첫 회차에서 하위 흐름 반환 누락으로 티켓 없이 빈 HTTP 200이 나온 실패는 결과 문서에 보존했습니다. 포털 애플리케이션 IP 차단이며 pfSense 차단은 포함하지 않습니다.\n출처: https://github.com/myeongjundev/haedam-soar-portfolio/blob/6bc8ee168434aed7a01facf060c404e6dd86bb64/docs/s1-results.md\nhttps://github.com/myeongjundev/haedam-soar-portfolio/blob/6bc8ee168434aed7a01facf060c404e6dd86bb64/docs/evidence/s1-live-20261110.json\nPR25: https://github.com/myeongjundev/haedam-soar-portfolio/pull/25`);
  txt(s,'원복 후 티켓 restored·활성 조치 0 · 8회+31분 무경보는 수정 전 별도 회차',66,636,1148,28,21,C.muted);
  metric(s,'39.2초','9번째 실패부터 Graylog 탐지까지',66,208);metric(s,'40.3초','9번째 실패부터 포털 차단 완료까지',680,208);
  table(s,[['대조 항목', '시험 클라이언트', '정상 클라이언트'], ['차단 중', '403 IP_BLOCKED', '200 · 새 로그인 유지'], ['원복 후', '200 정상 접근', '200 정상 접근']],410,[260,410,482],70);

  s=slide('본인 구현  포털과 대응 API','React 화면과 Flask 백엔드를 보안 이벤트·대응 경로에 연결했습니다.',`팀 단계에서 김명준이 주도한 포털 구현을 개인 레포에 기준 커밋으로 반입했습니다. 프론트994fc45, 백엔드98e549c. H1은 개인 후속 구현이며 팀 티켓 저장소는 김상혁의 구현을 확장했습니다.\n출처: ${source('docs/sources.md')}\n${source('docs/h1-results.md')}`);
  txt(s,'시민·담당자·관리자 화면',66,225,510,65,34,C.teal,true);
  txt(s,'React 민원포털\n로그인과 역할별 화면\n민원 등록·조회 흐름',66,318,510,200,30);
  txt(s,'백엔드와 보안 연결',680,225,535,65,34,C.teal,true);
  txt(s,'Flask 세션·권한 검사\nMySQL 마이그레이션\n앱 이벤트와 IP 대응 API\n개인 H1 계정 작성 제한',680,318,535,240,30);
  txt(s,'팀 원본 커밋과 개인 후속 변경을 출처 문서·PR로 추적',66,600,1130,48,26,C.muted);

  s=slide('개인 실습 제어판','시험 입력과 실제 탐지 확인, 원복 완료를 회차별로 기록합니다.',`실제 11/10 추가 파일 격리 후 티켓 원복 완료 캡처입니다. 반소람의 제어판 소개는 흐름 참고이며 HTML/코드를 반입하지 않았습니다. S7만 버튼 연결했고 S8/H1/S10은 버튼 미연결입니다. S10은 CLI로 실측했으며 제어판에서는 실행 잠금입니다. 새 입력 전에 프로젝트/worktree/포트/설정/기준 파일/티켓을 확인합니다.\n출처: ${source('docs/panel-lab.md')}\n${source('docs/evidence/panel-probe-restored-20261110.png')}`);
  txt(s,'입력 전 범위 검사',66,226,580,58,34,C.teal,true);txt(s,'허용한 개인 랩과 파일만 사용\n오래된 실행 볼륨은 새 입력 거부',66,305,570,100,29);
  txt(s,'같은 회차의 근거 보존',66,440,580,58,34,C.teal,true);txt(s,'경보·티켓·파일 효과를 대조\n소유 티켓의 원복 결과를 JSON 저장',66,519,570,105,29);
  image(s,'panel-probe-restored-20261110.png',720,192,495,450);

  s=slide('실측 중 발견한 문제','효과 확인과 원복이 실패한 회차도 문제 해결 기록으로 남겼습니다.',`세 문제는 실제 문서에 기록된 관측입니다. 자원 문제를 OOM으로 단정하지 않습니다. n8n payload0은 조회한 실행 테이블에 한정되며 디스크 보안 삭제를 의미하지 않습니다. stale volume 해결은 Claude PR9/12와 Codex PR14 통합입니다.\n출처: ${source('docs/s8-results.md')}\n${source('docs/s7-auto-results.md')}\n${source('docs/panel-results-20261110.md')}`);
  table(s,[['문제','관찰','영향'],['응답 확인 주소 불일치','차단 후 상태 조회가 403','조치 성공과 효과 검증이 불일치'],['n8n 실행 자료 잔류','저장 해제 후에도 payload 존재','응답에 쓰인 비밀값 보존 위험'],['이전 코드가 볼륨에 유지','재빌드 후 이미지와 실행 파일 불일치','새 코드를 검증했다고 오판 가능']],218,[310,410,432],94);

  s=slide('해결과 기술적 회고','새 환경 재실측과 현재 상태 대조를 완료 조건에 포함했습니다.',`해결책은 구현 및 검증 기록에서 추출했습니다. 60 tests는 통합 레포 호스트 테스트이며 전체 운영 안정성을 보증하지 않습니다.\n출처: ${source('docs/s8-results.md')}\n${source('docs/panel-results-20261110.md')}`);
  txt(s,'응답 확인 경로 통일',66,220,490,58,33,C.teal,true);txt(s,'차단과 조회를 같은 대응망으로 연결\n공격 403·정상 200·원복 200 재검증',595,220,620,96,27);
  txt(s,'실행 자료 저장 제한',66,350,490,58,33,C.teal,true);txt(s,'저장 설정과 삭제 경로를 함께 수정\n새 볼륨 실행 후 payload 0행 확인',595,350,620,96,27);
  txt(s,'이미지와 실행 파일 대조',66,480,490,58,33,C.teal,true);txt(s,'불일치 시 새 시험을 보류\n진행 중 사건의 관찰·원복은 유지',595,480,620,96,27);
  txt(s,'배운 점: API 성공 응답 뒤에도 실제 효과와 복구 상태를 따로 확인해야 합니다.',66,613,1150,44,25,C.muted);

  s=slide('개선 방향과 남은 검증','현재 완료 범위를 유지하면서 운영에 필요한 검증을 확장합니다.',`S10은 11/10 실측했습니다(S10-20261110T021934Z, docs/s10-results-20261110.md). 남은 S10 검증은 Graylog 알림 재시도, n8n 실행 중 중단, 방화벽 도구 응답 유실, 반복 측정, pfSense ISO 공식 체크섬 대조입니다.\n출처: ${source('docs/submission-integration.md')}\n${source('docs/portfolio-plan.md')}\nPR13: ${repo}/pull/13`);
  txt(s,'제출 전 우선 확인',66,224,510,60,34,C.teal,true);txt(s,'전체 README 초기 설치 재현\nS4·S12 개인 실측\nS10 제어판 버튼 연결',66,310,540,220,29);
  txt(s,'후속 개선',680,224,510,60,34,C.teal,true);txt(s,'manager 중단·중간 크래시 시험\n탐지 임계값과 오탐률 평가\n동시 사건·부분 실패 복구 강화\n티켓 시간 지표와 HTTP 효과 연결',680,310,540,245,29);
  txt(s,'검증 상태 기준  2026.11.10 · S10 실측 반영',66,610,1148,40,24,C.muted);

  s=slide('출처와 검증 자료','팀 원본, 개인 변경, 실제 실행 증적을 함께 확인할 수 있습니다.',`팀 구성: 김명준(조장, 포털·S8/S10 검증), 반소람(S1/S4), 김상혁(S7/Wazuh/티켓), 김대훈(S12/Graylog/n8n). AI 사용: Codex 구현·재현·자료 정리, Claude 독립 검토·실패 분석·pfSense 작업, 사용자 최종 판단과 병합. 팀 최종 PPT 원본은 현재 개인 레포에 확보하지 못했고 원본 코드·출처 문서·실측을 기반으로 구성했습니다.\n팀 원본: https://github.com/NoBugs-Aleph/aleph-soar-capstone\n개인 원본: ${repo}\n${source('docs/sources.md')}\n${source('docs/panel-results-20261110.md')}`);
  const links=[['팀 원본과 기여 출처',source('docs/sources.md')],['개인 S8 실측 보고서',source('docs/s8-results.md')],['S7 제어판 실측과 캡처',source('docs/panel-results-20261110.md')],['통합 PR #14',`${repo}/pull/14`]];
  links.forEach(([label,url],i)=>{txt(s,label,66,220+i*80,1150,60,32,C.teal,true,undefined,{uri:url,isExternal:true});});
  txt(s,'AI 활용: Codex 구현·재현 / Claude 독립 검토·문제 해결\n김명준이 범위와 결과를 확인하고 최종 판단',66,558,1148,82,25,C.muted);
  if (inventory) {
    const original=p.slides.items.map(s=>s.id);
    const extra=addNetworkSlides(p,inventory);
    p.slides.reorder([...original.slice(0,4),...extra,...original.slice(4)]);
    p.slides.items.forEach((s,i)=>{
      const marker=s.shapes.items.find(x=>x.position.top===671 && x.position.left===1150);
      if(marker)marker.text=String(i+1).padStart(2,'0');
      else txt(s,String(i+1).padStart(2,'0'),1150,671,64,24,16,C.muted);
    });
  }
  const beforeReview=p.slides.items.map(s=>s.id);
  const reviewSlides=addReviewSlides(p,{root});
  const reviewIndex=inventory?20:12;
  p.slides.reorder([...beforeReview.slice(0,reviewIndex),...reviewSlides,...beforeReview.slice(reviewIndex)]);
  p.slides.items.forEach((s,i)=>{const marker=s.shapes.items.find(x=>x.position.top===671&&x.position.left===1150);if(marker)marker.text=String(i+1).padStart(2,'0');else txt(s,String(i+1).padStart(2,'0'),1150,671,64,24,16,C.muted);});
  return {slideCount:p.slides.items.length,sourceCommit:'06fb3a4',statusAsOf:'2026-11-10 KST, S10 and S1 live runs included'};
}
