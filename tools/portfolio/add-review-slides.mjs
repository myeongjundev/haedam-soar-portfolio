import {readFileSync} from 'node:fs';

// Append evidence and teammate-inspired improvements to the existing deck.
// Dashboard UI captures are separate follow-up assets, never synthesized here.
export function addReviewSlides(p,{root}) {
 const C={bg:'#F5F7F3',ink:'#14312E',teal:'#167366',muted:'#536B65',pale:'#E5EEE7',white:'#FFFFFF'},F='Malgun Gothic';
 const source='https://github.com/myeongjundev/haedam-soar-portfolio/blob/06fb3a4/';
 const added=[];
 const read=(path)=>JSON.parse(readFileSync(`${root}/${path}`,'utf8'));
 function text(s,value,x,y,w,h=60,size=26,color=C.ink,bold=false){const t=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});t.text=value;t.text.style={fontFamily:F,fontSize:size,color,bold};t.text.insets=0;return t;}
 function slide(title,sub,notes){const s=p.slides.add();s.setViewportSize(1280,720);s.background.fill=C.bg;added.push(s.id);text(s,title,64,48,1152,72,42,C.ink,true);text(s,sub,64,130,1152,65,24,C.muted);text(s,'김명준  /  해담시청 SOAR',66,671,960,24,16,C.muted);s.speakerNotes.text=notes;return s;}
 function box(s,label,x,y,w,h=96){const t=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill:C.pale,line:{fill:C.teal,width:1.5}});t.text=label;t.text.style={fontFamily:F,fontSize:23,color:C.ink,bold:true,alignment:'center',verticalAlignment:'middle'};t.text.insets=8;return t;}
 function row(s,labels,y){const w=(1152-(labels.length-1)*24)/labels.length;const nodes=labels.map((label,i)=>box(s,label,64+i*(w+24),y,w));nodes.slice(1).forEach((b,i)=>s.shapes.connect(nodes[i],b,{kind:'elbow',fromSide:'right',toSide:'left',line:{fill:C.teal,width:2},tail:{type:'arrow',width:'med',length:'med'}}));}
 function table(s,values,widths,y=220,rowHeight=67,size=23){const t=s.tables.add({rows:values.length,columns:values[0].length,left:64,top:y,width:1152,height:values.length*rowHeight,columnWidths:widths,values});t.cells.block({row:0,column:0,rowCount:values.length,columnCount:values[0].length}).assign({fill:C.white,textStyle:{fontFamily:F,typeface:F,fontSize:size,color:C.ink},margins:{left:12,right:12,top:10,bottom:10}});t.cells.block({row:0,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.ink,textStyle:{fontFamily:F,typeface:F,fontSize:size,color:C.white,bold:true}});for(let r=2;r<values.length;r+=2)t.cells.block({row:r,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.pale});return t;}
 const response=read('infra/n8n/portfolio-s7/s7-respond.json');
 const complete=read('infra/n8n/portfolio-s7/s7-complete.json');
 const unwrap=(x)=>Array.isArray(x)?x[0]:x;
 const responseNames=new Set(unwrap(response).nodes.map(n=>n.name));
 const completeNames=new Set(unwrap(complete).nodes.map(n=>n.name));
 for(const name of ['Webhook','Validate','Claim trusted event','Record detection','Current ticket','Guarded response','Record applied','Record effect'])if(!responseNames.has(name))throw new Error(`Missing S7 response node: ${name}`);
 for(const name of ['Current ticket','Complete owned response','Record released','Respond'])if(!completeNames.has(name))throw new Error(`Missing S7 completion node: ${name}`);
 let s=slide('n8n S7 대응과 원복 노드','배포 JSON의 주요 노드 연결도 · 실제 n8n 캔버스 캡처와 구분합니다.',`실제 배포 JSON의 주요 성공 경로를 요약했습니다. Validate/Prepare/Check/IF 노드와 일부 중간 경로는 읽기 편하게 묶거나 생략했습니다. IF 거부 경로는 Respond로 종료하고 조치를 진행하지 않습니다. API 오류나 보류를 성공으로 표시하지 않습니다.\n대응 전체 노드 ${unwrap(response).nodes.length}개, 원복 전체 노드 ${unwrap(complete).nodes.length}개.\n${source}infra/n8n/portfolio-s7/s7-respond.json\n${source}infra/n8n/portfolio-s7/s7-complete.json`);
 text(s,'자동 대응',64,202,1152,40,28,C.teal,true);
 row(s,['Webhook\nValidate','Claim trusted\nevent','Record\ndetection','Current\nticket','Guarded\nresponse','Record applied\nRecord effect'],252);
 text(s,'원천 경보 확인 → 티켓 선기록 → 소유권 대조 → 제한된 조치 → 현재 효과 기록',64,362,1152,48,25,C.muted);
 text(s,'운영자 원복',64,422,1152,40,28,C.teal,true);
 row(s,['Current ticket','Complete owned\nresponse','Record released','Respond'],468);
 text(s,'탐지 키와 운영자 키 분리 · 조건 불일치 시 Respond로 보류 응답',64,604,1152,42,24,C.muted);

 const audit=read('docs/evidence/panel-live-audit-20261110.json');
 const a=audit.cases.find(x=>x.target==='index.html'),b=audit.cases.find(x=>x.target==='assets/s7-probe.txt');
 if(!a||!b)throw new Error('Missing observed S7 cases');
 s=slide('Graylog와 Wazuh 경보 연결','11월 10일 개인 S7 실측 증적 · 동일 사건의 경보와 티켓을 대조했습니다.',`UI 스크린샷을 대체한 모의 화면이 아니라 기존 실측 JSON에서 읽은 증적 표입니다. 실측 소스 ${audit.source_head}. Wazuh indexer 원천 조회, Gateway 읽기 전용 감사와 티켓 상태를 대조한 결과입니다. 실제 대시보드 캡처는 서비스 재개 후 별도로 추가합니다.\n${source}docs/evidence/panel-live-audit-20261110.json\n${source}docs/panel-results-20261110.md`);
 table(s,[['연결 근거','파일 복구','추가 파일 격리'],['Wazuh rule / alert',`${a.wazuh_alert.rule} / ${a.wazuh_alert.id}`,`${b.wazuh_alert.rule} / ${b.wazuh_alert.id}`],['Graylog event',a.response.graylog_event_id,b.response.graylog_event_id],['n8n 대응 / 원복',`${a.response.execution_id} / ${a.completion.execution_id}`,`${b.response.execution_id} / ${b.completion.execution_id}`],['대상 HTTP / 정상 홈',`${a.response.effect.target_status} / ${a.response.effect.home_status}`,`${b.response.effect.target_status} / ${b.response.effect.home_status}`],['최종 티켓',`${a.ticket_id}\n${a.ticket_status}`,`${b.ticket_id}\n${b.ticket_status}`]],[250,451,451],215,67,23);
 text(s,'단계 표시만으로 완료 판정하지 않고 원천 경보·현재 파일·HTTP·티켓을 확인',64,631,1152,30,22,C.muted);

 s=slide('공유 아이디어를 적용한 제어판','출처 반소람 · 명령 반복을 버튼과 회차별 증적 확인으로 개선했습니다.',`참고 자료: 반소람(whiteclover0542)이 2026-11-09 공유한 제어판-소개-공유.html. 공격/파악/원복 흐름을 참고했으며 팀원의 HTML 코드나 실측 성과를 개인 구현으로 반입하지 않았습니다. 김명준·Codex가 개인 제어판을 별도로 구현했습니다. 오른쪽 화면은 개인 실측의 자동 복구 확인·원복 대기 시점입니다. 원복 완료 결과는 별도 JSON과 기존 원복 화면에서 확인합니다.\n${source}docs/panel-lab.md\n${source}docs/evidence/panel-index-verified-20261110.png\n${source}docs/panel-results-20261110.md`);
 text(s,'공유받은 방향',64,218,550,48,31,C.teal,true);
 text(s,'공격 · 상태 파악 · 원복을\n한 화면에서 반복 실행',64,280,550,94,28);
 text(s,'개인 환경에 추가한 것',64,405,550,48,31,C.teal,true);
 text(s,'프로젝트·허용 대상 확인\n동시 입력 방지와 회차별 기록\n원천 경보·티켓·현재 효과 대조',64,466,550,137,27);
 s.images.add({blob:new Uint8Array(readFileSync(`${root}/docs/evidence/panel-index-verified-20261110.png`)),contentType:'image/png',alt:'개인 S7 실측 제어판에서 파일 자동 복구 확인 후 원복 대기 중인 화면',position:{left:670,top:202,width:540,height:424},fit:'contain'});
 text(s,'적용 완료: S7 버튼 실측 · 후속: S8/H1/S10 버튼 연결(S10은 CLI 실측 통과)',64,631,1152,30,23,C.muted);

 s=slide('시청 업무를 반영한 보안 개선','출처 반소람의 MVP 설계 · 개인 구현과 후속 제안을 구분합니다.',`출처: 2026-11-09 반소람(whiteclover0542), 공유 MVP-설계.md 7절 신규 케이스 H1~H4. 팀원 문서의 환경·계정·실측·기한은 개인 성과로 반입하지 않았습니다. H1만 김명준·Codex의 개인 구현·실측을 완료했습니다. H2는 현재 포털의 타인 민원 404 응답을 유지하며 내부 감사 이벤트를 추가하는 방향입니다. 제안의 403으로 바꾸지 않습니다. H3/H4는 이력·권한 복구·감사 정책 검토가 필요하며 미구현 제안입니다.\n${source}docs/sources.md\n${source}docs/h1-results.md\n${source}docs/portfolio-plan.md`);
 table(s,[['케이스','시청 업무 위험','개선 방향','개인 상태'],['H1 민원 도배','반복 등록으로\n담당자 업무 방해','작성만 제한\n로그인·조회 유지','구현·실측 완료'],['H2 타인 민원 열람','민원 번호 순회로\n개인정보 접근 시도','기존 404 유지\n거부 감사 이벤트','후속 제안'],['H3 처리 결과 조작','답변·처리 상태의\n부당한 대량 변경','변경 전 이력 저장\n승인된 값으로 복원','후속 제안'],['H4 담당자 대량 조회','내부 계정의\n과도한 정보 열람','조회 감사·업무 기준\n권한 회수와 복원','후속 제안']],[185,300,350,317],215,78,24);
 text(s,'H1 적용 이유: 민원 작성 제한 중에도 정상 조회와 다른 시민의 작성은 유지',64,625,1152,35,23,C.muted);
 return added;
}
