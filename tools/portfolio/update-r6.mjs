// Edit an existing r5 PPTX. Runtime and source/output paths are explicit CLI arguments.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const [runtime,root,source,output]=process.argv.slice(2);
if(!runtime||!root||!source||!output)throw new Error('runtime, repository root, source PPTX, private output directory required');
process.on('uncaughtException',e=>{console.error(e.message);process.exitCode=1;});
const {PresentationFile,FileBlob}=await import(pathToFileURL(runtime).href);
const p=await PresentationFile.importPptx(await FileBlob.load(source));
if(p.slides.items.length!==28)throw new Error('Expected unmodified 28-slide r5');
const old=p.slides.items.map(s=>s.id),F='Malgun Gothic';
const C={bg:'#F5F7F3',ink:'#14312E',teal:'#167366',muted:'#536B65'};
const repo='https://github.com/myeongjundev/haedam-soar-portfolio';
const evidence=JSON.parse(await fs.readFile(root+'/docs/evidence/s12-live-20261111.json','utf8'));
function set(s,name,value){const shape=s.shapes.items.find(x=>x.name===name);if(!shape)throw new Error('Missing '+name);shape.text=value;}
function txt(s,text,x,y,w,h,size=26,color=C.ink,bold=false,name){const t=s.shapes.add({name,geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});t.text=text;t.text.style={fontFamily:F,fontSize:size,color,bold};t.text.insets=0;return t;}
function slide(title,subtitle,notes){const s=p.slides.add({width:1280,height:720});s.background.fill=C.bg;txt(s,title,64,48,1152,70,42,C.ink,true,'title');txt(s,subtitle,66,130,1148,52,24,C.muted);txt(s,'김명준  /  해담시청 SOAR',66,671,960,24,16,C.muted);txt(s,'00',1150,671,64,24,16,C.muted);s.speakerNotes.text=notes;return s;}
function jpegSize(bytes){for(let offset=2;offset<bytes.length;){if(bytes[offset++]!==255)throw new Error('Malformed JPEG');const marker=bytes[offset++],length=bytes.readUInt16BE(offset);if([192,193,194].includes(marker))return {width:bytes.readUInt16BE(offset+5),height:bytes.readUInt16BE(offset+3)};offset+=length;}throw new Error('JPEG dimensions missing');}
async function image(s,path,frame,crop){const bytes=await fs.readFile(root+'/'+path);if(crop){const size=jpegSize(bytes),ratio=size.width*(1-crop.left-crop.right)/(size.height*(1-crop.top-crop.bottom));const width=Math.min(frame.width,frame.height*ratio),height=width/ratio;frame={left:frame.left+(frame.width-width)/2,top:frame.top,width,height};}s.images.add({blob:new Uint8Array(bytes),contentType:'image/jpeg',alt:'개인 랩 실제 화면',position:frame,fit:'contain',...(crop?{crop}:{})});}

const scope=p.slides.getItem(12),st=scope.tables.items[0];
['S4 / S12','11/10 / 11/11 통과','계정 잠금 / 통제 경합 차단·원복'].forEach((v,i)=>st.cells.set(6,i,v));
scope.speakerNotes.text='S4는 11/10 실제 계정 잠금·세션 회수·원복, S12는 11/11 통제된 자원 경합 환경에서 실제 차단·티켓·원복을 확인했습니다. S12는 운영 DDoS 성능 검증이 아닙니다. S7은 개인 FIM 즉시 대응 정책입니다. 출처: '+repo+'/blob/codex/s12-personal-live/docs/s12-results.md';
const future=p.slides.getItem(26);
set(future,'text-5','전체 README 초기 설치 재현\nWazuh 실제 대시보드 캡처 보강\nS10 제어판 버튼 연결');
set(future,'text-8','검증 상태 기준  2026.11.11 · S4·S12 실측 반영');
future.speakerNotes.text+='\n11/11 추가: S4/S12 실측은 완료했습니다. S12는 통제된 자원 경합 시험입니다. 새 PC의 통합 설치, Wazuh 실제 UI 캡처, S10 제어판 버튼은 남은 범위입니다.';

const s4=p.slides.getItem(17).duplicate();
set(s4,'title','S4  계정 잠금과 세션 회수');
set(s4,'text-1','같은 계정·IP의 실패 5회와 성공 1회를 결합한 개인 실측입니다.');
set(s4,'text-5','21.292초');set(s4,'text-6','6번째 로그인부터 Graylog 탐지까지');set(s4,'text-7','22.734초');set(s4,'text-8','6번째 로그인부터 잠금 API 완료까지');
set(s4,'text-4','같은 비밀번호로 원복 후 재로그인 성공 · 폐기된 옛 세션은 계속 무효');
const a=s4.tables.items[0];[['대조 항목','시험 계정','정상 계정'],['잠금 중','새 로그인 401 · 옛 2세션 무효','기존·새 로그인 유지'],['승인 원복 후','새 로그인 200 · 티켓 restored','활성 잠금·소유권 0']].forEach((r,i)=>r.forEach((v,j)=>a.cells.set(i,j,v)));
s4.speakerNotes.text='s4fix20261110, PR #30. 5건 경계 무탐지, 6건 자동 탐지. 대상 200→401→200, 기존 대상 세션 2개는 원복 후에도 무효. 정상 옛/새 세션 유지. 실제 실패에서 동적 Send Body 미지원 문제를 발견해 GET/POST 노드를 분리했습니다. 원본 정책은 순서가 아니라 실패/성공 혼재를 검사합니다. 개인 1회 관측. 출처: '+repo+'/blob/82eb98881a8a97d27d4b0078c93865f366e6c76f/docs/s4-results.md';

const s12=p.slides.getItem(17).duplicate();
set(s12,'title','S12  서비스 지연 확인 후 IP 차단');
set(s12,'text-1','공유 슬롯을 점유한 통제된 자원 경합 시험이며 운영 DDoS 성능과 구분합니다.');
set(s12,'text-5',evidence.timing.request_count_to_detection_seconds+'초');set(s12,'text-6','요청 수 기준 초과부터 탐지까지');set(s12,'text-7',evidence.timing.request_count_to_block_api_seconds+'초');set(s12,'text-8','요청 수 기준 초과부터 차단 API까지');
set(s12,'text-4','실제 health 509 / 526 / 524ms 초과 · 차단 후 7 / 7 / 7ms 회복');
const b=s12.tables.items[0];[['조건·효과','시험 출발지','정상 출발지'],['정책 / 차단 중','90건 초과 + health > 310ms 3회','100/100 정상 응답'],['승인 원복 후','403에서 200 · 같은 티켓 restored','활성 차단·조치 0']].forEach((r,i)=>r.forEach((v,j)=>b.cells.set(i,j,v)));
s12.speakerNotes.text='s12control20261111. 입력 142건(Graylog 고유 원천 일치), 탐지 창 116건. 요청 기준 충족 09:33:46.345 KST, 처리 09:34:04.311, 차단 API 09:34:11.049. health K=3은 별도 후속 조건이며 단순 API 지연과 구분합니다. 정상 p95 510.8ms, 실패0. 차단 직후 잔여 경합 영향 1건509.325ms 뒤 43건 기준 이내. 입력은 차단 관측 후 중지됩니다. 정상 경로는 config/health GET이고 로그인 업무 전체가 아닙니다. 1회 실측. 출처: '+repo+'/blob/codex/s12-personal-live/docs/s12-results.md';

const nodes=slide('n8n  실제 S12 대응 워크플로','현재 티켓과 소유권 확인 후 health 검사, 티켓 선기록, 차단을 실행합니다.','실제 게시된 n8n 2.39.5 구성 화면. 실행 payload는 저장하지 않습니다. 실행 26의 차단과 실행 47의 원복은 티켓 조치/클라이언트 증거로 확인합니다. 그림 자체는 실행 통과의 증명이 아닙니다. 출처: docs/evidence/s12-20261111/n8n-respond.jpg');
await image(nodes,'docs/evidence/s12-20261111/n8n-respond.jpg',{left:66,top:184,width:1148,height:458});

const gray=slide('Graylog  요청 수와 서비스 상태의 분리','요청 수가 기준을 넘어도 health가 정상이면 차단하지 않습니다.','실제 Graylog 6.1.16 화면. 첫 행116건은 저하 시험, 91/199/138건은 정상 상태 대조의 이벤트입니다. 요청 집계만으로 차단하지 않습니다. 알림 grace60초, 평가30초. UI 이벤트 timestamp와 실제 timestamp_processing이 다릅니다. 출처: docs/evidence/s12-20261111/graylog-events.jpg');
await image(gray,'docs/evidence/s12-20261111/graylog-events.jpg',{left:66,top:190,width:1148,height:438}, {left:0,top:0.13,right:0,bottom:0.25});
txt(gray,'정상 대조 231건: 티켓 0건   /   자원 경합: 실제 지연 확인 후 티켓 1건',66,635,1148,30,23,C.muted);

const ticket=slide('해담 보안 대시보드  동일 티켓의 원복','S12 자동 차단과 운영자 해제를 하나의 사건으로 추적했습니다.','실제 T-20261111-0001 restored 화면을 위쪽 사건 개요/타임라인 중심으로 잘라 배치했습니다. 원본 전체 이미지를 저장소에 보존합니다. UI MTTD/MTTR/effect_verified는 미측정 상태이며 외부 증적에서 직접 계산·대조했습니다. 원복 시각09:35:26 KST. 출처: docs/evidence/s12-20261111/ticket-restored.jpg');
await image(ticket,'docs/evidence/s12-20261111/ticket-restored.jpg',{left:66,top:190,width:1148,height:438},{left:0.17,top:0.04,right:0,bottom:0.615});
txt(ticket,'양쪽 HTTP 200 · 티켓 restored · DB 활성 차단 0 · 활성 조치 0',66,635,1148,30,23,C.muted);

const added=[s4,s12,nodes,gray,ticket].map(s=>s.id);
p.slides.reorder([...old.slice(0,18),...added,...old.slice(18)]);
p.slides.items.forEach((s,i)=>{const marker=s.shapes.items.find(x=>x.position.top===671&&x.position.left===1150);if(marker)marker.text=String(i+1).padStart(2,'0');});
await fs.mkdir(output,{recursive:true});
await(await PresentationFile.exportPptx(p)).save(output+'/candidate.pptx');
const changed=[13,19,20,21,22,23,32];
for(const n of changed){const blob=await p.slides.getItem(n-1).export({format:'png',scale:1});await fs.writeFile(output+'/slide-'+n+'.png',new Uint8Array(await blob.arrayBuffer()));}
await fs.writeFile(output+'/after.json',JSON.stringify(p.slides.items.map((s,i)=>({number:i+1,title:s.shapes.items.find(x=>x.name==='title')?.text?.toString()})),null,2));
console.log(JSON.stringify({slides:p.slides.items.length,candidate:output+'/candidate.pptx',changed}));
