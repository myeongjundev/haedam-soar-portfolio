// Add a real Wazuh overview capture to the preserved r6 deck.
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const [runtime,root,source,output]=process.argv.slice(2);
if(!runtime||!root||!source||!output)throw Error('runtime, root, source PPTX, private output directory required');
const {PresentationFile,FileBlob}=await import(pathToFileURL(runtime).href);
const p=await PresentationFile.importPptx(await FileBlob.load(source));
if(p.slides.items.length!==33)throw Error('Expected r6 with 33 slides');
const order=p.slides.items.map(s=>s.id),C={bg:'#F5F7F3',ink:'#14312E',teal:'#167366',muted:'#536B65'};
function txt(s,text,x,y,w,h,size=26,color=C.ink,bold=false,name){const t=s.shapes.add({name,geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});t.text=text;t.text.style={fontFamily:'Malgun Gothic',fontSize:size,color,bold};t.text.insets=0;return t;}
const s=p.slides.add({width:1280,height:720});s.background.fill=C.bg;
txt(s,'Wazuh  실제 관제 대시보드',64,48,1152,70,42,C.ink,true,'title');
txt(s,'2026.11.11 기존 관제 환경의 Overview 화면을 읽기 전용으로 확인했습니다.',66,130,1148,52,24,C.muted);
const bytes=await fs.readFile(root+'/docs/evidence/wazuh-overview-20261111.jpg');
// Preserve original screenshot; crop to the agent/alert overview in the slide only.
let width,height;for(let o=2;o<bytes.length;){if(bytes[o++]!==255)throw Error('Malformed JPEG');const m=bytes[o++],len=bytes.readUInt16BE(o);if([192,193,194].includes(m)){width=bytes.readUInt16BE(o+5);height=bytes.readUInt16BE(o+3);break;}o+=len;}
if(!width||!height)throw Error('Screenshot size missing');
const visibleHeight=1115,displayHeight=474,displayWidth=width/visibleHeight*displayHeight;
s.images.add({blob:new Uint8Array(bytes),contentType:'image/jpeg',alt:'실제 Wazuh Overview의 에이전트·최근 24시간 경보',position:{left:130,top:185,width:displayWidth,height:displayHeight},fit:'contain',crop:{left:0,top:0,right:0,bottom:1-visibleHeight/height}});
txt(s,'연결 상태와 경보 현황',440,218,734,50,32,C.teal,true);
txt(s,'활성 에이전트 1개 · 연결 끊김 0개\n최근 24시간 경보\nCritical 0 · High 0 · Medium 1 · Low 255',440,294,734,152,28);
txt(s,'화면과 실측 근거의 구분',440,475,734,44,28,C.teal,true);
txt(s,'이 화면은 기존 관제 환경의 현재 상태입니다.\n개인 S7 복구·격리 결과는 별도 경보 ID와\n클라이언트·티켓 증적으로 검증했습니다.',440,534,734,111,24,C.muted);
txt(s,'김명준  /  해담시청 SOAR',66,671,960,24,16,C.muted);txt(s,'24',1150,671,64,24,16,C.muted);
s.speakerNotes.text='출처: docs/evidence/wazuh-overview-20261111.jpg. 2026-11-11 약 10:07 KST localhost Wazuh 기존 관제 환경 Overview. Active1/Disconnected0, 최근24h severity 0/0/1/255. 전체 원본 캡처를 보존하고 슬라이드에는 위쪽 요약만 자릅니다. 기존 Docker/VM의 시작·중지·설정 명령을 실행하지 않았습니다. 이 화면은 개인 S7 실행 당시 경보의 캡처가 아니며 동일 회차 증거로 혼용하지 않습니다. 개인 S7 근거는 docs/panel-results-20261110.md 및 기존 경보 대조 슬라이드입니다.';
const future=p.slides.getItem(31),pending=future.shapes.items.find(x=>x.name==='text-5');pending.text='전체 README 초기 설치 재현\n개인 S7 회차의 Wazuh 상세 화면\nS10 제어판 버튼 연결';
future.speakerNotes.text+='\n11/11 r7: 기존 관제 Wazuh 실제 Overview를 추가했습니다. 개인 S7 동일 회차의 Wazuh UI 상세는 미추가이며 JSON 경보 증적을 유지합니다.';
p.slides.reorder([...order.slice(0,23),s.id,...order.slice(23)]);
p.slides.items.forEach((x,i)=>{const n=x.shapes.items.find(t=>t.position.top===671&&t.position.left===1150);if(n)n.text=String(i+1).padStart(2,'0');});
await fs.mkdir(output,{recursive:true});await(await PresentationFile.exportPptx(p)).save(output+'/candidate.pptx');
for(const n of [24,33]){const b=await p.slides.getItem(n-1).export({format:'png',scale:1});await fs.writeFile(output+'/slide-'+n+'.png',new Uint8Array(await b.arrayBuffer()));}
console.log('r7 candidate: 34 slides');
