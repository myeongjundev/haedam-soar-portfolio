// Native, editable diagrams and tables. Values come from the read-only inventory.
export function addNetworkSlides(p, inventory) {
 const C={bg:'#F5F7F3',ink:'#14312E',teal:'#167366',muted:'#536B65',pale:'#E5EEE7',white:'#FFFFFF',amber:'#916019'}, F='Malgun Gothic';
 const src='https://github.com/myeongjundev/haedam-soar-portfolio/blob/06fb3a4/';
 const added=[];
 function text(s,t,x,y,w,h=60,size=26,color=C.ink,bold=false){const q=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});q.text=t;q.text.style={fontFamily:F,fontSize:size,color,bold};q.text.insets=0;return q;}
 function slide(title,sub,notes){const s=p.slides.add();s.setViewportSize(1280,720);s.background.fill=C.bg;added.push(s.id);text(s,title,64,48,1150,72,42,C.ink,true);text(s,sub,64,130,1150,65,24,C.muted);text(s,'김명준  /  해담시청 SOAR',66,671,960,25,16,C.muted);s.speakerNotes.text=notes;return s;}
 function box(s,label,x,y,w,h=90,fill=C.pale){const q=s.shapes.add({geometry:'rect',position:{left:x,top:y,width:w,height:h},fill,line:{fill:C.teal,width:1.5}});q.text=label;q.text.style={fontFamily:F,fontSize:25,color:C.ink,bold:true,alignment:'center',verticalAlignment:'middle'};q.text.insets=10;return q;}
 function arrow(s,a,b,from='right',to='left',dash=false){s.shapes.connect(a,b,{kind:'elbow',fromSide:from,toSide:to,line:{fill:C.teal,width:2,style:dash?'dashed':'solid'},tail:{type:'arrow',width:'med',length:'med'}});}
 function tab(s,values,widths,y=218,row=70,size=24){const t=s.tables.add({rows:values.length,columns:values[0].length,left:64,top:y,width:1152,height:values.length*row,columnWidths:widths,values});t.cells.block({row:0,column:0,rowCount:values.length,columnCount:values[0].length}).assign({fill:C.white,textStyle:{fontFamily:F,typeface:F,fontSize:size,color:C.ink},margins:{left:12,right:12,top:10,bottom:8}});t.cells.block({row:0,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.ink,textStyle:{fontFamily:F,typeface:F,fontSize:size,color:C.white,bold:true}});for(let r=2;r<values.length;r+=2)t.cells.block({row:r,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.pale});return t;}

 let s=slide('공격·탐지·대응·원복 플로우','자동 대응과 운영자 원복을 분리하고, 각 단계의 근거를 같은 사건으로 연결합니다.',`S7은 실제 파일 변화, S8/H1은 실제 HTTP 요청을 입력으로 사용합니다. Graylog는 실제 로그를 조건별로 판정합니다. 티켓 기록 실패 시 조치를 보류하며 효과 검증 실패를 성공으로 표시하지 않습니다. 원복은 소유 티켓에 대해 운영자 인증으로 요청합니다.\n${src}docs/s7-auto-contract.md\n${src}docs/s8-contract.md\n${src}docs/h1-results.md`);
 const labels=['허용된\n시험 입력','앱 로그 /\nWazuh 경보','Graylog\n조건 판단','n8n\n인증된 호출'];const row=labels.map((v,i)=>box(s,v,64+i*300,220,250,95));row.slice(1).forEach((b,i)=>arrow(s,row[i],b));
 const ticket=box(s,'티켓 선기록',964,425,250,90),effect=box(s,'제한된 조치\n실제 효과 확인',664,425,250,90),restore=box(s,'운영자 원복\n소유 티켓 확인',364,425,250,90),final=box(s,'정상 상태 대조\n티켓 restored',64,425,250,90);
 arrow(s,row[3],ticket,'bottom','top');arrow(s,ticket,effect,'left','right');arrow(s,effect,restore,'left','right');arrow(s,restore,final,'left','right');
 text(s,'기록 실패: 조치 보류     효과 불일치: 성공 보류     원복 후: 잔여 조치·정상 이용 확인',64,575,1152,65,25,C.muted);

 s=slide('S7 상세 서비스 아키텍처','s7-response의 중계·Gateway 역할이 원천 경보와 조치 영수증을 연결합니다.',`S7의 portal GELF_ENABLED=0. S7 경로는 manager alerts를 공유 볼륨에서 읽는 s7-response relay가 HTTP GELF12202로 전달합니다. n8n은 gateway8097을 호출하고 gateway가 Wazuh API55000을 호출합니다. Active Response는 agent1514 연결로 전달됩니다. baseline과 receipt는 읽기 전용으로 검증합니다.\n${src}compose.s7-auto.yaml\n${src}infra/s7-auto-settings.json`);
 const portal=box(s,'포털 배포 파일\n공유 볼륨',64,220,230),agent=box(s,'Wazuh agent\nFIM / AR',374,220,230),manager=box(s,'Wazuh manager\n경보 생성',684,220,230),relay=box(s,'s7-response\n경보 중계·검증',994,220,220);
 arrow(s,portal,agent);arrow(s,agent,manager);arrow(s,manager,relay);
 text(s,'파일 감시',285,192,110,26,19);text(s,'1514/TCP',592,192,150,26,19);text(s,'alerts 볼륨 읽기',900,192,230,26,19);
 const gray=box(s,'Graylog\nGELF HTTP 12202',994,433,220,105),n=box(s,'n8n\nwebhook 5678',684,433,230,105),g=box(s,'Gateway 8097\n조치·효과 확인',374,433,230,105),t=box(s,'티켓 저장소\n쓰기 8088',64,433,230,105);
 arrow(s,relay,gray,'bottom','top');arrow(s,gray,n,'left','right');arrow(s,n,g,'left','right');arrow(s,n,t,'bottom','bottom');
 text(s,'대응 제어: Gateway → manager API 55000/TLS → agent AR',64,565,1150,48,27,C.teal,true);
 text(s,'검증 대상: 원천 경보 해시 · 읽기 전용 baseline · agent 영수증 · 실제 HTTP',64,615,1150,40,24,C.muted);

 s=slide('S7 Docker 네트워크 상세','아래 CIDR은 보존된 haedam-s7-panel-live 네트워크의 관측값입니다.',`11/10 docker network inspect 읽기 전용 조회. CIDR을 Compose에 고정하지 않았으므로 새 PC/프로젝트에서는 Docker 주소 할당에 따라 달라질 수 있습니다. access망에 여러 서비스가 함께 연결되므로 이를 서비스별 강제 분리망으로 과장하지 않습니다. 서비스 접속은 Docker DNS를 사용합니다. 포트 공개는127.0.0.1에 한정됩니다.\n${src}compose.s7.yaml\n${src}compose.soc.yaml\n${src}compose.s7-auto.yaml\n개인 기록: docs/portfolio/network-inventory-20261110.json`);
 const nets=inventory.S7.observed_networks;const net=(suffix)=>nets.find(x=>x.name.endsWith('_'+suffix));
 tab(s,[['망 / 격리','관측 서브넷','연결 서비스'],['default / internal',net('default').ipam[0].Subnet,'포털·DB·agent·manager·indexer\n대시보드·Graylog·n8n·티켓·Gateway'],['graylog-backend / internal',net('graylog-backend').ipam[0].Subnet,'Graylog·MongoDB·OpenSearch'],['access / 일반 bridge',net('access').ipam[0].Subnet,'포털·Wazuh 서버 3종\nGraylog·n8n·티켓']],[360,280,512],216,95,24);
 text(s,'운영 원칙: DNS로 서비스 연결 / 호스트 공개는 loopback / 랩별 볼륨 보존',64,625,1150,36,23,C.muted);

 s=slide('S8·H1 클라이언트망과 대응망','시험 클라이언트는 대응 API 전용 망에 직접 연결하지 않습니다.',`S8/H1은 각자 별도 Compose 프로젝트와 볼륨입니다. 클라이언트망과 대응망은 internal:true. portal과 n8n은 공통 default에도 연결되며 API 허용 CIDR은 대응망 n8n /32입니다. S8 클라이언트 .23/.24는 단일 신호 대조군입니다. 주소는 현재 Compose 정의의 값입니다.\n${src}compose.s8.yaml\n${src}compose.h1.yaml`);
 tab(s,[['구분','S8','H1'],['클라이언트망','172.30.88.0/24','172.30.90.0/24'],['시험 / 정상 클라이언트','.21 / .22  (추가 대조 .23·.24)','.21 / .22'],['포털 클라이언트 NIC','.10:5000','.10:5000'],['대응망','172.30.89.0/29','172.30.91.0/29'],['n8n / 포털 대응 NIC','.2  /  .3:5000','.2  /  .3:5000']],[330,411,411],205,64,24);
 text(s,'대응 API: portal-response DNS + 인증 키 + n8n 대응 주소 /32 허용',64,614,1152,42,24,C.teal,true);

 s=slide('pfSense/S10 실행 망 구조','11/10 P04·S10 실측에 사용한 망입니다. 시험·정상 요청은 pfSense WAN을 거쳐야만 포털에 닿습니다.',`설정 출처: PR13 infra/pfsense/lab-settings.json, compose.pf.yaml, compose.s10.yaml. 실측 P04-20261110T014245Z, S10-20261110T021934Z(docs/s10-results-20261110.md). 두 pf 망은 internal을 쓰지 않고 NAT를 끕니다(internal이면 Docker가 다른 대역 목적지 프레임을 버림). n8n은 컨트롤러의 HTTP relay(8099)를 거쳐 고정 호스트 키 SSH로 팀 PF 도구를 호출합니다. QEMU 컨테이너 내부에서 FreeBSD pfSense VM이 동작하는 방식이며 native Linux container pfSense가 아닙니다. 컨테이너 bridge .253 주소는 초기 bridge/tap 설정용이며 start.sh에서 제거합니다.\nhttps://github.com/myeongjundev/haedam-soar-portfolio/pull/13`);
 text(s,'pf-wan  203.0.113.0/24',64,213,600,42,29,C.teal,true);text(s,'pf-lan  172.30.94.0/24',740,213,500,42,29,C.teal,true);
 const clients=box(s,'시험 .22 / 정상 .12\n경로: LAN via .1',64,285,310,115),pf=box(s,'pfSense CE VM\nem0 203.0.113.1\nem1 172.30.94.1',460,275,320,145,'#F3EADC'),portal2=box(s,'포털 .10:5000\n반환: WAN via .1',866,285,350,115);
 arrow(s,clients,pf);arrow(s,pf,portal2);
 const ctrl=box(s,'컨트롤러 172.30.94.100\nn8n relay 8099 → SSH 22',866,475,350,90);arrow(s,ctrl,pf,'left','bottom',true);
 text(s,'QEMU + bridge/tap\n두 Docker 망: internal 해제·NAT 끔',64,475,610,90,28);
 text(s,'각 Docker gateway는 .254 / 차단 전후 요청 모두 pfSense 경유 경로로 실측',64,602,1150,45,25,C.muted);

 s=slide('호스트 접근 포트 구성','현재 개인 랩 설정값입니다. 모두 127.0.0.1에 바인딩하며 공용 인터넷에 공개하지 않습니다.',`현재 effective docker compose config에서 비밀값을 제외하고 ports만 추출했습니다. TCP 기준, Wazuh는 HTTPS/TLS입니다. 각 랩은 별도 프로젝트로 실행하며 Docker 메모리 제약에 따라 순차 운용합니다. Panel15800은 Docker publish가 아니라 호스트 Python listener입니다. GELF TCP22330은 S7에 상속된 공개 포트이며 실제 S7 릴레이는 내부HTTP12202를 사용합니다.\n${src}infra/s7-auto-settings.json\n${src}tools/s8_lab.py\n${src}tools/h1_lab.py\n${src}infra/panel-settings.json`);
 function port(c,k){return inventory[c].services[k]?.ports?.[0]?.published||'—';}
 tab(s,[['서비스','컨테이너','S7 호스트','S8 호스트','H1 호스트'],['해담 포털','5000',port('S7','portal'),port('S8','portal'),port('H1','portal')],['Graylog UI/API','9000',port('S7','graylog'),port('S8','graylog'),port('H1','graylog')],['n8n UI/webhook','5678',port('S7','n8n'),port('S8','n8n'),port('H1','n8n')],['해담 보안 대시보드','8089',port('S7','ticket-store'),port('S8','ticket-store'),port('H1','ticket-store')],['Wazuh 대시보드','5601','15630','—','—'],['Wazuh API / indexer','55000 / 9200','15530 / 19230','—','—'],['GELF TCP 입력','12201','22330','22300','22310'],['개인 제어판','호스트 실행','15800','미연결','미연결']],[325,205,220,201,201],200,49,23);

 s=slide('컨테이너 내부 통신 포트','호스트 접속 포트와 내부 서비스 포트는 구분해서 사용합니다.',`구성 파일에서 확인한 통신 계약입니다. 1514는 agent event와 AR 채널,1515는 등록입니다. 내부 경로를 모두 호스트에 공개하지 않습니다. ticket-store의 쓰기8088은 내부 전용이고 읽기/UI8089만 loopback publish합니다. Graylog OpenSearch와 Wazuh indexer는 서로 다른 서비스와 저장소입니다.\n${src}compose.soc.yaml\n${src}compose.s7-auto.yaml\n${src}infra/s7-auto-settings.json\n${src}infra/wazuh/agent/ossec.conf`);
 tab(s,[['출발 / 목적지','포트·프로토콜','목적'],['agent / Wazuh manager','1514 TCP / 1515 TCP','경보·AR 연결 / 에이전트 등록'],['S7 relay / Graylog','12202 HTTP','신뢰한 FIM 경보 전달'],['포털 / Graylog (S8·H1)','12201 TCP','실제 앱 이벤트 GELF 수집'],['Graylog / n8n','5678 HTTP','인증된 탐지 webhook'],['n8n / S7 Gateway','8097 HTTP','소유 사건 조치·원복·재확인'],['Gateway / Wazuh API','55000 HTTPS','지정 agent Active Response'],['n8n / 티켓 저장소','8088 HTTP','사건·조치 선기록'],['포털 / MySQL','3306 TCP','앱 데이터 저장']],[440,310,402],200,50,23);

 s=slide('저장·권한 경계와 원복 조건','탐지 자료, 조치 명령, 실제 효과를 서로 다른 근거로 대조합니다.',`Graylog-Mongo27017, Graylog-OpenSearch9200은 graylog-backend망 내부 통신입니다. Wazuh-indexer9200은 별도 서비스입니다. s7-baseline setup은 network_mode:none이며 정상 이미지 해시와 비교 후 baseline을 생성합니다. agent웹볼륨은RW, portal웹은RO, gateway웹/baseline/receipt/alerts는RO입니다. runtime 데이터 SQLite는각자의볼륨에저장합니다.\n${src}compose.s7-auto.yaml\n${src}compose.soc.yaml\n${src}docs/panel-results-20261110.md`);
 tab(s,[['경계','현재 구성','원복·검증 의미'],['탐지 저장소','Graylog MongoDB:27017 / OpenSearch:9200','관제망 내부 통신, Wazuh 저장소와 별도'],['정상 기준','setup만 생성 / runtime baseline 읽기 전용','변조 상태를 새 정상 기준으로 덮어쓰지 않음'],['파일 변경','agent 웹 볼륨 RW / portal·gateway RO','허용 대상 복구·격리와 현재 해시 대조'],['사건 소유권','event key + ticket ID + agent 영수증','다른 회차의 해제·중복 조치 방지']],[240,460,452],217,75,24);
 text(s,'원복 완료: 정상 파일·HTTP + 격리물/활성 조치 없음 + 티켓 restored',64,625,1150,36,24,C.teal,true);
 return added;
}
