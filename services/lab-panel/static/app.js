'use strict';
const $ = id => document.getElementById(id);
const labels = {preparing:'입력 준비 중',armed:'입력 준비 기록됨',input_sent:'탐지·대응 확인 대기',observing:'탐지·대응 관측 중',verified:'자동 대응 확인 · 원복 대기',restored:'원복 완료',needs_check:'확인 필요',not_started:'입력 시작 안 됨'};
const stepLabels = [['input','시험 입력'],['wazuh','Wazuh 탐지'],['graylog','Graylog 전달'],['response','자동 대응·티켓'],['restore','원복 완료']];
const errors = {busy:'다른 작업이 진행 중입니다.',unfinished_run:'기존 회차의 상태 확인과 원복을 먼저 완료하세요.',observe_first:'먼저 탐지·대응 확인을 실행하세요.',scope_mismatch:'이 회차의 프로젝트 또는 설정이 현재 환경과 다릅니다.',invalid_target:'등록되지 않은 대상입니다.',forbidden:'제어판 접근이 만료됐습니다. 페이지를 새로 열어주세요.',request_conflict:'동일 요청의 내용이 다릅니다.',unavailable:'제어판 작업을 시작하지 못했습니다.'};
let state, selected, sending=false, pollTimer;
function text(tag,value,className){const el=document.createElement(tag);el.textContent=value;if(className)el.className=className;return el;}
function stamp(value){return value?new Intl.DateTimeFormat('ko-KR',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'Asia/Seoul',hour12:false}).format(new Date(value)):'—';}
function notify(message,error=false){$('notice').hidden=!message;$('notice').textContent=message;$('notice').className='notice'+(error?' error':'');}
function current(){return state?.runs.find(r=>r.id===selected);}
function busy(){return sending||state?.jobs.some(j=>['queued','running'].includes(j.status));}
function healthFresh(){return state?.health.ready && Date.now()-Date.parse(state.health.observed_at)<60000;}
function render(){
  if(!state)return;
  const run=current(), working=busy(), fresh=healthFresh();
  $('project').textContent=state.project;
  $('health').textContent=fresh?'개인 랩 연결 확인':state.health.reason==='unchecked'?'환경 미확인':state.health.ready?'연결 정보 갱신 필요':state.health.reason==='scope_mismatch'?'환경 불일치':'개인 랩 연결 대기';
  $('health-dot').className='dot'+(fresh?'':' gray');
  $('health-time').textContent=state.health.observed_at?'마지막 조회 '+stamp(state.health.observed_at):'환경 확인 버튼으로 연결 상태를 조회하세요.';
  if(!run && state.runs.length){selected=state.runs[0].id;return render();}
  const unfinished=state.runs.some(r=>!['restored','not_started'].includes(r.stage));
  const desired=unfinished?run?.target:$('target').value;
  $('target').replaceChildren(...Object.entries(state.targets).map(([key,action])=>{const o=text('option',(action==='restore'?'파일 변조 · ':'추가 파일 · ')+key);o.value=key;return o;}));
  if(desired && desired in state.targets)$('target').value=desired;
  $('target').disabled=working||unfinished;
  $('refresh').disabled=working;
  $('attack').disabled=working||!fresh||unfinished;
  $('observe').disabled=working||!run||!run.input_sha256;
  $('restore').disabled=working||!run?.event_key||run.stage==='restored';
  $('run-stage').textContent=run?(labels[run.stage]||'확인 필요'):'실행을 기다리고 있습니다';
  $('run-id').textContent=run?run.id:'아직 실행 이력이 없습니다.';
  $('ticket').replaceChildren();
  if(run?.ticket_id && state.health.links?.tickets){const a=text('a',run.ticket_id);a.href=state.health.links.tickets+'/tickets/'+encodeURIComponent(run.ticket_id);a.target='_blank';a.rel='noopener noreferrer';$('ticket').append(a);}else $('ticket').textContent=run?.ticket_id||'—';
  $('home-status').textContent=run?.effect?.home_status??'미관측';
  $('target-status').textContent=run?.effect?.target_status??'미관측';
  $('observed-time').textContent=stamp(run?.observed_at);
  $('evidence').hidden=!run;if(run)$('evidence').href='/api/runs/'+run.id+'/evidence';
  $('steps').replaceChildren(...stepLabels.map(([id,label],i)=>{const li=document.createElement('li');const done=run?.steps?.[id];li.className=done?'complete':'';li.append(text('span',done?'✓':String(i+1).padStart(2,'0'),'step-number'),text('strong',label),text('small',done?stamp(done.at):'미관측'));if(done)li.title=done.detail;return li;}));
  const job=state.jobs.find(j=>['queued','running'].includes(j.status));
  $('job-status').textContent=job?({refresh:'환경 조회 중',attack:'시험 입력 중',observe:'실제 탐지·대응을 기다리는 중',restore:'원복 확인 중'}[job.action]):'관측한 단계만 표시합니다.';
  $('run-count').textContent=state.runs.length+'회';
  $('history-list').replaceChildren();
  if(!state.runs.length)$('history-list').append(text('p','첫 실습을 시작하면 이곳에 회차별 기록이 남습니다.','empty'));
  state.runs.forEach(r=>{const b=document.createElement('button');b.className='history-row'+(r.id===selected?' current':'');b.disabled=working;b.setAttribute('aria-pressed',r.id===selected?'true':'false');const a=document.createElement('span');a.append(text('strong',r.target),text('small',stamp(r.created_at)+' · '+r.id.slice(0,8)));b.append(a,text('span',labels[r.stage]||r.stage,'history-status'));b.onclick=()=>{selected=r.id;render();};$('history-list').append(b);});
  $('links').replaceChildren();
  const linkNames={portal:'해담 민원포털',graylog:'Graylog 이벤트',n8n:'n8n 워크플로',tickets:'티켓 대시보드'};
  Object.entries(state.health.links||{}).forEach(([key,url])=>{const a=text('a',linkNames[key]+' ↗');a.href=url;a.target='_blank';a.rel='noopener noreferrer';$('links').append(a);});
  if(!Object.keys(state.health.links||{}).length)$('links').append(text('p','환경 확인 후 표시됩니다.','empty'));
  if(run?.error)notify((state.errors[run.error]||errors[run.error]||'결과를 확인하지 못했습니다.')+' 회차 기록은 보존됩니다.',true);
  else if(job)notify($('job-status').textContent+'…');
  else if(state.jobs[0]?.error)notify(state.errors[state.jobs[0].error]||'결과를 확인하지 못했습니다.',true);
  else notify('');
}
async function load(){
  try{const res=await fetch('/api/state',{cache:'no-store'});if(!res.ok)throw Error('제어판 연결을 확인하세요.');state=await res.json();render();}
  catch(error){notify(error.message,true);$('attack').disabled=true;$('restore').disabled=true;$('observe').disabled=true;}
}
async function submit(action,extra={}){
  if(busy())return;
  sending=true;notify('');render();
  try{
    const res=await fetch('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json','X-Panel-CSRF':state.csrf},body:JSON.stringify({action,request_id:crypto.randomUUID(),...extra})});
    const body=await res.json();if(!res.ok)throw Error(errors[body.error]||state.errors[body.error]||'요청을 처리하지 못했습니다.');
    if(body.run_id)selected=body.run_id;
    notify(action==='refresh'?'환경을 조회하고 있습니다.':'작업을 시작했습니다. 페이지를 닫아도 서버가 실행 중이면 작업과 기록은 유지됩니다.');
  }catch(error){notify(error.message,true);}
  finally{sending=false;await load();}
}
$('refresh').onclick=()=>submit('refresh');
$('observe').onclick=()=>submit('observe',{run_id:selected});
$('restore').onclick=()=>submit('restore',{run_id:selected});
$('attack').onclick=()=>{$('confirm-target').textContent=state.project+' / '+$('target').value;$('confirm').showModal();};
$('confirm').addEventListener('close',()=>{if($('confirm').returnValue==='run')submit('attack',{target:$('target').value});});
load();pollTimer=setInterval(load,2000);
