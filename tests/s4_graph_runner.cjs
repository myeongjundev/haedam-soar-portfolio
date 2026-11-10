// Test-only graph interpreter. Executes generated Code/IF/subworkflow nodes,
// replaces HTTP nodes with an in-memory contract model. Never loads http/net.
const fs=require('node:fs');
const spec=JSON.parse(fs.readFileSync(0,'utf8'));
const workflows=Object.fromEntries(Object.values(spec.workflows).map(w=>[w.id,w]));
const state={tickets:[],blocks:new Set(),calls:[],receipts:new Map(),serial:0,...spec.state};
state.blocks=new Set(spec.state?.blocks||[]);
let faults={};
const copy=x=>JSON.parse(JSON.stringify(x));
const response=(body,statusCode=200)=>({statusCode,body});
const active=t=>t.actions.filter(a=>['applied','already_applied'].includes(a.result) && !a.released);
const ref=(a,withResult=false)=>({bot:a.bot,via:a.via,action:a.action,target:a.target,...(withResult?{result:a.result}:{})});
function http(method,url,body,headers){
 const u=new URL(url),path=u.pathname;
 state.calls.push({method,url,body:copy(body),headers});
 if(u.hostname==='portal-response'){
  const a=state.account;
  if(method==='GET'){
   if(faults.portalRead || faults.readAfterMutation && a.locked || faults.readWhenUnblocked && !a.locked) return response({},503);
   return response({success:true,data:copy(a)});
  }
  if(faults.portalMutation)return response({},503);
  if(faults.malformedMutation)return response({success:true,data:{}});
  const key=headers['Idempotency-Key'];
  if(state.receipts.has(key))return state.receipts.get(key);
  if(body.user_id!==a.user_id)return response({},409);
  const lock=path.endsWith('/lock');
  if(lock && (a.locked || a.owner_ticket_id))return response({},409);
  if(!lock && a.owner_ticket_id!==body.ticket_id)return response({},409);
  const changed=a.locked!==lock,revoked_sessions=a.active_sessions;
  a.locked=lock;a.active_sessions=0;a.owner_ticket_id=lock?body.ticket_id:null;
  const result=response({success:true,data:{...copy(a),changed,revoked_sessions}});
  state.receipts.set(key,result);
  if(faults.lostMutationResponse)return {error:{message:'private-key-must-not-leak'}};
  return result;
 }
 if(u.hostname!=='ticket-store')throw Error('Unexpected network destination');
 if(faults.ticketRead && method==='GET')return response({},503);
 if(path.endsWith('/active')){
  const resource=Object.fromEntries(u.searchParams);
  const tickets=state.tickets.map(t=>({ticket_id:t.ticket_id,seat:t.seat,status:t.status,active_actions:active(t).filter(a=>a.target===resource.target && a.via===resource.via).map(a=>ref(a))})).filter(t=>t.active_actions.length);
  return response({ok:true,resource,tickets});
 }
 if(path.endsWith('/open')){
  const t=state.tickets.findLast(t=>t.seat===u.searchParams.get('seat') && t.group_key===u.searchParams.get('group_key') && t.status!=='closed');
  return response({ok:true,exists:!!t,ticket_id:t?.ticket_id||null,status:t?.status||null,applied_actions:t?active(t).map(a=>ref(a,true)):[]});
 }
 if(!path.endsWith('/record') || method!=='POST')throw Error('Unexpected ticket request');
 if(faults.recordStage===body.stage)return response({},503);
 const key=headers['Idempotency-Key'];
 if(state.receipts.has(key))return state.receipts.get(key);
 let t=state.tickets.findLast(t=>t.seat===body.seat && t.group_key===body.group_key && t.status!=='closed');
 const owner=state.tickets.find(t=>t.seat===body.seat && t.group_key===body.group_key && body.event_ids.some(id=>t.event_ids.includes(id)));
 if(['detected','applied'].includes(body.stage) && owner && (owner!==t || owner.status==='restored')) return response({ok:true,ticket_id:owner.ticket_id,status:owner.status,created:false,duplicate:true});
 let created=false;
 if(!t || t.status==='restored' && body.stage==='detected'){
  if(t)t.status='closed';
  t={ticket_id:'T-20261110-'+String(++state.serial).padStart(4,'0'),seat:body.seat,case_id:body.case_id,asset_id:body.asset_id,group_key:body.group_key,status:'open',event_ids:[],actions:[]};
  state.tickets.push(t);created=true;
 }
 for(const id of body.event_ids)if(!t.event_ids.includes(id))t.event_ids.push(id);
 if(body.stage==='applied'){
  t.actions.push(copy(body.action));
  if(['applied','already_applied'].includes(body.action.result))t.status='responding';
 }
 if(body.stage==='released'){
  for(const a of active(t))if(a.target===body.action.target && a.via===body.action.via)a.released=true;
  t.status=active(t).length?'responding':'restored';
 }
 const result=response({ok:true,ticket_id:t.ticket_id,status:t.status,created,duplicate:false});
 state.receipts.set(key,result);return result;
}
let seq=0;
function run(id,input,execution){
 const w=workflows[id],nodes=Object.fromEntries(w.nodes.map(n=>[n.name,n]));
 const outputs={};
 const selector=name=>({first:()=>({json:outputs[name]})});
 const expr=(v,j)=>typeof v==='string' && v.startsWith('={{')?new Function('$json','$',`return (${v.slice(3,-2)});`)(j,selector):v;
 let name=w.nodes.find(n=>/\.(webhook|executeWorkflowTrigger)$/.test(n.type)).name,j=input;
 for(let budget=0;budget<500;budget++){
  const n=nodes[name],p=n.parameters,kind=n.type.split('.').pop();let branch=0;
  if(kind==='code')j=new Function('$input','$execution','$','$getWorkflowStaticData',p.jsCode)({first:()=>({json:j}),all:()=>[{json:j}]},{id:execution},selector,()=>{throw Error('Unexpected static-store fallback');})[0].json;
  else if(kind==='if')branch=expr(p.conditions.conditions[0].leftValue,j)===true?0:1;
  else if(kind==='executeWorkflow')j=run(p.workflowId.value,j,execution);
  else if(kind==='httpRequest'){
   const method=expr(p.method,j),url=expr(p.url,j);
   const headers=Object.fromEntries((p.headerParameters?.parameters||[]).map(v=>[v.name,expr(v.value,j)]));
   const body=p.jsonBody?JSON.parse(expr(p.jsonBody,j)):Object.fromEntries((p.bodyParameters?.parameters||[]).map(v=>[v.name,expr(v.value,j)]));
   j=http(method,url,body,headers);
  }else if(kind==='respondToWebhook')return {...j,actual_response_code:expr(p.options.responseCode,j)};
  else if(!['webhook','executeWorkflowTrigger'].includes(kind))throw Error('Unsupported node '+kind);
  outputs[name]=copy(j);
  const edge=w.connections[name]?.main[branch]||[];
  if(!edge.length){
   if(branch!==0)throw Error('Empty primary output: sub-workflow ended on a secondary branch');
   return copy(j);
  }
  if(edge.length!==1)throw Error('Unexpected fanout');
  name=edge[0].node;
 }
 throw Error('Graph did not terminate');
}
const results=[];
for(const request of spec.requests){
 faults={...request.faults};
 if(request.accountChange)Object.assign(state.account,request.accountChange);
 if(request.extraOwner)state.tickets.push(request.extraOwner);
 const body={...request.body};
 if(body.ticket_id==='$latest')body.ticket_id=state.tickets.at(-1)?.ticket_id;
 const before=state.calls.length;
 results.push({...run(request.workflow,{body},'offline-'+(++seq)),http_calls:state.calls.length-before});
}
process.stdout.write(JSON.stringify({results,tickets:state.tickets,blocks:[...state.blocks],calls:state.calls,account:state.account}));
