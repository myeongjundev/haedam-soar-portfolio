// Derived from personal S1 ownership/release flow; S12 policy remains separate.
// CFG is injected by the offline builder, never taken from a webhook body.
const out = j => [{json:j}];
const held = (verdict, status=409) => out({ok:false,proceed:false,verdict,http_status:status});
const idOK = v => typeof v==='string' && /^T-\d{8}-\d{4}$/.test(v);
const states = ['open','responding','verified','restored','closed'];
const activeOK = a => a && a.bot==='112' && a.via==='portal' && a.action==='block' && a.target===CFG.ip && ['applied','already_applied'].includes(a.result);
const snapshotOK = j => j.ok===true && typeof j.exists==='boolean' && Array.isArray(j.actions) && j.actions.every(activeOK) &&
  (j.exists ? idOK(j.ticket_id) && states.includes(j.status) : j.ticket_id===null && j.status===null && j.actions.length===0);
const resource = () => ({asset_id:CFG.asset_id,via:'portal',action:'block',target:CFG.ip});
const next = j => out({...j,proceed:true});
const check = ctx => next({mode:'check',seat:'D',group_key:ctx.group_key,ctx});
const ownership = ctx => next({mode:'active',resource:resource(),ctx});
const list = ctx => next({action:'list',dry_run:false,ip:CFG.ip,ctx});
const record = (ctx,stage,execution,action=null) => next({ctx,mode:'record',stage,seat:'D',case_id:'S12',
  group_key:ctx.group_key,title:'S12 request volume and observed service delay',asset_id:CFG.asset_id,src_ip:CFG.ip,
  event_ids:[ctx.event_id || `s12-release-${execution}`],detected_at:ctx.detected_at || null,
  received_at:ctx.received_at || null,idempotency_key:`s12-${execution}-${stage}`,action});

function run(stage,j,execution) {
 const x=j.ctx;
 if(stage==='validate_response' || stage==='validate_release') {
  const b=j.body,release=stage==='validate_release';
  const keys=release?['case_id','asset_id','src_ip','ticket_id']:['case_id','asset_id','src_ip','event_id','detected_at'];
  if(!b || typeof b!=='object' || Array.isArray(b) || Object.keys(b).length!==keys.length || keys.some(k=>typeof b[k]!=='string')) return held('invalid_input',400);
  if(b.case_id!=='S12' || b.asset_id!==CFG.asset_id || b.src_ip!==CFG.ip) return held('invalid_scope',400);
  if(release && !idOK(b.ticket_id)) return held('invalid_ticket_id',400);
  if(!release) {
   if(!/^[A-Za-z0-9_-]{1,128}$/.test(b.event_id) || !/T.*(Z|[+-]\d\d:\d\d)$/.test(b.detected_at)) return held('invalid_event',400);
   const age=Date.now()-Date.parse(b.detected_at);
   if(!Number.isFinite(age) || age < -CFG.future_clock_tolerance_seconds*1000 || age>CFG.event_max_age_seconds*1000) return held('stale_or_future_event',400);
   if(!CFG.detection_enabled) return held('held_detection_disabled');
  }
  return check({cfg:{dry_run:false,store_real:true},seat:'D',case_id:'S12',asset_id:CFG.asset_id,src_ip:CFG.ip,
    group_key:`S12|${CFG.ip}`,event_id:b.event_id,detected_at:b.detected_at,
    received_at:release?undefined:new Date().toISOString(),requested_ticket_id:b.ticket_id,
    approver:release?CFG.operator_name:undefined,release});
 }
 if(stage==='snapshot') {
  if(!snapshotOK(j)) return held('held_ticket_check',503);
  if(j.actions.length>1 || (['closed','restored'].includes(j.status) && j.actions.length)) return held('held_inconsistent_ticket');
  if(x.release && (!j.exists || j.ticket_id!==x.requested_ticket_id)) return held('held_stale_release_ticket');
  return ownership({...x,snapshot:{exists:j.exists,ticket_id:j.ticket_id,status:j.status,actions:j.actions}});
 }
 if(stage==='owners' || stage==='owners_before_block') {
  const r=resource();
  if(j.ok!==true || !j.resource || Object.keys(j.resource).length!==4 || !Object.keys(r).every(k=>j.resource[k]===r[k]) || !Array.isArray(j.tickets) || !j.tickets.every(t=>idOK(t.ticket_id) && ['A','B','C','D'].includes(t.seat) && states.includes(t.status) && Array.isArray(t.active_actions) && t.active_actions.length>0 && t.active_actions.every(a=>a.via==='portal' && a.action==='block' && a.target===CFG.ip && typeof a.bot==='string'))) return held('held_resource_check',503);
  const own=x.snapshot.actions.length===1;
  if(j.tickets.some(t=>t.ticket_id!==x.snapshot.ticket_id || t.seat!=='D' || t.active_actions.some(a=>a.bot!=='112'))) return held('held_other_resource_ticket');
  if(own !== (j.tickets.length===1)) return held('held_claim_mismatch');
  return list(x);
 }
 if(stage==='portal_before' || stage==='portal_before_block') {
  if(j.ok!==true || j.result!=='listed' || !Array.isArray(j.items) || !j.items.every(i=>i && typeof i.ip==='string')) return held('held_portal_readback',503);
  const blocked=j.items.some(i=>i.ip===CFG.ip),own=x.snapshot.actions.length===1;
  if(x.release) {
   if(!own) return blocked?held('held_unowned_portal_block'):out({ok:true,no_action:true,verdict:'nothing_to_release',ticket_id:x.snapshot.ticket_id,http_status:200});
   return next({ctx:{...x,ticket_id:x.snapshot.ticket_id},ticket_id:x.snapshot.ticket_id,action:'unblock',ip:CFG.ip,dry_run:false});
  }
  if(own) return blocked ? record({...x,duplicate_active:true},'detected',execution) : held('held_claim_state_drift');
  if(blocked) return held('held_unowned_portal_block');
  if(stage==='portal_before_block') return next({ctx:x,ticket_id:x.ticket_id,action:'block',ip:CFG.ip,dry_run:false});
  return next({ctx:x,health_required:true});
 }
 if(stage==='health_result') {
  if(j.health?.verdict!=='exceeded') return out({ok:true,proceed:false,no_action:true,verdict:j.health?.verdict||'invalid_health',health:j.health,http_status:200});
  return record({...x,health:j.health},'detected',execution);
 }
 if(stage==='detected_ack') {
  if(j.ok!==true || !idOK(j.ticket_id) || !states.includes(j.status)) return held('held_ticket_record',503);
  if(['restored','closed'].includes(j.status)) return j.duplicate===true?out({ok:true,no_action:true,verdict:'old_event_no_action',ticket_id:j.ticket_id,http_status:200}):held('held_ticket_cycle');
  if(x.snapshot.exists && x.snapshot.status!=='restored' && j.ticket_id!==x.snapshot.ticket_id) return held('held_ticket_changed');
  if(x.duplicate_active) return ['responding','verified'].includes(j.status)?out({ok:true,no_action:true,verdict:'duplicate_no_action',ticket_id:j.ticket_id,http_status:200}):held('held_ticket_changed');
  if(x.snapshot.status==='restored' && j.ticket_id===x.snapshot.ticket_id) return held('held_ticket_cycle');
  return check({...x,ticket_id:j.ticket_id});
 }
 if(stage==='current_before_block') {
  if(!snapshotOK(j) || !j.exists || j.ticket_id!==x.ticket_id || !['open','responding','verified'].includes(j.status) || j.actions.length) return held('held_ticket_changed');
  return ownership({...x,snapshot:{exists:true,ticket_id:j.ticket_id,status:j.status,actions:[]}});
 }
 if(stage==='block_result') {
  const allowed=['applied','already_applied','failed','rejected'];
  const result=allowed.includes(j.result)?j.result:'failed';
  const verified=j.applied_verified===true;
  return record({...x,response_verified:verified && ['applied','already_applied'].includes(result)},'applied',execution,
   {bot:'112',via:'portal',action:'block',target:CFG.ip,result,applied_verified:j.applied_verified??null,
    effect_verified:null,effect_verified_at:null,requested_at:j.requested_at,finished_at:j.finished_at,
    n8n_execution_id:execution,detail:JSON.stringify({verified,health:x.health?{verdict:x.health.verdict,baseline_ms:x.health.baseline_ms,samples:x.health.samples.map(s=>[s.ms,s.status,s.classification])}:null})});
 }
 if(stage==='applied_ack') {
  if(j.ok!==true || j.ticket_id!==x.ticket_id || !states.includes(j.status)) return held('held_applied_record_reconcile',503);
  const ok=x.response_verified===true && ['responding','verified'].includes(j.status);
  return out({ok,verdict:ok?'responded':'held_response_unverified',http_status:ok?200:503,
    ticket_id:j.ticket_id,ticket_status:j.status,applied_verified:ok,effect_verified:null});
 }
 if(stage==='release_result') {
  if(j.ok!==true || !['released','already_applied'].includes(j.result) || j.applied_verified!==true) return held('held_release_unverified',503);
  return record(x,'released',execution,{bot:'112',via:'portal',action:'unblock',target:CFG.ip,result:'released',
   applied_verified:true,effect_verified:null,effect_verified_at:null,requested_at:j.requested_at,finished_at:j.finished_at,
   n8n_execution_id:execution,detail:`operator ${CFG.operator_name}; portal absence verified`});
 }
 if(stage==='released_ack') {
  if(j.ok!==true || j.ticket_id!==x.ticket_id || j.status!=='restored') return held('held_release_record_reconcile',503);
  return check(x);
 }
 if(stage==='final_ticket') {
  if(!snapshotOK(j) || !j.exists || j.ticket_id!==x.ticket_id || j.status!=='restored' || j.actions.length) return held('held_final_ticket',503);
  return list(x);
 }
 if(stage==='final_portal') {
  if(j.ok!==true || j.result!=='listed' || !Array.isArray(j.items) || !j.items.every(i=>i && typeof i.ip==='string') || j.items.some(i=>i.ip===CFG.ip)) return held('held_final_portal',503);
  return out({ok:true,verdict:'released',http_status:200,ticket_id:x.ticket_id,ticket_status:'restored',applied_verified:true,effect_verified:null});
 }
 return held('unknown_stage',503);
}
