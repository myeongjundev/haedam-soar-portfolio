// Narrow account adapter. All URLs and credential references come from the builder.
const out = j => [{json:j}];
function validState(d) {
 return d && Number.isSafeInteger(d.user_id) && d.user_id>0 && d.username===CFG.username &&
  typeof d.locked==='boolean' && Number.isSafeInteger(d.active_sessions) && d.active_sessions>=0 &&
  (d.owner_ticket_id===null || /^T-\d{8}-\d{4}$/.test(d.owner_ticket_id));
}
function run(stage,j) {
 if(stage==='prepare') {
  const valid=j.ctx?.username===CFG.username && ['list','lock','unlock'].includes(j.action) &&
   (j.action==='list' || Number.isSafeInteger(j.ctx?.user_id) && j.ctx.user_id>0 && /^T-\d{8}-\d{4}$/.test(j.ticket_id));
  const read_url=CFG.portal_url+'/api/v1/response/s4/accounts/'+encodeURIComponent(CFG.username);
  const data=j.action==='list'?{}:{user_id:j.ctx.user_id,ticket_id:j.ticket_id,...(j.action==='unlock'?{reason_code:'false_positive'}:{})};
  return out({...j,valid,read_url,url:read_url+(j.action==='list'?'':'/'+j.action),data,
   idempotency_key:`s4-${j.ticket_id}-${j.ctx?.user_id}-${j.action}`,requested_at:new Date().toISOString()});
 }
 if(stage==='invalid') return out({ctx:j.ctx,ok:false,result:'rejected',applied_verified:false,requested_at:null,finished_at:null});
 if(stage==='done') return out(j);
 if(stage==='classify') {
  const p=$('Prepare').first().json,d=j.body?.data;
  const responseValid=j.statusCode===200 && j.body?.success===true && validState(d);
  if(p.action==='list') return out({ctx:p.ctx,ok:responseValid,result:responseValid?'listed':'failed',account:responseValid?d:null,needs_readback:false});
  return out({...p,mutation_ok:responseValid && typeof d.changed==='boolean' && d.user_id===p.ctx.user_id,
    needs_readback:true});
 }
 if(stage==='verify') {
  const p=$('Classify').first().json,d=j.body?.data;
  const readable=j.statusCode===200 && j.body?.success===true && validState(d) && d.user_id===p.ctx.user_id;
  const verified=readable && (p.action==='lock' ? d.locked && d.active_sessions===0 && d.owner_ticket_id===p.ticket_id : !d.locked && d.owner_ticket_id===null);
  // A lost response can be recovered from an atomic, ticket-bound portal claim.
  // Preserve an acknowledged mutation even if readback fails, so its ticket keeps ownership.
  const applied=p.mutation_ok || verified;
  return out({ctx:p.ctx,ok:verified,result:applied?(p.action==='lock'?'applied':'released'):'failed',
    applied_verified:readable?verified:null,effect_verified:null,requested_at:p.requested_at,finished_at:new Date().toISOString()});
 }
 return out({ok:false,result:'rejected'});
}
