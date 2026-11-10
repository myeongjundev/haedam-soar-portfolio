"""Shared n8n health sampling; emits code only, never performs network calls."""

COMMON = r"""
function healthConfig(c) {
 if (c.baseline_ms === null || c.baseline_ms === undefined) return 'no_baseline';
 if (typeof c.baseline_source!=='string' || !/^[A-Za-z0-9._:-]{1,120}$/.test(c.baseline_source) ||
     !Number.isFinite(c.baseline_ms) || c.baseline_ms <= 0 ||
     !Number.isFinite(c.health_timeout_ms) || c.health_timeout_ms <= c.baseline_ms || c.health_timeout_ms > 30000 ||
     !Number.isInteger(c.health_k) || c.health_k < 1 || c.health_k > 10 ||
     !Number.isFinite(c.health_interval_ms) || c.health_interval_ms <= 0 || c.health_interval_ms > 30000)
  return 'invalid_health_config';
 return null;
}
async function healthSample(c) {
 const started=Date.now();let status=null,body=null,error=null;
 try {
  const r=await this.helpers.httpRequest({method:'GET',url:c.health_url,timeout:c.health_timeout_ms,
   returnFullResponse:true,ignoreHttpStatusCodes:true,json:true});
  status=Number.isInteger(r.statusCode)?r.statusCode:null;body=r.body;
 } catch(e) {
  // Fixed codes only: a library error message may contain request/authentication data.
  error=['ETIMEDOUT','ESOCKETTIMEDOUT','ECONNABORTED'].includes(e?.code)||e?.name==='TimeoutError'?'timeout':
   e?.name==='SyntaxError'?'invalid_body':'network_error';
 }
 const ms=Math.max(0,Date.now()-started);
 let classification=error;
 if (!classification) {
  if (status>=500) classification='server_error';
  else if (status!==200) classification='unexpected_status';
  else if (body?.success!==true || body?.data?.status!=='ok') classification='invalid_body';
  else classification=ms>c.baseline_ms?'slow_success':'healthy';
 }
 return {started_at:new Date(started).toISOString(),finished_at:new Date().toISOString(),ms,status,error,
  classification,ok:classification==='healthy',
  degraded:['slow_success','timeout','network_error','server_error'].includes(classification)};
}
"""

DETECT = COMMON + r"""
const x=$input.first().json.ctx,c=x.cfg,samples=[];
let verdict=healthConfig(c);
if (!verdict) {
 for(let i=0;i<c.health_k;i++) {
  samples.push(await healthSample.call(this,c));
  if(i<c.health_k-1)await new Promise(r=>setTimeout(r,c.health_interval_ms));
 }
 verdict=samples.every(s=>s.degraded)?'exceeded':samples.every(s=>s.ok)?'within_baseline':'inconclusive';
}
const health={scope:'vpn_health_only',samples,baseline_ms:c.baseline_ms,baseline_source:c.baseline_source||null,
 interval_ms:c.health_interval_ms,timeout_ms:c.health_timeout_ms,k:c.health_k,verdict,
 normal_user_path_verified:null,effect_verified:null};
return [{json:{verdict,event_id:x.event_id,asset_id:x.asset_id,src_ip:x.src_ip,health,ctx:{...x,health}}}];
"""

RECOVER = COMMON + r"""
const x=$input.first().json.ctx,c=x.cfg;
const invalid=healthConfig(c);
if(invalid)return [{json:{noop:true,reason:invalid,recovered:null,effect_verified:null,ctx:x}}];
const budget=c.recover_timeout_ms??60000;
if(!Number.isFinite(budget)||budget<=0||budget>300000)
 return [{json:{noop:true,reason:'invalid_recovery_config',recovered:null,effect_verified:null,ctx:x}}];
const deadline=Date.now()+budget,samples=[];let streak=0;
// Do not start a request which cannot finish within the observation deadline.
while(deadline-Date.now()>=c.health_timeout_ms && streak<c.health_k) {
 const sample=await healthSample.call(this,c);samples.push(sample);streak=sample.ok?streak+1:0;
 if(streak<c.health_k && deadline-Date.now()>c.health_interval_ms)
  await new Promise(r=>setTimeout(r,c.health_interval_ms));
}
const recovered=streak>=c.health_k;
// VPN recovery does not prove recovery from a normal user's separate access path.
return [{json:{noop:!c.dry_run,reason:c.dry_run?'synthetic_recovery':'external_effect_evidence_required',
 recovered,effect_verified:null,ctx:{...x,recovery:{recovered,scope:'vpn_health_only',
 normal_user_path_verified:null,effect_verified:null,sample_count:samples.length,
 truncated:samples.length>100,samples:samples.slice(-100)}}}}];
"""
