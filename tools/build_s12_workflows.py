"""S12 artifacts reuse reviewed ticket/IP adapters; health and load policy stay separate."""
import argparse,json,re
from copy import deepcopy
from pathlib import Path
import build_s1_workflows as base
from n8n_layout import tidy_all
from s12_settings import ROOT,load
from s12_health import COMMON

IDS={k:v.replace('S1','S12') for k,v in base.IDS.items()}
IDS['health']='portfolioS12Health01'
def cfg(s,c):
    h=s['health']
    return {**{k:c[k] for k in ('detection_enabled','operator_name','event_max_age_seconds','future_clock_tolerance_seconds')},
      'ip':s['addresses']['attacker'],'asset_id':s['asset_id'],'health_url':c['portal_url']+s['paths']['health'],
      'baseline_ms':h['baseline_ms'],'baseline_source':h['baseline_source'],'health_k':h['k'],
      'health_interval_ms':h['interval_ms'],'health_timeout_ms':h['timeout_ms']}

def health_code(s,c,probe=False):
    config=cfg(s,c)
    prefix='const CFG = '+json.dumps(config)+';\n'+COMMON
    if probe:
        return prefix+"""
const b=$input.first().json.body;
if(!b || Object.keys(b).length!==2 || b.case_id!=='S12' || b.mode!=='sample') return [{json:{ok:false,http_status:400}}];
const samples=[];
for(let i=0;i<CFG.health_k;i++) {
 const v=await healthSample.call(this,{...CFG,baseline_ms:0});
 samples.push({started_at:v.started_at,finished_at:v.finished_at,ms:v.ms,status:v.status,error:v.error,valid_body:['slow_success','healthy'].includes(v.classification)});
 if(i<CFG.health_k-1) await new Promise(r=>setTimeout(r,CFG.health_interval_ms));
}
return [{json:{ok:true,scope:'actual_n8n_to_portal',samples,http_status:200}}];
"""
    return prefix+"""
const j=$input.first().json;if(!j.health_required)return [{json:j}];
const samples=[];let verdict=healthConfig(CFG);
if(!verdict) {
 for(let i=0;i<CFG.health_k;i++) {
  samples.push(await healthSample.call(this,CFG));
  if(i<CFG.health_k-1)await new Promise(r=>setTimeout(r,CFG.health_interval_ms));
 }
 verdict=samples.every(s=>s.degraded)?'exceeded':samples.every(s=>s.ok)?'within_baseline':'inconclusive';
}
return [{json:{...j,health:{scope:'actual_n8n_to_portal',samples,baseline_ms:CFG.baseline_ms,baseline_source:CFG.baseline_source,k:CFG.health_k,verdict,effect_verified:null}}}];
"""

def build(settings=None,integration=None):
    s,c=load(settings,integration);out={}
    for role in ('ticket','portal'):
        w=base.common_workflow(role,c,s);w['id']=IDS[role];w['name']='[Portfolio S12] '+role
        # Only the adapter label changes; its address allowlist already comes from S12 settings.
        out['s12-'+role+'.json']=w
    source=(ROOT/'infra/n8n/s12-src/flow.js').read_text(encoding='utf-8')
    for role in ('respond','release'):
        w=base.flow(role,{**s,'username_prefix':''},c);w['id']=IDS[role];w['name']='[Portfolio S12] '+role
        for n in w['nodes']:
            if n['type'].endswith('.code'):
                stage=re.search(r'return run\(("[a-z_]+"), \$input',n['parameters']['jsCode']).group(1)
                n['parameters']['jsCode']='const CFG = '+json.dumps(cfg(s,c))+';\n'+source+'\nreturn run('+stage+', $input.first().json, String($execution.id));'
            if n['type'].endswith('.executeWorkflow'):
                p=n['parameters']['workflowId'];p['value']=p['value'].replace('S1','S12')
        if role=='respond':
            for name,code in [('Health samples',health_code(s,c)),('Health result','const CFG = '+json.dumps(cfg(s,c))+';\n'+source+'\nreturn $input.first().json.health_required ? run("health_result",$input.first().json,String($execution.id)) : $input.all();')]:
                w['nodes'].append({'id':'s12-'+name,'name':name,'type':'n8n-nodes-base.code','typeVersion':2,'position':[0,0],'parameters':{'jsCode':code}})
            gate=deepcopy(next(n for n in w['nodes'] if n['name']=='Portal before proceed'));gate.update(id='s12-health-gate',name='Health proceed');w['nodes'].append(gate)
            def edge(n):return {'node':n,'type':'main','index':0}
            w['connections']['Portal before proceed']['main'][0]=[edge('Health samples')]
            w['connections']['Health samples']={'main':[[edge('Health result')]]}
            w['connections']['Health result']={'main':[[edge('Health proceed')]]}
            w['connections']['Health proceed']={'main':[[edge('Portal before API')],[edge('Respond')]]}
        out['s12-'+role+'.json']=w
    probe=deepcopy(out['s12-respond.json']);probe.update(id=IDS['health'],name='[Portfolio S12] baseline health probe')
    hook=deepcopy(probe['nodes'][0]);hook['parameters']['path']=c['respond_path']+'-health';hook['webhookId']=hook['parameters']['path']
    cred=c['credentials']['operator']['id'];hook['credentials']={'httpHeaderAuth':{'id':cred,'name':cred}}
    finish=deepcopy(next(n for n in probe['nodes'] if n['name']=='Respond'))
    probe['nodes']=[hook,{'id':'s12-baseline-health','name':'Sample health','type':'n8n-nodes-base.code','typeVersion':2,'position':[300,0],'parameters':{'jsCode':health_code(s,c,True)}},finish]
    probe['connections']={'Webhook':{'main':[[{'node':'Sample health','type':'main','index':0}]]},'Sample health':{'main':[[{'node':'Respond','type':'main','index':0}]]}}
    out['s12-health.json']=probe
    return tidy_all(out)

def graylog_artifacts(s,c,bindings=None):
    spec=base.graylog_artifacts({**s,'username_prefix':''},c,bindings)
    d=json.loads((ROOT/'lab/s12/graylog/s12-request-flood.json').read_text(encoding='utf-8'))
    d['title']=s['project']+' S12 measured request volume';d['description']='Personal measured threshold; health gate is independently evaluated in n8n. Keep disabled until baseline is supplied.'
    d['config']['query']='source:haedam-portal AND event_type:web.request AND src_ip:"'+s['addresses']['attacker']+'"'
    d['config']['conditions']['expression']['right']['value']=s['policy']['request_threshold']
    d['config']['streams']=spec['definition']['config']['streams'];d['notifications']=spec['definition']['notifications']
    d['notification_settings']['backlog_size']=0
    spec['definition']=d;spec['baseline_required']=s['policy']['request_threshold'] is None
    spec['notification']['title']=s['project']+' authenticated S12';spec['notification']['description']='Personal S12 with measured health gate'
    spec['notification']['config']['body_template']=json.dumps({'case_id':'S12','asset_id':s['asset_id'],'src_ip':'${event.fields.src_ip}','event_id':'${event.id}','detected_at':'${event.timestamp_processing}'})
    spec['required_message_fields']=['source','event_type','src_ip'];spec['url_allowlist'].update(id='portfolio-s12',title='S12 webhook')
    return spec

def materialize(s,c,bindings,secrets):
    s,c=load(s,c);expected={v['env'] for v in c['credentials'].values()}
    if set(secrets)!=expected or any(not re.fullmatch(r'[a-f0-9]{64}',v) for v in secrets.values()) or len(set(secrets.values()))!=4:raise ValueError('distinct_keys_required')
    spec=graylog_artifacts(s,c,bindings);spec['notification']['config']['api_secret']=secrets[c['credentials']['detection']['env']]
    return {'graylog':spec,'workflows':list(build(s,c).values()),'credentials':[{'id':v['id'],'name':v['id'],'type':'httpHeaderAuth','data':{'name':v['header'],'value':secrets[v['env']]}} for v in c['credentials'].values()]}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args();s,c=load()
    files={ROOT/'infra/n8n/portfolio-s12'/k:v for k,v in build(s,c).items()};files[ROOT/'infra/graylog/portfolio-s12.json']=graylog_artifacts(s,c)
    for path,v in files.items():
        text=json.dumps(v,ensure_ascii=False,indent=2)+'\n'
        if a.check:
            if not path.exists() or path.read_text(encoding='utf-8')!=text:raise SystemExit('S12 generated artifact differs')
        else:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')
    print('S12: 5 workflows and Graylog template checked/generated; no deployment')
