import json,sys,time,hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlencode
import s12_runtime as o
from s12_baseline_calc import summarize
from s12_settings import digest

def invoke(run,profile,role):
 p=o.S['paths'];args=['exec','-T',role,'python',p['tools_mount']+'/s12_client.py','--settings',p['settings_mount'],'--run-id',run,'--profile',profile,'--role',role,'--execute']
 result=json.loads(o.compose(*args,timeout=140))
 assert result['status'] in ('input_complete','blocked_observed'),result['status']
 print(run,profile,role,result['status'],len(result['records']),flush=True)
 return result

def webhook(role,body,suffix=''):
 cred=o.C['credentials']['operator' if role in ('release','health') else 'detection']
 path=o.C['release_path'] if role=='release' else o.C['respond_path']+('-health' if role=='health' else suffix)
 return o.http('http://127.0.0.1:'+str(o.S['host_ports']['N8N_PORT'])+'/webhook/'+path,body,{cred['header']:o.V[cred['env']]},timeout=50)

def health():
 code,data=webhook('health',{'case_id':'S12','mode':'sample'})
 assert code==200 and data.get('ok') is True,(code,data)
 return data

def logs(role='attacker',seconds=300):
 q='source:haedam-portal AND event_type:web.request AND src_ip:"'+o.S['addresses'][role]+'"'
 r=o.gl('/search/universal/relative?'+urlencode({'query':q,'range':seconds,'limit':1000,'fields':'timestamp,src_ip,status,event_id,path,duration_ms,gl2_source_input,streams','sort':'timestamp:asc'}))
 return {'at':o.now(),'total':r.get('total_results'),'messages':[x['message'] for x in r.get('messages',[])]}

def tickets():
 base='http://127.0.0.1:'+str(o.S['host_ports']['TICKET_PORT'])+'/api/v1/tickets'
 code,r=o.http(base+'?case_id=S12');assert code==200
 result=[]
 for row in r['items']:
  code,t=o.http(base+'/'+row['ticket_id']);assert code==200;result.append(t['ticket'])
 return result

def events():
 d=json.loads((o.B/'live-state.json').read_text())['definition_id']
 if d is None:return []
 r=o.gl('/events/search',{'query':'event_definition_id:'+d,'timerange':{'type':'relative','range':7200},'page':1,'per_page':100})
 return [x.get('event',x) for x in r.get('events',[])]

def summary(rows):
 return summarize([{'t':datetime.fromisoformat(r['started_at'].replace('Z','+00:00')),'ms':r['ms'],'status':r['status'],'error':r.get('error') or r.get('error_code') or ''} for r in rows])

def baseline():
 assert not (o.B/'baseline.json').exists(),'baseline_already_exists'
 assert not tickets() and not json.loads((o.B/'workload.json').read_text())['enabled']
 assert logs()['total']==0,'fresh baseline source required'
 start=o.now()
 def n8n():
  rows=[]
  for i in range(10):rows.extend(health()['samples'])
  return rows
 with ThreadPoolExecutor(max_workers=3) as pool:
  jobs={role:pool.submit(invoke,RUN_ID,'baseline',role) for role in ('attacker','normal')}
  engine=pool.submit(n8n)
  clients={role:f.result() for role,f in jobs.items()};samples=engine.result()
 assert all(r['status']==200 and r['valid_body'] for c in clients.values() for r in c['records'])
 assert len(samples)==30 and all(r['status']==200 and r['valid_body'] and not r['error'] for r in samples)
 for _ in range(12):
  raw={role:logs(role) for role in clients}
  if all(v['total']==31 for v in raw.values()):break
  time.sleep(5)
 assert all(v['total']==31 and len({r['event_id'] for r in v['messages']})==31 for v in raw.values()),'raw count mismatch'
 report={'case_id':'S12','run_id':RUN_ID,'started_at':start,'finished_at':o.now(),'client_summaries':{k:summary(v['records']) for k,v in clients.items()},'n8n_summary':summary(samples),'n8n_samples':samples,'raw_logs':raw,'measured_while_workload_disabled':True}
 o.save('baseline.json',report)
 s=json.loads((o.B/'settings.json').read_text());s['policy'].update(request_threshold=report['client_summaries']['attacker']['request_threshold_N'],baseline_source=report['run_id'])
 s['health'].update(baseline_ms=report['n8n_summary']['exceed_threshold_ms'],baseline_source=report['run_id'])
 from s12_settings import validate
 validate(s);o.save('settings.json',s)
 m=json.loads((o.B/'bundle.json').read_text());m['settings_sha256']=digest(s);o.save('bundle.json',m)
 print(json.dumps({'request_threshold':s['policy']['request_threshold'],'health_threshold_ms':s['health']['baseline_ms'],'normal':report['client_summaries']['normal'],'n8n':report['n8n_summary']}),flush=True)

def schedule(enabled):
 d=json.loads((o.B/'live-state.json').read_text())['definition_id'];assert d
 o.gl('/events/definitions/'+d+('/schedule' if enabled else '/unschedule'),{},'PUT')

def engine():
 query="SELECT id,workflowId,status,startedAt,stoppedAt FROM execution_entity ORDER BY CAST(id AS INTEGER) DESC LIMIT 30"
 script="const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});console.log(JSON.stringify(db.prepare(process.argv[1]).all()));db.close();"
 return json.loads(o.compose('exec','-T','n8n','node','-e',script,query))

def boundary():
 assert not tickets() and not events() and logs(seconds=60)['total']==0
 schedule(True);invoke(RUN_ID,'probe','attacker')
 checks=[];end=time.monotonic()+o.S['policy']['boundary_observation_seconds']
 while True:
  checks.append({'at':o.now(),'events':len(events()),'tickets':len(tickets()),'count':logs(seconds=60)['total']})
  assert checks[-1]['events']==0 and checks[-1]['tickets']==0
  o.save('boundary-observation.json',{'complete':False,'checks':checks})
  if time.monotonic()>=end:break
  time.sleep(min(15,end-time.monotonic()))
 o.save('boundary-observation.json',{'complete':True,'checks':checks,'scope':'3 requests below N; not an exact N/N+1 live boundary test'})
 print('3 requests; 90-second no-event/no-ticket observation passed',flush=True)

def round_test(controlled=False):
 label=RUN_ID
 assert not tickets() and logs(seconds=60)['total']==0
 baseline=health();assert all(r['status']==200 and r['valid_body'] and r['ms']<=o.S['health']['baseline_ms'] for r in baseline['samples'])
 start=o.now();before_ids={e['id'] for e in events()}
 arm={'enabled':controlled,'armed_at':time.time() if controlled else 0,'expires_at':0}
 if controlled:arm['expires_at']=arm['armed_at']+o.S['workload']['maximum_armed_seconds']
 o.save('workload.json',arm);o.save(label+'-start.json',{'at':start,'workload':arm,'settings':o.S,'health_before':baseline})
 schedule(True)
 with ThreadPoolExecutor(max_workers=2) as pool:
  normal=pool.submit(invoke,label,'monitor','normal');attack=pool.submit(invoke,label,'load','attacker')
  a=attack.result();n=normal.result()
 after=health();ts=tickets();es=[e for e in events() if e['id'] not in before_ids]
 report={'run_id':label,'started_at':start,'finished_at':o.now(),'controlled_resource_contention':controlled,'workload':arm,'health_before':baseline,'health_after':after,'attacker_status':a['status'],'attacker_requests':len(a['records']),'normal_summary':summary(n['records']),'events':es,'tickets':ts,'raw':logs(seconds=180),'engine':engine(),'armed_at_after_probe':controlled and time.time()<arm['expires_at']}
 o.save(label+'-result.json',report)
 if not controlled:
  assert es and not ts and a['status']=='input_complete'
  event=es[-1];body={'case_id':'S12','asset_id':o.S['asset_id'],'src_ip':o.S['addresses']['attacker'],'event_id':event['id'],'detected_at':event['timestamp_processing']}
  code,gate=webhook('respond',body);o.save('healthy-diagnostic-replay.json',{'at':o.now(),'http_status':code,'response':gate,'scope':'diagnostic replay after automatic run'})
  assert code==200 and gate.get('verdict')=='within_baseline' and not tickets()
  print('high volume detected; actual n8n health healthy; no ticket/block',flush=True)
 else:
  schedule(False)
  assert len(ts)==1 and ts[0]['status']=='responding' and a['status']=='blocked_observed','controlled response incomplete'
  assert all(r['status']==200 and r['valid_body'] and r['ms']<=o.S['health']['baseline_ms'] for r in after['samples']) and report['armed_at_after_probe'],'recovery not observed before workload expiry'
  blocked=invoke(label+'b','probe','attacker');normal_probe=invoke(label+'b','probe','normal')
  assert blocked['status']=='blocked_observed' and normal_probe['status']=='input_complete'
  print('automatic block/ticket, normal 200 and recovery before workload expiry verified',flush=True)

def recover():
 schedule(False);ts=tickets();assert len(ts)==1 and ts[0]['status']=='responding' and ts[0]['ticket_id']==TICKET_ID
 assert not any(x['status'] in ('running','waiting','new') for x in engine())
 o.save('workload.json',{'enabled':False,'armed_at':0,'expires_at':0})
 body={'case_id':'S12','asset_id':o.S['asset_id'],'src_ip':o.S['addresses']['attacker'],'ticket_id':ts[0]['ticket_id']}
 code,result=webhook('release',body);o.save('release-response.json',{'at':o.now(),'http_status':code,'response':result})
 assert code==200 and result.get('verdict')=='released'
 for role in ('attacker','normal'):
  probe=invoke(RUN_ID,'probe',role)
  assert probe['status']=='input_complete' and all(x['status']==200 and x['valid_body'] for x in probe['records']),'restored_client_not_healthy'
 ts=tickets();assert len(ts)==1 and ts[0]['status']=='restored'
 restored_health=health()
 assert all(x['status']==200 and x['valid_body'] and x['ms']<=o.S['health']['baseline_ms'] for x in restored_health['samples']),'restored_health_not_within_baseline'
 o.save('restored-ticket.json',ts[0]);o.save('restored-health.json',restored_health)
 print('both clients restored; same ticket restored',flush=True)

if __name__=='__main__':
 import argparse,re
 from pathlib import Path
 p=argparse.ArgumentParser(description='Bounded S12 measurement in an already configured owned bundle.')
 p.add_argument('phase',choices=['baseline','boundary','healthy','controlled','recover'])
 p.add_argument('--bundle',type=Path,required=True);p.add_argument('--run-id',required=True);p.add_argument('--ticket-id')
 a=p.parse_args();RUN_ID=a.run_id;TICKET_ID=a.ticket_id
 if not re.fullmatch(r'[a-z0-9][a-z0-9_]{0,19}',RUN_ID):p.error('run ID must be 1-20 lowercase letters/digits/underscores')
 if a.phase=='recover' and not re.fullmatch(r'T-\d{8}-\d{4}',TICKET_ID or ''):p.error('exact current ticket ID required')
 initialized=False
 try:
  o.initialize(a.bundle);initialized=True
  if not o.S['execution_enabled']:raise ValueError('execution_not_enabled')
  {'baseline':baseline,'boundary':boundary,'healthy':lambda:round_test(False),'controlled':lambda:round_test(True),'recover':recover}[a.phase]()
 except Exception as e:
  if initialized:
   # Stop further trigger input and expire only this bundle's lab workload.
   (o.B/'runs'/o.S['stop_filename']).touch(exist_ok=True)
   o.save('workload.json',{'enabled':False,'armed_at':0,'expires_at':0})
   try:schedule(False)
   except Exception:pass
  print('S12 measurement stopped: '+type(e).__name__+'; keep evidence and inspect the current ticket before release.',flush=True)
  raise SystemExit(1)
