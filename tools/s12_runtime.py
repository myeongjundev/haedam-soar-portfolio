"""One owned S12 bundle per process. No existing-environment stop/start operations."""
import base64,ipaddress,json,os,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from s12_settings import ROOT,load,digest
from s12_lab import overlay

def initialize(bundle):
 global B,S,C,M,V,ENV
 B=Path(bundle).resolve()
 if not B.is_relative_to(ROOT/'.local') or B==ROOT/'.local':raise ValueError('owned_local_bundle_required')
 S,C=load(json.loads((B/'settings.json').read_text()),json.loads((B/'integration-settings.json').read_text()))
 M=json.loads((B/'bundle.json').read_text())
 expected=['docker','compose','--project-directory',str(ROOT),'--env-file',str(B/'lab.env'),'-p',S['project'],'-f',str(ROOT/'compose.yaml'),'-f',str(ROOT/'compose.soc.yaml'),'-f',str(B/'compose.s12.json')]
 if M['case_id']!='S12' or M['compose_argv']!=expected or M['settings_sha256']!=digest(S):raise ValueError('bundle_drift')
 if json.loads((B/'compose.s12.json').read_text())!=overlay(S,ROOT,B):raise ValueError('overlay_drift')
 V={}
 for line in (B/'lab.env').read_text().splitlines():
  key,value=line.split('=',1)
  if key in V:raise ValueError('duplicate_env_key')
  V[key]=value
 if sorted(V)!=M['clear_process_env_before_future_compose']:raise ValueError('env_manifest_drift')
 if any(V.get(k)!=str(v) for k,v in S['host_ports'].items()):raise ValueError('port_drift')
 ENV={k:v for k,v in os.environ.items() if k not in V}

def now():return datetime.now(timezone.utc).isoformat()
def save(name,data):
 (B/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
def scrub(value):
 values=list(V.values())
 for name in ('passwords.json','n8n-owner.private.json'):
  if (B/name).exists():values.extend(json.loads((B/name).read_text()).values())
 for v in values:
  if isinstance(v,str) and len(v)>10:value=value.replace(v,'[REDACTED]')
 return value
def run(argv,timeout=120,stdin=None):
 r=subprocess.run(argv,cwd=ROOT,env=ENV,input=stdin,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
 if r.returncode:raise RuntimeError(scrub(r.stderr[-2500:]+r.stdout[-1000:]))
 return r.stdout
def compose(*args,timeout=120,stdin=None):return run(M['compose_argv']+list(args),timeout,stdin)
def http(url,data=None,headers=None,method=None,timeout=20):
 headers={'Accept':'application/json',**(headers or {})}
 if data is not None:headers['Content-Type']='application/json'
 q=Request(url,data=None if data is None else json.dumps(data).encode(),headers=headers,method=method)
 try:r=urlopen(q,timeout=timeout)
 except HTTPError as e:r=e
 with r:
  raw=r.read()
  try:body=json.loads(raw) if raw else {}
  except ValueError:body={'non_json':True}
  return r.status,body
def gl(path,data=None,method=None):
 auth=base64.b64encode(('admin:'+V['GRAYLOG_ADMIN_PASSWORD']).encode()).decode()
 code,body=http('http://127.0.0.1:'+str(S['host_ports']['GRAYLOG_PORT'])+'/api'+path,data,
 {'Authorization':'Basic '+auth,'X-Requested-By':'s12-personal-live'},method)
 if code not in (200,201,202,204):raise RuntimeError('Graylog '+path+' HTTP '+str(code)+' '+scrub(json.dumps(body))[:1000])
 return body
def state(ids=None):
 ids=ids or run(['docker','ps','-aq']).split()
 raw=json.loads(run(['docker','inspect',*ids])) if ids else []
 return [dict(id=x['Id'],name=x['Name'].lstrip('/'),project=(x['Config'].get('Labels') or {}).get('com.docker.compose.project'),
 running=x['State']['Running'],status=x['State']['Status'],started_at=x['State']['StartedAt'],
 health=x['State'].get('Health',{}).get('Status'),restart_count=x['RestartCount'],oom=x['State']['OOMKilled']) for x in raw]
