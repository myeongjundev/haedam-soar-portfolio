"""Create a fresh S12 bundle; does not start Docker or change existing services."""
import argparse,hashlib,json,secrets
from pathlib import Path
from s12_settings import ROOT,load,digest
from build_s12_workflows import build,graylog_artifacts

def overlay(s,root,b):
    a,p=s['addresses'],s['paths']
    mounts=[{'type':'bind','source':str(root/'tools'),'target':p['tools_mount'],'read_only':True},
            {'type':'bind','source':str(b/'settings.json'),'target':p['settings_mount'],'read_only':True},
            {'type':'bind','source':str(b/'runs'),'target':p['evidence_mount']}]
    services={'portal':{'environment':{'RESPONSE_API_KEY':'${PORTAL_RESPONSE_KEY:?S12 local key required}',
       'RESPONSE_ALLOWED_CIDRS':a['n8n_response']+'/32','HAEDAM_S12_LAB':'1','S12_SETTINGS_FILE':p['settings_mount'],
       'S12_WORKLOAD_FILE':'/run/s12/workload.json','PYTHONPATH':'/app/src:'+p['tools_mount']+':/opt/s12-target'},
       'command':['sh','-ec','flask --app lab_app:create_app db upgrade && exec waitress-serve --threads=8 --host=0.0.0.0 --port=5000 --call lab_app:create_app'],
       'volumes':[mounts[0],mounts[1],{'type':'bind','source':str(root/'services/s12-target'),'target':'/opt/s12-target','read_only':True},
                  {'type':'bind','source':str(b/'workload.json'),'target':'/run/s12/workload.json','read_only':True}],
       'networks':{'default':{},'s12-clients':{'ipv4_address':a['portal_client']},'s12-response':{'ipv4_address':a['portal_response'],'aliases':['portal-response']}}},
      'n8n':{'environment':{'N8N_CONCURRENCY_PRODUCTION_LIMIT':'1','EXECUTIONS_DATA_SAVE_ON_SUCCESS':'none','EXECUTIONS_DATA_SAVE_ON_ERROR':'none','EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS':'false','EXECUTIONS_DATA_SAVE_ON_PROGRESS':'false','EXECUTIONS_DATA_PRUNE':'false'},
       'networks':{'default':{},'s12-response':{'ipv4_address':a['n8n_response']}}}}
    for name in ('attacker','normal'):
        services[name]={'image':s['client_image'],'init':True,'command':['python','-c','import time; time.sleep(2147483647)'],
          'environment':{'HAEDAM_S12_PROJECT':s['project'],'HAEDAM_S12_ROLE':name},'labels':{'haedam.case':'S12'},
          'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
          'networks':{'s12-clients':{'ipv4_address':a[name]}},'volumes':mounts}
    services['observer']={'profiles':['s12-evidence'],'image':s['client_image'],'init':True,
      'command':['python','-c','import time; time.sleep(2147483647)'],'network_mode':'service:n8n',
      'environment':{'HAEDAM_S12_PROJECT':s['project'],'HAEDAM_S12_ROLE':'observer'},'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'volumes':mounts}
    nets={name:{'internal':s['network_internal'][key],'ipam':{'config':[{'subnet':s['networks'][key]}]}} for key,name in [('default','default'),('clients','s12-clients'),('response','s12-response'),('graylog_backend','graylog-backend')]}
    return {'name':s['project'],'services':services,'networks':nets}

def create(s,out):
    s,c=load(s);out=out.resolve()
    if not out.is_relative_to(ROOT/'.local') or out==ROOT/'.local':raise ValueError('local_new_bundle_required')
    out.mkdir(parents=True,exist_ok=False);(out/'runs').mkdir()
    env={k:secrets.token_hex(32) for k in ('MYSQL_ROOT_PASSWORD','MYSQL_PASSWORD','GRAYLOG_ADMIN_PASSWORD','N8N_ENCRYPTION_KEY','TICKET_STORE_KEY','PORTAL_RESPONSE_KEY','S12_DETECTION_KEY','S12_OPERATOR_KEY')}
    env['GRAYLOG_PASSWORD_SECRET']=secrets.token_hex(48);env['GRAYLOG_ROOT_PASSWORD_SHA2']=hashlib.sha256(env['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest();env.update({k:str(v) for k,v in s['host_ports'].items()})
    (out/'lab.env').write_text('\n'.join(k+'='+v for k,v in env.items())+'\n',encoding='utf-8');(out/'lab.env').chmod(0o600)
    argv=['docker','compose','--project-directory',str(ROOT),'--env-file',str(out/'lab.env'),'-p',s['project'],'-f',str(ROOT/'compose.yaml'),'-f',str(ROOT/'compose.soc.yaml'),'-f',str(out/'compose.s12.json')]
    files={'settings.json':s,'integration-settings.json':c,'compose.s12.json':overlay(s,ROOT,out),'workload.json':{'enabled':False,'armed_at':0,'expires_at':0},
      'graylog-integration.template.json':graylog_artifacts(s,c),'bundle.json':{'case_id':'S12','compose_argv':argv,'settings_sha256':digest(s),'clear_process_env_before_future_compose':sorted(env),'runtime_verified':False}}
    for name,value in files.items():(out/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--settings',type=Path,default=ROOT/'infra/s12-settings.json');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps({'created':str(create(json.loads(a.settings.read_text(encoding='utf-8-sig')),a.output)),'runtime_verified':False}))
