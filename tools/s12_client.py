"""Bounded source-bound S12 input. Default plan only, no redirects/retries/response API."""
import argparse
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
import hashlib,json,os,re,sys,time
from pathlib import Path
from s1_client import Transport,save,now
from s12_settings import validate,digest

def plan(s,run_id,profile,role):
    validate(s)
    if not re.fullmatch(r'[a-z0-9][a-z0-9_]{0,23}',run_id):raise ValueError('run_id')
    if profile not in ('baseline','load','probe','monitor') or role not in ('attacker','normal'):raise ValueError('profile_role')
    if profile=='load' and role!='attacker' or profile=='monitor' and role!='normal':raise ValueError('profile_role')
    return {'case_id':'S12','run_id':run_id,'profile':profile,'role':role,'project':s['project'],'settings_sha256':digest(s),
      'source_ip':s['addresses'][role],'target_ip':s['addresses']['portal_client'],'target_port':s['portal_internal_port'],
      'mode':'plan_only','maximum_requests':s['load']['maximum_requests'] if profile=='load' else 31 if profile=='baseline' else 3 if profile=='probe' else s['load']['maximum_duration_seconds']+10,
      'end_to_end_status':'not_run'}

def guard(s,role):
    if not s['execution_enabled'] or sys.platform!='linux' or not Path('/.dockerenv').exists():raise ValueError('owned_enabled_container_required')
    if os.environ.get('HAEDAM_S12_PROJECT')!=s['project'] or os.environ.get('HAEDAM_S12_ROLE')!=role:raise ValueError('project_role_mismatch')

def execute(s,run_id,profile,role,output,*,transport=Transport,runtime=guard):
    p=plan(s,run_id,profile,role);runtime(s,role)
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    path=output/(run_id+'-'+profile+'-'+role+'.json');stop=output/s['stop_filename'];lock=output/(role+'.lock');owned=False;created=False
    out={**p,'mode':'actual_http_input','status':'running','started_at':now(),'records':[],
      'source_sha256':{n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in ('s12_client.py','s12_settings.py','s1_client.py')}}
    def one():
        if stop.exists():return None
        kind='work' if profile=='load' else 'normal' if profile in ('probe','monitor') and role=='normal' else 'health'
        start,mono=now(),time.monotonic()
        try:
            status,body,source=transport(s,p).request(s['paths'][kind])
            if source!=p['source_ip']:raise ValueError('source_mismatch')
            data=body.get('data',{});code=body.get('error',{}).get('code')
            valid=body.get('success') is True and (data.get('status')=='ok' if kind=='health' else isinstance(data.get('categories'),list) if kind=='normal' else data.get('lab')=='S12')
            return {'started_at':start,'finished_at':now(),'ms':round((time.monotonic()-mono)*1000,3),'status':status,'source_ip':source,'operation':kind,'valid_body':valid,'error_code':'IP_BLOCKED' if code=='IP_BLOCKED' else None}
        except Exception as error:
            return {'started_at':start,'finished_at':now(),'ms':round((time.monotonic()-mono)*1000,3),'status':0,'source_ip':p['source_ip'],'operation':kind,'valid_body':False,'error_code':type(error).__name__}
    def accept(row):
        if row is None:return False
        out['records'].append(row);save(path,out)
        if row['status']==403 and row['error_code']=='IP_BLOCKED' and role=='attacker':out['status']='blocked_observed';return False
        if row['status']!=200 or not row['valid_body']:
            out['status']='failed';out['reason']='unexpected_response'
            if role=='normal':stop.touch(exist_ok=True)
            return False
        return True
    try:
        with lock.open('x') as f:f.write(run_id)
        owned=True
        with path.open('x',encoding='utf-8') as f:json.dump(out,f)
        created=True
        if stop.exists():out['status']='stopped';return out
        if profile=='load':
            begin=time.monotonic();deadline=begin+s['load']['maximum_duration_seconds'];pending=set();submitted=0;proceed=True
            with ThreadPoolExecutor(max_workers=s['load']['concurrency']) as pool:
                for rate in s['load']['rates_per_second']:
                    end=min(deadline,time.monotonic()+s['load']['stage_seconds']);next_at=time.monotonic()
                    while proceed and time.monotonic()<end and submitted<p['maximum_requests']:
                        if stop.exists():out['status']='stopped';proceed=False;break
                        completed={f for f in pending if f.done()}
                        for f in completed:
                            if not accept(f.result()):proceed=False
                        pending-=completed
                        if not proceed:break
                        if len(pending)<s['load']['concurrency'] and time.monotonic()>=next_at:
                            pending.add(pool.submit(one));submitted+=1;next_at=time.monotonic()+1/rate
                        time.sleep(.02)
                    if not proceed or submitted>=p['maximum_requests']:break
                for f in pending:accept(f.result())
            out['submitted_requests']=submitted
        else:
            interval=2 if profile=='baseline' else 1
            for i in range(p['maximum_requests']):
                if stop.exists():out['status']='stopped';break
                if not accept(one()):break
                if i+1<p['maximum_requests']:
                    end=time.monotonic()+interval
                    while time.monotonic()<end and not stop.exists():time.sleep(min(.1,max(0,end-time.monotonic())))
        if out['status']=='running':out['status']='input_complete'
        return out
    finally:
        out['finished_at']=now()
        if owned:
            if created:save(path,out)
            lock.unlink()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--settings',required=True,type=Path);p.add_argument('--run-id',required=True);p.add_argument('--profile',choices=['baseline','load','probe','monitor'],required=True);p.add_argument('--role',choices=['attacker','normal'],required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    try:
        s=validate(json.loads(a.settings.read_text(encoding='utf-8-sig')))
        result=execute(s,a.run_id,a.profile,a.role,s['paths']['evidence_mount']) if a.execute else plan(s,a.run_id,a.profile,a.role)
        print(json.dumps(result,ensure_ascii=False));sys.exit(0 if result.get('status') in (None,'input_complete','blocked_observed') else 2)
    except (ValueError,KeyError,TypeError,OSError):p.exit(2,'S12 input refused; check scope and use a fresh run ID.\n')
