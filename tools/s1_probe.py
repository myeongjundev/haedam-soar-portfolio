"""S1 client-side baseline/block/restoration checks. Default plan only; no Docker CLI."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from s1_client import Transport, runtime_guard, now, save, InputStopped
from s1_settings import plan as input_plan, validate, digest


def plan(s,run_id,role,phase):
    p=input_plan(s,run_id,'trigger9')
    if role not in ('attacker','normal') or phase not in ('baseline','blocked','restored'):
        raise ValueError('invalid_probe')
    username=s['username_prefix']+'n_'+run_id
    if len(username)>40:raise ValueError('username_too_long')
    return {'case_id':'S1','run_id':run_id,'role':role,'phase':phase,'project':s['project'],
            'settings_sha256':digest(s),'mode':'plan_only','source_ip':s['addresses'][role],
            'target_ip':p['target_ip'],'target_port':p['target_port'],
            'username':username if role=='normal' else None,
            'expected_health_status':403 if role=='attacker' and phase=='blocked' else 200,
            'maximum_http_requests':1 if role=='attacker' else 5 if phase=='baseline' else 4,
            'end_to_end_status':'not_run'}


def execute(s,run_id,role,phase,output,password=None,attempt=1,*,guard=runtime_guard,transport_factory=Transport):
    p=plan(s,run_id,role,phase);guard(s)
    if type(attempt) is not int or not 1<=attempt<=9:raise ValueError('invalid_attempt')
    if role=='normal' and (not isinstance(password,str) or not 10<=len(password)<=128):raise ValueError('password_required_on_stdin')
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    path=output/f'{run_id}-{role}-{phase}-{attempt}.json'
    result={**p,'mode':'actual_http_probe','status':'running','started_at':now(),'records':[],
            'normal_authenticated':None,'source_sha256':{n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()
              for n in ('s1_probe.py','s1_client.py','s1_settings.py')}}
    with path.open('x',encoding='utf-8') as f:json.dump(result,f)
    transport=transport_factory(s,p)
    def request(kind,body=None,csrf=None):
        if (output/s['stop_filename']).exists():raise InputStopped()
        if len(result['records'])>=p['maximum_http_requests']:raise ValueError('budget_exhausted')
        started=now();status,payload,source=transport.request(s['paths'][kind],body,csrf)
        if source!=p['source_ip']:raise ValueError('source_mismatch')
        result['records'].append({'operation':kind,'status':status,'source_ip':source,'started_at':started,'finished_at':now()})
        save(path,result)
        return status,payload
    try:
        status,body=request('health')
        if status!=p['expected_health_status']:raise ValueError('health_status_mismatch')
        if status==403:
            if body.get('success') is not False or body.get('error',{}).get('code')!='IP_BLOCKED':raise ValueError('block_not_confirmed')
        elif body.get('success') is not True or body.get('data',{}).get('service')!=s['asset_id'] or body['data'].get('status')!='ok':
            raise ValueError('unexpected_service')
        if role=='normal':
            status,body=request('session');data=body.get('data',{})
            csrf=data.get('csrf_token')
            if status!=200 or body.get('success') is not True or data.get('user') is not None or not isinstance(csrf,str) or not 1<=len(csrf)<=256:
                raise ValueError('anonymous_csrf_required')
            if phase=='baseline':
                status,body=request('register',{'username':p['username'],'display_name':'S1 synthetic normal','password':password},csrf)
                if status!=201 and not (status==409 and body.get('error',{}).get('code')=='CONFLICT'):
                    raise ValueError('registration_failed')
                # A 409 is not proof of ownership: the following password login must succeed.
            status,body=request('login',{'username':p['username'],'password':password},csrf)
            if status!=200 or body.get('success') is not True:raise ValueError('normal_login_failed')
            status,body=request('session');user=body.get('data',{}).get('user') or {}
            if status!=200 or body.get('success') is not True or user.get('username')!=p['username'] or user.get('role')!='citizen' or user.get('locked') is not False:
                raise ValueError('normal_identity_failed')
            result['normal_authenticated']=True
        result['status']='probe_passed'
    except (KeyboardInterrupt,InputStopped):result.update(status='stopped',reason='stop_requested')
    except Exception as error:result.update(status='failed',reason=type(error).__name__)
    result['finished_at']=now();save(path,result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings',required=True,type=Path);parser.add_argument('--run-id',required=True)
    parser.add_argument('--role',choices=['attacker','normal'],required=True)
    parser.add_argument('--phase',choices=['baseline','blocked','restored'],required=True)
    parser.add_argument('--attempt',type=int,default=1);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    try:
        s=validate(json.loads(args.settings.read_text(encoding='utf-8-sig')))
        if not args.execute:result=plan(s,args.run_id,args.role,args.phase)
        else:
            runtime_guard(s)  # reject before reading a secret on an unowned host
            password=sys.stdin.readline(130).rstrip('\r\n') if args.role=='normal' else None
            result=execute(s,args.run_id,args.role,args.phase,s['paths']['evidence_mount'],password,args.attempt)
        print(json.dumps(result,ensure_ascii=False))
        if args.execute and result['status']!='probe_passed':raise SystemExit(1)
    except (ValueError,KeyError,TypeError,OSError):parser.exit(2,'S1 probe refused; no secret/error body printed.\n')


if __name__=='__main__':main()
