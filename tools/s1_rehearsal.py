"""Offline S1 rehearsal packet/import materialization. Never runs Docker or HTTP."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets

from build_s1_workflows import load_settings, materialize, IDS
from s1_lab import ROOT, create_bundle
from s1_settings import digest, plan
from s1_probe import plan as probe_plan


def write(path,value):
    with path.open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')


def source_hashes(root=ROOT):
    files=list((root/'tools').glob('*s1*.py'))+list((root/'infra/n8n/s1-src').glob('*.js'))
    files+=list((root/'haedam-portal-backend/src').rglob('*.py'))+list((root/'services/ticket-store/ticket_store').glob('*.py'))
    files+=list((root/'haedam-portal-backend/migrations').rglob('*.py'))
    files+=list((root/'infra/n8n/workflows').glob('*.json'))+list((root/'infra/graylog/notifications').glob('*.json'))
    files+=list((root/'lab/s1s4/graylog').glob('*.json'))
    files+=[root/'infra/s1-integration-settings.json']
    files+=[root/'compose.yaml',root/'compose.soc.yaml',root/'Dockerfile']
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def prepare(s,run_id,output,arm_input=False):
    s={**s,'execution_enabled':arm_input};p=plan(s,run_id,'trigger9')
    target=create_bundle(s,ROOT,output)
    secret=target/'normal-password.txt'
    with secret.open('x',encoding='utf-8') as f:f.write(secrets.token_urlsafe(32)+'\n')
    secret.chmod(0o600)
    manifest=json.loads((target/'bundle.json').read_text(encoding='utf-8'))
    commands={}
    for profile in ('boundary8','trigger9'):
        commands[profile]=manifest['compose_argv']+['exec','-T','attacker','python',s['paths']['tools_mount']+'/s1_client.py',
          '--settings',s['paths']['settings_mount'],'--run-id',run_id,'--profile',profile,'--execute']
    for role in ('attacker','normal'):
        for phase in ('baseline','blocked','restored'):
            commands[role+'_'+phase]=manifest['compose_argv']+['exec','-T',role,'python',s['paths']['tools_mount']+'/s1_probe.py',
              '--settings',s['paths']['settings_mount'],'--run-id',run_id,'--role',role,'--phase',phase,'--execute']
    _,integration=load_settings(s)
    packet={'case_id':'S1','run_id':run_id,'project':s['project'],'settings_sha256':digest(s),
       'clock_tolerance_seconds':integration['future_clock_tolerance_seconds'],
       'source_sha256':source_hashes(),'commands_are_not_executed':True,'runtime_verified':False,
       'normal_username':probe_plan(s,run_id,'normal','baseline')['username'],
       'input':{profile:plan(s,run_id,profile) for profile in ('boundary8','trigger9')},'command_argv':commands,
       'normal_password_delivery':'stdin only; never argv/env/evidence; file stays outside client mounts',
       'release_body_base':{'case_id':'S1','asset_id':s['asset_id'],'src_ip':p['source_ip'],'username':p['username']},
       'pending':['owned fresh project/volumes and conflict check','workflow/credential import and publication',
          'actual Graylog bindings, authentication checks and schedule','baseline + normal login + 8/9 input',
          'same-event ticket, attacker block, normal login, paused detector, owned release + restoration']}
    write(target/'rehearsal.json',packet)
    index={'input':f'runs/{run_id}-trigger9.json','ticket_blocked':None,'ticket_restored':None,
           'graylog_event':None,'release_response':None,'definition_id':None,
           'probes':{f'{r}_{p}':f'runs/{run_id}-{r}-{p}-1.json' for r in ('attacker','normal') for p in ('baseline','blocked','restored')}}
    write(target/'evidence-index.json',index)
    return target


def load_bundle(path):
    path=path.resolve()
    if not path.is_relative_to(ROOT/'.local'):raise ValueError('local_bundle_required')
    s,c=load_settings(json.loads((path/'settings.json').read_text(encoding='utf-8')),
                      json.loads((path/'integration-settings.json').read_text(encoding='utf-8')))
    manifest=json.loads((path/'bundle.json').read_text(encoding='utf-8'))
    packet=json.loads((path/'rehearsal.json').read_text(encoding='utf-8'))
    if manifest['settings_sha256']!=digest(s) or packet['settings_sha256']!=digest(s) or packet['project']!=s['project']:
        raise ValueError('bundle_settings_drift')
    if manifest['integration_settings_sha256']!=digest(c):raise ValueError('integration_settings_drift')
    if packet['clock_tolerance_seconds']!=c['future_clock_tolerance_seconds']:raise ValueError('clock_policy_drift')
    if packet['source_sha256']!=source_hashes():raise ValueError('bundle_source_drift')
    return s,c,packet


def imports(bundle,bindings,enable_detection=False):
    s,c,packet=load_bundle(bundle)
    c={**c,'detection_enabled':enable_detection}
    values={}
    for line in (bundle/'lab.env').read_text(encoding='utf-8').splitlines():
        key,value=line.split('=',1)
        if key in values:raise ValueError('duplicate_local_key')
        values[key]=value
    if any(values.get(k)!=str(v) for k,v in s['host_ports'].items()):raise ValueError('bundle_port_drift')
    bound=materialize(s,c,bindings,{v['env']:values[v['env']] for v in c['credentials'].values()})
    # Fail before creating any output when binding/key validation fails; never overwrite.
    target=bundle/'import';target.mkdir(exist_ok=False)
    for name,value in [('credentials',bound['credentials']),('workflows',bound['workflows']),('graylog',bound['graylog'])]:
        path=target/(name+'.json');write(path,value);path.chmod(0o600)
    write(target/'manifest.json',{'project':s['project'],'run_id':packet['run_id'],'source_sha256':packet['source_sha256'],
          'settings_sha256':digest(s),'bindings':bindings,'workflow_ids':IDS,'detection_enabled':enable_detection,
          'schedule_enabled':False,'import_executed':False})
    return target


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--settings',type=Path,default=ROOT/'infra/s1-settings.json')
    p.add_argument('--run-id',required=True);p.add_argument('--output',required=True,type=Path);p.add_argument('--arm-input',action='store_true')
    p=sub.add_parser('imports');p.add_argument('--bundle',required=True,type=Path);p.add_argument('--bindings',required=True,type=Path)
    p.add_argument('--enable-detection',action='store_true')
    try:
        args=parser.parse_args()
        if args.command=='prepare':target=prepare(json.loads(args.settings.read_text(encoding='utf-8-sig')),args.run_id,args.output,args.arm_input)
        else:
            bundle=args.bundle.resolve();load_bundle(bundle)
            target=imports(bundle,json.loads(args.bindings.read_text(encoding='utf-8-sig')),args.enable_detection)
        print(json.dumps({'created':str(target),'runtime_verified':False,'secrets_printed':False}))
    except (ValueError,KeyError,TypeError,OSError):parser.exit(2,'S1 packet refused: check source/settings, new local directory and real bindings.\n')


if __name__=='__main__':main()
