"""Fixed S7 operations only; never starts/stops Docker or accepts shell commands."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def emit(kind, **values):
    print(json.dumps({'type':kind,**values}), flush=True)


def patch(**values):
    emit('patch',data=values)
    if sys.stdin.readline().strip() != 'ack':
        raise RuntimeError('interrupted')


def main():
    request=json.loads(sys.stdin.readline()); cfg=request['config']; run=request['run']; action=request['action']
    os.environ['S7_PROJECT']=cfg['s7_project']; os.environ['S7_CONFIG_FILE']=cfg['s7_settings']
    import s7_auto_verify as verify
    lab=verify.lab; settings=lab.SETTINGS
    health={'ready':False,'reason':'lab_unavailable','observed_at':verify.now(),'links':{}}
    try:
        # Names are built from the locally validated project, never request input.
        required=('portal','s7-agent','wazuh.manager','s7-response','graylog','n8n','ticket-store')
        objects=json.loads(lab.base.run(['docker','inspect',*[cfg['s7_project']+'-'+s+'-1' for s in required]],timeout=15))
        for item in objects:
            labels=item['Config']['Labels']
            if not item['State']['Running'] or labels.get('com.docker.compose.project')!=cfg['s7_project']:
                raise RuntimeError('lab_unavailable')
            if Path(labels.get('com.docker.compose.project.working_dir','')).resolve()!=lab.ROOT.resolve():
                raise RuntimeError('scope_mismatch')
        indexed={o['Config']['Labels']['com.docker.compose.service']:o for o in objects}
        env=lab.env_values()
        for service,key in [('portal','PORTAL_PORT'),('graylog','GRAYLOG_PORT'),
                            ('n8n','N8N_PORT'),('ticket-store','TICKET_PORT')]:
            bindings=[binding for entries in indexed[service]['NetworkSettings']['Ports'].values()
                      for binding in (entries or [])]
            if not any(b['HostIp']=='127.0.0.1' and b['HostPort']==env[key] for b in bindings):
                raise RuntimeError('scope_mismatch')
        snapshot=json.loads(verify.agent('print(json.dumps(settings,sort_keys=True))'))
        if snapshot!=settings: raise RuntimeError('scope_mismatch')
        # Prove the runtime gateway uses the same deployment settings, too.
        runtime=json.loads(lab.compose('exec','-T','s7-response','python','-c',
            'import json; from settings import load_settings; print(json.dumps(load_settings()))'))
        if runtime!=settings: raise RuntimeError('scope_mismatch')
        ident=lab.agent_id()
        if ident!=env['S7_AGENT_ID']: raise RuntimeError('scope_mismatch')
        definition=json.loads(lab.STATE.read_text())['definition']
        lab.graylog('/events/definitions/'+definition)
        for key,route in [('PORTAL_PORT','/api/v1/health'),('N8N_PORT','/healthz/readiness'),('TICKET_PORT','/')]:
            code,_=lab.http('http://127.0.0.1:'+env[key]+route,timeout=5)
            if code!=200: raise RuntimeError('lab_unavailable')
        health.update(ready=True,reason='ready',links={
            name:'http://127.0.0.1:'+env[key] for name,key in
            [('portal','PORTAL_PORT'),('graylog','GRAYLOG_PORT'),('n8n','N8N_PORT'),('tickets','TICKET_PORT')]})
    except Exception as exc:
        if str(exc)=='scope_mismatch': health['reason']='scope_mismatch'
        emit('health',data=health)
        raise RuntimeError(health['reason']) from None
    emit('health',data=health)
    if action=='refresh':
        emit('done'); return
    if run['scope']!=cfg['scope'] or run['project']!=cfg['s7_project'] or run['target'] not in settings['targets']:
        raise RuntimeError('scope_mismatch')
    key=run['target']; marker='PANEL-'+run['id']; steps=dict(run.get('steps',{}))
    def step(name, detail):
        steps[name]={'at':verify.now(), 'detail':detail}
        patch(steps=steps, observed_at=verify.now())
    def clean():
        # Inspect exact baseline and all web files without changing either.
        code='''import hashlib
values={k:v for v,k in (line.split('  ',1) for line in (base/'baseline.sha256').read_text().splitlines())}
actual={str(p.relative_to(web)):hashlib.sha256(p.read_bytes()).hexdigest() for p in web.rglob('*') if p.is_file()}
safe=not any(p.is_symlink() for p in web.rglob('*'))
print(json.dumps({'clean':safe and values==actual,'baseline_hash':hashlib.sha256((base/'baseline.sha256').read_bytes()).hexdigest()}))'''
        result=json.loads(verify.agent(code))
        if not result['clean']: raise RuntimeError('dirty_target')
        return result['baseline_hash']
    if action=='attack':
        if any(t['status'] in ('open','responding','verified') for t in verify.tickets()):
            raise RuntimeError('active_ticket')
        baseline=clean()
        prepared=json.loads(verify.agent('''import hashlib,sys
key,marker=sys.argv[1:]; p=web/key
assert not p.is_symlink() and p.parent.resolve()==p.parent
if settings['targets'][key]=='restore': data=(base/'baseline'/key).read_bytes()+('\\n<!-- '+marker+' -->\\n').encode()
else:
 assert not p.exists()
 data=('Harmless S7 personal test '+marker+'\\n').encode()
print(json.dumps({'hash':hashlib.sha256(data).hexdigest()}))''',key,marker))
        # Persist an identity before scheduling or mutating; no automatic attack replay.
        patch(stage='armed',input_sha256=prepared['hash'],input_at=verify.now(),baseline_hash=baseline)
        lab.graylog('/events/definitions/'+definition+'/schedule',{},'PUT')
        if verify.mutate(key,marker)!=prepared['hash']: raise RuntimeError('worker_failed')
        step('input','허용된 파일에 무해한 시험 입력을 기록했습니다.')
        patch(stage='input_sent')
        emit('done'); return
    if not run.get('input_sha256'): raise RuntimeError('awaiting_detection')
    deadline=time.monotonic()+cfg['observe_timeout_seconds']
    matched=None
    while True:
        matches=[r for r in verify.rows() if json.loads(r['event'])['file_key']==key
                 and json.loads(r['event'])['expected_hash']==run['input_sha256']
                 and json.loads(r['event'])['alert_at']>=run['input_at']]
        if len(matches)>1: raise RuntimeError('scope_mismatch')
        if matches:
            matched=matches[0]; event=json.loads(matched['event'])
            if run.get('event_key') and run['event_key']!=matched['key']: raise RuntimeError('scope_mismatch')
            patch(event_key=matched['key'],wazuh_event_id=event['wazuh_event_id'],stage='observing')
            if 'wazuh' not in steps: step('wazuh','실제 파일 해시와 일치하는 Wazuh 경보를 확인했습니다.')
            if matched['claim']:
                claim=json.loads(matched['claim'])
                patch(graylog_event_id=claim['graylog_event_id'])
                if 'graylog' not in steps: step('graylog','Graylog 이벤트의 인증된 n8n 전달을 확인했습니다.')
            if matched['ticket'] and matched['response']:
                t=verify.ticket(matched['ticket'])
                claim=json.loads(matched['claim'])
                if t['case_id']!='S7' or t['asset_id']!=settings['asset_id'] or t['group_key']!=claim['group_key']:
                    raise RuntimeError('scope_mismatch')
                if not all(e in t['event_ids'] for e in (event['wazuh_event_id'],claim['graylog_event_id'])):
                    raise RuntimeError('scope_mismatch')
                if t['status'] in ('verified','restored'):
                    # This readback is allowed only AFTER an existing successful response.
                    observed=verify.gateway('/respond',{'event_key':matched['key'],'ticket_id':t['ticket_id']})
                    if observed['status']!=200: raise RuntimeError('dirty_target')
                    effect=observed['body']['data']['effect']
                    patch(ticket_id=t['ticket_id'],ticket_status=t['status'],effect=effect)
                    if 'response' not in steps: step('response','티켓과 현재 파일 해시·HTTP 효과를 대조했습니다.')
                    break
        if time.monotonic()>=deadline: raise RuntimeError('awaiting_detection')
        time.sleep(2)
    if action=='observe':
        if t['status']=='restored':
            if not matched['completion']: raise RuntimeError('held_restore')
            step('restore','티켓의 원복 완료와 현재 정상 상태를 확인했습니다.')
        patch(stage='restored' if t['status']=='restored' else 'verified', observed_at=verify.now())
        emit('done'); return
    if action!='restore': raise RuntimeError('worker_failed')
    lab.graylog('/events/definitions/'+definition+'/unschedule',{},'PUT')
    patch(detection_paused=True)
    status,body=verify.completion(matched['key'],t['ticket_id'])
    if status!=200 or body.get('verdict')!='restored': raise RuntimeError('held_restore')
    final=verify.ticket(t['ticket_id'])
    if final['status']!='restored' or clean()!=run['baseline_hash']: raise RuntimeError('held_restore')
    if settings['targets'][key]=='quarantine':
        remains=verify.agent('import sys; print(any(p.name.endswith("_"+sys.argv[1]) for p in quarantine.iterdir()))',matched['key'])
        if remains!='False': raise RuntimeError('held_restore')
    patch(ticket_status='restored',stage='restored',observed_at=verify.now())
    step('restore','해당 티켓의 원복 완료·정상 파일·격리물 정리를 확인했습니다.')
    emit('done')


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        allowed={'lab_unavailable','scope_mismatch','active_ticket','dirty_target','awaiting_detection','held_restore','interrupted'}
        emit('error',code=str(exc) if str(exc) in allowed else 'worker_failed')
        raise SystemExit(1)
