"""Actual owned-file tamper -> Wazuh -> Graylog -> n8n -> verified/restored ticket.

The script injects only two fixed harmless lab inputs. It never requests the
normal response itself; only the final operator completion uses an n8n webhook.
"""
from datetime import datetime, timezone
import hashlib
import json
import time
import urllib.request
from urllib.parse import urlencode

import s7_auto_lab as lab

lab.bind()
SETTINGS=lab.SETTINGS


def agent(code,*args):
    setup=('import json,os; from pathlib import Path; '
           'settings=json.loads(Path(os.environ["S7_CONFIG_FILE"]).read_text()); paths=settings["paths"]; '
           'web=Path(paths["agent_web"]); base=Path(paths["agent_baseline"]); '
           'control=Path(paths["agent_control"]); quarantine=Path(paths["agent_quarantine"]); home=settings["home_file"]\n')
    return lab.compose('exec','-T','s7-agent','python3','-I','-c',setup+code,*args)


def alert(ident,key,event,since):
    query={'size':5,'sort':[{'timestamp':'desc'}],'query':{'bool':{'filter':[
        {'term':{'agent.id':ident}},{'term':{'syscheck.path':SETTINGS['paths']['agent_web']+'/'+key}},
        {'term':{'syscheck.event':event}},{'range':{'timestamp':{'gte':since}}}]}}}
    hits=lab.base.index('/wazuh-alerts-*/_search',query)['hits']['hits']
    if not hits: return None
    event=hits[0]['_source']; check=event['syscheck']
    return dict(id=event['id'],timestamp=event['timestamp'],rule=event['rule']['id'],agent_id=ident,
                path=check['path'],event=check['event'],sha256_before=check.get('sha256_before'),sha256_after=check.get('sha256_after'))


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def rows():
    code = ('import sqlite3,json; from settings import load_settings; '
            'c=sqlite3.connect("file:"+load_settings()["paths"]["gateway_data"]+"/state.db?mode=ro",uri=True); c.row_factory=sqlite3.Row; '
            'print(json.dumps([dict(r) for r in c.execute("SELECT key,event,claim,ticket,response,completion FROM events")]))')
    return json.loads(lab.compose('exec', '-T', 's7-response', 'python', '-c', code))


def ticket(ident):
    status, body = lab.http('http://127.0.0.1:' + lab.env_values()['TICKET_PORT'] + '/api/v1/tickets/' + ident)
    assert status == 200
    return body['ticket']


def tickets():
    status, body = lab.http('http://127.0.0.1:' + lab.env_values()['TICKET_PORT'] + '/api/v1/tickets?case_id=S7')
    assert status == 200
    return body['items']


def hook(operation, body, role=None):
    role = role or ('detection' if operation == 'respond' else 'operator')
    header, name = ('X-S7-Detection-Key', 'S7_DETECTION_KEY') if role == 'detection' else ('X-S7-Operator-Key', 'S7_OPERATOR_KEY')
    headers = {} if role == 'missing' else {header: lab.env_values()[name]}
    return lab.http('http://127.0.0.1:' + lab.env_values()['N8N_PORT'] + '/webhook/haedam-s7-' + operation, body, headers, timeout=90)


def gateway(path, body, role='bridge'):
    code = '''import json,sys,os
from urllib.request import Request,urlopen
from urllib.error import HTTPError
x=json.load(sys.stdin); key=os.environ['S7_COMPLETE_KEY' if x['role']=='operator' else 'S7_BRIDGE_KEY']
if x['role']=='wrong': key='wrong-test-key'
from settings import load_settings
r=Request(load_settings()['urls']['gateway']+x['path'],data=json.dumps(x['body']).encode(),headers={'Content-Type':'application/json','X-S7-Key':key})
try: res=urlopen(r,timeout=40)
except HTTPError as e: res=e
with res: print(json.dumps({'status':res.status,'body':json.loads(res.read())}))
'''
    return json.loads(lab.compose('exec', '-T', 's7-response', 'python', '-c', code,
                                stdin=json.dumps(dict(path=path,body=body,role=role))))


def scoped_api_checks():
    env = lab.env_values(); b = lab.base
    code, token = b.request(env['WAZUH_API_PORT'], '/security/user/authenticate', method='POST',
        auth=b.basic(SETTINGS['wazuh_user'], env['S7_WAZUH_PASSWORD']), ca=b.API_CA)
    assert code == 200
    auth = 'Bearer ' + token['data']['token']
    results = {}
    for label, path, data, method in [
        ('own_agent', '/agents?agents_list='+env['S7_AGENT_ID'], None, None),
        ('security_users', '/security/users', None, None),
        ('manager_agent_read', '/agents?agents_list=000', None, None),
        ('manager_agent_response', '/active-response?agents_list=000', {'command':'!'+SETTINGS['ar_command'],'arguments':['invalid']}, 'PUT')]:
        status, body = b.request(env['WAZUH_API_PORT'], path, data, method, auth, b.API_CA)
        results[label] = {'status':status,'error':body.get('error'), 'failed':body.get('data',{}).get('total_failed_items',0),
                          'affected':body.get('data',{}).get('total_affected_items',0)}
        if label == 'own_agent':
            assert status == 200 and body['data']['total_affected_items'] == 1
        elif label == 'security_users':
            assert status == 403 or (status == 200 and body.get('data',{}).get('affected_items') == [])
        else:
            assert status == 403 or (body.get('error') and body.get('data',{}).get('total_affected_items',0) == 0), results[label]
    return results


def completion(event_key, ident):
    return hook('complete', dict(case_id='S7',asset_id=SETTINGS['asset_id'],event_key=event_key,ticket_id=ident))


def mutate(key, marker):
    assert key in SETTINGS['targets']
    code = r'''import pathlib,hashlib,sys
key,marker=sys.argv[1:]; p=web/key
if settings['targets'][key]=='restore': data=(base/'baseline'/key).read_bytes()+('\n<!-- '+marker+' -->\n').encode()
else:
 assert not p.exists(), 'Probe already exists'
 data=('Harmless S7 personal test '+marker+'\n').encode()
p.write_bytes(data); print(hashlib.sha256(data).hexdigest())
'''
    return agent(code, key, marker)


def verify():
    b = lab.base
    lab.require_current_portal()  # before any evidence: a kept volume must not run older code
    definition = json.loads(lab.STATE.read_text())['definition']
    run_id = datetime.now(timezone.utc).strftime('S7AUTO-%Y%m%dT%H%M%SZ')
    result = dict(run_id=run_id,project=lab.PROJECT,started_at=now(),checks={},cases=[],result='running')
    before_count = len(rows())
    if any(t['status'] in ('open','responding','verified') for t in tickets()):
        raise RuntimeError('Complete existing tickets before this verification.')
    baseline = agent('import hashlib; print(hashlib.sha256((base/"baseline.sha256").read_bytes()).hexdigest())')
    try:
        ident = b.wait_for(b.agent_id)
        b.wait_for(lambda: b.api('/syscheck/'+ident+'?'+urlencode({'search':SETTINGS['home_file']}))['total_affected_items'] > 0)
        result['checks']['scoped_api'] = scoped_api_checks()
        readonly = agent('try:\n (base/"baseline.sha256").open("ab").close(); print("writable")\nexcept OSError: print("readonly")')
        assert readonly == 'readonly'; result['checks']['baseline_mount_readonly'] = True
        guard_job=hashlib.sha256((run_id+'-stale-guard').encode()).hexdigest()
        b.api('/active-response?agents_list='+ident, {'command':'!'+SETTINGS['ar_command'],
            'arguments':[guard_job,'T-20000101-9999',SETTINGS['home_file'],'0'*64,baseline,'respond']},'PUT')
        def rejected_receipt():
            text=agent('import sys; p=control/(sys.argv[1]+".json"); print(p.read_text() if p.exists() else "null")',guard_job)
            return json.loads(text)
        rejected=b.wait_for(rejected_receipt,30)
        assert rejected['result']=='error' and rejected['reason']=='stale_file_hash'
        result['checks']['agent_rejects_wrong_hash']=True
        for op in ('respond','complete'):
            assert hook(op,{},role='missing')[0] == 403
        assert hook('complete',{},role='detection')[0] == 403
        assert hook('respond',{'case_id':'S8'})[0] == 400
        assert gateway('/claim',{},'wrong')['status'] == 403
        unknown = dict(event_key='0'*64,graylog_event_id='A'*26,detected_at=now(),execution_id='1')
        assert gateway('/claim',unknown)['status'] == 404
        result['checks']['auth_and_unknown_event_denied'] = True
        lab.graylog('/events/definitions/'+definition+'/schedule',{},'PUT')
        for key, action in SETTINGS['targets'].items():
            event_type='modified' if action=='restore' else 'added'
            case = dict(file_key=key,input_at=now()); result['cases'].append(case)
            case['input_sha256'] = mutate(key, run_id + '-' + event_type)
            case['wazuh_alert'] = b.wait_for(lambda: alert(ident,key,event_type,case['input_at']), 150)
            assert case['wazuh_alert']['sha256_after'] == case['input_sha256']
            def completed():
                for r in rows():
                    ev=json.loads(r['event'])
                    if ev['file_key']==key and ev['expected_hash']==case['input_sha256'] and r['response'] and r['ticket']:
                        t=ticket(r['ticket'])
                        if t['status']=='verified': return r,t
                return None
            row,t = b.wait_for(completed,180)
            response = json.loads(row['response']); event = json.loads(row['event'])
            case.update(event_key=row['key'],ticket_id=t['ticket_id'],graylog_event_id=response['graylog_event_id'],
                        detected_at=response['detected_at'],verified_at=t['verified_at'],response=response,
                        automatic_execution_id=response['execution_id'])
            assert case['wazuh_alert']['id'] == event['wazuh_event_id']
            assert all(x in t['event_ids'] for x in (event['wazuh_event_id'],response['graylog_event_id']))
            # Replay only the real observed Graylog decision. No new file operation.
            payload=dict(case_id='S7',asset_id=SETTINGS['asset_id'],event_key=row['key'],event_id=response['graylog_event_id'],detected_at=response['detected_at'])
            s,r=hook('respond',payload); assert s==200 and r['verdict']=='verified',(s,r)
            assert len(ticket(t['ticket_id'])['actions']) == 1
            case['duplicate_no_new_action'] = True
            wrong = gateway('/complete',dict(event_key=row['key'],ticket_id='T-20000101-9999',execution_id='1'),'operator')
            assert wrong['status']==409
            s,r=completion(row['key'],t['ticket_id']); assert s==200 and r['verdict']=='restored',(s,r)
            final=ticket(t['ticket_id']); assert final['status']=='restored'
            case['restored_at']=final['restored_at']; case['final_actions']=final['actions']
            s,r=completion(row['key'],t['ticket_id']); assert s==200 and r['verdict']=='restored'
            s,r=hook('respond',payload); assert s==200 and r['verdict']=='already_restored'
            assert len(ticket(t['ticket_id'])['actions'])==2
            case['complete_and_old_event_replay_idempotent']=True
            case['input_to_verified_seconds']=round((datetime.fromisoformat(t['verified_at'])-datetime.fromisoformat(case['input_at'])).total_seconds(),3)
        time.sleep(8)
        assert len(rows()) == before_count+len(SETTINGS['targets']), 'Restoration generated an unexpected candidate'
        result['checks']['restoration_alerts_ignored'] = True
        result['checks']['quarantine_entries_remaining'] = int(agent('print(len(list(quarantine.iterdir())))'))
        assert result['checks']['quarantine_entries_remaining'] == 0
        assert agent('import hashlib; print(hashlib.sha256((base/"baseline.sha256").read_bytes()).hexdigest())') == baseline
        result['checks']['baseline_preserved'] = True
        privacy = "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});console.log(JSON.stringify({payload_rows:db.prepare('SELECT count(*) AS n FROM execution_data').get().n}));"
        def clean_payloads():
            data=json.loads(lab.compose('exec','-T','n8n','node','-e',privacy))
            return data if data['payload_rows']==0 else None
        result['checks']['n8n_execution_privacy']=b.wait_for(clean_payloads,30)
        result['result']='pass'
    except Exception as exc:
        result.update(result='fail',error=lab.scrub(str(exc)))
        raise
    finally:
        lab.graylog('/events/definitions/'+definition+'/unschedule',{},'PUT')
        # A failed response is kept for investigation. Restore only our two test
        # paths to the pinned baseline; this fallback never marks tickets successful.
        if result['result']!='pass':
            result['fallback_cleanup']=agent('import shutil\nfor key,action in settings["targets"].items():\n'
                ' if action=="restore": shutil.copyfile(base/"baseline"/key,web/key)\n'
                ' else: (web/key).unlink(missing_ok=True)\nprint("test paths restored; tickets/receipts retained")')
        result['finished_at']=now(); result['source_head']=b.run(['git','rev-parse','HEAD'])
        result['source_dirty_at_run']=bool(b.run(['git','status','--porcelain']))
        sources=['compose.s7-auto.yaml','infra/wazuh/manager-auto.conf','infra/s7-auto-settings.json','services/s7-response/settings.py','infra/wazuh/agent/s7_guard.py',
                 'services/s7-response/app.py','services/s7-response/policy.py','tools/s7_auto_lab.py','tools/s7_auto_verify.py','tools/build_s7_workflows.py','infra/graylog/s7-fim.json']
        sources += ['compose.yaml','compose.soc.yaml','compose.s7.yaml','Dockerfile','infra/wazuh/agent/Dockerfile',
                    'infra/wazuh/agent/entrypoint.sh','infra/wazuh/portal-rules.xml','services/s7-response/Dockerfile',
                    'services/ticket-store/ticket_store/db.py','tools/s7_lab.py','tools/s7_auto_failures.py',
                    'lab/s7/restore/s7_restore.py','infra/n8n/portfolio-s7/s7-respond.json','infra/n8n/portfolio-s7/s7-complete.json']
        result['source_sha256']={p:hashlib.sha256((lab.ROOT/p).read_bytes()).hexdigest() for p in sources}
        out=lab.LOCAL/(run_id+'.json'); out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('Evidence: '+str(out)+' result='+result['result'],flush=True)


if __name__=='__main__':
    try: verify()
    except Exception as exc: raise SystemExit(lab.scrub(str(exc)))
