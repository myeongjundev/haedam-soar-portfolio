"""Actual synthetic citizen HTTP -> GELF -> Graylog -> n8n -> write-only restriction.

No direct mutation of portal/ticket DBs. Credentials and cookies are never evidence.
The fixed lab target is h1_abuse. Pause detection before releasing to avoid old windows.
"""
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import json
import secrets
import time
import traceback
from urllib.parse import urlencode

from h1_lab import LOCAL, ROOT, STATE, compose, env_values, graylog, http, scrub


def now():
    return datetime.now(timezone.utc).isoformat()


CLIENT = r'''
import json,sys
from pathlib import Path
from http.cookiejar import MozillaCookieJar
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.error import HTTPError
from datetime import datetime,timezone
x=json.load(sys.stdin); username=x['username']; op=x['operation']
path=Path('/tmp/h1-'+username)
jar=MozillaCookieJar(str(path)+'.cookies')
if Path(jar.filename).exists(): jar.load(ignore_discard=True,ignore_expires=True)
client=build_opener(HTTPCookieProcessor(jar))
state=json.loads(path.read_text()) if path.exists() else {}
def req(p,b=None):
 r=Request('http://portal:5000/api/v1'+p,data=None if b is None else json.dumps(b).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':state.get('csrf','')})
 try: response=client.open(r,timeout=15)
 except HTTPError as e: response=e
 with response: return response.status,json.loads(response.read())
out={'username':username,'started_at':datetime.now(timezone.utc).isoformat()}
if op in ('setup','login'):
 s,b=req('/auth/me'); state['csrf']=b['data']['csrf_token']
 if op=='setup':
  s,b=req('/auth/register',{'username':username,'display_name':'합성시민','password':x['password']})
  assert s==201, (s,b.get('error',{}).get('code'))
 s,b=req('/auth/login',{'username':username,'password':x['password']})
 out['login_status']=s
 if s==200: state['csrf']=b['data']['csrf_token']
elif op=='write':
 out['writes']=[]
 for i in range(x.get('count',1)):
  start=datetime.now(timezone.utc).isoformat()
  s,b=req('/petitions',{'title':'H1 합성 검증 민원','content':'실제 개인정보가 없는 격리 랩 검증용 민원입니다.','category':'기타'})
  out['writes'].append({'status':s,'error':b.get('error',{}).get('code'),'started_at':start,'finished_at':datetime.now(timezone.utc).isoformat()})
  if s==201: state['petition_id']=b['data']['id']
elif op=='probe':
 s,b=req('/auth/me'); out['session_status']=s; out['session_preserved']=b.get('data',{}).get('user',{}).get('username')==username
 s,b=req('/petitions'); out['list_status']=s
 if state.get('petition_id'): out['detail_status']=req('/petitions/'+str(state['petition_id']))[0]
else: raise ValueError('unsupported operation')
jar.save(ignore_discard=True,ignore_expires=True); path.write_text(json.dumps(state)); path.chmod(0o600)
out['finished_at']=datetime.now(timezone.utc).isoformat(); print(json.dumps(out))
'''


def client(service, username, operation, count=1):
    if service not in ('attacker', 'normal') or username not in ('h1_abuse', 'h1_normal', 'h1_other'):
        raise ValueError('outside H1 test clients')
    secret_file = LOCAL / 'test-account.json'
    if not secret_file.exists():
        secret_file.write_text(json.dumps({'password': secrets.token_urlsafe(24)}))
        secret_file.chmod(0o600)
    payload = {**json.loads(secret_file.read_text()), 'username': username, 'operation': operation, 'count': count}
    return json.loads(compose('exec', '-T', service, 'python', '-c', CLIENT, stdin=json.dumps(payload)))


def hook(operation, body, role=None, wrong=False):
    role = role or ('detection' if operation == 'restrict' else 'operator')
    header, key = ('X-H1-Detection-Key', 'H1_DETECTION_KEY') if role == 'detection' else ('X-H1-Operator-Key', 'H1_OPERATOR_KEY')
    headers = {} if role == 'missing' else {header: 'invalid-review-key' if wrong else env_values()[key]}
    return http(f"http://127.0.0.1:{env_values()['N8N_PORT']}/webhook/haedam-h1-{operation}", body, headers, timeout=90)


def tickets():
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets?case_id=H1")
    assert status == 200
    return body['items']


def ticket(ident):
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets/{ident}")
    assert status == 200
    return body['ticket']


def events(definition):
    result = graylog('/events/search', {'query': f'event_definition_id:{definition}',
        'timerange': {'type': 'relative', 'range': 1800}, 'page': 1, 'per_page': 100})
    return [item.get('event', item) for item in result.get('events', [])]


def wait_for(check, label, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(2)
    raise AssertionError('Timed out: ' + label)


def receipts():
    script = "from haedam_portal import create_app; from haedam_portal.models import db,ResponseReceipt; from sqlalchemy import select,func; app=create_app(); ctx=app.app_context(); ctx.push(); print(db.session.scalar(select(func.count()).select_from(ResponseReceipt)))"
    return int(compose('exec', '-T', 'portal', 'python', '-c', script))


def active():
    script = """const fs=require('fs'),k=JSON.parse(fs.readFileSync(0,'utf8'));
    (async()=>{const p=await fetch('http://portal-response:5000/api/v1/response/petitions/restrictions/h1_abuse',{headers:{'X-Response-Key':k.portal}});
    const t=await fetch('http://ticket-store:8088/api/v1/tickets/active?asset_id=haedam-portal&via=portal&action=restrict_write&target=h1_abuse',{headers:{'X-Response-Key':k.ticket}});
    console.log(JSON.stringify({portal_status:p.status,restriction:(await p.json()).data,ticket_status:t.status,claims:(await t.json()).tickets}));})().catch(()=>process.exit(1));"""
    return json.loads(compose('exec', '-T', 'n8n', 'node', '-e', script,
        stdin=json.dumps({'portal': env_values()['PORTAL_RESPONSE_KEY'], 'ticket': env_values()['TICKET_STORE_KEY']})))


def verify():
    state = json.loads(STATE.read_text())
    definition = state['definition']
    run_id = datetime.now(timezone.utc).strftime('H1-%Y%m%dT%H%M%SZ')
    out = {'run_id': run_id, 'kind': 'actual-portal-http-with-synthetic-citizens', 'started_at': now(),
           'threshold': {'distinct_events': 5, 'window_seconds': 600, 'basis': 'synthetic lab baseline, not citizen usage statistics'}, 'checks': {}}
    files = [ROOT / n for n in ('Dockerfile', 'compose.yaml', 'compose.soc.yaml', 'compose.h1.yaml',
             'tools/build_h1_workflows.py', 'tools/h1_lab.py', 'tools/h1_control.py',
             'tools/h1_verify.py', 'infra/graylog/h1-petition-flood.json')]
    files += sorted((ROOT / 'haedam-portal-backend/src').rglob('*.py'))
    files += sorted((ROOT / 'haedam-portal-backend/migrations').rglob('*.py'))
    files += sorted((ROOT / 'services/ticket-store/ticket_store').rglob('*.py'))
    files += sorted((ROOT / 'infra/n8n/portfolio-h1').glob('*.json'))
    out['source_sha256'] = [{'file': p.relative_to(ROOT).as_posix(), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    evidence = LOCAL / (run_id + '.json')
    replay = None
    if tickets():
        raise RuntimeError('Use a fresh owned H1 lab for this fixed-account verification; do not overwrite previous evidence.')
    try:
        for service, username in (('attacker', 'h1_abuse'), ('attacker', 'h1_other'), ('normal', 'h1_normal')):
            assert client(service, username, 'setup')['login_status'] == 200
        for operation in ('restrict', 'release'):
            assert hook(operation, {}, role='missing')[0] == 403
            assert hook(operation, {}, wrong=True)[0] == 403
        assert hook('release', {}, role='detection')[0] == 403
        assert hook('restrict', {'case_id': 'S8'})[0] == 400
        out['checks']['webhook_auth_and_scope'] = True
        boundary = "import json,sys; from urllib.request import Request,urlopen; from urllib.error import HTTPError; key=json.load(sys.stdin)['key']; r=Request('http://portal:5000/api/v1/response/petitions/restrictions/h1_abuse',headers={'X-Response-Key':key,'X-Forwarded-For':'172.30.91.2'});\ntry: print(urlopen(r,timeout=10).status)\nexcept HTTPError as e: print(e.code)"
        assert int(compose('exec', '-T', 'attacker', 'python', '-c', boundary,
                          stdin=json.dumps({'key': env_values()['PORTAL_RESPONSE_KEY']}))) == 403
        out['checks']['response_network_boundary'] = True
        fake = {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'event_id': 'A' * 26, 'detected_at': now()}
        before = receipts()
        compose('stop', 'ticket-store')
        try:
            status, result = hook('restrict', fake)
            assert status == 503 and result['verdict'] == 'held_ticket_record', (status, result)
            assert receipts() == before
        finally:
            compose('up', '-d', '--wait', '--wait-timeout', '90', 'ticket-store')
        assert not tickets()
        out['checks']['ticket_outage_before_action'] = {'status': status, 'new_receipts': 0}
        graylog(f'/events/definitions/{definition}/schedule', {}, 'PUT')
        out['baseline_normal'] = client('normal', 'h1_normal', 'write', 2)
        out['baseline_same_ip_other'] = client('attacker', 'h1_other', 'write', 2)
        out['before_threshold'] = client('attacker', 'h1_abuse', 'write', 4)
        assert all(w['status'] == 201 for name in ('baseline_normal', 'baseline_same_ip_other', 'before_threshold') for w in out[name]['writes'])
        print('Baseline 2+2 and target 4 accepted; observing 40 seconds before threshold.', flush=True)
        time.sleep(40)
        assert not tickets() and not events(definition)
        out['checks']['no_cross_account_aggregation'] = True
        out['threshold_write'] = client('attacker', 'h1_abuse', 'write')
        assert out['threshold_write']['writes'][0]['status'] == 201
        event = wait_for(lambda: next((e for e in events(definition) if e.get('fields', {}).get('username') == 'h1_abuse'), None), 'real Graylog event')
        replay = {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'event_id': event['id'], 'detected_at': event['timestamp_processing']}
        found = wait_for(lambda: next((t for t in tickets() if t['status'] == 'responding'), None), 'H1 ticket and restriction')
        ident = found['ticket_id']
        graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
        out['graylog_event'] = {k: event.get(k) for k in ('id', 'timestamp', 'timestamp_processing', 'event_definition_id', 'source_streams', 'fields')}
        assert state['stream'] in event['source_streams']
        out['restricted_write'] = client('attacker', 'h1_abuse', 'write')
        assert out['restricted_write']['writes'][0]['status'] == 429
        assert out['restricted_write']['writes'][0]['error'] == 'PETITION_WRITE_RESTRICTED'
        out['preserved_session'] = client('attacker', 'h1_abuse', 'probe')
        assert out['preserved_session']['session_preserved'] and out['preserved_session']['detail_status'] == out['preserved_session']['list_status'] == 200
        out['new_login_other_ip'] = client('normal', 'h1_abuse', 'login')
        assert out['new_login_other_ip']['login_status'] == 200
        assert client('normal', 'h1_abuse', 'write')['writes'][0]['status'] == 429
        out['same_ip_other_write'] = client('attacker', 'h1_other', 'write')
        out['normal_write'] = client('normal', 'h1_normal', 'write')
        assert out['same_ip_other_write']['writes'][0]['status'] == out['normal_write']['writes'][0]['status'] == 201
        out['ticket_after_restrict'] = ticket(ident)
        assert event['id'] in out['ticket_after_restrict']['event_ids']
        assert out['ticket_after_restrict']['data_origin'] == 'live'
        inputs = graylog('/search/universal/relative?' + urlencode({'query': 'source:haedam-portal AND event_type:petition.created AND username:h1_abuse', 'range': 600}))['messages']
        unique = {r['message']['event_id']: json.loads(r['message']['portal_event']) for r in inputs}
        assert len(unique) == 5
        out['input_events'] = [{k: e[k] for k in ('event_id', 'timestamp', 'event_type', 'username', 'src_ip')} for e in unique.values()]
        condition = max(datetime.fromisoformat(e['timestamp']) for e in unique.values())
        detected = datetime.fromisoformat(event['timestamp_processing'].replace('Z', '+00:00'))
        responded = datetime.fromisoformat(out['ticket_after_restrict']['responded_at'].replace('Z', '+00:00'))
        out['timing_seconds'] = {'condition_to_detection': (detected-condition).total_seconds(),
            'detection_to_response': (responded-detected).total_seconds(), 'condition_to_response': (responded-condition).total_seconds()}
        replay = {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'event_id': event['id'], 'detected_at': event['timestamp_processing']}
        before = receipts()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            duplicates = list(pool.map(lambda _: hook('restrict', replay), range(2)))
        assert all(s == 200 and b['verdict'] == 'duplicate_no_action' for s, b in duplicates), duplicates
        assert receipts() == before
        out['checks']['concurrent_duplicates'] = {'calls': 2, 'new_receipts': 0}
        release = {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'ticket_id': ident}
        assert hook('release', {**release, 'ticket_id': 'T-20000101-9999'})[0] == 409
        assert receipts() == before
        out['checks']['stale_release_rejected'] = True
        status, result = hook('release', release)
        assert status == 200 and result['verdict'] == 'restored', (status, result)
        out['restored_write'] = client('attacker', 'h1_abuse', 'write')
        assert out['restored_write']['writes'][0]['status'] == 201
        out['ticket_final'] = ticket(ident)
        assert out['ticket_final']['status'] == 'restored'
        assert [a['result'] for a in out['ticket_final']['actions']] == ['applied', 'released']
        assert receipts() == before + 1
        status, result = hook('release', release)
        assert status == 200 and result['verdict'] == 'already_restored'
        status, result = hook('restrict', replay)
        assert status == 409 and receipts() == before + 1, (status, result)
        out['checks']['duplicate_release_and_old_event'] = True
        out['final_state'] = active()
        assert out['final_state'] == {'portal_status': 200, 'restriction': {'username': 'h1_abuse', 'restricted': False, 'ticket_id': None}, 'ticket_status': 200, 'claims': []}
        audit = "const fs=require('fs');const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});const keys=JSON.parse(fs.readFileSync(0,'utf8'));const rows=db.prepare('SELECT data FROM execution_data').all();console.log(JSON.stringify({payload_rows:rows.length,rows_with_keys:rows.filter(r=>keys.some(k=>String(r.data).includes(k))).length}));"
        def privacy():
            value = json.loads(compose('exec', '-T', 'n8n', 'node', '-e', audit, stdin=json.dumps([
                env_values()[k] for k in ('H1_DETECTION_KEY', 'H1_OPERATOR_KEY', 'PORTAL_RESPONSE_KEY', 'TICKET_STORE_KEY')])))
            return value if value['payload_rows'] == value['rows_with_keys'] == 0 else None
        out['checks']['persisted_execution_privacy'] = wait_for(privacy, 'payload deletion', 20)
        out['result'] = 'PASS'
        print('PASS: write 429; login/read 200; other citizens write 201; release -> write 201 and ticket restored.', flush=True)
    except Exception as error:
        out.update(result='FAIL', failure=scrub(str(error) or type(error).__name__),
                   failure_location=traceback.extract_tb(error.__traceback__)[-1].lineno)
        raise
    finally:
        try:
            graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
            if out.get('result') != 'PASS':
                if replay:
                    hook('restrict', replay)  # reconcile any applied-but-unrecorded response
                for t in tickets():
                    if t['status'] in ('responding', 'verified'):
                        status, _ = hook('release', {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'ticket_id': t['ticket_id']})
                        out['cleanup_release_status'] = status
                out['cleanup_state'] = active()
        except Exception as error:
            out['cleanup_error'] = scrub(str(error))
        out['finished_at'] = now()
        evidence.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
        print('Evidence: ' + str(evidence), flush=True)


if __name__ == '__main__':
    try:
        verify()
    except Exception as error:
        raise SystemExit(scrub(str(error)))
