"""Actual HTTP -> portal GELF -> Graylog -> n8n -> block/ticket/release.

Authenticated webhook replays and service outage checks are separate from the
real detection path. Saves only allowlisted evidence fields, never credentials.
"""
import concurrent.futures
from datetime import datetime, timezone
import json
import hashlib
import time
import traceback
from urllib.parse import urlencode

from s8_lab import compose, env_values, graylog, http, LOCAL, ROOT, STATE, scrub

IP = '172.30.88.21'


def now():
    return datetime.now(timezone.utc).isoformat()


def client(service, operation='health', run_id='s8'):
    assert service in ('attacker', 'normal', 'scan-only', 'login-only')
    assert operation in ('health', 'scan', 'login')
    script = '''
import json, sys, time
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
op, run_id = sys.argv[1:]
base = 'http://portal:5000'
client = build_opener(HTTPCookieProcessor(CookieJar()))
def request(path, body=None, headers=None):
    r = Request(base + path, data=None if body is None else json.dumps(body).encode(),
                headers={'Content-Type':'application/json', **(headers or {})})
    try: response = client.open(r, timeout=10)
    except HTTPError as error: response = error
    with response:
        data=response.read()
        try: data=json.loads(data)
        except ValueError: data={}
        return response.status, data
start = datetime.now(timezone.utc).isoformat()
if op == 'login':
    status, me = request('/api/v1/auth/me')
    assert status == 200, status
    status, body = request('/api/v1/auth/login', {'username':'s8_absent_' + run_id[-12:], 'password':'synthetic-invalid-password'}, {'X-CSRF-Token':me['data']['csrf_token']})
elif op == 'scan': status, body = request('/s8-missing-' + run_id)
else: status, body = request('/api/v1/health')
print(json.dumps({'status':status,'error':body.get('error',{}).get('code'), 'started_at':start,'finished_at':datetime.now(timezone.utc).isoformat()}))
'''
    return json.loads(compose('exec', '-T', service, 'python', '-', operation, run_id, stdin=script, quiet=True))


def hook(path, body, role='detection', wrong=False):
    env = env_values()
    headers = {}
    if role:
        header, key = ('X-S8-Detection-Key', 'S8_DETECTION_KEY') if role == 'detection' else ('X-S8-Operator-Key', 'S8_OPERATOR_KEY')
        headers[header] = 'invalid-review-key' if wrong else env[key]
    return http(f"http://127.0.0.1:{env['N8N_PORT']}/webhook/" + path, body, headers, timeout=90)


def tickets():
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets?case_id=S8")
    assert status == 200, status
    return body['items']


def ticket(ident):
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets/{ident}")
    assert status == 200, status
    return body['ticket']


def events(definition):
    result = graylog('/events/search', {'query': f'event_definition_id:{definition}',
                     'timerange': {'type': 'relative', 'range': 1800}, 'page': 1, 'per_page': 100})
    return [item.get('event', item) for item in result.get('events', [])]


def receipts():
    script = "from haedam_portal import create_app; from haedam_portal.models import db,ResponseReceipt; from sqlalchemy import select,func; app=create_app(); ctx=app.app_context(); ctx.push(); print(db.session.scalar(select(func.count()).select_from(ResponseReceipt)))"
    return int(compose('exec', '-T', 'portal', 'python', '-c', script, quiet=True))


def wait_for(check, label, seconds=100):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(2)
    raise AssertionError('Timed out: ' + label)


def verify():
    state = json.loads(STATE.read_text())
    definition = state['definition']
    run_id = datetime.now(timezone.utc).strftime('S8-%Y%m%dT%H%M%SZ')
    out = {'run_id': run_id, 'started_at': now(), 'kind': 'actual-portal-http', 'checks': {}}
    files = [ROOT / name for name in ('Dockerfile', 'compose.yaml', 'compose.soc.yaml', 'compose.s8.yaml',
                                      'tools/build_s8_workflows.py', 'tools/s8_lab.py', 'tools/s8_verify.py', 'tools/s8_control.py')]
    files += sorted((ROOT / 'infra/n8n/portfolio-s8').glob('*.json'))
    files += sorted((ROOT / 'haedam-portal-backend/src').rglob('*.py'))
    files += sorted((ROOT / 'services/ticket-store').rglob('*.py'))
    out['source_sha256'] = {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    evidence = LOCAL / (run_id + '.json')
    ident, restore_body = None, None
    old_ticket_ids = {t['ticket_id'] for t in tickets()}
    old_events = {e['id'] for e in events(definition)}
    # Prevent old 15-minute inputs from being reported as new evidence.
    query = urlencode({'query': 'source:haedam-portal AND src_ip:172.30.88.* AND (rule:web-scan OR rule:login-bruteforce)', 'range': 900})
    if graylog('/search/universal/relative?' + query).get('total_results', 0):
        raise AssertionError('S8 inputs still in the 15-minute window. Wait 15 minutes or use a fresh owned lab volume set.')
    try:
        for path in ('haedam-s8-s10', 'haedam-effect-report', 'haedam-release'):
            role = 'detection' if path == 'haedam-s8-s10' else 'operator'
            for auth in ('missing', 'wrong'):
                status, _ = hook(path, {}, role=None if auth == 'missing' else role, wrong=auth == 'wrong')
                assert status == 403, (path, auth, status)
        status, _ = hook('haedam-release', {}, role='detection')
        assert status == 403
        out['checks']['webhook_auth'] = '7 unauthorized requests rejected with 403'
        status, _ = hook('haedam-s8-s10', {'event_id': 'scope-check', 'asset_id': 'haedam-portal', 'src_ip': IP, 'case_id': 'S10'})
        assert status == 400
        boundary_script = "import json,sys; from urllib.request import Request,urlopen; from urllib.error import HTTPError; key=json.load(sys.stdin)['key']; r=Request('http://portal:5000/api/v1/response/ips',headers={'X-Response-Key':key,'X-Forwarded-For':'172.30.89.2'});\ntry: print(urlopen(r,timeout=10).status)\nexcept HTTPError as e: print(e.code)"
        status = int(compose('exec', '-T', 'attacker', 'python', '-c', boundary_script,
                            stdin=json.dumps({'key': env_values()['PORTAL_RESPONSE_KEY']}), quiet=True))
        assert status == 403
        out['checks']['response_network_boundary'] = 'Correct portal key plus spoofed XFF from attacker still 403'
        for service in ('attacker', 'normal', 'scan-only', 'login-only'):
            assert client(service)['status'] == 200
        graylog(f'/events/definitions/{definition}/schedule', {}, 'PUT')
        out['checks']['scan_only'] = client('scan-only', 'scan', run_id)
        out['checks']['login_only'] = client('login-only', 'login', run_id)
        out['attack_scan'] = client('attacker', 'scan', run_id)
        assert out['checks']['scan_only']['status'] == out['attack_scan']['status'] == 404
        assert out['checks']['login_only']['status'] == 401
        print('Negative controls sent; observing 40 seconds across detection cycles.', flush=True)
        time.sleep(40)
        assert {t['ticket_id'] for t in tickets()} == old_ticket_ids
        assert {e['id'] for e in events(definition)} == old_events
        out['checks']['no_cross_ip_correlation'] = True
        out['attack_login'] = client('attacker', 'login', run_id)
        assert out['attack_login']['status'] == 401
        found = wait_for(lambda: next((t for t in tickets() if t['ticket_id'] not in old_ticket_ids
                                      and t['group_key'] == IP and t['status'] == 'responding'), None), 'actual ticket and response')
        ident = found['ticket_id']
        wait_for(lambda: client('attacker')['status'] == 403, 'actual attacker 403')
        detected = wait_for(lambda: next((e for e in events(definition) if e['id'] not in old_events
                                          and e.get('fields', {}).get('src_ip') == IP), None), 'Graylog S8 event')
        graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
        out['graylog_event'] = {k: detected.get(k) for k in ('id', 'event_definition_id', 'timestamp', 'timestamp_processing', 'fields', 'source_streams')}
        assert state['stream'] in detected['source_streams']
        out['blocked'] = client('attacker')
        out['normal_during_block'] = client('normal')
        assert out['blocked']['status'] == 403 and out['blocked']['error'] == 'IP_BLOCKED'
        assert out['normal_during_block']['status'] == 200
        out['ticket_after_block'] = ticket(ident)
        assert detected['id'] in out['ticket_after_block']['event_ids']
        assert out['ticket_after_block']['data_origin'] == 'live'
        input_query = urlencode({'query': 'source:haedam-portal AND src_ip:172.30.88.21 AND (rule:web-scan OR rule:login-bruteforce)', 'range': 900})
        raw = graylog('/search/universal/relative?' + input_query)['messages']
        input_events = [json.loads(row['message']['portal_event']) for row in raw]
        out['input_events'] = [{k: e[k] for k in ('event_id', 'timestamp', 'src_ip', 'event_type')} for e in input_events]
        times = [datetime.fromisoformat(e['timestamp']) for e in input_events]
        condition_at = max(times)
        detection_at = datetime.fromisoformat(detected['timestamp_processing'])
        response_at = datetime.fromisoformat(out['ticket_after_block']['responded_at'])
        out['metrics'] = {'basis': 'Actual portal JSONL event timestamps collected by Graylog; ticket response timestamp',
                          'condition_met_at': condition_at.isoformat(), 'input_count': len(input_events),
                          'condition_to_detection_seconds': round((detection_at - condition_at).total_seconds(), 3),
                          'detection_to_response_seconds': round((response_at - detection_at).total_seconds(), 3),
                          'condition_to_response_seconds': round((response_at - condition_at).total_seconds(), 3)}
        actions = out['ticket_after_block']['actions']
        assert len(actions) == 1 and actions[0]['applied_verified'] is True, 'Portal mutation succeeded but independent list readback was not verified'
        print('PASS actual Graylog event -> n8n -> ticket ' + ident + ', attacker 403 / normal 200', flush=True)
        replay = {'event_id': detected['id'], 'case_id': 'S8', 'asset_id': 'haedam-portal',
                  'src_ip': IP, 'detected_at': detected['timestamp_processing'], 'dry_run': False, 'store_real': True}
        before = receipts()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            duplicates = list(pool.map(lambda _: hook('haedam-s8-s10', replay), range(2)))
        assert all(status == 200 and data[0]['verdict'] == 'duplicate_no_action' for status, data in duplicates), duplicates
        assert receipts() == before and len(ticket(ident)['actions']) == 1
        out['checks']['concurrent_duplicate'] = {'responses': [d[1][0]['verdict'] for d in duplicates], 'new_portal_receipts': 0}
        restore_body = {'seat': 'B', 'case_id': 'S8', 'group_key': IP, 'asset_id': 'haedam-portal', 'ticket_id': ident}
        status, data = hook('haedam-release', {**restore_body, 'ticket_id': 'T-20000101-0001'}, 'operator')
        assert status == 503 and data[0]['verdict'] == 'held_stale_release_ticket', (status, data)
        assert client('attacker')['status'] == 403 and receipts() == before
        out['checks']['stale_release_rejected'] = status
        effect = {**restore_body, 'target': IP, 'bot': '112', 'via': 'portal', 'action': 'block',
                  'event_id': detected['id'], 'effect_verified': True, 'applied_verified': True,
                  'effect_verified_at': now(), 'detail': 'Independent attacker HTTP 403 IP_BLOCKED; normal HTTP 200'}
        status, data = hook('haedam-effect-report', effect, 'operator')
        assert status == 200 and data[0]['ok'] is True, (status, data)
        assert ticket(ident)['status'] == 'verified'
        out['checks']['effect_recorded'] = 'verified'
        compose('stop', 'ticket-store', quiet=True)
        try:
            status, data = hook('haedam-s8-s10', replay)
            assert status == 503 and data[0]['ok'] is False, (status, data)
            assert receipts() == before
            out['checks']['ticket_outage'] = {'http_status': status, 'verdict': data[0].get('verdict'), 'new_portal_receipts': 0}
        finally:
            compose('up', '-d', '--wait', 'ticket-store', quiet=True)
        status, data = hook('haedam-s8-s10', replay)
        assert status == 200 and data[0]['verdict'] == 'duplicate_no_action'
        out['checks']['same_event_retry_after_recovery'] = 'duplicate_no_action'
        status, data = hook('haedam-release', restore_body, 'operator')
        assert status == 200 and data[0]['ok'] is True and data[0]['verdict'] == 'released', (status, data)
        out['release_response'] = data[0]
        out['restored_attacker'] = client('attacker')
        out['restored_normal'] = client('normal')
        assert out['restored_attacker']['status'] == out['restored_normal']['status'] == 200
        out['ticket_final'] = ticket(ident)
        assert out['ticket_final']['status'] == 'restored'
        assert [a['result'] for a in out['ticket_final']['actions']] == ['applied', 'released']
        assert receipts() == before + 1
        active_script = """const fs=require('fs'); const k=JSON.parse(fs.readFileSync(0,'utf8'));
        (async()=>{
          const p=await fetch('http://portal-response:5000/api/v1/response/ips',{headers:{'X-Response-Key':k.portal}});
          const t=await fetch('http://ticket-store:8088/api/v1/tickets/active?asset_id=haedam-portal&via=portal&action=block&target=172.30.88.21',{headers:{'X-Response-Key':k.ticket}});
          const pb=await p.json(),tb=await t.json();
          console.log(JSON.stringify({portal_status:p.status,ticket_status:t.status,blocked_ips:pb.data?.items,active_claims:tb.tickets}));
        })().catch(()=>process.exit(1));"""
        active = json.loads(compose('exec', '-T', 'n8n', 'node', '-e', active_script,
                          stdin=json.dumps({'portal': env_values()['PORTAL_RESPONSE_KEY'], 'ticket': env_values()['TICKET_STORE_KEY']}), quiet=True))
        assert active == {'portal_status': 200, 'ticket_status': 200, 'blocked_ips': [], 'active_claims': []}, active
        out['checks']['no_active_response_after_restore'] = active
        status, data = hook('haedam-release', restore_body, 'operator')
        assert status == 200 and data[0]['verdict'] == 'nothing_to_release'
        assert receipts() == before + 1
        out['checks']['duplicate_release'] = 'nothing_to_release'
        # Replay an old event after restore: must not create a new block/ticket.
        status, data = hook('haedam-s8-s10', replay)
        assert status >= 400 and receipts() == before + 1 and client('attacker')['status'] == 200
        out['checks']['old_event_after_restore'] = {'http_status': status, 'new_portal_receipts': 0}
        privacy_script = "const fs=require('fs'); const {DatabaseSync}=require('node:sqlite'); const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true}); const keys=JSON.parse(fs.readFileSync(0,'utf8')); const rows=db.prepare('SELECT data FROM execution_data').all(); console.log(JSON.stringify({payload_rows:rows.length,rows_with_keys:rows.filter(r=>keys.some(k=>String(r.data).includes(k))).length}));"
        def privacy_after_completion():
            value = json.loads(compose('exec', '-T', 'n8n', 'node', '-e', privacy_script,
                               stdin=json.dumps([env_values()[k] for k in ('S8_DETECTION_KEY','S8_OPERATOR_KEY','PORTAL_RESPONSE_KEY','TICKET_STORE_KEY')]), quiet=True))
            return value if value['payload_rows'] == 0 and value['rows_with_keys'] == 0 else None
        privacy = wait_for(privacy_after_completion, 'completed execution payload deletion', seconds=15)
        out['checks']['persisted_execution_privacy'] = privacy
        out['result'] = 'PASS'
        print('PASS ticket verified -> restored; both clients 200; duplicate/outage/stale-event checks passed.', flush=True)
    except Exception as error:
        out['result'] = 'FAIL'
        out['failure'] = scrub(str(error) or type(error).__name__)
        out['failure_location'] = traceback.extract_tb(error.__traceback__)[-1].lineno
        raise
    finally:
        graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
        # Best-effort recovery on failed verification; never mark that as success.
        if out.get('result') != 'PASS':
            candidates = [t for t in tickets() if t['group_key'] == IP and t['status'] in ('responding', 'verified')]
            if candidates:
                body = {'seat': 'B', 'case_id': 'S8', 'group_key': IP, 'asset_id': 'haedam-portal', 'ticket_id': candidates[0]['ticket_id']}
                status, _ = hook('haedam-release', body, 'operator')
                out['cleanup_release_status'] = status
                out['cleanup_attacker'] = client('attacker')
        out['finished_at'] = now()
        evidence.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
        print('Evidence: ' + str(evidence), flush=True)


if __name__ == '__main__':
    try:
        verify()
    except Exception as error:
        raise SystemExit(scrub(str(error)))
