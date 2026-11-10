"""S10 on real traffic: ICMP probe + 404 scan + failed login from the lab attacker, all crossing the pfSense VM ->
pfSense syslog and portal GELF -> Graylog S10 definition -> n8n (ticket first) -> portal block + pfSense block ->
duplicate replay -> operator release of that ticket -> both clients back to 200, nothing left.

Nothing is injected on the detection path; the duplicate and stale-release checks replay the observed decision.
Prerequisites: s10_lab.py up, pfsense, configure; serial shell open; P04 adapter installed.
"""
import concurrent.futures
import json
import subprocess
import time
from datetime import datetime, timezone

import pf_lab as lab
import s10_lab
import pf_verify as pv
from s8_lab import http

S = lab.SETTINGS
TARGET, NORMAL = S['clients']['attacker'], S['clients']['normal']
BASE = f"http://{S['portal']['ip']}:{S['portal']['port']}"
CLIENT = r'''
import json, subprocess, sys
from http.cookiejar import CookieJar
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
base, op, run_id, wan = sys.argv[1:5]
opener = build_opener(HTTPCookieProcessor(CookieJar()))
def req(path, body=None, headers=None):
    r = Request(base + path, data=None if body is None else json.dumps(body).encode(),
                headers={'Content-Type': 'application/json', **(headers or {})})
    try: res = opener.open(r, timeout=8)
    except HTTPError as e: res = e
    with res:
        raw = res.read()
        try: data = json.loads(raw or b'{}')
        except ValueError: data = {}
        return res.status, data
if op == 'ping':
    print(json.dumps({'ping_exit': subprocess.run(['ping', '-c', '3', '-W', '1', wan], capture_output=True).returncode}))
elif op == 'scan':
    print(json.dumps({'status': req('/s10-missing-' + run_id)[0]}))
else:
    s, me = req('/api/v1/auth/me')
    s2, _ = req('/api/v1/auth/login', {'username': 's10_absent_' + run_id[-8:], 'password': 'synthetic-invalid-password'},
                {'X-CSRF-Token': me['data']['csrf_token']})
    print(json.dumps({'status': s2}))
'''


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def attack(op, run_id):
    return {'at': now(), **json.loads(lab.compose('exec', '-T', 'attacker', 'python', '-', BASE, op, run_id,
                                                  S['wan']['pfsense_ip'], stdin=CLIENT))}


def env():
    return lab.env_values()


def hook(path, body, role='detection'):
    header, key = (('X-S10-Detection-Key', 'S10_DETECTION_KEY') if role == 'detection'
                   else ('X-S10-Operator-Key', 'S10_OPERATOR_KEY'))
    return http(f"http://127.0.0.1:{env()['N8N_PORT']}/webhook/{path}", body, {header: env()[key]}, timeout=240)


def tickets():
    status, body = http(f"http://127.0.0.1:{env()['TICKET_PORT']}/api/v1/tickets?case_id=S10")
    assert status == 200, status
    return body['items']


def ticket(ident):
    status, body = http(f"http://127.0.0.1:{env()['TICKET_PORT']}/api/v1/tickets/{ident}")
    assert status == 200, status
    return body['ticket']


def portal_blocks():
    script = ("const k=JSON.parse(require('fs').readFileSync(0,'utf8'));"
              "fetch('http://portal-response:5000/api/v1/response/ips',{headers:{'X-Response-Key':k}})"
              ".then(r=>r.json().then(b=>console.log(JSON.stringify({status:r.status,body:b}))))")
    out = json.loads(lab.compose('exec', '-T', 'n8n', 'node', '-e', script, stdin=json.dumps(env()['PORTAL_RESPONSE_KEY'])))
    items = out['body'].get('data', {}).get('items', out['body'].get('data', []))
    return out['status'], sorted({i.get('ip') if isinstance(i, dict) else i for i in (items or [])})


def events(definition):
    body = s10_lab.graylog('/events/search', {'query': '', 'page': 1, 'per_page': 20, 'filter': {
        'alerts': 'include', 'event_definitions': [definition]}, 'timerange': {'type': 'relative', 'range': 1800}}, 'POST')
    return [e['event'] for e in body.get('events', [])]


def wait_for(check, label, seconds=240):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(3)
    raise AssertionError('timeout: ' + label)


def pf_status(run_id, n):
    return pv.adapter('status', f'{run_id}-status-{n}', run_id)


def verify(out):
    run_id = out['run_id']
    state = json.loads(s10_lab.STATE.read_text())
    definition = state['definition']
    assert not [t for t in tickets() if t['status'] in ('open', 'responding', 'verified')], 'active S10 ticket'
    out['preflight'] = {'pfsense': pf_status(run_id, 0)['state'], 'portal_blocks': portal_blocks()}
    assert not out['preflight']['pfsense']['configured'] and TARGET not in out['preflight']['portal_blocks'][1]
    out['baseline'] = {'attacker': pv.probe('attacker'), 'normal': pv.probe('normal')}
    assert out['baseline']['attacker']['result'] == out['baseline']['normal']['result'] == 200, out['baseline']
    before = {t['ticket_id'] for t in tickets()}

    s10_lab.graylog(f'/events/definitions/{definition}/schedule', {}, 'PUT')
    out['input'] = {'ping': attack('ping', run_id), 'scan': attack('scan', run_id), 'login': attack('login', run_id)}
    assert out['input']['ping']['ping_exit'] != 0 and out['input']['scan']['status'] == 404 \
        and out['input']['login']['status'] == 401, out['input']
    started = out['input']['ping']['at']
    # Only an event raised after this run's input counts (Graylog keeps earlier events in the search range).
    event = wait_for(lambda: next((e for e in events(definition) if e.get('fields', {}).get('src_ip') == TARGET
                                   and e.get('timestamp', '') >= started), None), 'Graylog S10 event')
    out['graylog_event'] = {k: event.get(k) for k in ('id', 'timestamp', 'timestamp_processing', 'event_definition_id', 'fields')}

    def responded():
        found = [t for t in tickets() if t['ticket_id'] not in before]
        if not found:
            return None
        t = ticket(found[0]['ticket_id'])
        applied = {(a['via'], a['action']) for a in t['actions'] if a['result'] in ('applied', 'already_applied')}
        return t if {('portal', 'block'), ('pfsense', 'block')} <= applied else None
    t = wait_for(responded, 'ticket with portal and pfSense blocks applied')
    ident = t['ticket_id']
    s10_lab.graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
    out['ticket_after_response'] = t
    assert event['id'] in t['event_ids'], (event['id'], t['event_ids'])
    assert all(a.get('applied_verified') is True for a in t['actions'] if a['result'] == 'applied'), t['actions']
    out['blocked'] = {'attacker': pv.probe('attacker'), 'normal': pv.probe('normal'),
                      'pfsense': pf_status(run_id, 1)['state'], 'portal_blocks': portal_blocks(),
                      'pf_rules': pv.easyrule_rules()}
    assert out['blocked']['attacker']['result'] != 200 and out['blocked']['normal']['result'] == 200, out['blocked']
    assert out['blocked']['pfsense']['configured'] and out['blocked']['pfsense']['rule_present']
    assert TARGET in out['blocked']['portal_blocks'][1], out['blocked']['portal_blocks']
    out['checks']['both_layers_applied'] = True

    replay = {'event_id': event['id'], 'asset_id': 'haedam-portal', 'case_id': 'S10', 'src_ip': TARGET,
              'detected_at': event['timestamp_processing'], 'dry_run': False, 'store_real': True}
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        duplicates = list(pool.map(lambda _: hook(s10_lab.WEBHOOK, replay), range(2)))
    out['checks']['duplicate_replay'] = [(s, (b[0] if isinstance(b, list) else b).get('verdict')) for s, b in duplicates]
    assert all(v == 'duplicate_no_action' for _, v in out['checks']['duplicate_replay']), duplicates
    assert len(ticket(ident)['actions']) == len(t['actions'])

    release = {'seat': 'B', 'case_id': 'S10', 'group_key': TARGET, 'asset_id': 'haedam-portal', 'ticket_id': ident}
    status, data = hook('haedam-release', {**release, 'ticket_id': 'T-20000101-0001'}, 'operator')
    out['checks']['stale_release'] = [status, (data[0] if isinstance(data, list) else data).get('verdict')]
    assert pf_status(run_id, 2)['state']['configured'], 'stale release changed pfSense'
    out['release_requested_at'] = now()
    status, data = hook('haedam-release', release, 'operator')
    out['release'] = {'status': status, 'body': data[0] if isinstance(data, list) else data}
    assert status == 200 and out['release']['body'].get('verdict') == 'released', out['release']
    time.sleep(1)
    out['restored'] = {'attacker': pv.probe('attacker'), 'normal': pv.probe('normal'),
                       'pfsense': pf_status(run_id, 3), 'portal_blocks': portal_blocks(), 'pf_rules': pv.easyrule_rules(),
                       'ticket': ticket(ident)}
    r = out['restored']
    assert r['attacker']['result'] == r['normal']['result'] == 200, r
    assert not r['pfsense']['state']['configured'] and not r['pfsense']['state']['rule_present'] and not r['pf_rules']
    assert not any(r['pfsense']['journal_state'].values()), r['pfsense']['journal_state']
    assert TARGET not in r['portal_blocks'][1] and r['ticket']['status'] == 'restored', r
    status, data = hook('haedam-release', release, 'operator')
    out['checks']['duplicate_release'] = [status, (data[0] if isinstance(data, list) else data).get('verdict')]
    out['result'] = 'PASS'


def main():
    run_id = 'S10-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = {'run_id': run_id, 'started_at': now(), 'checks': {}, 'result': 'running',
           'source_head': subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=lab.ROOT, capture_output=True, text=True).stdout.strip(),
           'source_dirty': bool(subprocess.run(['git', 'status', '--porcelain'], cwd=lab.ROOT, capture_output=True, text=True).stdout.strip())}
    path = lab.LOCAL / (run_id + '.json')
    try:
        verify(out)
    except (AssertionError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
        out.update(result='FAIL', error=lab.scrub(f'{type(error).__name__}: {error}')[:2000])
        try:
            s10_lab.graylog(f"/events/definitions/{json.loads(s10_lab.STATE.read_text())['definition']}/unschedule", {}, 'PUT')
        except Exception:
            pass
    out['finished_at'] = now()
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    print(out['result'], path)
    if out['result'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
