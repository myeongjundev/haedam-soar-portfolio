"""S10 partial failures, called directly on the authenticated n8n webhook with a labelled test event (not Graylog):

F1 ticket store down  -> no portal or pfSense change, not a success.
F2 relay down         -> portal block applied, pfSense failed -> not a success; after the relay is back, the
                         operator release of that ticket removes what was applied and the ticket matches reality.
Each step reads the real portal block list, the adapter state and both clients. Detection stays paused.
"""
import json
import subprocess
from datetime import datetime, timezone

import s10_verify as v

lab = v.lab


def state(tag):
    st = v.pf_status('fault', tag)['state']
    return {'pfsense': {k: st[k] for k in ('configured', 'table_present', 'rule_present')},
            'portal_blocks': v.portal_blocks()[1], 'attacker': v.pv.probe('attacker')['result'],
            'normal': v.pv.probe('normal')['result']}


def first(data):
    return data[0] if isinstance(data, list) and data else data


def event(run_id, name):
    return {'event_id': f'{run_id}-{name}', 'asset_id': 'haedam-portal', 'case_id': 'S10', 'src_ip': v.TARGET,
            'detected_at': v.now(), 'dry_run': False, 'store_real': True}


def run(out):
    run_id = out['run_id']
    assert not [t for t in v.tickets() if t['status'] in ('open', 'responding', 'verified')], 'active S10 ticket'
    clean = state(0)
    assert clean == {'pfsense': {'configured': False, 'table_present': False, 'rule_present': False},
                     'portal_blocks': [], 'attacker': 200, 'normal': 200}, clean
    before = {t['ticket_id'] for t in v.tickets()}

    lab.compose('stop', 'ticket-store')
    try:
        status, data = v.hook(v.s10_lab.WEBHOOK, event(run_id, 'ticket-down'))
    finally:
        lab.compose('up', '-d', '--wait', 'ticket-store', timeout=300)
    out['F1_ticket_store_down'] = {'status': status, 'verdict': first(data).get('verdict'), 'after': state(1),
                                   'new_tickets': sorted({t['ticket_id'] for t in v.tickets()} - before)}
    f1 = out['F1_ticket_store_down']
    assert f1['status'] != 200 and f1['after'] == clean and not f1['new_tickets'], f1

    lab.compose('stop', 'controller')
    try:
        status, data = v.hook(v.s10_lab.WEBHOOK, event(run_id, 'relay-down'))
    finally:
        lab.compose('up', '-d', 'controller', timeout=300)
    new = sorted({t['ticket_id'] for t in v.tickets()} - before)
    ticket = v.ticket(new[0]) if new else None
    out['F2_relay_down'] = {'status': status, 'verdict': first(data).get('verdict'), 'after': state(2),
                            'ticket': ticket and {'id': ticket['ticket_id'], 'status': ticket['status'],
                                                  'actions': [(a['via'], a['action'], a['result']) for a in ticket['actions']]}}
    f2 = out['F2_relay_down']
    assert f2['status'] != 200, f2  # one layer only: never reported as a success
    assert v.TARGET in f2['after']['portal_blocks'] and not f2['after']['pfsense']['configured'], f2
    release = {'seat': 'B', 'case_id': 'S10', 'group_key': v.TARGET, 'asset_id': 'haedam-portal', 'ticket_id': ticket['ticket_id']}
    status, data = v.hook('haedam-release', release, 'operator')
    final = v.ticket(ticket['ticket_id'])
    out['F2_release'] = {'status': status, 'verdict': first(data).get('verdict'), 'after': state(3),
                         'ticket': {'status': final['status'], 'actions': [(a['via'], a['action'], a['result']) for a in final['actions']]}}
    assert out['F2_release']['after'] == clean, out['F2_release']
    out['result'] = 'PASS'


def main():
    out = {'run_id': 'S10FAULT-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'), 'started_at': v.now(), 'result': 'running',
           'source_head': subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=lab.ROOT, capture_output=True, text=True).stdout.strip(),
           'source_dirty': bool(subprocess.run(['git', 'status', '--porcelain'], cwd=lab.ROOT, capture_output=True, text=True).stdout.strip())}
    try:
        run(out)
    except (AssertionError, RuntimeError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        out.update(result='FAIL', error=lab.scrub(f'{type(error).__name__}: {error}')[:2000])
    out['finished_at'] = v.now()
    path = lab.LOCAL / (out['run_id'] + '.json')
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    print(out['result'], path)
    if out['result'] != 'PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
