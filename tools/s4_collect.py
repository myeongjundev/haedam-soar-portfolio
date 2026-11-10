"""Bounded GET-only S4 account/ticket snapshots from the owned observer container."""
import argparse
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

from build_s4_workflows import load_settings
from s1_client import InputStopped, now, save
from s4_client import runtime_guard
from s4_settings import digest, plan as input_plan


def require(value):
    if not value: raise ValueError('snapshot_contract_mismatch')


def instant(value):
    require(isinstance(value, str) and len(value) <= 40)
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None)
    return result


def sources():
    return {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()
            for n in ('s4_collect.py', 's4_settings.py', 's4_client.py', 'build_s4_workflows.py')}


def guard(s):
    runtime_guard(s)
    if os.environ.get('HAEDAM_S4_ROLE') != 'observer': raise ValueError('observer_required')


def ticket_id(value):
    require(isinstance(value, str) and re.fullmatch(r'T-\d{8}-\d{4}', value))
    return value


def account(s, value):
    require(value.get('success') is True)
    data = value['data']
    require(data['username'] == s['accounts']['target'] and type(data['user_id']) is int and data['user_id'] > 0)
    require(type(data['locked']) is bool and type(data['active_sessions']) is int and data['active_sessions'] >= 0)
    if data['owner_ticket_id'] is not None: ticket_id(data['owner_ticket_id'])
    return {k: data[k] for k in ('username', 'user_id', 'locked', 'active_sessions', 'owner_ticket_id')}


def ticket(s, value, expected_id, uid):
    require(value.get('ok') is True)
    t = value['ticket']
    expected = {'ticket_id': ticket_id(expected_id), 'seat': 'A', 'case_id': 'S4', 'asset_id': s['asset_id'],
                'src_ip': s['addresses']['attacker'], 'username': s['accounts']['target'],
                'group_key': 'S4|' + s['accounts']['target'], 'data_origin': 'live'}
    require(all(t.get(k) == v for k, v in expected.items()))
    require(t['status'] in ('open', 'responding', 'verified', 'restored', 'closed'))
    result = {**expected, 'status': t['status']}
    for key in ('created_at', 'updated_at', 'restored_at'):
        value = t.get(key)
        if value is not None: instant(value)
        result[key] = value
    require(isinstance(t['event_ids'], list) and 1 <= len(t['event_ids']) <= 1000)
    require(all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', v) for v in t['event_ids']))
    result['event_ids'] = t['event_ids']
    require(isinstance(t['actions'], list) and len(t['actions']) <= 1000)
    result['actions'] = []
    for action in t['actions']:
        require(action['bot'] == '111' and action['via'] == 'portal' and action['action'] in ('lock', 'unlock')
                and action['target'] == s['accounts']['target'] + ':' + str(uid))
        require(action['result'] in ('applied', 'already_applied', 'released', 'failed', 'skipped'))
        if action['result'] in ('applied', 'already_applied'): require(action['action'] == 'lock')
        if action['result'] == 'released': require(action['action'] == 'unlock')
        a = {k: action[k] for k in ('bot', 'via', 'action', 'target', 'result')}
        for key in ('applied_verified', 'effect_verified', 'duplicate'):
            v = action.get(key)
            require(v is None or type(v) is bool)
            a[key] = v
        result['actions'].append(a)
    return result


def active(actions):
    claims = {}
    for a in actions:
        if a.get('duplicate') is True: continue
        key = (a['bot'], a['via'], 'lock' if a['action'] == 'unlock' else a['action'], a['target'])
        if a['result'] in ('applied', 'already_applied'): claims[key] = a
        elif a['result'] == 'released': claims.pop(key, None)
    return claims


def plan(s, c, run_id, phase, tid=None):
    load_settings(s, c); input_plan(s, run_id, 'trigger6')
    require(phase in ('baseline', 'locked', 'restored'))
    require(tid is None if phase == 'baseline' else ticket_id(tid))
    return {'case_id': 'S4', 'run_id': run_id, 'phase': phase, 'project': s['project'], 'mode': 'plan_only',
            'settings_sha256': digest(s), 'integration_sha256': digest(c), 'ticket_id': tid,
            'maximum_http_requests': 1 if phase == 'baseline' else 3,
            'http_method': 'GET', 'end_to_end_status': 'not_run'}


class Reader:
    def __init__(self, s, c, key):
        self.s, self.c, self.key = s, c, key

    def get(self, kind, tid=None):
        if kind == 'account':
            u = urlsplit(self.c['portal_url'])
            path = '/api/v1/response/s4/accounts/' + self.s['accounts']['target']
            # Shared n8n namespace; the existing response /32 authorization remains unchanged.
            source = (self.s['addresses']['n8n_response'], 0)
            headers = {self.c['credentials']['portal']['header']: self.key}
        elif kind == 'ticket':
            u = urlsplit(self.s['observation']['ticket_read_url'])
            path = '/api/v1/tickets/' + ticket_id(tid)
            source, headers = None, {}
        else: raise ValueError('unsupported_read')
        connection = http.client.HTTPConnection(u.hostname, u.port,
            timeout=self.s['request_timeout_seconds'], source_address=source)
        try:
            connection.request('GET', path, headers={**headers, 'Accept': 'application/json'})
            response = connection.getresponse(); raw = response.read(1048577)
            require(len(raw) <= 1048576 and response.status == 200)
            data = json.loads(raw); require(isinstance(data, dict))
            return data
        finally: connection.close()


def execute(s, c, run_id, phase, output, key, tid=None, attempt=1, *, runtime=guard, reader_factory=Reader):
    p = plan(s, c, run_id, phase, tid); runtime(s)
    require(isinstance(key, str) and re.fullmatch(r'[a-f0-9]{64}', key))
    require(type(attempt) is int and 1 <= attempt <= 9)
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    path = output / f'{run_id}-snapshot-{phase}-{attempt}.json'
    out = {**p, 'mode': 'actual_http_snapshot', 'status': 'running', 'started_at': now(),
           'source_sha256': sources(), 'records': []}
    with path.open('x', encoding='utf-8') as stream: json.dump(out, stream)
    try:
        reader = reader_factory(s, c, key)
        def read(kind):
            if (output / s['stop_filename']).exists(): raise InputStopped()
            require(len(out['records']) < p['maximum_http_requests'])
            started = now(); value = reader.get(kind, tid)
            out['records'].append({'operation': kind, 'started_at': started, 'finished_at': now()})
            return value
        a = account(s, read('account')); out['account'] = a
        if phase == 'baseline':
            require(not a['locked'] and a['owner_ticket_id'] is None and a['active_sessions'] >= 2)
        else:
            t = ticket(s, read('ticket'), tid, a['user_id']); out['ticket'] = t
            require(account(s, read('account')) == a)  # Avoid a torn snapshot during lock/release.
            claims = active(t['actions'])
            if phase == 'locked':
                require(a['locked'] and a['active_sessions'] == 0 and a['owner_ticket_id'] == tid)
                require(t['status'] in ('responding', 'verified') and len(claims) == 1)
                require(next(iter(claims.values()))['applied_verified'] is True)
            else:
                require(not a['locked'] and a['owner_ticket_id'] is None and not claims
                        and t['status'] == 'restored' and t['restored_at'] is not None)
        out['status'] = 'snapshot_passed'
    except (InputStopped, KeyboardInterrupt): out.update(status='stopped', reason='stop_requested')
    except Exception as error: out.update(status='failed', reason=type(error).__name__)
    out['finished_at'] = now(); save(path, out)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True); parser.add_argument('--integration', type=Path, required=True)
    parser.add_argument('--run-id', required=True); parser.add_argument('--phase', choices=['baseline', 'locked', 'restored'], required=True)
    parser.add_argument('--ticket-id'); parser.add_argument('--attempt', type=int, default=1)
    parser.add_argument('--execute', action='store_true'); args = parser.parse_args()
    try:
        s, c = load_settings(json.loads(args.settings.read_text(encoding='utf-8-sig')),
                             json.loads(args.integration.read_text(encoding='utf-8-sig')))
        if args.execute:
            guard(s); key = sys.stdin.readline(67).rstrip('\r\n')
            result = execute(s,c,args.run_id,args.phase,s['paths']['evidence_mount'],key,args.ticket_id,args.attempt)
        else: result = plan(s,c,args.run_id,args.phase,args.ticket_id)
        print(json.dumps(result, ensure_ascii=False))
        if args.execute and result['status'] != 'snapshot_passed': raise SystemExit(1)
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(2, 'S4 collector refused; no response bodies or credentials printed.\n')


if __name__ == '__main__': main()
