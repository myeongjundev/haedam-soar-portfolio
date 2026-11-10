"""Offline S4 artifact consistency, not engine execution/provenance attestation."""
import argparse
import json
from pathlib import Path
import re

from s4_collect import require, instant, active, ticket, account
from s4_settings import digest, plan
from s4_rehearsal import load_bundle


def provenance(value, packet):
    require(isinstance(value.get('source_sha256'), dict) and value['source_sha256'])
    for filename, hash_value in value['source_sha256'].items():
        require(hash_value == packet['source_sha256']['tools/' + filename])


def metadata(value, s, packet, mode, status):
    require(all(value.get(k) == v for k, v in {'case_id': 'S4', 'run_id': packet['run_id'], 'project': s['project'],
            'settings_sha256': digest(s), 'mode': mode, 'status': status}.items()))
    required_sources = {
        'actual_http_input': {'s4_client.py', 's4_settings.py', 's1_client.py'},
        'actual_http_probe': {'s4_probe.py', 's4_settings.py', 's4_client.py', 's1_client.py', 's1_settings.py'},
        'actual_http_snapshot': {'s4_collect.py', 's4_settings.py', 's4_client.py', 'build_s4_workflows.py'},
    }
    require(set(value.get('source_sha256', {})) == required_sources[mode])
    provenance(value, packet)
    previous = instant(value['started_at'])
    for record in value['records']:
        start, end = instant(record['started_at']), instant(record['finished_at'])
        require(previous <= start <= end); previous = end
    require(previous <= instant(value['finished_at']))


def release_body(s, snapshot):
    require(snapshot.get('phase') == 'locked' and snapshot.get('status') == 'snapshot_passed'
            and snapshot.get('settings_sha256') == digest(s) and snapshot.get('project') == s['project'])
    a = account(s, {'success': True, 'data': snapshot['account']})
    t = ticket(s, {'ok': True, 'ticket': snapshot['ticket']}, snapshot['ticket_id'], a['user_id'])
    require(a['locked'] and a['active_sessions'] == 0 and a['owner_ticket_id'] == t['ticket_id'])
    require(t['status'] in ('responding', 'verified') and len(active(t['actions'])) == 1
            and next(iter(active(t['actions']).values()))['applied_verified'] is True)
    # This only prepares a body. The workflow must recheck current ownership at execution time.
    return {k: t[k] for k in ('case_id', 'asset_id', 'src_ip', 'username', 'ticket_id')}


def check(s, packet, evidence, definition_id):
    p = plan(s, packet['run_id'], 'trigger6'); i = evidence['input']
    require(re.fullmatch(r'[a-f0-9]{24}', definition_id or ''))
    require(packet['settings_sha256'] == digest(s))
    metadata(i, s, packet, 'actual_http_input', 'input_complete')
    require(all(i.get(k) == p[k] for k in ('profile', 'username', 'source_ip', 'target_ip', 'target_port', 'expected_login_statuses')))
    require(i['observed_login_statuses'] == p['expected_login_statuses'] and i['authenticated_identity_checks'] == 1)
    require([r['operation'] for r in i['records']] == ['health'] + ['session', 'login'] * 5 + ['session', 'login', 'session'])
    require(len(i['records']) == p['maximum_http_requests'])
    login = [r for r in i['records'] if r['operation'] == 'login']
    require([r['status'] for r in login] == p['expected_login_statuses'])
    require(all(r['source_ip'] == p['source_ip'] for r in i['records']))
    require(all(r['status'] == 200 for r in i['records'] if r['operation'] != 'login'))
    require(all(r.get('error_code') == 'INVALID_CREDENTIALS' for r in login[:-1]))
    require(all((instant(b['started_at']) - instant(a['finished_at'])).total_seconds() >= p['interval_seconds'] for a,b in zip(login,login[1:])))
    require((instant(login[-1]['finished_at']) - instant(login[0]['started_at'])).total_seconds() < s['policy']['window_seconds'])
    probes, snapshots = evidence['probes'], evidence['snapshots']
    baseline = probes['baseline']; ids = baseline['user_ids']; session_set = baseline['session_set_id']
    require(re.fullmatch(r'[a-f0-9]{32}', session_set))
    require(set(ids) == {'target', 'normal'} and all(type(v) is int and v > 0 for v in ids.values()) and ids['target'] != ids['normal'])
    for phase in ('baseline', 'locked', 'restored'):
        q, snap = probes[phase], snapshots[phase]
        metadata(q, s, packet, 'actual_http_probe', 'probe_passed')
        metadata(snap, s, packet, 'actual_http_snapshot', 'snapshot_passed')
        require(q['phase'] == snap['phase'] == phase and q['session_set_id'] == session_set and q['user_ids'] == ids)
        require(q['accounts'] == s['accounts'] and q['source_ip'] == s['addresses']['normal'])
        require(all(r['source_ip'] == s['addresses']['normal'] for r in q['records']))
        require(snap['integration_sha256'] == packet['integration_sha256'])
        a = account(s, {'success': True, 'data': snap['account']}); require(a['user_id'] == ids['target'])
        require(instant(q['finished_at']) <= instant(snap['started_at']))
        checks = q['checks']
        if phase == 'baseline':
            require(checks == {'target_sessions_prepared': 2, 'normal_session_prepared': True})
            ops = ['health'] + ['session', 'register'] * 2 + ['session', 'login', 'session'] * 3
            require(not a['locked'] and a['owner_ticket_id'] is None and a['active_sessions'] >= 2)
            require([r['operation'] for r in snap['records']] == ['account'])
            require(all(r['status'] in (201,409) if r['operation'] == 'register' else r['status'] == 200 for r in q['records']))
        else:
            require(checks == {'same_passwords': True, 'target1_revoked': True, 'target2_revoked': True,
                'normal_old_authenticated': True, 'target_new_login_status': 401 if phase == 'locked' else 200,
                'normal_new_authenticated': True})
            ops = ['health'] + ['session'] * 3 + ['session', 'login'] + ([] if phase == 'locked' else ['session']) + ['session', 'login', 'session']
            expected_statuses = [200] * len(ops)
            if phase == 'locked': expected_statuses[5] = 401
            require([r['status'] for r in q['records']] == expected_statuses)
            require([r['operation'] for r in snap['records']] == ['account', 'ticket', 'account'])
        require([r['operation'] for r in q['records']] == ops)
    require(instant(snapshots['baseline']['finished_at']) <= instant(i['started_at']))
    require(instant(i['finished_at']) <= instant(probes['locked']['started_at']))
    require(instant(snapshots['locked']['finished_at']) <= instant(probes['restored']['started_at']))
    before, after = snapshots['locked'], snapshots['restored']
    release_body(s, before)
    a = after['account']; require(not a['locked'] and a['owner_ticket_id'] is None and a['active_sessions'] >= 1)
    bt = before['ticket']; at = ticket(s, {'ok': True, 'ticket': after['ticket']}, bt['ticket_id'], ids['target'])
    require(after['ticket_id'] == bt['ticket_id'] and at['status'] == 'restored' and not active(at['actions']))
    require(at['created_at'] == bt['created_at'])
    require((instant(bt['created_at']) - instant(i['started_at'])).total_seconds() >= -packet['clock_tolerance_seconds'])
    require((instant(before['finished_at']) - instant(bt['created_at'])).total_seconds() >= -packet['clock_tolerance_seconds'])
    size = len(bt['actions']); require(at['actions'][:size] == bt['actions'])
    require(any(a['action'] == 'unlock' and a['result'] == 'released' and a['applied_verified'] is True
                and a.get('duplicate') is not True for a in at['actions'][size:]))
    event = evidence['graylog_event'].get('event', evidence['graylog_event'])
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', event['id']))
    require(event['event_definition_id'] == definition_id and event['fields']['username'] == p['username']
            and event['fields']['src_ip'] == p['source_ip'])
    require(event['id'] in bt['event_ids'] and event['id'] in at['event_ids'])
    detected = instant(event['timestamp_processing']); tolerance = packet['clock_tolerance_seconds']
    require((detected - instant(login[-1]['started_at'])).total_seconds() >= -tolerance)
    require((instant(probes['locked']['started_at']) - detected).total_seconds() >= -tolerance)
    release = evidence['release_response']
    require(release.get('ok') is True and release.get('verdict') == 'released' and release.get('ticket_id') == bt['ticket_id'])
    restored = instant(at['restored_at'])
    require((restored - instant(before['finished_at'])).total_seconds() >= -1)  # ticket timestamps may be truncated to seconds
    require((instant(probes['restored']['started_at']) - restored).total_seconds() >= -tolerance)
    return {'case_id': 'S4', 'run_id': packet['run_id'], 'artifact_consistency': 'passed', 'provenance_attested': False,
            'ticket_id': bt['ticket_id'], 'event_id': event['id'], 'target_login_sequence': [200,401,200],
            'old_target_sessions_revoked_after_restore': 2, 'normal_session_preserved': True,
            'same_passwords': True, 'ticket_status': 'restored', 'active_actions': 0,
            'scope': 'supplied artifacts only; Graylog/n8n execution provenance requires separate review'}


def read_local(bundle, name):
    require(isinstance(name, str)); path = (bundle / name).resolve()
    require(path.is_relative_to(bundle.resolve()) and not path.is_relative_to((bundle / 'private').resolve()))
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'release-body']); parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    try:
        bundle = args.bundle.resolve(); s, c, packet = load_bundle(bundle)
        index = read_local(bundle, 'evidence-index.json')
        if args.command == 'release-body':
            snap = read_local(bundle, index['snapshots']['locked'])
            metadata(snap, s, packet, 'actual_http_snapshot', 'snapshot_passed')
            result = release_body(s, snap)
        else:
            evidence = {k: read_local(bundle, index[k]) for k in ('input', 'graylog_event', 'release_response')}
            evidence.update({k: {p: read_local(bundle, v) for p,v in index[k].items()} for k in ('probes', 'snapshots')})
            result = check(s, packet, evidence, index['definition_id'])
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, TypeError, KeyError, OSError): parser.exit(2, 'S4 evidence incomplete or inconsistent; no success declared.\n')


if __name__ == '__main__': main()
