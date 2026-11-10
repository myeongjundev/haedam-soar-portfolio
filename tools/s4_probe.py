"""Prepare S4 citizen sessions and observe effects. Default plan; stdin secrets only."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sys

from s1_client import Transport, InputStopped, now, save
from s4_client import runtime_guard
from s4_settings import digest, plan as input_plan, validate

PHASES = ('baseline', 'locked', 'restored')


def sources():
    return {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()
            for n in ('s4_probe.py', 's4_settings.py', 's4_client.py', 's1_client.py', 's1_settings.py')}


def guard(s):
    runtime_guard(s)
    if os.environ.get('HAEDAM_S4_ROLE') != 'normal':
        raise ValueError('normal_client_required')


def require(value):
    if not value:
        raise ValueError('probe_contract_mismatch')


def plan(s, run_id, phase):
    input_plan(s, run_id, 'trigger6')
    require(phase in PHASES)
    return {'case_id': 'S4', 'run_id': run_id, 'phase': phase, 'mode': 'plan_only',
            'project': s['project'], 'settings_sha256': digest(s), 'source_ip': s['addresses']['normal'],
            'target_ip': s['addresses']['portal_client'], 'target_port': s['portal_internal_port'],
            'accounts': s['accounts'], 'maximum_http_requests': 14 if phase == 'baseline' else 9 if phase == 'locked' else 10,
            'end_to_end_status': 'not_run'}


def fingerprint(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200000).hex()


def private_write(path, value):
    # POSIX permissions; on Windows the parent directory's ACL still governs access.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as stream:
        json.dump(value, stream)


def execute(s, run_id, phase, output, private, passwords, attempt=1, *,
            transport_factory=Transport, runtime=guard):
    p = plan(s, run_id, phase)
    runtime(s)
    require(type(attempt) is int and 1 <= attempt <= 9)
    require(isinstance(passwords, dict) and set(passwords) == {'target', 'normal'})
    require(all(isinstance(v, str) and 10 <= len(v) <= 128 and '\n' not in v and '\r' not in v for v in passwords.values()))
    require(passwords['target'] != passwords['normal'])
    output, private = Path(output).resolve(), Path(private).resolve()
    require(output != private and not private.is_relative_to(output) and not output.is_relative_to(private))
    output.mkdir(parents=True, exist_ok=True); private.mkdir(parents=True, exist_ok=True, mode=0o700)
    path, vault = output / f'{run_id}-probe-{phase}-{attempt}.json', private / f'{run_id}-sessions.json'
    lock, stop = output / 'input.lock', output / s['stop_filename']
    out = {**p, 'mode': 'actual_http_probe', 'status': 'running', 'started_at': now(),
           'records': [], 'source_sha256': sources(), 'checks': {}}
    with lock.open('x', encoding='utf-8') as stream:
        stream.write(run_id + '/probe/' + phase)
    try:
        # Refuse clobbering either original cookies or any prior observation.
        if phase == 'baseline' and vault.exists():
            raise FileExistsError('baseline_already_prepared')
        with path.open('x', encoding='utf-8') as stream:
            json.dump(out, stream)

        def request(transport, kind, body=None, csrf=None):
            if stop.exists(): raise InputStopped()
            require(len(out['records']) < p['maximum_http_requests'])
            started = now()
            status, payload, source = transport.request(s['paths'][kind], body, csrf)
            require(source == p['source_ip'])
            out['records'].append({'operation': kind, 'status': status, 'source_ip': source,
                                   'started_at': started, 'finished_at': now()})
            save(path, out)
            return status, payload

        def identity(body, role):
            user = body.get('data', {}).get('user') or {}
            require(body.get('success') is True and user.get('username') == s['accounts'][role]
                    and user.get('role') == 'citizen' and user.get('locked') is False)
            require(type(user.get('id')) is int and user['id'] > 0)
            return user['id']

        def anonymous(transport):
            status, body = request(transport, 'session')
            data = body.get('data') or {}; csrf = data.get('csrf_token')
            require(status == 200 and body.get('success') is True and data.get('user') is None
                    and isinstance(csrf, str) and 1 <= len(csrf) <= 256)
            return csrf

        def login(role, expected=200):
            transport = transport_factory(s, p)
            csrf = anonymous(transport)
            status, body = request(transport, 'login', {'username': s['accounts'][role], 'password': passwords[role]}, csrf)
            require(status == expected)
            if expected == 401:
                require(body.get('success') is False and body.get('error', {}).get('code') == 'INVALID_CREDENTIALS')
                return None, None
            require(body.get('success') is True)
            status, body = request(transport, 'session'); require(status == 200)
            uid = identity(body, role)
            require(isinstance(transport.cookie, str) and re.fullmatch(r'haedam_session=[A-Za-z0-9_-]{16,128}', transport.cookie))
            return uid, transport.cookie

        try:
            stored = None
            if phase != 'baseline':
                stored = json.loads(vault.read_text(encoding='utf-8'))
                require(all(stored.get(k) == v for k, v in {'run_id': run_id, 'settings_sha256': digest(s),
                        'project': s['project'], 'source_sha256': sources(), 'accounts': s['accounts']}.items()))
                require(set(stored['cookies']) == {'target1', 'target2', 'normal'})
                require(len(set(stored['cookies'].values())) == 3)
                require(all(isinstance(v,str) and re.fullmatch(r'haedam_session=[A-Za-z0-9_-]{16,128}',v) for v in stored['cookies'].values()))
                require(all(hmac.compare_digest(fingerprint(passwords[r], stored['salt']), stored['password_digests'][r]) for r in passwords))
                out['checks']['same_passwords'] = True
            status, body = request(transport_factory(s, p), 'health')
            require(status == 200 and body.get('success') is True and body.get('data', {}).get('service') == s['asset_id']
                    and body['data'].get('status') == 'ok')
            if phase == 'baseline':
                for role in passwords:
                    transport = transport_factory(s, p); csrf = anonymous(transport)
                    status, body = request(transport, 'register', {'username': s['accounts'][role],
                        'display_name': 'S4 synthetic ' + role, 'password': passwords[role]}, csrf)
                    require(status == 201 and body.get('success') is True or
                            status == 409 and body.get('error', {}).get('code') == 'CONFLICT')
                    # A conflict is only accepted if subsequent password login proves ownership.
                ids, cookies = {}, {}
                for slot, role in (('target1', 'target'), ('target2', 'target'), ('normal', 'normal')):
                    uid, cookie = login(role)
                    require(role not in ids or ids[role] == uid)
                    ids[role] = uid; cookies[slot] = cookie
                require(ids['target'] != ids['normal'] and len(set(cookies.values())) == 3)
                salt = secrets.token_hex(32)
                stored = {'run_id': run_id, 'settings_sha256': digest(s), 'project': s['project'],
                          'source_sha256': sources(), 'accounts': s['accounts'], 'user_ids': ids, 'cookies': cookies,
                          'session_set_id': secrets.token_hex(16), 'salt': salt,
                          'password_digests': {r: fingerprint(v, salt) for r, v in passwords.items()}}
                private_write(vault, stored)
                out['checks'] = {'target_sessions_prepared': 2, 'normal_session_prepared': True}
            else:
                for slot, role in (('target1', 'target'), ('target2', 'target'), ('normal', 'normal')):
                    transport = transport_factory(s, p)
                    # Never replace the retained cookie with an anonymous cookie returned after revocation.
                    transport.cookie = stored['cookies'][slot]
                    status, body = request(transport, 'session')
                    require(status == 200 and body.get('success') is True)
                    if role == 'target':
                        require('user' in body.get('data', {}) and body['data']['user'] is None)
                        out['checks'][slot + '_revoked'] = True
                    else:
                        require(identity(body, role) == stored['user_ids'][role])
                        out['checks']['normal_old_authenticated'] = True
                target_status = 401 if phase == 'locked' else 200
                uid, _ = login('target', target_status)
                if target_status == 200: require(uid == stored['user_ids']['target'])
                out['checks']['target_new_login_status'] = target_status
                uid, _ = login('normal'); require(uid == stored['user_ids']['normal'])
                out['checks']['normal_new_authenticated'] = True
            out.update(session_set_id=stored['session_set_id'], user_ids=stored['user_ids'], status='probe_passed')
        except (InputStopped, KeyboardInterrupt):
            out.update(status='stopped', reason='stop_requested')
        except Exception as error:
            out.update(status='failed', reason=type(error).__name__)
        out['finished_at'] = now(); save(path, out)
        return out
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', required=True, type=Path); parser.add_argument('--run-id', required=True)
    parser.add_argument('--phase', choices=PHASES, required=True); parser.add_argument('--attempt', type=int, default=1)
    parser.add_argument('--execute', action='store_true'); args = parser.parse_args()
    try:
        s = validate(json.loads(args.settings.read_text(encoding='utf-8-sig')))
        if args.execute:
            guard(s)
            passwords = json.loads(sys.stdin.readline(2049))
            result = execute(s, args.run_id, args.phase, s['paths']['evidence_mount'], s['paths']['private_mount'], passwords, args.attempt)
        else: result = plan(s, args.run_id, args.phase)
        print(json.dumps(result, ensure_ascii=False))
        if args.execute and result['status'] != 'probe_passed': raise SystemExit(1)
    except (ValueError, TypeError, KeyError, OSError):
        parser.exit(2, 'S4 probe refused; check configuration, private session state and stdin.\n')


if __name__ == '__main__': main()
