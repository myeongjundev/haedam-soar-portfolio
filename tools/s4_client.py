"""Bounded S4 login input. Default plan only; password via stdin inside owned lab.

No Docker operations, response APIs or detector webhooks. Completion proves only
the requested HTTP input and authenticated identity, never lock/ticket/recovery.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

from s1_client import Transport, InputStopped, now, save, wait_between
from s4_settings import PROFILES, plan, validate


def runtime_guard(s):
    if not s['execution_enabled']:
        raise ValueError('execution_disabled')
    if sys.platform != 'linux' or not Path('/.dockerenv').is_file():
        raise ValueError('owned_linux_client_container_required')
    if os.environ.get('HAEDAM_S4_PROJECT') != s['project']:
        raise ValueError('wrong_project')


def execute(s, run_id, profile, output, password=None, *, transport_factory=Transport,
            guard=runtime_guard, wait=wait_between):
    p = plan(s, run_id, profile)
    guard(s)
    if 200 in p['expected_login_statuses'] and (
            not isinstance(password, str) or not 10 <= len(password) <= 128
            or '\n' in password or '\r' in password):
        raise ValueError('password_required_on_stdin')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    stop, lock = output / s['stop_filename'], output / 'input.lock'
    path = output / f'{run_id}-{profile}.json'
    out = {**p, 'mode': 'actual_http_input', 'status': 'running', 'started_at': now(),
           'records': [], 'observed_login_statuses': [], 'authenticated_identity_checks': 0,
           'source_sha256': {n: hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest()
                             for n in ('s4_client.py', 's4_settings.py', 's1_client.py')}}
    # Exclusive directory-wide lock also serializes different profiles of the same key.
    with lock.open('x', encoding='utf-8') as stream:
        stream.write(run_id + '/' + profile + '\n')
    try:
        with path.open('x', encoding='utf-8') as stream:
            json.dump(out, stream)

        def request(transport, kind, body=None, csrf=None):
            if stop.exists():
                raise InputStopped()
            if len(out['records']) >= p['maximum_http_requests']:
                raise ValueError('request_budget_exhausted')
            started, mono = now(), time.monotonic()
            status, payload, source = transport.request(s['paths'][kind], body, csrf)
            if source != p['source_ip']:
                raise ValueError('socket_identity_mismatch')
            error = payload.get('error')
            raw_code = error.get('code') if isinstance(error, dict) else None
            code = raw_code if raw_code in ('INVALID_CREDENTIALS', 'IP_BLOCKED', 'ACCOUNT_LOCKED', 'RATE_LIMITED') else None
            out['records'].append({'operation': kind, 'status': status, 'error_code': code,
                                   'source_ip': source, 'started_at': started, 'finished_at': now(),
                                   'elapsed_seconds': round(time.monotonic() - mono, 6)})
            save(path, out)
            return status, payload

        try:
            status, body = request(transport_factory(s, p), 'health')
            data = body.get('data') or {}
            if status != 200 or body.get('success') is not True or data.get('service') != s['asset_id'] or data.get('status') != 'ok':
                raise ValueError('health_not_ready')
            invalid_password = secrets.token_urlsafe(48)
            if invalid_password == password:
                raise ValueError('invalid_password_collision')
            for index, expected in enumerate(p['expected_login_statuses']):
                if index:
                    wait(p['interval_seconds'], stop)
                # Fresh cookie jar: prior success cannot satisfy the next identity check.
                transport = transport_factory(s, p)
                status, body = request(transport, 'session')
                data = body.get('data') or {}
                csrf = data.get('csrf_token')
                if status != 200 or body.get('success') is not True or data.get('user') is not None or not isinstance(csrf, str) or not 1 <= len(csrf) <= 256:
                    raise ValueError('anonymous_session_required')
                status, body = request(transport, 'login',
                                       {'username': p['username'], 'password': password if expected == 200 else invalid_password}, csrf)
                if status != expected:
                    raise ValueError('unexpected_login_status')
                if expected == 401:
                    if body.get('success') is not False or body.get('error', {}).get('code') != 'INVALID_CREDENTIALS':
                        raise ValueError('unexpected_failure_code')
                elif body.get('success') is not True:
                    raise ValueError('login_not_successful')
                out['observed_login_statuses'].append(status)
                if expected == 200:
                    status, body = request(transport, 'session')
                    user = (body.get('data') or {}).get('user') or {}
                    if status != 200 or body.get('success') is not True or user.get('username') != p['username'] or user.get('role') != 'citizen' or user.get('locked') is not False:
                        raise ValueError('authenticated_identity_mismatch')
                    out['authenticated_identity_checks'] += 1
                save(path, out)
            out['status'] = 'input_complete'
        except (InputStopped, KeyboardInterrupt):
            out.update(status='stopped', reason='stop_requested')
        except Exception as error:
            # Never serialize response bodies, cookies, password or exception messages.
            out.update(status='failed', reason=type(error).__name__)
        out['finished_at'] = now()
        save(path, out)
        return out
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        s = validate(json.loads(args.settings.read_text(encoding='utf-8-sig')))
        p = plan(s, args.run_id, args.profile)
        if args.execute:
            runtime_guard(s)  # Reject before reading stdin on an unowned host.
            password = sys.stdin.readline(130).rstrip('\r\n') if 200 in p['expected_login_statuses'] else None
            result = execute(s, args.run_id, args.profile, s['paths']['evidence_mount'], password)
        else:
            result = p
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.execute and result['status'] != 'input_complete':
            raise SystemExit(1)
    except (ValueError, KeyError, TypeError, OSError):
        parser.exit(2, 'S4 refused: check settings, container identity, password stdin and evidence lock.\n')


if __name__ == '__main__':
    main()
