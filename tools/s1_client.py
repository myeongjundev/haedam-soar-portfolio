"""Bounded S1 HTTP input inside an owned client container. Default: plan only.

Input completion is not detection/response/restoration success. No response API,
webhook, Docker CLI, proxy, redirect, X-Forwarded-For or automatic retry is used.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time

from s1_settings import plan, validate


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


class InputStopped(Exception):
    pass


def runtime_guard(s):
    if not s['execution_enabled']:
        raise ValueError('execution_disabled')
    if sys.platform != 'linux' or not Path('/.dockerenv').is_file():
        raise ValueError('owned_linux_client_container_required')
    if os.environ.get('HAEDAM_S1_PROJECT') != s['project']:
        raise ValueError('wrong_project')


class Transport:
    """Literal IPv4 target and source-bound socket; redirects are ordinary failures."""
    def __init__(self, s, p):
        self.s, self.p, self.cookie = s, p, None

    def request(self, path, body=None, csrf=None):
        connection = http.client.HTTPConnection(self.p['target_ip'], self.p['target_port'],
                        timeout=self.s['request_timeout_seconds'], source_address=(self.p['source_ip'], 0))
        try:
            connection.connect()
            source = connection.sock.getsockname()[0]
            if source != self.p['source_ip'] or connection.sock.getpeername()[0] != self.p['target_ip']:
                raise ValueError('socket_identity_mismatch')
            headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
            if self.cookie:
                headers['Cookie'] = self.cookie
            if csrf:
                headers['X-CSRF-Token'] = csrf
            connection.request('GET' if body is None else 'POST', path,
                               body=None if body is None else json.dumps(body).encode(), headers=headers)
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('response_too_large')
            for key, value in response.getheaders():
                if key.lower() == 'set-cookie':
                    cookies = SimpleCookie(value)
                    if 'haedam_session' in cookies:
                        token = cookies['haedam_session'].value
                        if len(token) > 128:
                            raise ValueError('invalid_session_cookie')
                        self.cookie = 'haedam_session=' + cookies['haedam_session'].coded_value
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                data = {}
            return response.status, data if isinstance(data, dict) else {}, source
        finally:
            connection.close()


def wait_between(seconds, stop):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if stop.exists():
            raise InputStopped()
        time.sleep(min(1, max(0, end - time.monotonic())))


def save(path, body):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        json.dump(body, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        temp = Path(stream.name)
    temp.replace(path)


def execute(s, run_id, profile, output, *, transport_factory=Transport, guard=runtime_guard, wait=wait_between):
    p = plan(s, run_id, profile)
    guard(s)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    stop, lock = output / s['stop_filename'], output / 'input.lock'
    path = output / f'{run_id}-{profile}.json'
    locked = False
    out = {**p, 'mode': 'actual_http_input', 'status': 'running', 'started_at': now(),
           'records': [], 'observed_401_count': 0, 'end_to_end_status': 'not_run',
           'source_sha256': {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             for name in ('s1_client.py', 's1_settings.py')}}
    try:
        if profile != 'normal':
            with lock.open('x', encoding='utf-8') as f:
                f.write(run_id + '/' + profile + '\n')
            locked = True
        # Never overwrite another or a previous run's evidence.
        with path.open('x', encoding='utf-8') as f:
            json.dump(out, f)
        transport = transport_factory(s, p)

        def request(kind, body=None, csrf=None):
            if stop.exists():
                raise InputStopped()
            if len(out['records']) >= p['maximum_http_requests']:
                raise ValueError('request_budget_exhausted')
            started, mono = now(), time.monotonic()
            status, payload, source = transport.request(s['paths'][kind], body, csrf)
            if source != p['source_ip']:
                raise ValueError('socket_identity_mismatch')
            raw_code = payload.get('error', {}).get('code') if isinstance(payload.get('error'), dict) else None
            code = raw_code if raw_code in ('INVALID_CREDENTIALS', 'IP_BLOCKED', 'RATE_LIMITED') else None
            out['records'].append({'operation': kind, 'status': status, 'error_code': code, 'source_ip': source,
                                   'started_at': started, 'finished_at': now(),
                                   'elapsed_seconds': round(time.monotonic() - mono, 6)})
            save(path, out)
            return status, payload

        try:
            status, health = request('health')
            data = health.get('data') or {}
            if status != 200 or data.get('service') != s['asset_id'] or data.get('status') != 'ok':
                raise ValueError('health_not_ready')
            # Generated only in memory, never accepted from the CLI or written to evidence.
            invalid_password = secrets.token_urlsafe(32)
            for i in range(p['maximum_login_attempts']):
                if i:
                    wait(p['interval_seconds'], stop)
                status, session = request('session')
                data = session.get('data') or {}
                csrf = data.get('csrf_token')
                if status != 200 or data.get('user') is not None or not isinstance(csrf, str) or not 1 <= len(csrf) <= 256:
                    raise ValueError('anonymous_session_required')
                status, login = request('login', {'username': p['username'], 'password': invalid_password}, csrf)
                if status != 401 or login.get('error', {}).get('code') != 'INVALID_CREDENTIALS':
                    raise ValueError('unexpected_login_result_stop_without_retry')
                out['observed_401_count'] += 1
                save(path, out)
            out['status'] = 'probe_complete' if profile == 'normal' else 'input_complete'
        except (InputStopped, KeyboardInterrupt):
            out['status'], out['reason'] = 'stopped', 'stop_requested'
        except Exception as error:
            # Never serialize exception messages, response bodies, credentials or cookies.
            out['status'], out['reason'] = 'failed', type(error).__name__
        out['finished_at'] = now()
        save(path, out)
        return out
    finally:
        if locked:
            lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--profile', choices=['boundary8', 'trigger9', 'normal'], required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        s = validate(json.loads(args.settings.read_text(encoding='utf-8-sig')))
        if args.execute:
            result = execute(s, args.run_id, args.profile, Path(s['paths']['evidence_mount']))
        else:
            result = plan(s, args.run_id, args.profile)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.execute and result['status'] not in ('input_complete', 'probe_complete'):
            raise SystemExit(1)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(2, 'S1 refused: check configuration, execution flag, container identity, run ID and lock.\n')


if __name__ == '__main__':
    main()
