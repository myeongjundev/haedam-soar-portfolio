"""Fixed S4 lab round; default offline. No lock/unlock API calls or stored secrets."""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time

RUN = 'S4-20261103-LIVE01'
HOST, PORT = '192.0.2.2', 5000
ATTACK, NORMAL = '203.0.113.17', '203.0.113.100'
ACCOUNT, NORMAL_ACCOUNT = 'zz_s4_1103', 'zz_n1'
INTERVAL = 60


def stamp():
    return datetime.now(timezone(timedelta(hours=9))).isoformat()


class Evidence:
    def __init__(self, out, method):
        self.out = out
        self.data = dict(run_id=RUN, scope='S4_client_checks_only', unlock_method=method,
                         started_kst=stamp(), steps=[], checks={}, complete=False,
                         automatic_retries=0, response_API_calls=0)
        with out.open('x', encoding='utf-8') as f:
            json.dump(self.data, f)

    def save(self):
        temp = self.out.with_name(self.out.name + '.writing')
        temp.write_text(json.dumps(self.data, indent=2) + '\n', encoding='utf-8')
        os.replace(temp, self.out)


class Client:
    def __init__(self, source, evidence):
        self.source, self.evidence = source, evidence
        self.cookie = self.csrf = None
        self.authenticated = False
        self.logout_attempted = False

    def call(self, phase, method, path, expected=200, payload=None, proof_cookie=None):
        step = dict(phase=phase, source=self.source, method=method, path=path,
                    expected_status=expected, started_kst=stamp())
        self.evidence.data['steps'].append(step)
        self.evidence.save()
        conn = http.client.HTTPConnection(HOST, PORT, timeout=8, source_address=(self.source, 0))
        tick = time.monotonic()
        try:
            headers = {'Connection': 'close', 'Content-Type': 'application/json'}
            cookie = proof_cookie if proof_cookie is not None else self.cookie
            if cookie:
                headers['Cookie'] = 'haedam_session=' + cookie
            if method == 'POST':
                if not self.csrf:
                    raise ValueError('missing_csrf')
                headers['X-CSRF-Token'] = self.csrf
            conn.connect()
            step['source_actual'] = conn.sock.getsockname()[0]
            if step['source_actual'] != self.source:
                raise ValueError('source_mismatch')
            conn.request(method, path, json.dumps(payload or {}) if method == 'POST' else None, headers)
            response = conn.getresponse()
            step['status'] = response.status
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise ValueError('response_too_large')
            for key, value in response.getheaders():
                if key.lower() == 'set-cookie':
                    jar = SimpleCookie(); jar.load(value)
                    if 'haedam_session' in jar:
                        self.cookie = jar['haedam_session'].value
            if response.status != expected:
                raise ValueError('unexpected_status')
            body = json.loads(raw)
            if expected == 401:
                if body.get('success') is not False:
                    raise ValueError('invalid_failure_envelope')
                return {}
            data = body.get('data')
            if body.get('success') is not True or not isinstance(data, dict):
                raise ValueError('invalid_success_envelope')
            if 'csrf_token' in data:
                if not isinstance(data['csrf_token'], str) or not data['csrf_token'] or not self.cookie:
                    raise ValueError('invalid_session')
                self.csrf = data['csrf_token']
            if 'user' in data:
                self.authenticated = bool(data['user'])
            return data
        except (Exception, KeyboardInterrupt) as exc:
            step['error_type'] = type(exc).__name__
            raise
        finally:
            conn.close()
            step['finished_kst'] = stamp()
            step['ms'] = round((time.monotonic() - tick) * 1000, 3)
            self.evidence.save()

    def login(self, phase, account, password, expected=200):
        data = self.call(phase, 'POST', '/api/v1/auth/login', expected,
                         {'username': account, 'password': password})
        if expected == 200:
            self.logout_attempted = False
            user = data.get('user') or {}
            if user.get('username') != account or user.get('role') != 'staff':
                raise ValueError('identity_mismatch')
        return data

    def logout(self, phase):
        self.logout_attempted = True
        data = self.call(phase, 'POST', '/api/v1/auth/logout')
        if data.get('logged_out') is not True:
            raise ValueError('logout_not_confirmed')
        self.authenticated = False


def run(out, method, password, normal_password, gate=input, reset_password=None):
    evidence = Evidence(out, method)
    attacker, normal = Client(ATTACK, evidence), Client(NORMAL, evidence)
    checks = evidence.data['checks']
    try:
        attacker.call('bootstrap', 'GET', '/api/v1/auth/me')
        wrong = secrets.token_urlsafe(32)
        while wrong == password:
            wrong = secrets.token_urlsafe(32)
        first = time.monotonic()
        for index in range(6):
            if index:
                delay = max(0, INTERVAL - (time.monotonic() - previous))
                time.sleep(delay)
            if time.monotonic() - first >= 600:
                raise ValueError('ten_minute_window_expired')
            previous = time.monotonic()
            attacker.login('trigger_failure' if index < 5 else 'trigger_success',
                           ACCOUNT, wrong if index < 5 else password, 401 if index < 5 else 200)
        original_cookie = attacker.cookie  # Memory only, never replaced by later anonymous cookies.
        if not original_cookie:
            raise ValueError('original_session_missing')
        checks['trigger_5_failures_then_success'] = True
        evidence.save()
        if gate('After D/A confirm actual account lock, type LOCKED: ').strip() != 'LOCKED':
            raise ValueError('lock_gate_not_confirmed')
        data = attacker.call('old_session_while_locked', 'GET', '/api/v1/auth/me', proof_cookie=original_cookie)
        if 'user' not in data or data['user'] is not None:
            raise ValueError('old_session_still_valid')
        checks['old_session_revoked'] = True
        attacker.login('correct_password_while_locked', ACCOUNT, password, 401)
        checks['locked_login_rejected'] = True

        normal.call('normal_bootstrap', 'GET', '/api/v1/auth/me')
        normal.login('normal_login', NORMAL_ACCOUNT, normal_password)
        data = normal.call('normal_business', 'GET', '/api/v1/petitions')
        if not isinstance(data.get('items'), list):
            raise ValueError('invalid_business_response')
        checks['normal_business'] = True
        normal.logout('normal_logout')
        checks['normal_logout'] = True
        evidence.save()

        if gate('After A confirms the agreed manual unlock/reset, type UNLOCKED: ').strip() != 'UNLOCKED':
            raise ValueError('unlock_gate_not_confirmed')
        data = attacker.call('same_old_session_after_unlock', 'GET', '/api/v1/auth/me', proof_cookie=original_cookie)
        if 'user' not in data or data['user'] is not None:
            raise ValueError('old_session_resurrected')
        checks['old_session_still_revoked'] = True
        new_password = reset_password() if method == 'reset' else password
        if not new_password:
            raise ValueError('empty_restored_password')
        attacker.login('new_login_after_unlock', ACCOUNT, new_password)
        checks['new_login_after_unlock'] = True
        attacker.logout('restored_logout')
        checks['restored_logout'] = True
        evidence.data['complete'] = True
    except (Exception, KeyboardInterrupt) as exc:
        evidence.data['error_type'] = type(exc).__name__
        evidence.data['followup'] = 'Stop trial inputs; coordinate A recovery and C/D reconciliation. Do not rerun this round.'
    finally:
        # Only sign out sessions created here; never attempt response/administrative actions.
        for label, client in [('normal', normal), ('target', attacker)]:
            if client.authenticated and not client.logout_attempted:
                try:
                    client.logout(label + '_failure_cleanup_logout')
                    evidence.data[label + '_cleanup_logout'] = True
                except (Exception, KeyboardInterrupt) as exc:
                    evidence.data[label + '_cleanup_error_type'] = type(exc).__name__
        evidence.data['finished_kst'] = stamp()
        evidence.save()
    return evidence.data


def wait_for_start(start, deadline, now=None, sleep=None):
    now = now or (lambda: datetime.now(timezone.utc))
    sleep = sleep or time.sleep
    if start.tzinfo is None or deadline.tzinfo is None or deadline <= start:
        raise ValueError('invalid_start_window')
    while True:
        current = now()
        if current > deadline:
            raise ValueError('start_window_missed_no_requests')
        remaining = (start - current).total_seconds()
        if remaining <= 0:
            return
        sleep(min(remaining, 0.5))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--unlock-method', choices=['reset', 'keep'])
    parser.add_argument('--confirmed-run', choices=[RUN])
    parser.add_argument('--start-at', type=datetime.fromisoformat)
    parser.add_argument('--latest-start', type=datetime.fromisoformat)
    args = parser.parse_args()
    if bool(args.start_at) != bool(args.latest_start):
        parser.error('Provide both start-at and latest-start')
    if not args.execute:
        print('PLAN ONLY: no network or password prompt. S4 .17/zz_s4_1103; normal .100/zz_n1.')
        print('5 failures then success, 60s start spacing; explicit LOCKED/UNLOCKED gates; no admin API calls.')
        return 0
    out = Path(RUN + '-client.json')
    if os.name == 'nt' or not sys.stdin.isatty() or not args.unlock_method or out.exists():
        parser.error('Use interactive Kali TTY, agreed --unlock-method, and a new result path.')
    for source in (ATTACK, NORMAL):
        with socket.socket() as sock:
            sock.bind((source, 0))  # Local-only address availability check.
    if args.confirmed_run != RUN and input('After D individual GO, type the run ID: ').strip() != RUN:
        parser.error('GO acknowledgement missing; no requests sent')
    password = getpass.getpass('Target account password (not stored): ')
    normal_password = getpass.getpass('zz_n1 password (not stored): ')
    if not password or not normal_password:
        parser.error('Empty password; no requests sent')
    if args.start_at:
        print('Credentials ready. Waiting until ' + args.start_at.isoformat() + '; no requests before then.', flush=True)
        try:
            wait_for_start(args.start_at, args.latest_start)
        except ValueError as exc:
            parser.error(str(exc))
    result = run(out, args.unlock_method, password, normal_password,
                 reset_password=lambda: getpass.getpass('A-provided reset password (not stored): '))
    print(json.dumps({'client_checks_complete': result['complete'], 'evidence': str(out),
                      'external_ticket_action_closure_verified': False}))
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
