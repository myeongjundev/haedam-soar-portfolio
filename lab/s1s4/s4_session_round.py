"""Parameterized S4 lab round; default offline. No lock/unlock API calls or stored secrets."""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import http.client
from http.cookies import SimpleCookie
import json
import os
import ipaddress
import re
from pathlib import Path
import secrets
import socket
import sys
import time

PRESERVED_RUN = 'S4-20261103-LIVE01'
HOST, PORT = '192.0.2.2', 5000
NORMAL = '203.0.113.100'
PROTECTED_SOURCES = {'203.0.113.10', '203.0.113.12', NORMAL}
NORMAL_ACCOUNT = 'zz_n1'
INTERVAL = 60


def stamp():
    return datetime.now(timezone(timedelta(hours=9))).isoformat()


class Evidence:
    def __init__(self, out, method, run_id, account, source, failure_count):
        self.out = out
        self.data = dict(run_id=run_id, scope='S4_client_checks_only', unlock_method=method,
                         account=account, source=source, failure_count=failure_count,
                         expected_outcome='lock' if failure_count == 5 else 'no_lock',
                         external_ticket_action_closure_verified=False,
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


def validate_round(run_id, account, source, failure_count):
    if not re.fullmatch(r'S4-[A-Za-z0-9_-]{1,60}', run_id) or run_id == PRESERVED_RUN:
        raise ValueError('use_new_safe_S4_run_id')
    if not re.fullmatch(r'zz_[A-Za-z0-9_]{1,48}', account) or account == NORMAL_ACCOUNT:
        raise ValueError('use_dedicated_zz_test_account')
    ip = ipaddress.IPv4Address(source)
    if (str(ip) in PROTECTED_SOURCES
            or ip not in ipaddress.IPv4Network('203.0.113.0/24')
            or int(str(ip).split('.')[-1]) not in range(2, 100)):
        raise ValueError('use_agreed_lab_source_distinct_from_normal')
    if failure_count not in (4, 5):
        raise ValueError('only_four_boundary_or_five_trigger_failures')


class OperatorGateStopped(Exception):
    """A controlled reason code, never the operator's raw input."""

    def __init__(self, token, reason):
        self.code = 'operator_gate_' + token.lower() + '_' + reason
        super().__init__(self.code)


def wait_for_operator(evidence, token, prompt, gate):
    """Keep the in-memory session while waiting; this loop makes no requests."""
    record = dict(gate=token, status='waiting', started_kst=stamp(), invalid_entries=0)
    evidence.data.setdefault('operator_gates', []).append(record)
    evidence.save()
    while True:
        try:
            answer = gate(prompt + ' (STOP to end this run): ').strip().upper()
        except (EOFError, KeyboardInterrupt) as exc:
            reason = 'input_closed' if isinstance(exc, EOFError) else 'interrupted'
        else:
            if answer == token:
                record.update(status='confirmed', finished_kst=stamp())
                evidence.save()
                return
            if answer != 'STOP':
                record['invalid_entries'] += 1
                evidence.save()
                print('Still waiting. No request sent. Confirm the external checks, then type '
                      + token + '; type STOP to end this run.', flush=True)
                continue
            reason = 'stopped'
        record.update(status='stopped', reason=reason, finished_kst=stamp())
        evidence.save()
        raise OperatorGateStopped(token, reason) from None


def run(out, method, password, normal_password, gate=input, reset_password=None,
        *, run_id, account, source, failure_count):
    validate_round(run_id, account, source, failure_count)
    if method not in ('reset', 'keep'):
        raise ValueError('invalid_unlock_method')
    evidence = Evidence(out, method, run_id, account, source, failure_count)
    attacker, normal = Client(source, evidence), Client(NORMAL, evidence)
    checks = evidence.data['checks']
    try:
        attacker.call('bootstrap', 'GET', '/api/v1/auth/me')
        wrong = secrets.token_urlsafe(32)
        while wrong == password:
            wrong = secrets.token_urlsafe(32)
        first = time.monotonic()
        for index in range(failure_count + 1):
            if index:
                delay = max(0, INTERVAL - (time.monotonic() - previous))
                time.sleep(delay)
            if time.monotonic() - first >= 600:
                raise ValueError('ten_minute_window_expired')
            previous = time.monotonic()
            attacker.login('trigger_failure' if index < failure_count else 'trigger_success',
                           account, wrong if index < failure_count else password, 401 if index < failure_count else 200)
        original_cookie = attacker.cookie  # Memory only, never replaced by later anonymous cookies.
        if not original_cookie:
            raise ValueError('original_session_missing')
        checks['trigger_sequence_completed'] = True
        evidence.save()
        if failure_count == 4:
            wait_for_operator(evidence, 'NO_LOCK',
                'After agreed observation end and D/A/C confirm no detection/ticket/lock, type NO_LOCK', gate)
            data = attacker.call('boundary_same_session', 'GET', '/api/v1/auth/me', proof_cookie=original_cookie)
            if (data.get('user') or {}).get('username') != account:
                raise ValueError('boundary_session_not_valid')
            checks['boundary_same_session_valid'] = True
            evidence.data['external_no_lock_attested_by_operator'] = True
        else:
            wait_for_operator(evidence, 'LOCKED', 'After D/A confirm actual account lock, type LOCKED', gate)
            data = attacker.call('old_session_while_locked', 'GET', '/api/v1/auth/me', proof_cookie=original_cookie)
            if 'user' not in data or data['user'] is not None:
                raise ValueError('old_session_still_valid')
            checks['old_session_revoked'] = True
            attacker.login('correct_password_while_locked', account, password, 401)
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

        if failure_count == 4:
            attacker.logout('boundary_target_logout')
            checks['boundary_target_logout'] = True
        else:
            wait_for_operator(evidence, 'UNLOCKED',
                'After D effect record, C ACK and A manual unlock/reset confirmation, type UNLOCKED', gate)
            data = attacker.call('same_old_session_after_unlock', 'GET', '/api/v1/auth/me', proof_cookie=original_cookie)
            if 'user' not in data or data['user'] is not None:
                raise ValueError('old_session_resurrected')
            checks['old_session_still_revoked'] = True
            new_password = reset_password() if method == 'reset' else password
            if not new_password:
                raise ValueError('empty_restored_password')
            attacker.login('new_login_after_unlock', account, new_password)
            checks['new_login_after_unlock'] = True
            attacker.logout('restored_logout')
            checks['restored_logout'] = True
        evidence.data['complete'] = True
    except (Exception, KeyboardInterrupt) as exc:
        evidence.data['error_type'] = type(exc).__name__
        if isinstance(exc, OperatorGateStopped):
            evidence.data['error_code'] = exc.code
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
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--failure-count', type=int, choices=(4, 5), required=True)
    parser.add_argument('--unlock-method', choices=['reset', 'keep'], default='reset')
    parser.add_argument('--confirmed-run')
    parser.add_argument('--start-at', type=datetime.fromisoformat)
    parser.add_argument('--latest-start', type=datetime.fromisoformat)
    args = parser.parse_args()
    try:
        validate_round(args.run_id, args.account, args.source, args.failure_count)
        if bool(args.start_at) != bool(args.latest_start):
            raise ValueError('provide_both_start_times')
        if args.start_at and (args.start_at.tzinfo is None or args.latest_start.tzinfo is None
                              or args.latest_start <= args.start_at):
            raise ValueError('invalid_start_window')
    except ValueError as exc:
        parser.error(str(exc))
    if not args.execute:
        print('PLAN ONLY: no network or password prompt.')
        print(json.dumps({'run_id': args.run_id, 'account': args.account, 'source': args.source,
                          'failure_count': args.failure_count, 'normal_source': NORMAL,
                          'expected_outcome': 'lock' if args.failure_count == 5 else 'no_lock',
                          'interval_seconds': INTERVAL, 'automatic_retries': 0}))
        return 0
    out = Path(args.run_id + '-client.json')
    if os.name == 'nt' or not sys.stdin.isatty() or out.exists():
        parser.error('Use interactive Kali TTY and a new result path.')
    if args.confirmed_run != args.run_id:
        parser.error('Explicit --confirmed-run matching the new D GO is required; no requests sent')
    for source in (args.source, NORMAL):
        with socket.socket() as sock:
            sock.bind((source, 0))
    password = getpass.getpass('Target account password (not stored): ')
    normal_password = getpass.getpass('zz_n1 password (not stored): ')
    if not password or not normal_password:
        parser.error('Empty password; no requests sent')
    if args.start_at:
        print('Credentials ready. Waiting until ' + args.start_at.isoformat(), flush=True)
        try:
            wait_for_start(args.start_at, args.latest_start)
        except ValueError as exc:
            parser.error(str(exc))
    result = run(out, args.unlock_method, password, normal_password,
                 reset_password=lambda: getpass.getpass('A-provided reset password (not stored): '),
                 run_id=args.run_id, account=args.account, source=args.source, failure_count=args.failure_count)
    print(json.dumps({'client_checks_complete': result['complete'], 'evidence': str(out),
                      'external_ticket_action_closure_verified': False}))
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
