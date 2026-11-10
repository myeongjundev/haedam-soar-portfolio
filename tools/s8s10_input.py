"""Bounded lab input: default writes a plan; --execute sends three HTTP requests and S10 one ICMP."""
import argparse
from datetime import datetime, timezone
import http.client
from http.cookies import SimpleCookie
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.parse import urlsplit

SOURCES = {'S8': '203.0.113.21', 'S10': '203.0.113.22'}
TARGETS = {('203.0.113.1', 80), ('192.0.2.2', 5000)}


def make_plan(case, run_id, target='http://203.0.113.1'):
    if case not in SOURCES or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,39}', run_id):
        raise ValueError('invalid case/run ID')
    url = urlsplit(target)
    if (url.scheme != 'http' or (url.hostname, url.port or 80) not in TARGETS or url.username or url.password
            or url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('use an approved lab origin without credentials/path/query')
    return {'case_id': case, 'run_id': run_id, 'source': SOURCES[case], 'origin': target.rstrip('/'),
            'scan_path': '/_zz_s8s10_' + run_id, 'username': 'zz_b_' + case.lower() + '_' + hashlib.sha256(run_id.encode()).hexdigest()[:16],
            'http_sequence': ['GET scan (404)', 'GET /api/v1/auth/me (200, CSRF)', 'POST /api/v1/auth/login (401)'],
            'http_attempt_limit': 3, 'icmp_attempt_limit': int(case == 'S10'), 'automatic_retries': 0,
            'pf_signal_target': '203.0.113.1' if case == 'S10' else None,
            'devices_ready': False, 'graylog_verified': False, 'response_verified': False}


def execute(plan, save, *, connection_factory=None, ping=None):
    if connection_factory is None and os.name == 'nt':
        raise ValueError('actual input runs on prepared Kali/Linux; Windows supports planning only')
    connection_factory = connection_factory or http.client.HTTPConnection
    ping = ping or subprocess.run
    url = urlsplit(plan['origin'])
    attempts = []
    report = {'scope': 'actual_input_only', 'plan': plan, 'started_at': datetime.now(timezone.utc).isoformat(),
              'http': attempts, 'icmp': None, 'complete': False, 'error': None, 'external_detection_response_verified': False}
    save(report)
    cookies = SimpleCookie()
    def request(method, path, expected, payload=None, token=None):
        connection = connection_factory(url.hostname, url.port or 80, timeout=5,
                                               source_address=(plan['source'], 0))
        started = datetime.now(timezone.utc).isoformat()
        tick = time.perf_counter()
        item = {'method': method, 'path': path, 'expected_status': expected, 'started_at': started,
                'status': None, 'local_source': None, 'error': None}
        try:
            connection.connect()
            item['local_source'] = connection.sock.getsockname()[0]
            if item['local_source'] != plan['source']:
                raise ValueError('source mismatch')
            headers = {'Connection': 'close'}
            if payload is not None: headers['Content-Type'] = 'application/json'
            if token: headers['X-CSRF-Token'] = token
            if 'haedam_session' in cookies:
                headers['Cookie'] = 'haedam_session=' + cookies['haedam_session'].value
            connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
            response = connection.getresponse()
            for header, value in response.getheaders():
                if header.lower() == 'set-cookie': cookies.load(value)
            raw = response.read(65537)
            item['status'] = response.status
            if len(raw) > 65536: raise ValueError('response too large')
            if response.status != expected: raise ValueError('unexpected status')
            return raw
        except (OSError, ValueError, http.client.HTTPException) as exc:
            item['error'] = type(exc).__name__
            raise ValueError('input stopped; inspect the saved attempt before retrying') from None
        finally:
            item['ms'] = round((time.perf_counter() - tick) * 1000, 3)
            attempts.append(item)
            connection.close()
            save(report)
    phase = 'scan'
    try:
        request('GET', plan['scan_path'], 404)
        phase = 'csrf_bootstrap'
        bootstrap = json.loads(request('GET', '/api/v1/auth/me', 200))
        if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get('data'), dict):
            raise ValueError('invalid CSRF envelope')
        token = bootstrap['data'].get('csrf_token')
        if not isinstance(token, str) or not token:
            raise ValueError('CSRF bootstrap missing; no login attempted')
        # Random synthetic wrong password; never printed or written to the report.
        phase = 'login'
        request('POST', '/api/v1/auth/login', 401,
                {'username': plan['username'], 'password': 'Synthetic-wrong-' + secrets.token_hex(12)}, token)
        if plan['case_id'] == 'S10':
            phase = 'icmp'
            report['icmp'] = {'attempts': 1, 'returncode': None, 'block_log_verified': False}
            save(report)
            result = ping(['ping', '-n', '-I', plan['source'], '-c', '1', '-W', '1', '203.0.113.1'],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
            report['icmp'] = {'attempts': 1, 'returncode': result.returncode, 'block_log_verified': False}
            # No echo reply is expected; it does not prove that a logged PF block arrived at D.
        report['complete'] = True
    except (Exception, KeyboardInterrupt) as exc:
        # Never persist exception text, HTTP bodies, ping output, cookies or keys.
        report['error'] = {'phase': phase, 'type': type(exc).__name__}
        raise ValueError('input stopped at ' + phase + '; inspect saved report; no automatic retry') from None
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=SOURCES, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--target', default='http://203.0.113.1')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        plan = make_plan(args.case, args.run_id, args.target)
        if args.out.exists(): raise ValueError('output exists; use a new run ID and preserve earlier evidence')
        if args.execute and os.name == 'nt': raise ValueError('execute on prepared Kali/Linux')
        # Exclusive reservation. An interrupted report is kept, never silently replaced.
        with args.out.open('x', encoding='utf-8') as stream:
            json.dump({'scope': 'offline_plan', **plan}, stream, indent=2)
        if args.execute:
            execute(plan, lambda report: args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8'))
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print('Input completed; external detection/effect unverified.' if args.execute else 'Plan written; HTTP/ICMP attempts 0.')


if __name__ == '__main__':
    main()
