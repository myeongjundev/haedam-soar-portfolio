"""Bounded S1 input on Kali. Default: plan only, no network or credentials.

Execute only in the booked S1 window after A/C/D readiness and clock checks.
This generates input evidence, never proves detection, response or restoration.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

BASE = Path('/home/kali/haedam-prep-20261023/b_scenario_probe.py')
BASE_SHA = 'caa03dcb8250bc578a2e8d4fda49c54992c2a2c637de0570637e4781c2b67964'
SOURCE = '203.0.113.11'
ATTACK_SOURCES = ('203.0.113.11', '203.0.113.13', '203.0.113.14',
                  '203.0.113.15', '203.0.113.16')
TARGET = '203.0.113.1'
ATTEMPTS = 11
INTERVAL = 100


def now():
    return datetime.now(timezone.utc).isoformat()


def make_plan(run_id, username, source=SOURCE, attempts=ATTEMPTS, interval=INTERVAL,
              profile='trigger'):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', run_id):
        raise ValueError('invalid_run_id')
    if not re.fullmatch(r'zz_[a-zA-Z0-9_-]{1,40}', username):
        raise ValueError('synthetic_username_required')
    if source not in ATTACK_SOURCES:
        raise ValueError('source_not_in_agreed_attack_sources')
    if profile not in ('trigger', 'boundary8'):
        raise ValueError('invalid_profile')
    allowed = (8,) if profile == 'boundary8' else (9, 10, 11)
    if type(attempts) is not int or attempts not in allowed:
        raise ValueError('attempts_must_be_8_for_boundary_or_9_to_11_for_trigger')
    if type(interval) is not int or interval not in (100, 200):
        raise ValueError('interval_must_be_100_or_200_seconds')
    return {'mode': 'plan_only_no_traffic', 'case': 'S1', 'run_id': run_id,
            'profile': profile, 'expected_detection': profile == 'trigger',
            'username': username, 'source': source, 'target': TARGET,
            'maximum_login_attempts': attempts, 'interval_seconds': interval,
            'condition_failure_threshold': 9, 'condition_window_seconds': 1800,
            'boundary_observation_seconds': 1860 if profile == 'boundary8' else None,
            'boundary_observation_from': 'eighth_401_arrival_at_graylog' if profile == 'boundary8' else None,
            'boundary_validity': ('portal_origin_8_equals_graylog_received_8_no_ninth_failure'
                                  if profile == 'boundary8' else None),
            'minimum_first_to_last_seconds': (attempts - 1) * interval,
            'minimum_first_to_ninth_seconds': 8 * interval if attempts >= 9 else None,
            'maximum_http_requests': attempts * 2,
            'sequence_per_attempt': ['GET auth/me CSRF', 'POST auth/login expected 401'],
            'stop_on_http403': 'stop input; independently verify actual block effect',
            'automatic_retry': False, 'response_API_called': False,
            'preconditions': ['booked S1 window and A/C/D readiness',
                              'attempt cap and interval agreed; historical 200s runs are separate',
                              'account and previous 30-minute failure history checked',
                              'boundary8 uses an independent account and external non-detection checks',
                              'never top up lost boundary events on the same key; preserve invalid trial',
                              'actual source preservation and detector settings checked',
                              'clock offsets checked and Kali NTP synchronized',
                              'normal login and approved release paths ready']}


def preflight(source=SOURCE):
    if source not in ATTACK_SOURCES:
        raise ValueError('source_not_in_agreed_attack_sources')
    if sys.platform != 'linux':
        raise ValueError('execute_on_kali_only')
    def read(args):
        return subprocess.check_output(args, text=True, timeout=8, stderr=subprocess.DEVNULL)
    addresses = json.loads(read(['ip', '-j', '-4', 'addr', 'show', 'dev', 'eth0']))
    if sum(a.get('local') == source and a.get('prefixlen') == 32
           for row in addresses for a in row.get('addr_info', [])) != 1:
        raise ValueError('attack_source_missing_or_not_unique_32')
    routes = json.loads(read(['ip', '-j', 'route', 'get', TARGET, 'from', source]))
    if (len(routes) != 1 or routes[0].get('dev') != 'eth0'
            or routes[0].get('from') != source or 'gateway' in routes[0]):
        raise ValueError('source_route_mismatch')
    if read(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value']).strip() != 'yes':
        raise ValueError('kali_ntp_not_synchronized')
    if hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA:
        raise ValueError('base_client_hash_mismatch')
    spec = importlib.util.spec_from_file_location('verified_b_client', BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PortalClient


def save(path, report):
    # Unique temporary file; never overwrite another process's checkpoint.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def run(plan, output, client_factory, sleeper=time.sleep, monotonic=time.monotonic):
    # Revalidate before reserving evidence or constructing any network client.
    plan = make_plan(plan['run_id'], plan['username'], plan['source'],
                     plan['maximum_login_attempts'], plan['interval_seconds'],
                     plan.get('profile', 'trigger'))
    output = Path(output)
    report = {'plan': {**plan, 'mode': 'execute_bounded_input'}, 'started_at': now(),
              'state': 'reserved', 'completed_failures': 0, 'http_requests': [],
              'portal_src_ip_verified': False, 'graylog_detection_verified': False,
              'live_n8n_verified': False, 'ticket_verified': False,
              'normal_login_verified': False, 'restoration_verified': False}
    report['block_effect_verified'] = False
    report['non_detection_verified'] = False
    # Reserve before constructing a client. A reused evidence path sends no request.
    with output.open('x', encoding='utf-8') as stream:
        os.chmod(output, 0o600)
        json.dump(report, stream)
    client = None
    def checkpoint():
        report['http_requests'] = client.history if client is not None else []
        save(output, report)
    try:
        client = client_factory(TARGET, 80, plan['source'])
        client.on_record = checkpoint
        wrong_password = 'wrong_test_' + secrets.token_urlsafe(32)
        last_start = None
        for index in range(plan['maximum_login_attempts']):
            if last_start is not None:
                sleeper(max(0, plan['interval_seconds'] - (monotonic() - last_start)))
            last_start = monotonic()
            report['current_attempt'] = index + 1
            checkpoint()
            client.get_csrf()
            # Pinned client requires 401 INVALID_CREDENTIALS; never force more failures.
            client.fail_login(plan['username'], wrong_password)
            report['completed_failures'] += 1
            checkpoint()
        report['state'] = ('boundary_inputs_finished_non_detection_unverified'
                           if plan['profile'] == 'boundary8'
                           else 'inputs_finished_external_evidence_pending')
    except KeyboardInterrupt:
        report.update(state='aborted_no_automatic_retry', reason='operator_interrupted')
    except Exception as error:
        # Exception messages can contain response bodies or credentials.
        last = client.history[-1] if client is not None and client.history else {}
        if last.get('status') == 403:
            report.update(state=('unexpected_http403_boundary_external_review'
                                 if plan['profile'] == 'boundary8'
                                 else 'stopped_http403_effect_verification_pending'),
                          reason='http403_observed_no_more_input',
                          stopped_request_method=last.get('method'))
        else:
            report.update(state='aborted_no_automatic_retry', error_type=type(error).__name__)
    finally:
        report['login_post_attempts'] = sum(item.get('method') == 'POST'
                                           for item in client.history) if client is not None else 0
        report['login_posts_with_response'] = sum(item.get('method') == 'POST'
                                                  and isinstance(item.get('status'), int)
                                                  for item in client.history) if client is not None else 0
        report['finished_at'] = now()
        checkpoint()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--username', default='zz_a1')
    parser.add_argument('--source', choices=ATTACK_SOURCES, default=SOURCE)
    parser.add_argument('--profile', choices=('trigger', 'boundary8'), default='trigger')
    parser.add_argument('--attempts', type=int, choices=(8, 9, 10, 11))
    parser.add_argument('--interval-seconds', type=int, choices=(100, 200), default=INTERVAL)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        attempts = args.attempts if args.attempts is not None else (8 if args.profile == 'boundary8' else ATTEMPTS)
        plan = make_plan(args.run_id, args.username, args.source, attempts,
                         args.interval_seconds, args.profile)
    except ValueError as error:
        parser.error(str(error))
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    if not args.output or args.output.exists() or not args.output.parent.is_dir():
        parser.error('execute_needs_new_output_in_existing_directory')
    try:
        factory = preflight(plan['source'])
    except ValueError as error:
        parser.error(str(error))
    except (OSError, subprocess.SubprocessError, TypeError, KeyError):
        parser.error('preflight_unavailable_no_input_sent')
    report = run(plan, args.output, factory)
    print(json.dumps(report, indent=2))
    if report['state'] == 'stopped_http403_effect_verification_pending':
        return 3  # Expected stop candidate; still requires independent effect evidence.
    return 0 if report['state'] in ('inputs_finished_external_evidence_pending',
                                    'boundary_inputs_finished_non_detection_unverified') else 1


if __name__ == '__main__':
    raise SystemExit(main())
