"""Offline behavioral checks. No Docker, sockets, live credentials or sleeps."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import s1_client as client
import s1_lab as lab
from s1_settings import plan, validate


def settings():
    return json.loads((ROOT / 'infra/s1-settings.json').read_text(encoding='utf-8'))


class FakeTransport:
    def __init__(self, s, p, bad_status=None):
        self.s, self.p, self.bad_status, self.calls = s, p, bad_status, []

    def request(self, path, body=None, csrf=None):
        self.calls.append((path, body, csrf))
        if path == self.s['paths']['health']:
            result = (200, {'data': {'service': 'haedam-portal', 'status': 'ok'}})
        elif path == self.s['paths']['session']:
            result = (200, {'data': {'user': None, 'csrf_token': 'never-record-csrf'}})
        else:
            code = 'INVALID_CREDENTIALS' if not self.bad_status else 'RATE_LIMITED'
            result = (self.bad_status or 401, {'error': {'code': code, 'message': 'never-record-body'}})
        return (*result, self.p['source_ip'])


class SettingsTests(unittest.TestCase):
    def test_policy_and_distinct_boundary_trigger_keys(self):
        a, b = plan(settings(), 'round1', 'boundary8'), plan(settings(), 'round1', 'trigger9')
        self.assertNotEqual(a['username'], b['username'])
        self.assertEqual((a['maximum_login_attempts'], b['maximum_login_attempts']), (8, 9))
        self.assertEqual((a['minimum_input_span_seconds'], b['minimum_input_span_seconds']), (700, 800))
        self.assertFalse(a['expected_detection'])
        self.assertEqual(a['end_to_end_status'], 'not_run')

    def test_rejects_unsafe_configuration(self):
        cases = [lambda s: s['networks'].update(clients=s['networks']['default']),
                 lambda s: s['networks'].update(clients='8.8.8.0/24'),
                 lambda s: s['addresses'].update(attacker=s['addresses']['normal']),
                 lambda s: s['addresses'].update(attacker='172.30.101.1'),
                 lambda s: s['host_ports'].update(N8N_PORT=s['host_ports']['PORTAL_PORT']),
                 lambda s: s['policy'].update(input_interval_seconds=1),
                 lambda s: s['policy'].update(failure_threshold=2),
                 lambda s: s['paths'].update(login='//other/api'),
                 lambda s: s['paths'].update(tools_mount='/'),
                 lambda s: s.update(stop_filename='../../STOP'),
                 lambda s: s.update(project='haedam-pf-lab'),
                 lambda s: s.update(execution_enabled='false')]
        for change in cases:
            with self.subTest(change=change):
                s = settings()
                change(s)
                with self.assertRaises(ValueError):
                    validate(s)

    def test_input_identity_validation(self):
        for run in ('../escape', 'UPPER', '', 'x' * 25, 'a-b'):
            with self.assertRaises(ValueError):
                plan(settings(), run, 'trigger9')

    def test_malformed_or_extra_settings_rejected(self):
        for s in (None, [], {}, {**settings(), 'password': 'must-not-accept'},
                  {**settings(), 'paths': None}, {**settings(), 'project': None}):
            with self.assertRaises(ValueError):
                validate(s)

    def test_changes_to_settings_reach_all_consumers(self):
        s = settings()
        s['addresses']['attacker'] = '172.30.101.41'
        s['host_ports']['PORTAL_PORT'] = 25160
        s['project'] = 'haedam-s1-alternate'
        o = lab.overlay(s, ROOT, ROOT / '.local/test-s1')
        self.assertEqual(o['services']['attacker']['networks']['s1-clients']['ipv4_address'], '172.30.101.41')
        self.assertIn('172.30.101.41', lab.definition_template(s, ROOT)['config']['query'])
        self.assertEqual(plan(s, 'r1', 'trigger9')['source_ip'], '172.30.101.41')
        self.assertEqual(o['name'], 'haedam-s1-alternate')

    def test_bundle_does_not_read_or_overwrite_existing_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'lab/s1s4/graylog'
            target.mkdir(parents=True)
            (target / 's1-login-bruteforce.json').write_bytes((ROOT / 'lab/s1s4/graylog/s1-login-bruteforce.json').read_bytes())
            (root / '.env').write_text('MYSQL_PASSWORD=never-reuse-existing-value\n')
            dest = root / '.local/s1'
            with patch.dict(os.environ, {'PORTAL_PORT': '9999', 'MYSQL_PASSWORD': 'never-use-process-value'}):
                lab.create_bundle(settings(), root, dest)
            content = (dest / 'lab.env').read_text()
            self.assertNotIn('never-', content)
            self.assertIn('PORTAL_PORT=15060', content)
            self.assertEqual((root / '.env').read_text(), 'MYSQL_PASSWORD=never-reuse-existing-value\n')
            self.assertFalse(json.loads((dest / 'bundle.json').read_text())['integration_ready'])
            with self.assertRaises(FileExistsError):
                lab.create_bundle(settings(), root, dest)
            self.assertEqual((dest / 'lab.env').read_text(), content)
            with self.assertRaises(ValueError):
                lab.create_bundle(settings(), root, root / 'outside')

    def test_default_cli_does_not_execute(self):
        with patch.object(client, 'execute', side_effect=AssertionError('must not execute')), \
             patch.object(sys, 'argv', ['s1_client.py', '--settings', str(lab.DEFAULT_SETTINGS),
                                       '--run-id', 'offline', '--profile', 'trigger9']), \
             patch('sys.stdout', new_callable=io.StringIO) as output:
            client.main()
            self.assertEqual(json.loads(output.getvalue())['mode'], 'plan_only')

    def test_execution_disabled_before_file_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'not-created'
            with self.assertRaisesRegex(ValueError, 'execution_disabled'):
                client.execute(settings(), 'r1', 'trigger9', dest,
                               transport_factory=lambda *_: self.fail('transport must not be created'))
            self.assertFalse(dest.exists())

    def test_wrong_container_identity(self):
        s = settings()
        s['execution_enabled'] = True
        with patch.object(sys, 'platform', 'linux'), patch.object(Path, 'is_file', return_value=True), \
             patch.dict(os.environ, {'HAEDAM_S1_PROJECT': 'haedam-pf-lab'}):
            with self.assertRaisesRegex(ValueError, 'wrong_project'):
                client.runtime_guard(s)


class InputTests(unittest.TestCase):
    def run_fake(self, tmp, profile='trigger9', bad_status=None, wait=None):
        made = []
        def factory(s, p):
            made.append(FakeTransport(s, p, bad_status))
            return made[-1]
        result = client.execute(settings(), 'r1', profile, tmp, transport_factory=factory,
                                guard=lambda _: None, wait=wait or (lambda *_: None))
        return result, made[0]

    def test_exact_bounded_inputs_and_no_secrets_in_evidence(self):
        for profile, count in [('boundary8', 8), ('trigger9', 9), ('normal', 0)]:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as tmp:
                result, transport = self.run_fake(tmp, profile)
                self.assertEqual(result['observed_401_count'], count)
                self.assertEqual(len(transport.calls), 1 + 2 * count)
                self.assertEqual(result['end_to_end_status'], 'not_run')
                content = json.dumps(result)
                self.assertNotIn('never-record', content)
                self.assertNotIn('csrf_token', content)
                for _, body, _ in transport.calls:
                    if body:
                        self.assertNotIn(body['password'], content)
                self.assertFalse((Path(tmp) / 'input.lock').exists())

    def test_403_429_200_redirect_stop_without_retry(self):
        for status in (403, 429, 200, 302):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                result, transport = self.run_fake(tmp, bad_status=status)
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['observed_401_count'], 0)
                self.assertEqual(len(transport.calls), 3)

    def test_stop_file_prevents_all_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / settings()['stop_filename']).touch()
            result, transport = self.run_fake(tmp)
            self.assertEqual(result['status'], 'stopped')
            self.assertEqual(transport.calls, [])

    def test_stop_between_attempts_preserves_partial_evidence(self):
        def stop(_, path):
            path.touch()
        with tempfile.TemporaryDirectory() as tmp:
            result, transport = self.run_fake(tmp, wait=stop)
            self.assertEqual(result['status'], 'stopped')
            self.assertEqual(result['observed_401_count'], 1)
            self.assertEqual(len(transport.calls), 3)

    def test_existing_lock_and_run_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / 'input.lock'
            lock.write_text('other-run')
            with self.assertRaises(FileExistsError):
                self.run_fake(tmp)
            self.assertEqual(lock.read_text(), 'other-run')
            lock.unlink()
            self.run_fake(tmp)
            path = Path(tmp) / 'r1-trigger9.json'
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                self.run_fake(tmp)
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse(lock.exists())

    def test_socket_identity_checked_before_http(self):
        s = settings()
        p = plan(s, 'r1', 'trigger9')
        with patch.object(client.http.client, 'HTTPConnection') as constructor:
            conn = constructor.return_value
            conn.sock.getsockname.return_value = ('172.30.101.22', 1234)
            with self.assertRaisesRegex(ValueError, 'socket_identity_mismatch'):
                client.Transport(s, p).request(s['paths']['health'])
            self.assertEqual(constructor.call_args.kwargs['source_address'], (p['source_ip'], 0))
            conn.request.assert_not_called()
            conn.close.assert_called_once()

    def test_transport_does_not_follow_redirect_or_send_forwarded_header(self):
        s = settings()
        p = plan(s, 'r1', 'trigger9')
        with patch.object(client.http.client, 'HTTPConnection') as constructor:
            conn = constructor.return_value
            conn.sock.getsockname.return_value = (p['source_ip'], 1000)
            conn.sock.getpeername.return_value = (p['target_ip'], p['target_port'])
            response = conn.getresponse.return_value
            response.status, response.read.return_value = 302, b''
            response.getheaders.return_value = [('Location', 'http://outside.invalid')]
            status, _, _ = client.Transport(s, p).request(s['paths']['health'])
            self.assertEqual(status, 302)
            constructor.assert_called_once()
            self.assertNotIn('X-Forwarded-For', conn.request.call_args.kwargs['headers'])


if __name__ == '__main__':
    unittest.main()
