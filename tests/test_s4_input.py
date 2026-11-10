"""Offline client failure/stop/secret handling. No Docker or real HTTP calls."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from s4_client import execute, runtime_guard
from s4_settings import PROFILES, plan, validate
from s4_lab import command_packet, overlay

PASSWORD = 'synthetic-offline-password-123'


def settings():
    return json.loads((ROOT / 'infra/s4-settings.json').read_text(encoding='utf-8'))


class FakeTransport:
    def __init__(self, s, p):
        self.s, self.p, self.logged_in = s, p, False

    def request(self, path, body=None, csrf=None):
        if path == self.s['paths']['health']:
            result = 200, {'success': True, 'data': {'service': self.s['asset_id'], 'status': 'ok'}}
        elif body is None:
            user = {'username': self.p['username'], 'role': 'citizen', 'locked': False} if self.logged_in else None
            result = 200, {'success': True, 'data': {'user': user, 'csrf_token': 'secret-csrf'}}
        elif body['password'] == PASSWORD:
            self.logged_in = True
            result = 200, {'success': True}
        else:
            result = 401, {'success': False, 'error': {'code': 'INVALID_CREDENTIALS', 'message': PASSWORD}}
        return *result, self.p['source_ip']


class InputTests(unittest.TestCase):
    def run_input(self, profile='trigger6', factory=FakeTransport, wait=lambda *_: None, output=None):
        return execute(settings(), 'offline', profile, output or self.directory, PASSWORD,
                       guard=lambda _: None, transport_factory=factory, wait=wait)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_profiles_counts_budgets_and_identity(self):
        for profile, sequence in PROFILES.items():
            with self.subTest(profile=profile):
                out = self.run_input(profile, output=self.directory / profile)
                self.assertEqual(out['status'], 'input_complete')
                self.assertEqual(out['observed_login_statuses'], list(sequence))
                self.assertEqual(len(out['records']), out['maximum_http_requests'])
                self.assertEqual(out['authenticated_identity_checks'], sequence.count(200))
                self.assertEqual(out['end_to_end_status'], 'not_run')
                self.assertEqual(out['expected_detection'], profile in ('trigger6', 'success_first6', 'failure1_success5'))
                serialized = json.dumps(out)
                self.assertNotIn(PASSWORD, serialized)
                self.assertNotIn('secret-csrf', serialized)

    def test_execution_disabled_before_files_or_transport(self):
        with self.assertRaisesRegex(ValueError, 'execution_disabled'):
            execute(settings(), 'offline', 'trigger6', self.directory / 'no-create', PASSWORD)
        self.assertFalse((self.directory / 'no-create').exists())

    def test_wrong_project_rejected(self):
        s = settings(); s['execution_enabled'] = True
        with patch('s4_client.sys.platform', 'linux'), patch('s4_client.Path.is_file', return_value=True), patch.dict(os.environ, {'HAEDAM_S4_PROJECT': 'wrong'}):
            with self.assertRaisesRegex(ValueError, 'wrong_project'):
                runtime_guard(s)

    def test_network_policy_rejects_isolation_and_publication_regressions(self):
        s = settings()
        for key in s['network_internal']:
            changed = copy.deepcopy(s); changed['network_internal'][key] = not changed['network_internal'][key]
            with self.assertRaises(ValueError):
                validate(changed)
        result = overlay(s, ROOT, self.directory)
        self.assertEqual(list(result['services']['attacker']['networks']), ['s4-clients'])
        self.assertFalse(result['networks']['default']['internal'])

    def test_stop_before_http_and_between_attempts(self):
        (self.directory / 'STOP').touch()
        out = self.run_input()
        self.assertEqual(out['status'], 'stopped'); self.assertEqual(out['records'], [])
        (self.directory / 'STOP').unlink()
        def stop_during_wait(*_):
            (self.directory / 'STOP').touch()
        out = self.run_input('boundary5', wait=stop_during_wait)
        self.assertEqual(out['status'], 'stopped'); self.assertEqual(out['observed_login_statuses'], [401])

    def test_lock_and_evidence_collision_preserve_existing(self):
        lock = self.directory / 'input.lock'; lock.write_text('other-run')
        with self.assertRaises(FileExistsError): self.run_input()
        self.assertEqual(lock.read_text(), 'other-run')
        lock.unlink(); self.run_input()
        path = self.directory / 'offline-trigger6.json'; before = path.read_bytes()
        with self.assertRaises(FileExistsError): self.run_input()
        self.assertEqual(path.read_bytes(), before); self.assertFalse(lock.exists())

    def test_bad_responses_stop_without_retry_or_secret_leak(self):
        for variant in ('403', '429', 'redirect', 'csrf', 'source', 'identity', 'exception'):
            class Broken(FakeTransport):
                def request(inner, path, body=None, csrf=None):
                    status, payload, source = super().request(path, body, csrf)
                    if body is not None:
                        if variant in ('403', '429', 'redirect'):
                            status = {'403': 403, '429': 429, 'redirect': 302}[variant]
                        elif variant == 'exception': raise RuntimeError(PASSWORD)
                    elif path == inner.s['paths']['session']:
                        if variant == 'csrf': payload['data']['csrf_token'] = None
                        if variant == 'identity' and inner.logged_in: payload['data']['user']['username'] = 'other'
                    if variant == 'source': source = inner.s['addresses']['normal']
                    return status, payload, source
            out = self.run_input('success_first6', factory=Broken, output=self.directory / variant)
            self.assertEqual(out['status'], 'failed', variant)
            self.assertLessEqual(sum(r['operation'] == 'login' for r in out['records']), 1)
            self.assertNotIn(PASSWORD, json.dumps(out))

    def test_plan_packet_and_invalid_identity(self):
        packet = command_packet(settings(), 'review1', ['docker', 'compose'])
        self.assertFalse(packet['runtime_verified'])
        self.assertEqual(packet['end_to_end_status'], 'not_run')
        self.assertNotIn('--execute', packet['commands']['trigger6']['plan_argv'])
        self.assertEqual(packet['commands']['trigger6']['input_argv'][-1], '--execute')
        for run_id in ('../escape', 'UPPER', '', 'x'*25):
            with self.assertRaises(ValueError): plan(settings(), run_id, 'trigger6')


if __name__ == '__main__':
    unittest.main()
