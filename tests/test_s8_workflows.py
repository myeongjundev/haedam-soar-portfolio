"""Behavior checks for deployment guards. The Docker test proves real effects."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from build_s8_workflows import build


class S8Guards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = build()

    def workflow(self, number):
        return next(w for name, w in self.workflows.items() if name.startswith('haedam-' + number))

    def run_code(self, number, needle, value):
        code, = [n['parameters']['jsCode'] for n in self.workflow(number)['nodes']
                 if needle in n.get('parameters', {}).get('jsCode', '')]
        js = "const p=JSON.parse(require('fs').readFileSync(0,'utf8')); const f=new Function('$input','$execution',p.code); console.log(JSON.stringify(f({first:()=>({json:p.value})},{id:'unit-test'})));"
        run = subprocess.run(['node', '-e', js], input=json.dumps({'code': code, 'value': value}),
                             text=True, encoding='utf-8', capture_output=True, check=True)
        return json.loads(run.stdout)[0]['json']

    def test_s8_scope_and_modes(self):
        body = {'case_id': 'S8', 'asset_id': 'haedam-portal', 'event_id': 'test-event', 'src_ip': '172.30.88.21'}
        r = self.run_code('32', 'const t = {', {'body': body})
        self.assertTrue(r['proceed'])
        self.assertTrue(r['ctx']['cfg']['dry_run'])
        live = self.run_code('32', 'const t = {', {'body': {**body, 'dry_run': False, 'store_real': True}})
        self.assertFalse(live['ctx']['cfg']['dry_run'])
        self.assertTrue(live['ctx']['cfg']['store_real'])
        for changed in ({'case_id': 'S10'}, {'asset_id': 'other'}):
            r = self.run_code('32', 'const t = {', {'body': {**body, **changed}})
            self.assertEqual(r['verdict'], 'invalid_input')
        for ip in ('172.30.88.22', '172.30.89.2', '127.0.0.1', 'example.com', '8.8.8.8'):
            r = self.run_code('32', 'const t = {', {'body': {**body, 'src_ip': ip}})
            self.assertEqual(r['verdict'], 'protected_source')

    def test_release_requires_current_ticket_and_uses_authenticated_identity(self):
        b = {'seat': 'B', 'case_id': 'S8', 'group_key': '172.30.88.21', 'asset_id': 'haedam-portal',
             'ticket_id': 'T-20261109-0001', 'approver': 'spoofed-name'}
        r = self.run_code('50', 'live_release_enabled:', {'body': b})
        self.assertFalse(r['stop'])
        self.assertEqual(r['ctx']['approver'], 'portfolio-operator')
        self.assertEqual(r['ctx']['requested_ticket_id'], b['ticket_id'])
        for change in ({'ticket_id': ''}, {'case_id': 'S10'}, {'group_key': '172.30.88.22'}):
            r = self.run_code('50', 'live_release_enabled:', {'body': {**b, **change}})
            self.assertTrue(r['stop'])
        snapshot = {'ok': True, 'exists': True, 'status': 'responding', 'ticket_id': 'T-20261109-0002',
                    'actions': [], 'ctx': {'cfg': {'dry_run': False}, 'requested_ticket_id': b['ticket_id']}}
        r = self.run_code('50', 'const selected=actions.filter', snapshot)
        self.assertEqual(r['verdict'], 'held_stale_release_ticket')

    def test_http_errors_are_not_success(self):
        node = next(n for n in self.workflow('32')['nodes'] if n['type'].endswith('.respondToWebhook'))
        expr = node['parameters']['options']['responseCode'][3:-3]
        script = "const p=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(new Function('$json','return ('+p.expr+')')(p.value));"
        for value, expected in (({'ok': False, 'verdict': 'held_ticket_check'}, 503),
                                ({'ok': False, 'verdict': 'invalid_input'}, 400),
                                ({'ok': True, 'verdict': 'duplicate_no_action'}, 200),
                                ({'ok': True, 'verdict': 'held_other_resource_ticket'}, 409)):
            result = subprocess.run(['node', '-e', script], input=json.dumps({'expr': expr, 'value': value}),
                                    capture_output=True, text=True, check=True)
            self.assertEqual(int(result.stdout), expected)

    def test_every_dependency_is_installed_and_webhooks_separate_auth(self):
        ids = {w['id'] for w in self.workflows.values()}
        for w in self.workflows.values():
            self.assertEqual(w['settings']['saveDataSuccessExecution'], 'none')
            self.assertEqual(w['settings']['saveDataErrorExecution'], 'none')
            for n in w['nodes']:
                if n['type'].endswith('.executeWorkflow'):
                    self.assertIn(n['parameters']['workflowId']['value'], ids)
                if n['type'].endswith('.webhook'):
                    self.assertEqual(n['parameters']['authentication'], 'headerAuth')
                    expected = 's8DetectionAuth' if w['id'] == 'haedamS8S10Main01' else 's8OperatorAuth'
                    self.assertEqual(n['credentials']['httpHeaderAuth']['id'], expected)

    def test_portal_mutation_and_readback_use_response_network(self):
        # A valid mutation followed by readback over the client network fails 403.
        data = json.dumps(self.workflow('12'))
        self.assertNotIn('http://portal:5000', data)
        self.assertIn('http://portal-response:5000/api/v1/response/ips', data)


if __name__ == '__main__':
    unittest.main()
