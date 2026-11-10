"""Generated graphs with in-memory HTTP contracts, not a running n8n/Graylog engine."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_s4_workflows import build, load_settings, graylog_artifacts, materialize, IDS
from s4_lab import create_bundle
from s4_settings import validate


class S4Workflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s, cls.c = load_settings()
        cls.workflows = build(cls.s, {**cls.c, 'detection_enabled': True})

    def body(self, **changes):
        return {'case_id': 'S4', 'asset_id': self.s['asset_id'], 'src_ip': self.s['addresses']['attacker'],
                'username': self.s['accounts']['target'], 'event_id': 'offline_event_1',
                'detected_at': datetime.now(timezone.utc).isoformat(), **changes}

    def respond(self, **extra):
        return {'workflow': IDS['respond'], 'body': self.body(), **extra}

    def release(self, ticket='$latest', **extra):
        body = self.body(); body.pop('event_id'); body.pop('detected_at'); body['ticket_id'] = ticket
        return {'workflow': IDS['release'], 'body': body, **extra}

    def run_graph(self, requests, workflows=None, **state):
        state = {'account': {'user_id': 7, 'username': self.s['accounts']['target'], 'locked': False,
                            'active_sessions': 2, 'owner_ticket_id': None}, **state}
        run = subprocess.run(['node', str(ROOT / 'tests/s4_graph_runner.cjs')], text=True, encoding='utf-8',
                             input=json.dumps({'workflows': workflows or self.workflows, 'requests': requests, 'state': state}),
                             capture_output=True, timeout=30, check=True)
        return json.loads(run.stdout)

    def mutations(self, result, action='lock'):
        return [c for c in result['calls'] if c['method'] == 'POST' and c['url'].endswith('/'+action)]

    def test_full_graph_duplicates_restore_and_fresh_cycle(self):
        r = self.run_graph([self.respond(), self.respond(), self.respond(body=self.body(event_id='event2')),
                            self.release(), self.release(), self.respond(), self.respond(body=self.body(event_id='event2')),
                            self.respond(body=self.body(event_id='fresh')), self.release()])
        self.assertEqual([x['verdict'] for x in r['results']], ['responded', 'duplicate_no_action', 'duplicate_no_action',
                         'released', 'nothing_to_release', 'old_event_no_action', 'old_event_no_action', 'responded', 'released'])
        self.assertEqual(len(self.mutations(r)), 2)
        self.assertFalse(r['account']['locked']); self.assertIsNone(r['account']['owner_ticket_id'])
        self.assertEqual(r['account']['active_sessions'], 0)
        self.assertEqual([t['status'] for t in r['tickets']], ['closed', 'restored'])
        self.assertTrue(all(x.get('effect_verified') is None for x in r['results']))

    def test_input_scope_age_disabled_and_override(self):
        for change in ({'username': self.s['accounts']['normal']}, {'src_ip': self.s['addresses']['normal']},
                       {'cfg': {}}, {'case_id': 'S1'}, {'detected_at': 'bad'},
                       {'detected_at': (datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()}):
            with self.subTest(change=change):
                r = self.run_graph([self.respond(body=self.body(**change))])
                self.assertEqual(r['calls'], [])
        r = self.run_graph([self.respond()], workflows=build())
        self.assertEqual(r['calls'], [])

    def test_ticket_failure_never_mutates_account(self):
        for fault in ({'ticketRead': True}, {'recordStage': 'detected'}):
            r = self.run_graph([self.respond(faults=fault)])
            self.assertFalse(r['results'][0]['ok']); self.assertFalse(self.mutations(r))

    def test_existing_lock_or_portal_claim_is_not_adopted(self):
        for update in ({'locked': True}, {'locked': True, 'owner_ticket_id': 'T-20261110-9999'}):
            r = self.run_graph([self.respond(accountChange=update)])
            self.assertFalse(self.mutations(r)); self.assertFalse(r['results'][0]['ok'])

    def test_stale_ticket_and_recreated_account_hold_release(self):
        for request in (self.release('T-20261110-9999'), self.release(accountChange={'user_id': 8})):
            r = self.run_graph([self.respond(), request])
            self.assertFalse(r['results'][1]['ok']); self.assertFalse(self.mutations(r, 'unlock'))

    def test_other_ticket_claim_holds_release(self):
        owner = {'ticket_id': 'T-20261110-9999', 'seat': 'B', 'status': 'responding', 'event_ids': [],
                 'actions': [{'bot': '111', 'via': 'portal', 'action': 'lock', 'target': self.s['accounts']['target']+':7',
                              'result': 'applied', 'applied_verified': True}]}
        r = self.run_graph([self.respond(), self.release('T-20261110-0001', extraOwner=owner)])
        self.assertFalse(self.mutations(r, 'unlock')); self.assertEqual(r['results'][1]['verdict'], 'held_other_resource_ticket')

    def test_lost_response_readback_and_failed_mutation(self):
        r = self.run_graph([self.respond(faults={'lostMutationResponse': True}), self.release(faults={'lostMutationResponse': True})])
        self.assertEqual([x['verdict'] for x in r['results']], ['responded', 'released'])
        for fault in ({'portalMutation': True}, {'malformedMutation': True}):
            r = self.run_graph([self.respond(faults=fault)])
            self.assertFalse(r['results'][0]['ok']); self.assertFalse(r['account']['locked'])

    def test_unverified_readback_keeps_claim_for_release(self):
        r = self.run_graph([self.respond(faults={'readAfterMutation': True}), self.release()])
        self.assertEqual(r['results'][0]['http_status'], 503)
        self.assertEqual(r['results'][1]['verdict'], 'released')
        self.assertEqual(r['tickets'][0]['status'], 'restored')

    def test_applied_record_failure_requires_reconciliation(self):
        r = self.run_graph([self.respond(faults={'recordStage': 'applied'}), self.respond(), self.release()])
        self.assertEqual(r['results'][0]['verdict'], 'held_applied_record_reconcile')
        self.assertTrue(r['account']['locked']); self.assertEqual(len(self.mutations(r)), 1)
        self.assertFalse(self.mutations(r, 'unlock'))

    def test_release_record_failure_is_retryable_and_disabled_detection_allows_release(self):
        r = self.run_graph([self.respond(), self.release(faults={'recordStage': 'released'}), self.release()])
        self.assertEqual(r['results'][1]['verdict'], 'held_release_record_reconcile')
        self.assertEqual(r['results'][2]['verdict'], 'released')
        w = deepcopy(self.workflows); w['s4-release.json'] = build()['s4-release.json']
        self.assertEqual(self.run_graph([self.respond(), self.release()], workflows=w)['results'][1]['verdict'], 'released')

    def test_release_readback_failure_keeps_ticket_claim_until_retry(self):
        r=self.run_graph([self.respond(),self.release(faults={'readWhenUnblocked':True}),self.release()])
        self.assertEqual(r['results'][1]['verdict'],'held_release_unverified')
        self.assertEqual(r['results'][2]['verdict'],'released')
        releases=[c for c in r['calls'] if c['url'].endswith('/record') and c['body'].get('stage')=='released']
        self.assertEqual(len(releases),1)

    def test_settings_bundle_bindings_and_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Builder reads only versioned root for team templates, not another environment's dotenv.
            bundle = create_bundle(self.s, root, root / '.local/s4')
            manifest = json.loads((bundle/'bundle.json').read_text())
            self.assertFalse(manifest['runtime_verified']); self.assertFalse(manifest['integration_ready'])
            overlay = json.loads((bundle/'compose.s4.json').read_text())
            self.assertEqual(overlay['services']['portal']['environment']['S4_ACCOUNT_ALLOWLIST'], self.s['accounts']['target'])
            self.assertEqual({k: n['internal'] for k, n in overlay['networks'].items()},
                             {'default': False, 's4-clients': True, 's4-response': True, 'graylog-backend': True})
            with self.assertRaises(FileExistsError): create_bundle(self.s, root, bundle)
        bindings = {k: str(i)*24 for i,k in enumerate(('input_id','index_set_id','stream_id','notification_id'), 1)}
        keys = {v['env']: str(i)*64 for i,v in enumerate(self.c['credentials'].values(), 1)}
        m = materialize(self.s,self.c,bindings,keys)
        self.assertEqual(len(m['credentials']),5); self.assertFalse(m['schedule_enabled'])
        for bad in ({**keys,'S4_RELEASE_KEY':keys['PORTAL_RESPONSE_KEY']}, {}):
            with self.assertRaises(ValueError): materialize(self.s,self.c,bindings,bad)
        s = deepcopy(self.s); s['accounts']['normal'] = s['accounts']['target']
        with self.assertRaises(ValueError): validate(s)

    def test_alternate_settings_propagate_without_source_edits(self):
        s = deepcopy(self.s); s['accounts']['target']='zz_s4_alternate'; s['addresses']['attacker']='172.30.105.30'
        rendered = json.dumps(build(s,self.c)); spec = graylog_artifacts(s,self.c)
        self.assertIn('zz_s4_alternate', rendered); self.assertNotIn('zz_s4_target', rendered)
        self.assertIn('172.30.105.30', spec['definition']['config']['query'])
        self.assertEqual(spec['definition']['config']['group_by'], ['username','src_ip'])

    def test_generated_credentials_references_and_inactive_exports(self):
        generated=build()
        ids={w['id'] for w in generated.values()}
        for w in generated.values():
            self.assertFalse(w['active'])
            self.assertEqual(w['settings']['saveDataErrorExecution'],'none')
            for n in w['nodes']:
                if n['type'].endswith('.executeWorkflow'):
                    self.assertIn(n['parameters']['workflowId']['value'],ids)
        account=generated['s4-portal.json']
        nodes={n['name']:n for n in account['nodes']}
        for name,role in [('Account API','portal'),('Readback','portal'),('Release API','release')]:
            self.assertEqual(nodes[name]['credentials']['httpHeaderAuth']['id'],self.c['credentials'][role]['id'])
        for role,credential in [('respond','detection'),('release','operator')]:
            hook=next(n for n in generated[f's4-{role}.json']['nodes'] if n['name']=='Webhook')
            self.assertEqual(hook['parameters']['authentication'],'headerAuth')
            self.assertEqual(hook['credentials']['httpHeaderAuth']['id'],self.c['credentials'][credential]['id'])


if __name__ == '__main__':
    unittest.main()
