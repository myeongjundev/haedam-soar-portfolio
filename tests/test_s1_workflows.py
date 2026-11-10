"""Offline generated-graph and contract tests; no n8n engine or network."""
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build_s1_workflows import build, load_settings, graylog_artifacts, materialize, IDS


class S1WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s,cls.c=load_settings()
        cls.enabled={**cls.c,'detection_enabled':True}
        cls.workflows=build(cls.s,cls.enabled)

    def body(self,**changes):
        return {'case_id':'S1','asset_id':self.s['asset_id'],'src_ip':self.s['addresses']['attacker'],
                'username':self.s['username_prefix']+'t_offline','event_id':'offline_event_1',
                'detected_at':datetime.now(timezone.utc).isoformat(),**changes}

    def respond(self,body=None,**extra):
        return {'workflow':IDS['respond'],'body':body or self.body(),**extra}

    def release(self,ticket='$latest',**extra):
        b=self.body();b.pop('event_id');b.pop('detected_at');b['ticket_id']=ticket
        return {'workflow':IDS['release'],'body':b,**extra}

    def run_graph(self,requests,workflows=None,state=None):
        result=subprocess.run(['node',str(ROOT/'tests/s1_graph_runner.cjs')],
            input=json.dumps({'workflows':workflows or self.workflows,'requests':requests,'state':state or {}}),
            text=True,encoding='utf-8',capture_output=True,check=True,timeout=30)
        return json.loads(result.stdout)

    def mutations(self,result,action='block'):
        return [r for r in result['calls'] if r['method']=='POST' and r['url'].endswith('/ips/'+action)]

    def test_full_graph_duplicate_release_old_event_and_new_round(self):
        result=self.run_graph([self.respond(),self.respond(),self.respond(self.body(event_id='new_while_blocked')),
                              self.release(),self.release(),self.respond(),self.respond(self.body(event_id='new_while_blocked')),
                              self.respond(self.body(event_id='new_round')),self.release()])
        self.assertEqual([r['verdict'] for r in result['results']],['responded','duplicate_no_action','duplicate_no_action',
            'released','nothing_to_release','old_event_no_action','old_event_no_action','responded','released'])
        self.assertEqual(len(self.mutations(result)),2)
        self.assertEqual(result['blocks'],[])
        self.assertEqual([t['status'] for t in result['tickets']],['closed','restored'])
        self.assertTrue(all(r.get('effect_verified') is None for r in result['results']))

    def test_invalid_or_disabled_input_has_no_http(self):
        cases=[self.body(src_ip=self.s['addresses']['normal']),self.body(case_id='S8'),self.body(username='real_user'),
               self.body(dry_run=False),self.body(cfg={}),self.body(detected_at='bad'),
               self.body(detected_at=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()),
               self.body(detected_at=(datetime.now(timezone.utc)+timedelta(minutes=2)).isoformat())]
        for body in cases:
            with self.subTest(body=body):
                r=self.run_graph([self.respond(body)])
                self.assertEqual(r['calls'],[])
                self.assertEqual(r['results'][0]['actual_response_code'],400)
        r=self.run_graph([self.respond()],workflows=build())
        self.assertEqual(r['results'][0]['verdict'],'held_detection_disabled')
        self.assertEqual(r['calls'],[])

    def test_ticket_read_or_detected_write_failure_prevents_mutation(self):
        for fault in ({'ticketRead':True},{'recordStage':'detected'}):
            with self.subTest(fault=fault):
                r=self.run_graph([self.respond(faults=fault)])
                self.assertFalse(r['results'][0]['ok'])
                self.assertEqual(self.mutations(r),[])

    def test_mutation_readback_failure_not_success_but_owned_release_possible(self):
        r=self.run_graph([self.respond(faults={'readAfterMutation':True}),self.release()])
        self.assertEqual(r['results'][0]['verdict'],'held_response_unverified')
        self.assertEqual(r['results'][1]['verdict'],'released')
        self.assertEqual(r['blocks'],[])

    def test_failed_applied_record_requires_reconcile_no_silent_adoption(self):
        r=self.run_graph([self.respond(faults={'recordStage':'applied'}),self.respond()])
        self.assertEqual(r['results'][0]['verdict'],'held_applied_record_reconcile')
        self.assertEqual(r['results'][1]['verdict'],'held_unowned_portal_block')
        self.assertEqual(len(self.mutations(r)),1)

    def test_stale_release_and_other_username_cannot_unblock(self):
        r=self.run_graph([self.respond(),self.release('T-20000101-0001'),
                          self.respond(self.body(username=self.s['username_prefix']+'other',event_id='other'))])
        self.assertEqual(r['results'][1]['verdict'],'held_stale_release_ticket')
        self.assertEqual(r['results'][2]['verdict'],'held_other_resource_ticket')
        self.assertEqual(self.mutations(r,'unblock'),[])

    def test_other_resource_claim_prevents_release(self):
        owner={'ticket_id':'T-20261110-9999','seat':'B','status':'responding','group_key':'other','event_ids':['other'],
               'actions':[{'bot':'112','via':'portal','action':'block','target':self.s['addresses']['attacker'],'result':'applied'}]}
        r=self.run_graph([self.respond(),self.release('T-20261110-0001',extraOwner=owner)])
        self.assertEqual(r['results'][1]['verdict'],'held_other_resource_ticket')
        self.assertEqual(self.mutations(r,'unblock'),[])

    def test_duplicate_requires_actual_portal_readback(self):
        r=self.run_graph([self.respond(),self.respond(clearBlocks=True)])
        self.assertEqual(r['results'][1]['verdict'],'held_claim_state_drift')
        self.assertEqual(len(self.mutations(r)),1)

    def test_release_record_failure_retries_without_new_ticket(self):
        r=self.run_graph([self.respond(),self.release(faults={'recordStage':'released'}),self.release()])
        self.assertEqual(r['results'][1]['verdict'],'held_release_record_reconcile')
        self.assertEqual(r['results'][2]['verdict'],'released')
        self.assertEqual(len(r['tickets']),1)

    def test_bad_portal_response_and_lost_mutation_response(self):
        r=self.run_graph([self.respond(faults={'malformedMutation':True})])
        self.assertFalse(r['results'][0]['ok'])
        r=self.run_graph([self.respond(faults={'lostMutationResponse':True})])
        self.assertTrue(r['results'][0]['ok'])
        calls=self.mutations(r)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0]['headers']['Idempotency-Key'],calls[1]['headers']['Idempotency-Key'])
        self.assertNotIn('private-key-must-not-leak',json.dumps(r['tickets']))

    def test_release_remains_available_when_detection_disabled(self):
        first=self.run_graph([self.respond()])
        r=self.run_graph([self.release('T-20261110-0001')],workflows=build(),
                         state={'tickets':first['tickets'],'blocks':first['blocks'],'serial':1})
        self.assertEqual(r['results'][0]['verdict'],'released')

    def test_graph_integrity_and_separate_credentials(self):
        identifiers={w['id'] for w in self.workflows.values()}
        for w in self.workflows.values():
            self.assertFalse(w['active'])
            self.assertEqual(w['settings']['saveDataSuccessExecution'],'none')
            names={n['name'] for n in w['nodes']}
            for edges in w['connections'].values():
                for branch in edges['main']:
                    for edge in branch:self.assertIn(edge['node'],names)
            for n in w['nodes']:
                if n['type'].endswith('.executeWorkflow'):self.assertIn(n['parameters']['workflowId']['value'],identifiers)
                # n8n hands a caller only main[0] of the last node, so no IF branch may end unconnected.
                if n['type'].endswith('.if'):
                    branches=w['connections'][n['name']]['main']
                    self.assertTrue(len(branches)==2 and all(branches),(w['id'],n['name']))
                if n['type'].endswith('.webhook'):
                    role='detection' if w['id']==IDS['respond'] else 'operator'
                    self.assertEqual(n['credentials']['httpHeaderAuth']['id'],self.c['credentials'][role]['id'])
                    self.assertEqual(n['parameters']['authentication'],'headerAuth')

    def test_generated_ticket_http_trace_against_real_flask_sqlite_api(self):
        # Replays the generated graph's requests through the real app in-process;
        # no socket, running service or existing database is used.
        sys.path.insert(0,str(ROOT/'services/ticket-store'))
        from ticket_store.app import create_n8n_app
        from ticket_store import db
        trace=self.run_graph([self.respond(),self.respond(),self.release(),self.respond(self.body(event_id='next_round')),self.release()])
        with tempfile.TemporaryDirectory() as tmp:
            database=str(Path(tmp)/'tickets.db')
            key='offline-test-only-response-key'
            client=create_n8n_app(database,key).test_client()
            for call in trace['calls']:
                u=urlsplit(call['url'])
                if u.hostname!='ticket-store':continue
                headers={**call['headers'],'X-Response-Key':key}
                response=client.open(u.path+('?' + u.query if u.query else ''),method=call['method'],headers=headers,
                                     json=call['body'] if call['method']=='POST' else None)
                self.assertIn(response.status_code,(200,201),response.get_json())
                self.assertTrue(response.get_json()['ok'])
            with closing(db.connect(database)) as conn:
                self.assertEqual(db.dashboard_work(conn)['items'],[])

    def test_release_readback_failure_keeps_claim_until_retry(self):
        r=self.run_graph([self.respond(),self.release(faults={'readWhenUnblocked':True}),self.release()])
        self.assertEqual(r['results'][1]['verdict'],'held_release_unverified')
        self.assertEqual(r['results'][2]['verdict'],'released')
        records=[call['body'] for call in r['calls'] if call['url'].endswith('/record') and call['body'].get('stage')=='released']
        self.assertEqual(len(records),1)

    def test_graylog_bindings_credentials_and_no_secret_in_export(self):
        bindings=dict(zip(['input_id','index_set_id','stream_id','notification_id'],[str(i)*24 for i in range(1,5)]))
        secrets={v['env']:str(i)*64 for i,v in enumerate(self.c['credentials'].values(),1)}
        result=materialize(self.s,self.c,bindings,secrets)
        g=result['graylog'];d=g['definition']
        self.assertEqual(d['config']['streams'],[bindings['stream_id']])
        self.assertEqual(d['notifications'][0]['notification_id'],bindings['notification_id'])
        self.assertEqual(g['stream']['rules'][1]['type'],8)
        self.assertEqual(g['notification']['config']['api_secret'],secrets['S1_DETECTION_KEY'])
        self.assertEqual(len(result['credentials']),4)
        self.assertFalse(result['schedule_enabled'])
        exported=json.dumps({'w':build(),'g':graylog_artifacts(self.s,self.c)})
        self.assertTrue(all(v not in exported for v in secrets.values()))
        for ids in ({}, {**bindings,'stream_id':'REPLACE'}):
            with self.assertRaises(ValueError):materialize(self.s,self.c,ids,secrets)
        with self.assertRaises(ValueError):materialize(self.s,self.c,bindings,{k:'1'*64 for k in secrets})

    def test_config_changes_are_used_and_unsafe_values_rejected(self):
        s=deepcopy(self.s);s['addresses']['attacker']='172.30.101.41'
        c=deepcopy(self.c);c['respond_path']='haedam-s1-alt';c['operator_name']='different-operator'
        text=json.dumps(build(s,c))
        self.assertIn('172.30.101.41',text)
        self.assertNotIn(self.s['addresses']['attacker'],text)
        self.assertIn('haedam-s1-alt',graylog_artifacts(s,c)['notification']['config']['url'])
        for changed in ({'portal_url':'http://outside.invalid:5000'},{'detection_enabled':'true'},{'event_max_age_seconds':999999}):
            with self.assertRaises(ValueError):load_settings(self.s,{**self.c,**changed})


if __name__=='__main__':unittest.main()
