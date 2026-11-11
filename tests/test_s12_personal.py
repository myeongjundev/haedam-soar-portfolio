"""Synthetic graph/transport checks. Actual engine evidence is separate."""
from copy import deepcopy
from datetime import datetime,timezone
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from s12_settings import load,validate
from build_s12_workflows import build,IDS
from s12_client import execute,guard,plan

class S12Tests(unittest.TestCase):
    def setUp(self):
        self.s,self.c=load();self.s=deepcopy(self.s)
        self.s['policy'].update(request_threshold=90,baseline_source='offline-baseline')
        self.s['health'].update(baseline_ms=350,baseline_source='offline-baseline')
        self.c={**self.c,'detection_enabled':True}
    def body(self):return {'case_id':'S12','asset_id':self.s['asset_id'],'src_ip':self.s['addresses']['attacker'],'event_id':'offline_event','detected_at':datetime.now(timezone.utc).isoformat()}
    def response(self,health='degraded',**changes):return {'workflow':IDS['respond'],'body':self.body(),'faults':{'health':health,**changes}}
    def release(self,tid='$latest'):
        b=self.body();b.pop('event_id');b.pop('detected_at');b['ticket_id']=tid
        return {'workflow':IDS['release'],'body':b}
    def graph(self,requests,**state):
        r=subprocess.run(['node',str(ROOT/'tests/s12_graph_runner.cjs')],input=json.dumps({'workflows':build(self.s,self.c),'requests':requests,'state':state}),text=True,encoding='utf-8',capture_output=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr);return json.loads(r.stdout)
    def test_volume_alone_never_blocks_and_invalid_health_is_inconclusive(self):
        for health,verdict in [('healthy','within_baseline'),('malformed','inconclusive')]:
            r=self.graph([self.response(health)]);self.assertEqual(r['results'][0]['verdict'],verdict);self.assertEqual(r['tickets'],[]);self.assertEqual(r['blocks'],[])
    def test_degraded_lock_duplicate_release_and_old_event(self):
        r=self.graph([self.response(),self.response(),self.release(),self.release(),self.response()])
        self.assertEqual([x['verdict'] for x in r['results']],['responded','duplicate_no_action','released','nothing_to_release','old_event_no_action'])
        self.assertEqual(r['blocks'],[]);self.assertEqual(r['tickets'][0]['status'],'restored')
        health=json.loads(r['tickets'][0]['actions'][0]['detail'])['health'];self.assertEqual(len(health['samples']),3);self.assertEqual(health['verdict'],'exceeded')
    def test_unrelated_block_and_stale_release_refused(self):
        r=self.graph([self.response()],blocks=[self.s['addresses']['attacker']]);self.assertEqual(r['results'][0]['verdict'],'held_unowned_portal_block')
        r=self.graph([self.response(),self.release('T-20261111-9999')]);self.assertFalse(r['results'][1]['ok']);self.assertTrue(r['blocks'])
    def test_record_failure_and_missing_baseline_fail_closed(self):
        r=self.graph([self.response(recordStage='detected')]);self.assertFalse(r['results'][0]['ok']);self.assertEqual(r['blocks'],[])
        s=deepcopy(self.s);s['health'].update(baseline_ms=None,baseline_source=None)
        with self.assertRaises(ValueError):build(s,self.c)
    def test_scope_and_dynamic_input_rejected(self):
        for values in ({'src_ip':self.s['addresses']['normal']},{'cfg':{}},{'case_id':'S1'}):
            request=self.response();request['body'].update(values);r=self.graph([request]);self.assertEqual(r['calls'],[])
    def test_settings_limits_and_default_off(self):
        for group,key,value in [('load','concurrency',3),('load','maximum_requests',301),('workload','maximum_armed_seconds',181),('health','k',0)]:
            s=deepcopy(self.s);s[group][key]=value
            with self.assertRaises(ValueError):validate(s)
        with self.assertRaises(ValueError):guard(self.s,'attacker')
    def test_no_network_default_plan(self):
        p=plan(self.s,'offline','load','attacker');self.assertEqual(p['mode'],'plan_only');self.assertEqual(p['maximum_requests'],240)
    def test_probe_bodies_source_stop_and_preserve_old_evidence(self):
        s=self.s
        class Good:
            def __init__(self,_s,p):self.p=p
            def request(self,path):return 200,{'success':True,'data':{'categories':[]}},self.p['source_ip']
        with tempfile.TemporaryDirectory() as t,patch('s12_client.time.sleep',return_value=None):
            # Single response then STOP avoids waiting and verifies bounded fail-fast behavior.
            class Stopped(Good):
                def request(self,path):Path(t,s['stop_filename']).touch();return super().request(path)
            r=execute(s,'offline','probe','normal',t,transport=Stopped,runtime=lambda *_:None)
            self.assertEqual(len(r['records']),1);self.assertEqual(r['status'],'stopped')
            p=Path(t,'offline-probe-normal.json');before=p.read_bytes()
            with self.assertRaises(FileExistsError):execute(s,'offline','probe','normal',t,transport=Good,runtime=lambda *_:None)
            self.assertEqual(p.read_bytes(),before)

    def test_normal_error_stops_other_input(self):
        class Invalid:
            def __init__(self,s,p):self.p=p
            def request(self,path):return 200,{'success':True,'data':{}},self.p['source_ip']
        with tempfile.TemporaryDirectory() as t:
            result=execute(self.s,'badbody','probe','normal',t,transport=Invalid,runtime=lambda *_:None)
            self.assertEqual(result['status'],'failed');self.assertEqual(len(result['records']),1)
            self.assertTrue(Path(t,self.s['stop_filename']).exists())

    def test_runtime_refuses_modified_compose_command(self):
        from s12_lab import create
        import s12_runtime as runtime
        (ROOT/'.local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'.local') as t:
            bundle=create(self.s,Path(t)/'bundle')
            runtime.initialize(bundle)
            manifest=json.loads((bundle/'bundle.json').read_text());manifest['compose_argv']=['docker','stop','unrelated']
            (bundle/'bundle.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError,'bundle_drift'):runtime.initialize(bundle)

    def test_recovery_rejects_still_blocked_client(self):
        import s12_measure as measurement
        measurement.TICKET_ID='T-20261111-0001';measurement.RUN_ID='offline_restore'
        class Context:
            S=self.s
            B=ROOT/'.local'
            def save(self,*_):pass
            def now(self):return datetime.now(timezone.utc).isoformat()
        with patch.object(measurement,'o',Context()),patch.object(measurement,'schedule'),patch.object(measurement,'tickets',return_value=[{'ticket_id':measurement.TICKET_ID,'status':'responding'}]),patch.object(measurement,'engine',return_value=[]),patch.object(measurement,'webhook',return_value=(200,{'verdict':'released'})),patch.object(measurement,'invoke',return_value={'status':'blocked_observed','records':[{'status':403,'valid_body':False}]}):
            with self.assertRaisesRegex(AssertionError,'restored_client_not_healthy'):measurement.recover()

if __name__=='__main__':unittest.main()
