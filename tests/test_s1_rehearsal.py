from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from s1_rehearsal import prepare,imports,load_bundle,source_hashes
from s1_settings import digest,plan
from s1_probe import plan as probe_plan
from s1_evidence import check,release_body,read_local


class RehearsalTests(unittest.TestCase):
    def setUp(self):self.s=json.loads((ROOT/'infra/s1-settings.json').read_text(encoding='utf-8'))

    def test_packet_imports_no_overwrite_or_source_drift(self):
        (ROOT/'.local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
            b=prepare(self.s,'unit',Path(tmp)/'bundle')
            s,c,p=load_bundle(b)
            self.assertFalse(s['execution_enabled']);self.assertFalse(p['runtime_verified'])
            self.assertNotIn((b/'normal-password.txt').read_text().strip(),json.dumps(p))
            bindings={k:str(i)*24 for i,k in enumerate(('input_id','index_set_id','stream_id','notification_id'),1)}
            original=(b/'lab.env').read_text()
            (b/'lab.env').write_text(original.replace('PORTAL_PORT='+str(s['host_ports']['PORTAL_PORT']),'PORTAL_PORT=9999'))
            with self.assertRaises(ValueError):imports(b,bindings)
            self.assertFalse((b/'import').exists())
            (b/'lab.env').write_text(original)
            out=imports(b,bindings)
            self.assertFalse(json.loads((out/'manifest.json').read_text())['import_executed'])
            self.assertEqual(len(json.loads((out/'credentials.json').read_text())),4)
            with self.assertRaises(FileExistsError):imports(b,bindings)
            with self.assertRaises(ValueError):read_local(b,'../outside.json')
            raw=json.loads((b/'rehearsal.json').read_text());raw['source_sha256']={}
            (b/'rehearsal.json').write_text(json.dumps(raw))
            with self.assertRaises(ValueError):load_bundle(b)

    def fixture(self):
        s=self.s;run='unit';h=digest(s);hashes=source_hashes();start=datetime(2026,11,10,tzinfo=timezone.utc)
        iso=lambda seconds:(start+timedelta(seconds=seconds)).isoformat()
        p=plan(s,run,'trigger9');username=p['username'];ip=p['source_ip']
        records=[{'operation':'health','status':200,'source_ip':ip}]
        for n in range(9):
            records.extend([{'operation':'session','status':200,'source_ip':ip},{'operation':'login','status':401,'error_code':'INVALID_CREDENTIALS',
                'source_ip':ip,'started_at':iso(10+n*101),'finished_at':iso(11+n*101)}])
        packet={'run_id':run,'clock_tolerance_seconds':30,'normal_username':probe_plan(s,run,'normal','baseline')['username'],'source_sha256':hashes}
        inp={**p,'mode':'actual_http_input','status':'input_complete','observed_401_count':9,'records':records,'started_at':iso(5),
             'source_sha256':{n:hashes['tools/'+n] for n in ('s1_client.py','s1_settings.py')}}
        probes={}
        for role in ('attacker','normal'):
            for phase,second in [('baseline',0),('blocked',900),('restored',1000)]:
                q=probe_plan(s,run,role,phase)
                ops=['health'] if role=='attacker' else ['health','session']+(['register'] if phase=='baseline' else [])+['login','session']
                probes[role+'_'+phase]={**q,'mode':'actual_http_probe','status':'probe_passed','started_at':iso(second),'finished_at':iso(second+1),
                    'records':[{'operation':o,'status':q['expected_health_status'] if o=='health' else 201 if o=='register' else 200,
                                'source_ip':s['addresses'][role]} for o in ops],
                    'normal_authenticated':True if role=='normal' else None,
                    'source_sha256':{n:hashes['tools/'+n] for n in ('s1_probe.py','s1_client.py','s1_settings.py')}}
        action={'bot':'112','via':'portal','action':'block','target':ip,'result':'applied','applied_verified':True}
        ticket={'ticket_id':'T-20261110-0001','seat':'A','case_id':'S1','asset_id':s['asset_id'],'src_ip':ip,'username':username,
            'group_key':f'S1|{username}|{ip}','data_origin':'live','event_ids':['event1'],'status':'responding','actions':[action]}
        after={**ticket,'status':'restored','restored_at':iso(980),'actions':[action,{**action,'action':'unblock','result':'released'}]}
        e={'input':inp,'probes':probes,'ticket_blocked':{'ok':True,'ticket':ticket},'ticket_restored':{'ok':True,'ticket':after},
           'graylog_event':{'id':'event1','event_definition_id':'a'*24,'timestamp_processing':iso(850),
                           'fields':{'username':username,'src_ip':ip}},
           'release_response':{'ok':True,'verdict':'released','ticket_id':ticket['ticket_id']}}
        return packet,e

    def test_complete_artifacts_and_exact_release_payload(self):
        p,e=self.fixture();r=check(self.s,p,e,'a'*24)
        self.assertEqual(r['artifact_consistency'],'passed');self.assertFalse(r['provenance_attested'])
        self.assertEqual(set(release_body(self.s,'unit',e['ticket_blocked'])),{'case_id','asset_id','src_ip','username','ticket_id'})

    def test_restoration_requires_original_history_and_matching_release(self):
        for mutation in ('missing_history','unrelated_release_only','changed_history','wrong_bot','wrong_via','wrong_target',
                         'duplicate_release','unverified_release','release_before_apply'):
            with self.subTest(mutation=mutation):
                p,e=self.fixture()
                actions=deepcopy(e['ticket_restored']['ticket']['actions'])
                if mutation=='missing_history':actions=actions[1:]
                elif mutation=='unrelated_release_only':
                    actions=actions[1:]
                    actions[0].update(bot='999',target=self.s['addresses']['normal'])
                elif mutation=='changed_history':actions[0]['result']='already_applied'
                elif mutation=='wrong_bot':actions[1]['bot']='999'
                elif mutation=='wrong_via':actions[1]['via']='pfsense'
                elif mutation=='wrong_target':actions[1]['target']=self.s['addresses']['normal']
                elif mutation=='duplicate_release':actions[1]['duplicate']=True
                elif mutation=='unverified_release':actions[1]['applied_verified']=False
                elif mutation=='release_before_apply':actions.reverse()
                e['ticket_restored']['ticket']['actions']=actions
                with self.assertRaises(ValueError):check(self.s,p,e,'a'*24)

    def test_second_precision_restoration_accepts_same_second_probes(self):
        p,e=self.fixture()
        for role in ('attacker','normal'):
            e['probes'][role+'_blocked']['started_at']='2026-11-10T00:16:20.100+00:00'
            e['probes'][role+'_blocked']['finished_at']='2026-11-10T00:16:20.999+00:00'
        e['ticket_restored']['ticket']['restored_at']='2026-11-10T09:16:20+09:00'
        self.assertEqual(check(self.s,p,e,'a'*24)['artifact_consistency'],'passed')

    def test_restoration_precision_does_not_hide_reversed_order(self):
        for restored,finished in (
            ('2026-11-10T00:16:20+00:00','2026-11-10T00:16:21+00:00'),
            ('2026-11-10T00:16:20Z','2026-11-10T00:16:21.001+00:00'),
            ('2026-11-10T00:16:20.100+00:00','2026-11-10T00:16:20.101+00:00'),
        ):
            with self.subTest(restored=restored,finished=finished):
                p,e=self.fixture()
                e['ticket_restored']['ticket']['restored_at']=restored
                e['probes']['attacker_blocked']['finished_at']=finished
                with self.assertRaises(ValueError):check(self.s,p,e,'a'*24)

    def test_precise_restoration_accepts_probe_finishing_at_recorded_time(self):
        p,e=self.fixture()
        timestamp='2026-11-10T00:16:20.100+00:00'
        e['ticket_restored']['ticket']['restored_at']=timestamp
        e['probes']['attacker_blocked']['finished_at']=timestamp
        self.assertEqual(check(self.s,p,e,'a'*24)['artifact_consistency'],'passed')

    def test_missing_mixed_run_stale_event_and_incomplete_restoration_rejected(self):
        changes=[lambda e:e['input'].update(run_id='different'),lambda e:e['input'].update(observed_401_count=8),
                 lambda e:e['graylog_event'].update(id='different'),lambda e:e['ticket_restored']['ticket'].update(ticket_id='T-20261110-0002'),
                 lambda e:e['ticket_blocked']['ticket'].update(data_origin='sample'),
                 lambda e:e['probes']['normal_blocked'].update(normal_authenticated=False),
                 lambda e:e['ticket_restored']['ticket'].update(actions=e['ticket_restored']['ticket']['actions'][:1]),
                 lambda e:e['input']['source_sha256'].update({'s1_client.py':'wrong'}),
                 lambda e:e['probes']['attacker_restored']['records'][0].update(status=403),
                 lambda e:e.pop('release_response')]
        for change in changes:
            with self.subTest(change=change):
                p,e=self.fixture();change(e)
                with self.assertRaises((ValueError,KeyError)):check(self.s,p,e,'a'*24)


if __name__=='__main__':unittest.main()
