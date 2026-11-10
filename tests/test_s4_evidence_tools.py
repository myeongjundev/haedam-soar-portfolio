"""Guard, source drift, observer boundaries and GET transport failures; no runtime IO."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import s4_collect
import s4_probe
import s4_rehearsal
from build_s4_workflows import load_settings
from s4_lab import overlay, command_packet
from s4_settings import validate


class EvidenceTools(unittest.TestCase):
    def setUp(self):
        self.s,self.c=load_settings()
        self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def test_default_disabled_before_creating_files(self):
        with self.assertRaisesRegex(ValueError,'execution_disabled'):
            s4_probe.execute(self.s,'run1','baseline',self.directory/'runs',self.directory/'private',{})
        with self.assertRaisesRegex(ValueError,'execution_disabled'):
            s4_collect.execute(self.s,self.c,'run1','baseline',self.directory/'runs','1'*64)
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_wrong_container_roles_are_rejected(self):
        with patch('s4_probe.runtime_guard'),patch.dict(os.environ,{'HAEDAM_S4_ROLE':'attacker'}):
            with self.assertRaises(ValueError):s4_probe.guard(self.s)
        with patch('s4_collect.runtime_guard'),patch.dict(os.environ,{'HAEDAM_S4_ROLE':'normal'}):
            with self.assertRaises(ValueError):s4_collect.guard(self.s)

    def test_private_mount_only_normal_and_observer_no_extra_authority(self):
        o=overlay(self.s,ROOT,self.directory)
        private_mount=self.s['paths']['private_mount']
        self.assertTrue(any(v['target']==private_mount for v in o['services']['normal']['volumes']))
        for role in ('attacker','observer'):
            self.assertFalse(any(v['target']==private_mount for v in o['services'][role]['volumes']))
        observer=o['services']['observer']
        self.assertEqual(observer['network_mode'],'service:n8n')
        self.assertEqual(observer['profiles'],['s4-evidence']);self.assertNotIn('networks',observer)
        self.assertEqual(o['services']['portal']['environment']['RESPONSE_ALLOWED_CIDRS'],self.s['addresses']['n8n_response']+'/32')
        changed=copy.deepcopy(self.s);changed['paths']['private_mount']=self.s['paths']['evidence_mount']+'/nested'
        with self.assertRaises(ValueError):validate(changed)

    def test_read_plan_and_packet_do_not_execute(self):
        p=s4_collect.plan(self.s,self.c,'run1','locked','T-20261110-0001')
        self.assertEqual(p['http_method'],'GET');self.assertEqual(p['maximum_http_requests'],3)
        packet=command_packet(self.s,'run1',['docker','compose'])
        for phase in ('baseline','locked','restored'):
            self.assertNotIn('--execute',packet['commands']['probe_'+phase]['plan_argv'])
            self.assertIn('observer',packet['commands']['snapshot_'+phase]['plan_argv'])
        for tid in (None,'../escape','wrong'):
            with self.assertRaises(ValueError):s4_collect.plan(self.s,self.c,'run1','locked',tid)

    def test_new_bundle_drift_bindings_and_private_credentials(self):
        # Temporary root substitutes only the storage boundary; source inventory is explicit here.
        with patch.object(s4_rehearsal,'ROOT',self.directory),patch.object(s4_rehearsal,'source_hashes',return_value={'source':'hash'}):
            output=self.directory/'.local/run1'
            s4_rehearsal.prepare(self.s,'run1',output)
            s,c,p=s4_rehearsal.load_bundle(output)
            self.assertFalse(s['execution_enabled']);self.assertFalse(p['runtime_verified'])
            passwords=json.loads((output/'passwords.json').read_text())
            self.assertNotEqual(passwords['target'],passwords['normal'])
            self.assertEqual(list((output/'private').iterdir()),[])
            with self.assertRaises(FileExistsError):s4_rehearsal.prepare(self.s,'run1',output)
            bindings={k:str(i)*24 for i,k in enumerate(('input_id','index_set_id','stream_id','notification_id'),1)}
            s4_rehearsal.imports(output,bindings)
            self.assertFalse(json.loads((output/'import/manifest.json').read_text())['import_executed'])
            with self.assertRaises(FileExistsError):s4_rehearsal.imports(output,bindings)
            with patch.object(s4_rehearsal,'source_hashes',return_value={'source':'changed'}):
                with self.assertRaises(ValueError):s4_rehearsal.load_bundle(output)
            overlay_path=output/'compose.s4.json'; original=overlay_path.read_text()
            changed=json.loads(original);changed['services']['observer']['network_mode']='host'
            overlay_path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):s4_rehearsal.load_bundle(output)
            overlay_path.write_text(original)
            command_path=output/'input-packet.json';original=command_path.read_text()
            command_path.write_text('{}')
            with self.assertRaises(ValueError):s4_rehearsal.load_bundle(output)
            command_path.write_text(original)
            s['accounts']['target']='zz_s4_another'
            (output/'settings.json').write_text(json.dumps(s))
            with self.assertRaises(ValueError):s4_rehearsal.load_bundle(output)

    def test_reader_uses_only_bounded_get_and_no_redirect_or_error_body(self):
        calls=[]
        class Response:
            status=200
            def read(self,limit):
                self.limit=limit
                return b'{"success": true}'
        response=Response()
        class Connection:
            def __init__(self,*args,**kwargs):calls.append(('connect',args,kwargs))
            def request(self,*args,**kwargs):calls.append(('request',args,kwargs))
            def getresponse(self):return response
            def close(self):calls.append(('close',))
        reader=s4_collect.Reader(self.s,self.c,'1'*64)
        with patch('s4_collect.http.client.HTTPConnection',Connection):
            reader.get('account')
            self.assertEqual(calls[0][2]['source_address'],(self.s['addresses']['n8n_response'],0))
            self.assertEqual(calls[1][1][0],'GET')
            self.assertEqual(response.limit,1048577)
            calls.clear();reader.get('ticket','T-20261110-0001')
            self.assertNotIn('X-Response-Key',calls[1][2]['headers'])
            for status in (302,403,404,429,500):
                response.status=status
                with self.assertRaises(ValueError):reader.get('account')
            response.status=200
            with patch.object(response,'read',return_value=b'x'*1048577):
                with self.assertRaises(ValueError):reader.get('account')

    def test_collector_failure_stop_and_overwrite_do_not_disclose_secret(self):
        secret='1'*64
        class Broken:
            def __init__(self,*_):pass
            def get(self,*_):raise RuntimeError(secret)
        out=s4_collect.execute(self.s,self.c,'run1','baseline',self.directory,secret,runtime=lambda _:None,reader_factory=Broken)
        self.assertEqual(out['status'],'failed');self.assertNotIn(secret,json.dumps(out))
        with self.assertRaises(FileExistsError):
            s4_collect.execute(self.s,self.c,'run1','baseline',self.directory,secret,runtime=lambda _:None,reader_factory=Broken)
        (self.directory/self.s['stop_filename']).touch()
        out=s4_collect.execute(self.s,self.c,'run1','baseline',self.directory,secret,attempt=2,runtime=lambda _:None,reader_factory=Broken)
        self.assertEqual(out['status'],'stopped');self.assertEqual(out['records'],[])

    def test_evidence_paths_cannot_escape_or_read_private_sessions(self):
        from s4_evidence import read_local
        for path in ('../outside.json','private/session.json'):
            with self.assertRaises(ValueError):read_local(self.directory,path)

    def test_source_inventory_includes_graylog_builder_inputs(self):
        hashes=s4_rehearsal.source_hashes()
        self.assertIn('lab/s1s4/graylog/s4-fail-then-success.json',hashes)
        self.assertIn('infra/graylog/notifications/s1-n8n-haedam-s1.json',hashes)


if __name__=='__main__':unittest.main()
