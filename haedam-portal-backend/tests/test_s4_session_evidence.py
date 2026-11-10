"""Real Flask + temporary SQLite + generated workflow graph; no Docker/VM/HTTP sockets."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'services/ticket-store'))
import build_s4_workflows as builder
import s4_probe
import s4_client
import s4_collect
import s4_evidence
import s4_rehearsal
from ticket_store.app import create_dashboard_app, create_n8n_app
from ticket_store import db as ticket_db
from test_workflow_store_contract import drive


@pytest.fixture
def lifecycle(app, tmp_path, monkeypatch):
    s, c = builder.load_settings()
    passwords = {'target': 'synthetic-target-password-123', 'normal': 'synthetic-normal-password-456'}
    keys = {role: str(i) * 64 for i, role in enumerate(c['credentials'], 1)}
    app.config.update(RESPONSE_API_KEY=keys['portal'], S4_ENABLED=True,
                      S4_ACCOUNT_ALLOWLIST=[s['accounts']['target']], S4_RELEASE_KEY=keys['release'],
                      RESPONSE_ALLOWED_CIDRS=['127.0.0.0/8', s['addresses']['n8n_response'] + '/32'], LOGIN_RATE_LIMIT=20)
    class Clock:
        value = datetime.now(timezone.utc) - timedelta(seconds=180)
        def now(self):
            self.value += timedelta(milliseconds=2)
            return self.value.isoformat(timespec='milliseconds')
        def wait(self, seconds, _): self.value += timedelta(seconds=seconds)
    clock = Clock()
    for module in (s4_probe, s4_client, s4_collect): monkeypatch.setattr(module, 'now', clock.now)
    monkeypatch.setattr(ticket_db, 'now_iso', clock.now)
    class Transport:
        calls = []
        def __init__(self, settings, plan):
            self.client, self.source, self.cookie = app.test_client(), plan['source_ip'], None
        def request(self, path, body=None, csrf=None):
            if self.cookie: self.client.set_cookie('haedam_session', self.cookie.split('=',1)[1])
            self.calls.append((path, self.source))
            response = self.client.open(path, method='GET' if body is None else 'POST', json=body,
                headers={'X-CSRF-Token': csrf} if csrf else {}, environ_overrides={'REMOTE_ADDR': self.source})
            cookie = self.client.get_cookie('haedam_session')
            self.cookie = 'haedam_session=' + cookie.value if cookie else None
            return response.status_code, response.get_json(), self.source
    ticket_path = str(tmp_path / 'ticket.sqlite3')
    portal_client = app.test_client(); ticket_client = create_dashboard_app(ticket_path).test_client()
    class Reader:
        def __init__(self, *_): pass
        def get(self, kind, tid):
            if kind == 'account':
                res = portal_client.get('/api/v1/response/s4/accounts/' + s['accounts']['target'],
                    headers={'X-Response-Key': keys['portal']}, environ_overrides={'REMOTE_ADDR': s['addresses']['n8n_response']})
            else: res = ticket_client.get('/api/v1/tickets/' + tid)
            assert res.status_code == 200
            return res.json
    output, private = tmp_path / 'runs', tmp_path / 'private'
    def probe(phase, attempt=1, supplied=None, factory=Transport):
        return s4_probe.execute(s,'offlinecycle',phase,output,private,supplied or passwords,attempt,
                                transport_factory=factory,runtime=lambda _:None)
    def snapshot(phase, tid=None, attempt=1, factory=Reader):
        return s4_collect.execute(s,c,'offlinecycle',phase,output,keys['portal'],tid,attempt,
                                  reader_factory=factory,runtime=lambda _:None)
    probes = {'baseline': probe('baseline')}; assert probes['baseline']['status'] == 'probe_passed', probes
    vault = private / 'offlinecycle-sessions.json'; original = vault.read_bytes()
    snapshots = {'baseline': snapshot('baseline')}; assert snapshots['baseline']['status'] == 'snapshot_passed', snapshots
    initial = s4_client.execute(s,'offlinecycle','trigger6',output,passwords['target'],
                                guard=lambda _:None,transport_factory=Transport,wait=clock.wait)
    assert initial['status'] == 'input_complete'
    clock.value = datetime.now(timezone.utc)
    event = {'id':'s4_offline_event','event_definition_id':'a'*24,
             'fields':{'username':s['accounts']['target'],'src_ip':s['addresses']['attacker']},
             'timestamp_processing':clock.now()}
    clients = {'portal-response': app.test_client(), 'ticket-store': create_n8n_app(ticket_path,keys['ticket']).test_client()}
    credentials = {v['id']: keys[r] for r,v in c['credentials'].items()}
    workflows = builder.build(s,{**c,'detection_enabled':True})
    body = {'case_id':'S4','asset_id':s['asset_id'],'src_ip':s['addresses']['attacker'],
            'username':s['accounts']['target'],'event_id':event['id'],'detected_at':event['timestamp_processing']}
    results,_ = drive({'workflows':workflows,'requests':[{'workflow':builder.IDS['respond'],'body':body}]},
                      clients,credentials,tmp_path)
    assert results[0]['verdict'] == 'responded', results
    clock.value = max(clock.value, datetime.now(timezone.utc))
    tid = results[0]['ticket_id']
    probes['locked'] = probe('locked'); assert probes['locked']['status'] == 'probe_passed', probes['locked']
    snapshots['locked'] = snapshot('locked',tid); assert snapshots['locked']['status'] == 'snapshot_passed', snapshots['locked']
    release = s4_evidence.release_body(s,snapshots['locked'])
    results,_ = drive({'workflows':workflows,'requests':[{'workflow':builder.IDS['release'],'body':release}]},
                      clients,credentials,tmp_path)
    assert results[0]['verdict'] == 'released'
    clock.value = max(clock.value, datetime.now(timezone.utc))
    probes['restored'] = probe('restored'); assert probes['restored']['status'] == 'probe_passed', probes['restored']
    snapshots['restored'] = snapshot('restored',tid); assert snapshots['restored']['status'] == 'snapshot_passed', snapshots['restored']
    assert vault.read_bytes() == original  # Revocation probes never replace original cookies.
    evidence = {'input':initial,'probes':probes,'snapshots':snapshots,'graylog_event':event,'release_response':results[0]}
    packet = {'run_id':'offlinecycle','project':s['project'],'settings_sha256':s4_probe.digest(s),
              'integration_sha256':s4_probe.digest(c),'source_sha256':s4_rehearsal.source_hashes(),
              'clock_tolerance_seconds':c['future_clock_tolerance_seconds']}
    return dict(s=s,c=c,packet=packet,evidence=evidence,probe=probe,snapshot=snapshot,passwords=passwords,
                Transport=Transport,Reader=Reader,private=private,output=output,original=original)


def test_real_session_lock_ticket_release_consistency_and_negative_evidence(lifecycle):
    x = lifecycle; result = s4_evidence.check(x['s'],x['packet'],x['evidence'],'a'*24)
    assert result['artifact_consistency'] == 'passed' and result['provenance_attested'] is False
    assert result['target_login_sequence'] == [200,401,200] and result['active_actions'] == 0
    public = json.dumps(x['evidence'])
    for value in x['passwords'].values(): assert value not in public
    vault = json.loads(x['original'])
    for value in vault['cookies'].values(): assert value not in public and value.split('=',1)[1] not in public
    mutations = [
        lambda e: e['probes']['restored']['checks'].update(target1_revoked=False),
        lambda e: e['probes']['locked']['checks'].update(normal_old_authenticated=False),
        lambda e: e['probes']['restored']['checks'].update(same_passwords=False),
        lambda e: e['probes']['restored'].update(session_set_id='b'*32),
        lambda e: e['probes']['baseline']['user_ids'].update(target=9999),
        lambda e: e['snapshots']['restored']['account'].update(locked=True),
        lambda e: e['snapshots']['locked']['account'].update(owner_ticket_id='T-20260101-9999'),
        lambda e: e['snapshots']['restored']['ticket']['actions'].pop(),
        lambda e: e['snapshots']['restored']['ticket'].update(status='responding'),
        lambda e: e['snapshots']['restored']['ticket'].update(event_ids=['unrelated']),
        lambda e: e['input']['records'][2].update(status=429),
        lambda e: e['input']['source_sha256'].update({'s4_client.py':'0'*64}),
        lambda e: e['graylog_event'].update(event_definition_id='b'*24),
        lambda e: e['release_response'].update(verdict='nothing_to_release'),
    ]
    for mutate in mutations:
        bad=copy.deepcopy(x['evidence']);mutate(bad)
        with pytest.raises((ValueError,KeyError)): s4_evidence.check(x['s'],x['packet'],bad,'a'*24)


def test_failures_do_not_relogin_old_sessions_or_overwrite_vault(lifecycle):
    x=lifecycle; before=len(x['Transport'].calls)
    changed={**x['passwords'],'target':'changed-password-123456'}
    failed=x['probe']('restored',2,changed)
    assert failed['status']=='failed' and len(x['Transport'].calls)==before
    with pytest.raises(FileExistsError):x['probe']('baseline',2)
    with pytest.raises(FileExistsError):x['probe']('restored')
    (x['output']/'STOP').touch()
    assert x['probe']('restored',3)['status']=='stopped'
    assert x['snapshot']('restored',x['evidence']['snapshots']['restored']['ticket_id'],2)['status']=='stopped'
    assert len(x['Transport'].calls)==before
    (x['output']/'STOP').unlink()
    class Swapped(x['Transport']):
        def request(self,path,body=None,csrf=None):
            status,payload,source=super().request(path,body,csrf)
            if body is None and path.endswith('/me'):payload['data']['user']={'id':999,'username':'wrong'}
            return status,payload,source
    assert x['probe']('restored',4,factory=Swapped)['status']=='failed'
    assert (x['private']/'offlinecycle-sessions.json').read_bytes()==x['original']
    class BadReader(x['Reader']):
        def get(self,kind,tid):
            value=super().get(kind,tid)
            if kind=='ticket':value['ticket']['username']='other'
            return value
    assert x['snapshot']('restored',x['evidence']['snapshots']['restored']['ticket_id'],3,factory=BadReader)['status']=='failed'
