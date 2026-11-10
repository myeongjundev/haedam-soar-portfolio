"""Drive generated S1/S4 graphs with real in-process Flask responses, no HTTP server."""
from contextlib import closing
from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import subprocess
import sys
import threading
from urllib.parse import urlsplit

import pytest
from werkzeug.security import generate_password_hash

from conftest import PASSWORD
from haedam_portal.models import db, User, S4AccountClaim

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,str(ROOT/'services/ticket-store'))
from ticket_store.app import create_n8n_app
from ticket_store import db as ticket_db


def drive(spec,clients,credentials,tmp_path,failures=None):
    path=tmp_path/'graph.json';path.write_text(json.dumps(spec),encoding='utf-8')
    process=subprocess.Popen(['node',str(ROOT/'tests/generated_workflow_rpc.cjs'),str(path)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
    timer=threading.Timer(30,process.kill);timer.start()
    calls=[];failures=dict(failures or {})
    try:
        for line in process.stdout:
            message=json.loads(line)
            if message['type']=='result':
                result=message['results'];break
            assert message['type']=='http'
            calls.append(message)
            url=urlsplit(message['url'])
            assert url.hostname in clients, 'Unexpected destination'
            assert message['credential'] in credentials, 'Missing credential binding'
            stage=(message['body'] or {}).get('stage')
            if failures.get(stage,0)>0:
                failures[stage]-=1
                response={'statusCode':503,'body':{}}
            else:
                res=clients[url.hostname].open(url.path+('?' + url.query if url.query else ''),method=message['method'],
                    headers={**message['headers'],'X-Response-Key':credentials[message['credential']]},
                    json=message['body'] if message['method']=='POST' else None)
                response={'statusCode':res.status_code,'body':res.get_json()}
            process.stdin.write(json.dumps(response,ensure_ascii=True)+'\n');process.stdin.flush()
        else:
            raise AssertionError('Graph exited without result: '+process.stderr.read())
        process.stdin.close()
        assert process.wait(timeout=5)==0,process.stderr.read()
        return result,calls
    finally:
        timer.cancel()
        if process.poll() is None:process.kill();process.wait()
        for pipe in (process.stdin,process.stdout,process.stderr):
            if not pipe.closed:pipe.close()


@pytest.mark.parametrize('case',['s1','s4'])
@pytest.mark.parametrize('fault',[None,'applied','released'])
def test_real_store_responses_drive_duplicate_release_and_new_cycle(app,tmp_path,monkeypatch,case,fault):
    builder=importlib.import_module('build_'+case+'_workflows')
    s,c=builder.load_settings();c['detection_enabled']=True
    keys={role:'offline-'+role+'-'+str(i)*40 for i,role in enumerate(c['credentials'],1)}
    credentials={v['id']:keys[k] for k,v in c['credentials'].items()}
    app.config.update(RESPONSE_API_KEY=keys['portal'],S4_ENABLED=case=='s4',
        S4_ACCOUNT_ALLOWLIST=[s.get('accounts',{}).get('target','')],S4_RELEASE_KEY=keys.get('release',''))
    username=s['accounts']['target'] if case=='s4' else s['username_prefix']+'rpc'
    if case=='s4':
        with app.app_context():
            db.session.add(User(username=username,display_name='synthetic',password_hash=generate_password_hash(PASSWORD)))
            db.session.commit()
    monkeypatch.setattr(ticket_db,'now_iso',lambda:'2026-11-10T12:00:00+09:00')
    ticket_path=str(tmp_path/'tickets.sqlite3')
    clients={'portal-response':app.test_client(),'ticket-store':create_n8n_app(ticket_path,keys['ticket']).test_client()}
    base={'case_id':case.upper(),'asset_id':s['asset_id'],'src_ip':s['addresses']['attacker'],'username':username}
    def detect(event):
        return {'workflow':builder.IDS['respond'],'body':{**base,'event_id':event,'detected_at':datetime.now(timezone.utc).isoformat()}}
    def release(ticket):
        return {'workflow':builder.IDS['release'],'body':{**base,'ticket_id':ticket}}
    requests=[detect('event1'),detect('event1'),detect('event2'),release('T-20261110-0001'),
              release('T-20261110-0001'),detect('event1'),detect('event2'),detect('event3'),
              release('T-20261110-0001'),release('T-20261110-0002')]
    expected=['responded','duplicate_no_action','duplicate_no_action','released',
        'nothing_to_release','old_event_no_action','old_event_no_action','responded','held_stale_release_ticket','released']
    if fault=='applied':
        requests=[detect('event1'),detect('event2'),release('T-20261110-0001')]
        held='held_unowned_portal_block' if case=='s1' else 'held_portal_claim_mismatch'
        expected=['held_applied_record_reconcile',held,held]
    elif fault=='released':
        requests=[detect('event1'),release('T-20261110-0001'),release('T-20261110-0001')]
        expected=['responded','held_release_record_reconcile','released']
    results,calls=drive({'workflows':builder.build(s,c),'requests':requests},clients,credentials,tmp_path,
                        failures={fault:2} if fault else None)
    assert [r['verdict'] for r in results]==expected
    assert all(r.get('effect_verified') is None for r in results)
    if fault:
        failed=results[0 if fault=='applied' else 1]
        assert failed['http_status']==503 and failed.get('no_action') is not True
    with closing(ticket_db.connect(ticket_path)) as connection:
        assert ticket_db.dashboard_work(connection)['items']==[]
        assert [r[0] for r in connection.execute('SELECT status FROM tickets ORDER BY ticket_id')]==(
            ['open'] if fault=='applied' else ['restored'] if fault else ['closed','restored'])
    if case=='s4':
        with app.app_context():
            target=db.session.scalar(db.select(User).where(User.username==username))
            assert target.locked is (fault=='applied')
            assert (db.session.get(S4AccountClaim,target.id) is not None) is (fault=='applied')
    else:
        response=app.test_client().get('/api/v1/response/ips',headers={'X-Response-Key':keys['portal']})
        assert bool(response.json['data']['items']) is (fault=='applied')


@pytest.mark.parametrize('profile,count',[('boundary8',8),('trigger9',9),('normal',0)])
def test_s1_bounded_input_with_real_csrf_and_portal_errors(app,tmp_path,profile,count):
    import s1_client
    import s1_settings
    settings=json.loads((ROOT/'infra/s1-settings.json').read_text(encoding='utf-8'))
    class FlaskTransport:
        def __init__(self,s,p):
            self.client=app.test_client();self.source=p['source_ip']
        def request(self,path,body=None,csrf=None):
            result=self.client.open(path,method='POST' if body else 'GET',json=body,
                headers={'X-CSRF-Token':csrf} if csrf else {},environ_overrides={'REMOTE_ADDR':self.source})
            return result.status_code,result.json,self.source
    result=s1_client.execute(settings,'offline',profile,tmp_path/'input',transport_factory=FlaskTransport,
                             guard=lambda _:None,wait=lambda *_:None)
    assert result['status']==('probe_complete' if profile=='normal' else 'input_complete')
    assert result['observed_401_count']==count
    assert len(result['records'])==1+count*2
    assert result['end_to_end_status']=='not_run'
