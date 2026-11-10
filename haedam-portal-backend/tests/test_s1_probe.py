"""Client probes use real Flask sessions and IP enforcement with temporary SQLite."""
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import s1_probe


def settings():return json.loads((ROOT/'infra/s1-settings.json').read_text(encoding='utf-8'))


def transport(app):
    class FlaskTransport:
        def __init__(self,s,p):self.client=app.test_client();self.source=p['source_ip']
        def request(self,path,body=None,csrf=None):
            r=self.client.open(path,method='GET' if body is None else 'POST',json=body,
                headers={'X-CSRF-Token':csrf} if csrf else {},environ_overrides={'REMOTE_ADDR':self.source})
            return r.status_code,r.json,self.source
    return FlaskTransport


def test_attacker_block_normal_authenticated_and_restore(app,tmp_path):
    s=settings();password='offline-normal-password-not-recorded'
    def probe(role,phase,attempt=1):
        r=s1_probe.execute(s,'unit',role,phase,tmp_path,password,attempt,guard=lambda _:None,transport_factory=transport(app))
        assert r['status']=='probe_passed',r
        assert password not in json.dumps(r) and 'csrf_token' not in json.dumps(r)
        return r
    for role in ('attacker','normal'):probe(role,'baseline')
    # Repeating baseline must prove account ownership via password, not assume a 409 is success.
    probe('normal','baseline',2)
    client=app.test_client()
    for action,phase in [('block','blocked'),('unblock','restored')]:
        r=client.post('/api/v1/response/ips/'+action,json={'ip':s['addresses']['attacker']},
            headers={'X-Response-Key':app.config['RESPONSE_API_KEY'],'Idempotency-Key':'s1-probe-'+action})
        assert r.status_code==200
        a=probe('attacker',phase);n=probe('normal',phase)
        assert a['records'][0]['status']==(403 if phase=='blocked' else 200)
        assert n['normal_authenticated'] is True
    with pytest.raises(FileExistsError):probe('attacker','baseline')


def test_wrong_normal_password_and_missing_block_fail(app,tmp_path):
    s=settings();kwargs={'guard':lambda _:None,'transport_factory':transport(app)}
    assert s1_probe.execute(s,'unit','normal','baseline',tmp_path,'offline-correct-password',**kwargs)['status']=='probe_passed'
    r=s1_probe.execute(s,'unit','normal','blocked',tmp_path,'offline-wrong-password',**kwargs)
    assert r['status']=='failed' and r['normal_authenticated'] is None
    assert s1_probe.execute(s,'unit','attacker','blocked',tmp_path,**kwargs)['status']=='failed'


def test_disabled_or_stop_has_no_request(app,tmp_path):
    s=settings()
    with pytest.raises(ValueError,match='execution_disabled'):
        s1_probe.execute(s,'unit','attacker','baseline',tmp_path/'absent')
    assert not (tmp_path/'absent').exists()
    (tmp_path/'STOP').touch()
    def forbidden(*args):raise AssertionError('network forbidden')
    class NoRequests:
        def __init__(self,*_):pass
        request=forbidden
    r=s1_probe.execute(s,'unit','attacker','baseline',tmp_path,guard=lambda _:None,transport_factory=NoRequests)
    assert r['status']=='stopped' and r['records']==[]
