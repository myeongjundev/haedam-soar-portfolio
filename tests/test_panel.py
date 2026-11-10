"""Queue/security/recovery behavior. Fake workers here are NOT Docker evidence."""
import importlib
import http.client
import json
from pathlib import Path
import socket
import sys
import threading
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/lab-panel'))
from lab_panel.core import Engine, Rejected
from lab_panel.server import make_server, instance_lock
from lab_panel.config import load_config


@pytest.fixture
def config(tmp_path):
    return dict(state_dir=str(tmp_path),s7_project='haedam-s7-paneltest',scope='a'*64,
                targets={'index.html':'restore','assets/s7-probe.txt':'quarantine'},
                worker_timeout_seconds=10,observe_timeout_seconds=5,http_max_body_bytes=2048,
                http_drain_timeout_seconds=0.3,bind='127.0.0.1',port=0,origin='http://127.0.0.1:0')


def request(action,**fields):
    return dict(action=action,request_id=str(uuid.uuid4()),**fields)


def finish(engine):
    for t in engine.threads: t.join(timeout=3); assert not t.is_alive()


def test_single_job_and_idempotency(config):
    gate=threading.Event(); started=threading.Event(); count=[]
    def runner(*args): count.append(1); started.set(); gate.wait(3)
    e=Engine(config,runner); body=request('attack',target='index.html')
    first=e.submit(body); assert started.wait(1)
    try:
        assert e.submit(body)['job_id']==first['job_id']
        with pytest.raises(Rejected,match='request_conflict'): e.submit({**body,'target':'assets/s7-probe.txt'})
        with pytest.raises(Rejected,match='busy'): e.submit(request('refresh'))
    finally: gate.set(); finish(e)
    assert len(count)==1


def test_failed_preflight_allows_new_input_but_failed_armed_run_does_not(config):
    def unavailable(action,run,update): raise RuntimeError('lab_unavailable')
    e=Engine(config,unavailable); e.submit(request('attack',target='index.html')); finish(e)
    assert e.state()['runs'][0]['stage']=='not_started'
    def uncertain(action,run,update):
        update({'input_sha256':'b'*64,'stage':'armed'})
        raise RuntimeError('worker_timeout')
    e.runner=uncertain; e.submit(request('attack',target='index.html')); finish(e)
    assert e.state()['runs'][0]['stage']=='needs_check'
    with pytest.raises(Rejected,match='unfinished_run'): e.submit(request('attack',target='index.html'))


def test_restart_marks_interrupted_without_replaying(config):
    e=Engine(config,lambda *args:None)
    body=request('attack',target='index.html'); job=e.submit(body); finish(e)
    e.patch(job['run_id'],{'input_sha256':'b'*64,'stage':'armed'})
    with e.db() as db: db.execute("UPDATE jobs SET status='running' WHERE id=?",(job['job_id'],))
    recovered=Engine(config,lambda *args:pytest.fail('must never replay'))
    assert recovered.state()['runs'][0]['stage']=='needs_check'
    assert recovered.state()['jobs'][0]['status']=='interrupted'
    assert recovered.submit(body)['duplicate']


def test_scope_and_untrusted_fields_are_rejected(config):
    e=Engine(config,lambda *args:None)
    for target in ('../escape','/etc/passwd','missing.html'):
        with pytest.raises(Rejected): e.submit(request('attack',target=target))
    with pytest.raises(Rejected): e.submit(request('attack',target='index.html',command='whoami'))
    with pytest.raises(Rejected): e.submit(request('restore',run_id=str(uuid.uuid4())))
    job=e.submit(request('attack',target='index.html')); finish(e)
    e.config={**config,'scope':'c'*64}
    with pytest.raises(Rejected,match='scope_mismatch'): e.submit(request('observe',run_id=job['run_id']))


def test_restore_requires_observed_event_and_worker_error_redacted(config):
    e=Engine(config,lambda *args:(_ for _ in ()).throw(RuntimeError('password=never-display-this')))
    job=e.submit(request('attack',target='index.html')); finish(e)
    with pytest.raises(Rejected,match='observe_first'): e.submit(request('restore',run_id=job['run_id']))
    assert 'never-display' not in json.dumps(e.state())
    assert 'worker_failed' in json.dumps(e.evidence(job['run_id']))


@pytest.fixture
def http_server(config):
    with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    config.update(port=port,origin=f'http://127.0.0.1:{port}')
    engine=Engine(config,lambda *args:None); server=make_server(config,engine)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    yield config,engine
    server.shutdown(); server.server_close(); thread.join(); finish(engine)


def fetch(config,path,body=None,headers=None):
    headers=headers or {}
    if body is not None: headers={'Content-Type':'application/json',**headers}
    req=Request(config['origin']+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
    try: res=urlopen(req,timeout=3)
    except HTTPError as exc: res=exc
    with res: return res.status,res.headers,res.read()


def test_http_origin_cookie_csrf_and_no_commands(http_server):
    config,e=http_server
    status,headers,_=fetch(config,'/'); assert status==200
    cookie=headers['Set-Cookie'].split(';')[0]
    assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie']
    assert fetch(config,'/api/state')[0]==403
    status,_,raw=fetch(config,'/api/state',headers={'Cookie':cookie}); assert status==200
    csrf=json.loads(raw)['csrf']; valid={'Cookie':cookie,'Origin':config['origin'],'X-Panel-CSRF':csrf}
    assert fetch(config,'/api/jobs',request('refresh'),{'Cookie':cookie})[0]==403
    assert fetch(config,'/api/jobs',request('refresh'),{**valid,'Origin':'https://outside.invalid'})[0]==403
    assert fetch(config,'/api/jobs',request('refresh'),{**valid,'Host':'outside.invalid'})[0]==403
    assert fetch(config,'/api/jobs',request('refresh'),{**valid,'Sec-Fetch-Site':'cross-site'})[0]==403
    assert fetch(config,'/api/jobs',request('refresh',command='whoami'),valid)[0]==400
    assert fetch(config,'/api/jobs',request('refresh'),valid)[0]==202


@pytest.fixture
def closing_server(config):
    engine=Engine(config,lambda *args:pytest.fail('rejected request executed'))
    server=make_server(config,engine)
    closed=threading.Event(); original=server.RequestHandlerClass.finish
    def finish_request(handler):
        try: original(handler)
        finally: closed.set()
    server.RequestHandlerClass.finish=finish_request
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        yield server,engine,closed
    finally:
        server.shutdown();server.server_close();thread.join();finish(engine)


def test_rejected_post_preserves_response_until_delayed_body_is_drained(closing_server):
    server,engine,closed=closing_server
    with socket.create_connection(server.server_address,timeout=2) as client:
        client.sendall(b'POST /api/jobs HTTP/1.1\r\nHost: untrusted.invalid\r\nContent-Length: 2\r\n\r\n')
        response=http.client.HTTPResponse(client);response.begin()
        assert response.status==403 and response.getheader('Connection')=='close'
        assert json.loads(response.read())=={'error':'forbidden'}
        # Response arrives before the body; keep receiving briefly so a body
        # already in flight does not reset the connection before HTTP is read.
        assert not closed.wait(0.05)
        client.sendall(b'{}');client.shutdown(socket.SHUT_WR)
        assert closed.wait(1)
    assert engine.state()['jobs']==[]


@pytest.mark.parametrize('mode',['missing','trickled','oversized','peer_closed'])
def test_rejected_post_drain_is_bounded(closing_server,config,mode):
    server,engine,closed=closing_server
    if mode=='oversized':config['http_drain_timeout_seconds']=2
    with socket.create_connection(server.server_address,timeout=2) as client:
        client.sendall(b'POST /api/jobs HTTP/1.1\r\nHost: untrusted.invalid\r\nContent-Length: 1000000\r\n\r\n')
        response=http.client.HTTPResponse(client);response.begin()
        assert response.status==403
        assert json.loads(response.read())=={'error':'forbidden'}
        start=time.monotonic()
        if mode=='oversized':
            client.sendall(b'x'*config['http_max_body_bytes'])
            assert closed.wait(0.75)  # Byte cap, not the 2-second deadline, ends it.
        elif mode=='peer_closed':
            client.shutdown(socket.SHUT_WR)
            assert closed.wait(1)
        elif mode=='trickled':
            for _ in range(15):
                if closed.wait(0.05):break
                try:client.sendall(b'x')
                except OSError:break
            assert closed.wait(0.1)
            assert time.monotonic()-start<0.75  # Deadline must not reset per byte.
        else:
            assert not closed.wait(0.05)
            assert closed.wait(1)
    assert engine.state()['jobs']==[]


def test_authenticated_header_rejections_return_http_errors(http_server):
    config,engine=http_server
    _,headers,_=fetch(config,'/');cookie=headers['Set-Cookie'].split(';')[0]
    _,_,raw=fetch(config,'/api/state',headers={'Cookie':cookie})
    valid={'Cookie':cookie,'Origin':config['origin'],'X-Panel-CSRF':json.loads(raw)['csrf']}
    for path,extra,status in (
        ('/missing',{},404),
        ('/api/jobs',{'Content-Type':'text/plain'},415),
        ('/api/jobs',{'Content-Length':'invalid'},400),
        ('/api/jobs',{'Content-Length':str(config['http_max_body_bytes']+1)},413),
    ):
        actual,headers,_=fetch(config,path,request('refresh'),{**valid,**extra})
        assert actual==status and headers['Connection']=='close'
    assert engine.state()['jobs']==[]


def test_repeated_rejected_post_returns_http_error_without_reset(http_server):
    config,engine=http_server
    for _ in range(40):
        status,_,body=fetch(config,'/api/jobs',request('refresh'))
        assert status==403 and json.loads(body)=={'error':'forbidden'}
    assert engine.state()['jobs']==[]


def test_settings_reject_public_bind(tmp_path,monkeypatch):
    settings=json.loads((ROOT/'infra/panel-settings.json').read_text())
    settings['bind']='0.0.0.0'; path=tmp_path/'config.json';path.write_text(json.dumps(settings))
    monkeypatch.setenv('PANEL_CONFIG_FILE',str(path))
    with pytest.raises(ValueError,match='loopback'): load_config()


@pytest.mark.parametrize('key,value',[
    ('http_max_body_bytes',0),('http_max_body_bytes',65537),('http_max_body_bytes',True),
    ('http_drain_timeout_seconds',0),('http_drain_timeout_seconds',6),
    ('http_drain_timeout_seconds',float('nan')),('http_drain_timeout_seconds',True),
])
def test_settings_reject_unbounded_http_limits(tmp_path,monkeypatch,key,value):
    settings=json.loads((ROOT/'infra/panel-settings.json').read_text())
    settings[key]=value;path=tmp_path/'config.json';path.write_text(json.dumps(settings))
    monkeypatch.setenv('PANEL_CONFIG_FILE',str(path))
    with pytest.raises(ValueError,match='bounded HTTP'):load_config()


def test_same_project_cannot_run_two_servers():
    with instance_lock('haedam-s7-unit-'+uuid.uuid4().hex[:8]):
        pass
    name='haedam-s7-unit-'+uuid.uuid4().hex[:8]
    with instance_lock(name):
        with pytest.raises(OSError):
            with instance_lock(name): pass


def test_job_contract_examples():
    from jsonschema import Draft202012Validator
    schema=json.loads((ROOT/'contracts/panel-job.schema.json').read_text())
    validator=Draft202012Validator(schema)
    for example in json.loads((ROOT/'contracts/panel-job-examples.json').read_text()):
        validator.validate(example)
        assert not validator.is_valid({**example,'command':'whoami'})
