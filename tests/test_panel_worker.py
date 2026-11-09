"""Exercise worker file preparation and fail-closed routing with explicit fake services."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture
def harness(tmp_path,monkeypatch):
    settings=json.loads((ROOT/'infra/s7-auto-settings.json').read_text())
    web=tmp_path/'web'; base=tmp_path/'baseline'; (base/'baseline').mkdir(parents=True);(web/'assets').mkdir(parents=True)
    data=b'<html>baseline</html>'
    (web/'index.html').write_bytes(data);(base/'baseline/index.html').write_bytes(data)
    (base/'baseline.sha256').write_text(hashlib.sha256(data).hexdigest()+'  index.html\n')
    env={'PORTAL_PORT':'15030','GRAYLOG_PORT':'19130','N8N_PORT':'15730','TICKET_PORT':'18130','S7_AGENT_ID':'001'}
    calls=[]; project='haedam-s7-paneltest'
    services=('portal','s7-agent','wazuh.manager','s7-response','graylog','n8n','ticket-store')
    ports={'portal':('5000','15030'),'graylog':('9000','19130'),'n8n':('5678','15730'),'ticket-store':('8089','18130')}
    containers=[]
    for service in services:
        binding={}
        if service in ports:
            internal,host=ports[service];binding={internal+'/tcp':[{'HostIp':'127.0.0.1','HostPort':host}]}
        containers.append({'Config':{'Labels':{'com.docker.compose.project':project,
            'com.docker.compose.project.working_dir':str(ROOT),'com.docker.compose.service':service}},
            'State':{'Running':True},'NetworkSettings':{'Ports':binding}})
    state=tmp_path/'state.json';state.write_text('{"definition":"synthetic-definition"}')
    def agent(code,*args):
        out=io.StringIO();monkeypatch.setattr(sys,'argv',['-c',*args])
        with contextlib.redirect_stdout(out): exec(code,{'web':web,'base':base,'settings':settings,'json':json,'home':'index.html'})
        return out.getvalue().strip()
    def mutate(key,marker):
        calls.append('mutate')
        changed=(base/'baseline'/key).read_bytes()+('\n<!-- '+marker+' -->\n').encode() if key=='index.html' else ('Harmless S7 personal test '+marker+'\n').encode()
        (web/key).write_bytes(changed)
        return hashlib.sha256(changed).hexdigest()
    lab=SimpleNamespace(SETTINGS=settings,ROOT=ROOT,STATE=state,
        base=SimpleNamespace(run=lambda *a,**k:json.dumps(containers)),env_values=lambda:env,
        compose=lambda *a,**k:json.dumps(settings),agent_id=lambda:'001',
        graylog=lambda *a:calls.append(('graylog',len(a))) or {},http=lambda *a,**k:(200,{}))
    verify=SimpleNamespace(lab=lab,now=lambda:'2026-11-09T08:00:00+00:00',agent=agent,mutate=mutate,tickets=lambda:[])
    monkeypatch.setitem(sys.modules,'s7_auto_verify',verify)
    spec=importlib.util.spec_from_file_location('panel_worker_test',ROOT/'tools/panel_s7_worker.py')
    worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
    cfg=dict(s7_project=project,s7_settings=str(ROOT/'infra/s7-auto-settings.json'),scope='test-scope',observe_timeout_seconds=0)
    run=dict(id='00000000-0000-0000-0000-000000000001',scope='test-scope',project=project,target='index.html',steps={})
    def invoke(acks=True,action='attack'):
        monkeypatch.setattr(sys,'stdin',io.StringIO(json.dumps({'config':cfg,'run':run,'action':action})+'\n'+('ack\n'*30 if acks else '')))
        out=io.StringIO()
        with contextlib.redirect_stdout(out): worker.main()
        return [json.loads(line) for line in out.getvalue().splitlines()]
    return SimpleNamespace(invoke=invoke,containers=containers,calls=calls,web=web,base=base,run=run,verify=verify)


def test_input_waits_for_durable_ack_before_any_mutation(harness):
    with pytest.raises(RuntimeError,match='interrupted'): harness.invoke(acks=False)
    assert 'mutate' not in harness.calls
    assert not any(c==('graylog',3) for c in harness.calls)
    assert (harness.web/'index.html').read_bytes()==(harness.base/'baseline/index.html').read_bytes()


@pytest.mark.parametrize('target',['index.html','assets/s7-probe.txt'])
def test_prepared_hash_matches_actual_harmless_input(harness,target):
    harness.run['target']=target
    messages=harness.invoke()
    prepared=next(m['data'] for m in messages if m['type']=='patch' and 'input_sha256' in m['data'])
    assert prepared['input_sha256']==hashlib.sha256((harness.web/target).read_bytes()).hexdigest()
    assert messages[-1]['type']=='done' and harness.calls.count('mutate')==1


def test_other_worktree_or_port_cannot_receive_input(harness):
    harness.containers[0]['Config']['Labels']['com.docker.compose.project.working_dir']=str(ROOT/'other')
    with pytest.raises(RuntimeError,match='scope_mismatch'): harness.invoke()
    assert 'mutate' not in harness.calls


def test_existing_ticket_and_dirty_file_prevent_input(harness):
    harness.verify.tickets=lambda:[{'status':'verified'}]
    with pytest.raises(RuntimeError,match='active_ticket'): harness.invoke()
    harness.verify.tickets=lambda:[]
    (harness.web/'index.html').write_bytes(b'preexisting change')
    with pytest.raises(RuntimeError,match='dirty_target'): harness.invoke()
    assert 'mutate' not in harness.calls


def observed_setup(h):
    for message in h.invoke():
        if message['type']=='patch': h.run.update(message['data'])
    event_key='b'*64; ticket_id='T-20000101-0001'; graylog_id='01'+'A'*24; wazuh_id='1794211200.100'
    group='S7:haedam-portal:'+event_key
    row={'key':event_key,'event':json.dumps({'file_key':h.run['target'],'expected_hash':h.run['input_sha256'],
        'alert_at':h.run['input_at'],'wazuh_event_id':wazuh_id}),
        'claim':json.dumps({'graylog_event_id':graylog_id,'group_key':group}),
        'ticket':ticket_id,'response':'{"result":"applied"}','completion':None}
    ticket={'ticket_id':ticket_id,'case_id':'S7','asset_id':'haedam-portal','group_key':group,
            'event_ids':[wazuh_id,graylog_id],'status':'verified'}
    h.verify.rows=lambda:[row];h.verify.ticket=lambda ident:ticket
    h.verify.gateway=lambda *args:h.calls.append('readback') or {'status':200,'body':{'data':{'effect':{'home_status':200,'target_status':200}}}}
    (h.web/'index.html').write_bytes((h.base/'baseline/index.html').read_bytes())
    return row,ticket


def test_observe_waits_for_existing_response_and_does_not_dispatch(harness):
    row,ticket=observed_setup(harness);row['response']=None
    with pytest.raises(RuntimeError,match='awaiting_detection'): harness.invoke(action='observe')
    assert 'readback' not in harness.calls


def test_observe_binds_ticket_and_completion_checks_real_clean_file(harness):
    row,ticket=observed_setup(harness)
    for msg in harness.invoke(action='observe'):
        if msg['type']=='patch': harness.run.update(msg['data'])
    assert harness.run['stage']=='verified' and harness.run['ticket_id']==ticket['ticket_id']
    def complete(key,ident):
        assert key==row['key'] and ident==ticket['ticket_id']
        ticket['status']='restored';return 200,{'verdict':'restored'}
    harness.verify.completion=complete
    (harness.web/'index.html').write_bytes(b'new drift')
    with pytest.raises(RuntimeError,match='dirty_target'): harness.invoke(action='restore')
    (harness.web/'index.html').write_bytes((harness.base/'baseline/index.html').read_bytes())
    result=harness.invoke(action='restore')
    assert any(m.get('data',{}).get('stage')=='restored' for m in result)


def test_wrong_ticket_scope_prevents_current_effect_readback(harness):
    row,ticket=observed_setup(harness);ticket['group_key']='another-event'
    with pytest.raises(RuntimeError,match='scope_mismatch'): harness.invoke(action='observe')
    assert 'readback' not in harness.calls
