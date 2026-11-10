import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/ticket-store'))
sys.path.insert(0,str(ROOT/'tools'))
from ticket_store import core, db, validate
from build_s7_workflows import build
import build_s7_workflows as builder


@pytest.mark.parametrize('action,target',[('restore','index.html'),('quarantine','assets/s7-probe.txt')])
def test_completion_releases_only_matching_action_and_dashboard(tmp_path,action,target):
    stamp='2026-11-09T06:00:00+00:00'
    record=dict(seat='C',case_id='S7',group_key='S7:haedam-portal:'+action,title='Synthetic S7 contract',
                asset_id='haedam-portal',event_ids=['synthetic-'+action],stage='detected',action=None)
    with db.connect(str(tmp_path/'tickets.db')) as conn:
        for stage in ('detected','applied','effect','released'):
            record['stage']=stage
            if stage!='detected':
                record['action']=dict(bot='117',via='wazuh-ar',action='complete_'+action if stage=='released' else action,
                    target=target,result='released' if stage=='released' else 'applied',applied_verified=True,effect_verified=True,
                    requested_at=stamp,finished_at=stamp,effect_verified_at=stamp,n8n_execution_id='sample-1')
            validate.record_body(record)
            _, result=core.record(conn,record,'s7-'+action+'-'+stage)
            if stage=='effect':
                assert result['status']=='verified'
                assert db.active_actions(conn,result['ticket_id'])
                assert len(db.dashboard_work(conn)['items'])==1
        assert result['status']=='restored'
        assert db.active_actions(conn,result['ticket_id'])==[]
        assert db.dashboard_work(conn)['items']==[]


def test_legacy_restore_release_alias_is_preserved():
    value=dict(bot='117',via='wazuh-ar',action='restore',target='sample.txt')
    assert db.action_key(value)[2]=='restore'
    assert db.action_key(value,released=True)[2]=='quarantine'


def test_webhook_examples_and_workflow_exports():
    schema=json.loads((ROOT/'contracts/s7-auto-webhook.schema.json').read_text())
    validator=Draft202012Validator(schema,format_checker=FormatChecker())
    for name in ('respond','complete'):
        example=json.loads((ROOT/f'contracts/ticket-examples/s7-auto-{name}.json').read_text())
        validator.validate(example)
        assert not validator.is_valid({**example,'path':'/etc/passwd'})
    for name, flow in build().items():
        assert json.loads((ROOT/'infra/n8n/portfolio-s7'/name).read_text(encoding='utf-8'))==flow
        webhook=flow['nodes'][0]
        assert webhook['parameters']['authentication']=='headerAuth'
        assert flow['settings']['saveDataSuccessExecution']=='none'


def test_workflow_uses_configured_identity_and_endpoints(monkeypatch):
    monkeypatch.setattr(builder, 'SETTINGS', {**builder.SETTINGS, 'asset_id':'alternate-portal'})
    monkeypatch.setattr(builder, 'URLS', {**builder.URLS, 'gateway':'http://alternate-response:8098',
                                        'ticket_api':'http://alternate-tickets:8080',
                                        'ticket_read':'http://alternate-tickets:8081'})
    flows = builder.build()
    serialized = json.dumps(flows)
    assert 'haedam-portal' not in serialized and '__ASSET__' not in serialized
    assert 'S7:alternate-portal:' in serialized
    urls = [n['parameters']['url'] for f in flows.values() for n in f['nodes'] if 'url' in n['parameters']]
    assert 'http://alternate-response:8098/claim' in urls
    assert 'http://alternate-tickets:8080/api/v1/tickets/record' in urls
    assert any('http://alternate-tickets:8081/api/v1/tickets/' in u for u in urls)
