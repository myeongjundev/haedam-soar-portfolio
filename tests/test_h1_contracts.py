import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/ticket-store'))
sys.path.insert(0, str(ROOT / 'tools'))
from ticket_store import core, db, validate
from ticket_store.app import create_dashboard_app, create_n8n_app
from build_h1_workflows import build


def test_h1_ticket_contract_lifecycle_and_dashboard(tmp_path):
    schemas = [json.loads(p.read_text(encoding='utf-8')) for p in (ROOT / 'contracts').glob('*.schema.json')]
    registry = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in schemas if '$id' in s)
    schema = next(s for s in schemas if s.get('$id') == 'urn:nobugs:aleph:ticket-record:1.0')
    validator = Draft202012Validator(schema, registry=registry)
    stamp = '2026-11-09T03:00:00+00:00'
    record = {'seat': 'B', 'case_id': 'H1', 'group_key': 'H1:haedam-portal:h1_abuse', 'title': 'H1 민원 도배',
              'asset_id': 'haedam-portal', 'username': 'h1_abuse', 'event_ids': ['h1-test-event'], 'stage': 'detected', 'action': None}
    path = str(tmp_path / 'ticket.db')
    with db.connect(path) as connection:
        for stage in ('detected', 'applied', 'released'):
            record['stage'] = stage
            if stage != 'detected':
                record['action'] = {'bot': '112', 'via': 'portal', 'action': 'restrict_write', 'target': 'h1_abuse',
                    'result': 'applied' if stage == 'applied' else 'released', 'applied_verified': True,
                    'effect_verified': None, 'requested_at': stamp, 'finished_at': stamp,
                    'effect_verified_at': None, 'n8n_execution_id': 'test-1'}
            validator.validate(record)
            validate.record_body(record)
            status, result = core.record(connection, record, 'h1-test-' + stage)
            assert result['ok']
        assert result['status'] == 'restored'
        claims = core.active_for_resource(connection, {'asset_id': 'haedam-portal', 'via': 'portal', 'action': 'restrict_write', 'target': 'h1_abuse'})
        assert claims['tickets'] == []
    client = create_dashboard_app(path).test_client()
    html = client.get('/?case_id=H1').get_data(as_text=True)
    assert '<option value="H1" selected>' in html
    assert '민원 작성' in html


def test_h1_request_example_and_event_copies():
    schema = json.loads((ROOT / 'contracts/h1-petition-response.schema.json').read_text())
    example = json.loads((ROOT / 'contracts/ticket-examples/h1-petition-response.json').read_text())
    validator = Draft202012Validator(schema)
    validator.validate(example)
    for invalid in ({'ticket_id': 'stale'}, {'username': 'OTHER'}, {'extra': True}):
        assert not validator.is_valid({**example, **invalid})
    source = json.loads((ROOT / 'contracts/portal-event.schema.json').read_text())
    for folder in ('haedam-portal-backend', 'haedam-portal-frontend'):
        assert json.loads((ROOT / folder / 'contracts/portal-event.schema.json').read_text()) == source


def test_h1_response_example():
    schema = json.loads((ROOT / 'contracts/h1-petition-result.schema.json').read_text())
    example = json.loads((ROOT / 'contracts/ticket-examples/h1-petition-result.json').read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(example)
    assert not validator.is_valid({**example, 'data': {**example['data'], 'restricted': 'true'}})


def test_workflow_dependencies_credentials_and_errors_are_closed():
    for name, workflow in build().items():
        saved = json.loads((ROOT / 'infra/n8n/portfolio-h1' / name).read_text(encoding='utf-8'))
        assert saved == workflow
        names = {n['name'] for n in workflow['nodes']}
        for outputs in workflow['connections'].values():
            for lane in outputs['main']:
                for target in lane:
                    assert target['node'] in names
        for node in workflow['nodes']:
            if node['type'].endswith('.webhook'):
                assert node['parameters']['authentication'] == 'headerAuth'
                expected = 'h1OperatorAuth' if 'release' in name else 'h1DetectionAuth'
                assert node['credentials']['httpHeaderAuth']['id'] == expected
            if node['type'].endswith('.httpRequest'):
                assert node['parameters']['options']['timeout'] == 10000
                assert node.get('retryOnFail') is False
                # Every HTTP response immediately passes a checked code node.
                following = workflow['connections'][node['name']]['main'][0][0]['node']
                code = next(n for n in workflow['nodes'] if n['name'] == following)['parameters']['jsCode']
                assert 'if(!good' in code
        assert workflow['settings']['saveDataErrorExecution'] == 'none'
