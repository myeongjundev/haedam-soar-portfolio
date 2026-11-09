"""Fail-closed boundaries; live chain is separately measured in Docker."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/s7-response'))
from policy import normalize, validate_claim
from settings import load_settings


def source(**changes):
    value = {'id': '1794202030.9906', 'timestamp': '2026-11-09T06:00:00+00:00',
             'agent': {'id': '001', 'name': 'haedam-s7-agent'}, 'rule': {'id': '550'},
             'syscheck': {'path': '/var/www/haedam/index.html', 'event': 'modified', 'sha256_after': 'b' * 64}}
    value.update(changes)
    return value


def test_normalized_key_is_durable_and_binds_hash():
    first = normalize(source(), '001', {'index.html': 'a' * 64})
    assert first == normalize(source(), '001', {'index.html': 'a' * 64})
    assert first['action'] == 'restore'
    other = source(); other['syscheck']['sha256_after'] = 'c' * 64
    assert first['event_key'] != normalize(other, '001', {'index.html': 'a' * 64})['event_key']


@pytest.mark.parametrize('change', [
    {'agent': {'id': '002', 'name': 'haedam-s7-agent'}},
    {'agent': {'id': '001', 'name': 'another-agent'}},
    {'rule': {'id': '554'}},
    {'syscheck': {'path': '/var/lib/haedam/backend/secret.py', 'event': 'modified', 'sha256_after': 'b'*64}},
    {'syscheck': {'path': '/var/www/haedam/index.html', 'event': 'modified', 'sha256_after': 'a'*64}},
    {'syscheck': {'path': '/var/www/haedam/index.html', 'event': 'modified', 'sha256_after': 'bad'}},
    {'rule': {'id': '553'}, 'syscheck': {'path': '/var/www/haedam/assets/s7-probe.txt', 'event': 'deleted'}},
])
def test_wrong_scope_or_restoration_does_not_become_candidate(change):
    assert normalize(source(**change), '001', {'index.html': 'a' * 64}) is None


def test_claim_rejects_caller_controlled_path_and_naive_time():
    valid = dict(event_key='a'*64, graylog_event_id='01'+'A'*24, detected_at='2026-11-09T06:00:00Z', execution_id='4')
    validate_claim(valid)
    with pytest.raises(ValueError):
        validate_claim({**valid, 'file_key': '/etc/passwd'})
    with pytest.raises(ValueError):
        validate_claim({**valid, 'detected_at': '2026-11-09T06:00:00'})


def test_configured_agent_root_and_target_replace_default_scope(tmp_path, monkeypatch):
    settings = load_settings()
    settings['agent_name'] = 'alternate-agent'
    settings['paths']['agent_web'] = '/srv/alternate'
    settings['home_file'] = 'home.html'
    settings['targets'] = {'home.html': 'restore'}
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps(settings))
    monkeypatch.setenv('S7_CONFIG_FILE', str(path))
    assert normalize(source(), '001', {'index.html': 'a'*64}) is None
    event = source(agent={'id':'015','name':'alternate-agent'},
                   syscheck={'path':'/srv/alternate/home.html','event':'modified','sha256_after':'b'*64})
    result = normalize(event, '015', {'home.html':'a'*64})
    assert result['file_key'] == 'home.html' and result['action'] == 'restore'


@pytest.mark.parametrize('target', ['../escape', '/etc/passwd', '.', 'assets/../escape', 'assets//probe'])
def test_unsafe_configuration_rejected(tmp_path, monkeypatch, target):
    settings = load_settings()
    settings['targets'][target] = 'quarantine'
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps(settings))
    monkeypatch.setenv('S7_CONFIG_FILE', str(path))
    with pytest.raises(ValueError, match='Unsafe configured S7 target'):
        load_settings()


@pytest.fixture
def gateway(monkeypatch):
    for key, value in [('S7_AGENT_ID','001'),('S7_BRIDGE_KEY','a'*32),('S7_COMPLETE_KEY','b'*32)]:
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location('s7_gateway_test', ROOT / 'services/s7-response/app.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'wazuh', lambda *a, **k: pytest.fail('Must not dispatch an AR'))
    return module


def test_duplicate_success_does_not_hide_new_drift(gateway, monkeypatch):
    row = dict(claim=json.dumps({'file_key':'index.html'}), ticket='T-20261109-0001', response='{"ok":true}')
    monkeypatch.setattr(gateway, 'load', lambda _: row)
    def drift(_): raise gateway.Held('webroot_not_restored')
    monkeypatch.setattr(gateway, 'effect', drift)
    with pytest.raises(gateway.Held, match='webroot_not_restored'):
        gateway.respond(dict(event_key='a'*64, ticket_id='T-20261109-0001'))


def test_other_ticket_cannot_complete_response(gateway, monkeypatch):
    monkeypatch.setattr(gateway, 'load', lambda _: dict(claim='{}',ticket='T-20261109-0001'))
    with pytest.raises(gateway.Held, match='wrong_ticket_owner'):
        gateway.respond(dict(event_key='a'*64,ticket_id='T-20261109-0002',execution_id='3'), True)


def test_stale_unclaimed_event_cannot_be_claimed(gateway, monkeypatch):
    monkeypatch.setattr(gateway, 'load', lambda _: dict(claim=None,event=json.dumps({'file_key':'index.html','expected_hash':'a'*64})))
    monkeypatch.setattr(gateway, 'current', lambda _: 'b'*64)
    with pytest.raises(gateway.Held, match='stale_file_hash'):
        gateway.claim(dict(event_key='a'*64,graylog_event_id='01'+'A'*24,detected_at='2026-11-09T06:00:00Z',execution_id='3'))
