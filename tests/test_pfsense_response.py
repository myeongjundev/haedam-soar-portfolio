"""Isolated target/ownership/failure tests; never execute SSH, pfctl or EasyRule."""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker

MODULE_PATH = Path(__file__).resolve().parents[1] / 'lab/pfsense/pfsense_response.py'
spec = importlib.util.spec_from_file_location('pfsense_response_under_test', MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class Backend:
    def __init__(self):
        self.state = mod.Snapshot(True, False, False, False, other_config=('198.51.100.7/32',),
                                  other_table=('198.51.100.7/32',), config_rule_present=True,
                                  runtime_rule_present=True, rule_trackers=('100',))
        self.calls = []
        self.behavior = 'normal'

    def snapshot(self, target, deadline=None):
        assert target == '203.0.113.22'
        return self.state

    def change(self, action, target):
        assert target == '203.0.113.22'
        self.calls.append((action, target))
        if self.behavior == 'zero_exit_no_change':
            return
        present = action == 'block'
        self.state = replace(self.state, configured=present, table_present=present, rule_present=present)
        if self.behavior == 'mutate_then_timeout':
            raise mod.BackendError('timeout')
        if self.behavior == 'alter_unrelated':
            self.state = replace(self.state, other_config=())

    def kill_states(self, target):
        assert target == '203.0.113.22'
        self.calls.append(('kill_states', target))
        if self.behavior == 'state_kill_failed':
            raise mod.BackendError('failed')


def req(action='block', request_id='review-apply-01', owner='B-S10-review-01'):
    return mod.parse_request([action, '203.0.113.22', request_id, owner])


def run(backend, journal, action='block', request_id='review-apply-01', owner='B-S10-review-01'):
    return mod.operate(req(action, request_id, owner), backend, journal)


@pytest.fixture
def setup(tmp_path):
    return Backend(), mod.Journal(tmp_path / 'journal')


@pytest.fixture(autouse=True)
def fast_poll_budget(monkeypatch):
    monkeypatch.setattr(mod, 'READBACK_SECONDS', 0.02)
    monkeypatch.setattr(mod, 'READBACK_INTERVAL', 0.001)


@pytest.mark.parametrize('target', ['203.0.113.10', '203.0.113.21', '203.0.113.100',
                                    '203.0.113.109', '10.250.0.1', '10.250.0.2', '10.250.0.3',
                                    '10.250.0.100', '203.0.113.0/24', '::1', '203.0.113.22;id'])
def test_only_approved_trial_hosts_are_accepted(target):
    with pytest.raises(mod.Refused):
        mod.parse_request(['block', target, 'req-01', 'owner-01'])


def test_existing_s12_target_scope_is_preserved():
    assert mod.parse_request(['status', '203.0.113.41', 'r', 'o'])['target'] == '203.0.113.41'


@pytest.mark.parametrize('args', [['flush', '203.0.113.22', 'r', 'o'],
                                 ['block', '203.0.113.22', 'r;id', 'o'],
                                 ['block', '203.0.113.22', 'r', '../o'],
                                 ['block', '203.0.113.22', '', 'o']])
def test_unrecognized_commands_and_identifiers_fail(args):
    with pytest.raises(mod.Refused):
        mod.parse_request(args)


def test_forced_ssh_command_does_not_execute_shell_syntax():
    assert mod.command_arguments([], 'haedam-pf-response status 203.0.113.22 r o') == [
        'status', '203.0.113.22', 'r', 'o']
    for text in ['id', 'sh -c id', '/bin/sh', 'haedam-pf-response "', 'a' * 1025]:
        with pytest.raises(mod.Refused):
            mod.command_arguments([], text)
    with pytest.raises(mod.Refused):
        mod.parse_request(mod.command_arguments([], 'haedam-pf-response block 203.0.113.22 r o; id'))


def test_verified_block_preserves_other_entries_and_never_claims_effect(setup):
    backend, journal = setup
    out = run(backend, journal)
    assert out['ok'] and out['result'] == 'applied' and out['applied_verified'] is True
    assert out['effect_verified'] is None and out['changed'] is True
    assert backend.calls == [('block', '203.0.113.22'), ('kill_states', '203.0.113.22')]
    assert backend.state.other_config == ('198.51.100.7/32',)
    assert journal.load()['claim']['owner_id'] == 'B-S10-review-01'
    schema = json.loads((MODULE_PATH.parents[2] / 'contracts/pfsense-response.schema.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(out)


def test_repeated_request_is_durable_and_does_not_repeat_target_call(setup):
    backend, journal = setup
    first = run(backend, journal)
    count = len(backend.calls)
    again = run(backend, mod.Journal(journal.directory))
    assert again == {**first, 'replayed': True}
    assert len(backend.calls) == count
    conflict = run(backend, journal, 'unblock')
    assert conflict['reason'] == 'request_id_conflict' and len(backend.calls) == count


def test_another_owner_cannot_remove_or_adopt_an_owned_block(setup):
    backend, journal = setup
    run(backend, journal)
    count = len(backend.calls)
    for action in ['block', 'unblock']:
        out = run(backend, journal, action, 'another-' + action, 'another-owner')
        assert out['reason'] == 'another_owner' and not out['ok']
    assert len(backend.calls) == count


def test_unmanaged_block_is_never_adopted_or_removed(setup):
    backend, journal = setup
    backend.state = replace(backend.state, configured=True, table_present=True, rule_present=True)
    for action in ['block', 'unblock']:
        out = run(backend, journal, action)
        assert out['reason'] == 'unmanaged_existing_block' and not out['ok']
    assert backend.calls == []


def test_unblock_removes_only_own_host_and_new_cycle_can_be_applied(setup):
    backend, journal = setup
    run(backend, journal)
    out = run(backend, journal, 'unblock', 'release-01')
    assert out['ok'] and out['result'] == 'released' and out['applied_verified'] is False
    assert out['effect_verified'] is None and backend.state.absent
    assert journal.load()['claim'] is None
    assert backend.state.other_table == ('198.51.100.7/32',)
    stale = run(backend, journal)
    assert not stale['ok'] and stale['reason'] == 'replay_needs_reconciliation'
    fresh = run(backend, journal, request_id='apply-02', owner='new-owner')
    assert fresh['ok'] and fresh['result'] == 'applied'
    stale = run(backend, journal)
    assert not stale['ok'] and stale['reason'] == 'replay_needs_reconciliation'


@pytest.mark.parametrize('behavior', ['zero_exit_no_change', 'mutate_then_timeout', 'state_kill_failed', 'alter_unrelated'])
def test_uncertain_outcome_is_journaled_and_never_auto_retried(setup, behavior):
    backend, journal = setup
    backend.behavior = behavior
    out = run(backend, journal)
    assert not out['ok'] and out['result'] == 'failed' and out['changed'] is None
    saved = journal.load()
    assert saved['pending'] and saved['claim']
    count = len(backend.calls)
    assert run(backend, journal)['reason'] == 'replay_needs_reconciliation'
    assert run(backend, journal, request_id='another-attempt')['reason'] == 'pending_needs_reconciliation'
    assert run(backend, journal, 'status', 'status-pending')['reason'] == 'pending_needs_reconciliation'
    assert len(backend.calls) == count


def test_owner_can_compensate_partial_apply_but_cannot_reuse_failed_request(setup):
    backend, journal = setup
    backend.behavior = 'mutate_then_timeout'
    assert not run(backend, journal)['ok']
    backend.behavior = 'normal'
    result = run(backend, journal, 'unblock', 'compensate-01')
    assert result['ok'] and backend.state.absent
    old = run(backend, journal)
    assert not old['ok'] and old['reason'] == 'replay_needs_reconciliation'


@pytest.mark.parametrize('change', [{'ready': False}, {'covered_by_network': True}])
def test_preflight_mismatch_never_calls_target(setup, change):
    backend, journal = setup
    backend.state = replace(backend.state, **change)
    assert run(backend, journal)['reason'] == 'preflight_failed'
    assert backend.calls == []


def test_status_is_not_a_mutation_or_delivery_claim(setup):
    backend, journal = setup
    out = run(backend, journal, 'status')
    assert out['ok'] and out['result'] == 'status' and out['effect_verified'] is None
    assert backend.calls == [] and not (journal.directory / 'state.json').exists()


def test_stale_lock_and_corrupt_state_require_manual_review(setup):
    backend, journal = setup
    with journal.locked():
        with pytest.raises(mod.Refused, match='busy_or_stale'):
            run(backend, journal)
    (journal.directory / 'state.json').write_text('{broken', encoding='utf-8')
    with pytest.raises(json.JSONDecodeError):
        run(backend, journal)
    assert backend.calls == []


def actual_backend(tmp_path, *, address='203.0.113.22/32', table='203.0.113.22', rule=None):
    config = tmp_path / 'config.xml'
    config.write_text('<pfsense><interfaces><wan><if>em0</if><ipaddr>203.0.113.1</ipaddr></wan>'
                      '</interfaces><aliases><alias><name>EasyRuleBlockHostsWAN</name><type>network</type>'
                      f'<address>{address}</address></alias></aliases></pfsense>', encoding='utf-8')
    version = tmp_path / 'version'
    version.write_text('2.7.2-RELEASE', encoding='utf-8')
    backend = mod.PfSenseBackend(config, version)
    block = rule or 'block drop in quick on em0 inet from <EasyRuleBlockHostsWAN> to any'
    commands = {
        ('/sbin/pfctl', '-s', 'Tables'): 'EasyRuleBlockHostsWAN\n',
        ('/sbin/pfctl', '-t', mod.TABLE, '-T', 'show'): table,
        ('/sbin/pfctl', '-sr'): block + '\npass in quick on em0 inet proto tcp from any to 10.250.0.2 port = 5000',
    }
    backend.run = lambda args, timeout=20: CompletedProcess(args, 0, commands[tuple(args)], '')
    return backend, commands


@pytest.mark.parametrize('rule', [None, 'block drop in log quick on em0 inet from <EasyRuleBlockHostsWAN> to any'])
def test_backend_parses_config_table_and_real_pf_rule_shape(tmp_path, rule):
    backend, _ = actual_backend(tmp_path, rule=rule)
    assert backend.snapshot('203.0.113.22').applied


def test_backend_does_not_confuse_network_or_rule_priority_with_exact_owned_host(tmp_path):
    backend, commands = actual_backend(tmp_path, address='203.0.113.0/24', table='203.0.113.0/24')
    status = backend.snapshot('203.0.113.22')
    assert status.covered_by_network and not status.applied and not status.absent
    commands[('/sbin/pfctl', '-sr')] = ('pass in quick on em0 inet from any to any\n'
                                      'block drop in quick on em0 inet from <EasyRuleBlockHostsWAN> to any')
    assert not backend.snapshot('203.0.113.22').rule_present


def test_backend_checks_state_removal_and_never_uses_global_flush(tmp_path):
    backend, commands = actual_backend(tmp_path)
    commands[('/sbin/pfctl', '-k', '203.0.113.22')] = '1 states killed\n'
    commands[('/sbin/pfctl', '-ss')] = 'all tcp 203.0.113.21:1234 -> 10.250.0.2:5000 ESTABLISHED:ESTABLISHED'
    backend.kill_states('203.0.113.22')
    commands[('/sbin/pfctl', '-ss')] += '\nall tcp 203.0.113.22:1234 -> 10.250.0.2:5000 ESTABLISHED:ESTABLISHED'
    with pytest.raises(mod.BackendError, match='target_states_remain'):
        backend.kill_states('203.0.113.22')


def test_sample_is_a_contract_example_not_a_live_response():
    root = MODULE_PATH.parents[2]
    schema = json.loads((root / 'contracts/pfsense-response.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    sample = json.loads((root / 'contracts/pfsense-examples/blocked.sample.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(sample)
    assert sample['request_id'].startswith('sample-') and sample['effect_verified'] is None


def test_status_separates_target_alias_from_persistent_config_and_runtime_rule(tmp_path):
    backend, _ = actual_backend(tmp_path, address='', table='')
    text = backend.config_path.read_text()
    text = text.replace('</pfsense>', '<filter><rule><tracker>1793691757</tracker><interface>wan</interface>'
                        '<descr>Blocked via EasyRule</descr><source><address>EasyRuleBlockHostsWAN</address>'
                        '</source></rule></filter></pfsense>')
    backend.config_path.write_text(text)
    state = backend.snapshot('203.0.113.22')
    assert state.absent and not state.configured and not state.table_present
    assert state.config_rule_present and state.runtime_rule_present and state.rule_present
    assert state.rule_trackers == ('1793691757',)


def test_cleanup_refuses_foreign_or_nonempty_rule_before_php(tmp_path):
    backend, _ = actual_backend(tmp_path, address='', table='')
    with pytest.raises(mod.BackendError, match='owned_rule_changed'):
        backend.remove_owned_empty_rule('203.0.113.22', '1793691757')
    with pytest.raises(mod.BackendError, match='invalid_owned_rule_tracker'):
        backend.remove_owned_empty_rule('203.0.113.22', '1;exit')


def test_snapshot_deadline_prevents_unbounded_pfctl_reads(tmp_path):
    backend, _ = actual_backend(tmp_path)
    backend.run = lambda *args, **kwargs: pytest.fail('expired snapshot must not start a command')
    with pytest.raises(mod.BackendError, match='readback_timeout'):
        backend.snapshot('203.0.113.22', deadline=0)
