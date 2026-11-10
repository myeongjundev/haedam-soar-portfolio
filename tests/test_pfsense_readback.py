"""Replay the 11/03 partial snapshots with isolated journals and fake PF commands."""
from copy import deepcopy
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import pytest

path = Path(__file__).resolve().parents[1] / 'lab/pfsense/pfsense_response.py'
spec = importlib.util.spec_from_file_location('pf_readback_test', path)
m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m)


class DelayedBackend:
    def __init__(self):
        self.state = m.Snapshot(True, False, False, False)
        self.queue = []
        self.calls = []
        self.stuck = False
        self.cleanup_failure = False
        self.drift = False

    def snapshot(self, target, deadline=None):
        if self.queue:
            self.state = self.queue.pop(0)
        return self.state

    def change(self, action, target):
        self.calls.append(action)
        if action == 'block':
            self.state = replace(self.state, configured=True, config_rule_present=True,
                                 rule_trackers=('1793691757',))
            final = replace(self.state, table_present=True, rule_present=True, runtime_rule_present=True)
            if self.drift:
                final = replace(final, other_table=('198.51.100.9/32',))
        else:
            self.state = replace(self.state, configured=False)
            final = replace(self.state, table_present=False)
        if not self.stuck:
            self.queue = [self.state, self.state, final]

    def kill_states(self, target):
        self.calls.append('kill')

    def remove_owned_empty_rule(self, target, tracker):
        assert tracker == '1793691757'
        self.calls.append('cleanup')
        if self.cleanup_failure:
            raise m.BackendError('owned_rule_cleanup_failed')
        self.state = replace(self.state, config_rule_present=False, rule_trackers=())
        self.queue = [self.state, replace(self.state, runtime_rule_present=False, rule_present=False)]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'READBACK_SECONDS', .02)
    monkeypatch.setattr(m, 'READBACK_INTERVAL', .001)
    return DelayedBackend(), m.Journal(tmp_path/'journal')


def run(pair, action, rid):
    return m.operate(m.parse_request([action,'203.0.113.22',rid,'ACCEPT02']),*pair)


def test_delayed_block_unblock_and_rule_reload_converge_without_mutation_retries(setup):
    b,j=setup
    assert run(setup,'block','block1')['result']=='applied'
    assert j.load()['claim']['owned_rule_tracker']=='1793691757'
    released=run(setup,'unblock','release1')
    assert released['ok'] and released['result']=='released'
    assert not released['state']['config_rule_present'] and not released['state']['runtime_rule_present']
    assert b.calls==['block','kill','unblock','cleanup']
    assert j.load()['claim'] is None and j.load()['pending'] is None
    assert run(setup,'unblock','release1')['replayed']
    assert b.calls==['block','kill','unblock','cleanup']


def test_timeout_preserves_failed_receipt_pending_and_does_not_reissue_block(setup):
    b,j=setup;b.stuck=True
    failed=run(setup,'block','block1')
    assert not failed['ok'] and failed['changed'] is None
    assert failed['failure_detail']=='readback_timeout' and failed['state']['configured']
    original=deepcopy(j.load()['receipts'])
    assert run(setup,'block','block1')['reason']=='replay_needs_reconciliation'
    assert run(setup,'block','block2')['reason']=='pending_needs_reconciliation'
    assert b.calls==['block'] and j.load()['pending'] and j.load()['receipts']==original
    status=run(setup,'status','s')
    assert status['journal_state']['pending_action']=='block'
    assert status['journal_state']['claim_owner_id']=='ACCEPT02'


def test_failed_unblock_keeps_receipt_and_claim_even_when_target_later_disappears(setup):
    b,j=setup;assert run(setup,'block','b')['ok'];b.stuck=True
    out=run(setup,'unblock','u')
    assert not out['ok'] and j.load()['pending']['request']['action']=='unblock'
    saved=deepcopy(j.load()['receipts']['u'])
    b.state=replace(b.state,table_present=False)
    assert run(setup,'unblock','u')['reason']=='replay_needs_reconciliation'
    assert saved==j.load()['receipts']['u'] and b.calls==['block','kill','unblock']


def test_cleanup_failure_never_reports_released_or_clears_journal(setup):
    b,j=setup;run(setup,'block','b');b.cleanup_failure=True
    out=run(setup,'unblock','u')
    assert out['failure_detail']=='owned_rule_cleanup_failed'
    assert j.load()['claim'] and j.load()['pending']
    assert out['state']['config_rule_present']


def test_changed_tracker_cannot_be_deleted(setup):
    b,j=setup;run(setup,'block','b');b.state=replace(b.state,rule_trackers=('999',))
    out=run(setup,'unblock','u')
    assert out['failure_detail']=='owned_rule_cleanup_scope_changed'
    assert 'cleanup' not in b.calls and j.load()['pending']


def test_unrelated_entry_change_stops_waiting_without_cleanup(setup):
    b,j=setup;b.drift=True
    out=run(setup,'block','b')
    assert out['failure_detail']=='readback_scope_changed'
    assert b.calls==['block'] and j.load()['pending']


def test_legacy_claim_without_rule_provenance_requires_manual_review(setup):
    b,j=setup;run(setup,'block','b')
    data=j.load();data['claim']={'owner_id':'ACCEPT02','target':'203.0.113.22'};j.save(data)
    out=run(setup,'unblock','u')
    assert out['failure_detail']=='residual_rule_ownership_unknown'
    assert 'cleanup' not in b.calls and j.load()['pending']


def test_another_owner_or_target_cannot_clear_pending(setup):
    b,j=setup;b.stuck=True;run(setup,'block','b');before=deepcopy(j.load())
    for target,owner in [('203.0.113.22','OTHER'),('203.0.113.41','ACCEPT02')]:
        out=m.operate(m.parse_request(['unblock',target,'u',owner]),b,j)
        assert not out['ok']
    assert before==j.load() and b.calls==['block']


def test_preexisting_shared_rule_is_preserved_on_release(setup):
    b,j=setup
    b.state=replace(b.state, config_rule_present=True,runtime_rule_present=True,
                    rule_present=True,rule_trackers=('100',))
    assert run(setup,'block','b')['ok']
    assert j.load()['claim']['owned_rule_tracker'] is None
    out=run(setup,'unblock','u')
    assert out['ok'] and out['state']['config_rule_present'] and out['state']['runtime_rule_present']
    assert 'cleanup' not in b.calls and j.load()['claim'] is None


def test_delayed_compensation_preserves_original_failed_block_receipt(setup):
    b,j=setup;b.stuck=True
    assert not run(setup,'block','b')['ok']
    failure=deepcopy(j.load()['receipts']['b'])
    b.state=replace(b.state,table_present=True,rule_present=True,runtime_rule_present=True)
    b.stuck=False
    assert run(setup,'unblock','u')['ok']
    assert j.load()['receipts']['b']==failure
    assert b.calls==['block','unblock','cleanup']


def test_fresh_block_id_cannot_reassign_owned_tracker_to_replacement_rule(setup):
    b,j=setup;assert run(setup,'block','b')['ok']
    b.state=replace(b.state,rule_trackers=('999',))
    out=run(setup,'block','b2')
    assert out['failure_detail']=='owned_rule_identity_changed'
    assert j.load()['claim']['owned_rule_tracker']=='1793691757'
    assert b.calls==['block','kill']
