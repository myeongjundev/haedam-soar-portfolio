#!/usr/local/bin/python3.11
"""Restricted EasyRule adapter for isolated S10/S12 sources, not an HTTP server.

CLI: haedam-pf-response ACTION TARGET REQUEST_ID OWNER_ID
Can be an SSH forced command: SSH_ORIGINAL_COMMAND is parsed, never executed.
Default owner journal is persistent/root-only; no automatic retry or lock expiry.
"""
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

TARGETS = frozenset({'203.0.113.22', '203.0.113.41'})
TABLE = 'EasyRuleBlockHostsWAN'
STATE_DIR = Path('/cf/conf/haedam-pf-response')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z')
READBACK_SECONDS = 8.0
READBACK_INTERVAL = 0.25


class Refused(Exception):
    pass


class BackendError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def parse_request(args):
    if len(args) != 4:
        raise Refused('four_arguments_required')
    action, target, request_id, owner_id = args
    if action not in ('status', 'block', 'unblock'):
        raise Refused('invalid_action')
    if target not in TARGETS or str(ipaddress.IPv4Address(target)) != target:
        raise Refused('target_not_approved')
    if not IDENTIFIER.fullmatch(request_id) or not IDENTIFIER.fullmatch(owner_id):
        raise Refused('invalid_identifier')
    return dict(action=action, target=target, request_id=request_id, owner_id=owner_id)


def command_arguments(argv, original=None):
    if original is None:
        return argv
    if len(original) > 1024:
        raise Refused('invalid_ssh_command')
    try:
        args = shlex.split(original)
    except ValueError:
        raise Refused('invalid_ssh_command') from None
    if not args or args[0] != 'haedam-pf-response':
        raise Refused('invalid_ssh_command')
    return args[1:]


@dataclass(frozen=True)
class Snapshot:
    ready: bool
    configured: bool
    table_present: bool
    rule_present: bool
    covered_by_network: bool = False
    other_config: tuple = ()
    other_table: tuple = ()
    config_rule_present: bool = False
    runtime_rule_present: bool = False
    rule_trackers: tuple = ()

    @property
    def applied(self):
        return self.configured and self.table_present and self.rule_present

    @property
    def absent(self):
        return not self.configured and not self.table_present and not self.covered_by_network

    def public(self):
        return {k: v for k, v in asdict(self).items()
                if not k.startswith('other_') and k != 'rule_trackers'}


class ReadbackError(BackendError):
    def __init__(self, reason, snapshot):
        super().__init__(reason)
        self.snapshot = snapshot


def wait_for_state(backend, target, predicate, before, *, clock=None, sleep=None):
    """Retry reads only. Never retry a mutation or ignore an unrelated change."""
    clock, sleep = clock or time.monotonic, sleep or time.sleep
    deadline = clock() + READBACK_SECONDS
    last = None
    while True:
        try:
            last = backend.snapshot(target, deadline=deadline)
        except BackendError as exc:
            raise ReadbackError(str(exc), last) from None
        if (not last.ready or last.covered_by_network or
                (last.other_config, last.other_table) != (before.other_config, before.other_table)):
            raise ReadbackError('readback_scope_changed', last)
        if predicate(last):
            return last
        remaining = deadline - clock()
        if remaining <= 0:
            raise ReadbackError('readback_timeout', last)
        sleep(min(READBACK_INTERVAL, remaining))


class PfSenseBackend:
    def __init__(self, config_path='/cf/conf/config.xml', version_path='/etc/version'):
        self.config_path = Path(config_path)
        self.version_path = Path(version_path)

    def run(self, args, timeout=20):
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BackendError('command_unavailable_or_timeout') from None

    def read(self, args, deadline=None):
        timeout = 20 if deadline is None else min(20, deadline - time.monotonic())
        if timeout <= 0:
            raise BackendError('readback_timeout')
        p = self.run(args, timeout=timeout)
        if p.returncode != 0:
            raise BackendError('read_failed')
        return p.stdout

    def snapshot(self, target, deadline=None):
        root = ET.parse(self.config_path).getroot()
        ready = (self.version_path.read_text().strip() == '2.7.2-RELEASE'
                 and root.findtext('./interfaces/wan/if') == 'em0'
                 and root.findtext('./interfaces/wan/ipaddr') == '203.0.113.1')
        aliases = [a for a in root.findall('./aliases/alias') if a.findtext('name') == TABLE]
        if len(aliases) > 1 or any(a.findtext('type') != 'network' for a in aliases):
            raise BackendError('unexpected_alias_definition')
        configured = (aliases[0].findtext('address') or '').split() if aliases else []
        tables = self.read(['/sbin/pfctl', '-s', 'Tables'], deadline).split()
        runtime = self.read(['/sbin/pfctl', '-t', TABLE, '-T', 'show'], deadline).split() if TABLE in tables else []
        try:
            config_nets = {str(ipaddress.ip_network(v, strict=False)) for v in configured}
            table_nets = {str(ipaddress.ip_network(v, strict=False)) for v in runtime}
        except ValueError:
            raise BackendError('unexpected_alias_address') from None
        exact = target + '/32'
        ip = ipaddress.ip_address(target)
        covered = any(ip in ipaddress.ip_network(v) for v in config_nets | table_nets
                      if ipaddress.ip_network(v).version == 4 and v != exact)
        rules = self.read(['/sbin/pfctl', '-sr'], deadline).splitlines()
        config_rules = [r for r in root.findall('./filter/rule')
                        if r.findtext('./source/address') == TABLE]
        trackers = tuple(r.findtext('tracker') or '' for r in config_rules)
        runtime_present = any(f'<{TABLE}>' in line for line in rules)
        candidates = [i for i, line in enumerate(rules) if line.startswith('block ')
                      and ' on em0 inet ' in line and 'in' in line.split(' on em0 inet ')[0].split()
                      and 'quick' in line.split(' on em0 inet ')[0].split()
                      and f'from <{TABLE}> to any' in line]
        passes = [i for i, line in enumerate(rules) if line.startswith('pass ') and ' on em0 ' in line]
        rule_present = len(candidates) == 1 and (not passes or candidates[0] < min(passes))
        return Snapshot(ready, exact in config_nets, exact in table_nets, rule_present, covered,
                        tuple(sorted(config_nets - {exact})), tuple(sorted(table_nets - {exact})),
                        bool(config_rules), runtime_present, trackers)

    def remove_owned_empty_rule(self, target, tracker):
        """Remove only a journal-attributed rule; retain pre-existing empty alias/table."""
        if not re.fullmatch(r'[0-9]{1,20}', tracker):
            raise BackendError('invalid_owned_rule_tracker')
        raw = self.config_path.read_bytes()
        root = ET.fromstring(raw)
        rules = [r for r in root.findall('./filter/rule') if r.findtext('tracker') == tracker]
        if (len(rules) != 1 or rules[0].findtext('./source/address') != TABLE
                or rules[0].findtext('interface') != 'wan'
                or rules[0].findtext('descr') != 'Blocked via EasyRule'):
            raise BackendError('owned_rule_changed')
        state = self.snapshot(target)
        if (not state.ready or not state.absent or state.other_config or state.other_table
                or state.rule_trackers != (tracker,)):
            raise BackendError('owned_rule_not_empty')
        # Static PHP; arguments are validated tokens, never interpolated shell commands.
        code = r'''
require_once('/etc/inc/config.inc'); require_once('/etc/inc/functions.inc');
require_once('/etc/inc/filter.inc'); require_once('/etc/inc/shaper.inc');
if (hash_file('sha256','/cf/conf/config.xml') !== $argv[2]) {exit(10);}
$rules=$config['filter']['rule']; $hits=array();
foreach ($rules as $i=>$r) {if (($r['tracker'] ?? '')===$argv[1]) {$hits[]=$i;}}
if (count($hits)!==1) {exit(11);} $i=$hits[0]; $r=$rules[$i];
if (($r['source']['address'] ?? '')!=='EasyRuleBlockHostsWAN' ||
    ($r['interface'] ?? '')!=='wan' || ($r['descr'] ?? '')!=='Blocked via EasyRule') {exit(12);}
foreach (($config['aliases']['alias'] ?? array()) as $a) {
    if (($a['name'] ?? '')==='EasyRuleBlockHostsWAN' && trim($a['address'] ?? '')!=='') {exit(13);}
}
unset($rules[$i]); $config['filter']['rule']=array_values($rules);
$saved=write_config('ALEPH remove owned empty EasyRule -NoReMoTeBaCkUp',true,true);
if (!is_array($saved)) {exit(14);}
exit(filter_configure_sync(false)===0 ? 0 : 15);
'''
        result = self.run(['/usr/local/bin/php', '-r', code, tracker,
                           hashlib.sha256(raw).hexdigest()], timeout=20)
        if result.returncode:
            raise BackendError('owned_rule_cleanup_failed')

    def change(self, action, target):
        # easyrule may exit zero with a failure message. Controller must read back.
        p = self.run(['/usr/local/bin/easyrule', action, 'wan', target], timeout=30)
        if p.returncode != 0:
            raise BackendError('easyrule_exit_failed')

    def kill_states(self, target):
        p = self.run(['/sbin/pfctl', '-k', target])
        if p.returncode != 0:
            raise BackendError('target_state_kill_failed')
        states = self.read(['/sbin/pfctl', '-ss'])
        if re.search(r'(?<![\d.])' + re.escape(target) + r'(?=[:\s)])', states):
            raise BackendError('target_states_remain')


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory)

    @contextmanager
    def locked(self):
        if self.directory.is_symlink():
            raise Refused('unsafe_journal_path')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        lock = self.directory / 'operation.lock'
        try:
            lock.mkdir(mode=0o700)
        except FileExistsError:
            raise Refused('busy_or_stale_lock_requires_review') from None
        try:
            yield
        finally:
            lock.rmdir()

    def load(self):
        path = self.directory / 'state.json'
        if path.is_symlink():
            raise Refused('unsafe_journal_path')
        if not path.exists():
            return {'version': 1, 'claim': None, 'pending': None, 'receipts': {}}
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('version') != 1 or not isinstance(data.get('receipts'), dict):
            raise Refused('invalid_journal_requires_review')
        return data

    def save(self, data):
        fd, name = tempfile.mkstemp(prefix='state.', dir=self.directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(data, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(name, 0o600)
            os.replace(name, self.directory / 'state.json')
            if os.name == 'posix':
                fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def response(req, started, *, ok, result, reason, state=None, changed=False, replayed=False):
    return {**req, 'schema_version': '1.0', 'via': 'pfsense', 'ok': ok, 'result': result,
            'reason': reason, 'changed': changed, 'replayed': replayed,
            'applied_verified': state.applied if state else None, 'effect_verified': None,
            'state': state.public() if state else None, 'requested_at': started, 'finished_at': now()}


def operate(req, backend, journal):
    started = now()
    fingerprint = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
    with journal.locked():
        data = journal.load()
        before = backend.snapshot(req['target'])
        if not before.ready or before.covered_by_network:
            return response(req, started, ok=False, result='rejected', reason='preflight_failed', state=before)
        if req['action'] == 'status':
            journal_state = {'claim_owner_id': (data.get('claim') or {}).get('owner_id'),
                             'claim_target': (data.get('claim') or {}).get('target'),
                             'pending_action': (data.get('pending') or {}).get('request', {}).get('action'),
                             'pending_request_id': (data.get('pending') or {}).get('request', {}).get('request_id')}
            if data.get('pending'):
                out = response(req, started, ok=False, result='failed', reason='pending_needs_reconciliation', state=before)
            else:
                out = response(req, started, ok=True, result='status', reason='read_only_snapshot', state=before)
            return {**out, 'journal_state': journal_state}
        seen = data['receipts'].get(req['request_id'])
        if seen:
            if seen['fingerprint'] != fingerprint:
                return response(req, started, ok=False, result='rejected', reason='request_id_conflict', state=before)
            expected = seen['response']['result'] in ('applied', 'already_applied')
            owned = (data.get('claim') and data['claim']['owner_id'] == req['owner_id']
                     and data['claim']['target'] == req['target'])
            released_matches = before.absent and all(
                before.public().get(k) == (seen['response'].get('state') or {}).get(k)
                for k in ('config_rule_present', 'runtime_rule_present'))
            if seen['response']['ok'] and (before.applied and owned if expected else released_matches):
                return {**seen['response'], 'replayed': True}
            return response(req, started, ok=False, result='rejected', reason='replay_needs_reconciliation',
                            replayed=True, state=before)
        claim = data.get('claim')
        # The v1 journal intentionally owns ONE target at a time. Adding an
        # allowlisted IP must not let the same owner overwrite another claim,
        # or clear that claim by unblocking an unrelated (already absent) IP.
        if claim and claim.get('target') != req['target']:
            return response(req, started, ok=False, result='rejected', reason='another_target_active', state=before)
        if data.get('pending') and data['pending']['request']['target'] != req['target']:
            return response(req, started, ok=False, result='rejected', reason='another_target_pending', state=before)
        if (data.get('pending') and data['pending']['request']['request_id'] == req['request_id']
                and data['pending']['fingerprint'] != fingerprint):
            return response(req, started, ok=False, result='rejected', reason='request_id_conflict', state=before)
        if claim and claim['owner_id'] != req['owner_id']:
            return response(req, started, ok=False, result='rejected', reason='another_owner', state=before)
        if data.get('pending') and req['action'] != 'unblock':
            return response(req, started, ok=False, result='rejected', reason='pending_needs_reconciliation', state=before)
        if not claim and not before.absent:
            return response(req, started, ok=False, result='rejected', reason='unmanaged_existing_block', state=before)
        if len(data['receipts']) >= 4096:
            return response(req, started, ok=False, result='rejected', reason='journal_full', state=before)
        if req['action'] == 'block' and not (before.absent or before.applied):
            return response(req, started, ok=False, result='rejected', reason='inconsistent_state', state=before)
        if (req['action'] == 'block' and not before.config_rule_present
                and (before.other_config or before.other_table or before.runtime_rule_present)):
            return response(req, started, ok=False, result='rejected', reason='unmanaged_rule_baseline', state=before)
        # Persist ownership and intent BEFORE a possible side effect. A crash cannot erase intent.
        if req['action'] == 'block':
            if not data.get('claim'):
                data['claim'] = {'owner_id': req['owner_id'], 'target': req['target'],
                                 'baseline_rules_absent': not before.config_rule_present and not before.runtime_rule_present,
                                 'owned_rule_tracker': None}
        claim = data.get('claim')
        # A delayed/failed block can still have created its rule. Attribute only
        # when a recorded empty baseline and an exclusive target support it.
        if (claim and claim.get('baseline_rules_absent') and not claim.get('owned_rule_tracker')
                and len(before.rule_trackers) == 1 and before.configured
                and not before.other_config and not before.other_table):
            claim['owned_rule_tracker'] = before.rule_trackers[0]
        data['pending'] = {'request': req, 'fingerprint': fingerprint}
        journal.save(data)
        after = None
        changed = False
        try:
            if req['action'] == 'block':
                if before.absent:
                    backend.change('block', req['target'])
                    changed = True
                after = wait_for_state(backend, req['target'], lambda s: s.applied, before)
                if claim.get('baseline_rules_absent'):
                    if len(after.rule_trackers) != 1:
                        raise BackendError('owned_rule_identity_unavailable')
                    if (claim.get('owned_rule_tracker') and
                            claim['owned_rule_tracker'] != after.rule_trackers[0]):
                        raise BackendError('owned_rule_identity_changed')
                    claim['owned_rule_tracker'] = after.rule_trackers[0]
                    journal.save(data)
                backend.kill_states(req['target'])
                after = backend.snapshot(req['target'])
                if not after.applied or not after.ready or after.covered_by_network:
                    raise BackendError('block_changed_during_verification')
                result = 'applied' if changed else 'already_applied'
            else:
                if not before.absent:
                    backend.change('unblock', req['target'])
                    changed = True
                after = wait_for_state(backend, req['target'], lambda s: s.absent, before)
                tracker = (claim or {}).get('owned_rule_tracker')
                if tracker and (after.config_rule_present or after.runtime_rule_present):
                    if after.other_config or after.other_table:
                        raise BackendError('owned_rule_cleanup_scope_changed')
                    if after.config_rule_present:
                        if after.rule_trackers != (tracker,):
                            raise BackendError('owned_rule_cleanup_scope_changed')
                        backend.remove_owned_empty_rule(req['target'], tracker)
                        changed = True
                    after = wait_for_state(backend, req['target'],
                                           lambda s: s.absent and not s.config_rule_present and not s.runtime_rule_present,
                                           before)
                elif (after.config_rule_present or after.runtime_rule_present) and (
                        not claim or claim.get('baseline_rules_absent') is not False):
                    raise BackendError('residual_rule_ownership_unknown')
                result = 'released'
            if (before.other_config, before.other_table) != (after.other_config, after.other_table):
                raise BackendError('unrelated_alias_entries_changed')
        except Exception as exc:
            # May have changed the firewall. Keep claim/pending; never retry or claim no-change.
            after = getattr(exc, 'snapshot', None) or after
            failed = response(req, started, ok=False, result='failed', reason='outcome_needs_reconciliation',
                              state=after, changed=None)
            if isinstance(exc, BackendError) and re.fullmatch(r'[a-z_]+', str(exc)):
                failed['failure_detail'] = str(exc)
            data['receipts'][req['request_id']] = {'fingerprint': fingerprint, 'response': failed}
            journal.save(data)
            return failed
        result_body = response(req, started, ok=True, result=result, reason='verified_managed_state',
                               state=after, changed=changed)
        if req['action'] == 'unblock':
            data['claim'] = None
        data['pending'] = None
        data['receipts'][req['request_id']] = {'fingerprint': fingerprint, 'response': result_body}
        journal.save(data)
        return result_body


def main():
    try:
        req = parse_request(command_arguments(sys.argv[1:], os.environ.get('SSH_ORIGINAL_COMMAND')))
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise Refused('root_required')
        result = operate(req, PfSenseBackend(), Journal(STATE_DIR))
    except (Refused, ValueError) as exc:
        # Only fixed validation messages; raw original command and credentials are never logged.
        reason = str(exc) if isinstance(exc, Refused) else 'invalid_input'
        result = {'ok': False, 'result': 'rejected', 'reason': reason}
    except Exception:
        result = {'ok': False, 'result': 'failed', 'reason': 'backend_or_journal_unavailable'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
