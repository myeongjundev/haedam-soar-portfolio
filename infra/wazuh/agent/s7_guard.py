#!/usr/bin/python3 -I
"""Automatic S7 AR entry: fixed paths, hash precondition, immutable baseline, durable receipts.

Reuses the attributed team restore implementation without changing that file.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone

WEB = Path('/var/www/haedam')
BASE = Path('/opt/haedam-s7/state')
CONTROL = Path('/var/lib/haedam-s7/control')
QUARANTINE = Path('/var/lib/haedam-s7/quarantine')
ALLOWED = {'index.html': 'restore', 'assets/s7-probe.txt': 'quarantine'}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path, data):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    with os.fdopen(fd, 'w') as out:
        json.dump(data, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def safe_file(key):
    if key not in ALLOWED:
        raise ValueError('invalid_path')
    path = WEB / key
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise ValueError('symlink_rejected')
    return path


def manifest():
    pairs = [line.split('  ', 1) for line in (BASE / 'baseline.sha256').read_text().splitlines() if line]
    values = {key: value for value, key in pairs}
    if not values or len(values) != len(pairs) or any(not re.fullmatch('[0-9a-f]{64}', v) or
        Path(k).is_absolute() or '..' in Path(k).parts for k, v in values.items()):
        raise ValueError('invalid_baseline')
    return values


def verify_baseline():
    values = manifest()
    for key, expected in values.items():
        saved = BASE / 'baseline' / key
        if saved.is_symlink() or not saved.is_file() or digest(saved) != expected:
            raise ValueError('baseline_tampered')
    return values


def execute(args):
    if len(args) != 6:
        raise ValueError('invalid_arguments')
    job, ticket, key, expected, baseline_hash, operation = args
    if not re.fullmatch('[0-9a-f]{64}', job) or not re.fullmatch(r'T-\d{8}-\d{4}', ticket):
        raise ValueError('invalid_identity')
    if not re.fullmatch('[0-9a-f]{64}|absent', expected) or not re.fullmatch('[0-9a-f]{64}', baseline_hash):
        raise ValueError('invalid_hash')
    if operation not in ('respond', 'complete'):
        raise ValueError('invalid_operation')
    path = safe_file(key)
    CONTROL.mkdir(parents=True, exist_ok=True)
    receipt_path = CONTROL / (job + ('.completed' if operation == 'complete' else '') + '.json')
    fingerprint = hashlib.sha256(json.dumps(args).encode()).hexdigest()
    with (CONTROL / 'guard.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text())
            if receipt['fingerprint'] != fingerprint:
                raise ValueError('job_conflict')
            return receipt
        receipt = dict(job=job, ticket_id=ticket, file_key=key, operation=operation,
                       fingerprint=fingerprint, requested_at=now())
        try:
            if digest(BASE / 'baseline.sha256') != baseline_hash:
                raise ValueError('manifest_changed')
            values = verify_baseline()
            if operation == 'complete':
                original = json.loads((CONTROL / (job + '.json')).read_text())
                if original.get('ticket_id') != ticket or original.get('result') != 'ok' or original.get('file_key') != key:
                    raise ValueError('wrong_completion_owner')
                if key in values:
                    if not path.is_file() or digest(path) != values[key]:
                        raise ValueError('effect_changed')
                else:
                    if path.exists():
                        raise ValueError('effect_changed')
                    entry = original['action_record']['quarantine_entry']
                    if not re.fullmatch(r'\d{8}T\d{6}Z_' + job, entry):
                        raise ValueError('invalid_quarantine_entry')
                    saved = QUARANTINE / entry / key
                    if saved.is_symlink() or saved.parent.resolve() != saved.parent or not saved.is_file() or digest(saved) != expected:
                        raise ValueError('quarantine_changed')
                    saved.unlink()
                    parent = saved.parent
                    while parent != QUARANTINE:
                        parent.rmdir()  # refuse nonempty directories; never recursive deletion
                        parent = parent.parent
                receipt.update(result='ok', action='complete')
            else:
                observed = digest(path) if path.is_file() else 'absent'
                if observed != expected:
                    raise ValueError('stale_file_hash')
                if key == 'index.html' and (key not in values or expected == values[key]):
                    raise ValueError('not_a_tamper')
                if key != 'index.html' and (key in values or expected == 'absent'):
                    raise ValueError('not_a_new_file')
                spec = importlib.util.spec_from_file_location('team_restore', '/opt/haedam-s7/bin/s7_restore.py')
                team = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(team)
                action = team.restore_one(key, job)
                if action['result'] != 'ok':
                    raise ValueError(action.get('reason', 'restore_failed'))
                receipt.update(result='ok', action=ALLOWED[key], action_record=action)
        except (OSError, ValueError, KeyError) as exc:
            receipt.update(result='error', reason=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
        receipt['finished_at'] = now()
        atomic(receipt_path, receipt)
        return receipt


def main():
    message = json.loads(sys.stdin.readline(16384))
    if message.get('command') != 'add':
        return 0
    result = execute((message.get('parameters') or {}).get('extra_args') or [])
    print(json.dumps({'job': result['job'], 'result': result['result']}), flush=True)
    return 0 if result['result'] == 'ok' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('S7 guarded response rejected', flush=True)
        sys.exit(2)
