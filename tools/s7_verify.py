"""Live, reversible S7 FIM + Wazuh API restore test. No Graylog/n8n claims."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

from s7_lab import ROOT, LOCAL, PROJECT, API_CA, api, agent_id, baseline, compose, env_values, index, request, restore, run, scrub, wait_for

WEB = '/var/www/haedam/'
SCRIPT = '/opt/haedam-s7/bin/s7_restore.py'


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def http(path='/'):
    try:
        with urllib.request.urlopen('http://127.0.0.1:' + env_values()['PORTAL_PORT'] + path, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def agent(code, *args):
    return compose('exec', '-T', 's7-agent', 'python3', '-I', '-c', code, *args)


def logs(run_id):
    return json.loads(agent('import json,pathlib,sys; p=pathlib.Path("/var/log/haedam-s7/s7-restore.log"); '
        'print(json.dumps([r for line in p.read_text().splitlines() if (r:=json.loads(line)).get("run_id")==sys.argv[1]]))', run_id))


def alert(ident, path, event, since):
    body = index('/wazuh-alerts-*/_search', {'size': 5, 'sort': [{'timestamp': 'desc'}], 'query': {'bool': {'filter': [
        {'term': {'agent.id': ident}}, {'term': {'syscheck.path': WEB + path}},
        {'term': {'syscheck.event': event}}, {'range': {'timestamp': {'gte': since}}}]}}})
    hits = body['hits']['hits']
    if not hits:
        return None
    source = hits[0]['_source']
    return {'id': source['id'], 'index_id': hits[0]['_id'], 'timestamp': source['timestamp'],
            'rule': source['rule']['id'], 'agent_id': source['agent']['id'],
            'path': source['syscheck']['path'], 'event': source['syscheck']['event'],
            'sha256_before': source['syscheck'].get('sha256_before'),
            'sha256_after': source['syscheck'].get('sha256_after')}


def ar(ident, path, run_id):
    return api('/active-response?agents_list=' + ident, {
        'command': '!s7-restore-ar', 'arguments': [path, run_id]}, 'PUT')


def main():
    baseline()
    # First enrollment can trigger a short automatic restart after group sync.
    ident = wait_for(agent_id)
    # Initial FIM inventory must exist before changing files.
    wait_for(lambda: api('/syscheck/' + ident + '?search=index.html').get('total_affected_items', 0) > 0)
    run_id = datetime.now(timezone.utc).strftime('S7-%Y%m%dT%H%M%SZ')
    result = {'run_id': run_id, 'project': PROJECT, 'started_at': now(), 'scope': 'FIM/indexer/API restore; no n8n/ticket',
              'agent_id': ident, 'checks': {}, 'cases': []}
    code = ('import hashlib,json,pathlib; root=pathlib.Path("/var/www/haedam"); '
        'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() '
        'for p in root.rglob("*") if p.is_file()},sort_keys=True))')
    original = json.loads(agent(code))
    before_status, before = http()
    assert before_status == 200 and hashlib.sha256(before).hexdigest() == original['index.html']
    probe = 'assets/s7-probe.txt'
    assert probe not in original, 'Existing probe file; refuse to overwrite.'
    checks = result['checks']
    status, _ = request(env_values()['WAZUH_API_PORT'], '/agents', ca=API_CA)
    assert status == 401
    checks['unauthenticated_api'] = status
    readonly = compose('exec', '-T', 'portal', 'python', '-c',
        'try:\n open("/app/frontend/index.html", "ab").close()\n print("writable")\n'
        'except OSError:\n print("denied")')
    assert readonly == 'denied'
    checks['portal_webroot_write_denied'] = True
    changed = False
    try:
        for path, event, action in [('index.html', 'modified', 'restore'), (probe, 'added', 'quarantine')]:
            since, started = now(), time.monotonic()
            changed = True
            if event == 'modified':
                agent('import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                      'p.write_bytes(p.read_bytes()+b"\\n<!-- "+sys.argv[2].encode()+b" -->\\n")', WEB + path, run_id)
                assert run_id.encode() in http()[1]
                try:
                    baseline()
                except RuntimeError as exc:
                    assert 'differs from the built portal image' in str(exc)
                    checks['baseline_refuses_tamper'] = True
                else:
                    raise AssertionError('Baseline accepted a tampered webroot.')
            else:
                agent('import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                      'p.write_text("S7 harmless local probe "+sys.argv[2])', WEB + path, run_id)
                assert http('/' + path)[0] == 200
            detected = wait_for(lambda: alert(ident, path, event, since), timeout=120)
            elapsed = round(time.monotonic() - started, 3)
            if event == 'modified':
                assert detected['sha256_before'] == original[path]
                assert detected['sha256_after'] != original[path]
            sent = now()
            receipt = ar(ident, WEB + path, run_id)
            wait_for(lambda: any(r.get('path') == path and r.get('action') == action and r.get('result') == 'ok'
                                 for r in logs(run_id)), timeout=60)
            if action == 'restore':
                wait_for(lambda: http() == (200, before), timeout=30)
            else:
                wait_for(lambda: http('/' + path)[0] == 404, timeout=30)
            records = [r for r in logs(run_id) if r.get('path') == path and r.get('action') == action]
            result['cases'].append({'path': path, 'changed_at': since, 'indexed_alert': detected,
                'change_to_index_observed_seconds': elapsed, 'ar_requested_at': sent,
                'ar_delivery': receipt, 'effect_observed_at': now(), 'restore_record': records[-1],
                'http_after': http('/' if path == 'index.html' else '/' + path)[0]})
        # A delivered API request is not proof of a successful action: unsafe path must fail at agent.
        outside_id = run_id + '-outside'
        agent('import pathlib; pathlib.Path("/tmp/s7-sentinel").write_text("unchanged")')
        ar(ident, '/tmp/s7-sentinel', outside_id)
        rejected = wait_for(lambda: next((r for r in logs(outside_id)
            if r.get('reason') == 'path_outside_web_root'), None), timeout=60)
        assert agent('import pathlib; print(pathlib.Path("/tmp/s7-sentinel").read_text())') == 'unchanged'
        checks['outside_web_root_rejected'] = rejected['reason']
        current = json.loads(agent(code))
        assert current == original
        checks['all_web_files_match_image'] = len(original)
        checks['normal_assets_unchanged'] = len(original) - 1
        print(restore('verify'))
        # Preserve quarantine evidence, then purge exactly this run's known entry.
        for rec in logs(run_id):
            if rec.get('action') == 'quarantine':
                entry = rec['quarantine_entry']
                assert '/' not in entry and '\\' not in entry and entry.endswith('_' + run_id)
                print(restore('purge', entry))
        manifest_before = agent('import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("/opt/haedam-s7/state/baseline.sha256").read_bytes()).hexdigest())')
        compose('restart', 's7-agent')
        wait_for(agent_id)
        manifest_after = agent('import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("/opt/haedam-s7/state/baseline.sha256").read_bytes()).hexdigest())')
        assert manifest_after == manifest_before and json.loads(agent(code)) == original
        checks['restart_preserves_baseline'] = True
        checks['baseline_manifest_sha256'] = manifest_after
        checks['quarantine_entries_remaining'] = int(agent('import pathlib; print(len(list(pathlib.Path("/var/lib/haedam-s7/quarantine").iterdir())))'))
        assert checks['quarantine_entries_remaining'] == 0
        assert http() == (200, before)
        checks['restored_http_body_sha256'] = hashlib.sha256(before).hexdigest()
        result['result'] = 'pass'
    except Exception as exc:
        result['result'] = 'fail'
        result['error'] = scrub(str(exc))
        raise
    finally:
        if changed:
            # Bounded local fallback cleanup. This is separate from the measured API result.
            result['cleanup'] = []
            for path in ('index.html', probe):
                try:
                    result['cleanup'].append(restore('restore', '--run-id', run_id + '-cleanup', '--', path))
                except Exception as exc:
                    result['cleanup'].append(scrub(str(exc)))
                    result['result'] = 'fail'
            try:
                result['cleanup_verify'] = restore('verify')
            except Exception as exc:
                result['cleanup_verify'] = scrub(str(exc))
                result['result'] = 'fail'
        result['finished_at'] = now()
        sources = ['compose.yaml', 'compose.s7.yaml', 'Dockerfile', 'tools/s7_lab.py', 'tools/s7_verify.py',
                   'lab/s7/restore/s7_restore.py', 'lab/s7/restore/s7-restore-ar']
        sources += [str(p.relative_to(ROOT)).replace('\\', '/') for p in (ROOT / 'infra/wazuh').rglob('*') if p.is_file()]
        result['source_sha256'] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
        result['source_head_before_run'] = run(['git', 'rev-parse', 'HEAD'])
        result['source_dirty_at_run'] = bool(run(['git', 'status', '--porcelain']))
        output = LOCAL / (run_id + '.json')
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('Evidence: ' + str(output) + ' result=' + result.get('result', 'incomplete'))
    if result.get('result') != 'pass':
        raise RuntimeError('S7 verification or cleanup failed; inspect the evidence file.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit(scrub(str(exc)))
