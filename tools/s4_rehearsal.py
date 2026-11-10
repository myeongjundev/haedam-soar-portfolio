"""Offline S4 bundle, private credentials, import materialization and evidence index."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets

from build_s4_workflows import load_settings, materialize, IDS
from s4_lab import ROOT, create_bundle, overlay, command_packet
from s4_settings import digest
from s4_probe import private_write


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def source_hashes():
    files = list((ROOT / 'tools').glob('*s4*.py')) + list((ROOT / 'infra/n8n/s4-src').glob('*.js'))
    files += list((ROOT / 'haedam-portal-backend/src').rglob('*.py'))
    files += list((ROOT / 'haedam-portal-backend/migrations').rglob('*.py'))
    files += list((ROOT / 'services/ticket-store/ticket_store').glob('*.py'))
    files += list((ROOT / 'infra/n8n/workflows').glob('*.json'))
    files += [ROOT / 'lab/s1s4/graylog/s4-fail-then-success.json',
              ROOT / 'infra/graylog/notifications/s1-n8n-haedam-s1.json']
    files += [ROOT / p for p in ('tools/s1_client.py', 'tools/s1_settings.py', 'compose.yaml', 'compose.soc.yaml',
                                'Dockerfile', 'infra/s4-integration-settings.json')]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}


def prepare(s, run_id, output, arm_input=False):
    s = {**s, 'execution_enabled': arm_input}
    path = create_bundle(s, ROOT, output, run_id)
    _, c = load_settings(s)
    private_write(path / 'passwords.json', {role: secrets.token_urlsafe(32) for role in ('target', 'normal')})
    packet = {'case_id': 'S4', 'run_id': run_id, 'project': s['project'], 'settings_sha256': digest(s),
              'integration_sha256': digest(c), 'source_sha256': source_hashes(),
              'clock_tolerance_seconds': c['future_clock_tolerance_seconds'],
              'runtime_verified': False, 'commands_executed': False,
              'password_delivery': 'passwords.json stays outside all container mounts; stdin only',
              'private_sessions': 'private/ mounted only into normal; never publish or commit'}
    write(path / 'rehearsal.json', packet)
    index = {'input': f'runs/{run_id}-trigger6.json', 'graylog_event': None, 'definition_id': None,
             'release_response': None,
             'probes': {p: f'runs/{run_id}-probe-{p}-1.json' for p in ('baseline', 'locked', 'restored')},
             'snapshots': {p: f'runs/{run_id}-snapshot-{p}-1.json' for p in ('baseline', 'locked', 'restored')}}
    write(path / 'evidence-index.json', index)
    return path


def load_bundle(path):
    path = path.resolve()
    if not path.is_relative_to(ROOT / '.local'): raise ValueError('local_bundle_required')
    s, c = load_settings(json.loads((path / 'settings.json').read_text(encoding='utf-8')),
                         json.loads((path / 'integration-settings.json').read_text(encoding='utf-8')))
    manifest = json.loads((path / 'bundle.json').read_text(encoding='utf-8'))
    packet = json.loads((path / 'rehearsal.json').read_text(encoding='utf-8'))
    if manifest['settings_sha256'] != digest(s) or packet['settings_sha256'] != digest(s) or packet['project'] != s['project']:
        raise ValueError('settings_drift')
    if manifest['integration_settings_sha256'] != digest(c) or packet['integration_sha256'] != digest(c):
        raise ValueError('integration_drift')
    if packet['source_sha256'] != source_hashes() or packet['clock_tolerance_seconds'] != c['future_clock_tolerance_seconds']:
        raise ValueError('source_or_policy_drift')
    expected_argv = ['docker', 'compose', '--project-directory', str(ROOT), '--env-file', str(path / 'lab.env'),
        '-p', s['project'], '-f', str(ROOT / 'compose.yaml'), '-f', str(ROOT / 'compose.soc.yaml'), '-f', str(path / 'compose.s4.json')]
    if manifest['compose_argv'] != expected_argv or json.loads((path / 'compose.s4.json').read_text(encoding='utf-8')) != overlay(s, ROOT, path):
        raise ValueError('compose_drift')
    if json.loads((path / 'input-packet.json').read_text(encoding='utf-8')) != command_packet(s, packet['run_id'], expected_argv):
        raise ValueError('command_packet_drift')
    return s, c, packet


def imports(bundle, bindings, enable_detection=False):
    s, c, packet = load_bundle(bundle)
    c = {**c, 'detection_enabled': enable_detection}
    values = {}
    for line in (bundle / 'lab.env').read_text(encoding='utf-8').splitlines():
        key, value = line.split('=', 1)
        if key in values: raise ValueError('duplicate_key')
        values[key] = value
    if any(values.get(k) != str(v) for k, v in s['host_ports'].items()): raise ValueError('port_drift')
    generated = materialize(s, c, bindings, {v['env']: values[v['env']] for v in c['credentials'].values()})
    target = bundle / 'import'; target.mkdir(exist_ok=False)
    for name in ('credentials', 'workflows', 'graylog'): private_write(target / (name + '.json'), generated[name])
    write(target / 'manifest.json', {'run_id': packet['run_id'], 'bindings': bindings, 'workflow_ids': IDS,
        'source_sha256': packet['source_sha256'], 'detection_enabled': enable_detection,
        'schedule_enabled': False, 'import_executed': False})
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--settings', type=Path, default=ROOT / 'infra/s4-settings.json')
    p.add_argument('--run-id', required=True); p.add_argument('--output', required=True, type=Path)
    p.add_argument('--arm-input', action='store_true')
    p = sub.add_parser('imports'); p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--bindings', type=Path, required=True); p.add_argument('--enable-detection', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            path = prepare(json.loads(args.settings.read_text(encoding='utf-8-sig')), args.run_id, args.output, args.arm_input)
        else: path = imports(args.bundle.resolve(), json.loads(args.bindings.read_text(encoding='utf-8-sig')), args.enable_detection)
        print(json.dumps({'created': str(path), 'runtime_verified': False, 'secrets_printed': False}))
    except (ValueError, KeyError, TypeError, OSError): parser.exit(2, 'S4 bundle refused; verify settings/source and a new local directory.\n')


if __name__ == '__main__': main()
