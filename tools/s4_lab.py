"""Offline-only S4 bundle creation. Never calls Docker, HTTP or existing dotenvs."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets

from s4_settings import digest, validate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SETTINGS = ROOT / 'infra/s4-settings.json'


def overlay(s, root, bundle):
    validate(s)
    addresses, paths = s['addresses'], s['paths']
    services = {
        'portal': {'environment': {'RESPONSE_API_KEY': '${PORTAL_RESPONSE_KEY:?S4 local key required}',
                                  'RESPONSE_ALLOWED_CIDRS': addresses['n8n_response'] + '/32',
                                  'S4_ENABLED': '1', 'S4_ACCOUNT_ALLOWLIST': s['accounts']['target'],
                                  'S4_RELEASE_KEY': '${S4_RELEASE_KEY:?S4 release key required}'},
                   'networks': {'default': {}, 's4-clients': {'ipv4_address': addresses['portal_client']},
                                's4-response': {'ipv4_address': addresses['portal_response'], 'aliases': ['portal-response']}}},
        'n8n': {'environment': {'N8N_CONCURRENCY_PRODUCTION_LIMIT': '1',
                               'EXECUTIONS_DATA_SAVE_ON_SUCCESS': 'none', 'EXECUTIONS_DATA_SAVE_ON_ERROR': 'none',
                               'EXECUTIONS_DATA_SAVE_MANUAL_EXECUTIONS': 'false',
                               'EXECUTIONS_DATA_SAVE_ON_PROGRESS': 'false', 'EXECUTIONS_DATA_PRUNE': 'false'},
                'networks': {'default': {}, 's4-response': {'ipv4_address': addresses['n8n_response']}}}}
    for name in ('attacker', 'normal'):
        services[name] = {'image': s['client_image'], 'init': True,
                         'command': ['python', '-c', 'import time; time.sleep(2147483647)'],
                         'environment': {'HAEDAM_S4_PROJECT': s['project']},
                         'labels': {'haedam.case': 'S4'},
                         'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                         'networks': {'s4-clients': {'ipv4_address': addresses[name]}},
                         'volumes': [{'type': 'bind', 'source': str(root / 'tools'), 'target': paths['tools_mount'], 'read_only': True},
                                     {'type': 'bind', 'source': str(bundle / 'settings.json'), 'target': paths['settings_mount'], 'read_only': True},
                                     {'type': 'bind', 'source': str(bundle / 'runs'), 'target': paths['evidence_mount']}]}
    networks = {}
    for setting, name in [('default', 'default'), ('clients', 's4-clients'), ('response', 's4-response'), ('graylog_backend', 'graylog-backend')]:
        networks[name] = {'internal': True, 'ipam': {'config': [{'subnet': s['networks'][setting]}]}}
    return {'name': s['project'], 'services': services, 'networks': networks}


def definition_template(s, root):
    from build_s4_workflows import graylog_artifacts, load_settings
    return graylog_artifacts(*load_settings(s))['definition']


def create_bundle(s, root, output):
    validate(s)
    from build_s4_workflows import build, load_settings, graylog_artifacts
    _, integration = load_settings(s)
    root, output = root.resolve(), output.resolve()
    if not output.is_relative_to(root / '.local') or output == root / '.local':
        raise ValueError('output_must_be_a_new_directory_inside_local')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'runs').mkdir()
    env = {key: secrets.token_hex(32) for key in ('MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD', 'GRAYLOG_ADMIN_PASSWORD',
            'N8N_ENCRYPTION_KEY', 'TICKET_STORE_KEY', 'PORTAL_RESPONSE_KEY', 'S4_DETECTION_KEY', 'S4_OPERATOR_KEY', 'S4_RELEASE_KEY')}
    env['GRAYLOG_PASSWORD_SECRET'] = secrets.token_hex(48)
    env['GRAYLOG_ROOT_PASSWORD_SHA2'] = hashlib.sha256(env['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest()
    env.update({k: str(v) for k, v in s['host_ports'].items()})
    env_path = output / 'lab.env'
    with env_path.open('x', encoding='utf-8') as f:
        f.write('\n'.join(k + '=' + v for k, v in env.items()) + '\n')
    env_path.chmod(0o600)
    command = ['docker', 'compose', '--project-directory', str(root), '--env-file', str(env_path),
               '-p', s['project'], '-f', str(root / 'compose.yaml'), '-f', str(root / 'compose.soc.yaml'),
               '-f', str(output / 'compose.s4.json')]
    files = {'settings.json': s, 'compose.s4.json': overlay(s, root, output),
             'graylog-definition.template.json': definition_template(s, root),
             'integration-settings.json': integration,
             'graylog-integration.template.json': graylog_artifacts(s, integration),
             'bundle.json': {'case_id': 'S4', 'settings_sha256': digest(s), 'runtime_verified': False,
                             'integration_ready': False, 'integration_artifacts_generated': True,
                             'integration_settings_sha256': digest(integration), 'compose_argv': command,
                             'clear_process_env_before_future_compose': sorted(env),
                             'pending': ['check network/port conflicts before startup', 'new owned volumes',
                                         'Graylog resource IDs and authentication materialization/import',
                                         'n8n credential/workflow import and publication; detection remains disabled',
                                         'normal authenticated login and end-to-end observation']}}
    (output / 'workflows').mkdir()
    files.update({'workflows/' + name: workflow for name, workflow in build(s, integration).items()})
    for name, body in files.items():
        (output / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'init'])
    parser.add_argument('--settings', type=Path, default=DEFAULT_SETTINGS)
    parser.add_argument('--output', type=Path, default=ROOT / '.local/s4')
    args = parser.parse_args()
    try:
        s = validate(json.loads(args.settings.read_text(encoding='utf-8-sig')))
        if args.action == 'init':
            path = create_bundle(s, ROOT, args.output)
            print(json.dumps({'created': str(path), 'runtime_verified': False, 'secrets_printed': False}))
        else:
            print(json.dumps({'settings': 'valid', 'project': s['project'], 'settings_sha256': digest(s),
                              'runtime_verified': False, 'execution_enabled': s['execution_enabled']}))
    except (ValueError, KeyError, TypeError, OSError):
        parser.exit(2, 'S4 configuration rejected. Check settings and use a new .local output directory.\n')


if __name__ == '__main__':
    main()
