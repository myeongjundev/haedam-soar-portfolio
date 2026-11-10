"""Manage only haedam-h1-live. No global settings or existing containers changed."""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
from pathlib import Path

from s8_lab import http
from build_h1_workflows import ROOT, build

PROJECT = 'haedam-h1-live'
LOCAL = ROOT / '.local/h1'
STATE = LOCAL / 'state.json'


def env_values():
    path = ROOT / '.env.h1'
    if not path.exists():
        return {}
    return dict(line.split('=', 1) for line in path.read_text(encoding='utf-8-sig').splitlines()
                if '=' in line and not line.lstrip().startswith('#'))


def scrub(value):
    for key, secret in env_values().items():
        if secret and any(word in key for word in ('KEY', 'PASSWORD', 'SECRET')):
            value = value.replace(secret, '[REDACTED]')
    return value


def compose(*args, stdin=None, quiet=True):
    command = ['docker', 'compose', '-p', PROJECT, '--env-file', '.env.h1',
               '-f', 'compose.yaml', '-f', 'compose.soc.yaml', '-f', 'compose.h1.yaml', *args]
    run = subprocess.run(command, cwd=ROOT, input=stdin, text=True, encoding='utf-8',
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
                         env={k: v for k, v in os.environ.items() if k not in env_values()})
    if run.returncode:
        raise RuntimeError(scrub(run.stderr + run.stdout)[-5000:])
    if not quiet and run.stderr:
        print(scrub(run.stderr), flush=True)
    return run.stdout.strip()


def init():
    values = env_values()
    for key in ('MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD', 'GRAYLOG_ADMIN_PASSWORD',
                'GRAYLOG_PASSWORD_SECRET', 'N8N_ENCRYPTION_KEY', 'TICKET_STORE_KEY',
                'PORTAL_RESPONSE_KEY', 'H1_DETECTION_KEY', 'H1_OPERATOR_KEY'):
        if not values.get(key):
            values[key] = secrets.token_hex(48 if key == 'GRAYLOG_PASSWORD_SECRET' else 32)
    if not values.get('GRAYLOG_ROOT_PASSWORD_SHA2'):
        values['GRAYLOG_ROOT_PASSWORD_SHA2'] = hashlib.sha256(values['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest()
    for key, value in dict(PORTAL_PORT='15010', GRAYLOG_PORT='19110', N8N_PORT='15710', GELF_PORT='22310', TICKET_PORT='18110').items():
        if not values.get(key):
            values[key] = value
    path = ROOT / '.env.h1'
    path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()), encoding='utf-8')
    path.chmod(0o600)
    LOCAL.mkdir(parents=True, exist_ok=True)
    print('H1 local secrets initialized; existing values preserved.')


def graylog(path, data=None, method=None):
    env = env_values()
    auth = base64.b64encode(('admin:' + env['GRAYLOG_ADMIN_PASSWORD']).encode()).decode()
    status, body = http(f"http://127.0.0.1:{env['GRAYLOG_PORT']}/api" + path, data,
                       {'Authorization': 'Basic ' + auth, 'X-Requested-By': 'portfolio-h1'}, method)
    if status not in (200, 201, 202, 204):
        raise RuntimeError(scrub(f'Graylog {path}: HTTP {status} {body}'))
    return body


def find_create(path, collection, body):
    for item in graylog(path).get(collection, []):
        if item.get('title') == body['title']:
            return item['id']
    created = graylog(path, body)
    return next(created[k] for k in ('id', 'input_id', 'stream_id') if k in created)


def install_n8n():
    env = env_values()
    specs = [('h1DetectionAuth', 'X-H1-Detection-Key', 'H1_DETECTION_KEY'),
             ('h1OperatorAuth', 'X-H1-Operator-Key', 'H1_OPERATOR_KEY'),  # gitleaks:allow -- static header name; value loaded from local env
             ('h1TicketAuth', 'X-Response-Key', 'TICKET_STORE_KEY'),
             ('h1PortalAuth', 'X-Response-Key', 'PORTAL_RESPONSE_KEY')]
    credentials = [{'id': ident, 'name': ident, 'type': 'httpHeaderAuth',
                    'data': {'name': header, 'value': env[key]}} for ident, header, key in specs]
    workflows = list(build().values())
    for filename, content in (('credentials', credentials), ('workflows', workflows)):
        path = f'/tmp/h1-{filename}.json'
        try:
            compose('exec', '-T', 'n8n', 'node', '-e',
                "require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})", path, stdin=json.dumps(content))
            print(compose('exec', '-T', 'n8n', 'n8n', 'import:' + ('credentials' if filename == 'credentials' else 'workflow'), '--input=' + path), flush=True)
        finally:
            compose('exec', '-T', 'n8n', 'node', '-e', "require('fs').rmSync(process.argv[1],{force:true})", path)
    for workflow in workflows:
        compose('exec', '-T', 'n8n', 'n8n', 'publish:workflow', '--id=' + workflow['id'])
    compose('restart', 'n8n')
    compose('up', '-d', '--wait', '--wait-timeout', '180', 'n8n')


def configure():
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets?status=responding,verified")
    if status != 200 or body.get('count', 0):
        raise RuntimeError('Restore active responses before configuring H1.')
    if STATE.exists():
        graylog('/events/definitions/' + json.loads(STATE.read_text())['definition'] + '/unschedule', {}, 'PUT')
    install_n8n()
    input_id = find_create('/system/inputs', 'inputs', {
        'title': 'Portfolio H1 GELF TCP', 'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput', 'global': True,
        'configuration': {'bind_address': '0.0.0.0', 'port': 12201, 'number_worker_threads': 2,
            'recv_buffer_size': 1048576, 'max_message_size': 2097152, 'tls_enable': False,
            'tcp_keepalive': True, 'use_null_delimiter': True}})
    index = next(x['id'] for x in graylog('/system/indices/index_sets')['index_sets'] if x['default'])
    stream = find_create('/streams', 'streams', {'title': 'Portfolio H1 portal', 'description': 'Actual portal GELF',
        'index_set_id': index, 'matching_type': 'AND', 'remove_matches_from_default_stream': False,
        'rules': [{'type': 1, 'field': 'source', 'value': 'haedam-portal', 'inverted': False, 'description': 'Portal source'}]})
    graylog(f'/streams/{stream}/resume', {}, 'POST')
    url = 'http://n8n:5678/webhook/haedam-h1-restrict'
    allowlist = graylog('/system/urlwhitelist')
    entries = [e for e in allowlist.get('entries', []) if e.get('id') != 'portfolio-h1']
    entries.append({'id': 'portfolio-h1', 'type': 'literal', 'title': 'Portfolio H1 n8n', 'value': url})
    graylog('/system/urlwhitelist', {'entries': entries, 'disabled': False}, 'PUT')
    notification = json.loads((ROOT / 'lab/s8s10/graylog/s8-s10-n8n-notification.json').read_text(encoding='utf-8'))
    notification['title'] = 'Portfolio H1 authenticated n8n'
    notification['config'].update(url=url, api_key_as_header=True, api_key='X-H1-Detection-Key',
        api_secret=env_values()['H1_DETECTION_KEY'], headers='', body_template=json.dumps({
            'event_id': '${event.id}', 'asset_id': 'haedam-portal', 'case_id': 'H1',
            'username': '${event.fields.username}', 'detected_at': '${event.timestamp_processing}'}))
    notification_id = find_create('/events/notifications', 'notifications', notification)
    notification['id'] = notification_id
    graylog('/events/notifications/' + notification_id, notification, 'PUT')
    definition = json.loads((ROOT / 'infra/graylog/h1-petition-flood.json').read_text(encoding='utf-8'))
    definition['config']['streams'] = [stream]
    definition['notifications'] = [{'notification_id': notification_id, 'notification_parameters': None}]
    definition_id = find_create('/events/definitions', 'event_definitions', definition)
    definition['id'] = definition_id
    graylog('/events/definitions/' + definition_id, definition, 'PUT')
    graylog(f'/events/definitions/{definition_id}/unschedule', {}, 'PUT')
    LOCAL.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({'input': input_id, 'stream': stream, 'notification': notification_id,
                                'definition': definition_id}, indent=2), encoding='utf-8')
    print('H1 configured; detection paused until a bounded verification run.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'up', 'configure', 'stop', 'status'])
    args = parser.parse_args()
    if args.command == 'init':
        init()
    elif args.command == 'up':
        memory = int(subprocess.check_output(['docker', 'info', '--format', '{{.MemTotal}}'], text=True, timeout=30))
        names = subprocess.check_output(['docker', 'ps', '--format', '{{.Names}}'], text=True, timeout=30).splitlines()
        if memory < 8 * 1024**3 and any(not n.startswith(PROJECT + '-') for n in names):
            raise RuntimeError('Less than 8 GiB; coordinate stopping other containers before H1.')
        compose('config', '--quiet')
        compose('up', '-d', '--build', '--wait', '--wait-timeout', '240', quiet=False)
        print(compose('ps'))
    elif args.command == 'configure':
        configure()
    elif args.command == 'stop':
        print(compose('stop'))
    else:
        print(compose('ps'))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(scrub(str(error)))
