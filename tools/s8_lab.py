"""Personal S8 lab lifecycle. Python stdlib + Docker Compose; no host packages.

Only project haedam-s8-live is managed. Never operates on team containers.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from build_s8_workflows import build, ROOT

PROJECT = 'haedam-s8-live'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
LOCAL = ROOT / '.local/s8'
STATE = LOCAL / 'state.json'


def env_values():
    values = {}
    for name in ('.env', '.env.soc', '.env.s8'):
        path = ROOT / name
        if path.exists():
            for line in path.read_text(encoding='utf-8-sig').splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    k, v = line.split('=', 1)
                    values[k.strip()] = v.strip()
    return values


def scrub(text):
    for key, value in env_values().items():
        if value and any(word in key for word in ('KEY', 'PASSWORD', 'SECRET')):
            text = text.replace(value, '[REDACTED]')
    return text


def compose(*args, stdin=None, quiet=False):
    command = ['docker', 'compose', '-p', PROJECT,
               '--env-file', '.env', '--env-file', '.env.soc', '--env-file', '.env.s8',
               '-f', 'compose.yaml', '-f', 'compose.soc.yaml', '-f', 'compose.s8.yaml', *args]
    # Compose process environment takes precedence over --env-file. Remove only
    # this project's dotenv keys so unrelated shells cannot redirect the test.
    env = {k: v for k, v in os.environ.items() if k not in env_values()}
    run = subprocess.run(command, cwd=ROOT, input=stdin, text=True, encoding='utf-8',
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=300)
    if run.returncode:
        raise RuntimeError(scrub(run.stderr + run.stdout)[-5000:])
    if not quiet and run.stderr:
        print(scrub(run.stderr).strip(), flush=True)
    return run.stdout.strip()


def init():
    LOCAL.mkdir(parents=True, exist_ok=True)
    values = env_values()
    additions = {
        '.env': {'MYSQL_ROOT_PASSWORD': secrets.token_hex(24), 'MYSQL_PASSWORD': secrets.token_hex(24)},
        '.env.soc': {'GRAYLOG_ADMIN_PASSWORD': secrets.token_hex(20),
                     'GRAYLOG_PASSWORD_SECRET': secrets.token_hex(48),
                     'N8N_ENCRYPTION_KEY': secrets.token_hex(32), 'TICKET_STORE_KEY': secrets.token_hex(32)},
        '.env.s8': {'PORTAL_RESPONSE_KEY': secrets.token_hex(32),
                    'S8_DETECTION_KEY': secrets.token_hex(32), 'S8_OPERATOR_KEY': secrets.token_hex(32),
                    'PORTAL_PORT': '15000', 'GRAYLOG_PORT': '19100', 'N8N_PORT': '15700',
                    'GELF_PORT': '22300', 'TICKET_PORT': '18100'},
    }
    for filename, defaults in additions.items():
        path = ROOT / filename
        existing = {}
        if path.exists():
            existing = dict(line.split('=', 1) for line in path.read_text().splitlines()
                            if '=' in line and not line.startswith('#'))
        lines = path.read_text(encoding='utf-8-sig').splitlines() if path.exists() else []
        for key, value in defaults.items():
            # .env.s8 intentionally overrides P02 ports. Fill blank examples,
            # preserve existing keys/passwords and avoid duplicate assignments.
            if not existing.get(key) and (filename == '.env.s8' or not values.get(key)):
                lines = [line for line in lines if not line.startswith(key + '=')]
                lines.append(f'{key}={value}')
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        path.chmod(0o600)
    values = env_values()
    if not values.get('GRAYLOG_ROOT_PASSWORD_SHA2'):
        digest = hashlib.sha256(values['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest()
        with (ROOT / '.env.soc').open('a') as stream:
            stream.write(f'\nGRAYLOG_ROOT_PASSWORD_SHA2={digest}\n')
    print('Local secrets initialized (existing values preserved).')


def http(url, data=None, headers=None, method=None, timeout=30):
    headers = {'Accept': 'application/json', **(headers or {})}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    request = Request(url, data=None if data is None else json.dumps(data).encode(), headers=headers, method=method)
    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {'text': raw.decode(errors='replace')[:200]}
        return response.status, body


def graylog(path, data=None, method=None):
    env = env_values()
    auth = base64.b64encode(('admin:' + env['GRAYLOG_ADMIN_PASSWORD']).encode()).decode()
    status, body = http(f"http://127.0.0.1:{env['GRAYLOG_PORT']}/api" + path, data,
                        {'Authorization': 'Basic ' + auth, 'X-Requested-By': 'portfolio-s8'}, method)
    if status not in (200, 201, 202, 204):
        raise RuntimeError(scrub(f'Graylog {path}: HTTP {status} {body}'))
    return body


def find_create(path, collection, body):
    existing = graylog(path).get(collection, [])
    for item in existing:
        if item.get('title') == body['title']:
            return item['id']
    created = graylog(path, body)
    return next(created[k] for k in ('id', 'input_id', 'stream_id') if k in created)


def install_n8n():
    env = env_values()
    specs = [('s8DetectionAuth', 'X-S8-Detection-Key', 'S8_DETECTION_KEY'),
             ('s8OperatorAuth', 'X-S8-Operator-Key', 'S8_OPERATOR_KEY'),  # gitleaks:allow -- literal header name, secret loaded from env
             ('s8TicketAuth', 'X-Response-Key', 'TICKET_STORE_KEY'),
             ('s8PortalAuth', 'X-Response-Key', 'PORTAL_RESPONSE_KEY')]
    credentials = [{'id': ident, 'name': ident, 'type': 'httpHeaderAuth',
                    'data': {'name': header, 'value': env[key]}} for ident, header, key in specs]
    workflows = list(build().values())
    for filename, content in (('credentials', credentials), ('workflows', workflows)):
        path = f'/tmp/s8-{filename}.json'
        try:
            compose('exec', '-T', 'n8n', 'node', '-e',
                    "require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})", path,
                    stdin=json.dumps(content), quiet=True)
            print(compose('exec', '-T', 'n8n', 'n8n', f'import:{"credentials" if filename == "credentials" else "workflow"}',
                          '--input=' + path), flush=True)
        finally:
            compose('exec', '-T', 'n8n', 'node', '-e',
                    "require('fs').rmSync(process.argv[1],{force:true})", path, quiet=True)
    for workflow in workflows:
        compose('exec', '-T', 'n8n', 'n8n', 'publish:workflow', '--id=' + workflow['id'], quiet=True)
        print('Published ' + workflow['id'], flush=True)
    compose('restart', 'n8n', quiet=True)
    compose('up', '-d', '--wait', '--wait-timeout', '180', 'n8n', quiet=True)


def configure():
    status, body = http(f"http://127.0.0.1:{env_values()['TICKET_PORT']}/api/v1/tickets?status=responding,verified")
    if status != 200 or body.get('count', 0):
        raise RuntimeError('Restore active responses before reconfiguring S8 workflows.')
    if STATE.exists():
        state = json.loads(STATE.read_text())
        graylog(f"/events/definitions/{state['definition']}/unschedule", {}, 'PUT')
    install_n8n()
    input_id = find_create('/system/inputs', 'inputs', {
        'title': 'Portfolio S8 GELF TCP', 'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput', 'global': True,
        'configuration': {'bind_address': '0.0.0.0', 'port': 12201, 'number_worker_threads': 2,
                          'recv_buffer_size': 1048576, 'max_message_size': 2097152,
                          'tls_enable': False, 'tcp_keepalive': True, 'use_null_delimiter': True}})
    index = next(x['id'] for x in graylog('/system/indices/index_sets')['index_sets'] if x['default'])
    stream_id = find_create('/streams', 'streams', {
        'title': 'Portfolio S8 portal', 'description': 'Only actual portal GELF logs', 'index_set_id': index,
        'matching_type': 'AND', 'remove_matches_from_default_stream': False,
        'rules': [{'type': 1, 'field': 'source', 'value': 'haedam-portal', 'inverted': False,
                   'description': 'Portal source'}]})
    graylog(f'/streams/{stream_id}/resume', {}, 'POST')
    url = 'http://n8n:5678/webhook/haedam-s8-s10'
    allowlist = graylog('/system/urlwhitelist')
    entries = allowlist.get('entries', [])
    if not any(e.get('value') == url for e in entries):
        entries.append({'id': 'portfolio-s8', 'type': 'literal', 'title': 'Portfolio S8 n8n', 'value': url})
    graylog('/system/urlwhitelist', {'entries': entries, 'disabled': False}, 'PUT')
    notification = json.loads((ROOT / 'lab/s8s10/graylog/s8-s10-n8n-notification.json').read_text(encoding='utf-8'))
    notification['title'] = 'Portfolio S8 authenticated n8n'
    config = notification['config']
    config.update(url=url, api_key_as_header=True, api_key='X-S8-Detection-Key',
                  api_secret=env_values()['S8_DETECTION_KEY'], headers='')
    config['body_template'] = json.dumps({
        'event_id': '${event.id}', 'asset_id': 'haedam-portal', 'case_id': 'S8',
        'src_ip': '${event.fields.src_ip}', 'detected_at': '${event.timestamp_processing}',
        'dry_run': False, 'store_real': True})
    notification_id = find_create('/events/notifications', 'notifications', notification)
    notification['id'] = notification_id
    graylog('/events/notifications/' + notification_id, notification, 'PUT')
    definition = json.loads((ROOT / 'lab/s8s10/graylog/s8-scan-then-login.json').read_text(encoding='utf-8'))
    definition['title'] = 'Portfolio S8 actual portal detection'
    definition['description'] = 'Same source, 404 scan + 401 login failure; unordered. Isolated lab only.'
    definition['config']['query'] = '(' + definition['config']['query'] + ') AND src_ip:172.30.88.*'
    definition['config']['streams'] = [stream_id]
    definition['config']['execute_every_ms'] = 15000
    definition['notification_settings']['backlog_size'] = 0
    definition['notifications'] = [{'notification_id': notification_id, 'notification_parameters': None}]
    definition_id = find_create('/events/definitions', 'event_definitions', definition)
    definition['id'] = definition_id
    graylog('/events/definitions/' + definition_id, definition, 'PUT')
    # Enable only during a bounded test; old 15-minute windows must not reblock after release.
    graylog(f'/events/definitions/{definition_id}/unschedule', {}, 'PUT')
    LOCAL.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({'input': input_id, 'stream': stream_id, 'notification': notification_id,
                                'definition': definition_id}, indent=2), encoding='utf-8')
    print('S8 configured. Detection paused until tools/s8_verify.py starts the test.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'up', 'configure', 'stop', 'status'])
    args = parser.parse_args()
    if args.command == 'init':
        init()
    elif args.command == 'up':
        memory = int(subprocess.check_output(['docker', 'info', '--format', '{{.MemTotal}}'], text=True, timeout=30))
        names = subprocess.check_output(['docker', 'ps', '--format', '{{.Names}}'], text=True, timeout=30).splitlines()
        others = [name for name in names if not name.startswith(PROJECT + '-')]
        if memory < 8 * 1024**3 and others:
            raise RuntimeError('Docker has less than 8 GiB and other containers are running. Coordinate a temporary stop before S8: ' + ', '.join(others))
        compose('config', '--quiet', quiet=True)
        compose('up', '-d', '--build', '--wait', '--wait-timeout', '240', quiet=True)
        print(compose('ps'), flush=True)
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
