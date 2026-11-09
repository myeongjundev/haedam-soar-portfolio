"""Personal S7 automatic pipeline. Own Compose project; never stops other stacks."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import urllib.request

import s7_lab as base
from s8_lab import http
from build_s7_workflows import build

ROOT = base.ROOT
LOCAL = ROOT / '.local/s7-auto'
PROJECT = os.environ.get('S7_PROJECT', 'haedam-s7-auto')
if not base.re.fullmatch(r'haedam-s7-[a-z0-9][a-z0-9-]{0,31}', PROJECT):
    raise ValueError('Invalid personal S7 project')
ENV = ROOT / '.env.s7-auto'
STATE = LOCAL / (PROJECT + '-state.json')


def env_values():
    if not ENV.exists():
        return {}
    return dict(line.split('=', 1) for line in ENV.read_text(encoding='utf-8-sig').splitlines()
                if '=' in line and not line.startswith('#'))


def scrub(text):
    for k, v in env_values().items():
        if v and any(word in k for word in ('PASSWORD', 'SECRET', 'KEY')):
            text = text.replace(v, '[REDACTED]')
    return text


def compose(*args, stdin=None, timeout=300):
    return base.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(ENV),
        '-f', 'compose.yaml', '-f', 'compose.soc.yaml', '-f', 'compose.s7.yaml', '-f', 'compose.s7-auto.yaml', *args], stdin, timeout)


def bind():
    # Reuse pinned Wazuh API/index helpers with this project's ports and scoped Compose.
    base.PROJECT = PROJECT
    base.ENV_FILE = ENV
    base.API_CA = ROOT / '.local/s7/certs/root-ca-manager.pem'
    base.env_values = env_values
    base.scrub = scrub
    base.compose = compose


def init():
    # Wazuh's public certs and private bootstrap settings are shared with the
    # manual personal lab; Docker runtime state/volumes are separate per project.
    # Initialize this prerequisite in a separate process to preserve helper scope.
    base.run(['py', '-3.12', 'tools/s7_lab.py', 'init'])
    LOCAL.mkdir(parents=True, exist_ok=True)
    values = env_values()
    original = dict(line.split('=', 1) for line in (ROOT / '.env.s7').read_text().splitlines() if '=' in line)
    for k, v in original.items():
        if not values.get(k):
            values[k] = v
    for k in ('GRAYLOG_ADMIN_PASSWORD', 'GRAYLOG_PASSWORD_SECRET', 'N8N_ENCRYPTION_KEY', 'TICKET_STORE_KEY',
              'S7_DETECTION_KEY', 'S7_OPERATOR_KEY', 'S7_BRIDGE_KEY', 'S7_COMPLETE_KEY', 'S7_WAZUH_PASSWORD'):
        if not values.get(k):
            values[k] = secrets.token_hex(48 if k == 'GRAYLOG_PASSWORD_SECRET' else 24) + 'aA1-'
    values['GRAYLOG_ROOT_PASSWORD_SHA2'] = hashlib.sha256(values['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest()
    ports = dict(PORTAL_PORT='15030', WAZUH_API_PORT='15530', WAZUH_INDEXER_PORT='19230',
                 WAZUH_DASHBOARD_PORT='15630', GRAYLOG_PORT='19130', N8N_PORT='15730', GELF_PORT='22330', TICKET_PORT='18130')
    existing = env_values()
    for k, v in ports.items():
        values[k] = existing.get(k) or v
    values.setdefault('S7_AGENT_ID', '001')
    base.private_file(ENV, ''.join(f'{k}={v}\n' for k, v in values.items()))
    # Public CA, copied separately so the gateway needs no DAC override capability.
    base.private_file(LOCAL / 'manager-ca.pem', (ROOT / '.local/s7/certs/root-ca-manager.pem').read_text())
    compose('config', '--quiet')
    print('Automatic S7 local settings initialized; credentials not printed.')


def graylog(path, data=None, method=None):
    env = env_values()
    status, body = http('http://127.0.0.1:' + env['GRAYLOG_PORT'] + '/api' + path, data,
        {'Authorization': base.basic('admin', env['GRAYLOG_ADMIN_PASSWORD']), 'X-Requested-By': 'portfolio-s7'}, method)
    if status not in (200, 201, 202, 204):
        raise RuntimeError(scrub(f'Graylog {path}: {status} {body}'))
    return body


def ready():
    ident = base.wait_for(base.agent_id)
    if ident != env_values()['S7_AGENT_ID']:
        raise RuntimeError('Enrolled agent differs from configured scope; do not broaden RBAC.')
    base.wait_for(lambda: base.index('/_cluster/health')['status'] in ('green', 'yellow'))
    for port, path in [('GRAYLOG_PORT', '/api/system/lbstatus'), ('N8N_PORT', '/healthz/readiness'), ('PORTAL_PORT', '/api/v1/health'), ('TICKET_PORT', '/')]:
        def reachable():
            with urllib.request.urlopen('http://127.0.0.1:' + env_values()[port] + path, timeout=8) as res:
                return res.status == 200
        base.wait_for(reachable)
    print('S7 automatic stack ready: real agent, indexer, Graylog, n8n, portal, tickets.')


def up():
    projects=base.run(['docker','ps','--format','{{.Label "com.docker.compose.project"}}']).splitlines()
    memory=int(base.run(['docker','info','--format','{{.MemTotal}}']))
    if any(p.startswith('haedam-s7-') and p!=PROJECT for p in projects):
        raise RuntimeError('Stop the other personal S7 project before using shared ports.')
    if memory < 8*1024**3 and any(p!=PROJECT for p in projects):
        raise RuntimeError('Under 8GiB with other workloads running; none stopped here.')
    compose('up','-d','--build',timeout=900)
    print('Automatic S7 started. Run s7_auto_lab.py ready, then configure.')


def baseline():
    image = base.run(['docker', 'image', 'inspect', PROJECT + '-portal', '--format', '{{.Id}}'])
    code = ('import hashlib,json,pathlib; p=pathlib.Path("/app/frontend"); '
            'print(json.dumps({str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob("*") if f.is_file()},sort_keys=True))')
    expected = base.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python', image, '-c', code])
    if json.loads(expected) != json.loads(compose('exec', '-T', 'portal', 'python', '-c', code)):
        raise RuntimeError('Changed web volume; refusing to replace baseline.')
    exists = compose('exec', '-T', 's7-agent', 'python3', '-c',
        'from pathlib import Path; print(Path("/opt/haedam-s7/state/baseline.sha256").exists())') == 'True'
    print(compose('run', '--rm', '--no-deps', 's7-baseline', 'verify' if exists else 'baseline'))


def scope_api():
    api = base.api
    if api('/security/config')['rbac_mode'] != 'white':
        raise RuntimeError('Personal Wazuh must deny ungranted API actions (white RBAC mode).')
    def ensure(path, name, payload, field):
        items = api(path)['affected_items']
        old = next((x for x in items if x.get(field) == name), None)
        return old['id'] if old else api(path, payload, 'POST')['affected_items'][0]['id']
    user = ensure('/security/users', 's7-responder', {'username': 's7-responder', 'password': env_values()['S7_WAZUH_PASSWORD']}, 'username')
    role = ensure('/security/roles', 's7-one-agent', {'name': 's7-one-agent'}, 'name')
    policy = ensure('/security/policies', 's7-one-agent', {'name': 's7-one-agent', 'policy': {
        'actions': ['agent:read', 'active-response:command'], 'resources': ['agent:id:' + env_values()['S7_AGENT_ID']], 'effect': 'allow'}}, 'name')
    current_role = api(f'/security/roles?role_ids={role}')['affected_items'][0]
    current_user = api(f'/security/users?user_ids={user}')['affected_items'][0]
    actual_policy = api(f'/security/policies?policy_ids={policy}')['affected_items'][0]['policy']
    expected_policy = {'actions': ['agent:read', 'active-response:command'],
                       'resources': ['agent:id:' + env_values()['S7_AGENT_ID']], 'effect': 'allow'}
    if actual_policy != expected_policy or set(current_user.get('roles', [])) - {role} or set(current_role.get('policies', [])) - {policy}:
        raise RuntimeError('Existing responder scope drifted; do not silently broaden or overwrite permissions.')
    if policy not in current_role.get('policies', []):
        api(f'/security/roles/{role}/policies?policy_ids={policy}', {}, 'POST')
    if role not in current_user.get('roles', []):
        api(f'/security/users/{user}/roles?role_ids={role}', {}, 'POST')
    print('Scoped s7-responder role assigned; runtime denies are verified separately.')


def install_n8n():
    env = env_values()
    specs = [('s7DetectionAuth', 'X-S7-Detection-Key', 'S7_DETECTION_KEY'),
             ('s7OperatorAuth', 'X-S7-Operator-Key', 'S7_OPERATOR_KEY'),  # gitleaks:allow -- static header/variable names, values loaded privately
             ('s7TicketAuth', 'X-Response-Key', 'TICKET_STORE_KEY'),
             ('s7BridgeAuth', 'X-S7-Key', 'S7_BRIDGE_KEY'), ('s7CompleteAuth', 'X-S7-Key', 'S7_COMPLETE_KEY')]
    credentials = [{'id': i, 'name': i, 'type': 'httpHeaderAuth', 'data': {'name': h, 'value': env[k]}} for i, h, k in specs]
    workflows = list(build().values())
    for kind, content in [('credentials', credentials), ('workflow', workflows)]:
        path = '/tmp/s7-' + kind + '.json'
        try:
            compose('exec', '-T', 'n8n', 'node', '-e',
                "require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})", path, stdin=json.dumps(content))
            print(compose('exec', '-T', 'n8n', 'n8n', 'import:' + kind, '--input=' + path))
        finally:
            compose('exec', '-T', 'n8n', 'node', '-e', "require('fs').rmSync(process.argv[1],{force:true})", path)
    for workflow in workflows:
        compose('exec', '-T', 'n8n', 'n8n', 'publish:workflow', '--id=' + workflow['id'])
    compose('restart', 'n8n')
    compose('up', '-d', '--wait', '--wait-timeout', '180', 'n8n')


def configure():
    status, body = http('http://127.0.0.1:' + env_values()['TICKET_PORT'] + '/api/v1/tickets?status=open,responding,verified')
    if status != 200 or body.get('count', 0):
        raise RuntimeError('Complete existing S7 tickets before reconfiguration.')
    if STATE.exists():
        graylog('/events/definitions/' + json.loads(STATE.read_text())['definition'] + '/unschedule', {}, 'PUT')
    baseline(); scope_api(); install_n8n()
    def ensure(path, collection, body):
        old = next((x for x in graylog(path).get(collection, []) if x.get('title') == body['title']), None)
        if old:
            return old['id']
        result = graylog(path, body)
        return next(result[k] for k in ('id', 'input_id', 'stream_id') if k in result)
    input_id = ensure('/system/inputs', 'inputs', {'title': 'Portfolio S7 trusted GELF HTTP',
        'type': 'org.graylog2.inputs.gelf.http.GELFHttpInput', 'global': True,
        'configuration': {'bind_address': '0.0.0.0', 'port': 12202, 'number_worker_threads': 2,
                          'recv_buffer_size': 1048576, 'max_message_size': 2097152, 'tls_enable': False, 'enable_cors': False}})
    index = next(x['id'] for x in graylog('/system/indices/index_sets')['index_sets'] if x['default'])
    stream = ensure('/streams', 'streams', {'title': 'Portfolio S7 trusted Wazuh', 'description': 'Fixed personal FIM candidates',
        'index_set_id': index, 'matching_type': 'AND', 'remove_matches_from_default_stream': False,
        'rules': [{'type': 1, 'field': 'source', 'value': 'haedam-wazuh', 'inverted': False, 'description': 'Owned relay'}]})
    graylog('/streams/' + stream + '/resume', {}, 'POST')
    url = 'http://n8n:5678/webhook/haedam-s7-respond'
    allowlist = graylog('/system/urlwhitelist')
    entries = [e for e in allowlist.get('entries', []) if e.get('id') != 'portfolio-s7']
    entries.append({'id': 'portfolio-s7', 'type': 'literal', 'title': 'Portfolio S7 n8n', 'value': url})
    graylog('/system/urlwhitelist', {'entries': entries, 'disabled': False}, 'PUT')
    notification = json.loads((ROOT / 'lab/s8s10/graylog/s8-s10-n8n-notification.json').read_text(encoding='utf-8'))
    notification['title'] = 'Portfolio S7 authenticated n8n'
    notification['config'].update(url=url, api_key_as_header=True, api_key='X-S7-Detection-Key',
        api_secret=env_values()['S7_DETECTION_KEY'], headers='', body_template=json.dumps({
            'event_id': '${event.id}', 'event_key': '${event.fields.event_key}', 'asset_id': 'haedam-portal',
            'case_id': 'S7', 'detected_at': '${event.timestamp_processing}'}))
    notif = ensure('/events/notifications', 'notifications', notification)
    notification['id'] = notif; graylog('/events/notifications/' + notif, notification, 'PUT')
    definition = json.loads((ROOT / 'infra/graylog/s7-fim.json').read_text(encoding='utf-8'))
    definition['config']['streams'] = [stream]
    definition['notifications'] = [{'notification_id': notif, 'notification_parameters': None}]
    ident = ensure('/events/definitions', 'event_definitions', definition)
    definition['id'] = ident; graylog('/events/definitions/' + ident, definition, 'PUT')
    graylog('/events/definitions/' + ident + '/unschedule', {}, 'PUT')
    STATE.write_text(json.dumps(dict(input=input_id, stream=stream, notification=notif, definition=ident), indent=2))
    compose('up', '-d', '--build', 's7-response')
    print('S7 configured; detection paused until a bounded test or explicit enable.')


def main():
    p = argparse.ArgumentParser(); p.add_argument('command', choices=['init', 'up', 'ready', 'configure', 'enable', 'pause', 'status', 'stop'])
    args = p.parse_args()
    if args.command == 'init':
        return init()
    bind()
    if args.command == 'up':
        up()
    elif args.command in ('enable', 'pause'):
        ident = json.loads(STATE.read_text())['definition']
        graylog('/events/definitions/' + ident + ('/schedule' if args.command == 'enable' else '/unschedule'), {}, 'PUT')
    elif args.command in ('status', 'stop'):
        print(compose('ps' if args.command == 'status' else 'stop'))
    else:
        globals()[args.command]()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit(scrub(str(exc)))
