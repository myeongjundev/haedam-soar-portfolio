"""Manage the personal S10 lab: the P04 pfSense lab plus Graylog, n8n and tickets (project from lab-settings.json).

  init      add S10 secrets/ports to .env.pf (existing values kept; nothing printed)
  up        start every service (pfSense VM keeps its disk)
  pfsense   send pfSense syslog to Graylog and add the logged WAN ICMP block (config.xml through the transfer disk)
  configure n8n credentials/workflows, Graylog inputs/streams/pipeline/S10 definition/notification (paused)
  enable|pause|status|stop
Standard library only. Addresses, ports and identities come from infra/pfsense/lab-settings.json.
"""
import argparse
import base64
import hashlib
import json
import re
import secrets
from pathlib import Path
from urllib.parse import urlencode

import pf_lab as lab
from build_s10_workflows import build
from s8_lab import http

lab.FILES = ['compose.yaml', 'compose.soc.yaml', 'compose.pf.yaml', 'compose.s10.yaml']
S = lab.SETTINGS
S10 = S['s10']
STATE = lab.LOCAL / 's10-state.json'
WEBHOOK = 'haedam-s8-s10'
SECRETS = ('GRAYLOG_ADMIN_PASSWORD', 'GRAYLOG_PASSWORD_SECRET', 'N8N_ENCRYPTION_KEY', 'TICKET_STORE_KEY',
           'PORTAL_RESPONSE_KEY', 'S10_DETECTION_KEY', 'S10_OPERATOR_KEY', 'PF_RELAY_KEY')
PORTS = {'GRAYLOG_PORT': '19140', 'N8N_PORT': '15740', 'TICKET_PORT': '18140', 'GELF_PORT': '22340'}


def init():
    values = lab.env_values()
    if not values.get('PFSENSE_ISO'):
        raise SystemExit('Run tools/pf_lab.py init --iso PATH first.')
    for key in SECRETS:
        values.setdefault(key, secrets.token_hex(48 if key == 'GRAYLOG_PASSWORD_SECRET' else 32))
    values['GRAYLOG_ROOT_PASSWORD_SHA2'] = hashlib.sha256(values['GRAYLOG_ADMIN_PASSWORD'].encode()).hexdigest()
    for key, value in PORTS.items():
        values.setdefault(key, value)
    lab.ENV.write_text(''.join(f'{k}={v}\n' for k, v in values.items()), encoding='utf-8')
    print('S10 secrets and ports added to .env.pf (local only; values not printed).')


def graylog(path, data=None, method=None):
    env = lab.env_values()
    auth = base64.b64encode(('admin:' + env['GRAYLOG_ADMIN_PASSWORD']).encode()).decode()
    status, body = http(f"http://127.0.0.1:{env['GRAYLOG_PORT']}/api" + path, data,
                        {'Authorization': 'Basic ' + auth, 'X-Requested-By': 'portfolio-s10'}, method)
    if status not in (200, 201, 202, 204):
        raise RuntimeError(lab.scrub(f'Graylog {path}: HTTP {status} {body}'))
    return body


def find_create(path, collection, body, key='title'):
    for item in graylog(path).get(collection, []) if collection else graylog(path):
        if item.get(key) == body[key]:
            return item['id']
    created = graylog(path, body)
    return next(created[k] for k in ('id', 'input_id', 'stream_id') if k in created)


def install_n8n():
    env = lab.env_values()
    specs = [('s10DetectionAuth', 'X-S10-Detection-Key', 'S10_DETECTION_KEY'),
             ('s10OperatorAuth', 'X-S10-Operator-Key', 'S10_OPERATOR_KEY'),  # gitleaks:allow -- header names only
             ('s10TicketAuth', 'X-Response-Key', 'TICKET_STORE_KEY'),
             ('s10PortalAuth', 'X-Response-Key', 'PORTAL_RESPONSE_KEY'),
             ('s10RelayAuth', 'X-PF-Relay-Key', 'PF_RELAY_KEY')]
    credentials = [{'id': i, 'name': i, 'type': 'httpHeaderAuth', 'data': {'name': h, 'value': env[k]}}
                   for i, h, k in specs]
    workflows = list(build().values())
    for kind, content in (('credentials', credentials), ('workflow', workflows)):
        path = f'/tmp/s10-{kind}.json'
        try:
            lab.compose('exec', '-T', 'n8n', 'node', '-e',
                        "require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})",
                        path, stdin=json.dumps(content))
            print(lab.compose('exec', '-T', 'n8n', 'n8n', 'import:' + kind, '--input=' + path))
        finally:
            lab.compose('exec', '-T', 'n8n', 'node', '-e', "require('fs').rmSync(process.argv[1],{force:true})", path)
    for workflow in workflows:
        lab.compose('exec', '-T', 'n8n', 'n8n', 'publish:workflow', '--id=' + workflow['id'])
    lab.compose('restart', 'n8n')
    lab.compose('up', '-d', '--wait', '--wait-timeout', '180', 'n8n', timeout=300)


def pipeline_parts():
    text = (lab.ROOT / 'infra/graylog/pipelines/pfsense-parse.txt').read_text(encoding='utf-8')
    rules = re.findall(r'^rule "[^"]+"\n.*?^end$', text, re.M | re.S)
    head = re.search(r'^// (pipeline "pfsense-parse".*?)^// end$', text, re.M | re.S).group(1)
    pipeline = '\n'.join(line[3:] if line.startswith('// ') else line for line in head.splitlines()) + '\nend\n'
    return rules, pipeline


def configure():
    env = lab.env_values()
    status, body = http(f"http://127.0.0.1:{env['TICKET_PORT']}/api/v1/tickets?status=open,responding,verified")
    if status != 200 or body.get('count', 0):
        raise RuntimeError('Release active S10 tickets before reconfiguring.')
    if STATE.exists():
        graylog(f"/events/definitions/{json.loads(STATE.read_text())['definition']}/unschedule", {}, 'PUT')
    install_n8n()
    gelf = find_create('/system/inputs', 'inputs', {
        'title': 'Portfolio S10 portal GELF TCP', 'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput', 'global': True,
        'configuration': {'bind_address': '0.0.0.0', 'port': 12201, 'number_worker_threads': 2,
                          'recv_buffer_size': 1048576, 'max_message_size': 2097152, 'tls_enable': False,
                          'tcp_keepalive': True, 'use_null_delimiter': True}})
    syslog = find_create('/system/inputs', 'inputs', {
        'title': 'Portfolio S10 pfSense syslog UDP', 'type': 'org.graylog2.inputs.syslog.udp.SyslogUDPInput',
        'global': True, 'configuration': {'bind_address': '0.0.0.0', 'port': S10['syslog_port'],
                                          'recv_buffer_size': 262144, 'number_worker_threads': 2,
                                          'override_source': '', 'force_rdns': False, 'allow_override_date': True,
                                          'store_full_message': True, 'expand_structured_data': False}})
    index = next(x['id'] for x in graylog('/system/indices/index_sets')['index_sets'] if x['default'])
    portal = find_create('/streams', 'streams', {
        'title': 'Portfolio S10 portal', 'description': 'Actual portal GELF', 'index_set_id': index,
        'matching_type': 'AND', 'remove_matches_from_default_stream': False,
        'rules': [{'type': 1, 'field': 'source', 'value': 'haedam-portal', 'inverted': False, 'description': 'Portal'}]})
    pfsense = find_create('/streams', 'streams', {
        'title': 'Portfolio S10 pfSense', 'description': 'pfSense syslog UDP input only', 'index_set_id': index,
        'matching_type': 'AND', 'remove_matches_from_default_stream': False,
        'rules': [{'type': 8, 'field': 'gl2_source_input', 'value': syslog, 'inverted': False,
                   'description': 'Match the pfSense syslog input'}]})
    for stream in (portal, pfsense):
        graylog(f'/streams/{stream}/resume', {}, 'POST')
    rules, pipeline_source = pipeline_parts()
    existing = {r['title']: r for r in graylog('/system/pipelines/rule')}
    for source in rules:
        title = re.match(r'rule "([^"]+)"', source).group(1)
        body = {'title': title, 'description': 'Team pfsense-parse (attributed)', 'source': source}
        if title in existing:
            graylog('/system/pipelines/rule/' + existing[title]['id'], {**body, 'id': existing[title]['id']}, 'PUT')
        else:
            graylog('/system/pipelines/rule', body)
    pipeline = next((p for p in graylog('/system/pipelines/pipeline') if p['title'] == 'pfsense-parse'), None)
    body = {'title': 'pfsense-parse', 'description': 'Team pfSense filterlog parser', 'source': pipeline_source}
    pipeline_id = (graylog('/system/pipelines/pipeline/' + pipeline['id'], {**body, 'id': pipeline['id']}, 'PUT')
                   if pipeline else graylog('/system/pipelines/pipeline', body))['id']
    graylog('/system/pipelines/connections/to_stream', {'stream_id': pfsense, 'pipeline_ids': [pipeline_id]})
    url = f'http://n8n:5678/webhook/{WEBHOOK}'
    allow = graylog('/system/urlwhitelist')
    entries = [e for e in allow.get('entries', []) if e.get('id') != 'portfolio-s10']
    entries.append({'id': 'portfolio-s10', 'type': 'literal', 'title': 'Portfolio S10 n8n', 'value': url})
    graylog('/system/urlwhitelist', {'entries': entries, 'disabled': False}, 'PUT')
    notification = json.loads((lab.ROOT / 'lab/s8s10/graylog/s8-s10-n8n-notification.json').read_text(encoding='utf-8'))
    notification['title'] = 'Portfolio S10 authenticated n8n'
    notification['config'].update(url=url, api_key_as_header=True, api_key='X-S10-Detection-Key',
                                  api_secret=env['S10_DETECTION_KEY'], headers='')
    notification['config']['body_template'] = json.dumps({
        'event_id': '${event.id}', 'asset_id': 'haedam-portal', 'case_id': 'S10', 'src_ip': '${event.fields.src_ip}',
        'detected_at': '${event.timestamp_processing}', 'dry_run': False, 'store_real': True})
    notification_id = find_create('/events/notifications', 'notifications', notification)
    notification['id'] = notification_id
    graylog('/events/notifications/' + notification_id, notification, 'PUT')
    definition = json.loads((lab.ROOT / 'lab/s8s10/graylog/acceptance/s10-three-layer.json').read_text(encoding='utf-8'))
    query = definition['config']['query']
    # The team acceptance profile names the lab source, the WAN address and a tracker placeholder; use this lab's values.
    for old, new in (('REPLACE_input_tracker', str(S10['icmp_tracker'])), ('203.0.113.22', S['clients']['attacker']),
                     ('203.0.113.1 ', S['wan']['pfsense_ip'] + ' ')):
        if old not in query:
            raise RuntimeError('Upstream S10 query changed: ' + old)
        query = query.replace(old, new)
    definition['title'] = 'Portfolio S10 boundary + scan + login (src_ip)'
    definition['config'].update(query=query, streams=[portal, pfsense], execute_every_ms=15000,
                                search_within_ms=S10['window_minutes'] * 60000)
    definition['notification_settings']['backlog_size'] = 0
    definition['notifications'] = [{'notification_id': notification_id, 'notification_parameters': None}]
    definition_id = find_create('/events/definitions', 'event_definitions', definition)
    definition['id'] = definition_id
    graylog('/events/definitions/' + definition_id, definition, 'PUT')
    graylog(f'/events/definitions/{definition_id}/unschedule', {}, 'PUT')
    STATE.write_text(json.dumps({'gelf_input': gelf, 'syslog_input': syslog, 'portal_stream': portal,
                                 'pfsense_stream': pfsense, 'pipeline': pipeline_id, 'notification': notification_id,
                                 'definition': definition_id, 'query': query}, indent=2), encoding='utf-8')
    print('S10 configured; detection paused until tools/s10_verify.py runs.')


def pfsense():
    """Apply syslog + the logged ICMP block to the running VM (serial shell must be open)."""
    import subprocess
    target = lab.LOCAL / 'config-s10.xml'
    subprocess.run([__import__('sys').executable, str(lab.ROOT / 'tools/pf_config.py'), str(lab.LOCAL / 'default-config.xml'),
                    str(target), '--public-key', str(lab.LOCAL / 'ssh/controller.pub'),
                    '--syslog', f"{S10['graylog_ip']}:{S10['syslog_port']}"], check=True)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    lab.xfer_put(target, 'config.xml')
    status, out = lab.shell('set -e; mkdir -p /tmp/x; mount_msdosfs /dev/vtbd1 /tmp/x; cp /tmp/x/config.xml '
                            '/cf/conf/config.xml; umount /tmp/x; rm -f /tmp/config.cache; sha256 -q /cf/conf/config.xml; '
                            '/etc/rc.filter_configure_sync >/dev/null 2>&1; /usr/local/sbin/pfSsh.php playback svc '
                            'restart syslogd >/dev/null 2>&1; grep -c "@' + S10['graylog_ip'] + '" /var/etc/syslog.d/* '
                            '/etc/syslog.conf 2>/dev/null | tail -3', 60)
    if status or digest not in out:
        raise RuntimeError('pfSense config not applied: ' + out[-400:])
    print('pfSense syslog -> Graylog applied; config.xml sha256 ' + digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'up', 'pfsense', 'configure', 'enable', 'pause', 'status', 'stop'])
    args = parser.parse_args()
    if args.command == 'init':
        init()
    elif args.command == 'up':
        print(lab.compose('up', '-d', '--build', '--wait', '--wait-timeout', '300', timeout=1200)[-2000:])
    elif args.command in ('enable', 'pause'):
        ident = json.loads(STATE.read_text())['definition']
        graylog(f"/events/definitions/{ident}/{'schedule' if args.command == 'enable' else 'unschedule'}", {}, 'PUT')
    elif args.command == 'status':
        print(lab.compose('ps'))
    elif args.command == 'stop':
        print(lab.compose('stop', timeout=600))
    else:
        globals()[args.command]()


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(lab.scrub(str(error)))
