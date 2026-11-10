"""Build the personal S10 deployment: the reviewed S8 deployment patches for case S10 and its one lab source,
plus the team pfSense workflow (haedam-14) calling the controller relay instead of n8n's SSH node.

The team contract is kept: ticket first (no action if it fails), portal block then pfSense block, each recorded;
success only when every expected action is applied and read back; release undoes both for the owning ticket.
n8n's SSH node cannot pin a host key, so the relay runs the adapter over SSH with the pinned key and forced command.
"""
import argparse
import json
from pathlib import Path

import build_s8_workflows as s8

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'infra/n8n/portfolio-s10'
SETTINGS = json.loads((ROOT / 'infra/pfsense/lab-settings.json').read_text(encoding='utf-8'))
ATTACK_IP = SETTINGS['clients']['attacker']
RELAY_URL = f"http://controller:{SETTINGS['s10']['relay_port']}/pf"
CREDENTIALS = {'detection': 's10DetectionAuth', 'operator': 's10OperatorAuth',
               'ticket': 's10TicketAuth', 'portal': 's10PortalAuth'}
RELAY_CREDENTIAL = 's10RelayAuth'
PF_WORKFLOW = 'haedam-14-pfsense-block.json'


def relay_node(ssh):
    return {'id': ssh['id'], 'name': 'pfSense relay (haedam-pf-response)', 'type': 'n8n-nodes-base.httpRequest',
            'typeVersion': 4.2, 'position': ssh['position'], 'onError': 'continueRegularOutput', 'retryOnFail': False,
            'credentials': {'httpHeaderAuth': {'id': RELAY_CREDENTIAL, 'name': RELAY_CREDENTIAL}},
            'parameters': {'method': 'POST', 'url': RELAY_URL, 'authentication': 'genericCredentialType',
                           'genericAuthType': 'httpHeaderAuth', 'sendBody': True, 'specifyBody': 'json',
                           'jsonBody': '={{ JSON.stringify({action:$json.action,target:$json.ip,'
                                       'request_id:$json.request_id,owner_id:$json.owner_id}) }}',
                           'options': {'timeout': 120000}}}


def build():
    result = s8.build(case='S10', attack_ip=ATTACK_IP, credentials=CREDENTIALS)
    w = result[PF_WORKFLOW]
    nodes = []
    for node in w['nodes']:
        p = node['parameters']
        if node['type'].endswith('.code') and 'function protectedIp(ip)' in p['jsCode']:
            code = p['jsCode']
            start = code.index('function protectedIp(ip)')
            end = code.index('\n}', start) + 2
            p['jsCode'] = (code[:start] + f"function protectedIp(ip) {{ return ip === '{ATTACK_IP}' ? null : "
                           "'outside_s10_lab_target'; }" + code[end:])
        if node['type'].endswith('.ssh'):
            old, node = node['name'], relay_node(node)
            w['connections'][node['name']] = w['connections'].pop(old)
            for outputs in w['connections'].values():
                for lane in outputs['main']:
                    for target in lane:
                        if target['node'] == old:
                            target['node'] = node['name']
        nodes.append(node)
    if not any(n['name'].startswith('pfSense relay') for n in nodes):
        raise ValueError('Upstream haedam-14 changed: SSH node not found')
    w['nodes'] = nodes
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, workflow in build().items():
        data = json.dumps(workflow, ensure_ascii=False, indent=2) + '\n'
        path = OUTPUT / name
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8') != data:
                raise SystemExit(f'S10 export differs: {name}')
        else:
            path.write_text(data, encoding='utf-8')
    print(f"S10 deployment: {len(build())} workflows {'checked' if args.check else 'generated'}")


if __name__ == '__main__':
    main()
