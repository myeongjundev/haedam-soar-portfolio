"""Build the explicit personal S8 deployment from attributed team exports.

No credentials in output. Legacy S1/S4/S7/S10/S12 and offline candidates are
not installed by this deployment. Fail loudly when upstream node code changes.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'infra/n8n/workflows'
OUTPUT = ROOT / 'infra/n8n/portfolio-s8'
SELECTED = ('10', '11', '12', '14', '32', '40', '50')
ATTACK_IP = '172.30.88.21'


def replace(code, old, new):
    if old not in code:
        raise ValueError(f'Upstream code changed: {old[:70]}')
    return code.replace(old, new)


def build():
    result = {}
    for number in SELECTED:
        source = next(SOURCE.glob(f'haedam-{number}-*.json'))
        w = json.loads(source.read_text(encoding='utf-8'))
        if isinstance(w, list):
            w, = w
        w['active'] = False
        w['name'] = '[Portfolio S8] ' + w['name']
        w['settings'].update(saveDataSuccessExecution='none', saveDataErrorExecution='none',
                             saveManualExecutions=False, saveExecutionProgress=False)
        for node in w['nodes']:
            p, kind = node['parameters'], node['type'].split('.')[-1]
            if number == '12' and isinstance(p.get('url'), str):
                p['url'] = p['url'].replace('http://portal:5000', 'http://portal-response:5000')
            if kind == 'webhook':
                p['authentication'] = 'headerAuth'
                credential = 's8DetectionAuth' if number == '32' else 's8OperatorAuth'
                node['credentials'] = {'httpHeaderAuth': {'id': credential, 'name': credential}}
            if kind == 'httpRequest' and p.get('genericAuthType') == 'httpHeaderAuth':
                credential = 's8TicketAuth' if number == '10' else 's8PortalAuth'
                node['credentials'] = {'httpHeaderAuth': {'id': credential, 'name': credential}}
            if kind == 'respondToWebhook':
                # A completed n8n execution is not necessarily a successful action.
                p.setdefault('options', {})['responseCode'] = "={{ $json.ok === false || $json.bad === true || $json.verdict === 'invalid_input' ? ($json.verdict === 'invalid_input' || $json.bad === true ? 400 : 503) : ($json.verdict?.startsWith('held_') ? 409 : 200) }}"
            if kind != 'code':
                continue
            code = p['jsCode']
            if number == '12':
                code = code.replace('http://portal:5000', 'http://portal-response:5000')
            if number in ('12', '32') and 'function protectedIp(ip)' in code:
                start = code.index('function protectedIp(ip)')
                end = code.index('\n}', start) + 2
                code = code[:start] + f"function protectedIp(ip) {{ return ip === '{ATTACK_IP}' ? null : 'outside_s8_lab_target'; }}" + code[end:]
            if number == '32' and "const t = { ...($input.first().json.body || {}) };" in code:
                code = replace(code, "const t = { ...($input.first().json.body || {}) };",
                    "const t = { ...($input.first().json.body || {}) };\n"
                    "if (t.case_id !== 'S8' || t.asset_id !== 'haedam-portal') return [{json:{ok:false,verdict:'invalid_input',no_action:true}}];")
            if number == '40' and 'const CFG = { dry_run: true };' in code:
                code = replace(code, 'const CFG = { dry_run: true };',
                    'const CFG = { dry_run: false, store_real: true };')
                code = replace(code, 'const b = $input.first().json.body || {};',
                    "const b = $input.first().json.body || {};\n"
                    f"if (b.seat !== 'B' || b.case_id !== 'S8' || b.asset_id !== 'haedam-portal' || b.group_key !== '{ATTACK_IP}' || b.target !== '{ATTACK_IP}' || b.via !== 'portal' || String(b.bot) !== '112' || b.action !== 'block') return [{{json:{{ok:false,bad:true,verdict:'invalid_input'}}}}];")
            if number == '50' and 'live_release_enabled: false' in code:
                code = replace(code, 'const CFG = { dry_run: true, live_release_enabled: false };',
                    'const CFG = { dry_run: false, store_real: true, live_release_enabled: true };')
                code = replace(code, 'const b = $input.first().json.body || {};',
                    "const b = {...($input.first().json.body || {}), approver: 'portfolio-operator'};\n"
                    f"if (b.seat !== 'B' || b.case_id !== 'S8' || b.asset_id !== 'haedam-portal' || b.group_key !== '{ATTACK_IP}' || !/^T-\\d{{8}}-\\d{{4}}$/.test(b.ticket_id || '')) return [{{json:{{ok:false,stop:true,verdict:'invalid_input'}}}}];")
                code = replace(code, 'const X = { seat: b.seat,', 'const X = { requested_ticket_id: b.ticket_id, seat: b.seat,')
            if number == '50' and "const selected=actions.filter" in code:
                code = replace(code, 'const actions=j.actions.map',
                    "if (j.ticket_id !== x.requested_ticket_id) return held(x,'held_stale_release_ticket');\nconst actions=j.actions.map")
            # Existing response lists may be unavailable despite a 200 mutation response.
            if number == '32' and 'verdict: x.cfg.dry_run' in code:
                code = code.replace("['failed','rejected'].includes(s.result)",
                                    "['failed','rejected'].includes(s.result) || (s.result !== 'skipped' && s.applied_verified !== true)")
            if number == '32' and "const res = { step:" in code:
                code = code.replace('result: r.result, detail: r.detail', 'result: r.result, applied_verified: r.applied_verified ?? null, detail: r.detail')
            if number == '50' and "r.applied_verified === false" in code:
                code = code.replace("r.applied_verified === false", "r.applied_verified !== true")
            p['jsCode'] = code
        if number == '40':
            # Bind delayed evidence to the exact ticket cycle before recording it.
            def code_node(name, code):
                return {'id': name, 'name': name, 'type': 'n8n-nodes-base.code', 'typeVersion': 2,
                        'position': [500, 300], 'parameters': {'jsCode': code}}
            prepare = code_node('Current effect ticket input',
                "const r=$input.first().json; const id=$('Webhook').first().json.body.ticket_id;\n"
                "if (!/^T-\\d{8}-\\d{4}$/.test(id||'')) throw new Error('EFFECT_TICKET_REQUIRED');\n"
                "return [{json:{mode:'check',seat:r.seat,group_key:r.group_key,ctx:{cfg:r.ctx.cfg,expected_ticket_id:id,effect_record:r}}}];")
            check = {'id': 's8-effect-check', 'name': 'Check current effect ticket',
                     'type': 'n8n-nodes-base.executeWorkflow', 'typeVersion': 1.2, 'position': [700, 300],
                     'parameters': {'source': 'database', 'workflowId': {'__rl': True, 'value': 'haedamResultLog01', 'mode': 'id'}, 'options': {}}}
            match = code_node('Match effect ticket',
                "const r=$input.first().json;\n"
                "if(r.ok!==true || !r.exists || r.ticket_id!==r.ctx.expected_ticket_id || !['responding','verified'].includes(r.status)) throw new Error('STALE_EFFECT_TICKET');\n"
                "return [{json:r.ctx.effect_record}];")
            existing = w['connections']['검증 통과?']['main'][0]
            w['connections']['검증 통과?']['main'][0] = [{'node': prepare['name'], 'type': 'main', 'index': 0}]
            for left, right in ((prepare, check), (check, match)):
                w['connections'][left['name']] = {'main': [[{'node': right['name'], 'type': 'main', 'index': 0}]]}
            w['connections'][match['name']] = {'main': [existing]}
            w['nodes'].extend([prepare, check, match])
        if number == '11':
            # This solo lab has no external notification destination. Never claim sent.
            trigger = next(n for n in w['nodes'] if n['type'].endswith('.executeWorkflowTrigger'))
            output = {'id': 's8-local-notice', 'name': 'Local ticket notification',
                      'type': 'n8n-nodes-base.code', 'typeVersion': 2, 'position': [260, 0],
                      'parameters': {'jsCode': "return [{json:{ctx:$input.first().json.ctx,sent:false,error:null,notification_channel:'ticket-dashboard'}}];"}}
            w['nodes'] = [trigger, output]
            w['connections'] = {trigger['name']: {'main': [[{'node': output['name'], 'type': 'main', 'index': 0}]]}}
        result[source.name] = w
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
                raise SystemExit(f'S8 export differs: {name}')
        else:
            path.write_text(data, encoding='utf-8')
    print('S8 deployment: 7 workflows checked' if args.check else 'S8 deployment: 7 workflows generated')


if __name__ == '__main__':
    main()
