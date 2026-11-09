"""Personal S7: trusted FIM claim -> ticket -> guarded AR -> measured effect.

Reuses the structural node builder only; does not change/install H1 workflows.
"""
import argparse
import json
import sys
from build_h1_workflows import Flow as BaseFlow, ROOT

sys.path.insert(0, str(ROOT / 'services/s7-response'))
from settings import load_settings
SETTINGS = load_settings()
URLS = SETTINGS['urls']
OUTPUT = ROOT / 'infra/n8n/portfolio-s7'


class Flow(BaseFlow):
    def __init__(self, operation):
        super().__init__(operation)
        node = self.nodes[0]
        node['parameters']['path'] = 'haedam-s7-' + operation
        node['webhookId'] = 'haedam-s7-' + operation
        credential = 's7DetectionAuth' if operation == 'respond' else 's7OperatorAuth'
        node['credentials']['httpHeaderAuth'] = {'id': credential, 'name': credential}

    def code(self, name, code, guard=True):
        code = code.replace('__ASSET__', json.dumps(SETTINGS['asset_id']))
        code = code.replace('__GROUP_PREFIX__', json.dumps('S7:' + SETTINGS['asset_id'] + ':'))
        super().code(name, code, guard)

    def http(self, name, url, credential='s7TicketAuth', body=None, idem=None):
        super().http(name, url, credential, body, idem)
        self.nodes[-1]['parameters']['options']['timeout'] = 45000

    def finish(self):
        data = super().finish()
        data.update(id='portfolioS7' + self.op.title(), name='[Portfolio S7] ' + self.op)
        return data


RECORD = """
const record={seat:'C',case_id:'S7',group_key:x.group_key,title:'S7 파일 무결성: '+x.file_key,
asset_id:__ASSET__,event_ids:[x.graylog_event_id,x.wazuh_event_id],
detected_at:x.detected_at,condition_met_at:x.alert_at,stage:'detected',action:null};
"""
ACTION = """
const action={bot:'117',via:'wazuh-ar',action:x.result==='released'?'complete_'+x.action:x.action,target:x.file_key,result:x.result,
applied_verified:true,effect_verified:true,requested_at:x.requested_at,finished_at:x.finished_at,
effect_verified_at:x.effect_verified_at,n8n_execution_id:x.execution_id,
detail:'Guarded agent receipt, full baseline hashes and real HTTP readback verified.'};
"""


def build():
    f = Flow('respond')
    f.code('Validate', """
const b=r.body||{};
if(Object.keys(b).sort().join(',')!=='asset_id,case_id,detected_at,event_id,event_key') return fail('invalid_fields',400);
if(b.case_id!=='S7'||b.asset_id!==__ASSET__||!/^[0-9a-f]{64}$/.test(b.event_key||'')||
 !/^[0-9A-Z]{26}$/.test(b.event_id||'')||!Number.isFinite(Date.parse(b.detected_at))) return fail('invalid_scope',400);
return emit({event_key:b.event_key,graylog_event_id:b.event_id,detected_at:b.detected_at,execution_id:String($execution.id)});
""")
    f.http('Claim trusted event', URLS['gateway'] + '/claim', 's7BridgeAuth', body='={{ JSON.stringify($json) }}')
    f.code('Prepare detection', """
if(!good||r.body?.ok!==true) return fail('held_claim',r.statusCode===503?503:409);
const x=r.body.data;
""" + RECORD + 'return emit({...x,record});')
    f.http('Record detection', URLS['ticket_api'] + '/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 's7-detected-'+$json.event_key }}")
    f.code('Check detection', """
if(!good||r.body?.ok!==true) return fail('held_detection_record',r.statusCode===409?409:503);
const x=$('Prepare detection').first().json;
if(!/^T-[0-9]{8}-[0-9]{4}$/.test(r.body.ticket_id)) return fail('invalid_ticket',409);
return emit({...x,ticket_id:r.body.ticket_id});
""")
    f.http('Current ticket', "={{ " + json.dumps(URLS['ticket_read'] + '/api/v1/tickets/') + "+$json.ticket_id }}")
    f.code('Check ticket', """
const x=$('Check detection').first().json,t=r.body?.ticket;
if(!good||r.body?.ok!==true||t?.ticket_id!==x.ticket_id||t.group_key!==x.group_key||t.case_id!=='S7'||
 !['open','responding','verified','restored'].includes(t.status)) return fail('held_ticket_scope',409);
return emit({...x,already_restored:t.status==='restored'});
""")
    f.http('Guarded response', URLS['gateway'] + '/respond', 's7BridgeAuth',
           body='={{ JSON.stringify({event_key:$json.event_key,ticket_id:$json.ticket_id}) }}')
    f.code('Prepare applied', """
if(!good||r.body?.ok!==true) return fail('held_response',r.statusCode===503?503:409);
const previous=$('Check ticket').first().json,x=r.body.data;
if(x.ticket_id!==previous.ticket_id||x.event_key!==previous.event_key||x.result!=='applied') return fail('invalid_response',409);
if(previous.already_restored) return emit({ok:true,stop:true,status:200,verdict:'already_restored',ticket_id:x.ticket_id});
""" + RECORD + ACTION + "return emit({...x,record:{...record,stage:'applied',action}});")
    f.http('Record applied', URLS['ticket_api'] + '/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 's7-applied-'+$json.event_key }}")
    f.code('Prepare effect', """
const x=$('Prepare applied').first().json;
if(!good||r.body?.ok!==true||r.body.ticket_id!==x.ticket_id) return fail('held_applied_record',r.statusCode===409?409:503);
return emit({...x,record:{...x.record,stage:'effect'}});
""")
    f.http('Record effect', URLS['ticket_api'] + '/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 's7-effect-'+$json.event_key }}")
    f.code('Final', """
const x=$('Prepare effect').first().json;
if(!good||r.body?.ok!==true||r.body.ticket_id!==x.ticket_id||r.body.status!=='verified') return fail('held_effect_record',r.statusCode===409?409:503);
return emit({ok:true,status:200,verdict:'verified',ticket_id:x.ticket_id,event_key:x.event_key});
""", False)
    respond = f.finish()

    f = Flow('complete')
    f.code('Validate', """
const b=r.body||{};
if(Object.keys(b).sort().join(',')!=='asset_id,case_id,event_key,ticket_id') return fail('invalid_fields',400);
if(b.case_id!=='S7'||b.asset_id!==__ASSET__||!/^[0-9a-f]{64}$/.test(b.event_key||'')||
 !/^T-[0-9]{8}-[0-9]{4}$/.test(b.ticket_id||'')) return fail('invalid_scope',400);
return emit({event_key:b.event_key,ticket_id:b.ticket_id,execution_id:String($execution.id)});
""")
    f.http('Current ticket', "={{ " + json.dumps(URLS['ticket_read'] + '/api/v1/tickets/') + "+$json.ticket_id }}")
    f.code('Check ticket', """
const x=$('Validate').first().json,t=r.body?.ticket;
if(!good||r.body?.ok!==true||t?.ticket_id!==x.ticket_id||t.group_key!==__GROUP_PREFIX__+x.event_key||
 t.case_id!=='S7'||t.asset_id!==__ASSET__||!['verified','restored'].includes(t.status)) return fail('held_ticket_scope',409);
return emit(x);
""")
    f.http('Complete owned response', URLS['gateway'] + '/complete', 's7CompleteAuth', body='={{ JSON.stringify($json) }}')
    f.code('Prepare released', """
if(!good||r.body?.ok!==true) return fail('held_completion',r.statusCode===503?503:409);
const x=r.body.data,p=$('Validate').first().json;
if(x.event_key!==p.event_key||x.ticket_id!==p.ticket_id||x.result!=='released') return fail('invalid_completion',409);
""" + RECORD + ACTION + "return emit({...x,record:{...record,stage:'released',action}});")
    f.http('Record released', URLS['ticket_api'] + '/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 's7-released-'+$json.event_key }}")
    f.code('Final', """
const x=$('Prepare released').first().json;
if(!good||r.body?.ok!==true||r.body.ticket_id!==x.ticket_id||r.body.status!=='restored') return fail('held_release_record',r.statusCode===409?409:503);
return emit({ok:true,status:200,verdict:'restored',ticket_id:x.ticket_id,event_key:x.event_key});
""", False)
    return {'s7-respond.json': respond, 's7-complete.json': f.finish()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, flow in build().items():
        text = json.dumps(flow, ensure_ascii=False, indent=2) + '\n'
        if args.check:
            assert (OUTPUT / name).read_text(encoding='utf-8') == text, name
        else:
            (OUTPUT / name).write_text(text, encoding='utf-8')
    print('S7: two workflows ' + ('checked' if args.check else 'generated'))
