"""H1-only workflows. Credentials stay in n8n; HTTP errors fail closed.

Original individual implementation. Team ticket API by Kim Sanghyeok is reused.
The validated S8 exports are not rewritten or installed by this builder.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'infra/n8n/portfolio-h1'

HELPERS = """
const fail=(code,status=503)=>[{json:{ok:false,stop:true,status,verdict:code}}];
const emit=x=>[{json:x}];
const r=$input.first().json;
const good=r.statusCode>=200 && r.statusCode<300;
"""


class Flow:
    def __init__(self, operation):
        self.nodes, self.links, self.last = [], {}, None
        self.op = operation
        self.add('Webhook', 'webhook', {
            'httpMethod': 'POST', 'path': 'haedam-h1-' + operation,
            'responseMode': 'responseNode', 'authentication': 'headerAuth', 'options': {}}, 2,
            'h1DetectionAuth' if operation == 'restrict' else 'h1OperatorAuth')
        self.nodes[-1]['webhookId'] = 'haedam-h1-' + operation

    def link(self, left, right, branch=0):
        lanes = self.links.setdefault(left, {'main': [[]]})['main']
        while len(lanes) <= branch:
            lanes.append([])
        lanes[branch] = [{'node': right, 'type': 'main', 'index': 0}]

    def add(self, name, kind, params, version=2, credential=None):
        node = {'id': self.op + '-' + name.replace(' ', '-'), 'name': name,
                'type': 'n8n-nodes-base.' + kind, 'typeVersion': version,
                'position': [len(self.nodes) * 220, 0], 'parameters': params}
        if credential:
            node['credentials'] = {'httpHeaderAuth': {'id': credential, 'name': credential}}
        self.nodes.append(node)
        if self.last:
            self.link(self.last, name)
        self.last = name

    def code(self, name, code, guard=True):
        self.add(name, 'code', {'jsCode': HELPERS + code})
        if guard:
            self.add(name + ' proceed', 'if', {'conditions': {
                'options': {'caseSensitive': True, 'leftValue': '', 'typeValidation': 'strict', 'version': 2},
                'conditions': [{'id': name + '-gate', 'leftValue': '={{ $json.stop !== true }}',
                    'rightValue': '', 'operator': {'type': 'boolean', 'operation': 'true', 'singleValue': True}}],
                'combinator': 'and'}, 'options': {}}, 2.2)
            self.link(self.last, 'Respond', 1)

    def http(self, name, url, credential='h1TicketAuth', body=None, idem=None):
        params = {'method': 'POST' if body else 'GET', 'url': url,
            'authentication': 'genericCredentialType', 'genericAuthType': 'httpHeaderAuth',
            'options': {'timeout': 10000, 'response': {'response': {'fullResponse': True, 'neverError': True}}}}
        if body:
            params.update(sendBody=True, specifyBody='json', jsonBody=body)
        if idem:
            params.update(sendHeaders=True, headerParameters={'parameters': [{'name': 'Idempotency-Key', 'value': idem}]})
        self.add(name, 'httpRequest', params, 4.2, credential)
        self.nodes[-1].update(onError='continueRegularOutput', retryOnFail=False)

    def finish(self):
        self.add('Respond', 'respondToWebhook', {'respondWith': 'json', 'responseBody': '={{ JSON.stringify($json) }}',
            'options': {'responseCode': '={{ $json.status || 200 }}'}}, 1.1)
        return {'id': 'portfolioH1' + self.op.title(), 'name': '[Portfolio H1] ' + self.op,
                'active': False, 'nodes': self.nodes, 'connections': self.links,
                'settings': {'executionOrder': 'v1', 'saveDataSuccessExecution': 'none',
                    'saveDataErrorExecution': 'none', 'saveManualExecutions': False, 'saveExecutionProgress': False}}


VALIDATE = """
const b=r.body||{};
if(b.case_id!=='H1'||b.asset_id!=='haedam-portal'||b.username!=='h1_abuse') return fail('invalid_scope',400);
const x={username:b.username,group_key:'H1:haedam-portal:'+b.username};
"""
RECORD = """
const record={seat:'B',case_id:'H1',group_key:x.group_key,title:'H1 민원 작성 도배',asset_id:'haedam-portal',
username:x.username,event_ids:[x.event_id],detected_at:x.detected_at,stage:'detected',action:null};
"""


def build():
    f = Flow('restrict')
    f.code('Validate', VALIDATE + """
if(!/^[0-9A-Z]{26}$/.test(b.event_id||'') || !Number.isFinite(Date.parse(b.detected_at))) return fail('invalid_event',400);
x.event_id=b.event_id; x.detected_at=b.detected_at;
""" + RECORD + "return emit({...x,record});")
    f.http('Record detection', 'http://ticket-store:8088/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 'h1-detected-' + $json.event_id }}")
    f.code('Detection recorded', """
if(!good||r.body?.ok!==true) return fail('held_ticket_record');
const t=r.body, x=$('Validate').first().json;
if(!/^T-[0-9]{8}-[0-9]{4}$/.test(t.ticket_id)||!['open','responding','verified'].includes(t.status)) return fail('held_old_event',409);
return emit({...x,ticket_id:t.ticket_id});
""")
    f.http('Current ticket', "={{ 'http://ticket-store:8088/api/v1/tickets/open?seat=B&group_key='+encodeURIComponent($json.group_key) }}")
    f.code('Check current', """
const x=$('Detection recorded').first().json,t=r.body;
if(!good||t?.ok!==true||t.ticket_id!==x.ticket_id||!['open','responding','verified'].includes(t.status)||!Array.isArray(t.applied_actions)) return fail('held_current_ticket',409);
if(t.applied_actions.some(a=>a.via==='portal'&&a.action==='restrict_write'&&a.target===x.username))
 return emit({ok:true,stop:true,status:200,verdict:'duplicate_no_action',ticket_id:x.ticket_id});
return emit({...x,requested_at:new Date().toISOString()});
""")
    f.http('Restrict portal', 'http://portal-response:5000/api/v1/response/petitions/restrict', 'h1PortalAuth',
           body='={{ JSON.stringify({username:$json.username,ticket_id:$json.ticket_id}) }}',
           idem="={{ 'h1-restrict-'+$json.ticket_id }}")
    f.code('Check mutation', """
const x=$('Check current').first().json,d=r.body?.data;
if(!good||r.body?.success!==true||d?.restricted!==true||d.ticket_id!==x.ticket_id||d.username!==x.username) return fail('held_portal_restrict');
return emit({...x,finished_at:new Date().toISOString()});
""")
    f.http('Read restriction', "={{ 'http://portal-response:5000/api/v1/response/petitions/restrictions/'+$json.username }}", 'h1PortalAuth')
    f.code('Prepare applied', """
const x=$('Check mutation').first().json,d=r.body?.data;
if(!good||r.body?.success!==true||d?.restricted!==true||d.ticket_id!==x.ticket_id||d.username!==x.username) return fail('held_portal_readback');
const action={bot:'112',via:'portal',action:'restrict_write',target:x.username,result:'applied',applied_verified:true,
effect_verified:null,requested_at:x.requested_at,finished_at:x.finished_at,effect_verified_at:null,n8n_execution_id:String($execution.id),detail:'Write restriction read back; HTTP effect is measured separately.'};
return emit({...x,record:{...x.record,stage:'applied',action}});
""")
    f.http('Record applied', 'http://ticket-store:8088/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 'h1-applied-'+$json.ticket_id+'-'+$execution.id }}")
    f.code('Final', """
const x=$('Prepare applied').first().json;
if(!good||r.body?.ok!==true||r.body.ticket_id!==x.ticket_id) return fail('held_applied_record');
return emit({ok:true,status:200,verdict:'restricted',ticket_id:x.ticket_id});
""", False)
    restrict = f.finish()

    f = Flow('release')
    f.code('Validate', VALIDATE + """
if(!/^T-[0-9]{8}-[0-9]{4}$/.test(b.ticket_id||'')) return fail('invalid_ticket',400);
return emit({...x,ticket_id:b.ticket_id});
""")
    f.http('Current ticket', "={{ 'http://ticket-store:8088/api/v1/tickets/open?seat=B&group_key='+encodeURIComponent($json.group_key) }}")
    f.code('Check current', """
const x=$('Validate').first().json,t=r.body;
if(!good||t?.ok!==true) return fail('held_ticket_lookup');
if(t.ticket_id!==x.ticket_id) return fail('held_stale_release',409);
if(t.status==='restored') return emit({ok:true,stop:true,status:200,verdict:'already_restored',ticket_id:x.ticket_id});
if(!['responding','verified'].includes(t.status)) return fail('held_ticket_status',409);
return emit(x);
""")
    f.http('Ticket details', "={{ 'http://ticket-store:8089/api/v1/tickets/'+$json.ticket_id }}")
    f.code('Check details', """
const x=$('Validate').first().json,t=r.body?.ticket;
if(!good||r.body?.ok!==true||t?.ticket_id!==x.ticket_id||t.case_id!=='H1'||t.asset_id!=='haedam-portal'||t.group_key!==x.group_key||t.username!==x.username||!t.event_ids?.length) return fail('held_ticket_scope',409);
x.event_id=t.event_ids[0];x.detected_at=t.detected_at;
""" + RECORD + "return emit({...x,record});")
    f.http('Active claims', "={{ 'http://ticket-store:8088/api/v1/tickets/active?asset_id=haedam-portal&via=portal&action=restrict_write&target='+$json.username }}")
    f.code('Check claims', """
const x=$('Check details').first().json,t=r.body?.tickets;
if(!good||r.body?.ok!==true||!Array.isArray(t)||t.length!==1||t[0].ticket_id!==x.ticket_id) return fail('held_other_claim',409);
return emit({...x,requested_at:new Date().toISOString()});
""")
    f.http('Release portal', 'http://portal-response:5000/api/v1/response/petitions/release', 'h1PortalAuth',
           body='={{ JSON.stringify({username:$json.username,ticket_id:$json.ticket_id}) }}',
           idem="={{ 'h1-release-'+$json.ticket_id }}")
    f.code('Check mutation', """
const x=$('Check claims').first().json,d=r.body?.data;
if(!good||r.body?.success!==true||d?.restricted!==false||d.ticket_id!==x.ticket_id||d.username!==x.username) return fail('held_portal_release');
return emit({...x,finished_at:new Date().toISOString()});
""")
    f.http('Read restriction', "={{ 'http://portal-response:5000/api/v1/response/petitions/restrictions/'+$json.username }}", 'h1PortalAuth')
    f.code('Prepare released', """
const x=$('Check mutation').first().json,d=r.body?.data;
if(!good||r.body?.success!==true||d?.restricted!==false||d.ticket_id!==null||d.username!==x.username) return fail('held_release_readback');
const action={bot:'112',via:'portal',action:'restrict_write',target:x.username,result:'released',applied_verified:true,
effect_verified:null,requested_at:x.requested_at,finished_at:x.finished_at,effect_verified_at:null,n8n_execution_id:String($execution.id),detail:'Approved with H1 operator credential; no role or session changes.'};
return emit({...x,record:{...x.record,stage:'released',action}});
""")
    f.http('Record released', 'http://ticket-store:8088/api/v1/tickets/record',
           body='={{ JSON.stringify($json.record) }}', idem="={{ 'h1-released-'+$json.ticket_id+'-'+$execution.id }}")
    f.code('Final', """
const x=$('Prepare released').first().json;
if(!good||r.body?.ok!==true||r.body.ticket_id!==x.ticket_id||r.body.status!=='restored') return fail('held_release_record');
return emit({ok:true,status:200,verdict:'restored',ticket_id:x.ticket_id});
""", False)
    return {'h1-restrict.json': restrict, 'h1-release.json': f.finish()}


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
                raise SystemExit('H1 export differs: ' + name)
        else:
            path.write_text(data, encoding='utf-8')
    print('H1: two workflows ' + ('checked' if args.check else 'generated'))


if __name__ == '__main__':
    main()
