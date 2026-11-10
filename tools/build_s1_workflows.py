"""Deterministic S1 n8n/Graylog artifacts. No network, Docker or secret reads."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from s1_settings import validate

ROOT = Path(__file__).resolve().parents[1]
IDS = {'ticket': 'portfolioS1Ticket01', 'portal': 'portfolioS1Portal01',
       'respond': 'portfolioS1Respond01', 'release': 'portfolioS1Release01'}


def load_settings(settings=None, integration=None):
    s = validate(settings if settings is not None else json.loads((ROOT / 'infra/s1-settings.json').read_text(encoding='utf-8')))
    c = integration if integration is not None else json.loads((ROOT / 'infra/s1-integration-settings.json').read_text(encoding='utf-8'))
    if set(c) != {'schema_version','detection_enabled','portal_url','ticket_url','n8n_url','respond_path',
                  'release_path','operator_name','event_max_age_seconds','future_clock_tolerance_seconds','credentials'}:
        raise ValueError('invalid integration keys')
    if type(c['schema_version']) is not int or c['schema_version'] != 1 or type(c['detection_enabled']) is not bool:
        raise ValueError('invalid integration mode')
    for key, host, port in [('portal_url','portal-response',s['portal_internal_port']),('ticket_url','ticket-store',8088),('n8n_url','n8n',5678)]:
        u = urlsplit(c[key])
        if u.scheme!='http' or u.hostname!=host or u.port!=port or u.path or u.query or u.fragment or u.username or u.password:
            raise ValueError('owned compose service URL required')
    for key in ('respond_path','release_path'):
        if not re.fullmatch(r'haedam-s1-[a-z0-9-]{1,40}', c[key]):
            raise ValueError('invalid webhook path')
    if c['respond_path']==c['release_path'] or not re.fullmatch(r'[a-z0-9-]{1,40}',c['operator_name']):
        raise ValueError('invalid operator/path')
    if type(c['event_max_age_seconds']) is not int or not 1<=c['event_max_age_seconds']<=s['policy']['boundary_observation_seconds']:
        raise ValueError('invalid event age')
    if type(c['future_clock_tolerance_seconds']) is not int or not 0<=c['future_clock_tolerance_seconds']<=60:
        raise ValueError('invalid clock tolerance')
    creds=c['credentials']
    expected={'detection':('X-S1-Detection-Key','S1_DETECTION_KEY'), 'operator':('X-S1-Operator-Key','S1_OPERATOR_KEY'),
              'portal':('X-Response-Key','PORTAL_RESPONSE_KEY'), 'ticket':('X-Response-Key','TICKET_STORE_KEY')}
    if set(creds)!=set(expected):
        raise ValueError('invalid credential roles')
    for role,(header,env) in expected.items():
        v=creds[role]
        if set(v)!={'id','header','env'} or not re.fullmatch(r's1[A-Za-z0-9]{1,40}',v['id']) or (v['header'],v['env'])!=(header,env):
            raise ValueError('invalid credential reference')
    if len({v['id'] for v in creds.values()})!=4:
        raise ValueError('credentials must be separate')
    return s,c


def change(code, old, new):
    if old not in code:
        raise ValueError('upstream changed: '+old[:60])
    return code.replace(old,new)


def common_workflow(role,c,s):
    number={'ticket':'10','portal':'12'}[role]
    path=next((ROOT/'infra/n8n/workflows').glob('haedam-'+number+'-*.json'))
    w=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(w,list): w,=w
    w.update(id=IDS[role],name='[Portfolio S1] '+role,active=False)
    w['settings'].update(saveDataSuccessExecution='none',saveDataErrorExecution='none',saveManualExecutions=False,saveExecutionProgress=False)
    for n in w['nodes']:
        p=n['parameters']
        if n['type'].endswith('.httpRequest'):
            ident=c['credentials'][role]['id']
            n['credentials']={'httpHeaderAuth':{'id':ident,'name':ident}}
        for key in ('url','jsCode'):
            if isinstance(p.get(key),str):
                p[key]=p[key].replace('http://portal:5000',c['portal_url']).replace('http://ticket-store:8088',c['ticket_url'])
        if 'jsCode' not in p: continue
        code=p['jsCode']
        if role=='ticket' and n['name']=='저장소 요청 만들기':
            code=change(code,'const cfg = (b.ctx && b.ctx.cfg) || {};','const cfg = {dry_run:false,store_real:true};')
        if role=='portal' and 'function protectedIp(ip)' in code:
            start=code.index('function protectedIp(ip)'); end=code.index('\n}',start)+2
            code=code[:start]+f"function protectedIp(ip) {{ return ip === {json.dumps(s['addresses']['attacker'])} ? null : 'outside_s1_lab'; }}"+code[end:]
        if role=='portal' and n['name'].startswith('응답 분류'):
            code=change(code,"'timeout_or_network:' + String((j.error && j.error.message) || j.message || '').slice(0, 120)","'timeout_or_network'")
            code=change(code,"else if (status === 200) {", "else if (status === 200 && body?.success === true && (prev.action === 'list' ? Array.isArray(body?.data?.items) : typeof body?.data?.changed === 'boolean')) {")
            code=change(code,"`${status} ${(body && body.error && body.error.code) || ''}`","`${status} invalid_or_rejected_response`")
        if role=='portal' and n['name']=='반영 확인 판정':
            code=change(code,'(j.statusCode === 200 && j.body && j.body.data && j.body.data.items) || null',
                        "(j.statusCode === 200 && j.body?.success === true && Array.isArray(j.body?.data?.items) && j.body.data.items.every(i=>i && typeof i.ip==='string') ? j.body.data.items : null)")
        p['jsCode']=code
    if role=='portal':
        # n8n returns only main[0] of the last node: list/failed results ending on this IF's
        # false branch would reach the caller as no items (same fix as team haedam-10, b3c4a1f).
        branches=w['connections']['반영 확인 필요?']['main']
        if len(branches)!=2 or branches[1]:
            raise ValueError('upstream changed: 반영 확인 필요? false branch')
        w['nodes'].append({'id':'portfolio-s1-portal-pass-through','name':'결과 전달','type':'n8n-nodes-base.code',
                           'typeVersion':2,'position':[2620,360],
                           'parameters':{'jsCode':'return $input.all();   // 목록 조회·실패 결과를 하위 워크플로 출력으로 내보낸다'}})
        branches[1]=[{'node':'결과 전달','type':'main','index':0}]
    return w


def flow(role,s,c):
    cfg={k:c[k] for k in ('detection_enabled','operator_name','event_max_age_seconds','future_clock_tolerance_seconds')}
    cfg.update(ip=s['addresses']['attacker'],asset_id=s['asset_id'],username_prefix=s['username_prefix'])
    source=(ROOT/'infra/n8n/s1-src/flow.js').read_text(encoding='utf-8')
    w={'id':IDS[role],'name':'[Portfolio S1] '+role,'active':False,'nodes':[],'connections':{},
       'settings':{'executionOrder':'v1','saveDataSuccessExecution':'none','saveDataErrorExecution':'none',
                   'saveManualExecutions':False,'saveExecutionProgress':False}}
    def node(name,kind,parameters,version=2):
        n={'id':role+'-'+name,'name':name,'type':'n8n-nodes-base.'+kind,'typeVersion':version,
           'position':[len(w['nodes'])*220,0],'parameters':parameters}
        w['nodes'].append(n); return n
    def link(a,b,branch=0):
        outputs=w['connections'].setdefault(a,{'main':[]})['main']
        while len(outputs)<=branch: outputs.append([])
        outputs[branch].append({'node':b,'type':'main','index':0})
    path=c['respond_path' if role=='respond' else 'release_path']
    hook=node('Webhook','webhook',{'httpMethod':'POST','path':path,'responseMode':'responseNode','authentication':'headerAuth','options':{}})
    ident=c['credentials']['detection' if role=='respond' else 'operator']['id']
    hook['credentials']={'httpHeaderAuth':{'id':ident,'name':ident}};hook['webhookId']=path
    stages=[('Validate','validate_response' if role=='respond' else 'validate_release','ticket'),
            ('Snapshot','snapshot','ticket'),('Owners','owners','portal'),('Portal before','portal_before','ticket' if role=='respond' else 'portal')]
    if role=='respond': stages += [('Detected ack','detected_ack','ticket'),('Current before block','current_before_block','ticket'),
                                    ('Owners before block','owners_before_block','portal'),('Portal before block','portal_before_block','portal'),
                                    ('Block result','block_result','ticket'),('Applied ack','applied_ack',None)]
    else: stages += [('Release result','release_result','ticket'),('Released ack','released_ack','ticket'),
                     ('Final ticket','final_ticket','portal'),('Final portal','final_portal',None)]
    previous='Webhook'
    for name,stage,call in stages:
        node(name,'code',{'jsCode':'const CFG = '+json.dumps(cfg,ensure_ascii=False)+';\n'+source+f'\nreturn run({json.dumps(stage)}, $input.first().json, String($execution.id));\n'})
        link(previous,name)
        if call:
            gate=name+' proceed'
            node(gate,'if',{'conditions':{'options':{'caseSensitive':True,'typeValidation':'strict','version':2},
                    'conditions':[{'id':gate,'leftValue':'={{ $json.proceed === true }}','rightValue':'',
                                   'operator':{'type':'boolean','operation':'true','singleValue':True}}],'combinator':'and'},'options':{}},2.2)
            link(name,gate);link(gate,'Respond',1)
            sub=name+' API'
            node(sub,'executeWorkflow',{'source':'database','workflowId':{'__rl':True,'value':IDS[call],'mode':'id'},'options':{}},1.2)
            link(gate,sub);previous=sub
        else: link(name,'Respond')
    node('Respond','respondToWebhook',{'respondWith':'json','responseBody':'={{ JSON.stringify($json) }}',
                                      'options':{'responseCode':'={{ $json.http_status || 503 }}'}},1.1)
    return w


def graylog_artifacts(s,c,bindings=None):
    # This spec intentionally has no secrets. Materialization takes keys as explicit arguments.
    d=json.loads((ROOT/'lab/s1s4/graylog/s1-login-bruteforce.json').read_text(encoding='utf-8'))
    d['title']=s['project']+' S1 login failures'
    d['config']['query']+=' AND src_ip:"'+s['addresses']['attacker']+'" AND username:'+s['username_prefix']+'*'
    d['config']['streams']=[]
    d['notification_settings']['backlog_size']=0
    d['notifications']=[]
    notification=json.loads((ROOT/'infra/graylog/notifications/s1-n8n-haedam-s1.json').read_text(encoding='utf-8'))
    notification['title']=s['project']+' authenticated S1'
    notification['description']='Personal S1 authenticated notification. Pause definition before release.'
    notification['config'].update(url=c['n8n_url']+'/webhook/'+c['respond_path'],api_key_as_header=True,
          api_key=c['credentials']['detection']['header'],api_secret=None,headers='',basic_auth=None)
    notification['config']['body_template']=json.dumps({'case_id':'S1','asset_id':s['asset_id'],'src_ip':'${event.fields.src_ip}',
          'username':'${event.fields.username}','event_id':'${event.id}','detected_at':'${event.timestamp_processing}'})
    spec={'input':{'title':s['project']+' GELF TCP','type':'org.graylog2.inputs.gelf.tcp.GELFTCPInput','global':True,
                  'configuration':{'bind_address':'0.0.0.0','port':12201,'number_worker_threads':2,'recv_buffer_size':1048576,
                   'max_message_size':2097152,'tls_enable':False,'tcp_keepalive':True,'use_null_delimiter':True}},
          'stream':{'title':s['project']+' portal','description':'Dedicated S1 GELF input','matching_type':'AND','remove_matches_from_default_stream':False,
                    'rules':[{'type':1,'field':'source','value':'haedam-portal','inverted':False,'description':'Portal source'}]},
          'notification':notification,'definition':d,'schedule_enabled':False,'materialized':False,
          'required_message_fields':['source','rule','status','username','src_ip'],
          'url_allowlist':{'id':'portfolio-s1','type':'literal','title':'S1 webhook','value':c['n8n_url']+'/webhook/'+c['respond_path']}}
    if bindings is not None:
        if set(bindings)!={'input_id','index_set_id','stream_id','notification_id'} or any(not re.fullmatch(r'[a-f0-9]{24}',str(v)) for v in bindings.values()):
            raise ValueError('actual Graylog resource IDs required')
        spec['stream']['index_set_id']=bindings['index_set_id']
        spec['stream']['rules'].append({'type':8,'field':'gl2_source_input','value':bindings['input_id'],'inverted':False,'description':'Owned GELF input'})
        d['config']['streams']=[bindings['stream_id']]
        d['notifications']=[{'notification_id':bindings['notification_id'],'notification_parameters':None}]
        spec['materialized']=True
    return spec


def materialize(settings,integration,bindings,secrets):
    s,c=load_settings(settings,integration)
    required={v['env'] for v in c['credentials'].values()}
    if set(secrets)!=required or any(not isinstance(v,str) or not re.fullmatch(r'[a-f0-9]{64}',v) for v in secrets.values()) or len(set(secrets.values()))!=4:
        raise ValueError('four separate generated keys required')
    spec=graylog_artifacts(s,c,bindings)
    spec['notification']['config']['api_secret']=secrets[c['credentials']['detection']['env']]
    credentials=[{'id':v['id'],'name':v['id'],'type':'httpHeaderAuth','data':{'name':v['header'],'value':secrets[v['env']]}}
                 for v in c['credentials'].values()]
    return {'graylog':spec,'credentials':credentials,'workflows':list(build(s,c).values()),'schedule_enabled':False}


def build(settings=None,integration=None):
    s,c=load_settings(settings,integration)
    return {f's1-{role}.json':common_workflow(role,c,s) if role in ('ticket','portal') else flow(role,s,c)
            for role in ('ticket','portal','respond','release')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    s,c=load_settings()
    files={ROOT/'infra/n8n/portfolio-s1'/name:value for name,value in build(s,c).items()}
    files[ROOT/'infra/graylog/portfolio-s1.json']=graylog_artifacts(s,c)
    for path,value in files.items():
        content=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8')!=content:
                raise SystemExit('S1 generated artifact differs: '+path.name)
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding='utf-8')
    print('S1: 4 n8n workflows and 1 Graylog spec '+('checked' if args.check else 'generated')+'; no deployment')


if __name__=='__main__':
    main()
