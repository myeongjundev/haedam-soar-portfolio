"""Deterministic S4 n8n/Graylog artifacts. No network, Docker or secret reads."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from s4_settings import validate

ROOT = Path(__file__).resolve().parents[1]
IDS = {'ticket': 'portfolioS4Ticket01', 'portal': 'portfolioS4Portal01',
       'respond': 'portfolioS4Respond01', 'release': 'portfolioS4Release01'}


def load_settings(settings=None, integration=None):
    s = validate(settings if settings is not None else json.loads((ROOT / 'infra/s4-settings.json').read_text(encoding='utf-8')))
    c = integration if integration is not None else json.loads((ROOT / 'infra/s4-integration-settings.json').read_text(encoding='utf-8'))
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
        if not re.fullmatch(r'haedam-s4-[a-z0-9-]{1,40}', c[key]):
            raise ValueError('invalid webhook path')
    if c['respond_path']==c['release_path'] or not re.fullmatch(r'[a-z0-9-]{1,40}',c['operator_name']):
        raise ValueError('invalid operator/path')
    if type(c['event_max_age_seconds']) is not int or not 1<=c['event_max_age_seconds']<=s['policy']['boundary_observation_seconds']:
        raise ValueError('invalid event age')
    if type(c['future_clock_tolerance_seconds']) is not int or not 0<=c['future_clock_tolerance_seconds']<=60:
        raise ValueError('invalid clock tolerance')
    creds=c['credentials']
    expected={'detection':('X-S4-Detection-Key','S4_DETECTION_KEY'), 'operator':('X-S4-Operator-Key','S4_OPERATOR_KEY'),
              'portal':('X-Response-Key','PORTAL_RESPONSE_KEY'), 'ticket':('X-Response-Key','TICKET_STORE_KEY'), 'release':('X-Response-Key','S4_RELEASE_KEY')}
    if set(creds)!=set(expected):
        raise ValueError('invalid credential roles')
    for role,(header,env) in expected.items():
        v=creds[role]
        if set(v)!={'id','header','env'} or not re.fullmatch(r's4[A-Za-z0-9]{1,40}',v['id']) or (v['header'],v['env'])!=(header,env):
            raise ValueError('invalid credential reference')
    if len({v['id'] for v in creds.values()})!=5:
        raise ValueError('credentials must be separate')
    return s,c


def change(code, old, new):
    if old not in code:
        raise ValueError('upstream changed: '+old[:60])
    return code.replace(old,new)


def common_workflow(role,c,s):
    number='10'
    path=next((ROOT/'infra/n8n/workflows').glob('haedam-'+number+'-*.json'))
    w=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(w,list): w,=w
    w.update(id=IDS[role],name='[Portfolio S4] '+role,active=False)
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
        p['jsCode']=code
    return w


def account_workflow(s,c):
    source=(ROOT/'infra/n8n/s4-src/account.js').read_text(encoding='utf-8')
    cfg={'username':s['accounts']['target'],'portal_url':c['portal_url']}
    w={'id':IDS['portal'],'name':'[Portfolio S4] scoped account','active':False,'nodes':[], 'connections':{},
       'settings':{'executionOrder':'v1','saveDataSuccessExecution':'none','saveDataErrorExecution':'none','saveManualExecutions':False,'saveExecutionProgress':False}}
    def node(name,kind,p,v=2):
        n={'id':'account-'+name,'name':name,'type':'n8n-nodes-base.'+kind,'typeVersion':v,'position':[len(w['nodes'])*220,0],'parameters':p}
        w['nodes'].append(n);return n
    def link(a,b,branch=0):
        arr=w['connections'].setdefault(a,{'main':[]})['main']
        while len(arr)<=branch:arr.append([])
        arr[branch].append({'node':b,'type':'main','index':0})
    def code(name,stage):
        node(name,'code',{'jsCode':'const CFG = '+json.dumps(cfg)+';\n'+source+'\nreturn run('+json.dumps(stage)+', $input.first().json);'})
    def gate(name,expression):
        node(name,'if',{'conditions':{'options':{'caseSensitive':True,'typeValidation':'strict','version':2},'conditions':[{'id':name,'leftValue':'={{ '+expression+' }}','rightValue':'','operator':{'type':'boolean','operation':'true','singleValue':True}}],'combinator':'and'},'options':{}},2.2)
    def http(name,role,read=False):
        params={'method':'GET' if read else '={{ $json.action === "list" ? "GET" : "POST" }}',
                'url':'={{ $json.read_url }}' if read else '={{ $json.url }}',
                'authentication':'genericCredentialType','genericAuthType':'httpHeaderAuth',
                'options':{'timeout':10000,'response':{'response':{'fullResponse':True,'neverError':True,'responseFormat':'json'}}}}
        if not read:
            params.update(sendHeaders=True,headerParameters={'parameters':[{'name':'Idempotency-Key','value':'={{ $json.idempotency_key }}'}]},
                          sendBody='={{ $json.action !== "list" }}',specifyBody='json',jsonBody='={{ JSON.stringify($json.data) }}')
        n=node(name,'httpRequest',params,4.2);n['onError']='continueRegularOutput'
        ident=c['credentials'][role]['id'];n['credentials']={'httpHeaderAuth':{'id':ident,'name':ident}}
    node('Start','executeWorkflowTrigger',{'inputSource':'passthrough'},1.1)
    code('Prepare','prepare');link('Start','Prepare');gate('Valid','$json.valid === true');link('Prepare','Valid')
    code('Invalid','invalid');link('Valid','Invalid',1)
    gate('Is release','$json.action === "unlock"');link('Valid','Is release')
    http('Account API','portal');http('Release API','release');link('Is release','Release API');link('Is release','Account API',1)
    code('Classify','classify');link('Account API','Classify');link('Release API','Classify')
    gate('Readback needed','$json.needs_readback === true');link('Classify','Readback needed')
    code('Done','done');link('Readback needed','Done',1)
    http('Readback','portal',True);link('Readback needed','Readback');code('Verified','verify');link('Readback','Verified')
    return w


def flow(role,s,c):
    cfg={k:c[k] for k in ('detection_enabled','operator_name','event_max_age_seconds','future_clock_tolerance_seconds')}
    cfg.update(ip=s['addresses']['attacker'],asset_id=s['asset_id'],username=s['accounts']['target'])
    source=(ROOT/'infra/n8n/s4-src/flow.js').read_text(encoding='utf-8')
    w={'id':IDS[role],'name':'[Portfolio S4] '+role,'active':False,'nodes':[],'connections':{},
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
    stages=[('Validate','validate_response' if role=='respond' else 'validate_release','portal'),
            ('Identity','identity','ticket'),
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
    d=json.loads((ROOT/'lab/s1s4/graylog/s4-fail-then-success.json').read_text(encoding='utf-8'))
    d['title']=s['project']+' S4 mixed failure and success'
    d['config']['query']+=' AND src_ip:"'+s['addresses']['attacker']+'" AND username:'+'"'+s['accounts']['target']+'"'
    d['config']['streams']=[]
    d['notification_settings']['backlog_size']=0
    d['notifications']=[]
    notification=json.loads((ROOT/'infra/graylog/notifications/s1-n8n-haedam-s1.json').read_text(encoding='utf-8'))
    notification['title']=s['project']+' authenticated S4'
    notification['description']='Personal S4 authenticated notification. Pause definition before release.'
    notification['config'].update(url=c['n8n_url']+'/webhook/'+c['respond_path'],api_key_as_header=True,
          api_key=c['credentials']['detection']['header'],api_secret=None,headers='',basic_auth=None)
    notification['config']['body_template']=json.dumps({'case_id':'S4','asset_id':s['asset_id'],'src_ip':'${event.fields.src_ip}',
          'username':'${event.fields.username}','event_id':'${event.id}','detected_at':'${event.timestamp_processing}'})
    spec={'input':{'title':s['project']+' GELF TCP','type':'org.graylog2.inputs.gelf.tcp.GELFTCPInput','global':True,
                  'configuration':{'bind_address':'0.0.0.0','port':12201,'number_worker_threads':2,'recv_buffer_size':1048576,
                   'max_message_size':2097152,'tls_enable':False,'tcp_keepalive':True,'use_null_delimiter':True}},
          'stream':{'title':s['project']+' portal','description':'Dedicated S4 GELF input','matching_type':'AND','remove_matches_from_default_stream':False,
                    'rules':[{'type':1,'field':'source','value':'haedam-portal','inverted':False,'description':'Portal source'}]},
          'notification':notification,'definition':d,'schedule_enabled':False,'materialized':False,
          'required_message_fields':['source','rule','status','username','src_ip'],
          'url_allowlist':{'id':'portfolio-s4','type':'literal','title':'S4 webhook','value':c['n8n_url']+'/webhook/'+c['respond_path']}}
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
    if set(secrets)!=required or any(not isinstance(v,str) or not re.fullmatch(r'[a-f0-9]{64}',v) for v in secrets.values()) or len(set(secrets.values()))!=5:
        raise ValueError('five separate generated keys required')
    spec=graylog_artifacts(s,c,bindings)
    spec['notification']['config']['api_secret']=secrets[c['credentials']['detection']['env']]
    credentials=[{'id':v['id'],'name':v['id'],'type':'httpHeaderAuth','data':{'name':v['header'],'value':secrets[v['env']]}}
                 for v in c['credentials'].values()]
    return {'graylog':spec,'credentials':credentials,'workflows':list(build(s,c).values()),'schedule_enabled':False}


def build(settings=None,integration=None):
    s,c=load_settings(settings,integration)
    return {f's4-{role}.json':common_workflow(role,c,s) if role=='ticket' else account_workflow(s,c) if role=='portal' else flow(role,s,c)
            for role in ('ticket','portal','respond','release')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    s,c=load_settings()
    files={ROOT/'infra/n8n/portfolio-s4'/name:value for name,value in build(s,c).items()}
    files[ROOT/'infra/graylog/portfolio-s4.json']=graylog_artifacts(s,c)
    for path,value in files.items():
        content=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
        if args.check:
            if not path.exists() or path.read_text(encoding='utf-8')!=content:
                raise SystemExit('S4 generated artifact differs: '+path.name)
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding='utf-8')
    print('S4: 4 n8n workflows and 1 Graylog spec '+('checked' if args.check else 'generated')+'; no deployment')


if __name__=='__main__':
    main()
