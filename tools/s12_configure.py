import json,secrets,sys
import s12_runtime as o
from build_s12_workflows import materialize,IDS

def install(bindings,enabled=False,credentials=False):
 c={**o.C,'detection_enabled':enabled}
 generated=materialize(o.S,c,bindings,{v['env']:o.V[v['env']] for v in c['credentials'].values()})
 folder=o.B/('import-enabled' if enabled else 'import-baseline');folder.mkdir(exist_ok=True)
 for name,value in generated.items():(folder/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
 for name in (('credentials','workflows') if credentials else ('workflows',)):
  remote='/tmp/s12-'+name+'.json'
  try:
   o.compose('exec','-T','n8n','node','-e',"require('fs').writeFileSync(process.argv[1],require('fs').readFileSync(0),{mode:0o600})",remote,stdin=json.dumps(generated[name]))
   o.compose('exec','-T','n8n','n8n','import:credentials' if name=='credentials' else 'import:workflow','--input='+remote)
  finally:o.compose('exec','-T','n8n','node','-e',"require('fs').rmSync(process.argv[1],{force:true})",remote)
  print('imported',name,flush=True)
 for ident in IDS.values():
  o.compose('exec','-T','n8n','n8n','publish:workflow','--id='+ident)
 o.compose('restart','n8n',timeout=90)
 o.compose('up','-d','--wait','--wait-timeout','180','n8n',timeout=220)
 print('published five workflows; own n8n healthy',flush=True)
 return generated

def setup():
 spec=json.loads((o.B/'graylog-integration.template.json').read_text())
 assert not (o.B/'bindings.json').exists()
 index=next(x['id'] for x in o.gl('/system/indices/index_sets')['index_sets'] if x['default'])
 inp=o.gl('/system/inputs',spec['input'])['id']
 stream=spec['stream'];stream['index_set_id']=index
 stream['rules'].append({'type':8,'field':'gl2_source_input','value':inp,'inverted':False,'description':'Owned S12 input'})
 sid=o.gl('/streams',stream)['stream_id'];o.gl('/streams/'+sid+'/resume',{},'POST')
 entries=o.gl('/system/urlwhitelist').get('entries',[])+[spec['url_allowlist']]
 o.gl('/system/urlwhitelist',{'entries':entries,'disabled':False},'PUT')
 spec['notification']['config']['api_secret']=o.V[o.C['credentials']['detection']['env']]
 nid=o.gl('/events/notifications',spec['notification'])['id']
 bindings={'input_id':inp,'index_set_id':index,'stream_id':sid,'notification_id':nid};o.save('bindings.json',bindings)
 owner={'email':'s12-portfolio@example.invalid','firstName':'Personal','lastName':'S12','password':'S12!'+secrets.token_urlsafe(28)}
 o.save('n8n-owner.private.json',owner)
 code,_=o.http('http://127.0.0.1:'+str(o.S['host_ports']['N8N_PORT'])+'/rest/owner/setup',owner)
 assert code in (200,201),code
 install(bindings,credentials=True)
 o.save('live-state.json',{'at':o.now(),**bindings,'scheduled':False,'definition_id':None})
 print('baseline ready; no detection definition created',flush=True)

def enable():
 if json.loads((o.B/'live-state.json').read_text()).get('definition_id'):raise ValueError('definition_already_created')
 bindings=json.loads((o.B/'bindings.json').read_text())
 generated=install(bindings,enabled=True)
 spec=generated['graylog'];nid=bindings['notification_id'];spec['notification']['id']=nid
 o.gl('/events/notifications/'+nid,spec['notification'],'PUT')
 did=o.gl('/events/definitions',spec['definition'])['id'];o.gl('/events/definitions/'+did+'/unschedule',{},'PUT')
 o.save('live-state.json',{'at':o.now(),**bindings,'scheduled':False,'definition_id':did})
 print('measured definition ready; schedule remains OFF',flush=True)

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description='Configure only the specified personal S12 bundle; no Docker startup or external stack changes.')
 p.add_argument('phase',choices=['baseline','measured']);p.add_argument('--bundle',type=__import__('pathlib').Path,required=True)
 a=p.parse_args()
 try:
  o.initialize(a.bundle)
  if not o.S['execution_enabled']:raise ValueError('execution_not_enabled')
  setup() if a.phase=='baseline' else enable()
 except Exception as e:
  print('S12 configuration stopped: '+type(e).__name__+'; inspect private bundle state before retrying.',flush=True)
  raise SystemExit(1)
