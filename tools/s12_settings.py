"""Personal S12 configuration. No engine, network or environment access."""
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
from s1_settings import digest

ROOT=Path(__file__).resolve().parents[1]
GROUPS={'networks':{'default','clients','response','graylog_backend'},
 'network_internal':{'default','clients','response','graylog_backend'},
 'addresses':{'portal_client','attacker','normal','n8n_response','portal_response'},
 'host_ports':{'PORTAL_PORT','GRAYLOG_PORT','N8N_PORT','GELF_PORT','TICKET_PORT'},
 'paths':{'tools_mount','settings_mount','evidence_mount','health','work','normal'},
 'policy':{'request_threshold','baseline_source','window_seconds','execute_every_seconds','notification_grace_seconds','boundary_observation_seconds'},
 'health':{'baseline_ms','baseline_source','k','interval_ms','timeout_ms'},
 'load':{'rates_per_second','stage_seconds','concurrency','maximum_requests','maximum_duration_seconds'},
 'workload':{'resource_slots','work_ms','maximum_armed_seconds'}}
def validate(s):
    required=set(GROUPS)|{'schema_version','project','execution_enabled','asset_id','network_status','client_image','portal_internal_port','request_timeout_seconds','stop_filename'}
    if not isinstance(s,dict) or set(s)!=required:raise ValueError('settings_keys')
    for group,keys in GROUPS.items():
        if not isinstance(s[group],dict) or set(s[group])!=keys:raise ValueError('settings_group')
    if s['schema_version']!=1 or type(s['execution_enabled']) is not bool:raise ValueError('schema')
    if not re.fullmatch(r'haedam-s12-[a-z0-9][a-z0-9-]{0,35}',s['project']):raise ValueError('owned_project')
    if s['asset_id']!='haedam-portal' or s['portal_internal_port']!=5000:raise ValueError('owned_portal')
    nets={k:ipaddress.IPv4Network(v,strict=True) for k,v in s['networks'].items()}
    private=[ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    for k,n in nets.items():
        if not 24<=n.prefixlen<=29 or not any(n.subnet_of(p) for p in private) or any(n.overlaps(v) for key,v in nets.items() if key!=k):raise ValueError('network_scope')
    if s['network_internal']!={'default':False,'clients':True,'response':True,'graylog_backend':True}:raise ValueError('isolation')
    ips=[]
    for k,g in {'portal_client':'clients','attacker':'clients','normal':'clients','n8n_response':'response','portal_response':'response'}.items():
        ip=ipaddress.IPv4Address(s['addresses'][k]);n=nets[g]
        if ip not in n or ip in (n.network_address,n.network_address+1,n.broadcast_address):raise ValueError('address')
        ips.append(ip)
    if len(set(ips))!=len(ips):raise ValueError('duplicate_address')
    ports=list(s['host_ports'].values())
    if len(set(ports))!=len(ports) or any(type(p) is not int or not 1024<=p<=65535 for p in ports):raise ValueError('ports')
    for p in s['paths'].values():
        if not isinstance(p,str) or not p.startswith('/') or p.startswith('//') or '..' in PurePosixPath(p).parts or any(c in p for c in '\\?#\r\n$'):raise ValueError('paths')
    if not s['paths']['work'].startswith('/__lab/s12/') or s['paths']['health']!='/api/v1/health':raise ValueError('lab_path')
    if len(set(s['paths'].values()))!=len(s['paths']):raise ValueError('duplicate_path')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,30}',s['stop_filename']) or s['stop_filename'] in ('.','..'):raise ValueError('stop_file')
    if not re.fullmatch(r'[a-z0-9./_-]+:[a-zA-Z0-9_.-]+(?:@sha256:[a-f0-9]{64})?',s['client_image']):raise ValueError('image')
    def integer(v,lo,hi):return type(v) is int and lo<=v<=hi
    if not integer(s['request_timeout_seconds'],1,10):raise ValueError('timeout')
    p=s['policy'];h=s['health'];l=s['load'];w=s['workload']
    if any(p[k]!=v for k,v in {'window_seconds':60,'execute_every_seconds':30,'notification_grace_seconds':60,'boundary_observation_seconds':90}.items()):raise ValueError('team_window_changed')
    for threshold,source in ((p['request_threshold'],p['baseline_source']),(h['baseline_ms'],h['baseline_source'])):
        if (threshold is None)!=(source is None):raise ValueError('baseline_pair')
        if threshold is not None and (not isinstance(threshold,(int,float)) or isinstance(threshold,bool) or not 0<threshold<10000 or not re.fullmatch(r'[A-Za-z0-9._:-]{1,120}',source)):raise ValueError('baseline')
    if p['request_threshold'] is not None and not integer(p['request_threshold'],1,1000):raise ValueError('request_threshold')
    if h['k']!=3 or not integer(h['interval_ms'],500,5000) or not integer(h['timeout_ms'],1000,10000) or h['baseline_ms'] is not None and h['timeout_ms']<=h['baseline_ms']:raise ValueError('health')
    if not isinstance(l['rates_per_second'],list) or not 1<=len(l['rates_per_second'])<=3 or any(not integer(v,1,5) for v in l['rates_per_second']):raise ValueError('rate')
    if not integer(l['stage_seconds'],1,30) or not integer(l['concurrency'],1,2) or not integer(l['maximum_requests'],1,300) or not integer(l['maximum_duration_seconds'],1,90):raise ValueError('load_bounds')
    if len(l['rates_per_second'])*l['stage_seconds']>l['maximum_duration_seconds']:raise ValueError('duration')
    if not integer(w['resource_slots'],1,2) or not integer(w['work_ms'],1,1000) or not integer(w['maximum_armed_seconds'],1,180):raise ValueError('workload_bounds')
    return s

def load(settings=None,integration=None):
    s=validate(settings if settings is not None else json.loads((ROOT/'infra/s12-settings.json').read_text(encoding='utf-8')))
    c=integration if integration is not None else json.loads((ROOT/'infra/s12-integration-settings.json').read_text(encoding='utf-8'))
    from build_s1_workflows import load_settings as s1_load
    # Reuse the reviewed integration URL/key validation, without deploying S1 settings.
    c1=json.loads(json.dumps(c).replace('S12','S1').replace('s12','s1'))
    s1=json.loads((ROOT/'infra/s1-settings.json').read_text(encoding='utf-8'));s1_load(s1,c1)
    if c['detection_enabled'] and (s['policy']['request_threshold'] is None or s['health']['baseline_ms'] is None):raise ValueError('measured_baseline_required')
    return s,c
