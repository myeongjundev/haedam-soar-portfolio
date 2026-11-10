"""Offline consistency check of S1 run artifacts; does not attest their provenance."""
import argparse
from datetime import datetime,timedelta
import json
from pathlib import Path
import re

from s1_rehearsal import load_bundle, write
from s1_settings import digest, plan


def instant(value):
    d=datetime.fromisoformat(value)
    if d.tzinfo is None:raise ValueError('timezone_required')
    return d


def require(condition):
    if not condition:raise ValueError('evidence_mismatch')


def probe_precedes_restoration(finished_at,restored_at):
    finished=instant(finished_at);restored=instant(restored_at)
    # The ticket store truncates to seconds. Treat that value as [t, t+1s),
    # not a precise instant; explicit fractional timestamps keep strict order.
    if re.search(r'T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$',restored_at):
        return finished<restored+timedelta(seconds=1)
    return finished<=restored


def ticket(s,run_id,value):
    require(isinstance(value,dict) and value.get('ok') is True)
    t=value['ticket'];p=plan(s,run_id,'trigger9')
    expected={'seat':'A','case_id':'S1','asset_id':s['asset_id'],'src_ip':p['source_ip'],'username':p['username'],
              'group_key':'S1|'+p['username']+'|'+p['source_ip'],'data_origin':'live'}
    require(all(t.get(k)==v for k,v in expected.items()))
    require(isinstance(t.get('ticket_id'),str) and re.fullmatch(r'T-\d{8}-\d{4}',t['ticket_id']))
    return t


def active(actions):
    claims={}
    for a in actions:
        if a.get('duplicate') is True:continue
        name='block' if a['action']=='unblock' else a['action']
        key=(a['bot'],a['via'],name,a['target'])
        if a['result'] in ('applied','already_applied'):claims[key]=a
        elif a['result']=='released':claims.pop(key,None)
    return claims


def release_body(s,run_id,export):
    t=ticket(s,run_id,export)
    require(t['status'] in ('responding','verified'))
    require(set(active(t['actions']))=={('112','portal','block',s['addresses']['attacker'])})
    return {k:t[k] for k in ('case_id','asset_id','src_ip','username','ticket_id')}


def check(s,packet,evidence,definition_id):
    run_id=packet['run_id'];p=plan(s,run_id,'trigger9');h=digest(s)
    count=s['policy']['failure_threshold'];clock_tolerance=packet['clock_tolerance_seconds']
    require(isinstance(definition_id,str) and re.fullmatch(r'[a-f0-9]{24}',definition_id))
    i=evidence['input']
    require(all(i.get(k)==v for k,v in {'case_id':'S1','run_id':run_id,'profile':'trigger9','project':s['project'],
           'settings_sha256':h,'status':'input_complete','mode':'actual_http_input','username':p['username'],
           'source_ip':p['source_ip'],'observed_401_count':count}.items()))
    require(len(i['records'])==p['maximum_http_requests'])
    require([r['operation'] for r in i['records']]==['health']+['session','login']*count)
    require(all(r['source_ip']==p['source_ip'] and r['status']==(401 if r['operation']=='login' else 200) for r in i['records']))
    login=[r for r in i['records'] if r['operation']=='login']
    require(len(login)==count and all(r['status']==401 and r['error_code']=='INVALID_CREDENTIALS' and r['source_ip']==p['source_ip'] for r in login))
    require(all((instant(b['started_at'])-instant(a['finished_at'])).total_seconds()>=s['policy']['input_interval_seconds']
                for a,b in zip(login,login[1:])))
    require((instant(login[-1]['finished_at'])-instant(login[0]['started_at'])).total_seconds()<s['policy']['window_seconds'])
    for filename in ('s1_client.py','s1_settings.py'):
        require(i['source_sha256'][filename]==packet['source_sha256']['tools/'+filename])
    probes=evidence['probes'];tolerance=s['request_timeout_seconds']
    for role in ('attacker','normal'):
        for phase in ('baseline','blocked','restored'):
            q=probes[role+'_'+phase]
            require(all(q.get(k)==v for k,v in {'run_id':run_id,'role':role,'phase':phase,'project':s['project'],
              'settings_sha256':h,'mode':'actual_http_probe','status':'probe_passed','source_ip':s['addresses'][role]}.items()))
            for filename in ('s1_probe.py','s1_client.py','s1_settings.py'):
                require(q['source_sha256'][filename]==packet['source_sha256']['tools/'+filename])
            require(q['records'][0]['operation']=='health' and q['records'][0]['status']==(403 if role=='attacker' and phase=='blocked' else 200))
            require(all(r['source_ip']==s['addresses'][role] for r in q['records']))
            if role=='normal':
                require(q['normal_authenticated'] is True and q['username']==packet['normal_username'])
                require(len(q['records'])==(5 if phase=='baseline' else 4))
                require(len([r for r in q['records'] if r['operation']=='login' and r['status']==200])==1)
            else:require(len(q['records'])==1)
        require(instant(probes[role+'_baseline']['finished_at'])<=instant(i['started_at']))
        require(instant(probes[role+'_blocked']['started_at'])>=instant(i['started_at']))
        require(instant(probes[role+'_restored']['started_at'])>instant(probes[role+'_blocked']['finished_at']))
    event=evidence['graylog_event'];event=event.get('event',event)
    require(isinstance(event.get('id'),str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',event['id']))
    require(event['event_definition_id']==definition_id and event['fields']['username']==p['username'] and event['fields']['src_ip']==p['source_ip'])
    detected=instant(event['timestamp_processing'])
    require((detected-instant(login[-1]['started_at'])).total_seconds()>=-clock_tolerance)
    for role in ('attacker','normal'):
        require((instant(probes[role+'_blocked']['started_at'])-detected).total_seconds()>=-clock_tolerance)
    before=ticket(s,run_id,evidence['ticket_blocked']);after=ticket(s,run_id,evidence['ticket_restored'])
    release_body(s,run_id,evidence['ticket_blocked'])
    require(before['ticket_id']==after['ticket_id'] and after['status']=='restored' and not active(after['actions']))
    require(event['id'] in before['event_ids'] and event['id'] in after['event_ids'])
    # Ticket actions are append-only and exported in insertion order. A later
    # snapshot must preserve the original claim and append its verified release.
    history_size=len(before['actions'])
    require(after['actions'][:history_size]==before['actions'])
    claimed=set(active(before['actions']))
    require(any((a['bot'],a['via'],'block',a['target']) in claimed
                and a['action']=='unblock' and a['result']=='released'
                and a.get('duplicate') is not True and a['applied_verified'] is True
                for a in after['actions'][history_size:]))
    release=evidence['release_response']
    require(release.get('ok') is True and release.get('verdict')=='released' and release.get('ticket_id')==after['ticket_id'])
    restored=instant(after['restored_at'])
    for role in ('attacker','normal'):
        require(probe_precedes_restoration(probes[role+'_blocked']['finished_at'],after['restored_at']))
        require((instant(probes[role+'_restored']['started_at'])-restored).total_seconds()>=-tolerance)
    return {'case_id':'S1','run_id':run_id,'artifact_consistency':'passed','provenance_attested':False,
      'ticket_id':after['ticket_id'],'event_id':event['id'],'login_401_count':count,'ticket_status':'restored',
      'active_actions':0,'attacker_health_sequence':[200,403,200],'normal_authenticated_each_phase':True,
      'detected_at':event['timestamp_processing'],'restored_at':after['restored_at'],
      'scope':'supplied artifacts only; actual engine execution and capture provenance require operator review'}


def read_local(bundle,value):
    require(isinstance(value,str));path=(bundle/value).resolve()
    require(path.is_relative_to(bundle.resolve()))
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['check','release-body'])
    parser.add_argument('--bundle',required=True,type=Path);args=parser.parse_args()
    try:
        bundle=args.bundle.resolve();s,c,packet=load_bundle(bundle)
        index=read_local(bundle,'evidence-index.json')
        if args.command=='release-body':result=release_body(s,packet['run_id'],read_local(bundle,index['ticket_blocked']))
        else:
            evidence={k:read_local(bundle,index[k]) for k in ('input','ticket_blocked','ticket_restored','graylog_event','release_response')}
            evidence['probes']={k:read_local(bundle,v) for k,v in index['probes'].items()}
            result=check(s,packet,evidence,index['definition_id'])
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ValueError,KeyError,TypeError,OSError):
        parser.exit(2,'S1 evidence incomplete or inconsistent; no success declared.\n')


if __name__=='__main__':main()
