"""Bounded S7 outage/replay/drift checks using real observed FIM/Graylog events."""
from datetime import datetime, timezone
import hashlib
import json
import time

from s7_auto_verify import lab, rows, ticket, tickets, hook, gateway, completion, mutate, agent, now


def replay_body(row):
    claim = json.loads(row['claim'])
    return dict(case_id='S7',asset_id=lab.SETTINGS['asset_id'],event_key=row['key'],
                event_id=claim['graylog_event_id'],detected_at=claim['detected_at'])


def verify():
    lab.require_current_portal()
    old = next(r for r in reversed(rows()) if json.loads(r['event'])['file_key']==lab.SETTINGS['home_file'] and r['completion'])
    if any(t['status'] in ('open','responding','verified') for t in tickets()):
        raise RuntimeError('Finish existing S7 tickets first.')
    definition=json.loads(lab.STATE.read_text())['definition']
    run_id=datetime.now(timezone.utc).strftime('S7FAULT-%Y%m%dT%H%M%SZ')
    out=dict(run_id=run_id,project=lab.PROJECT,started_at=now(),checks={},result='running')
    stopped=False
    try:
        lab.graylog('/events/definitions/'+definition+'/unschedule',{},'PUT')
        changed=mutate(lab.SETTINGS['home_file'],run_id)
        status,body=hook('respond',replay_body(old))
        assert status==409 and body['verdict']=='held_response',(status,body)
        out['checks']['old_success_does_not_mask_new_tamper']=status
        def find_row():
            return next((r for r in rows() if json.loads(r['event'])['expected_hash']==changed),None)
        row=lab.base.wait_for(find_row,120)
        assert row['claim'] is None and row['response'] is None
        lab.compose('stop','ticket-store'); stopped=True
        lab.graylog('/events/definitions/'+definition+'/schedule',{},'PUT')
        def claimed():
            r=find_row()
            return r if r and r['claim'] else None
        row=lab.base.wait_for(claimed,120)
        status,body=hook('respond',replay_body(row))
        assert status==503 and body['verdict']=='held_detection_record',(status,body)
        assert find_row()['response'] is None
        assert agent('import hashlib; print(hashlib.sha256((web/home).read_bytes()).hexdigest())')==changed
        out['checks']['ticket_outage_no_response']={'status':status,'file_sha256_unchanged':True}
        lab.compose('up','-d','--wait','ticket-store'); stopped=False
        # Replay the original actual decision into n8n to exercise deterministic recovery.
        status,body=hook('respond',replay_body(row)); assert status==200 and body['verdict']=='verified',(status,body)
        row=find_row(); ident=row['ticket']; before=row['response']
        out.update(event_key=row['key'],ticket_id=ident,graylog_event_id=json.loads(row['claim'])['graylog_event_id'],
                   wazuh_event_id=json.loads(row['event'])['wazuh_event_id'])
        out['checks']['same_event_retry_verified']=ticket(ident)['status']=='verified'
        lab.compose('restart','s7-response')
        lab.base.wait_for(lambda: gateway('/respond',{'event_key':row['key'],'ticket_id':ident})['status']==200,30)
        assert find_row()['response']==before
        status,body=hook('respond',replay_body(row)); assert status==200 and body['verdict']=='verified'
        assert len(ticket(ident)['actions'])==1
        out['checks']['restart_replay_same_receipt_no_duplicate']=True
        status,body=completion(row['key'],ident); assert status==200 and body['verdict']=='restored',(status,body)
        assert ticket(ident)['status']=='restored'
        out['final_ticket']=ticket(ident)
        out['checks']['final_restored']=True
        out['result']='pass'
    except Exception as exc:
        out.update(result='fail',error=lab.scrub(str(exc)))
        raise
    finally:
        if stopped: lab.compose('up','-d','--wait','ticket-store')
        lab.graylog('/events/definitions/'+definition+'/unschedule',{},'PUT')
        if out['result']!='pass':
            out['fallback_cleanup']=agent('import shutil; shutil.copyfile(base/"baseline"/home,web/home); print("baseline restored; ticket retained")')
        out['finished_at']=now(); out['source_head']=lab.base.run(['git','rev-parse','HEAD'])
        out['source_dirty_at_run']=bool(lab.base.run(['git','status','--porcelain']))
        out['verifier_sha256']=hashlib.sha256((lab.ROOT/'tools/s7_auto_failures.py').read_bytes()).hexdigest()
        path=lab.LOCAL/(run_id+'.json'); path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('Evidence: '+str(path)+' result='+out['result'])


if __name__=='__main__':
    try: verify()
    except Exception as exc: raise SystemExit(lab.scrub(str(exc)))
