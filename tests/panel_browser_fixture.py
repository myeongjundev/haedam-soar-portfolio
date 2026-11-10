"""Browser-test server with synthetic workers. NOT a runnable security lab."""
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/lab-panel'))
from lab_panel.core import Engine, now
from lab_panel.server import make_server


def main():
    port=int(sys.argv[1])
    limits=json.loads((ROOT/'infra/panel-settings.json').read_text())
    with tempfile.TemporaryDirectory(prefix='panel-ui-test-') as directory:
        cfg=dict(bind='127.0.0.1',port=port,origin=f'http://127.0.0.1:{port}',state_dir=directory,
                 s7_project='haedam-s7-ui-fixture',scope='synthetic-ui-fixture',
                 targets={'index.html':'restore','assets/s7-probe.txt':'quarantine'})
        cfg.update({key:limits[key] for key in ('http_max_body_bytes','http_drain_timeout_seconds')})
        def runner(action,run,update):
            time.sleep(.3)
            if action=='refresh':
                with engine.db() as db: db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('health',json.dumps({'ready':True,'reason':'ready','observed_at':now(),'links':{}})))
                return
            steps=dict(run.get('steps',{}))
            if action=='attack':
                steps['input']={'at':now(),'detail':'SYNTHETIC UI TEST'}
                update({'stage':'input_sent','input_sha256':'a'*64,'steps':steps})
            elif action=='observe':
                for step in ('wazuh','graylog','response'): steps[step]={'at':now(),'detail':'SYNTHETIC UI TEST'}
                update({'stage':'verified','event_key':'b'*64,'ticket_id':'T-20000101-0001','ticket_status':'verified',
                        'effect':{'home_status':200,'target_status':404},'steps':steps,'observed_at':now()})
            elif action=='restore':
                steps['restore']={'at':now(),'detail':'SYNTHETIC UI TEST'}
                update({'stage':'restored','ticket_status':'restored','steps':steps,'observed_at':now()})
        engine=Engine(cfg,runner);server=make_server(cfg,engine)
        print('SYNTHETIC browser fixture '+cfg['origin'],flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()


if __name__=='__main__': main()
