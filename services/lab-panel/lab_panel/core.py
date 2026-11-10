"""Durable one-job queue. A failed/interrupted run never becomes a success."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import threading
import uuid

from .config import ROOT

STEPS = ('input', 'wazuh', 'graylog', 'response', 'restore')
PATCH_FIELDS = {'stage', 'steps', 'input_sha256', 'input_at', 'baseline_hash',
                'event_key', 'wazuh_event_id', 'graylog_event_id', 'ticket_id',
                'ticket_status', 'effect', 'observed_at', 'detection_paused'}
ERRORS = {
    'lab_unavailable':'지정한 개인 랩이 실행 중인지 확인하세요.',
    'scope_mismatch':'프로젝트 또는 설정이 실행 회차와 다릅니다.',
    'active_ticket':'미완료 티켓이 있습니다. 기존 회차를 먼저 확인하세요.',
    'dirty_target':'대상이 정상 기준과 다릅니다. 새 입력을 보류했습니다.',
    'stale_runtime':'실행 파일과 빌드 이미지가 일치하는지 확인하지 못했습니다. 새 입력을 보류했습니다.',
    'awaiting_detection':'관측 시간 안에 대응 완료를 확인하지 못했습니다. 다시 확인할 수 있습니다.',
    'held_restore':'원복 완료를 확인하지 못했습니다. 실제 티켓과 파일을 확인하세요.',
    'interrupted':'제어판이 중단되었습니다. 입력을 반복하지 말고 현재 상태를 확인하세요.',
    'worker_failed':'작업을 확인하지 못했습니다. 랩 상태와 원천 로그를 확인하세요.',
    'worker_timeout':'작업 시간이 초과됐습니다. 실제 상태 확인 전에는 새 입력을 실행하지 마세요.',
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def source_version():
    paths=[ROOT/'tools/panel_s7_worker.py',ROOT/'tools/s7_auto_verify.py',ROOT/'tools/s7_auto_lab.py']
    paths+=list((ROOT/'services/lab-panel/lab_panel').glob('*.py'))
    head=subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True,timeout=5)
    dirty=subprocess.run(['git','status','--porcelain'],cwd=ROOT,capture_output=True,text=True,timeout=5)
    return {'head':head.stdout.strip(),'dirty':bool(dirty.stdout.strip()),
            'sha256':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}


class Rejected(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


class Engine:
    def __init__(self, config, runner=None):
        self.config = config
        self.root = Path(config['state_dir']); self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'panel.sqlite3'
        self.runner = runner or self.worker
        self.threads = []
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL,
                  request TEXT NOT NULL, run_id TEXT, action TEXT NOT NULL, status TEXT NOT NULL,
                  created_at TEXT NOT NULL, finished_at TEXT, error TEXT);
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_job ON jobs((1)) WHERE status IN ('queued','running');
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
            for row in db.execute("SELECT run_id FROM jobs WHERE status IN ('queued','running') AND run_id IS NOT NULL"):
                data = json.loads(db.execute('SELECT data FROM runs WHERE id=?', (row[0],)).fetchone()[0])
                data.update(stage='needs_check' if data.get('input_sha256') else 'not_started', error='interrupted')
                db.execute('UPDATE runs SET data=? WHERE id=?', (json.dumps(data), row[0]))
            db.execute("UPDATE jobs SET status='interrupted',error='interrupted',finished_at=? WHERE status IN ('queued','running')", (now(),))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def state(self):
        with self.db() as db:
            runs = [json.loads(r[0]) for r in db.execute('SELECT data FROM runs ORDER BY rowid DESC LIMIT 50')]
            jobs = [dict(r) for r in db.execute('SELECT id,run_id,action,status,created_at,finished_at,error FROM jobs ORDER BY rowid DESC LIMIT 30')]
            health = db.execute("SELECT value FROM meta WHERE key='health'").fetchone()
        return {'project':self.config['s7_project'], 'targets':self.config['targets'], 'runs':runs, 'jobs':jobs,
                'health':json.loads(health[0]) if health else {'ready':False,'reason':'unchecked'},
                'errors':ERRORS, 'observed_at':now()}

    def submit(self, body):
        if not isinstance(body, dict) or body.get('action') not in ('refresh','attack','observe','restore'):
            raise Rejected('invalid_action',400)
        action = body['action']
        fields = {'action','request_id'} | ({'target'} if action=='attack' else {'run_id'} if action in ('observe','restore') else set())
        if set(body) != fields or not re.fullmatch(r'[0-9a-f-]{36}', str(body.get('request_id',''))):
            raise Rejected('invalid_fields',400)
        request = json.dumps(body, sort_keys=True)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT * FROM jobs WHERE request_id=?',(body['request_id'],)).fetchone()
            if existing:
                if existing['request'] != request: raise Rejected('request_conflict')
                return {'job_id':existing['id'],'run_id':existing['run_id'],'duplicate':True}
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','running')").fetchone():
                raise Rejected('busy')
            run = None
            if action == 'attack':
                if body['target'] not in self.config['targets']: raise Rejected('invalid_target',400)
                if any(json.loads(r[0])['stage'] not in ('restored','not_started') for r in db.execute('SELECT data FROM runs')):
                    raise Rejected('unfinished_run')
                run = dict(id=str(uuid.uuid4()), target=body['target'], project=self.config['s7_project'],
                           scope=self.config['scope'], source=source_version(), created_at=now(), stage='preparing', steps={}, error=None)
                db.execute('INSERT INTO runs VALUES (?,?)',(run['id'],json.dumps(run)))
            elif action in ('observe','restore'):
                record = db.execute('SELECT data FROM runs WHERE id=?',(body['run_id'],)).fetchone()
                if not record: raise Rejected('unknown_run',404)
                run = json.loads(record[0])
                if run['scope'] != self.config['scope']: raise Rejected('scope_mismatch')
                if action=='restore' and not run.get('event_key'): raise Rejected('observe_first')
            job = str(uuid.uuid4())
            db.execute('INSERT INTO jobs(id,request_id,request,run_id,action,status,created_at) VALUES (?,?,?,?,?,?,?)',
                       (job,body['request_id'],request,run['id'] if run else None,action,'queued',now()))
        thread = threading.Thread(target=self.execute, args=(job,action,run), daemon=True)
        self.threads.append(thread); thread.start()
        return {'job_id':job,'run_id':run['id'] if run else None,'duplicate':False}

    def patch(self, run_id, data):
        if not isinstance(data,dict) or set(data)-PATCH_FIELDS: raise ValueError('Invalid worker update')
        if 'steps' in data and set(data['steps'])-set(STEPS): raise ValueError('Invalid step')
        with self.db() as db:
            run = json.loads(db.execute('SELECT data FROM runs WHERE id=?',(run_id,)).fetchone()[0])
            run.update(data); run['error']=None
            db.execute('UPDATE runs SET data=? WHERE id=?',(json.dumps(run),run_id))

    def execute(self, job, action, run):
        error = None
        with self.db() as db: db.execute("UPDATE jobs SET status='running' WHERE id=?",(job,))
        try:
            self.runner(action, run, lambda patch:self.patch(run['id'],patch) if run else None)
        except Exception as exc:
            error = str(exc) if str(exc) in ERRORS else 'worker_failed'
        with self.db() as db:
            db.execute('UPDATE jobs SET status=?,finished_at=?,error=? WHERE id=?',('failed' if error else 'succeeded',now(),error,job))
            if error and run:
                current = json.loads(db.execute('SELECT data FROM runs WHERE id=?',(run['id'],)).fetchone()[0])
                current.update(error=error, stage='needs_check' if current.get('input_sha256') else 'not_started')
                db.execute('UPDATE runs SET data=? WHERE id=?',(json.dumps(current),run['id']))

    def worker(self, action, run, update):
        payload = {'action':action,'run':run,'config':self.config}
        proc = subprocess.Popen([sys.executable, '-u', str(ROOT/'tools/panel_s7_worker.py')],
                                cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                text=True,encoding='utf-8')
        timed_out = threading.Event()
        def expire():
            timed_out.set(); proc.kill()
        timer = threading.Timer(self.config['worker_timeout_seconds'], expire); timer.start()
        terminal = False
        try:
            proc.stdin.write(json.dumps(payload)+'\n'); proc.stdin.flush()
            for line in proc.stdout:
                message = json.loads(line)
                if message['type']=='patch':
                    update(message['data'])
                    # Persist preparation before granting the worker permission to mutate.
                    proc.stdin.write('ack\n'); proc.stdin.flush()
                elif message['type']=='health':
                    with self.db() as db:
                        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('health',json.dumps(message['data'])))
                elif message['type']=='done': terminal=True
                elif message['type']=='error': raise RuntimeError(message['code'])
                else: raise RuntimeError('worker_failed')
            code=proc.wait()
            if timed_out.is_set(): raise RuntimeError('worker_timeout')
            if code or not terminal: raise RuntimeError('worker_failed')
        finally:
            timer.cancel()
            if proc.poll() is None: proc.kill()
            proc.wait(); proc.stdout.close(); proc.stdin.close()

    def evidence(self, ident):
        with self.db() as db:
            row=db.execute('SELECT data FROM runs WHERE id=?',(ident,)).fetchone()
            if not row: raise Rejected('unknown_run',404)
            jobs=[dict(r) for r in db.execute('SELECT action,status,created_at,finished_at,error FROM jobs WHERE run_id=?',(ident,))]
        return {'kind':'panel-observed-run','run':json.loads(row[0]),'jobs':jobs,'exported_at':now()}
