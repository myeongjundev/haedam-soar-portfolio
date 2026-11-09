"""Durable Wazuh alert relay and narrowly scoped AR gateway. n8n owns ticket writes.

No Docker socket, no shell execution, no admin Wazuh user, no ticket-store key.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from policy import normalize, validate_claim
from settings import load_settings

SETTINGS = load_settings()
PATHS, URLS = SETTINGS['paths'], SETTINGS['urls']
DATA = Path(PATHS['gateway_data'])
WEB = Path(PATHS['gateway_web'])
BASE = Path(PATHS['gateway_baseline'])
RECEIPTS = Path(PATHS['gateway_receipts'])
ALERTS = Path(PATHS['gateway_alerts']) / 'alerts/alerts.json'
LOCK = threading.RLock()
AGENT = os.environ['S7_AGENT_ID']
KEY = os.environ['S7_BRIDGE_KEY']
OPERATOR = os.environ['S7_COMPLETE_KEY']


class Held(Exception):
    def __init__(self, message, status=409):
        self.status = status
        super().__init__(message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


@contextmanager
def db():
    conn = sqlite3.connect(DATA / 'state.db', timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def baseline():
    values = {}
    for line in (BASE / 'baseline.sha256').read_text().splitlines():
        value, key = line.split('  ', 1)
        if not re.fullmatch('[0-9a-f]{64}', value) or Path(key).is_absolute() or '..' in Path(key).parts or key in values:
            raise Held('invalid_baseline')
        saved = BASE / 'baseline' / key
        if saved.is_symlink() or not saved.is_file() or digest(saved) != value:
            raise Held('baseline_tampered')
        values[key] = value
    if not values or SETTINGS['home_file'] not in values:
        raise Held('missing_baseline')
    return values


def current(key):
    path = WEB / key
    if key not in SETTINGS['targets'] or path.is_symlink() or path.parent.resolve() != path.parent:
        raise Held('unsafe_path')
    return digest(path) if path.is_file() else 'absent'


def call(url, data=None, headers=None, method=None, context=None, timeout=8):
    req = urllib.request.Request(url, json.dumps(data).encode() if data is not None else None,
                                 {'Content-Type': 'application/json', **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            raw = response.read()
            return response.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wazuh(path, body=None, method=None):
    context = ssl.create_default_context(cafile=PATHS['ca_file'])
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT  # pinned 4.9 CA; signature/hostname checks stay enabled
    auth = base64.b64encode((SETTINGS['wazuh_user'] + ':' + os.environ['S7_WAZUH_PASSWORD']).encode()).decode()
    status, raw = call(URLS['wazuh_api'] + '/security/user/authenticate', method='POST',
                       headers={'Authorization': 'Basic ' + auth}, context=context)
    if status != 200:
        raise Held('wazuh_auth_unavailable', 503)
    token = json.loads(raw)['data']['token']
    status, raw = call(URLS['wazuh_api'] + path, body, {'Authorization': 'Bearer ' + token}, method, context)
    result = json.loads(raw)
    if status != 200 or result.get('error') or result.get('data', {}).get('total_failed_items'):
        raise Held('wazuh_request_failed', 503)
    return result['data']


def load(key):
    if not re.fullmatch('[0-9a-f]{64}', str(key)):
        raise Held('invalid_event', 400)
    with db() as conn:
        row = conn.execute('SELECT * FROM events WHERE key=?', (key,)).fetchone()
    if row is None:
        raise Held('unknown_wazuh_event', 404)
    return dict(row)


def claim(body):
    validate_claim(body)
    row = load(body['event_key'])
    event = json.loads(row['event'])
    if row['claim']:
        return json.loads(row['claim'])
    if current(event['file_key']) != event['expected_hash']:
        raise Held('stale_file_hash')
    canonical = {**event, **body, 'baseline_hash': digest(BASE / 'baseline.sha256')}
    canonical['group_key'] = 'S7:' + SETTINGS['asset_id'] + ':' + event['event_key']
    with db() as conn:
        conn.execute('UPDATE events SET claim=? WHERE key=? AND claim IS NULL', (json.dumps(canonical), body['event_key']))
    return canonical


def effect(event):
    values = baseline()
    for key, expected in values.items():
        path = WEB / key
        if path.is_symlink() or path.parent.resolve() != path.parent or not path.is_file() or digest(path) != expected:
            raise Held('webroot_not_restored')
    actual = {str(p.relative_to(WEB)) for p in WEB.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != set(values):
        raise Held('extra_web_files')
    code, page = call(URLS['portal'] + '/')
    if code != 200 or hashlib.sha256(page).hexdigest() != values[SETTINGS['home_file']]:
        raise Held('http_home_mismatch')
    status = 200
    if event['action'] == 'quarantine':
        status, _ = call(URLS['portal'] + '/' + event['file_key'])
        if status != 404:
            raise Held('http_probe_still_reachable')
    return {'home_status': 200, 'target_status': status, 'baseline_files': len(values),
            'home_sha256': values[SETTINGS['home_file']]}


def respond(body, complete=False):
    required = {'event_key', 'ticket_id'} | ({'execution_id'} if complete else set())
    if set(body) != required or not re.fullmatch(r'T-\d{8}-\d{4}', str(body.get('ticket_id', ''))):
        raise Held('invalid_request', 400)
    if complete and not re.fullmatch(r'\d{1,20}', str(body['execution_id'])):
        raise Held('invalid_execution', 400)
    key, ticket = body['event_key'], body['ticket_id']
    row = load(key)
    if not row['claim']:
        raise Held('unclaimed_event')
    event = json.loads(row['claim'])
    if row['ticket'] and row['ticket'] != ticket:
        raise Held('wrong_ticket_owner')
    column = 'completion' if complete else 'response'
    if row[column]:
        effect(event)  # old successful record never masks current state drift
        return json.loads(row[column])
    if complete and not row['response']:
        raise Held('response_not_verified')
    receipt_file = RECEIPTS / (key + ('.completed' if complete else '') + '.json')
    if not complete and not row['requested_at'] and current(event['file_key']) != event['expected_hash']:
        raise Held('stale_file_hash')
    with db() as conn:
        conn.execute('UPDATE events SET ticket=?, requested_at=COALESCE(requested_at,?) WHERE key=?', (ticket, now(), key))
    if not receipt_file.exists():
        if complete:
            effect(event)
        else:
            agents = wazuh('/agents?agents_list=' + AGENT)['affected_items']
            if len(agents) != 1 or agents[0]['status'] != 'active' or agents[0]['name'] != SETTINGS['agent_name']:
                raise Held('agent_unavailable', 503)
        args = [key, ticket, event['file_key'], event['expected_hash'], event['baseline_hash'], 'complete' if complete else 'respond']
        wazuh('/active-response?agents_list=' + AGENT, {'command': '!' + SETTINGS['ar_command'], 'arguments': args}, 'PUT')
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and not receipt_file.exists():
            time.sleep(0.2)
    if not receipt_file.exists():
        raise Held('awaiting_agent_receipt', 503)
    receipt = json.loads(receipt_file.read_text())
    if receipt.get('result') != 'ok' or receipt.get('ticket_id') != ticket or receipt.get('job') != key:
        raise Held('agent_rejected_' + receipt.get('reason', 'invalid_receipt'))
    observed = effect(event)
    output = {**event, 'ticket_id': ticket, 'requested_at': receipt['requested_at'],
              'finished_at': receipt['finished_at'], 'effect_verified_at': now(), 'effect': observed,
              'execution_id': body['execution_id'] if complete else event['execution_id'],
              'result': 'released' if complete else 'applied', 'receipt': receipt}
    with db() as conn:
        conn.execute(f'UPDATE events SET {column}=? WHERE key=?', (json.dumps(output), key))
    return output


def collect_once():
    values = baseline()
    info = ALERTS.stat()
    with db() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()
    saved = json.loads(row[0]) if row else {}
    offset = saved.get('offset', 0) if saved.get('inode') == info.st_ino else 0
    if offset > info.st_size:
        offset = 0
    with ALERTS.open('rb') as source:
        source.seek(offset)
        for _ in range(200):
            line = source.readline(131073)
            oversized = len(line) > 131072
            if oversized:
                # Drain a complete oversized record without retaining its body.
                # An incomplete tail is not acknowledged and is retried later.
                while line and not line.endswith(b'\n'):
                    line = source.readline(131073)
            if not line or not line.endswith(b'\n'):
                break  # do not acknowledge partial writes
            try:
                event = None if oversized else normalize(json.loads(line), AGENT, values, SETTINGS)
            except (ValueError, KeyError, TypeError):
                event = None
            if event:
                with db() as conn:
                    conn.execute('INSERT OR IGNORE INTO events(key,event) VALUES (?,?)', (event['event_key'], json.dumps(event)))
            with db() as conn:
                conn.execute("INSERT OR REPLACE INTO meta VALUES ('cursor',?)", (json.dumps({'inode': info.st_ino, 'offset': source.tell()}),))
    with db() as conn:
        pending = conn.execute('SELECT key,event FROM events WHERE delivered=0 LIMIT 20').fetchall()
    for row in pending:
        event = json.loads(row['event'])
        packet = {'version': '1.1', 'host': SETTINGS['relay_source'], 'short_message': 'S7 trusted FIM candidate',
                  'timestamp': datetime.fromisoformat(event['alert_at']).timestamp(),
                  '_event_key': event['event_key'], '_file_key': event['file_key'],
                  '_agent_id': AGENT, '_wazuh_event_id': event['wazuh_event_id'], '_case_id': 'S7', '_asset_id': SETTINGS['asset_id']}
        status, _ = call(URLS['graylog_gelf'], packet)
        if status not in (200, 202):
            raise Held('graylog_ingest_unavailable', 503)
        with db() as conn:
            conn.execute('UPDATE events SET delivered=1 WHERE key=?', (row['key'],))


def relay():
    previous = None
    while True:
        try:
            collect_once()
            previous = None
        except Exception as exc:
            code = type(exc).__name__  # never log raw alerts, bodies or credentials
            if code != previous:
                print('relay waiting: ' + code, flush=True)
            previous = code
        time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != '/health':
            return self.reply(404, {'ok': False})
        try:
            baseline()
            return self.reply(200, {'ok': True})
        except Exception:
            return self.reply(503, {'ok': False})

    def do_POST(self):
        secret = OPERATOR if self.path == '/complete' else KEY
        if not hmac.compare_digest(self.headers.get('X-S7-Key', '').encode(), secret.encode()):
            return self.reply(403, {'ok': False, 'error': 'forbidden'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise Held('invalid_body_size', 400)
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise Held('invalid_body', 400)
            with LOCK:
                if self.path == '/claim':
                    result = claim(body)
                elif self.path in ('/respond', '/complete'):
                    result = respond(body, self.path == '/complete')
                else:
                    raise Held('not_found', 404)
            self.reply(200, {'ok': True, 'data': result})
        except Held as exc:
            self.reply(exc.status, {'ok': False, 'error': str(exc)})
        except (ValueError, KeyError, TypeError):
            self.reply(400, {'ok': False, 'error': 'invalid_request'})
        except Exception:
            self.reply(503, {'ok': False, 'error': 'dependency_unavailable'})


if __name__ == '__main__':
    if not re.fullmatch(r'\d{3,8}', AGENT) or len(KEY) < 32 or len(OPERATOR) < 32 or KEY == OPERATOR:
        raise SystemExit('Invalid S7 scope or keys')
    DATA.mkdir(exist_ok=True)
    with db() as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS events(key TEXT PRIMARY KEY, event TEXT NOT NULL, delivered INTEGER DEFAULT 0, '
                     'claim TEXT, ticket TEXT, requested_at TEXT, response TEXT, completion TEXT)')
    threading.Thread(target=relay, daemon=True).start()
    ThreadingHTTPServer((SETTINGS['gateway_bind'], urlsplit(URLS['gateway']).port), Handler).serve_forever()
