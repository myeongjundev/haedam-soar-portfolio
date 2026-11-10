"""HTTP front for the team pfSense adapter, for n8n (its SSH node cannot pin a host key; this relay does).

Only POST /pf from the one configured n8n address, with the relay key and exactly
{action, target, request_id, owner_id}: action status|block|unblock, target the configured lab source, IDs in the
adapter's own format. The adapter runs over SSH with the pinned host key and the controller's forced command; the
reply is its exit code, stdout (the adapter JSON) and a short stderr. One call at a time; no retries.
"""
import hmac
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ['PF_RELAY_KEY']
ALLOWED = os.environ['PF_RELAY_ALLOWED']
TARGET = os.environ['PF_TARGET']
PORT = int(os.environ['PF_RELAY_PORT'])
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$')
SSH = ['ssh', '-i', '/tmp/key', '-o', 'UserKnownHostsFile=/ssh/known_hosts', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
       os.environ['PF_USER'] + '@' + os.environ['PF_HOST'], 'haedam-pf-response']
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # never log bodies or keys

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200 if self.path == '/health' else 404, {'ok': self.path == '/health'})

    def do_POST(self):
        if self.client_address[0] != ALLOWED:
            return self.reply(403, {'error': 'forbidden_source'})
        if not hmac.compare_digest(self.headers.get('X-PF-Relay-Key', '').encode(), KEY.encode()):
            return self.reply(403, {'error': 'forbidden'})
        if self.path != '/pf':
            return self.reply(404, {'error': 'not_found'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            body = json.loads(self.rfile.read(size)) if 0 < size <= 2048 else None
        except ValueError:
            body = None
        if (not isinstance(body, dict) or set(body) != {'action', 'target', 'request_id', 'owner_id'}
                or body['action'] not in ('status', 'block', 'unblock') or body['target'] != TARGET
                or not all(isinstance(body[k], str) and ID.match(body[k]) for k in ('request_id', 'owner_id'))):
            return self.reply(400, {'error': 'invalid_request'})
        with LOCK:
            try:
                run = subprocess.run(SSH + [body['action'], body['target'], body['request_id'], body['owner_id']],
                                     capture_output=True, text=True, timeout=110)
            except subprocess.TimeoutExpired:
                return self.reply(504, {'error': 'adapter_timeout'})  # outcome unknown: never a success
        self.reply(200, {'code': run.returncode, 'stdout': run.stdout[-8000:], 'stderr': run.stderr[-300:]})


if __name__ == '__main__':
    if len(KEY) < 32:
        raise SystemExit('Relay key missing')
    ipaddress.ip_address(TARGET), ipaddress.ip_address(ALLOWED)  # refuse to start on a bad scope
    shutil.copyfile('/ssh/controller', '/tmp/key')
    os.chmod('/tmp/key', 0o600)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
