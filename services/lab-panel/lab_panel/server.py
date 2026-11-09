"""Small loopback HTTP server with same-origin, cookie and CSRF checks."""
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import re
import secrets

from .config import ROOT, load_config
from .core import Engine, Rejected

STATIC=Path(__file__).resolve().parents[1]/'static'


@contextmanager
def instance_lock(project):
    directory=ROOT/'.local'; directory.mkdir(exist_ok=True)
    with (directory/(project+'-panel.lock')).open('a+b') as handle:
        handle.seek(0); handle.write(b'0'); handle.flush(); handle.seek(0)
        try:
            import msvcrt
        except ImportError:
            import fcntl
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        else:
            msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
        try: yield
        finally:
            handle.seek(0)
            try: import msvcrt
            except ImportError: fcntl.flock(handle,fcntl.LOCK_UN)
            else: msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)


def make_server(config, engine):
    session=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
    authority=config['origin'].split('://',1)[1]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass

        def send(self,status,body,mime='application/json; charset=utf-8',cookie=False,download=False):
            raw=json.dumps(body,ensure_ascii=False).encode() if not isinstance(body,bytes) else body
            self.send_response(status)
            self.send_header('Content-Type',mime); self.send_header('Content-Length',str(len(raw)))
            self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            if cookie: self.send_header('Set-Cookie','panel_session='+session+'; HttpOnly; SameSite=Strict; Path=/')
            if download: self.send_header('Content-Disposition','attachment; filename="panel-evidence.json"')
            self.end_headers(); self.wfile.write(raw)

        def allowed(self,write=False):
            if self.headers.get('Host')!=authority: return False
            if self.headers.get('Sec-Fetch-Site')=='cross-site': return False
            try:
                cookies=SimpleCookie(self.headers.get('Cookie',''))
                actual=cookies['panel_session'].value if 'panel_session' in cookies else ''
            except Exception: return False
            if not hmac.compare_digest(actual,session): return False
            if write and (self.headers.get('Origin')!=config['origin'] or
                          not hmac.compare_digest(self.headers.get('X-Panel-CSRF',''),csrf)):
                return False
            return True

        def do_GET(self):
            if self.headers.get('Host')!=authority or self.headers.get('Sec-Fetch-Site')=='cross-site':
                return self.send(403,{'error':'forbidden'})
            files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),
                   '/style.css':('style.css','text/css; charset=utf-8')}
            if self.path in files:
                name,mime=files[self.path]
                return self.send(200,(STATIC/name).read_bytes(),mime,cookie=self.path=='/')
            if not self.allowed(): return self.send(403,{'error':'forbidden'})
            if self.path=='/api/state': return self.send(200,{**engine.state(),'csrf':csrf})
            match=re.fullmatch(r'/api/runs/([0-9a-f-]{36})/evidence',self.path)
            if match:
                try: return self.send(200,engine.evidence(match[1]),download=True)
                except Rejected as exc: return self.send(exc.status,{'error':exc.code})
            return self.send(404,{'error':'not_found'})

        def do_POST(self):
            if not self.allowed(True): return self.send(403,{'error':'forbidden'})
            if self.path!='/api/jobs': return self.send(404,{'error':'not_found'})
            if self.headers.get('Content-Type','').split(';')[0]!='application/json':
                return self.send(415,{'error':'json_required'})
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=2048: return self.send(413,{'error':'invalid_size'})
                body=json.loads(self.rfile.read(size))
                return self.send(202,engine.submit(body))
            except Rejected as exc: return self.send(exc.status,{'error':exc.code})
            except (ValueError,TypeError): return self.send(400,{'error':'invalid_request'})
            except Exception: return self.send(503,{'error':'unavailable'})
    server=ThreadingHTTPServer((config['bind'],config['port']),Handler)
    server.daemon_threads=True
    return server


def main():
    config=load_config()
    with instance_lock(config['s7_project']):
        engine=Engine(config)
        server=make_server(config,engine)
        print('Personal lab panel: '+config['origin'],flush=True)
        print('Docker lifecycle and S10 are not controlled by this process.',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()
