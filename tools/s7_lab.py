"""Manage only the personal haedam-s7-live project. Never stop other stacks."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local/s7'
PROJECT = os.environ.get('S7_PROJECT', 'haedam-s7-live')
if not re.fullmatch(r'haedam-s7-[a-z0-9][a-z0-9-]{0,31}', PROJECT):
    raise ValueError('S7_PROJECT must be haedam-s7- followed by a short lowercase lab name.')
ENV_FILE = ROOT / '.env.s7'
API_CA = LOCAL / (PROJECT + '-api-ca.pem')


def env_values():
    if not ENV_FILE.exists():
        return {}
    return dict(line.split('=', 1) for line in ENV_FILE.read_text(encoding='utf-8-sig').splitlines()
                if '=' in line and not line.startswith('#'))


def scrub(text):
    for key, value in env_values().items():
        if value and ('PASSWORD' in key or 'SECRET' in key):
            text = text.replace(value, '[REDACTED]')
    return text


def run(command, stdin=None, timeout=300):
    result = subprocess.run(command, cwd=ROOT, input=stdin, text=True, encoding='utf-8',
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                            env={k: v for k, v in os.environ.items() if k not in env_values()})
    if result.returncode:
        raise RuntimeError(scrub(result.stderr + result.stdout)[-6000:])
    return result.stdout.strip()


def compose(*args, stdin=None, timeout=300):
    return run(['docker', 'compose', '-p', PROJECT, '--env-file', str(ENV_FILE),
                '-f', 'compose.yaml', '-f', 'compose.s7.yaml', *args], stdin, timeout)


def private_file(path, text):
    path.write_text(text, encoding='utf-8', newline='\n')
    path.chmod(0o600)


def init():
    LOCAL.mkdir(parents=True, exist_ok=True)
    values = env_values()
    for key in ('MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD', 'WAZUH_INDEXER_PASSWORD',
                'WAZUH_API_PASSWORD', 'WAZUH_DASHBOARD_PASSWORD', 'WAZUH_ENROLL_PASSWORD'):
        if not values.get(key):
            values[key] = secrets.token_hex(24) + 'aA1-'
    for key, value in dict(PORTAL_PORT='15020', WAZUH_API_PORT='15520',
                          WAZUH_INDEXER_PORT='19220', WAZUH_DASHBOARD_PORT='15620').items():
        if not values.get(key):
            values[key] = value
    private_file(ENV_FILE, ''.join(f'{k}={v}\n' for k, v in values.items()))
    private_file(LOCAL / 'authd.pass', values['WAZUH_ENROLL_PASSWORD'] + '\n')
    users = LOCAL / 'internal_users.yml'
    if not users.exists():
        hashes = {}
        for user, key in [('admin', 'WAZUH_INDEXER_PASSWORD'), ('kibanaserver', 'WAZUH_DASHBOARD_PASSWORD')]:
            # Credential is sent over stdin, never in the host process command line or console.
            output = run(['docker', 'run', '--rm', '-i', '--network', 'none',
                '-e', 'OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk', '--entrypoint', 'bash',
                'wazuh/wazuh-indexer:4.9.0', '-c',
                'read -r password; password=$(printf "%s" "$password" | tr -d "\\r"); '
                '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$password"'],
                values[key] + '\n')
            hashes[user] = next(line for line in output.splitlines() if line.startswith('$2'))
        private_file(users, '_meta:\n  type: internalusers\n  config_version: 2\n' +
            ''.join(f'{user}:\n  hash: "{digest}"\n  reserved: true\n' +
                    ('  backend_roles: [admin]\n' if user == 'admin' else '') for user, digest in hashes.items()))
    # 4.9 image entrypoint appends a default `hosts` mapping unless this ID exists.
    private_file(LOCAL / 'wazuh.yml', 'hosts:\n  - 1513629884013:\n      url: https://wazuh.manager\n'
        '      port: 55000\n      username: portfolio-api\n      password: ' +
        values['WAZUH_API_PASSWORD'] + '\n      run_as: false\n')
    certs = LOCAL / 'certs'
    if not (certs / 'root-ca.pem').is_file():
        certs.mkdir(exist_ok=True)
        run(['docker', 'run', '--rm', '-v', str(certs) + ':/certificates',
             '-v', str(ROOT / 'infra/wazuh/certs.yml') + ':/config/certs.yml:ro',
             'wazuh/wazuh-certs-generator:0.0.2'], timeout=300)
    # Agent enrollment uses a random shared password on the internal-only 1515 port.
    # No published agent ingress; manager API gets its own generated self-signed cert.
    compose('config', '--quiet')
    print('S7 local secrets and TLS initialized; existing credentials and volumes preserved.')


def tls_context(ca):
    context = ssl.create_default_context(cafile=str(ca))
    # Wazuh 4.9's CA omits KeyUsage. Keep chain/signature validation, using the
    # pre-Python-3.13 X.509 compatibility flags ONLY for this loopback lab client.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    context.check_hostname = False  # certificate SAN is Docker DNS, endpoint is fixed loopback
    return context


def request(port, path, data=None, method=None, auth=None, ca=None):
    headers = {'Content-Type': 'application/json'}
    if auth:
        headers['Authorization'] = auth
    context = tls_context(ca or LOCAL / 'certs/root-ca.pem')
    req = urllib.request.Request('https://127.0.0.1:' + str(port) + path,
        json.dumps(data).encode() if data is not None else None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def basic(user, password):
    return 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()


def api(path, data=None, method=None):
    values = env_values()
    ca = API_CA
    if not ca.exists():
        raise RuntimeError('Run s7_lab.py ready to capture the API certificate from the owned container.')
    status, token = request(values['WAZUH_API_PORT'], '/security/user/authenticate', method='POST',
        auth=basic('portfolio-api', values['WAZUH_API_PASSWORD']), ca=ca)
    if status != 200:
        raise RuntimeError('Wazuh API authentication failed: HTTP ' + str(status))
    status, body = request(values['WAZUH_API_PORT'], path, data, method,
                            'Bearer ' + token['data']['token'], ca)
    if status != 200 or body.get('error') or body.get('data', {}).get('total_failed_items', 0):
        raise RuntimeError(scrub(f'Wazuh API {path}: HTTP {status} {body}'))
    return body['data']


def index(path, data=None):
    values = env_values()
    status, body = request(values['WAZUH_INDEXER_PORT'], path, data,
                          auth=basic('admin', values['WAZUH_INDEXER_PASSWORD']))
    if status != 200:
        raise RuntimeError('Wazuh indexer HTTP ' + str(status))
    return body


def agent_id():
    items = api('/agents?name=haedam-s7-agent')['affected_items']
    if len(items) != 1 or items[0]['status'] != 'active':
        raise RuntimeError('Expected exactly one active haedam-s7-agent.')
    return items[0]['id']


def wait_for(check, timeout=180):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (RuntimeError, OSError, ValueError, KeyError) as exc:
            error = exc
        time.sleep(3)
    raise RuntimeError(scrub('Readiness timed out: ' + str(error)))


def image_drift(path):
    """Files under `path` that differ between the built portal image and the running portal."""
    # Docker's containerd image store can return a non-runnable config digest
    # from `compose images -q`; resolve the built image's manifest instead.
    image_id = run(['docker', 'image', 'inspect', PROJECT + '-portal', '--format', '{{.Id}}'])
    code = ('import hashlib,json,pathlib,sys; root=pathlib.Path(sys.argv[1]); '
            'print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() '
            'for p in root.rglob("*") if p.is_file()},sort_keys=True))')
    expected = json.loads(run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python',
                               image_id, '-c', code, path]))
    actual = json.loads(compose('exec', '-T', 'portal', 'python', '-c', code, path))
    return sorted(k for k in expected.keys() | actual.keys() if expected.get(k) != actual.get(k))


def mount_target(volume):
    """Where the portal mounts this project's named `volume`, from the effective Compose model."""
    portal = json.loads(compose('config', '--format', 'json'))['services']['portal']
    targets = [m['target'] for m in portal.get('volumes', [])
               if m.get('type') == 'volume' and m.get('source') == volume]
    if len(targets) != 1:
        raise RuntimeError('Portal mount for volume ' + volume + ' not found in the Compose config.')
    return targets[0]


def require_image_content(volume):
    # A named volume keeps its first contents; after `up --build` it can shadow newer image code.
    stale = image_drift(mount_target(volume))
    if stale:
        raise RuntimeError(volume + ' volume is stale vs the built portal image (' + ', '.join(stale[:5]) +
                           '); start a new S7_PROJECT instead of reusing this one.')


def ready():
    require_image_content('s7-backend')
    cert = compose('exec', '-T', 'wazuh.manager', 'cat', '/var/ossec/api/configuration/ssl/server.crt')
    private_file(API_CA, cert + '\n')
    ident = wait_for(agent_id)
    wait_for(lambda: index('/_cluster/health').get('status') in ('green', 'yellow'))
    # Require a usable HTTPS UI response, not merely a running container.
    def dashboard():
        context = tls_context(LOCAL / 'certs/root-ca.pem')
        with urllib.request.urlopen('https://127.0.0.1:' + env_values()['WAZUH_DASHBOARD_PORT'],
                                    context=context, timeout=15) as response:
            return response.status == 200
    wait_for(dashboard)
    print('S7 ready: agent ' + ident + ' active; indexer and dashboard reachable.')


def restore(*args):
    return compose('exec', '-T', 's7-agent', '/usr/bin/python3', '-I',
                   '/opt/haedam-s7/bin/s7_restore.py', *args)


def baseline():
    # Refuse to baseline an altered volume: compare every file to the built image first.
    if image_drift(mount_target('s7-web')):
        raise RuntimeError('Web volume differs from the built portal image; baseline refused.')
    exists = compose('exec', '-T', 's7-agent', 'sh', '-c',
                     'if test -f /opt/haedam-s7/state/baseline.sha256; then echo yes; fi')
    print(restore('verify') if exists else restore('baseline'))


def up():
    running = run(['docker', 'ps', '--format', '{{.Label "com.docker.compose.project"}}'])
    if any(line.startswith('haedam-s7-') and line != PROJECT for line in running.splitlines()):
        raise RuntimeError('Another S7 project is active on these ports; stop it first.')
    memory = int(run(['docker', 'info', '--format', '{{.MemTotal}}']))
    if memory < 8 * 1024**3 and any(line != PROJECT for line in running.splitlines()):
        raise RuntimeError('Under 8GiB with other containers running: stop the agreed lab workloads first; none stopped here.')
    compose('up', '-d', '--build', timeout=900)
    print('S7 containers started. Run ready, then baseline, then s7_verify.py.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'up', 'ready', 'baseline', 'status', 'stop'])
    args = parser.parse_args()
    if args.command == 'status':
        print(compose('ps'))
    elif args.command == 'stop':
        print(compose('stop', timeout=180))
    else:
        globals()[args.command]()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit(scrub(str(exc)))
