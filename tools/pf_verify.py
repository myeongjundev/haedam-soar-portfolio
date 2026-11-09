"""P04: real client traffic crosses the personal pfSense VM; the team adapter blocks one source, then releases it.

Every success below is read from the clients, the adapter's own JSON and pfctl on the VM. Nothing is injected.
Prerequisites: pf_lab.py up, config applied, adapter installed, serial console at the pfSense shell.
"""
import json
import subprocess
import time
from datetime import datetime, timezone

import pf_lab as lab

S = lab.SETTINGS
TARGET, NORMAL = S['clients']['attacker'], S['clients']['normal']
PORTAL = f"{S['portal']['ip']}:{S['portal']['port']}"
URL = f"http://{PORTAL}{S['portal']['health_path']}"
PROBE = ("import sys,time\nfrom urllib.request import urlopen\nt=time.monotonic()\n"
         "try:\n    r=urlopen(sys.argv[1],timeout=float(sys.argv[2])); print(r.status, round(time.monotonic()-t,3))\n"
         "except Exception as e:\n    print(type(e).__name__, round(time.monotonic()-t,3))\n")
# The forced command on pfSense ignores the remote command name; arguments are parsed by the adapter.
SSH = ('install -m 600 /ssh/controller /tmp/key && exec ssh -i /tmp/key -o UserKnownHostsFile=/ssh/known_hosts '
       '-o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 "$0" haedam-pf-response "$@"')
DESTINATION = f"{S['controller']['ssh_user']}@{S['lan']['pfsense_ip']}"


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def probe(service, timeout=5):
    status, seconds = lab.compose('exec', '-T', service, 'python', '-c', PROBE, URL, str(timeout)).split()
    return {'at': now(), 'result': int(status) if status.isdigit() else status, 'seconds': float(seconds)}


def adapter(action, request_id, owner):
    run = lab.compose('exec', '-T', 'controller', 'sh', '-c', SSH, DESTINATION, action, TARGET, request_id, owner,
                      check=False, timeout=120)
    try:
        body = json.loads(run.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise RuntimeError(f'adapter gave no JSON (exit {run.returncode}): {lab.scrub(run.stderr)[-500:]}') from None
    return {'exit': run.returncode, **body}


def pf(command):
    status, out = lab.shell(command, 4)
    if status:
        raise RuntimeError(f'pfSense command failed ({status}): {command}')
    return out


def states(source):
    return [line.strip() for line in pf('pfctl -ss').splitlines() if source + ':' in line and PORTAL in line]


def easyrule_rules():
    return [line for line in pf('pfctl -sr').splitlines() if '<EasyRuleBlockHostsWAN>' in line]


def verify():
    run_id = 'P04-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    owner, out = run_id, {'run_id': run_id, 'started_at': now(), 'checks': {}}
    out['appliance'] = {'version': pf('cat /etc/version'),
                        'adapter_sha256': pf('sha256 -q ' + S['adapter_path']),
                        'config_sha256': pf('sha256 -q /cf/conf/config.xml')}

    out['preflight'] = adapter('status', run_id + '-status-0', owner)
    assert out['preflight']['ok'] and out['preflight']['state']['ready'], out['preflight']
    assert not out['preflight']['state']['configured'] and not easyrule_rules(), 'start from an empty EasyRule state'

    out['baseline'] = {'attacker': probe('attacker'), 'normal': probe('normal')}
    out['baseline']['pf_states'] = {'attacker': states(TARGET), 'normal': states(NORMAL)}
    assert out['baseline']['attacker']['result'] == out['baseline']['normal']['result'] == 200, out['baseline']
    assert all(out['baseline']['pf_states'].values()), 'traffic did not create pfSense states'
    out['checks']['path_crosses_pfsense'] = True

    out['block'] = adapter('block', run_id + '-block', owner)
    assert out['block']['ok'] and out['block']['result'] == 'applied' and out['block']['applied_verified'], out['block']
    out['blocked'] = {'attacker': probe('attacker'), 'normal': probe('normal'), 'rules': easyrule_rules()}
    assert out['blocked']['attacker']['result'] != 200, out['blocked']
    assert out['blocked']['normal']['result'] == 200, out['blocked']
    out['checks']['target_dropped_normal_kept'] = True

    other = adapter('block', run_id + '-other-owner', run_id + '-other')
    assert not other['ok'], other
    out['checks']['other_owner_refused'] = other['reason']

    out['unblock'] = adapter('unblock', run_id + '-unblock', owner)
    assert out['unblock']['ok'] and out['unblock']['result'] == 'released', out['unblock']
    time.sleep(1)
    out['restored'] = {'attacker': probe('attacker'), 'normal': probe('normal')}
    assert out['restored']['attacker']['result'] == out['restored']['normal']['result'] == 200, out['restored']

    replay = adapter('block', run_id + '-block', owner)
    out['checks']['block_replay'] = {'replayed': replay.get('replayed'), 'changed': replay.get('changed'),
                                     'attacker_after': probe('attacker')['result']}
    assert replay.get('replayed') and out['checks']['block_replay']['attacker_after'] == 200, replay

    out['final'] = adapter('status', run_id + '-status-1', owner)
    final = out['final']['state']
    assert out['final']['ok'] and not final['configured'] and not final['table_present'] and not final['rule_present']
    assert not easyrule_rules(), 'EasyRule rule left behind'
    out['checks']['final_empty'] = True
    out['finished_at'] = now()
    out['result'] = 'PASS'
    return out


def main():
    lab.LOCAL.mkdir(parents=True, exist_ok=True)
    try:
        out = verify()
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit('FAIL: ' + lab.scrub(f'{type(error).__name__}: {error}')[:2000])
    path = lab.LOCAL / (out['run_id'] + '.json')
    path.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    print('PASS', path)


if __name__ == '__main__':
    main()
