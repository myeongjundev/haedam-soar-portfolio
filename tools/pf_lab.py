"""Manage only the personal pfSense lab (project haedam-pf-lab). Standard library only.

The pfSense VM's screen and keyboard go through the QEMU monitor, its console through the serial socket.
No global Docker, Windows, VMware or existing-container settings are changed.
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Lab addresses, interfaces, ports and paths: one file shared by Compose, the config generator and the verifier.
SETTINGS_PATH = Path(os.environ.get('PF_LAB_SETTINGS', ROOT / 'infra/pfsense/lab-settings.json'))
SETTINGS = json.loads(SETTINGS_PATH.read_text(encoding='utf-8'))
PROJECT = SETTINGS['project']
ENV = ROOT / '.env.pf'
LOCAL = ROOT / '.local/pf'
FILES = ['compose.yaml', 'compose.pf.yaml']


def compose_env(settings=SETTINGS):
    """Variables compose.pf.yaml reads; Compose refuses to start if any is missing."""
    wan, lan = settings['wan'], settings['lan']
    return {'PF_WAN_SUBNET': wan['subnet'], 'PF_WAN_GATEWAY': wan['docker_gateway'],
            'PF_WAN_BRIDGE_IP': wan['bridge_ip'], 'PF_WAN_PFSENSE_IP': wan['pfsense_ip'],
            'PF_LAN_SUBNET': lan['subnet'], 'PF_LAN_GATEWAY': lan['docker_gateway'],
            'PF_LAN_BRIDGE_IP': lan['bridge_ip'], 'PF_LAN_PFSENSE_IP': lan['pfsense_ip'],
            'PF_PORTAL_IP': settings['portal']['ip'], 'PF_CONTROLLER_IP': settings['controller']['ip'],
            'PF_ATTACKER_IP': settings['clients']['attacker'], 'PF_NORMAL_IP': settings['clients']['normal'],
            'PF_MEMORY': str(settings['vm']['memory_mb'])}
# QEMU sendkey names for characters typed on the VGA console.
KEYS = {' ': 'spc', '.': 'dot', '/': 'slash', '-': 'minus', '=': 'equal', ',': 'comma', ';': 'semicolon',
        "'": 'apostrophe', '\n': 'ret', '_': 'shift-minus', ':': 'shift-semicolon', '"': 'shift-apostrophe',
        '>': 'shift-dot', '<': 'shift-comma', '|': 'shift-backslash', '&': 'shift-7', '*': 'shift-8',
        '(': 'shift-9', ')': 'shift-0', '+': 'shift-equal', '!': 'shift-1', '@': 'shift-2', '#': 'shift-3',
        '$': 'shift-4', '%': 'shift-5', '^': 'shift-6', '~': 'shift-grave_accent', '\\': 'backslash'}


def env_values():
    if not ENV.exists():
        return {}
    return dict(line.split('=', 1) for line in ENV.read_text(encoding='utf-8-sig').splitlines()
                if '=' in line and not line.lstrip().startswith('#'))


def scrub(value):
    for key, secret in env_values().items():
        if secret and any(word in key for word in ('KEY', 'PASSWORD', 'SECRET')):
            value = value.replace(secret, '[REDACTED]')
    return value


def compose(*args, stdin=None, timeout=300, check=True):
    files = [x for f in FILES for x in ('-f', f)]
    run = subprocess.run(['docker', 'compose', '-p', PROJECT, '--env-file', str(ENV), *files, *args],
                         cwd=ROOT, input=stdin, text=True, encoding='utf-8', stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=timeout,
                         env={**{k: v for k, v in os.environ.items() if k not in env_values()}, **compose_env()})
    if not check:
        return run
    if run.returncode:
        raise RuntimeError(scrub(run.stderr + run.stdout)[-5000:])
    return run.stdout.strip()


def monitor(command):
    return compose('exec', '-T', 'pfsense', 'sh', '-c',
                   'printf "%s\\n" "$1" | socat -t 2 - UNIX-CONNECT:/run/qemu/monitor.sock', 'monitor', command)


def keys(*names, delay=0.15):
    for name in names:
        monitor('sendkey ' + name)
        time.sleep(delay)


def type_text(text):
    names = []
    for char in text:
        if char.isalpha():
            names.append(('shift-' if char.isupper() else '') + char.lower())
        elif char.isdigit():
            names.append(char)
        else:
            names.append(KEYS[char])
    keys(*names, delay=0.05)


def serial(text, wait=5.0):
    """Write lines to the guest serial console and return what it printed within `wait` seconds."""
    return compose('exec', '-T', 'pfsense', 'sh', '-c',
                   '(cat; sleep "$1") | socat -t 1 - UNIX-CONNECT:/run/qemu/serial.sock', 'serial', str(wait),
                   stdin=text, timeout=wait + 60)


def shell(command, wait=5.0):
    """Run one command in the pfSense shell on the serial console (console menu option 8 must be open).

    pfSense's root shell runs `resizewin` around each prompt, which waits ~1s for a terminal size reply
    and swallows input that arrives meanwhile, so the command is sent only after a settling newline.
    That shell is tcsh, so the command travels base64-encoded and runs under /bin/sh (no quoting issues),
    in short lines because the console's canonical input line is limited (about 255 bytes).
    """
    encoded = base64.b64encode(command.encode()).decode()
    lines = ['rm -f /tmp/pfcmd.b64'] + [f'echo {encoded[i:i + 160]} >> /tmp/pfcmd.b64'
                                        for i in range(0, len(encoded), 160)]
    lines.append('echo __BEGIN__; b64decode -r < /tmp/pfcmd.b64 | /bin/sh; echo __END__$?')
    out = compose('exec', '-T', 'pfsense', 'sh', '-c',
                  '(sleep 1; printf "\\r"; sleep 3; while IFS= read -r l; do printf "%s\\r" "$l"; sleep 2.5; done; '
                  'sleep "$1") | socat -t 1 - UNIX-CONNECT:/run/qemu/serial.sock',
                  'serial', str(wait), stdin='\n'.join(lines) + '\n', timeout=wait + 3 * len(lines) + 60)
    if '__BEGIN__' not in out or '__END__' not in out:
        raise RuntimeError('No shell markers on the serial console; open the shell (menu option 8) first.')
    body = out.rsplit('__BEGIN__', 1)[1]
    text, status = body.rsplit('__END__', 1)
    return int(status.split()[0]), text.strip('\r\n')


def xfer_get(name, target):
    """Copy a file out of the FAT transfer disk. The guest must not have it mounted."""
    data = compose('exec', '-T', 'pfsense', 'mtype', '-i', '/vm/xfer.img', '::/' + name)
    Path(target).write_text(data + '\n', encoding='utf-8')


def xfer_put(source, name):
    compose('cp', str(source), 'pfsense:/tmp/xfer-in')
    compose('exec', '-T', 'pfsense', 'mcopy', '-o', '-i', '/vm/xfer.img', '/tmp/xfer-in', '::/' + name)


def screen(name='screen'):
    LOCAL.mkdir(parents=True, exist_ok=True)
    monitor('screendump /tmp/screen.png -f png')
    target = LOCAL / (name + '.png')
    compose('cp', 'pfsense:/tmp/screen.png', str(target))
    return target


def init(iso):
    values = env_values()
    for key in ('MYSQL_ROOT_PASSWORD', 'MYSQL_PASSWORD'):
        values.setdefault(key, secrets.token_hex(32))
    values.setdefault('PORTAL_PORT', '25020')
    if iso:
        path = Path(iso).resolve()
        if not path.is_file():
            raise SystemExit('ISO not found: ' + str(path))
        values['PFSENSE_ISO'] = str(path)
    if not values.get('PFSENSE_ISO'):
        raise SystemExit('Give the local pfSense CE 2.7.2 ISO: tools/pf_lab.py init --iso PATH')
    ENV.write_text(''.join(f'{k}={v}\n' for k, v in values.items()), encoding='utf-8')
    print('Wrote .env.pf (local only).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'up', 'stop', 'status', 'screen', 'keys', 'type',
                                            'serial', 'shell', 'xfer-get', 'xfer-put', 'installed'])
    parser.add_argument('args', nargs='*')
    parser.add_argument('--iso')
    parser.add_argument('--wait', type=float, default=5.0)
    args = parser.parse_args()
    if args.command == 'serial':
        print(serial(' '.join(args.args) + '\n', args.wait))
        return
    if args.command == 'shell':
        status, out = shell(' '.join(args.args), args.wait)
        print(out)
        raise SystemExit(status)
    if args.command == 'xfer-get':
        xfer_get(*args.args)
        return
    if args.command == 'xfer-put':
        xfer_put(*args.args)
        return
    if args.command == 'installed':
        # Boot from the disk from now on; the ISO stays mounted read-only but unused.
        compose('exec', '-T', 'pfsense', 'touch', '/vm/installed')
        return
    if args.command == 'init':
        init(args.iso)
    elif args.command == 'up':
        services = args.args or []
        print(compose('up', '-d', '--build', *services, timeout=900))
    elif args.command == 'stop':
        print(compose('stop'))
    elif args.command == 'status':
        print(compose('ps'))
    elif args.command == 'screen':
        print(screen(*(args.args[:1] or ['screen'])))
    elif args.command == 'keys':
        keys(*args.args)
    else:
        type_text(' '.join(args.args))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(scrub(str(error)))
