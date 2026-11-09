#!/usr/local/bin/python3.11
"""Offline release verification; default plan. --install only publishes the tool, not SSH or rules."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET


TARGET = Path('/usr/local/sbin/haedam-pf-response')
TOOL = 'pfsense_response.py'
PINNED_SHA = '57ce49bdc1e91d2f15b7f401ae649d6be6f91427326f657b2369b524c6cd974a'
PAYLOADS = {TOOL, 'pfsense-response.schema.json', 'INSTALL.md', 'install_bundle.py'}


class Refused(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory):
    directory = Path(directory)
    marker = directory / 'bundle.json'
    if marker.is_symlink() or not marker.is_file():
        raise Refused('manifest_missing_or_unsafe')
    manifest = json.loads(marker.read_text(encoding='utf-8'))
    hashes = manifest.get('files', {})
    if manifest.get('version') != 1 or set(hashes) != PAYLOADS:
        raise Refused('unexpected_manifest')
    if manifest.get('targets') != ['203.0.113.22', '203.0.113.41']:
        raise Refused('unexpected_target_scope')
    if manifest.get('tool_sha256') != PINNED_SHA or hashes[TOOL] != PINNED_SHA:
        raise Refused('unapproved_tool_version')
    for name in sorted(PAYLOADS):
        path = directory / name
        if path.is_symlink() or not path.is_file() or digest(path) != hashes[name]:
            raise Refused('payload_missing_or_hash_mismatch')
    # Compile without importing/executing the candidate or writing __pycache__.
    compile((directory / TOOL).read_bytes(), TOOL, 'exec')
    compile((directory / 'install_bundle.py').read_bytes(), 'install_bundle.py', 'exec')
    json.loads((directory / 'pfsense-response.schema.json').read_text(encoding='utf-8'))
    return manifest


def require_appliance():
    if os.name != 'posix' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise Refused('root_on_appliance_required')
    if sys.version_info[:2] != (3, 11) or not Path('/usr/local/bin/python3.11').is_file():
        raise Refused('python_311_required')
    if Path('/etc/version').read_text().strip() != '2.7.2-RELEASE':
        raise Refused('appliance_version_mismatch')
    root = ET.parse('/cf/conf/config.xml').getroot()
    if root.findtext('./interfaces/wan/if') != 'em0' or root.findtext('./interfaces/wan/ipaddr') != '203.0.113.1':
        raise Refused('wan_mapping_mismatch')
    parent = TARGET.parent
    info = parent.stat()
    if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise Refused('unsafe_install_directory')


def publish_new(source, target):
    """Atomic create-only publication. Never overwrite an existing/dangling path."""
    if target.is_symlink() or target.exists():
        raise Refused('destination_already_exists')
    fd, name = tempfile.mkstemp(prefix='.haedam-pf-response-', dir=target.parent)
    staging = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staging, 0o750)
        if os.name == 'posix':
            os.chown(staging, 0, 0)
        if digest(staging) != PINNED_SHA:
            raise Refused('staging_hash_mismatch')
        # replace()/rename() could overwrite a concurrently installed version.
        os.link(staging, target)
        if os.name == 'posix':
            parent_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    finally:
        staging.unlink(missing_ok=True)


def install(directory):
    verify(directory)
    require_appliance()
    if TARGET.is_symlink():
        raise Refused('unsafe_existing_destination')
    if TARGET.exists():
        info = TARGET.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o750 or digest(TARGET) != PINNED_SHA):
            raise Refused('existing_version_or_permissions_require_review')
        return 'already_present_same_hash'
    publish_new(Path(directory) / TOOL, TARGET)
    return 'new_tool_file_installed'


def main(argv=None, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--verify', action='store_true')
    modes.add_argument('--install', action='store_true')
    args = parser.parse_args(argv)
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parent
    try:
        if args.install:
            outcome = install(directory)
        else:
            verify(directory)
            outcome = 'verified_files_only' if args.verify else 'plan_no_installation'
        report = {'ok': True, 'result': outcome, 'tool_sha256': PINNED_SHA,
                  'authorized_keys_changed': False, 'firewall_changed': False,
                  'journal_created': False, 'target_commands_executed': 0,
                  'D_ssh_verified': False, 'effect_verified': None}
        print(json.dumps(report, sort_keys=True))
        return 0
    except (Refused, OSError, ValueError, TypeError, KeyError, SyntaxError, ET.ParseError) as exc:
        reason = str(exc) if isinstance(exc, Refused) else 'bundle_or_installation_unavailable'
        print(json.dumps({'ok': False, 'result': 'refused', 'reason': reason}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
