"""Build a new local pfSense handoff directory. Never contacts or changes a device."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
APPROVED_SHA = '57ce49bdc1e91d2f15b7f401ae649d6be6f91427326f657b2369b524c6cd974a'
SOURCES = {'pfsense_response.py': 'lab/pfsense/pfsense_response.py',
           'pfsense-response.schema.json': 'contracts/pfsense-response.schema.json',
           'install_bundle.py': 'lab/pfsense/install_bundle.py', 'INSTALL.md': 'lab/pfsense/INSTALL.md'}


def build(output, root=ROOT):
    payload = {name: (Path(root) / source).read_bytes() for name, source in SOURCES.items()}
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in payload.items()}
    if hashes['pfsense_response.py'] != APPROVED_SHA:
        raise ValueError('Candidate differs from the approved local candidate hash; review version first.')
    for name in ('install_bundle.py', 'pfsense_response.py'):
        compile(payload[name], name, 'exec')
    json.loads(payload['pfsense-response.schema.json'])
    output = Path(output)
    if not output.parent.is_dir():
        raise ValueError('Output parent must already exist.')
    output.mkdir()  # Exclusive: an existing directory is never reused.
    for name, content in payload.items():
        with (output / name).open('xb') as stream:
            stream.write(content)
    manifest = {'version': 1, 'tool_sha256': APPROVED_SHA, 'files': hashes,
                'status': 'local_candidate_not_deployed', 'targets': ['203.0.113.22', '203.0.113.41'],
                'source_review': '11/03 readback/reconciliation candidate; live acceptance pending',
                'requires': ['agreed_test_window', 'D_dedicated_public_key', 'forced_command_and_source_limit',
                             'D_to_pfsense_22_path', 'C_D_active_owner_contract', 'live_effect_and_restore']}
    # Completion marker last; an interrupted directory is never accepted as a complete release.
    with (output / 'bundle.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='new local directory')
    args = parser.parse_args(argv)
    try:
        manifest = build(args.out)
        print(json.dumps({'ok': True, 'status': manifest['status'], 'files': len(manifest['files']),
                          'tool_sha256': manifest['tool_sha256']}, sort_keys=True))
        return 0
    except (OSError, ValueError, SyntaxError):
        print('Bundle not completed; existing paths and device state were not changed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
