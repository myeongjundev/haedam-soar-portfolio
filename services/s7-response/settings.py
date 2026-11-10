"""One non-secret deployment configuration, shared by relay, builder and verifier."""
import json
import os
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit


def load_settings():
    path = os.environ.get('S7_CONFIG_FILE')
    path = Path(path) if path else Path(__file__).resolve().parents[2] / 'infra/s7-auto-settings.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    for key, action in data['targets'].items():
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', key) or PurePosixPath(key).is_absolute() or '..' in PurePosixPath(key).parts or PurePosixPath(key).as_posix() != key or key == '.':
            raise ValueError('Unsafe configured S7 target')
        if action not in ('restore', 'quarantine'):
            raise ValueError('Unsupported configured S7 action')
    if data['targets'].get(data['home_file']) != 'restore':
        raise ValueError('Configured home must be a restore target')
    for value in data['paths'].values():
        if not PurePosixPath(value).is_absolute() or value == '/' or '..' in PurePosixPath(value).parts or PurePosixPath(value).as_posix() != value:
            raise ValueError('Invalid configured container path')
    for value in data['urls'].values():
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError('Endpoint must not contain credentials')
        if url.port is None or not 1 <= url.port <= 65535:
            raise ValueError('Endpoint must have an explicit valid port')
    if urlsplit(data['urls']['wazuh_api']).scheme != 'https':
        raise ValueError('Wazuh API must use TLS')
    for value in data['host_ports'].values():
        if not str(value).isdigit() or not 1 <= int(value) <= 65535:
            raise ValueError('Invalid host port')
    for key in ('agent_name', 'wazuh_user', 'wazuh_role', 'relay_source'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', data[key]):
            raise ValueError('Invalid configured identity')
    if not re.fullmatch(r'\d{3,8}', data['agent_id']):
        raise ValueError('Invalid configured agent ID')
    if not re.fullmatch('[a-z][a-z0-9-]{0,63}',data['asset_id']):
        raise ValueError('Invalid asset identity')
    if not re.fullmatch('[a-z][a-z0-9-]{0,63}',data['ar_command']):
        raise ValueError('Invalid configured AR command name')
    return data
