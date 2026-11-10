import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def load_config():
    path = Path(os.environ.get('PANEL_CONFIG_FILE', ROOT / 'infra/panel-settings.json'))
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    if config['bind'] != '127.0.0.1' or not isinstance(config['port'], int) or not 1024 <= config['port'] <= 65535:
        raise ValueError('Panel must bind to loopback on a valid unprivileged port')
    if not re.fullmatch(r'haedam-s7-[a-z0-9][a-z0-9-]{0,31}', config['s7_project']):
        raise ValueError('Invalid personal S7 project')
    for key in ('observe_timeout_seconds', 'worker_timeout_seconds'):
        if not isinstance(config[key], int) or not 10 <= config[key] <= 600:
            raise ValueError('Invalid bounded timeout')
    if config['worker_timeout_seconds'] <= config['observe_timeout_seconds']:
        raise ValueError('Worker timeout must exceed observation timeout')
    if type(config['http_max_body_bytes']) is not int or not 1<=config['http_max_body_bytes']<=65536:
        raise ValueError('Invalid bounded HTTP body size')
    if type(config['http_drain_timeout_seconds']) not in (int,float) or not 0.05<=config['http_drain_timeout_seconds']<=5:
        raise ValueError('Invalid bounded HTTP drain timeout')
    config['state_dir'] = str((ROOT / config['state_dir']).resolve())
    if not Path(config['state_dir']).is_relative_to((ROOT / '.local').resolve()):
        raise ValueError('Panel state must be under the ignored .local directory')
    config['s7_settings'] = str((ROOT / config['s7_settings']).resolve())
    settings = json.loads(Path(config['s7_settings']).read_text(encoding='utf-8-sig'))
    config['targets'] = settings['targets']
    config['scope'] = hashlib.sha256(json.dumps({
        'project':config['s7_project'], 'settings':settings,
    }, sort_keys=True).encode()).hexdigest()
    config['origin'] = f"http://{config['bind']}:{config['port']}"
    return config
