"""Real Flask routes/CSRF/session/event contract; temporary SQLite, no sockets."""
import json
from pathlib import Path
import sys

import pytest
from werkzeug.security import generate_password_hash

from conftest import PASSWORD
from haedam_portal.models import User, db

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from s4_client import execute
from s4_settings import PROFILES


@pytest.mark.parametrize('profile', list(PROFILES))
def test_input_matches_real_portal_login_and_event_contract(app, tmp_path, profile):
    s = json.loads((ROOT / 'infra/s4-settings.json').read_text(encoding='utf-8'))
    # Same production rate-limit setting, with a fresh DB for each parametrized run.
    app.config['LOGIN_RATE_LIMIT'] = 20
    with app.app_context():
        db.session.add(User(username=s['accounts']['target'], display_name='S4 synthetic',
                            password_hash=generate_password_hash(PASSWORD), role='citizen'))
        db.session.commit()

    class FlaskTransport:
        def __init__(self, settings, plan):
            self.client, self.source = app.test_client(), plan['source_ip']

        def request(self, path, body=None, csrf=None):
            response = self.client.open(path, method='GET' if body is None else 'POST', json=body,
                                        headers={'X-CSRF-Token': csrf} if csrf else {},
                                        environ_overrides={'REMOTE_ADDR': self.source})
            return response.status_code, response.get_json(), self.source

    out = execute(s, 'flaskcontract', profile, tmp_path / 'evidence', PASSWORD,
                  guard=lambda _: None, wait=lambda *_: None, transport_factory=FlaskTransport)
    assert out['status'] == 'input_complete'
    assert out['observed_login_statuses'] == list(PROFILES[profile])
    assert out['authenticated_identity_checks'] == PROFILES[profile].count(200)
    events = [json.loads(line) for line in Path(app.config['EVENT_LOG_PATH']).read_text(encoding='utf-8').splitlines()]
    logins = [event for event in events if event['event_type'].startswith('auth.login_')]
    assert [event['details']['status'] for event in logins] == list(PROFILES[profile])
    assert all(event['username'] == s['accounts']['target'] and event['src_ip'] == s['addresses']['attacker'] for event in logins)
    assert PASSWORD not in json.dumps(events)
    assert PASSWORD not in json.dumps(out)
    assert out['end_to_end_status'] == 'not_run'
