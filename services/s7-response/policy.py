"""Pure S7 event boundaries shared with host tests."""
from datetime import datetime
import hashlib
import json
import re

PATHS = {'/var/www/haedam/index.html': 'index.html', '/var/www/haedam/assets/s7-probe.txt': 'assets/s7-probe.txt'}


def normalize(alert, agent_id, baseline):
    agent, check, rule = (alert.get(k) or {} for k in ('agent', 'syscheck', 'rule'))
    path = check.get('path')
    if agent.get('id') != agent_id or agent.get('name') != 'haedam-s7-agent' or path not in PATHS:
        return None
    key = PATHS[path]
    event = check.get('event')
    expected_rule = {'modified': '550', 'added': '554', 'deleted': '553'}.get(event)
    if rule.get('id') != expected_rule or expected_rule is None:
        return None
    after = 'absent' if event == 'deleted' else check.get('sha256_after')
    if key == 'index.html':
        if key not in baseline or after == baseline[key]:
            return None  # restoration/metadata-only alert, never another incident
        action = 'restore'
    else:
        if key in baseline or event == 'deleted':
            return None  # deletion caused by quarantine
        action = 'quarantine'
    if not isinstance(after, str) or not re.fullmatch('[0-9a-f]{64}|absent', after):
        return None
    ident = alert.get('id', '')
    if not re.fullmatch(r'\d{10}\.\d{1,16}', ident):
        return None
    timestamp = datetime.fromisoformat(alert['timestamp'])
    if timestamp.tzinfo is None:
        raise ValueError('timezone_required')
    result = dict(agent_id=agent_id, file_key=key, wazuh_event_id=ident, alert_at=timestamp.isoformat(),
                  expected_hash=after, action=action, rule_id=expected_rule)
    result['event_key'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def validate_claim(body):
    if set(body) != {'event_key', 'graylog_event_id', 'detected_at', 'execution_id'}:
        raise ValueError('invalid_fields')
    if not re.fullmatch('[0-9a-f]{64}', str(body['event_key'])) or not re.fullmatch('[0-9A-Z]{26}', str(body['graylog_event_id'])):
        raise ValueError('invalid_event')
    if not re.fullmatch('[0-9]{1,20}', str(body['execution_id'])):
        raise ValueError('invalid_execution')
    instant = datetime.fromisoformat(body['detected_at'])
    if instant.tzinfo is None:
        raise ValueError('timezone_required')
