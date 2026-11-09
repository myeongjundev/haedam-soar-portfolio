from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import h1_control  # noqa: E402

TICKET = 'T-20261109-0002'
STORED = {'event_ids': ['CLAUDE00000000000000000001', 'LATER'], 'detected_at': '2026-11-09T02:41:05.915335+00:00'}


def test_reconcile_replays_stored_detection_only_for_portal_owner(monkeypatch):
    state = {'restriction': {'ticket_id': TICKET}, 'claims': []}
    sent = []

    def hook(operation, body):
        sent.append((operation, body))
        state['claims'] = [{'ticket_id': TICKET}]
        return 200, {'verdict': 'restricted'}

    monkeypatch.setattr(h1_control, 'active', lambda: state)
    monkeypatch.setattr(h1_control, 'hook', hook)
    monkeypatch.setattr(h1_control, 'ticket', lambda _: STORED)
    h1_control.reconcile(TICKET)
    assert sent == [('restrict', {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse',
                                  'event_id': STORED['event_ids'][0], 'detected_at': STORED['detected_at']})]
    with pytest.raises(RuntimeError, match='not owned'):
        h1_control.reconcile('T-20261109-0003')  # portal owned by another ticket: no webhook call
    state['claims'] = []
    monkeypatch.setattr(h1_control, 'hook', lambda *_: (503, {'verdict': 'held_applied_record'}))
    with pytest.raises(RuntimeError, match='did not confirm'):
        h1_control.reconcile(TICKET)
    assert len(sent) == 1
