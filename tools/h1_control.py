"""Release one exact H1 lab ticket with the local operator credential, or reconcile a lost applied record."""
import argparse
import json
import re

from h1_lab import STATE, graylog, scrub
from h1_verify import active, hook, ticket


def reconcile(ticket_id):
    """Portal restricted for this ticket but the applied record was lost (record outage, timeout, n8n crash).

    Replays the ticket's own first detection byte for byte: the portal receipt replays (no new restriction)
    and the restrict workflow records `applied`. A fresh detected_at would be an idempotency conflict.
    """
    if active()['restriction']['ticket_id'] != ticket_id:
        raise RuntimeError('Portal restriction is not owned by this ticket; nothing to reconcile.')
    current = ticket(ticket_id)
    status, body = hook('restrict', {'case_id': 'H1', 'asset_id': 'haedam-portal', 'username': 'h1_abuse',
                                     'event_id': current['event_ids'][0], 'detected_at': current['detected_at']})
    print(json.dumps({'http_status': status, 'result': body}, ensure_ascii=False))
    observed = active()
    if status != 200 or observed['restriction']['ticket_id'] != ticket_id or \
            [c['ticket_id'] for c in observed['claims']] != [ticket_id]:
        raise RuntimeError('Reconcile did not confirm the applied record; inspect ticket and portal state.')
    print('Applied record matches the portal restriction. Release with: h1_control.py release ' + ticket_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['release', 'reconcile', 'status'])
    parser.add_argument('ticket_id', nargs='?')
    args = parser.parse_args()
    if args.command == 'status':
        print(json.dumps(active(), ensure_ascii=False, indent=2))
        return
    if not re.fullmatch(r'T-[0-9]{8}-[0-9]{4}', args.ticket_id or ''):
        parser.error(args.command + ' requires an exact ticket ID')
    if args.command == 'reconcile':
        reconcile(args.ticket_id)
        return
    definition = json.loads(STATE.read_text())['definition']
    graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
    status, body = hook('release', {'case_id': 'H1', 'asset_id': 'haedam-portal',
                                  'username': 'h1_abuse', 'ticket_id': args.ticket_id})
    print(json.dumps({'http_status': status, 'result': body}, ensure_ascii=False))
    if status != 200:
        raise RuntimeError('Release held; inspect the current ticket/owner before retrying.')
    observed = active()
    if observed['restriction']['restricted'] or observed['claims'] or ticket(args.ticket_id)['status'] != 'restored':
        raise RuntimeError('Release readback did not confirm restored state.')
    print('Restriction cleared; ticket restored; no active resource claims. Detection remains paused.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(scrub(str(error)))
