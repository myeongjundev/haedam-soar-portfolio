"""Release one exact H1 lab ticket with the local operator credential."""
import argparse
import json
import re

from h1_lab import STATE, graylog, scrub
from h1_verify import active, hook, ticket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['release', 'status'])
    parser.add_argument('ticket_id', nargs='?')
    args = parser.parse_args()
    if args.command == 'status':
        print(json.dumps(active(), ensure_ascii=False, indent=2))
        return
    if not re.fullmatch(r'T-[0-9]{8}-[0-9]{4}', args.ticket_id or ''):
        parser.error('release requires an exact ticket ID')
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
