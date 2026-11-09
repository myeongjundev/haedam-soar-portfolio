"""Explicit operator recovery without putting keys on the command line."""
import argparse
import json

from s8_lab import STATE, graylog, scrub
from s8_verify import IP, client, events, hook, ticket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('replay').add_argument('--event-id', required=True)
    sub.add_parser('release').add_argument('--ticket-id', required=True)
    args = parser.parse_args()
    definition = json.loads(STATE.read_text())['definition']
    if args.command == 'replay':
        event = next((e for e in events(definition) if e['id'] == args.event_id), None)
        if not event or event.get('fields', {}).get('src_ip') != IP:
            raise ValueError('No matching S8 lab event in the last 30 minutes. Do not invent a replacement event ID.')
        status, data = hook('haedam-s8-s10', {
            'event_id': event['id'], 'asset_id': 'haedam-portal', 'case_id': 'S8', 'src_ip': IP,
            'detected_at': event['timestamp_processing'], 'dry_run': False, 'store_real': True})
    else:
        current = ticket(args.ticket_id)
        if current['case_id'] != 'S8' or current['asset_id'] != 'haedam-portal' or current['group_key'] != IP:
            raise ValueError('Ticket is outside this S8 lab.')
        graylog(f'/events/definitions/{definition}/unschedule', {}, 'PUT')
        status, data = hook('haedam-release', {'seat': 'B', 'case_id': 'S8', 'asset_id': 'haedam-portal',
                                             'group_key': IP, 'ticket_id': args.ticket_id}, 'operator')
    body = data[0] if isinstance(data, list) and data else data
    summary = {k: body[k] for k in ('ok', 'verdict', 'ticket_id', 'ticket', 'n8n_execution_id', 'no_action') if k in body}
    print(json.dumps({'http_status': status, **summary}, ensure_ascii=False))
    if status != 200 or body.get('ok') is False:
        raise SystemExit(1)
    if args.command == 'release':
        attacker, normal = client('attacker'), client('normal')
        print(json.dumps({'attacker': attacker, 'normal': normal, 'ticket_status': ticket(args.ticket_id)['status']}))
        if attacker['status'] != 200 or normal['status'] != 200:
            raise SystemExit('Release response received but independent HTTP restoration failed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(scrub(str(error)))
