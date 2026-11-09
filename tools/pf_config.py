"""Patch the installed pfSense default config.xml for the personal lab. Standard library only.

The input is the VM's own default config (copied out through the FAT transfer disk), so pfSense's
schema version and generated defaults are kept; only lab settings from infra/pfsense/lab-settings.json change
(default WAN em0 203.0.113.1/24, an RFC 5737 test range, so private/bogon blocking is off; LAN em1 172.30.94.1/24):
one WAN pass rule to the portal, serial console, key-only SSH with a forced command for one controller,
and optional remote syslog for S10.
"""
import argparse
import base64
import ipaddress
import json
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_SETTINGS = Path(__file__).resolve().parents[1] / 'infra/pfsense/lab-settings.json'
FORCED = ('command="{adapter}",from="{ip}",no-pty,no-port-forwarding,'
          'no-agent-forwarding,no-X11-forwarding {key}')
RULE_DESCR = 'P04 WAN clients to portal'
RULE_TRACKER = '1731100000'


def interface(side):
    return {'if': side['pfsense_if'], 'ipaddr': side['pfsense_ip'],
            'subnet': str(ipaddress.ip_network(side['subnet']).prefixlen)}


def child(parent, tag):
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
    return node


def put(parent, tag, text=None):
    node = child(parent, tag)
    node.text = text
    return node


def drop(parent, *tags):
    for tag in tags:
        for node in parent.findall(tag):
            parent.remove(node)


def patch(root, public_key, settings, syslog=None):
    if root.tag != 'pfsense':
        raise ValueError('not a pfSense config.xml')
    interfaces = root.find('interfaces')
    wan, lan = interfaces.find('wan'), interfaces.find('lan')
    if wan is None or lan is None:
        raise ValueError('default config needs wan and lan interfaces')
    for node, values in ((wan, interface(settings['wan'])), (lan, interface(settings['lan']))):
        put(node, 'enable')
        for tag, value in values.items():
            put(node, tag, value)
        drop(node, 'ipaddrv6', 'subnetv6', 'track6-interface', 'track6-prefix-id', 'dhcphostname',
             'dhcp6-duid', 'dhcp6-ia-pd-len', 'gateway', 'gatewayv6')
    drop(wan, 'blockpriv', 'blockbogons')
    dhcpd = root.find('dhcpd')
    if dhcpd is not None:
        drop(dhcpd, 'lan')  # the default 192.168.1.x pool does not fit the lab LAN
    dhcpdv6 = root.find('dhcpdv6')
    if dhcpdv6 is not None:
        drop(dhcpdv6, 'lan')

    system = root.find('system')
    put(system, 'hostname', 'haedam-pf')
    put(system, 'enableserial')
    put(system, 'serialspeed', '115200')
    put(system, 'primaryconsole', 'serial')
    ssh = child(system, 'ssh')
    put(ssh, 'enable', 'enabled')
    put(ssh, 'sshdkeyonly', 'enabled')
    admins = [u for u in system.findall('user') if u.findtext('name') == 'admin']
    if len(admins) != 1:
        raise ValueError('expected exactly one admin user')
    if settings['controller']['ssh_user'] != 'admin':
        raise ValueError('the lab installs the forced command for the pfSense admin account only')
    line = FORCED.format(adapter=settings['adapter_path'], ip=settings['controller']['ip'], key=public_key.strip())
    put(admins[0], 'authorizedkeys', base64.b64encode(line.encode()).decode())

    filt = child(root, 'filter')
    for rule in filt.findall('rule'):
        if rule.findtext('descr') == RULE_DESCR:
            filt.remove(rule)
    rule = ET.Element('rule')
    for tag, value in (('id', ''), ('tracker', RULE_TRACKER), ('type', 'pass'), ('interface', 'wan'),
                       ('ipprotocol', 'inet'), ('tag', ''), ('tagged', ''), ('max', ''), ('max-src-nodes', ''),
                       ('max-src-conn', ''), ('max-src-states', ''), ('statetimeout', ''),
                       ('statetype', 'keep state'), ('os', ''), ('protocol', 'tcp')):
        put(rule, tag, value)
    put(child(rule, 'source'), 'any')
    dest = child(rule, 'destination')
    put(dest, 'address', settings['portal']['ip'])
    put(dest, 'port', str(settings['portal']['port']))
    put(rule, 'descr', RULE_DESCR)
    filt.insert(0, rule)

    if syslog:
        logs = child(root, 'syslog')
        put(logs, 'enable')
        put(logs, 'remoteserver', syslog)
        put(logs, 'filter')
        put(logs, 'ipproto', 'ipv4')
        put(logs, 'sourceip', 'lan')
    return root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--settings', type=Path, default=DEFAULT_SETTINGS)
    parser.add_argument('--syslog', help='host:port of the Graylog syslog UDP input (S10)')
    args = parser.parse_args()
    settings = json.loads(args.settings.read_text(encoding='utf-8'))
    tree = ET.parse(args.source)
    patch(tree.getroot(), args.public_key.read_text(encoding='utf-8'), settings, args.syslog)
    tree.write(args.output, encoding='UTF-8', xml_declaration=True)
    print('Wrote', args.output)


if __name__ == '__main__':
    main()
