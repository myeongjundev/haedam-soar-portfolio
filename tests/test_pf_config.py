import base64
import copy
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'lab/pfsense'))
import pf_config  # noqa: E402
import pf_lab  # noqa: E402
import pfsense_response  # noqa: E402

SETTINGS = json.loads((ROOT / 'infra/pfsense/lab-settings.json').read_text(encoding='utf-8'))
KEY = 'ssh-ed25519 AAAAtest haedam-pf-controller\n'
DEFAULT = """<?xml version="1.0"?>
<pfsense><version>23.3</version>
<system><hostname>pfSense</hostname><user><name>admin</name><bcrypt-hash>kept</bcrypt-hash></user></system>
<interfaces>
 <wan><enable/><if>em0</if><ipaddr>dhcp</ipaddr><blockpriv>on</blockpriv><blockbogons>on</blockbogons><ipaddrv6>dhcp6</ipaddrv6></wan>
 <lan><enable/><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet><ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface></lan>
</interfaces>
<dhcpd><lan><enable/><range><from>192.168.1.100</from><to>192.168.1.199</to></range></lan></dhcpd>
<filter><rule><type>pass</type><interface>lan</interface><descr>Default allow LAN to any rule</descr></rule></filter>
</pfsense>"""


def patched(settings=SETTINGS, syslog=None):
    root = ET.fromstring(DEFAULT)
    pf_config.patch(root, KEY, settings, syslog)
    return root


def test_default_settings_fit_the_team_adapter():
    # The adapter is pinned team code: it acts only on these targets and checks WAN em0/203.0.113.1.
    assert SETTINGS['clients']['attacker'] in pfsense_response.TARGETS
    assert SETTINGS['clients']['normal'] not in pfsense_response.TARGETS
    root = patched()
    assert root.findtext('./interfaces/wan/if') == 'em0'
    assert root.findtext('./interfaces/wan/ipaddr') == '203.0.113.1'
    assert root.find('./interfaces/wan/blockpriv') is None and root.find('./interfaces/wan/blockbogons') is None
    assert root.findtext('./interfaces/lan/ipaddr') == SETTINGS['lan']['pfsense_ip']
    assert root.find('./interfaces/lan/track6-interface') is None
    assert root.find('./dhcpd/lan') is None
    assert root.findtext('./system/user/bcrypt-hash') == 'kept'


def test_ssh_is_key_only_and_forced_to_the_adapter_from_one_controller():
    root = patched()
    assert root.findtext('./system/ssh/sshdkeyonly') == 'enabled'
    assert root.findtext('./system/primaryconsole') == 'serial'
    line = base64.b64decode(root.findtext('./system/user/authorizedkeys')).decode()
    assert line.startswith(f'command="{SETTINGS["adapter_path"]}",from="{SETTINGS["controller"]["ip"]}",no-pty,')
    assert line.endswith(KEY.strip())


def test_single_wan_pass_rule_to_portal_and_idempotent():
    root = patched()
    pf_config.patch(root, KEY, SETTINGS)
    rules = root.findall('./filter/rule')
    ours = [r for r in rules if r.findtext('descr') == pf_config.RULE_DESCR]
    assert len(ours) == 1 and rules[0] is ours[0]
    assert (ours[0].findtext('interface'), ours[0].findtext('protocol')) == ('wan', 'tcp')
    assert ours[0].findtext('./destination/address') == SETTINGS['portal']['ip']
    assert ours[0].findtext('./destination/port') == str(SETTINGS['portal']['port'])
    assert rules[1].findtext('descr') == 'Default allow LAN to any rule'
    assert root.find('syslog') is None
    assert patched(syslog='172.30.94.20:5140').findtext('./syslog/remoteserver') == '172.30.94.20:5140'


def test_other_settings_flow_into_config_and_compose():
    other = copy.deepcopy(SETTINGS)
    other['lan'].update(subnet='10.99.0.0/16', pfsense_ip='10.99.0.1', docker_gateway='10.99.255.254')
    other['portal'].update(ip='10.99.0.10', port=8080)
    other['controller']['ip'] = '10.99.0.50'
    root = patched(other)
    assert (root.findtext('./interfaces/lan/ipaddr'), root.findtext('./interfaces/lan/subnet')) == ('10.99.0.1', '16')
    assert root.findtext('./filter/rule/destination/port') == '8080'
    assert 'from="10.99.0.50"' in base64.b64decode(root.findtext('./system/user/authorizedkeys')).decode()
    env = pf_lab.compose_env(other)
    assert (env['PF_LAN_SUBNET'], env['PF_PORTAL_IP'], env['PF_CONTROLLER_IP']) == ('10.99.0.0/16', '10.99.0.10', '10.99.0.50')


def test_missing_or_unsupported_settings_fail_before_anything_is_written(tmp_path):
    broken = copy.deepcopy(SETTINGS)
    del broken['controller']
    with pytest.raises(KeyError):
        pf_lab.compose_env(broken)
    with pytest.raises(KeyError):
        patched(broken)
    other_user = copy.deepcopy(SETTINGS)
    other_user['controller']['ssh_user'] = 'operator'
    with pytest.raises(ValueError):
        patched(other_user)


def test_compose_has_no_literal_addresses():
    # Every address in compose.pf.yaml must come from lab-settings.json through pf_lab.compose_env().
    body = [line.split('#', 1)[0] for line in (ROOT / 'compose.pf.yaml').read_text(encoding='utf-8').splitlines()]
    assert not re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', '\n'.join(body))
    used = set(re.findall(r'\$\{(PF_[A-Z_]+)', (ROOT / 'compose.pf.yaml').read_text(encoding='utf-8')))
    assert used <= set(pf_lab.compose_env()) | {'PFSENSE_ISO'}


def test_console_typing_maps_every_character(monkeypatch):
    seen = []
    monkeypatch.setattr(pf_lab, 'keys', lambda *names, delay=0: seen.extend(names))
    pf_lab.type_text('mount_msdosfs /dev/vtbd1 /mnt && cp A.xml "$x"\n')
    assert seen[:6] == ['m', 'o', 'u', 'n', 't', 'shift-minus']
    assert 'shift-a' in seen and seen[-1] == 'ret'
