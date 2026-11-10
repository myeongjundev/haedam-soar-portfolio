"""S1 settings and offline plans. No environment reads, subprocesses or network."""
import hashlib
import ipaddress
import json
from pathlib import PurePosixPath
import re


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate(s):
    required = {'schema_version', 'project', 'execution_enabled', 'asset_id', 'network_status', 'networks',
                'addresses', 'host_ports', 'client_image', 'paths', 'portal_internal_port', 'username_prefix',
                'policy', 'request_timeout_seconds', 'stop_filename', 'network_internal'}
    if not isinstance(s, dict) or set(s) != required:
        raise ValueError('invalid_settings_keys')
    groups = {'networks': {'default', 'clients', 'response', 'graylog_backend'},
              'addresses': {'portal_client', 'attacker', 'normal', 'n8n_response', 'portal_response'},
              'paths': {'tools_mount', 'settings_mount', 'evidence_mount', 'health', 'session', 'login', 'register'},
              'policy': {'failure_threshold', 'window_seconds', 'execute_every_seconds',
                         'notification_grace_seconds', 'input_interval_seconds', 'boundary_observation_seconds'}}
    for key, keys in groups.items():
        if not isinstance(s[key], dict) or set(s[key]) != keys:
            raise ValueError('invalid_settings_group')
    isolation=s['network_internal']
    if not isinstance(isolation,dict) or set(isolation)!=set(s['networks']):
        raise ValueError('invalid_network_isolation')
    if isolation['default'] is not False or any(isolation[k] is not True for k in ('clients','response','graylog_backend')):
        raise ValueError('management_publish_and_internal_test_networks_required')
    for key in ('project', 'asset_id', 'network_status', 'client_image', 'username_prefix', 'stop_filename'):
        if not isinstance(s[key], str):
            raise ValueError('string_setting_required')
    if not isinstance(s['host_ports'], dict) or any(not isinstance(v, str) for k in ('networks', 'addresses', 'paths') for v in s[k].values()):
        raise ValueError('invalid_settings_types')
    if type(s.get('schema_version')) is not int or s['schema_version'] != 1 or type(s.get('execution_enabled')) is not bool:
        raise ValueError('invalid_schema_or_execution_flag')
    if not re.fullmatch(r'haedam-s1-[a-z0-9][a-z0-9-]{0,35}', s['project']):
        raise ValueError('s1_project_required')
    if s['asset_id'] != 'haedam-portal':
        raise ValueError('unsupported_asset')
    nets = {name: ipaddress.IPv4Network(s['networks'][name], strict=True)
            for name in ('default', 'clients', 'response', 'graylog_backend')}
    private = [ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    for name, net in nets.items():
        if not any(net.subnet_of(n) for n in private) or not 24 <= net.prefixlen <= 29:
            raise ValueError('small_rfc1918_network_required')
        if any(net.overlaps(other) for key, other in nets.items() if key != name):
            raise ValueError('overlapping_networks')
    assignments = {'portal_client': 'clients', 'attacker': 'clients', 'normal': 'clients',
                   'n8n_response': 'response', 'portal_response': 'response'}
    ips = []
    for key, network in assignments.items():
        ip, net = ipaddress.IPv4Address(s['addresses'][key]), nets[network]
        # Docker's default gateway is the first host; never allocate it to a service.
        if ip not in net or ip in (net.network_address, net.broadcast_address, net.network_address + 1):
            raise ValueError('invalid_service_address')
        ips.append(ip)
    if len(set(ips)) != len(ips):
        raise ValueError('duplicate_service_address')
    keys = {'PORTAL_PORT', 'GRAYLOG_PORT', 'N8N_PORT', 'GELF_PORT', 'TICKET_PORT'}
    ports = s['host_ports']
    if set(ports) != keys or any(type(v) is not int or not 1024 <= v <= 65535 for v in ports.values()):
        raise ValueError('invalid_host_ports')
    if len(set(ports.values())) != len(ports):
        raise ValueError('duplicate_host_ports')
    if s['portal_internal_port'] != 5000:
        raise ValueError('base_portal_container_listens_on_5000')
    if not re.fullmatch(r'zz_[a-z0-9_]{1,8}', s['username_prefix']):
        raise ValueError('synthetic_username_prefix_required')
    paths = s['paths']
    for value in paths.values():
        path = PurePosixPath(value)
        if not value.startswith('/') or value.startswith('//') or '..' in path.parts or any(c in value for c in '\\?#\r\n$'):
            raise ValueError('invalid_path')
    if len(set(paths.values())) != len(paths):
        raise ValueError('duplicate_paths')
    mounts = [PurePosixPath(paths[k]) for k in ('tools_mount', 'settings_mount', 'evidence_mount')]
    if any(a == PurePosixPath('/') or a in b.parents for a in mounts for b in mounts if a != b):
        raise ValueError('overlapping_mounts')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,30}', s['stop_filename']) or s['stop_filename'] in ('.', '..'):
        raise ValueError('invalid_stop_filename')
    if not re.fullmatch(r'[a-z0-9./_-]+:[a-zA-Z0-9_.-]+(?:@sha256:[a-f0-9]{64})?', s['client_image']):
        raise ValueError('pinned_client_image_required')
    if type(s['request_timeout_seconds']) is not int or not 1 <= s['request_timeout_seconds'] <= 30:
        raise ValueError('invalid_timeout')
    p = s['policy']
    if any(type(v) is not int for v in p.values()):
        raise ValueError('integer_policy_required')
    # Preserve the reviewed team S1 detector. A new policy requires a separate review.
    expected = {'failure_threshold': 9, 'window_seconds': 1800, 'execute_every_seconds': 60,
                'notification_grace_seconds': 1800, 'boundary_observation_seconds': 1860}
    if any(p.get(k) != v for k, v in expected.items()):
        raise ValueError('team_s1_policy_changed')
    if p['input_interval_seconds'] not in (100, 200):
        raise ValueError('reviewed_interval_required')
    return s


def plan(s, run_id, profile):
    validate(s)
    if not re.fullmatch(r'[a-z0-9][a-z0-9_]{0,23}', run_id):
        raise ValueError('run_id_requires_1_to_24_lowercase_letters_digits_underscores')
    if profile not in ('boundary8', 'trigger9', 'normal'):
        raise ValueError('unknown_profile')
    count = {'boundary8': 8, 'trigger9': 9, 'normal': 0}[profile]
    client = 'normal' if profile == 'normal' else 'attacker'
    username = None if not count else s['username_prefix'] + ('b_' if profile == 'boundary8' else 't_') + run_id
    if username and len(username) > 40:
        raise ValueError('username_too_long')
    return {'case_id': 'S1', 'run_id': run_id, 'profile': profile, 'mode': 'plan_only',
            'project': s['project'], 'settings_sha256': digest(s), 'client': client,
            'source_ip': s['addresses'][client], 'target_ip': s['addresses']['portal_client'],
            'target_port': s['portal_internal_port'], 'username': username,
            'maximum_login_attempts': count, 'maximum_http_requests': 1 + count * 2,
            'interval_seconds': s['policy']['input_interval_seconds'],
            'minimum_input_span_seconds': max(0, count - 1) * s['policy']['input_interval_seconds'],
            'boundary_observation_seconds': s['policy']['boundary_observation_seconds'] if profile == 'boundary8' else None,
            'observation_basis': 'last_required_401_received_by_Graylog_not_client_finish',
            'expected_detection': count == 9, 'automatic_retry': False,
            'normal_check_scope': 'health_only_not_authenticated_login',
            'end_to_end_status': 'not_run', 'response_api_called': False}
