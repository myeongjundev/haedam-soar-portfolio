"""Host-side safety boundaries that must fail before lab mutations."""
import importlib.util
import json
from pathlib import Path
import ssl
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import s7_lab
import s7_auto_lab

MOUNTS = {'s7-web': '/app/frontend', 's7-backend': '/app/src'}


def portal(running, mounts=MOUNTS):
    """Stub `compose`: the effective config for `config`, else the running portal's file hashes."""
    config = json.dumps({'services': {'portal': {'volumes': [
        {'type': 'volume', 'source': s, 'target': t} for s, t in mounts.items()]}}})
    return lambda *a, **k: config if a[0] == 'config' else running


def image(built, seen=None):
    """Stub `run`: the built image's file hashes for the path passed to `docker run`."""
    def run(command, *a, **k):
        if command[:3] == ['docker', 'image', 'inspect']:
            return 'image-digest'
        if seen is not None:
            seen.append(command[-1])
        return built
    return run


def test_changed_webroot_cannot_be_accepted_as_baseline(monkeypatch):
    mutations = []
    monkeypatch.setattr(s7_lab, 'run', image('{"index.html":"original"}'))
    monkeypatch.setattr(s7_lab, 'compose', portal('{"index.html":"tampered"}'))
    monkeypatch.setattr(s7_lab, 'restore', lambda *a: mutations.append(a))
    with pytest.raises(RuntimeError, match='baseline refused'):
        s7_lab.baseline()
    assert mutations == []


def test_stale_backend_volume_is_not_reported_ready(monkeypatch):
    # s7-backend shadows /app/src: after `up --build` the portal could keep running old code.
    written = []
    monkeypatch.setattr(s7_lab, 'run', image('{"haedam_portal/__init__.py":"new"}'))
    monkeypatch.setattr(s7_lab, 'compose', portal('{"haedam_portal/__init__.py":"old"}'))
    monkeypatch.setattr(s7_lab, 'private_file', lambda *a: written.append(a))
    monkeypatch.setattr(s7_lab, 'wait_for', lambda *a, **k: pytest.fail('reached readiness checks'))
    with pytest.raises(RuntimeError, match='stale'):
        s7_lab.ready()
    assert written == []


def test_automatic_ready_shares_the_stale_volume_check(monkeypatch):
    # The automatic lab has its own ready(); it must refuse before waiting on the agent or services.
    monkeypatch.setattr(s7_lab, 'run', image('{"haedam_portal/__init__.py":"new"}'))
    monkeypatch.setattr(s7_lab, 'compose', portal('{"haedam_portal/__init__.py":"old"}'))
    monkeypatch.setattr(s7_lab, 'wait_for', lambda *a, **k: pytest.fail('reached readiness checks'))
    with pytest.raises(RuntimeError, match='s7-backend volume is stale'):
        s7_auto_lab.ready()


def test_drift_path_comes_from_the_compose_mount(monkeypatch):
    seen = []
    monkeypatch.setattr(s7_lab, 'run', image('{}', seen))
    monkeypatch.setattr(s7_lab, 'compose', portal('{}', {'s7-backend': '/srv/backend'}))
    s7_lab.require_image_content('s7-backend')
    assert seen == ['/srv/backend']
    with pytest.raises(RuntimeError, match='not found'):
        s7_lab.require_image_content('s7-web')


def test_stale_runtime_prevents_reconfiguration(monkeypatch):
    def stale():
        raise RuntimeError('stale runtime')
    monkeypatch.setattr(s7_auto_lab, 'require_current_portal', stale)
    monkeypatch.setattr(s7_auto_lab, 'http', lambda *a, **k: pytest.fail('configuration began'))
    with pytest.raises(RuntimeError, match='stale runtime'):
        s7_auto_lab.configure()


def test_low_memory_up_does_not_stop_other_workloads(monkeypatch):
    mutations = []
    monkeypatch.setattr(s7_lab, 'run', lambda command, *a, **k:
        'team-lab' if command[1] == 'ps' else str(6 * 1024**3))
    monkeypatch.setattr(s7_lab, 'compose', lambda *a, **k: mutations.append(a))
    with pytest.raises(RuntimeError, match='none stopped here'):
        s7_lab.up()
    assert mutations == []


def test_tls_compatibility_keeps_certificate_validation(monkeypatch):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(s7_lab.ssl, 'create_default_context', lambda **_: context)
    observed = s7_lab.tls_context('pinned-local-ca.pem')
    assert observed.verify_mode == ssl.CERT_REQUIRED
    assert not observed.check_hostname  # fixed loopback, Docker DNS SAN


def test_project_namespace_rejects_team_project(monkeypatch):
    monkeypatch.setenv('S7_PROJECT', 'wazuh')
    spec = importlib.util.spec_from_file_location('s7_invalid_project', s7_lab.__file__)
    with pytest.raises(ValueError, match='S7_PROJECT'):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
