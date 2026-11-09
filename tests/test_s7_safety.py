"""Host-side safety boundaries that must fail before lab mutations."""
import importlib.util
from pathlib import Path
import ssl
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import s7_lab


def test_changed_webroot_cannot_be_accepted_as_baseline(monkeypatch):
    mutations = []
    monkeypatch.setattr(s7_lab, 'run', lambda command, *a, **k:
        'image-digest' if command[:3] == ['docker', 'image', 'inspect'] else '{"index.html":"original"}')
    monkeypatch.setattr(s7_lab, 'compose', lambda *a, **k: '{"index.html":"tampered"}')
    monkeypatch.setattr(s7_lab, 'restore', lambda *a: mutations.append(a))
    with pytest.raises(RuntimeError, match='baseline refused'):
        s7_lab.baseline()
    assert mutations == []


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
