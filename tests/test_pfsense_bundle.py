"""Offline release/install tests. Never call SSH, EasyRule, pfctl or a live journal."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('bundle_builder_test', 'tools/build_pfsense_bundle.py')
installer = load('bundle_installer_test', 'lab/pfsense/install_bundle.py')


@pytest.fixture
def release(tmp_path):
    path = tmp_path / 'release'
    manifest = builder.build(path)
    return path, manifest


@pytest.fixture
def simulated_root_ownership(monkeypatch):
    # Production install requires uid 0. Filesystem publication tests run as an
    # ordinary CI user and exercise ordering/atomicity without a real chown.
    monkeypatch.setattr(installer.os, 'chown', lambda *args: None, raising=False)


def test_build_and_verify_do_not_execute_candidate(release, monkeypatch, capsys):
    path, manifest = release
    def forbidden(*args, **kwargs): raise AssertionError('no process allowed')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(installer, 'require_appliance', forbidden)
    before = {p.name: p.read_bytes() for p in path.iterdir()}
    assert installer.verify(path) == manifest
    assert installer.main([], path) == 0
    assert installer.main(['--verify'], path) == 0
    reports = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert all(r['target_commands_executed'] == 0 and r['D_ssh_verified'] is False
               and r['effect_verified'] is None for r in reports)
    assert before == {p.name: p.read_bytes() for p in path.iterdir()}
    assert not (path / '__pycache__').exists()


def test_existing_release_never_reused(release):
    path, _ = release
    before = {p.name: p.read_bytes() for p in path.iterdir()}
    with pytest.raises(FileExistsError): builder.build(path)
    assert before == {p.name: p.read_bytes() for p in path.iterdir()}


def test_unapproved_tool_rejected_before_output_creation(tmp_path):
    source = tmp_path / 'source'
    for relative in builder.SOURCES.values():
        p = source / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes((ROOT / relative).read_bytes())
    tool = source / builder.SOURCES['pfsense_response.py']
    tool.write_bytes(tool.read_bytes() + b'\n# altered candidate\n')
    target = tmp_path / 'release'
    with pytest.raises(ValueError, match='approved'): builder.build(target, source)
    assert not target.exists()


@pytest.mark.parametrize('problem', ['changed_payload', 'missing_payload', 'missing_marker', 'extra_manifest_path',
                                    'unapproved_hash', 'wrong_manifest_version'])
def test_incomplete_tampered_or_unapproved_release_is_refused(release, problem, tmp_path):
    path, manifest = release
    if problem == 'changed_payload': (path / 'pfsense_response.py').write_text('WRONG')
    if problem == 'missing_payload': (path / 'INSTALL.md').unlink()
    if problem == 'missing_marker': (path / 'bundle.json').unlink()
    if problem == 'extra_manifest_path': manifest['files']['../escape'] = '0' * 64
    if problem == 'unapproved_hash': manifest['tool_sha256'] = '0' * 64
    if problem == 'wrong_manifest_version': manifest['version'] = 2
    if problem in ('extra_manifest_path', 'unapproved_hash', 'wrong_manifest_version'):
        (path / 'bundle.json').write_text(json.dumps(manifest), encoding='utf-8')
    with pytest.raises(installer.Refused): installer.verify(path)


def test_create_only_install_keeps_unrelated_files(release, tmp_path, simulated_root_ownership):
    path, _ = release
    target = tmp_path / 'haedam-pf-response'
    unrelated = tmp_path / 'administrator-key'
    unrelated.write_text('DO-NOT-CHANGE')
    installer.publish_new(path / 'pfsense_response.py', target)
    assert installer.digest(target) == installer.PINNED_SHA
    assert unrelated.read_text() == 'DO-NOT-CHANGE'
    with pytest.raises(installer.Refused): installer.publish_new(path / 'pfsense_response.py', target)
    assert unrelated.read_text() == 'DO-NOT-CHANGE'


def test_concurrent_destination_is_preserved_and_staging_removed(release, tmp_path, monkeypatch,
                                                                 simulated_root_ownership):
    path, _ = release
    target = tmp_path / 'haedam-pf-response'
    def raced(source, destination):
        destination.write_text('OTHER-INSTALLER')
        raise FileExistsError('race')
    monkeypatch.setattr(installer.os, 'link', raced)
    with pytest.raises(FileExistsError): installer.publish_new(path / 'pfsense_response.py', target)
    assert target.read_text() == 'OTHER-INSTALLER'
    assert not list(tmp_path.glob('.haedam-pf-response-*'))


def test_staging_mutation_is_refused_before_publication(release, tmp_path, simulated_root_ownership):
    path, _ = release
    source = tmp_path / 'changed.py'
    source.write_text('WRONG')
    target = tmp_path / 'haedam-pf-response'
    with pytest.raises(installer.Refused, match='staging_hash'): installer.publish_new(source, target)
    assert not target.exists() and not list(tmp_path.glob('.haedam-pf-response-*'))


def test_install_requires_appliance_before_any_destination_write(release, tmp_path, monkeypatch, capsys):
    path, _ = release
    target = tmp_path / 'haedam-pf-response'
    monkeypatch.setattr(installer, 'TARGET', target)
    def denied(): raise installer.Refused('root_on_appliance_required')
    monkeypatch.setattr(installer, 'require_appliance', denied)
    assert installer.main(['--install'], path) == 1
    assert json.loads(capsys.readouterr().out)['reason'] == 'root_on_appliance_required'
    assert not target.exists()


def test_existing_different_target_is_not_overwritten(release, tmp_path, monkeypatch):
    path, _ = release
    target = tmp_path / 'haedam-pf-response'
    target.write_text('OLD-OR-UNKNOWN')
    monkeypatch.setattr(installer, 'TARGET', target)
    monkeypatch.setattr(installer, 'require_appliance', lambda: None)
    with pytest.raises(installer.Refused): installer.install(path)
    assert target.read_text() == 'OLD-OR-UNKNOWN'


def test_generated_installer_runs_without_repository_imports(release):
    path, _ = release
    result = subprocess.run([sys.executable, '-I', '-B', str(path / 'install_bundle.py'), '--verify'],
                            cwd=path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout)['result'] == 'verified_files_only'
