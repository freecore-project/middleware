import base64
import importlib.util
from pathlib import Path
import stat
import subprocess

import pytest


RENDERER_PATH = Path(__file__).parents[3] / 'etc_files' / 'krb5.keytab.py'
SPEC = importlib.util.spec_from_file_location('middlewared.etc_files.krb5_keytab_renderer', RENDERER_PATH)
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class Middleware:
    def __init__(self, keytabs):
        self.keytabs = keytabs

    def call_sync(self, name):
        assert name == 'kerberos.keytab.query'
        return [
            {'id': index, 'file': base64.b64encode(keytab).decode()}
            for index, keytab in enumerate(self.keytabs, 1)
        ]


@pytest.fixture
def paths(tmp_path, monkeypatch):
    kdir = tmp_path / 'kerberos'
    keytabfile = tmp_path / 'krb5.keytab'
    monkeypatch.setattr(renderer, 'kdir', str(kdir))
    monkeypatch.setattr(renderer, 'keytabfile', str(keytabfile))
    monkeypatch.setattr(renderer.logger, 'trace', lambda *args: None, raising=False)
    return kdir, keytabfile


def install_mit_ktutil(monkeypatch, calls, returncode=0, stderr=b''):
    monkeypatch.setattr(renderer.KRB5, 'platform', lambda: renderer.KRB5.MIT)

    def run(args, **kwargs):
        calls.append((args, kwargs))
        keylist = []
        for command in kwargs['input'].decode().splitlines():
            if command == 'q':
                continue

            action, path = command.split(' ', 1)
            if action == 'rkt':
                keylist.extend(Path(path).read_bytes().splitlines())
            elif action == 'wkt' and returncode == 0 and not stderr:
                Path(path).write_bytes(b'\n'.join(keylist))
            else:
                assert action == 'wkt'

        return subprocess.CompletedProcess(args, returncode, stdout=b'', stderr=stderr)

    monkeypatch.setattr(renderer.subprocess, 'run', run)


def test_mit_renderer_merges_all_keytabs_once(paths, monkeypatch):
    kdir, keytabfile = paths
    calls = []
    install_mit_ktutil(monkeypatch, calls)

    renderer.render(None, Middleware([b'machine\nhost', b'nfs']))

    assert keytabfile.read_bytes().splitlines() == [b'machine', b'host', b'nfs']
    assert stat.S_IMODE(kdir.stat().st_mode) == 0o700
    assert stat.S_IMODE(keytabfile.stat().st_mode) == 0o600
    assert list(kdir.iterdir()) == []
    assert len(calls) == 1
    assert calls[0][0] == [renderer.mit_ktutil_cmd]

    commands = calls[0][1]['input'].decode().splitlines()
    assert [command.split(' ', 1)[0] for command in commands] == ['rkt', 'rkt', 'wkt', 'q']


def test_mit_renderer_replaces_previous_keytab_without_stale_entries(paths, monkeypatch):
    _, keytabfile = paths
    calls = []
    install_mit_ktutil(monkeypatch, calls)

    renderer.render(None, Middleware([b'machine', b'removed-principal']))
    renderer.render(None, Middleware([b'machine']))

    assert keytabfile.read_bytes() == b'machine'
    assert len(calls) == 2


def test_heimdal_renderer_preserves_copy_contract(paths, monkeypatch):
    kdir, keytabfile = paths
    calls = []
    monkeypatch.setattr(renderer.KRB5, 'platform', lambda: renderer.KRB5.HEIMDAL)

    def run(args, **kwargs):
        calls.append((args, kwargs))
        source = Path(args[2]).read_bytes()
        destination = Path(args[3])
        previous = destination.read_bytes() if destination.exists() else b''
        destination.write_bytes(previous + source)
        return subprocess.CompletedProcess(args, 1, stdout=b'', stderr=b'')

    monkeypatch.setattr(renderer.subprocess, 'run', run)

    renderer.render(None, Middleware([b'machine', b'nfs']))

    assert keytabfile.read_bytes() == b'machinenfs'
    assert list(kdir.iterdir()) == []
    assert [call[0][0:2] for call in calls] == [
        [renderer.heimdal_ktutil_cmd, 'copy'],
        [renderer.heimdal_ktutil_cmd, 'copy'],
    ]


def test_renderer_preserves_existing_keytab_and_cleans_staging_on_mit_failure(paths, monkeypatch):
    kdir, keytabfile = paths
    keytabfile.write_bytes(b'existing-keytab')
    calls = []
    install_mit_ktutil(monkeypatch, calls, returncode=1, stderr=b'write failed')

    with pytest.raises(RuntimeError, match='write failed'):
        renderer.render(None, Middleware([b'machine']))

    assert keytabfile.read_bytes() == b'existing-keytab'
    assert list(kdir.iterdir()) == []


def test_renderer_rejects_success_without_generated_output(paths, monkeypatch):
    kdir, keytabfile = paths
    keytabfile.write_bytes(b'existing-keytab')
    monkeypatch.setattr(renderer.KRB5, 'platform', lambda: renderer.KRB5.MIT)
    monkeypatch.setattr(
        renderer.subprocess,
        'run',
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=b'', stderr=b''),
    )

    with pytest.raises(RuntimeError, match='produced no output'):
        renderer.render(None, Middleware([b'machine']))

    assert keytabfile.read_bytes() == b'existing-keytab'
    assert list(kdir.iterdir()) == []


def test_renderer_with_no_database_keytabs_leaves_system_keytab_unchanged(paths, monkeypatch):
    kdir, keytabfile = paths
    keytabfile.write_bytes(b'existing-keytab')
    monkeypatch.setattr(renderer.subprocess, 'run', pytest.fail)

    renderer.render(None, Middleware([]))

    assert keytabfile.read_bytes() == b'existing-keytab'
    assert not kdir.exists()
