"""Configuration for moving to TrueNAS SCALE (the internal development record)."""
import io
import os
import sqlite3
import sys
import tarfile
import types
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # config.py imports the pool plugin, which imports py-libzfs; nothing here enters it.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins import config as config_plugin
from middlewared.plugins.config import ConfigService
from middlewared.plugins.config_ import scale as scale_config
from middlewared.service_exception import CallError

FREECORE_HEAD = 'b7e3d19a5c42'


def make_database(path, revision, tables):
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
        connection.execute('INSERT INTO alembic_version VALUES (?)', (revision,))
        for table in tables:
            connection.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT)')
            connection.execute(f"INSERT INTO {table} (value) VALUES ('{table}')")
    return str(path)


def fake_alembic(calls, drop=('services_wireguard',), revision=scale_config.SCALE_BASE_REVISION, returncode=0):
    """Stands in for `alembic downgrade`: edits the file FREENAS_DATABASE names, logs like alembic."""
    def run(argv, cwd=None, env=None, capture_output=None, text=None):
        calls.append({'argv': argv, 'cwd': cwd, 'database': env['FREENAS_DATABASE']})
        if returncode == 0:
            with sqlite3.connect(env['FREENAS_DATABASE']) as connection:
                for table in drop:
                    connection.execute(f'DROP TABLE {table}')
                connection.execute('UPDATE alembic_version SET version_num = ?', (revision,))
        prefix = 'INFO  [alembic.runtime.migration] Running downgrade'
        stderr = (
            f'{prefix} 4b7c1f0a9d32 -> 6950c136c5ac, Add WireGuard server service\n'
            f'{prefix} a1b2c3d4e5f6 -> b412304844e1, '
            'Migrate old-style ZFS sysctl names to OpenZFS 2.2+ dotted hierarchy\n'
        ) if returncode == 0 else 'FAILED: something broke\n'
        return SimpleNamespace(returncode=returncode, stdout='', stderr=stderr)
    return run


def test_build_downgrades_a_copy_and_never_the_live_database(tmp_path):
    live = make_database(tmp_path / 'live.db', FREECORE_HEAD, ['account_bsdusers', 'services_wireguard'])
    factory = make_database(tmp_path / 'factory.db', scale_config.SCALE_BASE_REVISION, ['account_bsdusers'])
    before = open(live, 'rb').read()
    work = tmp_path / 'work'
    work.mkdir()
    calls = []

    database, undone = scale_config.build(live, str(work), run=fake_alembic(calls), cwd='/mw', factory=factory)

    assert database == str(work / 'freenas-v1.db')
    assert calls == [{'argv': ['alembic', 'downgrade', 'b412304844e1'], 'cwd': '/mw', 'database': database}]
    assert undone == [
        'Add WireGuard server service',
        'Migrate old-style ZFS sysctl names to OpenZFS 2.2+ dotted hierarchy',
    ]
    assert scale_config.stamp(database) == 'b412304844e1'
    assert scale_config.tables(database) == {'alembic_version', 'account_bsdusers'}
    assert oct(os.stat(database).st_mode & 0o777) == '0o600'
    # The live database is only read.
    assert open(live, 'rb').read() == before
    assert scale_config.stamp(live) == FREECORE_HEAD


def test_build_refuses_what_scale_would_refuse(tmp_path):
    live = make_database(tmp_path / 'live.db', FREECORE_HEAD, ['account_bsdusers', 'services_wireguard'])
    factory = make_database(tmp_path / 'factory.db', scale_config.SCALE_BASE_REVISION, ['account_bsdusers'])
    for name, run, expected in (
        ('failed', fake_alembic([], returncode=1), '(?s)Unable to downgrade.*something broke'),
        ('stamp', fake_alembic([], revision='a1b2c3d4e5f6'), "stamped 'a1b2c3d4e5f6'"),
        ('tables', fake_alembic([], drop=()), 'extra: services_wireguard'),
    ):
        work = tmp_path / name
        work.mkdir()
        with pytest.raises(CallError, match=expected):
            scale_config.build(live, str(work), run=run, cwd='/mw', factory=factory)


def test_a_database_already_at_13_3_is_not_downgraded(tmp_path):
    live = make_database(tmp_path / 'live.db', scale_config.SCALE_BASE_REVISION, ['account_bsdusers'])
    work = tmp_path / 'work'
    work.mkdir()
    run = Mock(side_effect=AssertionError('alembic must not run'))
    database, undone = scale_config.build(live, str(work), run=run, factory=str(tmp_path / 'absent.db'))
    assert undone == [] and scale_config.stamp(database) == 'b412304844e1'


def test_readme_names_what_was_removed_and_how_to_use_it():
    text = scale_config.readme(['Add WireGuard server service'], 'FreeCORE-15.1-RC6', ['freenas-v1.db', 'pwenc_secret'])
    assert 'NOT a FreeCORE backup' in text and 'b412304844e1' in text
    assert '  - Add WireGuard server service' in text
    # The path is one hop: a clean install of the release the pool needs, never 24.04 as a stopover.
    assert '24.10 or later' in text and 'Upload File' in text and 'needs 24.04, and this file is not' in text
    assert 'network interfaces again' in text and 'create one again' in text
    assert 'OpenZFS 2.3 is TrueNAS 25.04, OpenZFS 2.4 is TrueNAS 26' in text and 'secret seed' in text
    assert 'Included: freenas-v1.db, pwenc_secret' in text
    assert '(none: the database was already at 13.3)' in scale_config.readme([], 'x', [])
    # The user's file names no internal tracker, even when a revision title does, and points at the export
    # the web interface has (Applications -> Installed, Export for Linux), not a Convert menu it lacks.
    tagged = scale_config.readme(
        ['Scrub telemetry residue values (the internal development record)'], 'FreeCORE-15.1-RC6', ['freenas-v1.db'],
    )
    assert '  - Scrub telemetry residue values\n' in tagged
    assert '#' not in tagged and 'freecore/' not in tagged
    assert 'Export for Linux' in tagged and 'Convert -> Export' not in tagged


def service_with(tmp_path, monkeypatch, secret=True, keys=True):
    live = make_database(tmp_path / 'freenas-v1.db', FREECORE_HEAD, ['account_bsdusers', 'services_wireguard'])
    monkeypatch.setattr(config_plugin, 'FREENAS_DATABASE', live)
    pwenc = tmp_path / 'pwenc_secret'
    pwenc.write_bytes(b'secret-seed')
    keyfile = tmp_path / 'authorized_keys'
    keyfile.write_text('ssh-ed25519 AAAA test\n')
    monkeypatch.setattr(config_plugin, 'PWENC_FILE_SECRET', str(pwenc))
    monkeypatch.setitem(config_plugin.CONFIG_FILES, 'pwenc_secret', str(pwenc))
    monkeypatch.setitem(config_plugin.CONFIG_FILES, 'root_authorized_keys', str(keyfile) if keys else '/nonexistent')
    monkeypatch.setitem(config_plugin.CONFIG_FILES, 'geli', str(tmp_path / 'geli'))
    calls = []
    real_build = scale_config.build
    monkeypatch.setattr(scale_config, 'build', lambda source, workdir: real_build(
        source, workdir, run=fake_alembic(calls), cwd='/mw', factory=str(tmp_path / 'absent.db'),
    ))
    middleware = Mock()
    middleware.call_sync = Mock(side_effect=lambda method, *args: {
        'system.version': 'FreeCORE-15.1-MASTER', 'pool.query': [{'name': 'tank'}],
    }[method])
    monkeypatch.setattr(scale_config, 'pool_feature_report', lambda pool: {
        'pool': pool, 'reference': 'TrueNAS SCALE 24.10.0', 'refused': [], 'read_only': [],
        'dormant': ['physical_rewrite'],
    })

    async def run_in_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    middleware.run_in_thread = run_in_thread
    job = Mock()
    job.pipes.output.w = io.BytesIO()
    return ConfigService(middleware), job, live, calls


@pytest.mark.asyncio
async def test_save_for_scale_streams_a_bundle_scale_can_read(tmp_path, monkeypatch):
    service, job, live, calls = service_with(tmp_path, monkeypatch)
    await ConfigService.save.wraps(service, job, {
        'secretseed': True, 'pool_keys': True, 'root_authorized_keys': True, 'target': 'truenas-scale',
    })
    archive = tarfile.open(fileobj=io.BytesIO(job.pipes.output.w.getvalue()))
    names = sorted(archive.getnames())
    # The names SCALE's config.upload looks for, plus the README it ignores; never GELI keys.
    assert names == ['README.truenas-scale', 'freenas-v1.db', 'pwenc_secret', 'root_authorized_keys']
    extracted = tmp_path / 'extracted'
    archive.extractall(extracted)
    assert scale_config.stamp(str(extracted / 'freenas-v1.db')) == 'b412304844e1'
    assert (extracted / 'pwenc_secret').read_bytes() == b'secret-seed'
    readme = (extracted / 'README.truenas-scale').read_text()
    assert 'FreeCORE-15.1-MASTER' in readme and 'Add WireGuard server service' in readme
    assert 'no GELI keys' in readme
    assert 'pool tank uses OpenZFS features TrueNAS SCALE 24.10.0 does not have: physical_rewrite (enabled)' in readme
    assert scale_config.stamp(live) == FREECORE_HEAD and len(calls) == 1


@pytest.mark.asyncio
async def test_save_for_scale_leaves_out_what_was_not_asked_for(tmp_path, monkeypatch):
    service, job, _live, _calls = service_with(tmp_path, monkeypatch, keys=False)
    await ConfigService.save.wraps(service, job, {
        'secretseed': False, 'pool_keys': False, 'root_authorized_keys': True, 'target': 'truenas-scale',
    })
    names = tarfile.open(fileobj=io.BytesIO(job.pipes.output.w.getvalue())).getnames()
    assert sorted(names) == ['README.truenas-scale', 'freenas-v1.db']


@pytest.mark.asyncio
async def test_a_plain_save_is_unchanged_by_the_target_option(tmp_path, monkeypatch):
    # The "no options -> the database file itself" rule must not see `target` as a set option.
    service, job, live, calls = service_with(tmp_path, monkeypatch)
    await ConfigService.save.wraps(service, job, {
        'secretseed': False, 'pool_keys': False, 'root_authorized_keys': False, 'target': 'freecore',
    })
    assert job.pipes.output.w.getvalue() == open(live, 'rb').read()
    assert calls == []


UPGRADE_V = """This system supports ZFS pool feature flags.

The following features are supported:

FEAT DESCRIPTION
-------------------------------------------------------------
async_destroy                         (read-only compatible)
     Destroy filesystems asynchronously.
longname
     Support for filenames up to 1024 bytes.
large_microzap                        (read-only compatible)
     Support for microzaps larger than 128KB.
physical_rewrite                      (read-only compatible)
     Support for zfs rewrite -P.
dynamic_gang_header
     Support for dynamic gang headers.

The following legacy versions are also supported:
"""

ZPOOL_GET = (
    'name\ttank\nfeature@async_destroy\tenabled\nfeature@longname\tactive\n'
    'feature@large_microzap\tactive\nfeature@physical_rewrite\tenabled\nfeature@dynamic_gang_header\tdisabled\n'
)


def fake_zpool(argv, capture_output=None, text=None, check=None):
    if argv[:2] == ['zpool', 'get']:
        return SimpleNamespace(stdout=ZPOOL_GET)
    if argv[:2] == ['zpool', 'upgrade']:
        return SimpleNamespace(stdout=UPGRADE_V)
    raise AssertionError(argv)


def test_pool_features_are_judged_against_what_scale_supports():
    assert scale_config.parse_feature_support(UPGRADE_V) == {
        'async_destroy': True, 'longname': False, 'large_microzap': True,
        'physical_rewrite': True, 'dynamic_gang_header': False,
    }
    assert scale_config.parse_feature_states(ZPOOL_GET)['longname'] == 'active'
    report = scale_config.pool_feature_report('tank', run=fake_zpool)
    # async_destroy is known to SCALE; dynamic_gang_header is disabled; the rest split by consequence.
    assert report == {'pool': 'tank', 'reference': 'TrueNAS SCALE 24.10.0', 'refused': ['longname'],
                      'read_only': ['large_microzap'], 'dormant': ['physical_rewrite']}
    lines = scale_config.describe_pool_report(report)
    # One line naming the release to go to; what a release below it would do is not described.
    assert lines == [
        'pool tank uses OpenZFS features TrueNAS SCALE 24.10.0 does not have: longname (in use), '
        'large_microzap (in use), physical_rewrite (enabled) -- import the pool only on '
        'OpenZFS 2.4 (TrueNAS 26 or later)'
    ]
    assert scale_config.needed_release(['longname', 'large_microzap']) == 'OpenZFS 2.3 (TrueNAS 25.04 or later)'
    assert scale_config.needed_release([]) is None
    assert scale_config.needed_release(['longname', 'from_the_future']) is None
    assert scale_config.describe_pool_report({**report, 'refused': ['from_the_future']}) == [
        'pool tank uses OpenZFS features TrueNAS SCALE 24.10.0 does not have: from_the_future (in use), '
        'large_microzap (in use), physical_rewrite (enabled) -- import the pool only on a release whose '
        '`zpool upgrade -v` lists them'
    ]
    assert scale_config.describe_pool_report(None) == []
    assert scale_config.describe_pool_report({**report, 'refused': [], 'read_only': [], 'dormant': []}) == []

    def broken(*args, **kwargs):
        raise FileNotFoundError('zpool')
    assert scale_config.pool_feature_report('tank', run=broken) is None
    text = scale_config.readme([], 'x', [], lines)
    assert 'Pools, checked against the OpenZFS features of TrueNAS SCALE 24.10.0:' in text
    assert '  - pool tank uses OpenZFS features' in text
    assert 'every pool uses only features' in scale_config.readme([], 'x', [], [])
