import asyncio
import sqlite3
from unittest.mock import ANY, AsyncMock, Mock, call

import pytest

from middlewared.plugins.jail_freebsd import (
    FREECORE_PLUGIN_REPOSITORY,
    JailFSAttachmentDelegate,
    JailService,
    PluginService,
    legacy_ix_plugin_repository,
    normalize_plugin_repository,
)
from middlewared.service_exception import CallError, ValidationErrors


@pytest.mark.parametrize('repository', [
    'https://github.com/freenas/iocage-ix-plugins.git',
    'https://github.com/truenas/iocage-ix-plugins',
    'git@github.com:ix-plugin-hub/iocage-plugin-index.git',
])
def test_legacy_ix_plugin_repository(repository):
    assert legacy_ix_plugin_repository(repository) is True


@pytest.mark.parametrize('repository', [
    FREECORE_PLUGIN_REPOSITORY,
    'https://example.invalid/example/custom-plugin-index.git',
])
def test_nonlegacy_plugin_repository(repository):
    assert legacy_ix_plugin_repository(repository) is False


def test_retired_freecore_repository_normalizes_to_current_catalog():
    assert normalize_plugin_repository(
        'https://plugins.freecore.org/plugins/git/iocage-zfs-plugins.git'
    ) == FREECORE_PLUGIN_REPOSITORY


def test_plugin_create_rejects_legacy_repository_before_any_jail_work():
    middleware = Mock()
    service = PluginService(middleware)

    with pytest.raises(ValidationErrors) as error:
        service.do_create(Mock(), {
            'plugin_name': 'transmission',
            'jail_name': 'transmission',
            'props': [],
            'branch': None,
            'plugin_repository': (
                'https://github.com/truenas/iocage-ix-plugins.git'
            ),
        })

    assert 'plugin_create.plugin_repository' in error.value
    middleware.call_sync.assert_not_called()


def test_official_repository_is_only_freecore_catalog():
    repositories = asyncio.run(
        PluginService(Mock()).official_repositories()
    )

    assert repositories == {
        'FREECORE': {
            'name': 'FreeCORE',
            'git_repository': FREECORE_PLUGIN_REPOSITORY,
        }
    }


def test_read_plugin_pkg_db_uses_package_name_as_data(tmp_path):
    database = tmp_path / 'local.sqlite'
    with sqlite3.connect(database) as connection:
        connection.execute('''
            CREATE TABLE packages (
                id INTEGER,
                origin TEXT,
                name TEXT,
                version TEXT
            )
        ''')
        connection.executemany(
            'INSERT INTO packages VALUES (?, ?, ?, ?)',
            [
                (1, 'net-p2p/qbittorrent', 'qbittorrent-nox', '5.2.3'),
                (2, 'net-p2p/transmission', 'transmission', '4.1.3'),
            ],
        )

    service = PluginService(Mock())

    assert service.read_plugin_pkg_db(str(database), 'qbittorrent-nox') == [
        (1, 'net-p2p/qbittorrent', 'qbittorrent-nox', '5.2.3'),
    ]
    assert service.read_plugin_pkg_db(str(database), '" OR 1=1 --') == []


def test_read_plugin_pkg_db_closes_its_connection(tmp_path, monkeypatch):
    database = tmp_path / 'local.sqlite'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE packages (id INTEGER, origin TEXT, name TEXT, version TEXT)')
        connection.execute('INSERT INTO packages VALUES (1, \'net-p2p/qbittorrent\', \'qbittorrent-nox\', \'5.2.3\')')

    connections = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, 'connect', recording_connect)
    service = PluginService(Mock())

    assert service.read_plugin_pkg_db(str(database), 'qbittorrent-nox') == [
        (1, 'net-p2p/qbittorrent', 'qbittorrent-nox', '5.2.3'),
    ]
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed database'):
        connections[0].execute('SELECT 1')


def test_read_plugin_pkg_db_closes_its_connection_when_the_query_fails(tmp_path, monkeypatch):
    database = tmp_path / 'local.sqlite'
    sqlite3.connect(database).close()  # a database without a packages table

    connections = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, 'connect', recording_connect)
    service = PluginService(Mock())

    with pytest.raises(sqlite3.OperationalError):
        service.read_plugin_pkg_db(str(database), 'qbittorrent-nox')
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match='closed database'):
        connections[0].execute('SELECT 1')


def test_jail_patch_update_uses_iocage_113_api_and_reports_progress():
    service = JailService(Mock())
    job = Mock()
    iocage = Mock()
    callback = None

    def check_jail_existence(jail, **kwargs):
        nonlocal callback
        callback = kwargs['callback']
        return jail, f'/iocage/jails/{jail}', iocage

    def update(*, pkgs):
        assert pkgs is True
        for message in (
            'Inspecting system... done',
            'Preparing to download files... done.',
            'Applying patches... done.',
            'Installing updates... done.',
            'test updates have been applied successfully.',
        ):
            callback({'level': 'INFO', 'message': f'{message}\n'}, RuntimeError)

    service.check_jail_existence = Mock(side_effect=check_jail_existence)
    iocage.update.side_effect = update

    assert service.update_to_latest_patch_internal(job, 'test', True) is True
    service.check_jail_existence.assert_called_once_with('test', callback=ANY)
    iocage.update.assert_called_once_with(pkgs=True)
    for progress in (20, 50, 75, 90, 100):
        assert call(progress) in job.set_progress.call_args_list


def test_jail_patch_update_reports_no_available_updates():
    service = JailService(Mock())
    job = Mock()
    iocage = Mock()

    def check_jail_existence(jail, **kwargs):
        callback = kwargs['callback']
        iocage.update.side_effect = lambda *, pkgs: callback({
            'level': 'INFO',
            'message': 'No updates needed to update system.\n',
        }, RuntimeError)
        return jail, f'/iocage/jails/{jail}', iocage

    service.check_jail_existence = Mock(side_effect=check_jail_existence)

    with pytest.raises(CallError, match='No updates available for test'):
        service.update_to_latest_patch_internal(job, 'test', False)

    iocage.update.assert_called_once_with(pkgs=False)
    job.set_progress.assert_called_once_with(0, 'Updating test')


JAILS = [
    {'host_hostuuid': 'web', 'state': 'up', 'boot': 0},
    {'host_hostuuid': 'db', 'state': 'down', 'boot': 1},
    {'host_hostuuid': 'base', 'state': 'up', 'boot': 0},
    {'host_hostuuid': 'old', 'state': 'down', 'boot': 0},
]
FSTABS = {
    'base': (
        '/mnt/tank/iocage/releases/14.3-RELEASE/root/bin\t/mnt/tank/iocage/jails/base/root/bin\tnullfs\tro\t0\t0'
        '\t# Added by iocage on 2026-11-20 07:50:00\n'
    ),
    'old': '# a comment\n\n/mnt/tank/iocage/templates/t1/root/lib /mnt/tank/iocage/jails/old/root/lib nullfs ro 0 0\n',
    'web': '/mnt/tank/media\\040files /mnt/tank/iocage/jails/web/root/media nullfs rw 0 0\n',
}


def jail_delegate(tmp_path):
    for name, text in FSTABS.items():
        (tmp_path / 'jails' / name).mkdir(parents=True)
        (tmp_path / 'jails' / name / 'fstab').write_text(text)

    async def dispatch(method, *args):
        if method == 'jail.query':
            if args:
                return [j for j in JAILS if j['state'] == 'up' or j['boot']]
            return JAILS
        return {
            'jail.iocage_set_up': True,
            'jail.get_activated_pool': 'tank',
            'jail.get_iocroot': str(tmp_path),
        }[method]

    async def run_in_thread(method, *args):
        return method(*args)

    return JailFSAttachmentDelegate(Mock(call=AsyncMock(side_effect=dispatch), run_in_thread=run_in_thread))


@pytest.mark.asyncio
@pytest.mark.parametrize('path,ids', [
    ('/mnt/tank', ['web', 'db', 'base']),
    ('/mnt/tank/iocage', ['web', 'db', 'base']),
    ('/mnt/tank/iocage/jails', ['web', 'db', 'base']),
    ('/mnt/tank/iocage/jails/web', ['web']),
    ('/mnt/tank/iocage/jails/web/root', ['web']),
    ('/mnt/tank/iocage/jails/old', []),
    ('/mnt/tank/iocage/test', []),
    ('/mnt/tank/iocage/download/14.3-RELEASE', []),
    ('/mnt/tank/iocage/releases/13.5-RELEASE', []),
    ('/mnt/tank/iocage/releases/14.3-RELEASE', ['base']),
    ('/mnt/tank/iocage/releases', ['base']),
    ('/mnt/tank/iocage/templates/t1', ['old']),
    ('/mnt/tank/iocage/releases/14.3', []),
    ('/mnt/tank/iocagebackup', []),
    ('/mnt/tank/iocage-old/jails/web', []),
    ('/mnt/tank/media', []),
])
async def test_jail_attachments_are_only_the_jails_that_use_the_dataset(tmp_path, path, ids):
    attachments = await jail_delegate(tmp_path).query(path, True)

    assert [a['id'] for a in attachments] == ids


@pytest.mark.asyncio
async def test_a_dataset_a_jail_mounts_is_refused_for_delete_and_only_active_jails_are_toggled(tmp_path):
    delegate = jail_delegate(tmp_path)
    release = await delegate.query('/mnt/tank/iocage/releases', True)
    template = await delegate.query('/mnt/tank/iocage/templates/t1', True)

    assert release == [{'id': 'base', 'mounts_from': True, 'active': True}]
    assert template == [{'id': 'old', 'mounts_from': True, 'active': False}]
    with pytest.raises(CallError, match='base mounts this dataset in its fstab'):
        await delegate.check_delete(release)
    await delegate.check_delete(await delegate.query('/mnt/tank/iocage/jails/web', True))

    delegate.middleware.call.reset_mock()
    await delegate.toggle(release + template, False)
    assert delegate.middleware.call.await_args_list == [call('jail.stop', 'base')]
