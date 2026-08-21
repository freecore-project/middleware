import asyncio
import inspect
import sqlite3
from pathlib import Path
from unittest.mock import ANY, AsyncMock, Mock, call, patch

import pytest
from middlewared.plugins.jail_freebsd import (
    IOCAGE_PLUGIN_STORE_RETIRED,
    JailFSAttachmentDelegate,
    JailService,
    PluginService,
)
from middlewared.service_exception import CallError


def assert_plugin_store_retired(call):
    with pytest.raises(CallError) as error:
        call()

    assert IOCAGE_PLUGIN_STORE_RETIRED in str(error.value)


def test_official_repositories_is_empty_without_middleware_calls():
    middleware = Mock()

    assert asyncio.run(PluginService(middleware).official_repositories()) == {}
    middleware.call.assert_not_called()
    middleware.call_sync.assert_not_called()


def test_plugin_create_is_retired_before_any_jail_work():
    middleware = Mock()
    service = PluginService(middleware)

    assert_plugin_store_retired(lambda: service.do_create(Mock(), {
        'plugin_name': 'transmission',
        'jail_name': 'transmission',
        'props': [],
        'branch': None,
        'plugin_repository': 'https://example.invalid/plugin-index.git',
    }))
    middleware.call_sync.assert_not_called()


def test_remote_plugin_operations_are_retired_without_middleware_calls():
    middleware = Mock()
    service = PluginService(middleware)

    assert_plugin_store_retired(lambda: service.available(Mock(), {}))
    assert_plugin_store_retired(lambda: service.defaults({
        'refresh': False,
        'plugin': 'transmission',
        'branch': None,
        'plugin_repository': 'https://example.invalid/plugin-index.git',
    }))
    assert_plugin_store_retired(lambda: service.update_plugin(Mock(), 'transmission', True))
    assert_plugin_store_retired(lambda: asyncio.run(
        service.branches_choices('https://example.invalid/plugin-index.git')
    ))
    middleware.call.assert_not_called()
    middleware.call_sync.assert_not_called()


def test_hidden_jail_fetch_plugin_path_is_retired_before_pool_work():
    middleware = Mock()
    service = JailService(middleware)

    assert_plugin_store_retired(lambda: service.fetch(Mock(), {
        'server': 'download.freebsd.org',
        'name': 'transmission',
        'jail_name': 'transmission',
        'props': [],
        'https': True,
    }))
    middleware.call_sync.assert_not_called()


@patch('middlewared.plugins.jail_freebsd.ioc.IOCage')
def test_ordinary_release_fetch_remains_available(iocage):
    middleware = Mock()
    service = JailService(middleware)
    service.check_dataset_existence = Mock()
    job = Mock()

    assert service.fetch(job, {
        'release': '15.0-RELEASE',
        'server': 'download.freebsd.org',
        'name': None,
        'props': [],
        'https': True,
    }) is True

    service.check_dataset_existence.assert_called_once_with()
    iocage.assert_called_once_with(callback=ANY, silent=False)
    iocage.return_value.fetch.assert_called_once_with(
        release='15.0-RELEASE',
        server='https://download.freebsd.org',
        props=[],
        user='anonymous',
        password='anonymous@',
        accept=True,
        files=['MANIFEST', 'base.txz', 'lib32.txz'],
        branch=None,
    )
    middleware.call_sync.assert_not_called()


def test_plugin_store_pollers_and_remote_implementation_are_removed():
    service = PluginService(Mock())
    source = inspect.getsource(PluginService)
    legacy_update_alert = Path(__file__).parents[3] / 'alert' / 'source' / 'jails.py'

    for method in (
        'available_impl',
        'periodic_plugin_update',
        'plugin_updates',
        'retrieve_index_plugins_data',
        'retrieve_plugin_versions',
        'retrieve_versions_for_repos',
    ):
        assert not hasattr(service, method)

    for remote_operation in (
        'IOCPlugin',
        '_clone_repo',
        'fetch_plugin_versions',
        'pull_clone_git_repo',
        'plugin.available_impl',
    ):
        assert remote_operation not in source

    assert not legacy_update_alert.exists()


def test_local_plugin_query_compatibility_remains_without_an_iocage_pool():
    middleware = Mock()
    middleware.call_sync.return_value = False
    service = PluginService(middleware)

    assert PluginService.query.wraps(service, [], {}) == []
    middleware.call_sync.assert_called_once_with('jail.iocage_set_up')


def test_plugin_update_and_delete_remain_generic_jail_wrappers():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[{'id': 'legacy'}, True])
    service = PluginService(middleware)
    service._get_instance = AsyncMock(return_value={'id': 'legacy'})

    assert asyncio.run(PluginService.do_update.wraps(service, 'legacy', {'boot': True})) == {'id': 'legacy'}
    assert asyncio.run(PluginService.do_delete.wraps(service, 'legacy')) is True
    assert middleware.call.await_args_list == [
        call('jail.update', 'legacy', {'boot': True}),
        call('jail.delete', 'legacy'),
    ]


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
