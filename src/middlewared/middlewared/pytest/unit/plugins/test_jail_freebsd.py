import asyncio
import inspect
import sqlite3
from pathlib import Path
from unittest.mock import ANY, AsyncMock, Mock, call, patch

import pytest
from middlewared.plugins.jail_freebsd import (
    IOCAGE_PLUGIN_STORE_RETIRED,
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
