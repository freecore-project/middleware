import asyncio
import sqlite3
from unittest.mock import Mock

import pytest

from middlewared.plugins.jail_freebsd import (
    FREECORE_PLUGIN_REPOSITORY,
    PluginService,
    legacy_ix_plugin_repository,
    normalize_plugin_repository,
)
from middlewared.service_exception import ValidationErrors


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
