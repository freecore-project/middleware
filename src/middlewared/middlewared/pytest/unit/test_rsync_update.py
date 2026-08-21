from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import rsync


class Middleware:

    def __init__(self):
        self.calls = []
        self.event_register = Mock()

    async def call(self, name, *args):
        self.calls.append((name, args))
        if name == 'dscache.get_uncached_user':
            return {'pw_dir': '/root'}
        if name in {'datastore.update', 'service.restart'}:
            return True
        raise AssertionError(f'unexpected middleware call {name!r}')


def rsync_task(**overrides):
    task = {
        'id': 1,
        'path': '/mnt/tank/source',
        'user': 'root',
        'remotehost': '127.0.0.1',
        'remoteport': 22,
        'mode': 'SSH',
        'remotemodule': '',
        'remotepath': '/mnt/tank/target',
        'direction': 'PUSH',
        'desc': 'partial update test',
        'schedule': {'minute': '00', 'hour': '*', 'dom': '*', 'month': '*', 'dow': '*'},
        'recursive': True,
        'times': True,
        'compress': False,
        'archive': False,
        'delete': False,
        'quiet': False,
        'preserveperm': False,
        'preserveattr': False,
        'delayupdates': False,
        'extra': [],
        'enabled': True,
        'locked': False,
        'job': None,
    }
    task.update(overrides)
    return task


def key_files(pattern):
    return [] if pattern.endswith('pub') else ['/root/.ssh/id_rsa']


@pytest.mark.asyncio
async def test_partial_update_does_not_require_transient_validate_rpath():
    middleware = Middleware()
    service = rsync.RsyncTaskService(middleware)
    service.query = AsyncMock(return_value=rsync_task())
    service.get_instance = AsyncMock(return_value={'id': 1, 'quiet': True})
    service.validate_path_field = AsyncMock()

    with (
        patch.object(rsync.glob, 'glob', side_effect=key_files),
        patch.object(rsync.os, 'stat', return_value=Mock(st_mode=0o600)),
        patch.object(rsync.asyncssh, 'connect') as connect,
    ):
        # Schema patches are resolved by the middleware plugin loader. Invoke
        # the implementation directly in this isolated service unit test.
        result = await service.do_update.wraps(service, 1, {'extra': [], 'quiet': True})

    assert result == {'id': 1, 'quiet': True}
    connect.assert_not_called()
    datastore_updates = [args for name, args in middleware.calls if name == 'datastore.update']
    assert len(datastore_updates) == 1
    assert datastore_updates[0][2]['quiet'] is True
    assert 'validate_rpath' not in datastore_updates[0][2]


@pytest.mark.asyncio
async def test_explicit_validate_rpath_still_checks_remote_path():
    middleware = Middleware()
    service = rsync.RsyncTaskService(middleware)
    service.validate_path_field = AsyncMock()
    connection = Mock()
    connection.__aenter__ = AsyncMock(return_value=connection)
    connection.__aexit__ = AsyncMock(return_value=None)
    connection.run = AsyncMock()
    connect = AsyncMock(return_value=connection)
    task = rsync_task(validate_rpath=True)
    task.pop('job')
    task.pop('locked')

    with (
        patch.object(rsync.glob, 'glob', side_effect=key_files),
        patch.object(rsync.os, 'stat', return_value=Mock(st_mode=0o600)),
        patch.object(rsync.asyncssh, 'connect', connect),
    ):
        verrors, validated = await service.validate_rsync_task(task, 'rsync_task_update')

    assert not verrors
    connect.assert_awaited_once()
    connection.run.assert_awaited_once_with('test -d /mnt/tank/target', check=True)
    assert 'validate_rpath' not in validated


@pytest.mark.asyncio
async def test_explicit_false_validate_rpath_skips_remote_path_check():
    middleware = Middleware()
    service = rsync.RsyncTaskService(middleware)
    service.validate_path_field = AsyncMock()
    task = rsync_task(validate_rpath=False)
    task.pop('job')
    task.pop('locked')

    with (
        patch.object(rsync.glob, 'glob', side_effect=key_files),
        patch.object(rsync.os, 'stat', return_value=Mock(st_mode=0o600)),
        patch.object(rsync.asyncssh, 'connect') as connect,
    ):
        verrors, validated = await service.validate_rsync_task(task, 'rsync_task_update')

    assert not verrors
    connect.assert_not_called()
    assert 'validate_rpath' not in validated
