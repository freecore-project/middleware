import asyncio
import textwrap
from unittest.mock import AsyncMock, Mock, call

import pytest

from middlewared.plugins.pool import parse_lsof, PoolDatasetService


@pytest.mark.parametrize("lsof,dirs,result", [
    (
        textwrap.dedent("""\
            p535
            cpython3.7
            f5
            n/usr/lib/data
            p536
            cpython3.7
            f5
            n/dev/zvol/backup/vol1
            p537
            cpython3.7
            f5
            n/dev/zvol/tank/vols/vol1
            p2520
            csmbd
            f9
            n/mnt/tank/blob1
            f31
            n/mnt/backup/blob2
            p97778
            cminio
            f7
            n/mnt/tank/data/blob3
        """),
        ["/mnt/tank", "/dev/zvol/tank"],
        [
            (537, "python3.7"),
            (2520, "smbd"),
            (97778, "minio"),
        ]
    )
])
def test__parse_lsof(lsof, dirs, result):
    assert parse_lsof(lsof, dirs) == result


@pytest.mark.asyncio
async def test_dataset_lock_waits_for_all_attachment_teardown_before_bastille_recovery(monkeypatch):
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.call_hook = AsyncMock()
    service = PoolDatasetService(middleware)
    service.get_instance = AsyncMock(return_value={
        'name': 'tank/bastille',
        'mountpoint': '/mnt/tank/bastille',
        'encrypted': True,
        'locked': False,
        'key_format': {'value': 'PASSPHRASE'},
        'encryption_root': 'tank/bastille',
    })

    failed_delegate = Mock(name='failed_delegate')
    failed_delegate.name = 'failed'
    failed_delegate.query = AsyncMock(return_value=[{'id': 'failed'}])
    failed_delegate.stop = AsyncMock(side_effect=RuntimeError('attachment teardown failed'))

    async def delayed_stop(attachments):
        await asyncio.sleep(0.01)

    bastille_delegate = Mock(name='bastille_delegate')
    bastille_delegate.name = 'bastille'
    bastille_delegate.query = AsyncMock(return_value=[{'id': 'bastille:boot-enabled'}])
    bastille_delegate.stop = AsyncMock(side_effect=delayed_stop)
    monkeypatch.setattr(
        PoolDatasetService,
        'attachment_delegates',
        [failed_delegate, bastille_delegate],
    )

    async def dispatch(name, *args):
        if name == 'systemdataset.config':
            return {'pool': 'boot-pool'}
        if name in {'cache.put', 'cache.pop'}:
            return None
        if name == 'bastille.pool_available':
            return {'matched': True, 'enabled': True}
        if name == 'system.ready':
            return True
        if name == 'service.start':
            return True
        raise AssertionError(name)

    middleware.call.side_effect = dispatch

    with pytest.raises(RuntimeError, match='attachment teardown failed'):
        await service.lock(Mock(), 'tank/bastille', {'force_umount': False})

    bastille_delegate.stop.assert_awaited_once()
    assert call('bastille.pool_available', 'tank') in middleware.call.await_args_list
    assert call('service.start', 'bastille') in middleware.call.await_args_list
    assert call('zfs.dataset.unload_key', 'tank/bastille', {
        'umount': True,
        'force_umount': False,
        'recursive': True,
    }) not in middleware.call.await_args_list


@pytest.mark.asyncio
async def test_dataset_lock_cancellation_recovers_bastille_teardown_intent(monkeypatch):
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.call_hook = AsyncMock()
    service = PoolDatasetService(middleware)
    service.get_instance = AsyncMock(return_value={
        'name': 'tank/bastille',
        'mountpoint': '/mnt/tank/bastille',
        'encrypted': True,
        'locked': False,
        'key_format': {'value': 'PASSPHRASE'},
        'encryption_root': 'tank/bastille',
    })
    stop_started = asyncio.Event()

    async def blocked_stop(attachments):
        stop_started.set()
        await asyncio.Event().wait()

    bastille_delegate = Mock(name='bastille_delegate')
    bastille_delegate.name = 'bastille'
    bastille_delegate.query = AsyncMock(return_value=[{'id': 'bastille:boot-enabled'}])
    bastille_delegate.stop = AsyncMock(side_effect=blocked_stop)
    monkeypatch.setattr(PoolDatasetService, 'attachment_delegates', [bastille_delegate])

    async def dispatch(name, *args):
        if name == 'systemdataset.config':
            return {'pool': 'boot-pool'}
        if name in {'cache.put', 'cache.pop'}:
            return None
        if name == 'bastille.pool_available':
            return {'matched': True, 'enabled': True}
        if name == 'system.ready':
            return True
        if name == 'service.start':
            return True
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    lock = asyncio.create_task(
        service.lock(Mock(), 'tank/bastille', {'force_umount': False})
    )
    await stop_started.wait()
    lock.cancel()
    with pytest.raises(asyncio.CancelledError):
        await lock

    assert call('bastille.pool_available', 'tank') in middleware.call.await_args_list
    assert call('service.start', 'bastille') in middleware.call.await_args_list
