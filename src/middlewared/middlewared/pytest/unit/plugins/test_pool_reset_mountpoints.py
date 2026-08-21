"""the internal development record: an imported pool's mountpoints are reset deepest dataset first.

A XigmaNAS pool has its root at /mnt/<pool> and, with a Bastille tree, datasets with mountpoints of
their own mounted inside an inherited one. `zfs inherit -r` resets the parent first and fails with
EBUSY; reset one by one from the deepest, every unmount is in that step's own change list.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.alert.base import AlertClass
from middlewared.plugins.pool import PoolService
from middlewared.service_exception import CallError

# `zfs get -H -r -t filesystem -s local -o name mountpoint xtank` on the XigmaNAS-shaped pool.
LOCAL = '\n'.join([
    'xtank',
    'xtank/bastille/cache',
    'xtank/bastille/cache/14.4-RELEASE',
    'xtank/bastille/jails',
    'xtank/bastille/logs',
    'xtank/bastille/releases',
    'xtank/bastille/releases/14.4-RELEASE',
    'xtank/bastille/templates',
    'xtank/with space',
]) + '\n'


def service(zfs_get=None, refuse=()):
    middleware = Mock()
    calls = []

    async def call(method, *args):
        calls.append((method, *args))
        if method == 'zfs.dataset.inherit' and args[0] in refuse:
            raise CallError(f"Failed to inherit mountpoint for {args[0]}: cannot unmount '/mnt/mnt/{args[0]}': "
                            'pool or dataset is busy')

    middleware.call = AsyncMock(side_effect=call)
    pool = PoolService(middleware)
    pool.logger = Mock()
    run = AsyncMock(return_value=zfs_get or SimpleNamespace(returncode=0, stdout=LOCAL, stderr=''))
    return pool, calls, run


async def reset(pool, run, name='xtank'):
    with patch('middlewared.plugins.pool.run', run):
        return await pool.reset_mountpoints(name)


@pytest.mark.asyncio
async def test_only_local_mountpoints_are_reset_deepest_first():
    pool, calls, run = service()

    assert await reset(pool, run) == []

    run.assert_awaited_once()
    assert run.await_args.args == (
        'zfs', 'get', '-H', '-r', '-t', 'filesystem', '-s', 'local', '-o', 'name', 'mountpoint', 'xtank',
    )
    inherited = [args[1] for args in calls if args[0] == 'zfs.dataset.inherit']
    assert inherited == [
        'xtank/bastille/cache/14.4-RELEASE',
        'xtank/bastille/releases/14.4-RELEASE',
        'xtank/bastille/cache',
        'xtank/bastille/jails',
        'xtank/bastille/logs',
        'xtank/bastille/releases',
        'xtank/bastille/templates',
        'xtank/with space',
        'xtank',
    ]
    # One dataset at a time, never recursively.
    assert all(args[2:] == ('mountpoint',) for args in calls if args[0] == 'zfs.dataset.inherit')
    assert calls[-1] == ('alert.oneshot_delete', 'PoolMountpointsNotReset', 'xtank')


@pytest.mark.asyncio
async def test_a_pool_with_nothing_local_only_clears_the_alert():
    pool, calls, run = service(SimpleNamespace(returncode=0, stdout='', stderr=''))

    assert await reset(pool, run) == []

    assert calls == [('alert.oneshot_delete', 'PoolMountpointsNotReset', 'xtank')]


@pytest.mark.asyncio
async def test_a_dataset_that_cannot_be_reset_raises_the_alert_and_the_rest_go_on():
    pool, calls, run = service(refuse={'xtank/bastille/jails', 'xtank'})

    assert await reset(pool, run) == ['xtank', 'xtank/bastille/jails']

    inherited = [args[1] for args in calls if args[0] == 'zfs.dataset.inherit']
    assert len(inherited) == 9
    assert calls[-1] == ('alert.oneshot_create', 'PoolMountpointsNotReset', {
        'pool': 'xtank',
        'datasets': 'xtank, xtank/bastille/jails',
        'error': "Failed to inherit mountpoint for xtank: cannot unmount '/mnt/mnt/xtank': pool or dataset is busy",
    })
    pool.logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_many_datasets_are_named_up_to_ten():
    names = [f'big/d{index:02}' for index in range(12)]
    pool, calls, run = service(SimpleNamespace(returncode=0, stdout='\n'.join(names), stderr=''), refuse=set(names))

    await reset(pool, run, 'big')

    assert calls[-1][2]['datasets'] == ', '.join(names[:10]) + ' and 2 more'


@pytest.mark.asyncio
async def test_a_failed_listing_raises_the_alert_without_resetting():
    pool, calls, run = service(SimpleNamespace(returncode=1, stdout='', stderr="cannot open 'gone': dataset does not exist"))

    assert await reset(pool, run, 'gone') == ['gone']

    assert not [args for args in calls if args[0] == 'zfs.dataset.inherit']
    assert calls[-1][0] == 'alert.oneshot_create'
    assert calls[-1][2]['error'] == "cannot open 'gone': dataset does not exist"


@pytest.mark.asyncio
async def test_an_alert_failure_never_reaches_the_import():
    pool, calls, run = service(refuse={'xtank'})
    real_call = pool.middleware.call.side_effect

    async def no_alerts(method, *args):
        if method.startswith('alert.'):
            raise CallError('alert service not ready')
        return await real_call(method, *args)

    pool.middleware.call.side_effect = no_alerts

    assert await reset(pool, run) == ['xtank']


@pytest.mark.asyncio
async def test_the_alert_is_one_per_pool():
    klass = AlertClass.class_by_name['PoolMountpointsNotReset']
    instance = klass(Mock())
    args = {'pool': 'xtank', 'datasets': 'xtank', 'error': 'busy'}

    alert = await instance.create(args)
    other = await instance.create({**args, 'pool': 'ytank'})

    assert alert.key == 'xtank'
    assert klass.format(args) == (
        'Pool xtank was imported, but the mountpoint of xtank could not be reset (busy), so they are not mounted '
        'below /mnt/xtank. Export the pool and import it again once nothing uses them.'
    )
    assert await instance.delete([alert, other], 'xtank') == [other]
