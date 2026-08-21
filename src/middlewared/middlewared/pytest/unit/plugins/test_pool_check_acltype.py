"""the internal development record: an imported pool with acltype=posix (a SCALE/CE pool) raises one alert per pool.

FreeBSD OpenZFS has no POSIX ACL implementation, so every NFSv4 ACL write on such a dataset fails with
ENOTSUP. pool.import_pool asks pool.check_acltype after the mountpoints are reset; the alert names the
subtree roots (local or received source) and the one-line fix.
"""
import sys
import types

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # The off-box harness has no py-libzfs; nothing here enters it. Same guard as test_pool_dataset_delete.py.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.alert.base import AlertClass
from middlewared.plugins.pool import PoolService
from middlewared.service_exception import CallError

# `zfs get -H -r -t filesystem -s local,received -o name,value acltype vknstrt9` on the reporter's CE pool:
# posix set on the root, received on one child, inherited (so absent here) everywhere else.
CE_POOL = 'vknstrt9\tposix\nvknstrt9/fileshare\tposix\nvknstrt9/plexmedia\tnfsv4\n'


def service(zfs_get=None):
    middleware = Mock()
    calls = []

    async def call(method, *args):
        calls.append((method, *args))

    middleware.call = AsyncMock(side_effect=call)
    pool = PoolService(middleware)
    pool.logger = Mock()
    run = AsyncMock(return_value=zfs_get or SimpleNamespace(returncode=0, stdout=CE_POOL, stderr=''))
    return pool, calls, run


async def check(pool, run, name='vknstrt9'):
    with patch('middlewared.plugins.pool.run', run):
        return await pool.check_acltype(name)


@pytest.mark.asyncio
async def test_posix_subtree_roots_raise_one_alert_for_the_pool():
    pool, calls, run = service()

    assert await check(pool, run) == ['vknstrt9', 'vknstrt9/fileshare']

    run.assert_awaited_once()
    assert run.await_args.args == (
        'zfs', 'get', '-H', '-r', '-t', 'filesystem', '-s', 'local,received', '-o', 'name,value', 'acltype', 'vknstrt9',
    )
    assert calls == [('alert.oneshot_create', 'PoolPosixAclType', {
        'pool': 'vknstrt9',
        'datasets': 'vknstrt9, vknstrt9/fileshare',
    })]
    pool.logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_a_pool_without_posix_only_clears_the_alert():
    pool, calls, run = service(SimpleNamespace(returncode=0, stdout='tank\tnfsv4\n', stderr=''))

    assert await check(pool, run, 'tank') == []

    assert calls == [('alert.oneshot_delete', 'PoolPosixAclType', 'tank')]


@pytest.mark.asyncio
async def test_many_datasets_are_named_up_to_ten():
    names = [f'big/d{index:02}' for index in range(12)]
    listing = ''.join(f'{name}\tposix\n' for name in names)
    pool, calls, run = service(SimpleNamespace(returncode=0, stdout=listing, stderr=''))

    assert await check(pool, run, 'big') == names

    assert calls[-1][2]['datasets'] == ', '.join(names[:10]) + ' and 2 more'


@pytest.mark.asyncio
async def test_a_failed_listing_neither_raises_nor_touches_the_alert():
    error = "cannot open 'gone': dataset does not exist"
    pool, calls, run = service(SimpleNamespace(returncode=1, stdout='', stderr=error))

    assert await check(pool, run, 'gone') == []

    assert calls == []
    pool.logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_an_alert_failure_never_reaches_the_import():
    pool, calls, run = service()

    async def no_alerts(method, *args):
        raise CallError('alert service not ready')

    pool.middleware.call.side_effect = no_alerts

    assert await check(pool, run) == ['vknstrt9', 'vknstrt9/fileshare']


@pytest.mark.asyncio
async def test_the_alert_is_one_per_pool_and_names_the_fix():
    klass = AlertClass.class_by_name['PoolPosixAclType']
    instance = klass(Mock())
    args = {'pool': 'vknstrt9', 'datasets': 'vknstrt9'}

    alert = await instance.create(args)
    other = await instance.create({**args, 'pool': 'tank'})

    assert alert.key == 'vknstrt9'
    assert klass.format(args) == (
        'Pool vknstrt9 was imported with acltype=posix on vknstrt9 (a TrueNAS SCALE/CE default). FreeBSD has no '
        'POSIX ACL support, so setting permissions or an ACL on these datasets fails with ENOTSUP. Run '
        '"zfs set acltype=nfsv4 <dataset>" on each and set the permissions again; existing mode bits are kept.'
    )
    assert await instance.delete([alert, other], 'vknstrt9') == [other]
