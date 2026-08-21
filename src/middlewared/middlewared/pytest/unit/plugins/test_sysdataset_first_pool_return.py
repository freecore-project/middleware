# the internal development record: a 13.3 box enrolled with no data pool keeps its system dataset on the boot pool, with an
# empty sys_pool in the database. When the first data pool is created or imported, setup() places the system dataset
# on it -- but while the return to TrueNAS CORE 13.3 is open, that move is what the internal development record refuses (it destroys
# the snapshots the return restores). setup() must then leave it on the boot pool, not raise.
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.sysdataset import SystemDatasetService

# config() as seen on such a box: the boot pool's .system; is_decrypted False ends setup() right after the placement
# step, so nothing below it (datasets, mounts) runs in the test.
BOOT = {'id': 1, 'pool': 'boot-pool', 'basename': 'boot-pool/.system', 'path': '/var/db/system', 'uuid': 'x',
        'syslog': False, 'is_decrypted': False}


def make(available):
    calls = []
    update_job = Mock(wait=AsyncMock(), error=None)

    async def call(method, *args):
        calls.append((method, args))
        if method == 'system.rollback.available':
            if isinstance(available, Exception):
                raise available
            return {'available': available, 'reason': None if available else 'no_window'}
        return {
            'boot.pool_name': 'boot-pool',
            'failover.licensed': False,
            'datastore.config': {'id': 1, 'pool': ''},
            'pool.query': [{'name': 'tank', 'encrypt': 0, 'is_decrypted': True}],
            'pool.dataset.query': [],
            'systemdataset.update': update_job,
        }.get(method)

    service = SystemDatasetService(Mock(call=AsyncMock(side_effect=call)))
    service.config = AsyncMock(return_value=dict(BOOT))
    return service, calls


async def setup(service):
    with patch('middlewared.plugins.sysdataset.run', AsyncMock()):
        return await service.setup(True)


def updates(calls):
    return [args for method, args in calls if method == 'systemdataset.update']


@pytest.mark.asyncio
async def test_first_pool_while_the_return_is_open_keeps_the_boot_pool():
    service, calls = make(available=True)
    await setup(service)  # must not raise: pool.create/import and every boot used to fail here
    assert updates(calls) == []
    assert ('system.rollback.available', ()) in calls


@pytest.mark.asyncio
async def test_first_pool_without_a_return_is_placed_as_on_13_3():
    service, calls = make(available=False)
    await setup(service)
    assert updates(calls) == [({'pool': 'tank'},)]


@pytest.mark.asyncio
async def test_a_failed_return_check_keeps_the_boot_pool():
    service, calls = make(available=RuntimeError('rollback state unreadable'))
    await setup(service)
    assert updates(calls) == []
