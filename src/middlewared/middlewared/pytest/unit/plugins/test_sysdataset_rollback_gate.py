# the internal development record: moving the system dataset while the 13.3 return is open destroys the snapshots that return
# restores (migrate() runs `zfs destroy -r <old pool>/.system`), so an explicit move must be confirmed.
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.sysdataset import SystemDatasetService
from middlewared.service_exception import CallError

CONFIG = {'id': 1, 'pool': 'tank', 'syslog': False, 'path': '/var/db/system', 'basename': 'tank/.system',
          'uuid_a': 'x', 'is_decrypted': True}


def make(available):
    calls = []

    async def call(method, *args):
        calls.append(method)
        return {
            'system.ready': True,
            'activedirectory.get_state': 'DISABLED',
            'boot.pool_name': 'boot-pool',
            'system.rollback.available': {'available': available, 'reason': None if available else 'no_window'},
            'system.rollback.config': {'origin_be': '13.3-U1.2'},
            'pool.query': [{'name': 'tank', 'encrypt': 0}],
            'pool.dataset.query': [],
        }.get(method)

    service = SystemDatasetService(Mock(call=AsyncMock(side_effect=call)))
    service.config = AsyncMock(return_value=dict(CONFIG))
    service.migrate = AsyncMock()
    service.setup = AsyncMock()
    return service, calls


async def update(service, data):
    return await SystemDatasetService.do_update.wraps(service, Mock(), data)


@pytest.mark.asyncio
async def test_an_explicit_move_while_the_return_is_open_is_refused():
    service, calls = make(available=True)
    with pytest.raises(CallError, match=r"boot environment '13.3-U1.2'.*confirm_rollback_loss"):
        await update(service, {'pool': 'boot-pool'})
    service.migrate.assert_not_awaited()
    assert 'datastore.update' not in calls


@pytest.mark.asyncio
async def test_a_confirmed_move_proceeds():
    service, calls = make(available=True)
    # the row as stored: the new pool once datastore.update has written it
    service.config.side_effect = lambda: dict(CONFIG, pool='boot-pool' if 'datastore.update' in calls else 'tank')
    await update(service, {'pool': 'boot-pool', 'confirm_rollback_loss': True})
    service.migrate.assert_awaited_once_with('tank', 'boot-pool')
    assert 'datastore.update' in calls


@pytest.mark.asyncio
@pytest.mark.parametrize('data,available', [
    ({'pool': 'boot-pool'}, False),                    # no open return: nothing to lose
    ({'pool': 'tank'}, True),                          # not a move
    ({'syslog': True}, True),                          # not a move
    ({'pool': None, 'pool_exclude': 'tank'}, True),    # the automatic relocation on export/lock keeps its behaviour
])
async def test_other_updates_do_not_ask_about_the_return(data, available):
    service, calls = make(available=available)
    await update(service, data)
    if data.get('pool') is None or data.get('pool') == 'tank':
        assert 'system.rollback.available' not in calls
