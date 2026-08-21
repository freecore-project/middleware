from unittest.mock import AsyncMock

import pytest

from middlewared.plugins.iscsi import iSCSITargetService
from middlewared.pytest.unit.middleware import Middleware
from middlewared.service_exception import CallError


def target_service(fibre_channel_enabled):
    middleware = Middleware()
    middleware['system.feature_enabled'] = AsyncMock(return_value=fibre_channel_enabled)
    middleware['iscsi.targetextent.query'] = AsyncMock(return_value=[])
    middleware['datastore.delete'] = AsyncMock(side_effect=[None, True])

    service = iSCSITargetService(middleware)
    service._get_instance = AsyncMock(return_value={'id': 1, 'name': 'test-target'})
    service.active_sessions_for_targets = AsyncMock(return_value=[])
    service._service_change = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_delete_target_does_not_require_removed_fcport_service():
    service = target_service(False)

    assert await service.do_delete(1, False) is True

    service.middleware['system.feature_enabled'].assert_awaited_once_with('FIBRECHANNEL')
    assert 'fcport.query' not in service.middleware
    service.middleware['datastore.delete'].assert_any_await(
        'services.iscsitarget', 1,
    )


@pytest.mark.asyncio
async def test_delete_target_preserves_fcport_in_use_guard_when_feature_enabled():
    service = target_service(True)
    service.middleware['fcport.query'] = AsyncMock(return_value=[{'name': 'isp0'}])

    with pytest.raises(CallError, match=r"Target 1 is in use by isp0 fcport\(s\)\."):
        await service.do_delete(1, False)

    service.middleware['fcport.query'].assert_awaited_once_with([['target', '=', 1]])
    service.middleware['datastore.delete'].assert_not_awaited()
