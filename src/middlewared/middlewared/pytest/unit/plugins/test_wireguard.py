from unittest.mock import AsyncMock

import pytest

from middlewared.plugins.wireguard import WireguardClientService, WireguardService
from middlewared.pytest.unit.middleware import Middleware


@pytest.mark.asyncio
@pytest.mark.parametrize('service_class', [WireguardService, WireguardClientService])
async def test_generate_keys_passes_only_private_key_to_update(service_class):
    service = service_class(Middleware())
    service.generate_keypair = AsyncMock(return_value={
        'private_key': 'fixture-private-key',
        'public_key': 'fixture-public-key',
    })
    service.update = AsyncMock(return_value={'public_key': 'fixture-public-key'})

    assert await service.generate_keys() == {'public_key': 'fixture-public-key'}

    service.update.assert_awaited_once_with({'private_key': 'fixture-private-key'})
