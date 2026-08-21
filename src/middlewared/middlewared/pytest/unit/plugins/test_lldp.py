from unittest.mock import AsyncMock

import pytest

from middlewared.plugins.lldp import LLDPService
from middlewared.service_exception import ValidationErrors

# The factory database row: no country, so ladvd runs without -c (rc.conf.py lldp_config).
FACTORY = {'id': 1, 'intdesc': True, 'country': '', 'location': ''}


class FakeMiddleware:
    async def call(self, method, *args):
        assert method == 'system.general.country_choices'
        return {'DE': 'Germany', 'US': 'United States'}


def lldp(config):
    service = LLDPService(FakeMiddleware())
    service.config = AsyncMock(return_value=config)
    service._update_service = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_update_that_leaves_the_default_country_alone_is_accepted():
    service = lldp(FACTORY)

    assert await service.do_update({'intdesc': False}) == {**FACTORY, 'intdesc': False}
    service._update_service.assert_awaited_once()


@pytest.mark.asyncio
async def test_country_can_be_cleared():
    service = lldp({**FACTORY, 'country': 'DE'})

    assert (await service.do_update({'country': ''}))['country'] == ''


@pytest.mark.asyncio
async def test_unknown_country_is_still_rejected():
    service = lldp(FACTORY)

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({'country': 'XX'})

    assert [e.attribute for e in ve.value.errors] == ['lldp_update.country']
    service._update_service.assert_not_awaited()
