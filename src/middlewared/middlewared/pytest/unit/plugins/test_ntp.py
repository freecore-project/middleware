import sys
import types
from unittest.mock import AsyncMock, Mock, patch

import pytest

try:
    import ntplib  # noqa: F401
except ModuleNotFoundError:
    # Every probe here is mocked; ntplib is only needed for the import.
    sys.modules['ntplib'] = types.ModuleType('ntplib')

from middlewared.plugins.ntp import NTPServerService
from middlewared.service_exception import ValidationErrors


# `force` saves a server that does not answer right now. The reachability probe waits for the NTP timeout on such a
# server, so a forced save must not run it at all instead of running it and then ignoring the result.

OLD = {'id': 1, 'address': 'ntp.example.com', 'burst': False, 'iburst': True, 'prefer': False, 'minpoll': 6,
       'maxpoll': 10}


def service():
    middleware = Mock()
    calls = {
        'datastore.insert': AsyncMock(return_value=1),
        'datastore.update': AsyncMock(),
        'service.restart': AsyncMock(),
    }

    async def call(method, *args):
        return await calls[method](*args)

    middleware.call = AsyncMock(side_effect=call)
    middleware.run_in_thread = AsyncMock(side_effect=lambda method, *args: method(*args))
    svc = NTPServerService(middleware)
    svc._get_instance = AsyncMock(return_value=OLD.copy())
    return svc, calls


@pytest.mark.asyncio
async def test_forced_create_does_not_probe_the_server():
    svc, calls = service()
    with patch.object(NTPServerService, 'test_ntp_server', Mock(return_value=False)) as probe:
        result = await svc.do_create({'address': '192.0.2.1', 'force': True})
    probe.assert_not_called()
    assert result == {'id': 1, 'address': '192.0.2.1', 'burst': False, 'iburst': True, 'prefer': False,
                      'minpoll': 6, 'maxpoll': 10}
    calls['datastore.insert'].assert_awaited_once()


@pytest.mark.asyncio
async def test_forced_update_does_not_probe_the_server():
    svc, calls = service()
    with patch.object(NTPServerService, 'test_ntp_server', Mock(return_value=False)) as probe:
        # do_update's Patch schema is resolved only when middleware starts, so call the undecorated method.
        result = await NTPServerService.do_update.wraps(svc, 1, {'address': '192.0.2.1', 'force': True})
    probe.assert_not_called()
    assert result == {**OLD, 'address': '192.0.2.1'}
    calls['datastore.update'].assert_awaited_once()


@pytest.mark.asyncio
async def test_unforced_create_of_an_unreachable_server_is_refused():
    svc, calls = service()
    with patch.object(NTPServerService, 'test_ntp_server', Mock(return_value=False)) as probe:
        with pytest.raises(ValidationErrors) as ve:
            await svc.do_create({'address': '192.0.2.1'})
    probe.assert_called_once_with('192.0.2.1')
    assert [e.attribute for e in ve.value.errors] == ['ntpserver_create.address']
    calls['datastore.insert'].assert_not_awaited()


@pytest.mark.asyncio
async def test_unforced_create_of_a_reachable_server_is_saved():
    svc, calls = service()
    with patch.object(NTPServerService, 'test_ntp_server', Mock(return_value=True)) as probe:
        await svc.do_create({'address': 'ntp.example.com', 'force': False})
    probe.assert_called_once_with('ntp.example.com')
    calls['datastore.insert'].assert_awaited_once()


@pytest.mark.asyncio
async def test_forced_create_still_checks_the_poll_interval():
    svc, calls = service()
    with patch.object(NTPServerService, 'test_ntp_server', Mock(return_value=False)) as probe:
        with pytest.raises(ValidationErrors) as ve:
            await svc.do_create({'address': '192.0.2.1', 'minpoll': 10, 'maxpoll': 6, 'force': True})
    probe.assert_not_called()
    assert [e.attribute for e in ve.value.errors] == ['ntpserver_create.maxpoll']
    calls['datastore.insert'].assert_not_awaited()
