"""The web terminal's `application` target (the internal development record): a shell
inside a running application's container, by application name."""
import errno
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins import webterminal
from middlewared.service_exception import CallError


def service_with_middleware(records):
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=lambda method, *args: {
        'applications.query': records,
        'applications.config': {'pool': 'tank'},
    }[method])
    service = webterminal.WebTerminalService(middleware)
    service.config = AsyncMock(return_value={'enabled': False})
    return service, middleware


def test_target_treats_application_as_one_more_exclusive_target():
    assert webterminal._target({'application': 'sabnzbd'}) == 'application'
    assert webterminal._target({'application': 'sabnzbd', 'jail': None, 'vm_id': None}) == 'application'
    with pytest.raises(CallError, match='application name is required'):
        webterminal._target({'application': '  '})
    with pytest.raises(CallError, match='Only one option'):
        webterminal._target({'application': 'sabnzbd', 'jail': 'ioc'})
    with pytest.raises(CallError, match='Only one option'):
        webterminal._target({'application': 'sabnzbd', 'processes': True})
    # Untouched: the pre-existing targets and the root shell default.
    assert webterminal._target({'jail': 'ioc'}) == 'jail'
    assert webterminal._target({'vm_id': 0}) == 'vm'
    assert webterminal._target({}) == 'shell'


def test_application_command_names_the_container_and_carries_the_runtime_environment():
    command = webterminal._application_command('tank', 'sabnzbd')
    assert command == [
        '/usr/bin/env',
        'CONTAINERS_CONF_OVERRIDE=/mnt/tank/applications/config/containers.conf',
        'CONTAINERS_STORAGE_CONF=/mnt/tank/applications/config/storage.conf',
        '/usr/local/bin/podman', 'exec', '-it', 'freecore-app-sabnzbd', '/bin/sh',
    ]
    for name in ('', '-rm', 'Sab', 'a' * 64, 'x y'):
        with pytest.raises(CallError):
            webterminal._application_command('tank', name)


@pytest.mark.asyncio
async def test_ticket_for_an_application_requires_it_to_exist_and_run():
    app = SimpleNamespace(request=SimpleNamespace(remote='192.0.2.1', headers={}))
    service, middleware = service_with_middleware([{'name': 'sabnzbd', 'running': True}])

    ticket = await webterminal.WebTerminalService.get_ticket.wraps(service, app, {'application': 'sabnzbd'})

    middleware.call.assert_awaited_once_with('applications.query', [('name', '=', 'sabnzbd')])
    minted = webterminal.WebTerminalService.pop_ticket(ticket, '192.0.2.1')
    assert minted['target'] == 'application'
    assert minted['options']['application'] == 'sabnzbd'
    # Not gated by the root-shell toggle: the page already manages the application.
    service.config.assert_not_awaited()

    service, _ = service_with_middleware([{'name': 'sabnzbd', 'running': False}])
    with pytest.raises(CallError, match='is not running'):
        await webterminal.WebTerminalService.get_ticket.wraps(service, app, {'application': 'sabnzbd'})

    service, _ = service_with_middleware([])
    with pytest.raises(CallError) as error:
        await webterminal.WebTerminalService.get_ticket.wraps(service, app, {'application': 'gone'})
    assert error.value.errno == errno.ENOENT


@pytest.mark.asyncio
async def test_resolve_command_reads_the_pool_at_connect_time():
    middleware = Mock()
    middleware.call = AsyncMock(return_value={'pool': 'fast'})
    application = webterminal.ShellApplication2(middleware)

    command = await application._resolve_command('application', {'application': 'radarr'}, '192.0.2.1')

    middleware.call.assert_awaited_once_with('applications.config')
    assert command[-4:] == ['exec', '-it', 'freecore-app-radarr', '/bin/sh']
    assert 'CONTAINERS_STORAGE_CONF=/mnt/fast/applications/config/storage.conf' in command

    middleware.call = AsyncMock(return_value={'pool': None})
    with pytest.raises(CallError, match='not configured'):
        await application._resolve_command('application', {'application': 'radarr'}, '192.0.2.1')

    # The other targets never touch the middleware.
    middleware.call = AsyncMock(side_effect=AssertionError('no call expected'))
    assert await application._resolve_command('jail', {'jail': 'ioc'}, None) == [
        '/usr/local/bin/iocage', 'console', '-f', 'ioc',
    ]
