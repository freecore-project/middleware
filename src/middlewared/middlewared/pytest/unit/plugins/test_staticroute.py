from unittest.mock import AsyncMock, call, Mock, patch

import pytest

from middlewared.plugins import network
from middlewared.plugins.network import StaticRouteService
from middlewared.pytest.unit.middleware import Middleware


# do_update's Patch schema is resolved only when middleware starts, so the tests call the undecorated method.
# A static route change applies that one kernel route instead of restarting routing: a routing restart flushes the
# table, and a default route a DHCP lease installed is not put back, so the system dropped off every other network.

def service(old=None):
    middleware = Middleware()
    middleware['datastore.insert'] = AsyncMock(return_value=1)
    middleware['datastore.update'] = AsyncMock()
    middleware['etc.generate'] = AsyncMock()
    middleware['service.restart'] = AsyncMock()
    svc = StaticRouteService(middleware)
    svc._get_instance = AsyncMock(return_value=old or {})
    return svc, middleware


def ok():
    return AsyncMock(return_value=Mock(returncode=0, stderr=''))


@pytest.mark.asyncio
async def test_create_adds_only_the_new_route():
    svc, middleware = service()
    with patch.object(network, 'run', ok()) as run:
        await svc.do_create({'destination': '192.168.200.0/24', 'gateway': '192.0.2.1', 'description': 'Lab'})
    middleware['etc.generate'].assert_awaited_once_with('rc')
    middleware['service.restart'].assert_not_awaited()
    run.assert_awaited_once_with(
        'route', '-n', 'add', '-inet', '-net', '192.168.200.0/24', '192.0.2.1', check=False, encoding='utf8', errors='ignore'
    )


@pytest.mark.asyncio
async def test_update_replaces_the_route_when_it_changes():
    old = {'id': 1, 'destination': '192.168.200.0/24', 'gateway': '192.0.2.1', 'description': 'Lab'}
    svc, middleware = service(old)
    with patch.object(network, 'run', ok()) as run:
        await StaticRouteService.do_update.wraps(svc, 1, {'gateway': '192.0.2.2'})
    middleware['service.restart'].assert_not_awaited()
    assert [c.args[2] for c in run.await_args_list] == ['delete', 'add']
    assert run.await_args_list[0].args[-1] == '192.0.2.1'
    assert run.await_args_list[1].args[-1] == '192.0.2.2'


@pytest.mark.asyncio
async def test_update_of_the_description_only_leaves_the_routing_table_alone():
    old = {'id': 1, 'destination': '192.168.200.0/24', 'gateway': '192.0.2.1', 'description': 'Lab'}
    svc, middleware = service(old)
    with patch.object(network, 'run', ok()) as run:
        await StaticRouteService.do_update.wraps(svc, 1, {'description': 'Lab subnet'})
    run.assert_not_awaited()
    middleware['service.restart'].assert_not_awaited()


@pytest.mark.asyncio
async def test_an_ipv6_route_uses_the_inet6_family():
    svc, middleware = service()
    with patch.object(network, 'run', ok()) as run:
        await svc.apply_route({'destination': 'fd00:1::/64', 'gateway': 'fd00::1'})
    assert run.await_args.args[:4] == ('route', '-n', 'add', '-inet6')


@pytest.mark.asyncio
async def test_a_failed_route_is_logged_not_raised():
    svc, middleware = service()
    failing = AsyncMock(return_value=Mock(returncode=1, stderr='route: writing to routing socket: Network is unreachable'))
    with patch.object(network, 'run', failing), patch.object(svc, 'logger') as logger:
        await svc.apply_route({'destination': '192.168.200.0/24', 'gateway': '10.99.0.1'})
    assert 'Network is unreachable' in logger.warning.call_args.args[-1]


# The description is stored and returned as typed (it used to be stored lower-cased and returned upper-cased).

@pytest.mark.asyncio
async def test_the_description_is_kept_as_typed():
    svc, middleware = service()
    with patch.object(network, 'run', ok()):
        await svc.do_create({'destination': '192.168.200.0/24', 'gateway': '192.0.2.1', 'description': 'Lab subnet via the Router'})
    assert middleware['datastore.insert'].await_args.args[1]['description'] == 'Lab subnet via the Router'
    assert not hasattr(svc, 'upper') and not hasattr(svc, 'lower')
    assert getattr(StaticRouteService._config, 'datastore_extend', None) is None
