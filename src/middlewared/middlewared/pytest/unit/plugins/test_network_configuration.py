from unittest.mock import AsyncMock, call, Mock, patch

import pytest

from middlewared.plugins.network import dhcp_gateway_from_leases, NetworkConfigurationService
from middlewared.pytest.unit.middleware import Middleware
from middlewared.service import CallError


def test_dhcp_gateway_uses_the_newest_lease_only():
    leases = '''
lease {
  option routers 192.0.2.1;
}
lease {
  option routers 192.0.2.254, 192.0.2.253;
}
'''

    assert dhcp_gateway_from_leases(leases) == '192.0.2.254'


def test_dhcp_gateway_does_not_reuse_a_stale_router():
    leases = '''
lease {
  option routers 192.0.2.1;
}
lease {
  option domain-name-servers 192.0.2.53;
}
'''

    assert dhcp_gateway_from_leases(leases) is None


@pytest.mark.asyncio
async def test_reacquire_dhcp_gateway_accepts_a_valid_router():
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[{
        'int_interface': 'vtnet0',
        'int_dhcp': True,
    }])
    middleware['interface.dhclient_rebind'] = AsyncMock(return_value=True)
    middleware['interface.dhclient_leases'] = AsyncMock(return_value='option routers 192.0.2.1;')

    assert await NetworkConfigurationService(middleware)._reacquire_dhcp_gateway() is True
    middleware['interface.dhclient_rebind'].assert_awaited_once_with('vtnet0')


@pytest.mark.asyncio
async def test_reacquire_dhcp_gateway_rejects_a_lease_without_a_router():
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[{
        'int_interface': 'vtnet0',
        'int_dhcp': True,
    }])
    middleware['interface.dhclient_rebind'] = AsyncMock(return_value=True)
    middleware['interface.dhclient_leases'] = AsyncMock(return_value='fixed-address 192.0.2.10;')

    with pytest.raises(CallError, match='did not supply'):
        await NetworkConfigurationService(middleware)._reacquire_dhcp_gateway()


@pytest.mark.asyncio
async def test_reacquire_dhcp_gateway_handles_empty_interface_database():
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[])
    middleware['interface.dhclient_rebind'] = AsyncMock(side_effect=[True, False])
    middleware['interface.dhclient_leases'] = AsyncMock(return_value='option routers 192.0.2.1;')

    with patch('middlewared.plugins.network.netif', Mock(list_interfaces=Mock(return_value={
        'vtnet0': object(),
        'vtnet1': object(),
        'lo0': object(),
        'bridge0': object(),
    }))):
        assert await NetworkConfigurationService(middleware)._reacquire_dhcp_gateway() is True

    assert middleware['interface.dhclient_rebind'].await_args_list == [
        call('vtnet0'),
        call('vtnet1'),
    ]


def network_config(ipv4gateway):
    return {
        'id': 1,
        'hostname': 'freecore',
        'hostname_b': None,
        'hostname_virtual': None,
        'domain': 'local',
        'domains': [],
        'service_announcement': {'mdns': True, 'netbios': False, 'wsd': True},
        'ipv4gateway': ipv4gateway,
        'ipv6gateway': '',
        'nameserver1': '',
        'nameserver2': '',
        'nameserver3': '',
        'httpproxy': '',
        'netwait_enabled': False,
        'netwait_ip': [],
        'hosts': '',
    }


def event_mock(events, name, result=None):
    async def event(*args):
        events.append((name, args))
        return result

    return AsyncMock(side_effect=event)


def configuration_service(events, old_gateway='192.0.2.1', new_gateway=''):
    middleware = Middleware()
    service = NetworkConfigurationService(middleware)
    old = network_config(old_gateway)
    new = network_config(new_gateway)

    service.config = AsyncMock(side_effect=[old, new])
    service.validate_general_settings = AsyncMock(return_value=type('VErrors', (), {'check': lambda self: None})())
    service.propagate_changes_to_remote = AsyncMock()

    middleware['failover.node'] = event_mock(events, 'failover.node', 'MANUAL')
    middleware['datastore.update'] = event_mock(events, 'datastore.update')
    middleware['failover.licensed'] = event_mock(events, 'failover.licensed', False)
    middleware['kerberos.keytab.has_nfs_principal'] = event_mock(
        events, 'kerberos.keytab.has_nfs_principal', False,
    )
    middleware['etc.generate'] = event_mock(events, 'etc.generate')
    middleware['route.sync'] = event_mock(events, 'route.sync')
    middleware['dns.sync'] = event_mock(events, 'dns.sync')
    middleware['service.restart'] = event_mock(events, 'service.restart')

    return service, middleware


@pytest.mark.asyncio
async def test_clearing_gateway_reacquires_dhcp_before_route_sync():
    events = []
    service, middleware = configuration_service(events)
    service._reacquire_dhcp_gateway = event_mock(events, 'reacquire', True)

    result = await service.do_update({'ipv4gateway': ''})

    assert result['ipv4gateway'] == ''
    names = [name for name, _ in events]
    assert names.index('datastore.update') < names.index('etc.generate')
    assert names.index('etc.generate') < names.index('reacquire')
    assert names.index('reacquire') < names.index('route.sync')
    middleware['dns.sync'].assert_awaited_once_with()
    middleware['service.restart'].assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_gateway_reacquire_restores_explicit_route():
    events = []
    service, middleware = configuration_service(events)
    service._reacquire_dhcp_gateway = AsyncMock(
        side_effect=CallError('DHCP did not supply an IPv4 gateway after the client was rebound')
    )

    with pytest.raises(CallError, match='did not supply'):
        await service.do_update({'ipv4gateway': ''})

    assert middleware['datastore.update'].await_args_list[-1] == call(
        'network.globalconfiguration', 1, {'ipv4gateway': '192.0.2.1'}, {'prefix': 'gc_'},
    )
    names = [name for name, _ in events]
    assert names[-3:] == ['datastore.update', 'etc.generate', 'route.sync']
    middleware['service.restart'].assert_not_awaited()


@pytest.mark.asyncio
async def test_setting_an_explicit_gateway_does_not_rebind_dhcp():
    events = []
    service, middleware = configuration_service(events, old_gateway='', new_gateway='192.0.2.1')
    service._reacquire_dhcp_gateway = AsyncMock()

    await service.do_update({'ipv4gateway': '192.0.2.1'})

    service._reacquire_dhcp_gateway.assert_not_awaited()
    middleware['service.restart'].assert_awaited_once_with('routing', {'ha_propagate': False})
