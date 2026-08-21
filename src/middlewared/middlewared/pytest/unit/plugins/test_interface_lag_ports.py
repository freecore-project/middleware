import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock

# Avoid importing platform-specific netif bindings on non-FreeBSD unit-test hosts.
netif_module = types.ModuleType('middlewared.plugins.interface.netif')
netif_module.netif = SimpleNamespace()
sys.modules.setdefault('middlewared.plugins.interface.netif', netif_module)

from middlewared.plugins.interface.type_base import InterfaceType
from middlewared.plugins.network import InterfaceService
from middlewared.utils import filter_list

CONFIG = {
    'id': 1,
    'int_interface': 'lagg0',
    'int_dhcp': False,
    'int_ipv4address': '',
    'int_ipv6auto': False,
    'int_ipv6address': '',
    'int_name': '',
    'int_options': '',
    'int_mtu': None,
    'int_disable_offload_capabilities': False,
}

# Rows in the order SQLite returns them without ORDER BY (rowid order). Their
# lagg_ordernum puts igb1 first, as happens when members were reordered without
# being re-inserted (the legacy UI let lagg_ordernum be edited in place).
LAGG_MEMBERS = [
    {'id': 1, 'interfacegroup': 1, 'ordernum': 1, 'physnic': 'igb0'},
    {'id': 2, 'interfacegroup': 1, 'ordernum': 0, 'physnic': 'igb1'},
]


def test_lag_ports_follow_lagg_ordernum():
    def datastore_query(name, filters=None, options=None):
        if name == 'network.lagginterface':
            return [{'id': 1, 'protocol': 'failover'}]
        if name == 'network.lagginterfacemembers':
            return filter_list(LAGG_MEMBERS, filters, options)
        if name == 'network.alias':
            return []
        raise AssertionError(name)

    calls = {
        'interface.type': Mock(return_value=InterfaceType.LINK_AGGREGATION),
        'datastore.query': datastore_query,
    }
    middleware = Mock()
    middleware.call_sync = Mock(side_effect=lambda method, *args: calls[method](*args))

    iface = InterfaceService(middleware).iface_extend({'name': 'lagg0'}, {'lagg0': CONFIG}, True)

    assert iface['lag_protocol'] == 'FAILOVER'
    assert iface['lag_ports'] == ['igb1', 'igb0']
