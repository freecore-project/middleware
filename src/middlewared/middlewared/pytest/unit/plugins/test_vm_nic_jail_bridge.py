"""A VM NIC on iocage's uplink shares the jail bridge instead of stranding DHCP VNET jails (the internal development record).

Off-box: netif is replaced by an in-memory interface table, and interface.ensure_jail_bridge by a
stand-in that does what the real routine does for an uplink that is in no bridge yet.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from middlewared.plugins import vm as vm_module
from middlewared.service_exception import CallError

UP = 'UP'


class FakeInterface:
    def __init__(self, name, members=()):
        self.name = name
        self.members = list(members)
        self.flags = {UP}

    def add_member(self, member):
        self.members.append(member)

    def up(self):
        self.flags.add(UP)


class FakeNetif:
    InterfaceFlags = SimpleNamespace(UP=UP)

    def __init__(self, interfaces, ipv4=None, ipv6=None):
        self.interfaces = {i.name: i for i in interfaces}
        self.ipv4, self.ipv6 = ipv4, ipv6

    def list_interfaces(self):
        return dict(self.interfaces)

    def get_interface(self, name):
        return self.interfaces[name]

    def create_interface(self, kind):
        unit = next(n for n in range(64) if f'{kind}{n}' not in self.interfaces)
        self.interfaces[f'{kind}{unit}'] = FakeInterface(f'{kind}{unit}')
        return f'{kind}{unit}'

    def destroy_interface(self, name):
        del self.interfaces[name]

    def RoutingTable(self):
        route = lambda interface: SimpleNamespace(interface=interface) if interface else None  # noqa: E731
        return SimpleNamespace(default_route_ipv4=route(self.ipv4), default_route_ipv6=route(self.ipv6))


def middleware(fake, error=None):
    def call_sync(method, member, expected_bridge):
        assert method == 'interface.ensure_jail_bridge'
        if error:
            raise error
        bridge = fake.interfaces.setdefault(expected_bridge, FakeInterface(expected_bridge))
        bridge.add_member(member)
        return expected_bridge
    return Mock(call_sync=Mock(side_effect=call_sync))


def nic(attach, mw):
    return vm_module.NIC({
        'id': 9, 'dtype': 'NIC', 'order': 1002,
        'attributes': {'type': 'VIRTIO', 'nic_attach': attach, 'mac': '00:a0:98:11:22:33'},
    }, mw)


@pytest.fixture
def host(monkeypatch):
    def build(*interfaces, ipv4='vtnet0', ipv6=None, error=None):
        fake = FakeNetif(interfaces, ipv4=ipv4, ipv6=ipv6)
        monkeypatch.setattr(vm_module, 'netif', fake)
        return fake, middleware(fake, error)
    return build


def test_iocage_uplink_takes_the_empty_reserved_jail_bridge(host):
    """ly2en's order: Applications reserved bridge0 empty, the VM starts first. 13.3 gave the VM
    bridge0; a DHCP jail started afterwards shares it instead of landing on an uplink-less bridge0."""
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('bridge0'))
    device = nic('vtnet0', mw)
    device.pre_start_vm()
    mw.call_sync.assert_called_once_with('interface.ensure_jail_bridge', 'vtnet0', 'bridge0')
    assert device.bridge == 'bridge0' and not device.bridge_created
    assert fake.interfaces['bridge0'].members == ['vtnet0']
    assert 'bridge1' not in fake.interfaces


def test_the_rollback_leaves_the_claimed_jail_bridge_in_place(host):
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('bridge0'))
    device = nic('vtnet0', mw)
    device.pre_start_vm()
    device.pre_start_vm_rollback()
    assert fake.interfaces['bridge0'].members == ['vtnet0']


def test_ipv6_only_host_resolves_the_uplink_the_way_iocage_does(host):
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('bridge0'), ipv4=None, ipv6='vtnet0')
    device = nic('vtnet0', mw)
    device.pre_start_vm()
    assert device.bridge == 'bridge0'


@pytest.mark.parametrize('attach,default', [('vlan20', 'vtnet0'), ('vtnet0', None)])
def test_any_other_uplink_keeps_a_bridge_of_its_own(host, attach, default):
    """A VM on another network never joins the jail bridge, where iocage would add the LAN uplink
    next to it; without a default route iocage has no uplink to add, so nothing is claimed."""
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('vlan20'), FakeInterface('bridge0'), ipv4=default)
    device = nic(attach, mw)
    device.pre_start_vm()
    mw.call_sync.assert_not_called()
    assert device.bridge == 'bridge1' and device.bridge_created
    assert fake.interfaces['bridge1'].members == [attach] and fake.interfaces['bridge0'].members == []


def test_an_uplink_already_on_a_bridge_stays_there(host):
    """Jail first (or an earlier VM): the existing bridge is reused, unchanged from 13.3."""
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('bridge0'), FakeInterface('bridge1', ['vtnet0', 'vnet0']))
    device = nic('vtnet0', mw)
    device.pre_start_vm()
    mw.call_sync.assert_not_called()
    assert device.bridge == 'bridge1' and not device.bridge_created


def test_a_named_bridge_attachment_is_unchanged(host):
    fake, mw = host(FakeInterface('vtnet0'), FakeInterface('bridge7', ['vtnet0']))
    device = nic('bridge7', mw)
    device.pre_start_vm()
    mw.call_sync.assert_not_called()
    assert device.bridge == 'bridge7'


def test_a_refused_claim_falls_back_to_the_13_3_bridge(host):
    """bridge0 already carries another host interface: the VM still starts, on a new bridge."""
    fake, mw = host(
        FakeInterface('vtnet0'), FakeInterface('bridge0', ['vlan30']),
        error=CallError("Jail bridge 'bridge0' already uses host interface(s): vlan30."),
    )
    device = nic('vtnet0', mw)
    device.pre_start_vm()
    assert device.bridge == 'bridge1' and device.bridge_created
    assert fake.interfaces['bridge1'].members == ['vtnet0']
