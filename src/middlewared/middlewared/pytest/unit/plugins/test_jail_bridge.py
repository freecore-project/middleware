import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

# These tests exercise only the command-backed jail bridge helpers.  Avoid
# importing platform-specific netif bindings on non-FreeBSD unit-test hosts.
netif_module = types.ModuleType('middlewared.plugins.interface.netif')
netif_module.netif = SimpleNamespace()
sys.modules.setdefault('middlewared.plugins.interface.netif', netif_module)

from middlewared.plugins.network import InterfaceService
from middlewared.service_exception import CallError


def result(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def service():
    middleware = Mock()
    middleware.call = AsyncMock()
    return InterfaceService(middleware)


class RuntimeInterface:
    def __init__(self, name):
        self.name = name
        self.members = []
        self.cloned = True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'name,expected_unconfigure',
    [('cni-podman0', False), ('cni-unmanaged0', True)],
)
async def test_network_sync_preserves_only_the_exact_empty_podman_bridge(
    name, expected_unconfigure,
):
    middleware = Mock()
    unconfigured = []

    async def call_middleware(method, *args):
        if method in {'interface.query', 'datastore.query'}:
            return []
        if method == 'failover.internal_interfaces':
            return []
        if method == 'interface.unconfigure':
            unconfigured.append(args[0].name)
            return None
        if method in {'dns.sync', 'route.sync'}:
            return None
        raise AssertionError((method, args))

    middleware.call = AsyncMock(side_effect=call_middleware)
    middleware.call_hook = AsyncMock()
    middleware.run_in_thread = AsyncMock(side_effect=lambda method, *args: method(*args))
    interface = InterfaceService(middleware)
    runtime_interface = RuntimeInterface(name)

    with patch(
        'middlewared.plugins.network.netif.list_interfaces',
        return_value={name: runtime_interface},
        create=True,
    ):
        await interface.sync()

    assert unconfigured == ([name] if expected_unconfigure else [])


@pytest.mark.asyncio
async def test_reserve_literal_bridge0_when_clone_unit_zero_was_renamed_by_cni():
    interface = service()
    responses = [
        result(stdout='cni-podman0\n'),
        result(stdout='bridge0\n'),
        result(stdout='cni-podman0 bridge0\n'),
        result(),
    ]

    with patch('middlewared.plugins.network.run', AsyncMock(side_effect=responses)) as run:
        assert await interface._reserve_jail_bridge('bridge0') == 'bridge0'

    assert run.await_args_list == [
        call('/sbin/ifconfig', '-g', 'bridge', check=False, encoding='utf8'),
        call(
            '/sbin/ifconfig', 'bridge', 'create', 'name', 'bridge0',
            check=False, encoding='utf8',
        ),
        call('/sbin/ifconfig', '-g', 'bridge', check=False, encoding='utf8'),
        call('/sbin/ifconfig', 'bridge0', 'up', check=False, encoding='utf8'),
    ]


@pytest.mark.asyncio
async def test_reserve_bridge_fails_closed_when_a_concurrent_create_wins_the_name():
    interface = service()
    responses = [
        result(stdout='cni-podman0\n'),
        result(returncode=1, stderr='SIOCIFCREATE2: File exists\n'),
    ]

    with (
        patch('middlewared.plugins.network.run', AsyncMock(side_effect=responses)) as run,
        pytest.raises(CallError, match='Unable to create.*bridge0'),
    ):
        await interface._reserve_jail_bridge('bridge0')

    assert run.await_count == 2


@pytest.mark.asyncio
async def test_ensure_jail_bridge_reuses_one_exact_existing_uplink_membership():
    interface = service()
    interface._jail_bridge_names = AsyncMock(
        return_value=['bridge0', 'cni-podman0']
    )

    async def members(name):
        return (
            ['em0', 'e0a_web'] if name == 'bridge0'
            else ['veth0']
        )

    interface._jail_bridge_members = AsyncMock(side_effect=members)

    with patch(
        'middlewared.plugins.network.run', AsyncMock(return_value=result())
    ) as run:
        assert await interface.ensure_jail_bridge('em0', 'bridge0') == 'bridge0'

    assert run.await_args_list == [
        call('/sbin/ifconfig', 'em0', 'up', check=False, encoding='utf8'),
        call('/sbin/ifconfig', 'bridge0', 'up', check=False, encoding='utf8'),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'bridges,members,match',
    [
        (
            ['bridge0'],
            {'bridge0': ['em0', 'em1']},
            'additional host interfaces',
        ),
        (
            ['bridge0', 'bridge1'],
            {'bridge0': ['em0'], 'bridge1': ['em0']},
            'multiple bridges',
        ),
        (
            ['cni-podman0'],
            {'cni-podman0': ['em0']},
            'non-jail bridge',
        ),
    ],
)
async def test_ensure_jail_bridge_refuses_ambiguous_or_foreign_topology(
    bridges, members, match,
):
    interface = service()
    interface._jail_bridge_names = AsyncMock(return_value=bridges)
    interface._jail_bridge_members = AsyncMock(
        side_effect=lambda name: members[name]
    )

    with (
        patch('middlewared.plugins.network.run', AsyncMock()) as run,
        pytest.raises(CallError, match=match),
    ):
        await interface.ensure_jail_bridge('em0')

    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_jail_bridge_adds_only_the_requested_member_and_never_tears_down():
    interface = service()
    interface._jail_bridge_names = AsyncMock(return_value=['bridge0'])
    interface._jail_bridge_members = AsyncMock(side_effect=[
        [],
        [],
        ['em0'],
        ['em0'],
    ])
    interface._reserve_jail_bridge = AsyncMock(return_value='bridge0')

    with patch(
        'middlewared.plugins.network.run', AsyncMock(return_value=result())
    ) as run:
        assert await interface.ensure_jail_bridge('em0') == 'bridge0'

    assert run.await_args_list == [
        call(
            '/sbin/ifconfig', 'bridge0', 'addm', 'em0',
            check=False, encoding='utf8',
        ),
        call('/sbin/ifconfig', 'em0', 'up', check=False, encoding='utf8'),
        call('/sbin/ifconfig', 'bridge0', 'up', check=False, encoding='utf8'),
    ]
    assert all('destroy' not in invocation.args for invocation in run.await_args_list)


@pytest.mark.asyncio
async def test_ensure_jail_bridge_uses_bridge1_when_bridge0_has_another_uplink():
    interface = service()
    interface._jail_bridge_names = AsyncMock(return_value=['bridge0'])
    interface._jail_bridge_members = AsyncMock(side_effect=[
        ['em0', 'e0a_web'],
        [],
        ['em1'],
        ['em1'],
    ])
    interface._reserve_jail_bridge = AsyncMock(return_value='bridge1')

    with patch(
        'middlewared.plugins.network.run', AsyncMock(return_value=result())
    ) as run:
        assert await interface.ensure_jail_bridge('em1') == 'bridge1'

    interface._reserve_jail_bridge.assert_awaited_once_with('bridge1')
    assert run.await_args_list == [
        call(
            '/sbin/ifconfig', 'bridge1', 'addm', 'em1',
            check=False, encoding='utf8',
        ),
        call('/sbin/ifconfig', 'em1', 'up', check=False, encoding='utf8'),
        call('/sbin/ifconfig', 'bridge1', 'up', check=False, encoding='utf8'),
    ]


@pytest.mark.asyncio
async def test_ensure_jail_bridge_fails_when_both_reserved_bridges_have_uplinks():
    interface = service()
    interface._jail_bridge_names = AsyncMock(return_value=['bridge0', 'bridge1'])
    interface._jail_bridge_members = AsyncMock(side_effect=[['em0'], ['em2']])
    interface._reserve_jail_bridge = AsyncMock()

    with (
        patch('middlewared.plugins.network.run', AsyncMock()) as run,
        pytest.raises(CallError, match='No unassigned jail bridge'),
    ):
        await interface.ensure_jail_bridge('em1')

    interface._reserve_jail_bridge.assert_not_awaited()
    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_jail_bridge_refuses_a_different_persisted_bridge():
    interface = service()
    interface._jail_bridge_names = AsyncMock(return_value=['bridge1'])
    interface._jail_bridge_members = AsyncMock(return_value=['em0'])

    with pytest.raises(CallError, match='moved from jail bridge'):
        await interface.ensure_jail_bridge('em0', 'bridge0')
