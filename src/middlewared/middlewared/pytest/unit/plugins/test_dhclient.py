import asyncio
from pathlib import Path
import signal
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import etc
from middlewared.plugins.interface import dhclient
from middlewared.pytest.unit.middleware import Middleware
from middlewared.service import CallError


@pytest.mark.asyncio
@pytest.mark.parametrize('wait,expected', [
    (False, ['dhclient', '-b', 'vtnet0']),
    (True, ['dhclient', 'vtnet0']),
])
async def test_freebsd_starts_base_dhclient(wait, expected):
    process = Mock(returncode=0)
    process.communicate = AsyncMock(return_value=(b'',))
    popen = AsyncMock(return_value=process)

    with patch.object(dhclient.osc, 'IS_FREEBSD', True), \
            patch.object(dhclient.osc, 'IS_LINUX', False), \
            patch.object(dhclient, 'Popen', popen):
        await dhclient.InterfaceService(Middleware()).dhclient_start('vtnet0', wait)

    popen.assert_awaited_once_with(
        expected,
        stdout=dhclient.subprocess.PIPE,
        stderr=dhclient.subprocess.STDOUT,
        close_fds=True,
    )


def test_dhclient_reads_the_text_lease_file(tmp_path):
    lease = tmp_path / 'dhclient.leases.vtnet0'
    lease.write_text('lease { fixed-address 192.0.2.10; }')

    with patch.object(dhclient, 'LEASEFILE_TEMPLATE', str(tmp_path / 'dhclient.leases.{}')):
        assert dhclient.InterfaceService(Middleware()).dhclient_leases('vtnet0') == lease.read_text()


def test_freebsd_network_etc_group_renders_dhclient_configuration():
    assert etc.EtcService.GROUPS['network'] == [
        {'type': 'mako', 'path': 'dhclient.conf', 'platform': 'FreeBSD'},
    ]

    etc_files = Path(dhclient.__file__).parents[2] / 'etc_files'
    assert (etc_files / 'dhclient.conf').is_file()
    assert not (etc_files / 'local' / 'dhcpcd.conf').exists()


@pytest.mark.asyncio
async def test_dhclient_rebind_replaces_the_running_client():
    service = dhclient.InterfaceService(Middleware())
    service.dhclient_status = Mock(side_effect=[(True, 123), (False, 123), (True, 456)])
    service.dhclient_start = AsyncMock()

    with patch.object(dhclient.os, 'kill') as kill:
        assert await service.dhclient_rebind('vtnet0') is True

    kill.assert_called_once_with(123, signal.SIGTERM)
    service.dhclient_start.assert_awaited_once_with('vtnet0', wait=True)


@pytest.mark.asyncio
async def test_dhclient_rebind_leaves_an_inactive_interface_alone():
    service = dhclient.InterfaceService(Middleware())
    service.dhclient_status = Mock(return_value=(False, None))
    service.dhclient_start = AsyncMock()

    with patch.object(dhclient.os, 'kill') as kill:
        assert await service.dhclient_rebind('vtnet0') is False

    kill.assert_not_called()
    service.dhclient_start.assert_not_awaited()


@pytest.mark.asyncio
async def test_dhclient_rebind_bounds_the_new_lease_wait():
    service = dhclient.InterfaceService(Middleware())
    service.dhclient_status = Mock(side_effect=[(True, 123), (False, 123)])
    service.dhclient_start = AsyncMock(side_effect=asyncio.TimeoutError)

    with patch.object(dhclient.os, 'kill'), pytest.raises(CallError, match='Timed out starting'):
        await service.dhclient_rebind('vtnet0')
