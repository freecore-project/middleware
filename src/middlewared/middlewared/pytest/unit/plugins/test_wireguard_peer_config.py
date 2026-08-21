# the internal development record: the downloaded peer configuration routes the tunnel network only. FreeCORE neither
# forwards nor NATs tunnel traffic, so the old full-tunnel route left a client with nothing but the NAS.
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.wireguard import WireguardPeerService


@pytest.mark.asyncio
@pytest.mark.parametrize('address,netmask,network', [
    ('10.100.0.1', 24, '10.100.0.0/24'),
    ('10.99.0.1', 16, '10.99.0.0/16'),
    ('fd00:100::1', 64, 'fd00:100::/64'),
])
async def test_the_peer_configuration_is_a_split_tunnel_to_the_nas(address, netmask, network):
    config = {'address': address, 'netmask': netmask, 'endpoint': 'nas.example.org', 'listen_port': 51820,
              'public_key': 'server-public-key', 'dns': None, 'mtu': None}

    async def call(method, *args):
        return config if method == 'wireguard.config' else None

    service = WireguardPeerService(Mock(call=AsyncMock(side_effect=call)))
    service.get_instance = AsyncMock(return_value={'allowed_ips': ['10.100.0.2/32'], 'preshared_key': None,
                                                   'keepalive': 25})

    conf = await service.peer_configuration_generation(1)

    assert f'AllowedIPs = {network}\n' in conf
    assert '0.0.0.0/0' not in conf and '::/0' not in conf
    assert 'Endpoint = nas.example.org:51820\n' in conf
    assert 'PersistentKeepalive = 25\n' in conf
