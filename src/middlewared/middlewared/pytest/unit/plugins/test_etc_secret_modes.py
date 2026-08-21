# Generated files that carry a key are written 0600 (DEFAULT_ETC_PERMS is 0644).
import pytest

from middlewared.plugins.etc import EtcService


@pytest.mark.parametrize('group,path', [
    ('openvpn_server', 'local/openvpn/server/openvpn_server.conf'),   # the internal development record: tls-crypt key inline
    ('openvpn_client', 'local/openvpn/client/openvpn_client.conf'),   # the internal development record
    ('wireguard', 'local/wireguard/wg1.conf'),
    ('wireguard_client', 'local/wireguard/wg2.conf'),
])
def test_files_with_keys_are_private(group, path):
    entries = [entry for entry in EtcService.GROUPS[group] if entry['path'] == path]
    assert entries and entries[0]['mode'] == 0o600
