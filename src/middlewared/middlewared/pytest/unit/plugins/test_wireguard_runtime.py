from copy import deepcopy
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from middlewared.plugins.wireguard_.runtime import peer_status_rows, read_peer_runtime


KEY = 'A' * 43 + '='
PEER = {'id': 1, 'name': 'peer', 'public_key': KEY, 'allowed_ips': ['192.0.2.2/32'],
        'keepalive': None, 'enabled': True, 'preshared_key': 'must-not-escape', 'private_key': 'also-private'}


@pytest.mark.parametrize('handshake,state,age', [(0, 'NEVER_CONNECTED', None), (900, 'RECENT', 100),
                                              (820, 'RECENT', 180), (819, 'STALE', 181), (1100, 'RECENT', 0)])
def test_handshake_and_unsigned_counters(handshake, state, age):
    outputs = [f'{KEY}\t{handshake}\n', f'{KEY}\t[2001:db8::1]:51820\n', f'{KEY}\t0\t4294967297\n']
    with patch('middlewared.plugins.wireguard_.runtime.subprocess.run', side_effect=[
        SimpleNamespace(returncode=0, stdout=x) for x in outputs
    ]) as run, patch('middlewared.plugins.wireguard_.runtime.time.time', return_value=1000):
        value = read_peer_runtime('wg1')[KEY]
    assert value == {'latest_handshake': handshake or None, 'handshake_age': age,
                     'endpoint': '[2001:db8::1]:51820', 'rx_bytes': 0, 'tx_bytes': 4294967297, 'state': state}
    assert [call.args[0] for call in run.call_args_list] == [
        ['wg', 'show', 'wg1', field] for field in ['latest-handshakes', 'endpoints', 'transfer']]


@pytest.mark.parametrize('failure', [FileNotFoundError(), subprocess.TimeoutExpired('wg', 3)])
def test_command_failure_is_unavailable(failure):
    with patch('middlewared.plugins.wireguard_.runtime.subprocess.run', side_effect=failure):
        assert read_peer_runtime('wg1') is None


@pytest.mark.parametrize('result', [SimpleNamespace(returncode=1, stdout=''),
                                   SimpleNamespace(returncode=0, stdout='malformed\n')])
def test_absent_interface_and_malformed_output(result):
    with patch('middlewared.plugins.wireguard_.runtime.subprocess.run', return_value=result):
        assert read_peer_runtime('wg1') is None


def test_no_peers_returns_empty_snapshot():
    with patch('middlewared.plugins.wireguard_.runtime.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='')):
        assert read_peer_runtime('wg1') == {}


@pytest.mark.parametrize('snapshot,enabled,state', [(None, True, 'UNAVAILABLE'), ({}, True, 'NOT_LOADED'),
                                                  ({}, False, 'DISABLED')])
def test_missing_runtime_is_explicit_and_secrets_never_escape(snapshot, enabled, state):
    peer = dict(PEER, enabled=enabled)
    original = deepcopy(peer)
    result = peer_status_rows([peer], snapshot)[0]
    assert result['runtime'] == {'latest_handshake': None, 'handshake_age': None, 'endpoint': None,
                                 'rx_bytes': None, 'tx_bytes': None, 'state': state}
    assert set(result) == {'id', 'name', 'public_key', 'allowed_ips', 'keepalive', 'enabled', 'runtime'}
    assert peer == original


def test_status_join_preserves_configuration_and_uses_public_key():
    runtime = {'latest_handshake': 10, 'handshake_age': 20, 'endpoint': '192.0.2.1:51820',
               'rx_bytes': 12, 'tx_bytes': 34, 'state': 'RECENT'}
    assert peer_status_rows([PEER], {KEY: runtime})[0]['runtime'] == runtime
    assert peer_status_rows([], None) == []
