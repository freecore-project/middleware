# the internal development record: the loopback root check reads sockstat's JSON output, not its text table.
import json
import socket
from unittest.mock import AsyncMock, Mock, patch

from middlewared.plugins import auth
from middlewared.plugins.auth import sockstat_peer_is_root

PEER = ('127.0.0.1', 51234)


def sockstat(*sockets):
    return json.dumps({'__version': '1', 'sockstat': {'socket': list(sockets)}}).encode()


def row(user, command, local, foreign, proto='tcp4'):
    return {
        'user': user, 'command': command, 'pid': 4242, 'fd': 3, 'proto': proto,
        'local': {'address': local[0], 'port': local[1]},
        'foreign': {'address': foreign[0], 'port': foreign[1]},
    }


SERVER = row(0, 'middlewared', ('127.0.0.1', 6000), PEER)


def test_a_root_client_is_root():
    assert sockstat_peer_is_root(sockstat(row(0, 'midclt', PEER, ('127.0.0.1', 6000)), SERVER), *PEER)


def test_a_non_root_client_is_not_root():
    assert not sockstat_peer_is_root(sockstat(row(1001, 'python3.11', PEER, ('127.0.0.1', 6000)), SERVER), *PEER)


def test_the_servers_own_socket_does_not_count():
    # middlewared's end is root-owned and its foreign end is the peer, but its local end is :6000.
    assert not sockstat_peer_is_root(sockstat(SERVER), *PEER)


def test_the_process_name_cannot_change_the_owner():
    # The text table printed the name raw, so control characters in it could make one row read as
    # two. In JSON the name is one escaped string, and the owner is its own field.
    name = 'x\nroot    sshd'
    out = sockstat(row(1001, name, PEER, ('127.0.0.1', 6000)), SERVER)
    assert b'\\n' in out
    assert not sockstat_peer_is_root(out, *PEER)


def test_an_ipv6_loopback_root_client_is_root():
    peer6 = ('::1', 40000)
    out = sockstat(row(0, 'midclt', peer6, ('::1', 6000), proto='tcp6'))
    assert sockstat_peer_is_root(out, *peer6)


def test_the_port_must_match_exactly():
    assert not sockstat_peer_is_root(sockstat(row(0, 'midclt', ('127.0.0.1', 5123), ('127.0.0.1', 6000))), *PEER)
    assert not sockstat_peer_is_root(sockstat(row(0, 'midclt', ('127.0.0.1', '51234'), ('127.0.0.1', 6000))), *PEER)


def test_only_an_integer_uid_zero_is_root():
    for user in ('root', '0', False, None, 0.0):
        assert not sockstat_peer_is_root(sockstat(row(user, 'midclt', PEER, ('127.0.0.1', 6000))), *PEER), user


def test_unexpected_output_is_not_root():
    text_table = (
        b'USER COMMAND    PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS\n'
        b'root midclt    4242 3  tcp4  127.0.0.1:51234       127.0.0.1:6000\n'
    )
    for out in (b'', b'not json', text_table, b'[]', b'{"sockstat": {}}', b'{"sockstat": {"socket": {}}}',
                b'{"sockstat": {"socket": [1, "x", {"user": 0}]}}'):
        assert not sockstat_peer_is_root(out, *PEER), out


def app_for(peer):
    sock = Mock(family=socket.AF_INET)
    info = {'socket': sock, 'peername': peer}
    transport = Mock()
    transport.get_extra_info.side_effect = info.get
    return Mock(request=Mock(transport=transport))


async def run_check(output, peer=PEER):
    proc = Mock()
    proc.communicate = AsyncMock(return_value=(output, b''))
    with patch.object(auth, 'Popen', AsyncMock(return_value=proc)) as popen, \
            patch.object(auth.AuthService, 'session_manager') as manager:
        await auth.check_permission(Mock(), app_for(peer))
    return popen, manager


async def test_check_permission_logs_a_root_client_in():
    popen, manager = await run_check(sockstat(row(0, 'midclt', PEER, ('127.0.0.1', 6000)), SERVER))
    assert popen.call_args.args[0] == ['/usr/bin/sockstat', '--libxo', 'json', '-46c', '-n', '-p', '51234']
    manager.login.assert_called_once()
    assert isinstance(manager.login.call_args.args[1], auth.RootTcpSocketSessionManagerCredentials)


async def test_check_permission_leaves_a_non_root_client_alone():
    _, manager = await run_check(sockstat(row(1001, 'python3.11', PEER, ('127.0.0.1', 6000)), SERVER))
    manager.login.assert_not_called()


async def test_check_permission_ignores_remote_clients():
    popen, manager = await run_check(sockstat(), peer=('192.0.2.5', 51234))
    popen.assert_not_called()
    manager.login.assert_not_called()
