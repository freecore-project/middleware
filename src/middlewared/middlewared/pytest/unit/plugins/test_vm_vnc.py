import subprocess
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.vm import VNC


def run_post_start(vnc_bind, vnc_port):
    vnc = VNC({
        'attributes': {
            'vnc_bind': vnc_bind,
            'vnc_port': vnc_port,
        },
    })
    process = Mock()

    with patch('middlewared.plugins.vm.subprocess.Popen', return_value=process) as popen:
        vnc.post_start_vm()

    assert vnc.web_process is process
    return popen.call_args[0][0]


def test_vnc_post_start_uses_packaged_websockify_console_script():
    argv = run_post_start('0.0.0.0', 5901)

    assert argv[:4] == [
        '/usr/local/bin/websockify',
        '--web',
        '/usr/local/libexec/novnc/',
        '--wrap-mode=ignore',
    ]


def test_vnc_post_start_passes_devnull_for_both_streams():
    vnc = VNC({'attributes': {'vnc_bind': '0.0.0.0', 'vnc_port': 5901}})

    with patch('middlewared.plugins.vm.subprocess.Popen', return_value=Mock()) as popen:
        vnc.post_start_vm()

    assert popen.call_args[1] == {
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.DEVNULL,
    }


@pytest.mark.parametrize('vnc_bind,expected_listen,expected_dial', [
    # A wildcard listens everywhere but must never be dialled.
    ('0.0.0.0', ':5801', '127.0.0.1:5901'),
    ('::', ':::5801', '::1:5901'),
    # A concrete address is both listened on and dialled unchanged.
    ('192.0.2.10', '192.0.2.10:5801', '192.0.2.10:5901'),
    ('::1', '::1:5801', '::1:5901'),
    ('127.0.0.1', '127.0.0.1:5801', '127.0.0.1:5901'),
])
def test_vnc_post_start_listen_and_dial_targets(vnc_bind, expected_listen, expected_dial):
    argv = run_post_start(vnc_bind, 5901)

    assert argv[-2:] == [expected_listen, expected_dial]


@pytest.mark.parametrize('wildcard', ['0.0.0.0', '::'])
def test_vnc_dial_target_is_never_a_wildcard(wildcard):
    """A wildcard reached connect() as a destination: 13.3 substituted a local
    address, FreeBSD 15 returns ENETUNREACH and websockify reports only a 1011
    close to the browser."""
    dial = VNC.get_vnc_dial_target(wildcard, 5901)

    assert not dial.startswith(f'{wildcard}:')
    assert dial in ('127.0.0.1:5901', '::1:5901')


def test_vnc_dial_target_preserves_a_concrete_address():
    assert VNC.get_vnc_dial_target('192.0.2.10', 5901) == '192.0.2.10:5901'
