import subprocess
from unittest.mock import Mock, patch

from middlewared.plugins.vm import VNC


def test_vnc_post_start_uses_packaged_websockify_console_script():
    vnc = VNC({
        'attributes': {
            'vnc_bind': '0.0.0.0',
            'vnc_port': 5901,
        },
    })
    process = Mock()

    with patch('middlewared.plugins.vm.subprocess.Popen', return_value=process) as popen:
        vnc.post_start_vm()

    popen.assert_called_once_with(
        [
            '/usr/local/bin/websockify',
            '--web',
            '/usr/local/libexec/novnc/',
            '--wrap-mode=ignore',
            ':5801',
            '0.0.0.0:5901',
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert vnc.web_process is process
