"""The ftp etc group creates the files proftpd needs without emptying ones that already exist.

/etc/hosts.allow and /etc/hosts.deny are read by every TCP-wrapped daemon (sshd, inetd, rpcbind),
and /var/log/wtmp holds the login history: an FTP render must leave their contents alone.
"""
import builtins
import os
from pathlib import Path
from unittest.mock import patch

from middlewared.plugins.etc import PyRenderer

FILES_DIR = Path(__file__).parents[3] / 'etc_files'
PROFTPD_FILES = (
    '/etc/hosts.allow', '/etc/hosts.deny', '/var/log/wtmp',
    '/var/run/proftpd/proftpd.delay', '/var/run/proftpd/proftpd.motd',
)
HOSTS_ALLOW = 'sshd : 192.168.1.0/24 : allow\nsshd : ALL : deny\nALL : ALL : allow\n'


class ProftpdMiddleware:

    def call_sync(self, name, *args):
        return {'ftp.config': {'banner': ''}, 'system.product_name': 'FreeCORE'}[name]

    async def run_in_thread(self, method, *args):
        return method(*args)


class ProftpdService:

    def __init__(self, middleware):
        self.middleware = middleware


async def render_proftpd(tmp_path):
    real_open, real_chmod = builtins.open, os.chmod

    def redirect(path):
        return str(tmp_path / os.path.basename(path)) if path in PROFTPD_FILES else path

    with patch('builtins.open', lambda path, *args, **kwargs: real_open(redirect(path), *args, **kwargs)), \
            patch('os.chmod', lambda path, *args, **kwargs: real_chmod(redirect(path), *args, **kwargs)), \
            patch('os.makedirs'):
        await PyRenderer(ProftpdService(ProftpdMiddleware())).render(str(FILES_DIR / 'local/proftpd'), None)


async def test_ftp_render_keeps_tcp_wrapper_rules_and_login_history(tmp_path):
    (tmp_path / 'hosts.allow').write_text(HOSTS_ALLOW)
    (tmp_path / 'hosts.deny').write_text('ALL : 192.0.2.1\n')
    (tmp_path / 'wtmp').write_bytes(b'login record')

    await render_proftpd(tmp_path)

    assert (tmp_path / 'hosts.allow').read_text() == HOSTS_ALLOW
    assert (tmp_path / 'hosts.deny').read_text() == 'ALL : 192.0.2.1\n'
    assert (tmp_path / 'wtmp').read_bytes() == b'login record'
    assert (tmp_path / 'proftpd.motd').read_text() == 'Welcome to FreeCORE FTP Server\n'


async def test_ftp_render_creates_missing_files(tmp_path):
    await render_proftpd(tmp_path)

    for name in ('hosts.allow', 'hosts.deny', 'wtmp', 'proftpd.delay'):
        assert (tmp_path / name).read_bytes() == b''
    assert (tmp_path / 'wtmp').stat().st_mode & 0o777 == 0o644
