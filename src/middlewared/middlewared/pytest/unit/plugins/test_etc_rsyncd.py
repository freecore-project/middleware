"""rsyncd.conf is rendered where the net/rsync daemon reads it.

net/rsync is built with --with-rsyncd-conf=${ETCDIR}/rsyncd.conf and its rc script starts
`rsync --daemon --config ${rsyncd_configfile:=%%ETCDIR%%/rsyncd.conf}`: that is
/usr/local/etc/rsync/rsyncd.conf, and /usr/local/etc is /etc/local here. /usr/local/etc/rsyncd.conf
is only picked up by the rc script's start_precmd, which moves it to the new place and leaves a
symlink behind.
"""
import os

import pytest

from middlewared.plugins.etc import EtcService


class Middleware:

    async def run_in_thread(self, method, *args):
        return method(*args)


class Renderer:

    def __init__(self):
        self.paths = []

    async def render(self, path, ctx):
        self.paths.append(path)
        return 'use chroot = yes\n'


@pytest.mark.parametrize('checkpoint', [None, 'pool_import'])
async def test_rsync_group_writes_the_config_the_rsync_daemon_reads(checkpoint):
    service = EtcService(Middleware())
    renderer = Renderer()
    service._renderers['mako'] = renderer
    written = []
    service.make_changes = lambda path, entry, rendered: written.append(path)

    await service.generate('rsync', checkpoint)

    assert written == ['/etc/local/rsync/rsyncd.conf']
    assert renderer.paths == [os.path.join(service.files_dir, 'local/rsyncd.conf')]
    assert os.path.isfile(renderer.paths[0])
