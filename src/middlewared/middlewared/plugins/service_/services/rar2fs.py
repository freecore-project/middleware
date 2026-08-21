import os

from middlewared.service_exception import CallError
from middlewared.utils import run

from .base import ServiceState, SimpleService


class Rar2fsService(SimpleService):
    name = 'rar2fs'
    etc = ['rar2fs']
    freebsd_rc = 'rar2fs'

    async def before_start(self):
        config = await self.middleware.call('rar2fs.config')
        source = config.get('source')
        mountpoint = config.get('mountpoint')

        if not source:
            raise CallError('Configure a rar2fs source directory before starting rar2fs.')
        if not mountpoint:
            raise CallError('Configure a rar2fs mountpoint before starting rar2fs.')
        if not os.path.isdir(source):
            raise CallError(f'rar2fs source directory {source!r} does not exist.')
        if os.path.exists(mountpoint) and not os.path.isdir(mountpoint):
            raise CallError(f'rar2fs mountpoint {mountpoint!r} exists but is not a directory.')

    async def _get_state_freebsd(self):
        config = await self.middleware.call('rar2fs.config')
        mountpoint = config.get('mountpoint')
        if not mountpoint:
            return ServiceState(False, [])

        proc = await run('mount', check=False, encoding='utf-8')
        if proc.returncode != 0:
            return ServiceState(False, [])

        marker = f' on {mountpoint} ('
        for line in proc.stdout.splitlines():
            if marker in line and 'fusefs.rar2fs' in line:
                return ServiceState(True, [])

        return ServiceState(False, [])
