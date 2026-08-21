import contextlib

from middlewared.service import lock
from middlewared.service_exception import CallError

from .base import ServiceState, SimpleService


class BastilleService(SimpleService):
    name = 'bastille'
    etc = ('rc',)
    freebsd_rc = 'bastille'
    restartable = True

    async def before_enable(self):
        await self.middleware.call('bastille.validate_startable')

    @lock('bastille_lifecycle_internal')
    async def before_start(self):
        config = await self.middleware.call('bastille.rc_config')
        if not config['pool']:
            if config['enabled']:
                await self._disable_after_start_failure()
            return
        try:
            await self.middleware.call('bastille.validate_startable')
        except Exception:
            await self._disable_after_start_failure()
            raise

    async def start(self):
        config = await self.middleware.call('bastille.rc_config')
        if not config['pool']:
            return
        await super().start()

    async def _disable_after_start_failure(self):
        with contextlib.suppress(Exception):
            await self.middleware.call('bastille.disable_service')

    async def _get_state_freebsd(self):
        running = await self.middleware.call('bastille.running_jails')
        return ServiceState(bool(running), [])

    async def _start_locked(self):
        await self.middleware.call('bastille.validate_startable')
        result = await self._freebsd_service(self.freebsd_rc, 'start')
        if result.returncode:
            await self._disable_after_start_failure()
            raise CallError('The Bastille rc service failed to start its boot-enabled jails.')
        try:
            await self.middleware.call('bastille.rc_postflight', 'start')
        except Exception:
            await self._disable_after_start_failure()
            raise

    async def _stop_locked(self):
        config = await self.middleware.call('bastille.rc_config')
        if not config['pool']:
            return
        await self.middleware.call('bastille.rc_preflight', 'stop')
        result = await self._freebsd_service(self.freebsd_rc, 'stop', force=True)
        if result.returncode:
            raise CallError('The Bastille rc service failed to stop every Bastille-owned jail.')
        running = await self.middleware.call('bastille.running_jails_strict')
        if running:
            raise CallError(
                f'The Bastille rc service left jail roots running: {", ".join(running)}.'
            )
        await self.middleware.call('bastille.rc_postflight', 'stop')

    @lock('bastille_lifecycle_internal')
    async def _start_freebsd(self):
        await self._start_locked()

    @lock('bastille_lifecycle_internal')
    async def _stop_freebsd(self):
        await self._stop_locked()

    @lock('bastille_lifecycle_internal')
    async def _restart_freebsd(self):
        await self.middleware.call('bastille.validate_startable')
        await self._stop_locked()
        await self._start_locked()

    async def _identify_freebsd(self, procname):
        # Bastille's rc entry is a jail orchestrator, not a resident daemon.
        return False
