from middlewared.service_exception import CallError

from .base import SimpleService, ServiceState


class WireguardClientService(SimpleService):
    name = 'wireguard_client'

    etc = ['rc', 'wireguard_client']

    # Not the port's "wireguard" rc script: that one acts on every interface listed in
    # wireguard_interfaces at once, so sharing it with the server would mean stopping
    # the client also stopped the server. This is our own overlay script owning wg2.
    freebsd_rc = 'wireguard_client'

    systemd_unit = 'wg-quick@wg2'

    async def start(self):
        # See the note in wireguard.py: an incomplete config makes this report "did not
        # start" (False through a 200), not raise. That is what 13.3's openvpn_client
        # did, and callers that iterate services depend on it.
        try:
            await self.middleware.call('wireguard.client.config_valid')
        except CallError as e:
            self.middleware.logger.info(
                'wireguard_client: not starting, configuration is incomplete: %s', e.errmsg
            )
            return

        await super().start()

    async def _get_state_freebsd(self):
        # wg-quick exits once the interface is up, so there is no resident process for
        # the default procname match to find. The rc script's status verb runs
        # `wg show wg2` and returns non-zero when it is down.
        proc = await self._freebsd_service(self.freebsd_rc, 'status')
        return ServiceState(proc.returncode == 0, [])
