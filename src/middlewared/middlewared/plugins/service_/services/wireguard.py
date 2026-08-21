from middlewared.service_exception import CallError

from .base import SimpleService, ServiceState


class WireguardService(SimpleService):
    name = 'wireguard'

    # 'rc' is required as well as 'wireguard': toggling the service has to regenerate
    # rc.conf so wireguard_server_enable follows it.
    etc = ['rc', 'wireguard']

    # Our own overlay script, not the one from net/wireguard-tools. The port's
    # script acts on every interface in wireguard_interfaces at once, so it cannot
    # give wg1 a lifecycle independent of TrueCommand's wg0 -- and its start never
    # returns on FreeBSD 15 because wg-quick(8) does not exit (freecore/the internal development record),
    # which would hang service.start and stall /etc/rc at boot. wireguard_client
    # already owned wg2 for the first of those reasons (the internal development record); the server now owns
    # wg1 for both.
    freebsd_rc = 'wireguard_server'

    systemd_unit = 'wg-quick@wg1'

    async def start(self):
        # An unconfigured service reports that it did not start; it does not make
        # service.start raise. 13.3's openvpn_server/openvpn_client -- which these two
        # services replace one-for-one -- were bare SimpleServices with no validation,
        # so starting one unconfigured returned False through a 200, and everything
        # that walks the service list relied on that. Raising here instead turned the
        # same situation into a 422 and broke callers that iterate services (found by
        # api2 test_007_systemdataset::test_11, which starts every service).
        #
        # The validation itself is kept and still raises where it belongs -- on the
        # config endpoints -- so the operator still gets "Generate or provide a
        # WireGuard private key first." when they save an incomplete config, rather
        # than a bare failure to start.
        try:
            await self.middleware.call('wireguard.config_valid')
        except CallError as e:
            self.middleware.logger.info(
                'wireguard: not starting, configuration is incomplete: %s', e.errmsg
            )
            return

        await super().start()

    async def _get_state_freebsd(self):
        # There is no resident daemon and no pidfile to match on: wg-quick(8) is a
        # script, not a service, so the stock pidfile/procname detection that 13.3
        # used for openvpn(8) cannot work here. wireguard_server's status verb runs
        # `wg show wg1` and returns its exit code, which is a direct question about
        # the one interface this service owns.
        #
        # The private-key gate below is kept from freecore/the internal development record. It is no
        # longer load-bearing -- our own script checks a specific interface rather
        # than iterating a possibly-empty list, so it cannot succeed vacuously the
        # way the port's script did -- but an unkeyed server genuinely is stopped,
        # and answering that without shelling out is both cheaper and clearer.
        config = await self.middleware.call('wireguard.config')
        if not config['private_key']:
            return ServiceState(False, [])

        proc = await self._freebsd_service(self.freebsd_rc, 'status')
        return ServiceState(proc.returncode == 0, [])
