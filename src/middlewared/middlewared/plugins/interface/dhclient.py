import asyncio
import os
import signal
import subprocess

from middlewared.service import CallError, private, Service
from middlewared.utils import osc, Popen


if osc.IS_FREEBSD:
    LEASEFILE_TEMPLATE = '/var/db/dhclient.leases.{}'
    PIDFILE_TEMPLATE = '/var/run/dhclient/dhclient.{}.pid'
else:
    LEASEFILE_TEMPLATE = '/var/lib/dhcp/dhclient.leases.{}'
    PIDFILE_TEMPLATE = '/var/run/dhclient.{}.pid'


class InterfaceService(Service):
    class Config:
        namespace_alias = 'interfaces'

    @private
    async def dhclient_start(self, interface, wait=False):
        cmd = ['dhclient']

        if osc.IS_FREEBSD:
            if not wait:
                cmd.append('-b')

        if osc.IS_LINUX:
            if not wait:
                cmd.append('-nw')

            cmd.extend(['-lf', LEASEFILE_TEMPLATE.format(interface)])
            cmd.extend(['-pf', PIDFILE_TEMPLATE.format(interface)])

        proc = await Popen(
            cmd + [interface],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True,
        )
        output = (await proc.communicate())[0].decode()
        if proc.returncode != 0:
            self.logger.error('Failed to run dhclient on {}: {}'.format(
                interface, output,
            ))

    @private
    async def dhclient_rebind(self, interface):
        """Restart an active DHCP client and wait for its replacement."""
        running, old_pid = self.dhclient_status(interface)
        if not running:
            return False

        try:
            os.kill(old_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

        for _ in range(100):
            if not self.dhclient_status(interface)[0]:
                break
            await asyncio.sleep(0.1)
        else:
            raise CallError(f'Timed out stopping dhclient on {interface!r}')

        try:
            await asyncio.wait_for(self.dhclient_start(interface, wait=True), timeout=60)
        except asyncio.TimeoutError:
            raise CallError(f'Timed out starting dhclient on {interface!r}')

        running, new_pid = self.dhclient_status(interface)
        if not running or new_pid == old_pid:
            raise CallError(f'Failed to restart dhclient on {interface!r}')

        return True

    @private
    def dhclient_status(self, interface):
        """
        Get the current status of dhclient for a given `interface`.

        Args:
            interface (str): name of the interface

        Returns:
            tuple(bool, pid): if dhclient is running follow its pid.
        """
        pidfile = PIDFILE_TEMPLATE.format(interface)
        pid = None
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as f:
                try:
                    pid = int(f.read().strip())
                except ValueError:
                    pass

        running = False
        if pid:
            try:
                os.kill(pid, 0)
            except OSError:
                pass
            else:
                running = True
        return running, pid

    @private
    def dhclient_leases(self, interface):
        """
        Reads the leases file for `interface` and returns the content.

        Args:
            interface (str): name of the interface.

        Returns:
            str: content of dhclient leases file for `interface`.
        """
        leasesfile = LEASEFILE_TEMPLATE.format(interface)
        if os.path.exists(leasesfile):
            with open(leasesfile, 'r') as f:
                return f.read()
