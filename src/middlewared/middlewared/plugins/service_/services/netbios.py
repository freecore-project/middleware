import asyncio
import os

from middlewared.utils import run

from .base import SimpleService
from .base_state import ServiceState


class NetBIOSService(SimpleService):
    name = "nmbd"
    etc = ["smb", "rc"]

    freebsd_pidfile = "/var/run/samba4/nmbd.pid"
    freebsd_procname = "nmbd"
    nmbd_command = "/usr/local/sbin/nmbd"
    smb_config = "/usr/local/etc/smb4.conf"

    systemd_unit = "nmbd"

    async def _get_state_freebsd(self):
        proc = await run("pgrep", "-F", self.freebsd_pidfile, self.freebsd_procname, check=False, encoding="utf-8")
        return ServiceState(
            proc.returncode == 0,
            [int(i) for i in proc.stdout.strip().split('\n') if i.isdigit()],
        )

    async def _start_freebsd(self):
        if (await self._get_state_freebsd()).running:
            return

        rundir = os.path.dirname(self.freebsd_pidfile)
        os.makedirs(rundir, mode=0o755, exist_ok=True)
        os.chmod(rundir, 0o755)

        proc = await run(
            self.nmbd_command,
            "--daemon",
            f"--configfile={self.smb_config}",
            check=False,
            encoding="utf-8",
        )
        if proc.returncode != 0:
            self.middleware.logger.warning("Failed to start nmbd: %s", proc.stdout)

    async def _stop_freebsd(self):
        await run("pkill", "-F", self.freebsd_pidfile, check=False)
        for _ in range(10):
            if not (await self._get_state_freebsd()).running:
                return
            await asyncio.sleep(1)

    async def _restart_freebsd(self):
        await self._stop_freebsd()
        await self._start_freebsd()
