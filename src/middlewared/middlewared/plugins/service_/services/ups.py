import contextlib
import os
import signal

import psutil

from middlewared.utils import run

from .base import SimpleService
from .base_state import ServiceState

UPSD_PIDFILE = "/var/db/nut/upsd.pid"


class UPSService(SimpleService):
    name = "ups"

    etc = ["ups"]

    freebsd_rc = "upsd"
    # We use upsmon state
    freebsd_pidfile = "/var/db/nut/upsmon.pid"
    freebsd_procname = "upsmon"

    systemd_unit = "nut-monitor"

    async def _get_state_freebsd(self):
        # the internal development record (Codeberg freecore#111): upsmon alone is not a
        # working UPS service. In MASTER mode the rc `nut` script starts the driver in
        # its precmd and upsd as its command; when the driver cannot reach the UPS at
        # boot (a network UPS behind a LACP trunk that is still negotiating, a USB UPS
        # that enumerates late) the precmd fails, rc skips upsd, and `nut_upsmon` /
        # `nut_upslog` start anyway because rcorder only orders them after `nut`. The
        # inherited 13.3 state check then reports RUNNING on the upsmon pid while
        # nothing listens on 3493 and every upsc query is refused. Require upsd too, so
        # the state (and `service.start`'s return value, which is this state) is honest.
        # SLAVE mode has no local upsd and keeps the upsmon-only check.
        state = await super()._get_state_freebsd()
        if not state.running:
            return state
        if (await self.middleware.call("ups.config"))["mode"] != "MASTER":
            return state
        upsd = await run("pgrep", "-F", UPSD_PIDFILE, "upsd", check=False, encoding="utf-8")
        if upsd.returncode != 0:
            return ServiceState(False, [])
        return ServiceState(True, state.pids + [int(i) for i in upsd.stdout.split() if i.isdigit()])

    async def before_start(self):
        await self.middleware.call("ups.dismiss_alerts")

    async def _start_freebsd(self):
        if (await self.middleware.call("ups.config"))["mode"] == "MASTER":
            await self._freebsd_service("nut", "start")
        await self._freebsd_service("nut_upsmon", "start")
        await self._freebsd_service("nut_upslog", "start")

    async def after_start(self):
        if await self.middleware.call("service.started", "collectd"):
            self.middleware.create_task(self.middleware.call("service.restart", "collectd"))

    async def before_stop(self):
        await self.middleware.call("ups.dismiss_alerts")

    async def _stop_freebsd(self):
        await self._freebsd_service("nut_upslog", "stop", force=True)
        await self._freebsd_service("nut_upsmon", "stop", force=True)
        await self._freebsd_service("nut", "stop", force=True)

        # We need to wait on upsmon service to die properly as multiple processes are
        # associated with it and in most cases they haven't exited when a restart is initiated
        # for upsmon which fails as the older process is still running.
        upsmon_processes = await run(["pgrep", "-x", "upsmon"], encoding="utf-8", check=False)
        if upsmon_processes.returncode == 0:
            gone, alive = await self.middleware.run_in_thread(
                psutil.wait_procs,
                map(
                    lambda v: psutil.Process(int(v)),
                    upsmon_processes.stdout.split()
                ),
                timeout=10
            )
            if alive:
                for pid in map(int, upsmon_processes.stdout.split()):
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGKILL)

    async def after_stop(self):
        if await self.middleware.call("service.started", "collectd"):
            self.middleware.create_task(self.middleware.call("service.restart", "collectd"))
