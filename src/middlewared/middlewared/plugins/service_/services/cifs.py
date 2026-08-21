from middlewared.service_exception import CallError
from middlewared.utils import run

from .base import SimpleService, ServiceState

import os
import psutil
import signal
import time


class CIFSService(SimpleService):
    name = "cifs"
    reloadable = True

    etc = ["smb", "smb_share"]

    freebsd_rc = "samba_server"
    freebsd_pidfile = "/var/run/samba4/smbd.pid"
    nmbd_pidfile = "/var/run/samba4/nmbd.pid"
    dcerpc_pidfile = "/var/run/samba4/samba-dcerpcd.pid"
    wsdd_rcfile = "/usr/local/etc/rc.d/wsdd"

    systemd_unit = "smbd"

    def lookup_pid(self):
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if proc.info['name'] == 'samba-dcerpcd':
                return proc.info['pid']

        return None

    def get_pid(self):
        try:
            with open(self.dcerpc_pidfile, 'r') as f:
                return int(f.read().strip())
        except FileNotFoundError:
            return self.lookup_pid()
        except Exception:
            self.middleware.logger.debug('Failed to open pidfile', exc_info=True)

        return None

    def wait_on_pid(self, pid, timeout=10):
        while timeout > 0:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            except Exception:
                self.middleware.logger.warning('%s: liveness check failed', pid, exc_info=True)
                break

            time.sleep(1)
            timeout -= 1

    def terminate_dcerpcd(self):
        pid = self.get_pid()
        if pid is None:
            return

        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception:
            self.middleware.logger.warning('%d: failed to kill samba-dcerpcd', pid, exc_info=True)
            return

        self.wait_on_pid(pid)

        try:
            os.unlink(self.dcerpc_pidfile)
        except Exception:
            self.middleware.logger.warning('Failed to unlink dcerpcd pidfile', exc_info=True)

        self.middleware.logger.debug('Successfully shut down samba-dcerpcd')

    async def _get_state_freebsd(self):
        # samba_server aggregate status checks nmbd+smbd+winbindd. nmbd is
        # skipped when announce[netbios]=False, so gate on smbd (always
        # required when cifs is on) to avoid a false-DOWN flap loop.
        proc = await run("pgrep", "-F", self.freebsd_pidfile, "smbd", check=False, encoding="utf-8")
        return ServiceState(
            proc.returncode == 0,
            [int(i) for i in proc.stdout.strip().split('\n') if i.isdigit()],
        )

    async def start(self):
        # forcestart bypasses per-daemon *_enable rcvars (samba_server.in
        # samba_server_cmd force_run branch starts nmbd+smbd+winbindd
        # unconditionally). Kill nmbd post-start to honour
        # announce[netbios]=False.
        await self._freebsd_service("samba_server", "start", force=True)
        announce = (await self.middleware.call("network.configuration.config"))["service_announcement"]
        if not announce["netbios"]:
            await run("pkill", "-F", self.nmbd_pidfile, check=False)
        if announce["wsd"]:
            if os.path.exists(self.wsdd_rcfile):
                await self.middleware.call("etc.generate", "wsd")
                await self.middleware.call("etc.generate", "rc")
                await self._freebsd_service("wsdd", "start", force=True)
            else:
                self.middleware.logger.warning(
                    "WSD announcements are enabled but %s is missing", self.wsdd_rcfile
                )

    async def after_start(self):
        await self.middleware.call("service.reload", "mdns")

        try:
            await self.middleware.call("smb.add_admin_group", "", True)
        except Exception as e:
            raise CallError(e)

    async def stop(self):
        await self._freebsd_service("samba_server", "stop", force=True)
        if os.path.exists(self.wsdd_rcfile):
            await self._freebsd_service("wsdd", "stop", force=True)
        await self.middleware.run_in_thread(self.terminate_dcerpcd)

    async def after_stop(self):
        await self.middleware.call("service.reload", "mdns")

    async def after_reload(self):
        await self.middleware.call("service.reload", "mdns")

    async def before_reload(self):
        await self.middleware.call("sharing.smb.sync_registry")
