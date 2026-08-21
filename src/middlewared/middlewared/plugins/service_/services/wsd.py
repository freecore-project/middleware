from middlewared.utils import run

from .base import SimpleService
from .base_state import ServiceState


class WSDService(SimpleService):
    name = "wsdd"
    etc = ["wsd", "rc"]
    freebsd_rc = "wsdd"
    freebsd_pidfile = "/var/run/wsdd.pid"

    async def _get_state_freebsd(self):
        proc = await run("pgrep", "-F", self.freebsd_pidfile, check=False, encoding="utf-8")
        return ServiceState(
            proc.returncode == 0,
            [int(i) for i in proc.stdout.strip().split('\n') if i.isdigit()],
        )
