import errno
import os

from middlewared.schema import accepts
from middlewared.service import Service

EULA_FILE = '/usr/local/share/truenas/eula.html'
EULA_PENDING_PATH = '/data/truenas-eula-pending'


class TrueNASService(Service):
    """
    Stand-in for the removed proprietary truenas plugin (the internal development record).
    Returns what the licensed plugin produced on non-iX hardware.
    """

    @accepts()
    async def get_chassis_hardware(self):
        """
        No iX chassis is ever detected on this system.
        """
        return 'TRUENAS-UNKNOWN'

    @accepts()
    def get_eula(self):
        """
        Returns the End-User License Agreement (EULA) text.
        """
        if not os.path.exists(EULA_FILE):
            return
        with open(EULA_FILE, 'r', encoding='utf8') as f:
            return f.read()

    @accepts()
    async def is_eula_accepted(self):
        return not os.path.exists(EULA_PENDING_PATH)

    @accepts()
    async def accept_eula(self):
        try:
            os.unlink(EULA_PENDING_PATH)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
