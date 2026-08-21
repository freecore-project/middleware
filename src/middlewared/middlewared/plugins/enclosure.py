from middlewared.service import Service, private


class EnclosureService(Service):
    """
    Stand-in for the removed proprietary enclosure plugin (freecore/the internal development record).
    No supported enclosure ever exists on this system; the sync hooks called from
    disk_/sync.py are no-ops.
    """

    @private
    async def sync_disk(self, disk_identifier):
        return None

    @private
    def sync_disks(self, enclosure_id=None, disks=None, ha_sync=False):
        return None
