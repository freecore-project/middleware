from os.path import exists

from nvme import get_nsid
from middlewared.service import private, Service


class DiskService(Service):

    @private
    def nvme_to_nvd_map(self, ignore_boot_disks=False):
        nvme_to_nvd = {}
        boot_disks = self.middleware.call_sync('boot.get_disks') if ignore_boot_disks else []
        for prefix in ('nvd', 'nda'):
            for disk in self.middleware.call_sync('disk.query', [['devname', '^', prefix]]):
                if disk['devname'] in boot_disks:
                    continue

                try:
                    n = int(disk['devname'][len(prefix):])
                except ValueError:
                    continue

                dev = f'/dev/{disk["devname"]}'
                if not exists(dev):
                    continue

                nvme, nsid = get_nsid(dev)
                if nvme:
                    nvme_to_nvd[int(nvme[4:])] = n

        return nvme_to_nvd
