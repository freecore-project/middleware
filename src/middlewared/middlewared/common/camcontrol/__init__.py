from collections import defaultdict
import re

from middlewared.utils import run


async def camcontrol_list():
    """
    Parse camcontrol devlist -v output to gather
    controller id, channel no and driver from a device

    Returns:
        dict(devname) = dict(driver, controller_id, channel_no, lun_id)
    """

    """
    Hacky workaround

    It is known that at least some HPT controller have a bug in the
    camcontrol devlist output with multiple controllers, all controllers
    will be presented with the same driver with index 0
    e.g. two hpt27xx0 instead of hpt27xx0 and hpt27xx1

    What we do here is increase the controller id by its order of
    appearance in the camcontrol output
    """
    hptctlr = defaultdict(int)

    re_drv_cid_bus = re.compile(r'.* on (?P<drv>.*?)(?P<cid>[0-9]+) bus (?P<bus>[0-9]+)', re.S | re.M)
    # Match device entries with 2 or more device names, e.g.:
    #   (pass0,da0) or (pass0,nda0,nvme0) on FB15 NVMe CAM
    re_tgt = re.compile(
        r'target (?P<tgt>[0-9]+) .*?lun (?P<lun>[0-9]+) .*\((?P<devs>[a-z][a-z0-9,]+)\)', re.S | re.M)
    drv, cid, bus, tgt, lun, dev = (None,) * 6

    camcontrol = {}
    proc = await run(['camcontrol', 'devlist', '-v'], encoding="utf8")
    for line in proc.stdout.splitlines():
        if not line.startswith('<'):
            reg = re_drv_cid_bus.search(line)
            if not reg:
                continue
            drv = reg.group('drv')
            if drv.startswith('hpt'):
                cid = hptctlr[drv]
                hptctlr[drv] += 1
            else:
                cid = reg.group('cid')
            bus = reg.group('bus')
        else:
            reg = re_tgt.search(line)
            if not reg:
                continue
            tgt = reg.group('tgt')
            lun = reg.group('lun')
            devs = reg.group('devs').split(',')
            # Pick the first non-pass device name
            dev = next((d for d in devs if not d.startswith('pass')), devs[0])
            camcontrol[dev] = {
                'driver': drv,
                'controller_id': int(cid),
                'bus': int(bus),
                'channel_no': int(tgt),
                'lun_id': int(lun)
            }

    return camcontrol
