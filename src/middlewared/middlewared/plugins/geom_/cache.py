import re
import functools
import subprocess
from collections import defaultdict
from xml.etree import ElementTree as etree

from sysctl import filter as sysctl_filter
from bsd.disk import get_ident_with_name

CLASSES = ('PART', 'MULTIPATH', 'DISK', 'LABEL', 'DEV', 'RAID')
RE_DISK_NAME = re.compile(r'^([a-z]+)([0-9]+)$')
DISK_TEMPLATE = {
    'name': None,
    'mediasize': None,
    'sectorsize': None,
    'stripesize': None,
    'rotationrate': None,
    'ident': '',
    'lunid': None,
    'descr': None,
    'subsystem': '',
    'number': 1,  # Database defaults
    'model': None,
    'type': 'UNKNOWN',
    'serial': '',
    'size': None,
    'serial_lunid': None,
    'blocks': None,
}
RE_DRV_CID_BUS = re.compile(r'.* on (?P<drv>.*?)(?P<cid>[0-9]+) bus (?P<bus>[0-9]+)', re.S | re.M)
RE_TGT = re.compile(
    r'target (?P<tgt>[0-9]+) .*?lun (?P<lun>[0-9]+) .*\((?P<dv1>[a-z]+[0-9]+),(?P<dv2>[a-z]+[0-9]+)\)', re.S | re.M
)


class GeomCachedObjects:

    def get_disks(self):
        return self.cache['disks']

    def get_multipath(self):
        return self.cache['multipath']

    def get_topology(self):
        return self.cache['topology']

    def get_xml(self, xml_class=None):
        if xml_class and xml_class in CLASSES:
            result = self.cache['xml'].find(f'.//class[name="{xml_class}"]')
            if result is None:
                # Return an empty element so callers can safely use
                # .iterfind()/.find()/.findall() without null checks.
                return etree.Element('class')
            return result
        elif not xml_class:
            return self.cache['xml']

    def fill_disks_details(self, xmlelem, topology):
        name = xmlelem.find('provider/name')
        if name is None or name.text.startswith('cd'):
            return None, None

        name = name.text

        # make a copy of disk template
        disk = DISK_TEMPLATE.copy()

        # sizes — use defensive lookups in case GEOM XML fields change in FB15
        mediasize = xmlelem.find('provider/mediasize')
        sectorsize = xmlelem.find('provider/sectorsize')
        stripesize = xmlelem.find('provider/stripesize')
        disk.update({
            'name': name,
            'mediasize': int(mediasize.text) if mediasize is not None and mediasize.text else 0,
            'sectorsize': int(sectorsize.text) if sectorsize is not None and sectorsize.text else 512,
            'stripesize': int(stripesize.text) if stripesize is not None and stripesize.text else 0,
        })

        if config := xmlelem.find('provider/config'):
            # unique identifiers
            disk.update({i.tag: i.text for i in config if i.tag not in ('fwheads', 'fwsectors')})
            if disk['rotationrate'] is not None and disk['rotationrate'].isdigit():
                disk['rotationrate'] = int(disk['rotationrate'])
                if disk['rotationrate'] == 0:
                    disk['type'] = 'SSD'
                    disk['rotationrate'] = None
                else:
                    disk['type'] = 'HDD'

            # description and model (they're the same)
            disk['descr'] = disk['model'] = None if not disk['descr'] else disk['descr']

            # if geom doesn't give us a serial then try again
            # (even though this is 100% guaranteed to return
            #   what geom gave us)
            if not disk['ident']:
                try:
                    disk['ident'] = get_ident_with_name(name)
                except Exception:
                    disk['ident'] = ''

        # sprinkle our own information here
        reg = RE_DISK_NAME.search(name)
        if reg:
            disk['subsystem'] = reg.group(1)
            disk['number'] = int(reg.group(2))

        # API backwards compatibility dictates that we keep the
        # serial and size keys in the output
        disk['serial'] = disk['ident']
        disk['size'] = disk['mediasize']

        # some more sprinkling of our own information
        if disk['serial'] and disk['lunid']:
            disk['serial_lunid'] = f'{disk["serial"]}_{disk["lunid"]}'
        if disk['size'] and disk['sectorsize']:
            disk['blocks'] = int(disk['size'] / disk['sectorsize'])

        # get the disk driver
        if driver := topology.get(name, {}).get('driver'):
            if driver == 'umass-sim':
                disk['bus'] = 'USB'
            else:
                disk['bus'] = driver.upper()
        else:
            disk['bus'] = 'UNKNOWN'

        return name, disk

    def fill_multipath_consumer_details(self, xmlelem, xml):
        children = []
        for i in xmlelem.findall('./consumer'):
            state_elem = i.find('./config/State')
            consumer_status = state_elem.text if state_elem is not None else 'UNKNOWN'
            prov_elem = i.find('./provider')
            if prov_elem is None:
                continue
            provref = prov_elem.attrib.get('ref', '')
            provs = xml.findall(f'.//provider[@id="{provref}"]')
            if not provs:
                continue
            prov = provs[0]
            name_elem = prov.find('./name')
            da_name = name_elem.text if name_elem is not None else ''
            try:
                lun_id = prov.find('./config/lunid').text
            except Exception:
                lun_id = ''

            children.append({
                'type': 'consumer',
                'name': da_name,
                'status': consumer_status,
                'lun_id': lun_id,
            })

        mp_name_elem = xmlelem.find('./name')
        multipath_name = 'multipath/' + (mp_name_elem.text if mp_name_elem is not None else 'unknown')
        state_elem = xmlelem.find('./config/State')
        info = {
            'type': 'root',
            'name': multipath_name,
            'status': state_elem.text if state_elem is not None else 'UNKNOWN',
            'children': children,
        }

        return multipath_name, info

    def fill_topology(self):
        hptctlr = defaultdict(int)
        drv, cid, bus, tgt, lun, dev, devtmp = (None,) * 7

        camcontrol = {}
        proc = subprocess.run(['camcontrol', 'devlist', '-v'], encoding="utf8", stdout=subprocess.PIPE)
        for line in proc.stdout.splitlines():
            if not line.startswith('<'):
                if not (reg := RE_DRV_CID_BUS.search(line)):
                    continue
                drv = reg.group('drv')
                if drv.startswith('hpt'):
                    cid = hptctlr[drv]
                    hptctlr[drv] += 1
                else:
                    cid = reg.group('cid')
                bus = reg.group('bus')
            else:
                if not (reg := RE_TGT.search(line)):
                    continue
                tgt = reg.group('tgt')
                lun = reg.group('lun')
                dev = reg.group('dv1')
                devtmp = reg.group('dv2')
                if dev.startswith('pass'):
                    dev = devtmp
                camcontrol[dev] = {
                    'driver': drv,
                    'controller_id': int(cid),
                    'bus': int(bus),
                    'channel_no': int(tgt),
                    'lun_id': int(lun)
                }

        return camcontrol

    @property
    @functools.cache
    def cache(self):
        xml = etree.fromstring(sysctl_filter('kern.geom.confxml')[0].value)
        topology = self.fill_topology()

        disks = {}
        for xmlelm in xml.findall('.//class[name="DISK"]/geom'):
            name, info = self.fill_disks_details(xmlelm, topology)
            if name and info:
                disks[name] = info

        multipath = {}
        for xmlelm in xml.findall('.//class[name="MULTIPATH"]/geom'):
            name, info = self.fill_multipath_consumer_details(xmlelm, xml)
            multipath[name] = info

        return {'xml': xml, 'disks': disks, 'multipath': multipath, 'topology': topology}
