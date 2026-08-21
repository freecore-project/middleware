"""the internal development record: a pool on a whole disk (no partition table) reserves that disk.

zfs.pool.get_disks mapped each vdev through the GEOM label and partition tables only, so a vdev named after
the disk itself (`/dev/vtbd2`, as XigmaNAS and `zpool create` on the CLI make them) was dropped. The disk was
then not reserved, disk.get_unused listed it, and Create Pool offered it.
"""
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

from middlewared.plugins.disk_.disk_info_freebsd import DiskService
from middlewared.plugins.zfs_.disks_freebsd import ZFSPoolService

CACHE = {
    'label_to_dev': {'gptid/1111': 'vtbd1p2', 'label/data': 'vtbd4'},
    'dev_to_disk': {'vtbd1p1': 'vtbd1', 'vtbd1p2': 'vtbd1', 'ada0p2': 'ada0'},
    'whole_disks': ['ada0', 'vtbd1', 'vtbd2', 'vtbd3', 'vtbd4'],
}


def get_disks(vdevs, cache=CACHE):
    middleware = Mock()
    middleware.call_sync.return_value = cache
    pool = Mock()
    pool.disks = vdevs
    zfs = Mock()
    zfs.__enter__ = Mock(return_value=Mock(get=Mock(return_value=pool)))
    zfs.__exit__ = Mock(return_value=False)
    with patch('middlewared.plugins.zfs_.disks_freebsd.ZFS', return_value=zfs):
        return ZFSPoolService(middleware).get_disks('tank')


def test_whole_disk_vdev_is_reported():
    assert get_disks(['/dev/vtbd2']) == ['vtbd2']


def test_whole_disk_vdev_behind_a_label_is_reported():
    assert get_disks(['/dev/label/data']) == ['vtbd4']


def test_partitioned_vdevs_map_to_their_disk_as_before():
    assert get_disks(['/dev/gptid/1111', '/dev/vtbd2', '/dev/ada0p2.eli']) == ['vtbd1', 'vtbd2', 'ada0']


def test_a_vdev_that_is_no_disk_is_still_dropped():
    assert get_disks(['/dev/md5', '/dev/zvol/tank/vol']) == []


def test_cache_lists_every_geom_disk():
    xml = ET.fromstring(
        '<mesh>'
        '<class><name>DISK</name><geom><name>vtbd1</name></geom><geom><name>vtbd2</name></geom></class>'
        '<class><name>PART</name><geom><name>vtbd1</name><provider><name>vtbd1p1</name></provider></geom></class>'
        '<class><name>LABEL</name></class>'
        '</mesh>'
    )
    middleware = Mock()
    middleware.call_sync.return_value = xml

    cache = DiskService(middleware).label_to_dev_disk_cache()

    assert cache['whole_disks'] == ['vtbd1', 'vtbd2']
    assert cache['dev_to_disk'] == {'vtbd1p1': 'vtbd1'}
