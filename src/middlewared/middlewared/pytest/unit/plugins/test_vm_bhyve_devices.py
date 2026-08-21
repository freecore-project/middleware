"""NVMe disks and virtio-9p shared directories for bhyve guests (the internal development record).

Off-box like test_vm_arch: the supervisor is assembled by hand around its XML builders,
and the device service around its validator.
"""
import os
from unittest.mock import AsyncMock, patch
from xml.etree import ElementTree as etree

import pytest

from middlewared.plugins import vm as vm_module
from middlewared.plugins.vm import DISK, FILESYSTEM, LIBVIRT_AVAILABLE_SLOTS, RAW, VMDeviceService, VMService
from middlewared.plugins.vm_.arch import device_rejection_reason
from middlewared.pytest.unit.plugins.test_vm_arch import cdrom, disk, make_supervisor, nic
from middlewared.schema import Error
from middlewared.service_exception import ValidationErrors


def raw(id, type='NVME', order=1001, logical=None, physical=None):
    return {
        'id': id, 'dtype': 'RAW', 'order': order,
        'attributes': {
            'path': f'/mnt/tank/vm/raw{id}.img', 'type': type, 'exists': True, 'boot': False, 'size': None,
            'logical_sectorsize': logical, 'physical_sectorsize': physical,
        },
    }


def share(id, source='/mnt/tank/shared', tag='shared', readonly=False, order=1002):
    return {
        'id': id, 'dtype': 'FILESYSTEM', 'order': order,
        'attributes': {'source': source, 'tag': tag, 'readonly': readonly},
    }


def devices_of(*devices):
    return make_supervisor('amd64', list(devices)).devices_xml()


def serialized(element):
    return etree.tostring(element)


# --- the XML ---------------------------------------------------------------------------

def test_ahci_and_virtio_layout_is_untouched_by_an_nvme_disk():
    """Everything that rendered before renders the same; the NVMe controller and disk are appended
    on the next free slot."""
    before = devices_of(cdrom(1), disk(2, type='AHCI'), disk(3, type='VIRTIO'), nic(9))
    after = devices_of(cdrom(1), disk(2, type='AHCI'), disk(3, type='VIRTIO'), disk(4, type='NVME'), nic(9))

    def storage(devices):
        return [serialized(e) for e in devices if e.tag in ('controller', 'disk')]

    assert storage(after)[:len(storage(before))] == storage(before)
    added = [e for e in after if e.tag in ('controller', 'disk')][len(storage(before)):]
    assert [(e.tag, e.get('type'), e.find('target').get('bus') if e.tag == 'disk' else None) for e in added] == [
        ('controller', 'nvme', None), ('disk', 'file', 'nvme'),
    ]
    assert serialized(after.find('serial')) == serialized(before.find('serial'))

    # the NIC moved one slot up, which is the only change to a pre-existing element
    assert before.find('interface/address').get('slot') == '5'
    assert after.find('interface/address').get('slot') == '6'


def test_every_nvme_disk_is_its_own_controller_on_its_own_slot():
    devices = devices_of(disk(2, type='AHCI'), disk(3, type='NVME'), raw(4, type='NVME'), nic(9))

    controllers = devices.findall('controller')
    # NVMe controllers count from 0 on their own: libvirt adds an implicit controller for every
    # index gap below the highest one referenced, and the SATA numbering stays exactly as before
    assert [(c.get('type'), c.get('index')) for c in controllers] == [('sata', '1'), ('nvme', '0'), ('nvme', '1')]
    assert [c.find('address').attrib for c in controllers[1:]] == [
        {'type': 'pci', 'slot': '4', 'function': '0'},
        {'type': 'pci', 'slot': '5', 'function': '0'},
    ]
    disks = devices.findall('disk')
    # the name is what libvirt's bhyve driver validates: nvme<controller>n<namespace>, one disk per controller
    assert [d.find('target').attrib for d in disks] == [
        {'bus': 'sata', 'dev': 'hdc2'},
        {'bus': 'nvme', 'dev': 'nvme0n1'},
        {'bus': 'nvme', 'dev': 'nvme1n1'},
    ]
    assert [d.find('address').attrib for d in disks[1:]] == [
        {'type': 'drive', 'controller': '0', 'bus': '0', 'target': '0', 'unit': '0'},
        {'type': 'drive', 'controller': '1', 'bus': '0', 'target': '0', 'unit': '0'},
    ]
    assert devices.find('interface/address').get('slot') == '6'


def test_nvme_disk_carries_the_sector_size_like_the_other_buses():
    devices = devices_of(raw(4, type='NVME', logical=4096, physical=4096))

    blockio = devices.find('disk/blockio')
    assert blockio.attrib == {'logical_block_size': '4096', 'physical_block_size': '4096'}
    assert devices.find('disk/source').get('file') == '/mnt/tank/vm/raw4.img'


def test_a_shared_directory_is_a_passthrough_9p_filesystem_on_its_own_slot():
    devices = devices_of(disk(2, type='VIRTIO'), share(5), share(6, source='/mnt/tank/iso', tag='iso', readonly=True))

    filesystems = devices.findall('filesystem')
    assert [fs.attrib for fs in filesystems] == [
        {'type': 'mount', 'accessmode': 'passthrough'},
        {'type': 'mount', 'accessmode': 'passthrough'},
    ]
    assert [fs.find('source').get('dir') for fs in filesystems] == ['/mnt/tank/shared', '/mnt/tank/iso']
    assert [fs.find('target').get('dir') for fs in filesystems] == ['shared', 'iso']
    assert [fs.find('readonly') is not None for fs in filesystems] == [False, True]
    assert [fs.find('address').attrib for fs in filesystems] == [
        {'type': 'pci', 'slot': '4', 'function': '0'},
        {'type': 'pci', 'slot': '5', 'function': '0'},
    ]
    assert serialized(devices.find('serial')).startswith(b'<serial type="nmdm">')


def test_shared_directory_identity_and_availability(tmp_path):
    device = FILESYSTEM(share(1, source=str(tmp_path)), None)

    assert device.identity() == str(tmp_path)
    assert device.is_available()
    assert not FILESYSTEM(share(1, source=str(tmp_path / 'missing')), None).is_available()


# --- the schema and the emulated-guest rule ------------------------------------------

@pytest.mark.parametrize('schema', [DISK.schema, RAW.schema])
def test_disk_and_raw_accept_nvme(schema):
    assert schema.attrs['type'].enum == ['AHCI', 'VIRTIO', 'NVME']


@pytest.mark.parametrize('tag', ['shared', 'a', 'Data-1.0_x', 'x' * 32])
def test_filesystem_tag_is_a_mount_name(tag):
    FILESYSTEM.schema.validate({'source': '/mnt/tank/shared', 'tag': tag, 'readonly': False})


@pytest.mark.parametrize('tag', ['', '-leading', 'has space', 'x' * 33, 'sl/ash'])
def test_filesystem_refuses_a_tag_the_guest_could_not_mount(tag):
    with pytest.raises(ValidationErrors):
        FILESYSTEM.schema.validate({'source': '/mnt/tank/shared', 'tag': tag})


def test_filesystem_source_is_required():
    with pytest.raises(Error):
        FILESYSTEM.schema.clean({'tag': 'shared'})


@pytest.mark.parametrize('device,attribute', [
    (disk(1, type='NVME'), 'attributes.type'),
    (raw(1, type='NVME'), 'attributes.type'),
    (share(1), 'dtype'),
])
def test_emulated_guests_get_neither(device, attribute):
    rejected = device_rejection_reason('aarch64', device)
    assert rejected is not None and rejected[0] == attribute


@pytest.mark.parametrize('device', [disk(1, type='NVME'), raw(1, type='NVME'), share(1)])
def test_bhyve_guests_get_both(device):
    assert device_rejection_reason('amd64', device) is None


# --- slots -----------------------------------------------------------------------------

def test_nvme_disks_and_shared_directories_are_one_slot_each():
    service = object.__new__(VMService)

    fits = {'devices': [disk(i, type='NVME') for i in range(LIBVIRT_AVAILABLE_SLOTS)]}
    assert service.validate_slots(fits) is False
    assert service.validate_slots({'devices': fits['devices'] + [share(99)]}) is True

    packed = {'devices': [disk(i, type='VIRTIO') for i in range(8)] + [disk(50, type='AHCI')] + [share(99)]}
    assert service.validate_slots(packed) is False  # 1 + 1 + 1 slots


# --- validation ------------------------------------------------------------------------

def make_device_service():
    service = object.__new__(VMDeviceService)
    service.middleware = AsyncMock()
    service.middleware.call = AsyncMock(return_value=[])
    return service


def vm_with(*devices, name='guest'):
    return {'id': 7, 'name': name, 'arch': 'amd64', 'bootloader': 'UEFI', 'devices': list(devices)}


async def validate(service, device, vm):
    with patch.object(vm_module, 'check_path_resides_within_volume', AsyncMock()):
        return await service.validate_device(device, None, vm)


async def test_shared_directory_must_be_an_existing_directory_under_mnt(tmp_path):
    service = make_device_service()

    with pytest.raises(ValidationErrors) as error:
        await validate(service, share(1, source='/etc'), vm_with())
    assert error.value.errors[0].attribute == 'attributes.source'

    with pytest.raises(ValidationErrors) as error:
        await validate(service, share(1, source='/mnt/tank/nowhere'), vm_with())
    assert error.value.errors[0].attribute == 'attributes.source'

    with patch.object(os.path, 'isdir', return_value=True):
        assert (await validate(service, share(1), vm_with()))['attributes']['tag'] == 'shared'


async def test_a_tag_is_unique_within_a_vm():
    service = make_device_service()
    existing = share(1, source='/mnt/tank/a', tag='data')

    with patch.object(os.path, 'isdir', return_value=True):
        with pytest.raises(ValidationErrors) as error:
            await validate(service, share(2, source='/mnt/tank/b', tag='data'), vm_with(existing))
        assert error.value.errors[0].attribute == 'attributes.tag'
        # editing the same device keeps its own tag
        edited = dict(existing, attributes=dict(existing["attributes"], readonly=True))
        await validate(service, edited, vm_with(existing))
        # another VM may use the same tag
        await validate(service, share(2, source='/mnt/tank/b', tag='data'), vm_with(name='other'))


def unsaved(device):
    """A device as vm.create validates it: in the VM's list, without an id yet."""
    return {key: value for key, value in device.items() if key != 'id'}


async def test_a_vm_being_created_does_not_collide_a_share_with_itself():
    """Seen on a test VM: during vm.create the device is in vm_instance['devices'] itself."""
    service = make_device_service()
    first = unsaved(share(1, source='/mnt/tank/a', tag='data'))
    second = unsaved(share(2, source='/mnt/tank/b', tag='other'))
    clash = unsaved(share(3, source='/mnt/tank/c', tag='data'))

    with patch.object(os.path, 'isdir', return_value=True):
        await validate(service, first, vm_with(first, second))
        await validate(service, second, vm_with(first, second))
        with pytest.raises(ValidationErrors) as error:
            await validate(service, clash, vm_with(first, second, clash))
        assert error.value.errors[0].attribute == 'attributes.tag'
