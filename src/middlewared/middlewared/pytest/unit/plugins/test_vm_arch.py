"""The QEMU lane beside bhyve: the architecture table and the domain XML it produces.

the internal development record. These run off-box: no libvirt daemon, no middleware, the
supervisor is assembled by hand around its XML builders.
"""
from xml.etree import ElementTree as etree

import pytest

from middlewared.plugins import vm as vm_module
from middlewared.plugins.vm import VMSupervisor, qemu_disk_target
from middlewared.plugins.vm_.arch import (
    ARCH_CHOICES, BHYVE, QEMU, LIBVIRT_QEMU_DRIVER, device_rejection_reason, emulated_lane_reason,
    hypervisor_for, is_emulated, normalize_arch,
)


def make_supervisor(arch, devices):
    supervisor = object.__new__(VMSupervisor)
    supervisor.vm_data = {
        'id': 7, 'name': 'guest', 'description': 'a guest', 'vcpus': 2, 'cores': 1, 'threads': 1,
        'memory': 2048, 'time': 'LOCAL', 'bootloader': 'UEFI', 'arch': arch, 'devices': devices,
    }
    supervisor.middleware = None
    supervisor.arch = normalize_arch(arch)
    supervisor.hypervisor = hypervisor_for(arch)
    supervisor.libvirt_domain_name = '7_guest'
    supervisor.devices = [
        getattr(vm_module, device['dtype'])(device, None)
        for device in sorted(devices, key=lambda d: (d['order'], d['id']))
    ]
    return supervisor


def disk(id, path='/dev/zvol/tank/vm/guest', type='VIRTIO', order=1001):
    return {
        'id': id, 'dtype': 'DISK', 'order': order,
        'attributes': {'path': path, 'type': type, 'logical_sectorsize': None, 'physical_sectorsize': None},
    }


def cdrom(id, order=1000):
    return {'id': id, 'dtype': 'CDROM', 'order': order, 'attributes': {'path': '/mnt/tank/iso/install.iso'}}


def nic(id, type='VIRTIO'):
    return {
        'id': id, 'dtype': 'NIC', 'order': 1002,
        'attributes': {'type': type, 'nic_attach': 'bridge0', 'mac': '00:a0:98:11:22:33'},
    }


def vnc(id, wait=False, password=None):
    return {
        'id': id, 'dtype': 'VNC', 'order': 1002,
        'attributes': {
            'vnc_port': 5907, 'vnc_bind': '0.0.0.0', 'vnc_resolution': '1280x720', 'wait': wait,
            'vnc_password': password, 'vnc_web': True,
        },
    }


# --- the table -------------------------------------------------------------------------

def test_amd64_is_the_default_and_runs_on_bhyve():
    assert ARCH_CHOICES[0] == 'amd64'
    assert hypervisor_for('amd64') == BHYVE
    assert hypervisor_for(None) == BHYVE, 'a row from before the column is an amd64 VM'
    assert not is_emulated('amd64')


@pytest.mark.parametrize('arch', ['aarch64', 'riscv64'])
def test_other_architectures_are_emulated(arch):
    assert hypervisor_for(arch) == QEMU
    assert is_emulated(arch)


def test_emulated_lane_needs_the_driver_and_the_emulator():
    assert emulated_lane_reason('amd64', exists=lambda p: False) is None
    assert 'QEMU driver' in emulated_lane_reason('aarch64', exists=lambda p: False)
    assert 'qemu-system-aarch64' in emulated_lane_reason('aarch64', exists=lambda p: p == LIBVIRT_QEMU_DRIVER)
    assert emulated_lane_reason('aarch64', exists=lambda p: True) is None


@pytest.mark.parametrize('device,attribute', [
    (disk(1, type='AHCI'), 'attributes.type'),
    ({'dtype': 'RAW', 'attributes': {'path': '/mnt/x', 'type': 'AHCI'}}, 'attributes.type'),
    ({'dtype': 'RAW', 'attributes': {'path': '/mnt/x'}}, 'attributes.type'),
    (nic(1, type='E1000'), 'attributes.type'),
    ({'dtype': 'PCI', 'attributes': {'pptdev': '1/0/0'}}, 'dtype'),
    (vnc(1, wait=True), 'attributes.wait'),
])
def test_emulated_guests_refuse_what_the_virt_machine_lacks(device, attribute):
    rejected = device_rejection_reason('aarch64', device)
    assert rejected is not None and rejected[0] == attribute


@pytest.mark.parametrize('device', [disk(1), nic(1), vnc(1), cdrom(1)])
def test_emulated_guests_accept_virtio_and_media(device):
    assert device_rejection_reason('riscv64', device) is None


def test_native_guests_are_not_restricted():
    assert device_rejection_reason('amd64', {'dtype': 'PCI', 'attributes': {'pptdev': '1/0/0'}}) is None
    assert device_rejection_reason('amd64', disk(1, type='AHCI')) is None


def test_disk_target_names_are_what_libvirt_validates():
    assert [qemu_disk_target('vd', i) for i in (0, 1, 25, 26, 27)] == ['vda', 'vdb', 'vdz', 'vdaa', 'vdab']


# --- the XML ---------------------------------------------------------------------------

def test_aarch64_domain_is_a_qemu_virt_machine_with_uefi():
    supervisor = make_supervisor('aarch64', [cdrom(1), disk(2), nic(3), vnc(4, password='s3cret')])
    root = supervisor.construct_xml()

    assert root.tag == 'domain' and root.get('type') == 'qemu'
    assert not [k for k in root.attrib if 'bhyve' in k], 'no bhyve namespace on a QEMU domain'
    assert root.find('devices/emulator').text == '/usr/local/bin/qemu-system-aarch64'
    os_type = root.find('os/type')
    assert (os_type.get('arch'), os_type.get('machine'), os_type.text) == ('aarch64', 'virt', 'hvm')
    loader = root.find('os/loader')
    assert (loader.get('type'), loader.get('readonly'), loader.text) == (
        'pflash', 'yes', '/usr/local/share/qemu/edk2-aarch64-code.fd',
    )
    nvram = root.find('os/nvram')
    assert nvram.get('template') == '/usr/local/share/qemu/edk2-arm-vars.fd'
    assert nvram.text == '/var/lib/libvirt/qemu/nvram/vm7_VARS.fd', 'keyed by id so a rename keeps the variables'
    assert root.find('cpu').get('mode') == 'maximum'
    assert root.find('cpu/topology').get('sockets') == '2'
    assert root.find('vcpu').text == '2'
    assert root.find('memory').text == '2048' and root.find('memory').get('unit') == 'M'
    assert root.find('features/acpi') is not None
    assert root.find('features/gic').get('version') == '3'
    assert root.find('features/msrs') is None, 'msrs is a bhyve-only feature'
    assert root.find('memoryBacking') is None


def test_qemu_devices_boot_media_first_and_share_the_bhyve_console():
    supervisor = make_supervisor('aarch64', [disk(2), cdrom(1), nic(3), vnc(4, password='s3cret')])
    devices = supervisor.construct_xml().find('devices')

    disks = devices.findall('disk')
    assert [(d.get('device'), d.find('target').get('dev'), d.find('target').get('bus'), d.find('boot').get('order'))
            for d in disks] == [('cdrom', 'sda', 'scsi', '1'), ('disk', 'vda', 'virtio', '2')]
    zvol = disks[1]
    assert zvol.get('type') == 'block' and zvol.find('source').get('dev') == '/dev/zvol/tank/vm/guest'
    assert zvol.find('driver').attrib == {'name': 'qemu', 'type': 'raw'}
    assert disks[0].find('readonly') is not None
    assert devices.find("controller[@type='scsi']").get('model') == 'virtio-scsi'
    assert devices.find("controller[@type='usb']").get('model') == 'qemu-xhci'

    interface = devices.find('interface')
    assert interface.get('type') == 'bridge'
    assert interface.find('model').get('type') == 'virtio'
    assert interface.find('mac').get('address') == '00:a0:98:11:22:33'
    assert interface.find('address') is None, 'libvirt assigns PCIe addresses on the virt machine'

    graphics = devices.find('graphics')
    assert graphics.attrib == {'type': 'vnc', 'port': '5907', 'autoport': 'no', 'listen': '0.0.0.0', 'passwd': 's3cret'}
    assert devices.find('video/model').get('type') == 'virtio'
    assert devices.find('video/model/resolution').attrib == {'x': '1280', 'y': '720'}
    assert {i.get('type') for i in devices.findall('input')} == {'tablet', 'keyboard'}

    serial = devices.find('serial')
    assert serial.get('type') == 'dev'
    assert serial.find('source').get('path') == '/dev/nmdm7A', 'same pair as bhyve: cu -l nmdm7B still works'


def test_riscv64_console_is_a_ramfb_display():
    # the internal development record: <model type='virtio'> is virtio-vga on riscv64, which the riscv64 EDK2 never
    # initializes (VNC dark); ramfb is what it draws on. aarch64 keeps virtio (virtio-gpu, driven by EDK2).
    devices = make_supervisor('riscv64', [disk(2), vnc(4)]).construct_xml().find('devices')
    assert devices.find('graphics').get('type') == 'vnc'
    assert devices.find('video/model').attrib == {'type': 'ramfb'}
    assert devices.find('video/model/resolution') is None, 'ramfb takes its mode from the firmware'
    assert len(devices.findall('video')) == 1

    aarch64 = make_supervisor('aarch64', [disk(2), vnc(4)]).construct_xml().find('devices')
    assert aarch64.find('video/model').get('type') == 'virtio'


def test_every_emulated_architecture_names_its_display():
    from middlewared.plugins.vm_.arch import ARCHES
    for arch, profile in ARCHES.items():
        if profile['hypervisor'] == QEMU:
            assert profile.get('video') in ('virtio', 'ramfb'), arch


def test_raw_file_is_a_file_disk_and_riscv64_has_no_gic():
    raw = {'id': 2, 'dtype': 'RAW', 'order': 1001, 'attributes': {
        'path': '/mnt/tank/vm/guest.img', 'type': 'VIRTIO', 'logical_sectorsize': 4096, 'physical_sectorsize': 4096,
    }}
    root = make_supervisor('riscv64', [raw]).construct_xml()

    assert root.find('devices/emulator').text == '/usr/local/bin/qemu-system-riscv64'
    assert root.find('os/loader').text == '/usr/local/share/qemu/edk2-riscv-code.fd'
    assert root.find('features') is None
    disk_xml = root.find('devices/disk')
    assert disk_xml.get('type') == 'file' and disk_xml.find('source').get('file') == '/mnt/tank/vm/guest.img'
    assert disk_xml.find('blockio').attrib == {'logical_block_size': '4096', 'physical_block_size': '4096'}


def test_amd64_domain_is_unchanged_bhyve():
    supervisor = make_supervisor('amd64', [disk(2, type='AHCI'), nic(3, type='E1000'), vnc(4)])
    root = supervisor.construct_xml()

    assert root.get('type') == 'bhyve'
    assert root.find('devices/emulator') is None
    assert root.find('os/type').attrib == {}, 'no arch or machine on the bhyve domain'
    assert root.find('os/loader').text == '/usr/local/share/uefi-firmware/BHYVE_UEFI.fd'
    assert root.find('features/msrs').get('unknown') == 'ignore'
    assert root.find('devices/serial').get('type') == 'nmdm'
    assert root.find('devices/graphics') is None, 'bhyve renders VNC as a command-line argument'
    # The whole document still serialises: the bhyve namespace is intact.
    assert b'commandline' in etree.tostring(root)


# --- host pid resolution (the internal development record) ----------------------------------------

def test_bhyve_host_pid_is_the_libvirt_domain_id():
    """libvirt's bhyve driver uses the bhyve process pid as the domain id, so ID() is it."""
    supervisor = make_supervisor('amd64', [disk(1, type='AHCI')])
    supervisor.domain = type('D', (), {'ID': staticmethod(lambda: 4242)})()
    assert supervisor.host_pid() == 4242


def test_qemu_host_pid_comes_from_the_pidfile_not_the_domain_id(tmp_path, monkeypatch):
    """The qemu driver's domain id is sequential; the real pid is in the pidfile."""
    supervisor = make_supervisor('aarch64', [disk(1)])
    supervisor.domain = type('D', (), {'ID': staticmethod(lambda: 1)})()
    pidfile = tmp_path / '7_guest.pid'
    pidfile.write_text('50931\n')

    real_open = open
    monkeypatch.setattr('builtins.open', lambda p, *a, **k: real_open(pidfile, *a, **k)
                        if p == '/var/run/libvirt/qemu/7_guest.pid' else real_open(p, *a, **k))
    assert supervisor.host_pid() == 50931


def test_qemu_host_pid_is_none_when_the_pidfile_is_absent(monkeypatch):
    supervisor = make_supervisor('aarch64', [disk(1)])
    supervisor.domain = type('D', (), {'ID': staticmethod(lambda: 1)})()

    def boom(p, *a, **k):
        raise FileNotFoundError(p)
    monkeypatch.setattr('builtins.open', boom)
    assert supervisor.host_pid() is None
