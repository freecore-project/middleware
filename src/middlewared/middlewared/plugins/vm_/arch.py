"""The guest architectures a VM can have, and which driver runs each one.

amd64 is the host's own architecture and runs natively on bhyve.  Everything else is
emulated by QEMU with TCG: there is no accelerator on FreeBSD, so such a guest is
usable and slow, and that sentence must survive into every user-facing surface.

This table is the one place an architecture is added.  the internal development record.
"""
import os

BHYVE = 'bhyve'
QEMU = 'qemu'

NATIVE_ARCH = 'amd64'

QEMU_BIN_DIR = '/usr/local/bin'
QEMU_DATA_DIR = '/usr/local/share/qemu'
LIBVIRT_QEMU_DRIVER = '/usr/local/lib/libvirt/connection-driver/libvirt_driver_qemu.so'

ARCHES = {
    'amd64': {
        'label': 'amd64 (native, bhyve)',
        'hypervisor': BHYVE,
    },
    'aarch64': {
        'label': 'aarch64 (emulated, QEMU)',
        'hypervisor': QEMU,
        'emulator': f'{QEMU_BIN_DIR}/qemu-system-aarch64',
        'machine': 'virt',
        'loader': f'{QEMU_DATA_DIR}/edk2-aarch64-code.fd',
        'nvram_template': f'{QEMU_DATA_DIR}/edk2-arm-vars.fd',
        'acpi': True,
        'gic': '3',
    },
    'riscv64': {
        'label': 'riscv64 (emulated, QEMU)',
        'hypervisor': QEMU,
        'emulator': f'{QEMU_BIN_DIR}/qemu-system-riscv64',
        'machine': 'virt',
        'loader': f'{QEMU_DATA_DIR}/edk2-riscv-code.fd',
        'nvram_template': f'{QEMU_DATA_DIR}/edk2-riscv-vars.fd',
        # Device tree only: FreeBSD boots the virt machine from it, and libvirt's
        # ACPI support for riscv64 is not something this lane verifies.
        'acpi': False,
        'gic': None,
    },
}

ARCH_CHOICES = list(ARCHES)

EMULATED_CAVEAT = (
    'Emulated guests run under QEMU/TCG with no hardware acceleration: usable, slow. '
    'amd64 guests run natively on bhyve.'
)


def normalize_arch(arch):
    """A stored row from before the column existed is an amd64 VM."""
    return arch if arch in ARCHES else NATIVE_ARCH


def arch_profile(arch):
    return ARCHES[normalize_arch(arch)]


def hypervisor_for(arch):
    return arch_profile(arch)['hypervisor']


def is_emulated(arch):
    return hypervisor_for(arch) == QEMU


def emulated_lane_reason(arch, exists=os.path.exists):
    """Why an emulated architecture cannot run on this host, or None when it can.

    ``exists`` is injectable so the table can be tested without the packages.
    """
    profile = arch_profile(arch)
    if profile['hypervisor'] != QEMU:
        return None
    if not exists(LIBVIRT_QEMU_DRIVER):
        return 'libvirt on this system was built without its QEMU driver.'
    for key in ('emulator', 'loader', 'nvram_template'):
        if not exists(profile[key]):
            return f'{profile[key]} is not installed.'
    return None


# What the QEMU "virt" machine gets: paravirtual disks and NICs, no passthrough, and
# no way to hold the guest at the firmware until a VNC client attaches.
EMULATED_DEVICE_RULES = {
    'DISK': ('type', 'VIRTIO', 'Emulated guests support VirtIO disks only.'),
    'RAW': ('type', 'VIRTIO', 'Emulated guests support VirtIO disks only.'),
    'NIC': ('type', 'VIRTIO', 'Emulated guests support VirtIO network adapters only.'),
    'VNC': ('wait', False, 'Emulated guests cannot wait for a VNC connection before booting.'),
}


def device_rejection_reason(arch, device):
    """(attribute, message) when ``device`` cannot be attached to an ``arch`` guest, else None."""
    if not is_emulated(arch):
        return None
    dtype = device.get('dtype')
    if dtype == 'PCI':
        return 'dtype', 'PCI passthrough is not available to emulated guests.'
    if dtype == 'FILESYSTEM':
        return 'dtype', 'Shared directories (virtio-9p) are available to bhyve guests only.'
    rule = EMULATED_DEVICE_RULES.get(dtype)
    if rule is None:
        return None
    attribute, wanted, message = rule
    attributes = device.get('attributes') or {}
    # A schema default that was never sent is the default the lane rejects, so an
    # absent attribute is judged by what the schema will fill in.
    actual = attributes.get(attribute, 'AHCI' if attribute == 'type' and dtype != 'NIC' else
                            'E1000' if attribute == 'type' else False)
    if actual != wanted:
        return f'attributes.{attribute}', message
    return None
