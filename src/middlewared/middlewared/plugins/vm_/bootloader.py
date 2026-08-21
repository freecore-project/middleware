GRUB_BOOTLOADER = 'GRUB'
GRUB_BHYVE_BINARY = '/usr/local/sbin/grub-bhyve'


def grub_bootloader_reject_reason(old_bootloader, new_bootloader):
    if new_bootloader == GRUB_BOOTLOADER and old_bootloader != GRUB_BOOTLOADER:
        return (
            'New GRUB VM configurations are disabled because grub2-bhyve is deprecated. '
            'Use UEFI or UEFI_CSM. Existing GRUB VMs may keep their current bootloader or migrate away from it.'
        )

    return None


def classify_grubconfig(grubconfig):
    """
    Return `(kind, path)` for a VM's stored `grubconfig`.

    `VMSupervisor` treats a value beginning with `/mnt` as the path of an existing `grub.cfg` and
    anything else as the literal file content it writes out itself, so the two have different
    failure modes and must be reported apart.  `kind` is one of `path`, `inline` or `none`; `path`
    is only set for the `path` kind.
    """
    config = (grubconfig or '').strip()
    if not config:
        return 'none', None
    if config.startswith('/mnt'):
        return 'path', config

    return 'inline', None


def grub_vm_report(vm, binary_present, config_path_exists=None):
    """
    Build the the internal security review Phase 1 read-only record for one GRUB VM.

    `startable` mirrors exactly what the start path enforces today -- the `grub-bhyve` binary must
    exist, and a `/mnt` style `grubconfig` must resolve -- so it is a statement about this appliance,
    not a prediction about whether the guest's own boot media works.  `concerns` carries everything
    an operator should look at before migrating, including conditions that do not block a start.
    """
    kind, path = classify_grubconfig(vm.get('grubconfig'))

    blocking = []
    if not binary_present:
        blocking.append(f'{GRUB_BHYVE_BINARY} is not installed, so this VM cannot start')
    if kind == 'path' and not config_path_exists:
        blocking.append(f'the configured grubconfig path {path!r} does not exist')

    concerns = list(blocking)
    if kind == 'none':
        concerns.append('no grubconfig is stored, so grub-bhyve has no configuration to boot from')

    return {
        'id': vm.get('id'),
        'name': vm.get('name'),
        'grubconfig_kind': kind,
        'grubconfig_path': path,
        'grubconfig_path_exists': config_path_exists if kind == 'path' else None,
        'bootloader_binary_present': binary_present,
        'startable': not blocking,
        'concerns': concerns,
    }
