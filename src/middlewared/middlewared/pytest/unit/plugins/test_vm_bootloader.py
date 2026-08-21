import pytest

from middlewared.plugins.vm_.bootloader import (
    classify_grubconfig, grub_bootloader_reject_reason, grub_vm_report, GRUB_BHYVE_BINARY,
)


@pytest.mark.parametrize('old_bootloader,new_bootloader', [
    (None, 'GRUB'),
    ('UEFI', 'GRUB'),
    ('UEFI_CSM', 'GRUB'),
])
def test__new_grub_configuration_is_rejected(old_bootloader, new_bootloader):
    reason = grub_bootloader_reject_reason(old_bootloader, new_bootloader)

    assert reason is not None
    assert 'Use UEFI or UEFI_CSM' in reason


@pytest.mark.parametrize('old_bootloader,new_bootloader', [
    (None, 'UEFI'),
    (None, 'UEFI_CSM'),
    ('UEFI', 'UEFI'),
    ('UEFI_CSM', 'UEFI_CSM'),
    ('GRUB', 'GRUB'),
    ('GRUB', 'UEFI'),
    ('GRUB', 'UEFI_CSM'),
])
def test__supported_or_existing_grub_configuration_is_allowed(old_bootloader, new_bootloader):
    assert grub_bootloader_reject_reason(old_bootloader, new_bootloader) is None


@pytest.mark.parametrize('grubconfig,expected_kind,expected_path', [
    ('/mnt/tank/vms/grub.cfg', 'path', '/mnt/tank/vms/grub.cfg'),
    ('  /mnt/tank/vms/grub.cfg  ', 'path', '/mnt/tank/vms/grub.cfg'),
    ('linux /boot/vmlinuz\ninitrd /boot/initrd\nboot', 'inline', None),
    ('', 'none', None),
    ('   ', 'none', None),
    (None, 'none', None),
])
def test__grubconfig_is_classified_the_way_the_start_path_reads_it(
    grubconfig, expected_kind, expected_path
):
    assert classify_grubconfig(grubconfig) == (expected_kind, expected_path)


def test__resolvable_path_config_is_startable():
    report = grub_vm_report(
        {'id': 3, 'name': 'legacy', 'grubconfig': '/mnt/tank/grub.cfg'},
        binary_present=True,
        config_path_exists=True,
    )

    assert report['id'] == 3 and report['name'] == 'legacy'
    assert report['grubconfig_kind'] == 'path'
    assert report['grubconfig_path'] == '/mnt/tank/grub.cfg'
    assert report['grubconfig_path_exists'] is True
    assert report['startable'] is True
    assert report['concerns'] == []


def test__missing_grubconfig_path_blocks_start():
    report = grub_vm_report(
        {'id': 1, 'name': 'stale', 'grubconfig': '/mnt/tank/gone.cfg'},
        binary_present=True,
        config_path_exists=False,
    )

    assert report['startable'] is False
    assert any('does not exist' in c for c in report['concerns'])


def test__absent_binary_blocks_every_grub_vm():
    """The package-less case the internal security review Phase 4 must report rather than crash."""
    report = grub_vm_report(
        {'id': 2, 'name': 'inline', 'grubconfig': 'linux /boot/vmlinuz'},
        binary_present=False,
    )

    assert report['grubconfig_kind'] == 'inline'
    assert report['bootloader_binary_present'] is False
    assert report['startable'] is False
    assert any(GRUB_BHYVE_BINARY in c for c in report['concerns'])


def test__inline_config_needs_no_path_check():
    report = grub_vm_report(
        {'id': 4, 'name': 'inline', 'grubconfig': 'linux /boot/vmlinuz'},
        binary_present=True,
    )

    assert report['grubconfig_path'] is None
    assert report['grubconfig_path_exists'] is None
    assert report['startable'] is True


def test__absent_grubconfig_is_a_concern_but_not_a_start_blocker():
    """The start path only refuses a missing /mnt file, so do not overstate this one."""
    report = grub_vm_report(
        {'id': 5, 'name': 'empty', 'grubconfig': None}, binary_present=True
    )

    assert report['grubconfig_kind'] == 'none'
    assert report['startable'] is True
    assert any('no grubconfig is stored' in c for c in report['concerns'])
