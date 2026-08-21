from pathlib import Path

import pytest

from middlewared.plugins.vm_.bootloader import (
    grub_bootloader_unsupported_reason, unsupported_bootloader_reason,
    GRUB_UNSUPPORTED_REASON, UEFI_CSM_UNSUPPORTED_REASON,
)


@pytest.mark.parametrize('bootloader', ['GRUB', 'grub', ' grub '])
def test__stored_grub_record_has_actionable_15_1_tombstone_error(bootloader):
    reason = grub_bootloader_unsupported_reason(bootloader)

    assert reason == GRUB_UNSUPPORTED_REASON
    assert 'ordinary UEFI' in reason
    assert 'FreeCORE 15.0' in reason


@pytest.mark.parametrize('bootloader', [None, 'UEFI', 'UEFI_CSM', ''])
def test__non_grub_bootloader_has_no_grub_inventory_error(bootloader):
    assert grub_bootloader_unsupported_reason(bootloader) is None


@pytest.mark.parametrize(('bootloader', 'expected'), [
    ('GRUB', GRUB_UNSUPPORTED_REASON),
    (' grub ', GRUB_UNSUPPORTED_REASON),
    ('UEFI_CSM', UEFI_CSM_UNSUPPORTED_REASON),
    (' uefi_csm ', UEFI_CSM_UNSUPPORTED_REASON),
])
def test__stored_retired_bootloader_has_actionable_15_1_tombstone_error(bootloader, expected):
    reason = unsupported_bootloader_reason(bootloader)

    assert reason == expected
    assert 'ordinary UEFI' in reason


@pytest.mark.parametrize('bootloader', [None, 'UEFI', ''])
def test__supported_or_absent_bootloader_has_no_tombstone_error(bootloader):
    assert unsupported_bootloader_reason(bootloader) is None


def test__vm_service_has_only_ordinary_uefi_executable_and_input_schema_path():
    source = (Path(__file__).resolve().parents[3] / 'plugins/vm.py').read_text()

    assert '/usr/local/sbin/grub-bhyve' not in source
    assert "create_element('bootloader'" not in source
    assert "create_element('bootloader_args'" not in source
    assert "Str('grubconfig'" not in source
    assert 'grubconfig = sa.Column' not in source
    assert 'BHYVE_UEFI_CSM.fd' not in source
    assert "enum=['UEFI']" in source


def test__stale_retired_bootloader_record_allows_whole_vm_deletion_but_not_device_mutation():
    source = (Path(__file__).resolve().parents[3] / 'plugins/vm.py').read_text()

    assert "await self.ensure_parent_vm_supported(data['vm'])" in source
    assert "await self.ensure_parent_vm_supported(device['vm'])" in source
    assert "await self.ensure_parent_vm_supported(new['vm'])" in source
    assert "unsupported_reason = unsupported_bootloader_reason(vm.get('bootloader'))" in source
    assert "if unsupported_bootloader_reason(vm.get('bootloader'))" in source
    assert "await self.middleware.call('datastore.delete', 'vm.device', device['id'])" in source
    assert "await self.middleware.call('vm.device.delete', device['id'])" in source
