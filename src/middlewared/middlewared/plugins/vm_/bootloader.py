GRUB_BOOTLOADER = 'GRUB'
GRUB_UNSUPPORTED_REASON = (
    'GRUB virtual machines are unsupported in FreeCORE 15.1. '
    'Migrate this VM to ordinary UEFI while running FreeCORE 15.0, delete the VM record, '
    'or remain on the FreeCORE 15.0 line.'
)
UEFI_CSM_BOOTLOADER = 'UEFI_CSM'
UEFI_CSM_UNSUPPORTED_REASON = (
    'UEFI-CSM virtual machines are unsupported in FreeCORE 15.1 because the required legacy firmware '
    'is not shipped. Boot FreeCORE 15.0 to verify the guest boot media and migrate this VM record to '
    'ordinary UEFI, or delete the VM record. No automatic conversion was performed.'
)


def normalize_bootloader(bootloader):
    return bootloader.strip().upper() if isinstance(bootloader, str) else None


def grub_bootloader_unsupported_reason(bootloader):
    """Return the 15.1 tombstone error for a stored GRUB VM record."""
    return GRUB_UNSUPPORTED_REASON if normalize_bootloader(bootloader) == GRUB_BOOTLOADER else None


def unsupported_bootloader_reason(bootloader):
    """Return the 15.1 tombstone error for any retired VM bootloader."""
    return {
        GRUB_BOOTLOADER: GRUB_UNSUPPORTED_REASON,
        UEFI_CSM_BOOTLOADER: UEFI_CSM_UNSUPPORTED_REASON,
    }.get(normalize_bootloader(bootloader))
