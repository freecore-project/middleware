from pathlib import Path
import sqlite3
import subprocess

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
INSTALLER = REPOSITORY_ROOT / 'src/freenas-installer/etc/install.sh'
INSTALLER_PORT = REPOSITORY_ROOT / 'nas_ports/freenas/freenas-installer'


@pytest.mark.parametrize('interactive', [False, True])
@pytest.mark.parametrize('bootloader', ['GRUB', 'UEFI'])
def test_upgrade_preserves_vm_records_and_reaches_installation_boundary(
    tmp_path, interactive, bootloader,
):
    preserved = tmp_path / 'data_preserved'
    preserved.mkdir()
    database = preserved / 'freenas-v1.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE vm_vm (id INTEGER, name TEXT, bootloader TEXT)')
        connection.execute('INSERT INTO vm_vm VALUES (1, ?, ?)', ('existing_vm', bootloader))
    database.chmod(0o600)
    before = database.read_bytes()

    source = INSTALLER.read_text()
    start = source.index('menu_install_locked()\n')
    end = source.index('    # Start critical section.', start)
    # Execute the real menu flow only up to the destructive boundary. All
    # hardware/UI operations are stubbed and every temporary path is isolated.
    flow = source[start:end].replace('/tmp/', f'{tmp_path}/')
    flow += '    printf "ready:%s:%s\\n" "$_action" "$_do_upgrade"\n}\n'
    stubs = """
cleanup() { :; }
pre_install_check() { return 0; }
get_physical_disks_list() { VAL=testdisk; }
get_media_description() { echo fixture; }
dialog() { case "$*" in *--checklist*) echo testdisk >&2 ;; esac; }
disk_is_mounted() { return 1; }
disk_is_freenas() { return 0; }
ask_upgrade() { return 0; }
ask_upgrade_inplace() { return 0; }
new_install_verify() { printf 'confirmed:%s\\n' "$1"; }
abort() { echo aborted >&2; exit 99; }
# The retired admission check must never be called, even for a GRUB record.
validate_grub_upgrade() { echo obsolete-grub-gate >&2; return 1; }
"""
    arguments = '' if interactive else '-U true testdisk'
    result = subprocess.run(
        ['/bin/sh', '-c', stubs + flow + f'menu_install_locked {arguments}\n'],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    expected = ('confirmed:upgrade\n' if interactive else '') + 'ready:upgrade:1\n'
    assert result.stdout == expected
    assert result.stderr == ''
    assert database.read_bytes() == before
    assert database.stat().st_mode & 0o777 == 0o600


def test_installer_does_not_package_obsolete_grub_checker():
    makefile = (INSTALLER_PORT / 'Makefile').read_text()
    plist = (INSTALLER_PORT / 'pkg-plist').read_text()

    assert 'validate_grub_upgrade' not in INSTALLER.read_text()
    assert 'validate_grub_upgrade' not in makefile
    assert 'validate_grub_upgrade' not in plist
    assert not (INSTALLER.parent / 'validate_grub_upgrade.sh').exists()
