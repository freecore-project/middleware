"""Moving to TrueNAS SCALE in place (the internal development record)."""
import os
import sqlite3
from types import SimpleNamespace

import pytest

from middlewared.plugins.config_ import scale as scale_config
from middlewared.plugins.update_ import scale_sidegrade as sidegrade
from middlewared.service_exception import CallError

FREECORE_HEAD = 'b7e3d19a5c42'


def make_database(path, revision, tables):
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)')
        connection.execute('INSERT INTO alembic_version VALUES (?)', (revision,))
        for table in tables:
            connection.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY)')
    return str(path)


def test_the_manifest_is_read_out_of_the_update_file_without_extracting_it():
    calls = []

    def run(argv, capture_output=None, text=None, check=None):
        calls.append(argv)
        return SimpleNamespace(stdout='{"version": "24.04.2.5", "kernel_version": "6.6.44-production+truenas"}')

    assert sidegrade.read_manifest('/var/tmp/firmware/manualupdate.tar', run=run)['version'] == '24.04.2.5'
    assert calls == [['unsquashfs', '-cat', '/var/tmp/firmware/manualupdate.tar', 'manifest.json']]

    def broken(argv, **kwargs):
        raise OSError('unsquashfs: not a squashfs')
    with pytest.raises(CallError, match='not a TrueNAS SCALE update file'):
        sidegrade.read_manifest('/x', run=broken)
    with pytest.raises(CallError, match='not a TrueNAS SCALE update file'):
        sidegrade.read_manifest('/x', run=lambda *a, **k: SimpleNamespace(stdout='not json'))


def test_only_a_24_04_release_passes_the_gate():
    assert sidegrade.parse_release('24.04.2.5') == (24, 4)
    assert sidegrade.parse_release('26.0.0-BETA.3') == (26, 0)
    assert sidegrade.parse_release('MASTER') is None
    assert sidegrade.check_target({'version': '24.04.2.5'}) == (24, 4)
    assert sidegrade.check_target({'version': '24.04.0'}) == (24, 4)
    assert sidegrade.check_target({'version': '23.10.2'}) == (23, 10)
    for version in ('24.10.0', '24.10.2.3', '25.04.2.6', '25.10.7', '26.0.0-BETA.3'):
        with pytest.raises(CallError, match='(?s)refuses to run here.*24.04 update file.*Save Config'):
            sidegrade.check_target({'version': version})
    with pytest.raises(CallError, match='does not say which'):
        sidegrade.check_target({'version': 'MASTER'})
    with pytest.raises(CallError, match='does not say which'):
        sidegrade.check_target({})


def test_the_image_must_carry_grub_for_freebsd():
    sidegrade.check_tools(which=lambda tool: f'/usr/local/sbin/{tool}')
    with pytest.raises(CallError, match='GRUB for FreeBSD \\(grub-probe, grub-mkconfig\\)'):
        sidegrade.check_tools(which=lambda tool: '/usr/local/sbin/grub-install' if tool == 'grub-install' else None)


# --- the internal development record: BIOS systems --------------------------------------------------------------

def test_the_boot_method_is_the_loaders_sysctl():
    def run(output=None, fail=False):
        def runner(cmd, **kwargs):
            assert cmd == ['sysctl', '-n', 'machdep.bootmethod']
            if fail:
                raise sidegrade.subprocess.CalledProcessError(1, cmd)
            return SimpleNamespace(stdout=output)
        return runner
    assert sidegrade.boot_method(run('BIOS\n')) == 'BIOS'
    assert sidegrade.boot_method(run('UEFI\n')) == 'UEFI'
    assert sidegrade.boot_method(run('\n')) is None
    assert sidegrade.boot_method(run(fail=True)) is None


def test_a_bios_system_needs_grubs_i386_pc_files():
    present = lambda path: True  # noqa: E731
    sidegrade.check_bios_grub('BIOS', exists=present)
    # the RC8 image: the .lst/.img files are there, every module and kernel.img were deleted (the internal development record)
    rc8 = lambda path: not path.endswith(('.mod', 'kernel.img'))  # noqa: E731
    with pytest.raises(CallError, match='boots through the BIOS.*kernel.img, normal.mod, biosdisk.mod, part_gpt.mod, '
                                        'zfs.mod, crypto.mod in /usr/local/lib/grub/i386-pc.*Nothing was changed'):
        sidegrade.check_bios_grub('BIOS', exists=rc8)
    # UEFI does not use the i386-pc platform; an unreadable boot method does not block either
    sidegrade.check_bios_grub('UEFI', exists=rc8)
    sidegrade.check_bios_grub(None, exists=rc8)


GPART_BIOS = """=>      40  67108784  vtbd0  GPT  (32G)
        40        24         - free -  (12K)
        64      1024      1  freebsd-boot  (512K)
      1088  67076096      2  freebsd-zfs  (32G)
  67077184     31640         - free -  (15M)
"""
GPART_RETYPED = GPART_BIOS.replace('freebsd-boot', 'bios-boot')
GPART_EFI = """=>      40  67108784  vtbd0  GPT  (32G)
        40    532480      1  efi  (260M)
    532520  66576384      2  freebsd-zfs  (32G)
"""


def gpart_run(outputs, calls=None, fail=()):
    def run(cmd, **kwargs):
        if calls is not None:
            calls.append(cmd)
        if cmd[:2] == ['gpart', 'show']:
            if cmd[2] not in outputs:
                raise sidegrade.subprocess.CalledProcessError(1, cmd)
            return SimpleNamespace(stdout=outputs[cmd[2]])
        if cmd[1] in fail:
            raise sidegrade.subprocess.CalledProcessError(1, cmd, stderr=f'gpart: {cmd[1]} refused\n')
        return SimpleNamespace(stdout='')
    return run


def test_the_freebsd_boot_partitions_are_read_before_the_install():
    mirror = {'vtbd0': GPART_BIOS, 'vtbd1': GPART_BIOS}
    assert sidegrade.bios_boot_partitions(['vtbd0', 'vtbd1'], gpart_run(mirror)) == [('vtbd0', 1), ('vtbd1', 1)]
    # a retyped partition (the state after iX's installer) or an EFI disk carries no freebsd-boot partition
    assert sidegrade.bios_boot_partitions(['vtbd0'], gpart_run({'vtbd0': GPART_RETYPED})) == []
    assert sidegrade.bios_boot_partitions(['vtbd0'], gpart_run({'vtbd0': GPART_EFI})) == []
    # a disk gpart cannot read is skipped, not fatal
    assert sidegrade.bios_boot_partitions(['vtbd0', 'gone'], gpart_run({'vtbd0': GPART_BIOS})) == [('vtbd0', 1)]


def test_the_restore_retypes_and_rewrites_freebsds_boot_code():
    calls = []
    assert sidegrade.restore_bios_boot([('vtbd0', 1), ('vtbd1', 1)], gpart_run({}, calls)) == []
    assert calls == [
        ['gpart', 'modify', '-i', '1', '-t', 'freebsd-boot', 'vtbd0'],
        ['gpart', 'bootcode', '-b', '/boot/pmbr', '-p', '/boot/gptzfsboot', '-i', '1', 'vtbd0'],
        ['gpart', 'modify', '-i', '1', '-t', 'freebsd-boot', 'vtbd1'],
        ['gpart', 'bootcode', '-b', '/boot/pmbr', '-p', '/boot/gptzfsboot', '-i', '1', 'vtbd1'],
    ]
    failures = sidegrade.restore_bios_boot([('vtbd0', 1)], gpart_run({}, fail=('modify',)))
    assert failures == ['gpart modify -i 1 -t freebsd-boot vtbd0: gpart: modify refused']


def test_the_error_says_whether_freecore_still_boots():
    done = sidegrade.bios_restore_message([('vtbd0', 1)], [])
    assert done == "FreeCORE's BIOS boot partition was restored (vtbd0 partition 1); FreeCORE boots as before."
    failed = sidegrade.bios_restore_message([('vtbd0', 1)], ['gpart modify ...: refused'])
    assert 'FreeCORE will not boot until it is restored' in failed
    assert ('gpart modify -i 1 -t freebsd-boot vtbd0 && gpart bootcode -b /boot/pmbr -p /boot/gptzfsboot -i 1 vtbd0'
            in failed)


def zdb_config(*ashifts):
    vdevs = ''.join(f'            children[{i}]:\n                type: \'disk\'\n                ashift: {a}\n'
                    for i, a in enumerate(ashifts))
    return f"boot-pool:\n    version: 5000\n    vdev_tree:\n        type: 'root'\n{vdevs}"


def zdb_run(output=None, fail=False):
    def run(cmd, **kwargs):
        assert cmd == ['zdb', '-C', 'boot-pool']
        if fail:
            raise sidegrade.subprocess.CalledProcessError(1, cmd)
        return SimpleNamespace(stdout=output, returncode=0)
    return run


@pytest.mark.parametrize('ashifts', [(9,), (12,), (13,), (12, 12)])
def test_a_boot_pool_grub_can_read_passes(ashifts):
    assert sidegrade.check_boot_pool('boot-pool', run=zdb_run(zdb_config(*ashifts))) == max(ashifts)


@pytest.mark.parametrize('ashifts', [(14,), (12, 14)])
def test_an_ashift_14_boot_pool_is_refused_before_anything_is_extracted(ashifts):
    """Found on the canary (RC6): a VM disk on a 16K zvol reports 16 KiB sectors, the boot pool gets
    ashift 14, and the 24.04 installer stopped at `grub-probe ... unknown filesystem`."""
    refused = 'ashift 14 .*reads ZFS only up to ashift 13. Nothing was changed.*clean install'
    with pytest.raises(CallError, match=refused):
        sidegrade.check_boot_pool('boot-pool', run=zdb_run(zdb_config(*ashifts)))


def test_an_unreadable_configuration_does_not_block_the_move():
    """The installer's own grub-probe still stands behind this; zdb failing is no reason to refuse."""
    assert sidegrade.check_boot_pool('boot-pool', run=zdb_run(fail=True)) is None
    assert sidegrade.check_boot_pool('boot-pool', run=zdb_run('boot-pool:\n    version: 5000\n')) is None


def test_the_staged_root_carries_the_13_3_copy_and_leaves_freecore_bookkeeping_behind(tmp_path):
    data = tmp_path / 'data'
    data.mkdir()
    live = make_database(data / 'freenas-v1.db', FREECORE_HEAD, ['account_bsdusers', 'services_wireguard'])
    before = open(live, 'rb').read()
    (data / 'pwenc_secret').write_bytes(b'seed')
    os.chmod(data / 'pwenc_secret', 0o600)
    (data / 'license').write_text('LICENSE')
    (data / 'zfs').mkdir()
    (data / 'zfs' / 'zpool.cache').write_bytes(b'cache')
    for left_behind in ('update.conf', 'manifest', 'factory-v1.db', 'freenas-v1.db.bak', 'need-update'):
        (data / left_behind).write_text('freecore')
    for directory in ('pkgdb', 'sentinels', 'crash'):
        (data / directory).mkdir()
        (data / directory / 'x').write_text('x')
    root = tmp_path / 'root'
    root.mkdir()
    hostid = tmp_path / 'hostid'
    hostid.write_text('12345678-1234-1234-1234-123456789abc\n')
    freebsd_version = tmp_path / 'freebsd-version'
    freebsd_version.write_text('#!/bin/sh\necho 15.1-RELEASE-p4\n')
    os.chmod(freebsd_version, 0o755)

    def build(source, workdir):
        # config_/scale.py's build, stood in for: a copy stamped 13.3 without the FreeCORE table.
        destination = os.path.join(workdir, 'freenas-v1.db')
        with sqlite3.connect(source) as origin, sqlite3.connect(destination) as copy:
            origin.backup(copy)
        with sqlite3.connect(destination) as copy:
            copy.execute('DROP TABLE services_wireguard')
            copy.execute('UPDATE alembic_version SET version_num = ?', (scale_config.SCALE_BASE_REVISION,))
        return destination, ['Add WireGuard server service']

    import subprocess
    mounts = []

    def run(argv, capture_output=None, text=None, check=None):
        if argv[0] in ('mount', 'umount'):
            mounts.append(argv)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        return subprocess.run(argv, capture_output=capture_output, text=text, check=check)

    staged = tmp_path / 'staged'
    staged.mkdir()
    undone = sidegrade.stage_old_root(
        str(staged), lambda undone: sidegrade.readme(undone, 'FreeCORE-15.1-MASTER', 'boot-pool/ROOT/default', []),
        data=str(data), root=str(root), hostid=str(hostid), freebsd_version=str(freebsd_version),
        build=build, run=run,
    )
    assert undone == ['Add WireGuard server service']
    assert (staged / 'bin' / 'freebsd-version').read_text().endswith('15.1-RELEASE-p4\n')
    assert (staged / 'etc' / 'hostid').read_text().startswith('12345678')
    assert scale_config.stamp(str(staged / 'data' / 'freenas-v1.db')) == scale_config.SCALE_BASE_REVISION
    assert 'services_wireguard' not in scale_config.tables(str(staged / 'data' / 'freenas-v1.db'))
    assert (staged / 'data' / 'pwenc_secret').read_bytes() == b'seed'
    assert oct(os.stat(staged / 'data' / 'pwenc_secret').st_mode & 0o777) == '0o600'
    assert (staged / 'data' / 'license').read_text() == 'LICENSE'
    assert (staged / 'data' / 'zfs' / 'zpool.cache').read_bytes() == b'cache'
    for left_behind in ('update.conf', 'manifest', 'factory-v1.db', 'freenas-v1.db.bak', 'need-update',
                        'pkgdb', 'sentinels', 'crash'):
        assert not (staged / 'data' / left_behind).exists(), left_behind
    text = (staged / 'data' / sidegrade.README_NAME).read_text()
    assert 'installed in place over FreeCORE-15.1-MASTER' in text and 'boot-pool/ROOT/default' in text
    # The way back proven on the canary: activate, then power off and on (a restart from SCALE kexecs past GRUB).
    assert 'shut' in text and 'power it on' in text and '"TrueNAS CORE" by default' in text
    assert '  - Add WireGuard server service' in text
    assert 'every pool uses only features' in text
    # /root travels as a nullfs mount, and the live database is only read.
    assert mounts == [['mount', '-t', 'nullfs', str(root), str(staged / 'root')]]
    assert open(live, 'rb').read() == before

    sidegrade.discard_staged_root(str(staged), run=run)
    assert mounts[-1] == ['umount', str(staged / 'root')]
    assert not staged.exists()


def test_the_readme_names_the_pool_line_and_the_way_back():
    text = sidegrade.readme([], 'FreeCORE-15.1-RC6', None, [
        'pool tank uses OpenZFS features TrueNAS SCALE 24.10.0 does not have: block_cloning_endian (in use) '
        '-- import the pool only on OpenZFS 2.4 (TrueNAS 26 or later)'
    ])
    assert '(unknown) still holds its own database' in text
    assert '(none: the database was already at 13.3)' in text
    assert '  - pool tank uses OpenZFS features' in text and 'TrueNAS 26 or later' in text
    assert 'Export for Linux' in text
    # The file left on SCALE names no internal tracker, even when a revision title does.
    tagged = sidegrade.readme(
        ['Scrub telemetry residue values (the internal development record)'], 'FreeCORE-15.1-RC6', None, [],
    )
    assert '  - Scrub telemetry residue values\n' in tagged and 'freecore/' not in tagged and '#' not in tagged
