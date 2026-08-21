"""Moving to TrueNAS SCALE in place, with the database SCALE accepts (the internal development record).

13.3 could install a TrueNAS SCALE update file from System -> Update: the
file's own installer makes a new boot environment, copies ``/data`` into it
and installs GRUB, and SCALE's first boot runs its Alembic chain over the
copied database.  FreeCORE's database is stamped with revisions SCALE does
not know (the internal development record), so the copy the installer sees has to be
the 13.3-shaped one.  This module builds a staged root the installer reads
instead of ``/``: the live root, its database and the FreeCORE boot
environment are untouched, which is what the way back (GRUB "TrueNAS CORE"
-> the FreeBSD boot environment) relies on.

Only TrueNAS SCALE 24.04 can be installed this way: from 24.10 on, the
update file's installer exits when it finds itself on FreeBSD.
"""
import json
import os
import re
import shutil
import subprocess

from middlewared.plugins.config_ import scale as scale_config
from middlewared.service_exception import CallError

LAST_IN_PLACE_RELEASE = (24, 4)
GRUB_TOOLS = ('grub-install', 'grub-probe', 'grub-mkconfig')
# GRUB 2.05's ZFS reader (the version 13.3 shipped for this route) reads pools up to ashift 13;
# grub-probe calls an ashift-14 pool an "unknown filesystem" and the installer stops there.
GRUB_MAX_ASHIFT = 13
# the internal development record: what `grub-install --target=i386-pc` loads to build core.img for a GPT disk with a
# ZFS boot pool. A BIOS-booted system cannot be moved without them.
GRUB_I386_PC = '/usr/local/lib/grub/i386-pc'
GRUB_I386_PC_REQUIRED = ('kernel.img', 'normal.mod', 'biosdisk.mod', 'part_gpt.mod', 'zfs.mod', 'crypto.mod')
FREEBSD_BOOT = 'freebsd-boot'
README_NAME = scale_config.README_NAME
# What does not travel from /data: FreeCORE's own bookkeeping, the files the staged
# copy replaces, and update.conf, which would point SCALE's updater at FreeCORE's train.
DATA_EXCLUDE = frozenset({
    'freenas-v1.db', 'freenas-v1.db.bak', 'factory-v1.db', 'uploaded.db', 'pwenc_secret_uploaded',
    'update.conf', 'manifest', 'manifest.json', 'pkgdb', 'sentinels', 'crash', 'need-update',
    README_NAME,
})
CONFIG_FILE_ADVICE = (
    'To move without the in-place route, save a configuration for TrueNAS SCALE '
    '(System -> General -> Save Config) and upload it on a clean install.'
)


# the internal development record: the guided move fetches TrueNAS SCALE 24.04 itself, from iX's train, or -- when
# iX no longer serves it -- from FreeCORE's mirror, which may only ever serve iX's exact file below.
MOVE_TRAIN = 'TrueNAS-SCALE-Dragonfish'
IX_SCALE_UPDATE_SERVER = 'https://update.freenas.org/scale'
FREECORE_SCALE_MIRROR = 'https://updates.freecore.org/scale'
PINNED_TARGET = {
    'version': '24.04.2.5',
    'filename': 'TrueNAS-SCALE-24.04.2.5.update',
    'filesize': 1320603648,
    'checksum': 'dfee3b50dd183619ee08714b4abff9158588e3a9c07847bac579cdfa1092f3be',
}
# SCALE 24.04's OpenZFS 2.2 (`zpool upgrade -v` on 24.04.0, zfs-2.2.3) lacks three of SCALE 24.10's features.
SCALE_2404_RELEASE = 'TrueNAS SCALE 24.04'
SCALE_2404_POOL_FEATURES = scale_config.SCALE_POOL_FEATURES - {'fast_dedup', 'raidz_expansion', 'redaction_list_spill'}
# The first TrueNAS release whose OpenZFS has each feature a FreeBSD 15 pool may use and 24.04 lacks.
FEATURE_FIRST_RELEASE = {
    'fast_dedup': 'TrueNAS SCALE 24.10', 'raidz_expansion': 'TrueNAS SCALE 24.10',
    'redaction_list_spill': 'TrueNAS SCALE 24.10',
    'longname': 'TrueNAS 25.04', 'large_microzap': 'TrueNAS 25.04',
    'block_cloning_endian': 'TrueNAS 27', 'dynamic_gang_header': 'TrueNAS 27', 'physical_rewrite': 'TrueNAS 27',
}
RELEASE_ORDER = ('TrueNAS SCALE 24.10', 'TrueNAS 25.04', 'TrueNAS 27')
WAY_BACK = (
    'To return to FreeCORE, activate its boot environment under System -> Boot in TrueNAS SCALE, then power the '
    'system off and on. A restart from TrueNAS SCALE does not return to FreeCORE.'
)


def move_target(manifest):
    """The update the guided move fetches, from a train manifest: a complete 24.04 entry or a refusal."""
    check_target(manifest)
    target = {key: manifest.get(key) for key in ('version', 'filename', 'filesize', 'checksum')}
    if (
        not isinstance(target['filename'], str) or '/' in target['filename'] or not target['filename'] or
        not isinstance(target['filesize'], int) or target['filesize'] <= 0 or
        not re.fullmatch(r'[0-9a-f]{64}', str(target['checksum']))
    ):
        raise CallError('The TrueNAS SCALE update manifest is incomplete.')
    return target


def required_space(target):
    """Room the move needs where it downloads: the file, its extracted image and some slack."""
    return target['filesize'] * 2 + 512 * 1024 * 1024


def pool_warning(report):
    """What a pool meets on TrueNAS SCALE 24.04, or None. A warning, never a reason to refuse the move.

    Features that are only enabled travel unnoticed (a pool with them imported on 24.04 in the
    acceptance round). A feature in use keeps the pool unavailable until a release whose OpenZFS has
    it runs: TrueNAS SCALE does not import it on its own, not even read-only (seen with an active
    block_cloning_endian, which is read-only compatible: OFFLINE at boot, `zpool import -o
    readonly=on` from the shell worked).
    """
    if report is None or not (report['refused'] or report['read_only']):
        return None
    in_use = report['refused'] + report['read_only']
    releases = [FEATURE_FIRST_RELEASE.get(feature) for feature in in_use]
    until = None if None in releases else max(releases, key=RELEASE_ORDER.index)
    when = f'{until} or later runs' if until else 'a TrueNAS release whose OpenZFS has them runs'
    features = ', '.join(in_use)
    if report['refused']:
        text = (f'Pool {report["pool"]} uses OpenZFS features TrueNAS SCALE 24.04 does not have ({features}). '
                f'It stays unavailable until {when}.')
    else:
        text = (f'Pool {report["pool"]} uses OpenZFS features TrueNAS SCALE 24.04 can only read ({features}). '
                f'TrueNAS SCALE does not import it on its own: it stays unavailable until {when}, and can '
                'only be imported read-only from the shell until then.')
    return {'pool': report['pool'], 'unavailable': True, 'read_only_import': not report['refused'],
            'features': in_use, 'until': until, 'text': text}


def read_manifest(path, run=subprocess.run):
    """The update file's manifest.json, read without extracting the file."""
    try:
        completed = run(['unsquashfs', '-cat', path, 'manifest.json'], capture_output=True, text=True, check=True)
        return json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise CallError(f'{path} is not a TrueNAS SCALE update file: {error}') from error


def parse_release(version):
    """'24.04.2.5' -> (24, 4); None when the version does not start with two numbers."""
    parts = str(version).split('.')
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return int(parts[0]), int(parts[1])


def check_target(manifest):
    version = manifest.get('version')
    release = parse_release(version)
    if release is None:
        raise CallError(f'The update file does not say which TrueNAS SCALE release it is ({version!r}).')
    if release > LAST_IN_PLACE_RELEASE:
        raise CallError(
            f'TrueNAS SCALE {version} cannot be installed in place from FreeBSD: its installer refuses to run '
            'here (iX supports the in-place move to 24.04 only). Install a TrueNAS SCALE 24.04 update file in '
            f'place and update from there. {CONFIG_FILE_ADVICE}'
        )
    return release


def check_tools(which=shutil.which):
    missing = [tool for tool in GRUB_TOOLS if which(tool) is None]
    if missing:
        raise CallError(
            f'This FreeCORE image does not include GRUB for FreeBSD ({", ".join(missing)}), which the '
            f'in-place move to TrueNAS SCALE needs. {CONFIG_FILE_ADVICE}'
        )


def pool_ashift(pool, run=subprocess.run):
    """The largest vdev ashift in the pool's configuration, or None when zdb cannot say."""
    try:
        output = run(['zdb', '-C', pool], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    values = [int(value) for value in re.findall(r'^\s*ashift: (\d+)$', output, re.MULTILINE)]
    return max(values) if values else None


def check_boot_pool(pool, run=subprocess.run):
    """Refuse a boot pool GRUB cannot read: the installer installs GRUB on it and boots SCALE through it.

    Auto-ashift follows the device: a disk that reports 16 KiB physical sectors (a VM disk on a
    16K zvol, some flash) gets ashift 14, which 13.3's installer line produced just the same.
    """
    ashift = pool_ashift(pool, run)
    if ashift is not None and ashift > GRUB_MAX_ASHIFT:
        raise CallError(
            f'The boot pool {pool} was created with ashift {ashift} ({1 << ashift}-byte blocks, chosen from the '
            f'boot device\'s sector size), and GRUB, which the in-place move installs to boot TrueNAS SCALE, '
            f'reads ZFS only up to ashift {GRUB_MAX_ASHIFT}. Nothing was changed. {CONFIG_FILE_ADVICE}'
        )
    return ashift


def boot_method(run=subprocess.run):
    """How the loader booted this system: 'BIOS' or 'UEFI' (machdep.bootmethod), or None when unreadable."""
    try:
        method = run(['sysctl', '-n', 'machdep.bootmethod'], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return method.strip() or None


def check_bios_grub(method, exists=os.path.isfile):
    """Refuse a BIOS-booted system when the image lacks GRUB's i386-pc platform (the internal development record).

    The installer runs `grub-install --target=i386-pc` there, after it has already retyped FreeBSD's boot
    partition; without these files it fails at that point.
    """
    if method != 'BIOS':
        return
    missing = [name for name in GRUB_I386_PC_REQUIRED if not exists(os.path.join(GRUB_I386_PC, name))]
    if missing:
        raise CallError(
            f'This system boots through the BIOS, and this FreeCORE image lacks the GRUB files for that '
            f'({", ".join(missing)} in {GRUB_I386_PC}), which the in-place move installs to boot TrueNAS SCALE. '
            f'Nothing was changed. {CONFIG_FILE_ADVICE}'
        )


def bios_boot_partitions(disks, run=subprocess.run):
    """(disk, index) of every freebsd-boot partition on the boot disks, read before the installer runs.

    On a BIOS system iX's installer retypes that partition to bios-boot before it installs GRUB. If the install
    fails after that, FreeBSD's pmbr finds no freebsd-boot partition and the system no longer boots
    (the internal development record).
    """
    found = []
    for disk in disks:
        try:
            output = run(['gpart', 'show', disk], capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        for line in output.splitlines():
            fields = line.split()
            # "        64      1024      1  freebsd-boot  (512K)": start, size, index, type
            if len(fields) >= 4 and fields[2].isdigit() and fields[3] == FREEBSD_BOOT:
                found.append((disk, int(fields[2])))
    return found


def restore_bios_boot(partitions, run=subprocess.run):
    """Put each recorded partition back to freebsd-boot with FreeBSD's boot code; returns the failures."""
    failures = []
    for disk, index in partitions:
        for command in (['gpart', 'modify', '-i', str(index), '-t', FREEBSD_BOOT, disk],
                        ['gpart', 'bootcode', '-b', '/boot/pmbr', '-p', '/boot/gptzfsboot', '-i', str(index), disk]):
            try:
                run(command, capture_output=True, text=True, check=True)
            except (OSError, subprocess.CalledProcessError) as error:
                detail = (getattr(error, 'stderr', None) or str(error)).strip()
                failures.append(f'{" ".join(command)}: {detail}')
    return failures


def bios_restore_message(partitions, failures):
    """What the failed install's error says about FreeCORE's BIOS boot afterwards."""
    where = ', '.join(f'{disk} partition {index}' for disk, index in partitions)
    if not failures:
        return f"FreeCORE's BIOS boot partition was restored ({where}); FreeCORE boots as before."
    commands = '; '.join(
        f'gpart modify -i {index} -t {FREEBSD_BOOT} {disk} && '
        f'gpart bootcode -b /boot/pmbr -p /boot/gptzfsboot -i {index} {disk}'
        for disk, index in partitions
    )
    return (f"Restoring FreeCORE's BIOS boot partition failed ({'; '.join(failures)}). FreeCORE will not boot "
            f'until it is restored. Before restarting, run: {commands}')


def root_dataset(run=subprocess.run):
    """The dataset mounted at /, i.e. the FreeCORE boot environment the rollback returns to."""
    try:
        return run(['zfs', 'list', '-H', '-o', 'name', '/'], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def stage_old_root(staged, render_readme, data='/data', root='/root', hostid='/etc/hostid',
                   freebsd_version='/bin/freebsd-version', build=scale_config.build, run=subprocess.run):
    """Build the root the SCALE installer copies from; returns what the downgrade undid.

    ``render_readme(undone)`` gives the README text once the downgrade has run.

    ``bin/freebsd-version`` makes the installer treat this as a FreeBSD upgrade,
    ``etc/hostid`` and ``root`` travel as they are (root is a nullfs mount, so
    nothing is copied twice), and ``data`` is /data with the database replaced
    by the 13.3-shaped copy and FreeCORE's own files left out.
    """
    for directory in ('bin', 'etc', 'data', 'root'):
        os.makedirs(os.path.join(staged, directory), mode=0o755)
    shutil.copy2(freebsd_version, os.path.join(staged, 'bin', 'freebsd-version'))
    shutil.copy2(hostid, os.path.join(staged, 'etc', 'hostid'))
    staged_data = os.path.join(staged, 'data')
    _database, undone = build(os.path.join(data, 'freenas-v1.db'), staged_data)
    for name in sorted(os.listdir(data)):
        if name in DATA_EXCLUDE:
            continue
        # cp -Rp keeps owners and modes the way the installer's rsync -a will pass them on.
        run(['cp', '-Rp', os.path.join(data, name), os.path.join(staged_data, name)],
            capture_output=True, text=True, check=True)
    with open(os.path.join(staged_data, README_NAME), 'w') as file:
        file.write(render_readme(undone))
    run(['mount', '-t', 'nullfs', root, os.path.join(staged, 'root')], capture_output=True, text=True, check=True)
    return undone


def discard_staged_root(staged, run=subprocess.run):
    run(['umount', os.path.join(staged, 'root')], capture_output=True, text=True, check=False)
    shutil.rmtree(staged, ignore_errors=True)


def readme(undone, version, boot_environment, pool_lines):
    lines = [
        f'This TrueNAS SCALE system was installed in place over {version}.',
        '',
        'The database SCALE received is a copy downgraded to the TrueNAS 13.3 revision',
        f'({scale_config.SCALE_BASE_REVISION}) that SCALE accepts. The FreeCORE boot environment',
        f'{boot_environment or "(unknown)"} still holds its own database and is untouched.',
        '',
        'To go back to FreeCORE: activate that boot environment under System -> Boot, then shut',
        'the system down and power it on. The GRUB menu then starts "TrueNAS CORE" by default.',
        'A restart from SCALE does not reach that menu: SCALE restarts straight into a kernel of',
        'its own, so power the system off and on instead.',
        '',
        'FreeCORE database changes undone in the copy (what they hold does not travel;',
        'SCALE has no place for FreeCORE-only settings such as WireGuard, Bastille or Applications):',
    ]
    lines += [f'  - {scale_config.TRACKER_REFERENCE.sub("", message)}' for message in undone] or [
        '  (none: the database was already at 13.3)'
    ]
    lines += ['', f'Pools, checked against the OpenZFS features of {scale_config.SCALE_REFERENCE_RELEASE}:']
    lines += [f'  - {line}' for line in pool_lines] or [
        f'  - every pool uses only features {scale_config.SCALE_REFERENCE_RELEASE} has'
    ]
    lines += [
        '',
        'Applications (Podman) are not part of the configuration: export each one for a',
        'Linux host with Export for Linux in its row under Applications -> Installed on FreeCORE.',
    ]
    return '\n'.join(lines) + '\n'
