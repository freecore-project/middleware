"""A configuration database TrueNAS SCALE accepts (the internal development record).

SCALE's config upload runs its Alembic chain over the uploaded database and
refuses it when that fails.  The chain knows CORE up to 13.3's last revision,
``b412304844e1``; FreeCORE's own revisions (``alembic/versions/15.0``) branch
from there and SCALE knows none of them.  So a copy of the database is taken
and FreeCORE's revisions are downgraded on the copy, leaving a database shaped
exactly like 13.3's.  The live database is only ever read.
"""
import os
import re
import sqlite3
import subprocess

from middlewared.service_exception import CallError

SCALE_BASE_REVISION = 'b412304844e1'
# OpenZFS pool features TrueNAS SCALE 24.10.0 (OpenZFS 2.2.99) supports: its `zpool upgrade -v`,
# measured 2026-09-30 (the internal development record Stage 0). A pool with an ACTIVE feature outside
# this set is refused there (or imported read-only when the feature is read-only compatible);
# an enabled-but-unused one imports until it is first used.
SCALE_REFERENCE_RELEASE = 'TrueNAS SCALE 24.10.0'
SCALE_POOL_FEATURES = frozenset({
    'allocation_classes', 'async_destroy', 'blake3', 'block_cloning', 'bookmark_v2', 'bookmark_written',
    'bookmarks', 'device_rebuild', 'device_removal', 'draid', 'edonr', 'embedded_data', 'empty_bpobj',
    'enabled_txg', 'encryption', 'extensible_dataset', 'fast_dedup', 'filesystem_limits', 'head_errlog',
    'hole_birth', 'large_blocks', 'large_dnode', 'livelist', 'log_spacemap', 'lz4_compress',
    'multi_vdev_crash_dump', 'obsolete_counts', 'project_quota', 'raidz_expansion', 'redacted_datasets',
    'redaction_bookmarks', 'redaction_list_spill', 'resilver_defer', 'sha512', 'skein', 'spacemap_histogram',
    'spacemap_v2', 'userobj_accounting', 'vdev_zaps_v2', 'zilsaxattr', 'zpool_checkpoint', 'zstd_compress',
})
FEATURE_LINE = re.compile(r'^(?P<name>[a-z][a-z0-9_]+)\s*(?P<ro>\(read-only compatible\))?\s*$')
# The OpenZFS release that introduced each pool feature a FreeBSD 15 pool enables and SCALE 24.10.0
# lacks, and the first TrueNAS release built on that OpenZFS (checked 2026-09-30: TrueNAS 25.04 ships
# OpenZFS 2.3.0, TrueNAS 26 ships 2.4.x). A feature outside this table gets the generic advice.
FEATURE_OPENZFS = {
    'longname': '2.3', 'large_microzap': '2.3',
    'block_cloning_endian': '2.4', 'dynamic_gang_header': '2.4', 'physical_rewrite': '2.4',
}
OPENZFS_TRUENAS = {'2.3': 'TrueNAS 25.04', '2.4': 'TrueNAS 26'}
FACTORY_13_3_DATABASE = '/usr/local/share/truenas/factory-v1.db'
README_NAME = 'README.truenas-scale'
DOWNGRADE_LINE = re.compile(r'Running downgrade \S+ -> \S+, (?P<message>.+)$')
TRACKER_REFERENCE = re.compile(r'\s*\((?:freecore|zfs|truenas)/[\w.-]+#\d+\)')


def middlewared_dir():
    import middlewared
    return os.path.dirname(middlewared.__spec__.origin)


def snapshot_database(source, destination):
    """A consistent copy of a live SQLite database (the backup API, not a file copy)."""
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as live, sqlite3.connect(destination) as copy:
        live.backup(copy)
    os.chmod(destination, 0o600)


def stamp(database):
    with sqlite3.connect(database) as connection:
        rows = connection.execute('SELECT version_num FROM alembic_version').fetchall()
    return rows[0][0] if len(rows) == 1 else None


def tables(database):
    with sqlite3.connect(database) as connection:
        return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def downgrade(database, run=subprocess.run, cwd=None):
    """Downgrade the copy to the 13.3 revision; the human line of every revision it undid.

    The same shape as /usr/local/sbin/migrate: alembic run from the middlewared
    package directory with FREENAS_DATABASE naming the file (the internal development record).
    """
    completed = run(
        ['alembic', 'downgrade', SCALE_BASE_REVISION],
        cwd=cwd or middlewared_dir(),
        env=dict(os.environ, FREENAS_DATABASE=database),
        capture_output=True, text=True,
    )
    output = f'{completed.stdout or ""}\n{completed.stderr or ""}'
    if completed.returncode != 0:
        tail = '\n'.join(output.strip().splitlines()[-5:])
        raise CallError(f'Unable to downgrade the configuration copy to the 13.3 revision:\n{tail}')
    return [match.group('message') for match in map(DOWNGRADE_LINE.search, output.splitlines()) if match]


def verify(database, factory=FACTORY_13_3_DATABASE):
    """Refuse unless the copy is stamped 13.3 and has exactly 13.3's tables."""
    current = stamp(database)
    if current != SCALE_BASE_REVISION:
        raise CallError(
            f'The configuration copy is stamped {current!r}, not the 13.3 revision {SCALE_BASE_REVISION}; '
            'TrueNAS SCALE would refuse it.'
        )
    if os.path.exists(factory):
        have, want = tables(database), tables(factory)
        if have != want:
            extra, missing = sorted(have - want), sorted(want - have)
            raise CallError(
                'The configuration copy does not have the 13.3 table set '
                f'(extra: {", ".join(extra) or "none"}; missing: {", ".join(missing) or "none"}).'
            )


def parse_feature_support(text):
    """`zpool upgrade -v` -> {feature: read-only compatible}."""
    support, listing = {}, False
    for line in text.splitlines():
        if line.startswith('---'):
            listing = True
            continue
        match = FEATURE_LINE.match(line) if listing else None
        if match:
            support[match.group('name')] = bool(match.group('ro'))
    return support


def parse_feature_states(text):
    """`zpool get -H -o property,value all <pool>` -> {feature: enabled|active|disabled}."""
    states = {}
    for line in text.splitlines():
        prop, _, value = line.partition('\t')
        if prop.startswith('feature@'):
            states[prop[len('feature@'):]] = value.strip()
    return states


def pool_feature_report(pool, run=subprocess.run, features=SCALE_POOL_FEATURES, reference=SCALE_REFERENCE_RELEASE):
    """What a pool would meet on TrueNAS SCALE: features SCALE lacks, by consequence.

    Returns None when the pool cannot be read (it is never a reason to refuse).
    """
    try:
        states = run(['zpool', 'get', '-H', '-o', 'property,value', 'all', pool],
                     capture_output=True, text=True, check=True).stdout
        support = run(['zpool', 'upgrade', '-v'], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    read_only_compatible = parse_feature_support(support)
    report = {'pool': pool, 'reference': reference, 'refused': [], 'read_only': [], 'dormant': []}
    for feature, state in sorted(parse_feature_states(states).items()):
        if feature in features or state not in ('enabled', 'active'):
            continue
        if state == 'enabled':
            report['dormant'].append(feature)
        elif read_only_compatible.get(feature):
            report['read_only'].append(feature)
        else:
            report['refused'].append(feature)
    return report


def needed_release(features):
    """The OpenZFS release, and the first TrueNAS built on it, that knows every one of these features."""
    versions = [FEATURE_OPENZFS.get(feature) for feature in features]
    if not versions or None in versions:
        return None
    newest = max(versions, key=lambda version: tuple(int(part) for part in version.split('.')))
    return f'OpenZFS {newest} ({OPENZFS_TRUENAS[newest]} or later)'


def describe_pool_report(report):
    """Guidance for one pool: the features it uses that the reference SCALE lacks, and the release to go to.

    The pool is imported once, on a release whose OpenZFS knows every one of them --
    nobody runs a pool on the releases below that, so what those would do with it is
    deliberately not described.
    """
    if report is None:
        return []
    in_use = report['refused'] + report['read_only']
    unused = report['dormant']
    if not in_use and not unused:
        return []
    named = [f'{feature} (in use)' for feature in in_use] + [f'{feature} (enabled)' for feature in unused]
    line = f'pool {report["pool"]} uses OpenZFS features {report["reference"]} does not have: {", ".join(named)}'
    release = needed_release(in_use + unused)
    if release:
        line += f' -- import the pool only on {release}'
    else:
        line += ' -- import the pool only on a release whose `zpool upgrade -v` lists them'
    return [line]


def build(source, workdir, run=subprocess.run, cwd=None, factory=FACTORY_13_3_DATABASE):
    """Write the SCALE-shaped copy into ``workdir``; returns its path and what the downgrade undid."""
    database = os.path.join(workdir, 'freenas-v1.db')
    snapshot_database(source, database)
    if stamp(database) == SCALE_BASE_REVISION:
        undone = []
    else:
        undone = downgrade(database, run=run, cwd=cwd)
    verify(database, factory=factory)
    return database, undone


def readme(undone, version, included, pool_lines=None):
    lines = [
        f'Configuration of {version} for moving to TrueNAS SCALE.',
        '',
        'This is NOT a FreeCORE backup: its database is downgraded to the TrueNAS 13.3',
        f'revision ({SCALE_BASE_REVISION}) that TrueNAS SCALE accepts, and it cannot be',
        'uploaded back onto FreeCORE. Save a normal configuration for that.',
        '',
        'How to use it: clean-install the TrueNAS SCALE release you will stay on, 24.10 or later.',
        '(iX documents restoring a 13.x configuration onto a clean install of any current release;',
        'only the in-place update route from CORE needs 24.04, and this file is not for that route.)',
        'Pick the release by the pool list below: every feature a pool uses must be in that',
        "release's OpenZFS -- OpenZFS 2.3 is TrueNAS 25.04, OpenZFS 2.4 is TrueNAS 26. Upload this",
        'file under System -> General -> Manage Configuration -> Upload File and let it reboot.',
        'Sign in as root with the old password (the upload removes the admin user made at install;',
        'create one again), configure the network interfaces again (Linux names them differently),',
        'then import the pool. Include the password secret seed in this file, or every stored',
        'password (services, cloud credentials, directory binds) is reset on SCALE.',
        '',
        'FreeCORE database changes undone in this copy (what they hold does not travel;',
        'SCALE has no place for FreeCORE-only settings such as WireGuard, Bastille or Applications):',
    ]
    # Revision titles may name the internal tracker; the user's file never does.
    lines += [f'  - {TRACKER_REFERENCE.sub("", message)}' for message in undone] or [
        '  (none: the database was already at 13.3)'
    ]
    lines += ['', 'Included: ' + ', '.join(included)]
    if pool_lines is not None:
        lines += ['', f'Pools, checked against the OpenZFS features of {SCALE_REFERENCE_RELEASE}:']
        lines += [f'  - {line}' for line in pool_lines] or [
            f'  - every pool uses only features {SCALE_REFERENCE_RELEASE} has; import them on any release from there'
        ]
    lines += [
        '',
        'Applications (Podman) are not part of the configuration: export each one for a',
        'Linux host with Export for Linux in its row under Applications -> Installed',
        '(offered while Convert & Import is turned on).',
    ]
    return '\n'.join(lines) + '\n'
