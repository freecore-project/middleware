"""The generic jail lift (the internal development record).

A jail becomes a native FreeBSD Application with no knowledge of the software
inside it: the image is the jail's software, an owned dataset per state tree
holds what the jail wrote, and ``jail-init`` runs the jail's own rc(8) system
as the container process.

- **base layer**: the release the jail was cloned from (the clone's origin
  snapshot) or the release directory a thin jail borrows, imported once per
  release and shared by every lift of it.
- **delta layer**: ``zfs diff`` between the origin and the plan's snapshot for
  a clone jail; a walk of the root for a basejail or a Bastille thin jail; the
  whole root for a thick jail (single layer, no base).
- **state**: ``/var``, ``/usr/local/etc``, ``/root`` and the home tree go to
  owned datasets, copied faithfully (owner, mode, flags) from the snapshot and
  mounted over the image.  Image ≠ state is what makes the result an
  application rather than a frozen jail.

Everything here is a pure function or a subprocess wrapper the service runs
in a thread.  Nothing reads the jail other than through the snapshot the plan
holds, and nothing writes outside the Applications pool.
"""
import os
import re
import shlex
import stat
import subprocess
from pathlib import Path

from middlewared.plugins.applications_.utils import PODMAN_PATH

TAR = '/usr/bin/tar'
INIT_SOURCE = Path(__file__).parent / 'jail-init.sh'
INIT_TARGET = '/usr/local/libexec/freecore-jail-init'
BASE_REPOSITORY = 'localhost/freecore/jail-base'
CONVERTED_REPOSITORY = 'localhost/freecore/converted'
# podman owns these inside every container; they are bind mounts there, so a
# layer must neither carry nor delete them (the internal development record spike).
PODMAN_MANAGED = frozenset({'etc/hosts', 'etc/resolv.conf', 'etc/hostname'})
# name, container target, path below the jail root
STATE_VOLUMES = (
    ('var', '/var', 'var'),
    ('usr-local-etc', '/usr/local/etc', 'usr/local/etc'),
    ('root', '/root', 'root'),
    ('home', '/home', 'home'),
    ('usr-home', '/usr/home', 'usr/home'),
)
# Directories kept, contents left behind: runtime sockets and pids, scratch,
# the package download cache.
STATE_EXCLUDED_CONTENTS = ('var/run', 'var/tmp', 'var/cache/pkg')
# iocage basejail nullfs targets: empty directories in a stopped basejail's root.
BASEJAIL_DIRECTORIES = (
    'bin', 'boot', 'lib', 'libexec', 'rescue', 'sbin', 'usr/bin', 'usr/include',
    'usr/lib', 'usr/lib32', 'usr/libdata', 'usr/libexec', 'usr/sbin', 'usr/share', 'usr/src',
)
BASTILLE_LINK_PREFIX = '/.bastille/'
BASTILLE_MOUNT = '.bastille'
# rc.conf settings that name the jail's network identity; the managed container
# network and podman own these in the application.
NETWORK_RC_SETTING = re.compile(
    r'^\s*(ifconfig_[A-Za-z0-9_]+|defaultrouter|ipv6_defaultrouter|hostname|'
    r'dhclient_[A-Za-z0-9_]+|ipv6_activate_all_interfaces)\s*='
)
IOCAGE_ANNOTATIONS = (
    # iocage property, truthy value(s), annotation name, annotation value
    ('allow_raw_sockets', ('1', 1, True), 'org.freebsd.jail.allow.raw_sockets', 'true'),
    ('allow_mlock', ('1', 1, True), 'org.freebsd.jail.allow.mlock', 'true'),
    ('sysvmsg', ('new',), 'org.freebsd.jail.sysvmsg', 'new'),
    ('sysvsem', ('new',), 'org.freebsd.jail.sysvsem', 'new'),
    ('sysvshm', ('new',), 'org.freebsd.jail.sysvshm', 'new'),
)
IOCAGE_UNSUPPORTED = (
    'allow_mount', 'allow_mount_devfs', 'allow_mount_fdescfs', 'allow_mount_fusefs',
    'allow_mount_linprocfs', 'allow_mount_linsysfs', 'allow_mount_nullfs',
    'allow_mount_procfs', 'allow_mount_tmpfs', 'allow_mount_zfs', 'allow_chflags',
    'allow_socket_af', 'allow_vmm', 'allow_nfsd', 'allow_quotas',
)
BASTILLE_ANNOTATIONS = (
    ('allow.raw_sockets', 'org.freebsd.jail.allow.raw_sockets', 'true'),
    ('allow.mlock', 'org.freebsd.jail.allow.mlock', 'true'),
)
BASTILLE_SYSV = ('sysvmsg', 'sysvsem', 'sysvshm')
FREEBSD_VERSION_LINE = re.compile(r'^USERLAND_VERSION="([^"]+)"', re.M)
SOCKSTAT_LOCAL = re.compile(r'^(?P<address>.+):(?P<port>\d+)$')
TAG_CHARACTERS = re.compile(r'[^A-Za-z0-9_.-]+')


class LiftError(Exception):
    pass


# -- zfs diff -----------------------------------------------------------------

def unescape(name):
    """Undo zfs diff's octal escaping: ``vanilla\\0040prometheus`` -> ``vanilla prometheus``."""
    return re.sub(r'\\(\d{4})', lambda match: chr(int(match.group(1), 8)), name)


def parse_zfs_diff(text, mountpoint):
    """Paths added or modified, and paths removed, relative to the dataset mountpoint.

    ``zfs diff -FH`` prints ``<change> <type> <path> [<new path>]``.  A path that
    is both removed and added is a replacement (iocage rewrites ``passwd`` and
    friends at every start), not a deletion.  Files podman manages are ignored.
    """
    prefix = mountpoint.rstrip('/') + '/'
    added, removed = set(), set()
    for line in text.splitlines():
        parts = line.rstrip('\n').split('\t')
        if len(parts) < 3:
            continue
        kind = parts[0]
        paths = [unescape(part) for part in parts[2:]]
        relative = [path[len(prefix):] for path in paths if path.startswith(prefix)]
        if not relative:
            continue
        if kind in ('+', 'M'):
            added.add(relative[0])
        elif kind == '-':
            removed.add(relative[0])
        elif kind == 'R':
            removed.add(relative[0])
            if len(relative) > 1:
                added.add(relative[1])
    added -= PODMAN_MANAGED
    removed = (removed - added) - PODMAN_MANAGED
    return added, removed


# -- walking ------------------------------------------------------------------

def walk_root(root, skip=()):
    """Every entry below ``root`` as a relative path: directories, files, symlinks.

    Never follows symlinks; skips ``.zfs`` and the given relative paths (whole
    subtrees).
    """
    root = root.rstrip('/')
    skip = set(skip)
    result = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        relative_dir = os.path.relpath(current, root)
        relative_dir = '' if relative_dir == '.' else relative_dir
        keep = []
        for name in directories:
            relative = os.path.join(relative_dir, name) if relative_dir else name
            if relative == '.zfs' or relative in skip:
                continue
            result.add(relative)
            if os.path.islink(os.path.join(current, name)):
                continue
            keep.append(name)
        directories[:] = keep
        for name in files:
            relative = os.path.join(relative_dir, name) if relative_dir else name
            if relative in skip:
                continue
            result.add(relative)
    result -= PODMAN_MANAGED
    return result


def bastille_borrowed(root):
    """Symlinks a Bastille thin jail points into ``/.bastille`` (its release), plus the mountpoint."""
    borrowed = set()
    for relative in ('bin', 'boot', 'lib', 'libexec', 'rescue', 'sbin', 'usr/bin', 'usr/include',
                     'usr/lib', 'usr/lib32', 'usr/libdata', 'usr/libexec', 'usr/sbin', 'usr/share',
                     'usr/src', 'usr/ports', 'usr/tests', 'usr/obj'):
        path = os.path.join(root, relative)
        if os.path.islink(path):
            try:
                target = os.readlink(path)
            except OSError:
                continue
            if target.startswith(BASTILLE_LINK_PREFIX) or target.startswith('.bastille/') or \
                    target.startswith('../.bastille/'):
                borrowed.add(relative)
    if os.path.isdir(os.path.join(root, BASTILLE_MOUNT)):
        borrowed.add(BASTILLE_MOUNT)
    return borrowed


def is_bastille_thin(root):
    return bool(bastille_borrowed(root) - {BASTILLE_MOUNT})


# -- state split --------------------------------------------------------------

def state_volumes(root):
    """The state trees present in this jail root as real directories.

    A 13.x root has ``home -> usr/home``; the symlink stays in the image and the
    real directory becomes the volume.
    """
    present = []
    for name, target, relative in STATE_VOLUMES:
        path = os.path.join(root, relative)
        if os.path.isdir(path) and not os.path.islink(path):
            present.append({'name': name, 'target': target, 'path': relative})
    return present


def _under(path, prefix):
    return path == prefix or path.startswith(prefix + '/')


def partition(paths, state_paths):
    """Split a path set into the image layer and the state trees.

    State trees leave the image entirely except for their own directory entry,
    which the image keeps as the mount point.
    """
    image = set()
    for path in paths:
        if any(_under(path, prefix) for prefix in state_paths):
            continue
        image.add(path)
    for prefix in state_paths:
        image.add(prefix)
        parent = os.path.dirname(prefix)
        while parent:
            image.add(parent)
            parent = os.path.dirname(parent)
    return image


def state_listing(root, relative):
    """Every entry of one state tree, relative to that tree, excluded contents left behind.

    The result feeds ``tar -C <root>/<relative>`` so the dataset holds the tree's
    contents directly: ``var/db/pkg`` in the jail is ``db/pkg`` on the ``var`` volume.
    """
    excluded = [
        item[len(relative) + 1:] for item in STATE_EXCLUDED_CONTENTS
        if _under(item, relative) and item != relative
    ]
    listing = set()
    for path in walk_root(os.path.join(root, relative)):
        if any(_under(path, item) and path != item for item in excluded):
            continue
        listing.add(path)
    return listing


# -- rc.conf --------------------------------------------------------------------

def rewrite_rc_conf(text):
    """Drop the network identity lines; return the new text and the dropped settings."""
    kept = []
    dropped = []
    for line in text.splitlines():
        match = NETWORK_RC_SETTING.match(line)
        if match:
            dropped.append(match.group(1))
            continue
        kept.append(line)
    header = (
        '# Network identity removed by FreeCORE Convert & Import: the managed container\n'
        '# network and podman own the interface, address, gateway and hostname.\n'
    )
    return header + '\n'.join(kept) + ('\n' if kept else ''), dropped


# -- jail metadata --------------------------------------------------------------

def parse_fstab(text, jail_root):
    """iocage/Bastille fstab entries as mounts inside the jail."""
    mounts = []
    root = jail_root.rstrip('/')
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        try:
            fields = shlex.split(stripped.split('#', 1)[0])
        except ValueError:
            continue
        if len(fields) < 3:
            continue
        source, destination, fstype = fields[0], fields[1], fields[2]
        options = fields[3].split(',') if len(fields) > 3 else []
        destination = os.path.normpath(destination)
        if not _under(destination, root) or destination == root:
            continue
        mounts.append({
            'source': os.path.normpath(source),
            'target': destination[len(root):] or '/',
            'fstype': fstype,
            'read_only': 'ro' in options,
        })
    return mounts


def parse_sockstat(text):
    """Listening TCP/UDP ports from ``sockstat -4 -6 -l -j <jid>``."""
    ports = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        user, command, _pid, _fd, proto, local = fields[:6]
        if not proto.startswith(('tcp', 'udp')):
            continue
        match = SOCKSTAT_LOCAL.match(local)
        if not match:
            continue
        port = int(match.group('port'))
        protocol = 'tcp' if proto.startswith('tcp') else 'udp'
        key = (port, protocol)
        address = match.group('address')
        if key not in ports:
            ports[key] = {
                'container_port': port, 'protocol': protocol, 'command': command, 'user': user,
                'address': address,
            }
        elif is_loopback(ports[key]['address']) and not is_loopback(address):
            # the internal development record: bound on loopback and on an address too --
            # the reachable one is the port's address.
            ports[key]['address'] = address
    return [ports[key] for key in sorted(ports)]


def is_loopback(address):
    return address == '::1' or str(address).startswith('127.')


def iocage_annotations(parameters):
    """Annotations the Applications runtime accepts, and the jail allowances it cannot carry."""
    annotations = []
    unsupported = []
    for prop, truthy, name, value in IOCAGE_ANNOTATIONS:
        if str(parameters.get(prop)) in {str(item) for item in truthy}:
            annotations.append({'name': name, 'value': value})
    for prop in IOCAGE_UNSUPPORTED:
        if str(parameters.get(prop)) in ('1', 'True', 'true'):
            unsupported.append(prop)
    return annotations, unsupported


def parse_jail_conf(text):
    """A lenient read of a Bastille jail.conf: ``name = value;`` and bare ``flag;`` lines."""
    settings = {}
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip().rstrip(';').strip()
        if not line or line.endswith('{') or line == '}':
            continue
        if '=' in line:
            key, value = line.split('=', 1)
            settings[key.strip()] = value.strip().strip('"\'')
        else:
            settings[line] = True
    return settings


def bastille_annotations(settings):
    annotations = []
    unsupported = []
    for key, name, value in BASTILLE_ANNOTATIONS:
        if settings.get(key) in (True, '1', 'true'):
            annotations.append({'name': name, 'value': value})
    for key in BASTILLE_SYSV:
        if settings.get(key) == 'new':
            annotations.append({'name': f'org.freebsd.jail.{key}', 'value': 'new'})
    for key, value in settings.items():
        if key.startswith('allow.mount') and value in (True, '1', 'true'):
            unsupported.append(key)
    return annotations, unsupported


def userland_release(root):
    """The userland a root carries, from its own ``bin/freebsd-version``."""
    try:
        with open(os.path.join(root, 'bin', 'freebsd-version'), 'r', encoding='utf-8', errors='replace') as file:
            match = FREEBSD_VERSION_LINE.search(file.read(65536))
    except OSError:
        return None
    return match.group(1) if match else None


def mentions_of(root, needle, limit=20):
    """Files below ``root`` (text, bounded) that mention ``needle``; for the address note."""
    hits = []
    if not needle:
        return hits
    encoded = needle.encode('utf-8')
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in files:
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    continue
                with open(path, 'rb') as file:
                    if encoded in file.read():
                        hits.append(os.path.relpath(path, root))
            except OSError:
                continue
            if len(hits) >= limit:
                return hits
    return hits


# -- image build ------------------------------------------------------------------

def sanitize_tag(value):
    cleaned = TAG_CHARACTERS.sub('-', value or '').strip('-.') or 'unknown'
    return cleaned[:96]


def render_containerfile(base, removed, labels, overlay=True):
    lines = [f'FROM {base}' if base else 'FROM scratch', 'ADD delta.tar /']
    if overlay:
        lines.append('COPY overlay/ /')
    lines.append(f'COPY jail-init {INIT_TARGET}')
    if removed:
        quoted = ' '.join(shlex.quote('/' + path) for path in sorted(removed))
        lines.append(f'RUN rm -rf -- {quoted}')
    for name, value in sorted(labels.items()):
        lines.append(f'LABEL {name}={shlex.quote(value)}')
    lines.append('ENTRYPOINT ["' + INIT_TARGET + '"]')
    return '\n'.join(lines) + '\n'


def write_listing(paths, destination):
    with open(destination, 'wb') as file:
        for path in sorted(paths):
            file.write(path.encode('utf-8', 'surrogateescape') + b'\0')


def _run(command, stdin=None, env=None):
    completed = subprocess.run(
        command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or b'').decode('utf-8', 'replace').strip()[-4096:]
        raise LiftError(f'{command[0]} {command[1]} failed: {detail}')
    return completed.stdout.decode('utf-8', 'replace')


def create_tar(root, listing, destination):
    """One tar of exactly the listed entries (no recursion), owners and flags kept."""
    _run([TAR, '-C', root, '-n', '--null', '-T', listing, '-cf', destination])


def import_base(root, reference, labels, env):
    """Import a release root as the shared base image (``podman import`` from a tar pipe)."""
    tar = subprocess.Popen([TAR, '-C', root, '-cf', '-', '.'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = [PODMAN_PATH, 'import', '--quiet', '--os', 'freebsd', '--arch', 'amd64']
    for name, value in sorted(labels.items()):
        command.extend(['--change', f'LABEL {name}={value}'])
    command.extend(['-', reference])
    importer = subprocess.run(
        command, stdin=tar.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,
    )
    tar.stdout.close()
    _stdout, tar_error = tar.communicate()
    if tar.returncode:
        raise LiftError(f'tar of {root} failed: {tar_error.decode("utf-8", "replace").strip()[-2048:]}')
    if importer.returncode:
        raise LiftError(
            f'podman import failed: {(importer.stderr or importer.stdout).decode("utf-8", "replace").strip()[-4096:]}'
        )
    return importer.stdout.decode('utf-8', 'replace').strip()


def copy_tree(root, listing, destination):
    """Copy the listed entries from a snapshot into a dataset: owner, mode, flags, links kept."""
    os.makedirs(destination, exist_ok=True)
    tar = subprocess.Popen([TAR, '-C', root, '-n', '--null', '-T', listing, '-cf', '-'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    untar = subprocess.run([TAR, '-C', destination, '-xpf', '-'], stdin=tar.stdout,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    tar.stdout.close()
    _stdout, tar_error = tar.communicate()
    if tar.returncode:
        raise LiftError(f'reading {root} failed: {tar_error.decode("utf-8", "replace").strip()[-2048:]}')
    if untar.returncode:
        raise LiftError(f'writing {destination} failed: {untar.stderr.decode("utf-8", "replace").strip()[-2048:]}')


def install_init(context):
    """Place jail-init into a build context, executable."""
    destination = os.path.join(context, 'jail-init')
    with open(INIT_SOURCE, 'rb') as source, open(destination, 'wb') as target:
        target.write(source.read())
    os.chmod(destination, 0o755)


def total_size(root, listing):
    """Bytes the listed regular files occupy (a plan estimate, not a promise)."""
    total = 0
    for path in listing:
        try:
            info = os.lstat(os.path.join(root, path))
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total
