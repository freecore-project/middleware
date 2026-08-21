"""Export bundles: a compose file beside the data it mounted (the internal development record).

Layout, relative to the directory the administrator points at::

    compose.yaml             one service (docker-compose.yml is accepted too)
    ./<bind dir>/...         every bind-mounted host path, relative to the compose file
    ./<volume>.tar           every named volume, one tar each
    README.export            optional, ignored

The fingerprint is sha256 over the compose bytes plus the sorted list of
(relative path, size, mtime) of every file in the bundle.  It is computed when
the plan is written and again when it is applied; a mismatch refuses.
"""
import hashlib
import os
import tarfile

from middlewared.plugins.applications_.catalog import CatalogContractError

COMPOSE_NAMES = ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')
MAX_COMPOSE_SIZE = 1024 * 1024
MAX_FINGERPRINT_FILES = 250_000
MAX_TAR_MEMBERS = 250_000


def discover(path):
    """Find the compose file of a bundle directory; refuse anything else."""
    if not isinstance(path, str) or not path.startswith('/mnt/') or os.path.normpath(path) != path:
        raise CatalogContractError('Export bundle path must be a normalized path below /mnt.')
    if os.path.islink(path) or not os.path.isdir(path):
        if os.path.isfile(path) and path.endswith(('.tar', '.tar.gz', '.tgz', '.tar.zst')):
            raise CatalogContractError(
                'Extract the bundle archive into a directory on a dataset first; '
                'the converter reads a directory.'
            )
        raise CatalogContractError('Export bundle path is not a directory.')
    for name in COMPOSE_NAMES:
        compose_path = os.path.join(path, name)
        if os.path.isfile(compose_path) and not os.path.islink(compose_path):
            break
    else:
        raise CatalogContractError(
            'Export bundle has no compose file (compose.yaml or docker-compose.yml).'
        )
    if os.path.getsize(compose_path) > MAX_COMPOSE_SIZE:
        raise CatalogContractError('Export bundle compose file is oversized.')
    with open(compose_path, 'rb') as file:
        content = file.read(MAX_COMPOSE_SIZE + 1)
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError as error:
        raise CatalogContractError('Export bundle compose file is not valid UTF-8.') from error
    return {'root': path, 'compose_path': compose_path, 'compose_text': text}


def fingerprint(root, compose_text):
    digest = hashlib.sha256()
    digest.update(compose_text.encode('utf-8'))
    digest.update(b'\0')
    entries = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories.sort()
        for name in sorted(files):
            full = os.path.join(directory, name)
            try:
                info = os.lstat(full)
            except OSError:
                continue
            relative = os.path.relpath(full, root)
            entries.append((relative, info.st_size, info.st_mtime_ns))
            if len(entries) > MAX_FINGERPRINT_FILES:
                raise CatalogContractError(
                    'Export bundle holds too many files to fingerprint; move media libraries out of it.'
                )
    for relative, size, mtime in sorted(entries):
        digest.update(f'{relative}\0{size}\0{mtime}\n'.encode('utf-8', 'surrogateescape'))
    return digest.hexdigest()


def resolve_bind(root, source):
    """A bind mount's data inside the bundle, relative to the compose file."""
    candidate = source
    if candidate.startswith('~'):
        candidate = candidate[1:]
    if candidate.startswith('/'):
        # An absolute host path is looked up by its basename beside the compose
        # file: /srv/grafana/data becomes ./data in the bundle.
        candidate = os.path.basename(candidate.rstrip('/'))
    full = os.path.normpath(os.path.join(root, candidate))
    if full != root and not full.startswith(root + os.sep):
        raise CatalogContractError(f'Bind mount {source!r} escapes the export bundle.')
    return full if os.path.exists(full) else None


def volume_tar(root, name):
    path = os.path.join(root, f'{name}.tar')
    return path if os.path.isfile(path) and not os.path.islink(path) else None


def _safe_member(member):
    name = member.name
    if name.startswith('/') or '..' in name.split('/'):
        raise CatalogContractError(f'Volume archive member {name!r} escapes its directory.')
    if member.issym() or member.islnk():
        target = member.linkname
        if target.startswith('/') or '..' in target.split('/'):
            raise CatalogContractError(f'Volume archive link {name!r} escapes its directory.')
    if member.isdev():
        raise CatalogContractError(f'Volume archive member {name!r} is a device node.')


def extract_volume(tar_path, destination):
    """Extract a named-volume archive into `destination`, refusing escapes and devices."""
    os.makedirs(destination, exist_ok=True)
    with tarfile.open(tar_path, 'r:*') as archive:
        members = []
        for member in archive:
            _safe_member(member)
            members.append(member)
            if len(members) > MAX_TAR_MEMBERS:
                raise CatalogContractError('Volume archive holds too many members.')
        try:
            archive.extractall(destination, members=members, filter='data')
        except TypeError:
            archive.extractall(destination, members=members)
