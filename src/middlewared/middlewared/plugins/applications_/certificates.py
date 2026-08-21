"""System certificates mounted into an application (the internal development record).

A certificate lives in the configuration database and is rendered for the host's own
services into ``/etc/certificates``; an application cannot read that directory, and
application volumes map datasets on the pool only, so until now a certificate reached
an application only as a hand-copied file that the next ACME renewal left stale.

An application carries an operator-owned ``certificates`` list -- like labels, not part
of the catalog contract.  Each entry names one certificate (id, plus the name and
fingerprint it had when it was chosen), the directory it appears in inside the
container, whether a change restarts the application, and optionally the uid/gid the
files belong to.  The binding itself is the certificate's public key
(``public_key_sha256``): an ACME renewal re-orders with the stored CSR, so it changes
the fingerprint but keeps the key, and a rename changes only the name -- neither may
unmount anything -- while a record that travels with an exported pool still cannot
bind to a different key under the same id.

The files are rendered in the certbot layout the ecosystem expects, under
``/var/run`` (tmpfs): keys never reach the pool, so no snapshot or replication keeps
them after a rotation or a removal.  This module is the pure half -- paths, validation,
the file set and the content hash -- so it is testable without a pool, a container or
a certificate store.
"""
import hashlib
import json
import posixpath
import re

from cryptography import x509
from cryptography.hazmat.primitives import serialization

RUNTIME_DIR = '/var/run/freecore-applications'
CERTIFICATES_ROOT = f'{RUNTIME_DIR}/certs'
MAX_CERTIFICATES = 32
# The certbot file names. `chain.pem` is always written, zero bytes when the
# certificate carries no intermediate, so an application's configuration can name
# the same four paths whatever the certificate is.
CERT_FILE = 'cert.pem'
CHAIN_FILE = 'chain.pem'
FULLCHAIN_FILE = 'fullchain.pem'
PRIVKEY_FILE = 'privkey.pem'
FILE_NAMES = (CERT_FILE, CHAIN_FILE, FULLCHAIN_FILE, PRIVKEY_FILE)
DIRECTORY_MODE = 0o750
FILE_MODE = 0o640
PEM_BLOCK = re.compile(r'-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----', re.S)
PUBLIC_KEY_SHA256 = re.compile(r'^[0-9a-f]{64}$')


class CertificateMountError(ValueError):
    pass


def certificates_root(application):
    return f'{CERTIFICATES_ROOT}/{application}'


def entry_directory(application, index):
    """Where entry ``index`` of ``application`` is rendered.

    The index is the entry's position in the record, so the path is stable for the
    life of a container: a renewal rewrites the files inside this directory and the
    running container sees them, no recreate. Changing the list recreates the
    container anyway (reconfigure replaces it).
    """
    if not isinstance(index, int) or index < 0:
        raise CertificateMountError('certificate entry index must be a non-negative integer')
    return f'{certificates_root(application)}/{index}'


def first_pem_block(text):
    match = PEM_BLOCK.search(text or '')
    if match is None:
        raise CertificateMountError('certificate does not contain a PEM block')
    return match.group(0).strip()


def rendered_files(certificate):
    """The four certbot files for a certificate, as ``{name: text}``.

    ``fullchain.pem`` is the chain the host's own ``<name>.crt`` carries
    (``'\\n'.join(chain_list)``) plus a final newline, as certbot writes it, so an
    internally signed certificate brings its root along as a host service sees it and
    ``cat fullchain.pem privkey.pem`` stays valid PEM.
    """
    chain_list = certificate.get('chain_list')
    if not isinstance(chain_list, list) or not chain_list or not all(
        isinstance(item, str) for item in chain_list
    ):
        raise CertificateMountError('certificate has no parsable chain')
    privatekey = certificate.get('privatekey')
    if not isinstance(privatekey, str) or not privatekey.strip():
        raise CertificateMountError('certificate has no private key')
    leaf = first_pem_block(chain_list[0])
    intermediates = [first_pem_block(item) for item in chain_list[1:]]
    return {
        CERT_FILE: leaf + '\n',
        # Zero bytes with no intermediate: the file is always there to point at.
        CHAIN_FILE: ('\n'.join(intermediates) + '\n') if intermediates else '',
        FULLCHAIN_FILE: '\n'.join(chain_list).strip() + '\n',
        PRIVKEY_FILE: privatekey.strip() + '\n',
    }


def public_key_sha256(certificate):
    """SHA-256 of the leaf's SubjectPublicKeyInfo: what an entry is bound to.

    Stable across an ACME renewal (same CSR, same key) and a rename; different for any
    other certificate, including one that happens to hold the same id on another system.
    """
    chain_list = certificate.get('chain_list')
    if not isinstance(chain_list, list) or not chain_list or not isinstance(chain_list[0], str):
        raise CertificateMountError('certificate has no parsable chain')
    try:
        leaf = x509.load_pem_x509_certificate(first_pem_block(chain_list[0]).encode())
        spki = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except CertificateMountError:
        raise
    except Exception as error:
        raise CertificateMountError(f'certificate public key cannot be read: {error}') from error
    return hashlib.sha256(spki).hexdigest()


def entry_owner(entry, runtime_owner):
    """``(uid, gid)`` for an entry's files.

    The entry's own uid/gid wins; otherwise the uid/gid the image says it runs as
    (PUID/PGID, the internal development record); otherwise root:wheel.
    """
    uid = entry.get('uid')
    gid = entry.get('gid')
    if uid is None or gid is None:
        if runtime_owner is not None:
            owner_uid, owner_gid = runtime_owner
            uid = owner_uid if uid is None else uid
            gid = owner_gid if gid is None else gid
    return (0 if uid is None else uid, 0 if gid is None else gid)


def validate_entries(entries, volume_targets=(), prefix='certificates'):
    """Structural validation of a record's/request's certificate entries.

    Returns the list of errors as ``(schema, message)``; the caller decides whether
    they are ``ValidationErrors`` (install) or an exception (record read).
    """
    errors = []
    if entries is None:
        return errors
    if not isinstance(entries, list):
        return [(prefix, 'certificates must be a list')]
    if len(entries) > MAX_CERTIFICATES:
        errors.append((prefix, f'At most {MAX_CERTIFICATES} certificates are supported.'))
    seen_targets = []
    seen_ids = []
    for index, entry in enumerate(entries):
        at = f'{prefix}.{index}'
        if not isinstance(entry, dict):
            errors.append((at, 'invalid certificate declaration'))
            continue
        if type(entry.get('id')) is not int:
            errors.append((f'{at}.id', 'A certificate id is required.'))
        if not isinstance(entry.get('name'), str) or not entry['name']:
            errors.append((f'{at}.name', 'A certificate name is required.'))
        fingerprint = entry.get('fingerprint')
        if not isinstance(fingerprint, str) or not fingerprint:
            errors.append((f'{at}.fingerprint', 'A certificate fingerprint is required.'))
        target = entry.get('target')
        if not isinstance(target, str):
            errors.append((f'{at}.target', 'A target directory is required.'))
        else:
            try:
                validate_target(target)
            except CertificateMountError as error:
                errors.append((f'{at}.target', str(error)))
            else:
                seen_targets.append((index, target))
        if not isinstance(entry.get('restart_on_change'), bool):
            errors.append((f'{at}.restart_on_change', 'restart_on_change must be true or false.'))
        for field in ('uid', 'gid'):
            value = entry.get(field)
            if value is not None and (type(value) is not int or value < 0):
                errors.append((f'{at}.{field}', f'{field} must be a non-negative integer.'))
        key = entry.get('public_key_sha256')
        if key is not None and (not isinstance(key, str) or not PUBLIC_KEY_SHA256.match(key)):
            errors.append((f'{at}.public_key_sha256', 'public_key_sha256 must be a SHA-256 hex digest.'))
        if isinstance(entry.get('id'), int):
            seen_ids.append((index, entry['id'], target if isinstance(target, str) else None))

    for index, target in seen_targets:
        for other_index, other in seen_targets:
            if other_index >= index:
                continue
            if target == other:
                errors.append((
                    f'{prefix}.{index}.target',
                    'Certificate target directories must be unique.',
                ))
            elif _is_within(target, other) or _is_within(other, target):
                errors.append((
                    f'{prefix}.{index}.target',
                    f'Certificate target {target!r} and {other!r} contain one another.',
                ))
        for volume_target in volume_targets:
            if not isinstance(volume_target, str):
                continue
            if target == volume_target or _is_within(target, volume_target):
                errors.append((
                    f'{prefix}.{index}.target',
                    f'Certificate target {target!r} is inside the volume mounted at '
                    f'{volume_target!r}; choose a directory of its own.',
                ))
            elif _is_within(volume_target, target):
                errors.append((
                    f'{prefix}.{index}.target',
                    f'Certificate target {target!r} contains the volume mounted at '
                    f'{volume_target!r}.',
                ))

    pairs = [(item[1], item[2]) for item in seen_ids]
    if len(pairs) != len(set(pairs)):
        errors.append((prefix, 'The same certificate cannot be mounted twice at one directory.'))
    return errors


def validate_target(target):
    if not target.startswith('/') or target == '/' or ':' in target or '\x00' in target:
        raise CertificateMountError(
            'A certificate target must be an absolute path below /.'
        )
    if posixpath.normpath(target) != target:
        raise CertificateMountError('A certificate target must be normalized.')
    return target


def _is_within(path, parent):
    return path.startswith(parent.rstrip('/') + '/')


def bound_entry(entry):
    """The record form of an entry: exactly the fields a record carries.

    ``public_key_sha256`` is set by the service from the certificate store, never by a
    caller (the public schemas do not declare it); an entry without it is one bound
    before the key was recorded and is checked by fingerprint instead.
    """
    result = {
        'id': entry['id'],
        'name': entry['name'],
        'fingerprint': entry['fingerprint'],
        'target': entry['target'],
        'restart_on_change': bool(entry.get('restart_on_change', True)),
        'uid': entry.get('uid'),
        'gid': entry.get('gid'),
    }
    if entry.get('public_key_sha256') is not None:
        result['public_key_sha256'] = entry['public_key_sha256']
    return result


def public_entry(entry):
    """What the page may see: no key material, ever -- only the reference."""
    return {
        'id': entry.get('id'),
        'name': entry.get('name'),
        'fingerprint': entry.get('fingerprint'),
        'target': entry.get('target'),
        'restart_on_change': bool(entry.get('restart_on_change', True)),
        'uid': entry.get('uid'),
        'gid': entry.get('gid'),
    }


def content_hash(rendered_entries):
    """A hash of what is mounted, so a renewal is detected by content, not by event.

    ``rendered_entries`` is the per-entry ``{name: text}`` mapping in record order.
    The private key is part of the hash (a re-keyed renewal changes it) but the hash
    is one-way, so storing it beside the record leaks nothing.
    """
    canonical = json.dumps(rendered_entries, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


def mount_arguments(record):
    """``--volume`` arguments for the record's certificate entries, in record order."""
    arguments = []
    for index, entry in enumerate(record.get('certificates') or []):
        source = entry_directory(record['name'], index)
        arguments.extend(['--volume', f'{source}:{entry["target"]}:ro'])
    return arguments
