"""Remote OCI image inspection without pulling (skopeo).

``sysutils/podman-suite`` ships skopeo.  Two bounded metadata reads give the
platform-specific manifest digest and the image configuration, which is enough
to answer three questions before any layer is fetched: what OS and architecture
the tag resolves to, which upstream project the image says it comes from, and
whether the image wants an init system we cannot give it.

Every failure here is soft: the caller decides whether "unknown" is acceptable.
"""
import json
import re

from middlewared.utils import run
from middlewared.utils.network import INTERNET_TIMEOUT

SKOPEO_PATH = '/usr/local/bin/skopeo'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
INIT_ENTRYPOINTS = {
    '/sbin/init', '/usr/sbin/init', '/lib/systemd/systemd', '/usr/lib/systemd/systemd',
    'systemd', 'init', '/bin/systemd',
}
# Compose or run-time requests that a jail-backed container cannot honour and
# that the Applications safety contract (the internal development record) never grants.
UNSUPPORTED_REQUESTS = (
    'privileged', 'cap_add', 'devices', 'sysctls', 'security_opt', 'userns_mode',
    'cgroup_parent', 'ipc', 'pid',
)


def _reference(image):
    if not isinstance(image, str) or not image or image.startswith('-') or any(
        character.isspace() for character in image
    ) or '\x00' in image:
        raise ValueError('Image reference must not begin with - or contain NUL/whitespace.')
    return f'docker://{image}'


# the internal development record: the registry answered and the tag does not exist.
# Everything else skopeo can fail with (no route, TLS, a 403 from a private or
# absent repository, a timeout) leaves the question open.
MISSING_MANIFEST = re.compile(r'manifest unknown|MANIFEST_UNKNOWN', re.IGNORECASE)
VERDICT_FOUND = 'found'
VERDICT_MISSING = 'missing'
VERDICT_UNKNOWN = 'unknown'


async def _skopeo(arguments, timeout):
    """(parsed JSON or None, stderr) -- stderr is what says why there is no JSON."""
    try:
        cp = await run(
            [SKOPEO_PATH, '--command-timeout', f'{int(timeout)}s', *arguments],
            check=False, encoding='utf8',
        )
    except (FileNotFoundError, PermissionError):
        return None, ''
    if cp.returncode:
        return None, cp.stderr or ''
    try:
        return json.loads(cp.stdout), ''
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, ''


async def probe_remote_image(image, os_name='freebsd', architecture='amd64', timeout=None):
    """``(inspection, verdict)``: the inspection ``inspect_remote_image`` returns, and
    whether its absence is definitive.

    ``missing`` means the registry answered and has no such tag; ``unknown`` means
    the question could not be put (offline, refused, timed out, skopeo absent).
    """
    timeout = INTERNET_TIMEOUT if timeout is None else timeout
    reference = _reference(image)
    platform = ['--override-os', os_name, '--override-arch', architecture]
    summary, error = await _skopeo(['inspect', '--no-tags', *platform, reference], timeout)
    if not isinstance(summary, dict):
        if MISSING_MANIFEST.search(error):
            return None, VERDICT_MISSING
        return None, VERDICT_UNKNOWN
    inspection = await _describe(summary, platform, reference, timeout)
    return inspection, VERDICT_FOUND if inspection is not None else VERDICT_UNKNOWN


async def inspect_remote_image(image, os_name='freebsd', architecture='amd64', timeout=None):
    """Return a normalised description of what the reference resolves to, or None.

    ``digest`` is the manifest digest of the platform child the registry serves
    for the requested OS/architecture, so a pull of ``<repository>@<digest>``
    gets exactly what was inspected.
    """
    inspection, _ = await probe_remote_image(image, os_name, architecture, timeout)
    return inspection


async def _describe(summary, platform, reference, timeout):
    image = reference[len('docker://'):]
    digest = summary.get('Digest')
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return None
    labels = summary.get('Labels') or {}
    if not isinstance(labels, dict):
        labels = {}
    config_blob, _ = await _skopeo(['inspect', '--config', *platform, reference], timeout)
    config = {}
    if isinstance(config_blob, dict) and isinstance(config_blob.get('config'), dict):
        config = config_blob['config']
    env = config.get('Env') or summary.get('Env') or []
    environment = {}
    for item in env if isinstance(env, list) else []:
        if isinstance(item, str) and '=' in item:
            name, value = item.split('=', 1)
            environment[name] = value
    return {
        'reference': image,
        'digest': digest,
        'os': str(summary.get('Os') or (config_blob or {}).get('os') or '').lower(),
        'architecture': str(
            summary.get('Architecture') or (config_blob or {}).get('architecture') or ''
        ).lower(),
        'labels': {str(key): str(value) for key, value in labels.items()},
        'environment': environment,
        'entrypoint': list(config.get('Entrypoint') or []),
        'cmd': list(config.get('Cmd') or []),
        'user': str(config.get('User') or ''),
        'volumes': sorted((config.get('Volumes') or {}).keys()),
        'exposed_ports': sorted((config.get('ExposedPorts') or {}).keys()),
    }


def image_refusals(inspection, expected_os='linux', expected_architecture='amd64'):
    """Reasons an inspected image cannot be installed, empty when it can.

    Static and conservative: only what the image itself declares.  An image
    that passes may still fail at runtime -- the Linux ABI is best effort.
    """
    reasons = []
    if inspection is None:
        return reasons
    if inspection['os'] and inspection['os'] != expected_os:
        reasons.append(
            f'image resolves to operating system {inspection["os"]!r}, not {expected_os!r}'
        )
    if inspection['architecture'] and inspection['architecture'] not in {
        expected_architecture, 'x86_64' if expected_architecture == 'amd64' else expected_architecture,
    }:
        reasons.append(
            f'image resolves to architecture {inspection["architecture"]!r}, '
            f'not {expected_architecture!r}'
        )
    command = [*inspection['entrypoint'], *inspection['cmd']]
    first = next((item for item in command if item and not item.startswith('-')), None)
    if first is not None and (first in INIT_ENTRYPOINTS or first.rsplit('/', 1)[-1] == 'systemd'):
        reasons.append(
            f'image starts an init system ({first}); a container runs one process and the '
            'Linux ABI provides no systemd'
        )
    return reasons
