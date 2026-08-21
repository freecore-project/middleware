import contextlib
import json
import os
import posixpath
import re
import tempfile

from middlewared.plugins.applications_ import certificates as app_certificates

PODMAN_PATH = '/usr/local/bin/podman'
APPLICATION_LABEL = 'io.freecore.application'
MANAGED_LABEL = 'io.freecore.managed'
TRANSACTION_LABEL = 'io.freecore.transaction'
RUNTIME_DIR = '/var/run/freecore-applications'
RUNTIME_PF_ACTIVE = f'{RUNTIME_DIR}/pf-active'
RUNTIME_READY = f'{RUNTIME_DIR}/ready'
VOLATILE_RUNROOT = f'{RUNTIME_DIR}/storage'
# the internal development record: where the host's own podman reads its configuration.
# The containers-common package installs @sample copies here; storage.conf is
# replaced with the pool's while the runtime is ready, the drop-in only exists then.
HOST_CONTAINERS_DIR = '/usr/local/etc/containers'
HOST_STORAGE_CONF_SAMPLE = f'{HOST_CONTAINERS_DIR}/storage.conf.sample'
NETWORK_OWNED_ANNOTATIONS = {
    'org.freebsd.jail.ip4.addr',
    'org.freebsd.jail.ip6.add',
    'org.freebsd.jail.ip6.addr',
    'org.freebsd.jail.jid',
    'org.freebsd.jail.vnet',
}
# the internal development record: Docker's default lets an unprivileged service bind ports below 1024
# (ip_unprivileged_port_start=0). ocijail sets this in the container's own vnet before the process
# runs (the internal development record; a stock ocijail ignores the annotation). The appliance adds it to every
# container; a record or a catalog entry cannot carry it (CATALOG_RUNTIME_ANNOTATIONS).
UNPRIVILEGED_PORTS_ANNOTATION = ('org.freebsd.jail.vnet.sysctl.net.inet.ip.portrange.reservedhigh', '0')
CATALOG_RUNTIME_ANNOTATIONS = {
    'org.freebsd.jail.allow.mlock': {'true'},
    'org.freebsd.jail.allow.raw_sockets': {'true'},
    'org.freebsd.jail.sysvmsg': {'new'},
    'org.freebsd.jail.sysvsem': {'new'},
    'org.freebsd.jail.sysvshm': {'new'},
}


def application_paths(pool):
    dataset = f'{pool}/applications'
    mountpoint = f'/mnt/{dataset}'
    return {
        'dataset': dataset,
        'mountpoint': mountpoint,
        'storage_dataset': f'{dataset}/storage',
        'storage': f'{mountpoint}/storage',
        'config_dataset': f'{dataset}/config',
        'config': f'{mountpoint}/config',
        'records_dataset': f'{dataset}/records',
        'records': f'{mountpoint}/records',
        'data_dataset': f'{dataset}/data',
        'data': f'{mountpoint}/data',
        'storage_conf': f'{mountpoint}/config/storage.conf',
        'containers_conf': f'{mountpoint}/config/containers.conf',
        'cni': f'{mountpoint}/config/cni/net.d',
    }


LAN_NETWORK_PREFIX = 'freecore-lan-'


def lan_network_name(application):
    return f'{LAN_NETWORK_PREFIX}{application}'


def lan_conflist_path(pool, application):
    return f'{application_paths(pool)["cni"]}/90-{LAN_NETWORK_PREFIX}{application}.conflist'


def lan_managed_network_name(application):
    return f'freecore-managed-{application}'


def lan_managed_conflist_path(pool, application):
    return f'{application_paths(pool)["cni"]}/91-freecore-managed-{application}.conflist'


def render_managed_leg_conflist(application, bridge, address):
    """The managed-bridge leg of a dual-attached application (the internal development record).

    An on-link presence in the managed subnet and nothing more: no routes (the
    LAN leg owns the only default), no masquerade, no gateway duties -- and
    static IPAM, because podman's own host-local allocator must remain the only
    dynamic allocator on this subnet.
    """
    return json.dumps({
        'cniVersion': '0.4.0',
        'name': lan_managed_network_name(application),
        'plugins': [{
            'type': 'bridge',
            'bridge': bridge,
            'isGateway': False,
            'ipMasq': False,
            'ipam': {
                'type': 'static',
                'addresses': [{'address': address}],
            },
        }],
    }, indent=2, sort_keys=True) + '\n'


def render_lan_conflist(application, bridge, address, gateway):
    """The CNI network of one LAN-attached application (the internal development record).

    The bridge plugin attaches the container's epair to ``bridge`` and neither
    addresses nor NATs it (isGateway/ipMasq false; the managed pf anchors are
    not involved).  Static IPAM carries the one address and the LAN gateway --
    the FreeBSD plugin set ships no dhcp IPAM, so static is the contract, not
    a simplification.
    """
    return json.dumps({
        'cniVersion': '0.4.0',
        'name': lan_network_name(application),
        'plugins': [{
            'type': 'bridge',
            'bridge': bridge,
            'isGateway': False,
            'ipMasq': False,
            'ipam': {
                'type': 'static',
                'addresses': [{'address': address, 'gateway': gateway}],
                'routes': [{'dst': '0.0.0.0/0', 'gw': gateway}],
            },
        }],
    }, indent=2, sort_keys=True) + '\n'


def render_storage_conf(pool):
    paths = application_paths(pool)
    return (
        '# Generated by middlewared for native Applications.\n'
        '[storage]\n'
        'driver = "zfs"\n'
        f'runroot = {json.dumps(VOLATILE_RUNROOT)}\n'
        f'graphroot = {json.dumps(paths["storage"])}\n'
        '\n'
        '[storage.options]\n'
        'additionalimagestores = []\n'
    )


def render_containers_conf(pool, subnet):
    paths = application_paths(pool)
    return (
        '# Generated by middlewared for native Applications.\n'
        '[network]\n'
        'network_backend = "cni"\n'
        f'network_config_dir = {json.dumps(paths["cni"])}\n'
        f'default_subnet = {json.dumps(subnet)}\n'
        '\n'
        '[engine]\n'
        'events_logger = "file"\n'
        f'events_logfile_path = {json.dumps(paths["records"] + "/events.log")}\n'
    )


def podman_scratch(pool):
    """Where podman stages image blobs for Applications (the internal development record).

    podman copies an image it pulls, builds or imports through a temporary
    directory, /var/tmp unless TMPDIR says otherwise -- on the appliance that is
    the boot device, often small.  Middleware passes this directory, on the
    Applications pool, as TMPDIR.  The rendered containers.conf stays as it is:
    its bytes are a contract with the host configuration.
    """
    return f'{application_paths(pool)["mountpoint"]}/tmp'


def podman_environment(pool):
    paths = application_paths(pool)
    return {
        'CONTAINERS_STORAGE_CONF': paths['storage_conf'],
        # Keep the FreeBSD containers-common defaults (including ocijail) and
        # load only the pool-specific Applications settings last.
        'CONTAINERS_CONF_OVERRIDE': paths['containers_conf'],
    }


def host_podman_ready(config):
    """Whether the host's podman may point at the Applications store.

    the internal development record: a pool is selected and the runtime marker is set. The
    marker rather than config['runtime_ready'], which is also false during a pool
    transition; pool_available regenerates rc from inside the transition once the
    runtime is ready again, and the host configuration has to follow the store.
    """
    return bool(config['pool'] and os.path.exists(RUNTIME_READY))


def validate_mount_target(target):
    if not target.startswith('/') or target == '/' or ':' in target or '\x00' in target:
        raise ValueError('Container mount target must be an absolute path below /.')
    if posixpath.normpath(target) != target:
        raise ValueError('Container mount target must be normalized.')
    return target


# the internal development record: a compose `user:` -- a user name or uid, optionally :group or :gid.
RUNTIME_USER = re.compile(r'(?:[0-9]{1,10}|[a-z_][a-z0-9_.-]{0,31})(?::(?:[0-9]{1,10}|[a-z_][a-z0-9_.-]{0,31}))?')


def validate_volume_subpath(subpath):
    """A file volume's file: one name inside its owned dataset (the internal development record)."""
    if not isinstance(subpath, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,255}', subpath) or \
            subpath in ('.', '..'):
        raise ValueError('Volume file must be a single file name inside the volume.')
    return subpath


def validate_image_reference(image):
    if image.startswith('-') or '\x00' in image or any(character.isspace() for character in image):
        raise ValueError('Image reference must not begin with - or contain NUL/whitespace.')
    return image


def podman_create_args(
    record, podman_path=PODMAN_PATH, environment_file=None, transaction_id=None,
):
    args = [
        podman_path,
        'create',
        '--name',
        record['container_name'],
        '--label',
        f'{MANAGED_LABEL}=true',
        '--label',
        f'{APPLICATION_LABEL}={record["name"]}',
        '--restart',
        record['restart_policy'],
    ]
    if transaction_id is not None:
        args[4:4] = ['--label', f'{TRANSACTION_LABEL}={transaction_id}']

    # the internal development record: a LAN-attached application joins its own CNI
    # network and publishes nothing -- it answers on its own address, so the
    # declared ports are informational there.
    network = record.get('network') or {'mode': 'managed'}
    lan_attached = network.get('mode') == 'lan'
    if not lan_attached and network.get('bridge_address'):
        # the internal development record: a stable address on the managed bridge, kept by
        # podman across every start of this container.
        args.extend(['--ip', network['bridge_address']])
    if lan_attached:
        args.extend(['--network', lan_network_name(record['name'])])
        # the internal development record: the optional managed-bridge leg of a gateway.
        if network.get('managed_access'):
            args.extend(['--network', lan_managed_network_name(record['name'])])

    for annotation in sorted(record.get('annotations', []), key=lambda item: item['name']):
        args.extend(['--annotation', f'{annotation["name"]}={annotation["value"]}'])
    args.extend(['--annotation', '='.join(UNPRIVILEGED_PORTS_ANNOTATION)])

    # the internal development record: the provider's stop grace period; podman stop and restart honour it.
    runtime = record.get('runtime') or {}
    if runtime.get('stop_timeout') is not None:
        args.extend(['--stop-timeout', str(runtime['stop_timeout'])])
    # the internal development record: names the container resolves to fixed addresses (its /etc/hosts).
    for item in runtime.get('extra_hosts') or []:
        args.extend(['--add-host', f'{item["host"]}:{item["address"]}'])
    # the internal development record: the user the service runs as (a compose `user:`).
    if runtime.get('user'):
        args.extend(['--user', runtime['user']])

    # the internal development record: user-defined labels. `io.freecore.` names are refused by both the
    # install validator and _validate_record, so a user label cannot impersonate the management
    # labels that query(), boot recovery and transaction rollback recognise our containers by.
    # Emitted last and name-sorted, so the argument list stays deterministic.
    for label in sorted(record.get('labels', []), key=lambda item: item['name']):
        args.extend(['--label', f'{label["name"]}={label["value"]}'])

    if record.get('environment'):
        if not environment_file:
            raise ValueError('An environment file is required when environment values are present.')
        args.extend(['--env-file', environment_file])

    if not lan_attached:
        # the internal development record: a port without a host port stays on the managed
        # bridge -- reachable from the other applications by the bridge address, not
        # published on the host.
        for port in sorted(
            (item for item in record.get('ports', []) if item['host_port'] is not None),
            key=lambda item: (item['host_port'], item['protocol'], item['container_port']),
        ):
            args.extend([
                '--publish',
                f'{port["host_port"]}:{port["container_port"]}/{port["protocol"]}',
            ])

    for volume in sorted(record.get('volumes', []), key=lambda item: item['name']):
        mode = 'ro' if volume['read_only'] else 'rw'
        args.extend(['--volume', f'{volume["source"]}:{volume["target"]}:{mode}'])

    # the internal development record: one read-only directory per mounted certificate, rendered
    # under /var/run (tmpfs). The source path is derived from the record, so a renewal
    # rewrites the files in place and the running container sees them.
    args.extend(app_certificates.mount_arguments(record))

    args.extend(['--', validate_image_reference(record['image'])])
    return args


@contextlib.contextmanager
def temporary_environment_file(record, directory=VOLATILE_RUNROOT):
    environment = sorted(record.get('environment', []), key=lambda item: item['name'])
    if not environment:
        yield None
        return

    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, path = tempfile.mkstemp(prefix='.application-env-', dir=directory)
    try:
        with os.fdopen(descriptor, 'w') as file:
            for item in environment:
                value = item['value']
                if any(character in value for character in ('\x00', '\r', '\n')):
                    raise ValueError('Environment values cannot contain NUL or newline characters.')
                file.write(f'{item["name"]}={value}\n')
            file.flush()
            os.fsync(file.fileno())
        os.chmod(path, 0o600)
        yield path
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def public_record(record):
    result = json.loads(json.dumps(record))
    # the internal development record: records written before schema 3 are native images
    # of catalog origin; present them with the fields newer records carry.
    result.setdefault('image_os', 'freebsd')
    result.setdefault('origin', None)
    # the internal development record: records written before schema 4 are managed-bridge.
    result.setdefault('network', {'mode': 'managed'})
    # the internal development record: records written before labels existed carry none, and the page
    # should still get the field rather than having to test for it.
    result.setdefault('labels', [])
    # the internal development record: records written before runtime options carry none.
    result.setdefault('runtime', {})
    # the internal development record: the reference only -- no key material ever reaches the page.
    result['certificates'] = [
        app_certificates.public_entry(entry) for entry in (result.get('certificates') or [])
    ]
    result['environment'] = [
        {'name': item['name'], 'set': True}
        for item in result.get('environment', [])
    ]
    return result


def atomic_write(path, content, mode=0o600):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.middlewared-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


# the internal development record: a container start that fails part way through its mounts can leave every
# mount it had made behind (ocijail before the the internal development record patch unwound nothing), and podman then
# removes the container without them. A nullfs bind out of an owned dataset into that dead rootfs
# keeps the dataset busy for good, so a rollback's `zfs destroy` fails and the datasets leak.
GRAPH_ROOT = re.compile(r'^(?P<root>.*/zfs/graph/[0-9a-f]{64})(?:/|$)')


def parse_mounts(text):
    """`mount -p` lines (source, target, fstype, options, dump, pass) as dicts; blank lines skipped."""
    entries = []
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) >= 3:
            entries.append({'source': parts[0], 'target': parts[1], 'fstype': parts[2]})
    return entries


def _under(path, prefixes):
    return any(path == prefix or path.startswith(prefix + '/') for prefix in prefixes)


def leaked_container_mounts(entries, dataset_mountpoints):
    """The mounts a failed container left on an application's owned datasets, deepest target first.

    A bind whose *source* lies in one of ``dataset_mountpoints`` is the leak itself; everything else
    still mounted under that container's rootfs (its proc, sys, dev, userdata binds) came from the
    same failed start and goes with it. The rootfs' own zfs layer mount is podman's and stays, as
    does anything belonging to another container.
    """
    roots = set()
    for entry in entries:
        if entry['fstype'] != 'zfs' and _under(entry['source'], dataset_mountpoints):
            match = GRAPH_ROOT.match(entry['target'])
            if match:
                roots.add(match.group('root'))
            # the internal development record: a bind outside a podman graph root is nobody's failed container (an
            # operator's nullfs of the dataset into a jail, say). It still holds the dataset busy, so it is
            # released by itself; nothing mounted next to it is touched.
    selected = [
        entry for entry in entries
        if (entry['fstype'] != 'zfs' and _under(entry['source'], dataset_mountpoints))
        or any(entry['target'].startswith(root + '/') for root in roots)
    ]
    return sorted(selected, key=lambda entry: (-entry['target'].count('/'), entry['target']))
