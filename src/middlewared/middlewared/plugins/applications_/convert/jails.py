"""Jail describers for the lift (the internal development record): iocage and Bastille.

Both read only.  A description says where the root is, which dataset holds it
and what it was cloned from, which release it carries, how the jail was
parameterised, what it mounts, what it listens on when it is running, and
which packages it holds.  The engine decides nothing here.
"""
import os
import re

from middlewared.plugins.applications_.convert import lift, probes
from middlewared.plugins.bastille_.utils import bastille_paths
from middlewared.service_exception import CallError
from middlewared.utils import run

IOCAGE_PARAMETERS = (
    'basejail', 'type', 'vnet', 'ip4_addr', 'ip6_addr', 'interfaces', 'devfs_ruleset',
    'exec_start', 'exec_stop', 'allow_raw_sockets', 'allow_mlock', 'allow_sysvipc',
    'sysvmsg', 'sysvsem', 'sysvshm', 'jid', 'plugin_name', 'template',
    *lift.IOCAGE_UNSUPPORTED,
)
MAX_TEXT = 1024 * 1024


def _read_text(path, required=False):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as file:
            return file.read(MAX_TEXT)
    except FileNotFoundError:
        if required:
            raise CallError(f'{path} is missing.') from None
        return ''
    except OSError as error:
        raise CallError(f'Unable to read {path}: {error}') from error


async def zfs_property(dataset, name):
    completed = await run(
        ['/sbin/zfs', 'get', '-Hp', '-o', 'value', name, dataset], check=False, encoding='utf8',
    )
    if completed.returncode:
        return None
    value = (completed.stdout or '').strip()
    return None if value in ('', '-') else value


async def dataset_exists(middleware, dataset):
    return bool(await middleware.call('zfs.dataset.query', [('id', '=', dataset)]))


async def listening_ports(jid):
    """What a running jail listens on, from sockstat(1) on the host; [] when it cannot be read."""
    if not jid:
        return []
    completed = await run(
        ['/usr/bin/sockstat', '-4', '-6', '-l', '-j', str(jid)], check=False, encoding='utf8',
    )
    if completed.returncode:
        return []
    return lift.parse_sockstat(completed.stdout or '')


def _base(description, root, jail_root_directory):
    fstab = _read_text(os.path.join(jail_root_directory, 'fstab'))
    description['fstab'] = lift.parse_fstab(fstab, root)
    # Mounts that are the jail's own base system (an iocage basejail borrows its
    # release directory by directory; a Bastille thin jail mounts it at /.bastille)
    # are the base layer, never volumes.
    releases = description.get('releases_root')
    for mount in description['fstab']:
        mount['base'] = mount['target'] == '/' + lift.BASTILLE_MOUNT or bool(
            releases and mount['source'].startswith(releases.rstrip('/') + '/')
        )
    description['rc_conf'] = _read_text(os.path.join(root, 'etc', 'rc.conf'))
    description['userland'] = lift.userland_release(root)
    description['packages'] = [
        {'name': name, 'version': version, 'automatic': automatic}
        for name, version, automatic in probes.installed_packages(root)
    ]
    return description


async def describe_iocage(middleware, name):
    if not name:
        raise CallError('A jail name is required.')
    if not await middleware.call('jail.iocage_set_up'):
        raise CallError('iocage is not set up on this system.')
    jails = await middleware.call('jail.query', [('id', '=', name)])
    if not jails:
        raise CallError(f'Jail {name!r} does not exist.')
    jail = jails[0]
    iocroot = await middleware.call('jail.get_iocroot')
    directory = f'{iocroot}/jails/{name}'
    root = f'{directory}/root'
    # iocage keeps a jail's root at <activated pool>/iocage/jails/<name>/root;
    # the iocroot mountpoint names the pool. Fall back to a mountpoint match
    # for an iocroot that is not under /mnt.
    dataset = None
    if iocroot.startswith('/mnt/'):
        candidate = f'{iocroot[len("/mnt/"):]}/jails/{name}/root'
        if await dataset_exists(middleware, candidate):
            dataset = candidate
    if dataset is None:
        datasets = await middleware.call('zfs.dataset.query', [('mountpoint', '=', root)])
        dataset = datasets[0]['id'] if datasets else None
    parameters = {key: jail.get(key) for key in IOCAGE_PARAMETERS if key in jail}
    origin = await zfs_property(dataset, 'origin') if dataset else None
    basejail = str(parameters.get('basejail')) in ('1', 'True', 'true')
    if origin:
        root_kind = 'clone'
    elif basejail:
        root_kind = 'basejail'
    else:
        root_kind = 'thick'
    description = {
        'kind': 'jail',
        'engine': 'iocage',
        'ref': name,
        'root': root,
        'directory': directory,
        'releases_root': f'{iocroot}/releases',
        'dataset': dataset,
        'origin': origin,
        'root_kind': root_kind,
        'state': jail.get('state'),
        'jid': parameters.get('jid') if jail.get('state') == 'up' else None,
        'release': jail.get('release'),
        'parameters': parameters,
        'annotations': [],
        'unsupported': [],
        'plugin': parameters.get('plugin_name') or None,
    }
    description['annotations'], description['unsupported'] = lift.iocage_annotations(parameters)
    if str(parameters.get('template')) in ('1', 'True', 'true'):
        description['unsupported'].append('template')
    if origin:
        origin_dataset = origin.split('@', 1)[0]
        description['base_root'] = None
        mountpoint = await zfs_property(origin_dataset, 'mountpoint')
        if mountpoint and mountpoint != 'legacy':
            description['base_root'] = os.path.join(mountpoint, '.zfs', 'snapshot', origin.split('@', 1)[1])
        description['base_guid'] = await zfs_property(origin, 'guid')
        description['base_release'] = os.path.basename(os.path.dirname(origin_dataset)) \
            if origin_dataset.endswith('/root') else os.path.basename(origin_dataset)
    elif basejail:
        # iocage names the release dataset without the patch level (15.1-RELEASE for a
        # 15.1-RELEASE-p3 jail); the basejail's own fstab names the directory it borrows.
        description['base_release'] = None
        description['base_root'] = None
        description['base_guid'] = None
        fstab_text = _read_text(os.path.join(directory, 'fstab'))
        for mount in lift.parse_fstab(fstab_text, root):
            prefix = f'{iocroot}/releases/'
            if mount['source'].startswith(prefix) and '/root/' in mount['source'][len(prefix):]:
                release_name = mount['source'][len(prefix):].split('/root/', 1)[0]
                description['base_release'] = release_name
                description['base_root'] = f'{iocroot}/releases/{release_name}/root'
                break
        if description['base_root'] is None:
            release = re.sub(r'-p\d+$', '', str(jail.get('release') or ''))
            if release:
                description['base_release'] = release
                description['base_root'] = f'{iocroot}/releases/{release}/root'
    else:
        description['base_release'] = None
        description['base_root'] = None
        description['base_guid'] = None
    return _base(description, root, directory)


async def describe_bastille(middleware, name):
    if not name:
        raise CallError('A jail name is required.')
    config = await middleware.call('bastille.config')
    if not config.get('pool'):
        raise CallError('Bastille is not configured on this system.')
    rows = await middleware.call('bastille.query', [('id', '=', name)])
    if not rows:
        raise CallError(f'Bastille jail {name!r} does not exist.')
    jail = rows[0]
    paths = bastille_paths(config['pool'])
    directory = os.path.join(paths['jails'], name)
    root = jail.get('path') or os.path.join(directory, 'root')
    dataset = None
    for candidate in (f'{paths["jails_dataset"]}/{name}/root', f'{paths["jails_dataset"]}/{name}'):
        if await dataset_exists(middleware, candidate):
            mountpoint = await zfs_property(candidate, 'mountpoint')
            if mountpoint == root:
                dataset = candidate
                break
    settings = lift.parse_jail_conf(_read_text(os.path.join(directory, 'jail.conf')))
    origin = await zfs_property(dataset, 'origin') if dataset else None
    thin = lift.is_bastille_thin(root)
    if origin:
        root_kind = 'clone'
    elif thin:
        root_kind = 'thin'
    else:
        root_kind = 'thick'
    annotations, unsupported = lift.bastille_annotations(settings)
    description = {
        'kind': 'jail',
        'engine': 'bastille',
        'ref': name,
        'root': root,
        'directory': directory,
        'releases_root': paths['releases'],
        'dataset': dataset,
        'origin': origin,
        'root_kind': root_kind,
        'state': jail.get('state'),
        'jid': jail.get('jid') if jail.get('state') == 'up' else None,
        'release': jail.get('release'),
        'parameters': {
            'exec_start': settings.get('exec.start'),
            'exec_stop': settings.get('exec.stop'),
            'ip4_addr': settings.get('ip4.addr'),
            'ip6_addr': settings.get('ip6.addr'),
            'vnet': settings.get('vnet'),
            'devfs_ruleset': settings.get('devfs_ruleset'),
        },
        'annotations': annotations,
        'unsupported': unsupported,
        'plugin': None,
        'base_release': None,
        'base_root': None,
        'base_guid': None,
    }
    if origin:
        origin_dataset = origin.split('@', 1)[0]
        mountpoint = await zfs_property(origin_dataset, 'mountpoint')
        if mountpoint and mountpoint != 'legacy':
            description['base_root'] = os.path.join(mountpoint, '.zfs', 'snapshot', origin.split('@', 1)[1])
        description['base_guid'] = await zfs_property(origin, 'guid')
        description['base_release'] = os.path.basename(origin_dataset)
    elif thin and jail.get('release'):
        description['base_release'] = jail['release']
        description['base_root'] = os.path.join(paths['releases'], jail['release'])
    return _base(description, root, directory)


async def describe(middleware, engine, name):
    if engine == 'bastille':
        return await describe_bastille(middleware, name)
    return await describe_iocage(middleware, name)
