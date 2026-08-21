"""The generic jail lift (the internal development record): pure parts, planner, apply."""
import json
import os
import sqlite3
import subprocess
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.applications_.convert import jails as jail_sources, lift, plan as plan_doc, probes
from middlewared.plugins.applications_convert_freebsd import ApplicationsConvertService
from middlewared.service_exception import CallError

ROOT = '/mnt/tank/iocage/jails/grafanajail/root'
ZFS_DIFF = '\n'.join([
    f'-\tF\t{ROOT}/etc/passwd',
    f'+\tF\t{ROOT}/etc/passwd',
    f'-\tF\t{ROOT}/etc/hosts',
    f'+\tF\t{ROOT}/etc/hosts',
    f'+\tF\t{ROOT}/etc/resolv.conf',
    f'M\t/\t{ROOT}/etc',
    f'+\t/\t{ROOT}/usr/local/share/grafana/public/vanilla\\0040prometheus',
    f'+\tF\t{ROOT}/usr/local/bin/grafana',
    f'+\tF\t{ROOT}/var/db/grafana/grafana.db',
    f'-\tF\t{ROOT}/usr/share/examples/README',
    f'R\tF\t{ROOT}/etc/old.conf\t{ROOT}/etc/new.conf',
    f'M\t/\t{ROOT}',
    'garbage line',
]) + '\n'

RC_CONF = """\
cron_flags="$cron_flags -J 15"
sendmail_enable="NO"
hostname="grafanajail"
ifconfig_vnet0="inet 192.0.2.50/24"
ifconfig_vnet0_ipv6="inet6 auto_linklocal"
defaultrouter="192.0.2.1"
ipv6_defaultrouter="fe80::1%vnet0"
syslogd_flags="-c -ss"
grafana_enable="YES"
"""

SOCKSTAT = """\
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
grafana  grafana    30579 34 tcp46  *:3050                *:*
root     sshd       30001 4  tcp4   192.0.2.50:22         *:*
root     syslogd    30002 6  dgram  /var/run/log
root     unbound    30003 5  udp4   *:53                  *:*
root     unbound    30004 6  tcp4   *:53                  *:*
grafana  grafana    30579 35 tcp4   127.0.0.1:3050        *:*
"""


def make_root(root, thirteen=False, thin=False):
    """A jail root with the trees the lift splits, plus a pkg database."""
    for relative in ('bin', 'etc', 'usr/local/bin', 'usr/local/etc/rc.d', 'usr/local/share/app',
                     'var/db/grafana', 'var/run', 'var/tmp', 'var/cache/pkg/All', 'var/log', 'root',
                     'tmp'):
        os.makedirs(os.path.join(root, relative), exist_ok=True)
    with open(os.path.join(root, 'bin', 'freebsd-version'), 'w') as file:
        file.write('#!/bin/sh\nUSERLAND_VERSION="15.1-RELEASE-p3"\n')
    with open(os.path.join(root, 'etc', 'rc.conf'), 'w') as file:
        file.write(RC_CONF)
    with open(os.path.join(root, 'usr/local/etc/rc.d/grafana'), 'w') as file:
        file.write('#!/bin/sh\n')
    with open(os.path.join(root, 'usr/local/etc/grafana.ini'), 'w') as file:
        file.write('[server]\nhttp_addr = 192.0.2.50\n')
    with open(os.path.join(root, 'var/db/grafana/grafana.db'), 'wb') as file:
        file.write(b'sqlite')
    with open(os.path.join(root, 'var/run/grafana.pid'), 'w') as file:
        file.write('1')
    with open(os.path.join(root, 'var/cache/pkg/All/grafana.pkg'), 'wb') as file:
        file.write(b'pkg')
    with open(os.path.join(root, 'var/log/messages'), 'w') as file:
        file.write('log')
    if thirteen:
        os.makedirs(os.path.join(root, 'usr/home/alice'))
        os.symlink('usr/home', os.path.join(root, 'home'))
    else:
        os.makedirs(os.path.join(root, 'home/alice'))
    if thin:
        os.makedirs(os.path.join(root, '.bastille'))
        for name in ('lib', 'sbin', 'usr/bin', 'usr/lib', 'usr/share'):
            os.makedirs(os.path.dirname(os.path.join(root, name)) or root, exist_ok=True)
            if os.path.isdir(os.path.join(root, name)):
                os.rmdir(os.path.join(root, name))
            os.symlink(f'/.bastille/{name}', os.path.join(root, name))
    pkgdb = os.path.join(root, 'var/db/pkg')
    os.makedirs(pkgdb, exist_ok=True)
    connection = sqlite3.connect(os.path.join(pkgdb, 'local.sqlite'))
    connection.execute('CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT, version TEXT, automatic INTEGER)')
    connection.execute("INSERT INTO packages (name, version, automatic) VALUES ('grafana', '13.1.1', 0)")
    connection.execute("INSERT INTO packages (name, version, automatic) VALUES ('sqlite3', '3.46', 1)")
    connection.commit()
    connection.close()
    return root


# -- pure parts ----------------------------------------------------------------

def test_zfs_diff_reconciles_replacements_managed_files_and_escapes():
    added, removed = lift.parse_zfs_diff(ZFS_DIFF, ROOT)
    assert 'etc/passwd' in added and 'etc/passwd' not in removed
    assert 'etc/hosts' not in added and 'etc/hosts' not in removed
    assert 'etc/resolv.conf' not in added
    assert 'usr/local/share/grafana/public/vanilla prometheus' in added
    assert 'etc' in added and 'var/db/grafana/grafana.db' in added
    assert removed == {'usr/share/examples/README', 'etc/old.conf'}
    assert 'etc/new.conf' in added
    assert '' not in added


def test_walk_partition_and_state_trees(tmp_path):
    root = make_root(str(tmp_path / 'root'))
    paths = lift.walk_root(root)
    assert 'var/db/grafana/grafana.db' in paths and 'usr/local/etc/rc.d/grafana' in paths and 'home/alice' in paths
    assert '.zfs' not in paths
    state = lift.state_volumes(root)
    assert [item['name'] for item in state] == ['var', 'usr-local-etc', 'root', 'home']
    image = lift.partition(paths, [item['path'] for item in state])
    assert 'var' in image and 'var/db/grafana/grafana.db' not in image
    assert 'usr/local/etc' in image and 'usr/local/etc/rc.d/grafana' not in image
    assert 'usr/local/bin' in image and 'bin/freebsd-version' in image
    assert 'home' in image and 'home/alice' not in image
    listing = lift.state_listing(root, 'var')
    assert 'db/grafana/grafana.db' in listing and 'log/messages' in listing
    assert 'run' in listing and 'run/grafana.pid' not in listing
    assert 'cache/pkg' in listing and 'cache/pkg/All' not in listing
    assert 'tmp' in listing


def test_a_thirteen_root_keeps_the_home_symlink_in_the_image(tmp_path):
    root = make_root(str(tmp_path / 'root'), thirteen=True)
    state = lift.state_volumes(root)
    assert [item['name'] for item in state] == ['var', 'usr-local-etc', 'root', 'usr-home']
    image = lift.partition(lift.walk_root(root), [item['path'] for item in state])
    assert 'home' in image and 'usr/home' in image and 'usr/home/alice' not in image
    assert lift.userland_release(root) == '15.1-RELEASE-p3'
    assert lift.userland_release(str(tmp_path)) is None


def test_bastille_thin_roots_borrow_their_base(tmp_path):
    root = make_root(str(tmp_path / 'root'), thin=True)
    borrowed = lift.bastille_borrowed(root)
    assert {'lib', 'sbin', 'usr/bin', 'usr/lib', 'usr/share', '.bastille'} == borrowed
    assert lift.is_bastille_thin(root) is True
    assert lift.is_bastille_thin(str(make_root(str(tmp_path / 'thick')))) is False
    walked = lift.walk_root(root, skip=borrowed)
    assert 'usr/bin' not in walked and '.bastille' not in walked and 'usr/local/bin' in walked


def test_rc_conf_rewrite_drops_only_network_identity():
    text, dropped = lift.rewrite_rc_conf(RC_CONF)
    assert sorted(dropped) == ['defaultrouter', 'hostname', 'ifconfig_vnet0', 'ifconfig_vnet0_ipv6', 'ipv6_defaultrouter']
    assert 'grafana_enable="YES"' in text and 'cron_flags' in text and 'sendmail_enable' in text
    assert 'ifconfig_vnet0' not in text and 'hostname=' not in text
    assert text.startswith('# Network identity removed')
    assert lift.rewrite_rc_conf('') == (lift.rewrite_rc_conf('')[0], [])


def test_fstab_sockstat_and_parameters():
    fstab = f"""
# comment
/mnt/tank/media {ROOT}/media nullfs ro 0 0
/mnt/tank/downloads {ROOT}/downloads nullfs rw 0 0 # trailing
proc {ROOT}/proc procfs rw 0 0
/mnt/elsewhere /somewhere/else nullfs rw 0 0
"""
    mounts = lift.parse_fstab(fstab, ROOT)
    assert mounts == [
        {'source': '/mnt/tank/media', 'target': '/media', 'fstype': 'nullfs', 'read_only': True},
        {'source': '/mnt/tank/downloads', 'target': '/downloads', 'fstype': 'nullfs', 'read_only': False},
        {'source': 'proc', 'target': '/proc', 'fstype': 'procfs', 'read_only': False},
    ]
    ports = lift.parse_sockstat(SOCKSTAT)
    assert [(item['container_port'], item['protocol'], item['command']) for item in ports] == [
        (22, 'tcp', 'sshd'), (53, 'tcp', 'unbound'), (53, 'udp', 'unbound'), (3050, 'tcp', 'grafana'),
    ]
    annotations, unsupported = lift.iocage_annotations({
        'allow_raw_sockets': 1, 'allow_mlock': '0', 'sysvmsg': 'new', 'sysvsem': 'inherit', 'sysvshm': 'new',
        'allow_mount_nullfs': 1, 'allow_mount': '0',
    })
    assert annotations == [
        {'name': 'org.freebsd.jail.allow.raw_sockets', 'value': 'true'},
        {'name': 'org.freebsd.jail.sysvmsg', 'value': 'new'},
        {'name': 'org.freebsd.jail.sysvshm', 'value': 'new'},
    ]
    assert unsupported == ['allow_mount_nullfs']
    settings = lift.parse_jail_conf("""
grafanajail {
  enforce_statfs = 2;
  exec.start = '/bin/sh /etc/rc';
  allow.raw_sockets;
  sysvmsg = new;
  allow.mount.zfs = 1;
  mount.fstab = "/usr/local/bastille/jails/grafanajail/fstab";
  ip4.addr = 192.0.2.51;   # static
}
""")
    assert settings['exec.start'] == '/bin/sh /etc/rc' and settings['allow.raw_sockets'] is True
    assert settings['ip4.addr'] == '192.0.2.51'
    annotations, unsupported = lift.bastille_annotations(settings)
    assert {item['name'] for item in annotations} == {'org.freebsd.jail.allow.raw_sockets', 'org.freebsd.jail.sysvmsg'}
    assert unsupported == ['allow.mount.zfs']


def test_containerfile_tags_and_mentions(tmp_path):
    text = lift.render_containerfile('localhost/freecore/jail-base:15.1-RELEASE-1234567890', {
        'usr/share/examples/README', "etc/it's.conf",
    }, {'io.freecore.plan': 'abc', 'io.freecore.converted-from': 'iocage:grafanajail'})
    lines = text.splitlines()
    assert lines[0] == 'FROM localhost/freecore/jail-base:15.1-RELEASE-1234567890'
    assert lines[1] == 'ADD delta.tar /' and lines[2] == 'COPY overlay/ /'
    assert lines[3] == f'COPY jail-init {lift.INIT_TARGET}'
    assert lines[4] == "RUN rm -rf -- '/etc/it'\"'\"'s.conf' /usr/share/examples/README"
    assert 'LABEL io.freecore.converted-from=iocage:grafanajail' in lines
    assert lines[-1] == 'ENTRYPOINT ["/usr/local/libexec/freecore-jail-init"]'
    scratch = lift.render_containerfile(None, set(), {}, overlay=False)
    assert scratch.startswith('FROM scratch\nADD delta.tar /\nCOPY jail-init')
    assert lift.sanitize_tag('15.1-RELEASE-p3') == '15.1-RELEASE-p3'
    assert lift.sanitize_tag('my template/x@y') == 'my-template-x-y'
    assert lift.sanitize_tag('') == 'unknown'
    root = make_root(str(tmp_path / 'root'))
    assert lift.mentions_of(os.path.join(root, 'usr/local/etc'), '192.0.2.50') == ['grafana.ini']
    assert lift.mentions_of(os.path.join(root, 'usr/local/etc'), '') == []
    lift.install_init(str(tmp_path))
    assert os.access(tmp_path / 'jail-init', os.X_OK)
    assert '/bin/sh /etc/rc' in (tmp_path / 'jail-init').read_text()
    assert probes.installed_packages(root) == [('grafana', '13.1.1', False), ('sqlite3', '3.46', True)]


@pytest.mark.skipif(not os.path.exists(lift.TAR), reason='bsdtar is required')
def test_listed_tar_and_faithful_copy_round_trip(tmp_path):
    root = make_root(str(tmp_path / 'root'))
    os.symlink('grafana.db', os.path.join(root, 'var/db/grafana/link.db'))
    state = lift.state_listing(root, 'var')
    listing = str(tmp_path / 'var.list')
    lift.write_listing(state, listing)
    destination = str(tmp_path / 'dataset')
    lift.copy_tree(os.path.join(root, 'var'), listing, destination)
    assert os.path.isfile(os.path.join(destination, 'db/grafana/grafana.db'))
    assert os.path.islink(os.path.join(destination, 'db/grafana/link.db'))
    assert os.path.isdir(os.path.join(destination, 'run')) and not os.listdir(os.path.join(destination, 'run'))
    assert os.path.isdir(os.path.join(destination, 'cache/pkg')) and not os.listdir(os.path.join(destination, 'cache/pkg'))
    image = lift.partition(lift.walk_root(root), ['var', 'usr/local/etc', 'root', 'home'])
    image_listing = str(tmp_path / 'image.list')
    lift.write_listing(image, image_listing)
    tar = str(tmp_path / 'delta.tar')
    lift.create_tar(root, image_listing, tar)
    names = [name.rstrip('/') for name in subprocess.run([lift.TAR, '-tf', tar], capture_output=True, text=True, check=True).stdout.split()]
    assert 'usr/local/bin' in names and 'var' in names and 'bin/freebsd-version' in names
    assert not any(name.startswith('var/db') for name in names)
    with pytest.raises(lift.LiftError, match='failed'):
        lift.create_tar(str(tmp_path / 'missing'), image_listing, tar)


# -- planner ---------------------------------------------------------------------

def service_with_middleware(tmp_path, config=None):
    middleware = Mock()
    middleware.call = AsyncMock()

    async def run_in_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    middleware.run_in_thread = AsyncMock(side_effect=run_in_thread)
    service = ApplicationsConvertService(middleware)
    service._applications_config = AsyncMock(return_value=config or {
        'pool': 'tank', 'convert_enabled': True, 'linux_compat_enabled': False, 'runtime_ready': True,
    })
    service._plans_dir = Mock(return_value=str(tmp_path / 'plans'))
    return service, middleware


ORIGIN = 'tank/iocage/releases/15.1-RELEASE/root@grafanajail'


def patch_seams(monkeypatch, tmp_path, origin=ORIGIN, listening=()):
    """The describer's ZFS and sockstat reads; the origin snapshot is a directory under tmp_path."""
    origin_root = tmp_path / 'origin'
    (origin_root / '.zfs' / 'snapshot' / 'grafanajail').mkdir(parents=True, exist_ok=True)

    async def zfs_property(dataset, name):
        if name == 'origin':
            return origin if 'jails/' in dataset else None
        if name == 'guid':
            return '18446744073709551615'
        if name == 'mountpoint':
            return str(origin_root)
        if name in ('used', 'referenced'):
            return '917504000'
        return None

    async def listening_ports(jid):
        return list(listening)

    monkeypatch.setattr(jail_sources, 'zfs_property', zfs_property)
    monkeypatch.setattr(jail_sources, 'listening_ports', listening_ports)


def iocage_jail(tmp_path, **overrides):
    jail = {
        'name': 'grafanajail', 'id': 'grafanajail', 'state': 'up', 'jid': 7, 'release': '15.1-RELEASE-p3',
        'basejail': 0, 'type': 'jail', 'vnet': 0, 'ip4_addr': 'vtnet0|192.0.2.50/24', 'devfs_ruleset': 4,
        'exec_start': '/bin/sh /etc/rc', 'exec_stop': '/bin/sh /etc/rc.shutdown', 'allow_raw_sockets': 1,
        'allow_mlock': 0, 'sysvmsg': 'new', 'sysvsem': 'new', 'sysvshm': 'new', 'allow_mount_nullfs': 0,
        'template': 0,
    }
    jail.update(overrides)
    return jail


def standard_calls(tmp_path, jail, extra=None, port_free=True, datasets=()):
    async def call(method, *args):
        if method == 'jail.iocage_set_up':
            return True
        if method == 'jail.query':
            return [jail]
        if method == 'jail.get_iocroot':
            return str(tmp_path)
        if method == 'zfs.dataset.query':
            wanted = args[0][0][2] if args and args[0] else None
            return [{'id': wanted}] if wanted and 'grafanajail' in wanted else []
        if method == 'zfs.snapshot.create':
            return True
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}, {'name': 'sonarr'}]
        if method == 'applications.host_port_free':
            return await port_free(*args) if callable(port_free) else port_free
        if method == 'pool.dataset.query':
            return list(datasets)
        if method == 'applications.catalog.details':
            return {'install': {'ports': [{'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}]}}
        if extra is not None:
            return await extra(method, *args)
        raise AssertionError(f'unexpected call {method}')
    return call


@pytest.mark.asyncio
async def test_lift_plan_for_a_running_clone_jail(tmp_path, monkeypatch):
    root = make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    with open(tmp_path / 'jails' / 'grafanajail' / 'fstab', 'w') as file:
        file.write(f'/mnt/tank/media {root}/media nullfs ro 0 0\n/mnt/tank/scratch/sub {root}/scratch nullfs rw 0 0\n')
    os.makedirs(os.path.join(root, 'media'))
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path)
    middleware.call.side_effect = standard_calls(tmp_path, jail, datasets=[
        {'id': 'tank/media', 'mountpoint': '/mnt/tank/media'}, {'id': 'tank/scratch', 'mountpoint': '/mnt/tank/scratch'},
    ])
    patch_seams(monkeypatch, tmp_path, listening=lift.parse_sockstat(SOCKSTAT))
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.uuid.uuid4', lambda: Mock(hex='abc' * 11))

    with pytest.raises(CallError) as excinfo:
        await service.plan({'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None}, {})
    message = str(excinfo.value)
    # A non-dataset nullfs mount is refused with the reason; so is a port whose host side is taken.
    assert '/mnt/tank/scratch/sub' in message and 'not a dataset mountpoint' in message

    with open(tmp_path / 'jails' / 'grafanajail' / 'fstab', 'w') as file:
        file.write(f'/mnt/tank/media {root}/media nullfs ro 0 0\n')

    async def free(port, protocol):
        return port != 22

    middleware.call.side_effect = standard_calls(tmp_path, jail, port_free=free, datasets=[
        {'id': 'tank/media', 'mountpoint': '/mnt/tank/media'},
    ])
    with pytest.raises(CallError, match='choose a host port for 22/tcp'):
        await service.plan({'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None}, {})

    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None},
        {'ports': [
            {'container_port': 3050, 'protocol': 'tcp', 'host_port': 3050},
            {'container_port': 53, 'protocol': 'udp', 'host_port': 5353},
            {'container_port': 22, 'protocol': 'tcp', 'host_port': None},
        ]},
    )
    assert plan['mode'] == 'lift' and plan['recommended'] == 'lift'
    assert plan['modes']['lift']['available'] is True
    assert plan['modes']['native']['available'] is False
    assert plan['source']['engine'] == 'iocage' and plan['source']['snapshot'].startswith('freecore-convert-')
    assert plan['application']['name'] == 'grafanajail'
    meta = plan['lift']
    assert meta['delta'] == 'zfs-diff' and meta['root_kind'] == 'clone'
    assert meta['base']['reference'] == 'localhost/freecore/jail-base:15.1-RELEASE-3709551615'
    assert meta['base']['root'] == f'{tmp_path}/origin/.zfs/snapshot/grafanajail'
    assert meta['origin'] == 'tank/iocage/releases/15.1-RELEASE/root@grafanajail'
    assert [item['name'] for item in meta['state_volumes']] == ['var', 'usr-local-etc', 'root', 'home']
    assert meta['external_volumes'] == [
        {'name': 'mount-media', 'target': '/media', 'dataset': 'tank/media', 'read_only': True},
    ]
    assert meta['ports'] == [
        {'host_port': 3050, 'container_port': 3050, 'protocol': 'tcp'},
        {'host_port': 5353, 'container_port': 53, 'protocol': 'udp'},
    ]
    assert meta['ports_detected_from'] == 'listening'
    assert meta['annotations'] == [
        {'name': 'org.freebsd.jail.allow.raw_sockets', 'value': 'true'},
        {'name': 'org.freebsd.jail.sysvmsg', 'value': 'new'},
        {'name': 'org.freebsd.jail.sysvsem', 'value': 'new'},
        {'name': 'org.freebsd.jail.sysvshm', 'value': 'new'},
    ]
    assert 'ifconfig_vnet0' in meta['rc_conf_dropped'] and meta['size_bytes'] == 917504000
    assert meta['userland'] == '15.1-RELEASE-p3' and meta['packages'] == ['grafana']
    assert meta['image_repository'] == 'localhost/freecore/converted/grafanajail'
    types = [item['type'] for item in plan['entries']]
    assert 'refuse' not in types
    whats = {item.get('what') for item in plan['entries']}
    assert {'rc_conf', 'image', 'port', 'annotation', 'running', 'address'} <= whats
    address = next(item for item in plan['entries'] if item.get('what') == 'address')
    assert address['address'] == '192.0.2.50' and address['files'] == ['grafana.ini']
    assert plan['plan_id'] == plan_doc.plan_id(plan)
    assert json.loads((tmp_path / 'plans' / f'{plan["plan_id"]}.json').read_text()) == plan


@pytest.mark.asyncio
async def test_lift_plan_for_a_stopped_basejail_uses_the_release_and_catalog_ports(tmp_path, monkeypatch):
    root = make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    os.makedirs(tmp_path / 'releases' / '15.1-RELEASE' / 'root')
    # iocage's basejail fstab borrows the release directory by directory; the jail's
    # release property carries the patch level the dataset name does not.
    with open(tmp_path / 'jails' / 'grafanajail' / 'fstab', 'w') as file:
        for name in ('bin', 'lib', 'usr/share'):
            file.write(f'{tmp_path}/releases/15.1-RELEASE/root/{name} {root}/{name} nullfs ro 0 0\n')
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path, state='down', jid=None, basejail=1, release='15.1-RELEASE-p3', ip4_addr='none')
    middleware.call.side_effect = standard_calls(tmp_path, jail)
    patch_seams(monkeypatch, tmp_path, origin=None)

    plan = await service.plan({'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None}, {})
    meta = plan['lift']
    assert meta['delta'] == 'walk' and meta['root_kind'] == 'basejail'
    assert meta['skip'] == list(lift.BASEJAIL_DIRECTORIES)
    assert meta['base']['reference'] == 'localhost/freecore/jail-base:15.1-RELEASE'
    assert meta['base']['root'] == f'{tmp_path}/releases/15.1-RELEASE/root'
    assert meta['external_volumes'] == [] and meta['release'] == '15.1-RELEASE-p3'
    assert meta['ports'] == [{'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}]
    assert meta['ports_detected_from'] == 'catalog:grafana'
    assert not any(item.get('what') == 'running' for item in plan['entries'])
    assert not any(item.get('what') == 'address' for item in plan['entries'])


@pytest.mark.asyncio
async def test_lift_refuses_templates_missing_releases_and_datasets(tmp_path, monkeypatch):
    make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path, state='down', jid=None, basejail=1, release='14.3-RELEASE', template=1)
    middleware.call.side_effect = standard_calls(tmp_path, jail)
    patch_seams(monkeypatch, tmp_path, origin=None)
    with pytest.raises(CallError) as excinfo:
        await service.plan({'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None}, {})
    message = str(excinfo.value)
    assert 'iocage template' in message and 'not readable' in message
    detect = await service.detect({'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None})
    assert detect['root_kind'] == 'basejail' and detect['packages'][0]['name'] == 'grafana'
    assert 'no recipe recognises this jail' in detect['refusals']
    # The wizard chooses host ports from what detect proposes; nothing large rides along.
    assert detect['ports'] == [{'container_port': 3000, 'protocol': 'tcp', 'host_port': 3000, 'command': 'grafana'}]
    assert detect['ports_detected_from'] == 'catalog:grafana' and 'rc_conf' not in detect


@pytest.mark.asyncio
async def test_sources_list_both_engines_with_lift_and_catalog_matches(tmp_path, monkeypatch):
    root = make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    bastille_root = make_root(str(tmp_path / 'bastille' / 'jails' / 'sonarrjail' / 'root'), thin=True)
    service, middleware = service_with_middleware(tmp_path)

    async def call(method, *args):
        return {
            'applications.catalog.query': [{'name': 'grafana'}],
            'jail.iocage_set_up': True,
            'jail.get_iocroot': str(tmp_path),
            'jail.query': [iocage_jail(tmp_path)],
            'bastille.config': {'pool': 'tank'},
            'bastille.query': [{'name': 'sonarrjail', 'state': 'down', 'release': '15.1-RELEASE', 'path': bastille_root, 'operable': True}],
        }[method]

    middleware.call.side_effect = call
    rows = await service.sources()
    assert [(row['engine'], row['name'], row['lift']) for row in rows] == [
        ('iocage', 'grafanajail', True), ('bastille', 'sonarrjail', True),
    ]
    assert rows[0]['catalog'] == ['grafana'] and rows[0]['packages'] == [{'name': 'grafana', 'version': '13.1.1'}]
    assert rows[0]['app'] is None and rows[0]['root'] == root


@pytest.mark.asyncio
async def test_bastille_thin_jail_is_described_from_its_configuration(tmp_path, monkeypatch):
    prefix = tmp_path / 'mnt' / 'tank' / 'bastille'
    root = make_root(str(prefix / 'jails' / 'sonarrjail' / 'root'), thin=True)
    (prefix / 'releases' / '15.1-RELEASE').mkdir(parents=True)
    with open(prefix / 'jails' / 'sonarrjail' / 'jail.conf', 'w') as file:
        file.write('sonarrjail {\n  exec.start = "/bin/sh /etc/rc";\n  allow.raw_sockets;\n  sysvshm = new;\n  ip4.addr = 192.0.2.51;\n}\n')
    with open(prefix / 'jails' / 'sonarrjail' / 'fstab', 'w') as file:
        file.write(f'{prefix}/releases/15.1-RELEASE {root}/.bastille nullfs ro 0 0\n')
    middleware = Mock()

    async def call(method, *args):
        if method == 'bastille.config':
            return {'pool': 'tank'}
        if method == 'bastille.query':
            return [{'name': 'sonarrjail', 'state': 'up', 'jid': 9, 'release': '15.1-RELEASE', 'path': root}]
        if method == 'zfs.dataset.query':
            return [{'id': args[0][0][2]}] if args[0][0][2] == 'tank/bastille/jails/sonarrjail/root' else []
        raise AssertionError(method)

    middleware.call = AsyncMock(side_effect=call)

    async def zfs_property(dataset, name):
        return {'mountpoint': root, 'origin': None, 'referenced': '1000'}.get(name)

    monkeypatch.setattr(jail_sources, 'zfs_property', zfs_property)
    monkeypatch.setattr('middlewared.plugins.applications_.convert.jails.bastille_paths', lambda pool: {
        'jails': str(prefix / 'jails'), 'jails_dataset': 'tank/bastille/jails', 'releases': str(prefix / 'releases'),
    })
    description = await jail_sources.describe(middleware, 'bastille', 'sonarrjail')
    assert description['engine'] == 'bastille' and description['root_kind'] == 'thin'
    assert description['dataset'] == 'tank/bastille/jails/sonarrjail/root' and description['jid'] == 9
    assert description['base_root'] == str(prefix / 'releases' / '15.1-RELEASE')
    assert description['base_release'] == '15.1-RELEASE'
    assert {item['name'] for item in description['annotations']} == {
        'org.freebsd.jail.allow.raw_sockets', 'org.freebsd.jail.sysvshm',
    }
    assert description['parameters']['ip4_addr'] == '192.0.2.51'
    assert description['userland'] == '15.1-RELEASE-p3'
    assert description['fstab'] == [{
        'source': str(prefix / 'releases' / '15.1-RELEASE'), 'target': '/.bastille', 'fstype': 'nullfs', 'read_only': True,
        'base': True,
    }]

    # The planner leaves the release mount alone: it is the base layer, not a volume.
    service, planner_middleware = service_with_middleware(tmp_path)

    async def planner_call(method, *args):
        return {'applications.catalog.query': [], 'applications.host_port_free': True, 'pool.dataset.query': []}[method]

    planner_middleware.call.side_effect = planner_call
    description['dataset'] = 'tank/bastille/jails/sonarrjail/root'
    description['jid'] = None
    entries, refusals, meta = await service._lift_entries(description, {}, {})
    assert refusals == [] and meta['external_volumes'] == []
    assert meta['delta'] == 'walk' and meta['skip'] == ['.bastille', 'lib', 'sbin', 'usr/bin', 'usr/lib', 'usr/share']
    assert meta['base']['reference'] == 'localhost/freecore/jail-base:15.1-RELEASE'


# -- apply ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lift_apply_builds_the_image_carries_state_and_installs(tmp_path, monkeypatch):
    root = make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path, state='down', jid=None)
    calls = []
    mountpoints = {}

    async def extra(method, *args):
        calls.append((method, args))
        if method == 'zfs.snapshot.query':
            return [{'id': args[0][0][2]}]
        if method == 'zfs.snapshot.delete':
            return True
        if method == 'applications.query':
            return []
        if method == 'applications.podman':
            if args[0] == 'image' and args[1] == 'exists':
                return {'returncode': 1, 'stdout': '', 'stderr': ''}
            if args[0] == 'build':
                context = args[-1]
                calls.append(('containerfile', (open(os.path.join(context, 'Containerfile')).read(),)))
                calls.append(('overlay', (open(os.path.join(context, 'overlay', 'etc', 'rc.conf')).read(),)))
                calls.append(('tar-listing', (open(os.path.join(context, 'image.list'), 'rb').read(),)))
                assert os.path.isfile(os.path.join(context, 'delta.tar'))
                assert os.access(os.path.join(context, 'jail-init'), os.X_OK)
                return {'returncode': 0, 'stdout': 'sha256:built', 'stderr': ''}
            raise AssertionError(args)
        if method == 'applications.prepare_owned_volume':
            mountpoint = tmp_path / 'data' / args[0] / args[1]
            mountpoint.mkdir(parents=True)
            mountpoints[args[1]] = str(mountpoint)
            return {'dataset': f'tank/applications/data/{args[0]}/{args[1]}', 'mountpoint': str(mountpoint),
                    'created': [f'tank/applications/data/{args[0]}/{args[1]}']}
        if method == 'applications.install_with_origin':
            return 'subjob'
        raise AssertionError(f'unexpected call {method}')

    async def wrapped(method, *args):
        calls.append((method, args))
        return await standard_calls(tmp_path, jail, extra=extra)(method, *args)

    middleware.call.side_effect = wrapped
    patch_seams(monkeypatch, tmp_path)
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.uuid.uuid4', lambda: Mock(hex='def' * 11))
    imported = []
    monkeypatch.setattr(lift, 'import_base', lambda base_root, reference, labels, env: imported.append((base_root, reference, labels)))

    async def zfs_diff(command, **kwargs):
        assert command[:3] == ['/sbin/zfs', 'diff', '-FH']
        # Everything in the fixture root is "added" relative to the base, plus two removals.
        lines = [f'+\tF\t{root}/{path}' for path in sorted(lift.walk_root(root))]
        lines += [f'-\tF\t{root}/usr/share/examples/README', f'R\tF\t{root}/etc/old.conf\t{root}/etc/rc.conf',
                  f'-\tF\t{root}/etc/hosts', f'+\tF\t{root}/etc/hosts']
        return Mock(returncode=0, stdout='\n'.join(lines) + '\n', stderr='')

    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.run', zfs_diff)

    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None},
        {'ports': [{'container_port': 3050, 'protocol': 'tcp', 'host_port': 13050}]},
    )
    snapshot_root = tmp_path / 'jails' / 'grafanajail' / 'root' / '.zfs' / 'snapshot' / plan['source']['snapshot']
    snapshot_root.parent.mkdir(parents=True)
    os.symlink(root, snapshot_root)

    job = Mock()
    job.wrap = AsyncMock(return_value={'name': 'grafanajail'})
    result = await ApplicationsConvertService.apply.wraps(service, job, plan['plan_id'], {'confirm': True})

    assert result == {'name': 'grafanajail'}
    assert imported == [(
        f'{tmp_path}/origin/.zfs/snapshot/grafanajail',
        'localhost/freecore/jail-base:15.1-RELEASE-3709551615',
        {'io.freecore.jail-base': '15.1-RELEASE',
         'io.freecore.base-source': f'{tmp_path}/origin/.zfs/snapshot/grafanajail',
         'io.freecore.base-guid': '18446744073709551615'},
    )]
    containerfile = next(args[0] for method, args in calls if method == 'containerfile')
    assert containerfile.startswith('FROM localhost/freecore/jail-base:15.1-RELEASE-3709551615\nADD delta.tar /\nCOPY overlay/ /\n')
    assert "RUN rm -rf -- /etc/old.conf /usr/share/examples/README" in containerfile
    assert 'LABEL io.freecore.converted-from=iocage:grafanajail' in containerfile
    assert f'LABEL io.freecore.plan={plan["plan_id"]}' in containerfile
    overlay = next(args[0] for method, args in calls if method == 'overlay')
    assert 'grafana_enable="YES"' in overlay and 'ifconfig_vnet0' not in overlay
    listing = next(args[0] for method, args in calls if method == 'tar-listing').split(b'\0')
    assert b'etc/rc.conf' not in listing and b'bin/freebsd-version' in listing and b'var' in listing
    assert b'var/db/grafana/grafana.db' not in listing and b'etc/hosts' not in listing
    assert os.path.isfile(os.path.join(mountpoints['var'], 'db', 'grafana', 'grafana.db'))
    assert os.path.isfile(os.path.join(mountpoints['usr-local-etc'], 'rc.d', 'grafana'))
    assert os.path.isdir(os.path.join(mountpoints['home'], 'alice'))
    install = next(args for method, args in calls if method == 'applications.install_with_origin')
    payload, origin = install
    assert payload['image'] == f'localhost/freecore/converted/grafanajail:{plan["plan_id"][:12]}'
    assert payload['image_os'] == 'freebsd' and payload['healthcheck'] is None
    assert payload['ports'] == [{'host_port': 13050, 'container_port': 3050, 'protocol': 'tcp'}]
    assert [item['name'] for item in payload['volumes']] == ['var', 'usr-local-etc', 'root', 'home']
    assert payload['annotations'][0] == {'name': 'org.freebsd.jail.allow.raw_sockets', 'value': 'true'}
    assert origin['kind'] == 'convert' and origin['mode'] == 'lift' and origin['engine'] == 'iocage'
    assert origin['image_owned'] is True and origin['image'] == payload['image']
    assert origin['base_image'] == 'localhost/freecore/jail-base:15.1-RELEASE-3709551615'
    assert all(isinstance(value, (str, int, bool, type(None))) for value in origin.values())
    assert ('zfs.snapshot.delete', (f'{plan["source"]["dataset"]}@{plan["source"]["snapshot"]}', {'defer': False})) in calls
    assert not (tmp_path / 'plans' / f'{plan["plan_id"]}.json').exists()
    assert not (tmp_path / 'plans' / 'work').exists() or not os.listdir(tmp_path / 'plans' / 'work')


@pytest.mark.asyncio
async def test_lift_apply_removes_the_built_image_when_the_install_fails(tmp_path, monkeypatch):
    root = make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path, state='down', jid=None)
    podman = []

    async def extra(method, *args):
        if method == 'zfs.snapshot.query':
            return [{'id': args[0][0][2]}]
        if method == 'applications.query':
            return []
        if method == 'applications.podman':
            podman.append(args)
            if args[0] == 'image':
                return {'returncode': 0, 'stdout': '', 'stderr': ''}
            return {'returncode': 0, 'stdout': '', 'stderr': ''}
        if method == 'applications.prepare_owned_volume':
            mountpoint = tmp_path / 'data' / args[1]
            mountpoint.mkdir(parents=True)
            return {'dataset': f'tank/applications/data/x/{args[1]}', 'mountpoint': str(mountpoint),
                    'created': [f'tank/applications/data/x/{args[1]}']}
        if method == 'applications.install_with_origin':
            raise CallError('Application container stopped during startup')
        if method == 'applications.discard_owned_datasets':
            podman.append(('discard', args))
            return []
        raise AssertionError(method)

    middleware.call.side_effect = standard_calls(tmp_path, jail, extra=extra)
    patch_seams(monkeypatch, tmp_path, origin=None)
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.uuid.uuid4', lambda: Mock(hex='fed' * 11))
    jail['basejail'] = 1
    jail['release'] = '15.1-RELEASE'
    os.makedirs(tmp_path / 'releases' / '15.1-RELEASE' / 'root')

    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None},
        {'ports': [{'container_port': 3000, 'protocol': 'tcp', 'host_port': 3000}]},
    )
    snapshot_root = tmp_path / 'jails' / 'grafanajail' / 'root' / '.zfs' / 'snapshot' / plan['source']['snapshot']
    snapshot_root.parent.mkdir(parents=True)
    os.symlink(root, snapshot_root)

    job = Mock()
    with pytest.raises(CallError, match='stopped during startup'):
        await ApplicationsConvertService.apply.wraps(service, job, plan['plan_id'], {'confirm': True})
    image = f'localhost/freecore/converted/grafanajail:{plan["plan_id"][:12]}'
    assert ('rmi', '--force', image, False) in podman
    assert any(item[0] == 'discard' for item in podman)
    # The base was already present: no import, and the failed apply leaves the plan for a retry.
    assert (tmp_path / 'plans' / f'{plan["plan_id"]}.json').exists()
    build = next(item for item in podman if item[0] == 'build')
    assert build[3] == image


# the internal development record: a loopback-bound listener is published with a warning; wording follows the state.

def test_sockstat_prefers_the_reachable_address_when_a_port_is_bound_twice():
    ports = lift.parse_sockstat(
        'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n'
        'git forgejo 1 19 tcp4 127.0.0.1:3000 *:*\n'
        'git forgejo 1 20 tcp46 *:3000 *:*\n'
        'root nginx 2 6 tcp4 127.0.0.1:8080 *:*\n'
    )
    assert [(p['container_port'], p['address']) for p in ports] == [(3000, '*'), (8080, '127.0.0.1')]
    assert lift.is_loopback('127.0.0.1') and lift.is_loopback('::1') and not lift.is_loopback('*')


@pytest.mark.asyncio
async def test_lift_plan_warns_about_a_loopback_listener_and_names_a_running_jails_silence(tmp_path, monkeypatch):
    make_root(str(tmp_path / 'jails' / 'grafanajail' / 'root'))
    with open(tmp_path / 'jails' / 'grafanajail' / 'fstab', 'w') as file:
        file.write('')
    service, middleware = service_with_middleware(tmp_path)
    jail = iocage_jail(tmp_path)
    middleware.call.side_effect = standard_calls(tmp_path, jail)
    patch_seams(monkeypatch, tmp_path, listening=lift.parse_sockstat(
        'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n'
        'git forgejo 1 19 tcp4 127.0.0.1:3000 *:*\n'
        'root nginx 2 6 tcp46 *:80 *:*\n'
    ))
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.uuid.uuid4', lambda: Mock(hex='abc' * 11))

    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None},
        {'ports': [
            {'container_port': 3000, 'protocol': 'tcp', 'host_port': 20300},
            {'container_port': 80, 'protocol': 'tcp', 'host_port': 20082},
        ]},
    )
    loopback = [item for item in plan['entries'] if item.get('what') == 'loopback']
    assert len(loopback) == 1
    assert loopback[0]['warning'] is True and loopback[0]['address'] == '127.0.0.1'
    assert loopback[0]['container_port'] == 3000
    assert '127.0.0.1 inside the jail' in loopback[0]['human'] and '20300' in loopback[0]['human']
    published = [item for item in plan['entries'] if item.get('what') == 'port']
    assert {item['container_port'] for item in published} == {80, 3000}  # still published

    # A running jail with nothing listening (and no catalog match) says so; it is not "stopped".
    patch_seams(monkeypatch, tmp_path, listening=[])
    standard = standard_calls(tmp_path, jail)

    async def no_catalog(method, *args):
        if method == 'applications.catalog.query':
            return []
        return await standard(method, *args)

    middleware.call.side_effect = no_catalog
    quiet = await service.plan(
        {'kind': 'jail', 'jail': 'grafanajail', 'engine': 'iocage', 'path': None, 'image': None}, {},
    )
    note = next(item for item in quiet['entries'] if item.get('what') == 'ports')
    assert 'nothing in the running jail is listening' in note['human']
    assert 'stopped' not in note['human']
