"""the internal development record: adopting a Bastille tree FreeCORE did not create.

The fixture is the shape the XigmaNAS Bastille extension leaves (extension 1.5.11 with
Bastille 1.4.0): `<pool>/bastille` is a dataset holding the extension's own files,
Bastille's bootstrap made `cache jails logs releases templates` datasets, `backups` is a
plain folder the extension made first, and FreeCORE's `config` does not exist. Paths are
moved under a temporary directory; ZFS and the commands are faked at `run` and
`middleware.call`.
"""
import os
import shutil
import stat
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from middlewared.plugins import bastille_freebsd
from middlewared.plugins.bastille_.utils import MANAGED_PROPERTY, bastille_dataset_specs, bastille_paths
from middlewared.plugins.bastille_freebsd import BastilleService
from middlewared.service_exception import CallError

XIGMANAS_DATASETS = [
    'tank/bastille',
    'tank/bastille/cache',
    'tank/bastille/jails',
    'tank/bastille/logs',
    'tank/bastille/releases',
    'tank/bastille/templates',
]
OWNERS = dict(bastille_dataset_specs('tank'))


@pytest.fixture(autouse=True)
def package_capability(monkeypatch):
    monkeypatch.setattr(BastilleService, '_package_capability_valid', staticmethod(lambda: True))


class FakeZFS:
    """ZFS state behind `run` and `middleware.call`, with the folders on a real disk."""

    def __init__(self, base):
        self.base = base
        self.datasets = {}
        self.running = ''
        self.fail_set = set()
        self.fail_copy = False
        # The kernel mount table (mount -p) as a fresh install leaves it: the system dataset on the data pool is
        # mounted legacy at /var/db/system (its mountpoint property is not a path), plus devfs and a jail's nullfs.
        self.mounts = [
            'boot-pool/ROOT/default / zfs rw,nfsv4acls 0 0',
            'devfs /dev devfs rw 0 0',
            'tank/.system /var/db/system zfs rw,nfsv4acls 0 0',
            'tank/.system/samba4 /var/db/system/samba4 zfs rw,nfsv4acls 0 0',
            f'tank {base}/tank zfs rw,nfsv4acls 0 0',
            f'/srv/release {base}/elsewhere/root/.bastille nullfs ro 0 0',
            r'tank/with\040space /var/with\040space zfs rw 0 0',
        ]
        self.commands = []
        self.calls = []

    def path(self, dataset):
        return os.path.join(self.base, dataset)

    def add(self, dataset, owner=('-', '-'), kind='filesystem', readonly='off', mounted='yes'):
        self.datasets[dataset] = {
            'type': kind, 'mounted': mounted, 'mountpoint': self.path(dataset),
            'readonly': readonly, 'owner': owner,
        }
        os.makedirs(self.path(dataset), exist_ok=True)

    def zfs_get(self, root):
        lines = []
        for name, values in sorted(self.datasets.items()):
            if name != root and os.path.dirname(name) != root:
                continue
            lines.extend([
                f'{name}\ttype\t{values["type"]}\t-',
                f'{name}\tmounted\t{values["mounted"]}\t-',
                f'{name}\tmountpoint\t{values["mountpoint"]}\tdefault',
                f'{name}\treadonly\t{values["readonly"]}\tdefault',
                f'{name}\t{MANAGED_PROPERTY}\t{values["owner"][0]}\t{values["owner"][1]}',
            ])
        return '\n'.join(lines) + '\n'

    async def run(self, *args, **kwargs):
        self.commands.append(args)
        ok = SimpleNamespace(returncode=0, stdout='', stderr='')
        if args[:2] == ('/sbin/zfs', 'get') and '-d' in args:
            return SimpleNamespace(returncode=0, stdout=self.zfs_get(args[-1]), stderr='')
        if args[:2] == ('/sbin/zfs', 'get'):
            # _managed_dataset_owners: name, value, source of the mark, recursively.
            root = args[-1]
            lines = [
                f'{name}\t{values["owner"][0]}\t{values["owner"][1]}'
                for name, values in sorted(self.datasets.items())
                if name == root or name.startswith(f'{root}/')
            ]
            return SimpleNamespace(returncode=0, stdout='\n'.join(lines), stderr='')
        if args[:2] == ('/sbin/mount', '-p'):
            return SimpleNamespace(returncode=0, stdout='\n'.join(self.mounts) + '\n', stderr='')
        if args[0] == '/usr/sbin/jls':
            return SimpleNamespace(returncode=0, stdout=self.running, stderr='')
        if args[:2] == ('/sbin/zfs', 'set'):
            if args[3] in self.fail_set:
                return SimpleNamespace(returncode=1, stdout='', stderr=f'cannot set {args[3]}')
            value = args[2].split('=', 1)[1]
            self.datasets[args[3]]['owner'] = (value, 'local')
            return ok
        if args[:2] == ('/sbin/zfs', 'inherit'):
            self.datasets[args[3]]['owner'] = ('-', '-')
            return ok
        if args[0] == '/bin/cp':
            assert args[1] == '-a' and args[2].endswith('/')
            if self.fail_copy:
                return SimpleNamespace(returncode=1, stdout='', stderr='cp: No space left on device')
            shutil.copytree(args[2].rstrip('/'), args[3], symlinks=True, dirs_exist_ok=True)
            return ok
        if args[0] == '/bin/rm':
            assert args[1:3] == ('-rf', '--')
            shutil.rmtree(args[3])
            return ok
        raise AssertionError(f'unexpected command {args}')

    async def call(self, method, *args):
        self.calls.append((method, *args))
        if method == 'zfs.dataset.query':
            return [{'id': args[0][0][2]}] if args[0][0][2] in self.datasets else []
        if method == 'zfs.snapshot.create':
            return {'name': f'{args[0]["dataset"]}@{args[0]["name"]}'}
        if method == 'zfs.dataset.create':
            name = args[0]['name']
            owner = args[0]['properties'][MANAGED_PROPERTY]
            self.datasets[name] = {
                'type': 'filesystem', 'mounted': 'yes', 'mountpoint': self.path(name),
                'readonly': 'off', 'owner': (owner, 'local'),
            }
            return None
        if method == 'zfs.dataset.mount':
            os.makedirs(self.path(args[0]), exist_ok=True)
            return None
        if method == 'zfs.dataset.delete':
            assert args[1] == {'force': True}, 'adoption only ever drops a dataset it made, alone'
            del self.datasets[args[0]]
            shutil.rmtree(self.path(args[0]))
            return True
        raise AssertionError(f'unexpected call {method}')


@pytest.fixture
def xigmanas(tmp_path, monkeypatch):
    zfs = FakeZFS(str(tmp_path))
    for dataset in XIGMANAS_DATASETS:
        zfs.add(dataset)
    root = tmp_path / 'tank/bastille'
    # The extension's own files live in the root.
    (root / 'bastille-dist').mkdir()
    (root / 'conf').mkdir()
    (root / 'bastille-init').write_text('#!/bin/sh\n')
    (root / 'backups').mkdir()
    (root / 'backups/web_2026-10-01.xz').write_text('archive')
    os.chmod(root / 'backups', 0o750)
    jail = root / 'jails/web'
    (jail / 'root').mkdir(parents=True)
    (jail / 'jail.conf').write_text(f'web {{\n  path = {jail / "root"};\n}}\n')
    (jail / 'fstab').write_text(
        f'{root}/releases/14.3-RELEASE {jail}/root/.bastille nullfs ro 0 0\n'
    )
    (root / 'releases/14.3-RELEASE').mkdir()

    paths = {
        key: value.replace('/mnt', str(tmp_path), 1) if value.startswith('/mnt/') else value
        for key, value in bastille_paths('tank').items()
    }
    monkeypatch.setattr(bastille_freebsd, 'bastille_paths', lambda pool: paths)
    monkeypatch.setattr(bastille_freebsd, 'adoption_mounted_path', zfs.path)
    monkeypatch.setattr(bastille_freebsd, 'run', zfs.run)
    monkeypatch.setattr(bastille_freebsd.os.path, 'ismount', lambda path: True)
    return zfs


def service_for(zfs):
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=zfs.call)
    return BastilleService(middleware), middleware


def mutations(zfs):
    return [
        command for command in zfs.commands
        if command[:2] in {('/sbin/zfs', 'set'), ('/sbin/zfs', 'inherit')} or command[0] in {'/bin/cp', '/bin/rm'}
    ] + [call for call in zfs.calls if call[0] not in {'zfs.dataset.query'}]


@pytest.mark.asyncio
async def test_preview_without_a_tree_is_absent(tmp_path, monkeypatch):
    zfs = FakeZFS(str(tmp_path))
    monkeypatch.setattr(bastille_freebsd, 'run', zfs.run)
    service, _ = service_for(zfs)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'ABSENT'
    assert zfs.commands == []


@pytest.mark.asyncio
async def test_preview_of_a_xigmanas_tree_lists_what_adoption_does(xigmanas):
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'ADOPTABLE'
    assert plan['blockers'] == []
    assert plan['create'] == ['tank/bastille/config']
    assert plan['convert'] == ['tank/bastille/backups']
    assert plan['mark'] == XIGMANAS_DATASETS
    assert plan['jails'] == [{'name': 'web', 'operable': True, 'reason': None}]
    assert plan['releases'] == ['14.3-RELEASE']
    assert mutations(xigmanas) == []
    get = next(command for command in xigmanas.commands if command[:2] == ('/sbin/zfs', 'get'))
    assert get[2:7] == ('-H', '-d', '1', '-t', 'filesystem,volume')


@pytest.mark.asyncio
async def test_preview_of_freecores_own_tree_is_managed(xigmanas):
    for dataset, owner in OWNERS.items():
        xigmanas.add(dataset, owner=(owner, 'local'))
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'MANAGED'
    assert (plan['create'], plan['convert'], plan['mark']) == ([], [], [])


@pytest.mark.asyncio
async def test_an_inherited_mark_still_needs_a_local_one(xigmanas):
    # A user who ran `zfs set org.freecore:managedby=bastille tank/bastille` by hand.
    for dataset in XIGMANAS_DATASETS[1:]:
        xigmanas.datasets[dataset]['owner'] = ('bastille', 'inherited from tank/bastille')
    xigmanas.datasets['tank/bastille']['owner'] = ('bastille', 'local')
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'ADOPTABLE'
    assert plan['mark'] == XIGMANAS_DATASETS[1:]


@pytest.mark.parametrize('arrange, reason', [
    (lambda zfs: zfs.datasets['tank/bastille/logs'].update(owner=('applications', 'local')),
     "tank/bastille/logs is marked as belonging to 'applications'."),
    (lambda zfs: zfs.datasets['tank/bastille/cache'].update(type='volume'),
     'tank/bastille/cache is a volume, not a filesystem dataset.'),
    (lambda zfs: zfs.datasets['tank/bastille/jails'].update(mounted='no'),
     'tank/bastille/jails is not mounted at'),
    (lambda zfs: setattr(zfs, 'running', f'name=web path={zfs.path("tank/bastille/jails")}/web/root\n'),
     'Stop these jails first: web.'),
    (lambda zfs: zfs.mounts.append(f'/srv/archive {zfs.path("tank/bastille/backups")}/old nullfs ro 0 0'),
     'has file systems mounted inside it: /srv/archive.'),
    (lambda zfs: zfs.mounts.append(f'tank/other\\040set {zfs.path("tank/bastille/backups")}/with\\040space zfs rw 0 0'),
     'has file systems mounted inside it: tank/other set.'),
])
@pytest.mark.asyncio
async def test_blockers_are_reported_and_nothing_changes(xigmanas, arrange, reason):
    arrange(xigmanas)
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'BLOCKED'
    assert any(reason in blocker for blocker in plan['blockers']), plan['blockers']
    with pytest.raises(CallError, match='cannot be adopted'):
        await service._adopt_foreign_tree('tank', True, Mock())
    assert mutations(xigmanas) == []


@pytest.mark.parametrize('folder', ['jails', 'releases'])
@pytest.mark.asyncio
async def test_a_bastille_without_zfs_is_not_adoptable(xigmanas, folder):
    # Bastille without ZFS: jails or releases are a folder holding the data itself.
    del xigmanas.datasets[f'tank/bastille/{folder}']
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'BLOCKED'
    assert any('this Bastille ran without ZFS' in blocker for blocker in plan['blockers'])


@pytest.mark.parametrize('arrange, reason', [
    (lambda zfs: zfs.datasets['tank/bastille'].update(readonly='on'), 'tank/bastille is read-only.'),
    (lambda zfs: zfs.datasets['tank/bastille'].update(mounted='no'), 'tank/bastille is not mounted at'),
])
@pytest.mark.asyncio
async def test_an_unusable_root_blocks_before_anything_else(xigmanas, arrange, reason):
    arrange(xigmanas)
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'BLOCKED'
    assert plan['blockers'] == [plan['blockers'][0]] and reason in plan['blockers'][0]


@pytest.mark.asyncio
async def test_a_symlinked_core_path_blocks(xigmanas, tmp_path):
    shutil.rmtree(tmp_path / 'tank/bastille/backups')
    os.symlink(tmp_path, tmp_path / 'tank/bastille/backups')
    service, _ = service_for(xigmanas)

    plan = await service.adoption_preview('tank')

    assert plan['state'] == 'BLOCKED'
    assert any('is neither a folder nor a dataset' in blocker for blocker in plan['blockers'])


@pytest.mark.asyncio
async def test_a_foreign_tree_without_adopt_is_refused_plainly_and_untouched(xigmanas):
    service, _ = service_for(xigmanas)

    with pytest.raises(CallError) as error:
        await service._prepare_switch_target('tank', [], adopt=False, job=Mock())

    assert error.value.errmsg == (
        'tank/bastille already holds Bastille data that FreeCORE did not create '
        '(jails: web; releases: 14.3-RELEASE). Adopt it in Bastille Settings to use it here.'
    )
    assert mutations(xigmanas) == []


@pytest.mark.asyncio
async def test_adoption_snapshots_creates_converts_and_marks(xigmanas, tmp_path):
    service, _ = service_for(xigmanas)
    service._validate_managed_tree = AsyncMock()
    service._validate_mounted_tree = AsyncMock()
    created = []

    await service._prepare_switch_target('tank', created, adopt=True, job=Mock())

    snapshot = next(call for call in xigmanas.calls if call[0] == 'zfs.snapshot.create')
    assert snapshot[1]['dataset'] == 'tank/bastille' and snapshot[1]['recursive'] is True
    assert snapshot[1]['name'].startswith('freecore-adopt-')
    assert xigmanas.calls.index(snapshot) < min(
        index for index, call in enumerate(xigmanas.calls) if call[0] == 'zfs.dataset.create'
    )
    for dataset, owner in OWNERS.items():
        assert xigmanas.datasets[dataset]['owner'] == (owner, 'local')
    backups = tmp_path / 'tank/bastille/backups'
    assert (backups / 'web_2026-10-01.xz').read_text() == 'archive'
    assert stat.S_IMODE(os.stat(backups).st_mode) == 0o750
    assert not (tmp_path / 'tank/bastille/.backups.freecore-adopt').exists()
    assert stat.S_IMODE(os.stat(tmp_path / 'tank/bastille/config').st_mode) == 0o750
    # The jails and the extension's files are left exactly as they were.
    assert (tmp_path / 'tank/bastille/jails/web/jail.conf').exists()
    assert (tmp_path / 'tank/bastille/bastille-init').exists()
    assert created == []
    service._validate_managed_tree.assert_awaited_with('tank')


@pytest.mark.asyncio
async def test_a_failure_mid_adoption_puts_the_tree_back(xigmanas, tmp_path):
    xigmanas.fail_set = {'tank/bastille/logs'}
    service, _ = service_for(xigmanas)
    before = {name: dict(values) for name, values in xigmanas.datasets.items()}

    with pytest.raises(CallError, match='Unable to mark tank/bastille/logs'):
        await service._prepare_switch_target('tank', [], adopt=True, job=Mock())

    assert xigmanas.datasets == before
    assert (tmp_path / 'tank/bastille/backups/web_2026-10-01.xz').read_text() == 'archive'
    assert not (tmp_path / 'tank/bastille/.backups.freecore-adopt').exists()
    assert not (tmp_path / 'tank/bastille/config').exists()
    deleted = [call[1] for call in xigmanas.calls if call[0] == 'zfs.dataset.delete']
    assert sorted(deleted) == ['tank/bastille/backups', 'tank/bastille/config']


@pytest.mark.asyncio
async def test_a_failed_copy_keeps_the_folder(xigmanas, tmp_path):
    xigmanas.fail_copy = True
    service, _ = service_for(xigmanas)

    with pytest.raises(CallError, match='No space left on device'):
        await service._prepare_switch_target('tank', [], adopt=True, job=Mock())

    assert (tmp_path / 'tank/bastille/backups/web_2026-10-01.xz').read_text() == 'archive'
    assert 'tank/bastille/backups' not in xigmanas.datasets


@pytest.mark.asyncio
async def test_a_failed_undo_names_the_snapshot(xigmanas):
    xigmanas.fail_set = {'tank/bastille/logs'}
    service, _ = service_for(xigmanas)
    real_call = xigmanas.call

    async def refuse_delete(method, *args):
        if method == 'zfs.dataset.delete':
            raise CallError('dataset is busy')
        return await real_call(method, *args)

    service.middleware.call.side_effect = refuse_delete

    with pytest.raises(CallError, match=r'Undoing the adoption failed .*; tank/bastille@freecore-adopt-\S+ holds'):
        await service._prepare_switch_target('tank', [], adopt=True, job=Mock())


@pytest.mark.asyncio
async def test_configure_failing_after_adoption_never_deletes_the_tree():
    middleware = Mock()
    middleware.call = AsyncMock(return_value=[{'id': 'tank/bastille'}])
    service = BastilleService(middleware)
    service._raw_config = AsyncMock(return_value={
        'id': 1, 'pool': None, 'startup_delay': 0, 'parallel_limit': 1,
    })
    service._validate_pool = AsyncMock()
    service._tree_is_managed = AsyncMock(return_value=False)
    service._adopt_foreign_tree = AsyncMock()
    service._validate_managed_tree = AsyncMock()
    service._validate_mounted_tree = AsyncMock()
    service._running_jails = AsyncMock(return_value=[])
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._disable_service_row = AsyncMock()
    service._generate_and_validate_rc = AsyncMock()
    service._validate_configured_row = AsyncMock(return_value=True)

    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=False),
        patch('middlewared.plugins.bastille_freebsd.atomic_write', side_effect=OSError('disk full')),
        pytest.raises(OSError, match='disk full'),
    ):
        await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 0, 'parallel_limit': 1, 'adopt': True,
        })

    service._adopt_foreign_tree.assert_awaited_once()
    assert not any(call.args[0] == 'zfs.dataset.delete' for call in middleware.call.await_args_list)
