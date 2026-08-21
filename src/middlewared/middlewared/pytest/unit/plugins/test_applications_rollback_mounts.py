"""the internal development record: a rollback releases the mounts a failed container left on the owned
datasets before destroying them, retries a busy destroy, and names what survives -- off-box."""
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.applications_.utils import leaked_container_mounts, parse_mounts
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError

GRAPH = '/mnt/tank/applications/storage/zfs/graph'
DEAD = f'{GRAPH}/2426b190b2bca17c4078409a8b048638503360015c3eb770bcc23e535da94cfb'
LIVE = f'{GRAPH}/c0355383c098a47aaee5e057ac2e7cb1e14fa74cf3c76b4213790b03b35c8397'

# A test VM, after an install failed part way through its mounts (ocijail 0.6.1):
# the leaktest datasets, the one bind out of leaktest/data into the dead rootfs, the rest of that
# rootfs' mounts, and the running ollama container's own mounts next to them.
MOUNT_P = f'''
tank/applications/data	/mnt/tank/applications/data zfs	rw,noatime,nfsv4acls 	0 0
tank/applications/data/leaktest /mnt/tank/applications/data/leaktest zfs	rw,noatime,nfsv4acls 	0 0
tank/applications/data/leaktest/data /mnt/tank/applications/data/leaktest/data zfs	rw,noatime,nfsv4acls 	0 0
tank/applications/storage/2426b190b2bca17c4078409a8b048638503360015c3eb770bcc23e535da94cfb {DEAD} zfs	rw,noatime,nfsv4acls 	0 0
linprocfs {DEAD}/proc linprocfs	rw 	0 0
devfs {DEAD}/dev devfs	rw 	0 0
fdescfs {DEAD}/dev/fd fdescfs	rw 	0 0
/var/run/freecore-applications/storage/zfs-containers/2e3e/userdata/hosts {DEAD}/etc/hosts nullfs	rw 	0 0
/mnt/tank/applications/data/leaktest/data {DEAD}/data nullfs	rw 	0 0
tank/applications/data/ollama/models /mnt/tank/applications/data/ollama/models zfs	rw,noatime,nfsv4acls 	0 0
tank/applications/storage/c0355383c098a47aaee5e057ac2e7cb1e14fa74cf3c76b4213790b03b35c8397 {LIVE} zfs	rw,noatime,nfsv4acls 	0 0
linprocfs {LIVE}/proc linprocfs	rw 	0 0
/mnt/tank/applications/data/ollama/models {LIVE}/root/.ollama nullfs	rw 	0 0
'''

LEAKTEST = ['tank/applications/data/leaktest', 'tank/applications/data/leaktest/data']


def test_mount_p_lines_parse_whatever_the_whitespace():
    entries = parse_mounts(MOUNT_P)
    assert len(entries) == 13
    assert entries[8] == {'source': '/mnt/tank/applications/data/leaktest/data', 'target': f'{DEAD}/data', 'fstype': 'nullfs'}
    assert parse_mounts('') == [] and parse_mounts(None) == []


def test_the_dead_container_mounts_are_selected_deepest_first_and_nothing_else():
    leaked = leaked_container_mounts(parse_mounts(MOUNT_P), [f'/mnt/{d}' for d in LEAKTEST])
    targets = [entry['target'] for entry in leaked]
    # deepest first, so each umount finds its target still mounted
    assert targets == [f'{DEAD}/dev/fd', f'{DEAD}/etc/hosts', f'{DEAD}/data', f'{DEAD}/dev', f'{DEAD}/proc']
    # the rootfs' own zfs layer is podman's, the datasets' own zfs mounts stay, ollama is untouched
    assert all(not t.startswith(LIVE) for t in targets)
    assert DEAD not in targets
    assert '/mnt/tank/applications/data/leaktest/data' not in targets


JAIL = '/mnt/tank/iocage/jails/jnullfs/root'

# A test VM: an operator's read-only nullfs of an application's dataset into a jail, next to the
# jail's own mounts (the internal development record).
JAIL_MOUNT_P = f"""
tank/applications/data/pg /mnt/tank/applications/data/pg zfs\trw,noatime,nfsv4acls \t0 0
tank/applications/data/pg/var-lib-postgresql-data /mnt/tank/applications/data/pg/var-lib-postgresql-data zfs\trw,noatime,nfsv4acls \t0 0
tank/iocage/jails/jnullfs/root {JAIL} zfs\trw,noatime,nfsv4acls \t0 0
devfs {JAIL}/dev devfs\trw \t0 0
fdescfs {JAIL}/dev/fd fdescfs\trw \t0 0
/mnt/tank/media {JAIL}/mnt/media nullfs\tro \t0 0
/mnt/tank/applications/data/pg/var-lib-postgresql-data {JAIL}/mnt/pgdata nullfs\tro \t0 0
"""


@pytest.mark.parametrize('target', [f'{JAIL}/mnt/pgdata', f'{JAIL}/pgdata'])
def test_an_operator_bind_outside_a_graph_root_is_released_alone(target):
    text = JAIL_MOUNT_P.replace(f'{JAIL}/mnt/pgdata', target)
    leaked = leaked_container_mounts(parse_mounts(text), ['/mnt/tank/applications/data/pg', '/mnt/tank/applications/data/pg/var-lib-postgresql-data'])
    # the bind itself goes (it holds the dataset busy); the jail's media bind, devfs and fdescfs stay
    assert [entry['target'] for entry in leaked] == [target]


def test_no_leak_selects_nothing():
    assert leaked_container_mounts(parse_mounts(MOUNT_P), ['/mnt/tank/applications/data/nothing']) == []


def service():
    svc = Mock(spec=ApplicationsService)
    svc.logger = Mock()
    svc.middleware = Mock()
    svc._dataset_exists = AsyncMock(return_value=True)
    svc._dataset_owner = AsyncMock(return_value='applications:leaktest')
    svc._release_owned_datasets = ApplicationsService._release_owned_datasets.__get__(svc)
    svc._delete_attempted_owned_datasets = ApplicationsService._delete_attempted_owned_datasets.__get__(svc)
    return svc


def completed(returncode=0, stdout='', stderr=''):
    return Mock(returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.mark.asyncio
async def test_rollback_unmounts_the_leak_then_destroys():
    svc = service()
    calls = []

    async def fake_run(argv, **kwargs):
        calls.append(argv)
        return completed(stdout=MOUNT_P) if argv == ['mount', '-p'] else completed()

    svc.middleware.call = AsyncMock(return_value=None)
    with patch('middlewared.plugins.applications_freebsd.run', fake_run):
        errors = await svc._delete_attempted_owned_datasets(LEAKTEST, {d: 'applications:leaktest' for d in LEAKTEST})

    assert errors == []
    umounts = [argv[2] for argv in calls if argv[:2] == ['umount', '-f']]
    assert umounts == [f'{DEAD}/dev/fd', f'{DEAD}/etc/hosts', f'{DEAD}/data', f'{DEAD}/dev', f'{DEAD}/proc']
    destroyed = [c.args[1] for c in svc.middleware.call.await_args_list if c.args[0] == 'zfs.dataset.delete']
    assert destroyed == ['tank/applications/data/leaktest/data', 'tank/applications/data/leaktest']


@pytest.mark.asyncio
async def test_a_busy_destroy_is_retried_and_a_survivor_is_named():
    svc = service()
    busy = CallError("Failed to delete dataset: cannot destroy 'tank/applications/data/leaktest/data': pool or dataset is busy")
    svc.middleware.call = AsyncMock(side_effect=[busy, busy, None, None])
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(stdout=''))), \
            patch('middlewared.plugins.applications_freebsd.asyncio.sleep', AsyncMock()) as sleep:
        errors = await svc._delete_attempted_owned_datasets(LEAKTEST, {d: 'applications:leaktest' for d in LEAKTEST})
    assert errors == []
    assert [c.args[0] for c in sleep.await_args_list] == [0.5, 1.0]

    svc.middleware.call = AsyncMock(side_effect=busy)
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(stdout=''))), \
            patch('middlewared.plugins.applications_freebsd.asyncio.sleep', AsyncMock()):
        errors = await svc._delete_attempted_owned_datasets(LEAKTEST, {d: 'applications:leaktest' for d in LEAKTEST})
    assert len(errors) == 2
    assert errors[0].startswith("left behind 'tank/applications/data/leaktest/data': ")
    assert 'busy' in errors[0]

    # Anything but busy is not retried.
    svc.middleware.call = AsyncMock(side_effect=CallError('permission denied'))
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(stdout=''))):
        errors = await svc._delete_attempted_owned_datasets(LEAKTEST[:1], {LEAKTEST[0]: 'applications:leaktest'})
    assert svc.middleware.call.await_count == 1 and 'left behind' in errors[0]
