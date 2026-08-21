from datetime import datetime
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
from unittest.mock import AsyncMock, call, Mock, patch

import pytest

from middlewared.plugins import system_rollback
from middlewared.pytest.unit.middleware import Middleware


SNAPSHOT_NAME = 'freecore-rollback-20260813010203'
SNAPSHOTS = [
    f'tank/.system@{SNAPSHOT_NAME}',
    f'tank/.system/samba4@{SNAPSHOT_NAME}',
    f'tank/iocage@{SNAPSHOT_NAME}',
    f'tank/iocage/jails@{SNAPSHOT_NAME}',
    f'tank/iocage/jails/old@{SNAPSHOT_NAME}',
]


def window(snapshots=None):
    now = datetime.utcnow()
    return {
        'id': 1,
        'origin_be': '13.3-U1.2',
        'arrival_path': 'manual_update',
        'captured_at': now,
        'system_dataset': 'tank/.system',
        'snapshots': SNAPSHOTS if snapshots is None else snapshots,
        'pool_state': {},
        'closed_reason': None,
    }


def service_for_available(*, snapshots=None, present=None, system_dataset='tank/.system', iocage='tank/iocage'):
    middleware = Middleware()
    rollback_window = window(snapshots)
    middleware['datastore.query'] = AsyncMock(return_value=[rollback_window])
    middleware['bootenv.query'] = AsyncMock(return_value=[{
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': True,
        'rawspace': 2048,
    }])
    middleware['zfs.snapshot.query'] = AsyncMock(
        return_value=[{'name': name} for name in (rollback_window['snapshots'] if present is None else present)]
    )
    middleware['systemdataset.config'] = AsyncMock(return_value={'basename': system_dataset})
    middleware['zfs.dataset.query'] = AsyncMock(return_value=[] if iocage is None else [{
        'children': [{'name': iocage}],
    }])
    return system_rollback.SystemRollbackService(middleware)


@pytest.mark.asyncio
async def test_available_checks_the_complete_restore_set():
    available = await service_for_available().available()
    assert available['available'] is True
    assert available['reason'] is None


@pytest.mark.asyncio
async def test_available_refuses_a_missing_recorded_snapshot():
    available = await service_for_available(present=SNAPSHOTS[:-1]).available()
    assert available == {'available': False, 'reason': 'snapshots_missing'}


@pytest.mark.asyncio
async def test_available_refuses_a_moved_system_dataset():
    available = await service_for_available(system_dataset='other/.system').available()
    assert available == {'available': False, 'reason': 'system_dataset_changed'}


@pytest.mark.asyncio
async def test_available_refuses_a_moved_iocage_tree():
    available = await service_for_available(iocage='other/iocage').available()
    assert available == {'available': False, 'reason': 'iocage_changed'}


@pytest.mark.asyncio
async def test_available_has_no_age_limit():
    stale = window()
    stale['captured_at'] = datetime(2020, 1, 1)
    service = service_for_available()
    service.middleware['datastore.query'] = AsyncMock(return_value=[stale])

    available = await service.available()
    assert available == {'available': True, 'reason': None}


@pytest.mark.asyncio
async def test_config_returns_the_persistent_capture():
    stored = window()
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[stored])
    service = system_rollback.SystemRollbackService(middleware)

    configured = await service.config()

    assert configured == stored


def test_rollback_model_has_no_expiry_column():
    assert 'expires_at' not in system_rollback.RollbackWindowModel.__table__.columns


@pytest.mark.asyncio
async def test_available_refuses_an_unpinned_origin_be():
    service = service_for_available()
    service.middleware['bootenv.query'] = AsyncMock(return_value=[{
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': False,
        'rawspace': 2048,
    }])

    assert await service.available() == {'available': False, 'reason': 'origin_be_unpinned'}


@pytest.mark.asyncio
async def test_available_reports_a_removed_capture():
    removed = window()
    removed['closed_reason'] = 'removed'
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[removed])
    service = system_rollback.SystemRollbackService(middleware)

    assert await service.available() == {'available': False, 'reason': 'removed'}


@pytest.mark.asyncio
async def test_space_reports_held_bytes():
    service = service_for_available()
    service.middleware['zfs.snapshot.query'] = AsyncMock(return_value=[
        {'name': name, 'properties': {'used': {'rawvalue': '1024'}}} for name in SNAPSHOTS
    ])

    assert await service.space() == {
        'snapshot_count': len(SNAPSHOTS),
        'snapshot_bytes_lower_bound': len(SNAPSHOTS) * 1024,
        'origin_be_bytes_estimate': 2048,
        'origin_be_pinned': True,
        'cleanup_pending': True,
    }


@pytest.mark.asyncio
async def test_space_does_not_count_an_unpinned_be_as_cleanup_pending():
    closed = window([])
    closed['closed_reason'] = 'removed'
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[closed])
    middleware['bootenv.query'] = AsyncMock(return_value=[{
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': False,
        'rawspace': 2048,
    }])
    service = system_rollback.SystemRollbackService(middleware)

    assert await service.space() == {
        'snapshot_count': 0,
        'snapshot_bytes_lower_bound': 0,
        'origin_be_bytes_estimate': 2048,
        'origin_be_pinned': False,
        'cleanup_pending': False,
    }


@pytest.mark.asyncio
async def test_remove_tears_down_and_records_the_reason():
    rows = [window()]
    origin = {
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': True,
        'rawspace': 2048,
    }
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(side_effect=lambda *a, **k: [dict(rows[0])])

    async def update(_datastore, _id, values):
        rows[0].update(values)

    middleware['datastore.update'] = AsyncMock(side_effect=update)

    async def set_attribute(_origin, attributes):
        origin['keep'] = attributes['keep']

    middleware['bootenv.query'] = AsyncMock(side_effect=lambda *a, **k: [dict(origin)])
    middleware['bootenv.set_attribute'] = AsyncMock(side_effect=set_attribute)
    middleware['zfs.snapshot.query'] = AsyncMock(return_value=[{'name': name} for name in SNAPSHOTS])
    middleware['zfs.snapshot.delete'] = AsyncMock()
    service = system_rollback.SystemRollbackService(middleware)
    job = Mock()

    result = await service.remove(job)

    assert result['closed_reason'] == 'removed'
    assert rows[0]['snapshots'] == []
    middleware['bootenv.set_attribute'].assert_awaited_with('13.3-U1.2', {'keep': False})
    assert middleware['zfs.snapshot.delete'].await_count == len(SNAPSHOTS)
    job.set_progress.assert_called_with(100, 'The captured return was removed')


@pytest.mark.asyncio
async def test_closed_cleanup_retries_unpin_after_snapshots_are_already_gone():
    closed = window([])
    closed['closed_reason'] = 'removed'
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[closed])
    middleware['datastore.update'] = AsyncMock()
    middleware['bootenv.query'] = AsyncMock(return_value=[{
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': True,
        'rawspace': 2048,
    }])
    middleware['bootenv.set_attribute'] = AsyncMock(side_effect=[RuntimeError('busy'), True])
    service = system_rollback.SystemRollbackService(middleware)

    await service.cleanup()
    await service.cleanup()

    assert middleware['bootenv.set_attribute'].await_count == 2


@pytest.mark.asyncio
async def test_closed_cleanup_records_and_retries_only_residual_snapshots():
    closed = window(SNAPSHOTS[:2])
    closed['closed_reason'] = 'removed'
    rows = [closed]
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(side_effect=lambda *a, **k: [dict(rows[0])])

    async def update(_datastore, _id, values):
        rows[0].update(values)

    middleware['datastore.update'] = AsyncMock(side_effect=update)
    middleware['bootenv.query'] = AsyncMock(return_value=[{
        'id': '13.3-U1.2',
        'realname': '13.3-U1.2',
        'keep': False,
        'rawspace': 2048,
    }])
    middleware['zfs.snapshot.query'] = AsyncMock(
        return_value=[{'name': name} for name in SNAPSHOTS[:2]]
    )

    failed_once = SNAPSHOTS[1]

    async def delete(name):
        if name == failed_once:
            raise RuntimeError('busy')

    middleware['zfs.snapshot.delete'] = AsyncMock(side_effect=delete)
    service = system_rollback.SystemRollbackService(middleware)

    first = await service.cleanup()
    assert first['snapshots'] == [failed_once]

    middleware['zfs.snapshot.delete'] = AsyncMock()
    second = await service.cleanup()
    assert second['snapshots'] == []
    middleware['zfs.snapshot.delete'].assert_awaited_once_with(failed_once)


@pytest.mark.asyncio
async def test_capture_is_idempotent_and_preserves_the_original_return_point():
    original = window()
    middleware = Middleware()
    middleware['datastore.query'] = AsyncMock(return_value=[original])
    middleware['datastore.insert'] = AsyncMock()
    middleware['bootenv.set_attribute'] = AsyncMock()
    service = system_rollback.SystemRollbackService(middleware)

    captured = await service.capture('train', int(datetime.utcnow().timestamp()))

    assert captured['origin_be'] == original['origin_be']
    assert captured['captured_at'] == original['captured_at']
    assert captured['snapshots'] == original['snapshots']
    assert 'expires_at' not in captured
    middleware['datastore.insert'].assert_not_awaited()
    middleware['bootenv.set_attribute'].assert_not_awaited()


def test_recorded_iocage_roots_are_derived_without_changing_the_row_schema():
    service = system_rollback.SystemRollbackService(Middleware())
    assert service.recorded_iocage_datasets(window()) == ['tank/iocage']


def test_restore_plan_is_staged_atomically_and_root_only(tmp_path):
    service = system_rollback.SystemRollbackService(Middleware())
    path = tmp_path / 'system-rollback.pending'
    plan = {
        'version': 1,
        'window_id': 1,
        'origin_be': '13.3-U1.2',
        'origin_realname': '13.3-U1.2',
        'origin_dataset': 'freenas-boot/ROOT/13.3-U1.2',
        'roots': ['tank/.system'],
        'snapshots': SNAPSHOTS[:2],
    }

    with patch.object(system_rollback, 'RESTORE_PLAN_PATH', str(path)):
        service.stage_restore_plan(plan)

    assert json.loads(path.read_text()) == plan
    assert path.stat().st_mode & 0o777 == 0o600


def completed_job(error=None):
    job = Mock()
    job.error = error
    job.wait = AsyncMock()
    return job


@pytest.mark.asyncio
async def test_quiesce_workloads_stops_vms_then_jails_and_verifies_both():
    middleware = Middleware()
    vm = {'id': 7, 'name': 'guest'}
    vm_job = completed_job()
    middleware['core.get_jobs'] = AsyncMock(side_effect=[[], []])
    middleware['vm.query'] = AsyncMock(side_effect=[[vm], []])
    middleware['vm.stop'] = AsyncMock(return_value=vm_job)
    middleware['jail.iocage_set_up'] = AsyncMock(return_value=True)
    middleware['jail.stop_on_shutdown'] = AsyncMock()
    middleware['jail.query'] = AsyncMock(return_value=[])
    service = system_rollback.SystemRollbackService(middleware)

    await service.quiesce_workloads(Mock())

    middleware['vm.stop'].assert_awaited_once_with(7, {'force_after_timeout': True})
    vm_job.wait.assert_awaited_once_with()
    middleware['jail.stop_on_shutdown'].assert_awaited_once_with()
    middleware['jail.query'].assert_awaited_once_with([('state', '=', 'up')])


@pytest.mark.asyncio
async def test_quiesce_workloads_is_inert_without_vms_or_iocage():
    middleware = Middleware()
    middleware['core.get_jobs'] = AsyncMock(side_effect=[[], []])
    middleware['vm.query'] = AsyncMock(side_effect=[[], []])
    middleware['vm.stop'] = AsyncMock()
    middleware['jail.iocage_set_up'] = AsyncMock(return_value=False)
    service = system_rollback.SystemRollbackService(middleware)

    await service.quiesce_workloads(Mock())

    middleware['vm.stop'].assert_not_awaited()


@pytest.mark.asyncio
async def test_quiesce_workloads_refuses_to_stage_while_a_vm_remains_running():
    middleware = Middleware()
    vm = {'id': 7, 'name': 'stuck-guest'}
    middleware['core.get_jobs'] = AsyncMock(return_value=[])
    middleware['vm.query'] = AsyncMock(side_effect=[[vm], [vm]])
    middleware['vm.stop'] = AsyncMock(return_value=completed_job())
    service = system_rollback.SystemRollbackService(middleware)

    with pytest.raises(system_rollback.CallError, match='stuck-guest'):
        await service.quiesce_workloads(Mock())


@pytest.mark.asyncio
async def test_quiesce_workloads_refuses_to_stage_while_a_jail_remains_running():
    middleware = Middleware()
    middleware['core.get_jobs'] = AsyncMock(return_value=[])
    middleware['vm.query'] = AsyncMock(side_effect=[[], []])
    middleware['jail.iocage_set_up'] = AsyncMock(return_value=True)
    middleware['jail.stop_on_shutdown'] = AsyncMock()
    middleware['jail.query'] = AsyncMock(return_value=[{'id': 9, 'host_hostuuid': 'stuck-jail'}])
    service = system_rollback.SystemRollbackService(middleware)

    with pytest.raises(system_rollback.CallError, match='stuck-jail'):
        await service.quiesce_workloads(Mock())


@pytest.mark.asyncio
async def test_quiesce_workloads_refuses_queued_jail_jobs_before_stopping_anything():
    middleware = Middleware()
    middleware['core.get_jobs'] = AsyncMock(return_value=[{
        'id': 33,
        'method': 'jail.start',
        'state': 'WAITING',
    }])
    middleware['vm.query'] = AsyncMock()
    service = system_rollback.SystemRollbackService(middleware)

    with pytest.raises(system_rollback.CallError, match=r'jail\.start \(job 33, waiting\)'):
        await service.quiesce_workloads(Mock())

    middleware['vm.query'].assert_not_awaited()


@pytest.mark.asyncio
async def test_quiesce_workloads_refuses_a_job_queued_while_workloads_are_stopping():
    middleware = Middleware()
    middleware['core.get_jobs'] = AsyncMock(side_effect=[[], [{
        'id': 34,
        'method': 'plugin.update',
        'state': 'WAITING',
    }]])
    middleware['vm.query'] = AsyncMock(side_effect=[[], []])
    middleware['jail.iocage_set_up'] = AsyncMock(return_value=False)
    service = system_rollback.SystemRollbackService(middleware)

    with pytest.raises(system_rollback.CallError, match=r'plugin\.update \(job 34, waiting\)'):
        await service.quiesce_workloads(Mock())


@pytest.mark.asyncio
async def test_reserve_shutdown_timeout_applies_the_runtime_floor():
    service = system_rollback.SystemRollbackService(Middleware())
    sysctl = AsyncMock(side_effect=[
        subprocess.CompletedProcess([], 0, '210\n', ''),
        subprocess.CompletedProcess([], 0, '', ''),
    ])

    with patch.object(system_rollback, 'run', sysctl):
        assert await service.reserve_shutdown_timeout() == 210

    assert sysctl.await_args_list == [
        call(
            system_rollback.SYSCTL,
            '-n',
            system_rollback.SHUTDOWN_TIMEOUT_SYSCTL,
            encoding='utf8',
        ),
        call(
            system_rollback.SYSCTL,
            f'{system_rollback.SHUTDOWN_TIMEOUT_SYSCTL}={system_rollback.ROLLBACK_SHUTDOWN_TIMEOUT}',
            encoding='utf8',
        ),
    ]


@pytest.mark.asyncio
async def test_reserve_shutdown_timeout_retains_a_larger_operator_value():
    service = system_rollback.SystemRollbackService(Middleware())
    sysctl = AsyncMock(return_value=subprocess.CompletedProcess([], 0, '1200\n', ''))

    with patch.object(system_rollback, 'run', sysctl):
        assert await service.reserve_shutdown_timeout() is None

    sysctl.assert_awaited_once_with(
        system_rollback.SYSCTL,
        '-n',
        system_rollback.SHUTDOWN_TIMEOUT_SYSCTL,
        encoding='utf8',
    )


@pytest.mark.asyncio
async def test_restore_shutdown_timeout_reinstates_a_changed_value():
    service = system_rollback.SystemRollbackService(Middleware())
    sysctl = AsyncMock(return_value=subprocess.CompletedProcess([], 0, '', ''))

    with patch.object(system_rollback, 'run', sysctl):
        await service.restore_shutdown_timeout(210)

    sysctl.assert_awaited_once_with(
        system_rollback.SYSCTL,
        f'{system_rollback.SHUTDOWN_TIMEOUT_SYSCTL}=210',
        encoding='utf8',
    )


@pytest.mark.asyncio
async def test_execute_stages_the_validated_plan_before_requesting_reboot(tmp_path):
    service = service_for_available()
    service.middleware['boot.pool_name'] = AsyncMock(return_value='freenas-boot')
    order = []

    async def reboot(*args):
        order.append('reboot')

    service.middleware['system.reboot'] = AsyncMock(side_effect=reboot)
    service.quiesce_workloads = AsyncMock(side_effect=lambda job: order.append('quiesce'))
    service.reserve_shutdown_timeout = AsyncMock(side_effect=lambda: order.append('timeout'))
    job = Mock()
    pending = tmp_path / 'pending'
    stage_restore_plan = service.stage_restore_plan

    def stage(plan):
        order.append('stage')
        return stage_restore_plan(plan)

    with (
        patch.object(system_rollback, 'RESTORE_PLAN_PATH', str(pending)),
        patch.object(system_rollback, 'RESTORE_RUNNING_PATH', str(tmp_path / 'running')),
        patch.object(system_rollback, 'RESTORE_FAILED_PATH', str(tmp_path / 'failed')),
        patch.object(service, 'stage_restore_plan', side_effect=stage),
    ):
        assert await service.execute(job) is True

    plan = json.loads(pending.read_text())
    assert plan['origin_be'] == '13.3-U1.2'
    assert plan['origin_dataset'] == 'freenas-boot/ROOT/13.3-U1.2'
    assert plan['roots'] == ['tank/.system', 'tank/iocage']
    service.middleware['system.reboot'].assert_awaited_once_with({'delay': 3})
    assert order == ['quiesce', 'timeout', 'stage', 'reboot']


@pytest.mark.asyncio
async def test_execute_cleans_the_plan_and_restores_timeout_when_reboot_dispatch_fails(tmp_path):
    service = service_for_available()
    service.middleware['boot.pool_name'] = AsyncMock(return_value='freenas-boot')
    service.middleware['system.reboot'] = AsyncMock(side_effect=RuntimeError('reboot failed'))
    service.quiesce_workloads = AsyncMock()
    service.reserve_shutdown_timeout = AsyncMock(return_value=210)
    service.restore_shutdown_timeout = AsyncMock()
    pending = tmp_path / 'pending'

    with (
        patch.object(system_rollback, 'RESTORE_PLAN_PATH', str(pending)),
        patch.object(system_rollback, 'RESTORE_RUNNING_PATH', str(tmp_path / 'running')),
        patch.object(system_rollback, 'RESTORE_FAILED_PATH', str(tmp_path / 'failed')),
        pytest.raises(RuntimeError, match='reboot failed'),
    ):
        await service.execute(Mock())

    assert not pending.exists()
    service.restore_shutdown_timeout.assert_awaited_once_with(210)


def load_shutdown_helper():
    root = Path(__file__).parents[6]
    path = root / 'src/freenas/usr/local/libexec/ix_system_rollback.py'
    spec = importlib.util.spec_from_file_location('ix_system_rollback', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shutdown_hook_runs_after_middlewared_has_stopped():
    root = Path(__file__).parents[6]
    hook = root / 'src/freenas/etc/ix.rc.d/ix-system-rollback'
    source = hook.read_text()
    assert '# BEFORE: middlewared' in source
    assert '# KEYWORD: shutdown' in source
    assert hook.stat().st_mode & 0o111


def restore_plan():
    return {
        'version': 1,
        'window_id': 1,
        'origin_be': '13.3-U1.2',
        'origin_realname': '13.3-U1.2',
        'origin_dataset': 'freenas-boot/ROOT/13.3-U1.2',
        'roots': ['tank/.system', 'tank/iocage'],
        'snapshots': SNAPSHOTS,
    }


class FakeCommand:

    def __init__(self, helper, missing_snapshot=None):
        self.helper = helper
        self.missing_snapshot = missing_snapshot
        self.calls = []
        self.mounted = {'tank/.system', 'tank/.system/samba4', 'tank/iocage', 'tank/iocage/jails/new'}

    def __call__(self, argv, check=True):
        self.calls.append((tuple(argv), check))
        if argv[:7] == [self.helper.ZFS, 'list', '-H', '-o', 'name', '-t', 'snapshot']:
            snapshot = argv[7]
            output = '' if snapshot == self.missing_snapshot else f'{snapshot}\n'
            return subprocess.CompletedProcess(argv, 0, output, '')
        if argv == [self.helper.BECTL, 'list', '-H']:
            return subprocess.CompletedProcess(argv, 0, '13.3-U1.2\t-\t-\t-\t-\n', '')
        if argv[:7] == [self.helper.ZFS, 'list', '-H', '-r', '-o', 'name', '-t']:
            root = argv[8]
            datasets = {
                'tank/.system': ['tank/.system', 'tank/.system/samba4'],
                'tank/iocage': [
                    'tank/iocage', 'tank/iocage/jails', 'tank/iocage/jails/old', 'tank/iocage/jails/new',
                ],
            }[root]
            return subprocess.CompletedProcess(argv, 0, '\n'.join(datasets) + '\n', '')
        if argv == [self.helper.MOUNT, '-p']:
            output = ''.join(f'{dataset} /mnt/{i} zfs rw 0 0\n' for i, dataset in enumerate(sorted(self.mounted)))
            return subprocess.CompletedProcess(argv, 0, output, '')
        if argv[:2] == [self.helper.UMOUNT, '-f']:
            self.mounted.remove(argv[2])
            return subprocess.CompletedProcess(argv, 0, '', '')
        return subprocess.CompletedProcess(argv, 0, '', '')


def rollback_database(path):
    with sqlite3.connect(path) as database:
        database.execute(
            'CREATE TABLE system_rollbackwindow '
            '(id INTEGER PRIMARY KEY, snapshots TEXT, closed_reason TEXT)'
        )
        database.execute(
            'INSERT INTO system_rollbackwindow (id, snapshots, closed_reason) VALUES (?, ?, ?)',
            (1, json.dumps(SNAPSHOTS), None),
        )


def test_shutdown_restore_removes_only_new_descendants_before_rollback(tmp_path):
    helper = load_shutdown_helper()
    command = FakeCommand(helper)
    database_path = tmp_path / 'freenas-v1.db'
    rollback_database(database_path)

    helper.execute_plan(
        restore_plan(), command=command, database_path=str(database_path), logger=lambda message: None,
    )

    commands = [call[0] for call in command.calls]
    destroy_new = (helper.ZFS, 'destroy', '-r', 'tank/iocage/jails/new')
    first_rollback = next(i for i, argv in enumerate(commands) if argv[:2] == (helper.ZFS, 'rollback'))
    activate = commands.index((helper.BECTL, 'activate', '13.3-U1.2'))
    assert destroy_new in commands
    assert commands.index(destroy_new) < first_rollback < activate
    assert not any(
        argv[:3] == (helper.ZFS, 'destroy', '-r') and argv[-1] == 'tank/iocage/jails/old'
        for argv in commands
    )

    with sqlite3.connect(database_path) as database:
        snapshots, reason = database.execute(
            'SELECT snapshots, closed_reason FROM system_rollbackwindow WHERE id = 1'
        ).fetchone()
    assert json.loads(snapshots) == []
    assert reason == 'consumed'


def test_shutdown_restore_does_nothing_destructive_when_preflight_fails(tmp_path):
    helper = load_shutdown_helper()
    command = FakeCommand(helper, missing_snapshot=SNAPSHOTS[-1])

    with pytest.raises(helper.RestoreError, match='no longer present'):
        helper.execute_plan(restore_plan(), command=command, database_path=str(tmp_path / 'unused.db'))

    commands = [call[0] for call in command.calls]
    assert not any(argv[0] in (helper.UMOUNT, helper.BECTL) and argv[1] in ('-f', 'activate') for argv in commands)
    assert not any(argv[:2] == (helper.ZFS, 'rollback') for argv in commands)


def test_shutdown_restore_never_destroys_an_uncaptured_parent(tmp_path):
    helper = load_shutdown_helper()
    command = FakeCommand(helper)
    plan = restore_plan()
    plan['snapshots'] = [snapshot for snapshot in plan['snapshots'] if '/jails@' not in snapshot]

    with pytest.raises(helper.RestoreError, match='parents of captured state'):
        helper.execute_plan(plan, command=command, database_path=str(tmp_path / 'unused.db'))

    commands = [call[0] for call in command.calls]
    assert not any(argv[:2] == (helper.UMOUNT, '-f') for argv in commands)
    assert not any(argv[:2] == (helper.ZFS, 'destroy') for argv in commands)


def test_failed_shutdown_attempt_is_quarantined_and_not_retried(tmp_path):
    helper = load_shutdown_helper()
    command = FakeCommand(helper, missing_snapshot=SNAPSHOTS[-1])
    pending = tmp_path / 'pending'
    running = tmp_path / 'running'
    failed = tmp_path / 'failed'
    log_path = tmp_path / 'restore.log'
    pending.write_text(json.dumps(restore_plan()))

    with pytest.raises(helper.RestoreError, match='no longer present'):
        helper.consume_plan(
            plan_path=str(pending),
            running_path=str(running),
            failed_path=str(failed),
            log_path=str(log_path),
            database_path=str(tmp_path / 'unused.db'),
            command=command,
        )

    assert not pending.exists()
    assert not running.exists()
    assert 'no longer present' in json.loads(failed.read_text())['error']
