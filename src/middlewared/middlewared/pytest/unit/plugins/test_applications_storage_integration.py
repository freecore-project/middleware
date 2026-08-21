import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins import applications_freebsd
from middlewared.plugins.applications_.utils import application_paths
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.pytest.unit.plugins.test_applications_store_recovery import recovery as recovery
from middlewared.service_exception import CallError


def stub_storage_inspection(service, middleware, monkeypatch):
    ids = {'a' * 64}
    plan = [('tank/applications/storage/' + 'a' * 64, {'guid': ('12345', '-')})]
    service._validate_application_store = AsyncMock()
    service._validate_managed_configs = Mock()
    service._podman = AsyncMock(return_value=SimpleNamespace(stdout='', returncode=0))
    middleware.run_in_thread = AsyncMock(return_value=ids)
    inspect = AsyncMock(return_value=plan)
    restore = AsyncMock()
    run = AsyncMock(return_value=SimpleNamespace(stdout='', returncode=0))
    monkeypatch.setattr(applications_freebsd, 'layer_recovery_plan', inspect)
    monkeypatch.setattr(applications_freebsd, 'restore_layer_mountpoints', restore)
    monkeypatch.setattr(applications_freebsd, 'run', run)
    return SimpleNamespace(ids=ids, plan=plan, inspect=inspect, restore=restore, run=run)


@pytest.mark.asyncio
async def test_first_adoption_recovers_layers_before_pf_or_configuration_writes(recovery):
    service, middleware, old, new, record, _ = recovery
    events = []
    service._recover_storage_mountpoints = AsyncMock(side_effect=lambda config: events.append('recover'))
    service._ensure_pf_module.side_effect = lambda: events.append('pf')
    service._write_managed_configs.side_effect = lambda *args: events.append('write')

    async def rpc(method, *args):
        if method == 'datastore.update':
            events.append('datastore')

    middleware.call.side_effect = rpc
    assert await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']}) == new
    service._recover_storage_mountpoints.assert_awaited_once()
    target = service._recover_storage_mountpoints.await_args.args[0]
    assert target['pool'] == 'tank'
    assert target['subnet'] == old['subnet']
    assert events[0] == 'recover'
    assert {'pf', 'write', 'datastore'} <= set(events[1:])
    service._create_application_datasets.assert_not_awaited()
    assert record['container_id'] == 'saved-id'
    assert record['volumes'] == [{'dataset': 'tank/external', 'owned': False}]


@pytest.mark.asyncio
@pytest.mark.parametrize('cancelled', [False, True])
async def test_adoption_recovery_refusal_preserves_original_store_and_configuration(recovery, cancelled):
    service, middleware, old, _, record, _ = recovery
    failure = asyncio.CancelledError() if cancelled else CallError('Active storage layer')
    service._recover_storage_mountpoints = AsyncMock(side_effect=failure)
    with pytest.raises(asyncio.CancelledError if cancelled else CallError):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']})
    service._ensure_pf_module.assert_not_awaited()
    service._write_managed_configs.assert_not_called()
    service._create_application_datasets.assert_not_awaited()
    service._restore_managed_configs.assert_not_called()
    middleware.call.assert_not_awaited()
    assert record['container_id'] == 'saved-id'


@pytest.mark.asyncio
async def test_ready_runtime_recovery_refusal_does_not_clear_readiness_or_stop_applications():
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16', 'runtime_ready': True}
    service.config = AsyncMock(return_value=config)
    service._active_controller = AsyncMock(return_value=True)
    service._recover_storage_mountpoints = AsyncMock(side_effect=CallError('A container is still running'))
    service._clear_runtime_state = Mock()
    service._stop_managed = AsyncMock()
    service._rollback_runtime_setup = AsyncMock()
    service._write_managed_configs = Mock()
    with pytest.raises(CallError, match='still running'):
        await service.runtime_setup()
    service._recover_storage_mountpoints.assert_awaited_once_with(config)
    service._clear_runtime_state.assert_not_called()
    service._stop_managed.assert_not_awaited()
    service._rollback_runtime_setup.assert_not_awaited()
    service._write_managed_configs.assert_not_called()
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('configured', [False, True])
async def test_unconfigured_or_standby_runtime_does_not_recover_storage(configured):
    service = ApplicationsService(Mock(call=AsyncMock()))
    config = {'pool': 'tank' if configured else None, 'runtime_ready': configured}
    service.config = AsyncMock(return_value=config)
    service._active_controller = AsyncMock(return_value=False)
    service._recover_storage_mountpoints = AsyncMock()
    service._clear_runtime_state = Mock()
    service._deactivate_runtime = AsyncMock(return_value=False)
    assert await service.runtime_setup() is False
    service._recover_storage_mountpoints.assert_not_awaited()
    if configured:
        service._deactivate_runtime.assert_awaited_once_with(config, True)
    else:
        service._active_controller.assert_not_awaited()
        service._deactivate_runtime.assert_not_awaited()


@pytest.mark.asyncio
async def test_healthy_storage_recovery_does_not_query_containers_or_change_mounts(monkeypatch):
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    storage = stub_storage_inspection(service, middleware, monkeypatch)
    storage.inspect.return_value = []
    await service._recover_storage_mountpoints({'pool': 'tank'})
    service._validate_application_store.assert_awaited_once_with('tank')
    middleware.run_in_thread.assert_awaited_once_with(
        applications_freebsd.read_layer_ids, '/mnt/tank/applications/storage',
    )
    storage.inspect.assert_awaited_once_with(application_paths('tank'), storage.ids)
    service._validate_managed_configs.assert_not_called()
    service._podman.assert_not_awaited()
    storage.run.assert_not_awaited()
    storage.restore.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('problem', [
    'owner', 'config', 'podman_running', 'podman_failed', 'jail_root', 'foreign_jail', 'jls_failed', 'jls_malformed',
])
async def test_storage_recovery_refuses_untrusted_or_busy_store_before_unmount(monkeypatch, problem):
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    storage = stub_storage_inspection(service, middleware, monkeypatch)
    if problem == 'owner':
        service._validate_application_store.side_effect = CallError('Foreign store owner')
    elif problem == 'config':
        service._validate_managed_configs.side_effect = CallError('Foreign storage configuration')
    elif problem == 'podman_running':
        # ps must include foreign containers, not only those in managed records.
        service._podman.return_value.stdout = 'b' * 64 + '\n'
    elif problem == 'podman_failed':
        service._podman.side_effect = CallError('Unable to inspect Podman state')
    elif problem == 'jail_root':
        storage.run.return_value.stdout = 'path=/mnt/tank/applications/storage\n'
    elif problem == 'foreign_jail':
        storage.run.return_value.stdout = 'path="/mnt/tank/applications/storage/zfs/graph/' + 'b' * 64 + '"\n'
    elif problem == 'jls_failed':
        storage.run.return_value.returncode = 1
    else:
        storage.run.return_value.stdout = 'jid=123\n'
    with pytest.raises(CallError):
        await service._recover_storage_mountpoints({'pool': 'tank'})
    storage.restore.assert_not_awaited()
    middleware.call.assert_not_awaited()
    if problem == 'owner':
        middleware.run_in_thread.assert_not_awaited()
        storage.inspect.assert_not_awaited()
    if problem in {'owner', 'config'}:
        service._podman.assert_not_awaited()
    if problem in {'owner', 'config', 'podman_running', 'podman_failed'}:
        storage.run.assert_not_awaited()


@pytest.mark.asyncio
async def test_idle_storage_recovery_checks_all_containers_and_ignores_unrelated_jail_paths(monkeypatch):
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    storage = stub_storage_inspection(service, middleware, monkeypatch)
    storage.run.return_value.stdout = (
        'path=/mnt/tank/applications/storage-other\n'
        'path=/mnt/other/applications/storage/zfs/graph/foreign\n'
    )
    events = []

    async def podman(*args):
        events.append('ps')
        return SimpleNamespace(stdout='', returncode=0)

    async def jls(*args, **kwargs):
        events.append('jls')
        return storage.run.return_value

    service._podman.side_effect = podman
    storage.run.side_effect = jls
    storage.restore.side_effect = lambda plan: events.append('restore')
    config = {'pool': 'tank'}
    await service._recover_storage_mountpoints(config)
    service._validate_managed_configs.assert_called_once_with('tank')
    service._podman.assert_awaited_once_with(config, 'ps', '--quiet')
    storage.run.assert_awaited_once_with(['jls', '-n', 'path'], check=False, encoding='utf8')
    storage.restore.assert_awaited_once_with(storage.plan)
    assert events == ['ps', 'jls', 'restore']
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_adoption_cancellation_settles_storage_repair_before_abort_without_configuration_writes(
    recovery, monkeypatch,
):
    service, middleware, old, _, _, _ = recovery
    service._recover_storage_mountpoints = ApplicationsService._recover_storage_mountpoints.__get__(service)
    storage = stub_storage_inspection(service, middleware, monkeypatch)
    entered = asyncio.Event()
    release = asyncio.Event()
    settled = []

    async def restore(plan):
        assert plan == storage.plan
        entered.set()
        await release.wait()
        settled.append(True)

    storage.restore.side_effect = restore
    task = asyncio.create_task(service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']}))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert not settled
        service._ensure_pf_module.assert_not_awaited()
        service._write_managed_configs.assert_not_called()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert settled == [True]
    service._ensure_pf_module.assert_not_awaited()
    service._write_managed_configs.assert_not_called()
    service._create_application_datasets.assert_not_awaited()
    middleware.call.assert_not_awaited()
