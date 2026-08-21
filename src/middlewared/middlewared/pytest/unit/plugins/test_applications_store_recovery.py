import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError, ValidationErrors


@pytest.fixture
def recovery():
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    service._recover_storage_mountpoints = AsyncMock()
    old = dict(id=1, pool=None, subnet='10.88.0.0/16', restart_on_boot=False,
               pf_owned=False, filter_local_original=None, ipv4_forwarding_original=None,
               bridge_pfil_member_original=None, runtime_ready=False)
    new = {**old, 'pool': 'tank', 'restart_on_boot': True, 'runtime_ready': True}
    service.config = AsyncMock(side_effect=[old, new])
    service._validate_pool_and_subnet = AsyncMock(return_value=True)
    service._validate_managed_configs = Mock()
    service._running_managed = AsyncMock(return_value=[])
    record = {'name': 'saved', 'restart_policy': 'always', 'container_id': 'saved-id',
              'volumes': [{'dataset': 'tank/external', 'owned': False}]}
    service._read_records = Mock(return_value=([record], []))
    snapshot = {'storage.conf': 'previous storage', 'containers.conf': 'previous network'}
    service._snapshot_managed_configs = Mock(return_value=snapshot)
    service._restore_managed_configs = Mock()
    service._ensure_pf_module = AsyncMock()
    service._pf_enabled = AsyncMock(return_value=False)
    service._capture_runtime_sysctls = AsyncMock(return_value={
        'filter_local_original': 0, 'ipv4_forwarding_original': 0, 'bridge_pfil_member_original': 0,
    })
    service._create_application_datasets = AsyncMock()
    service._write_managed_configs = Mock()
    service._reserve_jail_bridge = AsyncMock()
    service._apply_runtime_sysctls = AsyncMock()
    service._mark_pf_active = Mock()
    service._mark_runtime_ready = Mock()
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()
    with patch('middlewared.plugins.applications_freebsd.os.makedirs'), patch(
        'middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock(),
    ):
        yield service, middleware, old, new, record, snapshot


@pytest.mark.asyncio
async def test_first_configure_recovers_owned_store_without_recreating_data(recovery):
    service, middleware, old, new, record, _ = recovery
    assert await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']}) == new
    service._validate_pool_and_subnet.assert_awaited_once_with(
        'tank', old['subnet'], allow_managed_store=True,
    )
    service._validate_managed_configs.assert_called_once_with('tank', old['subnet'])
    service._create_application_datasets.assert_not_awaited()
    assert not any(c.args[0].startswith('zfs.dataset.') for c in middleware.call.await_args_list)
    saved = next(c.args[3] for c in middleware.call.await_args_list if c.args[0] == 'datastore.update')
    assert saved['restart_on_boot'] is True
    assert record['container_id'] == 'saved-id'
    assert record['volumes'] == [{'dataset': 'tank/external', 'owned': False}]


@pytest.mark.asyncio
@pytest.mark.parametrize('problem', ['network', 'running', 'records'])
async def test_recovery_refuses_unsafe_existing_state_before_runtime_writes(recovery, problem):
    service, middleware, old, *_ = recovery
    if problem == 'network':
        service._validate_managed_configs.side_effect = CallError('network does not match')
    elif problem == 'running':
        service._running_managed.return_value = ['saved']
    else:
        service._read_records.return_value = ([], [{'name': 'broken'}])
    with pytest.raises(CallError):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']})
    service._ensure_pf_module.assert_not_awaited()
    service._write_managed_configs.assert_not_called()
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('cancel', [False, True])
async def test_recovery_failure_restores_configuration_without_deleting_store(recovery, cancel):
    service, middleware, old, _, _, snapshot = recovery
    service._apply_runtime_sysctls.side_effect = asyncio.CancelledError() if cancel else CallError('runtime failure')
    with pytest.raises(asyncio.CancelledError if cancel else CallError):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']})
    service._restore_managed_configs.assert_called_once_with(snapshot)
    service._create_application_datasets.assert_not_awaited()
    assert not any(c.args[0] == 'zfs.dataset.delete' for c in middleware.call.await_args_list)
    updates = [c.args[3] for c in middleware.call.await_args_list if c.args[0] == 'datastore.update']
    assert updates[-1]['pool'] is None
    assert updates[-1]['restart_on_boot'] is False
    service._restore_runtime_sysctls.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('store_exists', [False, True])
@pytest.mark.parametrize('pf_active', [False, True])
async def test_first_use_never_takes_over_foreign_pf(store_exists, pf_active):
    async def rpc(method, *args):
        return {
            'pool.query': [{'healthy': True, 'status': 'ONLINE', 'is_decrypted': True}],
            'boot.pool_name': 'boot-pool',
            'zfs.dataset.query': [{'id': 'tank/applications'}] if store_exists else [],
            'route.system_routes': [], 'failover.licensed': False,
        }[method]
    middleware = Mock(call=AsyncMock(side_effect=rpc))
    service = ApplicationsService(middleware)
    service._active_controller = AsyncMock(return_value=True)
    service._defined_jail_networks = AsyncMock(return_value=[])
    service._validate_application_store = AsyncMock()
    service._pf_enabled = AsyncMock(return_value=pf_active)
    with patch('middlewared.plugins.applications_freebsd.os.access', return_value=True), patch(
        'middlewared.plugins.applications_freebsd.os.path.exists', return_value=not pf_active,
    ), pytest.raises(ValidationErrors, match='unmanaged ruleset'):
        await service._validate_pool_and_subnet('tank', '10.88.0.0/16', allow_managed_store=True)
    assert all(c.args[0] in {'pool.query', 'boot.pool_name', 'zfs.dataset.query',
                            'route.system_routes', 'failover.licensed'}
               for c in middleware.call.await_args_list)


@pytest.mark.asyncio
async def test_recovery_requires_owned_dataset_validation():
    async def rpc(method, *args):
        return {'pool.query': [{'healthy': True, 'status': 'ONLINE', 'is_decrypted': True}],
                'boot.pool_name': 'boot-pool', 'zfs.dataset.query': [{'id': 'tank/applications'}],
                'route.system_routes': [], 'failover.licensed': False}[method]
    service = ApplicationsService(Mock(call=AsyncMock(side_effect=rpc)))
    service._active_controller = AsyncMock(return_value=True)
    service._defined_jail_networks = AsyncMock(return_value=[])
    service._validate_application_store = AsyncMock(side_effect=CallError('invalid local ownership'))
    service._pf_enabled = AsyncMock(return_value=False)
    with patch('middlewared.plugins.applications_freebsd.os.access', return_value=True), patch(
        'middlewared.plugins.applications_freebsd.os.path.exists', return_value=False,
    ), pytest.raises(ValidationErrors, match='invalid local ownership'):
        await service._validate_pool_and_subnet('tank', '10.88.0.0/16', allow_managed_store=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('status,exists', [(0, True), (1, False), (125, None)])
async def test_container_exists_distinguishes_absence_from_storage_failure(status, exists):
    service = ApplicationsService(Mock())
    service._podman = AsyncMock(return_value=Mock(returncode=status))
    if exists is None:
        with pytest.raises(CallError, match='exit status 125'):
            await service._container_exists({}, 'saved')
    else:
        assert await service._container_exists({}, 'saved') is exists


@pytest.mark.asyncio
async def test_storage_inspection_failure_cannot_pass_recovery_gate(recovery):
    service, middleware, old, _, record, _ = recovery
    record['container_name'] = 'freecore-app-saved'
    service._running_managed = ApplicationsService._running_managed.__get__(service)
    service._podman = AsyncMock(return_value=Mock(returncode=125))
    with pytest.raises(CallError, match='classify application.*125'):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': old['subnet']})
    service._ensure_pf_module.assert_not_awaited()
    service._write_managed_configs.assert_not_called()
    middleware.call.assert_not_awaited()
