import asyncio
import copy
from unittest.mock import AsyncMock, Mock, patch

import pytest
from middlewared.plugins import applications_freebsd
from middlewared.plugins.applications_freebsd import (
    ApplicationsFSAttachmentDelegate,
    ApplicationsService,
)
from middlewared.service_exception import CallError


@pytest.fixture
def attached():
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    config = {'id': 1, 'pool': 'tank', 'subnet': '10.88.0.0/16',
              'runtime_ready': True, 'restart_on_boot': True}
    records = [
        {'name': name, 'container_id': char * 64, 'restart_policy': policy, 'volumes': []}
        for name, char, policy in [('first', 'a', 'always'), ('second', 'b', 'no'), ('idle', 'c', 'no')]
    ]
    running = {'first': True, 'second': True, 'idle': False}
    events = []

    async def get_config():
        return {**config, 'runtime_ready': config['runtime_ready'] and service._pool_transition() is None}

    async def inspect(current, record):
        events.append(('inspect', record['name']))
        return {'State': {'Running': running[record['name']]}}, record['container_id']

    async def podman(current, operation, container_id):
        name = next(record['name'] for record in records if record['container_id'] == container_id)
        events.append((operation, name))
        running[name] = operation == 'start'

    async def teardown(current, *, stop=True):
        events.append(('teardown', stop))
        config['runtime_ready'] = False
        return True

    async def setup(**kwargs):
        events.append(('setup', kwargs))
        config['runtime_ready'] = True
        return True

    service.config = AsyncMock(side_effect=get_config)
    service._validate_application_store = AsyncMock()
    service._validate_managed_configs = Mock()
    service._store_guid = AsyncMock(return_value='123456')
    service._read_records = Mock(return_value=(records, []))
    service._require_owned_container = AsyncMock(side_effect=inspect)
    service._inspect_owned_container = AsyncMock(side_effect=inspect)

    async def inspect_managed(current, records):
        # the internal development record: the batch helper answers with what the
        # per-record seam these tests reshape would have answered.
        result = {}
        for record in records:
            try:
                result[record['name']] = await service._require_owned_container(current, record)
            except CallError as error:
                result[record['name']] = error
        return result

    service._inspect_managed_containers = AsyncMock(side_effect=inspect_managed)
    service._podman = AsyncMock(side_effect=podman)
    service._runtime_teardown_impl = AsyncMock(side_effect=teardown)
    service._runtime_setup_impl = AsyncMock(side_effect=setup)
    service._active_controller = AsyncMock(return_value=True)
    return service, middleware, config, records, running, events


@pytest.mark.asyncio
async def test_pool_detachment_stops_validated_original_ids_before_runtime_teardown(attached):
    service, middleware, config, records, running, events = attached
    original = copy.deepcopy(records)
    assert await service.stop_for_pool('tank') is True
    first_stop = next(index for index, event in enumerate(events) if event[0] == 'stop')
    assert {event[1] for event in events[:first_stop] if event[0] == 'inspect'} == set(running)
    assert not any(running.values())
    assert events[-1] == ('teardown', False)
    assert service._pool_transition()['running'] == {'first': 'a' * 64, 'second': 'b' * 64}
    assert config['restart_on_boot'] is True
    assert records == original
    assert (await service.config())['runtime_ready'] is False
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['record', 'ownership', 'state', 'store'])
async def test_unsafe_detachment_refuses_before_stopping_any_workload(attached, fault):
    service, _, _, _, _, _ = attached
    if fault == 'record':
        service._read_records.return_value = ([], [{'name': 'broken', 'error': 'invalid'}])
    elif fault == 'ownership':
        service._require_owned_container.side_effect = CallError('container identity mismatch')
    elif fault == 'state':
        service._require_owned_container.return_value = ({'State': {'Running': 'false'}}, 'a' * 64)
        service._require_owned_container.side_effect = None
    else:
        service._validate_application_store.side_effect = CallError('store is not mounted')
    with pytest.raises(CallError):
        await service.stop_for_pool('tank')
    assert service._pool_transition() is None
    service._podman.assert_not_awaited()
    service._runtime_teardown_impl.assert_not_awaited()


@pytest.mark.asyncio
async def test_partial_stop_failure_can_restore_only_previously_running_apps(attached):
    service, _, config, records, running, _ = attached
    podman = service._podman.side_effect

    async def fail_second(current, operation, container_id):
        if operation == 'stop' and container_id == 'b' * 64:
            raise CallError('stop refused')
        return await podman(current, operation, container_id)

    service._podman.side_effect = fail_second
    with pytest.raises(CallError, match='could not all be stopped'):
        await service.stop_for_pool('tank')
    assert running == {'first': False, 'second': True, 'idle': False}
    service._runtime_teardown_impl.assert_not_awaited()
    assert service._pool_transition() is not None
    assert await service.rollback_pool_export('tank') is True
    assert running == {'first': True, 'second': True, 'idle': False}
    starts = [call.args[2] for call in service._podman.await_args_list if call.args[1] == 'start']
    assert starts == ['a' * 64]
    assert config['restart_on_boot'] is True
    assert [record['container_id'] for record in records] == [char * 64 for char in 'abc']
    assert service._pool_transition() is None


@pytest.mark.asyncio
async def test_successful_stop_then_failed_export_restores_manual_running_state(attached):
    service, _, _, _, running, _ = attached
    await service.stop_for_pool('tank')
    assert await service.rollback_pool_export('tank') is True
    assert running == {'first': True, 'second': True, 'idle': False}
    service._runtime_setup_impl.assert_awaited_once_with(allow_pool_transition=True)
    assert service._pool_transition() is None


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['guid', 'records', 'subnet', 'boot', 'container', 'store'])
async def test_rollback_revalidates_identity_before_runtime_or_start_mutations(attached, fault):
    service, _, config, records, _, _ = attached
    await service.stop_for_pool('tank')
    service._podman.reset_mock()
    if fault == 'guid':
        service._store_guid.return_value = '999999'
    elif fault == 'records':
        records[0]['container_id'] = 'f' * 64
    elif fault == 'subnet':
        config['subnet'] = '10.89.0.0/16'
    elif fault == 'boot':
        config['restart_on_boot'] = False
    elif fault == 'container':
        service._require_owned_container.side_effect = CallError('container ownership changed')
    else:
        service._validate_application_store.side_effect = CallError('pool unavailable')
    with pytest.raises(CallError):
        await service.rollback_pool_export('tank')
    service._runtime_setup_impl.assert_not_awaited()
    service._podman.assert_not_awaited()
    assert service._pool_transition() is not None


@pytest.mark.asyncio
async def test_cancelled_stop_settles_before_releasing_lifecycle_and_retains_recovery(attached):
    service, _, _, _, running, _ = attached
    entered, release = asyncio.Event(), asyncio.Event()
    podman = service._podman.side_effect

    async def delayed_stop(*args):
        entered.set()
        await release.wait()
        await podman(*args)

    service._podman.side_effect = delayed_stop
    task = asyncio.create_task(service.stop_for_pool('tank'))
    await asyncio.wait_for(entered.wait(), 1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not any(running.values())
    service._runtime_teardown_impl.assert_not_awaited()
    assert service._pool_transition() is not None
    assert await service.rollback_pool_export('tank') is True
    assert running == {'first': True, 'second': True, 'idle': False}


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['runtime', 'start'])
async def test_failed_recovery_keeps_gate_for_retry(attached, failure):
    service, _, _, _, _, _ = attached
    await service.stop_for_pool('tank')
    if failure == 'runtime':
        service._runtime_setup_impl.side_effect = CallError('runtime failed')
    else:
        service._podman.side_effect = CallError('start failed')
    with pytest.raises(CallError, match='failed'):
        await service.rollback_pool_export('tank')
    assert service._pool_transition() is not None
    with pytest.raises(CallError, match='changing or recovering'):
        await service._require_config()


@pytest.mark.asyncio
async def test_import_replays_record_boot_policy_instead_of_prior_manual_running_state(attached):
    service, _, config, records, running, _ = attached
    await service.stop_for_pool('tank')
    assert await service.pool_available('tank') is True
    assert running == {'first': True, 'second': False, 'idle': False}
    assert config['restart_on_boot'] is True
    assert [record['container_id'] for record in records] == [char * 64 for char in 'abc']
    assert service._pool_transition() is None


@pytest.mark.asyncio
async def test_import_rejects_replaced_store_and_keeps_transition(attached):
    service, _, _, _, _, _ = attached
    await service.stop_for_pool('tank')
    service._store_guid.return_value = '99'
    with pytest.raises(CallError, match='identity changed'):
        await service.pool_available('tank')
    service._runtime_setup_impl.assert_not_awaited()
    assert service._pool_transition() is not None


@pytest.mark.asyncio
async def test_transition_gates_public_configure_and_runtime_interface_boot_recovery(attached):
    service, middleware, _, _, _, _ = attached
    await service.stop_for_pool('tank')
    service._runtime_setup_impl = ApplicationsService._runtime_setup_impl.__get__(service)
    with pytest.raises(CallError, match='changing or recovering'):
        await service.configure(Mock(), {'pool': 'other', 'subnet': '10.89.0.0/16'})
    with pytest.raises(CallError, match='changing or recovering'):
        await service.start(Mock(), 'first')
    assert await service.runtime_setup() is False
    service._podman.reset_mock()
    await service.start_on_boot()
    await service.interface_sync()
    service._podman.assert_not_awaited()
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('condition', ['unconfigured', 'unrelated', 'standby'])
async def test_import_inert_for_unconfigured_unrelated_or_standby(attached, condition):
    service, _, config, _, _, _ = attached
    pool = 'tank'
    if condition == 'unconfigured':
        config['pool'] = None
    elif condition == 'unrelated':
        pool = 'other'
    else:
        service._active_controller.return_value = False
    assert await service.pool_available(pool) is False
    service._validate_application_store.assert_not_awaited()
    service._runtime_setup_impl.assert_not_awaited()
    service._podman.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('condition', ['unconfigured', 'unrelated'])
async def test_export_inert_for_unconfigured_or_unrelated_pool(attached, condition):
    service, _, config, _, running, _ = attached
    delegate = ApplicationsFSAttachmentDelegate(service.middleware)
    delegate.middleware.call = AsyncMock(side_effect=lambda method, *args: None)
    pool = 'tank'
    if condition == 'unconfigured':
        config['pool'] = None
    else:
        pool = 'other'

    # Exporting a pool this service does not own must not touch a single workload.
    assert await service.stop_for_pool(pool) is False
    assert service._pool_transition() is None
    assert running == {'first': True, 'second': True, 'idle': False}
    assert config['restart_on_boot'] is True
    service._validate_application_store.assert_not_awaited()
    service._validate_managed_configs.assert_not_called()
    service._podman.assert_not_awaited()
    service._runtime_teardown_impl.assert_not_awaited()

    # The delegate reports nothing for that pool's path, so the export loop never toggles it.
    assert await service.pool_attachments(f'/mnt/{pool}') == []


@pytest.mark.asyncio
async def test_attachment_paths_protect_store_children_and_external_references(attached):
    service, middleware, config, records, _, _ = attached
    records[0]['volumes'] = [
        {'name': 'data', 'dataset': 'archive/appdata', 'source': '/mnt/archive/custom/data', 'owned': False},
        {'name': 'cache', 'dataset': 'tank/applications/data/first/cache',
         'source': '/mnt/tank/applications/data/first/cache', 'owned': True},
    ]
    store = await service.pool_attachments('/mnt/tank')
    assert store == [{'id': 'applications:store', 'name': 'Applications', 'pool': 'tank'}]
    for path in ['/mnt/tank/applications/data', '/mnt/archive', '/mnt/archive/appdata',
                 '/mnt/archive/appdata/child', '/mnt/archive/custom/data']:
        refs = await service.pool_attachments(path)
        assert refs and all(ref['protected'] for ref in refs)
    assert await service.pool_attachments('/mnt/other') == []
    assert await service.pool_attachments('/mnt/archive/appdatabase') == []
    config['pool'] = None
    assert await service.pool_attachments('/mnt/tank') == []
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_unavailable_record_storage_cannot_hide_external_references(attached):
    service, _, _, _, _, _ = attached
    service._validate_application_store.side_effect = CallError('store unavailable')
    service._read_records.return_value = ([], [])
    with pytest.raises(CallError, match='store unavailable'):
        await service.pool_attachments('/mnt/other')


@pytest.mark.asyncio
async def test_detached_pool_retains_external_reference_protection_in_snapshot(attached):
    service, _, _, records, _, _ = attached
    records[0]['volumes'] = [{'name': 'data', 'dataset': 'archive/data',
                              'source': '/mnt/archive/data', 'owned': False}]
    await service.stop_for_pool('tank')
    service._validate_application_store.side_effect = CallError('store unavailable')
    service._read_records.return_value = ([], [])
    refs = await service.pool_attachments('/mnt/archive')
    assert len(refs) == 1 and refs[0]['protected'] is True


@pytest.mark.asyncio
async def test_delegate_refuses_external_detach_and_protected_deletion_before_mutations():
    middleware = Mock(call=AsyncMock())
    delegate = ApplicationsFSAttachmentDelegate(middleware)
    external = [{'id': 'applications:first:data', 'pool': 'tank', 'protected': True}]
    store = [{'id': 'applications:store', 'pool': 'tank'}]
    with pytest.raises(CallError, match='referenced'):
        await delegate.toggle(external, False)
    with pytest.raises(CallError, match='referenced by installed applications'):
        await delegate.delete(external)
    assert await delegate.rollback_export(external) is True
    await delegate.start(external)
    middleware.call.assert_not_awaited()
    await delegate.toggle(store, False)
    await delegate.toggle(store, True)
    await delegate.rollback_export(store)
    # the internal development record: a cascading deletion of the whole store is the explicit removal
    await delegate.delete(store)
    assert [call.args for call in middleware.call.await_args_list] == [
        ('applications.stop_for_pool', 'tank'), ('applications.pool_available', 'tank'),
        ('applications.rollback_pool_export', 'tank'), ('applications.deactivate_pool', 'tank')]


@pytest.mark.asyncio
async def test_external_refs_or_invalid_records_cannot_be_abandoned_by_pool_switch(attached):
    service, _, config, records, _, _ = attached
    service._validate_pool_and_subnet = AsyncMock()
    records[0]['volumes'] = [{'owned': False}]
    with pytest.raises(CallError, match='external dataset references'):
        await service._reconfigure(Mock(), config, {'pool': 'other', 'subnet': config['subnet']})
    service._read_records.return_value = ([], [{'name': 'broken'}])
    with pytest.raises(CallError, match='invalid managed records'):
        await service._reconfigure(Mock(), config, {'pool': 'other', 'subnet': config['subnet']})
    service._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_restart_with_unavailable_store_cannot_abandon_unknown_external_references(attached):
    service, _, config, _, _, _ = attached
    config['runtime_ready'] = False
    service._validate_pool_and_subnet = AsyncMock()
    service._validate_application_store.side_effect = CallError('old store unavailable')
    service._read_records.return_value = ([], [])
    with pytest.raises(CallError, match='old store unavailable'):
        await service._reconfigure(Mock(), config, {'pool': 'other', 'subnet': config['subnet']})
    service._read_records.assert_not_called()
    service._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_interface_recovery_remains_serialized_and_preserves_original_error(attached):
    service, middleware, _, _, _, _ = attached
    service._runtime_teardown_impl.side_effect = CallError('secondary cleanup failure')
    with patch.object(
        applications_freebsd, '_generate_pf_checked', AsyncMock(side_effect=CallError('PF failed')),
    ), pytest.raises(CallError, match='PF failed'):
        await service.interface_sync()
    middleware.call.assert_any_await('alert.oneshot_create', 'ApplicationsRuntimeSetupFailed', None)


@pytest.mark.asyncio
async def test_setup_registers_native_attachment_and_pool_recovery_hooks():
    middleware = Mock(call=AsyncMock(return_value={'pool': None}))
    await applications_freebsd.setup(middleware)
    registration = middleware.call.await_args_list[0].args
    assert registration[0] == 'pool.dataset.register_attachment_delegate'
    assert isinstance(registration[1], ApplicationsFSAttachmentDelegate)
    middleware.register_hook.assert_any_call('pool.post_import', applications_freebsd._pool_post_import)
    middleware.register_hook.assert_any_call('pool.post_unlock', applications_freebsd._pool_post_import)
    middleware.register_hook.assert_any_call('interface.post_sync', applications_freebsd._interface_post_sync)
