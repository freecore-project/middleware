import asyncio
import contextlib
import json
import re
from datetime import datetime, timedelta, timezone
import socket
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, call, patch

import pytest

from middlewared.plugins.applications_.utils import (
    APPLICATION_LABEL,
    MANAGED_LABEL,
    TRANSACTION_LABEL,
    application_paths,
    render_containers_conf,
    render_storage_conf,
)
from middlewared.plugins.applications_freebsd import (
    RESTART_WINDOW_SECONDS,
    STARTUP_SETTLE_SECONDS,
    DATASET_NAME,
    NETWORK_OWNED_ANNOTATIONS,
    ApplicationsService,
    _generate_pf_checked,
    _system_event,
    pf_renderer,
)
from middlewared.service_exception import CallError, ValidationErrors


def service_with_middleware():
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.run_in_thread = AsyncMock()
    service = ApplicationsService(middleware)
    service._recover_storage_mountpoints = AsyncMock()

    async def inspect_owned(
        config, record, container=None, transaction_id=None,
        require_record_identity=True,
    ):
        container_id = ('2' if transaction_id is not None else '1') * 64
        inspection = managed_inspection(
            record, container_id=container_id, transaction_id=transaction_id
        )
        return inspection, container_id

    service._inspect_owned_container = AsyncMock(side_effect=inspect_owned)

    async def inspect_managed(config, records):
        return await batched_from_single(service, config, records)

    service._inspect_managed_containers = AsyncMock(side_effect=inspect_managed)
    service._remove_owned_container = AsyncMock()
    service._remove_transaction_container = AsyncMock()
    service._release_image = AsyncMock(return_value=False)
    return service, middleware


async def batched_from_single(service, config, records):
    """the internal development record: drive the batch helper's contract from the per-record mock,
    so a test that shapes `_inspect_owned_container` shapes query/boot/attachment too."""
    result = {}
    for record in records:
        try:
            result[record['name']] = await service._inspect_owned_container(config, record)
        except CallError as error:
            result[record['name']] = error
    return result


def install_data(**overrides):
    data = {
        'name': 'demo',
        'image': 'registry.example/demo:1',
        'ports': [],
        'environment': [],
        'volumes': [],
        'annotations': [],
        'restart_policy': 'always',
        'portal': None,
        'healthcheck': None,
        'health_timeout': 0,
    }
    data.update(overrides)
    return data


def persisted_record(**overrides):
    record = {
        'schema': 2,
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'container_id': '1' * 64,
        'image': 'registry.example/demo:1',
        'image_id': 'sha256:abcdef',
        'digest': 'sha256:' + 'a' * 64,
        'ports': [],
        'environment': [],
        'volumes': [],
        'annotations': [],
        'restart_policy': 'always',
        'portal': None,
        'healthcheck': None,
        'created_at': '2026-08-24T00:00:00+00:00',
        'updated_at': '2026-08-24T00:00:00+00:00',
    }
    record.update(overrides)
    return record


def managed_inspection(
    record=None, *, running=True, container_id=None, transaction_id=None,
):
    record = record or persisted_record()
    labels = {
        MANAGED_LABEL: 'true',
        APPLICATION_LABEL: record['name'],
    }
    if transaction_id is not None:
        labels[TRANSACTION_LABEL] = transaction_id
    return {
        'Id': container_id or '1' * 64,
        'Config': {'Labels': labels},
        'State': {'Running': running},
    }


def managed_podman_harness(service, record, interrupt_operation=None):
    old_id = '1' * 64
    replacement_id = '2' * 64
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    interrupted = False
    containers = {
        old_id: {
            'name': record['container_name'],
            'labels': {
                MANAGED_LABEL: 'true',
                APPLICATION_LABEL: record['name'],
            },
            'running': True,
        },
    }

    def find_container(value):
        if value in containers:
            return value, containers[value]
        for container_id, container in containers.items():
            if container['name'] == value:
                return container_id, container
        return None, None

    async def container_exists(config, value):
        return find_container(value)[0] is not None

    async def inspect_container(config, value):
        container_id, container = find_container(value)
        if container is None:
            raise CallError(f'Container {value!r} is unavailable.')
        return {
            'Id': container_id,
            'Config': {'Labels': dict(container['labels'])},
            'State': {'Running': container['running']},
        }

    async def podman(config, *arguments, **kwargs):
        nonlocal interrupted
        operation = arguments[0]
        result = SimpleNamespace(returncode=0, stdout='', stderr='')
        if operation in {'stop', 'start', 'restart'}:
            container_id, container = find_container(arguments[1])
            if container is None:
                raise CallError('container is unavailable')
            container['running'] = operation != 'stop'
        elif operation == 'rename':
            container_id, container = find_container(arguments[1])
            if container is None:
                raise CallError('container is unavailable')
            if find_container(arguments[2])[0] is not None:
                raise CallError('target container name is occupied')
            container['name'] = arguments[2]
        elif operation == 'create':
            name = arguments[arguments.index('--name') + 1]
            labels = {
                arguments[index + 1].split('=', 1)[0]:
                arguments[index + 1].split('=', 1)[1]
                for index, argument in enumerate(arguments[:-1])
                if argument == '--label'
            }
            if find_container(name)[0] is not None:
                raise CallError('target container name is occupied')
            containers[replacement_id] = {
                'name': name,
                'labels': labels,
                'running': False,
            }
        elif operation == 'rm':
            container_id, container = find_container(arguments[-1])
            if container is not None:
                del containers[container_id]
        elif operation == 'container' and arguments[1] == 'ls':
            transaction_id = arguments[-1].rsplit('=', 1)[1]
            result = SimpleNamespace(
                returncode=0,
                stdout=''.join(
                    f'{container_id}\n'
                    for container_id, container in containers.items()
                    if container['labels'].get(TRANSACTION_LABEL) == transaction_id
                ),
                stderr='',
            )

        if operation == interrupt_operation and not interrupted:
            interrupted = True
            operation_started.set()
            await release_operation.wait()
        return result

    service._container_exists = AsyncMock(side_effect=container_exists)
    service._inspect_container = AsyncMock(side_effect=inspect_container)
    service._podman = AsyncMock(side_effect=podman)
    service._inspect_owned_container = ApplicationsService._inspect_owned_container.__get__(
        service, ApplicationsService
    )
    service._remove_transaction_container = (
        ApplicationsService._remove_transaction_container.__get__(
            service, ApplicationsService
        )
    )
    return SimpleNamespace(
        containers=containers,
        old_id=old_id,
        replacement_id=replacement_id,
        operation_started=operation_started,
        release_operation=release_operation,
    )


def catalog_record(**overrides):
    record = persisted_record(
        image=f'ghcr.io/daemonless/demo@sha256:{"a" * 64}',
        image_id='sha256:' + '1' * 64,
        ports=[{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        environment=[{'name': 'TOKEN', 'value': 'configured-secret'}],
        volumes=[{
            'name': 'data',
            'target': '/data',
            'dataset': 'tank/persistent-demo',
            'source': '/mnt/tank/persistent-demo',
            'owned': False,
            'read_only': False,
        }],
        portal={'scheme': 'http', 'port': 18080, 'path': '/'},
        healthcheck={
            'type': 'HTTP',
            'scheme': 'http',
            'container_port': 8080,
            'host_port': 18080,
            'path': '/health',
        },
        catalog={
            'id': 'daemonless:demo',
            'object_sha256': 'c' * 64,
            'entry_revision': 1,
            'version': 'v1',
            'snapshot_sequence': 1,
            'repository': 'https://github.com/daemonless/demo',
            'source_commit': 'd' * 40,
            'compose_sha256': 'e' * 64,
        },
    )
    record.update(overrides)
    return record


def catalog_replacement(**overrides):
    replacement = {
        'name': 'demo',
        'image': f'ghcr.io/daemonless/demo@sha256:{"b" * 64}',
        'ports': [{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        'environment': [{'name': 'TOKEN', 'value': 'configured-secret'}],
        'volumes': [{
            'name': 'data',
            'target': '/data',
            'dataset': 'tank/persistent-demo',
            'source': '/mnt/tank/persistent-demo',
            'owned': False,
            'read_only': False,
        }],
        'annotations': [],
        'restart_policy': 'always',
        'portal': {'scheme': 'http', 'port': 18080, 'path': '/'},
        'healthcheck': {
            'type': 'HTTP',
            'scheme': 'http',
            'container_port': 8080,
            'host_port': 18080,
            'path': '/health',
        },
    }
    replacement.update(overrides)
    return replacement


def replacement_provenance(**overrides):
    provenance = {
        'id': 'daemonless:demo',
        'object_sha256': 'f' * 64,
        'entry_revision': 2,
        'version': 'v2',
        'snapshot_sequence': 2,
        'repository': 'https://github.com/daemonless/demo',
        'source_commit': '1' * 40,
        'compose_sha256': '2' * 64,
    }
    provenance.update(overrides)
    return provenance


def test_dataset_names_cannot_ambiguously_split_podman_volume_arguments():
    assert re.fullmatch(DATASET_NAME, 'tank/app-data/config')
    assert re.fullmatch(DATASET_NAME, 'tank/app:data') is None


def test_managed_podman_configs_are_verified_before_reusing_a_store():
    service, _ = service_with_middleware()
    paths = application_paths('tank')
    snapshot = {
        paths['storage_conf']: render_storage_conf('tank'),
        paths['containers_conf']: render_containers_conf('tank', '10.88.0.0/16'),
    }
    service._snapshot_managed_configs = Mock(return_value=snapshot)

    assert service._validate_managed_configs('tank', '10.88.0.0/16') == snapshot

    snapshot[paths['storage_conf']] = render_storage_conf('other')
    with pytest.raises(CallError, match='storage configuration.*unsafe'):
        service._validate_managed_configs('tank')


def test_managed_podman_config_rejects_a_tampered_or_stale_subnet():
    service, _ = service_with_middleware()
    paths = application_paths('tank')
    snapshot = {
        paths['storage_conf']: render_storage_conf('tank'),
        paths['containers_conf']: render_containers_conf('tank', '10.89.0.0/16'),
    }
    service._snapshot_managed_configs = Mock(return_value=snapshot)

    with pytest.raises(CallError, match='does not match'):
        service._validate_managed_configs('tank', '10.88.0.0/16')

    snapshot[paths['containers_conf']] += 'default_subnet = "10.90.0.0/16"\n'
    with pytest.raises(CallError, match='network configuration.*unsafe'):
        service._validate_managed_configs('tank')


def test_persisted_record_validation_rejects_executable_and_mount_tampering():
    config = {'pool': 'tank'}
    record = persisted_record()
    assert ApplicationsService._validate_record(config, record, 'demo') is record

    with pytest.raises(ValueError, match='unsupported record schema'):
        ApplicationsService._validate_record(config, {**record, 'schema': 1}, 'demo')

    with pytest.raises(ValueError, match='immutable Podman identity'):
        ApplicationsService._validate_record(
            config, {**record, 'container_id': 'a' * 63}, 'demo'
        )

    with pytest.raises(ValueError, match='container name'):
        ApplicationsService._validate_record(
            config, {**record, 'container_name': '--latest'}, 'demo'
        )

    with pytest.raises(ValueError, match='owned volume'):
        ApplicationsService._validate_record(config, {
            **record,
            'volumes': [{
                'name': 'data',
                'target': '/data',
                'dataset': 'otherpool/private',
                'source': '/mnt/otherpool/private',
                'owned': True,
                'read_only': False,
            }],
        }, 'demo')


def test_persisted_record_accepts_tag_following_provenance_with_or_without_a_variant():
    # the internal development record: the pulled image's flavour label; 15.1-RC2 wrote none.
    config = {'pool': 'tank'}
    provenance = {
        'id': 'daemonless:demo', 'version': '1.37.3', 'compose_sha256': 'e' * 64,
        'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:latest',
    }
    for catalog in (
        provenance,
        {**provenance, 'variant': None},
        {**provenance, 'variant': 'latest'},
        {**provenance, 'variant': '14-pkg'},
    ):
        record = catalog_record(catalog=catalog)
        assert ApplicationsService._validate_record(config, record, 'demo') is record
    for variant in ('', 'not a tag', 7):
        with pytest.raises(ValueError, match='catalog provenance'):
            ApplicationsService._validate_record(
                config, catalog_record(catalog={**provenance, 'variant': variant}), 'demo'
            )
    with pytest.raises(ValueError, match='catalog provenance'):
        ApplicationsService._validate_record(
            config, catalog_record(catalog={**provenance, 'flavour': 'latest'}), 'demo'
        )


def test_persisted_health_check_must_bind_to_a_declared_tcp_port():
    record = catalog_record()
    assert ApplicationsService._validate_record({'pool': 'tank'}, record, 'demo') is record

    invalid = catalog_record(healthcheck={
        **record['healthcheck'],
        'host_port': 19999,
    })
    with pytest.raises(ValueError, match='declared health check'):
        ApplicationsService._validate_record({'pool': 'tank'}, invalid, 'demo')


@pytest.mark.parametrize(
    ('name', 'value'),
    [
        ('org.freebsd.jail.allow.mount', 'true'),
        ('org.freebsd.jail.allow.mlock', 'false'),
        ('org.freebsd.jail.allow.sysvipc', 'true'),
        ('org.freebsd.jail.sysvmsg', 'inherit'),
    ],
)
def test_persisted_record_validation_rejects_unapproved_jail_annotations(name, value):
    with pytest.raises(ValueError, match='invalid jail annotation'):
        ApplicationsService._validate_record({'pool': 'tank'}, persisted_record(annotations=[{
            'name': name,
            'value': value,
        }]), 'demo')


@pytest.mark.asyncio
async def test_unconfigured_runtime_setup_is_inert():
    service, middleware = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': None})
    service._clear_runtime_state = Mock()

    assert await service.runtime_setup() is False
    service._clear_runtime_state.assert_called_once_with()
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_partial_core_dataset_creation_is_reported_for_rollback():
    service, middleware = service_with_middleware()
    created = []
    calls = 0

    async def call_middleware(name, *args):
        nonlocal calls
        if name == 'zfs.dataset.create':
            calls += 1
            if calls == 3:
                raise CallError('injected create failure')
        else:
            assert name == 'zfs.dataset.mount'

    middleware.call.side_effect = call_middleware

    with pytest.raises(CallError, match='injected create failure'):
        await service._create_application_datasets('tank', created)

    assert created == [
        'tank/applications',
        'tank/applications/storage',
        'tank/applications/config',
    ]
    mount_calls = [
        invocation for invocation in middleware.call.await_args_list
        if invocation.args[0] == 'zfs.dataset.mount'
    ]
    assert mount_calls == [
        call('zfs.dataset.mount', 'tank/applications'),
        call('zfs.dataset.mount', 'tank/applications/storage'),
    ]


@pytest.mark.asyncio
async def test_core_dataset_is_registered_for_rollback_before_mounting():
    service, middleware = service_with_middleware()
    created = []

    async def fail_mount(name, *args):
        if name == 'zfs.dataset.mount':
            raise CallError('injected mount failure')

    middleware.call.side_effect = fail_mount

    with pytest.raises(CallError, match='injected mount failure'):
        await service._create_application_datasets('tank', created)

    assert created == ['tank/applications']


@pytest.mark.asyncio
async def test_configure_removes_partial_dataset_tree_on_failure():
    service, middleware = service_with_middleware()
    service.config = AsyncMock(return_value={
        'id': 1,
        'pool': None,
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'pf_owned': False,
        'filter_local_original': None,
        'ipv4_forwarding_original': None,
        'bridge_pfil_member_original': None,
    })
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._ensure_pf_module = AsyncMock()
    service._capture_runtime_sysctls = AsyncMock(return_value={
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    })
    service._pf_enabled = AsyncMock(return_value=False)
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: {
        'tank/applications': 'applications',
        'tank/applications/storage': 'applications:storage',
    }[dataset])
    middleware.call.return_value = [{'id': 'owned'}]

    async def fail_after_partial_create(pool, created):
        created.extend([f'{pool}/applications', f'{pool}/applications/storage'])
        raise CallError('injected create failure')

    service._create_application_datasets = fail_after_partial_create

    with pytest.raises(CallError, match='injected create failure'):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': '10.88.0.0/16'})

    assert [
        invocation for invocation in middleware.call.await_args_list
        if invocation.args[0] == 'zfs.dataset.delete'
    ] == [
        call(
            'zfs.dataset.delete', 'tank/applications/storage',
            {'force': True, 'recursive': False},
        ),
        call(
            'zfs.dataset.delete', 'tank/applications',
            {'force': True, 'recursive': False},
        ),
    ]
    assert not any(
        call.args and call.args[0] == 'datastore.update'
        for call in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_configure_selects_an_existing_stopped_applications_store():
    service, middleware = service_with_middleware()
    old = {
        'id': 1,
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'restart_on_boot': True,
        'runtime_ready': True,
        'pf_owned': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    }
    new = {**old, 'pool': 'backup', 'subnet': '10.89.0.0/16'}
    service.config = AsyncMock(side_effect=[old, new])
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._read_records = Mock(return_value=([], []))
    service._running_managed = AsyncMock(side_effect=[[], []])
    service._clear_runtime_state = Mock()
    paths = application_paths('backup')
    snapshot = {
        paths['storage_conf']: render_storage_conf('backup'),
        paths['containers_conf']: render_containers_conf('backup', '10.89.0.0/16'),
    }
    service._snapshot_managed_configs = Mock(return_value=snapshot)
    service._write_managed_configs = Mock()
    service._runtime_setup_impl = AsyncMock(return_value=True)
    middleware.call.return_value = [{'id': 'backup/applications'}]

    with patch(
        'middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()
    ):
        result = await service.configure(
            Mock(), {'pool': 'backup', 'subnet': '10.89.0.0/16'}
        )

    assert result == new
    service._running_managed.assert_has_awaits([
        call(old, strict=True),
        call({**old, 'pool': 'backup', 'subnet': '10.89.0.0/16', 'runtime_ready': False},
             strict=True),
    ])
    service._read_records.assert_has_calls([
        call(old),
        call({**old, 'pool': 'backup', 'subnet': '10.89.0.0/16', 'runtime_ready': False}),
    ])
    service._snapshot_managed_configs.assert_called_once_with('backup')
    middleware.call.assert_any_await(
        'datastore.update', 'services.applications', 1,
        {'pool': 'backup', 'subnet': '10.89.0.0/16'}, {'prefix': 'app_'}
    )
    service._runtime_setup_impl.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_configure_requires_applications_to_be_stopped_before_network_change():
    service, middleware = service_with_middleware()
    old = {
        'id': 1,
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'runtime_ready': True,
    }
    service.config = AsyncMock(return_value=old)
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._running_managed = AsyncMock(return_value=['redis'])

    with pytest.raises(CallError, match='Stop all Applications.*redis'):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': '10.89.0.0/16'})

    service._running_managed.assert_awaited_once_with(old, strict=True)
    assert not any(
        invocation.args and invocation.args[0] == 'datastore.update'
        for invocation in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_configure_rolls_back_pointer_and_new_store_when_runtime_setup_fails():
    service, middleware = service_with_middleware()
    old = {
        'id': 1,
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'restart_on_boot': True,
        'runtime_ready': True,
        'pf_owned': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    }
    service.config = AsyncMock(return_value=old)
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._running_managed = AsyncMock(return_value=[])
    service._clear_runtime_state = Mock()
    service._write_managed_configs = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()
    service._dataset_owner = AsyncMock(return_value='applications')
    service._runtime_setup_impl = AsyncMock(side_effect=[
        CallError('injected runtime failure'),
        True,
    ])
    dataset_queries = 0

    async def call_middleware(name, *args):
        nonlocal dataset_queries
        if name == 'zfs.dataset.query':
            dataset_queries += 1
            return [] if dataset_queries == 1 else [{'id': 'backup/applications'}]

    middleware.call.side_effect = call_middleware

    async def create_target(pool, created):
        created.append(f'{pool}/applications')

    service._create_application_datasets = create_target

    with (
        patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()),
        pytest.raises(CallError, match='injected runtime failure'),
    ):
        await service.configure(Mock(), {'pool': 'backup', 'subnet': '10.89.0.0/16'})

    middleware.call.assert_any_await(
        'datastore.update', 'services.applications', 1,
        {'pool': 'tank', 'subnet': '10.88.0.0/16', 'restart_on_boot': True},
        {'prefix': 'app_'},
    )
    middleware.call.assert_any_await(
        'zfs.dataset.delete', 'backup/applications', {'force': True, 'recursive': False}
    )
    assert service._runtime_setup_impl.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('status', 'expected'),
    [('SINGLE', True), ('MASTER', True), ('BACKUP', False), ('UNKNOWN', False)],
)
async def test_active_controller_is_fail_closed(status, expected):
    service, middleware = service_with_middleware()
    middleware.call.return_value = status

    assert await service._active_controller() is expected
    middleware.call.assert_awaited_once_with('failover.status')


@pytest.mark.asyncio
async def test_pf_without_loaded_device_is_disabled_and_inert():
    service, _ = service_with_middleware()
    run_mock = AsyncMock()

    with (
        patch('middlewared.plugins.applications_freebsd.os.path.exists', return_value=False),
        patch('middlewared.plugins.applications_freebsd.run', run_mock),
    ):
        assert await service._pf_enabled() is False

    run_mock.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('source', 'expected'),
    [('local', 'applications:demo'), ('inherited from tank/applications', None)],
)
async def test_dataset_ownership_must_be_set_locally(source, expected):
    service, _ = service_with_middleware()
    query = SimpleNamespace(
        returncode=0,
        stdout=f'applications:demo\t{source}\n',
        stderr='',
    )

    with patch(
        'middlewared.plugins.applications_freebsd.run',
        AsyncMock(return_value=query),
    ):
        assert await service._dataset_owner('tank/applications/data/demo') == expected


@pytest.mark.asyncio
async def test_owned_tree_inspection_failure_blocks_data_removal():
    service, _ = service_with_middleware()
    query = SimpleNamespace(returncode=1, stdout='', stderr='cannot open dataset')

    with (
        patch(
            'middlewared.plugins.applications_freebsd.run',
            AsyncMock(return_value=query),
        ),
        pytest.raises(CallError, match='cannot open dataset'),
    ):
        await service._owned_tree('tank/applications/data/demo', 'applications:demo')


@pytest.mark.asyncio
async def test_stop_all_does_not_touch_records_or_podman_when_runtime_is_unready():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': False})
    service._read_records = Mock()

    await service.stop_all()

    service._read_records.assert_not_called()


@pytest.mark.asyncio
async def test_corrupt_records_make_managed_stop_fail_closed():
    service, _ = service_with_middleware()
    service._read_records = Mock(return_value=([], [{
        'name': 'damaged',
        'status': 'ERROR',
        'error': 'Invalid managed record',
    }]))

    assert await service._stop_managed({'pool': 'tank'}) == ['damaged']


@pytest.mark.asyncio
async def test_system_ready_replays_boot_intent_after_runtime_setup():
    middleware = Mock()
    middleware.call = AsyncMock()

    async def call_middleware(name, *args):
        if name == 'applications.runtime_setup':
            return True
        if name in {
            'alert.oneshot_delete',
            'applications.start_on_boot',
        }:
            return None
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware

    await _system_event(middleware, 'CHANGED', {'id': 'ready'})

    middleware.call.assert_any_await('applications.runtime_setup')
    middleware.call.assert_any_await('applications.start_on_boot')


@pytest.mark.asyncio
async def test_restart_intent_regenerates_rc_state_when_it_changes():
    service, middleware = service_with_middleware()
    config = {'id': 1, 'pool': 'tank', 'restart_on_boot': False}
    service._read_records = Mock(return_value=([{'restart_policy': 'always'}], []))

    await service._refresh_restart_on_boot(config)

    assert config['restart_on_boot'] is True
    middleware.call.assert_any_await(
        'datastore.update', 'services.applications', 1,
        {'restart_on_boot': True}, {'prefix': 'app_'}
    )
    middleware.call.assert_any_await('etc.generate', 'rc')


@pytest.mark.asyncio
async def test_runtime_teardown_is_fail_closed_when_a_workload_does_not_stop():
    service, middleware = service_with_middleware()
    config = {
        'pool': 'tank',
        'runtime_ready': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
        'pf_owned': True,
    }
    service.config = AsyncMock(return_value=config)
    service._stop_managed = AsyncMock(return_value=['demo'])
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()

    with (
        patch(
            'middlewared.plugins.applications_freebsd._generate_pf_checked',
            AsyncMock(),
        ) as generate_pf,
        pytest.raises(CallError, match='demo'),
    ):
        await service.runtime_teardown()

    service._clear_runtime_state.assert_called_once_with()
    service._restore_runtime_sysctls.assert_awaited_once_with(config)
    generate_pf.assert_awaited_once_with(middleware)
    service._disable_owned_pf.assert_awaited_once_with(config)


@pytest.mark.asyncio
async def test_runtime_sysctls_are_captured_applied_and_restored_as_one_lifecycle():
    service, _ = service_with_middleware()
    service._sysctl = AsyncMock(side_effect=['0', '1', '0'])
    service._set_sysctl = AsyncMock()

    originals = await service._capture_runtime_sysctls()
    assert originals == {
        'filter_local_original': 0,
        'ipv4_forwarding_original': 1,
        'bridge_pfil_member_original': 0,
    }

    await service._apply_runtime_sysctls()
    assert service._set_sysctl.await_args_list == [
        call('net.pf.filter_local', '1'),
        call('net.inet.ip.forwarding', '1'),
        call('net.link.bridge.pfil_member', '1'),
    ]

    service._set_sysctl.reset_mock()
    assert await service._restore_runtime_sysctls(originals) == []
    assert service._set_sysctl.await_args_list == [
        call('net.pf.filter_local', '0'),
        call('net.inet.ip.forwarding', '1'),
        call('net.link.bridge.pfil_member', '0'),
    ]


@pytest.mark.asyncio
async def test_checked_pf_generation_does_not_swallow_renderer_errors():
    middleware = Mock()

    async def run_in_thread(function, *args):
        return function(*args)

    middleware.run_in_thread = AsyncMock(side_effect=run_in_thread)

    with (
        patch.object(pf_renderer, 'render', Mock(side_effect=CallError('PF load failed'))),
        pytest.raises(CallError, match='PF load failed'),
    ):
        await _generate_pf_checked(middleware)


@pytest.mark.asyncio
async def test_query_does_not_touch_podman_until_runtime_is_ready():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': False})
    service._read_records = Mock(return_value=([{
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'environment': [{'name': 'TOKEN', 'value': 'secret-value'}],
    }], []))
    service._catalog_states = AsyncMock(return_value=[{
        'update_available': False,
        'revoked': False,
        'revocation_reason': None,
        'catalog_error': None,
    }])
    service._inspect_owned_container = AsyncMock()

    result = await ApplicationsService.query.wraps(service)

    assert result == [{
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'environment': [{'name': 'TOKEN', 'set': True}],
        'image_os': 'freebsd',
        'origin': None,
        'network': {'mode': 'managed'},
        # the internal development record: a record written before labels existed still reports the field.
        'labels': [],
        'runtime': {},  # the internal development record
        # the internal development record: likewise for the certificates it mounts.
        'certificates': [],
        'update_available': False,
        'revoked': False,
        'revocation_reason': None,
        'catalog_error': None,
        'status': 'UNAVAILABLE',
        'running': False,
        'restarts': 0,
        'exit_code': None,
        'health_declared': False,
        'health': 'UNDECLARED',
        'error': 'Applications runtime prerequisites are not ready on this controller.',
        'bridge_address': None,
    }]
    service._catalog_states.assert_awaited_once()
    service._inspect_owned_container.assert_not_awaited()


@pytest.mark.asyncio
async def test_undeclared_health_is_not_reported_as_healthy_or_probed():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value={'State': {'Running': True}})
    service._probe_http_health = AsyncMock()

    result = await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)

    assert result == {'State': {'Running': True}}
    service._probe_http_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_query_reports_declared_health_without_inventing_a_healthy_state():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    service._read_records = Mock(return_value=([catalog_record()], []))
    service._catalog_states = AsyncMock(return_value=[{
        'update_available': False,
        'revoked': False,
        'revocation_reason': None,
        'catalog_error': None,
    }])
    inspection = {'State': {'Status': 'running', 'Running': True}}
    service._inspect_owned_container = AsyncMock(
        return_value=(inspection, '1' * 64)
    )

    result = await ApplicationsService.query.wraps(service)

    assert result[0]['health_declared'] is True
    assert result[0]['health'] == 'UNKNOWN'
    assert result[0]['healthcheck']['path'] == '/health'


@pytest.mark.asyncio
async def test_declared_http_health_must_succeed_and_timeout_is_explicit():
    service, _ = service_with_middleware()
    healthcheck = catalog_record()['healthcheck']
    service._inspect_container = AsyncMock(return_value={'State': {'Running': True}})
    service._probe_http_health = AsyncMock(return_value=(True, 'HTTP status 200'))

    result = await service._wait_healthy(
        {'pool': 'tank'}, 'freecore-app-demo', 0, healthcheck
    )
    assert result == {'State': {'Running': True}}

    service._probe_http_health = AsyncMock(return_value=(False, 'HTTP status 503'))
    with pytest.raises(CallError, match='declared.*HTTP.*503'):
        await service._wait_healthy(
            {'pool': 'tank'}, 'freecore-app-demo', 0, healthcheck
        )


@pytest.mark.asyncio
async def test_http_health_probe_uses_loopback_without_proxy_or_redirects():
    response = MagicMock(status=204)
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=response)
    response_context.__aexit__ = AsyncMock(return_value=None)
    session = MagicMock()
    session.get.return_value = response_context
    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    session_context.__aexit__ = AsyncMock(return_value=None)

    with patch(
        'middlewared.plugins.applications_freebsd.aiohttp.ClientSession',
        return_value=session_context,
    ) as client_session:
        healthy, detail = await ApplicationsService._probe_http_health(
            catalog_record()['healthcheck'], 1,
        )

    assert healthy is True
    assert detail == 'HTTP status 204'
    assert client_session.call_args.kwargs['trust_env'] is False
    session.get.assert_called_once_with(
        'http://127.0.0.1:18080/health', allow_redirects=False
    )


@pytest.mark.asyncio
async def test_declared_health_rejects_podman_unhealthy_before_http_probe():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value={
        'State': {'Running': True, 'Health': {'Status': 'unhealthy'}},
    })
    service._probe_http_health = AsyncMock()

    with pytest.raises(CallError, match='reported an unhealthy state'):
        await service._wait_healthy(
            {'pool': 'tank'}, 'freecore-app-demo', 30, catalog_record()['healthcheck']
        )

    service._probe_http_health.assert_not_awaited()


@pytest.mark.asyncio
async def test_initial_install_persists_verified_immutable_container_id():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': False}
    data = install_data(image=f'ghcr.io/daemonless/demo@sha256:{"b" * 64}')
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock()
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()
    middleware.call.return_value = {'name': 'demo', 'status': 'RUNNING'}

    result = await service._install_impl(Mock(), data, replacement_provenance())

    assert result == {'name': 'demo', 'status': 'RUNNING'}
    written = service._write_record.call_args.args[1]
    # the internal development record: every install records a pinned bridge address.
    assert written['schema'] == 4
    assert written['network'] == {'mode': 'managed', 'bridge_address': '10.88.255.254'}
    assert written['image_os'] == 'freebsd'
    assert written['container_id'] == '2' * 64
    service._wait_healthy.assert_awaited_once_with(
        config, '2' * 64, 0, None, redactions=ANY,
    )


@pytest.mark.asyncio
async def test_install_records_the_pulled_images_own_version_and_variant():
    # the internal development record: the review read the index (quarterly 1.36.0_1); the
    # ``latest`` image that arrived says it is the upstream 1.37.3 build.
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': False}
    data = install_data(image='ghcr.io/daemonless/demo:latest')
    reviewed = {
        'id': 'daemonless:demo', 'version': '1.36.0_1', 'variant': 'latest', 'compose_sha256': 'e' * 64,
        'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:latest',
    }
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock()
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64, 'digest': 'sha256:' + 'b' * 64, 'os': 'freebsd',
        'labels': {'org.opencontainers.image.version': '1.37.3', 'io.daemonless.variant': 'latest'},
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()
    middleware.call.return_value = {'name': 'demo', 'status': 'RUNNING'}

    await service._install_impl(Mock(), data, reviewed)

    written = service._write_record.call_args.args[1]
    assert written['catalog'] == {**reviewed, 'version': '1.37.3'}
    assert written['digest'] == 'sha256:' + 'b' * 64


@pytest.mark.asyncio
async def test_initial_install_health_failure_removes_container_without_committing_record():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': False}
    healthcheck = catalog_record()['healthcheck']
    data = install_data(
        image=f'ghcr.io/daemonless/demo@sha256:{"b" * 64}',
        ports=[{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        healthcheck=healthcheck,
    )
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock()
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(side_effect=CallError('declared health timed out'))
    service._write_record = Mock()
    service._delete_record = Mock()
    service._remove_owned_container = AsyncMock()
    service._refresh_restart_on_boot = AsyncMock()

    with pytest.raises(CallError, match='declared health timed out'):
        await service._install_impl(Mock(), data, replacement_provenance())

    service._wait_healthy.assert_awaited_once_with(
        config, '2' * 64, 0, healthcheck, redactions=ANY
    )
    service._write_record.assert_not_called()
    service._remove_transaction_container.assert_awaited_once_with(
        config,
        {'name': 'demo', 'container_name': 'freecore-app-demo'},
        ANY,
        '2' * 64,
    )


@pytest.mark.asyncio
async def test_catalog_update_records_the_pulled_images_own_labels():
    # the internal development record: crpb's vaultwarden after the fix -- the tag-following
    # provenance the review bound is corrected by what the pull delivered.
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    replacement = catalog_replacement(image='ghcr.io/daemonless/demo:latest')
    provenance = {
        'id': 'daemonless:demo', 'version': '1.36.0_1', 'variant': 'latest', 'compose_sha256': '2' * 64,
        'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:latest',
    }
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    managed_podman_harness(service, current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64, 'digest': 'sha256:' + 'b' * 64, 'os': 'freebsd',
        'labels': {'org.opencontainers.image.version': '1.37.3', 'io.daemonless.variant': 'latest'},
    })
    service._wait_healthy = AsyncMock()
    service._write_record = Mock()
    middleware.call.return_value = {'name': 'demo', 'status': 'RUNNING'}

    with patch(
        'middlewared.plugins.applications_freebsd.temporary_environment_file',
        return_value=contextlib.nullcontext('/tmp/application-env'),
    ):
        await service.update_catalog(Mock(), current, replacement, provenance, 0)

    written = service._write_record.call_args.args[1]
    assert written['catalog'] == {**provenance, 'version': '1.37.3'}
    assert written['image'] == 'ghcr.io/daemonless/demo:latest'
    assert written['digest'] == 'sha256:' + 'b' * 64


@pytest.mark.asyncio
async def test_catalog_update_commits_only_after_health_and_preserves_persistent_data():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    replacement = catalog_replacement()
    provenance = replacement_provenance()
    job = Mock()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    podman_state = managed_podman_harness(service, current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock()
    service._write_record = Mock()
    middleware.call.return_value = {'name': 'demo', 'status': 'RUNNING'}

    with patch(
        'middlewared.plugins.applications_freebsd.temporary_environment_file',
        return_value=contextlib.nullcontext('/tmp/application-env'),
    ):
        result = await service.update_catalog(job, current, replacement, provenance, 0)

    assert result == {'name': 'demo', 'status': 'RUNNING'}
    written = service._write_record.call_args.args[1]
    # Legacy provenance passes through; a labelled image would override it (#463).
    assert written['catalog'] == provenance
    # the internal development record: an update pins a managed application that predates pinning.
    assert written['schema'] == 4
    assert written['network']['mode'] == 'managed'
    assert written['network']['bridge_address'].startswith('10.88.')
    assert written['image_os'] == 'freebsd'
    assert written['container_id'] == '2' * 64
    assert written['volumes'] == current['volumes']
    assert written['environment'] == current['environment']
    assert written['ports'] == current['ports']
    assert written['created_at'] == current['created_at']
    assert written['updated_at'] != current['updated_at']
    operations = [invocation.args[1] for invocation in service._podman.await_args_list]
    assert operations[:4] == ['pull', 'stop', 'rename', 'create']
    assert 'start' in operations
    rename = next(
        invocation for invocation in service._podman.await_args_list
        if invocation.args[1] == 'rename'
    )
    backup_name = rename.args[3]
    assert backup_name.startswith('freecore-app-demo-rollback-')
    service._podman.assert_any_await(config, 'rm', '--force', '1' * 64)
    service._wait_healthy.assert_awaited_once_with(
        config, '2' * 64, 0, replacement['healthcheck'], redactions=ANY
    )
    assert set(podman_state.containers) == {'2' * 64}


@pytest.mark.asyncio
async def test_failed_catalog_replacement_restores_prior_runnable_container_and_record():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    replacement = catalog_replacement()
    provenance = replacement_provenance()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    podman_state = managed_podman_harness(service, current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(side_effect=[
        CallError('replacement is unhealthy'),
        {'State': {'Running': True}},
    ])
    service._write_record = Mock()

    with (
        patch(
            'middlewared.plugins.applications_freebsd.temporary_environment_file',
            return_value=contextlib.nullcontext('/tmp/application-env'),
        ),
        pytest.raises(CallError, match='replacement is unhealthy'),
    ):
        await service.update_catalog(Mock(), current, replacement, provenance, 0)

    rename_calls = [
        invocation for invocation in service._podman.await_args_list
        if invocation.args[1] == 'rename'
    ]
    assert len(rename_calls) == 2
    backup_name = rename_calls[0].args[3]
    assert backup_name.startswith('freecore-app-demo-rollback-')
    assert rename_calls[0].args[2] == '1' * 64
    assert rename_calls[1].args[2:] == ('1' * 64, current['container_name'])
    assert [
        invocation.args[2] for invocation in service._podman.await_args_list
        if invocation.args[1] == 'start'
    ] == ['2' * 64, '1' * 64]
    service._podman.assert_any_await(config, 'rm', '--force', '2' * 64)
    service._write_record.assert_called_once_with(config, current)
    # the internal development record: both the replacement attempt and the restore of the
    # prior container name the values that must not survive into a retained excerpt,
    # so a secret cannot leak through whichever of the two fails.
    assert service._wait_healthy.await_args_list == [
        call(
            config, '2' * 64, 0, replacement['healthcheck'],
            redactions=[item['value'] for item in replacement['environment']],
        ),
        call(
            config, '1' * 64, 0, current['healthcheck'],
            redactions=[item['value'] for item in current['environment']],
        ),
    ]
    assert 'configured-secret' in [item['value'] for item in current['environment']]
    assert podman_state.containers['1' * 64]['name'] == current['container_name']
    assert podman_state.containers['1' * 64]['running'] is True


@pytest.mark.asyncio
async def test_catalog_update_restores_restart_intent_when_rc_refresh_fails():
    service, _ = service_with_middleware()
    config = {'id': 1, 'pool': 'tank', 'restart_on_boot': True, 'runtime_ready': True}
    current = catalog_record()
    replacement = catalog_replacement(restart_policy='no')
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    podman_state = managed_podman_harness(service, current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()
    service._refresh_restart_on_boot = AsyncMock(side_effect=[
        CallError('rc regeneration failed'),
        None,
    ])

    with (
        patch(
            'middlewared.plugins.applications_freebsd.temporary_environment_file',
            return_value=contextlib.nullcontext('/tmp/application-env'),
        ),
        pytest.raises(CallError, match='rc regeneration failed'),
    ):
        await service.update_catalog(
            Mock(), current, replacement, replacement_provenance(), 0,
        )

    assert service._write_record.call_count == 2
    assert service._write_record.call_args_list[0].args[0] == config
    assert service._write_record.call_args_list[0].args[1]['restart_policy'] == 'no'
    assert service._write_record.call_args_list[1] == call(config, current)
    assert service._refresh_restart_on_boot.await_args_list == [
        call(config),
        call(config, force=True),
    ]
    assert set(podman_state.containers) == {podman_state.old_id}
    assert podman_state.containers[podman_state.old_id]['name'] == current['container_name']


@pytest.mark.asyncio
async def test_update_rollback_preserves_foreign_current_name_occupant():
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    current = catalog_record()
    podman_state = managed_podman_harness(service, current)
    foreign_id = 'f' * 64
    podman_state.containers[podman_state.old_id].update({
        'name': f'{current["container_name"]}-rollback-existing',
        'running': False,
    })
    podman_state.containers[foreign_id] = {
        'name': current['container_name'],
        'labels': {MANAGED_LABEL: 'false', APPLICATION_LABEL: 'foreign'},
        'running': True,
    }
    service._write_record = Mock()
    service._wait_healthy = AsyncMock()

    errors = await service._rollback_catalog_replacement(
        config,
        current,
        podman_state.old_id,
        True,
        'b' * 32,
        None,
        True,
        0,
        False,
    )

    assert errors and 'restore prior container name' in errors[0]
    assert foreign_id in podman_state.containers
    assert podman_state.containers[foreign_id]['name'] == current['container_name']
    assert podman_state.old_id in podman_state.containers
    assert not any(
        invocation.args[1:4] == ('rm', '--force', foreign_id)
        for invocation in service._podman.await_args_list
    )
    service._write_record.assert_called_once_with(config, current)


@pytest.mark.asyncio
async def test_catalog_update_preserves_foreign_backup_name_collision():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    podman_state = managed_podman_harness(service, current)
    foreign_id = 'f' * 64
    backup_suffix = 'b' * 12
    podman_state.containers[foreign_id] = {
        'name': f'{current["container_name"]}-rollback-{backup_suffix}',
        'labels': {MANAGED_LABEL: 'false', APPLICATION_LABEL: 'foreign'},
        'running': True,
    }
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()

    with (
        patch('middlewared.plugins.applications_freebsd.uuid.uuid4', side_effect=[
            SimpleNamespace(hex='a' * 32),
            SimpleNamespace(hex='b' * 32),
        ]),
        pytest.raises(CallError, match='target container name is occupied'),
    ):
        await service.update_catalog(
            Mock(), current, catalog_replacement(), replacement_provenance(), 0,
        )

    assert foreign_id in podman_state.containers
    assert podman_state.containers[foreign_id]['name'].endswith(backup_suffix)
    assert podman_state.old_id in podman_state.containers
    assert podman_state.containers[podman_state.old_id]['name'] == current['container_name']
    assert podman_state.containers[podman_state.old_id]['running'] is True
    assert not any(
        invocation.args[1:4] == ('rm', '--force', foreign_id)
        for invocation in service._podman.await_args_list
    )


@pytest.mark.asyncio
async def test_podman_errors_redact_environment_values():
    service, _ = service_with_middleware()
    result = SimpleNamespace(
        returncode=1,
        stdout='',
        stderr='invalid argument TOKEN=secret-value',
    )

    with (
        patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=result)),
        pytest.raises(CallError) as error,
    ):
        await service._podman(
            {'pool': 'tank'},
            'create', '--env-file', '/tmp/application-env', '--', 'registry.example/demo:1',
            redactions=['secret-value'],
        )

    assert 'secret-value' not in str(error.value)
    assert 'TOKEN=********' in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize('annotation_name', sorted(NETWORK_OWNED_ANNOTATIONS))
async def test_managed_network_annotations_cannot_be_overridden(annotation_name):
    service, middleware = service_with_middleware()
    service._read_records = Mock(return_value=([], []))
    service._container_exists = AsyncMock(return_value=False)
    service._reserved_management_ports = AsyncMock(return_value=set())
    middleware.run_in_thread.return_value = True
    data = install_data(annotations=[{
        'name': annotation_name,
        'value': 'inherit',
    }])

    with pytest.raises(ValidationErrors) as error:
        await service._validate_install({'pool': 'tank'}, data)

    assert 'owned by the managed container network' in str(error.value)


@pytest.mark.asyncio
async def test_external_jail_dataset_is_rejected_on_any_pool():
    service, middleware = service_with_middleware()
    data = install_data(volumes=[{
        'name': 'data',
        'target': '/data',
        'dataset': 'otherpool/iocage/jails/example/data',
        'read_only': False,
    }])

    with pytest.raises(CallError, match='overlaps a managed jail'):
        await service._prepare_volumes({'pool': 'tank'}, data, [])

    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_external_dataset_mountpoint_must_be_unambiguous_and_below_mnt():
    service, middleware = service_with_middleware()
    middleware.call.return_value = [{
        'mountpoint': '/mnt/external:rw',
    }]
    data = install_data(volumes=[{
        'name': 'data',
        'target': '/data',
        'dataset': 'otherpool/external',
        'read_only': False,
    }])

    with pytest.raises(CallError, match='unsafe mountpoint'):
        await service._prepare_volumes({'pool': 'tank'}, data, [])


def test_defined_jail_networks_include_static_addresses_and_nat_prefix():
    networks = ApplicationsService._jail_address_networks({
        'ip4_addr': 'vnet0|192.0.2.42/24,lo1|198.51.100.8/32',
        'ip6_addr': 'vnet0|2001:db8::4/64',
        'nat': 1,
        'nat_prefix': '172.16',
    })

    assert {str(network) for network in networks} == {
        '192.0.2.0/24',
        '198.51.100.8/32',
        '2001:db8::/64',
        '172.16.0.0/16',
    }


@pytest.mark.asyncio
async def test_defined_jail_networks_include_iocage_and_bastille():
    service, middleware = service_with_middleware()

    async def call(name):
        if name == 'jail.get_activated_pool':
            return 'tank'
        if name == 'jail.query':
            return [{'ip4_addr': 'vnet0|192.0.2.10/24'}]
        if name == 'bastille.query':
            return [{'ip4_addr': 'vnet0|198.51.100.10/24'}]
        raise AssertionError(name)

    middleware.call.side_effect = call

    assert {str(network) for network in await service._defined_jail_networks()} == {
        '192.0.2.0/24',
        '198.51.100.0/24',
    }


@pytest.mark.asyncio
async def test_defined_jail_networks_skip_only_explicitly_unconfigured_iocage():
    service, middleware = service_with_middleware()

    async def call(name):
        if name == 'jail.get_activated_pool':
            return None
        if name == 'bastille.query':
            return [{'ip4_addr': 'vnet0|198.51.100.10/24'}]
        raise AssertionError(name)

    middleware.call.side_effect = call

    assert [str(network) for network in await service._defined_jail_networks()] == [
        '198.51.100.0/24',
    ]


@pytest.mark.asyncio
async def test_defined_jail_networks_fail_closed_when_configured_engine_cannot_be_read():
    service, middleware = service_with_middleware()

    async def call(name):
        if name == 'jail.get_activated_pool':
            return 'tank'
        if name == 'jail.query':
            return []
        if name == 'bastille.query':
            raise CallError('Bastille jail configuration cannot be inspected')
        raise AssertionError(name)

    middleware.call.side_effect = call

    with pytest.raises(CallError, match='cannot be inspected'):
        await service._defined_jail_networks()


def test_port_availability_checks_live_listeners():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('0.0.0.0', 0))
        listener.listen()
        port = listener.getsockname()[1]

        assert ApplicationsService._port_available(port, 'tcp') is False


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['create', 'start', 'restart'])
async def test_podman_network_mutation_reserves_bridge0_before_exec(operation):
    service, middleware = service_with_middleware()
    events = []

    async def call_middleware(name, *args):
        events.append((name, *args))
        return 'bridge0'

    async def run_podman(command, **kwargs):
        events.append(('podman', command[1]))
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    middleware.call.side_effect = call_middleware
    with patch(
        'middlewared.plugins.applications_freebsd.run', AsyncMock(side_effect=run_podman)
    ):
        await service._podman({'pool': 'tank'}, operation, 'target')

    assert events == [
        ('interface.reserve_jail_bridge', 'bridge0'),
        ('podman', operation),
    ]


@pytest.mark.asyncio
async def test_podman_read_only_command_does_not_reserve_a_bridge():
    service, middleware = service_with_middleware()

    with patch(
        'middlewared.plugins.applications_freebsd.run',
        AsyncMock(return_value=SimpleNamespace(returncode=0, stdout='', stderr='')),
    ):
        await service._podman({'pool': 'tank'}, 'image', 'exists', 'example:latest')

    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_podman_start_settles_bridge_reservation_without_exec():
    service, middleware = service_with_middleware()
    reservation_started = asyncio.Event()
    release_reservation = asyncio.Event()
    reservation_finished = asyncio.Event()

    async def call_middleware(name, *args):
        assert (name, args) == ('interface.reserve_jail_bridge', ('bridge0',))
        reservation_started.set()
        await release_reservation.wait()
        reservation_finished.set()
        return 'bridge0'

    middleware.call.side_effect = call_middleware
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock()) as run_mock:
        start = asyncio.create_task(
            service._podman({'pool': 'tank'}, 'start', 'container')
        )
        await reservation_started.wait()
        start.cancel()
        await asyncio.sleep(0)
        assert not start.done()
        release_reservation.set()
        with pytest.raises(asyncio.CancelledError):
            await start

    assert reservation_finished.is_set()
    run_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_initial_configure_reserves_bridge_before_runtime_becomes_ready():
    service, middleware = service_with_middleware()
    events = []
    old = {
        'id': 1,
        'pool': None,
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'pf_owned': False,
        'filter_local_original': None,
        'ipv4_forwarding_original': None,
        'bridge_pfil_member_original': None,
    }
    configured = {**old, 'pool': 'tank', 'runtime_ready': True}
    service.config = AsyncMock(side_effect=[old, configured])
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._ensure_pf_module = AsyncMock()
    service._capture_runtime_sysctls = AsyncMock(return_value={
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    })
    service._pf_enabled = AsyncMock(return_value=False)
    service._create_application_datasets = AsyncMock()
    service._write_managed_configs = Mock()
    service._apply_runtime_sysctls = AsyncMock(
        side_effect=lambda: events.append('sysctls')
    )
    service._mark_pf_active = Mock()
    service._mark_runtime_ready = Mock(side_effect=lambda: events.append('ready'))

    async def call_middleware(name, *args):
        if name == 'interface.reserve_jail_bridge':
            events.append('reserve')
            return 'bridge0'
        if name in {'datastore.update', 'etc.generate'}:
            return None
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware
    with (
        patch('middlewared.plugins.applications_freebsd.os.makedirs'),
        patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()),
    ):
        assert await service.configure(
            Mock(), {'pool': 'tank', 'subnet': '10.88.0.0/16'}
        ) == configured

    assert events == ['reserve', 'sysctls', 'ready']


@pytest.mark.asyncio
async def test_runtime_setup_reserves_bridge_before_writing_podman_network_config():
    service, middleware = service_with_middleware()
    events = []
    config = {
        'id': 1,
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'runtime_ready': False,
    }
    owners = dict(service._application_dataset_specs('tank'))
    service.config = AsyncMock(return_value=config)
    service._active_controller = AsyncMock(return_value=True)
    service._clear_runtime_state = Mock()
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: owners[dataset])
    service._write_managed_configs = Mock(side_effect=lambda *args: events.append('write'))
    service._ensure_pf_module = AsyncMock()
    service._apply_runtime_sysctls = AsyncMock()
    service._refresh_restart_on_boot = AsyncMock()
    service._mark_pf_active = Mock()
    service._mark_runtime_ready = Mock()

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            return [{'id': args[0][0][2]}]
        if name == 'interface.reserve_jail_bridge':
            events.append('reserve')
            return 'bridge0'
        if name == 'etc.generate':
            return None
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware
    with (
        patch('middlewared.plugins.applications_freebsd.os.makedirs'),
        patch('middlewared.plugins.applications_freebsd.os.access', return_value=True),
        patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()),
    ):
        assert await service.runtime_setup() is True

    assert events == ['reserve', 'write']


@pytest.mark.asyncio
async def test_configure_cancellation_waits_for_owned_rollback():
    service, middleware = service_with_middleware()
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    rollback_finished = asyncio.Event()
    old = {
        'id': 1,
        'pool': None,
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'pf_owned': False,
        'filter_local_original': None,
        'ipv4_forwarding_original': None,
        'bridge_pfil_member_original': None,
    }
    service.config = AsyncMock(return_value=old)
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._ensure_pf_module = AsyncMock()
    service._capture_runtime_sysctls = AsyncMock(return_value={
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    })
    service._pf_enabled = AsyncMock(return_value=False)
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()
    service._dataset_owner = AsyncMock(return_value='applications')

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.create':
            operation_started.set()
            await release_operation.wait()
        if name == 'zfs.dataset.query':
            return [{'id': 'tank/applications'}]
        if name == 'zfs.dataset.delete':
            rollback_finished.set()

    middleware.call.side_effect = call_middleware
    with patch(
        'middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()
    ):
        configure = asyncio.create_task(service.configure(
            Mock(), {'pool': 'tank', 'subnet': '10.88.0.0/16'}
        ))
        await operation_started.wait()
        configure.cancel()
        await asyncio.sleep(0)
        assert not configure.done()
        release_operation.set()
        with pytest.raises(asyncio.CancelledError):
            await configure

    assert rollback_finished.is_set()
    middleware.call.assert_any_await(
        'zfs.dataset.delete', 'tank/applications', {'force': True, 'recursive': False}
    )


@pytest.mark.asyncio
async def test_runtime_setup_cancellation_settles_runtime_cleanup():
    service, middleware = service_with_middleware()
    operation_started = asyncio.Event()
    config = {
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'runtime_ready': False,
        'pf_owned': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    }
    service.config = AsyncMock(return_value=config)
    service._active_controller = AsyncMock(return_value=True)
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            operation_started.set()
            await asyncio.Event().wait()

    middleware.call.side_effect = call_middleware
    with patch(
        'middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()
    ):
        setup = asyncio.create_task(service.runtime_setup())
        await operation_started.wait()
        setup.cancel()
        with pytest.raises(asyncio.CancelledError):
            await setup

    service._restore_runtime_sysctls.assert_awaited_once_with(config)
    service._disable_owned_pf.assert_awaited_once_with(config)


@pytest.mark.asyncio
async def test_inactive_runtime_cleanup_reports_workloads_that_did_not_stop():
    service, middleware = service_with_middleware()
    config = {
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'runtime_ready': True,
        'pf_owned': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    }
    service.config = AsyncMock(return_value=config)
    service._active_controller = AsyncMock(return_value=False)
    service._clear_runtime_state = Mock()
    service._stop_managed = AsyncMock(return_value=['demo'])
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()

    with (
        patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()),
        pytest.raises(CallError, match='workloads not stopped: demo'),
    ):
        await service.runtime_setup()

    middleware.call.assert_awaited_once_with('etc.generate', 'rc')
    service._disable_owned_pf.assert_awaited_once_with(config)


@pytest.mark.asyncio
async def test_install_cancellation_removes_every_attempted_owned_artifact():
    service, middleware = service_with_middleware()
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    rollback_finished = asyncio.Event()
    config = {'pool': 'tank', 'restart_on_boot': False}
    image = f'ghcr.io/daemonless/demo@sha256:{"b" * 64}'
    data = install_data(image=image)
    created_dataset = 'tank/applications/data/demo'
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)

    async def prepare_volumes(config, data, created):
        created.append(created_dataset)
        return []

    async def podman(config, *arguments, **kwargs):
        if arguments[0] == 'create':
            operation_started.set()
            await release_operation.wait()

    async def refresh(config, force=False):
        assert force is True
        rollback_finished.set()

    service._prepare_volumes = prepare_volumes
    service._podman = AsyncMock(side_effect=podman)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._remove_transaction_container = AsyncMock()
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock(side_effect=refresh)
    service._dataset_owner = AsyncMock(return_value='applications:demo')

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            return [{'id': created_dataset}]

    middleware.call.side_effect = call_middleware

    with patch(
        'middlewared.plugins.applications_freebsd.temporary_environment_file',
        return_value=contextlib.nullcontext('/tmp/application-env'),
    ):
        install = asyncio.create_task(
            service._install_impl(Mock(), data, replacement_provenance())
        )
        await operation_started.wait()
        install.cancel()
        await asyncio.sleep(0)
        assert not install.done()
        install.cancel()
        await asyncio.sleep(0)
        assert not install.done()
        release_operation.set()
        with pytest.raises(asyncio.CancelledError):
            await install

    assert rollback_finished.is_set()
    service._remove_transaction_container.assert_awaited_once_with(
        config,
        {'name': 'demo', 'container_name': 'freecore-app-demo'},
        ANY,
        None,
    )
    service._delete_record.assert_called_once_with(config, 'demo')
    middleware.call.assert_any_await(
        'zfs.dataset.delete', created_dataset, {'force': True, 'recursive': False}
    )
    assert any(
        invocation.args[1:3] == ('image', 'rm')
        for invocation in service._podman.await_args_list
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'inspection',
    [
        {
            'Id': 'a' * 64,
            'Config': {'Labels': {
                MANAGED_LABEL: 'false',
                APPLICATION_LABEL: 'demo',
                TRANSACTION_LABEL: 'b' * 32,
            }},
        },
        managed_inspection(
            container_id='a' * 64, transaction_id='c' * 32,
        ),
        managed_inspection(
            container_id='a' * 64, transaction_id='b' * 32,
        ),
        managed_inspection(
            container_id='not-an-immutable-container-id', transaction_id='b' * 32,
        ),
    ],
)
async def test_owned_container_removal_refuses_foreign_identity(inspection):
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    record = persisted_record()
    service._container_exists = AsyncMock(return_value=True)
    service._inspect_container = AsyncMock(return_value=inspection)
    service._podman = AsyncMock()
    service._inspect_owned_container = ApplicationsService._inspect_owned_container.__get__(
        service, ApplicationsService
    )
    service._remove_owned_container = ApplicationsService._remove_owned_container.__get__(
        service, ApplicationsService
    )

    with pytest.raises(CallError, match='ownership labels do not match'):
        await service._remove_owned_container(
            config, record, transaction_id='b' * 32,
        )

    service._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_owned_container_removal_targets_verified_immutable_id():
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    container_id = 'a' * 64
    record = persisted_record(container_id=container_id)
    transaction_id = 'b' * 32
    service._container_exists = AsyncMock(return_value=True)
    service._inspect_container = AsyncMock(return_value=managed_inspection(
        record, container_id=container_id, transaction_id=transaction_id,
    ))
    service._podman = AsyncMock()
    service._inspect_owned_container = ApplicationsService._inspect_owned_container.__get__(
        service, ApplicationsService
    )
    service._remove_owned_container = ApplicationsService._remove_owned_container.__get__(
        service, ApplicationsService
    )

    await service._remove_owned_container(
        config, record, transaction_id=transaction_id,
    )

    service._container_exists.assert_awaited_once_with(config, container_id)
    service._inspect_container.assert_awaited_once_with(config, container_id)
    service._podman.assert_awaited_once_with(config, 'rm', '--force', container_id)


@pytest.mark.asyncio
async def test_transaction_rollback_finds_renamed_container_without_touching_foreign_name():
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    record = persisted_record()
    transaction_id = 'b' * 32
    podman_state = managed_podman_harness(service, record)
    foreign_id = 'f' * 64
    podman_state.containers[podman_state.old_id].update({
        'name': 'renamed-transaction-container',
        'labels': {
            MANAGED_LABEL: 'true',
            APPLICATION_LABEL: record['name'],
            TRANSACTION_LABEL: transaction_id,
        },
    })
    podman_state.containers[foreign_id] = {
        'name': record['container_name'],
        'labels': {MANAGED_LABEL: 'false', APPLICATION_LABEL: 'foreign'},
        'running': True,
    }

    await ApplicationsService._remove_transaction_container(
        service, config, record, transaction_id,
    )

    assert podman_state.old_id not in podman_state.containers
    assert foreign_id in podman_state.containers
    assert podman_state.containers[foreign_id]['name'] == record['container_name']
    service._podman.assert_any_await(
        config, 'rm', '--force', podman_state.old_id,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('method_name', 'podman_operation'),
    [('start', 'start'), ('stop', 'stop'), ('restart', 'restart')],
)
async def test_lifecycle_action_targets_only_the_managed_container(
    method_name, podman_operation,
):
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=persisted_record())
    service._podman = AsyncMock()

    assert await getattr(service, method_name)(Mock(), 'demo') is True

    service._podman.assert_awaited_once_with(
        config, podman_operation, '1' * 64
    )


@pytest.mark.asyncio
async def test_logs_are_read_only_and_bounded_to_the_managed_container():
    service, _ = service_with_middleware()
    config = {'pool': 'tank'}
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=persisted_record())
    service._podman = AsyncMock(return_value=SimpleNamespace(stdout='line one\n'))

    assert await service.logs('demo', 50) == 'line one\n'
    service._podman.assert_awaited_once_with(
        config, 'logs', '--tail', '50', '1' * 64
    )


@pytest.mark.asyncio
async def test_remove_without_data_does_not_query_or_delete_external_storage():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)
    service._remove_owned_container = AsyncMock()
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()

    assert await service.remove(Mock(), 'demo', {'remove_data': False}) is True

    service._remove_owned_container.assert_awaited_once_with(config, record)
    service._delete_record.assert_called_once_with(config, 'demo')
    service._refresh_restart_on_boot.assert_awaited_once_with(config)
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_owned_data_removal_failure_retains_record_for_safe_retry():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    app_dataset = 'tank/applications/data/demo'
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)
    service._owned_tree = AsyncMock(return_value=[app_dataset])
    service._dataset_owner = AsyncMock(return_value='applications:demo')
    service._remove_owned_container = AsyncMock()
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            return [{'id': app_dataset}]
        if name == 'zfs.dataset.delete':
            raise CallError('injected dataset removal failure')
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware
    with pytest.raises(CallError, match='injected dataset removal failure'):
        await service.remove(Mock(), 'demo', {'remove_data': True})

    assert service._owned_tree.await_args_list == [
        call(app_dataset, 'applications:demo'),
        call(app_dataset, 'applications:demo'),
    ]
    service._delete_record.assert_not_called()
    service._refresh_restart_on_boot.assert_not_awaited()
    middleware.call.assert_any_await(
        'zfs.dataset.delete', app_dataset, {'force': True, 'recursive': False}
    )
    assert not any(
        invocation.args[0] == 'zfs.dataset.delete' and invocation.args[2].get('recursive')
        for invocation in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_remove_cancellation_waits_for_destructive_phase_to_settle():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)

    async def remove_container(*args):
        operation_started.set()
        await release_operation.wait()

    service._remove_owned_container = AsyncMock(side_effect=remove_container)
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()

    removal = asyncio.create_task(
        service.remove(Mock(), 'demo', {'remove_data': False})
    )
    await operation_started.wait()
    removal.cancel()
    await asyncio.sleep(0)
    assert not removal.done()
    removal.cancel()
    await asyncio.sleep(0)
    assert not removal.done()
    release_operation.set()
    with pytest.raises(asyncio.CancelledError):
        await removal

    service._delete_record.assert_called_once_with(config, 'demo')
    service._refresh_restart_on_boot.assert_awaited_once_with(config)


@pytest.mark.asyncio
async def test_update_cancellation_waits_for_prior_container_and_record_restore():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    replacement = catalog_replacement()
    provenance = replacement_provenance()
    health_started = asyncio.Event()
    health_calls = 0
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    podman_state = managed_podman_harness(service, current)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._write_record = Mock()

    # the internal development record: the callers now name the values that must not appear in
    # a retained log excerpt, so the double has to tolerate keywords.
    async def wait_healthy(*args, **kwargs):
        nonlocal health_calls
        health_calls += 1
        if health_calls == 1:
            health_started.set()
            await asyncio.Event().wait()
        return {'State': {'Running': True}}

    service._wait_healthy = AsyncMock(side_effect=wait_healthy)
    with patch(
        'middlewared.plugins.applications_freebsd.temporary_environment_file',
        return_value=contextlib.nullcontext('/tmp/application-env'),
    ):
        update = asyncio.create_task(
            service.update_catalog(Mock(), current, replacement, provenance, 0)
        )
        await health_started.wait()
        update.cancel()
        with pytest.raises(asyncio.CancelledError):
            await update

    service._write_record.assert_called_once_with(config, current)
    rename_calls = [
        invocation for invocation in service._podman.await_args_list
        if invocation.args[1] == 'rename'
    ]
    assert len(rename_calls) == 2
    assert health_calls == 2
    assert set(podman_state.containers) == {'1' * 64}
    assert podman_state.containers['1' * 64]['name'] == current['container_name']


@pytest.mark.asyncio
async def test_configure_refuses_to_delete_foreign_dataset_from_create_race():
    service, middleware = service_with_middleware()
    old = {
        'id': 1,
        'pool': None,
        'subnet': '10.88.0.0/16',
        'restart_on_boot': False,
        'pf_owned': False,
        'filter_local_original': None,
        'ipv4_forwarding_original': None,
        'bridge_pfil_member_original': None,
    }
    service.config = AsyncMock(return_value=old)
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._ensure_pf_module = AsyncMock()
    service._capture_runtime_sysctls = AsyncMock(return_value={
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    })
    service._pf_enabled = AsyncMock(return_value=False)
    service._clear_runtime_state = Mock()
    service._restore_runtime_sysctls = AsyncMock(return_value=[])
    service._disable_owned_pf = AsyncMock()
    service._dataset_owner = AsyncMock(return_value='external:owner')

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.create':
            raise CallError('dataset appeared during create')
        if name == 'zfs.dataset.query':
            return [{'id': 'tank/applications'}]

    middleware.call.side_effect = call_middleware
    with (
        patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()),
        pytest.raises(CallError, match='rollback was incomplete.*refused to remove'),
    ):
        await service.configure(Mock(), {'pool': 'tank', 'subnet': '10.88.0.0/16'})

    assert not any(
        invocation.args[0] == 'zfs.dataset.delete'
        for invocation in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_reconfigure_cancellation_restores_pointer_and_managed_configs():
    service, middleware = service_with_middleware()
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    rollback_finished = asyncio.Event()
    old = {
        'id': 1,
        'pool': 'tank',
        'subnet': '10.88.0.0/16',
        'restart_on_boot': True,
        'runtime_ready': True,
        'pf_owned': True,
        'filter_local_original': 0,
        'ipv4_forwarding_original': 0,
        'bridge_pfil_member_original': 0,
    }
    service.config = AsyncMock(return_value=old)
    service._validate_pool_and_subnet = AsyncMock(return_value=False)
    service._read_records = Mock(return_value=([], []))
    service._running_managed = AsyncMock(side_effect=[[], []])
    service._snapshot_managed_configs = Mock(return_value={'managed': 'snapshot'})
    service._restore_managed_configs = Mock()
    service._write_managed_configs = Mock()
    service._clear_runtime_state = Mock()
    service._runtime_setup_impl = AsyncMock(return_value=True)

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            return [{'id': 'backup/applications'}]
        if name == 'datastore.update':
            update = args[2]
            if update['pool'] == 'backup':
                operation_started.set()
                await release_operation.wait()
            rollback_finished.set()

    middleware.call.side_effect = call_middleware
    with patch(
        'middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()
    ):
        reconfigure = asyncio.create_task(service.configure(
            Mock(), {'pool': 'backup', 'subnet': '10.89.0.0/16'}
        ))
        await operation_started.wait()
        reconfigure.cancel()
        await asyncio.sleep(0)
        assert not reconfigure.done()
        release_operation.set()
        with pytest.raises(asyncio.CancelledError):
            await reconfigure

    assert rollback_finished.is_set()
    middleware.call.assert_any_await(
        'datastore.update', 'services.applications', 1,
        {'pool': 'tank', 'subnet': '10.88.0.0/16', 'restart_on_boot': True},
        {'prefix': 'app_'},
    )
    service._restore_managed_configs.assert_called_once_with({'managed': 'snapshot'})
    service._runtime_setup_impl.assert_awaited_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize('boundary', ['stop', 'rename', 'create'])
async def test_update_cancellation_reconciles_interrupted_podman_response(boundary):
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'runtime_ready': True}
    current = catalog_record()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=current)
    podman_state = managed_podman_harness(service, current, boundary)
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()

    with patch(
        'middlewared.plugins.applications_freebsd.temporary_environment_file',
        return_value=contextlib.nullcontext('/tmp/application-env'),
    ):
        update = asyncio.create_task(service.update_catalog(
            Mock(), current, catalog_replacement(), replacement_provenance(), 0
        ))
        await podman_state.operation_started.wait()
        update.cancel()
        await asyncio.sleep(0)
        assert not update.done()
        podman_state.release_operation.set()
        with pytest.raises(asyncio.CancelledError):
            await update

    assert set(podman_state.containers) == {podman_state.old_id}
    restored = podman_state.containers[podman_state.old_id]
    assert restored['name'] == current['container_name']
    assert restored['running'] is True
    service._write_record.assert_called_once_with(config, current)
    service._wait_healthy.assert_awaited_once_with(
        config, podman_state.old_id, 0, current['healthcheck'], redactions=ANY
    )


@pytest.mark.asyncio
async def test_remove_revalidates_owned_tree_immediately_before_destroy():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    app_dataset = 'tank/applications/data/demo'
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)
    service._owned_tree = AsyncMock(side_effect=[
        [app_dataset],
        CallError('dataset ownership changed'),
    ])
    service._remove_owned_container = AsyncMock()
    service._delete_record = Mock()
    middleware.call.return_value = [{'id': app_dataset}]

    with pytest.raises(CallError, match='dataset ownership changed'):
        await service.remove(Mock(), 'demo', {'remove_data': True})

    assert service._owned_tree.await_count == 2
    service._delete_record.assert_not_called()
    assert not any(
        invocation.args[0] == 'zfs.dataset.delete'
        for invocation in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_remove_restores_record_when_restart_intent_refresh_fails():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)
    service._remove_owned_container = AsyncMock()
    service._delete_record = Mock()
    service._write_record = Mock()
    service._refresh_restart_on_boot = AsyncMock(side_effect=[
        CallError('rc regeneration failed'),
        None,
    ])

    with pytest.raises(CallError, match='rc regeneration failed'):
        await service.remove(Mock(), 'demo', {'remove_data': False})

    service._delete_record.assert_called_once_with(config, 'demo')
    service._write_record.assert_called_once_with(config, record)
    assert service._refresh_restart_on_boot.await_count == 2


@pytest.mark.asyncio
async def test_remove_force_reconciles_committed_restart_intent_after_lost_response():
    service, middleware = service_with_middleware()
    config = {'id': 1, 'pool': 'tank', 'restart_on_boot': True}
    record = catalog_record()
    record_present = True
    persisted_restart_on_boot = True
    update_calls = 0
    service._require_config = AsyncMock(return_value=config)
    service._get_record = Mock(return_value=record)
    service._remove_owned_container = AsyncMock()

    def read_records(config):
        return ([record], []) if record_present else ([], [])

    def delete_record(config, name):
        nonlocal record_present
        record_present = False

    def write_record(config, restored):
        nonlocal record_present
        assert restored == record
        record_present = True

    async def call_middleware(name, *args):
        nonlocal persisted_restart_on_boot, update_calls
        if name == 'datastore.update':
            update_calls += 1
            persisted_restart_on_boot = args[2]['restart_on_boot']
            if update_calls == 1:
                raise CallError('datastore response was lost after commit')
            return
        if name == 'etc.generate':
            return
        raise AssertionError((name, args))

    service._read_records = Mock(side_effect=read_records)
    service._delete_record = Mock(side_effect=delete_record)
    service._write_record = Mock(side_effect=write_record)
    middleware.call.side_effect = call_middleware

    with pytest.raises(CallError, match='response was lost after commit'):
        await service.remove(Mock(), 'demo', {'remove_data': False})

    assert record_present is True
    assert persisted_restart_on_boot is True
    assert config['restart_on_boot'] is True
    assert update_calls == 2
    service._delete_record.assert_called_once_with(config, 'demo')
    service._write_record.assert_called_once_with(config, record)
    middleware.call.assert_any_await('etc.generate', 'rc')


@pytest.mark.asyncio
async def test_install_reports_incomplete_rollback_instead_of_hiding_it():
    service, _ = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': False}
    data = install_data(image=f'ghcr.io/daemonless/demo@sha256:{"b" * 64}')
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=True)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock()
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64,
        'digest': 'sha256:' + 'b' * 64,
    })
    service._wait_healthy = AsyncMock(side_effect=CallError('health failed'))
    service._remove_transaction_container = AsyncMock(
        side_effect=CallError('remove failed')
    )
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()

    with (
        patch(
            'middlewared.plugins.applications_freebsd.temporary_environment_file',
            return_value=contextlib.nullcontext('/tmp/application-env'),
        ),
        pytest.raises(CallError, match='rollback was incomplete.*remove attempted container'),
    ):
        await service._install_impl(Mock(), data, replacement_provenance())


@pytest.mark.asyncio
@pytest.mark.parametrize('method_name', ['start', 'stop', 'restart'])
async def test_lifecycle_action_propagates_podman_failure(method_name):
    service, _ = service_with_middleware()
    service._require_config = AsyncMock(return_value={'pool': 'tank'})
    service._get_record = Mock(return_value=persisted_record())
    service._podman = AsyncMock(side_effect=CallError('podman action failed'))

    with pytest.raises(CallError, match='podman action failed'):
        await getattr(service, method_name)(Mock(), 'demo')


@pytest.mark.asyncio
async def test_lifecycle_action_cancellation_waits_for_podman_to_settle():
    service, _ = service_with_middleware()
    operation_started = asyncio.Event()
    release_operation = asyncio.Event()
    service._require_config = AsyncMock(return_value={'pool': 'tank'})
    service._get_record = Mock(return_value=persisted_record())

    async def podman(*args, **kwargs):
        operation_started.set()
        await release_operation.wait()

    service._podman = AsyncMock(side_effect=podman)
    start = asyncio.create_task(service.start(Mock(), 'demo'))
    await operation_started.wait()
    start.cancel()
    await asyncio.sleep(0)
    assert not start.done()
    start.cancel()
    release_operation.set()

    assert await start is True


@pytest.mark.asyncio
async def test_logs_propagate_podman_failure():
    service, _ = service_with_middleware()
    service._require_config = AsyncMock(return_value={'pool': 'tank'})
    service._get_record = Mock(return_value=persisted_record())
    service._podman = AsyncMock(side_effect=CallError('log read failed'))

    with pytest.raises(CallError, match='log read failed'):
        await service.logs('demo', 50)


# --- the internal development record: keep the traceback that rollback is about to destroy ----
#
# The record is committed only after _wait_healthy returns and rollback removes the
# transaction container, so applications.logs can reach neither. If the failure does not
# carry the output, nothing does.


def _stopped(exit_code=1, error=''):
    return {'State': {'Running': False, 'ExitCode': exit_code, 'Error': error}}


@pytest.mark.asyncio
async def test_a_startup_failure_carries_the_output_that_explains_it():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value=_stopped())
    service._podman = AsyncMock(return_value=Mock(
        stdout='sqlite3.OperationalError: unable to open database file\n', stderr='',
    ))

    with pytest.raises(CallError) as error:
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)

    message = error.value.errmsg
    assert 'stopped during startup' in message
    # State.Error is empty for an ordinary process exit, which is the common case and
    # is why this used to read "unknown error".
    assert 'exit status 1' in message
    assert 'unable to open database file' in message
    assert service._podman.await_args[0][1] == 'logs'


@pytest.mark.asyncio
async def test_a_declared_sensitive_value_never_reaches_the_retained_excerpt():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value=_stopped())
    service._podman = AsyncMock(return_value=Mock(
        stdout='connecting with password hunter2 failed\n', stderr='',
    ))

    with pytest.raises(CallError) as error:
        await service._wait_healthy(
            {'pool': 'tank'}, 'freecore-app-demo', 0, None, redactions=['hunter2'],
        )

    assert 'hunter2' not in error.value.errmsg
    assert '********' in error.value.errmsg


@pytest.mark.asyncio
async def test_failing_to_collect_the_output_does_not_replace_the_failure():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value=_stopped(exit_code=137))
    service._podman = AsyncMock(side_effect=OSError('podman is gone'))

    with pytest.raises(CallError) as error:
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)

    message = error.value.errmsg
    assert 'stopped during startup' in message
    assert 'exit status 137' in message
    assert 'podman is gone' not in message


@pytest.mark.asyncio
async def test_the_retained_excerpt_is_bounded():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value=_stopped())
    service._podman = AsyncMock(return_value=Mock(stdout='x' * 100_000, stderr=''))

    with pytest.raises(CallError) as error:
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)

    # It reaches a job error and the operator's browser; a traceback, not a log file.
    assert len(error.value.errmsg) < 6000
    assert service._podman.await_args[0][3] == '40'


@pytest.mark.asyncio
async def test_a_container_that_reports_its_own_error_keeps_saying_so():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(
        return_value=_stopped(exit_code=0, error='OCI runtime refused to start')
    )
    service._podman = AsyncMock(return_value=Mock(stdout='', stderr=''))

    with pytest.raises(CallError, match='OCI runtime refused to start'):
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)


# --- the internal development record: an owned volume must be usable by the app that owns it --
#
# A new dataset mounts root:wheel 0755. We pass no --user to podman, so a container runs
# as whatever its image declares -- and is then handed its own volume as a directory it
# cannot write to. Images that chown their own volume hide this; the ones that do not
# fail with an error that looks like theirs.


@pytest.mark.parametrize('environment,expected', [
    ([{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}], (1000, 1000)),
    ([{'name': 'PUID', 'value': '0'}, {'name': 'PGID', 'value': '0'}], (0, 0)),
    # A convention, not a contract: say nothing and nothing changes.
    ([], None),
    ([{'name': 'PUID', 'value': '1000'}], None),
    ([{'name': 'PUID', 'value': 'bsd'}, {'name': 'PGID', 'value': '1000'}], None),
    ([{'name': 'PUID', 'value': '-1'}, {'name': 'PGID', 'value': '1000'}], None),
    (None, None),
])
def test_a_declared_runtime_user_is_read_only_when_it_is_stated_plainly(environment, expected):
    assert ApplicationsService._declared_runtime_owner(environment) == expected


def volume_service():
    service, middleware = service_with_middleware()
    chown_job = Mock()
    chown_job.wait = AsyncMock()
    chown_job.error = None
    service._dataset_owner = AsyncMock(return_value='applications:demo')

    async def call(method, *args, **kwargs):
        if method == 'zfs.dataset.query':
            return []
        if method == 'filesystem.chown':
            return chown_job
        return None

    middleware.call = AsyncMock(side_effect=call)
    return service, middleware, chown_job


def chown_calls(middleware):
    return [
        invocation.args[1] for invocation in middleware.call.await_args_list
        if invocation.args[0] == 'filesystem.chown'
    ]


@pytest.mark.asyncio
async def test_a_new_owned_volume_is_given_to_the_user_the_image_runs_as():
    service, middleware, _ = volume_service()
    data = install_data(
        environment=[{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}],
        volumes=[{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}],
    )

    await service._prepare_volumes({'pool': 'tank'}, data, [])

    # Exactly one directory changes hands: the volume, not its parent.
    assert chown_calls(middleware) == [{
        'path': '/mnt/tank/applications/data/demo/config',
        'uid': 1000,
        'gid': 1000,
        'options': {'recursive': False, 'traverse': False},
    }]


@pytest.mark.asyncio
async def test_an_entry_that_declares_no_user_installs_exactly_as_before():
    service, middleware, _ = volume_service()
    data = install_data(
        volumes=[{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}],
    )

    await service._prepare_volumes({'pool': 'tank'}, data, [])

    assert chown_calls(middleware) == []


# the internal development record: retroassembly's compose names no PUID/PGID, but its image runs as
# bsd (1000) and says so in its own Env; the new /data volume must be 1000's, as a podman
# named volume would be.
@pytest.mark.parametrize('image_env,expected', [
    (['PATH=/usr/local/bin:/usr/bin', 'PUID=1000', 'PGID=1000', 'HOME=/root'], (1000, 1000)),
    (['PUID=0', 'PGID=0'], (0, 0)),
    (['PATH=/bin'], None),
    (['PUID=1000'], None),
    (['PUID=bsd', 'PGID=1000'], None),
    ([], None),
    (None, None),
])
def test_an_image_says_who_it_runs_as_by_the_same_rule_as_a_request(image_env, expected):
    assert ApplicationsService._image_runtime_owner(image_env) == expected


@pytest.mark.asyncio
async def test_only_the_volumes_this_transaction_created_change_hands():
    service, middleware, _ = volume_service()
    volumes = [
        {'name': 'data', 'target': '/data', 'dataset': 'tank/applications/data/demo/data', 'owned': True},
        {'name': 'kept', 'target': '/kept', 'dataset': 'tank/applications/data/demo/kept', 'owned': True},
        {'name': 'media', 'target': '/media', 'dataset': 'tank/media', 'owned': False},
    ]
    created = ['tank/applications/data/demo', 'tank/applications/data/demo/data', 'tank/media']

    await service._give_new_volumes_to(volumes, created, (1000, 1000))

    # The new volume only: not the pre-existing one, not the app's parent, never an external dataset
    # (even one that happens to be named in the list).
    assert chown_calls(middleware) == [{
        'path': '/mnt/tank/applications/data/demo/data',
        'uid': 1000,
        'gid': 1000,
        'options': {'recursive': False, 'traverse': False},
    }]


@pytest.mark.asyncio
async def test_image_inspection_carries_the_image_environment():
    service, _ = service_with_middleware()
    service._podman = AsyncMock(return_value=Mock(stdout=json.dumps([{
        'Id': 'abc', 'Os': 'freebsd', 'Digest': 'sha256:' + '1' * 64,
        'Config': {'Env': ['PUID=1000', 'PGID=1000'], 'Labels': {}},
    }])))

    info = await service._inspect_image({'pool': 'tank'}, 'ghcr.io/daemonless/retroassembly:latest')

    assert info['env'] == ['PUID=1000', 'PGID=1000']


@pytest.mark.asyncio
async def test_an_external_dataset_keeps_the_permissions_its_operator_gave_it():
    service, middleware, _ = volume_service()

    async def call(method, *args, **kwargs):
        if method == 'zfs.dataset.query' and args[0] == [('id', '=', 'otherpool/external')]:
            return [{'id': 'otherpool/external', 'mountpoint': '/mnt/otherpool/external'}]
        if method == 'zfs.dataset.query':
            return []
        return None

    middleware.call = AsyncMock(side_effect=call)
    data = install_data(
        environment=[{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}],
        volumes=[{
            'name': 'config', 'target': '/config',
            'dataset': 'otherpool/external', 'read_only': False,
        }],
    )

    await service._prepare_volumes({'pool': 'tank'}, data, [])

    assert chown_calls(middleware) == []
    # the internal development record: one dataset, no subtree, one property.
    lookup = next(c for c in middleware.call.await_args_list if c.args[0] == 'zfs.dataset.query')
    assert lookup.args[2]['extra']['recursive'] is False
    assert lookup.args[2]['extra']['properties'] == ['mountpoint']


# the internal development record: an `id =` lookup without `recursive: False` serialises the
# whole subtree; under the graphroot that was 3 MB and 17 s per existence check.
@pytest.mark.asyncio
async def test_dataset_existence_checks_never_serialise_the_subtree():
    service, middleware = service_with_middleware()
    middleware.call = AsyncMock(return_value=[{'id': 'tank/applications'}])

    assert await service._dataset_exists('tank/applications') is True
    middleware.call.assert_awaited_once_with(
        'zfs.dataset.query', [('id', '=', 'tank/applications')],
        {'extra': {'recursive': False, 'retrieve_properties': False}},
    )

    middleware.call = AsyncMock(return_value=[])
    assert await service._dataset_exists('tank/applications/missing') is False


@pytest.mark.asyncio
async def test_dataset_mountpoint_reads_one_property_and_reports_absence_as_none():
    service, middleware = service_with_middleware()
    middleware.call = AsyncMock(return_value=[{
        'id': 'otherpool/external',
        'properties': {'mountpoint': {'value': '/mnt/otherpool/external'}},
    }])

    assert await service._dataset_mountpoint('otherpool/external') == '/mnt/otherpool/external'
    options = middleware.call.await_args.args[2]['extra']
    assert options['recursive'] is False
    assert options['properties'] == ['mountpoint']

    middleware.call = AsyncMock(return_value=[])
    assert await service._dataset_mountpoint('otherpool/gone') is None


@pytest.mark.asyncio
async def test_every_existence_check_on_the_runtime_path_is_non_recursive():
    """The five runtime_setup checks were 5 x 17 s on a box with 268 layer datasets."""
    service, middleware = service_with_middleware()
    seen = []

    async def call_middleware(name, *args):
        if name == 'zfs.dataset.query':
            seen.append(args)
            return [{'id': args[0][0][2]}]
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: {
        'tank/applications': 'applications',
        'tank/applications/storage': 'applications:storage',
        'tank/applications/config': 'applications:config',
        'tank/applications/records': 'applications:records',
        'tank/applications/data': 'applications:data',
    }[dataset])
    with patch('middlewared.plugins.applications_freebsd.os.path.ismount', return_value=True):
        await service._validate_application_store('tank')

    assert len(seen) == 5
    assert all(options == {'extra': {'recursive': False, 'retrieve_properties': False}} for _, options in seen)


@pytest.mark.asyncio
async def test_an_existing_owned_volume_is_never_restamped():
    service, middleware, _ = volume_service()

    async def call(method, *args, **kwargs):
        if method == 'zfs.dataset.query':
            return [{'id': 'tank/applications/data/demo/config'}]
        return None

    middleware.call = AsyncMock(side_effect=call)
    data = install_data(
        environment=[{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}],
        volumes=[{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}],
    )

    await service._prepare_volumes({'pool': 'tank'}, data, [])

    # It may hold data, and permissions the operator has since adjusted.
    assert chown_calls(middleware) == []


@pytest.mark.asyncio
async def test_a_failed_handover_refuses_the_install_rather_than_shipping_a_dead_volume():
    service, middleware, chown_job = volume_service()
    chown_job.error = 'permission denied'
    data = install_data(
        environment=[{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}],
        volumes=[{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}],
    )

    with pytest.raises(CallError, match='Unable to give application volume'):
        await service._prepare_volumes({'pool': 'tank'}, data, [])


# -- the internal development record: locally built images and owned image removal --------

@pytest.mark.asyncio
async def test_a_local_image_is_installed_without_a_pull_and_kept_on_rollback():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank', 'restart_on_boot': False}
    data = install_data(image='localhost/freecore/converted/grafanajail:abc123def456')
    service._require_config = AsyncMock(return_value=config)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=True)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock()
    # podman reports a manifest digest for imported and built images too (checked on RC2).
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:' + '3' * 64, 'digest': 'sha256:' + '4' * 64, 'os': 'freebsd', 'labels': {},
    })
    service._wait_healthy = AsyncMock(return_value={'State': {'Running': True}})
    service._write_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()
    middleware.call.return_value = {'name': 'demo', 'status': 'RUNNING'}

    result = await service._install_impl(
        Mock(), data, None, {'kind': 'convert', 'reference': 'grafanajail', 'mode': 'lift', 'image_owned': True},
    )

    assert result == {'name': 'demo', 'status': 'RUNNING'}
    operations = [invocation.args[1] for invocation in service._podman.await_args_list]
    assert 'pull' not in operations
    written = service._write_record.call_args.args[1]
    assert written['origin']['mode'] == 'lift' and written['image'].startswith('localhost/')

    # Missing locally: refused before anything is prepared.
    service._image_exists = AsyncMock(return_value=False)
    with pytest.raises(CallError, match='does not exist in the Applications store'):
        await service._install_impl(Mock(), data, None, {'kind': 'convert', 'reference': 'x'})
    service._prepare_volumes.assert_awaited_once()

    # A failure after the container is created rolls the container back but never the image.
    service._image_exists = AsyncMock(return_value=True)
    service._wait_healthy = AsyncMock(side_effect=CallError('stopped during startup'))
    service._podman.reset_mock()
    with pytest.raises(CallError, match='stopped during startup'):
        await service._install_impl(Mock(), data, None, {'kind': 'convert', 'reference': 'x'})
    operations = [invocation.args[1] for invocation in service._podman.await_args_list]
    assert 'rmi' not in operations and 'pull' not in operations


@pytest.mark.asyncio
async def test_removal_drops_an_owned_lifted_image_but_never_a_catalog_image():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank'}
    service._refresh_restart_on_boot = AsyncMock()
    service._delete_record = Mock()
    service._podman = AsyncMock(return_value=SimpleNamespace(returncode=0, stdout='', stderr=''))
    middleware.call.return_value = []

    owned = persisted_record(schema=3, image_os='freebsd', origin={
        'kind': 'convert', 'reference': 'grafanajail', 'mode': 'lift', 'image_owned': True,
        'image': 'localhost/freecore/converted/grafanajail:abc123def456',
    })
    await service._remove_impl(config, owned, 'tank/applications/data/demo', False)
    service._podman.assert_awaited_once_with(
        config, 'rmi', '--force', 'localhost/freecore/converted/grafanajail:abc123def456', check=False,
    )

    service._podman.reset_mock()
    await service._remove_impl(config, persisted_record(), 'tank/applications/data/demo', False)
    service._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_host_port_free_answers_records_reservations_and_live_listeners():
    service, middleware = service_with_middleware()
    config = {'pool': 'tank'}
    service._require_config = AsyncMock(return_value=config)
    service._read_records = Mock(return_value=([persisted_record(ports=[
        {'host_port': 8080, 'container_port': 80, 'protocol': 'tcp'},
    ])], []))
    service._reserved_management_ports = AsyncMock(return_value={(443, 'tcp')})
    middleware.run_in_thread = AsyncMock(side_effect=lambda function, port, protocol: port != 2222)

    assert await service.host_port_free(8080, 'tcp') is False
    assert await service.host_port_free(8080, 'udp') is True
    assert await service.host_port_free(443, 'tcp') is False
    assert await service.host_port_free(2222, 'tcp') is False
    assert await service.host_port_free(3050, 'tcp') is True


# the internal development record: a page of applications is two podman invocations, not two per record.

def batch_podman(listing, inspections, fail_inspect=False):
    calls = []

    async def podman(config, *arguments, check=True, redactions=()):
        calls.append(arguments)
        if arguments[:2] == ('ps', '--all'):
            return Mock(returncode=0, stdout=json.dumps(listing))
        if arguments[:2] == ('container', 'inspect'):
            if fail_inspect:
                return Mock(returncode=125, stdout='', stderr='no such container')
            return Mock(returncode=0, stdout=json.dumps([
                inspection for inspection in inspections if inspection['Id'] in arguments[2:]
            ]))
        raise AssertionError(arguments)

    return calls, podman


@pytest.mark.asyncio
async def test_batched_inspection_is_two_podman_calls_for_any_number_of_records():
    service, _ = service_with_middleware()
    records = [persisted_record(name=f'app{i}', container_id=str(i) * 64) for i in range(1, 4)]
    inspections = [managed_inspection(record, container_id=record['container_id']) for record in records]
    calls, podman = batch_podman([{'Id': record['container_id']} for record in records], inspections)
    service._podman = AsyncMock(side_effect=podman)
    service._inspect_owned_container = AsyncMock()

    result = await ApplicationsService._inspect_managed_containers(service, {'pool': 'tank'}, records)

    assert [arguments[:2] for arguments in calls] == [('ps', '--all'), ('container', 'inspect')]
    assert set(calls[1][2:]) == {record['container_id'] for record in records}
    assert result == {
        record['name']: (inspection, record['container_id'])
        for record, inspection in zip(records, inspections)
    }
    service._inspect_owned_container.assert_not_awaited()


@pytest.mark.asyncio
async def test_batched_inspection_reports_absence_and_foreign_containers_like_the_single_path():
    service, _ = service_with_middleware()
    present = persisted_record(name='present', container_id='1' * 64)
    absent = persisted_record(name='absent', container_id='2' * 64)
    stolen = persisted_record(name='stolen', container_id='3' * 64)
    foreign = managed_inspection(persisted_record(name='someone-else'), container_id='3' * 64)
    calls, podman = batch_podman(
        [{'Id': '1' * 64}, {'Id': '3' * 64}],
        [managed_inspection(present, container_id='1' * 64), foreign],
    )
    service._podman = AsyncMock(side_effect=podman)

    result = await ApplicationsService._inspect_managed_containers(
        service, {'pool': 'tank'}, [present, absent, stolen]
    )

    assert result['present'][1] == '1' * 64
    assert result['absent'] is None
    assert isinstance(result['stolen'], CallError)
    assert 'ownership labels do not match' in str(result['stolen'])
    assert '2' * 64 not in calls[1]  # an absent container is never asked for


@pytest.mark.asyncio
async def test_batched_inspection_falls_back_to_the_single_path_when_podman_disagrees_with_itself():
    service, _ = service_with_middleware()
    record = persisted_record(name='racy', container_id='1' * 64)
    calls, podman = batch_podman([{'Id': '1' * 64}], [], fail_inspect=True)
    service._podman = AsyncMock(side_effect=podman)
    service._inspect_owned_container = AsyncMock(return_value=None)

    result = await ApplicationsService._inspect_managed_containers(service, {'pool': 'tank'}, [record])

    assert result == {'racy': None}
    service._inspect_owned_container.assert_awaited_once_with({'pool': 'tank'}, record)


@pytest.mark.asyncio
async def test_a_record_without_a_container_id_keeps_the_single_path_and_its_errors():
    service, _ = service_with_middleware()
    odd = persisted_record(name='odd')
    odd['container_id'] = 'saved'
    service._podman = AsyncMock(side_effect=AssertionError('no batched call for an unnameable container'))
    service._inspect_owned_container = AsyncMock(side_effect=CallError('Podman exit status 125'))

    result = await ApplicationsService._inspect_managed_containers(service, {'pool': 'tank'}, [odd])

    assert isinstance(result['odd'], CallError)
    service._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_query_filtered_to_one_name_still_inspects_everything_once_and_reports_each_state():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    records = [
        persisted_record(name='up', container_id='1' * 64),
        persisted_record(name='down', container_id='2' * 64),
        persisted_record(name='gone', container_name='freecore-app-gone', container_id='3' * 64),
    ]
    service._read_records = Mock(return_value=(records, []))
    service._catalog_states = AsyncMock(return_value=[{
        'update_available': False, 'revoked': False, 'revocation_reason': None, 'catalog_error': None,
    }] * 3)
    service._inspect_managed_containers = AsyncMock(return_value={
        'up': ({'State': {'Status': 'running', 'Running': True}}, '1' * 64),
        'down': ({'State': {'Status': 'exited', 'Running': False, 'Error': ''}}, '2' * 64),
        'gone': None,
    })

    everything = await ApplicationsService.query.wraps(service)
    assert [(item['name'], item['status']) for item in everything] == [
        ('up', 'RUNNING'), ('down', 'EXITED'), ('gone', 'MISSING'),
    ]
    assert everything[2]['error'].endswith("Managed container 'freecore-app-gone' is unavailable.")

    one = await ApplicationsService.query.wraps(service, [['name', '=', 'down']])
    assert [(item['name'], item['status']) for item in one] == [('down', 'EXITED')]
    assert service._inspect_managed_containers.await_count == 2
    for awaited in service._inspect_managed_containers.await_args_list:
        assert awaited.args[1] == records


@pytest.mark.asyncio
async def test_query_reads_the_installed_version_from_the_running_image():
    # the internal development record: crpb's box after the RC2 update -- the record says
    # 1.36.0_1 (the index's quarterly field), the running image says 1.37.3.
    service, middleware = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    provenance = {
        'id': 'daemonless:vaultwarden', 'version': '1.36.0_1', 'compose_sha256': 'e' * 64,
        'repository': 'https://github.com/daemonless/vaultwarden',
        'image_tag': 'ghcr.io/daemonless/vaultwarden:latest',
    }
    records = [
        persisted_record(name='vw', container_id='1' * 64, catalog=dict(provenance)),
        persisted_record(name='byo', container_id='2' * 64),
        persisted_record(name='gone', container_id='3' * 64, catalog=dict(provenance)),
    ]
    service._read_records = Mock(return_value=(records, []))
    service._inspect_managed_containers = AsyncMock(return_value={
        'vw': ({'State': {'Status': 'running', 'Running': True}, 'Config': {'Labels': {
            'org.opencontainers.image.version': '1.37.3', 'io.daemonless.variant': 'latest',
        }}}, '1' * 64),
        'byo': ({'State': {'Status': 'running', 'Running': True}, 'Config': {'Labels': {}}}, '2' * 64),
        'gone': None,
    })
    middleware.call.return_value = [
        {'update_available': False, 'revoked': False, 'revocation_reason': None, 'catalog_error': None},
    ] * 3

    result = await ApplicationsService.query.wraps(service)

    method, provenances, observed = middleware.call.await_args.args
    assert method == 'applications.catalog.installed_state'
    assert provenances == [provenance, None, provenance]
    assert observed == [('1.37.3', 'latest'), None, None]
    by_name = {item['name']: item for item in result}
    assert by_name['vw']['catalog'] == {**provenance, 'version': '1.37.3', 'variant': 'latest', 'version_source': 'image'}
    assert by_name['gone']['catalog'] == provenance
    assert by_name['byo'].get('catalog') is None


@pytest.mark.asyncio
async def test_start_on_boot_starts_only_stopped_always_records_from_one_batched_inspection():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True, 'restart_on_boot': True})
    records = [
        persisted_record(name='running', container_id='1' * 64),
        persisted_record(name='stopped', container_id='2' * 64),
        persisted_record(name='manual', container_id='3' * 64, restart_policy='no'),
        persisted_record(name='missing', container_id='4' * 64),
    ]
    service._read_records = Mock(return_value=(records, []))
    service._inspect_managed_containers = AsyncMock(return_value={
        'running': ({'State': {'Running': True}}, '1' * 64),
        'stopped': ({'State': {'Running': False}}, '2' * 64),
        'missing': None,
    })
    service._podman = AsyncMock()

    await service._start_on_boot_impl()

    inspected = service._inspect_managed_containers.await_args.args[1]
    assert [record['name'] for record in inspected] == ['running', 'stopped', 'missing']
    service._podman.assert_awaited_once_with(
        {'pool': 'tank', 'runtime_ready': True, 'restart_on_boot': True}, 'start', '2' * 64,
    )


# the internal development record: a crash loop is visible, and an install notices one.

def looping_inspection(record, *, status='running', restarts=6, exit_code=0, started_ago=3):
    started = (datetime.now(timezone.utc) - timedelta(seconds=started_ago)).isoformat()
    inspection = managed_inspection(record, running=status == 'running')
    inspection['RestartCount'] = restarts
    inspection['State'].update({'Status': status, 'ExitCode': exit_code, 'StartedAt': started})
    return inspection


def test_a_restart_count_with_recent_starts_reads_restarting_and_says_why():
    record = persisted_record()
    state = ApplicationsService._classify_state(record, looping_inspection(record))
    assert state['status'] == 'RESTARTING'
    assert state['running'] is True
    assert state['restarts'] == 6
    assert 'restarted 6 times' in state['error']

    between = looping_inspection(record, status='stopped', restarts=4, exit_code=3)
    state = ApplicationsService._classify_state(record, between)
    assert state == {
        'status': 'RESTARTING', 'running': False, 'restarts': 4, 'exit_code': 3,
        'error': 'The container restarted 4 times (exit status 3; restart policy always); see the application log.',
    }


def test_a_user_stopped_or_long_stable_container_is_not_restarting():
    record = persisted_record()
    stopped = looping_inspection(record, status='exited', restarts=6, exit_code=137)
    assert ApplicationsService._classify_state(record, stopped) == {
        'status': 'EXITED', 'running': False, 'restarts': 6, 'exit_code': 137, 'error': None,
    }
    stable = looping_inspection(record, restarts=1, started_ago=RESTART_WINDOW_SECONDS + 60)
    state = ApplicationsService._classify_state(record, stable)
    assert (state['status'], state['restarts'], state['error']) == ('RUNNING', 1, None)
    manual = persisted_record(restart_policy='no')
    assert ApplicationsService._classify_state(manual, looping_inspection(manual))['status'] == 'RUNNING'
    clean = managed_inspection(record)
    assert ApplicationsService._classify_state(record, clean) == {
        'status': 'UNKNOWN', 'running': True, 'restarts': 0, 'exit_code': None, 'error': None,
    }


def test_podman_timestamps_with_nanoseconds_parse_and_the_zero_time_is_none():
    parsed = ApplicationsService._timestamp('2026-09-13T13:20:01.123456789-07:00')
    assert parsed.tzinfo is not None and parsed.year == 2026
    assert ApplicationsService._timestamp('0001-01-01T00:00:00Z') is None
    assert ApplicationsService._timestamp('garbage') is None
    assert ApplicationsService._timestamp(None) is None


@pytest.mark.asyncio
async def test_query_reports_a_crash_loop_instead_of_running():
    service, _ = service_with_middleware()
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    record = persisted_record()
    service._read_records = Mock(return_value=([record], []))
    service._catalog_states = AsyncMock(return_value=[{
        'update_available': False, 'revoked': False, 'revocation_reason': None, 'catalog_error': None,
    }])
    service._inspect_managed_containers = AsyncMock(return_value={'demo': (looping_inspection(record), '1' * 64)})

    result = await ApplicationsService.query.wraps(service)

    assert result[0]['status'] == 'RESTARTING'
    assert result[0]['restarts'] == 6
    assert result[0]['health'] == 'UNDECLARED'
    assert 'restarted 6 times' in result[0]['error']


@pytest.mark.asyncio
async def test_install_health_wait_fails_when_the_container_restarted_or_its_service_crashed():
    service, _ = service_with_middleware()
    service._startup_failure_detail = AsyncMock(return_value='exit status 1. Last output:\nboom')
    service._inspect_container = AsyncMock(return_value={'State': {'Running': True}, 'RestartCount': 2})
    with pytest.raises(CallError, match='restarted 2 times during startup: exit status 1'):
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 30, None)

    service._inspect_container = AsyncMock(return_value={'State': {'Running': True}, 'RestartCount': 0})
    service._podman = AsyncMock(return_value=Mock(returncode=0, stdout=(
        "FATAL: invalid Scanner.Schedule\n[s6] Service 'navidrome' crashed (Exit: 1, Signal: 0)\n"
        "[s6] Waiting 5 seconds before restart...\n"
    ), stderr=''))
    with patch('middlewared.plugins.applications_freebsd.asyncio.sleep', AsyncMock()) as sleep:
        with pytest.raises(CallError, match="service 'navidrome' crashed under s6"):
            await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 30, None)
    sleep.assert_awaited_once_with(STARTUP_SETTLE_SECONDS)
    service._podman.assert_awaited_once_with(
        {'pool': 'tank'}, 'logs', '--tail', '40', 'freecore-app-demo', check=False, redactions=(),
    )


@pytest.mark.asyncio
async def test_install_health_wait_settles_once_and_commits_a_quiet_container():
    service, _ = service_with_middleware()
    service._inspect_container = AsyncMock(return_value={'State': {'Running': True}, 'RestartCount': 0})
    service._podman = AsyncMock(return_value=Mock(
        returncode=0, stdout='[s6-init] making user provided files available\n', stderr='',
    ))
    with patch('middlewared.plugins.applications_freebsd.asyncio.sleep', AsyncMock()) as sleep:
        result = await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 30, None)
    assert result['RestartCount'] == 0
    assert service._inspect_container.await_count == 2
    sleep.assert_awaited_once_with(STARTUP_SETTLE_SECONDS)

    # timeout 0 means "do not wait": one inspection, no settle, no log read.
    service._inspect_container.reset_mock()
    service._podman.reset_mock()
    with patch('middlewared.plugins.applications_freebsd.asyncio.sleep', AsyncMock()) as sleep:
        await service._wait_healthy({'pool': 'tank'}, 'freecore-app-demo', 0, None)
    assert service._inspect_container.await_count == 1
    sleep.assert_not_awaited()


# the internal development record: the last application on an image takes it along; prune finds the rest.

def images_listing(*entries):
    return json.dumps([
        {'Id': image_id, 'Names': names, 'Size': size, 'Dangling': not names}
        for image_id, names, size in entries
    ])


@pytest.mark.asyncio
async def test_release_image_removes_only_an_image_no_other_record_uses():
    service, _ = service_with_middleware()
    service._release_image = ApplicationsService._release_image.__get__(service)
    service._stored_plans = Mock(return_value=[])
    service._read_records = Mock(return_value=([
        persisted_record(name='keeper', image_id='shared'),
        persisted_record(name='leaving', image_id='shared'),
        persisted_record(name='alone', image_id='lonely'),
    ], []))
    service._podman = AsyncMock(return_value=Mock(returncode=0, stdout='', stderr=''))

    # shared by keeper: stays, podman untouched
    assert await service._release_image({'pool': 'tank'}, 'shared', except_record='leaving') is False
    service._podman.assert_not_awaited()
    # only alone used it: goes
    assert await service._release_image({'pool': 'tank'}, 'lonely', except_record='alone') is True
    service._podman.assert_awaited_once_with({'pool': 'tank'}, 'rmi', 'lonely', check=False)
    # podman refusing (a container still uses it) is logged, never raised
    service._podman = AsyncMock(return_value=Mock(returncode=2, stdout='', stderr='image is in use by a container'))
    assert await service._release_image({'pool': 'tank'}, 'lonely', except_record='alone') is False
    service._podman = AsyncMock(side_effect=OSError('no podman'))
    assert await service._release_image({'pool': 'tank'}, 'lonely', except_record='alone') is False
    assert await service._release_image({'pool': 'tank'}, None) is False


@pytest.mark.asyncio
async def test_remove_releases_the_image_and_update_releases_the_superseded_one():
    service, _ = service_with_middleware()
    service._release_image = AsyncMock(return_value=True)
    service._delete_record = Mock()
    service._refresh_restart_on_boot = AsyncMock()
    record = persisted_record(name='demo', image_id='old-image')

    await service._remove_impl({'pool': 'tank'}, record, 'tank/applications/data/demo', False)
    service._release_image.assert_awaited_once_with({'pool': 'tank'}, 'old-image', 'demo')

    lifted = persisted_record(name='lifted', image_id='built', origin={
        'kind': 'convert', 'mode': 'lift', 'image_owned': True, 'image': 'localhost/freecore/converted/lifted:abc',
    })
    service._release_image.reset_mock()
    service._podman = AsyncMock(return_value=Mock(returncode=0, stdout='', stderr=''))
    await service._remove_impl({'pool': 'tank'}, lifted, 'tank/applications/data/lifted', False)
    service._podman.assert_awaited_once_with(
        {'pool': 'tank'}, 'rmi', '--force', 'localhost/freecore/converted/lifted:abc', check=False,
    )
    service._release_image.assert_not_awaited()  # the owned path already took its image


@pytest.mark.asyncio
async def test_prune_keeps_referenced_lift_base_hop_and_in_use_images_and_honours_dry_run():
    service, _ = service_with_middleware()
    service._require_config = AsyncMock(return_value={'pool': 'tank'})
    service._read_records = Mock(return_value=([
        persisted_record(name='demo', image='ghcr.io/daemonless/demo:latest', image_id='used-by-record'),
    ], []))
    service._stored_plans = Mock(return_value=[{'hop': {'image': 'docker.io/grafana/grafana-oss:10.4.19'}}])
    listing = images_listing(
        ('used-by-record', ['ghcr.io/daemonless/demo:latest'], 100),
        ('base', ['localhost/freecore/jail-base:15.0-RELEASE'], 200),
        ('hop', ['docker.io/grafana/grafana-oss:10.4.19'], 300),
        ('in-use-unmanaged', ['docker.io/library/alpine:3.20'], 400),
        ('stale-tagged', ['ghcr.io/daemonless/jellyfin:latest', 'ghcr.io/daemonless/jellyfin:10.11'], 5000),
        ('dangling', [], 2800),
    )
    calls = []

    async def podman(config, *arguments, check=True, redactions=()):
        calls.append(arguments)
        if arguments[:2] == ('images', '--format'):
            return Mock(returncode=0, stdout=listing, stderr='')
        if arguments[:2] == ('ps', '--all'):
            return Mock(returncode=0, stdout=json.dumps([{'Id': 'c' * 64, 'ImageID': 'in-use-unmanaged'}]), stderr='')
        if arguments[0] == 'rmi':
            return Mock(returncode=0, stdout='', stderr='')
        raise AssertionError(arguments)

    service._podman = AsyncMock(side_effect=podman)

    report = await ApplicationsService.prune.wraps(service, Mock(), {'dry_run': True})
    assert report['dry_run'] is True and report['removed'] == 0
    assert [(item["id"], item["dangling"]) for item in report["images"]] == [
        ("stale-tagged", False), ("dangling", True),
    ]
    assert report['reclaimable'] == 7800
    assert not any(arguments[0] == 'rmi' for arguments in calls)

    report = await ApplicationsService.prune.wraps(service, Mock(), {'dry_run': False})
    assert report['removed'] == 7800 and report['errors'] == []
    assert [arguments for arguments in calls if arguments[0] == 'rmi'] == [
        ('rmi', 'ghcr.io/daemonless/jellyfin:latest', 'ghcr.io/daemonless/jellyfin:10.11'),
        ('rmi', 'dangling'),
    ]


# the internal development record: the store is marked opaque once, and never in a way that can fail setup.

@pytest.mark.asyncio
async def test_store_is_marked_opaque_once_and_the_zfs_cache_is_forgotten():
    service, middleware = service_with_middleware()
    outcomes = iter([
        Mock(returncode=0, stdout='-\n', stderr=''),      # not marked yet
        Mock(returncode=0, stdout='', stderr=''),         # zfs set
    ])
    fake_run = AsyncMock(side_effect=lambda *a, **k: next(outcomes))
    with patch('middlewared.plugins.applications_freebsd.run', fake_run) as run:
        await service._mark_store_opaque('tank/applications/storage')
    assert run.await_args_list[0].args[0][:4] == ['zfs', 'get', '-H', '-s']
    assert run.await_args_list[1].args[0] == ['zfs', 'set', 'org.freecore:opaque=on', 'tank/applications/storage']
    middleware.call.assert_awaited_with('zfs.dataset.forget_opaque_datasets')

    marked = AsyncMock(return_value=Mock(returncode=0, stdout='on\n', stderr=''))
    with patch('middlewared.plugins.applications_freebsd.run', marked) as run:
        await service._mark_store_opaque('tank/applications/storage')
    assert run.await_count == 1  # already marked: nothing set

    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(side_effect=FileNotFoundError('zfs'))):
        await service._mark_store_opaque('tank/applications/storage')  # logged, not raised


# -- LAN-attached network mode (the internal development record) ----------------------


def lan_record(**overrides):
    return persisted_record(**{
        'schema': 4, 'image_os': 'freebsd', 'origin': None,
        'network': {
            'mode': 'lan', 'interface': 'em0',
            'address': '203.0.113.201/24', 'gateway': '203.0.113.1',
        },
        **overrides,
    })


def lan_middleware_calls(choices=None, in_use=(), jails=()):
    async def call(method, *args):
        if method == 'interface.choices':
            return choices if choices is not None else {'em0': 'em0', 'igb0': 'igb0'}
        if method == 'interface.ip_in_use':
            return list(in_use)
        if method == 'jail.get_activated_pool':
            return 'tank' if jails else None
        if method == 'jail.query':
            return list(jails)
        if method == 'bastille.query':
            return []
        if method == 'interface.reserve_jail_bridge':
            return None
        if method == 'interface.ensure_jail_bridge':
            return 'bridge0'
        raise AssertionError(f'unexpected middleware call {method!r}')
    return AsyncMock(side_effect=call)


def test_persisted_record_validation_enforces_the_lan_attachment_contract():
    config = {'pool': 'tank'}
    record = lan_record()
    assert ApplicationsService._validate_record(config, record, 'demo') is record
    managed = persisted_record(schema=4, image_os='freebsd', origin=None, network={'mode': 'managed'})
    assert ApplicationsService._validate_record(config, managed, 'demo') is managed

    with pytest.raises(ValueError, match='schema does not carry a network attachment'):
        ApplicationsService._validate_record(
            config, persisted_record(schema=3, image_os='freebsd', origin=None,
                                     network={'mode': 'managed'}), 'demo',
        )
    for network, complaint in [
        ({'mode': 'host'}, 'network mode is invalid'),
        ({'mode': 'managed', 'interface': 'em0'}, 'no attachment fields'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24'}, 'attachment fields'),
        ({'mode': 'lan', 'interface': 'em0 rm', 'address': '203.0.113.201/24',
          'gateway': '203.0.113.1'}, 'interface is invalid'),
        ({'mode': 'lan', 'interface': 'EM0', 'address': '203.0.113.201/24',
          'gateway': '203.0.113.1'}, 'interface is invalid'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201',
          'gateway': '203.0.113.1'}, 'not normalized|usable host address'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.0/24',
          'gateway': '203.0.113.1'}, 'usable host address'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/31',
          'gateway': '203.0.113.200'}, 'usable host address'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24',
          'gateway': '198.51.100.1'}, 'gateway is outside'),
        ({'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24',
          'gateway': '203.0.113.201'}, 'gateway is outside'),
    ]:
        with pytest.raises(ValueError, match=complaint):
            ApplicationsService._validate_record(config, lan_record(network=network), 'demo')


def test_health_probe_follows_the_network_mode():
    healthcheck = {
        'type': 'HTTP', 'scheme': 'http', 'container_port': 32400,
        'host_port': 18400, 'path': '/identity',
    }
    managed = persisted_record(healthcheck=dict(healthcheck))
    assert ApplicationsService._record_healthcheck_probe(managed) == healthcheck

    probe = ApplicationsService._record_healthcheck_probe(lan_record(healthcheck=dict(healthcheck)))
    assert probe['probe_host'] == '203.0.113.201'
    assert probe['probe_port'] == 32400

    assert ApplicationsService._record_healthcheck_probe(persisted_record()) is None


@pytest.mark.asyncio
async def test_lan_attachment_validation_names_each_collision():
    service, middleware = service_with_middleware()
    middleware.call = lan_middleware_calls(
        in_use=[{'type': 'INET', 'address': '203.0.113.7', 'netmask': 24}],
        jails=[{'ip4_addr': 'vnet0|203.0.113.30/24'}],
    )
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
    records = [lan_record(name='other'), persisted_record(name='plain')]

    async def refusals(network, current_name=None):
        verrors = ValidationErrors()
        await service._validate_lan_network(
            verrors, 'application_install.network', config, network, records, current_name,
        )
        return '; '.join(f'{error.attribute}: {error.errmsg}' for error in verrors.errors)

    good = {'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.50/24', 'gateway': '203.0.113.1'}
    assert await refusals(good) == ''
    assert 'does not exist' in await refusals({**good, 'interface': 'igc9'})
    assert 'managed container subnet' in await refusals({**good, 'address': '10.88.0.5/16'})
    assert 'already attached by application' in await refusals({**good, 'address': '203.0.113.201/24'})
    assert await refusals({**good, 'address': '203.0.113.201/24'}, current_name='other') == ''
    assert 'already configured on this host' in await refusals({**good, 'address': '203.0.113.7/24'})
    assert 'assigned to a defined jail' in await refusals({**good, 'address': '203.0.113.30/24'})
    assert 'inside the attached network' in await refusals({**good, 'gateway': '198.51.100.1'})
    assert 'host interface to join' in await refusals({**good, 'interface': None})
    assert 'usable IPv4 host address' in await refusals({**good, 'address': '203.0.113.50'})


@pytest.mark.asyncio
async def test_lan_install_skips_host_port_rules_and_managed_installs_ignore_lan_ports():
    service, middleware = service_with_middleware()
    service._read_records = Mock(return_value=([
        lan_record(name='other', ports=[
            {'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'},
        ]),
    ], []))
    service._container_exists = AsyncMock(return_value=False)
    service._reserved_management_ports = AsyncMock(return_value=set())
    middleware.run_in_thread.return_value = True
    middleware.call = lan_middleware_calls()
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}

    # a LAN-attached application's declared ports occupy no host port
    await service._validate_install(config, install_data(ports=[
        {'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'},
    ]))

    # a LAN install needs no free host port: every port is "taken" here
    reserved_lookups = service._reserved_management_ports.await_count
    middleware.run_in_thread.return_value = False
    await service._validate_install(config, install_data(
        ports=[{'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'}],
        network={'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.60/24', 'gateway': '203.0.113.1'},
    ))
    assert service._reserved_management_ports.await_count == reserved_lookups

    # and its attachment is still validated
    with pytest.raises(ValidationErrors, match='does not exist'):
        await service._validate_install(config, install_data(
            network={'mode': 'lan', 'interface': 'igc9', 'address': '203.0.113.60/24', 'gateway': '203.0.113.1'},
        ))


@pytest.mark.asyncio
async def test_lan_network_renders_against_the_bridge_that_carries_the_interface(tmp_path):
    service, middleware = service_with_middleware()
    async def jail_bridge(method, *args):
        assert (method, args) == ('interface.ensure_jail_bridge', ('em0',))
        return 'bridge7'
    middleware.call = AsyncMock(side_effect=jail_bridge)
    conflist = tmp_path / '90-freecore-lan-demo.conflist'
    with (
        patch(
            'middlewared.plugins.applications_freebsd.lan_conflist_path',
            Mock(return_value=str(conflist)),
        ),
    ):
        previous = await service._prepare_lan_network({'pool': 'tank'}, lan_record())
        assert previous == {'lan': None, 'managed': None}
        parsed = json.loads(conflist.read_text())
        assert parsed['plugins'][0]['bridge'] == 'bridge7'
        assert parsed['plugins'][0]['ipam']['addresses'] == [
            {'address': '203.0.113.201/24', 'gateway': '203.0.113.1'},
        ]
        # the internal development record: the jail-bridge routine owns slot policy
        middleware.call.assert_any_await('interface.ensure_jail_bridge', 'em0')

        # idempotent: the second render returns what the first wrote
        second = await service._prepare_lan_network({'pool': 'tank'}, lan_record())
        assert json.loads(second['lan']) == parsed and second['managed'] is None

    # a managed record touches nothing
    middleware.call = AsyncMock(side_effect=AssertionError('managed records must not touch the network'))
    assert await service._prepare_lan_network({'pool': 'tank'}, persisted_record()) is None


@pytest.mark.asyncio
async def test_lan_bridge_policy_is_the_jail_bridge_routine():
    """the internal development record: slot policy lives in interface.ensure_jail_bridge,
    so an app-first start lands the uplink in bridge0 and iocage shares it."""
    service, middleware = service_with_middleware()
    middleware.call = AsyncMock(return_value='bridge0')

    assert await service._ensure_lan_bridge('em0') == 'bridge0'
    middleware.call.assert_awaited_once_with('interface.ensure_jail_bridge', 'em0')

    middleware.call = AsyncMock(
        side_effect=CallError("No unassigned jail bridge is available for interface 'em9'."),
    )
    with pytest.raises(CallError, match='No unassigned jail bridge'):
        await service._ensure_lan_bridge('em9')


# -- gateway pattern: the managed-bridge leg (the internal development record) --------


def dual_record(**overrides):
    overrides.setdefault('network', {
        'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24', 'gateway': '203.0.113.1',
        'managed_access': True, 'managed_address': '10.88.255.254',
    })
    return lan_record(**overrides)


def test_persisted_record_validation_enforces_the_managed_leg_contract():
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
    record = dual_record()
    assert ApplicationsService._validate_record(config, record, 'demo') is record
    plain = lan_record()
    assert ApplicationsService._validate_record(config, plain, 'demo') is plain

    base = {'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24', 'gateway': '203.0.113.1'}
    for network, complaint in [
        ({**base, 'managed_access': True}, 'attachment fields'),
        ({**base, 'managed_address': '10.88.255.254'}, 'attachment fields'),
        ({**base, 'managed_access': False, 'managed_address': '10.88.255.254'}, 'must be explicit'),
        ({**base, 'managed_access': True, 'managed_address': '10.99.0.9'}, 'usable managed subnet'),
        ({**base, 'managed_access': True, 'managed_address': '10.88.0.1'}, 'usable managed subnet'),
        ({**base, 'managed_access': True, 'managed_address': 'nonsense'}, 'address is invalid'),
    ]:
        with pytest.raises(ValueError, match=complaint):
            ApplicationsService._validate_record(config, dual_record(network=network), 'demo')


def test_managed_leg_addresses_are_assigned_from_the_top_and_exhaust_cleanly():
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
    assert ApplicationsService._allocate_managed_leg_address(config, []) == '10.88.255.254'
    others = [dual_record(name='gateway')]
    assert ApplicationsService._allocate_managed_leg_address(config, others) == '10.88.255.253'
    # the application being reconfigured does not block its own address
    assert ApplicationsService._allocate_managed_leg_address(
        config, others, current_name='gateway',
    ) == '10.88.255.254'

    tiny = {'pool': 'tank', 'subnet': '203.0.113.0/29'}
    taken = []
    for index in range(5):
        address = ApplicationsService._allocate_managed_leg_address(tiny, taken)
        record = dual_record(name=f'app{index}')
        record['network']['managed_address'] = address
        taken.append(record)
    assert [r['network']['managed_address'] for r in taken] == \
        ['203.0.113.6', '203.0.113.5', '203.0.113.4', '203.0.113.3', '203.0.113.2']
    with pytest.raises(CallError, match='No managed-bridge address is free'):
        ApplicationsService._allocate_managed_leg_address(tiny, taken)


def test_bridge_address_follows_the_attachment():
    assert ApplicationsService._bridge_address(dual_record(), None) == '10.88.255.254'
    assert ApplicationsService._bridge_address(lan_record(), None) is None
    managed = persisted_record()
    inspection = {'NetworkSettings': {'Networks': {'podman': {'IPAddress': '10.88.0.5'}}}}
    assert ApplicationsService._bridge_address(managed, inspection) == '10.88.0.5'
    assert ApplicationsService._bridge_address(managed, {'NetworkSettings': {'IPAddress': '10.88.0.7'}}) == '10.88.0.7'
    assert ApplicationsService._bridge_address(managed, {'NetworkSettings': {'Networks': {'podman': {'IPAddress': 'junk'}}}}) is None
    assert ApplicationsService._bridge_address(managed, {}) is None


@pytest.mark.asyncio
async def test_dual_attachment_renders_both_legs_and_a_plain_lan_removes_the_stale_one(tmp_path):
    service, middleware = service_with_middleware()
    middleware.call = AsyncMock(return_value='bridge0')
    lan_path = tmp_path / '90-freecore-lan-demo.conflist'
    managed_path = tmp_path / '91-freecore-managed-demo.conflist'
    with (
        patch(
            'middlewared.plugins.applications_freebsd.lan_conflist_path',
            Mock(return_value=str(lan_path)),
        ),
        patch(
            'middlewared.plugins.applications_freebsd.lan_managed_conflist_path',
            Mock(return_value=str(managed_path)),
        ),
    ):
        config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
        previous = await service._prepare_lan_network(config, dual_record())
        assert previous == {'lan': None, 'managed': None}
        managed_leg = json.loads(managed_path.read_text())
        assert managed_leg['plugins'][0]['bridge'] == 'cni-podman0'
        assert managed_leg['plugins'][0]['ipam']['addresses'] == [{'address': '10.88.255.254/16'}]
        assert 'routes' not in managed_leg['plugins'][0]['ipam']

        # dropping the leg removes its conflist and reports what was there
        previous = await service._prepare_lan_network(config, lan_record())
        assert json.loads(previous['managed']) == managed_leg
        assert not managed_path.exists() and lan_path.exists()

        # restore brings both back; removal takes both away
        service._restore_lan_conflist('tank', 'demo', previous)
        assert json.loads(managed_path.read_text()) == managed_leg
        service._remove_lan_conflist('tank', 'demo')
        assert not managed_path.exists() and not lan_path.exists()


def test_network_requests_carry_the_flag_but_never_the_assigned_address():
    request = ApplicationsService._network_request({'network': {
        'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24', 'gateway': '203.0.113.1',
        'managed_access': True, 'managed_address': '10.88.0.9',
    }})
    assert request == {
        'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24', 'gateway': '203.0.113.1',
        'managed_access': True,
    }
    request = ApplicationsService._network_request({'network': {
        'mode': 'lan', 'interface': 'em0', 'address': '203.0.113.201/24', 'gateway': '203.0.113.1',
        'managed_access': False,
    }})
    assert 'managed_access' not in request


# -- stable managed bridge addresses (the internal development record) -----------------


def test_managed_pin_contract_and_shared_allocator():
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
    pinned = persisted_record(
        schema=4, image_os='freebsd', origin=None,
        network={'mode': 'managed', 'bridge_address': '10.88.255.254'},
    )
    assert ApplicationsService._validate_record(config, pinned, 'demo') is pinned
    for bad in ('10.99.0.9', '10.88.0.1', '10.88.255.255', 'nonsense'):
        with pytest.raises(ValueError, match='pinned bridge address'):
            ApplicationsService._validate_record(config, persisted_record(
                schema=4, image_os='freebsd', origin=None,
                network={'mode': 'managed', 'bridge_address': bad},
            ), 'demo')
    # one allocator for managed pins and dual legs: neither kind is handed out twice
    dual = dual_record(name='gateway')
    dual['network']['managed_address'] = '10.88.255.253'
    first = ApplicationsService._allocate_managed_leg_address(config, [pinned, dual])
    assert first == '10.88.255.252'
    assert ApplicationsService._bridge_pins(pinned) == ['10.88.255.254']
    assert ApplicationsService._bridge_pins(persisted_record()) == []


def test_bridge_address_prefers_the_live_address_and_falls_back_to_the_pin():
    pinned = persisted_record(
        schema=4, image_os='freebsd', origin=None,
        network={'mode': 'managed', 'bridge_address': '10.88.255.254'},
    )
    live = {'NetworkSettings': {'Networks': {'podman': {'IPAddress': '10.88.255.254'}}}}
    assert ApplicationsService._bridge_address(pinned, live) == '10.88.255.254'
    assert ApplicationsService._bridge_address(pinned, {}) == '10.88.255.254'


@pytest.mark.asyncio
async def test_subnet_change_is_refused_while_addresses_are_pinned():
    service, _ = service_with_middleware()
    service._validate_pool_and_subnet = AsyncMock()
    pinned = persisted_record(
        name='backend', schema=4, image_os='freebsd', origin=None,
        network={'mode': 'managed', 'bridge_address': '10.88.255.254'},
    )
    service._attachment_records = Mock(return_value=[pinned, dual_record(name='gateway'), persisted_record(name='legacy')])
    old = {'pool': 'tank', 'subnet': '10.88.0.0/16', 'runtime_ready': True, 'id': 1}
    with pytest.raises(CallError, match='backend, gateway') as error:
        await service._reconfigure(Mock(), old, {'pool': 'tank', 'subnet': '10.99.0.0/16'})
    assert 'legacy' not in str(error.value)
    assert 'data is kept' in str(error.value)


# -- ports kept on the managed bridge (the internal development record) -------------------


def bridge_only_record(**overrides):
    return persisted_record(**{
        'schema': 4, 'image_os': 'freebsd', 'origin': None,
        'network': {'mode': 'managed', 'bridge_address': '10.88.255.254'},
        'ports': [
            {'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'},
            {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
        ],
        'healthcheck': {
            'type': 'HTTP', 'scheme': 'http', 'container_port': 6379,
            'host_port': None, 'path': '/',
        },
        **overrides,
    })


def test_record_keeps_a_declared_port_on_the_bridge():
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}
    record = bridge_only_record()
    assert ApplicationsService._validate_record(config, record, 'demo') is record

    # LAN mode probes its own address, so it needs no bridge pin
    assert ApplicationsService._validate_record(config, lan_record(
        ports=record['ports'], healthcheck=record['healthcheck'],
    ), 'demo')

    # the probe address of an unpublished health check is the pin
    with pytest.raises(ValueError, match='needs a pinned bridge address'):
        ApplicationsService._validate_record(
            config, bridge_only_record(network={'mode': 'managed'}), 'demo',
        )
    # the binding still names the declared port exactly
    with pytest.raises(ValueError, match='invalid declared health check'):
        ApplicationsService._validate_record(config, bridge_only_record(healthcheck={
            **record['healthcheck'], 'host_port': 16379,
        }), 'demo')
    for port in (
        {'container_port': 6379, 'protocol': 'tcp'},
        {'host_port': 0, 'container_port': 6379, 'protocol': 'tcp'},
        {'host_port': '6379', 'container_port': 6379, 'protocol': 'tcp'},
        {'host_port': None, 'container_port': None, 'protocol': 'tcp'},
    ):
        with pytest.raises(ValueError, match='invalid declared port'):
            ApplicationsService._validate_record(
                config, bridge_only_record(ports=[port], healthcheck=None), 'demo',
            )


def test_health_probe_of_an_unpublished_port_goes_to_the_bridge_address():
    probe = ApplicationsService._record_healthcheck_probe(bridge_only_record())
    assert probe['probe_host'] == '10.88.255.254'
    assert probe['probe_port'] == 6379

    published = bridge_only_record(healthcheck={
        'type': 'HTTP', 'scheme': 'http', 'container_port': 80, 'host_port': 18080, 'path': '/',
    })
    assert 'probe_host' not in ApplicationsService._record_healthcheck_probe(published)


@pytest.mark.asyncio
async def test_unpublished_ports_take_no_part_in_the_host_port_rules():
    service, middleware = service_with_middleware()
    service._read_records = Mock(return_value=([
        bridge_only_record(name='other', healthcheck=None),
    ], []))
    service._container_exists = AsyncMock(return_value=False)
    service._reserved_management_ports = AsyncMock(return_value={(6379, 'tcp')})
    # every host port is "in use": an unpublished port must not ask
    middleware.run_in_thread.return_value = False
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}

    await service._validate_install(config, install_data(ports=[
        {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
        {'host_port': None, 'container_port': 6380, 'protocol': 'tcp'},
    ]))
    middleware.run_in_thread.assert_not_called()

    # a portal is a link on the host: it cannot name a port that is not published
    with pytest.raises(ValidationErrors, match='Portal port must reference'):
        await service._validate_install(config, install_data(
            ports=[{'host_port': None, 'container_port': 80, 'protocol': 'tcp'}],
            portal={'scheme': 'http', 'port': 80, 'path': '/'},
        ))

    # the published neighbours are checked as before
    middleware.run_in_thread.return_value = True
    with pytest.raises(ValidationErrors, match='already assigned'):
        await service._validate_install(config, install_data(ports=[
            {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
            {'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'},
        ]))


@pytest.mark.asyncio
async def test_reconfigure_that_unpublishes_a_port_frees_it_and_checks_only_the_rest():
    service, middleware = service_with_middleware()
    current = bridge_only_record(healthcheck=None, ports=[
        {'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'},
        {'host_port': 16379, 'container_port': 6379, 'protocol': 'tcp'},
    ])
    neighbour = bridge_only_record(name='other', healthcheck=None, ports=[
        {'host_port': None, 'container_port': 80, 'protocol': 'tcp'},
    ])
    service._read_records = Mock(return_value=([current, neighbour], []))
    service._reserved_management_ports = AsyncMock(return_value=set())
    middleware.run_in_thread.return_value = False
    config = {'pool': 'tank', 'subnet': '10.88.0.0/16'}

    await service._validate_reconfigure(config, current, [
        {'host_port': 18080, 'container_port': 80, 'protocol': 'tcp'},
        {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
    ], current['network'])
    middleware.run_in_thread.assert_not_called()

    with pytest.raises(ValidationErrors, match='already in use'):
        await service._validate_reconfigure(config, current, [
            {'host_port': 18081, 'container_port': 80, 'protocol': 'tcp'},
            {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
        ], current['network'])
