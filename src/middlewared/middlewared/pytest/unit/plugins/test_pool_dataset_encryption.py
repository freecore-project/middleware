import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # The zfs.dataset checks below take a dataset object and do not enter py-libzfs.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.afp import AFPFSAttachmentDelegate
from middlewared.plugins.pool import PoolDatasetService
from middlewared.plugins.zfs import ZFSDatasetService
from middlewared.service_exception import CallError, ValidationErrors


def pool_dataset_service():
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.call_hook = AsyncMock()
    middleware.run_in_thread = AsyncMock(side_effect=lambda method, *args: method(*args))
    return PoolDatasetService(middleware)


@pytest.mark.asyncio
async def test_inherit_refuses_passphrase_parent_root_with_key_encrypted_child_roots():
    service = pool_dataset_service()
    datasets = {
        'tank/pass/hex': {
            'encrypted': True, 'encryption_root': 'tank/pass/hex', 'locked': False,
            'key_format': {'value': 'HEX'},
        },
        'tank/pass': {
            'encrypted': True, 'encryption_root': 'tank/pass', 'locked': False,
            'key_format': {'value': 'PASSPHRASE'},
        },
    }
    service.get_instance = AsyncMock(side_effect=lambda id: datasets[id])
    service.query = Mock(return_value=[
        {'name': 'tank/pass/hex/child', 'encryption_root': 'tank/pass/hex/child'},
    ])

    with pytest.raises(CallError, match='has children which are encrypted with a key'):
        await service.inherit_parent_encryption_properties('tank/pass/hex')

    service.middleware.call.assert_not_awaited()


@pytest.mark.parametrize('method,ds,message', [
    (
        'common_encryption_checks', SimpleNamespace(name='tank/plain', encrypted=False, key_loaded=False),
        'tank/plain is not encrypted',
    ),
    (
        'common_load_dataset_checks', SimpleNamespace(name='tank/enc', encrypted=True, key_loaded=True),
        'tank/enc key is already loaded',
    ),
])
def test_encryption_checks_name_the_dataset(method, ds, message):
    service = ZFSDatasetService(Mock())

    with pytest.raises(CallError) as error:
        getattr(service, method)(ds)

    assert error.value.errmsg == message


@pytest.mark.asyncio
async def test_change_key_reads_key_from_key_file():
    service = pool_dataset_service()
    service.get_instance = AsyncMock(return_value={
        'encrypted': True, 'locked': False, 'key_format': {'value': 'HEX'},
    })
    service.insert_or_update_encrypted_record = AsyncMock()
    key = 'ab' * 32
    job = Mock()
    job.pipes.input.r.read.return_value = key.encode()

    async def dispatch(name, *args):
        if name == 'pool.dataset.query':
            return []
        if name == 'pool.dataset.validate_encryption_data':
            return service.validate_encryption_data(*args)
        if name == 'zfs.dataset.change_key':
            return None
        raise AssertionError(name)

    service.middleware.call.side_effect = dispatch

    await service.change_key(job, 'tank/enc', {'key_file': True})

    job.check_pipe.assert_called_once_with('input')
    service.middleware.call.assert_any_await('zfs.dataset.change_key', 'tank/enc', {
        'encryption_properties': {'keyformat': 'hex', 'keylocation': 'prompt'},
        'key': key, 'load_key': False,
    })


def test_sync_db_keys_keeps_key_of_encryption_root_whose_check_raised():
    service = pool_dataset_service()
    key = 'ab' * 32
    service.query_encrypted_roots_keys = Mock(return_value={
        'tank/raised': key, 'tank/invalid': key, 'tank/gone': key,
    })
    check_key_job = Mock(error=None, result=[
        {'result': None, 'error': '[EFAULT] check failed'},
        {'result': False, 'error': None},
        {'result': None, 'error': '[EFAULT] Failed to check key for tank/gone: dataset does not exist'},
    ])
    removed = []

    def call_sync(name, *args):
        if name == 'failover.is_single_master_node':
            return True
        if name == 'pool.query':
            return [{'name': 'tank'}]
        if name == 'zfs.dataset.query' and args[1]['extra'].get('flat') is False:
            return [{'id': 'tank'}]
        if name == 'zfs.dataset.query':
            return [
                {'name': 'tank/raised', 'encryption_root': 'tank/raised'},
                {'name': 'tank/invalid', 'encryption_root': 'tank/invalid'},
            ]
        if name == 'zfs.dataset.bulk_process':
            return check_key_job
        if name == 'pool.dataset.delete_encrypted_datasets_from_db':
            return removed.append(args[0])
        raise AssertionError(name)

    service.middleware.call_sync = Mock(side_effect=call_sync)

    service.sync_db_keys(Mock())

    assert removed == [[['name', 'in', ['tank/invalid', 'tank/gone']]]]


@pytest.mark.asyncio
async def test_afp_lock_stop_without_attachments_does_not_restart_afp():
    delegate = AFPFSAttachmentDelegate(Mock())
    delegate._service_change = AsyncMock()

    await delegate.stop([])

    delegate._service_change.assert_not_awaited()

    await delegate.stop([{'id': 1}])

    delegate._service_change.assert_awaited_once_with('afp', 'restart')


def test_encryption_summary_reports_errors_under_its_own_schema():
    service = pool_dataset_service()

    with pytest.raises(ValidationErrors) as error:
        service.encryption_summary(Mock(), 'tank', {
            'datasets': [{'name': 'tank/enc', 'key': 'ab' * 32, 'passphrase': 'passphrase'}],
        })

    assert [e.attribute for e in error.value.errors] == [
        'encryption_root_summary_options.datasets.0.dataset.key',
    ]
