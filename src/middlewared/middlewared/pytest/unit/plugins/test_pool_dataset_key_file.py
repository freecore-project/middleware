import io
import json
from unittest.mock import AsyncMock, Mock

import pytest

import sys
import types

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # pool.py imports py-libzfs at module level; these units never enter it. Keep them runnable off a FreeBSD box.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.pool import PoolDatasetService
from middlewared.service_exception import ValidationErrors


def key_file_job(data):
    job = Mock()
    job.pipes.input.r = io.BytesIO(data)
    return job


@pytest.mark.asyncio
@pytest.mark.parametrize('key', ['a' * 64, '0' + 'a' * 63])
async def test_change_key_reads_key_from_key_file(key):
    middleware = Mock()
    service = PoolDatasetService(middleware)
    calls = {}

    async def call(method, *args):
        calls[method] = args
        if method == 'pool.dataset.query':
            return []
        if method == 'pool.dataset.validate_encryption_data':
            return service.validate_encryption_data(*args)

    middleware.call = AsyncMock(side_effect=call)
    middleware.call_hook = AsyncMock()
    service.get_instance = AsyncMock(return_value={
        'encrypted': True, 'locked': False, 'key_format': {'value': 'HEX'},
    })
    service.insert_or_update_encrypted_record = AsyncMock()

    await service.change_key(key_file_job(key.encode()), 'tank/ds', {'key_file': True})

    assert calls['zfs.dataset.change_key'][1]['key'] == key
    assert calls['zfs.dataset.change_key'][1]['encryption_properties']['keyformat'] == 'hex'
    record = service.insert_or_update_encrypted_record.await_args.args[0]
    assert (record['name'], record['encryption_key'], record['key_format']) == ('tank/ds', key, 'HEX')


def encryption_dict(**kwargs):
    return {
        'enabled': True, 'passphrase': None, 'generate_key': False, 'key_file': True,
        'pbkdf2iters': 350000, 'algorithm': 'AES-256-GCM', 'key': None, **kwargs,
    }


@pytest.mark.parametrize('data,key', [
    (b'0' + b'a' * 63, '0' + 'a' * 63),
    (b'00' + b'F' * 62 + b'\n', '00' + 'f' * 62),
])
def test_validate_encryption_data_key_file_accepts_hex_key(data, key):
    verrors = ValidationErrors()
    opts = PoolDatasetService(Mock()).validate_encryption_data(
        key_file_job(data), verrors, encryption_dict(), 'change_key_options',
    )

    assert not verrors
    assert opts['key'] == key


@pytest.mark.parametrize('data', [
    b'a' * 63,
    b'g' * 64,
    b'0x' + b'a' * 62,
    b' ' + b'a' * 63,
    b'aa_' + b'a' * 61,
])
def test_validate_encryption_data_key_file_rejects_invalid_key(data):
    verrors = ValidationErrors()
    opts = PoolDatasetService(Mock()).validate_encryption_data(
        key_file_job(data), verrors, encryption_dict(), 'change_key_options',
    )

    assert opts == {}
    assert [attribute for attribute, errmsg, errno in verrors] == ['change_key_options.key_file']


def test_retrieve_keys_from_file_reads_more_than_10_kib():
    keys = {f'tank/encrypted/dataset{i:04d}': 'a' * 64 for i in range(200)}
    data = json.dumps(keys).encode()
    assert len(data) > 10240

    assert PoolDatasetService(Mock())._retrieve_keys_from_file(key_file_job(data)) == keys


def test_export_keys_does_not_write_keys_to_disk(monkeypatch):
    keys = {'tank/ds': 'a' * 64}
    middleware = Mock()
    service = PoolDatasetService(middleware)
    service.query_encrypted_roots_keys = Mock(return_value=keys)
    monkeypatch.setattr(
        'middlewared.plugins.pool.tempfile.NamedTemporaryFile',
        Mock(side_effect=AssertionError('keys written to a temporary file')),
    )
    job = Mock()
    job.pipes.output.w = io.BytesIO()

    service.export_keys(job, 'tank')

    assert json.loads(job.pipes.output.w.getvalue()) == keys
