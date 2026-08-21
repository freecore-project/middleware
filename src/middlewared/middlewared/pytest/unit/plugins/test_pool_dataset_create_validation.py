"""pool.dataset.create reports a missing parent or a readonly parent as validation errors.

Without an existing parent the encryption checks queried it with `get: True`, so the caller got a
bare MatchNotFound (an empty message) instead of the validation error that was already recorded.
"""
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # Nothing here enters py-libzfs; keep it runnable where that FreeBSD extension is unavailable.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.pool import PoolDatasetService
from middlewared.service_exception import ValidationErrors
from middlewared.utils import filter_list


def dataset(name, readonly='off'):
    return {
        'id': name, 'name': name, 'encrypted': False, 'key_loaded': False,
        'properties': {'readonly': {'rawvalue': readonly}},
    }


DATASETS = [dataset('tank'), dataset('tank/ro', readonly='on')]


def service():
    middleware = Mock()

    async def call(method, *args):
        if method == 'zfs.dataset.query':
            # Like zfs.dataset.query, whose results go through filter_list (`get: True` included).
            return filter_list(DATASETS, *args)
        if method == 'pool.dataset.validate_encryption_data':
            return None
        raise AssertionError(f'unexpected call {method}')

    middleware.call = AsyncMock(side_effect=call)
    return PoolDatasetService(middleware)


async def create(name):
    return await PoolDatasetService.do_create.wraps(service(), None, {
        'name': name, 'type': 'FILESYSTEM', 'share_type': 'GENERIC',
        'encryption': False, 'inherit_encryption': True, 'encryption_options': {},
    })


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['nopool/new', 'tank/missing/new'])
async def test_missing_parent_is_a_validation_error(name):
    with pytest.raises(ValidationErrors) as error:
        await create(name)

    assert [(e.attribute, e.errmsg) for e in error.value.errors] == [(
        'pool_dataset_create.name', 'Please specify a pool which exists for the dataset/volume to be created',
    )]


@pytest.mark.asyncio
async def test_readonly_parent_names_the_dataset_being_created():
    with pytest.raises(ValidationErrors) as error:
        await create('tank/ro/new')

    assert [(e.attribute, e.errmsg) for e in error.value.errors] == [
        ('pool_dataset_create.readonly', 'Turn off readonly mode on tank/ro to create tank/ro/new'),
    ]
