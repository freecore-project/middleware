from subprocess import CompletedProcess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import bastille_freebsd
from middlewared.plugins.bastille_.utils import MANAGED_PROPERTY


@pytest.mark.asyncio
async def test_managed_dataset_owners_queries_filesystems_only():
    result = CompletedProcess(
        [],
        0,
        (
            'tank/bastille/jails/example\tbastille:jail:example\tlocal\n'
            'tank/bastille/jails/example/root\tbastille:jail:example:root\tlocal\n'
        ),
        '',
    )
    service = bastille_freebsd.BastilleService(Mock())

    with patch.object(bastille_freebsd, 'run', AsyncMock(return_value=result)) as run:
        owners = await service._managed_dataset_owners('tank')

    run.assert_awaited_once_with(
        '/sbin/zfs', 'get', '-H', '-t', 'filesystem', '-o', 'name,value,source', '-r',
        MANAGED_PROPERTY, 'tank/bastille', check=False, encoding='utf8',
    )
    assert owners == {
        'tank/bastille/jails/example': ('bastille:jail:example', 'local'),
        'tank/bastille/jails/example/root': ('bastille:jail:example:root', 'local'),
    }
