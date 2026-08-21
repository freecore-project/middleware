import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from middlewared.plugins import sysdataset


def completed(returncode):
    return SimpleNamespace(returncode=returncode, stdout=b'', stderr=b'')


async def copy_with(returncodes, attempts=sysdataset.COPY_ATTEMPTS):
    run = AsyncMock(side_effect=[completed(rc) for rc in returncodes])
    with patch.object(sysdataset, 'run', run):
        cp = await sysdataset.copy_system_dataset('/var/db/system', '/tmp/system.new', logging.getLogger('test'), attempts)
    return cp.returncode, run


@pytest.mark.asyncio
async def test_a_clean_copy_runs_rsync_once():
    rc, run = await copy_with([0])
    assert rc == 0
    run.assert_awaited_once_with('rsync', '-az', '/var/db/system/', '/tmp/system.new', check=False)


@pytest.mark.asyncio
async def test_a_file_rotated_during_the_copy_is_copied_again():
    rc, run = await copy_with([sysdataset.RSYNC_VANISHED, 0])
    assert rc == 0
    assert run.await_count == 2
    assert run.await_args_list[0] == run.await_args_list[1]


@pytest.mark.asyncio
async def test_another_rsync_failure_is_returned_without_a_retry():
    rc, run = await copy_with([23])
    assert rc == 23
    assert run.await_count == 1


@pytest.mark.asyncio
async def test_files_still_vanishing_after_every_pass_still_fail():
    rc, run = await copy_with([sysdataset.RSYNC_VANISHED] * sysdataset.COPY_ATTEMPTS)
    assert rc == sysdataset.RSYNC_VANISHED
    assert run.await_count == sysdataset.COPY_ATTEMPTS


@pytest.mark.asyncio
async def test_a_failure_on_the_second_pass_is_returned():
    rc, run = await copy_with([sysdataset.RSYNC_VANISHED, 12])
    assert rc == 12
    assert run.await_count == 2
