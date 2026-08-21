"""the internal development record: Stop ends the Shell's exec session instead of failing on it.

``podman stop`` ends the application's processes but refuses to clean the container up while an
exec session (the Shell) is alive; the jail and the bridge address reservation then stay and the
next start fails. The helper kills what is left in the jail and cleans the container up."""
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import applications_freebsd
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError

CONFIG = {'pool': 'tank'}
CID = 'a61c55a31f165ab024d0031bdb86167f8e5022bda3d6380e8c05176314a86d3a'
# podman 5.8.8 on a test VM, as _podman raises it
REFUSAL = CallError(
    f'Podman stop failed: Error: container {CID} has active exec sessions, refusing to clean up: '
    'container state improper'
)


def completed(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def service():
    result = ApplicationsService(Mock())
    result.logger = Mock()
    return result


@pytest.mark.asyncio
async def test_a_clean_stop_is_one_podman_call():
    svc = service()
    svc._podman = AsyncMock(return_value=completed())
    with patch.object(applications_freebsd, 'run', AsyncMock()) as run:
        await svc._stop_container(CONFIG, CID)
    svc._podman.assert_awaited_once_with(CONFIG, 'stop', CID)
    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_open_exec_session_is_killed_and_the_container_cleaned_up():
    svc = service()
    svc._podman = AsyncMock(side_effect=[REFUSAL, completed()])
    with patch.object(applications_freebsd, 'run', AsyncMock(return_value=completed())) as run:
        await svc._stop_container(CONFIG, CID)
    # the jail is named by the container id; pkill -j takes a jail name
    run.assert_awaited_once_with(['pkill', '-KILL', '-j', CID], check=False)
    assert svc._podman.await_args_list[1].args == (CONFIG, 'container', 'cleanup', CID)
    svc.logger.info.assert_called_once()


@pytest.mark.asyncio
async def test_any_other_stop_failure_is_raised_as_before():
    svc = service()
    svc._podman = AsyncMock(side_effect=CallError('Podman stop failed: Error: no such container'))
    with patch.object(applications_freebsd, 'run', AsyncMock()) as run:
        with pytest.raises(CallError, match='Podman stop failed: Error: no such container'):
            await svc._stop_container(CONFIG, CID)
    run.assert_not_awaited()
    assert svc._podman.await_count == 1


@pytest.mark.asyncio
async def test_a_cleanup_that_fails_surfaces():
    svc = service()
    svc._podman = AsyncMock(side_effect=[REFUSAL, CallError('Podman container failed: boom')])
    with patch.object(applications_freebsd, 'run', AsyncMock(return_value=completed())):
        with pytest.raises(CallError, match='boom'):
            await svc._stop_container(CONFIG, CID)


def test_every_stop_site_uses_the_helper():
    source = inspect.getsource(applications_freebsd)
    # the one podman stop lives in the helper
    assert source.count("_podman(config, 'stop'") == 1
    # stop, the update's old container, the update's replacement when it should stay stopped, unconfigure
    assert source.count('self._stop_container(') == 4
