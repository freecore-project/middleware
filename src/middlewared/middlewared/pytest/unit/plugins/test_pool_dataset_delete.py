import errno
import sys
import types
from unittest.mock import AsyncMock, Mock, call

import pytest

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # pool.dataset.delete is exercised with every middleware call mocked. Keep it
    # runnable on developer platforms where that FreeBSD extension is unavailable.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.common.attachment import FSAttachmentDelegate
from middlewared.plugins.applications_freebsd import ApplicationsFSAttachmentDelegate
from middlewared.plugins.pool import PoolDatasetService
from middlewared.service_exception import CallError

SNAPSHOTS_REFUSAL = (
    "Failed to delete dataset: cannot destroy 'tank/work': filesystem has children\n"
    "use '-r' to destroy the following datasets:\ntank/work@auto-1"
)
CLONES_REFUSAL = (
    "Failed to delete dataset: cannot destroy 'tank/work': filesystem has dependent clones\n"
    "use '-R' to destroy the following datasets:\ntank/work-clone"
)


def delete_fixture(monkeypatch, *, children=(), refusal=None, delegates=None):
    middleware = Mock()
    service = PoolDatasetService(middleware)
    service.get_instance = AsyncMock(return_value={
        'id': 'tank/work', 'name': 'tank/work', 'mountpoint': '/mnt/tank/work', 'children': list(children),
    })
    share = Mock(spec=FSAttachmentDelegate)
    share.query = AsyncMock(return_value=[{'id': 7, 'path': '/mnt/tank/work'}])
    share.check_delete = AsyncMock()
    share.delete = AsyncMock()
    monkeypatch.setattr(PoolDatasetService, 'attachment_delegates', [share] + list(delegates or []))

    async def dispatch(method, *args):
        if method == 'zfs.dataset.delete':
            if refusal:
                raise CallError(refusal)
            return
        raise AssertionError(method)

    middleware.call = AsyncMock(side_effect=dispatch)
    return service, middleware, share


@pytest.mark.asyncio
@pytest.mark.parametrize('recursive,refusal', [(False, SNAPSHOTS_REFUSAL), (True, CLONES_REFUSAL)])
async def test_attachments_survive_a_destroy_that_zfs_refuses(monkeypatch, recursive, refusal):
    service, middleware, share = delete_fixture(monkeypatch, refusal=refusal)
    with pytest.raises(CallError) as error:
        await service.do_delete('tank/work', {'recursive': recursive, 'force': False})
    assert str(error.value) == f'[EFAULT] {refusal}'
    # The dataset is still there, so is everything that points into it.
    share.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_children_check_looks_only_at_the_dataset_itself(monkeypatch):
    service, middleware, share = delete_fixture(monkeypatch, children=[{'id': 'tank/work/child'}])
    with pytest.raises(CallError, match='filesystem has children') as error:
        await service.do_delete('tank/work', {'recursive': False, 'force': False})
    assert error.value.errno == errno.ENOTEMPTY
    assert not any(c.args[0] == 'zfs.dataset.query' for c in middleware.call.await_args_list)
    share.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refusing_delegate_stops_the_delete_before_any_attachment_is_deleted(monkeypatch):
    middleware = Mock()
    applications = ApplicationsFSAttachmentDelegate(middleware)
    applications.query = AsyncMock(return_value=[{'id': 'applications:first:data', 'pool': 'tank', 'protected': True}])
    service, middleware, share = delete_fixture(monkeypatch, delegates=[applications])
    with pytest.raises(CallError, match='referenced by installed applications'):
        await service.do_delete('tank/work', {'recursive': True, 'force': False})
    share.delete.assert_not_awaited()
    assert not any(
        c.args[0] == 'zfs.dataset.delete' and not c.args[2].get('dry_run') for c in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_attachments_are_deleted_between_the_dry_run_and_the_destroy(monkeypatch):
    service, middleware, share = delete_fixture(monkeypatch)
    order = Mock()
    order.attach_mock(middleware.call, 'call')
    order.attach_mock(share.delete, 'delete')
    await service.do_delete('tank/work', {'recursive': True, 'force': True})
    assert order.mock_calls == [
        call.call('zfs.dataset.delete', 'tank/work', {'force': True, 'recursive': True, 'dry_run': True}),
        call.delete([{'id': 7, 'path': '/mnt/tank/work'}]),
        call.call('zfs.dataset.delete', 'tank/work', {'force': True, 'recursive': True}),
    ]
