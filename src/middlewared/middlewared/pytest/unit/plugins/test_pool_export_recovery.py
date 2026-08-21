import asyncio
import copy
import errno
from unittest.mock import AsyncMock, Mock, call

import pytest

from middlewared.common.attachment import FSAttachmentDelegate
from middlewared.plugins.bastille_freebsd import BastilleFSAttachmentDelegate
from middlewared.plugins.pool import PoolDatasetService, PoolService
from middlewared.service_exception import CallError


def export_fixture(monkeypatch, *, previous=None, imported=True, same_guid=True, cascade=False):
    middleware = Mock()
    middleware.call = AsyncMock()
    service = PoolService(middleware)
    pool = {'id': 1, 'name': 'tank', 'guid': '123', 'path': '/mnt/tank'}
    service.get_instance = AsyncMock(return_value=pool)
    delegate = Mock(spec=FSAttachmentDelegate)
    delegate.name = 'bastille'
    delegate.title = 'Bastille'
    delegate.query = AsyncMock(return_value=[{'id': 'bastille:boot-enabled'}])
    delegate.toggle = AsyncMock()
    delegate.delete = AsyncMock()
    delegate.rollback_export = AsyncMock(return_value=True)
    monkeypatch.setattr(PoolDatasetService, 'attachment_delegates', [delegate])
    persisted = copy.deepcopy(previous)

    async def dispatch(method, *args):
        nonlocal persisted
        if method == 'pool.query':
            return 1
        if method == 'system.is_freenas':
            return True
        if method == 'keyvalue.has_key':
            return previous is not None
        if method == 'keyvalue.get':
            return copy.deepcopy(previous)
        if method == 'keyvalue.set':
            persisted = copy.deepcopy(args[1])
            return
        if method == 'keyvalue.delete':
            persisted = None
            return
        if method == 'pool.dataset.kill_processes':
            raise CallError('Busy application', errno.EBUSY)
        if method == 'zfs.pool.query':
            assert args == ([['name', '=', 'tank']],)
            return [{'name': 'tank', 'guid': '123' if same_guid else '456'}] if imported else []
        raise AssertionError(method)

    middleware.call.side_effect = dispatch
    options = {'cascade': cascade, 'destroy': False, 'restart_services': True}
    return service, middleware, delegate, options, lambda: persisted


@pytest.mark.asyncio
@pytest.mark.parametrize('previous', [None, {'bastille': ['older-intent'], 'nfs': [17]}])
async def test_failed_export_restores_delegate_and_exact_prior_import_intent(monkeypatch, previous):
    service, middleware, delegate, options, persisted = export_fixture(monkeypatch, previous=previous)
    with pytest.raises(CallError, match='Busy application') as error:
        await service.export(Mock(), 1, options)
    assert error.value.errno == errno.EBUSY
    delegate.rollback_export.assert_awaited_once_with(delegate.query.return_value)
    assert persisted() == previous
    assert call('zfs.pool.export', 'tank') not in middleware.call.await_args_list


@pytest.mark.asyncio
async def test_partially_failed_toggle_is_also_recovered(monkeypatch):
    service, middleware, delegate, options, persisted = export_fixture(monkeypatch)
    delegate.toggle.side_effect = CallError('Only some workloads stopped')
    with pytest.raises(CallError, match='Only some workloads stopped'):
        await service.export(Mock(), 1, options)
    delegate.rollback_export.assert_awaited_once()
    assert persisted() is None
    assert not any(c.args[0] == 'pool.dataset.kill_processes' for c in middleware.call.await_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize('imported,same_guid', [(False, True), (True, False)])
async def test_recovery_never_restarts_exported_or_replaced_pool(monkeypatch, imported, same_guid):
    service, _, delegate, options, persisted = export_fixture(
        monkeypatch, imported=imported, same_guid=same_guid,
    )
    with pytest.raises(CallError, match='Busy application'):
        await service.export(Mock(), 1, options)
    delegate.rollback_export.assert_not_awaited()
    assert persisted() == {'bastille': ['bastille:boot-enabled']}


@pytest.mark.asyncio
async def test_failed_recovery_preserves_import_intent_and_reports_both_failures(monkeypatch):
    service, _, delegate, options, persisted = export_fixture(monkeypatch)
    delegate.rollback_export.side_effect = CallError('Owned store is unavailable')
    with pytest.raises(CallError, match='Busy application.*Owned store is unavailable'):
        await service.export(Mock(), 1, options)
    assert persisted() == {'bastille': ['bastille:boot-enabled']}


@pytest.mark.asyncio
async def test_destructive_attachment_delete_is_not_rolled_back(monkeypatch):
    service, _, delegate, options, _ = export_fixture(monkeypatch, cascade=True)
    with pytest.raises(CallError, match='Busy application'):
        await service.export(Mock(), 1, options)
    delegate.delete.assert_awaited_once()
    delegate.rollback_export.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_export_waits_for_recovery_before_exiting(monkeypatch):
    service, _, delegate, options, persisted = export_fixture(monkeypatch)
    started = asyncio.Event()
    release = asyncio.Event()

    async def recover(attachments):
        started.set()
        await release.wait()
        return True

    delegate.toggle.side_effect = asyncio.CancelledError()
    delegate.rollback_export.side_effect = recover
    task = asyncio.create_task(service.export(Mock(), 1, options))
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert persisted() is None


@pytest.mark.asyncio
async def test_existing_delegates_do_not_opt_into_export_recovery():
    assert await FSAttachmentDelegate(Mock()).rollback_export([{'id': 1}]) is False


@pytest.mark.asyncio
@pytest.mark.parametrize('boot', [True, False])
async def test_bastille_recovers_only_prior_running_jails_after_revalidation(boot):
    middleware = Mock()
    job = Mock()
    job.wait = AsyncMock()

    async def dispatch(method, *args):
        if method == 'bastille.pool_stop_running':
            return ['alreadyup', 'web']
        if method == 'bastille.pool_available':
            return {'matched': True, 'enabled': False}
        if method == 'service.update':
            assert args == ('bastille', {'enable': boot})
            return True
        if method == 'bastille.running_jails_strict':
            return ['alreadyup']
        if method == 'bastille.start':
            assert args == ('web',)
            return job
        raise AssertionError(method)

    middleware.call = AsyncMock(side_effect=dispatch)
    delegate = BastilleFSAttachmentDelegate(middleware)
    assert await delegate.rollback_export([{
        'pool': 'tank', 'boot_enabled': boot, 'export_stop_attempted': True,
    }]) is True
    assert middleware.call.await_args_list[1] == call('bastille.pool_available', 'tank')
    job.wait.assert_awaited_once_with(raise_error=True)


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', [CallError('Changed store'), None])
async def test_bastille_does_not_recover_unvalidated_or_inactive_store(failure):
    middleware = Mock()

    async def dispatch(method, *args):
        if method == 'bastille.pool_stop_running':
            return ['web']
        if failure:
            raise failure
        return {'matched': False}

    middleware.call = AsyncMock(side_effect=dispatch)
    delegate = BastilleFSAttachmentDelegate(middleware)
    attachments = [{'pool': 'tank', 'boot_enabled': True, 'export_stop_attempted': True}]
    if failure:
        with pytest.raises(CallError, match='Changed store'):
            await delegate.rollback_export(attachments)
    else:
        assert await delegate.rollback_export(attachments) is False
    assert middleware.call.await_args_list == [
        call('bastille.pool_stop_running', 'tank'), call('bastille.pool_available', 'tank'),
    ]
