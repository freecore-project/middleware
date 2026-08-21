import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from middlewared.plugins import system_rollback


class Middleware(dict):

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger('middlewared.pytest.system_rollback_lifecycle')

    async def call(self, name, *args):
        return await self[name](*args)


def service_for_boot_capture():
    middleware = Middleware()
    middleware['alert.oneshot_create'] = AsyncMock()
    middleware['alert.oneshot_delete'] = AsyncMock()
    return system_rollback.SystemRollbackService(middleware)


@pytest.mark.asyncio
async def test_boot_capture_is_inert_without_arrival_marker(tmp_path):
    service = service_for_boot_capture()
    service.capture = AsyncMock()

    with patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(tmp_path / 'absent')):
        assert await service.capture_on_boot() is None

    service.capture.assert_not_awaited()
    service.middleware['alert.oneshot_create'].assert_not_awaited()
    service.middleware['alert.oneshot_delete'].assert_not_awaited()


@pytest.mark.asyncio
async def test_boot_capture_consumes_non_cd_marker_before_capturing(tmp_path):
    service = service_for_boot_capture()
    captured = {'id': 1, 'origin_be': '13.3-U1.2'}
    service.capture = AsyncMock(return_value=captured)
    marker = tmp_path / 'arrival'
    marker.write_text('unknown\n')

    with patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)):
        assert await service.capture_on_boot() == captured

    assert not marker.exists()
    service.capture.assert_awaited_once_with('unknown', None)
    service.middleware['alert.oneshot_delete'].assert_awaited_once_with(
        system_rollback.CAPTURE_FAILED_ALERT, None,
    )


@pytest.mark.asyncio
async def test_boot_capture_uses_source_timestamp_from_arrival_marker(tmp_path):
    service = service_for_boot_capture()
    captured = {'id': 1, 'origin_be': '13.3-U1.2'}
    service.capture = AsyncMock(return_value=captured)
    marker = tmp_path / 'arrival'
    marker.write_text('unknown 1786743307\n')

    with patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)):
        assert await service.capture_on_boot() == captured

    assert not marker.exists()
    service.capture.assert_awaited_once_with('unknown', 1786743307)


@pytest.mark.asyncio
async def test_boot_capture_consumes_cd_marker_without_creating_window(tmp_path):
    service = service_for_boot_capture()
    service.capture = AsyncMock()
    marker = tmp_path / 'arrival'
    marker.write_text('cd_upgrade\n')

    with patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)):
        assert await service.capture_on_boot() is None

    assert not marker.exists()
    service.capture.assert_not_awaited()
    service.middleware['alert.oneshot_delete'].assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('contents', [
    'not-an-arrival-path\n',
    'unknown not-a-timestamp\n',
    'unknown -1\n',
    'unknown 1786743307 trailing-data\n',
])
async def test_boot_capture_rejects_and_consumes_malformed_marker(tmp_path, contents):
    service = service_for_boot_capture()
    service.capture = AsyncMock()
    marker = tmp_path / 'arrival'
    marker.write_text(contents)

    with (
        patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)),
        pytest.raises(system_rollback.CallError, match='marker is invalid'),
    ):
        await service.capture_on_boot()

    assert not marker.exists()
    service.capture.assert_not_awaited()
    service.middleware['alert.oneshot_create'].assert_awaited_once_with(
        system_rollback.CAPTURE_FAILED_ALERT, None,
    )


@pytest.mark.asyncio
async def test_failed_boot_capture_is_alerted_and_never_retried(tmp_path):
    service = service_for_boot_capture()
    service.capture = AsyncMock(side_effect=RuntimeError('snapshot failed'))
    marker = tmp_path / 'arrival'
    marker.write_text('unknown\n')

    with (
        patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)),
        pytest.raises(RuntimeError, match='snapshot failed'),
    ):
        await service.capture_on_boot()

    assert not marker.exists()
    service.middleware['alert.oneshot_create'].assert_awaited_once_with(
        system_rollback.CAPTURE_FAILED_ALERT, None,
    )


@pytest.mark.asyncio
async def test_boot_capture_refuses_when_marker_cannot_be_consumed(tmp_path):
    service = service_for_boot_capture()
    service.capture = AsyncMock()
    marker = tmp_path / 'arrival'
    marker.write_text('unknown\n')

    with (
        patch.object(system_rollback, 'ARRIVAL_PATH_MARKER', str(marker)),
        patch.object(system_rollback.os, 'unlink', side_effect=PermissionError('read-only marker')),
        pytest.raises(PermissionError, match='read-only marker'),
    ):
        await service.capture_on_boot()

    service.capture.assert_not_awaited()
    service.middleware['alert.oneshot_create'].assert_awaited_once_with(
        system_rollback.CAPTURE_FAILED_ALERT, None,
    )


def test_cleanup_waits_until_after_middleware_start():
    descriptor = system_rollback.SystemRollbackService.cleanup._periodic
    assert descriptor.interval == 3600
    assert descriptor.run_on_start is False


def test_pool_import_captures_and_cleans_before_systemdataset_setup():
    root = Path(__file__).parents[6]
    source = (root / 'src/middlewared/middlewared/plugins/pool.py').read_text()
    capture = source.index("call_sync('system.rollback.capture_on_boot')")
    cleanup = source.index("call_sync('system.rollback.cleanup')", capture)
    checkpoint = source.index("call_sync('etc.generate_checkpoint', 'pool_import')", cleanup)
    assert capture < cleanup < checkpoint


def test_ix_update_persists_arrival_only_for_an_os_update():
    root = Path(__file__).parents[6]
    source = (root / 'src/freenas/etc/ix.rc.d/ix-update').read_text()
    upload_branch = source.index('if [ $is_upload -eq 1 ]')
    update_branch = source.index('record_rollback_arrival', upload_branch)
    consume_need_update = source.index('rm -f $NEED_UPDATE_SENTINEL', update_branch)
    assert upload_branch < update_branch < consume_need_update
    assert 'recorded_at=$(/bin/date +%s)' in source
    assert "printf '%s %s\\n' \"$arrival\" \"$recorded_at\"" in source


@pytest.mark.asyncio
async def test_capture_anchors_window_to_source_timestamp():
    service = service_for_boot_capture()
    captured_epoch = 1786743307
    captured_at = datetime.utcfromtimestamp(captured_epoch)
    snapshot_name = f'freecore-rollback-{captured_at.strftime("%Y%m%d%H%M%S")}'
    snapshots = [f'tank/.system@{snapshot_name}']
    expected = {'id': 7, 'captured_at': captured_at}

    service.middleware['datastore.query'] = AsyncMock(side_effect=[[], [expected]])
    service.middleware['systemdataset.config'] = AsyncMock(return_value={'basename': 'tank/.system'})
    service.middleware['bootenv.set_attribute'] = AsyncMock()
    service.middleware['datastore.insert'] = AsyncMock(return_value=7)
    service.origin_boot_environment = AsyncMock(return_value='13.3-U1.2')
    service.iocage_datasets = AsyncMock(return_value=[])
    service.pool_state = AsyncMock(return_value={})
    service.take_snapshots = AsyncMock(return_value=snapshots)

    assert await service.capture('unknown', captured_epoch) == expected
    inserted = service.middleware['datastore.insert'].await_args.args[1]
    assert inserted['captured_at'] == captured_at
    assert 'expires_at' not in inserted
    service.take_snapshots.assert_awaited_once_with(
        ['tank/.system'], snapshot_name,
    )
