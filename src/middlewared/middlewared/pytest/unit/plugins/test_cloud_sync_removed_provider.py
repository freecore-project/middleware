from unittest.mock import AsyncMock, Mock

import pytest

# The plugin imports aiorwlock. Where that is not installed the plugin cannot
# be loaded at all, and these cases are skipped instead of failing to collect.
pytest.importorskip('aiorwlock')

from middlewared.plugins import cloud_sync
from middlewared.service_exception import CallError

# What stays offered after the internal development record. A provider may be added;
# none of these may go missing with the removal of Hubic.
KEPT = {
    'AZUREBLOB', 'B2', 'BOX', 'DROPBOX', 'FTP', 'GOOGLE_CLOUD_STORAGE', 'GOOGLE_DRIVE', 'HTTP', 'MEGA',
    'ONEDRIVE', 'OPENSTACK_SWIFT', 'PCLOUD', 'S3', 'SFTP', 'STORJ_IX', 'WEBDAV', 'YANDEX',
}


def test_hubic_is_not_offered_and_the_others_are():
    names = {cls.name for cls in cloud_sync.remote_classes}
    types = {cls.rclone_type for cls in cloud_sync.remote_classes}

    assert 'HUBIC' not in names
    # rclone has had no such backend since the service shut down in 2022
    assert 'hubic' not in types
    assert KEPT <= names


def test_a_provider_that_is_registered_is_returned(monkeypatch):
    remote = Mock()
    monkeypatch.setattr(cloud_sync, 'REMOTES', {'S3': remote})

    assert cloud_sync.get_remote('S3') is remote


def test_a_stored_provider_that_is_not_there_is_a_plain_error(monkeypatch):
    monkeypatch.setattr(cloud_sync, 'REMOTES', {'S3': Mock()})

    with pytest.raises(CallError) as e:
        cloud_sync.get_remote('HUBIC')

    assert e.value.errmsg == 'The cloud sync provider HUBIC is not available in this version.'
    # the KeyError is not what the administrator gets to see
    assert e.value.__cause__ is None
    assert e.value.__suppress_context__


def test_a_task_of_a_removed_provider_cannot_build_its_rclone_configuration(monkeypatch):
    monkeypatch.setattr(cloud_sync, 'REMOTES', {'S3': Mock()})

    with pytest.raises(CallError) as e:
        cloud_sync.RcloneConfig({'credentials': {'provider': 'HUBIC', 'attributes': {'token': 't'}}})

    assert 'HUBIC' in e.value.errmsg


@pytest.mark.asyncio
async def test_list_buckets_of_a_removed_provider_is_a_plain_error(monkeypatch):
    monkeypatch.setattr(cloud_sync, 'REMOTES', {'S3': Mock()})
    service = cloud_sync.CloudSyncService(Mock())
    service._get_credentials = AsyncMock(return_value={'id': 1, 'provider': 'HUBIC', 'attributes': {'token': 't'}})

    with pytest.raises(CallError) as e:
        await service.list_buckets(1)

    assert 'HUBIC' in e.value.errmsg
