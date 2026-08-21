import asyncio
import errno
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.datastore.read import DatastoreService
from middlewared.plugins.service_.services.webdav import WebDAVService
from middlewared.plugins.webdav import WebDAVSharingService
from middlewared.schema import Schemas, resolve_methods
from middlewared.service_exception import ValidationError
from middlewared.utils import filter_list

SHARE = {
    'id': 1, 'name': 'share', 'comment': '', 'path': '/mnt/tank/share',
    'ro': False, 'perm': True, 'enabled': True, 'locked': False,
}


class Middleware(dict):

    def __init__(self):
        super().__init__()
        self.call_hook = AsyncMock()
        self.event_register = Mock()
        self.send_event = Mock()

    async def _call(self, name, serviceobj, method, args, app=None):
        return await method(*args)

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    async def run_in_thread(self, method, *args, **kwargs):
        return method(*args, **kwargs)


def webdav_sharing_service():
    m = Middleware()
    # datastore.query answers like plugins/datastore/read.py: a list, or MatchNotFound for a missing `get`
    m['datastore.query'] = lambda name, filters, options: filter_list([dict(SHARE)], filters, options)
    m['datastore.update'] = Mock()
    m['datastore.delete'] = Mock(return_value=True)
    m['service.query'] = Mock(return_value={'state': 'RUNNING'})
    m['etc.generate'] = Mock()
    m['service.reload'] = Mock(return_value=True)
    m['alert.oneshot_delete'] = Mock()
    service = WebDAVSharingService(m)
    # `query-filters` and `query-options` are registered by datastore.query
    resolve_methods(Schemas(), [DatastoreService.query] + [getattr(service, attr) for attr in dir(service)])
    m['sharing.webdav.query'] = service.query
    return service, m


@pytest.mark.asyncio
async def test_updating_a_missing_share_says_it_does_not_exist():
    service, m = webdav_sharing_service()

    with pytest.raises(ValidationError) as ve:
        await service.update(None, 2, {'comment': 'x'})

    assert ve.value.errno == errno.ENOENT
    assert 'does not exist' in ve.value.errmsg
    m['datastore.update'].assert_not_called()


@pytest.mark.asyncio
async def test_deleting_a_missing_share_fails_and_leaves_apache_alone():
    service, m = webdav_sharing_service()

    with pytest.raises(ValidationError) as ve:
        await service.delete(None, 2)

    assert ve.value.errno == errno.ENOENT
    m['datastore.delete'].assert_not_called()
    m['service.reload'].assert_not_called()


@pytest.mark.asyncio
async def test_deleting_a_share_reloads_webdav():
    service, m = webdav_sharing_service()

    assert await service.delete(None, 1) is True

    m['datastore.delete'].assert_called_once_with('sharing.webdav_share', 1)
    m['service.reload'].assert_called_once_with('webdav')


@pytest.mark.asyncio
async def test_reloading_webdav_is_a_graceful_apache_reload():
    service = WebDAVService(Mock())
    calls = []

    async def _freebsd_service(rc, verb, force=False):
        calls.append((rc, verb))

    service._freebsd_service = _freebsd_service

    assert service.reloadable
    await service._reload_freebsd()
    assert calls == [('apache24', 'reload')]
