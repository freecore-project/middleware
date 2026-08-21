import grp
import os
import pwd
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins import rsync
from middlewared.plugins.cache import DSCache
from middlewared.service_exception import ValidationErrors


class Middleware:

    def __init__(self):
        self.calls = []
        self.event_register = Mock()

    async def call(self, name, *args):
        self.calls.append((name, args))
        if name == 'datastore.delete':
            return True
        if name == 'service.query':
            return {'service': 'rsync', 'state': 'RUNNING'}
        if name == 'etc.generate':
            return None
        if name == 'service.reload':
            return True
        # The real lookups behind user.get_user_obj / group.get_group_obj
        if name == 'user.get_user_obj':
            return DSCache.get_uncached_user(None, args[0].get('username'), args[0].get('uid'))
        if name == 'group.get_group_obj':
            return DSCache.get_uncached_group(None, args[0].get('groupname'), args[0].get('gid'))
        raise AssertionError(f'unexpected middleware call {name!r}')


def rsync_module(**overrides):
    module = {
        'name': 'backup',
        'path': '/mnt/tank/backup',
        'mode': 'RW',
        'user': pwd.getpwuid(os.getuid()).pw_name,
        'group': grp.getgrgid(os.getgid()).gr_name,
        'hostsallow': [],
        'hostsdeny': [],
    }
    module.update(overrides)
    return module


@pytest.mark.asyncio
async def test_delete_reloads_rsync():
    middleware = Middleware()
    service = rsync.RsyncModService(middleware)

    assert await service.do_delete.wraps(service, 1) is True

    assert ('datastore.delete', ('services.rsyncmod', 1)) in middleware.calls
    assert ('service.reload', ('rsync',)) in middleware.calls


@pytest.mark.parametrize('name', ['backup', 'my module', 'a.b-c_d', 'a[b'])
def test_module_name_accepted(name):
    rsync.RsyncModService.do_create.accepts[0].attrs['name'].validate(name)


@pytest.mark.parametrize('name', ['', '/a', 'a/b', 'a/', ']a', 'x]y', 'a]', 'a\nb', 'a\n'])
def test_module_name_rejected(name):
    with pytest.raises(ValidationErrors):
        rsync.RsyncModService.do_create.accepts[0].attrs['name'].validate(name)


@pytest.mark.asyncio
async def test_valid_user_and_group_accepted():
    service = rsync.RsyncModService(Middleware())
    service.validate_path_field = AsyncMock()

    data = await service.common_validation(rsync_module(), 'rsyncmod_create')

    assert data['mode'] == 'rw'


@pytest.mark.asyncio
@pytest.mark.parametrize('entity', ['user', 'group'])
@pytest.mark.parametrize('value', ['', 'no-such-rsyncmod-owner'])
async def test_invalid_user_or_group_rejected(entity, value):
    service = rsync.RsyncModService(Middleware())
    service.validate_path_field = AsyncMock()

    with pytest.raises(ValidationErrors) as ve:
        await service.common_validation(rsync_module(**{entity: value}), 'rsyncmod_create')

    assert [e.attribute for e in ve.value.errors] == [f'rsyncmod_create.{entity}']
