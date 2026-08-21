from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

import pytest

from middlewared.plugins import nis
from middlewared.pytest.unit.middleware import Middleware
from middlewared.service import CallError


def process(returncode=0, stderr=b''):
    return SimpleNamespace(returncode=returncode, stderr=stderr)


def nis_service(events, state='HEALTHY'):
    middleware = Middleware()
    service = nis.NISService(middleware)
    service.get_state = AsyncMock(return_value=state)

    async def set_state(value):
        events.append(('state', value.name))

    async def cache_pop(key):
        events.append(('cache.pop', key))

    async def generate(group):
        events.append(('etc.generate', group))

    service.set_state = AsyncMock(side_effect=set_state)
    middleware['cache.pop'] = AsyncMock(side_effect=cache_pop)
    middleware['etc.generate'] = AsyncMock(side_effect=generate)
    return service, middleware


@pytest.mark.asyncio
@pytest.mark.parametrize('stop_result', [
    process(),
    process(1, b'ypbind not running'),
    process(1, b'no such process'),
])
async def test_stop_clears_nis_runtime_state_before_rendering_nss(stop_result):
    events = []
    service, middleware = nis_service(events)

    async def run(command, check=False):
        events.append(('run', tuple(command)))
        if command == ['/usr/sbin/service', 'ypbind', 'onestop']:
            return stop_result
        if command == ['/bin/domainname', '']:
            return process()
        raise AssertionError(command)

    def unlink(path):
        events.append(('unlink', path))

    with patch.object(nis, 'run', run), patch.object(nis.os, 'unlink', side_effect=unlink):
        assert await service.stop_impl(None) is True

    assert service.set_state.await_args_list == [
        call(nis.DSStatus['LEAVING']),
        call(nis.DSStatus['DISABLED']),
    ]
    assert middleware['cache.pop'].await_args_list == [call('NIS_State'), call('NIS_cache')]
    assert events.index(('run', ('/bin/domainname', ''))) < events.index(('state', 'DISABLED'))
    assert events.index(('state', 'DISABLED')) < events.index(('etc.generate', 'nss'))
    assert [event for event in events if event[0] == 'etc.generate'] == [
        ('etc.generate', 'nss'),
        ('etc.generate', 'rc'),
        ('etc.generate', 'pam'),
        ('etc.generate', 'hostname'),
        ('etc.generate', 'user'),
    ]
    assert ('unlink', '/var/db/system/.NIS_cache_backup') in events


@pytest.mark.asyncio
async def test_stop_ignores_an_absent_cache_backup():
    events = []
    service, _ = nis_service(events)

    async def run(command, check=False):
        return process()

    with patch.object(nis, 'run', run), patch.object(nis.os, 'unlink', side_effect=FileNotFoundError):
        assert await service.stop_impl(None) is True


@pytest.mark.asyncio
async def test_stop_fails_closed_when_domain_cannot_be_cleared():
    events = []
    service, middleware = nis_service(events)

    async def run(command, check=False):
        if command == ['/usr/sbin/service', 'ypbind', 'onestop']:
            return process()
        if command == ['/bin/domainname', '']:
            return process(1, b'permission denied')
        raise AssertionError(command)

    with patch.object(nis, 'run', run), pytest.raises(CallError, match='Failed to clear NIS domain'):
        await service.stop_impl(None)

    assert service.set_state.await_args_list == [
        call(nis.DSStatus['LEAVING']),
        call(nis.DSStatus['FAULTED']),
    ]
    middleware['cache.pop'].assert_not_awaited()
    middleware['etc.generate'].assert_not_awaited()
