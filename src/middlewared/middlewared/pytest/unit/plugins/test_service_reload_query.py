# the internal development record: `service.reload` must not call a reload failed while the daemon is
# still coming back (sshd unlinks and rewrites its pidfile on SIGHUP), and `service.query` must
# accept filters on `state`, which is not a datastore column.
from unittest.mock import patch

import pytest

from middlewared.plugins import service as service_plugin
from middlewared.plugins.datastore.filter import FilterMixin
from middlewared.plugins.service import ServiceService
from middlewared.plugins.service_.services.base_state import ServiceState
from middlewared.utils import filter_getattrs, filter_list

ROWS = [
    {'id': 1, 'srv_service': 'ssh', 'srv_enable': True},
    {'id': 2, 'srv_service': 'ftp', 'srv_enable': False},
]
RUNNING = {'ssh'}


class FakeServiceObject:
    """A service whose `get_state` answers come from `states` once `reload` has been called."""
    reloadable = True

    def __init__(self, name, states=None, running_before=True):
        self.name = name
        self.states = states
        self.running_before = running_before
        self.reloaded = False

    async def before_reload(self):
        pass

    async def reload(self):
        self.reloaded = True

    async def after_reload(self):
        pass

    async def get_state(self):
        if self.states is None:
            return ServiceState(self.name in RUNNING, [])
        if not self.reloaded:
            return ServiceState(self.running_before, [])
        return self.states.pop(0)


def datastore_query(name, filters=None, options=None):
    """`datastore.query` building its WHERE clause with the real datastore filter code."""
    datastore = FilterMixin()
    prefix = (options or {}).get('prefix', '')
    datastore._filters_to_queryset(filters or [], datastore._get_table(name), prefix, {})
    rows = [{k.removeprefix(prefix): v for k, v in row.items()} for row in ROWS]
    return filter_list(rows, filters, {'get': (options or {}).get('get', False)})


class FakeMiddleware:
    def __init__(self, objects):
        self.objects = objects

    async def call(self, method, *args):
        if method == 'datastore.query':
            return datastore_query(*args)
        if method == 'service.object':
            return self.objects[args[0]]
        assert method == 'service.generate_etc'

    async def call_hook(self, name, *args, **kwargs):
        pass

    def event_register(self, *args, **kwargs):
        pass


def service_service(objects):
    return ServiceService(FakeMiddleware(objects))


async def reload(service_object):
    sleeps = []

    async def sleep(t):
        sleeps.append(t)

    with patch.object(service_plugin.asyncio, 'sleep', sleep):
        result = await ServiceService.reload.wraps(service_service({'ssh': service_object}), 'ssh', {})

    return result, sleeps


@pytest.mark.asyncio
async def test_reload_waits_for_daemon_that_rewrites_its_pidfile():
    # `pgrep -F` fails twice while sshd re-executes itself, then finds it again
    ssh = FakeServiceObject('ssh', [ServiceState(False, []), ServiceState(False, []), ServiceState(True, [1234])])

    result, sleeps = await reload(ssh)

    assert result is True
    assert len(sleeps) == 2


@pytest.mark.asyncio
async def test_reload_still_fails_when_daemon_never_comes_back():
    ssh = FakeServiceObject('ssh', [ServiceState(False, [])] * 100)

    result, sleeps = await reload(ssh)

    assert result is False
    assert sum(sleeps) <= 10


@pytest.mark.asyncio
async def test_reload_does_not_wait_for_service_that_was_not_running():
    # e.g. mdns with mDNS announcements turned off: its reload() does nothing
    mdns = FakeServiceObject('ssh', [ServiceState(False, [])] * 100, running_before=False)

    assert await reload(mdns) == (False, [])


@pytest.mark.asyncio
@pytest.mark.parametrize('filters,options,expected', [
    ([['state', '=', 'RUNNING']], {}, ['ssh']),
    ([['state', '=', 'STOPPED']], {}, ['ftp']),
    ([['OR', [['state', '=', 'RUNNING'], ['enable', '=', True]]]], {}, ['ssh']),
    ([['service', '=', 'ftp']], {}, ['ftp']),
])
async def test_query_filters_on_state(filters, options, expected):
    svc = service_service({name: FakeServiceObject(name) for name in ('ssh', 'ftp')})

    result = await ServiceService.query.wraps(svc, filters, options)

    assert [s['service'] for s in result] == expected


@pytest.mark.asyncio
async def test_query_get_on_state():
    svc = service_service({name: FakeServiceObject(name) for name in ('ssh', 'ftp')})

    result = await ServiceService.query.wraps(svc, [['state', '=', 'STOPPED']], {'get': True})

    assert result['service'] == 'ftp'
    assert result['state'] == 'STOPPED'


@pytest.mark.parametrize('filters,expected', [
    ([['state', '=', 'RUNNING']], {'state'}),
    ([['OR', [['state', '=', 'RUNNING'], ['enable', '=', True]]]], {'state', 'enable'}),
    ([['OR', [['a', '=', 1], ['b', '=', 2], ['c', '=', 3]]], ['d', '=', 4]], {'a', 'b', 'c', 'd'}),
])
def test_filter_getattrs_sees_every_or_branch(filters, expected):
    assert filter_getattrs(filters) == expected
