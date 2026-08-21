# -*- coding=utf-8 -*-
"""
JSON-RPC 2.0 over WebSocket (freecore/freecore#23).

Two things are being pinned here: that a JSON-RPC client gets a JSON-RPC
answer, and that the legacy `msg`-based protocol every existing client speaks
did not move a byte while that was added.
"""
import asyncio
import errno
import json
import logging
from unittest.mock import Mock, patch

from asyncmock import AsyncMock  # FIXME: python 3.8
import pytest

from middlewared.event import EventSource
from middlewared.jsonrpc import is_jsonrpc_request
from middlewared.main import Application, Middleware
from middlewared.plugins.datastore.read import DatastoreService
from middlewared.schema import Dict, Int, Str
from middlewared.service import accepts, job, no_auth_required, private, CoreService, Service
from middlewared.service_exception import CallError, ValidationErrors


class ProtocolService(Service):

    class Config:
        namespace = 'protocol'

    @accepts(Int('a'), Int('b'))
    async def add(self, a, b):
        return a + b

    @no_auth_required
    @accepts()
    async def anonymous(self):
        return 'anyone'

    @accepts()
    async def boom(self):
        raise CallError('it broke', errno.ENOENT)

    @accepts(Str('name'))
    async def invalid(self, name):
        verrors = ValidationErrors()
        verrors.add('protocol.invalid.name', 'That name is taken')
        raise verrors

    @accepts()
    @job()
    async def slow(self, job):
        return 'done'

    @private
    async def hidden(self):
        return 'shh'


class IdleEventSource(EventSource):
    """Sends nothing on its own: these tests are about acknowledgements."""
    def run(self):
        self._cancel.wait(5)


def make_middleware(*services, resolve=False):
    with patch('middlewared.main.multiprocessing'):
        middleware = Middleware()
    middleware.loop = asyncio.get_event_loop()
    for service in services:
        middleware.add_service(service(middleware))
    if resolve:
        middleware._resolve_methods()
    return middleware


def make_app(middleware, jsonrpc=False, authenticated=True):
    """An Application wired to a list that collects everything it sends."""
    sent = []

    async def send_str(data):
        sent.append(json.loads(data))

    app = Application(middleware, asyncio.get_event_loop(), Mock(), Mock(send_str=send_str))
    if jsonrpc:
        app.use_jsonrpc()
    else:
        app.handshake = True
    app.authenticated = authenticated
    return app, sent


async def frames(sent, count=1, timeout=5):
    """Wait for `count` frames; method calls are dispatched as tasks."""
    async def wait():
        while len(sent) < count:
            await asyncio.sleep(0.01)

    await asyncio.wait_for(wait(), timeout)
    return sent


@pytest.mark.parametrize('message,expected', [
    ({'jsonrpc': '2.0', 'id': 1, 'method': 'system.info', 'params': []}, True),
    ({'jsonrpc': '2.0', 'method': 'core.ping'}, True),
    ({'id': 1, 'msg': 'method', 'method': 'system.info', 'params': []}, False),
    # A legacy frame does not stop being one by mentioning jsonrpc.
    ({'msg': 'method', 'jsonrpc': '2.0', 'id': 1, 'method': 'x.y'}, False),
    ({'jsonrpc': '1.0', 'id': 1, 'method': 'x.y'}, False),
    ({'id': 1, 'method': 'x.y'}, False),
    ([{'jsonrpc': '2.0', 'id': 1, 'method': 'x.y'}], False),
    ('nonsense', False),
])
def test__is_jsonrpc_request(message, expected):
    assert is_jsonrpc_request(message) is expected


@pytest.mark.asyncio
async def test__call_returns_jsonrpc_result():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 7, 'method': 'protocol.add', 'params': [2, 3]})

    assert (await frames(sent))[0] == {'jsonrpc': '2.0', 'id': 7, 'result': 5}


@pytest.mark.asyncio
async def test__string_id_is_echoed_verbatim():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 'abc', 'method': 'protocol.add', 'params': [1, 1]})

    assert (await frames(sent))[0]['id'] == 'abc'


@pytest.mark.asyncio
async def test__omitted_params_mean_no_arguments():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.anonymous'})

    assert (await frames(sent))[0]['result'] == 'anyone'


@pytest.mark.asyncio
async def test__jsonrpc_frame_on_the_legacy_endpoint_is_answered_not_dropped():
    """
    The reported bug: the first frame a JSON-RPC client sends carries no `msg`,
    which used to raise KeyError in on_message() and close the connection.
    """
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)
    app.handshake = False  # nothing legacy has happened on this connection yet

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.add', 'params': [40, 2]})

    assert app.rpc is not None
    assert (await frames(sent))[0] == {'jsonrpc': '2.0', 'id': 1, 'result': 42}


@pytest.mark.asyncio
async def test__legacy_connection_is_not_switched_after_its_handshake():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)  # handshake already done

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.add', 'params': [1, 2]})

    assert app.rpc is None
    assert (await frames(sent))[0]['msg'] == 'result'
    assert (await frames(sent))[0]['error']['error'] == errno.EINVAL


@pytest.mark.asyncio
async def test__unauthenticated_call_is_refused():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True, authenticated=False)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.add', 'params': [1, 2]})

    error = (await frames(sent))[0]['error']
    assert error['code'] == -32001
    assert error['data']['error'] == errno.EACCES
    assert error['data']['errname'] == 'EACCES'
    assert error['data']['reason'] == 'Not authenticated'


@pytest.mark.asyncio
async def test__unauthenticated_call_to_public_method_is_allowed():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True, authenticated=False)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.anonymous'})

    assert (await frames(sent))[0]['result'] == 'anyone'


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['protocol.nope', 'nosuchservice.method', 'notevenamethod'])
async def test__unknown_method(method):
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': []})

    assert (await frames(sent))[0]['error']['code'] == -32601


@pytest.mark.asyncio
@pytest.mark.parametrize('message,code', [
    ({'id': 1, 'method': 'protocol.add', 'params': []}, -32600),
    ({'jsonrpc': '1.0', 'id': 1, 'method': 'protocol.add'}, -32600),
    ({'jsonrpc': '2.0', 'id': 1}, -32600),
    ({'jsonrpc': '2.0', 'id': 1, 'method': 42}, -32600),
    ({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.add', 'params': {'a': 1}}, -32602),
])
async def test__malformed_request(message, code):
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message(message)

    assert (await frames(sent))[0]['error']['code'] == code


@pytest.mark.asyncio
@pytest.mark.parametrize('message', [
    [{'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.add', 'params': [1, 2]}],
    'not an object',
])
async def test__batch_and_non_object_requests_are_refused_by_id_less_error(message):
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message(message)

    frame = (await frames(sent))[0]
    assert frame['error']['code'] == -32600
    assert frame['id'] is None


@pytest.mark.asyncio
async def test__method_error_carries_the_errno_the_legacy_protocol_would_have_sent():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.boom', 'params': []})

    frame = (await frames(sent))[0]
    assert frame['id'] == 1
    assert frame['error']['code'] == -32001
    assert frame['error']['message'] == 'method call error'
    assert frame['error']['data']['error'] == errno.ENOENT
    assert frame['error']['data']['errname'] == 'ENOENT'
    assert 'it broke' in frame['error']['data']['reason']
    assert frame['error']['data']['trace']['class'] == 'CallError'


@pytest.mark.asyncio
async def test__validation_errors_travel_in_extra():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.invalid', 'params': ['bob']})

    data = (await frames(sent))[0]['error']['data']
    assert data['error'] == errno.EAGAIN
    assert data['extra'] == [['protocol.invalid.name', 'That name is taken', errno.EINVAL]]


@pytest.mark.asyncio
async def test__too_many_concurrent_calls_has_its_own_code():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)
    serviceobj, methodobj = middleware._method_lookup('protocol.add')

    with patch.object(app, '_softhardsemaphore') as semaphore:
        from middlewared.utils.lock import SoftHardSemaphoreLimit
        semaphore.__aenter__ = AsyncMock(side_effect=SoftHardSemaphoreLimit(10))
        semaphore.__aexit__ = AsyncMock()
        await app.call_method({'id': 1, 'method': 'protocol.add', 'params': [1, 2]}, serviceobj, methodobj)

    assert (await frames(sent))[0]['error']['code'] == -32000


@pytest.mark.asyncio
async def test__job_method_returns_the_job_id():
    middleware = make_middleware(CoreService, DatastoreService, ProtocolService, resolve=True)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'protocol.slow', 'params': []})

    assert isinstance((await frames(sent))[0]['result'], int)


@pytest.mark.asyncio
async def test__events_become_collection_update_notifications():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)
    await app.subscribe('sub-1', 'protocol.thing')

    app.send_event('protocol.thing', 'CHANGED', id=5, fields={'a': 1})

    assert (await frames(sent))[0] == {
        'jsonrpc': '2.0',
        'method': 'collection_update',
        'params': {'msg': 'changed', 'collection': 'protocol.thing', 'id': 5, 'fields': {'a': 1}},
    }


@pytest.mark.asyncio
async def test__core_subscribe_returns_an_identifier_that_core_unsubscribe_takes_back():
    middleware = make_middleware(CoreService, ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({'jsonrpc': '2.0', 'id': 1, 'method': 'core.subscribe', 'params': ['protocol.thing']})
    ident = (await frames(sent))[0]['result']
    assert isinstance(ident, str)

    app.send_event('protocol.thing', 'ADDED', id=1, fields={})
    assert (await frames(sent, 2))[1]['method'] == 'collection_update'

    await app.on_message({'jsonrpc': '2.0', 'id': 2, 'method': 'core.unsubscribe', 'params': [ident]})
    assert (await frames(sent, 3))[2] == {'jsonrpc': '2.0', 'id': 2, 'result': None}

    app.send_event('protocol.thing', 'ADDED', id=2, fields={})
    assert len(sent) == 3


@pytest.mark.asyncio
async def test__subscribing_twice_to_an_event_source_is_an_error():
    middleware = make_middleware(CoreService, ProtocolService)
    middleware.register_event_source('protocol.tick', IdleEventSource)
    app, _ = make_app(middleware, jsonrpc=True)

    await app.subscribe('sub-1', 'protocol.tick')
    try:
        with pytest.raises(CallError):
            await app.subscribe('sub-2', 'protocol.tick')
    finally:
        await app.unsubscribe('sub-1')


@pytest.mark.asyncio
async def test__server_side_unsubscribe_is_announced():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)
    await app.subscribe('sub-1', 'protocol.thing')

    await app.unsubscribe('sub-1', notify=True)

    assert (await frames(sent))[0] == {
        'jsonrpc': '2.0',
        'method': 'notify_unsubscribed',
        'params': {'collection': 'protocol.thing', 'error': None},
    }


@pytest.mark.asyncio
async def test__client_side_unsubscribe_is_not_announced():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)
    await app.subscribe('sub-1', 'protocol.thing')

    await app.unsubscribe('sub-1')

    assert sent == []


@pytest.mark.asyncio
async def test__core_set_options_turns_on_py_exceptions():
    middleware = make_middleware(CoreService, ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({
        'jsonrpc': '2.0', 'id': 1, 'method': 'core.set_options',
        'params': [{'py_exceptions': True, 'private_methods': True}],
    })
    assert (await frames(sent))[0] == {'jsonrpc': '2.0', 'id': 1, 'result': None}
    assert app._py_exceptions is True

    await app.on_message({'jsonrpc': '2.0', 'id': 2, 'method': 'protocol.boom', 'params': []})
    assert 'py_exception' in (await frames(sent, 2))[1]['error']['data']


@pytest.mark.asyncio
async def test__core_set_options_ignores_options_it_does_not_know():
    middleware = make_middleware(CoreService, ProtocolService)
    app, sent = make_app(middleware, jsonrpc=True)

    await app.on_message({
        'jsonrpc': '2.0', 'id': 1, 'method': 'core.set_options', 'params': [{'legacy_jobs': True}],
    })

    assert 'error' not in (await frames(sent))[0]


#
# The legacy protocol, unchanged.
#

@pytest.mark.asyncio
async def test__legacy_connect_and_call_are_byte_for_byte_what_they_were():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)
    app.handshake = False

    await app.on_message({'msg': 'connect', 'version': '1', 'support': ['1']})
    assert (await frames(sent))[0] == {'msg': 'connected', 'session': app.session_id}

    await app.on_message({'id': '2', 'msg': 'method', 'method': 'protocol.add', 'params': [2, 2]})
    assert (await frames(sent, 2))[1] == {'id': '2', 'msg': 'result', 'result': 4}

    await app.on_message({'msg': 'ping', 'id': '3'})
    assert (await frames(sent, 3))[2] == {'msg': 'pong', 'id': '3'}


@pytest.mark.asyncio
async def test__legacy_subscription_still_answers_ready_and_nosub():
    middleware = make_middleware(ProtocolService)
    middleware.register_event_source('protocol.tick', IdleEventSource)
    app, sent = make_app(middleware)

    await app.on_message({'msg': 'sub', 'id': 'sub-1', 'name': 'protocol.tick'})
    assert (await frames(sent))[0] == {'msg': 'ready', 'subs': ['sub-1']}

    await app.on_message({'msg': 'sub', 'id': 'sub-2', 'name': 'protocol.tick'})
    assert (await frames(sent, 2))[1] == {
        'msg': 'nosub', 'id': 'sub-2', 'error': {'error': 'Already subscribed'},
    }

    await app.unsubscribe('sub-1')


@pytest.mark.asyncio
async def test__legacy_events_are_still_bare_frames():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)
    await app.subscribe('sub-1', 'protocol.thing')

    app.send_event('protocol.thing', 'CHANGED', id=5, fields={'a': 1})

    assert (await frames(sent))[0] == {
        'msg': 'changed', 'collection': 'protocol.thing', 'id': 5, 'fields': {'a': 1},
    }


@pytest.mark.asyncio
async def test__legacy_error_frame_is_unchanged():
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)

    await app.on_message({'id': '1', 'msg': 'method', 'method': 'protocol.boom', 'params': []})

    frame = (await frames(sent))[0]
    assert frame['msg'] == 'result'
    assert frame['id'] == '1'
    assert frame['error']['error'] == errno.ENOENT
    assert frame['error']['type'] is None
    assert 'it broke' in frame['error']['reason']


@pytest.mark.asyncio
@pytest.mark.parametrize('message', [
    {'id': 1, 'method': 'protocol.add', 'params': []},
    ['not', 'an', 'object'],
])
async def test__unparseable_legacy_frame_is_reported_not_fatal(caplog, message):
    """It used to raise out of on_message(), which closed the connection."""
    caplog.set_level(logging.ERROR)
    middleware = make_middleware(ProtocolService)
    app, sent = make_app(middleware)

    await app.on_message(message)

    frame = (await frames(sent))[0]
    assert frame['msg'] == 'result'
    assert frame['error']['error'] == errno.EINVAL
