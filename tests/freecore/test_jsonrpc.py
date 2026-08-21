"""
FreeCORE JSON-RPC 2.0 over WebSocket acceptance (the internal development record).

Deliberately not in tests/api2: that tree is the frozen CORE-parity suite, and a
module 13.3 cannot pass would break the parity inventory. This is a FreeCORE-only
capability, so it belongs here.

Everything connects through nginx on port 80 rather than middlewared's own 6000,
so a missing `location /api/current` fails these tests the same way it fails a
real client -- with a redirect to the WebUI.
"""

import json
import os
import sys

import pytest
import websocket

apifolder = os.getcwd()
sys.path.append(apifolder)

from auto_config import dev_test, ip, password, user


pytestmark = pytest.mark.skipif(dev_test, reason='Skip for test development')

JSONRPC_URL = f'ws://{ip}:80/api/current'
LEGACY_URL = f'ws://{ip}:80/websocket'
TIMEOUT = 20

# filesystem.file_tail_follow emits the current tail as soon as it starts, which
# is the cheapest deterministic event on the box: no job, nothing mutated.
TAIL_PATH = '/var/log/messages'


class Rpc:
    """
    A JSON-RPC client written out by hand rather than reused from
    middlewared.client, so these tests exercise the wire format itself.
    """

    def __init__(self, url=None):
        self.ws = websocket.create_connection(url or JSONRPC_URL, timeout=TIMEOUT)
        self._id = 0
        self.notifications = []

    def send(self, method, params=None):
        self._id += 1
        self.ws.send(json.dumps({
            'jsonrpc': '2.0',
            'id': self._id,
            'method': method,
            'params': [] if params is None else params,
        }))
        return self._id

    def recv(self):
        return json.loads(self.ws.recv())

    def call(self, method, params=None):
        """
        Send one request and return its answer.

        Notifications are set aside rather than dropped: an event source can
        emit before the `core.subscribe` result is written.
        """
        id_ = self.send(method, params)
        while True:
            frame = self.recv()
            if frame.get('id') == id_:
                return frame
            self.notifications.append(frame)

    def next_notification(self, timeout=TIMEOUT):
        if self.notifications:
            return self.notifications.pop(0)
        self.ws.settimeout(timeout)
        return self.recv()

    def login(self):
        frame = self.call('auth.login', [user, password])
        assert frame.get('result') is True, frame
        return self

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


@pytest.fixture
def rpc():
    client = Rpc()
    try:
        yield client
    finally:
        client.close()


def test_api_current_is_reachable_and_answers_a_jsonrpc_call(rpc):
    frame = rpc.call('auth.login', [user, password])

    assert frame['jsonrpc'] == '2.0', frame
    assert frame['result'] is True, frame


def test_authenticated_call_returns_a_result(rpc):
    rpc.login()

    frame = rpc.call('system.info')

    assert 'error' not in frame, frame
    assert frame['result']['version'], frame


def test_unauthenticated_call_is_refused_with_eacces(rpc):
    frame = rpc.call('system.info')

    assert frame['error']['code'] == -32001, frame
    assert frame['error']['data']['errname'] == 'EACCES', frame


def test_unknown_method_is_method_not_found(rpc):
    frame = rpc.call('no.such_method')

    assert frame['error']['code'] == -32601, frame


def test_invalid_json_does_not_close_the_connection(rpc):
    rpc.ws.send('{not json')
    frame = rpc.recv()
    assert frame['error']['code'] == -32700, frame

    # The same socket is still usable.
    assert rpc.call('auth.login', [user, password])['result'] is True


def test_batch_requests_are_refused(rpc):
    rpc.ws.send(json.dumps([{'jsonrpc': '2.0', 'id': 1, 'method': 'core.ping'}]))
    frame = rpc.recv()

    assert frame['error']['code'] == -32600, frame
    assert frame['id'] is None, frame


def test_jsonrpc_frame_on_the_legacy_endpoint_is_answered():
    """The reported failure: this used to close the connection with a KeyError."""
    client = Rpc(LEGACY_URL)
    try:
        frame = client.call('auth.login', [user, password])

        assert frame['jsonrpc'] == '2.0', frame
        assert frame['result'] is True, frame
    finally:
        client.close()


def test_legacy_protocol_is_unchanged_on_its_own_endpoint():
    ws = websocket.create_connection(LEGACY_URL, timeout=TIMEOUT)
    try:
        ws.send(json.dumps({'msg': 'connect', 'version': '1', 'support': ['1']}))
        connected = json.loads(ws.recv())
        assert connected['msg'] == 'connected', connected
        assert connected['session'], connected

        ws.send(json.dumps({
            'id': '1', 'msg': 'method', 'method': 'auth.login', 'params': [user, password],
        }))
        result = json.loads(ws.recv())
        assert result == {'id': '1', 'msg': 'result', 'result': True}, result

        ws.send(json.dumps({'msg': 'ping', 'id': '2'}))
        assert json.loads(ws.recv()) == {'msg': 'pong', 'id': '2'}
    finally:
        ws.close()


def test_core_subscribe_delivers_a_collection_update(rpc):
    """Also covers the `name:arg` subscription form and the event-source path."""
    rpc.login()
    event = f'filesystem.file_tail_follow:{TAIL_PATH}'

    ident = rpc.call('core.subscribe', [event])['result']
    assert isinstance(ident, str), ident

    try:
        notification = rpc.next_notification()
        assert notification['jsonrpc'] == '2.0', notification
        assert notification['method'] == 'collection_update', notification
        assert notification['params']['collection'] == event, notification
        assert 'data' in notification['params']['fields'], notification
    finally:
        assert rpc.call('core.unsubscribe', [ident])['result'] is None


def test_duplicate_subscription_to_a_live_event_source_is_refused(rpc):
    rpc.login()
    event = f'filesystem.file_tail_follow:{TAIL_PATH}'
    ident = rpc.call('core.subscribe', [event])['result']

    try:
        frame = rpc.call('core.subscribe', [event])

        assert frame['error']['code'] == -32001, frame
        assert 'Already subscribed' in frame['error']['data']['reason'], frame
    finally:
        rpc.call('core.unsubscribe', [ident])


def test_unsubscribe_releases_the_event_source(rpc):
    """A live source refuses a duplicate, so re-subscribing proves it was released."""
    rpc.login()
    event = f'filesystem.file_tail_follow:{TAIL_PATH}'

    first = rpc.call('core.subscribe', [event])['result']
    assert rpc.call('core.unsubscribe', [first])['result'] is None

    second = rpc.call('core.subscribe', [event])
    assert 'error' not in second, second
    rpc.call('core.unsubscribe', [second['result']])


def test_core_set_options_is_accepted(rpc):
    rpc.login()

    frame = rpc.call('core.set_options', [{'py_exceptions': True, 'private_methods': True}])

    assert 'error' not in frame, frame
    assert frame['result'] is None, frame
