import json
from unittest.mock import Mock

import pytest

from middlewared.rclone.remote import onedrive
from middlewared.service_exception import CallError


class Response:
    def __init__(self, status_code, payload=None, text=''):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


def personal(drive_id):
    return {'id': drive_id, 'driveType': 'personal'}


def business(drive_id):
    return {'id': drive_id, 'driveType': 'business'}


@pytest.fixture
def remote():
    return onedrive.OneDriveRcloneRemote(Mock())


@pytest.fixture
def graph(monkeypatch):
    calls = {'get': [], 'post': []}
    routes = {}

    def get(url, headers, timeout):
        calls['get'].append((url, headers['Authorization']))
        return routes[(url, headers['Authorization'])]

    def post(url, data, timeout):
        calls['post'].append((url, data))
        return routes[('POST', url)]

    monkeypatch.setattr(onedrive.requests, 'get', get)
    monkeypatch.setattr(onedrive.requests, 'post', post)
    return calls, routes


def token(access='old', refresh='r1'):
    return json.dumps({'access_token': access, 'refresh_token': refresh, 'token_type': 'Bearer', 'expiry': 'x'})


def test_lists_drives_with_the_current_token(remote, graph):
    calls, routes = graph
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer old')] = Response(200, {'value': [business('b1'), personal('p1')]})
    routes[(f'{onedrive.GRAPH_URL}/me/drive', 'Bearer old')] = Response(200, personal('p1'))

    assert remote.list_drives({'token': token()}) == [
        {'drive_type': 'BUSINESS', 'drive_id': 'b1'},
        {'drive_type': 'PERSONAL', 'drive_id': 'p1'},
    ]
    assert calls['post'] == []


def test_own_drive_missing_from_me_drives_is_added_first(remote, graph):
    _, routes = graph
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer old')] = Response(200, {'value': [business('b1')]})
    routes[(f'{onedrive.GRAPH_URL}/me/drive', 'Bearer old')] = Response(200, personal('p1'))

    assert remote.list_drives({'token': token()}) == [
        {'drive_type': 'PERSONAL', 'drive_id': 'p1'},
        {'drive_type': 'BUSINESS', 'drive_id': 'b1'},
    ]


def test_expired_token_is_refreshed_with_the_default_application(remote, graph):
    calls, routes = graph
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer old')] = Response(401, text='expired')
    routes[('POST', onedrive.TOKEN_URL)] = Response(200, {'access_token': 'new'})
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer new')] = Response(200, {'value': [personal('p1')]})
    routes[(f'{onedrive.GRAPH_URL}/me/drive', 'Bearer new')] = Response(200, personal('p1'))

    assert remote.list_drives({'token': token()}) == [{'drive_type': 'PERSONAL', 'drive_id': 'p1'}]
    (url, data), = calls['post']
    assert data['grant_type'] == 'refresh_token'
    assert data['refresh_token'] == 'r1'
    assert data['client_id'] == onedrive.DEFAULT_CLIENT_ID
    assert data['client_secret'] == onedrive.DEFAULT_CLIENT_SECRET


def test_supplied_application_credentials_are_used_for_refresh(remote, graph):
    calls, routes = graph
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer old')] = Response(401)
    routes[('POST', onedrive.TOKEN_URL)] = Response(200, {'access_token': 'new'})
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer new')] = Response(200, {'value': []})
    routes[(f'{onedrive.GRAPH_URL}/me/drive', 'Bearer new')] = Response(404)

    assert remote.list_drives({'token': token(), 'client_id': 'mine', 'client_secret': 's3'}) == []
    (_, data), = calls['post']
    assert (data['client_id'], data['client_secret']) == ('mine', 's3')


@pytest.mark.parametrize('routes_setup, message', [
    ({('drives', 'Bearer old'): Response(403, text='denied')}, 'Unable to list OneDrive drives: HTTP 403'),
    ({('drives', 'Bearer old'): Response(401), ('POST', None): Response(400, text='invalid_grant')},
     'Unable to refresh the OneDrive access token: HTTP 400'),
])
def test_http_failures_become_call_errors(remote, graph, routes_setup, message):
    _, routes = graph
    for (kind, auth), response in routes_setup.items():
        if kind == 'POST':
            routes[('POST', onedrive.TOKEN_URL)] = response
        else:
            routes[(f'{onedrive.GRAPH_URL}/me/drives', auth)] = response

    with pytest.raises(CallError) as e:
        remote.list_drives({'token': token()})
    assert message in str(e.value)


@pytest.mark.parametrize('bad_token', ['not json', '{}', '[]'])
def test_malformed_token_is_a_call_error(remote, graph, bad_token):
    with pytest.raises(CallError, match='not a valid OAuth token'):
        remote.list_drives({'token': bad_token})


def test_expired_token_without_refresh_token_is_a_call_error(remote, graph):
    _, routes = graph
    routes[(f'{onedrive.GRAPH_URL}/me/drives', 'Bearer old')] = Response(401)
    with pytest.raises(CallError, match='no refresh token'):
        remote.list_drives({'token': json.dumps({'access_token': 'old'})})


def test_module_no_longer_needs_onedrivesdk():
    import inspect
    assert 'onedrivesdk' not in inspect.getsource(onedrive).replace('onedrivesdk package', '')
