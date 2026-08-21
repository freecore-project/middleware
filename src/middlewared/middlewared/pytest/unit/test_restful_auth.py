"""The API reference describes the authentication accepted by REST."""
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
import pytest

from middlewared.restful import authenticate, OpenAPIResource


def test_openapi_advertises_basic_or_api_key():
    resource = OpenAPIResource(SimpleNamespace(app=web.Application()))
    response = resource.get(SimpleNamespace(headers={'Host': 'nas.example'}, scheme='https'))
    document = json.loads(response.text)
    schemes = document['components']['securitySchemes']
    assert schemes['basic']['type'] == 'http'
    assert schemes['basic']['scheme'] == 'basic'
    assert schemes['api_key']['type'] == 'http'
    assert schemes['api_key']['scheme'] == 'bearer'
    assert 'JWT' not in schemes['api_key'].get('bearerFormat', '')
    # Two entries are alternatives; combining them would require both.
    assert document['security'] == [{'basic': []}, {'api_key': []}]


def request(value):
    return SimpleNamespace(headers={} if value is None else {'Authorization': value})


@pytest.mark.asyncio
async def test_api_key_uses_the_existing_bearer_handler():
    middleware = SimpleNamespace(call=AsyncMock(return_value={'id': 1}))
    await authenticate(middleware, request('Bearer test-only-api-key'))
    middleware.call.assert_awaited_once_with('api_key.authenticate', 'test-only-api-key')


@pytest.mark.asyncio
async def test_rejected_api_key_does_not_fall_back_to_basic():
    middleware = SimpleNamespace(call=AsyncMock(return_value=None))
    with pytest.raises(web.HTTPUnauthorized):
        await authenticate(middleware, request('Bearer invalid-test-key'))
    middleware.call.assert_awaited_once_with('api_key.authenticate', 'invalid-test-key')


@pytest.mark.asyncio
@pytest.mark.parametrize('authorization', [None, 'Token test-only-api-key'])
async def test_missing_or_unsupported_credentials_are_rejected(authorization):
    middleware = SimpleNamespace(call=AsyncMock())
    with pytest.raises(web.HTTPUnauthorized):
        await authenticate(middleware, request(authorization))
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('otp,webauthn,valid', [
    (False, False, True), (False, False, False), (True, False, True), (False, True, True),
])
async def test_basic_preserves_password_and_second_factor_checks(otp, webauthn, valid):
    async def call(name, *args):
        if name == 'auth.twofactor.config':
            return {'enabled': otp}
        if name == 'auth.webauthn.config':
            return {'enabled': webauthn}
        assert name == 'auth.check_user'
        assert args == ('test-user', 'test-password')
        return valid

    middleware = SimpleNamespace(call=AsyncMock(side_effect=call))
    authorization = 'Basic ' + base64.b64encode(b'test-user:test-password').decode()
    if otp or webauthn or not valid:
        with pytest.raises(web.HTTPUnauthorized):
            await authenticate(middleware, request(authorization))
    else:
        await authenticate(middleware, request(authorization))
    if otp or webauthn:
        assert all(call.args[0] != 'auth.check_user' for call in middleware.call.await_args_list)
