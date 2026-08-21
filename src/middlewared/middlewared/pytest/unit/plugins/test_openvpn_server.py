"""OpenVPN server: an optional argument that is optional, and a fresh configuration that validates.

`client_configuration_generation` documents `server_address` as optional, but without a default the schema
answered a call that left it out with `[server_address] attribute required`. The factory row has `server = ''`
(the datastore fills a NOT NULL text column with ''), and `validate` passed it to `ipaddress.ip_address`, so an
update that did not set `server` -- `renew_static_key` on a fresh box -- ended in a bare ValueError. The chain
error was the one certificate message that started in lower case.
"""
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.vpn import OpenVPN, OpenVPNServerService
from middlewared.schema import ValidationErrors

FRESH = {
    'id': 1, 'port': 1194, 'protocol': 'UDP', 'device_type': 'TUN', 'authentication_algorithm': None,
    'tls_crypt_auth': None, 'tls_crypt_auth_enabled': False, 'cipher': None, 'compression': None,
    'additional_parameters': '', 'server_certificate': None, 'root_ca': None, 'server': '', 'topology': None,
    'netmask': 24,
}


def mock_middleware(calls):
    async def call_method(name, serviceobj, method, args):
        return await method(*args)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=lambda method, *args: calls[method])
    middleware._call = AsyncMock(side_effect=call_method)
    middleware.call_hook = AsyncMock()
    return middleware


def server_service(config):
    service = OpenVPNServerService(mock_middleware({
        'openvpn.client.config': {'port': 1194, 'nobind': True},
        'service.started': False,
        'certificateauthority.query': {'certificate': 'CA'},
        'certificate.query': [{'certificate': 'CERT', 'privatekey': 'KEY'}],
    }))
    service.config = AsyncMock(return_value=config)
    service._update_service = AsyncMock()
    return service


async def test_client_configuration_without_a_server_address():
    service = server_service({**FRESH, 'server': '10.8.0.0', 'root_ca': 1, 'server_certificate': 2})
    service.config_valid = AsyncMock()

    with patch.object(OpenVPN, 'common_validation', AsyncMock(return_value=(ValidationErrors(), {}))):
        config = await service.client_configuration_generation(3)

    assert 'remote "PLEASE FILL OUT SERVER DOMAIN/IP HERE"' in config.splitlines()


async def test_renewing_the_static_key_of_a_fresh_server_is_a_validation_error():
    service = server_service(FRESH)
    service.generate_static_key = AsyncMock(return_value='KEY')

    with pytest.raises(ValidationErrors) as e:
        await service.renew_static_key()

    assert [error.attribute for error in e.value.errors] == ['openvpn_server_update.server']


async def test_an_update_that_sets_the_server_still_checks_the_netmask():
    service = server_service(FRESH)

    with pytest.raises(ValidationErrors) as e:
        await service.update({'server': '10.8.0.0', 'netmask': 64})

    assert [error.attribute for error in e.value.errors] == ['openvpn_server_update.netmask']


@pytest.mark.parametrize('mode', ['server', 'client'])
async def test_the_chain_error_starts_with_a_capital_like_the_others(mode):
    middleware = mock_middleware({
        'certificateauthority.query': [{'certificate': 'CA', 'extensions': {
            'BasicConstraints': 'CA:TRUE', 'KeyUsage': 'Certificate Sign, CRL Sign', 'SubjectKeyIdentifier': 'x',
        }}],
        'certificate.query': [{'certificate': 'CERT', 'common': 'cn', 'extensions': {}}],
        'cryptokey.validate_cert_with_chain': False,
    })

    verrors = await OpenVPN.cert_validation(
        middleware, {'root_ca': 1, f'{mode}_certificate': 2}, 'schema', mode, ValidationErrors()
    )

    assert f'{mode.capitalize()} certificate chain could not be verified with specified root CA.' in [
        error.errmsg for error in verrors.errors
    ]
