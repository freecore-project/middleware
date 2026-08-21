"""the internal development record: a certificate read does not re-validate the stored private key."""
from unittest.mock import AsyncMock, Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from middlewared.plugins import crypto
from middlewared.plugins.crypto import CERT_TYPE_EXISTING, CertificateService, CryptoKeyService


def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode()


@pytest.fixture(scope='module')
def rsa_pem():
    return pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))


def key_service():
    return CryptoKeyService(Mock())


def test_the_default_load_still_validates(rsa_pem):
    with patch.object(
        crypto.serialization, 'load_pem_private_key', wraps=serialization.load_pem_private_key,
    ) as load:
        key = key_service().load_private_key(rsa_pem)

    assert key.key_size == 2048
    assert 'unsafe_skip_rsa_key_validation' not in load.call_args.kwargs


def test_a_read_skips_the_rsa_check_and_reports_the_same_key(rsa_pem):
    with patch.object(
        crypto.serialization, 'load_pem_private_key', wraps=serialization.load_pem_private_key,
    ) as load:
        key = key_service().load_private_key(rsa_pem, None, False)

    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048
    assert load.call_args.kwargs['unsafe_skip_rsa_key_validation'] is True


@pytest.mark.parametrize('key,kind', [
    (ec.generate_private_key(ec.SECP256R1()), ec.EllipticCurvePrivateKey),
    (ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey),
])
def test_other_key_types_load_the_same_way(key, kind):
    assert isinstance(key_service().load_private_key(pem(key), None, False), kind)


def test_a_malformed_key_is_still_none():
    assert key_service().load_private_key('not a key', None, False) is None


@pytest.mark.asyncio
async def test_cert_extend_reads_size_and_type_without_validating(rsa_pem):
    calls = []

    async def call(method, *args):
        calls.append((method, args))
        if method == 'cryptokey.load_certificate':
            return {'common': 'box'}
        if method == 'cryptokey.load_private_key':
            return key_service().load_private_key(*args)
        raise AssertionError(method)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    service = CertificateService(middleware)
    cert = {
        'id': 1, 'type': CERT_TYPE_EXISTING, 'name': 'box', 'certificate': 'CERT', 'privatekey': rsa_pem,
        'CSR': None, 'signedby': None, 'revoked_date': None, 'acme': None,
    }

    with patch.object(crypto.os.path, 'exists', return_value=True):
        result = await service.cert_extend(cert)

    assert (result['key_length'], result['key_type']) == (2048, 'RSA')
    assert [args for method, args in calls if method == 'cryptokey.load_private_key'] == [(rsa_pem, None, False)]
