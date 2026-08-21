"""the internal development record: deleting an ACME certificate revokes it with the certificate type
acme 4.x takes; josepy 2 removed the ComparableX509 wrapper 13.3 used here."""
import datetime
import inspect
from unittest.mock import Mock

import pytest
from acme import errors
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from middlewared.plugins.crypto import CertificateService
from middlewared.service import CallError


class Middleware(dict):

    def __init__(self):
        super().__init__()
        self.event_register = Mock()

    async def call(self, name, *args):
        result = self[name](*args)
        return await result if inspect.isawaitable(result) else result

    def call_sync(self, name, *args):
        return self[name](*args)


def pem_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'acme.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(
        key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(
        now + datetime.timedelta(days=1)
    ).sign(key, hashes.SHA256())
    return certificate.public_bytes(Encoding.PEM).decode()


def service_for(client):
    middleware = Middleware()
    middleware['certificate.check_dependencies'] = Mock()
    middleware['certificate._get_instance'] = Mock(return_value={
        'id': 7, 'certificate': pem_certificate(),
        'acme': {'directory': 'https://acme.example.test/directory'},
    })
    middleware['datastore.delete'] = Mock(return_value=True)
    middleware['service.start'] = Mock()
    service = CertificateService(middleware)
    service.get_acme_client_and_key = Mock(return_value=(client, Mock()))
    return service, middleware


def test_acme_certificate_is_revoked_with_a_cryptography_certificate():
    client = Mock()
    service, middleware = service_for(client)

    assert CertificateService.do_delete.wraps(service, Mock(), 7) is True

    certificate, reason = client.revoke.call_args.args
    assert isinstance(certificate, x509.Certificate)
    assert certificate.subject.rfc4514_string() == 'CN=acme.example.test'
    assert reason == 0
    middleware['datastore.delete'].assert_called_once()


def test_a_refused_revocation_keeps_the_certificate_unless_forced():
    client = Mock()
    client.revoke.side_effect = errors.ClientError('revocation refused')
    service, middleware = service_for(client)

    with pytest.raises(CallError, match='Failed to revoke certificate'):
        CertificateService.do_delete.wraps(service, Mock(), 7)
    middleware['datastore.delete'].assert_not_called()

    assert CertificateService.do_delete.wraps(service, Mock(), 7, True) is True
    middleware['datastore.delete'].assert_called_once()
