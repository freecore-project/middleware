"""the internal development record: what the certificate store owes the applications that mount from it.

A certificate an application mounts is not deleted, and a renewal -- the one path that
rewrites a certificate's bytes -- tells Applications which certificates changed.
"""
import datetime
import errno
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from middlewared.plugins.crypto import CertificateService
from middlewared.service import CallError


class Middleware(dict):

    def __init__(self):
        super().__init__()
        self.event_register = Mock()

    def call_sync(self, name, *args):
        return self[name](*args)


def deleting_service(in_use):
    middleware = Middleware()
    middleware['certificate.check_dependencies'] = Mock()
    middleware['applications.certificates_in_use'] = Mock(side_effect=in_use)
    middleware['certificate._get_instance'] = Mock(return_value={'id': 7, 'certificate': '', 'acme': None})
    middleware['datastore.delete'] = Mock(return_value=True)
    middleware['service.start'] = Mock()
    return CertificateService(middleware), middleware


def test_a_certificate_an_application_mounts_is_not_deleted():
    service, middleware = deleting_service(lambda id_: ['proxy', 'web'])

    with pytest.raises(CallError, match=r'mounted into the application\(s\) proxy, web') as refused:
        CertificateService.do_delete.wraps(service, Mock(), 7)

    assert refused.value.errno == errno.EBUSY
    middleware['applications.certificates_in_use'].assert_called_once_with(7)
    middleware['certificate._get_instance'].assert_not_called()
    middleware['datastore.delete'].assert_not_called()


def test_forcing_the_delete_does_not_get_past_the_applications():
    service, middleware = deleting_service(lambda id_: ['proxy'])

    with pytest.raises(CallError, match='mounted into the application'):
        CertificateService.do_delete.wraps(service, Mock(), 7, True)
    middleware['datastore.delete'].assert_not_called()


def test_a_pool_that_cannot_be_read_refuses_the_delete_too():
    def unavailable(id_):
        raise CallError('The Applications pool is not available', errno.EBUSY)
    service, middleware = deleting_service(unavailable)

    with pytest.raises(CallError, match='is not available'):
        CertificateService.do_delete.wraps(service, Mock(), 7)
    middleware['datastore.delete'].assert_not_called()


def test_a_certificate_nothing_mounts_is_deleted_as_before():
    service, middleware = deleting_service(lambda id_: [])

    assert CertificateService.do_delete.wraps(service, Mock(), 7) is True
    middleware['datastore.delete'].assert_called_once()


# -- renewal -----------------------------------------------------------------------------------

def stamp(days):
    return (datetime.datetime.utcnow() + datetime.timedelta(days=days)).strftime('%a %b %d %H:%M:%S %Y')


def acme_certificate(id_, days_left):
    return {
        'id': id_, 'name': f'acme-{id_}', 'until': stamp(days_left), 'renew_days': 10,
        'acme': {'directory': 'https://acme.example.test/directory'},
        'domains_authenticators': {'app.example.test': 1},
    }


def renewing_service(certificates):
    order = []
    middleware = Middleware()
    middleware['certificate.query'] = Mock(return_value=certificates)
    middleware['datastore.update'] = Mock(side_effect=lambda *args: order.append(('update', args[1], args[2])))
    middleware['applications.reconcile_certificates'] = Mock(
        side_effect=lambda ids: order.append(('reconcile', list(ids)))
    )
    service = CertificateService(middleware)
    service.acme_issue_certificate = Mock(
        return_value=SimpleNamespace(fullchain_pem='RENEWED PEM', uri='https://acme.example.test/order/2'),
    )
    return service, middleware, order


def test_a_renewal_writes_the_row_and_then_tells_applications_which_certificates_changed():
    due, later, also_due = acme_certificate(3, 5), acme_certificate(4, 60), acme_certificate(5, 2)
    service, middleware, order = renewing_service([due, later, also_due])

    service.renew_certs(Mock())

    # One reconcile for the whole pass, after every row is written, naming only what was renewed.
    assert [step[0] for step in order] == ['update', 'update', 'reconcile']
    assert order[-1] == ('reconcile', [3, 5])
    # The renewal writes the certificate and its order only: the private key is never touched,
    # so the renewed leaf carries the key an application's entry is bound to.
    assert order[0] == ('update', 3, {'certificate': 'RENEWED PEM', 'acme_uri': 'https://acme.example.test/order/2'})
    assert service.acme_issue_certificate.call_count == 2


def test_a_pass_that_renews_nothing_leaves_applications_alone():
    service, middleware, order = renewing_service([acme_certificate(4, 60)])

    service.renew_certs(Mock())

    assert order == []
    middleware['applications.reconcile_certificates'].assert_not_called()
