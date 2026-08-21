# the internal development record: mDNS service records use the configured TFTP port and bind to the
# interface that actually has the service's bind address.
import logging
from unittest.mock import patch

import pytest

from middlewared.etc_files.local.avahi import avahi_services
from middlewared.etc_files.local.avahi.avahi_services import AvahiConst, mDNSService

INTERFACES = [
    {'name': 'igb1', 'aliases': [{'type': 'INET', 'address': '192.0.2.10', 'netmask': 24}]},
    {'name': 'igb0', 'aliases': [{'type': 'INET', 'address': '192.0.2.1', 'netmask': 24}]},
]
INDEXES = {'igb0': 1, 'igb1': 2}


class FakeMiddleware:
    logger = logging.getLogger('middlewared')

    def __init__(self, responses):
        self.responses = responses

    def call_sync(self, method, *args):
        return self.responses[method]


def mdns(service, responses):
    m = mDNSService(middleware=FakeMiddleware(responses), hostname='nas', service_info=[])
    m.service = service
    m.regtype, m.port = avahi_services.ServiceType[service].value
    return m


def if_nametoindex(name):
    try:
        return INDEXES[name]
    except KeyError:
        raise OSError(6, 'Device not configured')


def test_tftp_port_comes_from_tftp_config():
    assert mdns('TFTP', {'tftp.config': {'port': 6969}})._get_port() == 6969


def test_ftp_port_comes_from_ftp_config():
    assert mdns('FTP', {'ftp.config': {'port': 2121}})._get_port() == 2121


def test_bind_ip_matches_whole_address_not_substring():
    m = mdns('SMB', {'smb.config': {'bindip': ['192.0.2.1']}, 'interface.query': INTERFACES})

    with patch.object(avahi_services.socket, 'if_nametoindex', if_nametoindex):
        assert m._get_interfaceindex() == [INDEXES['igb0']]


@pytest.mark.parametrize('service,responses', [
    ('SMB', {'smb.config': {'bindip': ['192.0.2.1']}}),
    ('HTTP', {'system.general.config': {'ui_address': ['192.0.2.1']}}),
])
def test_interface_index_failure_is_logged_not_raised(service, responses):
    interfaces = [{'name': 'gone0', 'aliases': [{'type': 'INET', 'address': '192.0.2.1', 'netmask': 24}]}]
    m = mdns(service, responses | {'interface.query': interfaces})

    with patch.object(avahi_services.socket, 'if_nametoindex', if_nametoindex):
        assert m._get_interfaceindex() == [AvahiConst.AVAHI_IF_UNSPEC]
