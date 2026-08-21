from pathlib import Path
from unittest.mock import patch

import pytest
from mako.template import Template

TEMPLATE = Path(__file__).parents[3] / 'etc_files/local/openvpn/server/openvpn_server.conf'


class FileShouldNotExist(Exception):
    pass


class ServerMiddleware:

    def __init__(self, **config):
        self.config = {
            'server': '10.8.0.0', 'netmask': 24, 'protocol': 'UDP', 'port': 1194, 'device_type': 'TUN',
            'root_ca': 1, 'server_certificate': 2, 'topology': None, 'cipher': None, 'compression': None,
            'authentication_algorithm': None, 'tls_crypt_auth_enabled': False, 'tls_crypt_auth': None,
            'additional_parameters': '',
        }
        self.config.update(config)

    def call_sync(self, name, *args, **kwargs):
        return {
            'openvpn.server.config_valid': None,
            'openvpn.server.config': self.config,
            'certificateauthority.query': {'certificate_path': '/etc/certificates/CA/ca.crt',
                                           'crl_path': '/etc/certificates/CA/ca.crl'},
            'certificate.query': {'certificate_path': '/etc/certificates/srv.crt',
                                  'privatekey_path': '/etc/certificates/srv.key'},
            'certificate.dhparam': '/etc/certificates/dhparam.pem',
        }[name]


def render_lines(**config):
    with patch('os.makedirs'):
        text = Template(filename=str(TEMPLATE)).render(
            middleware=ServerMiddleware(**config), FileShouldNotExist=FileShouldNotExist,
        )
    return text.splitlines()


def timers(**config):
    return [line for line in render_lines(**config) if line.split(' ', 1)[0] in ('keepalive', 'ping', 'ping-restart')]


def test_the_server_keeps_idle_clients_alive_by_default():
    # without pushed timers an idle UDP client restarts every 120 s (its pre-pull ping-restart)
    assert timers() == ['keepalive 10 120']


@pytest.mark.parametrize('parameters', ['keepalive 5 30', 'ping 15\nping-restart 90', '  ping-restart 60'])
def test_timers_in_the_additional_parameters_stay_in_charge(parameters):
    assert 'keepalive 10 120' not in timers(additional_parameters=parameters)


def test_an_unrelated_parameter_does_not_suppress_the_keepalive():
    assert timers(additional_parameters='push "route 192.168.1.0 255.255.255.0"\nping-timer-rem') == ['keepalive 10 120']
