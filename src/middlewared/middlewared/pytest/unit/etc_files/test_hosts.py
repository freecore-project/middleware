import builtins
from pathlib import Path
from unittest.mock import patch

from mako.template import Template

TEMPLATE = Path(__file__).parents[3] / 'etc_files/hosts'


class HostsMiddleware:

    def call_sync(self, name, *args):
        return {
            'network.configuration.config': {'hostname_local': 'nas', 'domain': 'local', 'hosts': ''},
            'directoryservice.activedirectory': {'ad_enable': False},
            'directoryservice.nis': {'nis_enable': True},
        }[name if name != 'datastore.config' else args[0]]


def render_with_nis(host_conf):
    real_open = builtins.open

    def open_host_conf(file, *args, **kwargs):
        return real_open(host_conf if file == '/etc/host.conf' else file, *args, **kwargs)

    with patch('builtins.open', open_host_conf):
        return Template(filename=str(TEMPLATE)).render(middleware=HostsMiddleware())


def test_nis_is_listed_in_host_conf_once(tmp_path):
    host_conf = tmp_path / 'host.conf'
    host_conf.write_text('hosts\n')

    for _ in range(3):
        render_with_nis(host_conf)

    assert host_conf.read_text() == 'hosts\nnis\n'
