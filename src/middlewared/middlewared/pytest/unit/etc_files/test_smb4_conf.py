import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from mako.template import Template

if not sys.platform.startswith('freebsd'):
    # The template imports the idmap plugin, which loads Samba's Python bindings and tdb
    # through the directory services and SMB plugins. Off a FreeCORE box an empty loadparm,
    # two winbind message numbers and an empty tdb stand in.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    messaging = types.ModuleType('samba.dcerpc.messaging')
    messaging.MSG_WINBIND_OFFLINE, messaging.MSG_WINBIND_ONLINE = 100, 200
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    sys.modules.setdefault('samba.dcerpc', types.ModuleType('samba.dcerpc'))
    sys.modules.setdefault('samba.dcerpc.messaging', messaging)
    sys.modules.setdefault('tdb', types.ModuleType('tdb'))


TEMPLATE = Path(__file__).parents[3] / 'etc_files' / 'local' / 'smb4.conf'


class Middleware:
    def __init__(self, cifs=None, bindip_choices=None, idmap=None):
        self.cifs = {
            'netbiosname': 'FREECORE', 'netbiosname_b': '', 'netbiosalias': [], 'netbiosname_local': 'FREECORE',
            'workgroup': 'WORKGROUP', 'description': '', 'enable_smb1': False, 'unixcharset': 'UTF-8',
            'loglevel': 'MINIMUM', 'syslog': False, 'aapl_extensions': False, 'localmaster': False,
            'guest': 'nobody', 'admin_group': None, 'filemask': '', 'dirmask': '', 'ntlmv1_auth': False,
            'bindip': [], 'smb_options': '', 'spotlight': False,
        }
        self.cifs.update(cifs or {})
        self.bindip_choices = bindip_choices or {}
        self.idmap = idmap or []

    def call_sync(self, method, *args, **kwargs):
        return {
            'smb.config': self.cifs,
            'activedirectory.config': {'enable': False},
            'ldap.config': {'enable': False, 'has_samba_schema': False},
            'datastore.config': {},
            'network.configuration.config': {'hostname_virtual': None},
            'sharing.smb.query': [],
            'smb.get_smb_ha_mode': 'STANDALONE',
            'smb.bindip_choices': self.bindip_choices,
            'user.query': 0,
            'idmap.query': self.idmap,
        }[method]


def render(**kwargs):
    """The [global] section as Samba reads it: each `key = value` line split at the first `=`
    and stripped, as lib/param does."""
    text = Template(filename=str(TEMPLATE)).render(middleware=Middleware(**kwargs))
    lines = {}
    for line in text.split('[global]', 1)[1].splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            lines[key.strip()] = (value.strip(), line.strip())
    return lines


@pytest.mark.parametrize('smb_options, key, value', [
    ('log level = 1', 'log level', '1'),
    ('log level=1', 'log level', '1'),
    ('server string = my server string here', 'server string', 'my server string here'),
    ('min receivefile size = 16384', 'min receivefile size', '16384'),
])
def test_an_aux_parameter_is_written_as_given(smb_options, key, value):
    _, line = render(cifs={'smb_options': smb_options})[key]

    assert line == f'{key} = {value}'


@pytest.mark.parametrize('smb_options', ['# a comment', '; a comment', 'no value here', ' = x'])
def test_an_aux_line_that_is_not_a_parameter_is_skipped(smb_options):
    baseline = render()

    assert render(cifs={'smb_options': smb_options}) == baseline


def test_only_the_usable_bind_addresses_are_written():
    conf = render(
        cifs={'bindip': ['192.0.2.10', '198.51.100.7']},
        bindip_choices={'192.0.2.10': '192.0.2.10'},
    )

    assert conf['interfaces'][0] == '127.0.0.1 192.0.2.10'
