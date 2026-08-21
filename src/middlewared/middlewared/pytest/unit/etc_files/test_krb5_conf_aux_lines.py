import enum
from pathlib import Path
import sys
import types

import pytest
from mako.template import Template

TEMPLATE = Path(__file__).parents[3] / 'etc_files/krb5.conf'

if not sys.platform.startswith('freebsd'):
    # The template imports the kerberos plugin, which imports DSType from the idmap plugin; that one needs
    # Samba's tdb bindings, and DSType is only used at runtime. Load the plugin once against a stand-in.
    idmap = types.ModuleType('middlewared.plugins.idmap')
    idmap.DSType = enum.Enum('DSType', 'DS_TYPE_ACTIVEDIRECTORY DS_TYPE_LDAP')
    # Only while the real plugin is not loaded: replacing (and then deleting) a loaded one would make the next
    # import declare its tables a second time (`Table ... is already defined`).
    standin = 'middlewared.plugins.idmap' not in sys.modules
    if standin:
        sys.modules['middlewared.plugins.idmap'] = idmap
    try:
        import middlewared.plugins.kerberos  # noqa: F401
    finally:
        if standin:
            del sys.modules['middlewared.plugins.idmap']


class KerberosMiddleware:

    def __init__(self, appdefaults_aux='', libdefaults_aux=''):
        self.krb_aux = {'appdefaults_aux': appdefaults_aux, 'libdefaults_aux': libdefaults_aux}

    def call_sync(self, name, *args, **kwargs):
        return {
            'activedirectory.config': {'enable': False, 'kerberos_realm': None, 'domainname': None},
            'datastore.query': {'ldap_enable': False, 'ldap_kerberos_realm': None},
            'kerberos.config': self.krb_aux,
            'kerberos.realm.query': [
                {'realm': 'EXAMPLE.COM', 'kdc': [], 'admin_server': [], 'kpasswd_server': []},
            ],
        }[name]


def render(**aux):
    text = Template(filename=str(TEMPLATE)).render(middleware=KerberosMiddleware(**aux))
    return [line.strip() for line in text.splitlines() if line.strip()]


def section(lines, name):
    start = lines.index(f'[{name}]') + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith('[')), len(lines))
    return lines[start:end]


def test_aux_parameters_are_written():
    lines = render(appdefaults_aux='encrypt = true', libdefaults_aux='kdc_timeout = 5')
    assert 'encrypt = true' in section(lines, 'appdefaults')
    assert 'kdc_timeout = 5' in section(lines, 'libdefaults')


@pytest.mark.parametrize('aux', ['appdefaults_aux', 'libdefaults_aux'])
@pytest.mark.parametrize('line', ['forwardable true', 'ticket_lifetime'])
def test_an_aux_option_line_without_equals_does_not_stop_the_render(aux, line):
    # A stored line naming a known option but lacking "=" used to raise IndexError, so
    # etc.generate skipped krb5.conf and the previous file stayed in place
    lines = render(**{aux: f'{line}\nproxiable = true'})
    assert 'default_domain = EXAMPLE.COM' in lines
    assert 'proxiable = true' in section(lines, aux.split('_')[0])
    assert line not in lines


def test_a_libdefaults_block_keeps_its_scope():
    lines = render(libdefaults_aux='kdc_timeout = 5\nEXAMPLE.COM = {\n  max_retries = 2\n}')
    assert section(lines, 'libdefaults')[-4:] == ['kdc_timeout = 5', 'EXAMPLE.COM = {', 'max_retries = 2', '}']
