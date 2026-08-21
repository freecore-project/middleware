import enum
import importlib
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
from mako.template import Template

TEMPLATE = Path(__file__).parents[3] / 'etc_files/krb5.conf'


@pytest.fixture(scope='module')
def kerberos():
    try:
        return importlib.import_module('middlewared.plugins.kerberos')
    except ImportError:
        # Off-box the idmap plugin it takes DSType from needs Samba's tdb bindings; the template only uses the
        # KRB_* enums.
        idmap = types.ModuleType('middlewared.plugins.idmap')
        idmap.DSType = enum.Enum('DSType', 'DS_TYPE_ACTIVEDIRECTORY DS_TYPE_LDAP')
        with patch.dict(sys.modules, {'middlewared.plugins.idmap': idmap}):
            return importlib.import_module('middlewared.plugins.kerberos')


class KerberosMiddleware:

    def __init__(self, appdefaults_aux='', libdefaults_aux=''):
        self.config = {'appdefaults_aux': appdefaults_aux, 'libdefaults_aux': libdefaults_aux}

    def call_sync(self, name, *args, **kwargs):
        return {
            'activedirectory.config': {'enable': False, 'kerberos_realm': None},
            'datastore.query': {'ldap_enable': False},
            'kerberos.config': self.config,
            'kerberos.realm.query': [{'realm': 'EXAMPLE.COM', 'kdc': [], 'admin_server': [], 'kpasswd_server': []}],
        }[name]


@pytest.fixture
def section(kerberos):
    def render(name, **aux):
        with patch.dict(sys.modules, {'middlewared.plugins.kerberos': kerberos}):
            text = Template(filename=str(TEMPLATE)).render(middleware=KerberosMiddleware(**aux))
        lines = text.splitlines()
        start = lines.index(f'[{name}]') + 1
        end = next(i for i in range(start, len(lines)) if lines[i].startswith('['))
        return [line.strip() for line in lines[start:end] if line.strip()]

    return render


def test_the_built_in_libdefaults_are_written_without_aux_parameters(section):
    assert section('libdefaults') == [
        'dns_lookup_realm = true',
        'dns_lookup_kdc = true',
        'ticket_lifetime = 24h',
        'clockskew = 300',
        'forwardable = true',
    ]


def test_a_libdefaults_aux_parameter_replaces_the_built_in_default(section):
    # krb5 uses the first value of a repeated relation; a second line would never take effect
    assert section('libdefaults', libdefaults_aux='clockskew = 600\ndns_lookup_kdc = false\nkdc_timeout = 5') == [
        'dns_lookup_realm = true',
        'dns_lookup_kdc = false',
        'ticket_lifetime = 24h',
        'clockskew = 600',
        'forwardable = true',
        'kdc_timeout = 5',
    ]


def test_an_appdefaults_aux_parameter_replaces_the_built_in_pam_default(section):
    assert section('appdefaults', appdefaults_aux='pam = {\n  forwardable = false\n}') == [
        'pam = {',
        'forwardable = false',
        'ticket_lifetime = 86400',
        'renew_lifetime = 86400',
        '}',
    ]
